/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Stub-family async-collision provider fixture (new file; the shared
 * live-discovery-provider.c is never modified).
 *
 * A 104-slot one-signature table (every slot: unsigned long f(void *))
 * plus C_GetFunctionList, the stub-family marker P11ScopeSlot68, and the
 * async capability record P11ScopeAsyncCaps. The caps record names the
 * slot indices of the async entries, the polls-to-complete count, and
 * the message-wait minimum size; drivers must bind through it, never
 * through hardcoded indices. Table slot functions stay hidden (static);
 * only C_GetFunctionList and the two marker records are exported.
 *
 * Argument contract (AsyncArg, mirrored in collide.c and kept in sync
 * by hand): async_id carries the operation id (out on begin, in on
 * every other async entry), size carries the caller buffer size for the
 * message wait. All fields are uint64_t, so the layout is identical on
 * LP64 and ILP32. Return values use the vendored PKCS#11 codes
 * (cryptoki-sys vendor/pkcs11.h): CKR_OK 0, CKR_ARGUMENTS_BAD 7,
 * CKR_FUNCTION_CANCELED 0x50, CKR_OPERATION_NOT_INITIALIZED 0x91,
 * CKR_BUFFER_TOO_SMALL 0x150, CKR_PENDING 0x204.
 *
 * Per-process deterministic state: begin allocates async ids 1, 2, ...
 * (two processes driving the same script observe equal ids); each
 * pending op answers CKR_PENDING polls_to_complete times before it can
 * complete; status observes without consuming; the message wait refuses
 * short buffers without changing state and completes idempotently;
 * cancel ends a pending op; begin_fail always refuses; the finalize op
 * acknowledges teardown and answers CKR_OK. Post-teardown refusals are an
 * observer-side rule (snapshot gaps), not provider-side: entries keep
 * answering after finalize so the ledger can record the attempt. The
 * provider prints nothing.
 */
#include <stddef.h>
#include <stdint.h>

#define TABLE_SLOTS 104
#define MAX_OPS 256

#define CKR_OK 0ul
#define CKR_ARGUMENTS_BAD 7ul
#define CKR_OPERATION_NOT_INITIALIZED 0x91ul
#define CKR_BUFFER_TOO_SMALL 0x150ul
#define CKR_PENDING 0x204ul

#define IDX_BEGIN 80
#define IDX_POLL 81
#define IDX_STATUS 82
#define IDX_WAIT 83
#define IDX_CANCEL 84
#define IDX_BEGIN_FAIL 85
#define IDX_FINALIZE_OP 86

#define POLLS_TO_COMPLETE 2
#define WAIT_MIN_SIZE 64

/* Keep in sync with collide.c. */
typedef struct {
    uint64_t async_id;
    uint64_t size;
} AsyncArg;

/* Keep in sync with collide.c. */
typedef struct {
    uint32_t begin;
    uint32_t poll;
    uint32_t status;
    uint32_t wait;
    uint32_t cancel;
    uint32_t begin_fail;
    uint32_t finalize_op;
    uint32_t polls_to_complete;
    uint32_t wait_min_size;
} AsyncCaps;

typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[TABLE_SLOTS];
} ProviderTable;

typedef unsigned long (*AsyncEntry)(void *);

int P11ScopeSlot68;

const AsyncCaps P11ScopeAsyncCaps = {
    IDX_BEGIN, IDX_POLL, IDX_STATUS, IDX_WAIT, IDX_CANCEL, IDX_BEGIN_FAIL,
    IDX_FINALIZE_OP, POLLS_TO_COMPLETE, WAIT_MIN_SIZE,
};

enum op_state { OP_FREE, OP_PENDING, OP_COMPLETED, OP_CANCELLED };

static struct {
    uint64_t id;
    int polls_left;
    int state;
} ops[MAX_OPS];
static uint64_t next_async_id;
static unsigned op_count;

static int find_op(uint64_t id) {
    for (unsigned i = 0; i < op_count; i++) {
        if (ops[i].id == id) {
            return (int)i;
        }
    }
    return -1;
}

static unsigned long entry_noop(void *arg) {
    (void)arg;
    return CKR_OK;
}

static unsigned long entry_begin(void *arg) {
    AsyncArg *in = arg;
    if (in == NULL || op_count >= MAX_OPS) {
        return CKR_ARGUMENTS_BAD;
    }
    next_async_id++;
    ops[op_count].id = next_async_id;
    ops[op_count].polls_left = POLLS_TO_COMPLETE;
    ops[op_count].state = OP_PENDING;
    op_count++;
    in->async_id = next_async_id;
    return CKR_OK;
}

static unsigned long entry_poll(void *arg) {
    AsyncArg *in = arg;
    if (in == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    int at = find_op(in->async_id);
    if (at < 0) {
        return CKR_ARGUMENTS_BAD;
    }
    if (ops[at].state == OP_CANCELLED) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ops[at].state == OP_COMPLETED) {
        return CKR_OK;
    }
    if (ops[at].polls_left > 0) {
        ops[at].polls_left--;
        return CKR_PENDING;
    }
    ops[at].state = OP_COMPLETED;
    return CKR_OK;
}

static unsigned long entry_status(void *arg) {
    AsyncArg *in = arg;
    if (in == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    int at = find_op(in->async_id);
    if (at < 0) {
        return CKR_ARGUMENTS_BAD;
    }
    if (ops[at].state == OP_CANCELLED) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    return ops[at].state == OP_COMPLETED ? CKR_OK : CKR_PENDING;
}

static unsigned long entry_wait(void *arg) {
    AsyncArg *in = arg;
    if (in == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    if (in->size < WAIT_MIN_SIZE) {
        return CKR_BUFFER_TOO_SMALL;
    }
    int at = find_op(in->async_id);
    if (at < 0) {
        return CKR_ARGUMENTS_BAD;
    }
    if (ops[at].state == OP_CANCELLED) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    ops[at].state = OP_COMPLETED;
    return CKR_OK;
}

static unsigned long entry_cancel(void *arg) {
    AsyncArg *in = arg;
    if (in == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    int at = find_op(in->async_id);
    if (at < 0) {
        return CKR_ARGUMENTS_BAD;
    }
    if (ops[at].state != OP_PENDING) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    ops[at].state = OP_CANCELLED;
    return CKR_OK;
}

static unsigned long entry_begin_fail(void *arg) {
    (void)arg;
    return CKR_ARGUMENTS_BAD;
}

static unsigned long entry_finalize_op(void *arg) {
    (void)arg;
    return CKR_OK;
}

static ProviderTable provider_table;

__attribute__((constructor)) static void provider_init(void) {
    provider_table.major = 3;
    provider_table.minor = 2;
    for (int i = 0; i < TABLE_SLOTS; i++) {
        provider_table.functions[i] = (void *)entry_noop;
    }
    provider_table.functions[IDX_BEGIN] = (void *)entry_begin;
    provider_table.functions[IDX_POLL] = (void *)entry_poll;
    provider_table.functions[IDX_STATUS] = (void *)entry_status;
    provider_table.functions[IDX_WAIT] = (void *)entry_wait;
    provider_table.functions[IDX_CANCEL] = (void *)entry_cancel;
    provider_table.functions[IDX_BEGIN_FAIL] = (void *)entry_begin_fail;
    provider_table.functions[IDX_FINALIZE_OP] = (void *)entry_finalize_op;
}

__attribute__((visibility("default"))) unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return CKR_ARGUMENTS_BAD;
    }
    *out = &provider_table;
    return CKR_OK;
}
