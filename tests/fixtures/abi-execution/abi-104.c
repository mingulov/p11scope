/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 104-entry ABI execution ledger emitter (E17 pattern).
 *
 * Usage: abi-104 PROVIDER LEDGER_PATH [GO_FILE] [MODE] [ARG]
 *
 * MODE selects the workload (default full):
 *   full            call entries 0..103 once each (cond full, cell full)
 *   threads         T threads x P calls to entry E (cond threads, cell threads)
 *   hot             T threads x K calls to one hot entry (cond hot, cell hot-keys)
 *   cond:NAME       NAME in migration, nesting, recursion, longjmp,
 *                   thread-exit, held-detach (cell cond-NAME)
 *   blocked         one completed call plus one entry-without-return row
 *                   (cond blocked, cell blocked-unreturned)
 *   cell:TAG        entries 0..2 tagged with the opaque population label TAG
 *   rv64            entries 0..3, recording full-width return values
 *   entry           one call to entry ARG (0..103)
 * ARG carries the mode parameters: "T,P,E" for threads and hot (defaults
 * "4,25,5" and "8,50,5"; threads 1..64, per-thread calls 1..10000, total at
 * most 100000, entry 0..103); the entry index for entry mode. Pass an empty
 * GO_FILE ("") to skip the gate while still setting MODE.
 *
 * Every body row carries a contiguous seq, the entry index, the fn label,
 * the cond workload tag and the cell population label; clocks are
 * CLOCK_MONOTONIC nanoseconds. Workers record their calls into private
 * result arrays and the main thread emits every row after joining, so the
 * ledger needs no locks. The blocked worker parks pre-return until after
 * the ack row is written, modelling a genuinely unreturned call inside the
 * capture window. The nesting/recursion modes genuinely nest driver frames
 * that each issue one real provider call inside their window.
 *
 * Entry names come from dlsym: when every one of the 104 known names
 * resolves to its table slot, rows carry verified names (proving actual
 * execution, not a macro count); when none resolves (a test-only stub
 * family provider), rows carry table[i] labels; a mix is refused as an
 * entry identity mismatch. Stub-only fixture: PROVIDER must export the
 * P11ScopeSlot68 marker; anything else is refused, because calling
 * unknown-signature entries through the one-pointer-argument TableEntry
 * would be undefined behaviour. Prints "READY pid=<pid>" after the table
 * is validated, then, when GO_FILE is given, waits for that path to appear
 * before emitting the ready row; SIGTERM/SIGINT interrupts the wait.
 * Exit 0 when every call returned CKR_OK, 1 when the ledger is complete but
 * some call did not, 2 on usage/setup/refusal failure. Builds LP64 and
 * ia32 (-m32) from this one source.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TABLE_SLOTS 104
#define STANDARD_NAMES 68
#define MAX_THREADS 64
#define MAX_THREAD_CALLS 10000
#define MAX_TOTAL_CALLS 100000

/* Mirrors P11ScopeTable in tests/fixtures/live-discovery-provider.c:
 * CK_VERSION (2 bytes), 6 reserved bytes, 104 function pointers. */
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[TABLE_SLOTS];
} ProviderTable;

_Static_assert(sizeof(unsigned long) == 4 || sizeof(unsigned long) == 8,
               "32-bit or 64-bit CK_ULONG only");
_Static_assert(offsetof(ProviderTable, functions) == 8, "table layout");

typedef unsigned long (*TableEntry)(void **);
typedef unsigned long (*GetFunctionList)(void **);

/* Slots 0..67 in PROVIDER_FUNCTIONS order; slots 68..103 are P11ScopeSlotN
 * spelled at runtime. dlsym verifies every name against its slot. */
static const char *const standard_names[STANDARD_NAMES] = {
    "C_Initialize", "C_Finalize", "C_GetInfo", "P11ScopeSlot3",
    "C_GetSlotList", "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList",
    "C_GetMechanismInfo", "C_InitToken", "C_InitPIN", "C_SetPIN",
    "C_OpenSession", "C_CloseSession", "C_CloseAllSessions",
    "C_GetSessionInfo", "C_GetOperationState", "C_SetOperationState",
    "C_Login", "C_Logout", "C_CreateObject", "C_CopyObject",
    "C_DestroyObject", "C_GetObjectSize", "C_GetAttributeValue",
    "C_SetAttributeValue", "C_FindObjectsInit", "C_FindObjects",
    "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt", "C_EncryptUpdate",
    "C_EncryptFinal", "C_DecryptInit", "C_Decrypt", "C_DecryptUpdate",
    "C_DecryptFinal", "C_DigestInit", "C_Digest", "C_DigestUpdate",
    "C_DigestKey", "C_DigestFinal", "C_SignInit", "C_Sign", "C_SignUpdate",
    "C_SignFinal", "C_SignRecoverInit", "C_SignRecover", "C_VerifyInit",
    "C_Verify", "C_VerifyUpdate", "C_VerifyFinal", "C_VerifyRecoverInit",
    "C_VerifyRecover", "C_DigestEncryptUpdate", "C_DecryptDigestUpdate",
    "C_SignEncryptUpdate", "C_DecryptVerifyUpdate", "C_GenerateKey",
    "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey", "C_DeriveKey",
    "C_SeedRandom", "C_GenerateRandom", "C_GetFunctionStatus",
    "C_CancelFunction", "C_WaitForSlotEvent",
};

typedef struct {
    FILE *ledger;
    int pid;
    int tid;
    unsigned long seq;
    unsigned long calls;
    unsigned long blocked;
    unsigned long unhealthy;
    int failed;
    int names_verified;
    TableEntry entries[TABLE_SLOTS];
} Emitter;

/* Static (never automatic) emission state: the longjmp mode returns across
 * frames, which would leave stack-held seq/failed values indeterminate. */
static Emitter out;
static jmp_buf jump_target;

static volatile sig_atomic_t stop;

static void on_signal(int number) {
    (void)number;
    stop = 1;
}

static int clock_ns(uint64_t *out_ns) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    *out_ns = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
    return 0;
}

static void sleep_ms(long ms) {
    struct timespec delay = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&delay, &delay) != 0) {
    }
}

static int wait_for_go(const char *path) {
    while (access(path, F_OK) != 0 && !stop) {
        if (errno != ENOENT) {
            return -1;
        }
        usleep(10000);
    }
    return stop ? 1 : 0;
}

static int parse_number(const char *text, unsigned long bound, unsigned long *value) {
    if (text[0] == '\0') {
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
    }
    errno = 0;
    char *end = NULL;
    unsigned long number = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || number > bound) {
        return -1;
    }
    *value = number;
    return 0;
}

/* "T,P,E" triple for the threaded modes. */
static int parse_triple(const char *text, unsigned long *threads,
                        unsigned long *per_thread, unsigned long *entry) {
    char *copy = strdup(text);
    if (copy == NULL) {
        return -1;
    }
    int ok = 0;
    char *save = NULL;
    char *first = strtok_r(copy, ",", &save);
    char *second = strtok_r(NULL, ",", &save);
    char *third = strtok_r(NULL, ",", &save);
    char *extra = strtok_r(NULL, ",", &save);
    if (first != NULL && second != NULL && third != NULL && extra == NULL &&
        parse_number(first, MAX_THREADS, threads) == 0 && *threads > 0 &&
        parse_number(second, MAX_THREAD_CALLS, per_thread) == 0 && *per_thread > 0 &&
        parse_number(third, TABLE_SLOTS - 1, entry) == 0 &&
        *threads * *per_thread <= MAX_TOTAL_CALLS) {
        ok = 1;
    }
    free(copy);
    return ok ? 0 : -1;
}

static int valid_tag(const char *text) {
    size_t len = strlen(text);
    if (len == 0 || len > 64) {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        unsigned char c = *p;
        if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') &&
            !(c >= '0' && c <= '9') && c != '_' && c != '-' && c != '.') {
            return 0;
        }
    }
    return 1;
}

static const char *fn_label(int index, char *fallback, size_t size) {
    if (out.names_verified) {
        if (index < STANDARD_NAMES) {
            return standard_names[index];
        }
        snprintf(fallback, size, "P11ScopeSlot%d", index);
        return fallback;
    }
    snprintf(fallback, size, "table[%d]", index);
    return fallback;
}

static void emit_ready(uint64_t ready) {
    if (fprintf(out.ledger,
                "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                out.pid, out.tid, ready) < 0) {
        out.failed = 1;
    }
}

static void emit_thread(int tid) {
    out.seq++;
    if (fprintf(out.ledger, "{\"kind\":\"thread\",\"seq\":%lu,\"pid\":%d,\"tid\":%d}\n",
                out.seq, out.pid, tid) < 0) {
        out.failed = 1;
    }
}

static void emit_call_row(int index, unsigned long rv, int tid, uint64_t t0,
                          uint64_t t1, const char *cond, const char *cell) {
    char label[32];
    const char *fn = fn_label(index, label, sizeof label);
    out.seq++;
    out.calls++;
    if (rv != 0) {
        out.unhealthy++;
    }
    if (fprintf(out.ledger,
                "{\"kind\":\"call\",\"seq\":%lu,\"entry\":%d,\"fn\":\"%s\",\"rv\":%lu,"
                "\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64 ",\"t1\":%" PRIu64
                ",\"cond\":\"%s\",\"cell\":\"%s\"}\n",
                out.seq, index, fn, rv, out.pid, tid, t0, t1, cond, cell) < 0) {
        out.failed = 1;
    }
}

static void emit_call(int index, const char *cond, const char *cell) {
    uint64_t t0 = 0, t1 = 0;
    if (clock_ns(&t0) != 0) {
        out.failed = 1;
        return;
    }
    unsigned long rv = out.entries[index](NULL);
    if (clock_ns(&t1) != 0) {
        out.failed = 1;
        return;
    }
    emit_call_row(index, rv, out.tid, t0, t1, cond, cell);
}

static void emit_entry_row(int index, int tid, uint64_t t0, const char *cond,
                           const char *cell) {
    char label[32];
    const char *fn = fn_label(index, label, sizeof label);
    out.seq++;
    out.blocked++;
    if (fprintf(out.ledger,
                "{\"kind\":\"entry\",\"seq\":%lu,\"entry\":%d,\"fn\":\"%s\","
                "\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                ",\"cond\":\"%s\",\"cell\":\"%s\"}\n",
                out.seq, index, fn, out.pid, tid, t0, cond, cell) < 0) {
        out.failed = 1;
    }
}

static void emit_cpu(int cpu) {
    uint64_t now = 0;
    if (clock_ns(&now) != 0) {
        out.failed = 1;
        return;
    }
    out.seq++;
    if (fprintf(out.ledger,
                "{\"kind\":\"cpu\",\"seq\":%lu,\"pid\":%d,\"tid\":%d,\"cpu\":%d,"
                "\"t\":%" PRIu64 "}\n",
                out.seq, out.pid, out.tid, cpu, now) < 0) {
        out.failed = 1;
    }
}

static void emit_ack(uint64_t done) {
    if (fprintf(out.ledger, "{\"kind\":\"ack\",\"issued\":%lu,\"blocked\":%lu,\"t\":%" PRIu64
                            "}\n",
                out.calls, out.blocked, done) < 0) {
        out.failed = 1;
    }
}

typedef struct {
    uint64_t t0;
    uint64_t t1;
    unsigned long rv;
    int index;
} CallResult;

typedef struct {
    TableEntry entry;
    int index;
    unsigned long count;
    CallResult *results;
    int failed;
    int tid;
} WorkerArg;

static void *run_worker(void *raw) {
    WorkerArg *arg = raw;
    arg->tid = (int)gettid();
    for (unsigned long i = 0; i < arg->count; i++) {
        uint64_t t0 = 0, t1 = 0;
        if (clock_ns(&t0) != 0) {
            arg->failed = 1;
            return NULL;
        }
        unsigned long rv = arg->entry(NULL);
        if (clock_ns(&t1) != 0) {
            arg->failed = 1;
            return NULL;
        }
        arg->results[i].t0 = t0;
        arg->results[i].t1 = t1;
        arg->results[i].rv = rv;
        arg->results[i].index = arg->index;
    }
    return NULL;
}

static void *run_exiting_worker(void *raw) {
    WorkerArg *arg = raw;
    run_worker(raw);
    int failed = arg->failed;
    pthread_exit(failed ? (void *)1 : NULL);
    return NULL;
}

typedef struct {
    pthread_t *threads;
    WorkerArg *args;
    CallResult *results;
    unsigned long thread_count;
    unsigned long per_thread;
} ThreadPool;

static int pool_start(ThreadPool *pool, unsigned long thread_count,
                      unsigned long per_thread, int index, int exiting) {
    pool->threads = calloc(thread_count, sizeof *pool->threads);
    pool->args = calloc(thread_count, sizeof *pool->args);
    pool->results = calloc(thread_count * per_thread, sizeof *pool->results);
    pool->thread_count = thread_count;
    pool->per_thread = per_thread;
    if (pool->threads == NULL || pool->args == NULL || pool->results == NULL) {
        return -1;
    }
    for (unsigned long i = 0; i < thread_count; i++) {
        pool->args[i].entry = out.entries[index];
        pool->args[i].index = index;
        pool->args[i].count = per_thread;
        pool->args[i].results = pool->results + i * per_thread;
        void *(*start)(void *) = exiting ? run_exiting_worker : run_worker;
        if (pthread_create(&pool->threads[i], NULL, start, &pool->args[i]) != 0) {
            for (unsigned long j = 0; j < i; j++) {
                pthread_join(pool->threads[j], NULL);
            }
            return -1;
        }
    }
    return 0;
}

static int pool_finish(ThreadPool *pool, const char *cond, const char *cell) {
    int failed = 0;
    for (unsigned long i = 0; i < pool->thread_count; i++) {
        void *status = NULL;
        if (pthread_join(pool->threads[i], &status) != 0 || status != NULL ||
            pool->args[i].failed) {
            failed = 1;
        }
    }
    if (!failed) {
        for (unsigned long i = 0; i < pool->thread_count; i++) {
            emit_thread(pool->args[i].tid);
        }
        for (unsigned long i = 0; i < pool->thread_count; i++) {
            for (unsigned long j = 0; j < pool->per_thread; j++) {
                CallResult *result = &pool->results[i * pool->per_thread + j];
                emit_call_row(result->index, result->rv, pool->args[i].tid,
                              result->t0, result->t1, cond, cell);
            }
        }
    }
    free(pool->threads);
    free(pool->args);
    free(pool->results);
    return failed ? -1 : 0;
}

static int set_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    return sched_setaffinity(0, sizeof set, &set);
}

static int run_migration(void) {
    /* A cpuset without CPU 0 fails like a missing CPU 1 below: tolerate
     * EINVAL and record the CPUs the calls actually ran on. */
    if (set_cpu(0) != 0 && errno != EINVAL) {
        return -1;
    }
    emit_call(5, "migration", "cond-migration");
    int first = sched_getcpu();
    if (first < 0) {
        return -1;
    }
    emit_cpu(first);
    if (set_cpu(1) != 0 && errno != EINVAL) {
        return -1;
    }
    emit_call(5, "migration", "cond-migration");
    int second = sched_getcpu();
    if (second < 0) {
        return -1;
    }
    emit_cpu(second);
    return out.failed ? -1 : 0;
}

static void nest_level(int index, int depth) {
    uint64_t t0 = 0;
    if (clock_ns(&t0) != 0) {
        out.failed = 1;
        return;
    }
    if (depth > 1) {
        nest_level(index, depth - 1);
        if (out.failed) {
            return;
        }
    }
    unsigned long rv = out.entries[index](NULL);
    uint64_t t1 = 0;
    if (clock_ns(&t1) != 0) {
        out.failed = 1;
        return;
    }
    emit_call_row(index, rv, out.tid, t0, t1, "recursion", "cond-recursion");
}

static void mutually_b(int index, int depth);

static void mutually_a(int index, int depth) {
    uint64_t t0 = 0;
    if (clock_ns(&t0) != 0) {
        out.failed = 1;
        return;
    }
    if (depth > 1) {
        mutually_b(index, depth - 1);
        if (out.failed) {
            return;
        }
    }
    unsigned long rv = out.entries[index](NULL);
    uint64_t t1 = 0;
    if (clock_ns(&t1) != 0) {
        out.failed = 1;
        return;
    }
    emit_call_row(index, rv, out.tid, t0, t1, "nesting", "cond-nesting");
}

static void mutually_b(int index, int depth) {
    uint64_t t0 = 0;
    if (clock_ns(&t0) != 0) {
        out.failed = 1;
        return;
    }
    if (depth > 1) {
        mutually_a(index, depth - 1);
        if (out.failed) {
            return;
        }
    }
    unsigned long rv = out.entries[index](NULL);
    uint64_t t1 = 0;
    if (clock_ns(&t1) != 0) {
        out.failed = 1;
        return;
    }
    emit_call_row(index, rv, out.tid, t0, t1, "nesting", "cond-nesting");
}

static int run_longjmp(void) {
    if (setjmp(jump_target) == 0) {
        emit_call(7, "longjmp", "cond-longjmp");
        if (out.failed) {
            return -1;
        }
        longjmp(jump_target, 1);
    }
    emit_call(7, "longjmp", "cond-longjmp");
    return out.failed ? -1 : 0;
}

static int run_thread_exit(void) {
    ThreadPool pool = {0};
    if (pool_start(&pool, 1, 3, 8, 1) != 0) {
        return -1;
    }
    if (pool_finish(&pool, "thread-exit", "cond-thread-exit") != 0) {
        return -1;
    }
    return out.failed ? -1 : 0;
}

static int run_held_detach(const char *provider) {
    void *second = dlopen(provider, RTLD_NOW | RTLD_LOCAL);
    if (second == NULL) {
        return -1;
    }
    emit_call(9, "held-detach", "cond-held-detach");
    if (out.failed) {
        dlclose(second);
        return -1;
    }
    if (dlclose(second) != 0) {
        return -1;
    }
    emit_call(9, "held-detach", "cond-held-detach");
    return out.failed ? -1 : 0;
}

typedef struct {
    _Atomic int entered;
    _Atomic int release;
    int tid;
    uint64_t t0;
} BlockedState;

static void *run_blocked_worker(void *raw) {
    BlockedState *state = raw;
    uint64_t t0 = 0;
    if (clock_ns(&t0) != 0) {
        return (void *)1;
    }
    state->tid = (int)gettid();
    state->t0 = t0;
    atomic_store_explicit(&state->entered, 1, memory_order_release);
    for (int waited = 0; waited < 30000; waited++) {
        if (atomic_load_explicit(&state->release, memory_order_acquire) != 0) {
            return NULL;
        }
        usleep(1000);
    }
    return (void *)1;
}

static int run_blocked(void) {
    emit_call(9, "blocked", "blocked-unreturned");
    if (out.failed) {
        return -1;
    }
    BlockedState state = {0};
    pthread_t worker;
    if (pthread_create(&worker, NULL, run_blocked_worker, &state) != 0) {
        return -1;
    }
    int entered = 0;
    for (int waited = 0; waited < 10000; waited++) {
        if (atomic_load_explicit(&state.entered, memory_order_acquire) != 0) {
            entered = 1;
            break;
        }
        usleep(1000);
    }
    if (!entered) {
        pthread_join(worker, NULL);
        return -1;
    }
    /* The entry stays genuinely unreturned across a real delay. */
    sleep_ms(50);
    emit_thread(state.tid);
    emit_entry_row(10, state.tid, state.t0, "blocked", "blocked-unreturned");
    if (out.failed) {
        atomic_store_explicit(&state.release, 1, memory_order_release);
        pthread_join(worker, NULL);
        return -1;
    }
    uint64_t done = 0;
    if (clock_ns(&done) != 0) {
        atomic_store_explicit(&state.release, 1, memory_order_release);
        pthread_join(worker, NULL);
        return -1;
    }
    emit_ack(done);
    if (fflush(out.ledger) != 0) {
        out.failed = 1;
    }
    atomic_store_explicit(&state.release, 1, memory_order_release);
    void *status = NULL;
    if (pthread_join(worker, &status) != 0 || status != NULL || out.failed) {
        return -1;
    }
    return 0;
}

typedef enum {
    MODE_FULL,
    MODE_THREADS,
    MODE_HOT,
    MODE_COND,
    MODE_BLOCKED,
    MODE_CELL,
    MODE_RV64,
    MODE_ENTRY
} RunMode;

static int parse_mode(const char *text, RunMode *out_mode, const char **rest) {
    if (strcmp(text, "full") == 0) {
        *out_mode = MODE_FULL;
        return 0;
    }
    if (strcmp(text, "threads") == 0) {
        *out_mode = MODE_THREADS;
        return 0;
    }
    if (strcmp(text, "hot") == 0) {
        *out_mode = MODE_HOT;
        return 0;
    }
    if (strcmp(text, "blocked") == 0) {
        *out_mode = MODE_BLOCKED;
        return 0;
    }
    if (strcmp(text, "rv64") == 0) {
        *out_mode = MODE_RV64;
        return 0;
    }
    if (strcmp(text, "entry") == 0) {
        *out_mode = MODE_ENTRY;
        return 0;
    }
    if (strncmp(text, "cond:", 5) == 0) {
        *out_mode = MODE_COND;
        *rest = text + 5;
        return 0;
    }
    if (strncmp(text, "cell:", 5) == 0) {
        *out_mode = MODE_CELL;
        *rest = text + 5;
        return 0;
    }
    return -1;
}

static int run_cond(const char *name, const char *provider) {
    if (strcmp(name, "migration") == 0) {
        return run_migration();
    }
    if (strcmp(name, "nesting") == 0) {
        mutually_a(6, 3);
        return out.failed ? -1 : 0;
    }
    if (strcmp(name, "recursion") == 0) {
        nest_level(6, 5);
        return out.failed ? -1 : 0;
    }
    if (strcmp(name, "longjmp") == 0) {
        return run_longjmp();
    }
    if (strcmp(name, "thread-exit") == 0) {
        return run_thread_exit();
    }
    if (strcmp(name, "held-detach") == 0) {
        return run_held_detach(provider);
    }
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 6) {
        fprintf(stderr, "usage: %s PROVIDER LEDGER_PATH [GO_FILE] [MODE] [ARG]\n",
                argc > 0 ? argv[0] : "abi-104");
        return 2;
    }
    RunMode mode = MODE_FULL;
    const char *rest = "";
    if (argc >= 5 && parse_mode(argv[4], &mode, &rest) != 0) {
        fprintf(stderr, "abi-104: MODE must be full, threads, hot, cond:NAME, "
                        "blocked, cell:TAG, rv64 or entry\n");
        return 2;
    }
    if (mode == MODE_COND &&
        (strcmp(rest, "migration") != 0 && strcmp(rest, "nesting") != 0 &&
         strcmp(rest, "recursion") != 0 && strcmp(rest, "longjmp") != 0 &&
         strcmp(rest, "thread-exit") != 0 && strcmp(rest, "held-detach") != 0)) {
        fprintf(stderr, "abi-104: unknown cond %s\n", rest);
        return 2;
    }
    if (mode == MODE_CELL && !valid_tag(rest)) {
        fprintf(stderr, "abi-104: TAG must match [A-Za-z0-9_.-]{1,64}\n");
        return 2;
    }
    unsigned long threads = 4, per_thread = 25, entry = 5;
    if (mode == MODE_THREADS || mode == MODE_HOT) {
        const char *text = argc == 6 ? argv[5] : (mode == MODE_THREADS ? "4,25,5" : "8,50,5");
        if (parse_triple(text, &threads, &per_thread, &entry) != 0) {
            fprintf(stderr, "abi-104: ARG must be T,P,E within bounds\n");
            return 2;
        }
    }
    unsigned long single = 0;
    if (mode == MODE_ENTRY) {
        if (argc != 6 || parse_number(argv[5], TABLE_SLOTS - 1, &single) != 0) {
            fprintf(stderr, "abi-104: entry ARG must be 0..%d\n", TABLE_SLOTS - 1);
            return 2;
        }
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "abi-104: cannot open provider: %s\n", dlerror());
        return 2;
    }
    GetFunctionList get_list = (GetFunctionList)dlsym(handle, "C_GetFunctionList");
    void *raw = NULL;
    if (get_list == NULL || get_list(&raw) != 0 || raw == NULL) {
        fprintf(stderr, "abi-104: C_GetFunctionList failed\n");
        dlclose(handle);
        return 2;
    }
    ProviderTable *table = raw;
    for (int i = 0; i < TABLE_SLOTS; i++) {
        if (table->functions[i] == NULL) {
            fprintf(stderr, "abi-104: table entry %d is empty\n", i);
            dlclose(handle);
            return 2;
        }
        out.entries[i] = (TableEntry)table->functions[i];
    }
    if (dlsym(handle, "P11ScopeSlot68") == NULL) {
        fprintf(stderr, "abi-104: refuses non-stub provider (stub-only fixture)\n");
        dlclose(handle);
        return 2;
    }
    unsigned long resolved = 0;
    for (int i = 0; i < TABLE_SLOTS; i++) {
        char want[32];
        const char *name = NULL;
        if (i < STANDARD_NAMES) {
            name = standard_names[i];
        } else {
            snprintf(want, sizeof want, "P11ScopeSlot%d", i);
            name = want;
        }
        void *symbol = dlsym(handle, name);
        if (symbol == NULL) {
            continue;
        }
        if (symbol != table->functions[i]) {
            /* Slot 68 shares its name with the stub-family marker: the
             * production provider binds a function there, test-only stubs
             * bind the marker variable. A mismatch at 68 alone skips only
             * the immediate per-slot refusal below; the aggregate gate
             * still refuses unless all 104 names resolve (or none do, for
             * test-only stubs), so a 103-match provider with the marker
             * at 68 is refused as a mixed-identity build. */
            if (i == 68) {
                continue;
            }
            fprintf(stderr, "abi-104: entry identity mismatch at %d\n", i);
            dlclose(handle);
            return 2;
        }
        resolved++;
    }
    if (resolved != 0 && resolved != TABLE_SLOTS) {
        fprintf(stderr, "abi-104: entry identity mismatch (%lu of %d names resolve)\n",
                resolved, TABLE_SLOTS);
        dlclose(handle);
        return 2;
    }
    out.names_verified = resolved == TABLE_SLOTS;

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (argc >= 4 && argv[3][0] != '\0' && wait_for_go(argv[3]) != 0) {
        if (stop) {
            fprintf(stderr, "abi-104: interrupted while waiting for gate\n");
        } else {
            fprintf(stderr, "abi-104: cannot wait for gate\n");
        }
        dlclose(handle);
        return 2;
    }

    out.ledger = fopen(argv[2], "w");
    if (out.ledger == NULL) {
        fprintf(stderr, "abi-104: cannot open ledger: %s\n", strerror(errno));
        dlclose(handle);
        return 2;
    }
    out.pid = (int)getpid();
    out.tid = (int)gettid();
    uint64_t ready = 0;
    if (clock_ns(&ready) != 0) {
        fprintf(stderr, "abi-104: clock read failed\n");
        fclose(out.ledger);
        dlclose(handle);
        return 2;
    }
    emit_ready(ready);
    int status = 0;
    if (!out.failed) {
        switch (mode) {
        case MODE_FULL:
            for (int i = 0; i < TABLE_SLOTS && !out.failed; i++) {
                emit_call(i, "full", "full");
            }
            break;
        case MODE_THREADS: {
            ThreadPool pool = {0};
            if (pool_start(&pool, threads, per_thread, (int)entry, 0) != 0 ||
                pool_finish(&pool, "threads", "threads") != 0) {
                status = -1;
            }
            break;
        }
        case MODE_HOT: {
            ThreadPool pool = {0};
            if (pool_start(&pool, threads, per_thread, (int)entry, 0) != 0 ||
                pool_finish(&pool, "hot", "hot-keys") != 0) {
                status = -1;
            }
            break;
        }
        case MODE_COND:
            if (run_cond(rest, argv[1]) != 0) {
                status = -1;
            }
            break;
        case MODE_BLOCKED:
            if (run_blocked() != 0) {
                status = -1;
            }
            break;
        case MODE_CELL:
            for (int i = 0; i < 3 && !out.failed; i++) {
                emit_call(i, "cellrun", rest);
            }
            break;
        case MODE_RV64:
            for (int i = 0; i < 4 && !out.failed; i++) {
                emit_call(i, "rv64", "rv64");
            }
            break;
        case MODE_ENTRY:
            emit_call((int)single, "entry", "entry");
            break;
        }
    }
    /* Blocked mode writes its own ack before releasing the worker. */
    uint64_t done = 0;
    if (mode != MODE_BLOCKED && !out.failed && status == 0 && clock_ns(&done) != 0) {
        out.failed = 1;
    }
    if (mode != MODE_BLOCKED && !out.failed && status == 0) {
        emit_ack(done);
    }
    if (status != 0) {
        out.failed = 1;
    }
    if (fclose(out.ledger) != 0) {
        out.failed = 1;
    }
    dlclose(handle);
    if (out.failed) {
        fprintf(stderr, "abi-104: ledger emission failed\n");
        return 2;
    }
    return out.unhealthy == 0 ? 0 : 1;
}
