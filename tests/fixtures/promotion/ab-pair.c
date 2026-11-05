/* SPDX-License-Identifier: GPL-3.0-or-later */
/* A/B promotion-pair ledger emitter (E17 pattern).
 *
 * Usage: ab-pair PROVIDER LEDGER_PATH [GO_FILE] [MODE] [B_CALLS]
 *
 * MODE is pair (default), cancel or retire; B_CALLS defaults to 8 (1..1000).
 * Pass an empty GO_FILE ("") to skip the gate while still setting MODE.
 * Side A is one held return: the hold_begin row opens the hold window, side B
 * makes B_CALLS useful provider calls inside it, and the hold_end row closes
 * it with the real A return value. Cancel mode emits a cancel marker halfway
 * through the B calls, keeps the caller live, withholds the remaining B calls
 * until the A completion, then runs them. Retire mode appends a retire row
 * after the A completion. Every row carries a contiguous seq; clocks are
 * CLOCK_MONOTONIC nanoseconds.
 *
 * The A hold is driver-side: the stub entries return instantly, so no kernel
 * call stays in flight across the window. The ledger brackets the hold with
 * real stamps (hold_begin t0 before the first B call, hold_end t1 after the
 * real A call returns), and B rows genuinely execute between those stamps.
 *
 * Stub-only fixture: PROVIDER must come from the live-discovery-provider
 * stub family (the P11ScopeSlot68 marker export must be present); anything
 * else is refused, because calling unknown-signature entries through the
 * one-pointer-argument TableEntry would be undefined behaviour. Entry 4
 * (C_GetSlotList) serves side A, entry 12 (C_OpenSession) side B; both must
 * be non-NULL. Prints "READY pid=<pid>" after the table is validated, then,
 * when GO_FILE is given, waits for that path to appear before emitting the
 * ready row; SIGTERM/SIGINT interrupts the wait. Exit 0 when every call
 * returned CKR_OK, 1 when the ledger is complete but some call did not,
 * 2 on usage/setup/refusal failure. LP64 only; ia32 twins use their own
 * driver, never this emitter.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TABLE_SLOTS 104
#define ENTRY_A 4
#define ENTRY_B 12
#define MAX_B_CALLS 1000

/* Mirrors P11ScopeTable in tests/fixtures/live-discovery-provider.c:
 * CK_VERSION (2 bytes), 6 reserved bytes, 104 function pointers. */
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[TABLE_SLOTS];
} ProviderTable;

_Static_assert(sizeof(void *) == 8 && sizeof(unsigned long) == 8, "LP64 only");
_Static_assert(offsetof(ProviderTable, functions) == 8, "table layout");

typedef unsigned long (*TableEntry)(void **);
typedef unsigned long (*GetFunctionList)(void **);

static volatile sig_atomic_t stop;

static void on_signal(int number) {
    (void)number;
    stop = 1;
}

static int clock_ns(uint64_t *out) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    *out = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
    return 0;
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

static int parse_number(const char *text, unsigned long bound, unsigned long *out) {
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
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value > bound) {
        return -1;
    }
    *out = value;
    return 0;
}

typedef enum { MODE_PAIR, MODE_CANCEL, MODE_RETIRE } RunMode;

static int parse_mode(const char *text, RunMode *out) {
    if (strcmp(text, "pair") == 0) {
        *out = MODE_PAIR;
        return 0;
    }
    if (strcmp(text, "cancel") == 0) {
        *out = MODE_CANCEL;
        return 0;
    }
    if (strcmp(text, "retire") == 0) {
        *out = MODE_RETIRE;
        return 0;
    }
    return -1;
}

typedef struct {
    FILE *ledger;
    int pid;
    int tid;
    unsigned long seq;
    unsigned long unhealthy;
    int failed;
} Emitter;

static void emit_ready(Emitter *out, uint64_t ready) {
    if (fprintf(out->ledger,
                "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                out->pid, out->tid, ready) < 0) {
        out->failed = 1;
    }
}

static void emit_hold_begin(Emitter *out, uint64_t t0) {
    out->seq++;
    if (fprintf(out->ledger,
                "{\"kind\":\"hold_begin\",\"seq\":%lu,\"side\":\"A\",\"fn\":\"table[%d]\","
                "\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64 "}\n",
                out->seq, ENTRY_A, out->pid, out->tid, t0) < 0) {
        out->failed = 1;
    }
}

static void emit_call(Emitter *out, TableEntry entry, int index) {
    uint64_t t0 = 0, t1 = 0;
    if (clock_ns(&t0) != 0) {
        out->failed = 1;
        return;
    }
    unsigned long rv = entry(NULL);
    if (clock_ns(&t1) != 0) {
        out->failed = 1;
        return;
    }
    if (rv != 0) {
        out->unhealthy++;
    }
    out->seq++;
    if (fprintf(out->ledger,
                "{\"kind\":\"call\",\"seq\":%lu,\"side\":\"B\",\"fn\":\"table[%d]\","
                "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64 ",\"t1\":%" PRIu64 "}\n",
                out->seq, index, rv, out->pid, out->tid, t0, t1) < 0) {
        out->failed = 1;
    }
}

static void emit_alive(Emitter *out) {
    uint64_t now = 0;
    if (clock_ns(&now) != 0) {
        out->failed = 1;
        return;
    }
    out->seq++;
    if (fprintf(out->ledger,
                "{\"kind\":\"alive\",\"seq\":%lu,\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64 "}\n",
                out->seq, out->pid, out->tid, now) < 0) {
        out->failed = 1;
    }
}

static void emit_cancel(Emitter *out) {
    uint64_t now = 0;
    if (clock_ns(&now) != 0) {
        out->failed = 1;
        return;
    }
    out->seq++;
    if (fprintf(out->ledger,
                "{\"kind\":\"cancel\",\"seq\":%lu,\"t\":%" PRIu64 "}\n", out->seq, now) < 0) {
        out->failed = 1;
    }
}

static unsigned long emit_hold_end(Emitter *out, TableEntry entry, unsigned long ref) {
    unsigned long rv = entry(NULL);
    uint64_t t1 = 0;
    if (clock_ns(&t1) != 0) {
        out->failed = 1;
        return 0;
    }
    if (rv != 0) {
        out->unhealthy++;
    }
    out->seq++;
    if (fprintf(out->ledger,
                "{\"kind\":\"hold_end\",\"seq\":%lu,\"side\":\"A\",\"ref\":%lu,"
                "\"rv\":%lu,\"t1\":%" PRIu64 "}\n",
                out->seq, ref, rv, t1) < 0) {
        out->failed = 1;
    }
    return out->seq;
}

static void emit_retire(Emitter *out, unsigned long after) {
    uint64_t now = 0;
    if (clock_ns(&now) != 0) {
        out->failed = 1;
        return;
    }
    out->seq++;
    if (fprintf(out->ledger,
                "{\"kind\":\"retire\",\"seq\":%lu,\"side\":\"A\",\"after\":%lu,"
                "\"t\":%" PRIu64 "}\n",
                out->seq, after, now) < 0) {
        out->failed = 1;
    }
}

static void emit_ack(Emitter *out, unsigned long issued, uint64_t done) {
    if (fprintf(out->ledger, "{\"kind\":\"ack\",\"issued\":%lu,\"held\":1,\"t\":%" PRIu64 "}\n",
                issued, done) < 0) {
        out->failed = 1;
    }
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 6) {
        fprintf(stderr, "usage: %s PROVIDER LEDGER_PATH [GO_FILE] [MODE] [B_CALLS]\n",
                argc > 0 ? argv[0] : "ab-pair");
        return 2;
    }
    RunMode mode = MODE_PAIR;
    if (argc >= 5 && parse_mode(argv[4], &mode) != 0) {
        fprintf(stderr, "ab-pair: MODE must be pair, cancel or retire\n");
        return 2;
    }
    unsigned long b_calls = 8;
    if (argc == 6 && (parse_number(argv[5], MAX_B_CALLS, &b_calls) != 0 || b_calls == 0)) {
        fprintf(stderr, "ab-pair: B_CALLS must be 1..%d\n", MAX_B_CALLS);
        return 2;
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "ab-pair: cannot open provider: %s\n", dlerror());
        return 2;
    }
    GetFunctionList get_list = (GetFunctionList)dlsym(handle, "C_GetFunctionList");
    void *raw = NULL;
    if (get_list == NULL || get_list(&raw) != 0 || raw == NULL) {
        fprintf(stderr, "ab-pair: C_GetFunctionList failed\n");
        dlclose(handle);
        return 2;
    }
    ProviderTable *table = raw;
    if (table->functions[ENTRY_A] == NULL || table->functions[ENTRY_B] == NULL) {
        fprintf(stderr, "ab-pair: table entry %d or %d is empty\n", ENTRY_A, ENTRY_B);
        dlclose(handle);
        return 2;
    }
    if (dlsym(handle, "P11ScopeSlot68") == NULL) {
        fprintf(stderr, "ab-pair: refuses non-stub provider (stub-only fixture)\n");
        dlclose(handle);
        return 2;
    }
    TableEntry entry_a = (TableEntry)table->functions[ENTRY_A];
    TableEntry entry_b = (TableEntry)table->functions[ENTRY_B];

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (argc >= 4 && argv[3][0] != '\0' && wait_for_go(argv[3]) != 0) {
        if (stop) {
            fprintf(stderr, "ab-pair: interrupted while waiting for gate\n");
        } else {
            fprintf(stderr, "ab-pair: cannot wait for gate\n");
        }
        dlclose(handle);
        return 2;
    }

    FILE *ledger = fopen(argv[2], "w");
    if (ledger == NULL) {
        fprintf(stderr, "ab-pair: cannot open ledger: %s\n", strerror(errno));
        dlclose(handle);
        return 2;
    }
    Emitter out = {.ledger = ledger, .pid = (int)getpid(), .tid = (int)gettid()};
    uint64_t ready = 0;
    if (clock_ns(&ready) != 0) {
        fprintf(stderr, "ab-pair: clock read failed\n");
        fclose(ledger);
        dlclose(handle);
        return 2;
    }
    emit_ready(&out, ready);
    uint64_t hold_t0 = 0;
    if (!out.failed && clock_ns(&hold_t0) != 0) {
        out.failed = 1;
    }
    unsigned long begin_seq = 0;
    if (!out.failed) {
        emit_hold_begin(&out, hold_t0);
        begin_seq = out.seq;
    }
    unsigned long before = b_calls;
    if (mode == MODE_CANCEL) {
        before = b_calls / 2;
    }
    for (unsigned long i = 0; i < before && !out.failed; i++) {
        emit_call(&out, entry_b, ENTRY_B);
    }
    if (mode == MODE_CANCEL && !out.failed) {
        emit_cancel(&out);
        emit_alive(&out);
    } else if (!out.failed) {
        emit_alive(&out);
    }
    unsigned long end_seq = 0;
    if (!out.failed) {
        end_seq = emit_hold_end(&out, entry_a, begin_seq);
    }
    if (mode == MODE_RETIRE && !out.failed) {
        emit_retire(&out, end_seq);
    }
    for (unsigned long i = before; i < b_calls && !out.failed; i++) {
        emit_call(&out, entry_b, ENTRY_B);
    }
    if (!out.failed) {
        emit_alive(&out);
    }
    uint64_t done = 0;
    if (!out.failed && clock_ns(&done) != 0) {
        out.failed = 1;
    }
    if (!out.failed) {
        emit_ack(&out, b_calls, done);
    }
    if (fclose(ledger) != 0) {
        out.failed = 1;
    }
    dlclose(handle);
    if (out.failed) {
        fprintf(stderr, "ab-pair: ledger emission failed\n");
        return 2;
    }
    return out.unhealthy == 0 ? 0 : 1;
}
