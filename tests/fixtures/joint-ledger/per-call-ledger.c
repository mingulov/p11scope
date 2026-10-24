/* SPDX-License-Identifier: GPL-3.0-or-later */
/* R2 T0: independent per-call ledger emitter (E17 pattern).
 *
 * Usage: per-call-ledger PROVIDER TABLE_INDEX COUNT LEDGER_PATH [GO_FILE]
 *
 * Opens PROVIDER, resolves C_GetFunctionList, and calls the table entry at
 * TABLE_INDEX (0..103, one-pointer-argument shape, NULL argument) COUNT
 * times, recording one JSONL row per call with CLOCK_MONOTONIC t0/t1 stamps.
 * Prints "READY pid=<pid>" after the table is validated, then, when GO_FILE
 * is given, waits for that path to appear before emitting the ready row.
 * Exit 0 when every call returned CKR_OK, 1 when the ledger is complete but
 * some call did not, 2 on usage/setup failure. LP64 only.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TABLE_SLOTS 104
#define MAX_CALLS 200000

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

static int clock_ns(uint64_t *out) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    *out = (uint64_t)now.tv_sec * 1000000000u + (uint64_t)now.tv_nsec;
    return 0;
}

static int wait_for_go(const char *path) {
    while (access(path, F_OK) != 0) {
        if (errno != ENOENT) {
            return -1;
        }
        usleep(10000);
    }
    return 0;
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

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        fprintf(stderr, "usage: %s PROVIDER TABLE_INDEX COUNT LEDGER_PATH [GO_FILE]\n",
                argc > 0 ? argv[0] : "per-call-ledger");
        return 2;
    }
    unsigned long index = 0, count = 0;
    if (parse_number(argv[2], TABLE_SLOTS - 1, &index) != 0) {
        fprintf(stderr, "per-call-ledger: TABLE_INDEX must be 0..%d\n", TABLE_SLOTS - 1);
        return 2;
    }
    if (parse_number(argv[3], MAX_CALLS, &count) != 0 || count == 0) {
        fprintf(stderr, "per-call-ledger: COUNT must be 1..%d\n", MAX_CALLS);
        return 2;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "per-call-ledger: cannot open provider: %s\n", dlerror());
        return 2;
    }
    GetFunctionList get_list = (GetFunctionList)dlsym(handle, "C_GetFunctionList");
    void *raw = NULL;
    if (get_list == NULL || get_list(&raw) != 0 || raw == NULL) {
        fprintf(stderr, "per-call-ledger: C_GetFunctionList failed\n");
        dlclose(handle);
        return 2;
    }
    ProviderTable *table = raw;
    if (table->functions[index] == NULL) {
        fprintf(stderr, "per-call-ledger: table entry %lu is empty\n", index);
        dlclose(handle);
        return 2;
    }
    TableEntry entry = (TableEntry)table->functions[index];

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (argc == 6 && wait_for_go(argv[5]) != 0) {
        fprintf(stderr, "per-call-ledger: cannot wait for gate\n");
        dlclose(handle);
        return 2;
    }

    FILE *ledger = fopen(argv[4], "w");
    if (ledger == NULL) {
        fprintf(stderr, "per-call-ledger: cannot open ledger: %s\n", strerror(errno));
        dlclose(handle);
        return 2;
    }
    int pid = (int)getpid();
    int tid = (int)gettid();
    uint64_t ready = 0;
    if (clock_ns(&ready) != 0) {
        fprintf(stderr, "per-call-ledger: clock read failed\n");
        fclose(ledger);
        dlclose(handle);
        return 2;
    }
    int failed = 0;
    if (fprintf(ledger,
                "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                pid, tid, ready) < 0) {
        failed = 1;
    }
    unsigned long unhealthy = 0;
    for (unsigned long seq = 1; seq <= count && !failed; seq++) {
        uint64_t t0 = 0, t1 = 0;
        if (clock_ns(&t0) != 0) {
            failed = 1;
            break;
        }
        unsigned long rv = entry(NULL);
        if (clock_ns(&t1) != 0) {
            failed = 1;
            break;
        }
        if (rv != 0) {
            unhealthy++;
        }
        if (fprintf(ledger,
                    "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"table[%lu]\",\"rv\":%lu,"
                    "\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64 ",\"t1\":%" PRIu64 "}\n",
                    seq, index, rv, pid, tid, t0, t1) < 0) {
            failed = 1;
        }
    }
    uint64_t done = 0;
    if (!failed && clock_ns(&done) != 0) {
        failed = 1;
    }
    if (!failed && fprintf(ledger, "{\"kind\":\"ack\",\"issued\":%lu,\"t\":%" PRIu64 "}\n",
                           count, done) < 0) {
        failed = 1;
    }
    if (fclose(ledger) != 0) {
        failed = 1;
    }
    dlclose(handle);
    if (failed) {
        fprintf(stderr, "per-call-ledger: ledger emission failed\n");
        return 2;
    }
    return unhealthy == 0 ? 0 : 1;
}
