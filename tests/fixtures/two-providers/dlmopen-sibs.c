/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Same-process dlmopen sibling fixture: one provider file, two namespaces.
 *
 * One source, two builds (the s1-dlmopen-double-load.c pattern):
 *
 *   provider: gcc -std=c11 -O2 -Wall -Wextra -Werror -fPIC \
 *                 -DTWO_PROVIDERS_SIBLING_BUILD -shared -Wl,-z,defs \
 *                 -o sibs-provider.so dlmopen-sibs.c
 *   driver:   gcc -std=c11 -O2 -Wall -Wextra -Werror \
 *                 dlmopen-sibs.c -ldl -o dlmopen-sibs
 *
 *   driver PROVIDER MODE COUNT LEDGER [GO_FILE]
 *     MODE   ab (sibling A then B per round) or ba (B then A)
 *     COUNT  1..100000 rounds; the ledger carries 2*COUNT call rows
 *
 * The provider build is a stub-family object: C_GetFunctionList returns a
 * 104-entry table in which every slot shares the one-pointer-argument
 * shape. Slot 4 is the counted entry (returns CKR_OK). Slot 12 is the
 * colliding-handle entry: it writes the fixed handle value through its
 * one pointer argument, so both namespaces return the same value by
 * construction. TwoProvidersMarker is the family gate.
 *
 * The driver dlmopen()s PROVIDER in two new namespaces (siblings A and B),
 * refuses objects without the marker (calling unknown-signature entries
 * through the one-pointer-argument shape would be undefined behaviour),
 * prints "READY pid=<pid>" plus one NS line per sibling, then, when
 * GO_FILE is given, waits for that path to appear before emitting the
 * ledger; SIGTERM/SIGINT interrupts the wait. It samples the colliding
 * handle once per sibling (a mismatch is a construction failure), makes
 * COUNT real PKCS#11-shaped calls through each namespace in MODE order,
 * and writes one feed-labeled ledger: two ready rows, two handle rows,
 * 2*COUNT call rows with a global contiguous seq, one ack row. Exit 0
 * when every call returned CKR_OK, 1 when the ledger is complete but some
 * call did not, 2 on usage/setup/refusal failure.
 *
 * When GO-gated, the driver holds both mappings until SIGTERM/SIGINT
 * after the ledger is complete, so repeated observer rescans observe
 * identical state (idempotent rescan); no second burst runs. LP64 only.
 */
#ifdef TWO_PROVIDERS_SIBLING_BUILD

#include <stddef.h>

#define TABLE_SLOTS 104
#define COUNT_SLOT 4
#define HANDLE_SLOT 12
#define COLLIDING_HANDLE 0x0A11CEUL

typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[TABLE_SLOTS];
} SiblingTable;

static SiblingTable sibling_table;

int TwoProvidersMarker;

static unsigned long sibling_entry(void **out) {
    if (out != NULL) {
        *out = &sibling_table;
    }
    return 0;
}

static unsigned long sibling_handle_entry(void **out) {
    if (out == NULL) {
        return 7;
    }
    *(unsigned long *)out = COLLIDING_HANDLE;
    return 0;
}

__attribute__((constructor)) static void sibling_init(void) {
    sibling_table.major = 3;
    sibling_table.minor = 2;
    for (int i = 0; i < TABLE_SLOTS; i++) {
        sibling_table.functions[i] = (void *)sibling_entry;
    }
    sibling_table.functions[HANDLE_SLOT] = (void *)sibling_handle_entry;
}

unsigned long C_GetFunctionList(void **out) {
    if (out == NULL) {
        return 7;
    }
    *out = &sibling_table;
    return 0;
}

#else

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TABLE_SLOTS 104
#define COUNT_SLOT 4
#define HANDLE_SLOT 12
#define MAX_COUNT 100000

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

static int parse_count(const char *text, unsigned long *out) {
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
    if (errno != 0 || *end != '\0' || value == 0 || value > MAX_COUNT) {
        return -1;
    }
    *out = value;
    return 0;
}

struct sibling {
    const char *feed;
    void *handle;
    ProviderTable *table;
    TableEntry entry;
    TableEntry handle_entry;
};

static int open_sibling(const char *provider, const char *feed, struct sibling *sib) {
    sib->feed = feed;
    sib->handle = dlmopen(LM_ID_NEWLM, provider, RTLD_NOW | RTLD_LOCAL);
    if (sib->handle == NULL) {
        fprintf(stderr, "dlmopen-sibs: cannot dlmopen provider for %s: %s\n",
                feed, dlerror());
        return -1;
    }
    GetFunctionList get_list =
        (GetFunctionList)dlsym(sib->handle, "C_GetFunctionList");
    void *raw = NULL;
    if (get_list == NULL || get_list(&raw) != 0 || raw == NULL) {
        fprintf(stderr, "dlmopen-sibs: C_GetFunctionList failed for %s\n", feed);
        return -1;
    }
    if (dlsym(sib->handle, "TwoProvidersMarker") == NULL) {
        fprintf(stderr, "dlmopen-sibs: refuses non-stub provider (stub-only fixture)\n");
        return -1;
    }
    sib->table = raw;
    if (sib->table->functions[COUNT_SLOT] == NULL ||
        sib->table->functions[HANDLE_SLOT] == NULL) {
        fprintf(stderr, "dlmopen-sibs: provider table lacks slot %d or %d\n",
                COUNT_SLOT, HANDLE_SLOT);
        return -1;
    }
    sib->entry = (TableEntry)sib->table->functions[COUNT_SLOT];
    sib->handle_entry = (TableEntry)sib->table->functions[HANDLE_SLOT];
    return 0;
}

static void close_sibling(struct sibling *sib) {
    if (sib->handle != NULL) {
        dlclose(sib->handle);
        sib->handle = NULL;
    }
}

int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) {
        fprintf(stderr, "usage: %s PROVIDER MODE COUNT LEDGER [GO_FILE]\n",
                argc > 0 ? argv[0] : "dlmopen-sibs");
        return 2;
    }
    int a_first;
    if (strcmp(argv[2], "ab") == 0) {
        a_first = 1;
    } else if (strcmp(argv[2], "ba") == 0) {
        a_first = 0;
    } else {
        fprintf(stderr, "dlmopen-sibs: MODE must be ab or ba\n");
        return 2;
    }
    unsigned long count = 0;
    if (parse_count(argv[3], &count) != 0) {
        fprintf(stderr, "dlmopen-sibs: COUNT must be 1..%d\n", MAX_COUNT);
        return 2;
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    struct sibling sib_a = {0}, sib_b = {0};
    if (open_sibling(argv[1], "A", &sib_a) != 0) {
        close_sibling(&sib_a);
        return 2;
    }
    if (open_sibling(argv[1], "B", &sib_b) != 0) {
        close_sibling(&sib_a);
        close_sibling(&sib_b);
        return 2;
    }
    if (sib_a.handle == sib_b.handle || sib_a.table == sib_b.table) {
        fprintf(stderr, "dlmopen-sibs: the two namespaces did not isolate\n");
        close_sibling(&sib_a);
        close_sibling(&sib_b);
        return 2;
    }
    if (printf("READY pid=%d\n", (int)getpid()) < 0 ||
        printf("NS feed=A table=%p handle=%p\n",
               (void *)sib_a.table, sib_a.handle) < 0 ||
        printf("NS feed=B table=%p handle=%p\n",
               (void *)sib_b.table, sib_b.handle) < 0 ||
        fflush(stdout)) {
        close_sibling(&sib_a);
        close_sibling(&sib_b);
        return 2;
    }
    if (argc == 6 && wait_for_go(argv[5]) != 0) {
        if (stop) {
            fprintf(stderr, "dlmopen-sibs: interrupted while waiting for gate\n");
        } else {
            fprintf(stderr, "dlmopen-sibs: cannot wait for gate\n");
        }
        close_sibling(&sib_a);
        close_sibling(&sib_b);
        return 2;
    }
    FILE *ledger = fopen(argv[4], "w");
    if (ledger == NULL) {
        fprintf(stderr, "dlmopen-sibs: cannot open ledger: %s\n", strerror(errno));
        close_sibling(&sib_a);
        close_sibling(&sib_b);
        return 2;
    }
    int failed = 0;
    int pid = (int)getpid();
    int tid = (int)gettid();
    uint64_t ready_a = 0, ready_b = 0;
    uint64_t handle_at_a = 0, handle_at_b = 0;
    unsigned long handle_a = 0, handle_b = 0;
    if (clock_ns(&ready_a) != 0 || clock_ns(&ready_b) != 0) {
        failed = 1;
    }
    if (!failed && clock_ns(&handle_at_a) == 0) {
        if (sib_a.handle_entry((void **)&handle_a) != 0) {
            failed = 1;
        }
    } else {
        failed = 1;
    }
    if (!failed && clock_ns(&handle_at_b) == 0) {
        if (sib_b.handle_entry((void **)&handle_b) != 0) {
            failed = 1;
        }
    } else {
        failed = 1;
    }
    if (!failed && handle_a != handle_b) {
        fprintf(stderr, "dlmopen-sibs: sibling handles do not collide\n");
        failed = 1;
    }
    if (!failed && (fprintf(ledger,
                            "{\"kind\":\"ready\",\"feed\":\"A\",\"pid\":%d,\"tid\":%d,"
                            "\"t\":%" PRIu64 ",\"clock\":\"CLOCK_MONOTONIC\","
                            "\"unit\":\"ns\"}\n",
                            pid, tid, ready_a) < 0 ||
                    fprintf(ledger,
                            "{\"kind\":\"ready\",\"feed\":\"B\",\"pid\":%d,\"tid\":%d,"
                            "\"t\":%" PRIu64 ",\"clock\":\"CLOCK_MONOTONIC\","
                            "\"unit\":\"ns\"}\n",
                            pid, tid, ready_b) < 0 ||
                    fprintf(ledger,
                            "{\"kind\":\"handle\",\"feed\":\"A\",\"slot\":%d,"
                            "\"value\":%lu,\"t\":%" PRIu64 "}\n",
                            HANDLE_SLOT, handle_a, handle_at_a) < 0 ||
                    fprintf(ledger,
                            "{\"kind\":\"handle\",\"feed\":\"B\",\"slot\":%d,"
                            "\"value\":%lu,\"t\":%" PRIu64 "}\n",
                            HANDLE_SLOT, handle_b, handle_at_b) < 0)) {
        failed = 1;
    }
    unsigned long unhealthy = 0;
    unsigned long seq = 0;
    struct sibling *first = a_first ? &sib_a : &sib_b;
    struct sibling *second = a_first ? &sib_b : &sib_a;
    for (unsigned long round = 0; round < count && !failed; round++) {
        struct sibling *order[2] = {first, second};
        for (int k = 0; k < 2 && !failed; k++) {
            uint64_t t0 = 0, t1 = 0;
            if (clock_ns(&t0) != 0) {
                failed = 1;
                break;
            }
            unsigned long rv = order[k]->entry(NULL);
            if (clock_ns(&t1) != 0) {
                failed = 1;
                break;
            }
            if (rv != 0) {
                unhealthy++;
            }
            seq++;
            if (fprintf(ledger,
                        "{\"kind\":\"call\",\"seq\":%lu,\"feed\":\"%s\","
                        "\"fn\":\"table[%d]\",\"rv\":%lu,\"pid\":%d,\"tid\":%d,"
                        "\"t0\":%" PRIu64 ",\"t1\":%" PRIu64 "}\n",
                        seq, order[k]->feed, COUNT_SLOT, rv, pid, tid,
                        t0, t1) < 0) {
                failed = 1;
            }
        }
    }
    uint64_t done = 0;
    if (!failed && clock_ns(&done) != 0) {
        failed = 1;
    }
    if (!failed && fprintf(ledger, "{\"kind\":\"ack\",\"issued\":%lu,\"t\":%" PRIu64 "}\n",
                           seq, done) < 0) {
        failed = 1;
    }
    if (fclose(ledger) != 0) {
        failed = 1;
    }
    int gated = argc == 6;
    if (gated && !failed) {
        /* Poll the stop flag: pause() would lose a signal that arrives
         * between the flag test and the sleep. */
        while (!stop) {
            usleep(10000);
        }
    }
    close_sibling(&sib_a);
    close_sibling(&sib_b);
    if (failed) {
        fprintf(stderr, "dlmopen-sibs: ledger emission failed\n");
        return 2;
    }
    return unhealthy == 0 ? 0 : 1;
}

#endif
