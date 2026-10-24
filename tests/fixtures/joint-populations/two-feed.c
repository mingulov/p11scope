/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Two-feed interleaved ledger emitter (E17 pattern).
 *
 * Usage: two-feed PROVIDER_A PROVIDER_B MODE OPS LEDGER_A LEDGER_B [GO_FILE]
 *
 * MODE is one of:
 *   interleave  feed A signs (init/update/update/terminal) while feed B runs
 *               message_sign contexts (init/update/terminal), calls
 *               interleaved A,B,A,B...; scopes session:1/session:2.
 *   wrap        feed A drives the wrapping-key role and feed B the
 *               wrapped-object role (init/terminal each); scopes
 *               provider:PA/provider:PB.
 *   loss        feed A signs (init/terminal) while feed B runs the same
 *               script as an S1Only sibling (init/terminal); its locally
 *               completed calls are metered as lost-to-Joint, never joined;
 *               scopes image:IA/image:IB.
 *
 * Both feeds observe the same numeric handle value (101) in different
 * scopes, so a snapshot that joins them is observable as a violation.
 * Every declared workload identity (feed, path, instance, object,
 * category, role, established metadata, scope, handle) is recorded in
 * the per-ledger feed row; the call rows carry only what happened
 * (entry index, return value, CLOCK_MONOTONIC t0/t1) plus the script
 * position (feed, op, phase).
 *
 * Stub-only fixture: each PROVIDER must come from the stub family (the
 * P11ScopeSlot68 marker export must be present); anything else is
 * refused, because calling unknown-signature entries through the
 * one-pointer-argument TableEntry would be undefined behaviour. With
 * tests/fixtures/live-discovery-provider.c the marker is exported only
 * with P11SCOPE_EXPORT_TABLES=1, so the hidden-tables (=0) build is
 * refused as non-stub. Refusals happen before READY and before either
 * ledger is created. Prints "READY pid=<pid>" after both tables are
 * validated, then, when GO_FILE is given, waits for that path to appear
 * before emitting the ready rows; SIGTERM/SIGINT interrupts the wait.
 * Exit 0 when every call returned CKR_OK, 1 when both ledgers are
 * complete but some call did not, 2 on usage/setup/refusal failure.
 * Builds LP64 and ILP32 (no pointer-size assumption).
 */
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
#define MAX_OPS 10000
#define SHARED_HANDLE 101ul

/* Fixture-local slot choices; the fn label records the index used. */
#define IDX_INIT 40
#define IDX_UPDATE 41
#define IDX_TERMINAL 42
#define IDX_WRAP_A 43
#define IDX_WRAP_B 44

/* Mirrors P11ScopeTable in tests/fixtures/live-discovery-provider.c:
 * CK_VERSION (2 bytes), 6 reserved bytes, 104 function pointers. */
typedef struct {
    unsigned char major, minor;
    unsigned char reserved[6];
    void *functions[TABLE_SLOTS];
} ProviderTable;

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

typedef struct {
    const char *phase;
    unsigned long index;
} Step;

static const Step STEPS_SIGN4[] = {
    {"init", IDX_INIT}, {"update", IDX_UPDATE}, {"update", IDX_UPDATE}, {"terminal", IDX_TERMINAL},
};
static const Step STEPS_MSG3[] = {
    {"init", IDX_INIT}, {"update", IDX_UPDATE}, {"terminal", IDX_TERMINAL},
};
static const Step STEPS_WRAP_A[] = {
    {"init", IDX_WRAP_A}, {"terminal", IDX_WRAP_A},
};
static const Step STEPS_WRAP_B[] = {
    {"init", IDX_WRAP_B}, {"terminal", IDX_WRAP_B},
};
static const Step STEPS_SIGN2[] = {
    {"init", IDX_INIT}, {"terminal", IDX_TERMINAL},
};

typedef struct {
    const char *feed;
    const char *path;
    const char *instance;
    unsigned long object;
    const char *category;
    const char *role;
    const char *metadata;
    const char *scope;
    const Step *steps;
    unsigned long nsteps;
} FeedScript;

typedef struct {
    const char *mode;
    FeedScript feeds[2];
} ModeScript;

static const ModeScript MODES[] = {
    {"interleave",
     {{"A", "joint", "i3", 11, "sign", "key", "rsa_2048", "session:1", STEPS_SIGN4, 4},
      {"B", "joint", "i4", 12, "message_sign", "key", "rsa_2048", "session:2", STEPS_MSG3, 3}}},
    {"wrap",
     {{"A", "joint", "i3", 11, "wrap", "wrapping_key", "rsa_2048", "provider:PA", STEPS_WRAP_A, 2},
      {"B", "joint", "i3", 12, "wrap", "wrapped_object", "rsa_2048", "provider:PB", STEPS_WRAP_B,
       2}}},
    {"loss",
     {{"A", "joint", "i3", 11, "sign", "key", "rsa_2048", "image:IA", STEPS_SIGN2, 2},
      {"B", "s1only", "i4", 12, "sign", "key", "rsa_2048", "image:IB", STEPS_SIGN2, 2}}},
};

static const ModeScript *find_mode(const char *name) {
    for (size_t i = 0; i < sizeof(MODES) / sizeof(MODES[0]); i++) {
        if (strcmp(MODES[i].mode, name) == 0) {
            return &MODES[i];
        }
    }
    return NULL;
}

static int open_validated(const char *path, void **handle, TableEntry *entries,
                          const unsigned long *wanted, size_t nwanted) {
    void *dl = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (dl == NULL) {
        fprintf(stderr, "two-feed: cannot open provider: %s\n", dlerror());
        return -1;
    }
    GetFunctionList get_list = (GetFunctionList)dlsym(dl, "C_GetFunctionList");
    void *raw = NULL;
    if (get_list == NULL || get_list(&raw) != 0 || raw == NULL) {
        fprintf(stderr, "two-feed: C_GetFunctionList failed for %s\n", path);
        dlclose(dl);
        return -1;
    }
    ProviderTable *table = raw;
    for (size_t i = 0; i < nwanted; i++) {
        if (table->functions[wanted[i]] == NULL) {
            fprintf(stderr, "two-feed: table entry %lu of %s is empty\n", wanted[i], path);
            dlclose(dl);
            return -1;
        }
        entries[i] = (TableEntry)table->functions[wanted[i]];
    }
    if (dlsym(dl, "P11ScopeSlot68") == NULL) {
        fprintf(stderr, "two-feed: refuses non-stub provider %s (stub-only fixture)\n", path);
        dlclose(dl);
        return -1;
    }
    *handle = dl;
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 7 && argc != 8) {
        fprintf(stderr, "usage: %s PROVIDER_A PROVIDER_B MODE OPS LEDGER_A LEDGER_B [GO_FILE]\n",
                argc > 0 ? argv[0] : "two-feed");
        return 2;
    }
    const ModeScript *mode = find_mode(argv[3]);
    if (mode == NULL) {
        fprintf(stderr, "two-feed: MODE must be interleave, wrap or loss\n");
        return 2;
    }
    unsigned long ops = 0;
    if (parse_number(argv[4], MAX_OPS, &ops) != 0 || ops == 0) {
        fprintf(stderr, "two-feed: OPS must be 1..%d\n", MAX_OPS);
        return 2;
    }
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    void *handles[2] = {NULL, NULL};
    TableEntry entries[2][4];
    for (int f = 0; f < 2; f++) {
        const FeedScript *feed = &mode->feeds[f];
        unsigned long wanted[4];
        for (unsigned long s = 0; s < feed->nsteps; s++) {
            wanted[s] = feed->steps[s].index;
        }
        if (open_validated(argv[1 + f], &handles[f], entries[f], wanted, feed->nsteps) != 0) {
            for (int g = 0; g < f; g++) {
                dlclose(handles[g]);
            }
            return 2;
        }
    }

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (argc == 8 && wait_for_go(argv[7]) != 0) {
        if (stop) {
            fprintf(stderr, "two-feed: interrupted while waiting for gate\n");
        } else {
            fprintf(stderr, "two-feed: cannot wait for gate\n");
        }
        dlclose(handles[0]);
        dlclose(handles[1]);
        return 2;
    }

    FILE *ledgers[2] = {NULL, NULL};
    for (int f = 0; f < 2; f++) {
        ledgers[f] = fopen(argv[5 + f], "w");
        if (ledgers[f] == NULL) {
            fprintf(stderr, "two-feed: cannot open ledger: %s\n", strerror(errno));
            for (int g = 0; g < f; g++) {
                fclose(ledgers[g]);
            }
            dlclose(handles[0]);
            dlclose(handles[1]);
            return 2;
        }
    }

    int pid = (int)getpid();
    int tid = (int)gettid();
    uint64_t ready = 0;
    if (clock_ns(&ready) != 0) {
        fprintf(stderr, "two-feed: clock read failed\n");
        fclose(ledgers[0]);
        fclose(ledgers[1]);
        dlclose(handles[0]);
        dlclose(handles[1]);
        return 2;
    }
    int failed = 0;
    for (int f = 0; f < 2 && !failed; f++) {
        const FeedScript *feed = &mode->feeds[f];
        if (fprintf(ledgers[f],
                    "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                    ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                    pid, tid, ready) < 0) {
            failed = 1;
            break;
        }
        if (fprintf(ledgers[f],
                    "{\"kind\":\"feed\",\"feed\":\"%s\",\"path\":\"%s\",\"instance\":\"%s\","
                    "\"object\":%lu,\"category\":\"%s\",\"role\":\"%s\",\"metadata\":\"%s\","
                    "\"scope\":\"%s\",\"handle\":%lu}\n",
                    feed->feed, feed->path, feed->instance, feed->object, feed->category,
                    feed->role, feed->metadata, feed->scope, SHARED_HANDLE) < 0) {
            failed = 1;
        }
    }
    unsigned long seq[2] = {0, 0};
    unsigned long unhealthy = 0;
    unsigned long maxsteps = mode->feeds[0].nsteps > mode->feeds[1].nsteps
        ? mode->feeds[0].nsteps
        : mode->feeds[1].nsteps;
    for (unsigned long op = 1; op <= ops && !failed; op++) {
        for (unsigned long s = 0; s < maxsteps && !failed; s++) {
            for (int f = 0; f < 2 && !failed; f++) {
                const FeedScript *feed = &mode->feeds[f];
                if (s >= feed->nsteps) {
                    continue;
                }
                uint64_t t0 = 0, t1 = 0;
                if (clock_ns(&t0) != 0) {
                    failed = 1;
                    break;
                }
                unsigned long rv = entries[f][s](NULL);
                if (clock_ns(&t1) != 0) {
                    failed = 1;
                    break;
                }
                if (rv != 0) {
                    unhealthy++;
                }
                seq[f]++;
                if (fprintf(ledgers[f],
                            "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"table[%lu]\",\"rv\":%lu,"
                            "\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64 ",\"t1\":%" PRIu64
                            ",\"feed\":\"%s\",\"op\":%lu,\"phase\":\"%s\"}\n",
                            seq[f], feed->steps[s].index, rv, pid, tid, t0, t1, feed->feed, op,
                            feed->steps[s].phase) < 0) {
                    failed = 1;
                }
            }
        }
    }
    uint64_t done = 0;
    if (!failed && clock_ns(&done) != 0) {
        failed = 1;
    }
    for (int f = 0; f < 2 && !failed; f++) {
        if (fprintf(ledgers[f], "{\"kind\":\"ack\",\"issued\":%lu,\"t\":%" PRIu64 "}\n", seq[f],
                    done) < 0) {
            failed = 1;
        }
    }
    for (int f = 0; f < 2; f++) {
        if (fclose(ledgers[f]) != 0) {
            failed = 1;
        }
        dlclose(handles[f]);
    }
    if (failed) {
        fprintf(stderr, "two-feed: ledger emission failed\n");
        return 2;
    }
    return unhealthy == 0 ? 0 : 1;
}
