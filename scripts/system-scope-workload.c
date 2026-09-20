/* SPDX-License-Identifier: GPL-3.0-or-later */
/* system-scope-workload.c — deterministic counting workload for the
 * system-scope measurement harness (scripts/system-scope-measure.sh).
 *
 * Two phases, gated by files so the observer can attach between setup and
 * the measured call burst. EARLY=1 maps the provider (dlopen + session)
 * before READY so a --system scan corroborates it; EARLY=0 reports READY
 * first and does everything after GO (bench-style: per-PID attach on this
 * HEAD fails when the provider is already mapped — see the design note).
 * The generated-call truth is identical either way.
 *
 * Prints `TRUTH_PREGO {...}` at READY (calls already made, outside the
 * capture window), one `BURST go_ns=... end_ns=...` line bounding the
 * post-go window on CLOCK_MONOTONIC (the harness derives the ring input
 * rate from it), and one `TRUTH {...}` JSON line at the end with the exact
 * post-go generated-call counts (the harness's workload oracle), and exits
 * 0. Same dlopen/table convention as scripts/fixtures/hammer.c.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;

#define CKF_SERIAL_SESSION 4UL

enum { I_Initialize = 0, I_Finalize = 1, I_GetSlotList = 4,
       I_OpenSession = 12, I_CloseSession = 13, I_GenerateRandom = 64 };

typedef CK_RV (*fn_gen)(void *);
typedef CK_RV (*fn_slots)(unsigned char, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_rand)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);

static void **fns;

#define CHECK(what, expr) do { CK_RV _rv = (expr); \
    if (_rv != 0) { fprintf(stderr, "workload: %s failed: 0x%lx\n", what, _rv); return 1; } } while (0)

static int wait_for_file(const char *path, int timeout_s)
{
    time_t deadline = time(NULL) + timeout_s;
    while (access(path, F_OK) != 0) {
        if (time(NULL) > deadline) {
            fprintf(stderr, "workload: timed out waiting for %s\n", path);
            return 1;
        }
        usleep(5000);
    }
    return 0;
}

static int phase_setup(const char *module, CK_SESSION_HANDLE *sess)
{
    void *h = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "workload: dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "workload: no function list\n"); return 1; }
    fns = (void **)((char *)list + 8);

    CHECK("C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));

    CK_SLOT_ID slots[64]; CK_ULONG nslots = 64;
    CHECK("C_GetSlotList", ((fn_slots)fns[I_GetSlotList])(1, slots, &nslots));
    if (nslots < 1) { fprintf(stderr, "workload: no token present\n"); return 1; }

    CHECK("C_OpenSession",
          ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION, NULL, NULL, sess));
    return 0;
}

static unsigned long long now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ULL + (unsigned long long)ts.tv_nsec;
}

static int signal_ready(const char *ready_file)
{
    FILE *rf = fopen(ready_file, "w");
    if (!rf) { perror("workload: ready file"); return 1; }
    fprintf(rf, "pid=%d\n", (int)getpid());
    fclose(rf);
    printf("workload: READY pid=%d\n", (int)getpid());
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 7) {
        fprintf(stderr, "usage: %s /path/to/module.so <n_calls> <pace_us> <early:0|1> <ready_file> <go_file>\n",
                argv[0]);
        return 2;
    }
    long n = atol(argv[2]);
    long pace_us = atol(argv[3]);
    int early = atoi(argv[4]);
    const char *ready_file = argv[5];
    const char *go_file = argv[6];
    if (n < 0 || pace_us < 0 || (early != 0 && early != 1)) {
        fprintf(stderr, "workload: bad arguments\n");
        return 2;
    }

    CK_SESSION_HANDLE sess = 0;
    unsigned long long go_ns = 0;
    if (early) {
        if (phase_setup(argv[1], &sess) != 0)
            return 1;
        /* Pre-go calls are outside the capture window by construction. */
        printf("TRUTH_PREGO {\"C_GetFunctionList\": 1, \"C_Initialize\": 1, "
               "\"C_GetSlotList\": 1, \"C_OpenSession\": 1}\n");
        fflush(stdout);
        if (signal_ready(ready_file) != 0)
            return 1;
        /* Longer than the harness's own attach-gate timeout (600 s): the
         * harness kills this process on gate failure, so the wait must
         * never give up first and waste a slow-but-moving attach. */
        if (wait_for_file(go_file, 660) != 0)
            return 1;
        go_ns = now_ns();
    } else {
        printf("TRUTH_PREGO {}\n");
        fflush(stdout);
        if (signal_ready(ready_file) != 0)
            return 1;
        if (wait_for_file(go_file, 660) != 0)
            return 1;
        go_ns = now_ns();
        if (phase_setup(argv[1], &sess) != 0)
            return 1;
    }

    unsigned char rnd[4];
    for (long i = 0; i < n; i++) {
        CHECK("C_GenerateRandom", ((fn_rand)fns[I_GenerateRandom])(sess, rnd, sizeof rnd));
        if (pace_us > 0)
            usleep((useconds_t)pace_us);
    }

    CHECK("C_CloseSession", ((fn_close)fns[I_CloseSession])(sess));
    CHECK("C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));
    /* BURST bounds the TRUTH window on CLOCK_MONOTONIC: go observed to
     * last post-go call. The harness derives the ring input rate from it. */
    printf("BURST go_ns=%llu end_ns=%llu\n", go_ns, now_ns());
    fflush(stdout);

    /* TRUTH covers post-go calls only (the capture window). With early=0
     * the setup calls happen post-go and are included; with early=1 they
     * ran pre-go and live in TRUTH_PREGO instead. C_GetFunctionList is
     * called once via dlsym (loader/export probes observe it); every other
     * call goes through the function list. */
    if (early)
        printf("TRUTH {\"C_GenerateRandom\": %ld, \"C_CloseSession\": 1, "
               "\"C_Finalize\": 1}\n", n);
    else
        printf("TRUTH {\"C_GetFunctionList\": 1, \"C_Initialize\": 1, \"C_GetSlotList\": 1, "
               "\"C_OpenSession\": 1, \"C_GenerateRandom\": %ld, \"C_CloseSession\": 1, "
               "\"C_Finalize\": 1}\n", n);
    printf("workload: OK %ld C_GenerateRandom calls\n", n);
    return 0;
}
