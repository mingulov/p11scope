/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* mt_mixed: deterministic multi-threaded mixed-function SoftHSM2 workload.
 *
 * usage: mt_mixed MODULE THREADS ITERS GATE MODE ERRORS
 *   MODE: sessions (per-thread session) | shared (one session, mutex per
 *         iteration) | churn (two thread generations of ITERS/2 and
 *         ERRORS/2 each; both must be even)
 *   MT_MIXED_HOLD=1: after LEDGER, hold for SIGTERM/SIGINT instead of
 *         exiting (inventory capture windows; like cgroup-fork).
 *   GATE: path to wait for, or "-" for no wait (self-tests only)
 *   ERRORS: deliberate bogus-handle C_GenerateRandom calls per thread
 *
 * Every thread runs exactly ITERS x {C_GenerateRandom, C_DigestInit,
 * C_DigestUpdate, C_DigestFinal, C_FindObjectsInit, C_FindObjects,
 * C_FindObjectsFinal, C_GetSessionInfo} on a plain session (no login),
 * plus ERRORS failing calls. Totals are exact by construction: every
 * function runs THREADS x ITERS times. The LEDGER (schema
 * p11scope/public-cli-ledger/v2) carries per-function attempts/successful
 * plus the exact return map, so the oracle asserts calls, errors and
 * per-CKR counts exactly.
 *
 * Gate discipline (as mt.c): only C_Initialize/C_GetSlotList run before
 * READY; every session and every counted call happens after the gate
 * opens, i.e. after the observer attaches. Any unexpected return (a
 * should-succeed call failing, an error probe succeeding, an
 * inconsistent error code) exits nonzero with no LEDGER, so a sample
 * that did not run exactly as scripted can never count. C_Finalize runs
 * before LEDGER so the SCAFFOLD line (session open/close/finalize
 * attempts, entry-side exact) completes the record inventory edge
 * totals need.
 *
 * Reuse: mt_fork.c compiles this file with MT_MIXED_AS_LIB to run the
 * same workload in forked children; main() is skipped then.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE, CK_FLAGS;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;
typedef struct { CK_SLOT_ID slotID; CK_ULONG state; CK_FLAGS flags; CK_ULONG ulDeviceError; } CK_SESSION_INFO;

#define CKF_SERIAL_SESSION 4UL
#define CKF_RW_SESSION 2UL
#define CKR_OK 0UL
#define BOGUS_SESSION ((CK_SESSION_HANDLE)0xDEADBEEFUL)

enum { FNS = 8 };
/* Index into the v2.40 CK_FUNCTION_LIST for each workload function. */
static const int MT_INDEX[FNS] = {64, 37, 39, 41, 26, 27, 28, 15};
static const char *MT_NAME[FNS] = {
    "C_GenerateRandom", "C_DigestInit", "C_DigestUpdate", "C_DigestFinal",
    "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetSessionInfo"};

struct mt_counts {
    unsigned long attempts[FNS];
    unsigned long ok[FNS];
    unsigned long err_rv;
    unsigned long err_n;
    /* Session scaffolding, entry-side exact (retries included): the
     * inventory edge totals count every through-table call, so the
     * SCAFFOLD line reports these alongside the LEDGER. */
    unsigned long opens_attempted;
    unsigned long opens_ok;
    unsigned long closes;
    unsigned long finalizes;
};

struct mt_ctx {
    void **fns;
    CK_SLOT_ID slot;
    int threads;
    int iters;
    int errors;
    pthread_mutex_t lock;
    CK_SESSION_HANDLE shared;
};

#define F(fns, i, t) ((t)(fns)[i])

static void mt_die(const char *what, CK_RV rv)
{
    fprintf(stderr, "mt_mixed: %s: rv=0x%lx\n", what, rv);
    exit(1);
}

static void mt_target(const char *name, void *address)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[4096], perms[5];
    unsigned long lo, hi, off, ino;
    unsigned int major, minor;
    uintptr_t ptr;
    if (!maps)
        mt_die("maps", 0);
    ptr = (uintptr_t)address;
    while (fgets(line, sizeof line, maps)) {
        if (sscanf(line, "%lx-%lx %4s %lx %x:%x %lu", &lo, &hi, perms, &off, &major, &minor, &ino) == 7 &&
            ptr >= lo && ptr < hi && perms[2] == 'x' && ino) {
            printf("TARGET {\"name\":\"%s\",\"dev\":[%u,%u],\"ino\":%lu,\"file_offset\":%lu}\n",
                   name, major, minor, ino, (unsigned long)(ptr - lo) + off);
            fclose(maps);
            return;
        }
    }
    fclose(maps);
    mt_die("target not mapped", 0);
}

/* One mixed iteration on an already-open session. Records every return;
 * any unexpected return aborts the whole sample immediately. */
static void mt_iteration(struct mt_ctx *ctx, CK_SESSION_HANDLE session, struct mt_counts *out)
{
    void **fns = ctx->fns;
    unsigned char buf[64];
    CK_MECHANISM mech;
    CK_ULONG len;
    CK_OBJECT_HANDLE objs[10];
    CK_ULONG nobj;
    CK_SESSION_INFO info;
    CK_RV rv;

    rv = F(fns, 64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(session, buf, 16);
    out->attempts[0]++;
    if (rv != CKR_OK)
        mt_die("C_GenerateRandom", rv);
    out->ok[0]++;

    mech.mechanism = 0x250UL;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    rv = F(fns, 37, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *))(session, &mech);
    out->attempts[1]++;
    if (rv != CKR_OK)
        mt_die("C_DigestInit", rv);
    out->ok[1]++;

    memcpy(buf, "hello-mt", 8);
    rv = F(fns, 39, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(session, buf, 8);
    out->attempts[2]++;
    if (rv != CKR_OK)
        mt_die("C_DigestUpdate", rv);
    out->ok[2]++;

    len = sizeof buf;
    rv = F(fns, 41, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG *))(session, buf, &len);
    out->attempts[3]++;
    if (rv != CKR_OK)
        mt_die("C_DigestFinal", rv);
    out->ok[3]++;

    rv = F(fns, 26, CK_RV (*)(CK_SESSION_HANDLE, void *, CK_ULONG))(session, NULL, 0);
    out->attempts[4]++;
    if (rv != CKR_OK)
        mt_die("C_FindObjectsInit", rv);
    out->ok[4]++;

    nobj = 0;
    rv = F(fns, 27, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *))(
        session, objs, 10, &nobj);
    out->attempts[5]++;
    if (rv != CKR_OK)
        mt_die("C_FindObjects", rv);
    out->ok[5]++;

    rv = F(fns, 28, CK_RV (*)(CK_SESSION_HANDLE))(session);
    out->attempts[6]++;
    if (rv != CKR_OK)
        mt_die("C_FindObjectsFinal", rv);
    out->ok[6]++;

    rv = F(fns, 15, CK_RV (*)(CK_SESSION_HANDLE, CK_SESSION_INFO *))(session, &info);
    out->attempts[7]++;
    if (rv != CKR_OK)
        mt_die("C_GetSessionInfo", rv);
    out->ok[7]++;
}

static void mt_error_probes(struct mt_ctx *ctx, struct mt_counts *out, int errors)
{
    unsigned char buf[16];
    for (int i = 0; i < errors; i++) {
        CK_RV rv = F(ctx->fns, 64, CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG))(
            BOGUS_SESSION, buf, sizeof buf);
        out->attempts[0]++;
        if (rv == CKR_OK)
            mt_die("bogus-handle probe unexpectedly succeeded", rv);
        if (out->err_n > 0 && out->err_rv != rv)
            mt_die("bogus-handle probe returned an inconsistent code", rv);
        out->err_rv = rv;
        out->err_n++;
    }
}

static CK_SESSION_HANDLE mt_open(struct mt_ctx *ctx, struct mt_counts *out)
{
    CK_SESSION_HANDLE session = 0;
    /* Bounded retry: concurrent opens from many threads/processes on one
     * token are occasionally refused. Every attempt is entry-side counted
     * by observers, so every attempt is recorded, never just successes. */
    for (int i = 0; i < 200; i++) {
        CK_RV rv = F(ctx->fns, 12,
                     CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(
            ctx->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
        out->opens_attempted++;
        if (rv == CKR_OK) {
            out->opens_ok++;
            return session;
        }
        usleep(10000);
    }
    mt_die("C_OpenSession", 0);
    return 0;
}

static void mt_close(struct mt_ctx *ctx, CK_SESSION_HANDLE session, struct mt_counts *out)
{
    CK_RV rv = F(ctx->fns, 13, CK_RV (*)(CK_SESSION_HANDLE))(session);
    out->closes++;
    if (rv != CKR_OK)
        mt_die("C_CloseSession", rv);
}

struct mt_worker_arg {
    struct mt_ctx *ctx;
    struct mt_counts *out;
    int iters;
    int errors;
    int use_shared;
};

static void *mt_worker(void *arg)
{
    struct mt_worker_arg *wa = arg;
    struct mt_ctx *ctx = wa->ctx;
    CK_SESSION_HANDLE session = 0;
    int own = !wa->use_shared;
    if (own)
        session = mt_open(ctx, wa->out);
    else
        session = ctx->shared;
    for (int i = 0; i < wa->iters; i++) {
        if (wa->use_shared)
            pthread_mutex_lock(&ctx->lock);
        mt_iteration(ctx, session, wa->out);
        if (wa->use_shared)
            pthread_mutex_unlock(&ctx->lock);
    }
    /* Error probes carry a bogus handle, so they never touch session
     * state and run outside the shared-session lock for maximal
     * entry/return interleave. */
    mt_error_probes(ctx, wa->out, wa->errors);
    if (own)
        mt_close(ctx, session, wa->out);
    return NULL;
}

static void mt_add(struct mt_counts *sum, const struct mt_counts *add)
{
    for (int i = 0; i < FNS; i++) {
        sum->attempts[i] += add->attempts[i];
        sum->ok[i] += add->ok[i];
    }
    sum->opens_attempted += add->opens_attempted;
    sum->opens_ok += add->opens_ok;
    sum->closes += add->closes;
    sum->finalizes += add->finalizes;
    if (add->err_n > 0) {
        if (sum->err_n > 0 && sum->err_rv != add->err_rv)
            mt_die("inconsistent error code across threads", add->err_rv);
        sum->err_rv = add->err_rv;
        sum->err_n += add->err_n;
    }
}

static void mt_run_threads(struct mt_ctx *ctx, int iters, int errors, int use_shared,
                           struct mt_counts *sum)
{
    pthread_t *threads = calloc((size_t)ctx->threads, sizeof *threads);
    struct mt_worker_arg *args = calloc((size_t)ctx->threads, sizeof *args);
    struct mt_counts *outs = calloc((size_t)ctx->threads, sizeof *outs);
    if (!threads || !args || !outs)
        mt_die("alloc", 0);
    for (int i = 0; i < ctx->threads; i++) {
        args[i].ctx = ctx;
        args[i].out = &outs[i];
        args[i].iters = iters;
        args[i].errors = errors;
        args[i].use_shared = use_shared;
        if (pthread_create(&threads[i], NULL, mt_worker, &args[i]) != 0)
            mt_die("pthread_create", 0);
    }
    for (int i = 0; i < ctx->threads; i++) {
        if (pthread_join(threads[i], NULL) != 0)
            mt_die("pthread_join", 0);
        mt_add(sum, &outs[i]);
    }
    free(threads);
    free(args);
    free(outs);
}

/* mode: 0=sessions, 1=shared, 2=churn. Fills sum; dies loud on any defect. */
static void mt_run(struct mt_ctx *ctx, int mode, struct mt_counts *sum)
{
    memset(sum, 0, sizeof *sum);
    if (mode == 1) {
        if (pthread_mutex_init(&ctx->lock, NULL) != 0)
            mt_die("mutex_init", 0);
        ctx->shared = mt_open(ctx, sum);
        mt_run_threads(ctx, ctx->iters, ctx->errors, 1, sum);
        mt_close(ctx, ctx->shared, sum);
    } else if (mode == 2) {
        if (ctx->iters % 2 != 0 || ctx->errors % 2 != 0)
            mt_die("churn needs even ITERS and ERRORS", 0);
        /* Two thread generations: every thread is created and ends
         * during capture while ~THREADS stay in flight per wave. */
        mt_run_threads(ctx, ctx->iters / 2, ctx->errors / 2, 0, sum);
        mt_run_threads(ctx, ctx->iters / 2, ctx->errors / 2, 0, sum);
    } else {
        mt_run_threads(ctx, ctx->iters, ctx->errors, 0, sum);
    }
}

static void mt_verify(const struct mt_counts *sum, unsigned long threads, unsigned long iters,
                      unsigned long errors_per_thread, unsigned long opens_ok_want,
                      unsigned long finalizes_want)
{
    for (int i = 0; i < FNS; i++) {
        unsigned long want = threads * iters + (i == 0 ? threads * errors_per_thread : 0);
        if (sum->attempts[i] != want) {
            fprintf(stderr, "mt_mixed: %s attempts=%lu want=%lu\n", MT_NAME[i], sum->attempts[i],
                    want);
            exit(1);
        }
        if (sum->ok[i] + (i == 0 ? sum->err_n : 0) != sum->attempts[i]) {
            fprintf(stderr, "mt_mixed: %s ok/err inconsistent\n", MT_NAME[i]);
            exit(1);
        }
    }
    if (sum->err_n != threads * errors_per_thread) {
        fprintf(stderr, "mt_mixed: errors=%lu want=%lu\n", sum->err_n, threads * errors_per_thread);
        exit(1);
    }
    if (sum->opens_ok != opens_ok_want || sum->closes != opens_ok_want ||
        sum->opens_attempted < opens_ok_want || sum->finalizes != finalizes_want) {
        fprintf(stderr,
                "mt_mixed: scaffolding inconsistent: attempted=%lu ok=%lu closes=%lu finalizes=%lu\n",
                sum->opens_attempted, sum->opens_ok, sum->closes, sum->finalizes);
        exit(1);
    }
}

static void mt_emit_targets(void **fns)
{
    for (int i = 0; i < FNS; i++)
        mt_target(MT_NAME[i], fns[MT_INDEX[i]]);
}

static void mt_emit_ledger(const struct mt_counts *sum)
{
    printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v2\",\"pid\":%d,\"complete\":true,\"functions\":[",
           (int)getpid());
    for (int i = 0; i < FNS; i++) {
        printf("%s{\"name\":\"%s\",\"attempts\":%lu,\"successful\":%lu,\"rv_counts\":{"
               "\"0x0000000000000000\":%lu",
               i ? "," : "", MT_NAME[i], sum->attempts[i], sum->ok[i], sum->ok[i]);
        if (i == 0 && sum->err_n > 0)
            printf(",\"0x%016lx\":%lu", sum->err_rv, sum->err_n);
        printf("}}");
    }
    printf("]}\n");
    /* Scaffolding is a separate line (not LEDGER functions): the profile
     * oracle matches LEDGER rows to TARGETs exactly, while the inventory
     * edge totals need every through-table call including scaffolding. */
    printf("SCAFFOLD {\"opens_attempted\":%lu,\"opens_ok\":%lu,\"closes\":%lu,\"finalizes\":%lu}\n",
           sum->opens_attempted, sum->opens_ok, sum->closes, sum->finalizes);
    fflush(stdout);
}

static void mt_setup(void ***fns_out, CK_SLOT_ID *slot_out, const char *module)
{
    typedef struct { void *c, *d, *l, *u; CK_FLAGS flags; void *r; } INITARGS;
    void *handle = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    CK_RV (*gfl)(void **);
    void *list = NULL;
    INITARGS args;
    CK_SLOT_ID slots[8];
    CK_ULONG nslots = 8;
    CK_RV rv;
    if (!handle) {
        fprintf(stderr, "mt_mixed: dlopen: %s\n", dlerror());
        exit(1);
    }
    gfl = (CK_RV(*)(void **))dlsym(handle, "C_GetFunctionList");
    if (!gfl || gfl(&list) || !list)
        mt_die("C_GetFunctionList", 0);
    *fns_out = (void **)((char *)list + 8);
    memset(&args, 0, sizeof args);
    args.flags = 2; /* CKF_OS_LOCKING_OK */
    rv = F(*fns_out, 0, CK_RV (*)(void *))(&args);
    if (rv != CKR_OK)
        mt_die("C_Initialize", rv);
    rv = F(*fns_out, 4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &nslots);
    if (rv != CKR_OK || nslots == 0)
        mt_die("C_GetSlotList", rv);
    *slot_out = slots[0];
}

static void mt_finalize(void **fns, struct mt_counts *out)
{
    CK_RV rv;
    /* Recorded before the call: a failure dies with no LEDGER, so an
     * emitted count always matches the observer's entry-side count. */
    if (out)
        out->finalizes++;
    rv = F(fns, 1, CK_RV (*)(void *))(NULL);
    if (rv != CKR_OK)
        mt_die("C_Finalize", rv);
}

static void mt_wait_gate(const char *gate)
{
    if (!gate || !*gate || (gate[0] == '-' && !gate[1]))
        return;
    while (access(gate, F_OK) != 0)
        usleep(10000);
}

static void mt_hold_if_asked(void)
{
    const char *hold = getenv("MT_MIXED_HOLD");
    if (!hold || strcmp(hold, "1"))
        return;
    {
        sigset_t mask, old;
        int sig = 0;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);
        pthread_sigmask(SIG_BLOCK, &mask, &old);
        while (sig != SIGTERM && sig != SIGINT)
            sigwait(&mask, &sig);
        pthread_sigmask(SIG_SETMASK, &old, NULL);
    }
}

#ifndef MT_MIXED_AS_LIB
int main(int argc, char **argv)
{
    struct mt_ctx ctx;
    struct mt_counts sum;
    int mode;
    long threads, iters, errors;
    if (argc != 7) {
        fprintf(stderr, "usage: %s MODULE THREADS ITERS GATE {sessions|shared|churn} ERRORS\n",
                argv[0]);
        return 2;
    }
    threads = atol(argv[2]);
    iters = atol(argv[3]);
    errors = atol(argv[6]);
    if (!strcmp(argv[5], "sessions"))
        mode = 0;
    else if (!strcmp(argv[5], "shared"))
        mode = 1;
    else if (!strcmp(argv[5], "churn"))
        mode = 2;
    else {
        fprintf(stderr, "bad MODE\n");
        return 2;
    }
    if (threads < 1 || threads > 256 || iters < 1 || errors < 0 || errors > 100000) {
        fprintf(stderr, "bad THREADS/ITERS/ERRORS\n");
        return 2;
    }
    memset(&ctx, 0, sizeof ctx);
    ctx.threads = (int)threads;
    ctx.iters = (int)iters;
    ctx.errors = (int)errors;
    mt_setup(&ctx.fns, &ctx.slot, argv[1]);
    mt_emit_targets(ctx.fns);
    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    mt_wait_gate(argv[4]);
    mt_run(&ctx, mode, &sum);
    /* Finalize before LEDGER so the SCAFFOLD line carries the complete
     * entry-side record; the hold keeps the mapping (not the session). */
    mt_finalize(ctx.fns, &sum);
    mt_verify(&sum, (unsigned long)threads, (unsigned long)iters, (unsigned long)errors,
              mode == 1 ? 1 : (unsigned long)threads * (mode == 2 ? 2 : 1), 1);
    mt_emit_ledger(&sum);
    mt_hold_if_asked();
    return 0;
}
#endif
