/* SPDX-License-Identifier: GPL-3.0-or-later */
/* live-joint: the READY/GO owned provider workload for the R1.6 live Joint
 * root cells (inventory::privileged_tests::privileged_joint_*_lp64).
 *
 * usage: live-joint MODE --cell LABEL [options]
 *   MODE a        held-call owner: dlopen the held provider, READY, wait
 *                   --go, run C_SignInit (returns at once), print HELD,
 *                   enter C_Sign (which blocks on the --release FIFO),
 *                   print RETURNED on return, DONE. The held call is a
 *                   semantic session call on purpose: a COUNT_ONLY slot
 *                   can never birth Joint, so the q1/q2 Joint
 *                   choreography needs a real admittable operation here.
 *   MODE b        SoftHSM script: READY, wait --go, run the fixed call
 *                   script, print CALLS + DONE.
 *   MODE exec     exec producer: gen 0 maps the provider, READY, waits
 *                   --go, runs the mini probe (GEN0DONE, never CALLS: its
 *                   image is retired at conversion, so it sheds), prints
 *                   EXEC and execs itself with --gen 1; gen 1 maps again
 *                   (fresh image), READY, waits --trig, runs the mini
 *                   probe (TRIGDONE, tallied: its current image stages),
 *                   waits --late, runs the b script, DONE. The two probes
 *                   are observed pre/post-exec calls, so the native binder
 *                   sees the ended image and its later image in one domain
 *                   and mints the exec successor.
 *   MODE absent   absence subject: maps --module only, runs Initialize +
 *                   one GetSlotList + Finalize (so it is admitted), never
 *                   maps the subset's other provider, DONE. The observer
 *                   proves the absence; this process only reports what IT
 *                   mapped/called.
 * options:
 *   --module P     provider .so (a: the held provider; b/exec/absent: the
 *                   SoftHSM copy). Required.
 *   --cell LABEL   ledger cell label (no whitespace). Required.
 *   --go FILE      wait for FILE to exist after READY (default -: no gate).
 *                   The S1Only sibling's gate opens before attach, so its
 *                   entries are genuinely pre-attach while its return is
 *                   post-attach.
 *   --late FILE    second gate (exec gen 1). Required by that mode.
 *   --trig FILE    first gate (exec gen 1): the trigger probe proving the
 *                   later image runs once it opens. Required by that mode.
 *   --release FIFO (a) the release FIFO the held call blocks on. Required.
 *                   One FIFO per held process (each opens its own).
 *   --iters N      (b/exec) digest iterations (default 2).
 *   --gen N        (exec, internal) exec generation, set by the chain itself.
 *   --hold         after DONE, wait for SIGTERM/SIGINT before exiting.
 *
 * Every line is an independent ledger of what THIS process did; it never
 * reads p11scope state. Lines (one key=value token each, no spaces in values):
 *   READY cell pid exe                  mapped, gated, making no calls yet
 *   MAPPED cell pid module ino           a provider was dlopen()ed (st_ino of
 *                                         the realpath)
 *   HELD cell pid fn t                   about to enter a call that will block
 *   RETURNED cell pid fn t rv            the held call returned
 *   CALLS cell pid fn n bad              n calls ENTERED (counted before the
 *                                         call), bad = calls returning rv != 0
 *   EXEC cell pid gen next               about to exec (next = gen + 1)
 *   GEN0DONE cell pid gen status         gen 0 finished its mini probe
 *   TRIGDONE cell pid gen status         gen 1 finished its trigger probe
 *   DONE cell pid gen exe status         finished (status ok|fail)
 * t values are CLOCK_MONOTONIC ns in the workload's time namespace, for the
 * hold-window check (same namespace as the observer on the root lane).
 *
 * Built with -DLIVE_JOINT_HELD_PROVIDER -shared -fPIC, this file is instead
 * the held provider: a v2.40 68-entry table whose exported C_Sign blocks
 * until a writer opens and closes $LIVE_JOINT_RELEASE (a FIFO), retrying
 * EINTR. C_GetFunctionList, C_SignInit and C_Sign are real exported
 * symbols (the manifest resolves their file offsets); every other table
 * entry is a static ok.
 */
#define _GNU_SOURCE
#ifdef LIVE_JOINT_HELD_PROVIDER
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_ULONG;
static CK_RV ok(void) { return 0; }
/* Exported: the observer attaches its uprobes to these symbols. */
CK_RV C_SignInit(CK_SESSION_HANDLE session, void *mechanism, CK_OBJECT_HANDLE key)
{
    (void)session;
    (void)mechanism;
    (void)key;
    return 0;
}
CK_RV C_Sign(CK_SESSION_HANDLE session, void *data, CK_ULONG data_len, void *sig, CK_ULONG *sig_len)
{
    const char *path;
    int fd;
    char byte;
    ssize_t got;
    (void)session;
    (void)data;
    (void)data_len;
    (void)sig;
    (void)sig_len;
    path = getenv("LIVE_JOINT_RELEASE");
    if (!path)
        return 5; /* CKR_GENERAL_ERROR: no release channel, refuse to hang */
    while ((fd = open(path, O_RDONLY)) < 0)
        if (errno != EINTR)
            return 5;
    while ((got = read(fd, &byte, 1)) != 0)
        if (got < 0 && errno != EINTR)
            break;
    close(fd);
    return 0;
}
static struct {
    unsigned char major, minor;
    void *f[68];
} table;
CK_RV C_GetFunctionList(void **pp)
{
    table.major = 2;
    table.minor = 40;
    for (int i = 0; i < 68; i++)
        table.f[i] = (void *)ok;
    table.f[42] = (void *)C_SignInit;
    table.f[43] = (void *)C_Sign;
    *pp = &table;
    return 0;
}
#else
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_FLAGS;
typedef struct {
    unsigned long mechanism;
    void *p;
    unsigned long len;
} CK_MECHANISM;
typedef struct {
    unsigned long type;
    void *pValue;
    unsigned long len;
} CK_ATTRIBUTE;
typedef struct {
    char label[32];
    char manufacturerID[32];
    char model[16];
    char serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG maxSessionCount, sessionCount, maxRwSessionCount, rwSessionCount;
    CK_ULONG maxPinLen, minPinLen, totalPublicMemory, freePublicMemory;
    CK_ULONG totalPrivateMemory, freePrivateMemory;
    unsigned char hardwareVersion[2], firmwareVersion[2];
    char utcTime[16];
} CK_TOKEN_INFO;
typedef struct {
    void *create, *destroy, *lock, *unlock;
    CK_FLAGS flags;
    void *reserved;
} CK_INIT_ARGS;

/* v2.40 function-table order (index after the CK_VERSION header). */
enum {
    I_Initialize = 0,
    I_Finalize = 1,
    I_GetSlotList = 4,
    I_GetTokenInfo = 6,
    I_OpenSession = 12,
    I_CloseSession = 13,
    I_Login = 18,
    I_Logout = 19,
    I_DigestInit = 37,
    I_Digest = 38,
    I_SignInit = 42,
    I_Sign = 43,
    I_GenerateKey = 58,
};
#define CKM_SHA256 0x250UL
#define CKM_SHA256_HMAC 0x251UL
#define CKM_GENERIC_SECRET_KEY_GEN 0x350UL
#define CKF_RW_SESSION 0x2UL
#define CKF_SERIAL_SESSION 0x4UL
#define CKU_USER 1UL
#define NFN 68

static const char *cell = "?";
static int gen;
static char self_exe[PATH_MAX];
static volatile sig_atomic_t stop;
static void on_signal(int s) { (void)s; stop = 1; }

static unsigned long now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long)t.tv_sec * 1000000000UL + (unsigned long)t.tv_nsec;
}

static const char *fn_name(int i)
{
    switch (i) {
    case I_Initialize: return "C_Initialize";
    case I_Finalize: return "C_Finalize";
    case I_GetSlotList: return "C_GetSlotList";
    case I_GetTokenInfo: return "C_GetTokenInfo";
    case I_OpenSession: return "C_OpenSession";
    case I_Login: return "C_Login";
    case I_Logout: return "C_Logout";
    case I_CloseSession: return "C_CloseSession";
    case I_DigestInit: return "C_DigestInit";
    case I_Digest: return "C_Digest";
    case I_SignInit: return "C_SignInit";
    case I_Sign: return "C_Sign";
    case I_GenerateKey: return "C_GenerateKey";
    default: return "?";
    }
}

/* Per-function entered/failed counters, flushed as CALLS lines. */
static unsigned long entered[NFN], failed[NFN];
static void tally(int i, CK_RV rv)
{
    entered[i]++;
    if (rv != 0)
        failed[i]++;
}
static void flush_calls(void)
{
    int i;
    for (i = 0; i < NFN; i++) {
        if (!entered[i])
            continue;
        printf("CALLS cell=%s pid=%d fn=%s n=%lu bad=%lu\n", cell, getpid(), fn_name(i),
               entered[i], failed[i]);
        entered[i] = failed[i] = 0;
    }
    fflush(stdout);
}

static _Noreturn void die(const char *what)
{
    fprintf(stderr, "live-joint %s: %s\n", cell, what);
    flush_calls();
    printf("DONE cell=%s pid=%d gen=%d exe=%s status=fail\n", cell, getpid(), gen, self_exe);
    fflush(stdout);
    exit(1);
}

static void wait_for_file(const char *path, const char *what)
{
    unsigned waited;
    if (!path || !strcmp(path, "-"))
        return;
    for (waited = 0; waited < 3000; waited++) {
        struct stat st;
        if (!stat(path, &st))
            return;
        usleep(10000);
    }
    die(what);
}

static void *map_provider(const char *path)
{
    char real[PATH_MAX];
    struct stat st;
    void *dl;
    if (!realpath(path, real))
        die("provider realpath failed");
    dl = dlopen(real, RTLD_NOW | RTLD_LOCAL);
    if (!dl)
        die("provider dlopen failed");
    if (stat(real, &st))
        die("provider stat failed");
    printf("MAPPED cell=%s pid=%d module=%s ino=%lu\n", cell, getpid(), real,
           (unsigned long)st.st_ino);
    fflush(stdout);
    return dl;
}

/* The table as data pointers: each call casts from void *, which the
 * ledger fixtures use to stay clean under -Wcast-function-type. */
static void **function_table(void *dl)
{
    CK_RV (*get_list)(void **);
    void *table = NULL;
    *(void **)(&get_list) = dlsym(dl, "C_GetFunctionList");
    if (!get_list)
        die("no C_GetFunctionList");
    if (get_list(&table) != 0 || !table)
        die("C_GetFunctionList failed");
    /* Skip the CK_VERSION header (padded to 8, as in the ledger). */
    return (void **)((char *)table + 8);
}

static void hold_until_signaled(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    while (!stop)
        pause();
}

/* The fixed SoftHSM script. Returns nonzero if any call failed. */
static int run_soft_script(void **f, int iters)
{
    CK_RV rv;
    CK_SLOT_ID slots[16];
    CK_ULONG count = 16, i;
    CK_SLOT_ID slot = 0;
    CK_SESSION_HANDLE session = 0;
    CK_MECHANISM mech;
    unsigned char digest[64];
    CK_ULONG digest_len;
    int bad = 0, found = 0;
    CK_INIT_ARGS args;
    static const char pin[] = "1234";

    memset(&args, 0, sizeof(args));
    rv = ((CK_RV(*)(void *))f[I_Initialize])(&args);
    tally(I_Initialize, rv);
    bad |= (rv != 0);
    rv = ((CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))f[I_GetSlotList])(1, slots, &count);
    tally(I_GetSlotList, rv);
    bad |= (rv != 0);
    for (i = 0; i < count && i < 16; i++) {
        CK_TOKEN_INFO info;
        rv = ((CK_RV(*)(CK_SLOT_ID, void *))f[I_GetTokenInfo])(slots[i], &info);
        tally(I_GetTokenInfo, rv);
        bad |= (rv != 0);
        if (!memcmp(info.label, "c51", 3)) {
            slot = slots[i];
            found = 1;
        }
    }
    if (!found)
        return 1;
    rv = ((CK_RV(*)(CK_SLOT_ID, CK_FLAGS, void *, void *, CK_SESSION_HANDLE *))f[I_OpenSession])(
        slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    tally(I_OpenSession, rv);
    bad |= (rv != 0);
    rv = ((CK_RV(*)(CK_SESSION_HANDLE, CK_ULONG, void *, CK_ULONG))f[I_Login])(
        session, CKU_USER, (void *)pin, 4);
    tally(I_Login, rv);
    bad |= (rv != 0);
    /* One key operation: generic-secret keygen + HMAC-SHA256 sign (the
     * ledger's proven template), so the Joint cells observe key facts. */
    {
        unsigned long cls = 4 /* CKO_SECRET_KEY */, key_type = 0x10 /* CKK_GENERIC_SECRET */,
                      klen = 32;
        unsigned char yes = 1, no = 0;
        CK_ATTRIBUTE t[] = {
            {0x0 /* CKA_CLASS */, &cls, sizeof(cls)},
            {0x100 /* CKA_KEY_TYPE */, &key_type, sizeof(key_type)},
            {0x161 /* CKA_VALUE_LEN */, &klen, sizeof(klen)},
            {0x1 /* CKA_TOKEN */, &no, 1},
            {0x108 /* CKA_SIGN */, &yes, 1},
        };
        CK_MECHANISM gen = {CKM_GENERIC_SECRET_KEY_GEN, NULL, 0};
        CK_MECHANISM mac = {CKM_SHA256_HMAC, NULL, 0};
        CK_OBJECT_HANDLE key = 0;
        unsigned char sig[64];
        CK_ULONG sig_len;
        rv = ((CK_RV(*)(CK_SESSION_HANDLE, void *, void *, CK_ULONG, CK_OBJECT_HANDLE *))f
                  [I_GenerateKey])(session, &gen, t, 5, &key);
        tally(I_GenerateKey, rv);
        bad |= (rv != 0);
        rv = ((CK_RV(*)(CK_SESSION_HANDLE, void *, CK_OBJECT_HANDLE))f[I_SignInit])(session,
                                                                                    &mac, key);
        tally(I_SignInit, rv);
        bad |= (rv != 0);
        sig_len = sizeof(sig);
        rv = ((CK_RV(*)(CK_SESSION_HANDLE, void *, CK_ULONG, void *, CK_ULONG *))f[I_Sign])(
            session, (void *)"hello", 5, sig, &sig_len);
        tally(I_Sign, rv);
        bad |= (rv != 0);
    }
    mech.mechanism = CKM_SHA256;
    mech.p = NULL;
    mech.len = 0;
    for (i = 0; i < (CK_ULONG)iters; i++) {
        rv = ((CK_RV(*)(CK_SESSION_HANDLE, void *))f[I_DigestInit])(session, &mech);
        tally(I_DigestInit, rv);
        bad |= (rv != 0);
        digest_len = sizeof(digest);
        rv = ((CK_RV(*)(CK_SESSION_HANDLE, void *, CK_ULONG, void *, CK_ULONG *))f[I_Digest])(
            session, (void *)"abc", 3, digest, &digest_len);
        tally(I_Digest, rv);
        bad |= (rv != 0);
    }
    rv = ((CK_RV(*)(CK_SESSION_HANDLE))f[I_Logout])(session);
    tally(I_Logout, rv);
    bad |= (rv != 0);
    rv = ((CK_RV(*)(CK_SESSION_HANDLE))f[I_CloseSession])(session);
    tally(I_CloseSession, rv);
    bad |= (rv != 0);
    rv = ((CK_RV(*)(void *))f[I_Finalize])(NULL);
    tally(I_Finalize, rv);
    bad |= (rv != 0);
    return bad;
}

/* A three-call probe (Initialize/GetSlotList/Finalize): gen 0 binds its
 * native image with it before EXEC, and gen 1 proves its later image with
 * it after READY, so one native domain sees both and the observer mints
 * the exec successor. When ledger is set the three calls tally into the
 * CALLS ledger (gen 1: its current image stages); otherwise they stay
 * out (gen 0: its retired image sheds at conversion). Prints one TAGDONE
 * line. Returns nonzero if any call failed. */
static int run_mini_probe(void **f, const char *tag, int ledger)
{
    CK_RV rv;
    CK_SLOT_ID slots[16];
    CK_ULONG count = 16;
    CK_INIT_ARGS args;
    int bad = 0;
    memset(&args, 0, sizeof(args));
    rv = ((CK_RV(*)(void *))f[I_Initialize])(&args);
    bad |= (rv != 0);
    if (ledger)
        tally(I_Initialize, rv);
    rv = ((CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))f[I_GetSlotList])(1, slots,
                                                                              &count);
    bad |= (rv != 0);
    if (ledger)
        tally(I_GetSlotList, rv);
    rv = ((CK_RV(*)(void *))f[I_Finalize])(NULL);
    bad |= (rv != 0);
    if (ledger)
        tally(I_Finalize, rv);
    printf("%s cell=%s pid=%d gen=%d status=%s\n", tag, cell, getpid(), gen,
           bad ? "fail" : "ok");
    fflush(stdout);
    return bad;
}

static void read_self_exe(void)
{
    ssize_t len = readlink("/proc/self/exe", self_exe, sizeof(self_exe) - 1);
    if (len < 0)
        die("no /proc/self/exe");
    self_exe[len] = 0;
}

int main(int argc, char **argv)
{
    const char *mode, *module = NULL, *go = "-", *late = NULL, *trig = NULL, *release = NULL;
    int iters = 2, hold = 0, i;
    void *dl;
    void **f;
    if (argc < 2) {
        fprintf(stderr, "usage: live-joint MODE --cell LABEL ...\n");
        return 2;
    }
    mode = argv[1];
    for (i = 2; i < argc; i++) {
        const char *a = argv[i], *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (!strcmp(a, "--cell") && v) {
            cell = v;
            i++;
        } else if (!strcmp(a, "--module") && v) {
            module = v;
            i++;
        } else if (!strcmp(a, "--go") && v) {
            go = v;
            i++;
        } else if (!strcmp(a, "--late") && v) {
            late = v;
            i++;
        } else if (!strcmp(a, "--trig") && v) {
            trig = v;
            i++;
        } else if (!strcmp(a, "--release") && v) {
            release = v;
            i++;
        } else if (!strcmp(a, "--iters") && v) {
            iters = atoi(v);
            i++;
        } else if (!strcmp(a, "--gen") && v) {
            gen = atoi(v);
            i++;
        } else if (!strcmp(a, "--hold")) {
            hold = 1;
        } else {
            fprintf(stderr, "live-joint: bad arg %s\n", a);
            return 2;
        }
    }
    if (strchr(cell, ' ') || strchr(cell, '=') || !strcmp(cell, "?")) {
        fprintf(stderr, "--cell must be a single token\n");
        return 2;
    }
    if (!module) {
        fprintf(stderr, "--module is required\n");
        return 2;
    }
    read_self_exe();

    if (!strcmp(mode, "a")) {
        /* Held-call owner: C_SignInit returns at once, then C_Sign
         * blocks until the harness releases the FIFO. A semantic
         * session pair, so the observer can admit and birth it. */
        unsigned long t_enter, t_exit;
        CK_RV rv, rv_init;
        CK_MECHANISM mac;
        unsigned char sig[64];
        CK_ULONG sig_len;
        if (!release) {
            fprintf(stderr, "mode a needs --release\n");
            return 2;
        }
        if (setenv("LIVE_JOINT_RELEASE", release, 1))
            die("setenv failed");
        dl = map_provider(module);
        (void)dl;
        f = function_table(dl);
        printf("READY cell=%s pid=%d exe=%s\n", cell, getpid(), self_exe);
        fflush(stdout);
        wait_for_file(go, "go gate never opened");
        mac.mechanism = CKM_SHA256_HMAC;
        mac.p = NULL;
        mac.len = 0;
        rv_init = ((CK_RV(*)(CK_SESSION_HANDLE, void *, CK_OBJECT_HANDLE))f[I_SignInit])(1,
                                                                                          &mac,
                                                                                          1);
        tally(I_SignInit, rv_init);
        t_enter = now_ns();
        printf("HELD cell=%s pid=%d fn=C_Sign t=%lu\n", cell, getpid(), t_enter);
        fflush(stdout);
        entered[I_Sign]++;
        sig_len = sizeof(sig);
        rv = ((CK_RV(*)(CK_SESSION_HANDLE, void *, CK_ULONG, void *, CK_ULONG *))f[I_Sign])(
            1, (void *)"hello", 5, sig, &sig_len);
        if (rv != 0)
            failed[I_Sign]++;
        t_exit = now_ns();
        printf("RETURNED cell=%s pid=%d fn=C_Sign t=%lu rv=%lu\n", cell, getpid(), t_exit,
               (unsigned long)rv);
        flush_calls();
        printf("DONE cell=%s pid=%d gen=%d exe=%s status=%s\n", cell, getpid(), gen, self_exe,
               rv == 0 && rv_init == 0 ? "ok" : "fail");
        fflush(stdout);
        if (hold)
            hold_until_signaled();
        return rv == 0 && rv_init == 0 ? 0 : 1;
    }
    if (!strcmp(mode, "b")) {
        int bad;
        dl = map_provider(module);
        (void)dl;
        f = function_table(dl);
        printf("READY cell=%s pid=%d exe=%s\n", cell, getpid(), self_exe);
        fflush(stdout);
        wait_for_file(go, "go gate never opened");
        bad = run_soft_script(f, iters);
        flush_calls();
        printf("DONE cell=%s pid=%d gen=%d exe=%s status=%s\n", cell, getpid(), gen, self_exe,
               bad ? "fail" : "ok");
        fflush(stdout);
        if (hold)
            hold_until_signaled();
        return bad ? 1 : 0;
    }
    if (!strcmp(mode, "exec")) {
        if (gen == 0) {
            /* Pre-exec image: bind its native image with the mini probe
             * (observed calls), then EXEC. Without an observed pre-exec
             * call the binder could never prove the image ended. */
            char gen_arg[32];
            char *child_argv[64];
            int n = 0, k;
            dl = map_provider(module);
            (void)dl;
            printf("READY cell=%s pid=%d exe=%s\n", cell, getpid(), self_exe);
            fflush(stdout);
            wait_for_file(go, "go gate never opened");
            f = function_table(dl);
            if (run_mini_probe(f, "GEN0DONE", 0))
                die("gen 0 probe failed");
            printf("EXEC cell=%s pid=%d gen=0 next=1\n", cell, getpid());
            fflush(stdout);
            snprintf(gen_arg, sizeof(gen_arg), "%d", 1);
            for (k = 0; k < argc && n < 60; k++) {
                if (!strcmp(argv[k], "--gen")) {
                    k++;
                    continue;
                }
                child_argv[n++] = argv[k];
            }
            child_argv[n++] = (char *)"--gen";
            child_argv[n++] = gen_arg;
            child_argv[n] = NULL;
            execv(child_argv[0], child_argv);
            die("exec failed");
        }
        /* Post-exec image: fresh mapping; the trigger probe proves the
         * later image (the binder mints the successor), then the late
         * gate releases the b script. The probe tallies: e_total counts
         * the b script plus these three staged calls. */
        if (!late) {
            fprintf(stderr, "mode exec gen 1 needs --late\n");
            return 2;
        }
        if (!trig) {
            fprintf(stderr, "mode exec gen 1 needs --trig\n");
            return 2;
        }
        dl = map_provider(module);
        (void)dl;
        f = function_table(dl);
        printf("READY cell=%s pid=%d exe=%s\n", cell, getpid(), self_exe);
        fflush(stdout);
        wait_for_file(trig, "trig gate never opened");
        if (run_mini_probe(f, "TRIGDONE", 1))
            die("gen 1 probe failed");
        wait_for_file(late, "late gate never opened");
        {
            int bad = run_soft_script(f, iters);
            flush_calls();
            printf("DONE cell=%s pid=%d gen=%d exe=%s status=%s\n", cell, getpid(), gen,
                   self_exe, bad ? "fail" : "ok");
            fflush(stdout);
            if (hold)
                hold_until_signaled();
            return bad ? 1 : 0;
        }
    }
    if (!strcmp(mode, "absent")) {
        /* Absence subject: exactly one C_GetSlotList call through
         * --module, then quiet. Never maps any other provider. */
        CK_RV rv;
        CK_SLOT_ID slots[16];
        CK_ULONG count = 16;
        CK_INIT_ARGS args;
        dl = map_provider(module);
        (void)dl;
        f = function_table(dl);
        printf("READY cell=%s pid=%d exe=%s\n", cell, getpid(), self_exe);
        fflush(stdout);
        wait_for_file(go, "go gate never opened");
        memset(&args, 0, sizeof(args));
        rv = ((CK_RV(*)(void *))f[I_Initialize])(&args);
        tally(I_Initialize, rv);
        rv = ((CK_RV(*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))f[I_GetSlotList])(1, slots,
                                                                                  &count);
        tally(I_GetSlotList, rv);
        rv = ((CK_RV(*)(void *))f[I_Finalize])(NULL);
        tally(I_Finalize, rv);
        flush_calls();
        printf("DONE cell=%s pid=%d gen=%d exe=%s status=ok\n", cell, getpid(), gen, self_exe);
        fflush(stdout);
        if (hold)
            hold_until_signaled();
        return 0;
    }
    fprintf(stderr, "live-joint: bad MODE %s\n", mode);
    return 2;
}
#endif
