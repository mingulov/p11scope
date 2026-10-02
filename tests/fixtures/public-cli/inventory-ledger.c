/* SPDX-License-Identifier: GPL-3.0-or-later */
/* inventory-ledger: the ledgered PKCS#11 workload for the installed
 * `p11scope inventory` acceptance (Task 6 C8). Driven by
 * scripts/qualify-inventory-native.sh, checked by scripts/inventory-native-oracle.py.
 *
 * usage: inventory-ledger MODE --cell LABEL [--module PROVIDER]... [options]
 *   MODE mech         setup, ITERS x {Digest SHA256, AES keygen + AES-GCM encrypt,
 *                     generic-secret keygen + HMAC-SHA256 sign, 2x DestroyObject} per
 *                     module (module k runs ITERS*(k+1) iterations), teardown   [P1 P2 P4 P7]
 *   MODE map          dlopen every module, never call into any of them              [P3]
 *   MODE exec-chain   one mech generation per image, then exec the next --chain step [P5]
 *   MODE held         call the held provider's C_WaitForSlotEvent, which blocks until
 *                     the release FIFO named by $INVENTORY_LEDGER_RELEASE is written [P6]
 *   MODE leader-exit  setup on the leader, which then pthread_exit()s; a worker runs
 *                     the mech iterations as a non-leader thread                    [LX]
 * options:
 *   --iters N        main-phase iterations (default 4)
 *   --gate FILE|-    wait for FILE to exist before the main phase (default -: no gate)
 *   --hold           after teardown, wait for SIGTERM/SIGINT before exiting
 *   --late           (mech) dlopen only after the gate opens: a late provider     [P7]
 *   --delay-ms N     sleep N ms after the gate (after a --late dlopen) before calling;
 *                    exec-chain also sleeps N ms before every exec
 *   --sleep-us N     sleep N us after every iteration (stretches a short CLI)
 *   --chain SPEC     (exec-chain) comma list of HOW:EXE steps, HOW = leader|thread
 *   --gen K          (internal) exec generation, set by the chain itself
 *
 * Every line is an independent, deterministic ledger of what THIS process did; it
 * never reads p11scope state. Lines (one key=value token each, no spaces in values):
 *   IDENT  cell pid start gen exe                 the image identity (start = /proc stat
 *                                                 field 22, clock ticks since boot)
 *   MAPPED cell pid start gen exe module ino      a provider was dlopen()ed (st_ino of the
 *                                                 realpath; device is not printed because
 *                                                 st_dev and mountinfo disagree on btrfs)
 *   LEDGER cell pid start gen exe module fn mech n bad phase t0 t1
 *          one line per (module, function, mechanism, phase): n calls ENTERED (counted
 *          before the call, so a held call is ledgered), bad = calls returning rv != 0,
 *          t0/t1 = CLOCK_MONOTONIC ns of the first/last entry (the capture clock basis).
 *          mech is the operation's mechanism (0x..) or "-". fn C_GetFunctionList is the
 *          dlsym() entry, not a function-table call.
 *   HELD   cell pid start gen exe module fn t     a call that will not return was entered
 *   RETURNED cell pid start gen exe fn t          the held call returned (t = CLOCK_MONOTONIC ns)
 *   ZOMBIE cell pid start gen exe state t         leader-exit: /proc/self/stat state of the
 *                                                 leader seen by the worker (Z = zombie leader)
 *   EXEC   cell pid start gen exe how next        about to exec (how = leader|thread)
 *   DONE   cell pid start gen exe status          this image finished its work (status ok|fail)
 * Ledger lines are flushed in batches (each flush prints only the counts since the
 * previous one); consumers sum n over identical keys.
 *
 * Clock: t0/t1/t are CLOCK_MONOTONIC in the workload's time namespace. The oracle
 * compares them with p11scope's CLOCK_MONOTONIC capture clock, which is only valid
 * while workload and observer share one time namespace (true on the host and in a
 * vng guest; a container lane with its own time namespace must add the offset).
 *
 * Built with -DINVENTORY_LEDGER_HELD_PROVIDER -shared -fPIC, this file is instead the
 * held provider: a v2.40 68-entry table whose C_WaitForSlotEvent blocks until a
 * writer opens and closes $INVENTORY_LEDGER_RELEASE (a FIFO), retrying EINTR, so the
 * call stays held across any signal until the harness releases it.
 */
#define _GNU_SOURCE
#ifdef INVENTORY_LEDGER_HELD_PROVIDER
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

typedef unsigned long CK_RV;
static CK_RV ok(void) { return 0; }
static CK_RV held_until_released(void) {
    const char *path = getenv("INVENTORY_LEDGER_RELEASE");
    if (!path) return 5; /* CKR_GENERAL_ERROR: no release channel, refuse to hang */
    int fd;
    while ((fd = open(path, O_RDONLY)) < 0)
        if (errno != EINTR) return 5;
    char byte;
    ssize_t got;
    while ((got = read(fd, &byte, 1)) != 0)
        if (got < 0 && errno != EINTR) break;
    close(fd);
    return 0;
}
static struct { unsigned char major, minor; void *f[68]; } table;
CK_RV C_GetFunctionList(void **pp) {
    table.major = 2;
    table.minor = 40;
    for (int i = 0; i < 68; i++) table.f[i] = (void *)ok;
    table.f[67] = (void *)held_until_released;
    *pp = &table;
    return 0;
}
#else
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_FLAGS;
typedef struct { unsigned long mechanism; void *p; unsigned long len; } CK_MECHANISM;
typedef struct { unsigned long type; void *p; unsigned long len; } CK_ATTRIBUTE;
typedef struct { void *create, *destroy, *lock, *unlock; CK_FLAGS flags; void *reserved; } CK_INIT_ARGS;
typedef struct {
    unsigned char *iv; CK_ULONG iv_len; CK_ULONG iv_bits;
    unsigned char *aad; CK_ULONG aad_len; CK_ULONG tag_bits;
} CK_GCM_PARAMS;

/* v2.40 function-table order (index after the CK_VERSION header). */
static const char *const FN_NAMES[68] = {
    "C_Initialize", "C_Finalize", "C_GetInfo", "C_GetFunctionList", "C_GetSlotList",
    "C_GetSlotInfo", "C_GetTokenInfo", "C_GetMechanismList", "C_GetMechanismInfo",
    "C_InitToken", "C_InitPIN", "C_SetPIN", "C_OpenSession", "C_CloseSession",
    "C_CloseAllSessions", "C_GetSessionInfo", "C_GetOperationState", "C_SetOperationState",
    "C_Login", "C_Logout", "C_CreateObject", "C_CopyObject", "C_DestroyObject",
    "C_GetObjectSize", "C_GetAttributeValue", "C_SetAttributeValue", "C_FindObjectsInit",
    "C_FindObjects", "C_FindObjectsFinal", "C_EncryptInit", "C_Encrypt", "C_EncryptUpdate",
    "C_EncryptFinal", "C_DecryptInit", "C_Decrypt", "C_DecryptUpdate", "C_DecryptFinal",
    "C_DigestInit", "C_Digest", "C_DigestUpdate", "C_DigestKey", "C_DigestFinal",
    "C_SignInit", "C_Sign", "C_SignUpdate", "C_SignFinal", "C_SignRecoverInit",
    "C_SignRecover", "C_VerifyInit", "C_Verify", "C_VerifyUpdate", "C_VerifyFinal",
    "C_VerifyRecoverInit", "C_VerifyRecover", "C_DigestEncryptUpdate",
    "C_DecryptDigestUpdate", "C_SignEncryptUpdate", "C_DecryptVerifyUpdate",
    "C_GenerateKey", "C_GenerateKeyPair", "C_WrapKey", "C_UnwrapKey", "C_DeriveKey",
    "C_SeedRandom", "C_GenerateRandom", "C_GetFunctionStatus", "C_CancelFunction",
    "C_WaitForSlotEvent",
};
enum {
    I_Initialize = 0, I_Finalize = 1, I_GetFunctionList = 3, I_GetSlotList = 4,
    I_OpenSession = 12, I_CloseSession = 13, I_Login = 18, I_Logout = 19,
    I_DestroyObject = 22, I_EncryptInit = 29, I_Encrypt = 30, I_DigestInit = 37,
    I_Digest = 38, I_SignInit = 42, I_Sign = 43, I_GenerateKey = 58,
    I_WaitForSlotEvent = 67,
};
#define CKM_SHA256 0x250UL
#define CKM_SHA256_HMAC 0x251UL
#define CKM_GENERIC_SECRET_KEY_GEN 0x350UL
#define CKM_AES_KEY_GEN 0x1080UL
#define CKM_AES_GCM 0x1087UL
#define NO_MECH (~0UL)
#define MAX_MODULES 4

static const char *cell = "?";
static char self_exe[PATH_MAX];
static unsigned long self_start;
static int gen;
static volatile sig_atomic_t stop;
static void on_signal(int s) { (void)s; stop = 1; }

static unsigned long now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long)t.tv_sec * 1000000000UL + (unsigned long)t.tv_nsec;
}

static void flush_ledger_try(void);
static _Noreturn void die(const char *what) {
    flush_ledger_try();
    fprintf(stdout, "DONE cell=%s pid=%d start=%lu gen=%d exe=%s status=fail\n", cell, getpid(),
            self_start, gen, self_exe);
    fflush(stdout);
    fprintf(stderr, "inventory-ledger[%s]: %s\n", cell, what);
    exit(1);
}

static int has_space(const char *s) {
    for (; *s; s++)
        if (*s == ' ' || *s == '\t' || *s == '\n' || *s == '=') return 1;
    return 0;
}

/* Identity is read once per image, before any thread can exit: a zombie leader's
 * /proc/self/exe no longer resolves. */
static void read_identity(void) {
    ssize_t n = readlink("/proc/self/exe", self_exe, sizeof self_exe - 1);
    if (n <= 0) die("readlink /proc/self/exe");
    self_exe[n] = 0;
    if (has_space(self_exe)) die("executable path must not contain whitespace or '='");
    FILE *f = fopen("/proc/self/stat", "r");
    char buf[1024];
    if (!f || !fgets(buf, sizeof buf, f)) die("read /proc/self/stat");
    fclose(f);
    char *p = strrchr(buf, ')');
    if (!p) die("parse /proc/self/stat");
    /* after ") " come fields 3..; starttime is field 22 */
    p += 2;
    for (int field = 3; field < 22; field++) {
        p = strchr(p, ' ');
        if (!p) die("parse /proc/self/stat");
        p++;
    }
    self_start = strtoul(p, NULL, 10);
}

#define HEAD "cell=%s pid=%d start=%lu gen=%d exe=%s"
#define HEAD_ARGS cell, getpid(), self_start, gen, self_exe

struct entry { int module, fn, phase; unsigned long mech, n, bad, t0, t1; };
static struct entry ledger[512];
static int ledger_len;
static pthread_mutex_t ledger_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *const PHASES[] = {"setup", "main", "teardown", "held"};
enum { PH_SETUP, PH_MAIN, PH_TEARDOWN, PH_HELD };

struct module {
    char path[PATH_MAX];
    void *handle;
    void **fns;
    unsigned long ino;
};
static struct module modules[MAX_MODULES];
static int module_count;

static struct entry *slot(int module, int fn, unsigned long mech, int phase) {
    for (int i = 0; i < ledger_len; i++) {
        struct entry *e = &ledger[i];
        if (e->module == module && e->fn == fn && e->mech == mech && e->phase == phase) return e;
    }
    if (ledger_len == (int)(sizeof ledger / sizeof ledger[0])) die("ledger table full");
    struct entry *e = &ledger[ledger_len++];
    memset(e, 0, sizeof *e);
    e->module = module; e->fn = fn; e->mech = mech; e->phase = phase;
    return e;
}

/* Count the call BEFORE it is made: an entered call is a fact even if it never returns. */
static void enter(int module, int fn, unsigned long mech, int phase) {
    unsigned long t = now_ns();
    pthread_mutex_lock(&ledger_lock);
    struct entry *e = slot(module, fn, mech, phase);
    if (e->n++ == 0) e->t0 = t;
    e->t1 = t;
    pthread_mutex_unlock(&ledger_lock);
}

static void returned(int module, int fn, unsigned long mech, int phase, CK_RV rv) {
    if (rv == 0) return;
    pthread_mutex_lock(&ledger_lock);
    slot(module, fn, mech, phase)->bad++;
    pthread_mutex_unlock(&ledger_lock);
}

static void flush_ledger(void) {
    pthread_mutex_lock(&ledger_lock);
    for (int i = 0; i < ledger_len; i++) {
        struct entry *e = &ledger[i];
        char mech[24];
        if (e->mech == NO_MECH) strcpy(mech, "-");
        else snprintf(mech, sizeof mech, "0x%lx", e->mech);
        printf("LEDGER " HEAD " module=%s fn=%s mech=%s n=%lu bad=%lu phase=%s t0=%lu t1=%lu\n",
               HEAD_ARGS, modules[e->module].path, FN_NAMES[e->fn], mech, e->n, e->bad,
               PHASES[e->phase], e->t0, e->t1);
    }
    ledger_len = 0;
    pthread_mutex_unlock(&ledger_lock);
    fflush(stdout);
}

/* die() may run while another thread holds the ledger lock: flush only if free. */
static void flush_ledger_try(void) {
    if (pthread_mutex_trylock(&ledger_lock)) {
        printf("LEDGER_UNFLUSHED cell=%s pid=%d reason=lock-held\n", cell, getpid());
        return;
    }
    pthread_mutex_unlock(&ledger_lock);
    flush_ledger();
}

/* CALL(module, phase, index, mech, type, args...) records, calls, and records rv. */
#define CALL(m, ph, idx, mech, T, ...)                                               \
    ({                                                                               \
        enter((m), (idx), (mech), (ph));                                             \
        CK_RV rv_ = ((T)modules[(m)].fns[(idx)])(__VA_ARGS__);                       \
        returned((m), (idx), (mech), (ph), rv_);                                     \
        rv_;                                                                         \
    })

static void load_module(int m) {
    struct module *mod = &modules[m];
    char real[PATH_MAX];
    if (!realpath(mod->path, real)) die("realpath of a module failed");
    if (has_space(real)) die("module path must not contain whitespace or '='");
    strcpy(mod->path, real);
    struct stat st;
    if (stat(mod->path, &st)) die("stat of a module failed");
    mod->ino = (unsigned long)st.st_ino;
    mod->handle = dlopen(mod->path, RTLD_NOW | RTLD_LOCAL);
    if (!mod->handle) { fprintf(stderr, "dlopen: %s\n", dlerror()); die("dlopen failed"); }
    printf("MAPPED " HEAD " module=%s ino=%lu\n", HEAD_ARGS, mod->path, mod->ino);
    fflush(stdout);
}

static void bind_module(int m) {
    struct module *mod = &modules[m];
    CK_RV (*gfl)(void **) = (CK_RV (*)(void **))dlsym(mod->handle, "C_GetFunctionList");
    if (!gfl) die("no C_GetFunctionList");
    void *list = NULL;
    enter(m, I_GetFunctionList, NO_MECH, PH_SETUP);
    CK_RV rv = gfl(&list);
    returned(m, I_GetFunctionList, NO_MECH, PH_SETUP, rv);
    if (rv || !list) die("C_GetFunctionList failed");
    mod->fns = (void **)((char *)list + 8);
}

static void wait_gate(const char *gate) {
    if (!gate || !strcmp(gate, "-")) return;
    unsigned long deadline = now_ns() + 600UL * 1000000000UL;
    while (access(gate, F_OK) != 0) {
        if (stop) die("stopped before the gate opened");
        if (now_ns() > deadline) die("gate never opened");
        usleep(10000);
    }
}

static void sleep_ms(long ms) {
    if (ms <= 0) return;
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}

static CK_SESSION_HANDLE setup(int m) {
    CK_INIT_ARGS args = {0};
    args.flags = 2; /* CKF_OS_LOCKING_OK: leader-exit calls from a second thread */
    if (CALL(m, PH_SETUP, I_Initialize, NO_MECH, CK_RV (*)(void *), &args)) die("C_Initialize");
    CK_SLOT_ID slots[16];
    CK_ULONG ns = 16;
    if (CALL(m, PH_SETUP, I_GetSlotList, NO_MECH, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *),
             1, slots, &ns) || !ns)
        die("C_GetSlotList");
    CK_SESSION_HANDLE s;
    if (CALL(m, PH_SETUP, I_OpenSession, NO_MECH,
             CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *), slots[0], 6, 0, 0, &s))
        die("C_OpenSession");
    if (CALL(m, PH_SETUP, I_Login, NO_MECH, CK_RV (*)(CK_SESSION_HANDLE, unsigned long, unsigned char *, CK_ULONG),
             s, 1, (unsigned char *)"1234", 4))
        die("C_Login");
    return s;
}

static void teardown(int m, CK_SESSION_HANDLE s) {
    CALL(m, PH_TEARDOWN, I_Logout, NO_MECH, CK_RV (*)(CK_SESSION_HANDLE), s);
    CALL(m, PH_TEARDOWN, I_CloseSession, NO_MECH, CK_RV (*)(CK_SESSION_HANDLE), s);
    CALL(m, PH_TEARDOWN, I_Finalize, NO_MECH, CK_RV (*)(void *), NULL);
}

static CK_OBJECT_HANDLE keygen(int m, CK_SESSION_HANDLE s, unsigned long mech, unsigned long key_type,
                               unsigned long usage_attr) {
    unsigned long cls = 4 /* CKO_SECRET_KEY */, len = 32;
    unsigned char yes = 1, no = 0;
    CK_ATTRIBUTE t[] = {
        {0x0 /* CKA_CLASS */, &cls, sizeof cls},
        {0x100 /* CKA_KEY_TYPE */, &key_type, sizeof key_type},
        {0x161 /* CKA_VALUE_LEN */, &len, sizeof len},
        {0x1 /* CKA_TOKEN */, &no, 1},
        {usage_attr, &yes, 1},
    };
    CK_MECHANISM mm = {mech, 0, 0};
    CK_OBJECT_HANDLE h = 0;
    CALL(m, PH_MAIN, I_GenerateKey, mech,
         CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *), s, &mm, t,
         5, &h);
    return h;
}

/* One iteration: 10 table calls, mechanisms 0x250 0x1080 0x1087 0x350 0x251. */
static void iteration(int m, CK_SESSION_HANDLE s) {
    unsigned char in[64] = {1}, out[128];
    CK_ULONG ol;
    CK_MECHANISM digest = {CKM_SHA256, 0, 0};
    CALL(m, PH_MAIN, I_DigestInit, CKM_SHA256, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *), s, &digest);
    ol = sizeof out;
    CALL(m, PH_MAIN, I_Digest, CKM_SHA256,
         CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *), s, in, sizeof in,
         out, &ol);

    CK_OBJECT_HANDLE aes = keygen(m, s, CKM_AES_KEY_GEN, 0x1f /* CKK_AES */, 0x104 /* CKA_ENCRYPT */);
    unsigned char iv[12] = {7};
    CK_GCM_PARAMS gcm = {iv, sizeof iv, 96, NULL, 0, 128};
    CK_MECHANISM enc = {CKM_AES_GCM, &gcm, sizeof gcm};
    CALL(m, PH_MAIN, I_EncryptInit, CKM_AES_GCM, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE),
         s, &enc, aes);
    ol = sizeof out;
    CALL(m, PH_MAIN, I_Encrypt, CKM_AES_GCM,
         CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *), s, in, 32, out,
         &ol);

    CK_OBJECT_HANDLE mac = keygen(m, s, CKM_GENERIC_SECRET_KEY_GEN, 0x10 /* CKK_GENERIC_SECRET */,
                                  0x108 /* CKA_SIGN */);
    CK_MECHANISM hmac = {CKM_SHA256_HMAC, 0, 0};
    CALL(m, PH_MAIN, I_SignInit, CKM_SHA256_HMAC,
         CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE), s, &hmac, mac);
    ol = sizeof out;
    CALL(m, PH_MAIN, I_Sign, CKM_SHA256_HMAC,
         CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *), s, in, sizeof in,
         out, &ol);

    CALL(m, PH_MAIN, I_DestroyObject, NO_MECH, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE), s, aes);
    CALL(m, PH_MAIN, I_DestroyObject, NO_MECH, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE), s, mac);
}

struct options {
    const char *mode, *gate, *chain;
    long iters, delay_ms, sleep_us;
    int hold, late;
};
static struct options opt = {.gate = "-", .iters = 4};

static void hold_if_asked(void) {
    if (!opt.hold) return;
    while (!stop) pause();
}

static void done_ok(void) {
    printf("DONE " HEAD " status=ok\n", HEAD_ARGS);
    fflush(stdout);
}

/* The mech generation over every module: setup all, gate, main, teardown. */
static void mech_generation(long iters, int gated) {
    CK_SESSION_HANDLE s[MAX_MODULES];
    if (!opt.late)
        for (int m = 0; m < module_count; m++) { load_module(m); bind_module(m); s[m] = setup(m); }
    flush_ledger();
    if (gated) {
        printf("READY " HEAD "\n", HEAD_ARGS);
        fflush(stdout);
        wait_gate(opt.gate);
    }
    if (opt.late) {
        for (int m = 0; m < module_count; m++) load_module(m);
        sleep_ms(opt.delay_ms);
        for (int m = 0; m < module_count; m++) { bind_module(m); s[m] = setup(m); }
    } else {
        sleep_ms(opt.delay_ms);
    }
    for (int m = 0; m < module_count; m++)
        for (long i = 0; i < iters * (m + 1); i++) {
            iteration(m, s[m]);
            if (opt.sleep_us > 0) usleep((useconds_t)opt.sleep_us);
        }
    flush_ledger();
    for (int m = 0; m < module_count; m++) teardown(m, s[m]);
    flush_ledger();
}

static char **saved_argv;
static int saved_argc;

struct exec_request { const char *path; char **argv; };
static void *exec_from_thread(void *arg) {
    struct exec_request *r = arg;
    execv(r->path, r->argv);
    die("non-leader execv failed");
}

/* Exec the first --chain step with the remaining steps and gen+1. */
static void exec_next(void) {
    if (!opt.chain || !*opt.chain) return;
    char step[PATH_MAX + 16];
    const char *comma = strchr(opt.chain, ',');
    size_t len = comma ? (size_t)(comma - opt.chain) : strlen(opt.chain);
    if (len >= sizeof step) die("--chain step too long");
    memcpy(step, opt.chain, len);
    step[len] = 0;
    const char *rest = comma ? comma + 1 : "";
    char *colon = strchr(step, ':');
    if (!colon) die("--chain step must be HOW:EXE");
    *colon = 0;
    const char *how = step, *exe = colon + 1;
    int thread = !strcmp(how, "thread");
    if (!thread && strcmp(how, "leader")) die("--chain HOW must be leader or thread");
    char genbuf[16];
    snprintf(genbuf, sizeof genbuf, "%d", gen + 1);
    char **argv = calloc((size_t)saved_argc + 8, sizeof *argv);
    int k = 0;
    argv[k++] = (char *)exe;
    for (int i = 1; i < saved_argc; i++) {
        if (!strcmp(saved_argv[i], "--chain") || !strcmp(saved_argv[i], "--gen") ||
            !strcmp(saved_argv[i], "--gate")) { i++; continue; }
        argv[k++] = saved_argv[i];
    }
    argv[k++] = "--gen"; argv[k++] = genbuf;
    if (*rest) { argv[k++] = "--chain"; argv[k++] = (char *)rest; }
    argv[k] = NULL;
    printf("EXEC " HEAD " how=%s next=%s\n", HEAD_ARGS, how, exe);
    fflush(stdout);
    if (!thread) { execv(exe, argv); die("execv failed"); }
    struct exec_request r = {exe, argv};
    pthread_t t;
    if (pthread_create(&t, NULL, exec_from_thread, &r)) die("pthread_create");
    pthread_join(t, NULL); /* never returns: the worker's exec replaces this thread group */
    die("non-leader exec returned");
}

static CK_SESSION_HANDLE lx_session;
static void *leader_exit_worker(void *arg) {
    (void)arg;
    /* Give the leader time to become a zombie before the first call, and record
     * what the kernel says about it: the cell is only meaningful with a Z leader. */
    sleep_ms(200);
    char buf[512], state = '?';
    FILE *f = fopen("/proc/self/stat", "r");
    if (f && fgets(buf, sizeof buf, f)) {
        char *p = strrchr(buf, ')');
        if (p && p[1] == ' ') state = p[2];
    }
    if (f) fclose(f);
    printf("ZOMBIE " HEAD " state=%c t=%lu\n", HEAD_ARGS, state, now_ns());
    fflush(stdout);
    wait_gate(opt.gate);
    sleep_ms(opt.delay_ms);
    for (long i = 0; i < opt.iters; i++) {
        iteration(0, lx_session);
        if (opt.sleep_us > 0) usleep((useconds_t)opt.sleep_us);
    }
    flush_ledger();
    teardown(0, lx_session);
    flush_ledger();
    done_ok();
    hold_if_asked();
    exit(0);
}

int main(int argc, char **argv) {
    saved_argc = argc;
    saved_argv = argv;
    if (argc < 2) {
        fprintf(stderr, "usage: inventory-ledger mech|map|exec-chain|held|leader-exit --cell LABEL "
                        "[--module P]... [--iters N] [--gate F|-] [--hold] [--late] [--delay-ms N] "
                        "[--sleep-us N] [--chain HOW:EXE,...]\n");
        return 2;
    }
    opt.mode = argv[1];
    for (int i = 2; i < argc; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--hold")) { opt.hold = 1; continue; }
        if (!strcmp(a, "--late")) { opt.late = 1; continue; }
        if (!v) { fprintf(stderr, "missing value for %s\n", a); return 2; }
        i++;
        if (!strcmp(a, "--cell")) cell = v;
        else if (!strcmp(a, "--module")) {
            if (module_count == MAX_MODULES) { fprintf(stderr, "too many --module\n"); return 2; }
            snprintf(modules[module_count++].path, PATH_MAX, "%s", v);
        } else if (!strcmp(a, "--iters")) opt.iters = atol(v);
        else if (!strcmp(a, "--gate")) opt.gate = v;
        else if (!strcmp(a, "--delay-ms")) opt.delay_ms = atol(v);
        else if (!strcmp(a, "--sleep-us")) opt.sleep_us = atol(v);
        else if (!strcmp(a, "--chain")) opt.chain = v;
        else if (!strcmp(a, "--gen")) gen = atoi(v);
        else { fprintf(stderr, "unknown option %s\n", a); return 2; }
    }
    if (has_space(cell)) { fprintf(stderr, "--cell must not contain whitespace or '='\n"); return 2; }
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    read_identity();
    printf("IDENT " HEAD "\n", HEAD_ARGS);
    fflush(stdout);

    if (!strcmp(opt.mode, "mech")) {
        if (!module_count) die("mech needs --module");
        mech_generation(opt.iters, 1);
        done_ok();
        hold_if_asked();
        return 0;
    }
    if (!strcmp(opt.mode, "map")) {
        if (!module_count) die("map needs --module");
        for (int m = 0; m < module_count; m++) load_module(m);
        printf("READY " HEAD "\n", HEAD_ARGS);
        fflush(stdout);
        wait_gate(opt.gate);
        flush_ledger();
        done_ok();
        hold_if_asked();
        return 0;
    }
    if (!strcmp(opt.mode, "exec-chain")) {
        if (module_count != 1) die("exec-chain needs exactly one --module");
        if (opt.late) die("exec-chain does not take --late");
        /* Generation k runs ITERS*(k+1) iterations, so every image's count is distinct. */
        mech_generation(opt.iters * (gen + 1), gen == 0);
        done_ok();
        if (opt.chain && *opt.chain) {
            /* A quiet gap on both sides of every exec, so a witness timestamp
             * can only fall inside one image's call window. */
            sleep_ms(opt.delay_ms);
            exec_next();
        }
        hold_if_asked();
        return 0;
    }
    if (!strcmp(opt.mode, "held")) {
        if (module_count != 1) die("held needs exactly one --module (the blocking provider)");
        load_module(0);
        bind_module(0);
        flush_ledger();
        printf("READY " HEAD "\n", HEAD_ARGS);
        fflush(stdout);
        wait_gate(opt.gate);
        enter(0, I_WaitForSlotEvent, NO_MECH, PH_HELD);
        flush_ledger();
        printf("HELD " HEAD " module=%s fn=C_WaitForSlotEvent t=%lu\n", HEAD_ARGS, modules[0].path, now_ns());
        fflush(stdout);
        CK_RV rv = ((CK_RV (*)(void))modules[0].fns[I_WaitForSlotEvent])();
        returned(0, I_WaitForSlotEvent, NO_MECH, PH_HELD, rv);
        printf("RETURNED " HEAD " fn=C_WaitForSlotEvent t=%lu rv=0x%lx\n", HEAD_ARGS, now_ns(), rv);
        flush_ledger();
        done_ok();
        return 0;
    }
    if (!strcmp(opt.mode, "leader-exit")) {
        if (module_count != 1) die("leader-exit needs exactly one --module");
        load_module(0);
        bind_module(0);
        lx_session = setup(0);
        flush_ledger();
        printf("READY " HEAD "\n", HEAD_ARGS);
        fflush(stdout);
        pthread_t t;
        if (pthread_create(&t, NULL, leader_exit_worker, NULL)) die("pthread_create");
        pthread_exit(NULL);
    }
    fprintf(stderr, "unknown mode %s\n", opt.mode);
    return 2;
}
#endif /* INVENTORY_LEDGER_HELD_PROVIDER */
