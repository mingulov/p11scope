/* SPDX-License-Identifier: GPL-3.0-or-later */
/* S1/Joint throughput driver: paced SoftHSM digest or keyed HMAC-sign
 * calls with per-call ledgers.
 *
 * Usage: gen-calls PROVIDER MODE RATE DURATION_S LEDGER [GO_FILE [FINISH_FILE]]
 *   PROVIDER    SoftHSM library path to dlopen and drive
 *   MODE        single (one worker) or churn (waves of short-lived threads),
 *               or keyed / keyed-churn (the same shapes over one HMAC key
 *               per worker instead of digest calls)
 *   RATE        1k, 10k or 100k (paced PKCS#11 calls per second)
 *   DURATION_S  hot-loop seconds, 1..3600 (gated cells need >= 2)
 *   LEDGER      single/keyed: hot-loop ledger JSONL path; churn/keyed-churn:
 *               filename prefix, one PREFIX.t<nn>.jsonl per worker thread.
 *               Teardown is ledgered beside the hot ledgers (2 calls
 *               single/keyed, 9 churn/keyed-churn); keyed modes also ledger
 *               their observed setup beside the hot ledgers (4 calls
 *               keyed, 11 keyed-churn). Pass every emitted file to --ledger.
 *   GO_FILE     optional gate path: print READY, wait for the path, run
 *   FINISH_FILE optional active-target gate, initially absent. After all
 *               healthy hot/teardown ledgers close, print/flush DONE and
 *               wait before dlclose/exit, with no further PKCS#11 calls.
 *               The controller must prove the original PID/mapping stays
 *               held through observer drain, then create this path.
 *
 * Also: gen-calls --help (usage, exit 0) and gen-calls --dry-run with the
 * same arguments (print the call/thread/ledger plan, exit 0). Both need
 * no provider.
 *
 * Setup (C_Initialize, first token slot, one session per concurrent
 * worker) runs before READY. Digest modes never ledger it: setup
 * causally precedes the observer's attach, so it stays outside the
 * compared window. Keyed modes ledger it in its own T0-valid file
 * (<base>-setup.jsonl): the Joint flow execs this process after the
 * observer seals its linked lane, so every setup call is observed and
 * must be conserved. When GEN_CALLS_SETUP_GATE names a path, this
 * process prints MAPPED and waits for that path after dlopen but
 * before its first provider call, so the observer can admit the
 * fresh mapping before first use (first use after admission keeps
 * the usage edge counted; use before admission voids it for good).
 * The hot loop is ledgered per worker: digest modes
 * run repeated single-part C_DigestInit + C_Digest operations under
 * CKM_SHA_256, two ledgered calls per op, on a fixed 64-byte input;
 * keyed modes create one session generic-secret key per worker after
 * GO (ledgered C_GenerateKey), run repeated single-part C_SignInit +
 * C_Sign operations under CKM_SHA256_HMAC, two ledgered calls per op,
 * on a fixed 64-byte input, then destroy the key (ledgered
 * C_DestroyObject). Teardown (C_CloseSession per session plus
 * C_Finalize) runs after the hot loop while the observer is still
 * attached, so it is ledgered too, in its own T0-valid file: single
 * and keyed modes write <LEDGER minus a trailing .jsonl>-teardown.jsonl
 * (2 calls), churn modes <PREFIX>-teardown.jsonl (8 closes + finalize).
 * Every ledgered row carries CLOCK_MONOTONIC t0/t1 stamps in the T0
 * per-call shape (ready, call, ack), one ready row per file, so every
 * emitted file validates with scripts/joint-ledger-oracle.py unchanged.
 *
 * Gated comparisons need DURATION_S >= 2: workers pace 5% above nominal
 * on absolute deadlines, so a 1 s run ends near 0.95 s with no full 1 s
 * window, and the comparison refuses it. Use 1 s runs as --min-rate 0
 * smoke only.
 *
 * GO/FINISH waits poll every 10 ms and are signal-interruptible; neither
 * has an internal timeout. Qualification requires the controller's one
 * absolute 30 s supervisor deadline from before process launch (never
 * renewed at DONE), with timeout -> TERM and reap. FINISH mode qualifies
 * active throughput, not exit coverage; the default immediate exit stays
 * available for the separate lifecycle/count regression.
 *
 * Pacing aims 5% above nominal on absolute CLOCK_MONOTONIC deadlines,
 * so scheduling jitter and churn wave boundaries cannot push a full 1 s
 * window under the nominal rate; a worker that falls behind skips sleep
 * and never bursts to catch up. Churn mode runs WAVES sequential waves
 * of 8 threads (one
 * pre-opened session per wave slot, so threads share no operation
 * state); each thread writes its own ledger file.
 *
 * Exit 0 when every ledgered call returned CKR_OK, 1 when the ledgers
 * are complete but some call did not (or a stop flag cut the run short
 * with a valid partial ledger), 2 on usage, setup or ledger failure.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;

typedef struct {
    unsigned long mechanism;
    void *parameter;
    unsigned long parameter_len;
} CK_MECHANISM;

typedef struct {
    unsigned long type;
    void *value;
    unsigned long value_len;
} CK_ATTRIBUTE;

#define CKR_OK 0ul
#define CK_TRUE 1
#define CKF_SERIAL_SESSION 0x00000004ul
#define CKF_RW_SESSION 0x00000002ul
#define CKM_SHA_256 0x00000250ul
#define CKM_SHA256_HMAC 0x00000251ul
#define CKM_GENERIC_SECRET_KEY_GEN 0x00000350ul
#define CKO_SECRET_KEY 0x00000004ul
#define CKK_GENERIC_SECRET 0x00000010ul
#define CKA_CLASS 0x00000000ul
#define CKA_TOKEN 0x00000001ul
#define CKA_PRIVATE 0x00000002ul
#define CKA_KEY_TYPE 0x00000100ul
#define CKA_SIGN 0x00000108ul
#define CKA_VALUE_LEN 0x00000161ul
#define KEY_BYTES 32
#define SIGNATURE_BYTES 64

/* T0 ledger ceiling (scripts/joint-ledger-oracle.py MAX_CALLS): no emitted
 * file may hold more calls, so every file validates unchanged. Test-tool
 * limit only (10k/60s needs 600k); not a product limit. */
#define MAX_CALLS_PER_LEDGER 700000ul
#define MAX_DURATION_S 3600ul
/* Paced 5% above nominal: scheduling jitter and churn wave boundaries
 * cannot sink a full window under the named floor. */
#define PACE_NUMERATOR 100ull
#define PACE_DENOMINATOR 105ull
#define CHURN_THREADS_PER_WAVE 8ul
#define CHURN_MIN_WAVES 4ul
#define INPUT_BYTES 64
#define DIGEST_BYTES 64

typedef CK_RV (*fn_initialize)(void *);
typedef CK_RV (*fn_finalize)(void *);
typedef CK_RV (*fn_get_slot_list)(int, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open_session)(CK_SLOT_ID, CK_FLAGS, void *, void *,
                                 CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close_session)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_digest_init)(CK_SESSION_HANDLE, CK_MECHANISM *);
typedef CK_RV (*fn_digest)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *,
                           CK_ULONG *);
typedef CK_RV (*fn_generate_key)(CK_SESSION_HANDLE, CK_MECHANISM *,
                                 CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (*fn_sign_init)(CK_SESSION_HANDLE, CK_MECHANISM *,
                              CK_OBJECT_HANDLE);
typedef CK_RV (*fn_sign)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *,
                         CK_ULONG *);
typedef CK_RV (*fn_destroy_object)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);

static volatile sig_atomic_t stop;

/* SoftHSM 2.6 faults on concurrent C_Digest calls from distinct sessions
 * (a shared map insert inside C_Digest), so each provider call runs under
 * one lock. The observed load shape is unchanged: the call rate, the
 * thread churn and the per-thread ledgers stay exactly as paced; only
 * in-provider overlap is gone. Single mode takes the same lock
 * uncontended, keeping one code path. */
static pthread_mutex_t crypto_lock = PTHREAD_MUTEX_INITIALIZER;

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

static void sleep_until_ns(uint64_t deadline) {
    struct timespec point;
    point.tv_sec = (time_t)(deadline / 1000000000u);
    point.tv_nsec = (long)(deadline % 1000000000u);
    (void)clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &point, NULL);
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

/* A gate released before DONE cannot establish a held active target. */
static int finish_is_absent(const char *path) {
    if (path[0] != '\0' && access(path, F_OK) != 0 && errno == ENOENT) {
        return 1;
    }
    fprintf(stderr, "gen-calls: finish gate must be absent before DONE\n");
    return 0;
}

static int parse_duration(const char *text, unsigned long *out) {
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
    if (errno != 0 || *end != '\0' || value == 0 || value > MAX_DURATION_S) {
        return -1;
    }
    *out = value;
    return 0;
}

static int parse_rate(const char *text, unsigned long *out) {
    if (strcmp(text, "1k") == 0) {
        *out = 1000;
        return 0;
    }
    if (strcmp(text, "10k") == 0) {
        *out = 10000;
        return 0;
    }
    if (strcmp(text, "100k") == 0) {
        *out = 100000;
        return 0;
    }
    return -1;
}

static void usage(const char *name) {
    printf("usage: %s PROVIDER MODE RATE DURATION_S LEDGER [GO_FILE [FINISH_FILE]]\n"
           "  PROVIDER    SoftHSM library path to dlopen and drive\n"
           "  MODE        single (one worker) or churn (thread waves);\n"
           "              keyed / keyed-churn run the same shapes over one\n"
           "              HMAC key per worker (GenerateKey, paced SignInit +\n"
           "              Sign under CKM_SHA256_HMAC, DestroyObject)\n"
           "  RATE        1k, 10k or 100k paced calls per second\n"
           "  DURATION_S  hot-loop seconds, 1..3600; gated cells need >= 2\n"
           "              (1 s runs are --min-rate 0 smoke only)\n"
           "  LEDGER      single/keyed: hot-loop ledger path;\n"
           "              churn/keyed-churn: filename prefix (one\n"
           "              PREFIX.t<nn>.jsonl per worker).\n"
           "              Teardown (closes + finalize) is ledgered beside\n"
           "              the hot ledgers: 2 calls single/keyed, 9 churn.\n"
           "              Keyed modes also ledger their observed setup\n"
           "              beside the hot ledgers: 4 calls keyed, 11\n"
           "              keyed-churn.\n"
           "  GO_FILE     optional gate: print READY, wait for it, run\n"
           "  FINISH_FILE optional initially absent gate: healthy closed ledgers,\n"
           "              flush DONE, wait before dlclose/exit; no further calls.\n"
           "              No internal deadline: requires one absolute 30 s\n"
           "              process supervisor from launch, then TERM/reap.\n"
           "  %s --help | --dry-run PROVIDER MODE RATE DURATION_S LEDGER "
           "[GO_FILE [FINISH_FILE]]\n"
           "GEN_CALLS_SETUP_GATE optional env path: after dlopen, print\n"
           "              MAPPED and wait for the path before the first\n"
           "              provider call\n",
           name, name);
}

struct provider {
    void *handle;
    fn_initialize initialize;
    fn_finalize finalize;
    fn_get_slot_list get_slot_list;
    fn_open_session open_session;
    fn_close_session close_session;
    fn_digest_init digest_init;
    fn_digest digest;
    fn_generate_key generate_key;
    fn_sign_init sign_init;
    fn_sign sign;
    fn_destroy_object destroy_object;
};

static int open_provider(const char *path, struct provider *out, int keyed) {
    memset(out, 0, sizeof *out);
    out->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (out->handle == NULL) {
        fprintf(stderr, "gen-calls: cannot open provider: %s\n", dlerror());
        return -1;
    }
    out->initialize = (fn_initialize)dlsym(out->handle, "C_Initialize");
    out->finalize = (fn_finalize)dlsym(out->handle, "C_Finalize");
    out->get_slot_list = (fn_get_slot_list)dlsym(out->handle, "C_GetSlotList");
    out->open_session = (fn_open_session)dlsym(out->handle, "C_OpenSession");
    out->close_session = (fn_close_session)dlsym(out->handle, "C_CloseSession");
    out->digest_init = (fn_digest_init)dlsym(out->handle, "C_DigestInit");
    out->digest = (fn_digest)dlsym(out->handle, "C_Digest");
    out->generate_key = (fn_generate_key)dlsym(out->handle, "C_GenerateKey");
    out->sign_init = (fn_sign_init)dlsym(out->handle, "C_SignInit");
    out->sign = (fn_sign)dlsym(out->handle, "C_Sign");
    out->destroy_object = (fn_destroy_object)dlsym(out->handle, "C_DestroyObject");
    if (out->initialize == NULL || out->finalize == NULL ||
        out->get_slot_list == NULL || out->open_session == NULL ||
        out->close_session == NULL) {
        fprintf(stderr, "gen-calls: provider lacks a required entry point\n");
        dlclose(out->handle);
        return -1;
    }
    if (keyed) {
        if (out->generate_key == NULL || out->sign_init == NULL ||
            out->sign == NULL || out->destroy_object == NULL) {
            fprintf(stderr, "gen-calls: provider lacks a keyed entry point\n");
            dlclose(out->handle);
            return -1;
        }
    } else {
        if (out->digest_init == NULL || out->digest == NULL) {
            fprintf(stderr, "gen-calls: provider lacks a digest entry point\n");
            dlclose(out->handle);
            return -1;
        }
    }
    return 0;
}

struct worker_arg {
    struct provider *provider;
    CK_SESSION_HANDLE session;
    unsigned long ops;
    uint64_t span_ns;
    const char *ledger_path;
    int keyed;
    /* Out: 0 ok, 1 unhealthy call seen, 2 ledger failure. */
    int status;
    unsigned long unhealthy;
};

/* Ledgered key creation for one keyed worker: a session generic-secret
 * HMAC key (public, so no login), stamped like every other call. The
 * handle starts 0; when creation fails the worker still runs its paced
 * sign operations against it, so the ledger keeps its uniform shape and
 * the unhealthy returns fail the run at comparison. */
static int ledger_generate_key(struct worker_arg *arg, FILE *ledger,
                               unsigned long *seq, int pid, int tid,
                               CK_OBJECT_HANDLE *key) {
    CK_ULONG klass = CKO_SECRET_KEY;
    CK_ULONG key_type = CKK_GENERIC_SECRET;
    CK_BYTE off = 0;
    CK_BYTE on = 1;
    CK_ULONG value_len = KEY_BYTES;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS, &klass, sizeof klass},
        {CKA_KEY_TYPE, &key_type, sizeof key_type},
        {CKA_TOKEN, &off, sizeof off},
        {CKA_PRIVATE, &off, sizeof off},
        {CKA_VALUE_LEN, &value_len, sizeof value_len},
        {CKA_SIGN, &on, sizeof on},
    };
    CK_MECHANISM keygen;
    keygen.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
    keygen.parameter = NULL;
    keygen.parameter_len = 0;
    uint64_t t0 = 0, t1 = 0;
    if (clock_ns(&t0) != 0) {
        return -1;
    }
    if (pthread_mutex_lock(&crypto_lock) != 0) {
        return -1;
    }
    CK_RV rv = arg->provider->generate_key(arg->session, &keygen, tmpl,
                                           sizeof tmpl / sizeof tmpl[0], key);
    int stamped = clock_ns(&t1) == 0;
    if (pthread_mutex_unlock(&crypto_lock) != 0) {
        return -1;
    }
    if (!stamped) {
        return -1;
    }
    (*seq)++;
    arg->unhealthy += rv != CKR_OK;
    return fprintf(ledger,
                   "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_GenerateKey\","
                   "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                   ",\"t1\":%" PRIu64 "}\n",
                   *seq, (unsigned long)rv, pid, tid, t0, t1) < 0 ? -1 : 0;
}

/* Ledgered key destruction for one keyed worker. */
static int ledger_destroy_key(struct worker_arg *arg, FILE *ledger,
                              unsigned long *seq, int pid, int tid,
                              CK_OBJECT_HANDLE key) {
    uint64_t t0 = 0, t1 = 0;
    if (clock_ns(&t0) != 0) {
        return -1;
    }
    if (pthread_mutex_lock(&crypto_lock) != 0) {
        return -1;
    }
    CK_RV rv = arg->provider->destroy_object(arg->session, key);
    int stamped = clock_ns(&t1) == 0;
    if (pthread_mutex_unlock(&crypto_lock) != 0) {
        return -1;
    }
    if (!stamped) {
        return -1;
    }
    (*seq)++;
    arg->unhealthy += rv != CKR_OK;
    return fprintf(ledger,
                   "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_DestroyObject\","
                   "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                   ",\"t1\":%" PRIu64 "}\n",
                   *seq, (unsigned long)rv, pid, tid, t0, t1) < 0 ? -1 : 0;
}

/* One keyed worker's paced sign operations: C_SignInit + C_Sign under
 * CKM_SHA256_HMAC on the worker's key, two ledgered calls per op, on
 * absolute deadlines 5% above nominal like the digest loop. Returns 0,
 * or -1 when stamping, locking or emission fails. */
static int run_keyed_ops(struct worker_arg *arg, FILE *ledger,
                         unsigned long *seq, int pid, int tid, uint64_t start,
                         uint64_t period, CK_OBJECT_HANDLE key) {
    CK_BYTE input[INPUT_BYTES];
    CK_BYTE signature[SIGNATURE_BYTES];
    for (size_t i = 0; i < sizeof input; i++) {
        input[i] = (CK_BYTE)i;
    }
    for (unsigned long op = 1; op <= arg->ops && !stop; op++) {
        sleep_until_ns(start + op * period);
        if (stop) {
            break;
        }
        CK_MECHANISM mechanism;
        mechanism.mechanism = CKM_SHA256_HMAC;
        mechanism.parameter = NULL;
        mechanism.parameter_len = 0;
        uint64_t t0 = 0, t1 = 0;
        if (clock_ns(&t0) != 0) {
            return -1;
        }
        if (pthread_mutex_lock(&crypto_lock) != 0) {
            return -1;
        }
        CK_RV rv = arg->provider->sign_init(arg->session, &mechanism, key);
        int stamped = clock_ns(&t1) == 0;
        if (pthread_mutex_unlock(&crypto_lock) != 0) {
            return -1;
        }
        if (!stamped) {
            return -1;
        }
        (*seq)++;
        arg->unhealthy += rv != CKR_OK;
        if (fprintf(ledger,
                    "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_SignInit\","
                    "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                    ",\"t1\":%" PRIu64 "}\n",
                    *seq, (unsigned long)rv, pid, tid, t0, t1) < 0) {
            return -1;
        }
        if (clock_ns(&t0) != 0) {
            return -1;
        }
        CK_ULONG out_len = sizeof signature;
        if (pthread_mutex_lock(&crypto_lock) != 0) {
            return -1;
        }
        rv = arg->provider->sign(arg->session, input, sizeof input,
                                 signature, &out_len);
        stamped = clock_ns(&t1) == 0;
        if (pthread_mutex_unlock(&crypto_lock) != 0) {
            return -1;
        }
        if (!stamped) {
            return -1;
        }
        (*seq)++;
        arg->unhealthy += rv != CKR_OK;
        if (fprintf(ledger,
                    "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_Sign\","
                    "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                    ",\"t1\":%" PRIu64 "}\n",
                    *seq, (unsigned long)rv, pid, tid, t0, t1) < 0) {
            return -1;
        }
    }
    return 0;
}

/* One worker: pace thread_ops digest ops over span_ns into its own T0
 * ledger. Returns through arg->status; partial ledgers on stop stay
 * valid (ack carries the rows actually written). */
static void *run_worker(void *raw) {
    struct worker_arg *arg = raw;
    CK_BYTE input[INPUT_BYTES];
    CK_BYTE digest[DIGEST_BYTES];
    for (size_t i = 0; i < sizeof input; i++) {
        input[i] = (CK_BYTE)i;
    }
    FILE *ledger = fopen(arg->ledger_path, "w");
    if (ledger == NULL) {
        fprintf(stderr, "gen-calls: cannot open ledger %s: %s\n",
                arg->ledger_path, strerror(errno));
        arg->status = 2;
        return NULL;
    }
    int pid = (int)getpid();
    int tid = (int)gettid();
    uint64_t start = 0;
    if (clock_ns(&start) != 0) {
        fprintf(stderr, "gen-calls: clock read failed\n");
        fclose(ledger);
        arg->status = 2;
        return NULL;
    }
    /* Per-op period, 5% above nominal: span*100/(ops*105). The planner
     * guarantees at least one op per worker, so this never divides by 0. */
    uint64_t period =
        arg->span_ns * PACE_NUMERATOR / ((uint64_t)arg->ops * PACE_DENOMINATOR);
    int failed = fprintf(ledger,
                         "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                         ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                         pid, tid, start) < 0;
    unsigned long seq = 0;
    CK_OBJECT_HANDLE key = 0;
    if (arg->keyed && ledger_generate_key(arg, ledger, &seq, pid, tid, &key) != 0) {
        failed = 1;
    }
    if (arg->keyed) {
        if (!failed && run_keyed_ops(arg, ledger, &seq, pid, tid, start,
                                     period, key) != 0) {
            failed = 1;
        }
        if (!failed && ledger_destroy_key(arg, ledger, &seq, pid, tid, key) != 0) {
            failed = 1;
        }
    }
    for (unsigned long op = 1; !arg->keyed && op <= arg->ops && !failed && !stop; op++) {
        sleep_until_ns(start + op * period);
        if (stop) {
            break;
        }
        CK_MECHANISM mechanism;
        mechanism.mechanism = CKM_SHA_256;
        mechanism.parameter = NULL;
        mechanism.parameter_len = 0;
        uint64_t t0 = 0, t1 = 0;
        if (clock_ns(&t0) != 0) {
            failed = 1;
            break;
        }
        if (pthread_mutex_lock(&crypto_lock) != 0) {
            failed = 1;
            break;
        }
        CK_RV rv = arg->provider->digest_init(arg->session, &mechanism);
        int stamped = clock_ns(&t1) == 0;
        if (pthread_mutex_unlock(&crypto_lock) != 0) {
            failed = 1;
            break;
        }
        if (!stamped) {
            failed = 1;
            break;
        }
        seq++;
        arg->unhealthy += rv != CKR_OK;
        if (fprintf(ledger,
                    "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_DigestInit\","
                    "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                    ",\"t1\":%" PRIu64 "}\n",
                    seq, (unsigned long)rv, pid, tid, t0, t1) < 0) {
            failed = 1;
            break;
        }
        if (clock_ns(&t0) != 0) {
            failed = 1;
            break;
        }
        CK_ULONG out_len = sizeof digest;
        if (pthread_mutex_lock(&crypto_lock) != 0) {
            failed = 1;
            break;
        }
        rv = arg->provider->digest(arg->session, input, sizeof input,
                                   digest, &out_len);
        stamped = clock_ns(&t1) == 0;
        if (pthread_mutex_unlock(&crypto_lock) != 0) {
            failed = 1;
            break;
        }
        if (!stamped) {
            failed = 1;
            break;
        }
        seq++;
        arg->unhealthy += rv != CKR_OK;
        if (fprintf(ledger,
                    "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_Digest\","
                    "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                    ",\"t1\":%" PRIu64 "}\n",
                    seq, (unsigned long)rv, pid, tid, t0, t1) < 0) {
            failed = 1;
            break;
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
    if (failed) {
        fprintf(stderr, "gen-calls: ledger emission failed for %s\n",
                arg->ledger_path);
        arg->status = 2;
        return NULL;
    }
    arg->status = arg->unhealthy == 0 ? 0 : 1;
    return NULL;
}

struct plan {
    int churn;
    int keyed;
    unsigned long rate;
    unsigned long duration;
    unsigned long total_calls;
    unsigned long total_ops;
    unsigned long threads;
    unsigned long waves;
    unsigned long max_thread_calls;
};

static int make_plan(int churn, int keyed, unsigned long rate,
                     unsigned long duration, struct plan *out) {
    out->churn = churn;
    out->keyed = keyed;
    out->rate = rate;
    out->duration = duration;
    out->total_calls = rate * duration;
    if (out->total_calls % 2 != 0) {
        fprintf(stderr, "gen-calls: RATE*DURATION must be even (two calls per op)\n");
        return -1;
    }
    /* Keyed workers add one GenerateKey plus one DestroyObject per
     * thread around their paced ops; those two calls per thread come
     * out of the RATE*DURATION budget, so every emitted file still
     * fits the ledger ceiling unchanged. */
    unsigned long key_overhead = keyed ? 2 : 0;
    if (!churn) {
        out->threads = 1;
        out->waves = 1;
        if (out->total_calls < key_overhead + 2) {
            fprintf(stderr, "gen-calls: keyed needs at least one op\n");
            return -1;
        }
        out->total_ops = (out->total_calls - key_overhead) / 2;
        out->max_thread_calls = out->total_calls;
    } else {
        out->waves = duration > CHURN_MIN_WAVES ? duration : CHURN_MIN_WAVES;
        out->threads = out->waves * CHURN_THREADS_PER_WAVE;
        if (key_overhead * out->threads >= out->total_calls) {
            fprintf(stderr, "gen-calls: keyed needs at least one op per thread\n");
            return -1;
        }
        out->total_ops = (out->total_calls - key_overhead * out->threads) / 2;
        unsigned long base = out->total_ops / out->threads;
        unsigned long extra = out->total_ops % out->threads;
        if (base == 0 && extra == 0) {
            fprintf(stderr, "gen-calls: churn needs at least one op per thread\n");
            return -1;
        }
        out->max_thread_calls =
            (base + (extra > 0 ? 1 : 0)) * 2 + key_overhead;
    }
    if (out->max_thread_calls == 0 ||
        out->max_thread_calls > MAX_CALLS_PER_LEDGER) {
        fprintf(stderr,
                "gen-calls: per-thread calls %lu exceed the ledger ceiling %lu; "
                "shorten DURATION_S\n",
                out->max_thread_calls, MAX_CALLS_PER_LEDGER);
        return -1;
    }
    return 0;
}

/* Sidecar ledger path: "<base>-<tag>.jsonl", where base is the churn
 * prefix, or the single ledger path minus a trailing ".jsonl". Returns
 * 0, or -1 when the path does not fit. */
static int sidecar_path_for(int churn, const char *ledger_arg, const char *tag,
                            char *out, size_t out_size) {
    if (churn) {
        if (snprintf(out, out_size, "%s-%s.jsonl", ledger_arg, tag) >=
            (int)out_size) {
            return -1;
        }
        return 0;
    }
    static const char suffix[] = ".jsonl";
    size_t len = strlen(ledger_arg);
    size_t base = len;
    if (len > sizeof suffix - 1 &&
        strcmp(ledger_arg + len - (sizeof suffix - 1), suffix) == 0) {
        base = len - (sizeof suffix - 1);
    }
    if (snprintf(out, out_size, "%.*s-%s.jsonl", (int)base, ledger_arg, tag) >=
        (int)out_size) {
        return -1;
    }
    return 0;
}

static int teardown_path_for(int churn, const char *ledger_arg, char *out,
                             size_t out_size) {
    return sidecar_path_for(churn, ledger_arg, "teardown", out, out_size);
}

/* One observed setup call, stamped in main while it runs. */
struct setup_call {
    const char *fn;
    CK_RV rv;
    uint64_t t0;
    uint64_t t1;
};

/* At most C_Initialize, two C_GetSlotList probes and one C_OpenSession
 * per wave slot. */
#define MAX_SETUP_CALLS (1 + 2 + CHURN_THREADS_PER_WAVE)

static void record_setup(struct setup_call *calls, unsigned long *count,
                         const char *fn, CK_RV rv, uint64_t t0, uint64_t t1) {
    calls[*count].fn = fn;
    calls[*count].rv = rv;
    calls[*count].t0 = t0;
    calls[*count].t1 = t1;
    (*count)++;
}

/* Ledgered setup: C_Initialize, both C_GetSlotList probes and every
 * C_OpenSession, each stamped while it ran, written to its own
 * T0-valid ledger. Keyed modes only: the Joint flow execs this process
 * after the observer seals its linked lane, so setup is observed and
 * must be conserved. Returns 0, or -1 when the ledger is unusable. */
static int write_setup_ledger(const struct setup_call *calls,
                              unsigned long count, const char *path) {
    FILE *ledger = fopen(path, "w");
    if (ledger == NULL) {
        fprintf(stderr, "gen-calls: cannot open ledger %s: %s\n", path,
                strerror(errno));
        return -1;
    }
    int pid = (int)getpid();
    int tid = (int)gettid();
    int failed = fprintf(ledger,
                         "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                         ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                         pid, tid, calls[0].t0) < 0;
    for (unsigned long i = 0; i < count && !failed; i++) {
        if (fprintf(ledger,
                    "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"%s\","
                    "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                    ",\"t1\":%" PRIu64 "}\n",
                    i + 1, calls[i].fn, (unsigned long)calls[i].rv, pid, tid,
                    calls[i].t0, calls[i].t1) < 0) {
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
    if (failed) {
        fprintf(stderr, "gen-calls: ledger emission failed for %s\n", path);
        return -1;
    }
    return 0;
}

/* Ledgered teardown: C_CloseSession per session, then C_Finalize, each
 * stamped and written to its own T0-valid ledger. The provider calls
 * always run to completion (process hygiene), even when stamping or
 * emission fails; returns 0 with *unhealthy counting non-OK returns, or
 * -1 when the ledger is unusable. */
static int write_teardown_ledger(struct provider *provider,
                                 CK_SESSION_HANDLE *sessions,
                                 unsigned long sessions_open,
                                 const char *path,
                                 unsigned long *unhealthy) {
    *unhealthy = 0;
    FILE *ledger = fopen(path, "w");
    if (ledger == NULL) {
        fprintf(stderr, "gen-calls: cannot open ledger %s: %s\n", path,
                strerror(errno));
        for (unsigned long i = 0; i < sessions_open; i++) {
            provider->close_session(sessions[i]);
        }
        provider->finalize(NULL);
        return -1;
    }
    int pid = (int)getpid();
    int tid = (int)gettid();
    uint64_t start = 0;
    if (clock_ns(&start) != 0) {
        fprintf(stderr, "gen-calls: clock read failed\n");
        fclose(ledger);
        for (unsigned long i = 0; i < sessions_open; i++) {
            provider->close_session(sessions[i]);
        }
        provider->finalize(NULL);
        return -1;
    }
    int failed = fprintf(ledger,
                         "{\"kind\":\"ready\",\"pid\":%d,\"tid\":%d,\"t\":%" PRIu64
                         ",\"clock\":\"CLOCK_MONOTONIC\",\"unit\":\"ns\"}\n",
                         pid, tid, start) < 0;
    unsigned long seq = 0;
    unsigned long closed = 0;
    for (; closed < sessions_open && !failed;) {
        uint64_t t0 = 0, t1 = 0;
        if (clock_ns(&t0) != 0) {
            failed = 1;
            break;
        }
        CK_RV rv = provider->close_session(sessions[closed]);
        closed++;
        if (clock_ns(&t1) != 0) {
            failed = 1;
            break;
        }
        seq++;
        *unhealthy += rv != CKR_OK;
        if (fprintf(ledger,
                    "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_CloseSession\","
                    "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                    ",\"t1\":%" PRIu64 "}\n",
                    seq, (unsigned long)rv, pid, tid, t0, t1) < 0) {
            failed = 1;
            break;
        }
    }
    /* Sessions the ledgered loop did not reach still close, unledgered. */
    for (; closed < sessions_open; closed++) {
        provider->close_session(sessions[closed]);
    }
    int finalized = 0;
    if (!failed) {
        uint64_t t0 = 0, t1 = 0;
        if (clock_ns(&t0) != 0) {
            failed = 1;
        } else {
            CK_RV rv = provider->finalize(NULL);
            finalized = 1;
            if (clock_ns(&t1) != 0) {
                failed = 1;
            } else {
                seq++;
                *unhealthy += rv != CKR_OK;
                if (fprintf(ledger,
                            "{\"kind\":\"call\",\"seq\":%lu,\"fn\":\"C_Finalize\","
                            "\"rv\":%lu,\"pid\":%d,\"tid\":%d,\"t0\":%" PRIu64
                            ",\"t1\":%" PRIu64 "}\n",
                            seq, (unsigned long)rv, pid, tid, t0, t1) < 0) {
                    failed = 1;
                }
            }
        }
    }
    if (!finalized) {
        /* The finalize call above never ran; the provider still
         * finalizes, unledgered. */
        provider->finalize(NULL);
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
    if (failed) {
        fprintf(stderr, "gen-calls: ledger emission failed for %s\n", path);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *name = argc > 0 ? argv[0] : "gen-calls";
    int dry_run = 0;
    int first = 1;
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        usage(name);
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--dry-run") == 0) {
        dry_run = 1;
        first = 2;
    }
    int rest = argc - first;
    if (rest != 5 && rest != 6 && rest != 7) {
        usage(name);
        return 2;
    }
    const char *provider_path = argv[first];
    int churn;
    int keyed;
    if (strcmp(argv[first + 1], "single") == 0) {
        churn = 0;
        keyed = 0;
    } else if (strcmp(argv[first + 1], "churn") == 0) {
        churn = 1;
        keyed = 0;
    } else if (strcmp(argv[first + 1], "keyed") == 0) {
        churn = 0;
        keyed = 1;
    } else if (strcmp(argv[first + 1], "keyed-churn") == 0) {
        churn = 1;
        keyed = 1;
    } else {
        fprintf(stderr, "gen-calls: MODE must be single, churn, keyed or keyed-churn\n");
        return 2;
    }
    unsigned long rate = 0, duration = 0;
    if (parse_rate(argv[first + 2], &rate) != 0) {
        fprintf(stderr, "gen-calls: RATE must be 1k, 10k or 100k\n");
        return 2;
    }
    if (parse_duration(argv[first + 3], &duration) != 0) {
        fprintf(stderr, "gen-calls: DURATION_S must be 1..%lu\n", MAX_DURATION_S);
        return 2;
    }
    const char *ledger_arg = argv[first + 4];
    const char *gate = rest >= 6 ? argv[first + 5] : NULL;
    const char *finish = rest == 7 ? argv[first + 6] : NULL;
    struct plan plan;
    if (make_plan(churn, keyed, rate, duration, &plan) != 0) {
        return 2;
    }
    char teardown[4096];
    if (teardown_path_for(churn, ledger_arg, teardown, sizeof teardown) != 0) {
        fprintf(stderr, "gen-calls: teardown ledger path too long\n");
        return 2;
    }
    char setup[4096];
    setup[0] = '\0';
    if (keyed && sidecar_path_for(churn, ledger_arg, "setup", setup, sizeof setup) != 0) {
        fprintf(stderr, "gen-calls: setup ledger path too long\n");
        return 2;
    }
    if (dry_run) {
        if (!churn && !keyed) {
            printf("gen-calls dry run: provider=%s mode=single rate=%lu/s "
                   "duration=%lus %lu calls %lu ops threads=1 ledgers=%s "
                   "teardown=%s (2 calls)\n",
                   argv[first], rate, duration, plan.total_calls,
                   plan.total_ops, ledger_arg, teardown);
        } else if (!churn && keyed) {
            printf("gen-calls dry run: provider=%s mode=keyed rate=%lu/s "
                   "duration=%lus %lu calls %lu ops threads=1 "
                   "key=generic-secret-hmac-sha256 ledgers=%s setup=%s "
                   "(4 calls) teardown=%s (2 calls)\n",
                   argv[first], rate, duration, plan.total_calls,
                   plan.total_ops, ledger_arg, setup, teardown);
        } else if (churn && !keyed) {
            printf("gen-calls dry run: provider=%s mode=churn rate=%lu/s "
                   "duration=%lus %lu calls %lu ops threads=%lu waves=%lu "
                   "ledgers=%s.t<nn>.jsonl teardown=%s (9 calls)\n",
                   argv[first], rate, duration, plan.total_calls,
                   plan.total_ops, plan.threads, plan.waves, ledger_arg,
                   teardown);
        } else {
            printf("gen-calls dry run: provider=%s mode=keyed-churn rate=%lu/s "
                   "duration=%lus %lu calls %lu ops threads=%lu waves=%lu "
                   "key=generic-secret-hmac-sha256 ledgers=%s.t<nn>.jsonl "
                   "setup=%s (11 calls) teardown=%s (9 calls)\n",
                   argv[first], rate, duration, plan.total_calls,
                   plan.total_ops, plan.threads, plan.waves, ledger_arg,
                   setup, teardown);
        }
        return 0;
    }
    if (finish != NULL && !finish_is_absent(finish)) {
        return 2;
    }

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);

    struct provider provider;
    if (open_provider(provider_path, &provider, keyed) != 0) {
        return 2;
    }
    /* Optional admission window: the provider is mapped now, but no
     * provider call has run yet. When the controller sets
     * GEN_CALLS_SETUP_GATE, print MAPPED and wait for that path, so
     * the observer can admit the fresh mapping before first use. */
    const char *setup_gate = getenv("GEN_CALLS_SETUP_GATE");
    if (setup_gate != NULL && setup_gate[0] != '\0') {
        printf("MAPPED pid=%d\n", (int)getpid());
        fflush(stdout);
        if (wait_for_go(setup_gate) != 0) {
            dlclose(provider.handle);
            return 2;
        }
    }
    /* Keyed setup is observed (post-closure exec), so every setup call
     * is stamped while it runs and ledgered before READY. A clock or
     * ledger failure here is exit 2 like any setup failure; the digest
     * path records nothing and behaves exactly as before. */
    struct setup_call setup_calls[MAX_SETUP_CALLS];
    unsigned long setup_count = 0;
    uint64_t setup_t0 = 0, setup_t1 = 0;
    if (keyed && clock_ns(&setup_t0) != 0) {
        fprintf(stderr, "gen-calls: clock read failed\n");
        dlclose(provider.handle);
        return 2;
    }
    CK_RV setup_rv = provider.initialize(NULL);
    if (keyed) {
        if (clock_ns(&setup_t1) != 0) {
            fprintf(stderr, "gen-calls: clock read failed\n");
            dlclose(provider.handle);
            return 2;
        }
        record_setup(setup_calls, &setup_count, "C_Initialize", setup_rv,
                     setup_t0, setup_t1);
    }
    if (setup_rv != CKR_OK) {
        fprintf(stderr, "gen-calls: C_Initialize failed\n");
        dlclose(provider.handle);
        return 2;
    }
    CK_ULONG slots = 0;
    if (keyed && clock_ns(&setup_t0) != 0) {
        fprintf(stderr, "gen-calls: clock read failed\n");
        dlclose(provider.handle);
        return 2;
    }
    setup_rv = provider.get_slot_list(CK_TRUE, NULL, &slots);
    if (keyed) {
        if (clock_ns(&setup_t1) != 0) {
            fprintf(stderr, "gen-calls: clock read failed\n");
            dlclose(provider.handle);
            return 2;
        }
        record_setup(setup_calls, &setup_count, "C_GetSlotList", setup_rv,
                     setup_t0, setup_t1);
    }
    if (setup_rv != CKR_OK || slots == 0) {
        fprintf(stderr, "gen-calls: no token slot available\n");
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }
    CK_SLOT_ID *list = malloc(slots * sizeof *list);
    if (list == NULL) {
        fprintf(stderr, "gen-calls: out of memory\n");
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }
    if (keyed && clock_ns(&setup_t0) != 0) {
        fprintf(stderr, "gen-calls: clock read failed\n");
        free(list);
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }
    setup_rv = provider.get_slot_list(CK_TRUE, list, &slots);
    if (keyed) {
        if (clock_ns(&setup_t1) != 0) {
            fprintf(stderr, "gen-calls: clock read failed\n");
            free(list);
            provider.finalize(NULL);
            dlclose(provider.handle);
            return 2;
        }
        record_setup(setup_calls, &setup_count, "C_GetSlotList", setup_rv,
                     setup_t0, setup_t1);
    }
    if (setup_rv != CKR_OK || slots == 0) {
        fprintf(stderr, "gen-calls: cannot read the slot list\n");
        free(list);
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }
    CK_SLOT_ID slot = list[0];
    free(list);
    unsigned long sessions_wanted = churn ? CHURN_THREADS_PER_WAVE : 1;
    CK_SESSION_HANDLE *sessions = malloc(sessions_wanted * sizeof *sessions);
    if (sessions == NULL) {
        fprintf(stderr, "gen-calls: out of memory\n");
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }
    unsigned long sessions_open = 0;
    for (; sessions_open < sessions_wanted; sessions_open++) {
        if (keyed && clock_ns(&setup_t0) != 0) {
            fprintf(stderr, "gen-calls: clock read failed\n");
            break;
        }
        setup_rv = provider.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
                                         NULL, NULL, &sessions[sessions_open]);
        if (keyed) {
            if (clock_ns(&setup_t1) != 0) {
                fprintf(stderr, "gen-calls: clock read failed\n");
                break;
            }
            record_setup(setup_calls, &setup_count, "C_OpenSession", setup_rv,
                         setup_t0, setup_t1);
        }
        if (setup_rv != CKR_OK) {
            fprintf(stderr, "gen-calls: C_OpenSession %lu failed\n", sessions_open);
            break;
        }
    }
    if (sessions_open != sessions_wanted) {
        for (unsigned long i = 0; i < sessions_open; i++) {
            provider.close_session(sessions[i]);
        }
        free(sessions);
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }
    if (keyed && write_setup_ledger(setup_calls, setup_count, setup) != 0) {
        for (unsigned long i = 0; i < sessions_open; i++) {
            provider.close_session(sessions[i]);
        }
        free(sessions);
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }

    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (gate != NULL && wait_for_go(gate) != 0) {
        if (stop) {
            fprintf(stderr, "gen-calls: interrupted while waiting for gate\n");
        } else {
            fprintf(stderr, "gen-calls: cannot wait for gate\n");
        }
        for (unsigned long i = 0; i < sessions_open; i++) {
            provider.close_session(sessions[i]);
        }
        free(sessions);
        provider.finalize(NULL);
        dlclose(provider.handle);
        return 2;
    }

    int rc = 0;
    uint64_t span_ns = (uint64_t)duration * 1000000000u;
    if (!churn) {
        struct worker_arg arg = {
            .provider = &provider,
            .session = sessions[0],
            .ops = plan.total_ops,
            .span_ns = span_ns,
            .ledger_path = ledger_arg,
            .keyed = keyed,
            .status = 0,
            .unhealthy = 0,
        };
        run_worker(&arg);
        rc = arg.status;
        if (stop && rc == 0) {
            fprintf(stderr, "gen-calls: stopped early after %lu ops\n",
                    plan.total_ops);
            rc = 1;
        }
    } else {
        unsigned long base = plan.total_ops / plan.threads;
        unsigned long extra = plan.total_ops % plan.threads;
        uint64_t wave_span = span_ns / plan.waves;
        unsigned long thread_no = 0;
        pthread_t *wave = malloc(CHURN_THREADS_PER_WAVE * sizeof *wave);
        struct worker_arg *args =
            malloc(CHURN_THREADS_PER_WAVE * sizeof *args);
        char (*paths)[4096] = malloc(CHURN_THREADS_PER_WAVE * sizeof *paths);
        if (wave == NULL || args == NULL || paths == NULL) {
            fprintf(stderr, "gen-calls: out of memory\n");
            rc = 2;
        } else {
            for (unsigned long wave_no = 0;
                 wave_no < plan.waves && rc == 0 && !stop; wave_no++) {
                unsigned long started = 0;
                for (unsigned long slot_no = 0;
                     slot_no < CHURN_THREADS_PER_WAVE; slot_no++) {
                    if (snprintf(paths[slot_no], sizeof paths[slot_no],
                                 "%s.t%lu.jsonl", ledger_arg,
                                 thread_no) >= (int)sizeof paths[slot_no]) {
                        fprintf(stderr, "gen-calls: ledger path too long\n");
                        rc = 2;
                        break;
                    }
                    args[slot_no].provider = &provider;
                    args[slot_no].session = sessions[slot_no];
                    /* Remainder ops go to the first `extra` threads. */
                    args[slot_no].ops =
                        base + (thread_no < extra ? 1 : 0);
                    args[slot_no].span_ns = wave_span;
                    args[slot_no].ledger_path = paths[slot_no];
                    args[slot_no].keyed = keyed;
                    args[slot_no].status = 0;
                    args[slot_no].unhealthy = 0;
                    if (pthread_create(&wave[slot_no], NULL, run_worker,
                                       &args[slot_no]) != 0) {
                        fprintf(stderr, "gen-calls: cannot create thread\n");
                        rc = 2;
                        break;
                    }
                    started++;
                    thread_no++;
                }
                /* Join every thread this wave started, even after a
                 * create failure: their ledger paths stay valid until
                 * the joins below return. */
                for (unsigned long slot_no = 0; slot_no < started;
                     slot_no++) {
                    if (pthread_join(wave[slot_no], NULL) != 0) {
                        fprintf(stderr, "gen-calls: cannot join thread\n");
                        rc = 2;
                        break;
                    }
                    if (args[slot_no].status == 2) {
                        rc = 2;
                    } else if (args[slot_no].status == 1 && rc == 0) {
                        rc = 1;
                    }
                }
            }
        }
        free(wave);
        free(args);
        free(paths);
        if (stop && rc == 0) {
            fprintf(stderr, "gen-calls: stopped early\n");
            rc = 1;
        }
    }

    unsigned long teardown_unhealthy = 0;
    if (write_teardown_ledger(&provider, sessions, sessions_open, teardown,
                              &teardown_unhealthy) != 0) {
        rc = 2;
    } else if (teardown_unhealthy != 0 && rc == 0) {
        rc = 1;
    }
    if (finish != NULL && rc == 0) {
        if (stop || !finish_is_absent(finish)) {
            rc = 2;
        } else if (printf("DONE pid=%d\n", (int)getpid()) < 0 || fflush(stdout) != 0) {
            fprintf(stderr, "gen-calls: cannot flush DONE\n");
            rc = 2;
        } else if (wait_for_go(finish) != 0) {
            fprintf(stderr, "gen-calls: interrupted or cannot wait for finish gate\n");
            rc = 2;
        }
        /* write_teardown_ledger already closed/finalized the provider.
         * Finish success, interruption and failure make no PKCS#11 calls. */
    }
    free(sessions);
    dlclose(provider.handle);
    return rc;
}
