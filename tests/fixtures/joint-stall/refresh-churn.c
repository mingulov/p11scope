/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* refresh-churn: long-lived SoftHSM digest caller with exec/reload churn,
 * plus a short-lived single-operation mode for the joint-stall live cell.
 *
 * Long mode:
 *   refresh-churn PROVIDER ROUNDS CALLS_PER_ROUND DEADLINE_S
 *               [REMAINING DEADLINE_NS ACC_OPS ACC_CALLS ACC_OK]
 *   PROVIDER         SoftHSM library path to dlopen and drive
 *   ROUNDS           total digest rounds, 1..100000
 *   CALLS_PER_ROUND  digest ops per round (one op = C_DigestInit + C_Digest),
 *                    1..100000
 *   DEADLINE_S       absolute lifetime from the first start, 1..7200 seconds
 *   REMAINING, DEADLINE_NS, ACC_OPS, ACC_CALLS, ACC_OK
 *                    internal exec-chain state: rounds left, the absolute
 *                    CLOCK_MONOTONIC deadline in ns, and the accumulated
 *                    totals from prior images. Callers omit all five; the
 *                    exec step fills them.
 *
 * Each round runs CALLS_PER_ROUND single-part C_DigestInit + C_Digest ops
 * under CKM_SHA_256 on a fixed 64-byte input, then either execve's itself
 * (argv carries the remaining rounds and the absolute deadline) or
 * dlclose/dlopen's the provider, alternating starting with exec. The first
 * action after round one is exec (ImageRetired), after round two reload
 * (InstancesRetired), and so on. The run ends when the rounds are done or
 * the absolute deadline passes, whichever comes first; both bound the run.
 *
 * Short mode:
 *   refresh-churn --short PROVIDER
 * One digest op (C_DigestInit + C_Digest), then exit. For waves of
 * short-lived callers whose first call can land before their image's
 * first scan.
 *
 * Also: refresh-churn --help (usage, exit 0) and
 *   refresh-churn --dry-run PROVIDER ROUNDS CALLS_PER_ROUND DEADLINE_S
 * (print the call/round/action plan, exit 0). Both need no provider.
 *
 * Ledger lines on stdout (flushed per round):
 *   LEDGER round=<done> remaining=<left> calls=<n> ok=<n> next=<exec|reload|done> pid=<pid>
 *   DONE rounds=<done> ops=<n> calls=<n> ok=<n> pid=<pid>
 * Short mode prints one LEDGER line with mode=short. Stderr carries errors
 * only. Exit 0 when every attempted call returned CKR_OK, 1 when ledgers
 * are complete but some call failed or the deadline cut the run, 2 on
 * usage, setup or ledger failure.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV;
typedef unsigned long CK_ULONG;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;

typedef struct {
    unsigned long mechanism;
    void *parameter;
    unsigned long parameter_len;
} CK_MECHANISM;

#define CKR_OK 0ul
#define CKF_SERIAL_SESSION 0x00000004ul
#define CKM_SHA_256 0x00000250ul

#define MAX_ROUNDS 100000ul
#define MAX_CALLS_PER_ROUND 100000ul
#define MAX_DEADLINE_S 7200ul
#define INPUT_BYTES 64
#define DIGEST_BYTES 64
#define NS_PER_S 1000000000ull

typedef CK_RV (*fn_initialize)(void *);
typedef CK_RV (*fn_finalize)(void *);
typedef CK_RV (*fn_get_slot_list)(int, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open_session)(CK_SLOT_ID, CK_FLAGS, void *, void *,
                                 CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close_session)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_digest_init)(CK_SESSION_HANDLE, CK_MECHANISM *);
typedef CK_RV (*fn_digest)(CK_SESSION_HANDLE, CK_BYTE *, CK_ULONG, CK_BYTE *,
                           CK_ULONG *);

struct provider {
    void *handle;
    fn_initialize initialize;
    fn_finalize finalize;
    fn_get_slot_list get_slot_list;
    fn_open_session open_session;
    fn_close_session close_session;
    fn_digest_init digest_init;
    fn_digest digest;
};

static void usage(const char *name)
{
    printf("usage: %s PROVIDER ROUNDS CALLS_PER_ROUND DEADLINE_S "
           "[REMAINING DEADLINE_NS ACC_OPS ACC_CALLS ACC_OK]\n"
           "  PROVIDER         SoftHSM library path to dlopen and drive\n"
           "  ROUNDS           total rounds, 1..100000\n"
           "  CALLS_PER_ROUND  digest ops per round, 1..100000 "
           "(one op = C_DigestInit + C_Digest)\n"
           "  DEADLINE_S       absolute lifetime from first start, 1..7200 s\n"
           "  REMAINING ...    internal exec-chain state (omit them)\n"
           "  %s --short PROVIDER\n"
           "  %s --dry-run PROVIDER ROUNDS CALLS_PER_ROUND DEADLINE_S\n"
           "  %s --help\n",
           name, name, name, name);
}

static int clock_ns(unsigned long long *out)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return -1;
    *out = (unsigned long long)now.tv_sec * NS_PER_S +
           (unsigned long long)now.tv_nsec;
    return 0;
}

static int parse_ulong(const char *text, unsigned long min, unsigned long max,
                       unsigned long *out)
{
    if (text[0] == '\0')
        return -1;
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9')
            return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || *end != '\0' || value < min || value > max)
        return -1;
    *out = value;
    return 0;
}

static int parse_u64(const char *text, unsigned long long *out)
{
    if (text[0] == '\0')
        return -1;
    for (const unsigned char *p = (const unsigned char *)text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9')
            return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno != 0 || *end != '\0')
        return -1;
    *out = value;
    return 0;
}

static int open_provider(const char *path, struct provider *out)
{
    memset(out, 0, sizeof *out);
    out->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (out->handle == NULL) {
        fprintf(stderr, "refresh-churn: cannot open provider %s: %s\n", path,
                dlerror());
        return -1;
    }
    out->initialize = (fn_initialize)dlsym(out->handle, "C_Initialize");
    out->finalize = (fn_finalize)dlsym(out->handle, "C_Finalize");
    out->get_slot_list =
        (fn_get_slot_list)dlsym(out->handle, "C_GetSlotList");
    out->open_session =
        (fn_open_session)dlsym(out->handle, "C_OpenSession");
    out->close_session =
        (fn_close_session)dlsym(out->handle, "C_CloseSession");
    out->digest_init =
        (fn_digest_init)dlsym(out->handle, "C_DigestInit");
    out->digest = (fn_digest)dlsym(out->handle, "C_Digest");
    if (out->initialize == NULL || out->finalize == NULL ||
        out->get_slot_list == NULL || out->open_session == NULL ||
        out->close_session == NULL || out->digest_init == NULL ||
        out->digest == NULL) {
        fprintf(stderr, "refresh-churn: provider lacks a required entry point\n");
        dlclose(out->handle);
        memset(out, 0, sizeof *out);
        return -1;
    }
    return 0;
}

static void close_provider(struct provider *provider)
{
    if (provider->handle != NULL)
        dlclose(provider->handle);
    memset(provider, 0, sizeof *provider);
}

/* Bring the provider from dlopen to one open session. Returns 0 with the
 * session in *session, or -1 after printing the cause. */
static int provider_setup(struct provider *provider, CK_SESSION_HANDLE *session)
{
    if (provider->initialize(NULL) != CKR_OK) {
        fprintf(stderr, "refresh-churn: C_Initialize failed\n");
        return -1;
    }
    CK_SLOT_ID slots[64];
    CK_ULONG nslots = 64;
    if (provider->get_slot_list(1, slots, &nslots) != CKR_OK || nslots < 1) {
        fprintf(stderr, "refresh-churn: no token slot available\n");
        provider->finalize(NULL);
        return -1;
    }
    if (provider->open_session(slots[0], CKF_SERIAL_SESSION, NULL, NULL,
                               session) != CKR_OK) {
        fprintf(stderr, "refresh-churn: C_OpenSession failed\n");
        provider->finalize(NULL);
        return -1;
    }
    return 0;
}

/* One digest op: C_DigestInit + C_Digest. Adds 2 to *calls, 0..2 to *ok. */
static void digest_op(struct provider *provider, CK_SESSION_HANDLE session,
                      CK_BYTE *input, CK_BYTE *digest, unsigned long *calls,
                      unsigned long *ok)
{
    CK_MECHANISM mechanism;
    mechanism.mechanism = CKM_SHA_256;
    mechanism.parameter = NULL;
    mechanism.parameter_len = 0;
    CK_RV rv = provider->digest_init(session, &mechanism);
    *calls += 1;
    *ok += (rv == CKR_OK);
    CK_ULONG out_len = DIGEST_BYTES;
    rv = provider->digest(session, input, INPUT_BYTES, digest, &out_len);
    *calls += 1;
    *ok += (rv == CKR_OK);
}

static int dry_run(const char *provider, unsigned long rounds,
                   unsigned long calls_per_round, unsigned long deadline_s)
{
    unsigned long long total_ops =
        (unsigned long long)rounds * calls_per_round;
    unsigned long long total_calls = total_ops * 2ull;
    printf("refresh-churn dry-run: provider=%s rounds=%lu calls_per_round=%lu "
           "deadline_s=%lu total_ops=%llu total_calls=%llu\n",
           provider, rounds, calls_per_round, deadline_s, total_ops,
           total_calls);
    printf("refresh-churn dry-run: actions=");
    for (unsigned long done = 1; done < rounds; done++) {
        printf("%s%s", done > 1 ? "," : "",
               (done % 2 == 1) ? "exec" : "reload");
    }
    if (rounds == 1)
        printf("(none: single round)");
    printf("\n");
    return 0;
}

static int short_run(const char *provider_path)
{
    struct provider provider;
    if (open_provider(provider_path, &provider) != 0)
        return 2;
    CK_SESSION_HANDLE session = 0;
    int setup_ok = provider_setup(&provider, &session);
    unsigned long calls = 0;
    unsigned long ok = 0;
    if (setup_ok == 0) {
        CK_BYTE input[INPUT_BYTES];
        CK_BYTE digest[DIGEST_BYTES];
        for (size_t i = 0; i < sizeof input; i++)
            input[i] = (CK_BYTE)i;
        digest_op(&provider, session, input, digest, &calls, &ok);
        provider.close_session(session);
        provider.finalize(NULL);
    }
    close_provider(&provider);
    printf("LEDGER mode=short calls=%lu ok=%lu pid=%d\n", calls, ok,
           (int)getpid());
    fflush(stdout);
    if (setup_ok != 0)
        return 2;
    return ok == calls ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *name = argc > 0 ? argv[0] : "refresh-churn";
    if (argc == 2 &&
        (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage(name);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--dry-run") == 0) {
        if (argc != 6) {
            fprintf(stderr,
                    "usage: %s --dry-run PROVIDER ROUNDS CALLS_PER_ROUND "
                    "DEADLINE_S\n",
                    name);
            return 2;
        }
        unsigned long rounds = 0;
        unsigned long calls = 0;
        unsigned long deadline_s = 0;
        if (parse_ulong(argv[3], 1, MAX_ROUNDS, &rounds) != 0 ||
            parse_ulong(argv[4], 1, MAX_CALLS_PER_ROUND, &calls) != 0 ||
            parse_ulong(argv[5], 1, MAX_DEADLINE_S, &deadline_s) != 0) {
            fprintf(stderr, "refresh-churn: bad --dry-run numbers\n");
            return 2;
        }
        return dry_run(argv[2], rounds, calls, deadline_s);
    }
    if (argc >= 2 && strcmp(argv[1], "--short") == 0) {
        if (argc != 3) {
            fprintf(stderr, "usage: %s --short PROVIDER\n", name);
            return 2;
        }
        return short_run(argv[2]);
    }
    if (argc != 5 && argc != 10) {
        usage(name);
        return 2;
    }
    const char *provider_path = argv[1];
    unsigned long rounds = 0;
    unsigned long calls_per_round = 0;
    unsigned long deadline_s = 0;
    if (parse_ulong(argv[2], 1, MAX_ROUNDS, &rounds) != 0 ||
        parse_ulong(argv[3], 1, MAX_CALLS_PER_ROUND, &calls_per_round) != 0 ||
        parse_ulong(argv[4], 1, MAX_DEADLINE_S, &deadline_s) != 0) {
        fprintf(stderr, "refresh-churn: bad ROUNDS/CALLS_PER_ROUND/DEADLINE_S\n");
        return 2;
    }
    unsigned long remaining = rounds;
    unsigned long long deadline_ns = 0;
    unsigned long long acc_ops = 0;
    unsigned long long acc_calls = 0;
    unsigned long long acc_ok = 0;
    int chained = 0;
    if (argc == 10) {
        if (parse_ulong(argv[5], 0, rounds, &remaining) != 0 ||
            parse_u64(argv[6], &deadline_ns) != 0 ||
            parse_u64(argv[7], &acc_ops) != 0 ||
            parse_u64(argv[8], &acc_calls) != 0 ||
            parse_u64(argv[9], &acc_ok) != 0) {
            fprintf(stderr, "refresh-churn: bad exec-chain state\n");
            return 2;
        }
        chained = 1;
        if (remaining == 0) {
            printf("DONE rounds=%lu ops=%llu calls=%llu ok=%llu pid=%d\n",
                   rounds, acc_ops, acc_calls, acc_ok, (int)getpid());
            return 0;
        }
    } else {
        unsigned long long now = 0;
        if (clock_ns(&now) != 0) {
            fprintf(stderr, "refresh-churn: clock read failed\n");
            return 2;
        }
        deadline_ns = now + (unsigned long long)deadline_s * NS_PER_S;
    }

    struct provider provider;
    if (open_provider(provider_path, &provider) != 0)
        return 2;
    CK_SESSION_HANDLE session = 0;
    if (provider_setup(&provider, &session) != 0) {
        close_provider(&provider);
        return 2;
    }

    CK_BYTE input[INPUT_BYTES];
    CK_BYTE digest[DIGEST_BYTES];
    for (size_t i = 0; i < sizeof input; i++)
        input[i] = (CK_BYTE)i;

    unsigned long rounds_done = rounds - remaining;
    unsigned long long total_ops = acc_ops;
    unsigned long long total_calls = acc_calls;
    unsigned long long total_ok = acc_ok;
    int deadline_cut = 0;
    int pid = (int)getpid();
    (void)chained;

    while (remaining > 0) {
        unsigned long long now = 0;
        if (clock_ns(&now) != 0) {
            fprintf(stderr, "refresh-churn: clock read failed\n");
            provider.close_session(session);
            provider.finalize(NULL);
            close_provider(&provider);
            return 2;
        }
        if (now >= deadline_ns) {
            deadline_cut = 1;
            break;
        }
        unsigned long round_calls = 0;
        unsigned long round_ok = 0;
        for (unsigned long op = 0; op < calls_per_round; op++) {
            if (clock_ns(&now) != 0) {
                fprintf(stderr, "refresh-churn: clock read failed\n");
                provider.close_session(session);
                provider.finalize(NULL);
                close_provider(&provider);
                return 2;
            }
            if (now >= deadline_ns) {
                deadline_cut = 1;
                break;
            }
            digest_op(&provider, session, input, digest, &round_calls,
                      &round_ok);
        }
        total_ops += (unsigned long long)round_calls / 2ull;
        total_calls += round_calls;
        total_ok += round_ok;
        rounds_done += 1;
        remaining -= 1;
        const char *next = "done";
        if (remaining > 0 && !deadline_cut)
            next = (rounds_done % 2 == 1) ? "exec" : "reload";
        else if (remaining > 0 && deadline_cut)
            next = "done";
        printf("LEDGER round=%lu remaining=%lu calls=%lu ok=%lu next=%s "
               "pid=%d\n",
               rounds_done, remaining, round_calls, round_ok, next, pid);
        fflush(stdout);
        if (remaining == 0 || deadline_cut)
            break;
        if (rounds_done % 2 == 1) {
            /* Exec ourselves with the remaining count, deadline and totals. */
            char remaining_text[32];
            char deadline_text[32];
            char ops_text[32];
            char calls_text[32];
            char ok_text[32];
            (void)snprintf(remaining_text, sizeof remaining_text, "%lu",
                           remaining);
            (void)snprintf(deadline_text, sizeof deadline_text, "%llu",
                           deadline_ns);
            (void)snprintf(ops_text, sizeof ops_text, "%llu", total_ops);
            (void)snprintf(calls_text, sizeof calls_text, "%llu",
                           total_calls);
            (void)snprintf(ok_text, sizeof ok_text, "%llu", total_ok);
            char *next_argv[11];
            next_argv[0] = argv[0];
            next_argv[1] = argv[1];
            next_argv[2] = argv[2];
            next_argv[3] = argv[3];
            next_argv[4] = argv[4];
            next_argv[5] = remaining_text;
            next_argv[6] = deadline_text;
            next_argv[7] = ops_text;
            next_argv[8] = calls_text;
            next_argv[9] = ok_text;
            next_argv[10] = NULL;
            fflush(stdout);
            (void)execv("/proc/self/exe", next_argv);
            fprintf(stderr, "refresh-churn: exec failed: %s\n",
                    strerror(errno));
            provider.close_session(session);
            provider.finalize(NULL);
            close_provider(&provider);
            return 2;
        }
        /* Reload: close, unload, reopen, and set up again. */
        provider.close_session(session);
        provider.finalize(NULL);
        close_provider(&provider);
        if (open_provider(provider_path, &provider) != 0)
            return 2;
        if (provider_setup(&provider, &session) != 0) {
            close_provider(&provider);
            return 2;
        }
    }

    provider.close_session(session);
    provider.finalize(NULL);
    close_provider(&provider);
    printf("DONE rounds=%lu ops=%llu calls=%llu ok=%llu pid=%d\n", rounds_done,
           total_ops, total_calls, total_ok, pid);
    fflush(stdout);
    if (deadline_cut)
        return 1;
    return total_ok == total_calls ? 0 : 1;
}
