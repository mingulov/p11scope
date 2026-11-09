/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* mt_sign: deterministic multi-threaded shared-key signing workload.
 *
 * usage: mt_sign MODULE THREADS SIGNS GATE PIN LABEL
 *
 * Main opens a session, logs in, and generates a session RSA-2048 keypair
 * labeled LABEL. Every thread opens its own session, logs in, and runs
 * exactly SIGNS x {C_SignInit, C_Sign} one-shot signatures with the
 * shared private key handle (session objects are visible to all sessions
 * of the process), then logs out and closes. Totals: THREADS x SIGNS
 * signatures. The LEDGER (schema p11scope/public-cli-ledger/v2) carries
 * per-function attempts plus the key/operations binding the oracle uses
 * to find the object_observations key row.
 *
 * Gate discipline (as mt_mixed): only C_Initialize/C_GetSlotList run
 * before READY; keygen, logins and every counted call happen after the
 * gate opens. MT_MIXED_HOLD=1 holds after LEDGER for capture windows.
 * Any unexpected return exits nonzero with no LEDGER.
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

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE, CK_OBJECT_HANDLE;
typedef struct { CK_ULONG type; void *pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKF_SERIAL_SESSION 4UL
#define CKF_RW_SESSION 2UL
#define CKR_OK 0UL
#define CKU_USER 1UL
#define CKO_PUBLIC_KEY 2UL
#define CKO_PRIVATE_KEY 3UL
#define CKK_RSA 0UL
#define CKM_RSA_PKCS_KEY_PAIR_GEN 0UL
#define CKM_SHA256_RSA_PKCS 0x40UL
#define CKA_CLASS 0UL
#define CKA_TOKEN 1UL
#define CKA_PRIVATE 2UL
#define CKA_LABEL 3UL
#define CKA_KEY_TYPE 0x100UL
#define CKA_SIGN 0x108UL
#define CKA_VERIFY 0x10AUL
#define CKA_MODULUS_BITS 0x121UL
#define CKA_PUBLIC_EXPONENT 0x122UL

#define F(fns, i, t) ((t)(fns)[i])

static void **G_FNS;
static CK_SLOT_ID G_SLOT;
static CK_OBJECT_HANDLE G_PRIV;
static const char *G_PIN;
static int G_SIGNS;
static long G_SIGNINIT_OK, G_SIGN_OK;

static void die(const char *what, CK_RV rv)
{
    fprintf(stderr, "mt_sign: %s: rv=0x%lx\n", what, rv);
    exit(1);
}

static void target(const char *name, void *address)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    char line[4096], perms[5];
    unsigned long lo, hi, off, ino;
    unsigned int major, minor;
    uintptr_t ptr;
    if (!maps)
        die("maps", 0);
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
    die("target not mapped", 0);
}

struct worker_out {
    unsigned long signinit;
    unsigned long sign;
};

static void *worker(void *arg)
{
    struct worker_out *out = arg;
    CK_SESSION_HANDLE session = 0;
    CK_MECHANISM mech;
    unsigned char msg[32], sig[256];
    CK_ULONG siglen;
    CK_RV rv;
    memset(msg, 0xA5, sizeof msg);
    rv = F(G_FNS, 12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(
        G_SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
        die("worker C_OpenSession", rv);
    /* No per-worker login: the USER login is process-wide once the setup
     * session logs in (a second C_Login returns CKR_USER_ALREADY_LOGGED_IN
     * and a worker logout would race other threads' signatures). */
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    for (int i = 0; i < G_SIGNS; i++) {
        rv = F(G_FNS, 42, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))(
            session, &mech, G_PRIV);
        out->signinit++;
        if (rv != CKR_OK)
            die("C_SignInit", rv);
        siglen = sizeof sig;
        rv = F(G_FNS, 43,
               CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *))(
            session, msg, sizeof msg, sig, &siglen);
        out->sign++;
        if (rv != CKR_OK)
            die("C_Sign", rv);
    }
    rv = F(G_FNS, 13, CK_RV (*)(CK_SESSION_HANDLE))(session);
    if (rv != CKR_OK)
        die("worker C_CloseSession", rv);
    return NULL;
}

int main(int argc, char **argv)
{
    typedef struct { void *c, *d, *l, *u; CK_ULONG flags; void *r; } INITARGS;
    void *handle, *list = NULL;
    CK_RV (*gfl)(void **);
    INITARGS args;
    CK_SLOT_ID slots[8];
    CK_ULONG nslots = 8;
    CK_SESSION_HANDLE setup = 0;
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_RV rv;
    long threads, signs;
    pthread_t *tids;
    struct worker_out *outs;
    if (argc != 7) {
        fprintf(stderr, "usage: %s MODULE THREADS SIGNS GATE PIN LABEL\n", argv[0]);
        return 2;
    }
    threads = atol(argv[2]);
    signs = atol(argv[3]);
    if (threads < 1 || threads > 256 || signs < 1 || !argv[5][0] || !argv[6][0]) {
        fprintf(stderr, "bad THREADS/SIGNS/PIN/LABEL\n");
        return 2;
    }
    G_PIN = argv[5];
    G_SIGNS = (int)signs;
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "mt_sign: dlopen: %s\n", dlerror());
        return 1;
    }
    gfl = (CK_RV(*)(void **))dlsym(handle, "C_GetFunctionList");
    if (!gfl || gfl(&list) || !list)
        die("C_GetFunctionList", 0);
    G_FNS = (void **)((char *)list + 8);
    memset(&args, 0, sizeof args);
    args.flags = 2;
    rv = F(G_FNS, 0, CK_RV (*)(void *))(&args);
    if (rv != CKR_OK)
        die("C_Initialize", rv);
    rv = F(G_FNS, 4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &nslots);
    if (rv != CKR_OK || nslots == 0)
        die("C_GetSlotList", rv);
    G_SLOT = slots[0];
    target("C_SignInit", G_FNS[42]);
    target("C_Sign", G_FNS[43]);
    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (strcmp(argv[4], "-")) {
        while (access(argv[4], F_OK) != 0)
            usleep(10000);
    }
    /* Keygen after the gate: setup calls are unobserved scaffolding only
     * when pre-gate; post-gate they are observed but unverified rows. */
    rv = F(G_FNS, 12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(
        G_SLOT, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &setup);
    if (rv != CKR_OK)
        die("setup C_OpenSession", rv);
    rv = F(G_FNS, 18, CK_RV (*)(CK_SESSION_HANDLE, CK_ULONG, unsigned char *, CK_ULONG))(
        setup, CKU_USER, (unsigned char *)G_PIN, (CK_ULONG)strlen(G_PIN));
    if (rv != CKR_OK)
        die("setup C_Login", rv);
    {
        CK_ULONG pubclass = CKO_PUBLIC_KEY, privclass = CKO_PRIVATE_KEY, ktype = CKK_RSA;
        CK_ULONG bits = 2048;
        unsigned char no = 0, yes = 1;
        unsigned char exp[] = {1, 0, 1};
        CK_MECHANISM gen;
        CK_ATTRIBUTE pubt[] = {
            {CKA_CLASS, &pubclass, sizeof pubclass}, {CKA_KEY_TYPE, &ktype, sizeof ktype},
            {CKA_TOKEN, &no, sizeof no}, {CKA_VERIFY, &yes, sizeof yes},
            {CKA_MODULUS_BITS, &bits, sizeof bits}, {CKA_PUBLIC_EXPONENT, exp, sizeof exp},
            {CKA_LABEL, (void *)argv[6], (CK_ULONG)strlen(argv[6])},
        };
        CK_ATTRIBUTE privt[] = {
            {CKA_CLASS, &privclass, sizeof privclass}, {CKA_KEY_TYPE, &ktype, sizeof ktype},
            {CKA_TOKEN, &no, sizeof no}, {CKA_PRIVATE, &yes, sizeof yes},
            {CKA_SIGN, &yes, sizeof yes},
            {CKA_LABEL, (void *)argv[6], (CK_ULONG)strlen(argv[6])},
        };
        gen.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        gen.pParameter = NULL;
        gen.ulParameterLen = 0;
        rv = F(G_FNS, 59,
               CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_ATTRIBUTE *,
                         CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *))(
            setup, &gen, pubt, 7, privt, 6, &pub, &priv);
        if (rv != CKR_OK)
            die("C_GenerateKeyPair", rv);
        if (!pub || !priv || pub == priv)
            die("keygen handles", 0);
    }
    G_PRIV = priv;
    tids = calloc((size_t)threads, sizeof *tids);
    outs = calloc((size_t)threads, sizeof *outs);
    if (!tids || !outs)
        die("alloc", 0);
    for (long i = 0; i < threads; i++) {
        if (pthread_create(&tids[i], NULL, worker, &outs[i]) != 0)
            die("pthread_create", 0);
    }
    for (long i = 0; i < threads; i++) {
        if (pthread_join(tids[i], NULL) != 0)
            die("pthread_join", 0);
        G_SIGNINIT_OK += outs[i].signinit;
        G_SIGN_OK += outs[i].sign;
    }
    free(tids);
    free(outs);
    if (G_SIGNINIT_OK != threads * signs || G_SIGN_OK != threads * signs) {
        fprintf(stderr, "mt_sign: totals short: init=%ld sign=%ld\n", G_SIGNINIT_OK, G_SIGN_OK);
        return 1;
    }
    printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v2\",\"pid\":%d,\"complete\":true,"
           "\"functions\":["
           "{\"name\":\"C_SignInit\",\"attempts\":%ld,\"successful\":%ld,"
           "\"rv_counts\":{\"0x0000000000000000\":%ld}},"
           "{\"name\":\"C_Sign\",\"attempts\":%ld,\"successful\":%ld,"
           "\"rv_counts\":{\"0x0000000000000000\":%ld}}],"
           "\"key_operations\":{\"label\":\"%s\",\"signs\":%ld}}\n",
           (int)getpid(), G_SIGNINIT_OK, G_SIGNINIT_OK, G_SIGNINIT_OK, G_SIGN_OK, G_SIGN_OK,
           G_SIGN_OK, argv[6], G_SIGN_OK);
    fflush(stdout);
    {
        const char *hold = getenv("MT_MIXED_HOLD");
        if (hold && !strcmp(hold, "1")) {
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
    rv = F(G_FNS, 22, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE))(setup, priv);
    if (rv != CKR_OK)
        die("C_DestroyObject priv", rv);
    rv = F(G_FNS, 22, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE))(setup, pub);
    if (rv != CKR_OK)
        die("C_DestroyObject pub", rv);
    rv = F(G_FNS, 19, CK_RV (*)(CK_SESSION_HANDLE))(setup);
    if (rv != CKR_OK)
        die("setup C_Logout", rv);
    rv = F(G_FNS, 13, CK_RV (*)(CK_SESSION_HANDLE))(setup);
    if (rv != CKR_OK)
        die("setup C_CloseSession", rv);
    rv = F(G_FNS, 1, CK_RV (*)(void *))(NULL);
    if (rv != CKR_OK)
        die("C_Finalize", rv);
    return 0;
}
