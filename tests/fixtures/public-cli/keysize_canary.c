/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* keysize_canary: Task 4 privacy canary workload for --key-sizes.
 *
 * usage: keysize_canary MODULE GATE PIN LABEL
 *
 * Single-threaded deterministic RSA-2048 sign+verify workload. Every
 * C_Sign length cell sits between two 64-byte sentinel payload guards,
 * and every C_Verify scalar call carries the same guards around its
 * buffers, so a BPF over-read of any payload byte would plant the
 * pure repeated K3YS1Z3CANARY! marker into the observer's output, maps
 * or logs, where the privileged cell scans for it. The message buffers
 * carry the same marker bytes, so an input-payload leak is marked too;
 * the signature bytes stay genuine SoftHSM output (unmarked by
 * construction). Gate discipline mirrors mt_sign: only C_Initialize /
 * C_GetSlotList run before READY; keygen and every counted call happen
 * after the gate opens. MT_MIXED_HOLD=1 holds after LEDGER for the
 * capture window. Any unexpected return exits nonzero with no LEDGER.
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

/* The canary marker the privileged cell scans for. It must match
 * KEYSIZE_CANARY_MARKER in src/inventory/manifest_e2e_tests.rs exactly;
 * both spellings are pinned by the positive control (the scanner must
 * find an injected copy) and by the SENTINEL line below. */
static const char CANARY_MARK[] = "K3YS1Z3CANARY!";
#define GUARD_LEN 64

/* Fill `len` bytes with the pure repeated marker. No embedded length
 * word: every 8-byte window must fail the RSA-2048 verdict (a 256 word
 * here would alias the legitimate length and pass both the scan and
 * the verdict), and the Rust `keysize_canary_c_guards_carry_no_aliasing_word`
 * test compiles this file and pins that property on its real bytes. */
static void fill_marked(unsigned char *buf, size_t len)
{
    size_t mark_len = sizeof(CANARY_MARK) - 1;
    size_t i;
    for (i = 0; i < len; i++)
        buf[i] = (unsigned char)CANARY_MARK[i % mark_len];
}

static void fill_guard(unsigned char *buf, unsigned tag)
{
    fill_marked(buf, GUARD_LEN);
    /* Pure repeated marker: intact full copies survive at offsets 0,
     * 14, 28 and 42, and only the tag digit disturbs the 8-byte tail.
     * Any word-sized read out of this guard classifies outside the
     * admission bound, so the size verdict fails it. */
    buf[GUARD_LEN - 1] = (unsigned char)('0' + (tag % 10));
}

static void die(const char *what, CK_RV rv)
{
    fprintf(stderr, "keysize_canary: %s: rv=0x%lx\n", what, rv);
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

/* S-protocol frame: the C_Sign length cell with sentinel payload
 * guards immediately adjacent on both sides. The message and
 * signature buffers ride after the guards; only the cell sits
 * between them. */
struct sign_frame {
    unsigned char pre[GUARD_LEN];
    CK_ULONG siglen;
    unsigned char post[GUARD_LEN];
    unsigned char msg[32];
    unsigned char sig[512];
};

/* V-protocol frame: the C_Verify input buffers with the same guards.
 * The scalar length travels by value; BPF must read nothing here. */
struct verify_frame {
    unsigned char pre[GUARD_LEN];
    unsigned char msg[32];
    unsigned char sig[256];
    unsigned char post[GUARD_LEN];
};

int main(int argc, char **argv)
{
    typedef struct { void *c, *d, *l, *u; CK_ULONG flags; void *r; } INITARGS;
    void *handle, *list = NULL;
    void **fns;
    CK_RV (*gfl)(void **);
    INITARGS args;
    CK_SLOT_ID slots[8];
    CK_ULONG nslots = 8;
    CK_SESSION_HANDLE session = 0;
    CK_OBJECT_HANDLE pub = 0, priv = 0;
    CK_MECHANISM mech;
    CK_RV rv;
    long signs = 0, verifies = 0;
    int round;

    if (argc != 5 || !argv[2][0] || !argv[3][0] || !argv[4][0]) {
        fprintf(stderr, "usage: %s MODULE GATE PIN LABEL\n", argv[0]);
        return 2;
    }
    handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "keysize_canary: dlopen: %s\n", dlerror());
        return 1;
    }
    gfl = (CK_RV(*)(void **))dlsym(handle, "C_GetFunctionList");
    if (!gfl || gfl(&list) || !list)
        die("C_GetFunctionList", 0);
    fns = (void **)((char *)list + 8);
    memset(&args, 0, sizeof args);
    args.flags = 2;
    rv = F(fns, 0, CK_RV (*)(void *))(&args);
    if (rv != CKR_OK)
        die("C_Initialize", rv);
    rv = F(fns, 4, CK_RV (*)(unsigned char, CK_SLOT_ID *, CK_ULONG *))(1, slots, &nslots);
    if (rv != CKR_OK || nslots == 0)
        die("C_GetSlotList", rv);
    target("C_Sign", fns[43]);
    target("C_Verify", fns[49]);
    printf("READY pid=%d\n", (int)getpid());
    fflush(stdout);
    if (strcmp(argv[2], "-")) {
        while (access(argv[2], F_OK) != 0)
            usleep(10000);
    }
    rv = F(fns, 12, CK_RV (*)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *))(
        slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK)
        die("setup C_OpenSession", rv);
    rv = F(fns, 18, CK_RV (*)(CK_SESSION_HANDLE, CK_ULONG, unsigned char *, CK_ULONG))(
        session, CKU_USER, (unsigned char *)argv[3], (CK_ULONG)strlen(argv[3]));
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
            {CKA_LABEL, (void *)argv[4], (CK_ULONG)strlen(argv[4])},
        };
        CK_ATTRIBUTE privt[] = {
            {CKA_CLASS, &privclass, sizeof privclass}, {CKA_KEY_TYPE, &ktype, sizeof ktype},
            {CKA_TOKEN, &no, sizeof no}, {CKA_PRIVATE, &yes, sizeof yes},
            {CKA_SIGN, &yes, sizeof yes},
            {CKA_LABEL, (void *)argv[4], (CK_ULONG)strlen(argv[4])},
        };
        gen.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        gen.pParameter = NULL;
        gen.ulParameterLen = 0;
        rv = F(fns, 59,
               CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_ATTRIBUTE *, CK_ULONG, CK_ATTRIBUTE *,
                         CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *))(
            session, &gen, pubt, 7, privt, 6, &pub, &priv);
        if (rv != CKR_OK)
            die("C_GenerateKeyPair", rv);
        if (!pub || !priv || pub == priv)
            die("keygen handles", 0);
    }
    mech.mechanism = CKM_SHA256_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    for (round = 0; round < 3; round++) {
        static struct sign_frame sframe;
        static struct verify_frame vframe;
        fill_guard(sframe.pre, 1);
        fill_guard(sframe.post, 2);
        /* Mark the input too: SoftHSM signs any bytes, so a leak of
         * the message payload carries the marker. The signature
         * buffer keeps genuine output (unmarked by construction). */
        fill_marked(sframe.msg, sizeof sframe.msg);
        sframe.siglen = sizeof sframe.sig;
        rv = F(fns, 42, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))(
            session, &mech, priv);
        if (rv != CKR_OK)
            die("C_SignInit", rv);
        rv = F(fns, 43,
               CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *))(
            session, sframe.msg, sizeof sframe.msg, sframe.sig, &sframe.siglen);
        if (rv != CKR_OK)
            die("C_Sign", rv);
        if (sframe.siglen != 256)
            die("C_Sign length is not RSA-2048", 0);
        signs++;
        fill_guard(vframe.pre, 3);
        fill_guard(vframe.post, 4);
        memcpy(vframe.msg, sframe.msg, sizeof vframe.msg);
        memcpy(vframe.sig, sframe.sig, 256);
        rv = F(fns, 48, CK_RV (*)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE))(
            session, &mech, pub);
        if (rv != CKR_OK)
            die("C_VerifyInit", rv);
        rv = F(fns, 49,
               CK_RV (*)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG))(
            session, vframe.msg, sizeof vframe.msg, vframe.sig, 256);
        if (rv != CKR_OK)
            die("C_Verify", rv);
        verifies++;
        /* Scrub the signature copies; the guards stay planted until exit
         * so any late BPF read would still carry the marker. */
        memset(sframe.sig, 0, sizeof sframe.sig);
        memset(vframe.sig, 0, sizeof vframe.sig);
        /* Pace the rounds (200 ms): the six counted calls would otherwise
         * complete in milliseconds, before the semantic lane's joint birth
         * lands, flaking the run as bootstrap_unavailable. Threaded
         * fixtures (mt_sign) get this pacing from thread overhead. */
        usleep(200000);
    }
    printf("SENTINEL marker=%s signs=%ld verifies=%ld\n", CANARY_MARK, signs, verifies);
    printf("LEDGER {\"schema\":\"p11scope/public-cli-ledger/v2\",\"pid\":%d,\"complete\":true,"
           "\"functions\":["
           "{\"name\":\"C_SignInit\",\"attempts\":%ld,\"successful\":%ld,"
           "\"rv_counts\":{\"0x0000000000000000\":%ld}},"
           "{\"name\":\"C_Sign\",\"attempts\":%ld,\"successful\":%ld,"
           "\"rv_counts\":{\"0x0000000000000000\":%ld}},"
           "{\"name\":\"C_VerifyInit\",\"attempts\":%ld,\"successful\":%ld,"
           "\"rv_counts\":{\"0x0000000000000000\":%ld}},"
           "{\"name\":\"C_Verify\",\"attempts\":%ld,\"successful\":%ld,"
           "\"rv_counts\":{\"0x0000000000000000\":%ld}}],"
           "\"key_operations\":{\"label\":\"%s\",\"signs\":%ld,\"verifies\":%ld}}\n",
           (int)getpid(), signs, signs, signs, signs, signs, signs,
           verifies, verifies, verifies, verifies, verifies, verifies,
           argv[4], signs, verifies);
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
    rv = F(fns, 22, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE))(session, priv);
    if (rv != CKR_OK)
        die("C_DestroyObject priv", rv);
    rv = F(fns, 22, CK_RV (*)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE))(session, pub);
    if (rv != CKR_OK)
        die("C_DestroyObject pub", rv);
    rv = F(fns, 19, CK_RV (*)(CK_SESSION_HANDLE))(session);
    if (rv != CKR_OK)
        die("setup C_Logout", rv);
    rv = F(fns, 13, CK_RV (*)(CK_SESSION_HANDLE))(session);
    if (rv != CKR_OK)
        die("setup C_CloseSession", rv);
    rv = F(fns, 1, CK_RV (*)(void *))(NULL);
    if (rv != CKR_OK)
        die("C_Finalize", rv);
    return 0;
}
