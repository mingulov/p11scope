/* SPDX-License-Identifier: GPL-3.0-or-later */
/* sign_hammer.c — fires C_SignInit+C_Sign (HMAC-SHA256 session key) at
 * SoftHSM2 back to back: the "heavier call" arm of the overhead bench.
 * Same dlopen/table convention and two-phase go-file protocol as
 * hammer.c (P11SCOPE_HAMMER_WARMUP_GO/WARMUP_CALLS/WARMED/MAIN_GO), so
 * the same harness drives it. PIN via P11SCOPE_SIGN_PIN (default 1234).
 *
 * Counts for the coverage oracle: the measured window holds exactly N
 * C_SignInit and N C_Sign calls plus W of each in warm-up; trace sees
 * 2*(N+W)+7 total calls (Initialize, GetSlotList, OpenSession, Login,
 * CreateObject, CloseSession, Finalize around the burst).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
typedef unsigned long CK_OBJECT_HANDLE, CK_MECHANISM_TYPE, CK_USER_TYPE;
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_BBOOL;

typedef struct { CK_MECHANISM_TYPE mechanism; void *parameter; CK_ULONG parameter_len; } CK_MECHANISM;
typedef struct { CK_ULONG type; void *value; CK_ULONG value_len; } CK_ATTRIBUTE;

#define CKF_SERIAL_SESSION 4UL
#define CKF_RW_SESSION 2UL
#define CKU_USER 1UL
#define CKM_SHA_256_HMAC 0x251UL
#define CKA_CLASS 0UL
#define CKA_TOKEN 1UL
#define CKA_KEY_TYPE 0x100UL
#define CKA_SIGN 0x108UL
#define CKA_VALUE 0x11UL
#define CKA_VALUE_LEN 0x161UL
#define CKO_SECRET_KEY 4UL
#define CKK_GENERIC_SECRET 0x10UL

enum {
    I_Initialize = 0, I_Finalize = 1, I_GetSlotList = 4,
    I_OpenSession = 12, I_CloseSession = 13, I_Login = 18,
    I_CreateObject = 20, I_SignInit = 42, I_Sign = 43
};

typedef CK_RV (*fn_gen)(void *);
typedef CK_RV (*fn_slots)(unsigned char, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_login)(CK_SESSION_HANDLE, CK_USER_TYPE, unsigned char *, CK_ULONG);
typedef CK_RV (*fn_create)(CK_SESSION_HANDLE, CK_ATTRIBUTE *, CK_ULONG, CK_OBJECT_HANDLE *);
typedef CK_RV (*fn_signinit)(CK_SESSION_HANDLE, CK_MECHANISM *, CK_OBJECT_HANDLE);
typedef CK_RV (*fn_sign)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);

static void **fns;

#define CHECK(what, expr) do { CK_RV _rv = (expr); \
    if (_rv != 0) { fprintf(stderr, "%s failed: 0x%lx\n", what, _rv); exit(1); } } while (0)

static void wait_for_file(const char *path)
{
    while (access(path, F_OK) != 0)
        usleep(5000);
}

static void touch_file(const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) { perror(path); exit(1); }
    fclose(f);
}

static void sign_burst(CK_SESSION_HANDLE sess, CK_OBJECT_HANDLE key, long n)
{
    static unsigned char data[64];
    static unsigned char sig[64];
    CK_MECHANISM mech;
    mech.mechanism = CKM_SHA_256_HMAC;
    mech.parameter = NULL;
    mech.parameter_len = 0;
    memset(data, 0xA5, sizeof data);
    for (long i = 0; i < n; i++) {
        CK_ULONG siglen = sizeof sig;
        CHECK("C_SignInit", ((fn_signinit)fns[I_SignInit])(sess, &mech, key));
        CHECK("C_Sign", ((fn_sign)fns[I_Sign])(sess, data, sizeof data, sig, &siglen));
    }
}

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s /path/to/module.so <ops>\n", argv[0]); return 2; }
    long n = atol(argv[2]);

    const char *warmup_go = getenv("P11SCOPE_HAMMER_WARMUP_GO");
    int two_phase = warmup_go && *warmup_go;
    long w = 0;
    const char *warmed = NULL, *main_go = NULL;
    if (two_phase) {
        const char *ws = getenv("P11SCOPE_HAMMER_WARMUP_CALLS");
        warmed = getenv("P11SCOPE_HAMMER_WARMED");
        main_go = getenv("P11SCOPE_HAMMER_MAIN_GO");
        if (!ws || !*ws || !warmed || !*warmed || !main_go || !*main_go) {
            fprintf(stderr, "two-phase sign hammer needs P11SCOPE_HAMMER_WARMUP_CALLS/WARMED/MAIN_GO\n");
            return 2;
        }
        w = atol(ws);
        if (w < 0) { fprintf(stderr, "bad warm-up count\n"); return 2; }
    }

    const char *pin = getenv("P11SCOPE_SIGN_PIN");
    if (!pin || !*pin)
        pin = "1234";

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    fns = (void **)((char *)list + 8);

    if (two_phase)
        wait_for_file(warmup_go);

    CHECK("C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));

    CK_SLOT_ID slots[64]; CK_ULONG nslots = 64;
    CHECK("C_GetSlotList", ((fn_slots)fns[I_GetSlotList])(1, slots, &nslots));
    if (nslots < 1) { fprintf(stderr, "no token present\n"); return 1; }

    CK_SESSION_HANDLE sess;
    CHECK("C_OpenSession",
          ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &sess));
    CHECK("C_Login",
          ((fn_login)fns[I_Login])(sess, CKU_USER, (unsigned char *)pin, strlen(pin)));

    CK_BBOOL no = 0, yes = 1;
    CK_ULONG klass = CKO_SECRET_KEY, ktype = CKK_GENERIC_SECRET;
    static unsigned char keybytes[32];
    memset(keybytes, 0x3C, sizeof keybytes);
    CK_ATTRIBUTE tmpl[5];
    tmpl[0].type = CKA_CLASS; tmpl[0].value = &klass; tmpl[0].value_len = sizeof klass;
    tmpl[1].type = CKA_KEY_TYPE; tmpl[1].value = &ktype; tmpl[1].value_len = sizeof ktype;
    tmpl[2].type = CKA_TOKEN; tmpl[2].value = &no; tmpl[2].value_len = sizeof no;
    tmpl[3].type = CKA_SIGN; tmpl[3].value = &yes; tmpl[3].value_len = sizeof yes;
    tmpl[4].type = CKA_VALUE; tmpl[4].value = keybytes; tmpl[4].value_len = sizeof keybytes;
    CK_OBJECT_HANDLE key = 0;
    CHECK("C_CreateObject",
          ((fn_create)fns[I_CreateObject])(sess, tmpl, 5, &key));

    if (two_phase) {
        sign_burst(sess, key, w);
        touch_file(warmed);
        wait_for_file(main_go);
    }
    sign_burst(sess, key, n);

    CHECK("C_CloseSession", ((fn_close)fns[I_CloseSession])(sess));
    CHECK("C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));

    printf("sign OK: %ld ops (%ld C_SignInit, %ld C_Sign)\n", n, n, n);
    if (two_phase)
        printf("sign warm-up: %ld ops\n", w);
    fflush(stdout);
    if (getenv("P11SCOPE_HOLD") && raise(SIGSTOP) != 0) return 1;
    return 0;
}
