/* spike/harness.c — deterministic PKCS#11 workload with exact call counts.
 * Calls go through the module's own CK_FUNCTION_LIST (indirect calls), like a
 * real application. Digest + random only: no token objects, no login, no PIN.
 * Ground truth lives in spike/expected.txt.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKF_SERIAL_SESSION 4UL
#define CKM_SHA256 0x250UL

/* CK_FUNCTION_LIST indices (v2.40 order, see spike/discover.c) */
enum { I_Initialize = 0, I_Finalize = 1, I_GetInfo = 2, I_GetSlotList = 4,
       I_OpenSession = 12, I_CloseSession = 13, I_DigestInit = 37,
       I_Digest = 38, I_GenerateRandom = 64 };

typedef CK_RV (*fn_gen)(void *);
typedef CK_RV (*fn_slots)(unsigned char, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_diginit)(CK_SESSION_HANDLE, CK_MECHANISM *);
typedef CK_RV (*fn_digest)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG,
                           unsigned char *, CK_ULONG *);
typedef CK_RV (*fn_rand)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG);

static void **fns;

#define CHECK(what, expr) do { CK_RV _rv = (expr); \
    if (_rv != 0) { fprintf(stderr, "%s failed: 0x%lx\n", what, _rv); exit(1); } } while (0)

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s /path/to/module.so [go-file]\n", argv[0]);
        return 2;
    }

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }

    /* With a go-file the provider is mapped *before* the observer attaches, and
     * not one PKCS#11 call has run yet: the manifest-free lane needs both, since
     * this slice scans once at attach time. Waiting in the shell instead would
     * leave nothing mapped to scan. Call counts are unchanged either way —
     * C_GetFunctionList below still runs after the wait. */
    if (argc == 3) {
        struct timespec tick = { 0, 50 * 1000 * 1000 };
        while (access(argv[2], F_OK) != 0)
            nanosleep(&tick, NULL);
    }

    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    fns = (void **)((char *)list + 8);

    CHECK("C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));

    unsigned char info[256];
    for (int i = 0; i < 3; i++)
        CHECK("C_GetInfo", ((fn_gen)fns[I_GetInfo])(info));

    CK_SLOT_ID slots[64]; CK_ULONG nslots = 64;
    CHECK("C_GetSlotList", ((fn_slots)fns[I_GetSlotList])(1, slots, &nslots));
    if (nslots < 1) { fprintf(stderr, "no token present — init a token first\n"); return 1; }

    CK_SESSION_HANDLE sess[10];
    for (int i = 0; i < 10; i++)
        CHECK("C_OpenSession",
              ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &sess[i]));

    CK_MECHANISM sha256 = { CKM_SHA256, NULL, 0 };
    unsigned char data[] = "pkcs11-scope spike", out[64];
    for (int i = 0; i < 50; i++) {
        CK_ULONG outlen = sizeof out;
        CHECK("C_DigestInit", ((fn_diginit)fns[I_DigestInit])(sess[0], &sha256));
        CHECK("C_Digest",
              ((fn_digest)fns[I_Digest])(sess[0], data, sizeof data - 1, out, &outlen));
    }

    unsigned char rnd[16];
    for (int i = 0; i < 100; i++)
        CHECK("C_GenerateRandom", ((fn_rand)fns[I_GenerateRandom])(sess[0], rnd, sizeof rnd));

    for (int i = 0; i < 10; i++)
        CHECK("C_CloseSession", ((fn_close)fns[I_CloseSession])(sess[i]));
    CHECK("C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));

    printf("harness OK\n");
    return 0;
}
