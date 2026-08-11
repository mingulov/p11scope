/* hammer.c — fires C_GenerateRandom at SoftHSM2 as fast as possible, with
 * no per-call delay, so a tiny ring buffer (scripts/verify-induced-gaps.sh's
 * event-loss gap, small-ring build) overflows before the next drain.
 * Same dlopen/table convention as spike/harness.c.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

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
    if (_rv != 0) { fprintf(stderr, "%s failed: 0x%lx\n", what, _rv); exit(1); } } while (0)

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s /path/to/module.so <iterations>\n", argv[0]); return 2; }
    long n = atol(argv[2]);

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    fns = (void **)((char *)list + 8);

    CHECK("C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));

    CK_SLOT_ID slots[64]; CK_ULONG nslots = 64;
    CHECK("C_GetSlotList", ((fn_slots)fns[I_GetSlotList])(1, slots, &nslots));
    if (nslots < 1) { fprintf(stderr, "no token present\n"); return 1; }

    CK_SESSION_HANDLE sess;
    CHECK("C_OpenSession",
          ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &sess));

    unsigned char rnd[4];
    for (long i = 0; i < n; i++)
        CHECK("C_GenerateRandom", ((fn_rand)fns[I_GenerateRandom])(sess, rnd, sizeof rnd));

    CHECK("C_CloseSession", ((fn_close)fns[I_CloseSession])(sess));
    CHECK("C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));

    printf("hammer OK: %ld C_GenerateRandom calls\n", n);
    return 0;
}
