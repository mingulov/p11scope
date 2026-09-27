/* hammer.c — fires C_GenerateRandom at SoftHSM2 as fast as possible, with
 * no per-call delay, so a tiny ring buffer (scripts/verify-induced-gaps.sh's
 * event-loss gap, small-ring build) overflows before the next drain.
 * Same dlopen/table convention as spike/harness.c.
 *
 * Single-phase (default): `hammer MODULE N` runs N calls straight through.
 * Two-phase (scripts/bench-overhead.sh observed samples): when
 * P11SCOPE_HAMMER_WARMUP_GO is set, the workload maps the provider and
 * resolves the function list, waits for WARMUP_GO, opens a session, fires
 * P11SCOPE_HAMMER_WARMUP_CALLS warm-up calls, touches P11SCOPE_HAMMER_WARMED,
 * waits for P11SCOPE_HAMMER_MAIN_GO, then fires the measured N calls. Every
 * PKCS#11 call except the pre-wait C_GetFunctionList happens after the
 * observer's attach gate, so the observer's count authority must show
 * exactly N+W C_GenerateRandom calls (profile) or N+W+5 total calls (trace:
 * Initialize, GetSlotList, OpenSession, CloseSession, Finalize plus the
 * random burst).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s /path/to/module.so <iterations>\n", argv[0]); return 2; }
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
            fprintf(stderr, "two-phase hammer needs P11SCOPE_HAMMER_WARMUP_CALLS/WARMED/MAIN_GO\n");
            return 2;
        }
        w = atol(ws);
        if (w < 0) { fprintf(stderr, "bad warm-up count\n"); return 2; }
    }

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
          ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &sess));

    unsigned char rnd[4];
    if (two_phase) {
        for (long i = 0; i < w; i++)
            CHECK("C_GenerateRandom", ((fn_rand)fns[I_GenerateRandom])(sess, rnd, sizeof rnd));
        touch_file(warmed);
        wait_for_file(main_go);
    }
    for (long i = 0; i < n; i++)
        CHECK("C_GenerateRandom", ((fn_rand)fns[I_GenerateRandom])(sess, rnd, sizeof rnd));

    CHECK("C_CloseSession", ((fn_close)fns[I_CloseSession])(sess));
    CHECK("C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));

    printf("hammer OK: %ld C_GenerateRandom calls\n", n);
    if (two_phase)
        printf("hammer warm-up: %ld C_GenerateRandom calls\n", w);
    fflush(stdout);
    if (getenv("P11SCOPE_HOLD") && raise(SIGSTOP) != 0) return 1;
    return 0;
}
