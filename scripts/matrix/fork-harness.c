/* scripts/matrix/fork-harness.c — prefork-server-shape workload for Phase 4
 * Task 8 (fork scoping). Loads the module, then forks N children BEFORE any
 * PKCS#11 call is made by anyone (parent included) — the whole point is that
 * the children do not exist yet when the observer attaches. Each child makes
 * a fixed, known number of calls; the parent makes a fixed, known number of
 * its own after forking. Ground truth: scripts/matrix/fork-expected.txt
 * (N=4 children, M=5 digests/child — kept in sync by hand, both small and
 * exact on purpose).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long CK_RV, CK_ULONG, CK_SLOT_ID, CK_SESSION_HANDLE;
typedef struct { CK_ULONG mechanism; void *pParameter; CK_ULONG ulParameterLen; } CK_MECHANISM;

#define CKF_SERIAL_SESSION 4UL
#define CKM_SHA256 0x250UL

#define N_CHILDREN 4
#define M_DIGESTS 5

/* CK_FUNCTION_LIST indices (v2.40 order, see spike/discover.c) */
enum { I_Initialize = 0, I_Finalize = 1, I_GetInfo = 2, I_GetSlotList = 4,
       I_OpenSession = 12, I_CloseSession = 13, I_DigestInit = 37,
       I_Digest = 38 };

typedef CK_RV (*fn_gen)(void *);
typedef CK_RV (*fn_slots)(unsigned char, CK_SLOT_ID *, CK_ULONG *);
typedef CK_RV (*fn_open)(CK_SLOT_ID, CK_ULONG, void *, void *, CK_SESSION_HANDLE *);
typedef CK_RV (*fn_close)(CK_SESSION_HANDLE);
typedef CK_RV (*fn_diginit)(CK_SESSION_HANDLE, CK_MECHANISM *);
typedef CK_RV (*fn_digest)(CK_SESSION_HANDLE, unsigned char *, CK_ULONG,
                           unsigned char *, CK_ULONG *);

static void **fns;

#define CHECK(who, what, expr) do { CK_RV _rv = (expr); \
    if (_rv != 0) { fprintf(stderr, "[%s] %s failed: 0x%lx\n", who, what, _rv); exit(1); } } while (0)

static void child_work(int idx)
{
    char who[16];
    snprintf(who, sizeof who, "child%d", idx);

    CHECK(who, "C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));

    CK_SLOT_ID slots[64]; CK_ULONG nslots = 64;
    CHECK(who, "C_GetSlotList", ((fn_slots)fns[I_GetSlotList])(1, slots, &nslots));
    if (nslots < 1) { fprintf(stderr, "[%s] no token present\n", who); exit(1); }

    CK_SESSION_HANDLE sess;
    CHECK(who, "C_OpenSession",
          ((fn_open)fns[I_OpenSession])(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &sess));

    CK_MECHANISM sha256 = { CKM_SHA256, NULL, 0 };
    unsigned char data[] = "pkcs11-scope fork-harness", out[64];
    for (int i = 0; i < M_DIGESTS; i++) {
        CK_ULONG outlen = sizeof out;
        CHECK(who, "C_DigestInit", ((fn_diginit)fns[I_DigestInit])(sess, &sha256));
        CHECK(who, "C_Digest",
              ((fn_digest)fns[I_Digest])(sess, data, sizeof data - 1, out, &outlen));
    }

    CHECK(who, "C_CloseSession", ((fn_close)fns[I_CloseSession])(sess));
    CHECK(who, "C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s /path/to/module.so\n", argv[0]); return 2; }

    /* Load the module, resolve the function list — no PKCS#11 call yet. */
    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    fns = (void **)((char *)list + 8);

    /* Prefork: fork every child before anyone (parent or child) makes a
     * single PKCS#11 call. This is the shape under test — the children do
     * not exist as processes until this point. */
    pid_t kids[N_CHILDREN];
    for (int i = 0; i < N_CHILDREN; i++) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) { child_work(i); /* never returns */ }
        kids[i] = pid;
    }

    /* Parent's own known slice of work, after forking. */
    CHECK("parent", "C_Initialize", ((fn_gen)fns[I_Initialize])(NULL));
    unsigned char info[256];
    CHECK("parent", "C_GetInfo", ((fn_gen)fns[I_GetInfo])(info));
    CHECK("parent", "C_Finalize", ((fn_gen)fns[I_Finalize])(NULL));

    int fail = 0;
    for (int i = 0; i < N_CHILDREN; i++) {
        int status;
        if (waitpid(kids[i], &status, 0) != kids[i]) { perror("waitpid"); fail = 1; continue; }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "child%d exited abnormally (status=%d)\n", i, status);
            fail = 1;
        }
    }
    if (fail) return 1;

    printf("fork-harness OK\n");
    return 0;
}
