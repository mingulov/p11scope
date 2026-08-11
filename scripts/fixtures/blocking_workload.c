/* blocking_workload.c — calls the one blocking entry point in
 * blocking_provider.c (C_WaitForSlotEvent, legacy index 67) and hangs
 * there. scripts/verify-induced-gaps.sh starts this under attach, lets
 * --duration expire while the call is still blocked, then kills the
 * process — the point is the entered-but-never-returned call, not a
 * clean exit.
 */
#include <dlfcn.h>
#include <stdio.h>

typedef unsigned long CK_RV;
typedef CK_RV (*fn0)(void);

#define I_WaitForSlotEvent 67

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s /path/to/provider.so\n", argv[0]); return 2; }

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    void **fns = (void **)((char *)list + 8);

    fn0 wait_for_slot = (fn0)fns[I_WaitForSlotEvent];
    wait_for_slot(); /* blocks ~60s: the capture window ends mid-call */

    printf("blocking_workload: returned (should not happen inside the test window)\n");
    return 0;
}
