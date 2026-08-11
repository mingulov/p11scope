/* alias_workload.c — calls the two aliased entries in
 * crates/discover/tests/fixture/provider.c (C_CancelFunction and
 * C_WaitForSlotEvent, legacy table indices 66/67, which that fixture
 * points at one address on purpose). Used by
 * scripts/verify-induced-gaps.sh's aliasing gap: both names' calls must
 * land on the one attached slot.
 *
 * Table layout matches provider.c: CK_VERSION (2 bytes + 6 padding) then
 * function pointers, so the first pointer is at offset 8 — same
 * convention spike/harness.c uses against SoftHSM2.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long CK_RV;
typedef CK_RV (*fn0)(void);

#define I_CancelFunction 66
#define I_WaitForSlotEvent 67

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s /path/to/provider.so <cancel_calls> <wait_calls>\n", argv[0]);
        return 2;
    }
    int n_cancel = atoi(argv[2]);
    int n_wait = atoi(argv[3]);

    void *h = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    unsigned long (*gfl)(void **) =
        (unsigned long (*)(void **))dlsym(h, "C_GetFunctionList");
    void *list = NULL;
    if (!gfl || gfl(&list) != 0 || !list) { fprintf(stderr, "no function list\n"); return 1; }
    void **fns = (void **)((char *)list + 8);

    fn0 cancel = (fn0)fns[I_CancelFunction];
    fn0 wait_for_slot = (fn0)fns[I_WaitForSlotEvent];

    for (int i = 0; i < n_cancel; i++) cancel();
    for (int i = 0; i < n_wait; i++) wait_for_slot();

    printf("alias_workload OK: %d cancel + %d wait calls\n", n_cancel, n_wait);
    return 0;
}
