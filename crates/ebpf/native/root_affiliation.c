/* SPDX-License-Identifier: GPL-2.0-only */
#include "root_affiliation.h"

struct {
    ROOT_UINT(type, 29);
    ROOT_UINT(map_flags, 1);
    ROOT_UINT(max_entries, 0);
    ROOT_TYPE(key, int);
    ROOT_TYPE(value, u64);
} ROOT_AFFILIATION ROOT_SEC(".maps");
struct {
    ROOT_UINT(type, 2);
    ROOT_UINT(max_entries, 1);
    ROOT_TYPE(key, u32);
    ROOT_TYPE(value, struct root_affiliation_control);
} ROOT_CTL ROOT_SEC(".maps");

static ROOT_INLINE void root_fail(struct root_affiliation_control *ctl, u64 reason, u64 *counter)
{
    __sync_fetch_and_or(&ctl->failure_flags, reason);
    u64 old = *(volatile u64 *)counter;
    if (old != ~0ULL)
        __sync_val_compare_and_swap(counter, old, old + 1);
}

static ROOT_INLINE struct root_affiliation_control *root_control(void)
{
    u32 key = 0;
    struct root_affiliation_control *ctl = root_map_lookup(&ROOT_CTL, &key);
    if (ctl && ctl->affiliation_reserved > ROOT_AFFILIATION_LIMIT) {
        root_fail(ctl, ROOT_BAD_CONTROL, &ctl->malformed_failures);
        return (void *)0;
    }
    return ctl;
}

static ROOT_INLINE int root_reserve(struct root_affiliation_control *ctl)
{
#pragma unroll
    for (u32 attempt = 0; attempt < ROOT_CAS_TRIES; attempt++) {
        u64 old = *(volatile u64 *)&ctl->affiliation_reserved;
        if (old >= ROOT_AFFILIATION_LIMIT) {
            root_fail(ctl, ROOT_CAPACITY, &ctl->admission_failures);
            return 0;
        }
        if (__sync_val_compare_and_swap(&ctl->affiliation_reserved, old, old + 1) == old)
            return 1;
    }
    root_fail(ctl, ROOT_RESERVE_CAS, &ctl->admission_failures);
    return 0;
}

static ROOT_INLINE void root_refund(struct root_affiliation_control *ctl)
{
#pragma unroll
    for (u32 attempt = 0; attempt < ROOT_CAS_TRIES; attempt++) {
        u64 old = *(volatile u64 *)&ctl->affiliation_reserved;
        if (!old || old > ROOT_AFFILIATION_LIMIT)
            break;
        if (__sync_val_compare_and_swap(&ctl->affiliation_reserved, old, old - 1) == old)
            return;
    }
    root_fail(ctl, ROOT_REFUND_FAILED, &ctl->refund_failures);
}

__attribute__((noinline)) u32 p11_root_propagate_thread(struct task_struct *child, u64 clone_flags)
{
    if (!(clone_flags & ROOT_CLONE_THREAD))
        return ROOT_NOT_APPLICABLE;
    struct task_struct *parent = root_current_task();
    if (!parent)
        return ROOT_PARENT_UNKNOWN;
    u64 *tag = root_storage_get(&ROOT_AFFILIATION, parent, (void *)0, 0);
    /* NULL is UNKNOWN, not an absence certificate. No control mutation or
     * child operation follows it, even when an unrelated failure is sticky. */
    if (!tag)
        return ROOT_PARENT_UNKNOWN;
    struct root_affiliation_control *ctl = root_control();
    if (!ctl)
        return ROOT_FAILED;
    if (*tag != 1 || !child || child == parent || !ctl->affiliation_reserved) {
        root_fail(ctl, ROOT_BAD_CELL, &ctl->malformed_failures);
        return ROOT_FAILED;
    }
    if (*(volatile u64 *)&ctl->failure_flags)
        return ROOT_FAILED;
    if (root_storage_get(&ROOT_AFFILIATION, child, (void *)0, 0)) {
        root_fail(ctl, ROOT_EXISTING_CHILD, &ctl->create_failures);
        return ROOT_FAILED;
    }
    if (!root_reserve(ctl))
        return ROOT_FAILED;
    /* Required setup invariant: fresh unshared/unpinned map; only the original
     * already-born seed before links; userspace freeze; one typed birth handler
     * and one CREATE attempt per fresh child before wake; no other foreign writer.
     * CREATE itself does not prove novelty after a NULL lookup. Passing1 lets
     * the kernel initialize fresh storage without overwriting an existing cell. */
    u64 positive = 1;
    tag = root_storage_get(&ROOT_AFFILIATION, child, &positive, 1);
    if (!tag) {
        root_fail(ctl, ROOT_CREATE_FAILED, &ctl->create_failures);
        return ROOT_FAILED; /* Ambiguous installation retains the charged debt. */
    }
    if (*tag != 1) {
        root_fail(ctl, ROOT_BAD_CELL, &ctl->malformed_failures);
        return ROOT_FAILED; /* Never overwrite or refund an ambiguous cell. */
    }
    return ROOT_INSTALLED;
}

__attribute__((noinline)) u64 p11_root_current_tag(void)
{
    struct task_struct *task = root_current_task();
    if (!task)
        return 0;
    u64 *tag = root_storage_get(&ROOT_AFFILIATION, task, (void *)0, 0);
    if (!tag)
        return 0;
    if (*tag == 1)
        return 1; /* Sticky root failure cannot erase an authentic positive. */
    struct root_affiliation_control *ctl = root_control();
    if (ctl)
        root_fail(ctl, ROOT_BAD_CELL, &ctl->malformed_failures);
    return 0;
}

__attribute__((noinline)) void p11_root_current_exit(void)
{
    struct root_affiliation_control *ctl = root_control();
    if (!ctl || __sync_val_compare_and_swap(&ctl->affiliation_reserved, 0, 0) == 0)
        return;
    struct task_struct *task = root_current_task();
    if (!task) {
        root_fail(ctl, ROOT_EXIT_CLASSIFIER, &ctl->classifier_failures);
        return;
    }
    u64 *tag = root_storage_get(&ROOT_AFFILIATION, task, (void *)0, 0);
    if (!tag) {
        /* Only actual current-task raw exit may use this classifier. */
        if (root_storage_delete(&ROOT_AFFILIATION, task) != -2)
            root_fail(ctl, ROOT_EXIT_CLASSIFIER, &ctl->classifier_failures);
        return;
    }
    if (*tag != 1) {
        root_fail(ctl, ROOT_BAD_CELL, &ctl->malformed_failures);
        return;
    }
    if (root_storage_delete(&ROOT_AFFILIATION, task)) {
        root_fail(ctl, ROOT_EXIT_DELETE, &ctl->delete_failures);
        return;
    }
    root_refund(ctl); /* Never dereference deleted storage; refund only now. */
}
