/* SPDX-License-Identifier: GPL-2.0-only */
/* Detailed-only typed birth wrapper; the core owns the identity domain. */
#include "image_identity.h"
#include "stop_gate.h"

extern u32 p11_link_fork_allowed(void);
extern u32 p11_root_propagate_thread(struct task_struct *child, u64 clone_flags);
extern u32 p11_link_emit_fork(u32 child_tgid, u64 clone_flags,
                              const struct image_identity *parent,
                              const struct image_identity *child);

static __always_inline int task_newtask_impl(u64 *ctx);

SEC("tp_btf/task_newtask")
int task_newtask(u64 *ctx)
{
    int rc;

    if (!p11_stop_gate_enter())
        return 0;
    rc = task_newtask_impl(ctx);
    p11_stop_gate_leave();
    return rc;
}

static __always_inline int task_newtask_impl(u64 *ctx)
{
    u64 clone_flags;
    struct task_struct *current;
    struct task_struct *leader;
    struct task_struct *child;
    struct image_identity parent_identity;
    struct image_identity child_identity;
    u32 child_tgid;

    if (!ctx)
        return 0;
    clone_flags = ctx[1];
    child = (struct task_struct *)(unsigned long)ctx[0];
    (void)p11_root_propagate_thread(child, clone_flags);
    if (clone_flags & CLONE_THREAD)
        return 0;
    if (!p11_link_fork_allowed())
        return 0;

    current = bpf_get_current_task_btf();
    if (!current || !child)
        return 0;

    leader = current->group_leader;
    if (child->tgid <= 0)
        return 0;
    child_tgid = (u32)child->tgid;
    if (p11_link_task_identity(leader, &parent_identity) != COOKIE_STATUS_OK ||
        p11_link_task_identity(child, &child_identity) != COOKIE_STATUS_OK)
        return 0;

    (void)p11_link_emit_fork(child_tgid, clone_flags, &parent_identity, &child_identity);
    return 0;
}
