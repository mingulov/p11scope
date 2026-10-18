/* SPDX-License-Identifier: GPL-2.0-only */
/* One selected native domain. Identity/negative lifecycle only until the
 * runtime consumes its genuine final activation proof. No target user reads. */
#include "selected_detailed.h"
#include "image_identity_query.h"
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 1U << 7); /* userspace publishes then freezes */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct selected_target);
} SELECTED_DETAILED SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 1024); /* mmapable atomic lifecycle word */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} SELECTED_DETAILED_STATE SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct selected_bootstrap_control);
} SELECTED_BOOTSTRAP_CTL SEC(".maps");
extern unsigned char TASK_COOKIE;
extern unsigned char INSTANCE_GEN;
static void *(*selected_lookup)(void *, const void *) = (void *)1;
static struct task_struct *(*selected_current_task)(void) = (void *)158;
static u64 *(*selected_storage_get)(void *, struct task_struct *, u64 *, u64) = (void *)156;
static u64 (*selected_ktime)(void) = (void *)5;
static long (*selected_seq_write)(void *, const void *, u32) = (void *)127;
static __always_inline u64 selected_state(u64 *cell)
{
    return __sync_val_compare_and_swap(cell, 0, 0);
}
static __always_inline void selected_close(u64 *cell)
{
    /* Both orders win against the sole CLOSED->ACTIVE activation CAS. */
    (void)__sync_val_compare_and_swap(cell, SELECTED_CLOSED, SELECTED_TERMINAL);
    (void)__sync_val_compare_and_swap(cell, SELECTED_ACTIVE, SELECTED_TERMINAL);
    u32 key = IMG_GEN_COVERAGE;
    u64 *coverage = selected_lookup(&INSTANCE_GEN, &key);
    if (coverage) {
        (void)__sync_val_compare_and_swap(coverage, IMG_DISABLED, IMG_FAILED);
        (void)__sync_val_compare_and_swap(coverage, IMG_ENABLED, IMG_FAILED);
    }
}
__attribute__((noinline)) u32 p11_selected_current_allowed(u32 parent_allowed, u32 tgid)
{
    u32 key = 0;
    const struct selected_target *target = selected_lookup(&SELECTED_DETAILED, &key);
    if (!target)
        return 0;
    /* Immutable ordinary mode is the ONLY eager bypass. State zero cannot
     * turn a selected Session back into an ordinary Session. */
    if (target->mode == SELECTED_ORDINARY)
        return parent_allowed != 0;
    if (target->mode != SELECTED_MODE || !target->tgid)
        return 0;
    u64 *state = selected_lookup(&SELECTED_DETAILED_STATE, &key);
    if (!state || selected_state(state) != SELECTED_ACTIVE || tgid != target->tgid)
        return 0;
    struct task_struct *task = selected_current_task();
    struct task_struct *leader = task ? task->group_leader : (void *)0;
    u64 *cookie = leader ? selected_storage_get(&TASK_COOKIE, leader, (void *)0, 0) : (void *)0;
    if (!parent_allowed || !leader || leader->tgid != (int)tgid || !cookie ||
        !target->cookie || target->cookie > IMAGE_IDENTITY_TICKET_LIMIT ||
        *(volatile u64 *)cookie != target->cookie ||
        *(volatile u64 *)&leader->self_exec_id != target->exec_id) {
        selected_close(state);
        return 0;
    }
    return selected_state(state) == SELECTED_ACTIVE;
}
/* Negative-only before bootstrap: expected TGID is published before links.
 * Ambiguous replacement can cancel preparation, never authorize capture. */
__attribute__((noinline)) u32 p11_selected_invalidate_tgid(u32 tgid)
{
    u32 key = 0;
    const struct selected_target *target = selected_lookup(&SELECTED_DETAILED, &key);
    if (!target || target->mode != SELECTED_MODE || !tgid || target->tgid != tgid)
        return 0;
    u64 *state = selected_lookup(&SELECTED_DETAILED_STATE, &key);
    if (state)
        selected_close(state);
    return 1;
}
/* Must be loaded/audited before initial cgroup membership baseline. Subject
 * is the moved task, not the administrator running this callback. Capability
 * and complete cgroup2 path coverage remain required installed acceptance. */
SEC("fentry/cgroup_migrate")
int p11_selected_cgroup_migrate(u64 *ctx)
{
    u32 key = 0;
    const struct selected_target *target = selected_lookup(&SELECTED_DETAILED, &key);
    if (!target || target->mode != SELECTED_MODE || target->parent_kind != SELECTED_PARENT_CGROUP)
        return 0;
    struct task_struct *subject = (void *)ctx[0];
    if (subject && subject->tgid > 0)
        (void)p11_selected_invalidate_tgid((u32)subject->tgid);
    return 0;
}
