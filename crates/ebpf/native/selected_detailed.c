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
} SELECTED_DETAIL SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, 1024); /* mmapable atomic lifecycle word */
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} SELECTED_DSTATE SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct selected_bootstrap_control);
} SELECTED_BCTL SEC(".maps");
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
    const struct selected_target *target = selected_lookup(&SELECTED_DETAIL, &key);
    if (!target)
        return 0;
    /* Immutable ordinary mode is the ONLY eager bypass. State zero cannot
     * turn a selected Session back into an ordinary Session. */
    if (target->mode == SELECTED_ORDINARY)
        return parent_allowed != 0;
    if (target->mode != SELECTED_MODE || !target->tgid)
        return 0;
    u64 *state = selected_lookup(&SELECTED_DSTATE, &key);
    if (!state || selected_state(state) != SELECTED_ACTIVE || tgid != target->tgid)
        return 0;
    key = IMG_GEN_COVERAGE;
    u64 *coverage = selected_lookup(&INSTANCE_GEN, &key);
    if (!coverage || *(volatile u64 *)coverage != IMG_ENABLED) {
        selected_close(state);
        return 0;
    }
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
    const struct selected_target *target = selected_lookup(&SELECTED_DETAIL, &key);
    if (!target || target->mode != SELECTED_MODE || !tgid || target->tgid != tgid)
        return 0;
    u64 *state = selected_lookup(&SELECTED_DSTATE, &key);
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
    const struct selected_target *target = selected_lookup(&SELECTED_DETAIL, &key);
    if (!target || target->mode != SELECTED_MODE || target->parent_kind != SELECTED_PARENT_CGROUP)
        return 0;
    struct task_struct *subject = (void *)ctx[0];
    if (subject && subject->tgid > 0)
        (void)p11_selected_invalidate_tgid((u32)subject->tgid);
    return 0;
}

struct selected_iter_meta { void *seq; u64 session_id; u64 seq_num; };
struct selected_iter_task { struct selected_iter_meta *meta; struct task_struct *task; };
__attribute__((noinline)) u32 p11_selected_bootstrap_allowed(u32 tgid)
{
    u32 zero = 0;
    const struct selected_target *target = selected_lookup(&SELECTED_DETAIL, &zero);
    u64 *state = selected_lookup(&SELECTED_DSTATE, &zero);
    u32 coverage_key = IMG_GEN_COVERAGE;
    u64 *coverage = selected_lookup(&INSTANCE_GEN, &coverage_key);
    return target && target->mode == SELECTED_MODE && target->tgid == tgid &&
        tgid && state && selected_state(state) == SELECTED_CLOSED &&
        coverage && *(volatile u64 *)coverage == IMG_ENABLED;
}
SEC("iter/task")
int p11_selected_bootstrap(struct selected_iter_task *ctx)
{
    u32 zero = 0;
    const struct selected_target *target = selected_lookup(&SELECTED_DETAIL, &zero);
    struct selected_bootstrap_control *ctl = selected_lookup(&SELECTED_BCTL, &zero);
    if (!ctl || !ctx || !ctx->meta || !ctx->meta->seq)
        return 1;
    if (!target || !p11_selected_bootstrap_allowed(target->tgid) ||
        !ctl->generation || !ctl->visit_limit || ctl->visit_limit > SELECTED_VISIT_LIMIT ||
        ctl->failed || ctl->visits >= ctl->visit_limit || selected_ktime() >= ctl->deadline_ns) {
        ctl->failed = 1;
        return 1;
    }
    ctl->visits++;
    struct selected_bootstrap_row row = { .generation = ctl->generation,
        .cookie = 0, .exec_id = 0, .visits = ctl->visits, .tgid = target->tgid, .status = 2 };
    struct task_struct *task = ctx->task;
    if (!task) {
        if (ctl->emitted != 1 || !p11_selected_bootstrap_allowed(target->tgid)) {
            ctl->failed = 1;
            return 1;
        }
        if (selected_seq_write(ctx->meta->seq, &row, sizeof(row)))
            ctl->failed = 1;
        return 0;
    }
    if (task->tgid != (int)target->tgid || task->group_leader != task)
        return 0;
    if (ctl->emitted) {
        ctl->failed = 1;
        return 1;
    }
    struct image_identity image;
    if (p11_link_task_identity(task, &image) != COOKIE_STATUS_OK ||
        !p11_image_selected_seed(target->tgid, image.task_cookie, image.exec_id) ||
        task->group_leader != task || task->tgid != (int)target->tgid ||
        *(volatile u64 *)&task->self_exec_id != image.exec_id ||
        !p11_selected_bootstrap_allowed(target->tgid)) {
        ctl->failed = 1;
        return 1;
    }
    row.cookie = image.task_cookie;
    row.exec_id = image.exec_id;
    row.status = 1;
    if (selected_seq_write(ctx->meta->seq, &row, sizeof(row))) {
        ctl->failed = 1;
        return 1;
    }
    ctl->emitted = 1;
    return 0;
}
