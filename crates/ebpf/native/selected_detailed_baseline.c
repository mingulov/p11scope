/* SPDX-License-Identifier: GPL-2.0-only */
/* Caller Inventory identity only. This unit has no Detailed/START/continuity
 * dependency and never emits EVENTS/DISCOVERY or reads target user memory. */
#include "selected_detailed_baseline.h"
struct {
    __uint(type, 1);
    __uint(map_flags, 1 | (1U << 7));
    __uint(max_entries, BASELINE_QUERY_LIMIT);
    __type(key, u32);
    __type(value, struct baseline_request);
} INV_BASELINE_REQUESTS SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct baseline_control);
} INV_BASELINE_CTL SEC(".maps");
extern unsigned char TASK_COOKIE;
static void *(*baseline_lookup)(void *, const void *) = (void *)1;
static u64 (*baseline_ktime)(void) = (void *)5;
static long (*baseline_output)(void *, const void *, u32) = (void *)127;
struct baseline_meta { void *seq; u64 session_id; u64 seq_num; };
struct baseline_iter { struct baseline_meta *meta; struct task_struct *task; };
SEC("iter/task")
int p11_inventory_image_baseline(struct baseline_iter *ctx)
{
    u32 zero = 0;
    struct baseline_control *ctl = baseline_lookup(&INV_BASELINE_CTL, &zero);
    if (!ctl || !ctx || !ctx->meta || !ctx->meta->seq)
        return 1;
    if (!ctl->generation || !ctl->count || ctl->count > BASELINE_QUERY_LIMIT ||
        !ctl->visit_limit || ctl->visit_limit > BASELINE_VISIT_LIMIT || ctl->failed ||
        ctl->visits >= ctl->visit_limit || baseline_ktime() >= ctl->deadline_ns) {
        ctl->failed = 1;
        return 1;
    }
    ctl->visits++;
    struct baseline_row row = { .generation = ctl->generation, .cookie = 0,
        .exec_id = 0, .visits = ctl->visits, .slot = (u32)ctl->count, .status = 2 };
    struct task_struct *task = ctx->task;
    if (!task) {
        if (ctl->emitted != ctl->count) {
            ctl->failed = 1;
            return 1;
        }
        if (baseline_output(ctx->meta->seq, &row, sizeof(row)))
            ctl->failed = 1;
        return 0;
    }
    if (task->tgid <= 0 || task->group_leader != task)
        return 0;
    u32 tgid = (u32)task->tgid;
    const struct baseline_request *request = baseline_lookup(&INV_BASELINE_REQUESTS, &tgid);
    if (!request || request->generation != ctl->generation || request->tgid != tgid || request->slot >= ctl->count)
        return 0;
    if (ctl->emitted >= ctl->count) {
        ctl->failed = 1;
        return 1;
    }
    struct image_identity image;
    if (p11_link_task_identity(task, &image) != COOKIE_STATUS_OK ||
        task->group_leader != task || task->tgid != (int)tgid ||
        *(volatile u64 *)&task->self_exec_id != image.exec_id) {
        ctl->failed = 1;
        return 1;
    }
    u64 *cookie = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
    if (!cookie || *(volatile u64 *)cookie != image.task_cookie) {
        ctl->failed = 1;
        return 1;
    }
    row.cookie = image.task_cookie;
    row.exec_id = image.exec_id;
    row.slot = request->slot;
    row.status = 1;
    if (baseline_output(ctx->meta->seq, &row, sizeof(row))) {
        ctl->failed = 1;
        return 1;
    }
    ctl->emitted++;
    return 0;
}
