/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "../../../crates/ebpf/native/selected_detailed_baseline.c"
#include <assert.h>
#include <stdio.h>
#include <string.h>
extern unsigned char COOKIE_CTL;
static struct baseline_control ctl;
static struct baseline_request request;
static struct control cookie_ctl;
static struct task_struct task;
static u64 cookie;
static int have_cookie, unknown;
static struct baseline_row rows[3];
static unsigned int row_count;
static void *lookup(void *map, const void *key)
{
    if (map == &INV_BASELINE_REQUESTS) {
        assert(*(const u32 *)key == 400); return unknown ? NULL : &request;
    }
    assert(*(const u32 *)key == 0);
    if (map == &INV_BASELINE_CTL) return &ctl;
    if (map == &COOKIE_CTL) return &cookie_ctl;
    assert(0); return NULL;
}
static u64 *storage(void *map, struct task_struct *subject, u64 *value, u64 create)
{
    assert(map == &TASK_COOKIE && subject == &task);
    if (!have_cookie && create) { cookie = *value; have_cookie = 1; }
    return have_cookie ? &cookie : NULL;
}
static struct task_struct *current(void) { return &task; }
static u64 clock_ns(void) { return 100; }
static long output(void *seq, const void *row, u32 size)
{
    assert(seq == &rows && size == 40 && row_count < 3); memcpy(&rows[row_count++], row, size); return 0;
}
extern void selected_fixture_identity_setup(void *, void *, void *);
static void reset(void)
{
    memset(&ctl, 0, sizeof(ctl)); ctl.generation = 4; ctl.deadline_ns = 200; ctl.visit_limit = 8; ctl.count = 1;
    request.generation = 4; request.tgid = 400; request.slot = 0;
    memset(&cookie_ctl, 0, sizeof(cookie_ctl)); cookie_ctl.limit = 16384;
    task.tgid = 400; task.group_leader = &task; task.self_exec_id = 0;
    have_cookie = unknown = 0; row_count = 0;
    baseline_lookup = lookup; baseline_ktime = clock_ns; baseline_output = output; bpf_task_storage_get = storage;
    selected_fixture_identity_setup(lookup, storage, current);
}
int main(void)
{
    struct baseline_meta meta = { .seq = &rows };
    struct baseline_iter ctx = { .meta = &meta, .task = &task };
    reset(); assert(!p11_inventory_image_baseline(&ctx));
    assert(have_cookie && row_count == 1 && rows[0].cookie == cookie && rows[0].exec_id == 0);
    ctx.task = NULL; assert(!p11_inventory_image_baseline(&ctx)); assert(row_count == 2 && rows[1].status == 2);
    reset(); ctx.task = &task; task.self_exec_id = 0x8000000000000001ULL;
    assert(!p11_inventory_image_baseline(&ctx) && rows[0].exec_id == 0x8000000000000001ULL);
    reset(); unknown = 1; assert(!p11_inventory_image_baseline(&ctx) && !have_cookie); ctx.task = NULL;
    assert(p11_inventory_image_baseline(&ctx) == 1 && ctl.failed && !row_count);
    reset(); ctx.task = &task; request.generation = 3;
    assert(!p11_inventory_image_baseline(&ctx) && !have_cookie);
    reset(); ctl.deadline_ns = 100; assert(p11_inventory_image_baseline(&ctx) == 1 && !have_cookie);
    reset(); ctl.visit_limit = 1; assert(!p11_inventory_image_baseline(&ctx)); ctx.task = NULL;
    assert(p11_inventory_image_baseline(&ctx) == 1 && ctl.failed && row_count == 1);
    reset(); ctx.task = &task; cookie_ctl.limit = 0;
    assert(p11_inventory_image_baseline(&ctx) == 1 && ctl.failed && !row_count);
    puts("Inventory baseline: 7 controls passed");
}
