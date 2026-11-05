/* SPDX-License-Identifier: GPL-3.0-or-later */
#define P11SCOPE_SELECTED_HOST_TEST
#include "../../../crates/ebpf/native/selected_detailed.c"
#include <assert.h>
#include <stdio.h>
#include <string.h>
extern unsigned char COOKIE_CTL, IMAGE_CONTINUITY, IMAGE_TGID_INDEX, CONFIG;
unsigned char INSTANCE_GEN;
unsigned char CONFIG;
static struct selected_target target;
static struct selected_bootstrap_control ctl;
static struct control cookie_ctl;
static struct image_continuity continuity;
static int have_continuity, have_index, have_cookie, race_exec;
static u64 index_cookie, task_cookie, coverage, flags;
static struct task_struct task;
static struct selected_bootstrap_row rows[3];
static unsigned int row_count;
static void *lookup(void *map, const void *key)
{
    if (map == &INSTANCE_GEN) { assert(*(const u32 *)key == 3); return &coverage; }
    if (map == &IMAGE_CONTINUITY) return have_continuity ? &continuity : NULL;
    if (map == &IMAGE_TGID_INDEX) return have_index ? &index_cookie : NULL;
    assert(*(const u32 *)key == 0);
    if (map == &SELECTED_DETAIL) return &target;
    if (map == &SELECTED_DSTATE) return &flags;
    if (map == &SELECTED_BCTL) return &ctl;
    if (map == &COOKIE_CTL) return &cookie_ctl;
    if (map == &CONFIG) { static u64 policy = 1ULL << 2; return &policy; }
    assert(0); return NULL;
}
static u64 *storage(void *map, struct task_struct *subject, u64 *value, u64 create)
{
    assert(map == &TASK_COOKIE && subject == &task);
    if (!have_cookie && create) { assert(value && *value); task_cookie = *value; have_cookie = 1; }
    return have_cookie ? &task_cookie : NULL;
}
extern void selected_fixture_exec_release(void);
static long update(void *map, const void *key, const void *value, u64 noexist)
{
    (void)key; assert(noexist == 1);
    if (map == &IMAGE_TGID_INDEX) {
        if (have_index) return -17;
        index_cookie = *(const u64 *)value; have_index = 1;
        if (race_exec) selected_fixture_exec_release();
        return 0;
    }
    assert(map == &IMAGE_CONTINUITY);
    if (have_continuity) return -17;
    continuity = *(const struct image_continuity *)value; have_continuity = 1; return 0;
}
static u64 clock_ns(void) { return 100; }
static struct task_struct *current_task(void) { return &task; }
static long write_row(void *seq, const void *row, u32 bytes)
{
    assert(seq == &rows && bytes == 40 && row_count < 3);
    memcpy(&rows[row_count++], row, bytes); return 0;
}
extern void selected_fixture_identity_setup(void *, void *, void *);
extern void selected_fixture_query_setup(void *, void *, void *);
static void reset(void)
{
    memset(&target, 0, sizeof(target)); target.mode = 1; target.tgid = 400;
    memset(&ctl, 0, sizeof(ctl)); ctl.generation = 3; ctl.deadline_ns = 200; ctl.visit_limit = 8;
    memset(&cookie_ctl, 0, sizeof(cookie_ctl)); cookie_ctl.limit = 16384;
    memset(&continuity, 0, sizeof(continuity));
    flags = 1; coverage = 1; have_continuity = have_index = have_cookie = race_exec = 0;
    row_count = 0; task.tgid = 400; task.group_leader = &task; task.self_exec_id = 0;
    selected_lookup = lookup; selected_storage_get = storage; selected_current_task = current_task;
    selected_ktime = clock_ns; selected_seq_write = write_row;
    selected_fixture_identity_setup(lookup, storage, current_task);
    selected_fixture_query_setup(lookup, update, clock_ns);
}
int main(void)
{
    struct selected_iter_meta meta = { .seq = &rows };
    struct selected_iter_task ctx = { .meta = &meta, .task = &task };
    reset(); assert(p11_selected_bootstrap(&ctx) == 0);
    assert(flags == 1 && coverage == 1 && have_cookie && have_continuity);
    assert(row_count == 1 && rows[0].cookie == task_cookie && rows[0].exec_id == 0);
    ctx.task = NULL; assert(p11_selected_bootstrap(&ctx) == 0);
    assert(row_count == 2 && rows[1].status == 2 && rows[1].visits == 2);
    reset(); ctx.task = &task; task.self_exec_id = 0x8000000000000001ULL;
    assert(!p11_selected_bootstrap(&ctx) && rows[0].exec_id == 0x8000000000000001ULL);
    reset(); task.tgid = 401; assert(!p11_selected_bootstrap(&ctx));
    assert(!have_cookie && !row_count); ctx.task = NULL;
    assert(p11_selected_bootstrap(&ctx) == 1 && ctl.failed && !row_count);
    reset(); ctx.task = &task; ctl.deadline_ns = 100;
    assert(p11_selected_bootstrap(&ctx) == 1 && !have_cookie && !row_count);
    reset(); ctl.visit_limit = 1; assert(!p11_selected_bootstrap(&ctx)); ctx.task = NULL;
    assert(p11_selected_bootstrap(&ctx) == 1 && ctl.failed && row_count == 1);
    reset(); ctx.task = &task; race_exec = 1;
    assert(p11_selected_bootstrap(&ctx) == 1 && flags == 3 && coverage == 2 && !row_count);
    assert(have_continuity); /* Late READY is permanently non-authoritative. */
    reset(); cookie_ctl.limit = 0;
    assert(p11_selected_bootstrap(&ctx) == 1 && !row_count && !have_cookie);
    reset(); flags = 2;
    assert(p11_selected_bootstrap(&ctx) == 1 && !have_cookie && !row_count);
    puts("selected bootstrap: 9 controls passed");
}
