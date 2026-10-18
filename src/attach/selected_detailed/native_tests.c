/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Host substitution is limited to BPF map/task helpers. The selector and
 * irreversible state transition bodies below are the production C source. */
#define P11SCOPE_SELECTED_HOST_TEST
#include "../../../crates/ebpf/native/selected_detailed.c"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static struct selected_target target;
static u64 state;
static u64 task_cookie;
static u64 coverage = 1;
unsigned char INSTANCE_GEN;
unsigned char CONFIG;
static struct task_struct task;
static int missing_target, missing_state, missing_cookie;
static int terminal_during_cookie;
static void *lookup(void *map, const void *key)
{
    if (map == &INSTANCE_GEN) { assert(*(const u32 *)key == 3); return &coverage; }
    assert(*(const u32 *)key == 0);
    if (map == &SELECTED_DETAILED)
        return missing_target ? NULL : &target;
    if (map == &SELECTED_DETAILED_STATE)
        return missing_state ? NULL : &state;
    assert(0); return NULL;
}
static struct task_struct *current(void) { return &task; }
static u64 *storage(void *map, struct task_struct *subject, u64 *value, u64 flags)
{
    assert(map == &TASK_COOKIE && subject == &task);
    assert(!value && flags == 0); /* Hot gate MUST remain lookup-only. */
    if (terminal_during_cookie)
        state = 3;
    return missing_cookie ? NULL : &task_cookie;
}
static void reset(void)
{
    memset(&target, 0, sizeof(target));
    target.mode = 1; target.tgid = 400; target.cookie = 7; target.exec_id = 0;
    state = 2; task_cookie = 7; coverage = 1;
    task.tgid = 400; task.group_leader = &task; task.self_exec_id = 0;
    missing_target = missing_state = missing_cookie = terminal_during_cookie = 0;
    selected_lookup = lookup; selected_current_task = current; selected_storage_get = storage;
}
int main(void)
{
    reset(); assert(p11_selected_current_allowed(1, 400) == 1);
    task.self_exec_id = target.exec_id = 0x8000000000000001ULL;
    assert(p11_selected_current_allowed(1, 400) == 1);
    reset(); state = 0; assert(!p11_selected_current_allowed(1, 400));
    reset(); state = 1; assert(!p11_selected_current_allowed(1, 400));
    reset(); state = 3; assert(!p11_selected_current_allowed(1, 400));
    reset(); state = 99; assert(!p11_selected_current_allowed(1, 400));
    reset(); target.mode = 0; state = 0; assert(p11_selected_current_allowed(1, 900));
    assert(!p11_selected_current_allowed(0, 900));
    reset(); missing_target = 1; assert(!p11_selected_current_allowed(1, 400));
    reset(); missing_state = 1; assert(!p11_selected_current_allowed(1, 400));
    reset(); target.mode = 9; assert(!p11_selected_current_allowed(1, 400));
    reset(); assert(!p11_selected_current_allowed(1, 401)); assert(state == 2);
    reset(); task_cookie = 8; assert(!p11_selected_current_allowed(1, 400)); assert(state == 3);
    reset(); task.self_exec_id = 1; assert(!p11_selected_current_allowed(1, 400)); assert(state == 3);
    reset(); missing_cookie = 1; assert(!p11_selected_current_allowed(1, 400)); assert(state == 3);
    reset(); assert(!p11_selected_current_allowed(0, 400)); assert(state == 3);
    reset(); terminal_during_cookie = 1; assert(!p11_selected_current_allowed(1, 400));
    reset(); state = 1; assert(p11_selected_invalidate_tgid(400) == 1); assert(state == 3);
    reset(); state = 2; assert(p11_selected_invalidate_tgid(400) == 1); assert(state == 3);
    reset(); state = 1; assert(!p11_selected_invalidate_tgid(401)); assert(state == 1);
    reset(); state = 3; assert(p11_selected_invalidate_tgid(400) == 1); assert(state == 3);
    reset(); target.mode = 0; assert(!p11_selected_invalidate_tgid(400)); assert(state == 2);
    reset(); state = 1; target.cookie = 0;
    assert(p11_selected_invalidate_tgid(400) == 1 && state == 3 && coverage == 2);
    assert(__sync_val_compare_and_swap(&state, 1, 2) == 3 && state == 3);
    reset(); state = 1;
    assert(__sync_val_compare_and_swap(&state, 1, 2) == 1);
    assert(p11_selected_invalidate_tgid(400) == 1 && state == 3 && coverage == 2);
    reset(); target.parent_kind = 2; state = 1;
    u64 ctx[] = { (u64)&task, 1, 0 };
    assert(p11_selected_cgroup_migrate(ctx) == 0 && state == 3 && coverage == 2);
    reset(); target.parent_kind = 2; task.tgid = 401;
    assert(p11_selected_cgroup_migrate(ctx) == 0 && state == 2 && coverage == 1);
    reset(); target.parent_kind = 1;
    assert(p11_selected_cgroup_migrate(ctx) == 0 && state == 2 && coverage == 1);
    reset(); target.parent_kind = 2; struct task_struct thread = task;
    thread.group_leader = &task; ctx[0] = (u64)&thread;
    assert(p11_selected_cgroup_migrate(ctx) == 0 && state == 3);
    reset(); coverage = 2; assert(!p11_selected_current_allowed(1, 400) && state == 3);
    puts("selected native gate/state: 29 controls passed");
}
