#include "image_identity.c"
#include <assert.h>
#include <stdio.h>
static struct control ctl;
static u64 stored;
static int present, fail_create, control_present = 1;
static struct task_struct leader = { .tgid = 42 };
static struct task_struct worker = { .tgid = 42, .group_leader = &leader };
static void *lookup(void *map, const void *key) { (void)map; (void)key; return control_present ? &ctl : 0; }
static u64 *storage(void *map, struct task_struct *task, u64 *value, u64 flags) {
    (void)map; assert(task == &leader); (void)flags;
    if (present) return &stored;
    if (!value || fail_create) return 0;
    stored = *value; present = 1; return &stored;
}
static struct task_struct *current(void) { return &worker; }
u32 p11_link_fork_allowed(void) { return 0; }
u32 p11_root_propagate_thread(struct task_struct *child, u64 flags) {
    (void)child; (void)flags; assert(0); return 0;
}
u32 p11_link_emit_fork(u32 pid, u64 flags, const struct image_identity *a, const struct image_identity *b) {
    (void)pid; (void)flags; (void)a; (void)b; assert(0); return 0;
}
int main(void) {
    bpf_map_lookup_elem = lookup; bpf_task_storage_get = storage; bpf_get_current_task_btf = current;
    struct image_identity out = {99,99};
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_BAD_CONFIG);
    assert(out.task_cookie == 0 && out.exec_id == 0);
    ctl.limit = 32; assert(p11_link_current_identity(&out) == COOKIE_STATUS_BAD_CONFIG);
    ctl.limit = 1; assert(p11_link_current_identity(&out) == COOKIE_STATUS_BAD_CONFIG);
    ctl.limit = IMAGE_IDENTITY_TICKET_LIMIT; ctl.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT - 1;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_OK);
    assert(out.task_cookie == 16384 && out.exec_id == 0 && ctl.next_ticket == 16384);
    leader.self_exec_id = 1;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_OK);
    assert(out.task_cookie == 16384 && out.exec_id == 1 && ctl.next_ticket == 16384);
    present = 0;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_QUOTA);
    assert(ctl.next_ticket == 16384 && out.task_cookie == 0 && out.exec_id == 0);
    ctl.next_ticket = ~0ULL;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_BAD_CONFIG);
    assert(ctl.next_ticket == ~0ULL);
    ctl.next_ticket = 0; present = 1; stored = 0;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_ZERO_CELL);
    assert(ctl.next_ticket == 0);
    stored = 7; ctl.limit = 0;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_BAD_CONFIG);
    ctl.limit = IMAGE_IDENTITY_TICKET_LIMIT; present = 0; fail_create = 1;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_CREATE_FAILED);
    assert(ctl.next_ticket == 1 && ctl.create_failures == 1);
    control_present = 0;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_NO_CONTROL);
    assert(p11_link_current_identity(0) == COOKIE_STATUS_BAD_TASK);
    worker.group_leader = 0;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_BAD_TASK);
    puts("native control: malformed, near-limit exhaustion, stable cookie/exec, zero cell, creation failure, null refusal passed");
}
