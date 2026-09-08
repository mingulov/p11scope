/* Real typed birth hook calls real root propagation and identity helpers. */
#include "root_affiliation.c"
#include "image_identity.c"
#include <assert.h>
#include <stdio.h>

#define PARENT_COOKIE 0x12345678abcdef01ULL
#define CHILD_COOKIE 0xfedcba9876543211ULL
#define PARENT_EXEC_ID 0x8899aabbccddeeffULL
#define CHILD_EXEC_ID 0x1020304050607080ULL
#define PROCESS_FLAGS 0xfedcba9876543210ULL

static struct task_struct root_parent;
static struct task_struct caller;
static struct task_struct parent_leader = {
    .tgid = 41,
    .self_exec_id = PARENT_EXEC_ID,
};
static struct task_struct child = {
    .tgid = 0x1234567,
    .self_exec_id = CHILD_EXEC_ID,
};
static struct task_struct *current_task = &caller;
static u64 parent_tag = 1;
static u64 child_tag;
static u64 parent_cookie = PARENT_COOKIE;
static u64 child_cookie = CHILD_COOKIE;
static struct root_affiliation_control root_ctl = { .affiliation_reserved = 1 };
static struct control cookie_ctl = {
    .limit = IMAGE_IDENTITY_TICKET_LIMIT,
    .next_ticket = 17,
};
static int allowed;
static int allowed_calls;
static int cookie_get_calls;
static int cookie_create_calls;
static int emit_calls;
static u32 emitted_tgid;
static u64 emitted_flags;
static struct image_identity emitted_parent;
static struct image_identity emitted_child;

static struct task_struct *root_current(void) { return &root_parent; }
static struct task_struct *identity_current(void) { return current_task; }

static void *lookup(void *map, const void *key)
{
    assert(*(const u32 *)key == 0);
    if (map == &ROOT_CTL)
        return &root_ctl;
    assert(map == &COOKIE_CTL);
    return &cookie_ctl;
}

static u64 *root_storage(void *map, struct task_struct *task, u64 *initial, u64 flags)
{
    assert(map == &ROOT_AFFILIATION);
    if (task == &root_parent) {
        assert(!flags && !initial);
        return parent_tag ? &parent_tag : NULL;
    }
    assert(task == &child);
    if (flags) {
        assert(flags == BPF_LOCAL_STORAGE_GET_F_CREATE && initial && *initial == 1);
        child_tag = *initial;
    }
    return child_tag ? &child_tag : NULL;
}

static u64 *cookie_storage(void *map, struct task_struct *task, u64 *initial, u64 flags)
{
    assert(map == &TASK_COOKIE);
    cookie_get_calls++;
    if (flags) {
        cookie_create_calls++;
        assert(flags == BPF_LOCAL_STORAGE_GET_F_CREATE && initial);
    } else {
        assert(!initial);
    }
    if (task == &parent_leader)
        return &parent_cookie;
    assert(task == &child);
    return &child_cookie;
}

u32 p11_link_fork_allowed(void)
{
    allowed_calls++;
    return allowed;
}

u32 p11_link_emit_fork(u32 child_tgid, u64 clone_flags,
                       const struct image_identity *parent_identity,
                       const struct image_identity *child_identity)
{
    emit_calls++;
    emitted_tgid = child_tgid;
    emitted_flags = clone_flags;
    emitted_parent = *parent_identity;
    emitted_child = *child_identity;
    return 0;
}

static void reset_observation(void)
{
    allowed_calls = 0;
    cookie_get_calls = 0;
    cookie_create_calls = 0;
    emit_calls = 0;
    emitted_tgid = 0;
    emitted_flags = 0;
    emitted_parent = (struct image_identity){0};
    emitted_child = (struct image_identity){0};
}

static void assert_cookies_unchanged(u64 expected_parent, u64 expected_child,
                                     u64 expected_next_ticket)
{
    assert(parent_cookie == expected_parent);
    assert(child_cookie == expected_child);
    assert(cookie_ctl.next_ticket == expected_next_ticket);
    assert(!cookie_create_calls);
}

int main(void)
{
    root_current_task = root_current;
    root_map_lookup = lookup;
    root_storage_get = root_storage;
    bpf_get_current_task_btf = identity_current;
    bpf_map_lookup_elem = lookup;
    bpf_task_storage_get = cookie_storage;
    caller.group_leader = &parent_leader;
    parent_leader.group_leader = &parent_leader;
    child.group_leader = &child;

    /* Preserve the original root assertions: propagation precedes filtering. */
    u64 ctx[2] = {(u64)(unsigned long)&child, CLONE_THREAD};
    allowed = 0;
    assert(!task_newtask(ctx));
    assert(child_tag == 1 && root_ctl.affiliation_reserved == 2 && !allowed_calls);
    assert(!emit_calls && !cookie_get_calls);
    child_tag = 0;
    parent_tag = 0;
    assert(!task_newtask(ctx));
    assert(!child_tag && root_ctl.affiliation_reserved == 2 && !allowed_calls);
    assert(!emit_calls && !cookie_get_calls);
    parent_tag = 1;
    ctx[1] = 0;
    root_ctl.failure_flags = ROOT_CREATE_FAILED;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && !child_tag && root_ctl.affiliation_reserved == 2);
    assert(!emit_calls && !cookie_get_calls);
    root_ctl.failure_flags = 0;

    /* A process child emits the exact full-width identities from production. */
    reset_observation();
    allowed = 1;
    ctx[1] = PROCESS_FLAGS;
    assert(!(PROCESS_FLAGS & CLONE_THREAD));
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && emit_calls == 1 && cookie_get_calls == 2);
    assert(emitted_tgid == (u32)child.tgid);
    assert(emitted_flags == PROCESS_FLAGS);
    assert(emitted_parent.task_cookie == PARENT_COOKIE);
    assert(emitted_parent.exec_id == PARENT_EXEC_ID);
    assert(emitted_child.task_cookie == CHILD_COOKIE);
    assert(emitted_child.exec_id == CHILD_EXEC_ID);
    assert(!child_tag && root_ctl.affiliation_reserved == 2);
    assert_cookies_unchanged(PARENT_COOKIE, CHILD_COOKIE, 17);

    /* Semantic refusal paths must not create or alter TASK_COOKIE storage. */
    reset_observation();
    allowed = 0;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && !emit_calls && !cookie_get_calls);
    assert_cookies_unchanged(PARENT_COOKIE, CHILD_COOKIE, 17);

    reset_observation();
    assert(!task_newtask(NULL));
    assert(!allowed_calls && !emit_calls && !cookie_get_calls);
    assert_cookies_unchanged(PARENT_COOKIE, CHILD_COOKIE, 17);

    reset_observation();
    allowed = 1;
    current_task = NULL;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && !emit_calls && !cookie_get_calls);
    assert_cookies_unchanged(PARENT_COOKIE, CHILD_COOKIE, 17);
    current_task = &caller;

    reset_observation();
    ctx[0] = 0;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && !emit_calls && !cookie_get_calls);
    assert_cookies_unchanged(PARENT_COOKIE, CHILD_COOKIE, 17);
    ctx[0] = (u64)(unsigned long)&child;

    reset_observation();
    child.tgid = 0;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && !emit_calls && !cookie_get_calls);
    assert_cookies_unchanged(PARENT_COOKIE, CHILD_COOKIE, 17);
    child.tgid = -7;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 2 && !emit_calls && !cookie_get_calls);
    assert_cookies_unchanged(PARENT_COOKIE, CHILD_COOKIE, 17);
    child.tgid = 0x1234567;

    /* Existing zero cells make each real identity lookup fail without CREATE. */
    reset_observation();
    parent_cookie = 0;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && !emit_calls && cookie_get_calls == 1);
    assert_cookies_unchanged(0, CHILD_COOKIE, 17);
    parent_cookie = PARENT_COOKIE;

    reset_observation();
    child_cookie = 0;
    assert(!task_newtask(ctx));
    assert(allowed_calls == 1 && !emit_calls && cookie_get_calls == 2);
    assert_cookies_unchanged(PARENT_COOKIE, 0, 17);
    child_cookie = CHILD_COOKIE;

    puts("actual typed birth hook: root propagation precedes filtering; process FORK forwards exact identities");
}
