/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Witness counter neutrality: quota, zero-cell, create, retry and config
 * failures through p11_link_current_cookie must leave the shared health
 * counters (unavailable, create_failures, retry_exhausted) unchanged.
 * Allocation behavior (tickets, watermark, zero funnel) stays intact, and
 * the identity path keeps counting its own failures. */
#include "image_identity.h"
/* A weak declaration makes the test fail at the actual missing helper
 * assertion, without a link-error masquerading as runtime RED. */
extern u64 p11_link_current_cookie(void) __attribute__((weak));
/* A counter increment must survive another CPU winning a race on its cell. */
static u64 *lost_race_cell;
static unsigned int cas_attempts;
static u64 injected_identity_cas(u64 *cell, u64 old, u64 replacement)
{
    cas_attempts++;
    if (cell == lost_race_cell)
        return old + 1;
    return __sync_val_compare_and_swap(cell, old, replacement);
}
#define __sync_val_compare_and_swap injected_identity_cas
#include "image_identity.c"
#undef __sync_val_compare_and_swap
#include <assert.h>
#include <stdio.h>
static struct control ctl;
static u64 stored;
static int present, fail_create, control_present = 1, current_present = 1;
static struct task_struct leader = { .tgid = 42 };
static struct task_struct worker = { .tgid = 42, .group_leader = &leader };
static void *lookup(void *map, const void *key) { (void)map; (void)key; return control_present ? &ctl : 0; }
static u64 *storage(void *map, struct task_struct *task, u64 *value, u64 flags) {
    (void)map; (void)flags; assert(task == worker.group_leader);
    if (present) return &stored;
    if (!value || fail_create) return 0;
    stored = *value; present = 1; return &stored;
}
static struct task_struct *current(void) { return current_present ? &worker : 0; }
u32 p11_link_fork_allowed(void) { return 0; }
u32 p11_root_propagate_thread(struct task_struct *child, u64 flags) {
    (void)child; (void)flags; assert(0); return 0;
}
u32 p11_link_emit_fork(u32 pid, u64 flags, const struct image_identity *a, const struct image_identity *b) {
    (void)pid; (void)flags; (void)a; (void)b; assert(0); return 0;
}
/* Distinct seeds prove no counter moved: a bumped cell cannot still read
 * its seed, and a cross-written cell cannot keep all three seeds. */
static void seed_counters(void) {
    ctl.unavailable = 11;
    ctl.create_failures = 13;
    ctl.retry_exhausted = 17;
}
static void assert_counters_flat(void) {
    assert(ctl.unavailable == 11);
    assert(ctl.create_failures == 13);
    assert(ctl.retry_exhausted == 17);
}
int main(void) {
    bpf_map_lookup_elem = lookup; bpf_task_storage_get = storage; bpf_get_current_task_btf = current;
    assert(&p11_link_current_cookie && "EXEC needs the actual cookie-only helper");
    worker.group_leader = &leader;
    ctl = (struct control){ .limit = IMAGE_IDENTITY_TICKET_LIMIT };
    /* Healthy paths still allocate and reuse; nothing counts. */
    present = 0; seed_counters();
    assert(p11_link_current_cookie() == 1);
    assert(ctl.next_ticket == 1);
    assert_counters_flat();
    assert(p11_link_current_cookie() == 1);
    assert(ctl.next_ticket == 1);
    assert_counters_flat();
    /* Quota: zero ticket, watermark held, counters flat. */
    present = 0; ctl.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT; seed_counters();
    assert(p11_link_current_cookie() == 0);
    assert(ctl.next_ticket == IMAGE_IDENTITY_TICKET_LIMIT);
    assert_counters_flat();
    /* Zero cell: zero ticket, counters flat. */
    present = 1; stored = 0; seed_counters();
    assert(p11_link_current_cookie() == 0);
    assert_counters_flat();
    /* Create failure: zero ticket, the CAS ticket is still spent, flat. */
    present = 0; fail_create = 1; ctl.next_ticket = 0; seed_counters();
    assert(p11_link_current_cookie() == 0);
    assert(ctl.next_ticket == 1);
    assert_counters_flat();
    fail_create = 0;
    /* CAS exhaustion: zero ticket after the bounded tries, counters flat. */
    lost_race_cell = &ctl.next_ticket; cas_attempts = 0; seed_counters();
    assert(p11_link_current_cookie() == 0);
    assert(cas_attempts == COOKIE_CAS_TRIES);
    assert_counters_flat();
    lost_race_cell = 0;
    /* Bad config: zero ticket, counters flat. */
    ctl.limit = 0; seed_counters();
    assert(p11_link_current_cookie() == 0);
    assert_counters_flat();
    ctl.limit = IMAGE_IDENTITY_TICKET_LIMIT;
    /* The identity path keeps counting: quota and create failures still
     * raise the shared health cells there. */
    struct image_identity out = {99, 99};
    present = 0; ctl.next_ticket = IMAGE_IDENTITY_TICKET_LIMIT;
    ctl.unavailable = 0;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_QUOTA);
    assert(ctl.unavailable == 1);
    ctl.next_ticket = 0; fail_create = 1; ctl.create_failures = 0; ctl.unavailable = 0;
    assert(p11_link_current_identity(&out) == COOKIE_STATUS_CREATE_FAILED);
    assert(ctl.create_failures == 1 && ctl.unavailable == 1);
    puts("EXEC witness counter neutrality: failures leave the shared counters flat, allocation unchanged, identity path still counts");
    return 0;
}
