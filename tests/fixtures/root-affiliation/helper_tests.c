/* Reuse the actual owner implementation and its helper injection, not a model. */
#define main owner_fixture_main
/* A renamed C main loses main's implicit return0 rule; its unchanged test
 * entrypoint is retained only to keep all original fixture controls referenced. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreturn-type"
#include "../task-owner/helper_tests.c"
#pragma clang diagnostic pop
#undef main
#include "root_affiliation.h"
static struct root_affiliation_control root_ctl;
static int reserve_cas_fail, refund_cas_fail;
static u64 *root_lost_race_cell;
static u64 injected_root_cas(u64 *cell, u64 old, u64 replacement)
{
    if (cell == root_lost_race_cell)
        return old + 1; /* Another CPU won a race on this counter. */
    if (cell == &root_ctl.affiliation_reserved &&
        ((replacement > old && reserve_cas_fail) || (replacement < old && refund_cas_fail)))
        return old + 1;
    return __sync_val_compare_and_swap(cell, old, replacement);
}
#define __sync_val_compare_and_swap injected_root_cas
#include "root_affiliation.c"
#undef __sync_val_compare_and_swap

static u64 tags[3];
static int root_present[3], root_miss[3], root_create_fail, root_delete_error, root_control_missing;
static int root_gets, root_creates, root_deletes, root_control_reads;
static u64 debt_at_delete;
static void *root_lookup(void *map, const void *key)
{
    assert(map == &ROOT_CTL && *(const u32 *)key == 0);
    root_control_reads++;
    return root_control_missing ? NULL : &root_ctl;
}
static u64 *root_get(void *map, struct task_struct *task, u64 *initial, u64 flags)
{
    assert(map == &ROOT_AFFILIATION);
    root_gets++;
    if (!flags) {
        assert(initial == NULL);
        if (root_miss[task->index]) { root_miss[task->index]--; return NULL; }
    } else {
        assert(flags == 1 && initial && *initial == 1 && root_ctl.affiliation_reserved > 0);
        root_creates++;
        if (root_create_fail) return NULL;
        if (!root_present[task->index]) {
            root_present[task->index] = 1;
            tags[task->index] = *initial;
        }
    }
    return root_present[task->index] ? &tags[task->index] : NULL;
}
static long root_delete(void *map, struct task_struct *task)
{
    assert(map == &ROOT_AFFILIATION && task == current_task());
    root_deletes++;
    if (debt_at_delete) assert(root_ctl.affiliation_reserved == debt_at_delete);
    if (root_delete_error) return root_delete_error;
    if (!root_present[task->index]) return -2;
    root_present[task->index] = 0;
    return 0;
}
static void root_reset(void)
{
    reset();
    memset(&root_ctl, 0, sizeof(root_ctl));
    memset(tags, 0, sizeof(tags)); memset(root_present, 0, sizeof(root_present));
    memset(root_miss, 0, sizeof(root_miss));
    root_gets = root_creates = root_deletes = root_control_reads = 0;
    reserve_cas_fail = refund_cas_fail = root_create_fail = root_delete_error = root_control_missing = 0;
    debt_at_delete = 0; root_lost_race_cell = NULL;
    root_map_lookup = root_lookup; root_storage_get = root_get;
    root_storage_delete = root_delete; root_current_task = current_task;
}
static void seed(void)
{
    root_present[0] = 1; tags[0] = 1; root_ctl.affiliation_reserved = 1;
}
static void unknown_parent(void)
{
    root_reset(); seed(); current_index = 1;
    assert(p11_root_propagate_thread(&tasks[2], 0) == ROOT_NOT_APPLICABLE);
    assert(!root_gets && !root_control_reads);
    struct root_affiliation_control old = root_ctl;
    assert(p11_root_propagate_thread(&tasks[2], ROOT_CLONE_THREAD) == ROOT_PARENT_UNKNOWN);
    assert(!memcmp(&old, &root_ctl, sizeof(old)) && !root_creates && !root_deletes && !root_control_reads);
    current_index = 0; root_miss[0] = 1; root_ctl.failure_flags = ROOT_CREATE_FAILED;
    old = root_ctl;
    assert(p11_root_propagate_thread(&tasks[2], ROOT_CLONE_THREAD) == ROOT_PARENT_UNKNOWN);
    assert(!memcmp(&old, &root_ctl, sizeof(old)) && root_present[0]);
    assert(p11_root_current_tag() == 1);
    current_index = 1; assert(p11_root_current_tag() == 0);
}
static void propagation_failures(void)
{
    root_reset(); seed(); root_ctl.affiliation_reserved = ROOT_AFFILIATION_LIMIT;
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.failure_flags == ROOT_CAPACITY && !root_creates);
    assert(root_ctl.affiliation_reserved == ROOT_AFFILIATION_LIMIT && p11_owner_healthy());
    root_reset(); seed(); reserve_cas_fail = 1;
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.failure_flags == ROOT_RESERVE_CAS && root_ctl.affiliation_reserved == 1 && !root_creates);
    root_reset(); seed(); root_create_fail = 1;
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.failure_flags == ROOT_CREATE_FAILED && root_ctl.affiliation_reserved == 2);
    assert(p11_root_current_tag() == 1 && p11_owner_healthy());
    root_create_fail = 0;
    assert(p11_root_propagate_thread(&tasks[2], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.affiliation_reserved == 2 && root_creates == 1);
    root_reset(); seed();
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_INSTALLED);
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.failure_flags == ROOT_EXISTING_CHILD && root_ctl.affiliation_reserved == 2);
    assert(tags[1] == 1 && root_creates == 1 && !root_deletes);
    root_reset(); seed(); root_present[1] = 1; tags[1] = 99; root_miss[1] = 1;
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.failure_flags & ROOT_BAD_CELL);
    assert(tags[1] == 99 && root_ctl.affiliation_reserved == 2 && !root_deletes);
    root_reset(); seed(); tags[0] = 0;
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.failure_flags == ROOT_BAD_CELL && !root_creates);
    assert(p11_root_current_tag() == 0 && tags[0] == 0);
    root_reset(); seed(); root_ctl.affiliation_reserved = ROOT_AFFILIATION_LIMIT + 1;
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_FAILED);
    assert(root_ctl.failure_flags == ROOT_BAD_CONTROL && !root_creates);
}
static void settlement(void)
{
    root_reset(); root_delete_error = -16; p11_root_current_exit();
    assert(!root_gets && !root_deletes && !root_ctl.failure_flags);
    root_ctl.affiliation_reserved = 1; p11_root_current_exit();
    assert(root_ctl.failure_flags == ROOT_EXIT_CLASSIFIER && root_ctl.affiliation_reserved == 1);
    root_reset(); root_ctl.affiliation_reserved = 1; p11_root_current_exit();
    assert(!root_ctl.failure_flags && root_ctl.affiliation_reserved == 1 && root_deletes == 1);
    root_reset(); seed(); root_miss[0] = 1; p11_root_current_exit();
    assert(root_ctl.failure_flags == ROOT_EXIT_CLASSIFIER && root_ctl.affiliation_reserved == 1);
    root_reset(); seed(); root_delete_error = -16; debt_at_delete = 1; p11_root_current_exit();
    assert(root_ctl.failure_flags == ROOT_EXIT_DELETE && root_ctl.affiliation_reserved == 1 && root_present[0]);
    root_delete_error = 0; p11_root_current_exit();
    assert(root_ctl.failure_flags == ROOT_EXIT_DELETE && root_ctl.affiliation_reserved == 0);
    p11_root_current_exit(); assert(root_deletes == 2);
    root_reset(); seed(); refund_cas_fail = 1; debt_at_delete = 1; p11_root_current_exit();
    assert(root_ctl.failure_flags == ROOT_REFUND_FAILED && root_ctl.affiliation_reserved == 1 && !root_present[0]);
    root_reset(); seed(); tags[0] = 2; p11_root_current_exit();
    assert(root_ctl.failure_flags == ROOT_BAD_CELL && !root_deletes && root_ctl.affiliation_reserved == 1);
}
static void injected_freshness_violation(void)
{
    /* Deliberately violates the production single-birth/private-map premise.
     * CREATE1 cannot detect a hidden positive duplicate: no novelty claim. */
    root_reset(); seed();
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_INSTALLED);
    assert(root_ctl.affiliation_reserved == 2 && root_creates == 1);
    root_miss[1] = 1; /* Inject a second handler and hidden existing positive. */
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_INSTALLED);
    assert(tags[1] == 1 && root_ctl.affiliation_reserved == 3 && !root_deletes);
    current_index = 1; p11_root_current_exit();
    assert(root_ctl.affiliation_reserved == 2); /* Extra charge remains; no second refund. */
}
static void churn_and_independence(void)
{
    root_reset(); seed();
    assert(p11_root_propagate_thread(&tasks[1], ROOT_CLONE_THREAD) == ROOT_INSTALLED);
    current_index = 1;
    for (unsigned i = 0; i < 100; i++) {
        assert(p11_root_propagate_thread(&tasks[2], ROOT_CLONE_THREAD) == ROOT_INSTALLED);
        current_index = 2; assert(p11_root_current_tag() == 1); p11_root_current_exit();
        current_index = 1; assert(p11_root_current_tag() == 1 && root_ctl.affiliation_reserved == 2);
    }
    p11_root_current_exit(); current_index = 0; assert(root_ctl.affiliation_reserved == 1);
    struct owner_start_key key = start_key(7);
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_owner_start_remove(&key, 1));
    assert(p11_root_current_tag() == 1 && root_ctl.affiliation_reserved == 1); /* Return retains root. */
    assert(!p11_owner_start_insert(&key, value));
    p11_owner_cleanup(); assert(root_ctl.affiliation_reserved == 1); /* Exec retains root. */
    assert(!p11_owner_start_insert(&key, value));
    pair_delete_error = -16; p11_owner_cleanup(); p11_root_current_exit();
    assert(ctl.poison && ctl.outstanding == 1 && root_ctl.affiliation_reserved == 0);
    root_reset(); seed(); key = start_key(7); assert(!p11_owner_start_insert(&key, value));
    root_delete_error = -16; p11_owner_cleanup(); p11_root_current_exit();
    assert(!ctl.outstanding && root_ctl.affiliation_reserved == 1 && root_ctl.failure_flags);
}
/* Root failure counters are exact: a lost race on the counter cell never
 * drops the increment that accompanies a sticky failure flag. */
static void exact_failure_counters(void)
{
    root_reset(); seed(); tags[0] = 2;
    root_lost_race_cell = &root_ctl.malformed_failures;
    assert(!p11_root_current_tag());
    assert(root_ctl.failure_flags == ROOT_BAD_CELL && root_ctl.malformed_failures == 1);
}
int main(void)
{
    exact_failure_counters(); unknown_parent(); propagation_failures(); settlement(); churn_and_independence(); injected_freshness_violation();
    puts("actual root helpers: unknown, positive propagation, bounded leases, failure debt, independent exit and churn passed");
}
