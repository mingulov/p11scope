/* Executes the actual production transaction and classifier implementation.
 * Only kernel helper operations and CAS interference are injected; there is no
 * second owner-accounting algorithm. */
#include "task_owner.h"
enum { OWNER_CAS_CONTRACT_TRIES = 8 };
_Static_assert(OWNER_CAS_TRIES == OWNER_CAS_CONTRACT_TRIES,
               "owner accounting requires exactly eight CAS attempts");
static u64 *cas_interference_cell;
static unsigned cas_failures_remaining, cas_attempts;
static u64 controlled_cas(u64 *cell, u64 old, u64 replacement);
#define __sync_val_compare_and_swap controlled_cas
#include "task_owner.c"
#undef __sync_val_compare_and_swap
#include <assert.h>
#include <stdio.h>
#include <string.h>

unsigned char START, DISCOVERY_STATE;
struct task_struct { int index; };
static struct task_struct tasks[3] = {{0}, {1}, {2}};
static struct thread_owner owners[3];
static int installed[3], current_index;
static u64 current_number[3];
static struct owner_control ctl;
static int miss_get, fail_create, delete_error, update_error, pair_delete_error;
static int gets, creates, deletes;
static u64 expected_delete_debt;
static unsigned char value[288];
struct row { int used; void *map; unsigned char key[24], value[288]; };
static struct row rows[600];

static u64 controlled_cas(u64 *cell, u64 old, u64 replacement)
{
    if (cell == cas_interference_cell) {
        cas_attempts++;
        if (cas_failures_remaining) {
            cas_failures_remaining--;
            *cell = old ^ 1ULL;
            return old ^ 1ULL;
        }
    }
    return __sync_val_compare_and_swap(cell, old, replacement);
}

static size_t key_size(void *map) { return map == &START ? 16 : 24; }
static struct row *row(void *map, const void *key)
{
    for (unsigned i = 0; i < 600; i++)
        if (rows[i].used && rows[i].map == map && !memcmp(rows[i].key, key, key_size(map)))
            return &rows[i];
    return NULL;
}
static void *lookup(void *map, const void *key)
{
    if (map == &OWNER_CTL) return &ctl;
    struct row *r = row(map, key);
    return r ? r->value : NULL;
}
static long update(void *map, const void *key, const void *data, u64 flags)
{
    if (update_error) return update_error;
    struct row *r = row(map, key);
    if (r && flags == 1) return -17;
    if (!r && flags == 2) return -2;
    if (!r) {
        for (unsigned i = 0; i < 600; i++)
            if (!rows[i].used) { r = &rows[i]; break; }
    }
    if (!r) return -12;
    r->used = 1; r->map = map;
    memcpy(r->key, key, key_size(map));
    memcpy(r->value, data, map == &START ? 288 : 24);
    return 0;
}
static long pair_delete(void *map, const void *key)
{
    if (pair_delete_error) return pair_delete_error;
    struct row *r = row(map, key);
    if (!r) return -2;
    r->used = 0;
    return 0;
}
static struct task_struct *current_task(void) { return &tasks[current_index]; }
static u64 pid_tgid(void) { return current_number[current_index]; }
static void *storage_get(void *map, struct task_struct *task, void *initial, u64 flags)
{
    assert(map == &THREAD_OWNER && task == current_task() && initial == NULL);
    gets++;
    if (flags == 0 && miss_get) { miss_get--; return NULL; }
    if (flags == 1) {
        creates++;
        assert(ctl.outstanding > 0); /* Reservation precedes CREATE. */
        if (fail_create) return NULL;
        if (!installed[task->index]) {
            memset(&owners[task->index], 0, sizeof(owners[0]));
            installed[task->index] = 1;
        }
    }
    return installed[task->index] ? &owners[task->index] : NULL;
}
static long storage_delete(void *map, struct task_struct *task)
{
    assert(map == &THREAD_OWNER && task == current_task());
    deletes++;
    if (expected_delete_debt) assert(ctl.outstanding == expected_delete_debt);
    if (delete_error) return delete_error;
    if (!installed[task->index]) return -2;
    installed[task->index] = 0;
    return 0;
}
static void reset(void)
{
    memset(&ctl, 0, sizeof(ctl)); ctl.limit = OWNER_LIMIT;
    memset(owners, 0, sizeof(owners)); memset(installed, 0, sizeof(installed));
    memset(rows, 0, sizeof(rows)); memset(value, 0, sizeof(value));
    for (unsigned i = 0; i < 3; i++) current_number[i] = (42ULL << 32) | (100 + i);
    current_index = miss_get = fail_create = delete_error = update_error = pair_delete_error = 0;
    gets = creates = deletes = 0; expected_delete_debt = 0;
    cas_interference_cell = NULL; cas_failures_remaining = cas_attempts = 0;
    owner_map_lookup = lookup; owner_map_update = update; owner_map_delete = pair_delete;
    owner_storage_get = storage_get; owner_storage_delete = storage_delete;
    owner_current_task = current_task; owner_pid_tgid = pid_tgid;
}

static void cas_boundaries(void)
{
    reset();
    assert(ctl.limit == OWNER_LIMIT);
    assert(OWNER_LIMIT ==
#ifdef P11SCOPE_SMALL_STATE_MAPS
           65ULL
#else
           16448ULL
#endif
    );

    ctl.outstanding = 2;
    cas_interference_cell = &ctl.outstanding;
    cas_failures_remaining = OWNER_CAS_CONTRACT_TRIES - 1;
    assert(p11_owner_reserve());
    assert(cas_attempts == OWNER_CAS_CONTRACT_TRIES);

    cas_attempts = 0;
    cas_failures_remaining = OWNER_CAS_CONTRACT_TRIES - 1;
    assert(p11_owner_refund());
    assert(cas_attempts == OWNER_CAS_CONTRACT_TRIES);

    reset(); ctl.outstanding = 2;
    cas_interference_cell = &ctl.outstanding;
    cas_failures_remaining = OWNER_CAS_CONTRACT_TRIES;
    assert(!p11_owner_reserve());
    assert(cas_attempts == OWNER_CAS_CONTRACT_TRIES && ctl.admission_failures == 1);

    reset(); ctl.outstanding = 2;
    cas_interference_cell = &ctl.outstanding;
    cas_failures_remaining = OWNER_CAS_CONTRACT_TRIES;
    assert(!p11_owner_refund());
    assert(cas_attempts == OWNER_CAS_CONTRACT_TRIES && (ctl.poison & OWNER_REFUND_FAILED));

    reset(); ctl.outstanding = OWNER_LIMIT;
    cas_interference_cell = &ctl.outstanding;
    assert(!p11_owner_reserve());
    assert(!cas_attempts && ctl.outstanding == OWNER_LIMIT && ctl.admission_failures == 1);

    reset();
    cas_interference_cell = &ctl.outstanding;
    assert(!p11_owner_refund());
    assert(!cas_attempts && (ctl.poison & OWNER_REFUND_FAILED));

    reset(); ctl.outstanding = 1; ctl.poison = OWNER_CLASSIFIER_FAILED;
    cas_interference_cell = &ctl.outstanding;
    assert(p11_owner_refund());
    assert(cas_attempts == 1 && !ctl.outstanding && ctl.poison == OWNER_CLASSIFIER_FAILED);
}
static struct owner_start_key start_key(u32 slot)
{
    return (struct owner_start_key){pid_tgid(), slot, 0};
}
static struct owner_discovery_key discovery_key(u64 cookie, u64 domain)
{
    return (struct owner_discovery_key){pid_tgid(), cookie, domain};
}
static void classifier(void)
{
    reset(); miss_get = 1; delete_error = -16;
    p11_owner_cleanup(); assert(!ctl.poison && !gets && !deletes && !creates);
    /* Nonzero includes an in-progress reservation: NULL is not absence. */
    ctl.outstanding = 1;
    p11_owner_cleanup();
    assert(ctl.poison & OWNER_CLASSIFIER_FAILED);
    assert(ctl.outstanding == 1 && deletes == 1 && !creates);
    reset(); ctl.outstanding = 1;
    p11_owner_cleanup(); assert(!ctl.poison && ctl.outstanding == 1 && deletes == 1);
    reset(); struct owner_start_key key = start_key(7);
    assert(!p11_owner_start_insert(&key, value));
    miss_get = 1; /* Classifier unexpectedly deletes an unknown installed owner. */
    p11_owner_cleanup();
    assert(ctl.poison && ctl.outstanding == 1 && row(&START, &key));
    assert(!p11_owner_start_get(&key, 1)); /* Poison must dominate saved state. */
    assert(p11_owner_start_insert(&key, value));
    assert(!p11_owner_healthy());
}
static void transactions(void)
{
    reset(); struct owner_start_key key = start_key(7);
    assert(!p11_owner_start_insert(&key, value));
    assert(ctl.outstanding == 1 && owners[0].start_count == 1);
    miss_get = 1; struct owner_start_key second = start_key(8);
    assert(!p11_owner_start_insert(&second, value));
    assert(ctl.outstanding == 1 && owners[0].start_count == 2);
    assert(row(&START, &key)); /* Existing CREATE did not reinitialize keys. */
    assert(p11_owner_start_insert(&key, value));
    assert(!row(&START, &key) && owners[0].start_count == 1);
    expected_delete_debt = 1;
    assert(!p11_owner_start_remove(&second, 1));
    assert(!ctl.outstanding && !installed[0] && !ctl.poison);
    reset(); fail_create = 1;
    assert(p11_owner_start_insert(&key, value));
    assert(!ctl.outstanding && !installed[0] && !ctl.poison);
    reset(); update_error = -12;
    assert(p11_owner_start_insert(&key, value));
    assert(!ctl.outstanding && !installed[0] && !ctl.poison);
    reset(); assert(!p11_owner_start_insert(&key, value));
    pair_delete_error = -16;
    assert(p11_owner_start_remove(&key, 1));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].start_count == 1);
    reset(); assert(!p11_owner_start_insert(&key, value));
    delete_error = -16; expected_delete_debt = 1;
    assert(p11_owner_start_remove(&key, 1));
    assert(ctl.poison && ctl.outstanding == 1 && installed[0]);
    delete_error = 0; p11_owner_cleanup();
    assert(!ctl.outstanding && ctl.poison); /* Settlement never clears poison. */
    reset(); ctl.limit = 0;
    assert(!p11_owner_healthy() && p11_owner_start_insert(&key, value));
    assert(!creates && ctl.poison);
    reset(); ctl.outstanding = OWNER_LIMIT;
    assert(p11_owner_start_insert(&key, value));
    assert(!creates && ctl.outstanding == OWNER_LIMIT && !ctl.poison);
    ctl.outstanding--; assert(!p11_owner_start_insert(&key, value));
    assert(ctl.outstanding == OWNER_LIMIT);
    assert(!p11_owner_start_remove(&key, 1));
    assert(ctl.outstanding == OWNER_LIMIT - 1);
    reset(); /* Healthy cumulative churn exceeds even the normal concurrent cap. */
    for (unsigned i = 0; i < 16500; i++) {
        assert(!p11_owner_start_insert(&key, value));
        assert(!p11_owner_start_remove(&key, 1));
    }
    assert(!ctl.poison && !ctl.outstanding);
}
static void directory(void)
{
    reset(); struct owner_discovery_key a = discovery_key(0, 1), b = discovery_key(0, 2);
    assert(!p11_owner_discovery_insert(&a, value, 1));
    assert(!p11_owner_discovery_insert(&b, value, 1));
    assert(owners[0].occupied == 3 && owners[0].selection_domains == 2);
    value[0] = 37;
    assert(!p11_owner_discovery_insert(&a, value, 2));
    assert(*(unsigned char *)p11_owner_discovery_get(&a, 1) == 37);
    update_error = -12;
    assert(p11_owner_discovery_insert(&a, value, 2));
    assert(owners[0].occupied == 3);
    update_error = 0;
    assert(p11_owner_discovery_insert(&b, value, 1));
    assert(!row(&DISCOVERY_STATE, &b) && owners[0].occupied == 1);
    assert(!p11_owner_discovery_remove(&a, 1)); assert(!ctl.outstanding && !ctl.poison);
    reset(); update_error = -12;
    assert(p11_owner_discovery_insert(&a, value, 1));
    assert(!installed[0] && !ctl.outstanding && !ctl.poison);
    reset(); struct owner_discovery_key bad = discovery_key(0, 3);
    assert(p11_owner_discovery_insert(&bad, value, 1));
    assert(!installed[0] && !ctl.outstanding);
    reset(); assert(!p11_owner_discovery_insert(&a, value, 1));
    pair_delete_error = -16;
    assert(p11_owner_discovery_remove(&a, 1));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].occupied == 1);
    reset();
    for (unsigned i = 0; i < 64; i++) {
        a = discovery_key(i, 1); assert(!p11_owner_discovery_insert(&a, value, 1));
    }
    a = discovery_key(64, 1); assert(p11_owner_discovery_insert(&a, value, 1));
    assert(owners[0].occupied == ~0ULL && ctl.outstanding == 1);
    p11_owner_cleanup(); assert(ctl.abandoned_discovery == 64 && !ctl.outstanding);
}
static void lifecycle(void)
{
    reset(); struct owner_start_key first = start_key(7);
    struct owner_discovery_key a = discovery_key(0, 1), b = discovery_key(0, 2);
    assert(!p11_owner_start_insert(&first, value));
    assert(!p11_owner_discovery_insert(&a, value, 1));
    assert(!p11_owner_discovery_insert(&b, value, 1));
    current_index = 1; struct owner_start_key sibling = start_key(9);
    assert(!p11_owner_start_insert(&sibling, value));
    current_index = 0;
    current_number[0] = (42ULL << 32) | 42; /* Successful/fatal de_thread changed TID. */
    expected_delete_debt = 2;
    p11_owner_cleanup();
    assert(!row(&START, &first) && !row(&DISCOVERY_STATE, &a) && !row(&DISCOVERY_STATE, &b));
    assert(ctl.abandoned_start == 1 && ctl.abandoned_discovery == 2);
    assert(ctl.outstanding == 1 && row(&START, &sibling) && !ctl.poison);
    expected_delete_debt = 0; p11_owner_cleanup();
    assert(ctl.outstanding == 1 && ctl.abandoned_start == 1);
    current_index = 1;
    assert(p11_owner_start_get(&sibling, 1)); /* Arbitrarily slow sibling still live. */
    assert(!p11_owner_start_remove(&sibling, 1)); assert(!ctl.outstanding);
}
static void poisoned_reads(void)
{
    reset(); struct owner_start_key start = start_key(3);
    struct owner_discovery_key discovery = discovery_key(0, 2);
    assert(!p11_owner_start_insert(&start, value));
    assert(!p11_owner_discovery_insert(&discovery, value, 1));
    ctl.poison = OWNER_CLASSIFIER_FAILED;
    assert(!p11_owner_start_get(&start, 1));
    assert(!p11_owner_discovery_get(&discovery, 1));
    assert(p11_owner_start_insert(&start, value));
    assert(p11_owner_discovery_insert(&discovery, value, 2));
    assert(row(&START, &start) && row(&DISCOVERY_STATE, &discovery));
    p11_owner_cleanup(); /* Reclamation remains possible, poison remains terminal. */
    assert(!ctl.outstanding && ctl.poison);
    reset(); start = start_key(3);
    assert(!p11_owner_start_insert(&start, value));
    current_index = 1; current_number[1] = current_number[0];
    assert(!p11_owner_start_get(&start, 1)); /* Numeric equality is not authority. */
    assert(ctl.poison && row(&START, &start) && owners[0].start_count == 1);
    reset(); start = start_key(3);
    assert(!p11_owner_start_insert(&start, value));
    current_index = 1; current_number[1] = current_number[0];
    assert(p11_owner_start_insert(&start, value));
    assert(ctl.poison && row(&START, &start) && ctl.outstanding == 1);
}
/* Each operation starts healthy: poison from the first refusal must not make
 * the later refusals vacuous. Both domains use the same numeric key in a
 * different physical task, including one with its own installed owner. */
static void discovery_foreign_owner(void)
{
    for (u64 domain = 1; domain <= 2; domain++) {
        for (unsigned resident = 0; resident <= 1; resident++) {
            for (unsigned operation = 0; operation < 3; operation++) {
                reset();
                struct owner_discovery_key key = discovery_key(0, domain);
                value[0] = 37;
                assert(!p11_owner_discovery_insert(&key, value, 1));
                struct thread_owner original = owners[0];
                current_index = 1; current_number[1] = current_number[0];
                struct owner_discovery_key other = discovery_key(1, domain);
                if (resident) assert(!p11_owner_discovery_insert(&other, value, 1));
                struct thread_owner foreign = owners[1];
                u64 debt = ctl.outstanding;
                assert(!ctl.poison);
                value[0] = 99;
                if (operation == 0) assert(!p11_owner_discovery_get(&key, 1));
                else if (operation == 1) assert(p11_owner_discovery_insert(&key, value, 2));
                else assert(p11_owner_discovery_remove(&key, 1));
                assert(ctl.poison && ctl.outstanding == debt);
                assert(!memcmp(&owners[0], &original, sizeof(original)));
                assert(!memcmp(&owners[1], &foreign, sizeof(foreign)));
                assert(row(&DISCOVERY_STATE, &key)->value[0] == 37);
                if (resident) assert(row(&DISCOVERY_STATE, &other)->value[0] == 37);
                assert(!ctl.abandoned_discovery && ctl.reclamation_failures);
                p11_owner_cleanup();
                assert(ctl.poison && ctl.outstanding == 1);
                assert(row(&DISCOVERY_STATE, &key)->value[0] == 37);
                assert(!memcmp(&owners[0], &original, sizeof(original)));
                current_index = 0; p11_owner_cleanup();
                assert(ctl.poison && !ctl.outstanding && !row(&DISCOVERY_STATE, &key));
                assert(ctl.abandoned_discovery == 1 + resident);
            }
        }
    }
}
static void capacity_collision(void)
{
    reset();
    for (unsigned i = 0; i < 512; i++) {
        struct owner_start_key key = start_key(i);
        assert(!p11_owner_start_insert(&key, value));
    }
    struct owner_start_key nested = start_key(511);
    assert(p11_owner_start_insert(&nested, value));
    assert(!row(&START, &nested) && owners[0].start_count == 511);
    p11_owner_cleanup(); assert(ctl.abandoned_start == 511 && !ctl.outstanding);
}
static void ordinary_absence(void)
{
    reset(); struct owner_start_key live = start_key(1);
    struct owner_discovery_key live_discovery = discovery_key(0, 1);
    assert(!p11_owner_start_insert(&live, value));
    assert(!p11_owner_discovery_insert(&live_discovery, value, 1));
    current_index = 1; miss_get = 20;
    struct owner_start_key absent = start_key(1);
    assert(!p11_owner_start_get(&absent, 0));
    assert(p11_owner_start_remove(&absent, 0) == -2);
    assert(p11_owner_start_remove(&absent, 0) == -2); /* Direct scope/ABI refusal. */
    for (u64 domain = 1; domain <= 2; domain++) {
        struct owner_discovery_key absent_discovery = discovery_key(0, domain);
        assert(!p11_owner_discovery_get(&absent_discovery, 0));
        assert(p11_owner_discovery_remove(&absent_discovery, 0) == -2);
        assert(p11_owner_discovery_remove(&absent_discovery, 0) == -2);
    }
    assert(!ctl.poison && ctl.outstanding == 1 && creates == 1 && !deletes);
    assert(!ctl.abandoned_start && !ctl.abandoned_discovery && !ctl.reclamation_failures);
    assert(owners[0].start_count == 1 && owners[0].occupied == 1);
    assert(row(&START, &live) && row(&DISCOVERY_STATE, &live_discovery));
    /* An accessible exact directory residue is a contradiction, not a no-op. */
    reset(); live_discovery = discovery_key(0, 2);
    assert(!p11_owner_discovery_insert(&live_discovery, value, 1));
    assert(!pair_delete(&DISCOVERY_STATE, &live_discovery));
    assert(!p11_owner_discovery_get(&live_discovery, 0));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].occupied == 1);
    /* Hidden index-only residue is not certified settled by a hash absence. */
    reset(); assert(!p11_owner_discovery_insert(&live_discovery, value, 1));
    assert(!pair_delete(&DISCOVERY_STATE, &live_discovery)); miss_get = 2;
    assert(!p11_owner_discovery_get(&live_discovery, 0));
    assert(p11_owner_discovery_remove(&live_discovery, 0) == -2);
    assert(!ctl.poison && ctl.outstanding == 1 && owners[0].occupied == 1);
    p11_owner_cleanup(); assert(ctl.poison && ctl.outstanding == 1);
    /* A present hash value never turns an unknown physical owner into authority. */
    reset(); live = start_key(1); assert(!p11_owner_start_insert(&live, value));
    miss_get = 1; assert(!p11_owner_start_get(&live, 0));
    assert(ctl.poison && ctl.outstanding == 1 && row(&START, &live));
    /* Post-get disappearance and failed rollback stay strict. */
    reset(); assert(!p11_owner_start_insert(&live, value));
    assert(p11_owner_start_get(&live, 0)); assert(!pair_delete(&START, &live));
    assert(p11_owner_start_remove(&live, 1));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].start_count == 1);
    reset(); assert(!p11_owner_discovery_insert(&live_discovery, value, 1));
    assert(p11_owner_discovery_get(&live_discovery, 0));
    assert(!pair_delete(&DISCOVERY_STATE, &live_discovery));
    assert(p11_owner_discovery_remove(&live_discovery, 1));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].occupied == 1);
    reset(); assert(!p11_owner_discovery_insert(&live_discovery, value, 1));
    assert(!pair_delete(&DISCOVERY_STATE, &live_discovery));
    assert(p11_owner_discovery_insert(&live_discovery, value, 2));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].occupied == 1);
    reset(); update_error = -12; delete_error = -16;
    assert(p11_owner_discovery_insert(&live_discovery, value, 1));
    assert(ctl.poison && ctl.outstanding == 1 && installed[0]);
}
int main(int argc, char **argv)
{
    if (argc == 2) {
        if (!strcmp(argv[1], "classifier")) classifier();
        else if (!strcmp(argv[1], "transactions")) transactions();
        else if (!strcmp(argv[1], "directory")) directory();
        else if (!strcmp(argv[1], "lifecycle")) lifecycle();
        else if (!strcmp(argv[1], "poison")) poisoned_reads();
        else if (!strcmp(argv[1], "discovery-foreign")) discovery_foreign_owner();
        else if (!strcmp(argv[1], "capacity")) capacity_collision();
        else if (!strcmp(argv[1], "absence")) ordinary_absence();
        else if (!strcmp(argv[1], "cas")) cas_boundaries();
        else assert(0);
    } else {
        cas_boundaries(); classifier(); transactions(); directory(); lifecycle(); poisoned_reads(); capacity_collision(); ordinary_absence(); discovery_foreign_owner();
    }
    puts("task-owner: actual helper classifier, transactions, directory and lifecycle controls passed");
}
