/* SPDX-License-Identifier: GPL-2.0-only */
/* H8 slice-A inactive custody fixture: executes the actual production
 * lifetime-mint, side-map and ring-leaf implementation from
 * crates/ebpf/native/object_journal.{c,h} plus the owner lease/cleanup
 * paths that must preserve the lifetime words. Only kernel helper
 * operations and atomic interference are injected; there is no second
 * custody algorithm. Inactive: no live root calls these leaves. */
#include "task_owner.h"
static u64 *cas_interference_cell;
static unsigned cas_failures_remaining, cas_attempts;
static u64 controlled_cas(u64 *cell, u64 old, u64 replacement);
#define __sync_val_compare_and_swap controlled_cas
#include "task_owner.c"
#include "object_journal.h"
#include "object_journal.c"
#undef __sync_val_compare_and_swap
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef P11SCOPE_INVENTORY_ONLY
unsigned char START, OBJECT_START, OBJECT_DESCRIPTORS, OBJECT_ZERO;
unsigned char JOURNAL_START_MAP, JOURNAL_RING;
#endif
unsigned char DISCOVERY_STATE;

struct task_struct {
    int index;
};
static struct task_struct tasks[4] = {{0}, {1}, {2}, {3}};
static struct thread_owner owners[4];
static int installed[4], current_index;
static u64 current_number[4];
static struct owner_control ctl;
static int miss_get, fail_create, fail_current_task;
static int gets, creates;
static unsigned char start_value[288] __attribute__((aligned(8)));
struct row {
    int used;
    void *map;
    unsigned char key[24];
    unsigned char value[288] __attribute__((aligned(8)));
};
static struct row rows[256];

#ifndef P11SCOPE_INVENTORY_ONLY
static struct journal_control journal_ctl;
static int fail_reserve;
static void *ring_log[64];
static unsigned ring_log_len;
static unsigned ring_submits, ring_discards;
static unsigned char ring_arena[4096] __attribute__((aligned(8)));
static unsigned ring_arena_used;
#endif

static int failures;

#define EXPECT(cond, ...)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d: ", __func__, __LINE__);                                    \
            fprintf(stderr, __VA_ARGS__);                                                           \
            fprintf(stderr, "\n");                                                                 \
        }                                                                                          \
    } while (0)

static u64 controlled_cas(u64 *cell, u64 old, u64 replacement)
{
    if (cell == cas_interference_cell) {
        cas_attempts++;
        if (cas_failures_remaining) {
            /* Another CPU won the race and minted: the cell advances
             * past our observed word, so our compare fails. */
            cas_failures_remaining--;
            *cell = old + 1;
            return old + 1;
        }
    }
    return __sync_val_compare_and_swap(cell, old, replacement);
}

static size_t key_size(void *map)
{
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &JOURNAL_START_MAP)
        return 24;
    if (map == &START || map == &OBJECT_START)
        return 16;
#else
    (void)map;
#endif
    return 24;
}

static struct row *row(void *map, const void *key)
{
    unsigned i;
    for (i = 0; i < 256; i++)
        if (rows[i].used && rows[i].map == map && !memcmp(rows[i].key, key, key_size(map)))
            return &rows[i];
    return NULL;
}

static void *lookup(void *map, const void *key)
{
    struct row *r;
    if (map == &OWNER_CTL)
        return &ctl;
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &JOURNAL_CTL)
        return &journal_ctl;
#endif
    r = row(map, key);
    return r ? r->value : NULL;
}

static long update(void *map, const void *key, const void *data, u64 flags)
{
    size_t width = 24;
    struct row *r = row(map, key);
    unsigned i;
    if (r && flags == 1)
        return -17;
    if (!r && flags == 2)
        return -2;
    if (!r) {
#ifndef P11SCOPE_INVENTORY_ONLY
        if (map == &JOURNAL_START_MAP) {
            /* The side map honors its own limit, like the kernel map. */
            unsigned live = 0;
            for (i = 0; i < 256; i++)
                if (rows[i].used && rows[i].map == map)
                    live++;
            if (live >= JOURNAL_START_LIMIT)
                return -12;
        }
#endif
        for (i = 0; i < 256; i++)
            if (!rows[i].used) {
                r = &rows[i];
                break;
            }
    }
    if (!r)
        return -12;
    r->used = 1;
    r->map = map;
    memcpy(r->key, key, key_size(map));
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &START)
        width = 288;
    else if (map == &JOURNAL_START_MAP)
        width = 16;
#endif
    memcpy(r->value, data, width);
    return 0;
}

static long pair_delete(void *map, const void *key)
{
    struct row *r = row(map, key);
    if (!r)
        return -2;
    r->used = 0;
    return 0;
}

static struct task_struct *current_task(void)
{
    return fail_current_task ? NULL : &tasks[current_index];
}

static u64 pid_tgid(void)
{
    return current_number[current_index];
}

static void *storage_get(void *map, struct task_struct *task, void *initial, u64 flags)
{
    assert(map == &THREAD_OWNER && task == current_task() && initial == NULL);
    gets++;
    if (flags == 0 && miss_get) {
        miss_get--;
        return NULL;
    }
    if (flags == 1) {
        creates++;
        assert(ctl.outstanding > 0);
        if (fail_create)
            return NULL;
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
    if (!installed[task->index])
        return -2;
    installed[task->index] = 0;
    return 0;
}

#ifndef P11SCOPE_INVENTORY_ONLY
static void *ring_reserve(void *ring, u64 bytes, u64 flags)
{
    void *slot;
    (void)flags;
    assert(ring == &JOURNAL_RING);
    if (fail_reserve || !bytes || ring_arena_used + bytes > sizeof(ring_arena))
        return NULL;
    slot = ring_arena + ring_arena_used;
    ring_arena_used += (unsigned)bytes;
    return slot;
}

static void ring_submit(void *record, u64 flags)
{
    (void)flags;
    assert(record != NULL);
    assert(ring_log_len < 64);
    ring_log[ring_log_len++] = record;
    ring_submits++;
}

static void ring_discard(void *record, u64 flags)
{
    (void)flags;
    assert(record != NULL);
    assert(ring_log_len < 64);
    ring_log[ring_log_len++] = record;
    ring_discards++;
}
#endif

static void reset(void)
{
    unsigned i;
    memset(&ctl, 0, sizeof(ctl));
    ctl.limit = OWNER_LIMIT;
    memset(owners, 0, sizeof(owners));
    memset(installed, 0, sizeof(installed));
    memset(rows, 0, sizeof(rows));
    memset(start_value, 0, sizeof(start_value));
    for (i = 0; i < 4; i++)
        current_number[i] = (42ULL << 32) | (100 + i);
    current_index = miss_get = fail_create = fail_current_task = 0;
    gets = creates = 0;
    cas_interference_cell = NULL;
    cas_failures_remaining = cas_attempts = 0;
    owner_map_lookup = lookup;
    owner_map_update = update;
    owner_map_delete = pair_delete;
    owner_storage_get = storage_get;
    owner_storage_delete = storage_delete;
    owner_current_task = current_task;
    owner_pid_tgid = pid_tgid;
#ifndef P11SCOPE_INVENTORY_ONLY
    memset(&journal_ctl, 0, sizeof(journal_ctl));
    fail_reserve = 0;
    ring_log_len = ring_submits = ring_discards = 0;
    ring_arena_used = 0;
    journal_ring_reserve = ring_reserve;
    journal_ring_submit = ring_submit;
    journal_ring_discard = ring_discard;
#endif
}

#ifndef P11SCOPE_INVENTORY_ONLY

/* Slice-A RED matrix, per object: idle/release/reacquire, nested slots,
 * migration, TID reuse, exec cleanup, zero/wrap/CAS contention and
 * task-storage failures over the inactive leaves. */

static void abi_layout(void)
{
    reset();
    EXPECT(sizeof(struct thread_owner) == 560, "detailed owner is 560 B, got %u",
           (unsigned)sizeof(struct thread_owner));
    EXPECT(__builtin_offsetof(struct thread_owner, journal_thread) == 544, "thread word at 544");
    EXPECT(__builtin_offsetof(struct thread_owner, journal_sequence) == 552, "sequence word at 552");
    EXPECT(sizeof(struct journal_start_key) == 24, "side key is 24 B");
    EXPECT(sizeof(struct journal_start_value) == 16, "side value is 16 B");
    EXPECT(sizeof(struct journal_control) == 24, "journal control is 24 B");
#ifdef P11SCOPE_SMALL_STATE_MAPS
    EXPECT(JOURNAL_START_LIMIT == 1U, "small side limit is 1");
#else
    EXPECT(JOURNAL_START_LIMIT == 16384U, "side limit matches START");
#endif
    EXPECT(JOURNAL_THREAD_LIMIT == 16448ULL, "lifetime bound is 16,448");
    EXPECT(journal_phase_valid(JOURNAL_PHASE_PREPARING), "preparing is finite");
    EXPECT(journal_phase_valid(JOURNAL_PHASE_BEGUN), "begun is finite");
    EXPECT(journal_phase_valid(JOURNAL_PHASE_RETURNING), "returning is finite");
    EXPECT(!journal_phase_valid(0), "phase 0 is not finite");
    EXPECT(!journal_phase_valid(4), "phase 4 is not finite");
    EXPECT(P11SCOPE_OWNER_SLOT_BOUND == 512U || P11SCOPE_OWNER_SLOT_BOUND == 2112U,
           "slot bound is a frozen object");
}

static void fresh_row_mints_once(void)
{
    u64 first, again;
    reset();
    EXPECT(p11_owner_lease() == 1, "fresh row leases");
    EXPECT(owners[0].journal_thread == 0 && owners[0].journal_sequence == 0,
           "fresh words start unminted");
    first = p11_journal_thread(&owners[0], &journal_ctl);
    EXPECT(first == 1, "first ticket is 1, got %llu", (unsigned long long)first);
    EXPECT(owners[0].journal_thread == 1, "ticket installs on the row");
    again = p11_journal_thread(&owners[0], &journal_ctl);
    EXPECT(again == 1 && journal_ctl.next_thread == 1, "re-read mints nothing new");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 1, "first sequence is 1");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 2, "sequence advances checked");
    EXPECT(journal_ctl.poison == 0 && journal_ctl.admission_failures == 0, "no failure counted");
}

static void second_row_never_recycles(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "row zero leases");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "row zero mints 1");
    current_index = 1;
    EXPECT(p11_owner_lease() == 1, "row one leases");
    EXPECT(p11_journal_thread(&owners[1], &journal_ctl) == 2, "row one mints 2, never recycled");
    EXPECT(p11_journal_next_sequence(&owners[1]) == 1, "sequences are per-task");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 1, "row zero sequence is its own");
}

static void idle_release_preserves_and_reacquires(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "mint 1");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 1, "sequence 1");
    /* Release the lease through a discovery cycle: idle keeps the words. */
    {
        struct owner_discovery_key dkey = {pid_tgid(), 9, 1};
        EXPECT(p11_owner_discovery_insert(&dkey, start_value, 1) == 0, "discovery inserts");
        EXPECT(p11_owner_discovery_remove(&dkey, 1) == 0, "discovery releases");
    }
    EXPECT(owners[0].flags == 0 && owners[0].original_pid_tgid == 0, "lease state cleared");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "idle preserves lifetime words");
    /* Reacquire on the same task: same ticket, continuing sequence. */
    EXPECT(p11_owner_lease() == 1, "re-lease after idle");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "no re-mint on reacquire");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 2, "sequence continues");
    EXPECT(journal_ctl.next_thread == 1, "counter untouched by idle");
}

static void loader_row_mints_on_first_use(void)
{
    reset();
    /* A row previously created by loader work: leased, words zero. */
    EXPECT(p11_owner_lease() == 1, "loader row leases");
    owners[0].journal_thread = 0;
    owners[0].journal_sequence = 0;
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1,
           "loader row mints on first journal use");
}

static void cleanup_preserves_words(void)
{
    struct owner_start_key key;
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "mint 1");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 1, "sequence 1");
    key = (struct owner_start_key){pid_tgid(), 7, 0};
    EXPECT(!p11_owner_start_insert(&key, start_value), "START row inserts");
    EXPECT(p11_owner_cleanup() == 0, "exec/exit cleanup settles");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "cleanup removed the START row");
    EXPECT(owners[0].flags == 0 && owners[0].start_count == 0, "lease released by cleanup");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "cleanup preserves lifetime words");
    /* A second cleanup over the idle row is a no-op that keeps them. */
    EXPECT(p11_owner_cleanup() == 0, "idle cleanup settles");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "idle cleanup preserves lifetime words");
}

static void tid_reuse_mints_fresh(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "first task leases");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "first task mints 1");
    /* New task storage after TID reuse: a fresh row, a fresh ticket. */
    current_index = 2;
    current_number[2] = current_number[0];
    EXPECT(p11_owner_lease() == 1, "reused TID leases");
    EXPECT(owners[2].journal_thread == 0, "fresh storage starts unminted");
    EXPECT(p11_journal_thread(&owners[2], &journal_ctl) == 2, "reused TID mints fresh");
}

static void migration_keeps_row(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "mint 1");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 1, "sequence 1");
    /* Cross-CPU migration re-gets the same task storage: same words. */
    EXPECT(p11_owner_lease() == 1, "re-lease after migration");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "migration keeps lifetime words");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 2, "sequence continues after migration");
}

static void wrap_fails_closed(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    owners[0].journal_sequence = ~0ULL;
    EXPECT(p11_journal_next_sequence(&owners[0]) == 0, "wrapped sequence refuses");
    EXPECT(owners[0].journal_sequence == ~0ULL, "wrapped sequence is not reset");
    journal_ctl.next_thread = ~0ULL;
    EXPECT(p11_journal_mint_thread(&journal_ctl) == 0, "wrapped counter refuses");
    EXPECT(journal_ctl.poison != 0, "wrapped counter poisons");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 0, "poisoned control mints nothing");
}

static void exhaustion_refuses_and_sticks(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    journal_ctl.next_thread = JOURNAL_THREAD_LIMIT;
    EXPECT(p11_journal_mint_thread(&journal_ctl) == 0, "N+1 refuses before effects");
    EXPECT(journal_ctl.next_thread == JOURNAL_THREAD_LIMIT, "exhausted bound never resets");
    EXPECT(journal_ctl.admission_failures == 1, "exhaustion is counted");
    journal_ctl.next_thread = JOURNAL_THREAD_LIMIT - 1;
    EXPECT(p11_journal_mint_thread(&journal_ctl) == JOURNAL_THREAD_LIMIT,
           "the last ticket still mints");
    EXPECT(p11_journal_mint_thread(&journal_ctl) == 0, "then the bound sticks");
}

static void cas_contention_is_bounded(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    /* A few lost races still mint within the bound; the winners' three
     * tickets came first, so ours is fourth. */
    cas_interference_cell = &journal_ctl.next_thread;
    cas_failures_remaining = 3;
    EXPECT(p11_journal_mint_thread(&journal_ctl) == 4, "contended mint succeeds");
    EXPECT(cas_attempts == 4, "three races then success, saw %u", cas_attempts);
    /* A permanently losing streak fails closed after the bound. */
    cas_failures_remaining = JOURNAL_MINT_CAS_BOUND + 2;
    cas_attempts = 0;
    EXPECT(p11_journal_mint_thread(&journal_ctl) == 0, "hopeless contention refuses");
    EXPECT(cas_attempts == JOURNAL_MINT_CAS_BOUND, "retries are bounded, saw %u", cas_attempts);
    EXPECT(journal_ctl.admission_failures == 1, "bounded failure is counted");
    cas_interference_cell = NULL;
}

static void storage_failure_mints_nothing(void)
{
    reset();
    fail_create = 1;
    EXPECT(p11_owner_lease() == 0, "failed CREATE leases nothing");
    EXPECT(journal_ctl.next_thread == 0, "failed CREATE mints nothing");
    EXPECT(ctl.outstanding == 0, "speculative reservation refunded");
    fail_create = 0;
    fail_current_task = 1;
    EXPECT(p11_owner_lease() == 0, "missing task leases nothing");
    EXPECT(p11_journal_mint_thread(NULL) == 0, "NULL control mints nothing");
    EXPECT(p11_journal_thread(NULL, &journal_ctl) == 0, "NULL owner binds nothing");
    EXPECT(p11_journal_next_sequence(NULL) == 0, "NULL owner advances nothing");
    fail_current_task = 0;
}

static void side_map_lifecycle(void)
{
    struct journal_start_key key = {7, 3, JOURNAL_PHASE_BEGUN};
    struct journal_start_value value = {9, 0};
    struct journal_start_value *found;
    reset();
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "side insert");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->slot == 9 && found->flags == 0, "side lookup hits");
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == -1,
           "duplicate insert refuses (NOEXIST)");
    EXPECT(p11_journal_side_remove(&JOURNAL_START_MAP, &key) == 0, "side remove");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "removed row is gone");
    EXPECT(p11_journal_side_remove(&JOURNAL_START_MAP, &key) == -1, "double remove refuses");
}

static void side_map_rejects_bad_shapes(void)
{
    struct journal_start_key key = {7, 3, JOURNAL_PHASE_BEGUN};
    struct journal_start_value value = {9, 0};
    struct journal_start_key bad = key;
    struct journal_start_value bad_value = value;
    reset();
    bad.thread = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &bad, &value) == -1, "zero thread refuses");
    bad = key;
    bad.sequence = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &bad, &value) == -1,
           "zero sequence refuses");
    bad = key;
    bad.phase = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &bad, &value) == -1, "phase 0 refuses");
    bad.phase = 9;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &bad, &value) == -1, "phase 9 refuses");
    bad_value.slot = P11SCOPE_OWNER_SLOT_BOUND;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &bad_value) == -1,
           "wild slot refuses");
    bad_value = value;
    bad_value.flags = 1;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &bad_value) == -1,
           "reserved value flags refuse");
    EXPECT(p11_journal_side_insert(NULL, &key, &value) == -1, "NULL map refuses");
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, NULL, &value) == -1, "NULL key refuses");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &bad) == NULL, "bad key looks up nothing");
    EXPECT(p11_journal_side_remove(&JOURNAL_START_MAP, &bad) == -1, "bad key removes nothing");
#ifdef P11SCOPE_SMALL_STATE_MAPS
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "small row one fits");
    key.sequence = 4;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == -1,
           "small row two refuses at limit 1");
#else
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "default row fits");
    key.sequence = 4;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "default row two fits");
#endif
}

static void ring_header_matrix(void)
{
    unsigned char record[32];
    reset();
    EXPECT(p11_journal_header_init(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 7, 3) == 0,
           "valid BEGIN header writes");
    EXPECT(record[0] == 1 && record[1] == 0, "version bytes are exact");
    EXPECT(record[2] == 224 && record[3] == 0, "BEGIN length bytes are exact");
    EXPECT((u64)record[4] == JOURNAL_KIND_BEGIN && record[5] == 0,
           "kind and flags are exact");
    EXPECT(record[6] == 0 && record[7] == 0, "reserved stays zero");
    EXPECT(memcmp(record + 8, &(u64){7}, 8) == 0, "thread word is exact");
    EXPECT(memcmp(record + 16, &(u64){3}, 8) == 0, "sequence word is exact");
    EXPECT(p11_journal_header_init(
               record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, JOURNAL_FLAG_NO_END, 7,
               3) == 0,
           "BEGIN admits NO_END");
    EXPECT(p11_journal_header_init(
               record, JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, JOURNAL_FLAG_ABSENT_TAIL, 7,
               3) == 0,
           "END admits absent-tail");
    EXPECT(p11_journal_header_init(
               record, JOURNAL_END_COMPACT_BYTES, JOURNAL_KIND_END, 0, 7, 3) == 0,
           "compact END admits");
    EXPECT(p11_journal_header_init(record, JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 7, 3) ==
               0,
           "ABANDON admits");
    EXPECT(p11_journal_header_init(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 2, 7, 3) == -1,
           "BEGIN rejects bit1");
    EXPECT(p11_journal_header_init(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 3) == -1,
           "zero thread refuses");
    EXPECT(p11_journal_header_init(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 7, 0) == -1,
           "zero sequence refuses");
    EXPECT(p11_journal_header_init(record, 100, JOURNAL_KIND_BEGIN, 0, 7, 3) == -1,
           "wrong BEGIN length refuses");
    EXPECT(p11_journal_header_init(record, JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, 1, 7, 3) == -1,
           "END rejects NO_END");
    EXPECT(p11_journal_header_init(record, 100, JOURNAL_KIND_END, 0, 7, 3) == -1,
           "wrong END length refuses");
    EXPECT(p11_journal_header_init(record, JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 1, 7, 3) ==
               -1,
           "ABANDON rejects flags");
    EXPECT(p11_journal_header_init(record, JOURNAL_BEGIN_BYTES, 9, 0, 7, 3) == -1,
           "unknown kind refuses");
    EXPECT(p11_journal_header_init(NULL, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 7, 3) == -1,
           "NULL record refuses");
    EXPECT(!journal_header_valid(224, 1, 0, 1, 7, 3), "nonzero reserved refuses");
}

static void ring_reserve_submit_discard(void)
{
    void *first, *second;
    reset();
    first = p11_journal_reserve(&JOURNAL_RING, 232);
    EXPECT(first != NULL, "reserve hands out arena");
    second = p11_journal_reserve(&JOURNAL_RING, 640);
    EXPECT(second != NULL && second != first, "reserves advance");
    p11_journal_submit(first);
    EXPECT(ring_submits == 1 && ring_log_len == 1 && ring_log[0] == first, "submit is recorded");
    p11_journal_discard(second);
    EXPECT(ring_discards == 1 && ring_log_len == 2 && ring_log[1] == second,
           "discard is recorded");
    fail_reserve = 1;
    EXPECT(p11_journal_reserve(&JOURNAL_RING, 232) == NULL, "failed reserve hands out nothing");
    EXPECT(ring_log_len == 2, "failed reserve records nothing");
    fail_reserve = 0;
}

struct mint_work {
    u64 *out;
    unsigned count;
};

static void *mint_hammer(void *arg)
{
    struct mint_work *work = arg;
    unsigned i;
    for (i = 0; i < work->count; i++)
        work->out[i] = p11_journal_mint_thread(&journal_ctl);
    return NULL;
}

static void mint_contention_unique(void)
{
    static u64 tickets[4][200];
    struct mint_work work[4];
    pthread_t thread[4];
    unsigned i, j, k;
    int seen[800];
    reset();
    for (i = 0; i < 4; i++) {
        work[i].out = tickets[i];
        work[i].count = 200;
        assert(!pthread_create(&thread[i], NULL, mint_hammer, &work[i]));
    }
    for (i = 0; i < 4; i++)
        assert(!pthread_join(thread[i], NULL));
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < 4; i++)
        for (j = 0; j < 200; j++) {
            u64 ticket = tickets[i][j];
            EXPECT(ticket >= 1 && ticket <= 800, "hammer ticket %llu in range",
                   (unsigned long long)ticket);
            if (ticket >= 1 && ticket <= 800) {
                EXPECT(!seen[ticket - 1], "hammer ticket %llu is unique",
                       (unsigned long long)ticket);
                seen[ticket - 1] = 1;
            }
        }
    for (k = 0; k < 800; k++)
        if (!seen[k]) {
            EXPECT(0, "hammer ticket %u minted", k + 1);
            break;
        }
    EXPECT(journal_ctl.next_thread == 800, "counter advanced exactly, saw %llu",
           (unsigned long long)journal_ctl.next_thread);
    EXPECT(journal_ctl.poison == 0, "no poison under contention");
}

#endif /* P11SCOPE_INVENTORY_ONLY */

#ifdef P11SCOPE_INVENTORY_ONLY
static void inventory_carries_no_journal(void)
{
    struct owner_discovery_key dkey;
    reset();
    EXPECT(sizeof(struct thread_owner) == 544, "inventory owner stays 544 B, got %u",
           (unsigned)sizeof(struct thread_owner));
    /* The lease still cycles; the journal words do not exist here (any
     * reference fails compilation above, where every journal use is
     * compiled out). */
    EXPECT(p11_owner_lease() == 1, "inventory lease");
    dkey.pid_tgid = pid_tgid();
    dkey.cookie = 9;
    dkey.domain = 1;
    EXPECT(p11_owner_discovery_insert(&dkey, start_value, 1) == 0, "inventory discovery inserts");
    EXPECT(p11_owner_discovery_remove(&dkey, 1) == 0, "inventory discovery releases");
    EXPECT(owners[0].flags == 0, "inventory lease released");
}
#endif

int main(void)
{
#ifdef P11SCOPE_INVENTORY_ONLY
    inventory_carries_no_journal();
#else
    abi_layout();
    fresh_row_mints_once();
    second_row_never_recycles();
    idle_release_preserves_and_reacquires();
    loader_row_mints_on_first_use();
    cleanup_preserves_words();
    tid_reuse_mints_fresh();
    migration_keeps_row();
    wrap_fails_closed();
    exhaustion_refuses_and_sticks();
    cas_contention_is_bounded();
    storage_failure_mints_nothing();
    side_map_lifecycle();
    side_map_rejects_bad_shapes();
    ring_header_matrix();
    ring_reserve_submit_discard();
    mint_contention_unique();
#endif
    if (!failures)
        fprintf(stderr, "journal owner fixture: all checks passed\n");
    return failures != 0;
}
