/* SPDX-License-Identifier: GPL-3.0-or-later */
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
#include <stdlib.h>
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
    unsigned char value[432] __attribute__((aligned(8)));
};
static struct row rows[256];

#ifndef P11SCOPE_INVENTORY_ONLY
static struct journal_control journal_ctl;
static int fail_reserve;
static int fail_journal_delete;
static void *ring_log[64];
static unsigned ring_log_len;
static unsigned ring_submits, ring_discards;
static unsigned char ring_arena[4096] __attribute__((aligned(8)));
static unsigned ring_arena_used;
/* Scrub-before-release order proof: the last deleted journal value's
 * bytes, plus an armed assertion that the journal row is already gone
 * when its START row deletes. */
static unsigned char last_journal_deleted[24];
static int last_journal_deleted_seen;
static const struct owner_start_key *order_key;
static int order_checked;
/* Terminal-order proofs: at END submission the START custody (START +
 * OBJECT_START) is already retired with the journal row RETURNING; at
 * ABANDON submission the journal row is already deleted. Armed per
 * section; the submit hook checks them. */
static const struct owner_start_key *end_order_key;
static int end_order_checked;
static const struct owner_start_key *abandon_order_key;
static int abandon_order_checked;
/* Fault-then-discard proof: the CHECKED generation advances only in
 * the root's raise, and every discard hook observes it — never the
 * transaction's local report cell. Nothing below the root discards:
 * the transactions hand their uncommitted reservation back, and the
 * root raises the checked fault (covering that exact reservation)
 * BEFORE discarding it. The reserve hook stamps each reservation with
 * the generation at reserve time; the discard hook (armed by the root
 * around its own discard) asserts a raise covered this reservation
 * after its reserve. `raise_armed` is NULL for raw ring-leaf use. */
static u64 checked_generation;
static u64 checked_fault;
static const void *checked_ptr;
static const void *raise_armed;
static void *reserve_ptr[64];
static u64 reserve_gen[64];
static unsigned reserve_len;
/* Submitted-record dump for the Rust wire oracle: when armed (an output
 * directory), every combined-transaction submit writes its exact bytes
 * to record-%03u.bin. Armed once the combined sections start (the raw
 * ring-leaf section's submits are not wire records). */
static const char *dump_dir;
static int dump_armed;
static unsigned dump_seq;
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
        return 16;
    if (map == &START || map == &OBJECT_START)
        return 16;
    if (map == &OBJECT_DESCRIPTORS || map == &OBJECT_ZERO)
        return 4;
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
        width = 24;
    else if (map == &OBJECT_START)
        width = 432;
    else if (map == &OBJECT_DESCRIPTORS)
        width = 16;
    else if (map == &OBJECT_ZERO)
        width = 432;
#endif
    memcpy(r->value, data, width);
    return 0;
}

static long pair_delete(void *map, const void *key)
{
    struct row *r = row(map, key);
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &JOURNAL_START_MAP && fail_journal_delete)
        return -1;
#endif
    if (!r)
        return -2;
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &JOURNAL_START_MAP) {
        memcpy(last_journal_deleted, r->value, 24);
        last_journal_deleted_seen = 1;
    }
    if (order_key && map == &START && !memcmp(key, order_key, key_size(map))) {
        /* Scrub-before-release order proof: the journal row for this
         * key is already gone when its START row deletes. */
        order_checked = (row(&JOURNAL_START_MAP, key) == NULL);
    }
#endif
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
    assert(reserve_len < 64);
    reserve_ptr[reserve_len] = slot;
    reserve_gen[reserve_len] = checked_generation;
    reserve_len++;
    return slot;
}

static void ring_submit(void *record, u64 flags)
{
    const unsigned char *bytes = record;
    (void)flags;
    assert(record != NULL);
    assert(ring_log_len < 64);
    ring_log[ring_log_len++] = record;
    ring_submits++;
    if (end_order_key && bytes[4] == JOURNAL_KIND_END) {
        /* N9: the END submits only after its custody retired — START
         * and OBJECT_START gone, journal row RETURNING. */
        struct journal_start_value *found = lookup(&JOURNAL_START_MAP, end_order_key);
        end_order_checked = (lookup(&START, end_order_key) == NULL &&
                             lookup(&OBJECT_START, end_order_key) == NULL && found != NULL &&
                             found->phase == JOURNAL_PHASE_RETURNING);
    }
    if (abandon_order_key && bytes[4] == JOURNAL_KIND_ABANDON) {
        /* N9: the ABANDON submits only after ALL required cleanup
         * commits — the journal row deleted AND the START leg (START +
         * OBJECT_START) retired. */
        abandon_order_checked = (lookup(&JOURNAL_START_MAP, abandon_order_key) == NULL &&
                                 lookup(&START, abandon_order_key) == NULL &&
                                 lookup(&OBJECT_START, abandon_order_key) == NULL);
    }
    if (dump_armed && dump_dir) {
        /* The record's own header carries its length. */
        unsigned len = (unsigned)bytes[2] | ((unsigned)bytes[3] << 8);
        char path[1024];
        FILE *out;
        snprintf(path, sizeof(path), "%s/record-%03u.bin", dump_dir, dump_seq);
        out = fopen(path, "wb");
        if (out) {
            fwrite(record, 1, len, out);
            fclose(out);
        }
        dump_seq++;
    }
}

static void ring_discard(void *record, u64 flags)
{
    (void)flags;
    assert(record != NULL);
    assert(ring_log_len < 64);
    ring_log[ring_log_len++] = record;
    ring_discards++;
    if (raise_armed) {
        /* The root's discard: a checked raise covered THIS reservation
         * after its reserve — generation order, not a local shadow. */
        unsigned i;
        int covered = 0;
        EXPECT(record == raise_armed, "root discards its armed reservation");
        EXPECT(checked_ptr == record && checked_fault != JOURNAL_FAULT_NONE,
               "checked fault raised for the discarded reservation");
        for (i = 0; i < reserve_len; i++)
            if (reserve_ptr[i] == record)
                EXPECT(checked_generation > reserve_gen[i],
                       "raise generation %llu past reserve generation %llu",
                       (unsigned long long)checked_generation,
                       (unsigned long long)reserve_gen[i]);
        for (i = 0; i < reserve_len; i++)
            covered = covered || (reserve_ptr[i] == record);
        EXPECT(covered, "discarded reservation was reserved");
    }
}
#endif

#if (defined(P11SCOPE_COUNTER_BANK_PROOF) || P11SCOPE_OWNER_SLOT_BOUND == 2112U) && !defined(P11SCOPE_INVENTORY_ONLY)
static unsigned owner_loop_calls;
/* Replace only kernel helper 181; execute the production cleanup callbacks. */
static long controlled_owner_loop(u32 count, long (*callback)(u32, void *),
                                  void *context, u64 flags)
{
    assert(count == P11SCOPE_OWNER_SLOT_BOUND && flags == 0);
    owner_loop_calls++;
    for (u32 slot = 0; slot < count; slot++) {
        long stop = callback(slot, context);
        assert(stop == 0 || stop == 1);
        if (stop)
            return slot + 1;
    }
    return count;
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
#if (defined(P11SCOPE_COUNTER_BANK_PROOF) || P11SCOPE_OWNER_SLOT_BOUND == 2112U) && !defined(P11SCOPE_INVENTORY_ONLY)
    owner_loop_calls = 0;
    owner_loop = controlled_owner_loop;
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
    memset(&journal_ctl, 0, sizeof(journal_ctl));
    fail_reserve = 0;
    fail_journal_delete = 0;
    ring_log_len = ring_submits = ring_discards = 0;
    ring_arena_used = 0;
    checked_generation = 0;
    checked_fault = JOURNAL_FAULT_NONE;
    checked_ptr = NULL;
    raise_armed = NULL;
    reserve_len = 0;
    memset(last_journal_deleted, 0, sizeof(last_journal_deleted));
    last_journal_deleted_seen = 0;
    order_key = NULL;
    order_checked = 0;
    end_order_key = NULL;
    end_order_checked = 0;
    abandon_order_key = NULL;
    abandon_order_checked = 0;
    journal_ring_reserve = ring_reserve;
    journal_ring_submit = ring_submit;
    journal_ring_discard = ring_discard;
#endif
}

#ifndef P11SCOPE_INVENTORY_ONLY

/* The REAL ROOT: the only discarder. Every combined call runs through
 * these wrappers, which prove nothing discarded during the call, then
 * settle any handed-back reservation with a checked raise BEFORE its
 * discard (the discard hook observes the checked generation). A
 * handoff without a reported fault, or a settled call handing back a
 * reservation, fails here. */
static void root_raise(u64 fault, void *reservation)
{
    checked_fault = fault;
    checked_ptr = reservation;
    checked_generation++;
}

static int root_settle(struct journal_txn *txn, int rc, unsigned discards_before)
{
    EXPECT(ring_discards == discards_before, "nothing below the root discards");
    if (rc != 0 && txn->uncommitted != NULL) {
        EXPECT(*txn->fault_out != JOURNAL_FAULT_NONE,
               "every handoff carries a reported fault");
        root_raise(*txn->fault_out, txn->uncommitted);
        raise_armed = txn->uncommitted;
        p11_journal_discard(txn->uncommitted);
        raise_armed = NULL;
        txn->uncommitted = NULL;
    } else {
        EXPECT(txn->uncommitted == NULL, "settled calls hand back nothing");
    }
    return rc;
}

static int root_entry(struct journal_txn *txn)
{
    unsigned discards_before = ring_discards;
    return root_settle(txn, p11_journal_combined_entry(txn), discards_before);
}

static int root_return(struct journal_txn *txn)
{
    unsigned discards_before = ring_discards;
    return root_settle(txn, p11_journal_combined_return(txn), discards_before);
}

static int root_remove(struct journal_txn *txn)
{
    unsigned discards_before = ring_discards;
    return root_settle(txn, p11_journal_combined_remove(txn), discards_before);
}

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
    /* H8 plan StartKey-to-identity/phase contract: the side map is
     * keyed by the existing 16 B START key, and the 24 B value
     * carries identity/phase. */
    EXPECT(sizeof(struct owner_start_key) == 16, "side key is the 16 B StartKey");
    EXPECT(sizeof(struct journal_start_value) == 24, "side value is 24 B identity/phase");
    EXPECT(__builtin_offsetof(struct journal_start_value, sequence) == 8, "value sequence at 8");
    EXPECT(__builtin_offsetof(struct journal_start_value, phase) == 16, "value phase at 16");
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

static void missed_lookup_preserves_idle_words(void)
{
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "mint 1");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 1, "sequence 1");
    /* Release to idle: the words persist while lease state clears. */
    {
        struct owner_discovery_key dkey = {pid_tgid(), 9, 1};
        EXPECT(p11_owner_discovery_insert(&dkey, start_value, 1) == 0, "discovery inserts");
        EXPECT(p11_owner_discovery_remove(&dkey, 1) == 0, "discovery releases");
    }
    EXPECT(owners[0].flags == 0, "row is idle");
    /* A busy initial probe misses, then CREATE returns the existing
     * idle storage: the lifetime words must survive the reacquire. */
    miss_get = 1;
    EXPECT(p11_owner_lease() == 1, "re-lease after missed lookup");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "missed lookup preserves lifetime words, saw %llu/%llu",
           (unsigned long long)owners[0].journal_thread,
           (unsigned long long)owners[0].journal_sequence);
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "no re-mint after miss");
    EXPECT(p11_journal_next_sequence(&owners[0]) == 2, "sequence continues after miss");
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
    EXPECT(owner_map_lookup(&START, &key) != NULL && owners[0].start_count == 1,
           "live START held at cleanup");
    EXPECT(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START,
           "exec/exit cleanup settles abandoning live START");
    EXPECT(ctl.abandoned_start == 1, "cleanup abandoned one live START");
#if (defined(P11SCOPE_COUNTER_BANK_PROOF) || P11SCOPE_OWNER_SLOT_BOUND == 2112U) && !defined(P11SCOPE_INVENTORY_ONLY)
    EXPECT(owner_loop_calls == 2, "both production callback sweeps completed");
#endif
    EXPECT(owner_map_lookup(&START, &key) == NULL, "cleanup removed the START row");
    EXPECT(owners[0].flags == 0 && owners[0].start_count == 0, "lease released by cleanup");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "cleanup preserves lifetime words");
    /* A second cleanup over the idle row is a no-op that keeps them. */
    EXPECT(owners[0].start_count == 0 && owner_map_lookup(&START, &key) == NULL,
           "no live START at idle cleanup");
    EXPECT(p11_owner_cleanup() == 0, "idle cleanup settles");
    EXPECT(ctl.abandoned_start == 1, "idle cleanup abandons nothing new");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "idle cleanup preserves lifetime words");
}

static void cleanup_idle_returns_zero(void)
{
    struct owner_start_key key;
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    EXPECT(p11_journal_thread(&owners[0], &journal_ctl) == 1, "mint 1");
    key = (struct owner_start_key){pid_tgid(), 7, 0};
    EXPECT(owners[0].start_count == 0 && owner_map_lookup(&START, &key) == NULL,
           "no live START held");
    EXPECT(p11_owner_cleanup() == 0, "idle cleanup with no live START returns zero");
    EXPECT(ctl.abandoned_start == 0, "idle cleanup abandons no START");
    EXPECT(owners[0].journal_thread == 1, "idle cleanup preserves lifetime words");
    EXPECT(p11_owner_cleanup() == 0, "repeated idle cleanup stays zero");
    EXPECT(ctl.abandoned_start == 0, "repeated idle cleanup abandons nothing");
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
    struct owner_start_key key;
    struct journal_start_value value = {7, 3, JOURNAL_PHASE_BEGUN};
    struct journal_start_value *found;
    reset();
    key.pid_tgid = pid_tgid();
    key.slot = 9;
    key.pad = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "side insert");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->thread == 7 && found->sequence == 3 &&
               found->phase == JOURNAL_PHASE_BEGUN,
           "side lookup hits");
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == -1,
           "duplicate insert refuses (NOEXIST)");
    EXPECT(p11_journal_side_remove(&JOURNAL_START_MAP, &key) == 0, "side remove");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "removed row is gone");
    EXPECT(p11_journal_side_remove(&JOURNAL_START_MAP, &key) == -1, "double remove refuses");
}

static void side_map_rejects_bad_shapes(void)
{
    struct owner_start_key key;
    struct journal_start_value value = {7, 3, JOURNAL_PHASE_BEGUN};
    struct owner_start_key bad;
    struct journal_start_value bad_value;
    reset();
    key.pid_tgid = pid_tgid();
    key.slot = 9;
    key.pad = 0;
    bad = key;
    bad.pid_tgid = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &bad, &value) == -1,
           "zero carrier refuses");
    bad = key;
    bad.slot = P11SCOPE_OWNER_SLOT_BOUND;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &bad, &value) == -1, "wild slot refuses");
    bad = key;
    bad.pad = 1;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &bad, &value) == -1,
           "nonzero pad refuses");
    bad_value = value;
    bad_value.thread = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &bad_value) == -1,
           "zero thread refuses");
    bad_value = value;
    bad_value.sequence = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &bad_value) == -1,
           "zero sequence refuses");
    bad_value = value;
    bad_value.phase = 0;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &bad_value) == -1, "phase 0 refuses");
    bad_value.phase = 9;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &bad_value) == -1, "phase 9 refuses");
    EXPECT(p11_journal_side_insert(NULL, &key, &value) == -1, "NULL map refuses");
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, NULL, &value) == -1, "NULL key refuses");
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, NULL) == -1, "NULL value refuses");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &bad) == NULL, "bad key looks up nothing");
    EXPECT(p11_journal_side_remove(&JOURNAL_START_MAP, &bad) == -1, "bad key removes nothing");
#ifdef P11SCOPE_SMALL_STATE_MAPS
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "small row one fits");
    key.slot = 10;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == -1,
           "small row two refuses at limit 1");
#else
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "default row fits");
    key.slot = 10;
    EXPECT(p11_journal_side_insert(&JOURNAL_START_MAP, &key, &value) == 0, "default row two fits");
#endif
}

static void journal_transaction_matrix(void)
{
    struct owner_start_key key, nested;
    struct journal_start_value *found;
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    /* Entry mints the call's words and inserts its PREPARING row. */
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == 0,
           "entry inserts");
    EXPECT(owners[0].journal_thread == 1 && owners[0].journal_sequence == 1,
           "entry minted 1/1");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->thread == 1 && found->sequence == 1 &&
               found->phase == JOURNAL_PHASE_PREPARING,
           "row is PREPARING");
    /* A nested call on another slot shares the thread ticket with a
     * continuing sequence; both rows live side by side. Limit 1
     * holds a single row, so the nested entry refuses there until
     * the first row settles. */
    nested = key;
    nested.slot = 6;
#ifdef P11SCOPE_SMALL_STATE_MAPS
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &nested) == -1,
           "small nested entry refuses at limit 1");
#else
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &nested) == 0,
           "nested entry inserts");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &nested);
    EXPECT(found != NULL && found->thread == 1 && found->sequence == 2 &&
               found->phase == JOURNAL_PHASE_PREPARING,
           "nested row shares the ticket");
#endif
    /* Same-key re-entry collides: refused, old row intact. The failed
     * entry consumed its minted sequence (tickets never recycle). */
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == -1,
           "same-key entry collides");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->sequence == 1 && found->phase == JOURNAL_PHASE_PREPARING,
           "collision keeps the old row");
    EXPECT(owners[0].journal_sequence == 3, "failed entry consumed its sequence");
    /* Return before begun refuses; begun demands the exact words. */
    EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &key, 1, 1) == -1,
           "return before begun refuses");
    EXPECT(p11_journal_mark_begun(&JOURNAL_START_MAP, &key, 1, 3) == -1,
           "begun with live words refuses");
    EXPECT(p11_journal_mark_begun(&JOURNAL_START_MAP, &key, 2, 1) == -1,
           "begun with wrong thread refuses");
    EXPECT(p11_journal_mark_begun(&JOURNAL_START_MAP, &key, 1, 1) == 0, "begun commits");
    EXPECT(p11_journal_mark_begun(&JOURNAL_START_MAP, &key, 1, 1) == -1, "double begun refuses");
    /* Return advances the exactly-matching BEGUN row to RETURNING. */
    EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &key, 1, 3) == -1,
           "return with live words refuses");
    EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &key, 1, 1) == 0,
           "return advances");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->phase == JOURNAL_PHASE_RETURNING, "row is RETURNING");
    EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &key, 1, 1) == -1,
           "double return refuses");
    /* Removal settles the row; a missing required row is loss, a
     * missing optional row is healthy absence. */
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &key, 1) == 0,
           "required removal settles");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "removed row is gone");
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &key, 1) == -1,
           "required missing is loss");
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &key, 0) == -2,
           "optional missing is absence");
    /* The nested row settles independently through its own words;
     * at limit 1 it enters only after the first row retired. */
#ifdef P11SCOPE_SMALL_STATE_MAPS
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &nested) == 0,
           "small nested entry reuses the freed row");
    {
        u64 seq = owners[0].journal_sequence;
        found = p11_journal_side_lookup(&JOURNAL_START_MAP, &nested);
        EXPECT(found != NULL && found->thread == 1 && found->sequence == seq,
               "freed row continues the sequence");
        EXPECT(p11_journal_mark_begun(&JOURNAL_START_MAP, &nested, 1, seq) == 0,
               "small nested begun");
        EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &nested, 1, seq) == 0,
               "small nested return");
        EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &nested, 1) == 0,
               "small nested removal");
    }
#else
    EXPECT(p11_journal_mark_begun(&JOURNAL_START_MAP, &nested, 1, 2) == 0, "nested begun");
    EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &nested, 1, 2) == 0,
           "nested return");
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &nested, 1) == 0,
           "nested removal");
#endif
}

static void journal_transaction_refusals(void)
{
    struct owner_start_key key, bad;
    struct journal_start_value *found;
    reset();
    EXPECT(p11_owner_lease() == 1, "lease");
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    /* NULL legs refuse everywhere. */
    EXPECT(p11_journal_entry(NULL, &journal_ctl, &JOURNAL_START_MAP, &key) == -1,
           "entry with NULL owner refuses");
    EXPECT(p11_journal_entry(&owners[0], NULL, &JOURNAL_START_MAP, &key) == -1,
           "entry with NULL control refuses");
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, NULL, &key) == -1,
           "entry with NULL map refuses");
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, NULL) == -1,
           "entry with NULL key refuses");
    /* A key for another owner, or a misshapen one, never enters. */
    bad = key;
    bad.pid_tgid = key.pid_tgid + 1;
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &bad) == -1,
           "foreign-carrier entry refuses");
    bad = key;
    bad.slot = P11SCOPE_OWNER_SLOT_BOUND;
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &bad) == -1,
           "wild-slot entry refuses");
    bad = key;
    bad.pad = 1;
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &bad) == -1,
           "padded entry refuses");
    /* A released owner holds no rows: entry, return and removal all
     * refuse after its lease clears. */
    {
        struct owner_discovery_key dkey = {pid_tgid(), 9, 1};
        EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == 0,
               "entry inserts");
        EXPECT(p11_owner_discovery_insert(&dkey, start_value, 1) == 0, "discovery inserts");
        EXPECT(p11_owner_discovery_remove(&dkey, 1) == 0, "discovery releases");
    }
    EXPECT(owners[0].flags == 0, "owner released");
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == -1,
           "released owner never enters");
    EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &key, 1, 1) == -1,
           "released owner never returns");
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &key, 1) == -1,
           "released owner never removes");
    /* Re-lease and settle the leftover row so later sections start
     * clean; settlement still works after the release cycle. This pins
     * leg-after-release refusal only — the scrub-before-release
     * ordering proof lives in combined_scrub_before_release, which
     * scrubs and releases in ONE call. */
    EXPECT(p11_owner_lease() == 1, "re-lease");
    EXPECT(p11_journal_mark_begun(&JOURNAL_START_MAP, &key, 1, 1) == 0, "leftover begun");
    EXPECT(p11_journal_return(&owners[0], &JOURNAL_START_MAP, &key, 1, 1) == 0, "leftover return");
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &key, 1) == 0, "leftover removal");
    /* A poisoned control and a wrapped sequence mint nothing. Poison
     * refuses before any effect, even with a minted ticket. */
    journal_ctl.poison = 1;
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == -1,
           "poisoned control refuses entry");
    EXPECT(owners[0].journal_sequence == 1, "poison refuses before effects");
    journal_ctl.poison = 0;
    owners[0].journal_sequence = ~0ULL;
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == -1,
           "wrapped sequence refuses entry");
    /* A contradicted row retires scrubbed but reports loss, never an
     * orphan and never success. */
    owners[0].journal_sequence = 1;
    EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == 0,
           "entry inserts");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL, "row present to contradict");
    found->phase = 9;
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &key, 1) == -1,
           "contradicted removal reports loss");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL,
           "contradicted row still retires");
    EXPECT(p11_journal_remove(&owners[0], &JOURNAL_START_MAP, &key, 7) == -1,
           "non-bit required refuses");
#ifdef P11SCOPE_SMALL_STATE_MAPS
    {
        struct owner_start_key second = key;
        second.slot = 6;
        EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == 0,
               "small entry one fits");
        EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &second) == -1,
               "small entry two refuses at limit 1");
    }
#else
    {
        struct owner_start_key second = key;
        second.slot = 6;
        EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &key) == 0,
               "default entry one fits");
        EXPECT(p11_journal_entry(&owners[0], &journal_ctl, &JOURNAL_START_MAP, &second) == 0,
               "default entry two fits");
    }
#endif
}

static int init_header(unsigned char *record, u64 bytes, u64 kind, u64 flags, u64 thread,
                       u64 sequence)
{
    struct journal_header_spec spec = {bytes, kind, flags, thread, sequence};
    return p11_journal_header_init(record, &spec);
}

static void ring_header_matrix(void)
{
    unsigned char record[32];
    reset();
    EXPECT(sizeof(struct journal_header_spec) == 40, "header spec is 40 B");
    EXPECT(init_header(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 7, 3) == 0,
           "valid BEGIN header writes");
    EXPECT(record[0] == 1 && record[1] == 0, "version bytes are exact");
    EXPECT(record[2] == 224 && record[3] == 0, "BEGIN length bytes are exact");
    EXPECT((u64)record[4] == JOURNAL_KIND_BEGIN && record[5] == 0,
           "kind and flags are exact");
    EXPECT(record[6] == 0 && record[7] == 0, "reserved stays zero");
    EXPECT(memcmp(record + 8, &(u64){7}, 8) == 0, "thread word is exact");
    EXPECT(memcmp(record + 16, &(u64){3}, 8) == 0, "sequence word is exact");
    EXPECT(init_header(
               record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, JOURNAL_FLAG_NO_END, 7,
               3) == 0,
           "BEGIN admits NO_END");
    EXPECT(init_header(
               record, JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, JOURNAL_FLAG_ABSENT_TAIL, 7,
               3) == 0,
           "END admits absent-tail");
    EXPECT(init_header(
               record, JOURNAL_END_COMPACT_BYTES, JOURNAL_KIND_END, 0, 7, 3) == 0,
           "compact END admits");
    EXPECT(init_header(record, JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 7, 3) ==
               0,
           "ABANDON admits");
    EXPECT(init_header(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 2, 7, 3) == -1,
           "BEGIN rejects bit1");
    EXPECT(init_header(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 3) == -1,
           "zero thread refuses");
    EXPECT(init_header(record, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 7, 0) == -1,
           "zero sequence refuses");
    EXPECT(init_header(record, 100, JOURNAL_KIND_BEGIN, 0, 7, 3) == -1,
           "wrong BEGIN length refuses");
    EXPECT(init_header(record, JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, 1, 7, 3) == -1,
           "END rejects NO_END");
    EXPECT(init_header(record, 100, JOURNAL_KIND_END, 0, 7, 3) == -1,
           "wrong END length refuses");
    EXPECT(init_header(record, JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 1, 7, 3) ==
               -1,
           "ABANDON rejects flags");
    EXPECT(init_header(record, JOURNAL_BEGIN_BYTES, 9, 0, 7, 3) == -1,
           "unknown kind refuses");
    EXPECT(init_header(NULL, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 7, 3) == -1,
           "NULL record refuses");
    EXPECT(p11_journal_header_init(record, NULL) == -1, "NULL spec refuses");
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
    pthread_barrier_t *round;
};

static void mint_pthread_require(int rc, const char *operation)
{
    if (!rc)
        return;
    /* A partial thread start or failed barrier must terminate this fixture,
     * never leave the parent waiting for workers missing a participant. */
    fprintf(stderr, "FAIL mint_contention_unique: %s failed: %d\n", operation, rc);
    exit(EXIT_FAILURE);
}

static void *mint_hammer(void *arg)
{
    struct mint_work *work = arg;
    unsigned i;
    for (i = 0; i < work->count; i++) {
        int rc = pthread_barrier_wait(work->round);
        mint_pthread_require(rc == PTHREAD_BARRIER_SERIAL_THREAD ? 0 : rc, "round start");
        work->out[i] = p11_journal_mint_thread(&journal_ctl);
        rc = pthread_barrier_wait(work->round);
        mint_pthread_require(rc == PTHREAD_BARRIER_SERIAL_THREAD ? 0 : rc, "round end");
    }
    return NULL;
}

static void mint_contention_unique(void)
{
    static u64 tickets[4][200];
    struct mint_work work[4];
    pthread_t thread[4];
    pthread_barrier_t round;
    unsigned i, j, k, minted = 0;
    int seen[800];
    reset();
    /* Each round permits one call per worker: at most three other calls can
     * win while one call is retrying, within the production eight-CAS bound.
     * The separate interference control proves bounded refusal. These rounds
     * do not change the host volatile accesses into C11 atomics. */
    mint_pthread_require(pthread_barrier_init(&round, NULL, 4), "barrier init");
    for (i = 0; i < 4; i++) {
        work[i].out = tickets[i];
        work[i].count = 200;
        work[i].round = &round;
        mint_pthread_require(
            pthread_create(&thread[i], NULL, mint_hammer, &work[i]), "thread create");
    }
    for (i = 0; i < 4; i++)
        mint_pthread_require(pthread_join(thread[i], NULL), "thread join");
    mint_pthread_require(pthread_barrier_destroy(&round), "barrier destroy");
    memset(seen, 0, sizeof(seen));
    for (i = 0; i < 4; i++)
        for (j = 0; j < 200; j++) {
            u64 ticket = tickets[i][j];
            minted += ticket != 0;
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
    EXPECT(journal_ctl.admission_failures == 0, "no bounded-round admission refusal, saw %llu",
           (unsigned long long)journal_ctl.admission_failures);
    fprintf(stderr,
            "mint_contention_unique: attempts=800 nonzero=%u counter=%llu "
            "admission_failures=%llu poison=%llu\n",
            minted, (unsigned long long)journal_ctl.next_thread,
            (unsigned long long)journal_ctl.admission_failures,
            (unsigned long long)journal_ctl.poison);
}

/* Seed the OBJECT_START subordinate path: descriptor row 1 (marker
 * 2 selects it) and the zero row allocation copies. */
static void seed_object_tables(void)
{
    struct object_descriptor_row desc;
    static u64 zero[OBJECT_START_WORDS];
    u32 one = 1, zero_key = 0;
    memset(&desc, 0, sizeof(desc));
    desc.function = 0;
    desc.action = 1;
    desc.guard = 1;
    EXPECT(owner_map_update(&OBJECT_DESCRIPTORS, &one, &desc, 0) == 0, "descriptor seeds");
    EXPECT(owner_map_update(&OBJECT_ZERO, &zero_key, zero, 0) == 0, "zero seeds");
}

/* A required-marker START value: entry time, marker 2 at the marker
 * word, image words for the side binding. */
static void required_start_value(unsigned char *out)
{
    u64 ts = 777, marker = 2, cookie = 0xc0ffee, exec = 0xe;
    memset(out, 0, 288);
    memcpy(out + OBJECT_CALL_START_TS_OFF, &ts, 8);
    memcpy(out + OBJECT_CALL_START_MARKER_OFF, &marker, 8);
    memcpy(out + OBJECT_CALL_START_IMAGE_OFF, &cookie, 8);
    memcpy(out + OBJECT_CALL_START_IMAGE_OFF + 8, &exec, 8);
}

/* Root-supplied facts mirroring the Rust wire oracle's valid fixtures
 * (tests/object_journal_contracts.rs valid_begin/valid_full_payload): a
 * C_CreateObject call (descriptor 21) with a VALUE session, a VALID
 * entry stamp and inspected-empty requested lists. Slot/pid bind to the
 * live key (the native exact-match gate); the rest are fixed evidence. */
static void make_begin_facts(const struct owner_start_key *key, struct journal_begin_facts *facts)
{
    static const unsigned char stamp[16] = {7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0,
                                            0, 3, 0, 0, 0x80};
    memset(facts, 0, sizeof(*facts));
    facts->pid_tgid = key->pid_tgid;
    facts->image_cookie = 0x1010101010101010ULL;
    facts->image_exec = 0x2020202020202020ULL;
    facts->entry_ns = 0x3030303030303030ULL;
    facts->entry_ip = 0x4040404040404040ULL;
    memcpy(facts->entry_stamp, stamp, sizeof(stamp));
    facts->session_word = 0x5050505050505050ULL;
    facts->slot = key->slot;
    facts->descriptor = 21;
    facts->capture = 0;
    facts->layout = JOURNAL_LAYOUT_LP64;
    facts->session_status = JOURNAL_HANDLE_VALUE;
    facts->slot_id = 0x6060606060606060ULL;
    facts->call_flags = 0x7070707070707070ULL;
    facts->user_type = 1;
}

static void make_abandon_facts(const struct owner_start_key *key,
                               struct journal_abandon_facts *facts)
{
    memset(facts, 0, sizeof(*facts));
    facts->pid_tgid = key->pid_tgid;
    facts->image_cookie = 0x1010101010101010ULL;
    facts->image_exec = 0x2020202020202020ULL;
    facts->entry_ns = 0x3030303030303030ULL;
    facts->slot = key->slot;
    facts->reason = 6;
}

/* The 608-byte H7 completed payload behind an END, mirroring the
 * oracle's valid_full_payload: CALL base, affiliation 1, valid Create
 * tail, zero legacy span (compact-eligible). */
static void build_end_payload(unsigned char out[JOURNAL_END_PAYLOAD_BYTES])
{
    u64 v;
    memset(out, 0, JOURNAL_END_PAYLOAD_BYTES);
    v = 0x1111111111111111ULL;
    memcpy(out + 0, &v, 8);
    v = 0x2222222222222222ULL;
    memcpy(out + 8, &v, 8);
    v = 0xAAAABBBBCCCCDDDDULL;
    memcpy(out + 16, &v, 8);
    v = 0x3333333333333333ULL;
    memcpy(out + 24, &v, 8);
    v = 0x5050505050505050ULL;
    memcpy(out + 32, &v, 8);
    v = 0x6060606060606060ULL;
    memcpy(out + 40, &v, 8);
    v = 0x7070707070707070ULL;
    memcpy(out + 56, &v, 8);
    {
        u32 w = 11;
        memcpy(out + 104, &w, 4);
        w = 1;
        memcpy(out + 112, &w, 4);
        w = JOURNAL_EVENT_CALL;
        memcpy(out + 284, &w, 4);
    }
    v = 0x1010101010101010ULL;
    memcpy(out + 288, &v, 8);
    v = 0x2020202020202020ULL;
    memcpy(out + 296, &v, 8);
    v = 1;
    memcpy(out + 320, &v, 8);
    v = 0x4040404040404040ULL;
    memcpy(out + 328, &v, 8);
    {
        /* Joined entry/exit stamps: epoch/global/fault/slot/VALID. */
        static const unsigned char stamp[16] = {7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0,
                                                0, 3, 0, 0, 0x80};
        memcpy(out + 336, stamp, 16);
        memcpy(out + 352, stamp, 16);
    }
    {
        /* Valid Create tail: version/length/index, LP64 CREATE action,
         * VALUE result word. */
        unsigned char *tail = out + 368;
        u32 w;
        unsigned h = 1;
        memcpy(tail + 0, &h, 2);
        h = 240;
        memcpy(tail + 2, &h, 2);
        w = 21;
        memcpy(tail + 4, &w, 4);
        tail[12] = JOURNAL_LAYOUT_LP64;
        tail[13] = 1;
        v = 0x9090909090909090ULL;
        memcpy(tail + 32, &v, 8);
        tail[114] = JOURNAL_HANDLE_VALUE;
    }
}

static u32 record_u32(const unsigned char *record, unsigned off)
{
    u32 v;
    memcpy(&v, record + off, 4);
    return v;
}

static u64 record_u64(const unsigned char *record, unsigned off)
{
    u64 v;
    memcpy(&v, record + off, 8);
    return v;
}

static void check_submitted(unsigned index, u64 bytes, u64 kind, u64 flags, u64 thread,
                            u64 sequence, const char *what)
{
    const unsigned char *record = ring_log[index];
    u64 got_bytes = (u64)record[2] | ((u64)record[3] << 8);
    EXPECT(got_bytes == bytes, "%s length %llu, got %llu", what, (unsigned long long)bytes,
           (unsigned long long)got_bytes);
    EXPECT(record[0] == 1 && record[1] == 0, "%s version is exact", what);
    EXPECT((u64)record[4] == kind && (u64)record[5] == flags, "%s kind/flags are exact", what);
    EXPECT(record[6] == 0 && record[7] == 0, "%s reserved stays zero", what);
    EXPECT(memcmp(record + 8, &thread, 8) == 0, "%s thread word is exact", what);
    EXPECT(memcmp(record + 16, &sequence, 8) == 0, "%s sequence word is exact", what);
    if (kind == JOURNAL_KIND_BEGIN) {
        /* C4: the BEGIN carries valid wire facts, never zero fill. */
        EXPECT(record_u32(record, 108) == 21, "%s descriptor is Create+1", what);
        EXPECT(record[124] == JOURNAL_LAYOUT_LP64, "%s layout is LP64", what);
        EXPECT(record[78] == 0 && record[79] == 0x80, "%s stamp is VALID", what);
        EXPECT(record[125] == JOURNAL_HANDLE_VALUE && record_u64(record, 80) != 0,
               "%s session is VALUE with a nonzero word", what);
        EXPECT(record_u32(record, 220) == 0, "%s trailing reserved is zero", what);
    } else if (kind == JOURNAL_KIND_ABANDON) {
        EXPECT(record_u32(record, 52) >= JOURNAL_REASON_MIN &&
                   record_u32(record, 52) <= JOURNAL_REASON_MAX,
               "%s reason is finite", what);
    } else if (kind == JOURNAL_KIND_END && bytes == JOURNAL_END_FULL_BYTES) {
        EXPECT(record_u32(record, JOURNAL_COMMON_BYTES + 284) == JOURNAL_EVENT_CALL,
               "%s event type is CALL", what);
        EXPECT(record_u64(record, JOURNAL_COMMON_BYTES + 320) <= 1,
               "%s affiliation is at most 1", what);
    }
}

static void combined_entry_publishes_begin(void)
{
    struct owner_start_key key;
    struct journal_start_value *found;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_txn txn;
    struct journal_begin_facts facts;
    struct object_start *side;
    u64 fault = 0;
    reset();
    seed_object_tables();
    /* The combined sections submit wire records: arm the oracle dump. */
    dump_dir = getenv("P11_JOURNAL_DUMP_DIR");
    dump_armed = (dump_dir != NULL);
    dump_seq = 0;
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    EXPECT(root_entry(&txn) == 0, "combined entry settles");
    EXPECT(fault == JOURNAL_FAULT_NONE, "no fault, got %llu", (unsigned long long)fault);
    /* All three legs landed: START row, OBJECT_START subordinate with
     * its immutable binding, journal row committed to BEGUN. */
    EXPECT(owner_map_lookup(&START, &key) != NULL, "START row present");
    side = owner_map_lookup(&OBJECT_START, &key);
    EXPECT(side != NULL, "OBJECT_START subordinate allocated");
    EXPECT(side->descriptor_index == 1 && side->action == 1, "subordinate carries index/action");
    EXPECT(side->task_cookie == 0xc0ffee && side->exec_id == 0xe && side->entry_ns == 777,
           "subordinate binding matches the START row");
    EXPECT(side->phase == OBJECT_PHASE_ENTRY, "subordinate phase is entry");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->thread == 1 && found->sequence == 1 &&
               found->phase == JOURNAL_PHASE_BEGUN,
           "journal row is BEGUN(1,1)");
    /* The BEGIN published exactly once with the row's own words. */
    EXPECT(ring_submits == 1 && ring_discards == 0, "one submit, no discard");
    check_submitted(0, JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 1, 1, "BEGIN");
}

static void combined_return_publishes_end(void)
{
    struct owner_start_key key;
    struct journal_start_value *found;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_header_spec end;
    struct journal_txn txn;
    struct journal_begin_facts facts;
    unsigned char end_payload[JOURNAL_END_PAYLOAD_BYTES];
    u64 fault = 0;
    reset();
    seed_object_tables();
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    build_end_payload(end_payload);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    txn.end_payload = end_payload;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    /* Return advances, retires START with its subordinate, and only
     * then submits END: the terminal submits after the required
     * cleanup commits. The submit hook proves the order. */
    end.bytes = JOURNAL_END_FULL_BYTES;
    end.kind = JOURNAL_KIND_END;
    end.flags = 0;
    end.thread = 1;
    end.sequence = 1;
    txn.spec = &end;
    txn.thread = 1;
    txn.sequence = 1;
    end_order_key = &key;
    end_order_checked = 0;
    EXPECT(root_return(&txn) == 0, "combined return settles");
    EXPECT(fault == JOURNAL_FAULT_NONE, "no fault, got %llu", (unsigned long long)fault);
    EXPECT(end_order_checked, "START custody retired before END submission");
    end_order_key = NULL;
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->phase == JOURNAL_PHASE_RETURNING, "row is RETURNING");
    EXPECT(ring_submits == 2 && ring_discards == 0, "BEGIN then END submitted");
    check_submitted(1, JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, 0, 1, 1, "END");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START retired before END submission");
    EXPECT(owner_map_lookup(&OBJECT_START, &key) == NULL, "subordinate retired with START");
    EXPECT(owners[0].flags == 0, "emptied lease released at return");
    /* Removal retires the RETURNING row silently: the END was the
     * disposition, so no ABANDON follows (one original key
     * disposition); the already-retired START is healthy absence. */
    txn.spec = NULL;
    txn.required = 1;
    EXPECT(root_remove(&txn) == 0, "combined remove settles");
    EXPECT(fault == JOURNAL_FAULT_NONE, "no fault, got %llu", (unsigned long long)fault);
    EXPECT(ring_submits == 2, "no ABANDON after END");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    /* The compact END shape publishes too. */
    key.slot = 6;
    make_begin_facts(&key, &facts);
    txn.spec = &begin;
    txn.required = 0;
    txn.thread = 0;
    txn.sequence = 0;
    EXPECT(root_entry(&txn) == 0, "second entry settles");
    end.bytes = JOURNAL_END_COMPACT_BYTES;
    end.thread = 1;
    end.sequence = 2;
    txn.spec = &end;
    txn.thread = 1;
    txn.sequence = 2;
    end_order_key = &key;
    end_order_checked = 0;
    EXPECT(root_return(&txn) == 0, "compact END settles");
    EXPECT(end_order_checked, "START custody retired before compact END");
    end_order_key = NULL;
    check_submitted(3, JOURNAL_END_COMPACT_BYTES, JOURNAL_KIND_END, 0, 1, 2, "compact END");
}

static void combined_remove_abandons_unsettled(void)
{
    struct owner_start_key key;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_header_spec abandon = {JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 1, 1};
    struct journal_txn txn;
    struct journal_begin_facts facts;
    struct journal_abandon_facts afacts;
    u64 fault = 0;
    reset();
    seed_object_tables();
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    make_abandon_facts(&key, &afacts);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    txn.abandon = &afacts;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    /* Exit cleanup without a return: the unsettled row deletes (the
     * required cleanup commits), then ABANDON submits, then the START
     * leg retires — one call, terminal last. */
    txn.spec = &abandon;
    txn.thread = 1;
    txn.sequence = 1;
    txn.required = 1;
    abandon_order_key = &key;
    abandon_order_checked = 0;
    EXPECT(root_remove(&txn) == 0, "abandoning remove settles");
    EXPECT(abandon_order_checked, "full cleanup before ABANDON submission");
    abandon_order_key = NULL;
    EXPECT(fault == JOURNAL_FAULT_NONE, "no fault, got %llu", (unsigned long long)fault);
    EXPECT(ring_submits == 2, "BEGIN then ABANDON submitted");
    check_submitted(1, JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 1, 1, "ABANDON");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START row retired");
    EXPECT(owner_map_lookup(&OBJECT_START, &key) == NULL, "subordinate retired");
    EXPECT(owners[0].flags == 0, "emptied lease released");
}

static void combined_scrub_before_release(void)
{
    struct owner_start_key key;
    struct journal_start_value *found;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_txn txn;
    struct journal_begin_facts facts;
    u64 fault = 0;
    unsigned i;
    int scrubbed;
    reset();
    seed_object_tables();
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL, "row present to contradict");
    found->phase = 9;
    /* One call: the contradicted row is scrubbed BEFORE the lease is
     * released — no release-then-reacquire-to-remove. The START-delete
     * stub asserts the journal row is already gone. */
    order_key = &key;
    order_checked = 0;
    last_journal_deleted_seen = 0;
    txn.spec = NULL;
    txn.thread = 1;
    txn.sequence = 1;
    txn.required = 1;
    EXPECT(root_remove(&txn) == -1, "contradicted remove reports loss");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted, got %llu",
           (unsigned long long)fault);
    EXPECT(last_journal_deleted_seen, "journal deletion observed");
    scrubbed = 1;
    for (i = 0; i < 24; i++)
        scrubbed = scrubbed && (last_journal_deleted[i] == 0);
    EXPECT(scrubbed, "contradicted bytes scrubbed before deletion");
    EXPECT(order_checked, "journal row gone before its START row deleted");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START row retired");
    EXPECT(owner_map_lookup(&OBJECT_START, &key) == NULL, "subordinate retired");
    EXPECT(owners[0].flags == 0, "lease released in the same call");
    EXPECT(ring_submits == 1, "no ABANDON for contradicted rows: the fault is the disposition");
    order_key = NULL;
}

static void combined_collision_lifecycle(void)
{
    struct owner_start_key key;
    struct journal_start_value *found;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_header_spec end = {JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, 0, 1, 1};
    struct journal_txn txn;
    struct journal_begin_facts facts;
    unsigned char end_payload[JOURNAL_END_PAYLOAD_BYTES];
    u64 fault = 0;
    reset();
    seed_object_tables();
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    build_end_payload(end_payload);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    txn.end_payload = end_payload;
    EXPECT(root_entry(&txn) == 0, "first entry settles");
    /* A second entry on the same key refuses BEFORE effects: the busy
     * key never reaches the H7 insert, so nothing unwinds — the first
     * call keeps its START row, its journal row and its lease. Never
     * release-then-reacquire under a retained journal row. */
    fault = 0;
    EXPECT(root_entry(&txn) == -1, "colliding entry refuses");
    EXPECT(fault == JOURNAL_FAULT_START_LEG, "START leg faulted, got %llu",
           (unsigned long long)fault);
    EXPECT(owner_map_lookup(&START, &key) != NULL, "first START row intact");
    EXPECT(owner_map_lookup(&OBJECT_START, &key) != NULL, "first subordinate intact");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->thread == 1 && found->sequence == 1 &&
               found->phase == JOURNAL_PHASE_BEGUN,
           "first journal row intact");
    EXPECT(owners[0].flags != 0, "lease still held");
    EXPECT(ring_submits == 1, "colliding entry published nothing");
    /* The first call proceeds normally: return retires START, then the
     * silent removal retires the RETURNING row. */
    fault = 0;
    txn.spec = &end;
    txn.thread = 1;
    txn.sequence = 1;
    EXPECT(root_return(&txn) == 0, "first return settles");
    fault = 0;
    txn.spec = NULL;
    txn.required = 1;
    EXPECT(root_remove(&txn) == 0, "first remove settles");
    /* The key is reusable after full retirement; the refused entry
     * minted nothing. */
    fault = 0;
    txn.spec = &begin;
    txn.thread = 0;
    txn.sequence = 0;
    EXPECT(root_entry(&txn) == 0, "reused key enters");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->thread == 1 && found->sequence == 2 &&
               found->phase == JOURNAL_PHASE_BEGUN,
           "reused key continues the sequence");
    /* Retire the reused call, then the orphan-return case runs
     * alone (also under the small limit). */
    fault = 0;
    txn.spec = &end;
    end.thread = 1;
    end.sequence = 2;
    txn.thread = 1;
    txn.sequence = 2;
    EXPECT(root_return(&txn) == 0, "reused return settles");
    fault = 0;
    txn.spec = NULL;
    txn.required = 1;
    EXPECT(root_remove(&txn) == 0, "reused remove settles");
    /* A return whose START row vanished refuses quietly through the
     * START leg: the journal row stays intact and publishes nothing.
     * Setup deletes the START row directly; the raw presence check
     * refuses without touching H7 poison, so no poison sticks. The
     * direct delete still corrupts the START count, so this closes
     * the section. */
    {
        struct owner_start_key orphan = key;
        unsigned submits_before;
        orphan.slot = 7;
        make_begin_facts(&orphan, &facts);
        txn.key = &orphan;
        txn.spec = &begin;
        txn.required = 0;
        txn.thread = 0;
        txn.sequence = 0;
        fault = 0;
        EXPECT(root_entry(&txn) == 0, "orphan-setup entry settles");
        EXPECT(owner_map_delete(&START, &orphan) == 0, "START row vanishes");
        submits_before = ring_submits;
        txn.spec = &end;
        end.thread = 1;
        end.sequence = 3;
        txn.thread = 1;
        txn.sequence = 3;
        fault = 0;
        EXPECT(root_return(&txn) == -1, "orphaned return refuses");
        EXPECT(fault == JOURNAL_FAULT_START_LEG, "START leg faulted, got %llu",
               (unsigned long long)fault);
        found = p11_journal_side_lookup(&JOURNAL_START_MAP, &orphan);
        EXPECT(found != NULL && found->phase == JOURNAL_PHASE_BEGUN, "orphan row intact");
        EXPECT(ring_submits == submits_before, "no END without its START");
        EXPECT(ctl.poison == 0, "quiet refusal poisons nothing");
    }
}

static void combined_fault_paths(void)
{
    struct owner_start_key key;
    struct journal_start_value *found;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_header_spec end = {JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, 0, 1, 1};
    struct journal_header_spec abandon = {JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 1, 1};
    struct journal_txn txn, bad;
    struct journal_begin_facts facts, bad_facts;
    struct journal_abandon_facts afacts, bad_afacts;
    unsigned char end_payload[JOURNAL_END_PAYLOAD_BYTES];
    unsigned char bad_payload[JOURNAL_END_PAYLOAD_BYTES];
    u64 fault = 0;
    reset();
    seed_object_tables();
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    make_abandon_facts(&key, &afacts);
    build_end_payload(end_payload);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    txn.end_payload = end_payload;
    txn.abandon = &afacts;
    /* Cells are caller-owned and sticky: each independent probe below
     * passes a fresh cell (fault = 0); only the deliberate N10
     * sequences share one. */
    /* NULL wiring refuses before effects. */
    EXPECT(p11_journal_combined_entry(NULL) == -1, "NULL txn refuses");
    EXPECT(p11_journal_combined_return(NULL) == -1, "NULL return refuses");
    EXPECT(p11_journal_combined_remove(NULL) == -1, "NULL remove refuses");
    memset(&bad, 0, sizeof(bad));
    EXPECT(root_entry(&bad) == -1, "NULL fault cell refuses");
    bad = txn;
    bad.fault_out = NULL;
    EXPECT(root_entry(&bad) == -1, "missing fault cell refuses");
    bad = txn;
    bad.jctl = NULL;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "NULL control refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    bad = txn;
    bad.journal_map = NULL;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "NULL journal map refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    bad = txn;
    bad.ring = NULL;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "NULL ring refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    bad = txn;
    bad.key = NULL;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "NULL key refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    bad = txn;
    bad.start_value = NULL;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "NULL START value refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    bad = txn;
    bad.spec = NULL;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "NULL spec refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    bad = txn;
    bad.begin = NULL;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "NULL BEGIN facts refuse");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    bad = txn;
    bad.end_payload = NULL;
    fault = 0;
    EXPECT(root_return(&bad) == -1, "NULL END payload refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    EXPECT(owners[0].flags == 0, "no lease from refused entries");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "no START row from refused entries");
    EXPECT(ring_submits == 0 && ring_discards == 0, "no ring use from refused entries");
    /* A template smuggling identity refuses before effects. */
    {
        struct journal_header_spec smuggled = begin;
        smuggled.thread = 9;
        bad = txn;
        bad.spec = &smuggled;
        fault = 0;
        EXPECT(root_entry(&bad) == -1, "smuggled identity refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
               (unsigned long long)fault);
        EXPECT(owner_map_lookup(&START, &key) == NULL, "smuggling leaves no START row");
    }
    /* A tainted cell refuses entry before effects: the earlier fault
     * is the report, and nothing is touched. */
    fault = JOURNAL_FAULT_PUBLISH;
    EXPECT(root_entry(&txn) == -1, "tainted entry refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "earlier fault preserved");
    EXPECT(owners[0].flags == 0, "tainted entry leases nothing");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "tainted entry inserts nothing");
    EXPECT(ring_submits == 0 && ring_discards == 0, "tainted entry reserves nothing");
    /* Invalid BEGIN facts refuse with unwind: bad layout, zero stamp,
     * zero descriptor, slot/pid confusion. Each reserves, fails the
     * finite gate, reports the fault, hands back, unwinds; the root
     * raises and discards each handoff. */
    {
        unsigned discards_before = ring_discards;
        bad = txn;
        bad_facts = facts;
        bad_facts.layout = 9;
        bad.begin = &bad_facts;
        fault = 0;
        EXPECT(root_entry(&bad) == -1, "bad layout refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        bad_facts = facts;
        memset(bad_facts.entry_stamp, 0, sizeof(bad_facts.entry_stamp));
        fault = 0;
        EXPECT(root_entry(&bad) == -1, "zero stamp refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        bad_facts = facts;
        bad_facts.descriptor = 0;
        fault = 0;
        EXPECT(root_entry(&bad) == -1, "zero descriptor refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        bad_facts = facts;
        bad_facts.slot = 6;
        fault = 0;
        EXPECT(root_entry(&bad) == -1, "slot-confused facts refuse");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        bad_facts = facts;
        bad_facts.pid_tgid = 1;
        fault = 0;
        EXPECT(root_entry(&bad) == -1, "pid-confused facts refuse");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        EXPECT(ring_discards == discards_before + 5, "each bad-facts entry discarded once");
        EXPECT(ring_submits == 0, "bad facts submit nothing");
        EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "legs unwound");
        EXPECT(owner_map_lookup(&START, &key) == NULL, "START legs unwound");
        EXPECT(owners[0].flags == 0, "unwinds released the lease");
    }
    /* Reserve failure unwinds every leg: fault set, nothing kept. */
    fail_reserve = 1;
    fault = 0;
    EXPECT(root_entry(&txn) == -1, "reserve failure refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
           (unsigned long long)fault);
    EXPECT(ring_submits == 0 && ring_discards == 5, "nothing reserved, nothing discarded");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal leg unwound");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START leg unwound");
    EXPECT(owners[0].flags == 0, "unwind released the lease");
    fail_reserve = 0;
    /* A bad header kind refuses before effects (operation-specific
     * kinds): no reserve, no discard, no legs touched. Every root call
     * below proves nothing discarded during the call and settles any
     * handed-back reservation with a checked raise before its discard. */
    {
        struct journal_header_spec bad_kind = begin;
        bad_kind.kind = 9;
        bad = txn;
        bad.spec = &bad_kind;
        fault = 0;
        EXPECT(root_entry(&bad) == -1, "bad header refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
               (unsigned long long)fault);
        EXPECT(ring_submits == 0 && ring_discards == 5, "kind refusal reserves nothing");
        EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal leg unwound");
        EXPECT(owner_map_lookup(&START, &key) == NULL, "START leg unwound");
    }
    /* A poisoned control refuses before effects; the START leg
     * rewinds and no sequence mints. */
    {
        u64 sequence_before = owners[0].journal_sequence;
        journal_ctl.poison = 1;
        fault = 0;
        EXPECT(root_entry(&txn) == -1, "poisoned entry refuses");
        EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
        EXPECT(owner_map_lookup(&START, &key) == NULL, "START rewound past poison");
        EXPECT(owners[0].journal_sequence == sequence_before, "poison mints no sequence");
        journal_ctl.poison = 0;
    }
    /* A wrapped sequence consumes its ticket but refuses; START rewinds. */
    EXPECT(p11_owner_lease() == 1, "lease");
    owners[0].journal_sequence = ~0ULL;
    fault = 0;
    EXPECT(root_entry(&txn) == -1, "wrapped sequence refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
    EXPECT(owners[0].journal_thread == 1, "refused ticket still consumed");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START rewound past wrap");
    owners[0].journal_sequence = 0;
    /* A healthy entry then a wrong-facts return: refused, row intact,
     * nothing published. */
    fault = 0;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    txn.spec = &end;
    txn.thread = 2;
    txn.sequence = 1;
    fault = 0;
    EXPECT(root_return(&txn) == -1, "wrong-facts return refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "spec mismatch faults publish, got %llu",
           (unsigned long long)fault);
    txn.thread = 1;
    txn.sequence = 1;
    {
        struct journal_header_spec wrong = end;
        wrong.sequence = 2;
        txn.spec = &wrong;
        fault = 0;
        EXPECT(root_return(&txn) == -1, "spec/facts mismatch refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        txn.spec = &end;
    }
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->phase == JOURNAL_PHASE_BEGUN, "row still BEGUN");
    EXPECT(ring_submits == 1, "BEGIN only");
    /* A tainted cell refuses return before effects: the BEGUN row
     * waits for exit cleanup, and the earlier fault is the report. */
    fault = JOURNAL_FAULT_JOURNAL_LEG;
    EXPECT(root_return(&txn) == -1, "tainted return refuses");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "earlier fault preserved");
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->phase == JOURNAL_PHASE_BEGUN, "row still BEGUN");
    EXPECT(ring_submits == 1, "tainted return published nothing");
    /* Invalid END payloads refuse before the advance commits: a bad
     * event type and a compact-ineligible payload with a compact spec.
     * The row stays BEGUN with START intact; each faulted reservation
     * hands back for a root raise-then-discard. */
    {
        struct journal_header_spec compact = end;
        u32 w = 99;
        memcpy(bad_payload, end_payload, sizeof(bad_payload));
        memcpy(bad_payload + 284, &w, 4);
        bad = txn;
        bad.end_payload = bad_payload;
        fault = 0;
        EXPECT(root_return(&bad) == -1, "bad event type refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        memcpy(bad_payload, end_payload, sizeof(bad_payload));
        bad_payload[120] = 1;
        compact.bytes = JOURNAL_END_COMPACT_BYTES;
        bad.spec = &compact;
        fault = 0;
        EXPECT(root_return(&bad) == -1, "compact-ineligible refuses");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
        found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
        EXPECT(found != NULL && found->phase == JOURNAL_PHASE_BEGUN, "row still BEGUN");
        EXPECT(owner_map_lookup(&START, &key) != NULL, "START intact");
        EXPECT(ring_submits == 1, "bad payloads submit nothing");
    }
    /* Return reserve failure: nothing committed — the row stays BEGUN
     * and exit cleanup abandons it (BEGIN then ABANDON). The remove
     * shares the return's fault cell: cleanup settles forward but
     * reports the earlier fault, never success (N10). */
    fail_reserve = 1;
    fault = 0;
    EXPECT(root_return(&txn) == -1, "reserve-failed return refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
    fail_reserve = 0;
    found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
    EXPECT(found != NULL && found->phase == JOURNAL_PHASE_BEGUN, "row stays BEGUN");
    txn.spec = &abandon;
    txn.required = 1;
    {
        /* Discards share the ring log: capture the ABANDON's index. */
        unsigned abandon_index = ring_log_len;
        EXPECT(root_remove(&txn) == -1,
               "tainted cleanup reports the earlier fault");
        EXPECT(fault == JOURNAL_FAULT_PUBLISH, "earlier fault preserved");
        EXPECT(ring_submits == 2, "BEGIN then ABANDON");
        check_submitted(abandon_index, JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 1, 1,
                        "ABANDON");
    }
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START row retired");
    EXPECT(owners[0].flags == 0, "emptied lease released");
    /* Invalid ABANDON facts fault but still retire (forward-only
     * cleanup settles; the fault is the disposition): a bad reason and
     * a missing template. Neither submits. */
    fault = 0;
    txn.spec = &begin;
    txn.thread = 0;
    txn.sequence = 0;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    bad = txn;
    bad_afacts = afacts;
    bad_afacts.reason = 0;
    bad.abandon = &bad_afacts;
    bad.spec = &abandon;
    bad.thread = 1;
    bad.sequence = 2;
    fault = 0;
    EXPECT(root_remove(&bad) == -1, "bad reason faults");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
    EXPECT(ring_submits == 3, "faulted ABANDON submits nothing");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START row retired");
    fault = 0;
    EXPECT(root_entry(&txn) == 0, "entry settles again");
    bad = txn;
    bad.spec = NULL;
    bad.abandon = NULL;
    bad.thread = 1;
    bad.sequence = 3;
    fault = 0;
    EXPECT(root_remove(&bad) == -1, "missing template faults");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted");
    EXPECT(ring_submits == 4, "missing template submits nothing");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START row retired");
    /* Missing required rows are loss on both legs (the H7 lookup
     * poison sticks, so later healthy-control cases reset first). */
    key.slot = 6;
    txn.thread = 0;
    txn.sequence = 0;
    fault = 0;
    EXPECT(root_remove(&txn) == -1, "missing required is loss");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted first");
    reset();
    seed_object_tables();
    required_start_value(start_value);
    fault = 0;
    txn.key = &key;
    txn.spec = NULL;
    txn.required = 0;
    EXPECT(root_remove(&txn) == -2, "missing optional is absence");
    EXPECT(fault == JOURNAL_FAULT_NONE, "healthy absence faults nothing");
    txn.required = 7;
    fault = 0;
    EXPECT(root_remove(&txn) == -1, "non-bit required refuses");
    /* A lost task with an orphaned row retires its journal leg but
     * publishes nothing: the START leg reports, and the ABANDON waits
     * for cleanup that never commits. A retry with the task back still
     * reports the missing journal row and republishes nothing. */
    reset();
    seed_object_tables();
    required_start_value(start_value);
    key.slot = 5;
    make_begin_facts(&key, &facts);
    make_abandon_facts(&key, &afacts);
    fault = 0;
    txn.key = &key;
    txn.required = 1;
    txn.spec = &begin;
    txn.thread = 0;
    txn.sequence = 0;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    {
        /* N9: the START leg fails, so the terminal never publishes —
         * the reservation returns to the root (which raises and
         * discards it) WITHOUT submitting. The journal row already
         * deleted; the START row stays with its lease for retry. */
        unsigned submits_before;
        unsigned discards_before;
        fail_current_task = 1;
        txn.spec = &abandon;
        txn.thread = 1;
        txn.sequence = 1;
        submits_before = ring_submits;
        discards_before = ring_discards;
        fault = 0;
        EXPECT(root_remove(&txn) == -1, "taskless remove reports START");
        EXPECT(fault == JOURNAL_FAULT_START_LEG, "START leg faulted, got %llu",
               (unsigned long long)fault);
        EXPECT(ring_submits == submits_before, "failed START leg publishes no ABANDON");
        EXPECT(ring_discards == discards_before + 1, "the root settled the handoff");
        EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
        fail_current_task = 0;
        fault = 0;
        EXPECT(root_remove(&txn) == -1, "retry reports the missing journal row");
        EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted first");
        EXPECT(ring_submits == submits_before, "retry republishes nothing");
        /* H7 poison is capture-terminal: the poisoned control refuses
         * the retry's START leg, so its row stays with its lease. */
        EXPECT(owner_map_lookup(&START, &key) != NULL, "poisoned START leg keeps its row");
        EXPECT(owners[0].flags != 0, "poisoned lease stays held");
    }
    /* The taskless case poisoned the control; later healthy-control
     * cases reset first. */
    reset();
    seed_object_tables();
    required_start_value(start_value);
    fault = 0;
    txn.key = &key;
#ifdef P11SCOPE_SMALL_STATE_MAPS
    {
        /* At limit 1 the second key's journal leg refuses and its
         * START leg rewinds; the first call is intact. */
        struct owner_start_key second = key;
        struct journal_begin_facts facts2;
        second.slot = 7;
        key.slot = 5;
        make_begin_facts(&key, &facts);
        make_begin_facts(&second, &facts2);
        txn.required = 0;
        txn.spec = &begin;
        txn.begin = &facts;
        txn.thread = 0;
        txn.sequence = 0;
        fault = 0;
        EXPECT(root_entry(&txn) == 0, "small first entry settles");
        txn.key = &second;
        txn.begin = &facts2;
        fault = 0;
        EXPECT(root_entry(&txn) == -1, "small second entry refuses at limit 1");
        EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted");
        EXPECT(owner_map_lookup(&START, &second) == NULL, "second START rewound");
        txn.key = &key;
        EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) != NULL,
               "first row intact");
    }
#else
    {
        /* Wider maps hold a second concurrent key. */
        struct owner_start_key second = key;
        struct journal_begin_facts facts2;
        second.slot = 7;
        key.slot = 5;
        make_begin_facts(&key, &facts);
        make_begin_facts(&second, &facts2);
        txn.required = 0;
        txn.spec = &begin;
        txn.begin = &facts;
        txn.thread = 0;
        txn.sequence = 0;
        fault = 0;
        EXPECT(root_entry(&txn) == 0, "first entry settles");
        txn.key = &second;
        txn.begin = &facts2;
        fault = 0;
        EXPECT(root_entry(&txn) == 0, "second entry settles");
        EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &second) != NULL,
               "second row present");
    }
#endif
    /* A failed START removal inside return: the advance committed, so
     * the row stays RETURNING, the END never submits, and the START
     * leg fault is the report. Exit cleanup then retires the
     * RETURNING row silently on the shared cell — settling forward
     * while reporting the earlier fault (N10). Setup contradicts the
     * subordinate (H7 retires its START anyway and records mismatch),
     * so this closes the section. */
    reset();
    seed_object_tables();
    required_start_value(start_value);
    key.slot = 5;
    make_begin_facts(&key, &facts);
    fault = 0;
    txn.key = &key;
    txn.spec = &begin;
    txn.begin = &facts;
    txn.thread = 0;
    txn.sequence = 0;
    txn.required = 1;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    {
        struct object_start *side = owner_map_lookup(&OBJECT_START, &key);
        unsigned submits_before = ring_submits;
        EXPECT(side != NULL, "subordinate present to contradict");
        side->phase = 9;
        txn.spec = &end;
        txn.thread = 1;
        txn.sequence = 1;
        fault = 0;
        EXPECT(root_return(&txn) == -1, "START-failed return refuses");
        EXPECT(fault == JOURNAL_FAULT_START_LEG, "START leg faulted");
        EXPECT(ring_submits == submits_before, "failed cleanup submits no END");
        found = p11_journal_side_lookup(&JOURNAL_START_MAP, &key);
        EXPECT(found != NULL && found->phase == JOURNAL_PHASE_RETURNING, "row stays RETURNING");
        txn.spec = NULL;
        EXPECT(root_remove(&txn) == -1, "tainted cleanup reports START fault");
        EXPECT(fault == JOURNAL_FAULT_START_LEG, "earlier fault preserved");
        EXPECT(ring_submits == submits_before, "silent retirement publishes nothing");
        EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    }
}

/* C4: operation-specific kinds at the transaction entry points. Entry
 * publishes BEGIN only, return END only, remove ABANDON only — a
 * wrong-kind template faults PUBLISH. Entry and return refuse before
 * effects; forward-only remove still retires but submits nothing. */
static void combined_operation_kinds(void)
{
    struct owner_start_key key;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_header_spec end = {JOURNAL_END_FULL_BYTES, JOURNAL_KIND_END, 0, 0, 0};
    struct journal_header_spec abandon = {JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 0, 0};
    struct journal_header_spec named;
    struct journal_txn txn, bad;
    struct journal_begin_facts facts;
    struct journal_abandon_facts afacts;
    unsigned char end_payload[JOURNAL_END_PAYLOAD_BYTES];
    unsigned submits_before;
    u64 fault = 0;
    reset();
    seed_object_tables();
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    make_abandon_facts(&key, &afacts);
    build_end_payload(end_payload);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    txn.end_payload = end_payload;
    txn.abandon = &afacts;
    /* Entry with an END template (zero identity, so only the kind
     * refuses) and with an ABANDON template: both refuse before
     * effects — no reserve, no rows, no lease. */
    bad = txn;
    bad.spec = &end;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "END through entry refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
           (unsigned long long)fault);
    bad.spec = &abandon;
    fault = 0;
    EXPECT(root_entry(&bad) == -1, "ABANDON through entry refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
           (unsigned long long)fault);
    EXPECT(owner_map_lookup(&START, &key) == NULL, "wrong-kind entry inserts no START");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL,
           "wrong-kind entry inserts no journal row");
    EXPECT(owners[0].flags == 0, "wrong-kind entry leases nothing");
    EXPECT(ring_submits == 0 && ring_discards == 0, "wrong-kind entry reserves nothing");
    /* Return with a BEGIN or ABANDON template naming the retained call
     * exactly (so only the kind refuses): both refuse before effects,
     * ahead of even the START lookup. */
    named = begin;
    named.thread = 1;
    named.sequence = 1;
    bad = txn;
    bad.spec = &named;
    bad.thread = 1;
    bad.sequence = 1;
    fault = 0;
    EXPECT(root_return(&bad) == -1, "BEGIN through return refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
           (unsigned long long)fault);
    named = abandon;
    named.thread = 1;
    named.sequence = 1;
    bad.spec = &named;
    fault = 0;
    EXPECT(root_return(&bad) == -1, "ABANDON through return refuses");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
           (unsigned long long)fault);
    EXPECT(ring_submits == 0 && ring_discards == 0, "wrong-kind return reserves nothing");
    /* Remove with an END template on an unsettled row: the template
     * faults PUBLISH but cleanup still retires forward — journal row
     * gone, START leg retired, lease released, nothing submitted. */
    fault = 0;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    submits_before = ring_submits;
    named = end;
    named.thread = 1;
    named.sequence = 1;
    bad = txn;
    bad.spec = &named;
    bad.thread = 1;
    bad.sequence = 1;
    bad.required = 1;
    fault = 0;
    EXPECT(root_remove(&bad) == -1, "END through remove faults");
    EXPECT(fault == JOURNAL_FAULT_PUBLISH, "publish faulted, got %llu",
           (unsigned long long)fault);
    EXPECT(ring_submits == submits_before, "wrong-kind remove submits nothing");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START row retired");
    EXPECT(owner_map_lookup(&OBJECT_START, &key) == NULL, "subordinate retired");
    EXPECT(owners[0].flags == 0, "emptied lease released");
}

/* N8: a failed journal deletion reports the fault FIRST, hands the
 * uncommitted reservation back to the root (checked raise before its
 * discard), keeps the lease for retry and publishes nothing — never a
 * discard ahead of the report. The healed retry then settles with the
 * ABANDON after full cleanup. */
static void combined_journal_delete_failure(void)
{
    struct owner_start_key key;
    struct journal_header_spec begin = {JOURNAL_BEGIN_BYTES, JOURNAL_KIND_BEGIN, 0, 0, 0};
    struct journal_header_spec abandon = {JOURNAL_ABANDON_BYTES, JOURNAL_KIND_ABANDON, 0, 1, 1};
    struct journal_txn txn;
    struct journal_begin_facts facts;
    struct journal_abandon_facts afacts;
    unsigned submits_before, discards_before;
    u64 fault = 0;
    reset();
    seed_object_tables();
    key.pid_tgid = pid_tgid();
    key.slot = 5;
    key.pad = 0;
    required_start_value(start_value);
    make_begin_facts(&key, &facts);
    make_abandon_facts(&key, &afacts);
    memset(&txn, 0, sizeof(txn));
    txn.jctl = &journal_ctl;
    txn.journal_map = &JOURNAL_START_MAP;
    txn.ring = &JOURNAL_RING;
    txn.key = &key;
    txn.start_value = start_value;
    txn.spec = &begin;
    txn.fault_out = &fault;
    txn.begin = &facts;
    txn.abandon = &afacts;
    EXPECT(root_entry(&txn) == 0, "entry settles");
    txn.spec = &abandon;
    txn.thread = 1;
    txn.sequence = 1;
    txn.required = 1;
    submits_before = ring_submits;
    discards_before = ring_discards;
    fault = 0;
    fail_journal_delete = 1;
    EXPECT(root_remove(&txn) == -1, "failed deletion reports loss");
    EXPECT(fault == JOURNAL_FAULT_JOURNAL_LEG, "journal leg faulted, got %llu",
           (unsigned long long)fault);
    EXPECT(ring_submits == submits_before, "failed cleanup publishes nothing");
    EXPECT(ring_discards == discards_before + 1, "the root settled the handoff");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) != NULL,
           "failed deletion keeps its row for retry");
    EXPECT(owner_map_lookup(&START, &key) != NULL, "failed cleanup keeps START");
    EXPECT(owners[0].flags != 0, "failed cleanup keeps the lease");
    fail_journal_delete = 0;
    fault = 0;
    abandon_order_key = &key;
    abandon_order_checked = 0;
    EXPECT(root_remove(&txn) == 0, "healed retry settles");
    EXPECT(abandon_order_checked, "retry ABANDON after full cleanup");
    abandon_order_key = NULL;
    EXPECT(fault == JOURNAL_FAULT_NONE, "no fault, got %llu", (unsigned long long)fault);
    EXPECT(ring_submits == submits_before + 1, "retry publishes the ABANDON once");
    EXPECT(p11_journal_side_lookup(&JOURNAL_START_MAP, &key) == NULL, "journal row retired");
    EXPECT(owner_map_lookup(&START, &key) == NULL, "START row retired");
    EXPECT(owner_map_lookup(&OBJECT_START, &key) == NULL, "subordinate retired");
    EXPECT(owners[0].flags == 0, "emptied lease released");
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
    missed_lookup_preserves_idle_words();
    loader_row_mints_on_first_use();
    cleanup_preserves_words();
    cleanup_idle_returns_zero();
    tid_reuse_mints_fresh();
    migration_keeps_row();
    wrap_fails_closed();
    exhaustion_refuses_and_sticks();
    cas_contention_is_bounded();
    storage_failure_mints_nothing();
    side_map_lifecycle();
    side_map_rejects_bad_shapes();
    journal_transaction_matrix();
    journal_transaction_refusals();
    ring_header_matrix();
    ring_reserve_submit_discard();
    mint_contention_unique();
    combined_entry_publishes_begin();
    combined_return_publishes_end();
    combined_remove_abandons_unsettled();
    combined_scrub_before_release();
    combined_collision_lifecycle();
    combined_fault_paths();
    combined_operation_kinds();
    combined_journal_delete_failure();
#endif
    if (!failures)
        fprintf(stderr, "journal owner fixture: all checks passed\n");
    return failures != 0;
}
