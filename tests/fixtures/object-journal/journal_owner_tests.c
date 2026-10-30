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
unsigned char INSTANCE_START, DESCRIPTORS, EVENTS, EVIDENCE;
static u64 producer_evidence[6];
static unsigned producer_gaps, producer_side_lookups;
static int producer_mode, producer_insert_fail, producer_phase_fail;
static int producer_object_delete_fail, producer_start_delete_fail;
static struct owner_start_key producer_terminal_key;
u32 p11_instance_scope_gap(void)
{
    producer_gaps++;
    return 1;
}
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
    if (map == &JOURNAL_START_MAP || map == &JOURNAL_START || map == &INSTANCE_START)
        return 16;
    if (map == &START || map == &OBJECT_START)
        return 16;
    if (map == &OBJECT_DESCRIPTORS || map == &OBJECT_ZERO || map == &DESCRIPTORS || map == &EVIDENCE)
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
    if (map == &EVIDENCE) {
        u32 index = *(const u32 *)key;
        return index < 6 ? &producer_evidence[index] : NULL;
    }
    if (producer_mode && map == &JOURNAL_START)
        producer_side_lookups++;
#endif
    r = row(map, key);
    return r ? r->value : NULL;
}

static long update(void *map, const void *key, const void *data, u64 flags)
{
    size_t width = 24;
    struct row *r = row(map, key);
    unsigned i;
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &JOURNAL_START && ((flags == 1 && producer_insert_fail) ||
                                 (flags == 2 && producer_phase_fail)))
        return -12;
#endif
    if (r && flags == 1)
        return -17;
    if (!r && flags == 2)
        return -2;
    if (!r) {
#ifndef P11SCOPE_INVENTORY_ONLY
        if (map == &JOURNAL_START_MAP || map == &JOURNAL_START) {
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
    else if (map == &JOURNAL_START_MAP || map == &JOURNAL_START || map == &INSTANCE_START)
        width = 24;
    else if (map == &DESCRIPTORS)
        width = 18;
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
    if ((map == &JOURNAL_START_MAP || map == &JOURNAL_START) && fail_journal_delete)
        return -1;
    if (producer_mode && ((map == &OBJECT_START && producer_object_delete_fail) ||
                           (map == &START && producer_start_delete_fail)))
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
    assert(ring == &JOURNAL_RING || ring == &EVENTS);
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
    if (producer_mode && (bytes[4] == JOURNAL_KIND_END || bytes[4] == JOURNAL_KIND_ABANDON)) {
        EXPECT(lookup(&JOURNAL_START, &producer_terminal_key) == NULL, "producer journal retired before terminal");
        EXPECT(lookup(&OBJECT_START, &producer_terminal_key) == NULL, "producer object retired before terminal");
        EXPECT(lookup(&START, &producer_terminal_key) == NULL, "producer START retired before terminal");
    }
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
    if (producer_mode)
        EXPECT(producer_gaps && (producer_evidence[0] || producer_evidence[5]),
               "producer reports gap/loss before discard");
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
    memset(producer_evidence, 0, sizeof(producer_evidence));
    producer_gaps = producer_side_lookups = 0;
    producer_mode = producer_insert_fail = producer_phase_fail = 0;
    producer_object_delete_fail = producer_start_delete_fail = 0;
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

#if defined(P11SCOPE_OBJECT_JOURNAL) && !defined(P11SCOPE_INVENTORY_ONLY)
/* P1 tests drive the actual proposed producer API, separately from the
 * historical combined-transaction fixture above. No synthetic transaction
 * graph supplies the producer's retained fields. */
static void producer_return_words_absent(void)
{
    const struct owner_start_key key = { .pid_tgid = (42ULL << 32) | 100, .slot = 5 };
    struct journal_return_words words;
    reset();
    memset(&words, 0xa5, sizeof(words));
    p11_journal_returning(&key, &words);
    EXPECT(words.thread == 0 && words.sequence == 0 && words.flags == 4 && words.pad == 0,
           "an absent journal row fills every return word as UNJOURNALED");
    {
        struct journal_settle_words settle;
        memset(&settle, 0xa5, sizeof(settle));
        p11_journal_settle_prepare(&key, 0, &settle);
        EXPECT(!memcmp(&settle, (unsigned char[72]){0}, sizeof(settle)),
               "absent prepare fills the entire bounded workspace");
        EXPECT(!producer_side_lookups, "an unminted owner never reads the side map");
    }
}

static struct journal_entry_context producer_setup(u32 descriptor, u32 class_bits, int object,
                                                    unsigned char session_arg)
{
    struct journal_entry_context entry = {descriptor, class_bits, JOURNAL_LAYOUT_LP64, 0};
    struct journal_descriptor_row semantics = {};
    struct journal_entry_witness witness;
    struct journal_begin_facts facts;
    struct object_descriptor_row object_desc = {};
    static unsigned char zero[432];
    u32 zero_key = 0;
    u64 word;
    reset();
    producer_mode = 1;
    producer_terminal_key = (struct owner_start_key){ .pid_tgid = pid_tgid(), .slot = 5 };
    make_begin_facts(&producer_terminal_key, &facts);
    facts.entry_ns = 1000;
    facts.entry_mechanism = ~0ULL; /* Real START's MECH_NONE sentinel. */
    memset(start_value, 0, sizeof(start_value));
#define P1_WORD(offset, value) do { word = (value); memcpy(start_value + (offset), &word, 8); } while (0)
    P1_WORD(0, facts.entry_ns);
    P1_WORD(8, session_arg == 255 ? ~0ULL : facts.session_word);
    P1_WORD(16, facts.slot_id);
    P1_WORD(24, facts.entry_mechanism);
    P1_WORD(40, facts.call_flags);
    memcpy(start_value + 56, &facts.user_type, 4);
    P1_WORD(264, object ? descriptor + 1 : 0);
    P1_WORD(272, facts.image_cookie);
    P1_WORD(280, facts.image_exec);
#undef P1_WORD
    semantics.session_arg = session_arg;
    EXPECT(update(&DESCRIPTORS, &descriptor, &semantics, 0) == 0, "frozen descriptor fixture");
    witness.entry_ip = facts.entry_ip;
    memcpy(witness.entry_stamp, facts.entry_stamp, 16);
    EXPECT(update(&INSTANCE_START, &producer_terminal_key, &witness, 0) == 0, "retained instance fixture");
    if (object) {
        object_desc.function = descriptor - 1;
        object_desc.action = 1;
        object_desc.guard = 1;
        EXPECT(update(&OBJECT_DESCRIPTORS, &descriptor, &object_desc, 0) == 0, "object descriptor fixture");
        EXPECT(update(&OBJECT_ZERO, &zero_key, zero, 0) == 0, "zero fixture");
    }
    EXPECT(p11_owner_start_insert(&producer_terminal_key, start_value) == 0, "actual START insertion");
    if (object) {
        struct object_start *side = lookup(&OBJECT_START, &producer_terminal_key);
        EXPECT(side != NULL, "actual subordinate allocation");
        side->layout = JOURNAL_LAYOUT_LP64;
        side->phase = OBJECT_PHASE_READY;
#ifdef P11_JOURNAL_FIXTURE_UNINSPECTED
        if (descriptor == 21)
            side->requested[0].flags = 0x10;
#endif
    }
    dump_dir = getenv("P11_JOURNAL_PRODUCER_DUMP_DIR");
    dump_armed = dump_dir != NULL;
    return entry;
}

static void producer_begin_return_settle(void)
{
    struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
    struct journal_return_words words;
    struct journal_start_value *side;
    struct journal_header_spec header;
    unsigned char payload[JOURNAL_END_PAYLOAD_BYTES];
    void *record;
    p11_journal_begin(&producer_terminal_key, &entry);
    EXPECT(ring_submits == 1 && ring_discards == 0 && producer_gaps == 0, "one native BEGIN");
    side = lookup(&JOURNAL_START, &producer_terminal_key);
    EXPECT(side && side->thread == 1 && side->sequence == 1 && side->phase == JOURNAL_PHASE_BEGUN,
           "native BEGIN owns a BEGUN row");
    memset(&words, 0xa5, sizeof(words));
    p11_journal_returning(&producer_terminal_key, &words);
    EXPECT(words.thread == 1 && words.sequence == 1 && words.flags == 0 && words.pad == 0,
           "return fills all words from the original BEGIN");
    header = (struct journal_header_spec){632, JOURNAL_KIND_END, words.flags, words.thread, words.sequence};
    build_end_payload(payload);
    { u64 value = 2000; memcpy(payload, &value, 8); value = 1000; memcpy(payload + 8, &value, 8); }
    memcpy(payload + 16, &producer_terminal_key.pid_tgid, 8);
    memcpy(payload + 104, &producer_terminal_key.slot, 4);
    { u64 value = ~0ULL; memcpy(payload + 48, &value, 8); }
    record = p11_journal_reserve(&EVENTS, 632);
    EXPECT(record && !p11_journal_header_init(record, &header) && !txn_fill_end(record, payload, 632, 0),
           "return root frames the actual words");
    EXPECT(p11_owner_start_remove(&producer_terminal_key, 1) == 0, "physical return settles");
    p11_journal_submit(record);
    EXPECT(ring_submits == 2 && !producer_gaps, "one BEGIN and one END, no ABANDON");
}

static void producer_layout_matrix(void)
{
    for (u32 layout = JOURNAL_LAYOUT_LP64; layout <= JOURNAL_LAYOUT_ILP32; layout++) {
        for (unsigned object_case = 0; object_case < 2; object_case++) {
            for (unsigned word_case = 0; word_case < 3; word_case++) {
                struct journal_entry_context entry = producer_setup(
                    object_case ? 30 : 17, JOURNAL_CLASS_TRACKED, object_case, 0);
                unsigned char *start = lookup(&START, &producer_terminal_key);
                struct object_start *object = lookup(&OBJECT_START, &producer_terminal_key);
                struct journal_return_words words;
                unsigned char original[288], instance[24], side[432];
                u64 word = word_case == 0 ? 0x80000001ULL : word_case == 1 ? 0xffffffffULL : 0;
                entry.layout = layout;
                memcpy(start + 8, &word, 8);
                if (object) {
                    object->layout = layout;
                    object->action = 8;
                    object->inputs[0] = word;
                    object->input_statuses[0] = word ? JOURNAL_HANDLE_VALUE : 3;
                    memcpy(side, object, sizeof(side));
                }
                memcpy(original, start, sizeof(original));
                memcpy(instance, lookup(&INSTANCE_START, &producer_terminal_key), sizeof(instance));
                p11_journal_begin(&producer_terminal_key, &entry);
                EXPECT(ring_submits == 1 && !ring_discards && !producer_gaps,
                       "retained layout BEGIN: layout=%u object=%u word=%u", layout, object_case, word_case);
                EXPECT(!memcmp(original, start, sizeof(original)) &&
                       !memcmp(instance, lookup(&INSTANCE_START, &producer_terminal_key), sizeof(instance)) &&
                       (!object || !memcmp(side, object, sizeof(side))),
                       "BEGIN preserves independent original rows");
                if (ring_submits == 1) {
                    const unsigned char *bytes = ring_log[0];
                    u64 actual;
                    memcpy(&actual, bytes + 80, 8);
                    EXPECT(bytes[124] == layout && bytes[125] == (word ? 1 : 3) && actual == word,
                           "layout and normalized session retained without truncation");
                    if (object) {
                        memcpy(&actual, bytes + 88, 8);
                        EXPECT(bytes[126] == (word ? 1 : 3) && actual == word,
                               "normalized input retained without truncation");
                    }
                    p11_journal_returning(&producer_terminal_key, &words);
                    EXPECT(words.thread == 1 && words.sequence == 1 && !words.flags && !words.pad,
                           "both layouts return the original invocation");
                    EXPECT(!p11_owner_start_remove(&producer_terminal_key, 1) && !ctl.outstanding &&
                           !lookup(&START, &producer_terminal_key) && !lookup(&OBJECT_START, &producer_terminal_key) &&
                           !lookup(&JOURNAL_START, &producer_terminal_key) && ring_submits == 1 && !producer_gaps,
                           "returning cleanup preserves one BEGIN and releases all rows");
                }
            }
        }
        for (unsigned negative = 0; negative < 7; negative++) {
            struct journal_entry_context entry = producer_setup(30, JOURNAL_CLASS_TRACKED, 1, 0);
            struct object_start *object = lookup(&OBJECT_START, &producer_terminal_key);
            unsigned char *start = lookup(&START, &producer_terminal_key);
            u64 session = 0x80000001ULL;
            entry.layout = object->layout = layout;
            memcpy(start + 8, &session, 8);
            if (negative == 0) entry.layout = 3;
            if (negative == 1) object->layout = layout == JOURNAL_LAYOUT_LP64 ? JOURNAL_LAYOUT_ILP32 : JOURNAL_LAYOUT_LP64;
            if (negative == 2) object->descriptor_index++;
            if (negative == 3) {
                session = ~0ULL;
                u32 capture = 16;
                memcpy(start + 8, &session, 8);
                memcpy(start + 256, &capture, 4);
            }
            if (negative == 4) pair_delete(&INSTANCE_START, &producer_terminal_key);
            if (negative == 5) {
                session = 0x100000001ULL;
                memcpy(start + 8, &session, 8);
            }
            if (negative == 6) {
                object->inputs[0] = 0x1ffffffffULL;
                object->input_statuses[0] = JOURNAL_HANDLE_VALUE;
            }
            p11_journal_begin(&producer_terminal_key, &entry);
            if (negative >= 5 && layout == JOURNAL_LAYOUT_LP64) {
                EXPECT(ring_submits == 1 && !producer_gaps, "wide LP64 healthy twin: %u", negative);
            } else {
                EXPECT(!ring_submits && producer_gaps == 1 && producer_evidence[5] == 1 &&
                       !lookup(&JOURNAL_START, &producer_terminal_key) && lookup(&START, &producer_terminal_key),
                       "retained layout refusal conserves ordinary START: layout=%u case=%u", layout, negative);
            }
        }
        for (u32 class_bits = JOURNAL_CLASS_COUNT_ONLY; class_bits <= JOURNAL_CLASS_NO_END; class_bits += 2) {
            struct journal_entry_context entry = producer_setup(2, class_bits, 0, 255);
            entry.layout = layout;
            p11_journal_begin(&producer_terminal_key, &entry);
            EXPECT(ring_submits == (class_bits == JOURNAL_CLASS_NO_END) && !producer_gaps &&
                   !lookup(&JOURNAL_START, &producer_terminal_key), "finite layout preserves endpoint class");
            EXPECT(!p11_owner_start_remove(&producer_terminal_key, 1) && !ctl.outstanding,
                   "finite class releases ordinary custody");
        }
    }
}

static void producer_classes_and_projection(void)
{
    struct journal_entry_context entry;
    struct journal_return_words words;
    const unsigned char *bytes;
    entry = producer_setup(1, JOURNAL_CLASS_COUNT_ONLY, 0, 255);
    p11_journal_begin(&producer_terminal_key, &entry);
    EXPECT(!ring_submits && !producer_gaps && !owners[0].journal_thread && !producer_side_lookups,
           "count-only remains completely unjournaled");
    EXPECT(!p11_owner_start_remove(&producer_terminal_key, 1) && !producer_side_lookups,
           "unminted owner does no journal side-map work");
    entry = producer_setup(2, JOURNAL_CLASS_NO_END, 0, 255);
    p11_journal_begin(&producer_terminal_key, &entry);
    EXPECT(ring_submits == 1 && ((unsigned char *)ring_log[0])[5] == 1,
           "NO_END BEGIN publishes the commitment");
    EXPECT(!lookup(&JOURNAL_START, &producer_terminal_key), "NO_END holds no side row");
    p11_journal_returning(&producer_terminal_key, &words);
    EXPECT(words.flags == 4 && !words.thread && !words.sequence && !words.pad, "NO_END returns unjournaled");
    EXPECT(!p11_owner_start_remove(&producer_terminal_key, 1) && !producer_gaps, "NO_END ordinary result settles");
    for (unsigned test = 0; test < 5; test++) {
        u64 session;
        u32 capture;
        unsigned char *start;
        entry = producer_setup(test == 0 ? 13 : 17, JOURNAL_CLASS_TRACKED, 0, test == 0 ? 255 : 0);
        start = lookup(&START, &producer_terminal_key);
        session = test == 0 ? ~0ULL : test == 1 ? 0 : test == 2 ? ~0ULL : 42;
        capture = test >= 3 ? 16 : 0;
        if (test == 4) session = ~0ULL;
        memcpy(start + 8, &session, 8);
        memcpy(start + 256, &capture, 4);
        p11_journal_begin(&producer_terminal_key, &entry);
        if (test == 4) {
            EXPECT(!ring_submits && producer_gaps == 1 && producer_evidence[5] == 1,
                   "ambiguous unreadable sentinel preserves ordinary data and refuses BEGIN");
        } else {
            EXPECT(ring_submits == 1 && !producer_gaps, "real neutral/lifecycle BEGIN");
            bytes = ring_log[0];
            EXPECT(bytes[125] == (test == 0 ? 0 : test == 1 ? 3 : 1), "session projection is conservative");
            EXPECT(!memcmp(bytes + 88, (unsigned char[16]){0}, 16), "no object row means absent inputs");
            EXPECT(!memcmp(bytes + 128, (unsigned char[72]){0}, 72), "no object row means absent lists");
        }
        EXPECT(!p11_owner_start_remove_reason(&producer_terminal_key, 1, 6), "projected START physical cleanup");
    }
}

static void producer_failure_matrix(void)
{
    for (unsigned test = 0; test < 14; test++) {
        struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
        struct object_start *object = lookup(&OBJECT_START, &producer_terminal_key);
        struct journal_entry_witness *witness = lookup(&INSTANCE_START, &producer_terminal_key);
        unsigned char *start = lookup(&START, &producer_terminal_key);
        if (test == 0) entry.descriptor = 0;
        if (test == 1) entry.descriptor = 105;
        if (test == 2) entry.class_bits = 3;
        if (test == 3) entry.reserved = 1;
        if (test == 4) entry.layout = 3;
        if (test == 5) pair_delete(&INSTANCE_START, &producer_terminal_key);
        if (test == 6) witness->entry_stamp[15] = 0;
        if (test == 7) ((struct journal_descriptor_row *)lookup(&DESCRIPTORS, &entry.descriptor))->session_arg = 6;
        if (test == 8) object->descriptor_index++;
        if (test == 9) object->layout = 2;
        if (test == 10) object->entry_ns++;
        if (test == 11) object->task_cookie++;
        if (test == 12) { object->inputs[0] = 99; object->input_statuses[0] = 0; }
        if (test == 13) { u64 value = 7; memcpy(start + 264, &value, 8); }
        p11_journal_begin(&producer_terminal_key, &entry);
        EXPECT(!ring_submits && producer_gaps == 1 && producer_evidence[5] == 1,
               "invalid retained context fails once: %u", test);
        EXPECT(lookup(&START, &producer_terminal_key) != NULL, "journal refusal preserves ordinary START");
    }
    for (unsigned test = 0; test < 4; test++) {
        struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
        if (test == 0) journal_ctl.next_thread = JOURNAL_THREAD_LIMIT;
        if (test == 1) producer_insert_fail = 1;
        if (test == 2) fail_reserve = 1;
        if (test == 3) producer_phase_fail = 1;
        p11_journal_begin(&producer_terminal_key, &entry);
        EXPECT(producer_gaps == 1 && producer_evidence[test == 2 ? 0 : 5] == 1,
               "allocation/publication failure counted once: %u", test);
        EXPECT(lookup(&START, &producer_terminal_key) != NULL, "failed BEGIN retains ordinary result");
        if (test == 0) EXPECT(journal_ctl.admission_failures == 1, "allocator admission evidence survives");
        if (test == 3) {
            const struct journal_start_value *side = lookup(&JOURNAL_START, &producer_terminal_key);
            EXPECT(ring_submits == 1 && !ring_discards && side && side->phase == JOURNAL_PHASE_PREPARING,
                   "BEGIN submits before phase commit; failed commit retains PREPARING");
            producer_phase_fail = 0;
            EXPECT(!p11_owner_start_remove_reason(&producer_terminal_key, 1, 6), "failed commit retires by named cleanup");
            EXPECT(ring_submits == 2 && !lookup(&JOURNAL_START, &producer_terminal_key) && !ctl.outstanding,
                   "published BEGIN gets one ABANDON after cleanup, not a discard");
        } else {
            EXPECT(!ring_submits && !lookup(&JOURNAL_START, &producer_terminal_key),
                   "pre-publication failure leaves no journal row");
        }
    }
}

static void producer_terminal_matrix(void)
{
    for (u32 reason = 0; reason <= 9; reason++) {
        struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
        u32 actual_reason;
        p11_journal_begin(&producer_terminal_key, &entry);
        EXPECT(!p11_owner_start_remove_reason(&producer_terminal_key, 1, reason), "named removal %u", reason);
        EXPECT(ring_submits == 2, "one native BEGIN/ABANDON pair: %u", reason);
        memcpy(&actual_reason, (unsigned char *)ring_log[1] + 52, 4);
        EXPECT(actual_reason == (reason ? reason : 9), "normal unsettled removal is reason9");
        EXPECT(producer_gaps == (reason ? 0U : 1U), "only unsettled normal return adds its own loss");
    }
    for (unsigned test = 0; test < 4; test++) {
        struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
        p11_journal_begin(&producer_terminal_key, &entry);
        if (test == 0) fail_journal_delete = 1;
        if (test == 1) producer_object_delete_fail = 1;
        if (test == 2) producer_start_delete_fail = 1;
        if (test == 3) fail_reserve = 1;
        {
            long result = p11_owner_start_remove_reason(&producer_terminal_key, 1, 6);
            EXPECT(test == 3 ? result == 0 : result != 0, "original physical failure preserved: %u", test);
        }
        EXPECT(ring_submits == 1 && producer_gaps == 1 && producer_evidence[test == 3 ? 0 : 5] == 1,
               "failed terminal never publishes or hides loss: %u", test);
        if (test == 0) {
            EXPECT(lookup(&START, &producer_terminal_key) && lookup(&OBJECT_START, &producer_terminal_key)
                   && lookup(&JOURNAL_START, &producer_terminal_key) && ctl.outstanding == 1,
                   "failed journal deletion keeps every retry authority");
            fail_journal_delete = 0;
            EXPECT(!p11_owner_start_remove_reason(&producer_terminal_key, 1, 6), "healed terminal retries");
            EXPECT(ring_submits == 2 && !ctl.outstanding, "retry publishes once after all cleanup");
            EXPECT(p11_owner_start_remove(&producer_terminal_key, 0) == -2 && ring_submits == 2,
                   "a repeated optional removal never doubles the terminal");
        } else {
            EXPECT(!lookup(&JOURNAL_START, &producer_terminal_key), "no journal orphan after physical/publication failure");
            if (test == 3) EXPECT(!lookup(&START, &producer_terminal_key) && !ctl.outstanding,
                                  "late reserve failure cannot suppress physical cleanup");
        }
    }
}

static void producer_return_refusals(void)
{
    for (unsigned test = 0; test < 6; test++) {
        struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
        struct journal_start_value *side;
        struct journal_return_words words;
        p11_journal_begin(&producer_terminal_key, &entry);
        side = lookup(&JOURNAL_START, &producer_terminal_key);
        if (test == 0) side->phase = JOURNAL_PHASE_PREPARING;
        if (test == 1) side->phase = JOURNAL_PHASE_RETURNING;
        if (test == 2) side->phase = 99;
        if (test == 3) side->thread++;
        if (test == 4) side->sequence = 0;
        if (test == 5) producer_phase_fail = 1;
        memset(&words, 0xa5, sizeof(words));
        p11_journal_returning(&producer_terminal_key, &words);
        EXPECT(words.thread == 0 && words.sequence == 0 && words.flags == 4 && words.pad == 0,
               "return contradiction fills unjournaled words: %u", test);
        EXPECT(producer_gaps == 1 && producer_evidence[5] == 1 && lookup(&START, &producer_terminal_key),
               "return contradiction refuses only journal authority: %u", test);
    }
}

static void producer_prepare_finish_and_collision(void)
{
    struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
    struct journal_settle_words words;
    p11_journal_begin(&producer_terminal_key, &entry);
    p11_journal_settle_prepare(&producer_terminal_key, 6, &words);
    EXPECT(words.state == JOURNAL_SETTLE_ABANDON && words.pad == 0, "bounded terminal snapshot");
    EXPECT(reserve_len == 1 && ring_submits == 1, "prepare owns no ring reservation");
    EXPECT(!p11_owner_start_remove(&producer_terminal_key, 1), "physical cleanup commits before finish");
    p11_journal_settle_finish(&words, 1);
    EXPECT(ring_submits == 2 && words.state == JOURNAL_SETTLE_EMPTY, "finish consumes terminal once");
    p11_journal_settle_finish(&words, 1);
    EXPECT(ring_submits == 2 && !producer_gaps, "repeat finish never republishes");
    entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
    p11_journal_begin(&producer_terminal_key, &entry);
    EXPECT(p11_owner_start_insert(&producer_terminal_key, start_value) != 0, "real entry collision refuses new call");
    EXPECT(ring_submits == 2 && !lookup(&START, &producer_terminal_key) && !ctl.outstanding,
           "collision settles only the original invocation");
    { u32 reason; memcpy(&reason, (unsigned char *)ring_log[1] + 52, 4);
      EXPECT(reason == 1, "real collision preserves its named reason"); }
}

/* A second tracked slot on the same physical owner, built from the first
 * slot's retained fixture rows without a reset. */
static void producer_second_begin(struct journal_entry_context *entry, struct owner_start_key *key)
{
    struct journal_entry_witness witness;
    void *first = lookup(&INSTANCE_START, &producer_terminal_key);
    struct object_start *side;
    EXPECT(first != NULL, "first slot witness retained");
    memcpy(&witness, first, sizeof(witness));
    EXPECT(update(&INSTANCE_START, key, &witness, 0) == 0, "second slot witness");
    EXPECT(p11_owner_start_insert(key, start_value) == 0, "second slot START");
    side = lookup(&OBJECT_START, key);
    EXPECT(side != NULL, "second slot subordinate");
    side->layout = JOURNAL_LAYOUT_LP64;
    side->phase = OBJECT_PHASE_READY;
    p11_journal_begin(key, entry);
}

/* Pending stop then exec/exit: returns never run, custody stays intact,
 * and cleanup abandons every live tracked BEGIN exactly once with the
 * exec/exit reason. Lifetime words survive so the exec successor keeps
 * the same thread and continues the sequence. */
static void producer_cleanup_exec_exit(void)
{
    struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
    struct owner_start_key second = producer_terminal_key;
    struct journal_return_words words;
    struct object_start *side;
    u64 thread;
    second.slot = 6;
    p11_journal_begin(&producer_terminal_key, &entry);
    producer_second_begin(&entry, &second);
    EXPECT(ring_submits == 2 && !producer_gaps, "two tracked BEGINs on one owner");
    EXPECT(lookup(&START, &producer_terminal_key) && lookup(&START, &second) &&
               lookup(&JOURNAL_START, &producer_terminal_key) && lookup(&JOURNAL_START, &second),
           "pending stop leaves ordinary and journal custody untouched");
    EXPECT(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START,
           "cleanup reports abandoned live STARTs");
    EXPECT(ring_submits == 4 && !producer_gaps, "one ABANDON per live BEGIN, no second loss");
    EXPECT(((unsigned char *)ring_log[2])[4] == JOURNAL_KIND_ABANDON &&
               record_u32(ring_log[2], 48) == 5 && record_u32(ring_log[2], 52) == 6 &&
               record_u64(ring_log[2], 16) == 1,
           "first cleanup ABANDON names slot, exec/exit reason and original sequence");
    EXPECT(((unsigned char *)ring_log[3])[4] == JOURNAL_KIND_ABANDON &&
               record_u32(ring_log[3], 48) == 6 && record_u32(ring_log[3], 52) == 6 &&
               record_u64(ring_log[3], 16) == 2,
           "second cleanup ABANDON names slot, exec/exit reason and original sequence");
    EXPECT(!lookup(&START, &producer_terminal_key) && !lookup(&START, &second) &&
               !lookup(&OBJECT_START, &producer_terminal_key) && !lookup(&OBJECT_START, &second) &&
               !lookup(&JOURNAL_START, &producer_terminal_key) && !lookup(&JOURNAL_START, &second) &&
               !ctl.outstanding,
           "cleanup retires every custody row");
    thread = owners[0].journal_thread;
    EXPECT(thread == 1 && owners[0].journal_sequence == 2, "exec preserves lifetime words");
    EXPECT(p11_owner_start_insert(&producer_terminal_key, start_value) == 0, "exec successor START");
    side = lookup(&OBJECT_START, &producer_terminal_key);
    EXPECT(side != NULL, "exec successor subordinate");
    side->layout = JOURNAL_LAYOUT_LP64;
    side->phase = OBJECT_PHASE_READY;
    p11_journal_begin(&producer_terminal_key, &entry);
    EXPECT(ring_submits == 5 && record_u64(ring_log[4], 8) == thread &&
               record_u64(ring_log[4], 16) == 3,
           "successor BEGIN continues thread and sequence, never reuses a terminal identity");
    p11_journal_returning(&producer_terminal_key, &words);
    EXPECT(words.thread == thread && words.sequence == 3 && words.flags == 0,
           "successor return joins its own BEGIN");
    EXPECT(!p11_owner_start_remove(&producer_terminal_key, 1) && ring_submits == 5 &&
               !producer_gaps && !ctl.outstanding,
           "successor settles silently beside its END");
}

/* NO_END owes no terminal: cleanup abandons only the ordinary START. */
static void producer_cleanup_no_end(void)
{
    struct journal_entry_context entry = producer_setup(2, JOURNAL_CLASS_NO_END, 0, 255);
    p11_journal_begin(&producer_terminal_key, &entry);
    EXPECT(ring_submits == 1 && !lookup(&JOURNAL_START, &producer_terminal_key),
           "NO_END BEGIN holds no side row");
    EXPECT(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START,
           "cleanup still reports the abandoned ordinary START");
    EXPECT(ring_submits == 1 && !producer_gaps && !lookup(&START, &producer_terminal_key) &&
               !ctl.outstanding,
           "NO_END cleanup publishes no ABANDON and counts no journal loss");
}

/* A RETURNING row at exit never submitted its END (submission follows
 * removal), so cleanup abandons it exactly once instead of staying
 * silent on a reason-carrying removal. */
static void producer_cleanup_returning(void)
{
    struct journal_entry_context entry = producer_setup(21, JOURNAL_CLASS_TRACKED, 1, 0);
    struct journal_return_words words;
    p11_journal_begin(&producer_terminal_key, &entry);
    p11_journal_returning(&producer_terminal_key, &words);
    EXPECT(words.thread == 1 && words.sequence == 1 && words.flags == 0, "return advanced the row");
    EXPECT(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START,
           "cleanup reports the still-owned START");
    EXPECT(ring_submits == 2 && ((unsigned char *)ring_log[1])[4] == JOURNAL_KIND_ABANDON &&
               record_u32(ring_log[1], 52) == 6 && record_u64(ring_log[1], 16) == 1 &&
               !producer_gaps && !lookup(&JOURNAL_START, &producer_terminal_key) &&
               !lookup(&START, &producer_terminal_key) && !ctl.outstanding,
           "unsubmitted END abandons once with the exec/exit reason");
}

/* Exact pre-BEGIN native row snapshots for the private P0a unit module.
 * END construction there uses shared production Rust writers, not BEGIN
 * bytes copied back into an equality-shaped payload. */
static void producer_snapshot(const char *name, const char *kind, const void *bytes, size_t size)
{
    char path[1024];
    FILE *file;
    const char *directory = getenv("P11_JOURNAL_PRODUCER_SNAPSHOT_DIR");
    EXPECT(directory != NULL, "snapshot directory selected explicitly");
    if (!directory)
        return;
    snprintf(path, sizeof(path), "%s/%s.%s", directory, name, kind);
    file = fopen(path, "wb");
    EXPECT(file != NULL, "open exact native snapshot");
    if (!file)
        return;
    EXPECT(fwrite(bytes, 1, size, file) == size, "write exact native snapshot");
    EXPECT(fclose(file) == 0, "close exact native snapshot");
}

static void producer_agreement_snapshots(void)
{
    static const char *names[] = {"object", "neutral", "open-session", "mechanism", "zero-session", "sentinel", "high-session", "max-input"};
    /* The agreement test also executes the real retained-row refusal twins. */
    producer_layout_matrix();
    for (u32 layout = JOURNAL_LAYOUT_LP64; layout <= JOURNAL_LAYOUT_ILP32; layout++) {
        for (unsigned test = 0; test < 8; test++) {
            char name[64];
            u32 descriptor = test == 0 ? 21 : test == 2 ? 13 : test == 3 || test == 7 ? 30 : 17;
            struct journal_entry_context entry = producer_setup(descriptor, JOURNAL_CLASS_TRACKED,
                                                                 test == 0 || test == 3 || test == 7, test == 2 ? 255 : 0);
            unsigned char *start = lookup(&START, &producer_terminal_key);
            struct object_start *object = lookup(&OBJECT_START, &producer_terminal_key);
            u64 word;
            snprintf(name, sizeof(name), "%s%s", layout == JOURNAL_LAYOUT_ILP32 ? "ilp32-" : "", names[test]);
            entry.layout = layout;
            if (object) object->layout = layout;
            if (layout == JOURNAL_LAYOUT_ILP32 && test != 2) {
                word = 0x80000001ULL; memcpy(start + 8, &word, 8);
            }
            if (test == 2) {
                u32 capture = 8; /* OUTPUT_NON_NULL: real OpenSession return rewrite. */
                word = 0x2000; memcpy(start + 48, &word, 8);
                memcpy(start + 256, &capture, 4);
            }
            if (test == 3 || test == 7) {
                word = ~0ULL; memcpy(start + 24, &word, 8); /* entry MECH_NONE */
                word = 0x1000; memcpy(start + 32, &word, 8); /* retained mechanism pointer */
                object->inputs[0] = test == 7 ? (layout == JOURNAL_LAYOUT_ILP32 ? 0xffffffffULL : 0x1ffffffffULL) : 7;
                object->input_statuses[0] = 1;
                object->action = 8;
            }
            if (test == 4 || test == 5) {
                word = test == 4 ? 0 : layout == JOURNAL_LAYOUT_ILP32 ? 0xffffffffULL : ~0ULL;
                memcpy(start + 8, &word, 8);
            }
            if (test == 6) {
                word = layout == JOURNAL_LAYOUT_ILP32 ? 0x80000001ULL : 0x180000001ULL;
                memcpy(start + 8, &word, 8);
            }
            producer_snapshot(name, "start", start, 288);
            producer_snapshot(name, "key", &producer_terminal_key, 16);
            producer_snapshot(name, "context", &entry, 16);
            producer_snapshot(name, "instance", lookup(&INSTANCE_START, &producer_terminal_key), 24);
            if (object)
                producer_snapshot(name, "object", object, 432);
            p11_journal_begin(&producer_terminal_key, &entry);
            EXPECT(ring_submits == 1 && !producer_gaps, "native agreement BEGIN: %s", name);
            if (ring_submits == 1) {
                struct journal_return_words words;
                producer_snapshot(name, "begin", ring_log[0], 224);
                p11_journal_returning(&producer_terminal_key, &words);
                EXPECT(words.thread == 1 && words.sequence == 1 && words.flags == 0 && words.pad == 0,
                       "actual native return words: %s", name);
                producer_snapshot(name, "return", &words, sizeof(words));
            }
        }
    }
}
#endif

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

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
#if defined(P11SCOPE_OBJECT_JOURNAL) && !defined(P11SCOPE_INVENTORY_ONLY)
    if (argc == 2 && !strcmp(argv[1], "producer-pairs")) {
        producer_agreement_snapshots();
        if (!failures)
            fprintf(stderr, "journal producer snapshots: sixteen real native cases passed\n");
        return failures != 0;
    }
    if (argc == 2 && !strcmp(argv[1], "producer-layouts")) {
        producer_layout_matrix();
        if (!failures)
            fprintf(stderr, "journal producer layouts: 12 word positives, 14 refusal/twin cases and 4 endpoint classes passed\n");
        return failures != 0;
    }
    if (argc == 2 && !strcmp(argv[1], "producer")) {
        producer_return_words_absent();
        producer_begin_return_settle();
        producer_classes_and_projection();
        producer_failure_matrix();
        producer_terminal_matrix();
        producer_return_refusals();
        producer_prepare_finish_and_collision();
        producer_cleanup_exec_exit();
        producer_cleanup_no_end();
        producer_cleanup_returning();
        if (!failures)
            fprintf(stderr, "journal producer fixture: all checks passed\n");
        return failures != 0;
    }
#endif
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
