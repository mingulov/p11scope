/* Executes the actual production transaction and classifier implementation.
 * Only kernel helper operations and atomic interference are injected; there is
 * no second owner-accounting algorithm. */
#include "task_owner.h"
#if defined(P11SCOPE_OBJECT_JOURNAL) && !defined(P11SCOPE_INVENTORY_ONLY)
/* This owner-only fixture counts the journal call boundary; the journal
 * fixture separately executes the actual producer and side-map body. */
static unsigned journal_settle_calls;
static struct owner_start_key journal_settle_key;
static u32 journal_settle_reason;
static unsigned journal_finish_calls;
static u32 journal_finish_committed;
static u32 journal_prepare_state = JOURNAL_SETTLE_SILENT;
static void record_journal_prepare(const struct owner_start_key *key, u32 reason)
{
    journal_settle_calls++;
    journal_settle_key = *key;
    journal_settle_reason = reason;
}
u32 p11_journal_settle_prepare(const struct owner_start_key *key, u32 reason,
                               struct journal_settle_words *out)
{
    record_journal_prepare(key, reason);
    __builtin_memset(out, 0, sizeof(*out));
    out->state = journal_prepare_state;
    return 0;
}
u32 p11_journal_settle_finish(struct journal_settle_words *words, u32 cleanup_committed)
{
    (void)words;
    journal_finish_calls++;
    journal_finish_committed = cleanup_committed;
    return 0;
}
#endif
#if (defined(P11SCOPE_COUNTER_BANK_PROOF) || P11SCOPE_OWNER_SLOT_BOUND == 2112U) && !defined(P11SCOPE_INVENTORY_ONLY)
#define P11SCOPE_HOST_OWNER_LOOP 1
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
/* Host-only weak declaration makes a missing constructor fail at runtime. */
extern void *p11_owner_start_begin(const struct owner_start_key *,
                                   const struct call_start_seed *) __attribute__((weak));
extern u32 p11_owner_start_aggregate(const struct owner_start_key *, u64) __attribute__((weak));
#endif
_Static_assert(OWNER_TRANSIENT_CLAIMS == (1ULL << 22),
               "transient admission excess is bounded by PID_MAX_LIMIT");
_Static_assert(OWNER_CONTROL_BOUND == OWNER_LIMIT + OWNER_TRANSIENT_CLAIMS,
               "corruption bound sits above every transient admission excess");
static u64 *cas_interference_cell;
static unsigned cas_failures_remaining, cas_attempts;
static u64 controlled_cas(u64 *cell, u64 old, u64 replacement);
#ifdef P11SCOPE_HOST_OWNER_LOOP
static long controlled_owner_loop(u32 count, long (*callback)(u32, void *),
                                  void *context, u64 flags);
#endif
/* The timing-bank suites build in both producer modes; only the bucket
 * assertions stay latency-only. */
#if defined(P11SCOPE_BANK_MODE_LATENCY) || defined(P11SCOPE_BANK_MODE_TIMESTAMPS)
#define P11SCOPE_BANK_TIMING_SUITES 1
#endif
#define __sync_val_compare_and_swap controlled_cas
/* Simulated concurrent claims: another CPU's reservations land between an
 * admission pre-check and this CPU's own atomic add. */
static u64 *add_interference_cell;
static u64 add_racing_claims;
u64 controlled_add(u64 *cell, u64 delta);
#define __sync_fetch_and_add controlled_add
#include "task_owner.c"
#ifndef P11SCOPE_INVENTORY_ONLY
/* The object fault leaf lives with the checked fault cell; include the real
 * unit so the fixture advances production state, not a model. */
#define P11SCOPE_INSTANCE_HOST_TEST 1
#include "instance_epoch.h"
#include "instance_epoch.c"
#ifdef P11SCOPE_BANK_TIMING_SUITES
/* Timing bank producer under test: the actual C helpers run with the
 * controlled_cas hook active above, in whichever mode was selected. */
#include "counter_bank_timing.c"
#endif
#endif
#undef __sync_fetch_and_add
#undef __sync_val_compare_and_swap
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

unsigned char START, DISCOVERY_STATE;
#ifndef P11SCOPE_INVENTORY_ONLY
unsigned char OBJECT_START, OBJECT_DESCRIPTORS, OBJECT_ZERO;
#endif
#ifdef P11SCOPE_BANK_TIMING_SUITES
/* Map identities for the timing bank producer (extern in its TU). */
unsigned char COUNTER_HEALTH, RV_COUNTS;
#endif
struct task_struct { int index; };
static struct task_struct tasks[3] = {{0}, {1}, {2}};
static struct thread_owner owners[3];
static int installed[3], current_index;
static u64 current_number[3];
static struct owner_control ctl;
static int miss_get, miss_get_skip, fail_create, delete_error, update_error, pair_delete_error;
static int fail_start_delete;
static int fail_current_task;
static int gets, creates, deletes;
static u64 expected_delete_debt;
static unsigned char value[288] __attribute__((aligned(8)));
struct row { int used; void *map; unsigned char key[24]; unsigned char value[432] __attribute__((aligned(8))); };
/* START capacity plus subordinate rows and frozen descriptor/zero cells. */
#ifdef P11SCOPE_COUNTER_BANK_PROOF
/* Sparse high-key controls exercise at most four live rows, not an 8192-row
 * population. Keep the replaceable I/O seam small and the real bound literal. */
#define FIXTURE_ROW_BOUND 128U
#else
#define FIXTURE_ROW_BOUND (2U * P11SCOPE_OWNER_SLOT_BOUND + 128U)
#endif
static struct row rows[FIXTURE_ROW_BOUND];
#ifdef P11SCOPE_HOST_OWNER_LOOP
static unsigned bank_loop_calls, bank_loop_error_on, bank_loop_short_on;
static int bank_hide_start_slot;
#endif
#ifdef P11SCOPE_BANK_TIMING_SUITES
/* Live inner stores for the timing-bank suites: one 512-cell inner per
 * bank, sized for the latency value (the timestamps value is smaller). */
static struct {
    u32 live;
    u32 pad;
    unsigned char cells[512][296] __attribute__((aligned(8)));
} bank_inners[16];
static u64 bank_fault_cell;
static u64 bank_health_cells[2];
/* Models kernel use-after-delete: a removed START row's bytes are no
 * longer readable. The ts-order suite arms it; a read-after-remove then
 * observes zero instead of the retired timestamp. */
static int scrub_start_on_delete;
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
static int fail_object_side_update, fail_object_side_delete, drop_zero_row, poison_zero_row;
static int fail_object_side_lookup_once, hide_side_slot, zero_outstanding_on_delete;
static int fail_start_readback_once;
/* Pre-delete snapshot of the last removed subordinate value: every terminal
 * path must scrub before deleting. */
static unsigned char deleted_side[432];
static int deleted_side_seen;
static int require_scrubbed_side_delete, checked_side_deletes;
static u64 instance_gen[INST_GEN_CELLS];
static struct instance_counters instance_counters_live;
#endif

#ifdef P11SCOPE_HOST_OWNER_LOOP
/* Only helper 181 is replaced. The callback remains the real native cleanup
 * body, including its owner checks, removals, scrub, counters and faults. */
static long controlled_owner_loop(u32 count, long (*callback)(u32, void *),
                                  void *context, u64 flags)
{
    assert(count == P11SCOPE_OWNER_SLOT_BOUND && flags == 0);
    bank_loop_calls++;
    if (bank_loop_error_on == bank_loop_calls)
        return -22;
    u32 end = bank_loop_short_on == bank_loop_calls ? count - 1 : count;
    for (u32 i = 0; i < end; i++) {
        long stop = callback(i, context);
        assert(stop == 0 || stop == 1);
        if (stop)
            return i + 1;
    }
    return end;
}
#endif

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

u64 controlled_add(u64 *cell, u64 delta)
{
    if (cell == add_interference_cell && delta == 1 && add_racing_claims) {
        __sync_fetch_and_add(cell, add_racing_claims);
        add_racing_claims = 0;
    }
    return __sync_fetch_and_add(cell, delta);
}

static size_t key_size(void *map) {
#ifdef P11SCOPE_INVENTORY_ONLY
    /* Any remaining START transaction or cleanup is a test failure. */
    assert(map == &DISCOVERY_STATE);
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &OBJECT_DESCRIPTORS || map == &OBJECT_ZERO)
        return 4;
    if (map == &OBJECT_START)
        return 16;
#endif
#ifdef P11SCOPE_BANK_TIMING_SUITES
    if (map == &COUNTER_BANK_META || map == &COUNTER_BANK_FAULT)
        return 4;
    if (map == &COUNTER_BANK_COMMIT)
        return 8;
    if (map == &RV_COUNTS)
        return 16;
#endif
    return map == &START ? 16 : 24;
}
static struct row *row(void *map, const void *key)
{
    for (unsigned i = 0; i < FIXTURE_ROW_BOUND; i++)
        if (rows[i].used && rows[i].map == map && !memcmp(rows[i].key, key, key_size(map)))
            return &rows[i];
    return NULL;
}
static void *lookup(void *map, const void *key)
{
    if (map == &OWNER_CTL) return &ctl;
#ifdef P11SCOPE_BANK_TIMING_SUITES
    if (map == &COUNTER_BANKS) {
        u32 bank = *(const u32 *)key;
        if (bank < 16 && bank_inners[bank].live)
            return &bank_inners[bank];
        return NULL;
    }
    if ((const unsigned char *)map >= (const unsigned char *)&bank_inners[0] &&
        (const unsigned char *)map < (const unsigned char *)(&bank_inners[16])) {
        /* Inner lookup: the outer lookup returned the live inner store. */
        const unsigned char *base = (const unsigned char *)map;
        unsigned bank = (unsigned)((base - (const unsigned char *)&bank_inners[0]) /
                                   sizeof(bank_inners[0]));
        u32 cell = *(const u32 *)key;
        if (bank < 16 && bank_inners[bank].live && cell < 512)
            return &bank_inners[bank].cells[cell];
        return NULL;
    }
    if (map == &COUNTER_BANK_FAULT)
        return *(const u32 *)key == 0 ? &bank_fault_cell : NULL;
    if (map == &COUNTER_HEALTH) {
        u32 disposition = *(const u32 *)key;
        return disposition < 2 ? &bank_health_cells[disposition] : NULL;
    }
#endif
#ifdef P11SCOPE_HOST_OWNER_LOOP
    if (map == &START && bank_hide_start_slot >= 0 &&
        ((const struct owner_start_key *)key)->slot == (u32)bank_hide_start_slot)
        return NULL;
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &OBJECT_ZERO && drop_zero_row) return NULL;
    if (map == &START && fail_start_readback_once && row(map, key)) {
        fail_start_readback_once = 0;
        return NULL;
    }
    if (map == &OBJECT_START && fail_object_side_lookup_once) {
        fail_object_side_lookup_once = 0;
        return NULL;
    }
    if (map == &OBJECT_START && hide_side_slot >= 0 &&
        ((const struct owner_start_key *)key)->slot == (u32)hide_side_slot)
        return NULL;
#endif
    struct row *r = row(map, key);
    return r ? r->value : NULL;
}
static long update(void *map, const void *key, const void *data, u64 flags)
{
    size_t width = 24;
    if (update_error) return update_error;
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &OBJECT_START && fail_object_side_update) return fail_object_side_update;
#endif
    struct row *r = row(map, key);
    if (r && flags == 1) return -17;
    if (!r && flags == 2) return -2;
    if (!r) {
        for (unsigned i = 0; i < FIXTURE_ROW_BOUND; i++)
            if (!rows[i].used) { r = &rows[i]; break; }
    }
    if (!r) return -12;
    r->used = 1; r->map = map;
    memcpy(r->key, key, key_size(map));
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &OBJECT_START || map == &OBJECT_ZERO) width = 432;
    else if (map == &OBJECT_DESCRIPTORS) width = 16;
    else
#endif
    if (map == &START) width = 288;
#ifdef P11SCOPE_BANK_TIMING_SUITES
    if (map == &COUNTER_BANK_META) width = 32;
    else if (map == &COUNTER_BANK_COMMIT) width = 16;
    else if (map == &COUNTER_BANK_FAULT || map == &RV_COUNTS) width = 8;
#endif
    memcpy(r->value, data, width);
    return 0;
}
static long pair_delete(void *map, const void *key)
{
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &OBJECT_START && require_scrubbed_side_delete) {
        struct row *side = row(map, key);
        assert(side);
        for (unsigned i = 0; i < 432; i++) assert(side->value[i] == 0);
        checked_side_deletes++;
    }
#endif
    if (pair_delete_error) return pair_delete_error;
    /* Models a concurrent lease-accounting loss landing mid-transaction:
     * entry validation already passed with a live count, so only this
     * mid-path corruption can reach the refund-failure line it guards. */
#ifndef P11SCOPE_INVENTORY_ONLY
    if (zero_outstanding_on_delete && map == &START) {
        zero_outstanding_on_delete = 0;
        ctl.outstanding = 0;
    }
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &OBJECT_START && fail_object_side_delete) return fail_object_side_delete;
#endif
    if (map == &START && fail_start_delete) return fail_start_delete;
    struct row *r = row(map, key);
    if (!r) return -2;
#ifdef P11SCOPE_BANK_TIMING_SUITES
    if (map == &START && scrub_start_on_delete)
        memset(r->value, 0, 288);
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
    if (map == &OBJECT_START) {
        memcpy(deleted_side, r->value, 432);
        deleted_side_seen = 1;
    }
#endif
    r->used = 0;
    return 0;
}
static struct task_struct *current_task(void) { return fail_current_task ? NULL : &tasks[current_index]; }
static u64 pid_tgid(void) { return current_number[current_index]; }
static void *storage_get(void *map, struct task_struct *task, void *initial, u64 flags)
{
    assert(map == &THREAD_OWNER && task == current_task() && initial == NULL);
    gets++;
    if (flags == 0 && miss_get) {
        /* miss_get_skip lets that many lookups succeed before the misses. */
        if (miss_get_skip) miss_get_skip--;
        else { miss_get--; return NULL; }
    }
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
/* Retained, unleased and empty: what a release now leaves behind. */
static int idle(int i)
{
    return installed[i] && !owners[i].flags && !owners[i].original_pid_tgid &&
        !owners[i].start_count && !owners[i].occupied && !owners[i].selection_domains;
}
#ifndef P11SCOPE_INVENTORY_ONLY
/* The object fault path only reads the generation cells and its counters:
 * any instance map write or delete is a test failure. */
static void *instance_lookup(void *map, const void *key)
{
    u32 cell;
    if (map == &INSTANCE_COUNT)
        return &instance_counters_live;
    assert(map == &INSTANCE_GEN);
    memcpy(&cell, key, 4);
    assert(cell < INST_GEN_CELLS);
    return &instance_gen[cell];
}
static long instance_update_fails(void *map, const void *key, const void *data, u64 flags)
{
    (void)map; (void)key; (void)data; (void)flags;
    assert(!"no instance map write in the object fault path");
    return -1;
}
static long instance_delete_fails(void *map, const void *key)
{
    (void)map; (void)key;
    assert(!"no instance map delete in the object fault path");
    return -1;
}
/* The entry hook's image authority is never reached by the fault path. */
u32 p11_image_entry(u64 tgid, u64 cookie, u64 exec_id)
{
    (void)tgid; (void)cookie; (void)exec_id;
    assert(!"image entry unreachable in the object fault path");
    return 0;
}
#endif
static void reset(void)
{
#if defined(P11SCOPE_OBJECT_JOURNAL) && !defined(P11SCOPE_INVENTORY_ONLY)
    journal_settle_calls = 0;
    memset(&journal_settle_key, 0, sizeof(journal_settle_key));
    journal_settle_reason = ~0U;
    journal_finish_calls = 0;
    journal_finish_committed = ~0U;
    journal_prepare_state = JOURNAL_SETTLE_SILENT;
#endif
    memset(&ctl, 0, sizeof(ctl)); ctl.limit = OWNER_LIMIT;
    memset(owners, 0, sizeof(owners)); memset(installed, 0, sizeof(installed));
    memset(rows, 0, sizeof(rows)); memset(value, 0, sizeof(value));
    for (unsigned i = 0; i < 3; i++) current_number[i] = (42ULL << 32) | (100 + i);
    current_index = miss_get = miss_get_skip = fail_create = delete_error = update_error = pair_delete_error = 0;
    fail_start_delete = 0;
    fail_current_task = 0;
    gets = creates = deletes = 0; expected_delete_debt = 0;
    cas_interference_cell = NULL; cas_failures_remaining = cas_attempts = 0;
    add_interference_cell = NULL; add_racing_claims = 0;
    owner_map_lookup = lookup; owner_map_update = update; owner_map_delete = pair_delete;
    owner_storage_get = storage_get; owner_storage_delete = storage_delete;
    owner_current_task = current_task; owner_pid_tgid = pid_tgid;
#ifdef P11SCOPE_HOST_OWNER_LOOP
    bank_loop_calls = bank_loop_error_on = bank_loop_short_on = 0;
    bank_hide_start_slot = -1;
    owner_loop = controlled_owner_loop;
#endif
#ifdef P11SCOPE_BANK_TIMING_SUITES
    memset(bank_inners, 0, sizeof(bank_inners));
    bank_fault_cell = 0;
    bank_health_cells[0] = bank_health_cells[1] = 0;
    scrub_start_on_delete = 0;
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
    fail_object_side_update = fail_object_side_delete = drop_zero_row = poison_zero_row = 0;
    fail_object_side_lookup_once = 0; hide_side_slot = -1; zero_outstanding_on_delete = 0;
    fail_start_readback_once = 0;
    deleted_side_seen = 0;
    require_scrubbed_side_delete = checked_side_deletes = 0;
    memset(instance_gen, 0, sizeof(instance_gen));
    memset(&instance_counters_live, 0, sizeof(instance_counters_live));
    inst_map_lookup = instance_lookup;
    inst_map_update = instance_update_fails;
    inst_map_delete = instance_delete_fails;
#endif
}

static void cas_boundaries(void)
{
    reset();
    assert(ctl.limit == OWNER_LIMIT);
    assert(OWNER_LIMIT ==
#if defined(P11SCOPE_INVENTORY_ONLY)
           64ULL
#elif defined(P11SCOPE_SMALL_STATE_MAPS)
           65ULL
#else
           16448ULL
#endif
    );

    /* Accounting never compare-exchanges the count: interference on every
     * attempt changes nothing (the old eight-try loop poisoned here). */
    ctl.outstanding = 2;
    cas_interference_cell = &ctl.outstanding;
    cas_failures_remaining = OWNER_LIMIT;
    assert(p11_owner_reserve() && ctl.outstanding == 3);
    assert(p11_owner_refund() && ctl.outstanding == 2);
    assert(!cas_attempts && !ctl.poison && !ctl.admission_failures);

    reset(); ctl.outstanding = OWNER_LIMIT;
    cas_interference_cell = &ctl.outstanding;
    assert(!p11_owner_reserve());
    assert(!cas_attempts && ctl.outstanding == OWNER_LIMIT && ctl.admission_failures == 1);
    assert(!ctl.poison);

    reset();
    cas_interference_cell = &ctl.outstanding;
    assert(!p11_owner_refund());
    assert(!cas_attempts && (ctl.poison & OWNER_REFUND_FAILED) && !ctl.outstanding);

    reset(); ctl.outstanding = 1; ctl.poison = OWNER_CLASSIFIER_FAILED;
    cas_interference_cell = &ctl.outstanding;
    assert(p11_owner_refund());
    assert(!cas_attempts && !ctl.outstanding && ctl.poison == OWNER_CLASSIFIER_FAILED);

    /* The corruption bound is exact: the largest transient excess is healthy,
     * one past it is a bad control. */
    reset(); ctl.outstanding = OWNER_CONTROL_BOUND;
    assert(p11_owner_healthy() && !ctl.poison);
    assert(p11_owner_refund() && ctl.outstanding == OWNER_CONTROL_BOUND - 1);
    reset(); ctl.outstanding = OWNER_CONTROL_BOUND + 1;
    assert(!p11_owner_healthy() && ctl.poison == OWNER_BAD_CONTROL);
    assert(!p11_owner_reserve() && !p11_owner_refund());
    assert(ctl.outstanding == OWNER_CONTROL_BOUND + 1);
}

/* Contention is never corruption: another CPU winning every race on the
 * shared count must neither poison the owner nor refuse an admission. Only a
 * genuine accounting violation (underflow, wrapped count) poisons. */
static void accounting_contention(void)
{
    reset(); ctl.outstanding = 2;
    cas_interference_cell = &ctl.outstanding;
    cas_failures_remaining = ~0U; /* Every compare-exchange on the count loses. */
    assert(p11_owner_reserve());
    assert(ctl.outstanding == 3 && !ctl.admission_failures && !ctl.poison);
    assert(p11_owner_refund());
    assert(ctl.outstanding == 2 && !ctl.poison && p11_owner_healthy());
    assert(!cas_attempts); /* No retry loop exists for contention to exhaust. */

    /* A racing claim lands between the admission pre-check and this claim's
     * add and takes the last unit: this claim undoes exactly itself. */
    reset(); ctl.outstanding = OWNER_LIMIT - 1;
    add_interference_cell = &ctl.outstanding; add_racing_claims = 1;
    assert(!p11_owner_reserve());
    assert(ctl.outstanding == OWNER_LIMIT && ctl.admission_failures == 1 && !ctl.poison);

    /* In-flight over-limit claims transiently exceed the limit. That is
     * neither a bad control nor a refund failure. */
    reset(); ctl.outstanding = OWNER_LIMIT + 3;
    assert(p11_owner_healthy() && !ctl.poison);
    assert(!p11_owner_reserve());
    assert(ctl.outstanding == OWNER_LIMIT + 3 && ctl.admission_failures == 1 && !ctl.poison);
    assert(p11_owner_refund());
    assert(ctl.outstanding == OWNER_LIMIT + 2 && !ctl.poison);

    /* A genuine underflow poisons and never wraps the count. */
    reset();
    assert(!p11_owner_refund());
    assert(ctl.poison == OWNER_REFUND_FAILED && !ctl.outstanding);
    /* A wrapped count is a corrupt control. */
    reset(); ctl.outstanding = ~0ULL;
    assert(!p11_owner_healthy() && (ctl.poison & OWNER_BAD_CONTROL));
}

enum { HAMMER_ROUNDS = 100000, HAMMER_MAX_THREADS = 16 };
static u64 hammer_refused, hammer_unrefunded;
static void *reserve_refund_hammer(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < HAMMER_ROUNDS; i++) {
        if (!p11_owner_reserve())
            __atomic_fetch_add(&hammer_refused, 1, __ATOMIC_RELAXED);
        else if (!p11_owner_refund())
            __atomic_fetch_add(&hammer_unrefunded, 1, __ATOMIC_RELAXED);
    }
    return NULL;
}
static void *refused_admission_hammer(void *unused)
{
    (void)unused;
    for (unsigned i = 0; i < HAMMER_ROUNDS; i++)
        if (p11_owner_reserve())
            __atomic_fetch_add(&hammer_unrefunded, 1, __ATOMIC_RELAXED);
    return NULL;
}
static unsigned run_hammer(void *(*body)(void *))
{
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);
    unsigned threads = cpus < 4 ? 4 : cpus > HAMMER_MAX_THREADS ? HAMMER_MAX_THREADS : (unsigned)cpus;
    pthread_t workers[HAMMER_MAX_THREADS];
    hammer_refused = hammer_unrefunded = 0;
    for (unsigned i = 0; i < threads; i++)
        assert(!pthread_create(&workers[i], NULL, body, NULL));
    for (unsigned i = 0; i < threads; i++)
        assert(!pthread_join(workers[i], NULL));
    return threads;
}
/* Real CPUs, real atomics, the production accounting: every call reserves and
 * refunds the one shared count, so contention must never poison or refuse,
 * and refused admissions must be counted exactly (no dropped increment). */
static void threaded_contention(void)
{
    reset();
    unsigned threads = run_hammer(reserve_refund_hammer);
    fprintf(stderr, "reserve/refund x%u threads: poison=%llu outstanding=%llu admission=%llu refused=%llu unrefunded=%llu\n",
            threads, ctl.poison, ctl.outstanding, ctl.admission_failures, hammer_refused, hammer_unrefunded);
    assert(!ctl.poison && !ctl.outstanding && !ctl.admission_failures);
    assert(!hammer_refused && !hammer_unrefunded);
    reset(); ctl.outstanding = OWNER_LIMIT;
    threads = run_hammer(refused_admission_hammer);
    fprintf(stderr, "refused admissions x%u threads: counted=%llu expected=%llu poison=%llu\n",
            threads, ctl.admission_failures, (u64)threads * HAMMER_ROUNDS, ctl.poison);
    assert(!ctl.poison && ctl.outstanding == OWNER_LIMIT && !hammer_unrefunded);
    assert(ctl.admission_failures == (u64)threads * HAMMER_ROUNDS);
}
#ifndef P11SCOPE_INVENTORY_ONLY
static struct owner_start_key start_key(u32 slot)
{
    return (struct owner_start_key){pid_tgid(), slot, 0};
}
#endif
static struct owner_discovery_key discovery_key(u64 cookie, u64 domain)
{
    return (struct owner_discovery_key){pid_tgid(), cookie, domain};
}
/* Steady-state calls allocate nothing. Creating and deleting the 544-byte task
 * storage owner on every call made the kernel allocate (and RCU-defer freeing)
 * an element per call: under multi-threaded load the allocator runs dry and
 * calls were refused. The owner storage is created once per thread and then
 * retained idle (no lease) between calls; only exec/exit cleanup settles it. */
static void idle_owner_retention(void)
{
    reset();
    struct owner_discovery_key dkey = discovery_key(9, 1);
    for (unsigned i = 0; i < 1000; i++) {
#ifdef P11SCOPE_INVENTORY_ONLY
        assert(!p11_owner_discovery_insert(&dkey, value, 1));
        assert(!p11_owner_discovery_remove(&dkey, 1));
#else
        struct owner_start_key key = (struct owner_start_key){pid_tgid(), 7, 0};
        assert(!p11_owner_start_insert(&key, value));
        assert(!p11_owner_start_remove(&key, 1));
        assert(!p11_owner_discovery_insert(&dkey, value, 1));
        assert(!p11_owner_discovery_remove(&dkey, 1));
#endif
    }
    fprintf(stderr, "1000 call cycles: creates=%d deletes=%d outstanding=%llu poison=%llu\n",
            creates, deletes, ctl.outstanding, ctl.poison);
    assert(creates == 1 && deletes == 0);
    assert(!ctl.outstanding && !ctl.poison && !ctl.admission_failures);
    /* Between calls the retained owner is idle: installed, unleased, empty. */
    assert(installed[0] && !owners[0].flags && !owners[0].original_pid_tgid);
    assert(!owners[0].start_count && !owners[0].occupied && !owners[0].selection_domains);
    /* Allocation failure after the first call can no longer refuse a call. */
    fail_create = 1;
#ifndef P11SCOPE_INVENTORY_ONLY
    struct owner_start_key key = (struct owner_start_key){pid_tgid(), 7, 0};
    assert(!p11_owner_start_insert(&key, value));
    assert(ctl.outstanding == 1 && owners[0].flags == OWNER_LEASED);
    assert(!p11_owner_start_remove(&key, 1));
#else
    assert(!p11_owner_discovery_insert(&dkey, value, 1));
    assert(!p11_owner_discovery_remove(&dkey, 1));
#endif
    assert(!ctl.outstanding && !ctl.admission_failures && !ctl.poison);
    /* An idle owner is absence, not a record: no poison from peeks. */
    fail_create = 0;
    struct owner_discovery_key absent = discovery_key(10, 2);
    assert(!p11_owner_discovery_get(&absent, 0));
    assert(p11_owner_discovery_remove(&absent, 0) == -2);
    assert(!ctl.poison);
    /* An idle owner can never satisfy a required lookup (it holds no rows). */
    assert(!p11_owner_discovery_get(&dkey, 1) && (ctl.poison & OWNER_LOOKUP_UNKNOWN));
}

/* The lease is one global scalar transaction (verified once, not per caller
 * path, so older verifiers stay under their instruction budget): it creates or
 * re-leases the owner and counts one reservation, and a caller then only reads
 * the leased owner back. */
static void lease_boundary(void)
{
    reset();
    assert(p11_owner_lease());
    assert(creates == 1 && ctl.outstanding == 1 && owners[0].flags == OWNER_LEASED);
    assert(owners[0].original_pid_tgid == pid_tgid());
    /* Re-leasing a held owner reserves nothing more. */
    assert(p11_owner_lease());
    assert(creates == 1 && ctl.outstanding == 1 && !ctl.poison);
    /* It holds no rows, so returning it leaves the retained owner idle. */
    assert(release_empty(&ctl, &owners[0]) && idle(0) && !ctl.outstanding);
    /* A lease whose owner the caller then cannot read back (a busy lookup)
     * refuses the call and refunds nothing twice: the lease stays with its
     * empty owner until this thread's next release or exit cleanup. */
    miss_get = 1; miss_get_skip = 1;
#ifndef P11SCOPE_INVENTORY_ONLY
    struct owner_start_key key = (struct owner_start_key){pid_tgid(), 3, 0};
    assert(p11_owner_start_insert(&key, value) == -1);
#else
    struct owner_discovery_key dkey = discovery_key(11, 1);
    assert(p11_owner_discovery_insert(&dkey, value, 1) == -1);
#endif
    assert(ctl.admission_failures == 1 && !ctl.poison);
    assert(ctl.outstanding == 1 && owners[0].flags == OWNER_LEASED && !owners[0].start_count);
    /* The next call reuses that lease, and its release settles it. */
#ifndef P11SCOPE_INVENTORY_ONLY
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_owner_start_remove(&key, 1));
#else
    assert(!p11_owner_discovery_insert(&dkey, value, 1));
    assert(!p11_owner_discovery_remove(&dkey, 1));
#endif
    assert(!ctl.outstanding && idle(0) && !ctl.poison && creates == 1);
    /* A poisoned owner control refuses a lease without reserving. */
    ctl.poison = OWNER_CLASSIFIER_FAILED;
    assert(!p11_owner_lease() && !ctl.outstanding);
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
#ifdef P11SCOPE_INVENTORY_ONLY
    reset(); struct owner_discovery_key key = discovery_key(7, 1);
    assert(!p11_owner_discovery_insert(&key, value, 1));
    miss_get = 1;
    p11_owner_cleanup();
    assert(ctl.poison && ctl.outstanding == 1 && row(&DISCOVERY_STATE, &key));
    assert(!p11_owner_discovery_get(&key, 1));
    assert(p11_owner_discovery_insert(&key, value, 1));
#else
    reset(); struct owner_start_key key = start_key(7);
    assert(!p11_owner_start_insert(&key, value));
    miss_get = 1; /* Classifier unexpectedly deletes an unknown installed owner. */
    p11_owner_cleanup();
    assert(ctl.poison && ctl.outstanding == 1 && row(&START, &key));
    assert(!p11_owner_start_get(&key, 1)); /* Poison must dominate saved state. */
    assert(p11_owner_start_insert(&key, value));
#endif
    assert(!p11_owner_healthy());
}
#ifndef P11SCOPE_INVENTORY_ONLY
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
    assert(!ctl.outstanding && idle(0) && !ctl.poison && !deletes);
    reset(); fail_create = 1;
    assert(p11_owner_start_insert(&key, value));
    assert(!ctl.outstanding && !installed[0] && !ctl.poison);
    reset(); update_error = -12;
    assert(p11_owner_start_insert(&key, value));
    assert(!ctl.outstanding && idle(0) && !ctl.poison);
    reset(); assert(!p11_owner_start_insert(&key, value));
    pair_delete_error = -16;
    assert(p11_owner_start_remove(&key, 1));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].start_count == 1);
    /* Release never deletes storage, so a storage delete error is irrelevant. */
    reset(); assert(!p11_owner_start_insert(&key, value));
    delete_error = -16;
    assert(!p11_owner_start_remove(&key, 1));
    assert(!ctl.poison && !ctl.outstanding && idle(0) && !deletes);
    /* Settlement after poison still returns the lease; poison stays terminal. */
    reset(); assert(!p11_owner_start_insert(&key, value));
    ctl.poison = OWNER_CLASSIFIER_FAILED; p11_owner_cleanup();
    assert(!ctl.outstanding && ctl.poison == OWNER_CLASSIFIER_FAILED && idle(0));
    assert(!row(&START, &key) && ctl.abandoned_start == 1);
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
#endif
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
    assert(idle(0) && !ctl.outstanding && !ctl.poison);
    reset(); struct owner_discovery_key bad = discovery_key(0, 3);
    assert(p11_owner_discovery_insert(&bad, value, 1));
    assert(idle(0) && !ctl.outstanding);
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
#ifndef P11SCOPE_INVENTORY_ONLY
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
#endif
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
#ifndef P11SCOPE_INVENTORY_ONLY
static void capacity_collision(void)
{
    reset();
    for (unsigned i = 0; i < P11SCOPE_OWNER_SLOT_BOUND; i++) {
        struct owner_start_key key = start_key(i);
        assert(!p11_owner_start_insert(&key, value));
    }
    struct owner_start_key nested = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
    assert(p11_owner_start_insert(&nested, value));
    assert(!row(&START, &nested) && owners[0].start_count == P11SCOPE_OWNER_SLOT_BOUND - 1);
    p11_owner_cleanup(); assert(ctl.abandoned_start == P11SCOPE_OWNER_SLOT_BOUND - 1 && !ctl.outstanding);
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
    /* A failed insert returns its lease; no storage delete can fail it. */
    reset(); update_error = -12; delete_error = -16;
    assert(p11_owner_discovery_insert(&live_discovery, value, 1));
    assert(!ctl.poison && !ctl.outstanding && idle(0) && !deletes);
}
#endif
#ifndef P11SCOPE_INVENTORY_ONLY
/* H7 slice B object custody controls. Test descriptor rows: function 22 at
 * index 23 (marker 24) and function 20 at index 21 (marker 22). */
static void object_write_start(unsigned char *slot, u64 marker)
{
    u64 cookie = 0x1111000000000000ULL | (u64)current_index;
    u64 exec = 0x2222000000000000ULL | (u64)current_index;
    u64 ts = 0x3333000000000000ULL | (u64)current_index;
    memcpy(slot + 264, &marker, 8);
    memcpy(slot + 272, &cookie, 8);
    memcpy(slot + 280, &exec, 8);
    memcpy(slot + 0, &ts, 8);
}
static void object_desc_row(unsigned char *slot, u32 function, unsigned char action)
{
    memset(slot, 0xFF, 16);
    memcpy(slot + 0, &function, 4);
    slot[14] = action;
    slot[15] = 1;
}
static void object_setup(void)
{
    unsigned char zero[432];
    unsigned char desc[16];
    u32 key;
    memset(zero, poison_zero_row == 1 ? 0xA5 : 0, sizeof(zero));
    if (poison_zero_row == 2)
        zero[424] = 1; /* START's first 288 bytes remain clean. */
    key = 0;
    assert(!update(&OBJECT_ZERO, &key, zero, 0));
    for (key = 0; key < 105; key++) {
        memset(desc, 0xFF, sizeof(desc));
        desc[14] = 0;
        desc[15] = 0;
        if (key == 23)
            object_desc_row(desc, 22, 7);
        else if (key == 21)
            object_desc_row(desc, 20, 1);
        assert(!update(&OBJECT_DESCRIPTORS, &key, desc, 0));
    }
}
static struct object_start object_side_copy(const struct owner_start_key *key)
{
    struct object_start out;
    struct row *found = row(&OBJECT_START, key);
    assert(found);
    memcpy(&out, found->value, 432);
    return out;
}
static void object_aggregate_start_construction(void)
{
    assert(&p11_owner_start_aggregate && "production aggregate START constructor is missing");
    struct owner_start_key key = { .slot = 7 };
    for (unsigned clock = 0; clock < 2; clock++) {
        reset(); object_setup(); key.pid_tgid = pid_tgid();
        const u64 timestamp = clock ? 0x13579bdf02468aceULL : 0;
        assert(p11_owner_start_aggregate(&key, timestamp) == 1);
        unsigned char expected[288] = {0};
        memcpy(expected, &timestamp, 8);
        assert(row(&START, &key) && !memcmp(row(&START, &key)->value, expected, 288));
        assert(!row(&OBJECT_START, &key));
        assert(owners[0].start_count == 1 && ctl.outstanding == 1 && !ctl.poison);
        assert(!p11_owner_start_remove(&key, 1));
        assert(!row(&START, &key) && !ctl.outstanding && idle(0) && !ctl.poison);
    }
    for (unsigned fault = 0; fault < 7; fault++) {
        reset();
        if (fault == 1) poison_zero_row = 1;
        if (fault == 6) poison_zero_row = 2;
        object_setup(); key.pid_tgid = pid_tgid(); key.pad = 0;
        if (fault == 0) drop_zero_row = 1;
        if (fault == 2) fail_start_readback_once = 1;
        if (fault == 3) update_error = -12;
        if (fault == 4) key.pid_tgid++;
        if (fault == 5) key.pad = 1;
        assert(!p11_owner_start_aggregate(&key, 17));
        assert(!row(&START, &key) && !row(&OBJECT_START, &key));
        assert(!ctl.outstanding && !owners[0].start_count && idle(0));
    }
    key.pad = 0;
    /* Readback rollback failure retains an allzero owned row for retry. */
    reset(); object_setup(); key.pid_tgid = pid_tgid();
    fail_start_readback_once = 1; fail_start_delete = -12;
    assert(!p11_owner_start_aggregate(&key, 17));
    assert(row(&START, &key) && !row(&OBJECT_START, &key));
    assert(!memcmp(row(&START, &key)->value, (unsigned char[288]){0}, 288));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    fail_start_delete = 0;
    assert(p11_owner_cleanup() == 1 && !row(&START, &key) && !ctl.outstanding);
    reset(); object_setup(); key.pid_tgid = pid_tgid();
    assert(p11_owner_start_aggregate(&key, 17));
    assert(!p11_owner_start_aggregate(&key, 18));
    assert(!row(&START, &key) && !row(&OBJECT_START, &key) && !ctl.outstanding);
    /* A nested aggregate still retires its ambiguous older object invocation. */
    reset(); object_setup(); key.pid_tgid = pid_tgid();
    struct call_start_seed original = {
        .ts_ns = 17, .task_cookie = 19, .exec_id = 3, .object_required = 22,
    };
    assert(p11_owner_start_begin(&key, &original));
    deleted_side_seen = 0;
    assert(!p11_owner_start_aggregate(&key, 18));
    assert(!row(&START, &key) && !row(&OBJECT_START, &key) && !ctl.outstanding);
    assert(deleted_side_seen && !memcmp(deleted_side, (unsigned char[432]){0}, 432));
    assert(!ctl.poison);
    puts("aggregate START construction passed");
}
static void object_seeded_start_construction(void)
{
    assert(&p11_owner_start_begin && "production seeded START constructor is missing");
    struct owner_start_key key = { .slot = 7 };
    struct call_start_seed seed = {
        .ts_ns = 0, /* Zero is a real timestamp, never an unavailable sentinel. */
        .task_cookie = 0x123456789abcdef0ULL,
        .exec_id = 0,
        .object_required = 0,
    };
    for (unsigned variant = 0; variant < 4; variant++) {
        reset(); object_setup(); key.pid_tgid = pid_tgid();
        const unsigned required = variant & 1;
        seed.ts_ns = variant < 2 ? 0 : 0x13579bdf02468aceULL;
        seed.exec_id = variant < 2 ? 0 : 0x2468ace013579bdfULL;
        seed.object_required = required ? 22 : 0;
        unsigned char *start = p11_owner_start_begin(&key, &seed);
        assert(start && start == row(&START, &key)->value);
        assert(owners[0].start_count == 1 && ctl.outstanding == 1 && !ctl.poison);
        unsigned char expected[288] = {0};
        memcpy(expected, &seed.ts_ns, 8);
        memcpy(expected + 264, &seed.object_required, 8);
        memcpy(expected + 272, &seed.task_cookie, 8);
        memcpy(expected + 280, &seed.exec_id, 8);
        assert(!memcmp(start, expected, sizeof(expected)));
        if (required) {
            struct object_start *side = p11_object_side_get(&key, 21, 0);
            assert(side && side->phase == OBJECT_PHASE_ENTRY);
            assert(side->entry_ns == seed.ts_ns && side->task_cookie == seed.task_cookie);
            assert(side->exec_id == seed.exec_id && side->descriptor_index == 21);
            assert(!p11_object_side_get(&key, 21, 1));
            u64 session = 0x9988776655443322ULL;
            memcpy(start + 8, &session, 8);
            assert(p11_object_side_get(&key, 21, 0) == side);
            assert(side->entry_ns == seed.ts_ns && side->task_cookie == seed.task_cookie);
        } else {
            assert(!row(&OBJECT_START, &key));
        }
        assert(!p11_owner_start_remove(&key, 1));
        assert(!row(&START, &key) && !row(&OBJECT_START, &key));
        assert(!ctl.outstanding && idle(0) && !ctl.poison);
    }
    /* Changed immutable identity is refused, never rebound. */
    reset(); object_setup(); key.pid_tgid = pid_tgid(); seed.object_required = 22;
    unsigned char *start = p11_owner_start_begin(&key, &seed);
    assert(start);
    u64 changed = seed.ts_ns + 1;
    memcpy(start, &changed, 8);
    assert(!p11_object_side_get(&key, 21, 0));
    assert(p11_owner_start_remove(&key, 1));
    assert(!row(&START, &key) && !row(&OBJECT_START, &key));
    assert(!ctl.outstanding && (ctl.poison & OWNER_OBJECT_MISMATCH));
    puts("seeded START construction passed");
}

static void object_seeded_start_failures(void)
{
    assert(&p11_owner_start_begin && "production seeded START constructor is missing");
    struct owner_start_key key = { .slot = 7 };
    const struct call_start_seed seed = {
        .ts_ns = 0x13579bdfULL, .task_cookie = 0x2468ace0ULL,
        .exec_id = 3, .object_required = 22,
    };
    for (unsigned fault = 0; fault < 8; fault++) {
        reset();
        if (fault == 1) poison_zero_row = 1;
        if (fault == 7) poison_zero_row = 2;
        object_setup(); key.pid_tgid = pid_tgid();
        if (fault == 0) drop_zero_row = 1;
        if (fault == 2) fail_start_readback_once = 1;
        if (fault == 3) fail_object_side_update = -12;
        if (fault == 4) fail_object_side_lookup_once = 1;
        if (fault == 5) key.pid_tgid++;
        if (fault == 6) update_error = -12;
        struct call_start_seed checked = seed;
        /* Ordinary marker avoids the later side-allocation zero check:
         * byte424 must be rejected by START construction itself. */
        if (fault == 7) checked.object_required = 0;
        assert(!p11_owner_start_begin(&key, &checked));
        assert(!row(&START, &key) && !row(&OBJECT_START, &key));
        assert(!ctl.outstanding && !owners[0].start_count && idle(0));
    }
    /* Missing identity and an invalid descriptor marker never publish a row. */
    for (unsigned fault = 0; fault < 5; fault++) {
        reset(); object_setup(); key.pid_tgid = pid_tgid();
        struct call_start_seed rejected = seed;
        if (fault == 0) rejected.task_cookie = 0;
        if (fault == 1) rejected.object_required = 1;
        if (fault == 2) rejected.object_required = OBJECT_DESCRIPTORS_COUNT + 1;
        if (fault == 4) key.pad = 1;
        assert(!p11_owner_start_begin(&key, fault == 3 ? NULL : &rejected));
        assert(!row(&START, &key) && !row(&OBJECT_START, &key));
        assert(!ctl.outstanding && !owners[0].start_count);
    }
    key.pad = 0;
    /* At the real slot bound, nested ambiguity still retires only its own
     * invocation and subordinate row; siblings retain their shared lease. */
    reset(); object_setup(); key.pid_tgid = pid_tgid();
    for (unsigned slot = 0; slot < P11SCOPE_OWNER_SLOT_BOUND; slot++) {
        struct owner_start_key fill = { .pid_tgid = pid_tgid(), .slot = slot };
        struct call_start_seed bounded = seed;
        if (slot != key.slot) bounded.object_required = 0;
        assert(p11_owner_start_begin(&fill, &bounded));
    }
    assert(owners[0].start_count == P11SCOPE_OWNER_SLOT_BOUND && ctl.outstanding == 1);
    deleted_side_seen = 0;
    assert(!p11_owner_start_begin(&key, &seed));
    assert(!row(&START, &key) && !row(&OBJECT_START, &key));
    assert(deleted_side_seen && !memcmp(deleted_side, (unsigned char[432]){0}, 432));
    assert(owners[0].start_count == P11SCOPE_OWNER_SLOT_BOUND - 1 && ctl.outstanding == 1);
    assert(!ctl.poison
           && p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(!ctl.outstanding && ctl.abandoned_start == P11SCOPE_OWNER_SLOT_BOUND - 1);
    /* Failed START rollback retains its count, lease and teardown route. */
    reset(); object_setup(); key.pid_tgid = pid_tgid();
    fail_start_readback_once = 1; fail_start_delete = -12;
    assert(!p11_owner_start_begin(&key, &seed));
    assert(row(&START, &key) && !row(&OBJECT_START, &key));
    assert(!memcmp(row(&START, &key)->value, (unsigned char[288]){0}, 288));
    assert(ctl.outstanding == 1 && owners[0].start_count == 1);
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    fail_start_delete = 0;
    assert(p11_owner_cleanup() == 1); /* Sticky poison remains visible. */
    assert(!row(&START, &key) && !ctl.outstanding);
    /* The subordinate orphan-delete retry contract remains intact. */
    reset(); object_setup(); key.pid_tgid = pid_tgid();
    fail_object_side_lookup_once = 1; fail_object_side_delete = -12;
    assert(!p11_owner_start_begin(&key, &seed));
    assert(row(&START, &key) && row(&OBJECT_START, &key));
    assert(ctl.outstanding == 1 && owners[0].start_count == 1);
    assert(!memcmp(row(&OBJECT_START, &key)->value, (unsigned char[432]){0}, 432));
    fail_object_side_delete = 0;
    assert(p11_owner_cleanup() == 1); /* Cleanup settles debt, not poison. */
    assert(!row(&START, &key) && !row(&OBJECT_START, &key) && !ctl.outstanding);
    /* Same-key NOEXIST ambiguity retires the original invocation. */
    reset(); object_setup(); key.pid_tgid = pid_tgid();
    assert(p11_owner_start_begin(&key, &seed));
    assert(!p11_owner_start_begin(&key, &seed));
    assert(!row(&START, &key) && !row(&OBJECT_START, &key));
    assert(!ctl.outstanding && !owners[0].start_count && ctl.admission_failures);
    /* A foreign task's live key never supplies cleanup authority. */
    reset(); object_setup(); current_index = 1; key.pid_tgid = pid_tgid();
    assert(p11_owner_start_begin(&key, &seed));
    current_index = 0;
    assert(!p11_owner_start_begin(&key, &seed));
    assert(row(&START, &key) && row(&OBJECT_START, &key));
    assert(owners[1].start_count == 1 && ctl.outstanding == 1 && idle(0));
    assert(!ctl.poison);
    current_index = 1;
    assert(!p11_owner_start_remove(&key, 1) && !ctl.outstanding);
    puts("seeded START failure controls passed");
}

static int object_bytes_zeroed(const unsigned char *bytes)
{
    for (unsigned i = 0; i < 432; i++)
        if (bytes[i])
            return 0;
    return 1;
}
static void object_expect_binding(struct object_start got, u32 index, unsigned char action)
{
    assert(got.descriptor_index == index);
    assert(got.action == action);
    assert(got.layout == 0);
    assert(got.derive == 0);
    assert(got.phase == 1);
    assert(got.task_cookie == (0x1111000000000000ULL | (u64)current_index));
    assert(got.exec_id == (0x2222000000000000ULL | (u64)current_index));
    assert(got.entry_ns == (0x3333000000000000ULL | (u64)current_index));
    assert(got.inputs[0] == 0 && got.inputs[1] == 0);
    assert(got.result_ptrs[0] == 0 && got.result_ptrs[1] == 0);
    assert(got.slots[3].value_ptr == 0 && got.slots[7].returned_len == 0);
    assert(got.requested[1].inspected == 0 && got.flags == 0);
}
/* Fixture-only mirror of the BPF return drain's agreement conjunct: query
 * the validated side row (required=0), check attached-descriptor and
 * retained-ABI agreement, retire through the ordinary removal. Calls
 * production functions only. The agreement below must match the drain arm's
 * required=0 query plus agreement line for line; the Rust arm additionally
 * conjoins the required=1 ready fill (`filled &&`), which the Rust
 * source-shapes test pins. Returns the drained sane phase, or 0 when the
 * drain faults. A monolithic native drain is kernel-infeasible: it would
 * nest one level deeper than return's 512-byte call-chain budget allows.
 * The query records nothing; the retire records once. */
static unsigned drain_via_query(const struct owner_start_key *key, u32 descriptor, u32 layout)
{
    const struct object_start *side = p11_object_side_get(key, descriptor, 0);
    unsigned phase = 0;
    int agree = side != NULL && side->descriptor_index == descriptor &&
        (!side->layout || side->layout == layout);
    if (agree)
        phase = side->phase;
    if (p11_owner_start_remove(key, 1))
        return 0;
    return agree ? phase : 0;
}
static void object_producer_owner_terminal_matrix(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    struct object_start side;
    /* Normal settle: subordinate row bound, scrubbed, deleted; START
     * deleted; lease refunded; nothing retained. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    side = object_side_copy(&key);
    object_expect_binding(side, 23, 7);
    assert(drain_via_query(&key, 23, 1) == 1);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && idle(0) && !ctl.poison);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    assert(!p11_object_side_get(&key, 23, 0) && !p11_object_side_get(&key, 23, 1));
    assert(!p11_owner_start_get(&key, 0));
    /* Ready and returning phases drain with their phase. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    assert(drain_via_query(&key, 23, 1) == 2);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key) && !ctl.outstanding && !ctl.poison);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 22);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 3;
    assert(drain_via_query(&key, 21, 2) == 3);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key) && !ctl.outstanding && !ctl.poison);
    /* Wrong attached descriptor: retired, fault verdict, no poison. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!drain_via_query(&key, 21, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && !ctl.poison);
    /* Wrong retained ABI: retired, fault verdict, no poison; a matching
     * retained ABI drains. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[28] = 2;
    assert(!drain_via_query(&key, 23, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key) && !ctl.poison);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[28] = 2;
    assert(drain_via_query(&key, 23, 2) == 1);
    assert(!ctl.poison);
    /* Ordinary rows retire safely through the drain with a fault verdict. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&key, value));
    assert(!drain_via_query(&key, 0, 1));
    assert(!row(&START, &key) && !ctl.outstanding && !ctl.poison);
    /* A side row leaked onto an ordinary call is scrubbed, deleted and
     * reported: the query stays quiet, the retire records once. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_object_side_get(&key, 0, 0) && !ctl.poison);
    {
        unsigned char leaked[432];
        memset(leaked, 0, sizeof(leaked));
        assert(!update(&OBJECT_START, &key, leaked, 1));
    }
    assert(!p11_object_side_get(&key, 0, 0) && !ctl.poison);
    assert(!drain_via_query(&key, 0, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && (ctl.poison & OWNER_OBJECT_MISMATCH));
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    /* Scope-loss and ABI-refusal drains retire cleanly with scrub. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_owner_start_remove(&key, 0));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && !ctl.poison);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    assert(p11_owner_start_remove(&key, 0) == -2 && !ctl.poison);
    /* An unproven numeric key never authorizes side cleanup: the absent
     * START refuses, the orphan stays, and the accounting fault is
     * reported. A consistent teardown then sweeps the orphaned row. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!pair_delete(&START, &key));
    deleted_side_seen = 0;
    assert(p11_owner_start_remove(&key, 0) == -2 && !ctl.poison);
    assert(row(&OBJECT_START, &key) && !deleted_side_seen);
    assert(p11_owner_cleanup() == 1);
    assert(ctl.poison & OWNER_START_COUNT_MISMATCH);
    assert(row(&OBJECT_START, &key) && ctl.outstanding == 1);
    owners[0].start_count--;
    deleted_side_seen = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&OBJECT_START, &key) && ctl.abandoned_start == 1);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    assert(!ctl.outstanding && (ctl.poison & OWNER_START_COUNT_MISMATCH));
    /* Recursive collision invalidates the older invocation including its
     * subordinate row, without poisoning. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(p11_owner_start_insert(&key, value) == -17);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!owners[0].start_count && !ctl.outstanding && !ctl.poison);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    /* Capacity-bound invalidation retires the nested subordinate row. */
    reset(); object_setup();
    for (unsigned slot = 0; slot < P11SCOPE_OWNER_SLOT_BOUND; slot++) {
        struct owner_start_key fill = { .pid_tgid = pid_tgid(), .slot = slot };
        if (slot == 7)
            continue;
        memset(value, 0, sizeof(value));
        assert(!p11_owner_start_insert(&fill, value));
    }
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(owners[0].start_count == P11SCOPE_OWNER_SLOT_BOUND && ctl.outstanding == 1);
    memset(value, 0, sizeof(value)); object_write_start(value, 22);
    deleted_side_seen = 0;
    assert(p11_owner_start_insert(&key, value) == -1);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(owners[0].start_count == P11SCOPE_OWNER_SLOT_BOUND - 1);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START
           && ctl.abandoned_start == P11SCOPE_OWNER_SLOT_BOUND - 1);
    assert(!ctl.outstanding && !ctl.poison);
    /* Missing side row: invocation retired, refunded, poisoned. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!pair_delete(&OBJECT_START, &key));
    assert(!drain_via_query(&key, 23, 1));
    assert(!row(&START, &key) && !ctl.outstanding);
    assert((ctl.poison & (OWNER_BOOKKEEPING_FAILED | OWNER_OBJECT_MISMATCH)) ==
        (OWNER_BOOKKEEPING_FAILED | OWNER_OBJECT_MISMATCH));
    /* Conflicting side rows are never replaced: the invocation fails
     * visibly and the older row is untouched. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    {
        unsigned char older[432];
        struct row *kept;
        memset(older, 0, sizeof(older));
        assert(!update(&OBJECT_START, &key, older, 1));
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(p11_owner_start_insert(&key, value) == -17);
        assert(!row(&START, &key));
        kept = row(&OBJECT_START, &key);
        assert(kept && object_bytes_zeroed(kept->value));
        assert((ctl.poison & OWNER_OBJECT_MISMATCH) && !ctl.outstanding && idle(0));
    }
    /* Failed side admission refuses visibly without poisoning. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    fail_object_side_update = -12;
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(p11_owner_start_insert(&key, value) == -12);
    assert(!row(&START, &key) && ctl.admission_failures == 1);
    assert(!ctl.poison && !ctl.outstanding && idle(0));
    /* A missing or dirty zero template refuses visibly with bookkeeping. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    drop_zero_row = 1;
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(p11_owner_start_insert(&key, value) == -1);
    assert(!row(&START, &key) && (ctl.poison & OWNER_OBJECT_MISMATCH));
    assert(!ctl.outstanding && idle(0));
    reset(); poison_zero_row = 1; object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(p11_owner_start_insert(&key, value) == -1);
    assert(!row(&START, &key) && (ctl.poison & OWNER_OBJECT_MISMATCH));
    assert(!ctl.outstanding && idle(0));
    /* Invalid markers roll the START row back; never downgraded. */
    {
        u64 bad[] = {1, 105, 106, 255, 256, 0x100 | 24, 0xFFFFFFFFFFFFFFFFULL};
        for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            reset(); object_setup();
            key.pid_tgid = pid_tgid();
            memset(value, 0, sizeof(value)); object_write_start(value, bad[i]);
            assert(p11_owner_start_insert(&key, value) == -1);
            assert(!row(&START, &key) && !row(&OBJECT_START, &key));
            assert((ctl.poison & OWNER_OBJECT_MISMATCH));
            assert(!ctl.outstanding && idle(0));
        }
    }
    /* Failed side deletion keeps both rows, the lease and no refund; the
     * side value is already scrubbed and a retry converges. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    fail_object_side_delete = -16;
    assert(!drain_via_query(&key, 23, 1));
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    assert(object_bytes_zeroed(row(&OBJECT_START, &key)->value));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    fail_object_side_delete = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key) && !ctl.outstanding);
    assert(ctl.abandoned_start == 1);
    /* A failed START deletion on a contradicted row also keeps its lease. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!pair_delete(&OBJECT_START, &key));
    pair_delete_error = -16;
    assert(!drain_via_query(&key, 23, 1));
    assert(row(&START, &key) && owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    pair_delete_error = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &key) && !ctl.outstanding && ctl.abandoned_start == 1);
    /* A failed START deletion on a healthy row keeps START, its count
     * and its lease; the side row is already scrubbed and deleted.
     * Teardown converges through the contradiction path once the error
     * clears. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    fail_start_delete = -16;
    deleted_side_seen = 0;
    assert(p11_owner_start_remove(&key, 1));
    assert(!row(&OBJECT_START, &key) && row(&START, &key));
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    fail_start_delete = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &key) && !ctl.outstanding && ctl.abandoned_start == 1);
    /* Wrong physical owner: a different live task, an unproven recycled
     * numeric identity, and a fresh recycled owner all refuse without
     * touching the rows or the scrubber. Leases settle exactly as the
     * ordinary removal settles them: a live foreign lease is kept, while
     * the fresh owner's emptied lease is refunded; row custody never
     * follows an unproven identity either way. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    current_index = 1;
    {
        struct owner_start_key other = { .pid_tgid = pid_tgid(), .slot = 3 };
        memset(value, 0, sizeof(value));
        assert(!p11_owner_start_insert(&other, value));
        assert(!drain_via_query(&key, 23, 1));
        assert(!p11_object_side_get(&key, 23, 1));
        assert(ctl.poison & OWNER_START_KEY_MISMATCH);
        assert(row(&OBJECT_START, &key) && row(&START, &key));
        assert(row(&START, &other) && ctl.outstanding == 2);
        assert(!deleted_side_seen);
    }
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    current_index = 1;
    current_number[1] = current_number[0];
    assert(!drain_via_query(&key, 23, 1));
    assert(!p11_object_side_get(&key, 23, 1));
    assert(ctl.poison & OWNER_LOOKUP_UNKNOWN);
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(!deleted_side_seen);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    current_index = 1;
    current_number[1] = current_number[0];
    assert(p11_owner_lease());
    assert(!drain_via_query(&key, 23, 1));
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    assert(ctl.poison & OWNER_START_COUNT_MISMATCH);
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(idle(1));
    assert(!deleted_side_seen);
    /* Repeated cleanup converges and stays quiet. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(row(&START, &key) && owners[0].start_count == 1);
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(!row(&START, &key) && ctl.abandoned_start == 1);
    assert(!p11_owner_cleanup() && ctl.abandoned_start == 1);
    assert(!p11_object_side_get(&key, 23, 0) && !p11_object_side_get(&key, 23, 1));
    /* No cross-call reuse: a reinserted call starts from a zeroed row. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    memset(row(&OBJECT_START, &key)->value + 32, 0xA5, 64);
    assert(drain_via_query(&key, 23, 1) == 1);
    memset(value, 0, sizeof(value)); object_write_start(value, 22);
    assert(!p11_owner_start_insert(&key, value));
    side = object_side_copy(&key);
    object_expect_binding(side, 21, 1);
    assert(drain_via_query(&key, 21, 1) == 1);
    assert(!ctl.poison);
    puts("object custody terminal matrix passed");
}
static void object_producer_side_state_n_and_n_plus_one(void)
{
    struct owner_start_key five = { .pid_tgid = 0, .slot = 5 };
    struct owner_start_key six = { .pid_tgid = 0, .slot = 6 };
    struct object_start side;
    /* Adjacent slots keep independent subordinate rows: settling one
     * leaves the other bound and readable. */
    reset(); object_setup();
    five.pid_tgid = pid_tgid();
    six.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&five, value));
    memset(value, 0, sizeof(value)); object_write_start(value, 22);
    assert(!p11_owner_start_insert(&six, value));
    assert(owners[0].start_count == 2 && ctl.outstanding == 1);
    row(&OBJECT_START, &six)->value[31] = 2;
    assert(drain_via_query(&five, 23, 1) == 1);
    assert(!row(&START, &five) && row(&START, &six) && row(&OBJECT_START, &six));
    side = object_side_copy(&six);
    assert(side.descriptor_index == 21 && side.action == 1 && side.phase == 2);
    assert(owners[0].start_count == 1 && ctl.outstanding == 1 && !ctl.poison);
    assert(drain_via_query(&six, 21, 1) == 2);
    assert(!row(&START, &six) && !row(&OBJECT_START, &six));
    assert(!ctl.outstanding && idle(0) && !ctl.poison);
    /* Interleaved plain removal keeps the neighbor untouched. */
    reset(); object_setup();
    five.pid_tgid = pid_tgid();
    six.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&five, value));
    memset(value, 0, sizeof(value)); object_write_start(value, 22);
    assert(!p11_owner_start_insert(&six, value));
    assert(!p11_owner_start_remove(&six, 1));
    assert(!row(&START, &six) && !row(&OBJECT_START, &six));
    side = object_side_copy(&five);
    object_expect_binding(side, 23, 7);
    assert(drain_via_query(&five, 23, 1) == 1);
    assert(!row(&START, &five) && !ctl.outstanding && !ctl.poison);
    /* The N+1th subordinate row is refused without disturbing the N live
     * rows: visibly failed, rolled back, unpoisoned. */
    reset(); object_setup();
    five.pid_tgid = pid_tgid();
    six.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&five, value));
    memset(value, 0, sizeof(value)); object_write_start(value, 22);
    assert(!p11_owner_start_insert(&six, value));
    {
        struct owner_start_key seven = { .pid_tgid = pid_tgid(), .slot = 7 };
        fail_object_side_update = -12;
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(p11_owner_start_insert(&seven, value) == -12);
        assert(!row(&START, &seven) && !row(&OBJECT_START, &seven));
    }
    assert(owners[0].start_count == 2 && ctl.outstanding == 1);
    assert(ctl.admission_failures == 1 && !ctl.poison);
    side = object_side_copy(&five);
    object_expect_binding(side, 23, 7);
    side = object_side_copy(&six);
    object_expect_binding(side, 21, 1);
    assert(drain_via_query(&five, 23, 1) == 1);
    assert(drain_via_query(&six, 21, 1) == 1);
    assert(!ctl.outstanding && !ctl.poison);
    puts("object custody side state passed");
}
static void object_producer_missing_side_state_faults_before_return(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    /* A missing side row authorizes nothing: the verdict fails, the
     * invocation is retired, and no live row remains for a tail. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!pair_delete(&OBJECT_START, &key));
    assert(!drain_via_query(&key, 23, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding);
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    /* Mismatched bindings fail the same way. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    memset(row(&OBJECT_START, &key)->value + 24, 0xFF, 4);
    assert(!drain_via_query(&key, 23, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    memset(row(&OBJECT_START, &key)->value + 0, 0xFF, 16);
    assert(!drain_via_query(&key, 23, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    /* Insane phases fail; entry/returning phases refuse reads quietly. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 9;
    assert(!drain_via_query(&key, 23, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_object_side_get(&key, 23, 1) && !ctl.poison);
    row(&OBJECT_START, &key)->value[31] = 3;
    assert(!p11_object_side_get(&key, 23, 1) && !ctl.poison);
    row(&OBJECT_START, &key)->value[31] = 2;
    assert(p11_object_side_get(&key, 23, 1));
    assert(!ctl.poison);
    row(&OBJECT_START, &key)->value[31] = 9;
    assert(!p11_object_side_get(&key, 23, 1) && !ctl.poison);
    assert(p11_owner_start_remove(&key, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    /* Attached-descriptor disagreement refuses quietly: per-call loss. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_object_side_get(&key, 21, 1) && !ctl.poison);
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    /* The fault leaf advances the checked cell visibly. */
    reset(); object_setup();
    instance_gen[0] = 5;
    p11_object_fault();
    assert(instance_gen[0] == 6 && instance_counters_live.faults == 1);
    /* An exhausted fault counter stays refused and never wraps. */
    reset(); object_setup();
    instance_gen[0] = 0x100000000ULL;
    p11_object_fault();
    assert(instance_gen[0] == 0x100000000ULL && instance_counters_live.faults == 1);
    /* An exhausted CAS budget refuses the same way. */
    reset(); object_setup();
    instance_gen[0] = 5;
    cas_interference_cell = &instance_gen[0];
    cas_failures_remaining = 8;
    p11_object_fault();
    assert(cas_attempts == 8 && instance_gen[0] == 5);
    assert(instance_counters_live.faults == 1);
    puts("object custody missing side state passed");
}
static void object_producer_cleanup_result_reaches_exec_exit_fault(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    /* Healthy fast paths: zero-outstanding, absent or idle owner. */
    reset(); object_setup();
    assert(!p11_owner_cleanup() && !ctl.poison);
    reset(); object_setup();
    ctl.outstanding = 1;
    assert(!p11_owner_cleanup() && ctl.outstanding == 1 && !ctl.poison);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_owner_start_remove(&key, 1));
    assert(idle(0) && !ctl.outstanding);
    assert(!p11_owner_cleanup() && !ctl.poison);
    /* Ordinary, object and mixed teardown settles abandoning live STARTs. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&key, value));
    assert(row(&START, &key) && owners[0].start_count == 1);
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(!row(&START, &key) && !ctl.outstanding && ctl.abandoned_start == 1);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(row(&START, &key) && owners[0].start_count == 1);
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && ctl.abandoned_start == 1 && !ctl.poison);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    {
        struct owner_discovery_key dkey = discovery_key(9, 1);
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(!p11_owner_start_insert(&key, value));
        assert(!p11_owner_discovery_insert(&dkey, value, 1));
        assert(row(&START, &key) && owners[0].start_count == 1);
        assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
        assert(!row(&OBJECT_START, &key) && !row(&START, &key));
        assert(!ctl.outstanding && ctl.abandoned_start == 1);
        assert(ctl.abandoned_discovery == 1 && !ctl.poison);
    }
    /* Task lookup and classifier failures report failure. */
    reset(); object_setup();
    ctl.outstanding = 1;
    fail_current_task = 1;
    assert(p11_owner_cleanup() == 1);
    assert(ctl.poison & OWNER_LOOKUP_UNKNOWN);
    reset(); object_setup();
    assert(p11_owner_lease());
    miss_get = 1;
    assert(p11_owner_cleanup() == 1);
    assert(ctl.poison & OWNER_CLASSIFIER_FAILED);
    /* Marker and side failures retire their START and report failure. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&key, value));
    memset(row(&START, &key)->value + 264, 0x6A, 1);
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &key) && !ctl.outstanding && ctl.abandoned_start == 1);
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!pair_delete(&OBJECT_START, &key));
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &key) && !ctl.outstanding && ctl.abandoned_start == 1);
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    /* Deletion failures keep their rows and report failure; a retry
     * converges. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&key, value));
    pair_delete_error = -16;
    assert(p11_owner_cleanup() == 1);
    assert(row(&START, &key) && ctl.outstanding == 1);
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    pair_delete_error = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &key) && !ctl.outstanding && ctl.abandoned_start == 1);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    fail_object_side_delete = -16;
    assert(p11_owner_cleanup() == 1);
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    assert(object_bytes_zeroed(row(&OBJECT_START, &key)->value));
    assert(ctl.outstanding == 1 && (ctl.poison & OWNER_STATE_DELETE_FAILED));
    fail_object_side_delete = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && ctl.abandoned_start == 1);
    /* Poison is never cleared and never masks settled rows: cleanup still
     * runs, keeps the failure result, and reports zero-outstanding poison
     * through the fast path too. */
    reset(); object_setup();
    ctl.poison = OWNER_CLASSIFIER_FAILED;
    assert(p11_owner_cleanup() == 1);
    assert(ctl.poison == OWNER_CLASSIFIER_FAILED);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    {
        struct owner_discovery_key dkey = discovery_key(9, 1);
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(!p11_owner_start_insert(&key, value));
        assert(!p11_owner_discovery_insert(&dkey, value, 1));
        ctl.poison = OWNER_CLASSIFIER_FAILED;
        assert(p11_owner_cleanup() == 1);
        assert(!row(&OBJECT_START, &key) && !row(&START, &key));
        assert(!ctl.outstanding && ctl.abandoned_start == 1);
        assert(ctl.abandoned_discovery == 1);
        assert(ctl.poison == OWNER_CLASSIFIER_FAILED);
    }
    /* A corrupt control or owner record reports failure. */
    reset(); object_setup();
    ctl.limit = 0;
    assert(p11_owner_cleanup() == 1);
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&key, value));
    owners[0].flags = 0xFF;
    assert(p11_owner_cleanup() == 1);
    assert(ctl.poison & OWNER_BAD_RECORD);
    /* Stop-with-held-calls native: a held object call carrying known
     * private side bytes is scrubbed by teardown cleanup; the pre-delete
     * snapshot proves those exact bytes were zeroed, not merely deleted. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    memset(row(&OBJECT_START, &key)->value + 32, 0xA5, 64);
    memset(row(&OBJECT_START, &key)->value + 96, 0x5A, 64);
    deleted_side_seen = 0;
    assert(row(&START, &key) && owners[0].start_count == 1);
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && ctl.abandoned_start == 1 && !ctl.poison);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    puts("object custody cleanup result passed");
}

static void object_producer_scrub_preserves_whole_side_and_neighbors(void)
{
    struct {
        u64 before[2];
        u64 words[54];
        u64 after[2];
    } guarded;
    memset(&guarded, 0xA5, sizeof(guarded));
    object_scrub_side(guarded.words);
    for (unsigned i = 0; i < 54; i++) assert(guarded.words[i] == 0);
    for (unsigned i = 0; i < 2; i++) {
        assert(guarded.before[i] == 0xA5A5A5A5A5A5A5A5ULL);
        assert(guarded.after[i] == 0xA5A5A5A5A5A5A5A5ULL);
    }
    for (int failure = 0; failure < 2; failure++) {
        struct owner_start_key key = { .slot = 7 };
        struct owner_start_key foreign;
        unsigned char poison[432];
        reset(); object_setup();
        assert(p11_owner_lease());
        key.pid_tgid = owners[0].original_pid_tgid;
        foreign = key;
        foreign.pid_tgid ^= 1ULL << 32;
        memset(poison, 0x5A, sizeof(poison));
        /* No START exists: a valid retained owner authorizes its orphan
         * sweep. Poison EVERY side byte without forging a live binding. */
        assert(!update(&OBJECT_START, &key, poison, 1));
        assert(!update(&OBJECT_START, &foreign, poison, 1));
        require_scrubbed_side_delete = 1;
        fail_object_side_delete = failure ? -16 : 0;
        assert(p11_owner_cleanup() == (u32)failure);
        assert(checked_side_deletes == 1);
        assert(row(&OBJECT_START, &foreign));
        assert(!memcmp(row(&OBJECT_START, &foreign)->value, poison, 432));
        if (failure) {
            assert(row(&OBJECT_START, &key));
            assert(object_bytes_zeroed(row(&OBJECT_START, &key)->value));
            assert(ctl.outstanding == 1 && !ctl.abandoned_start);
            assert(ctl.poison == OWNER_STATE_DELETE_FAILED);
            fail_object_side_delete = 0;
            assert(p11_owner_cleanup() == 1); /* Sticky poison, settled debt. */
            assert(checked_side_deletes == 2);
        }
        assert(!row(&OBJECT_START, &key));
        assert(!ctl.outstanding && ctl.abandoned_start == 1);
        assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
        assert(p11_owner_cleanup() == (u32)failure);
        assert(checked_side_deletes == (failure ? 2 : 1));
        assert(!memcmp(row(&OBJECT_START, &foreign)->value, poison, 432));
    }
    puts("object custody complete scrub passed");
}
/* H7-E2 root-refusal mirror: replicates the FIXED BPF return root object
 * arms (`p11_return_impl`) through the real native owner transactions:
 * every refusal arm attempts the checked removal before returning, image
 * refusal faults, the reserve arm faults exactly when its cleanup fails,
 * and the emission case retires through the real removal under each
 * per-stage (`fill/tail/find`, plus the trivially-true Get stage on the
 * non-Get rows used here) outcome. Models the object arm only:
 * callers guarantee a required object call with a live START, exactly
 * the state the root holds at the object-arm entry (ordinary calls leave
 * at the aggregate arm; the Rust pin keeps their accounting-only image
 * refusal). Calls production functions only. The emission cleanup
 * DECISION (attempt independence plus the submit/fault verdict) is the
 * shared production `emission_finalize`, executed by the Rust G03
 * decision test with the `emitted && remove()` mutant failing there;
 * this mirror applies the same verdict shape to assert real-removal end
 * states. The Rust wrapper pins the root arms plus the delegation call.
 * Returns 1 on emission, 0 on any refusal. */
static unsigned root_return_mirror(const struct owner_start_key *key, u32 descriptor, u32 layout,
                                   int image_ok, int reserve_ok, int fill_ok, int tail_ok,
                                   int find_ok)
{
    const struct object_start *ready = p11_object_side_get(key, descriptor, 1);
    if (!ready) {
        p11_owner_start_remove(key, 1);
        p11_object_fault();
        return 0;
    }
    const struct object_start *side = p11_object_side_get(key, descriptor, 0);
    int agree = side != NULL && side->descriptor_index == descriptor &&
        (!side->layout || side->layout == layout);
    if (!agree) {
        p11_owner_start_remove(key, 1);
        p11_object_fault();
        return 0;
    }
    if (!image_ok) {
        p11_owner_start_remove(key, 1);
        p11_object_fault();
        return 0;
    }
    if (!reserve_ok) {
        /* Production faults exactly when the reserve-path cleanup fails:
         * a settled retire is quiet loss, a failed retire is corruption. */
        if (p11_owner_start_remove(key, 1))
            p11_object_fault();
        return 0;
    }
    {
        /* Production chains the four emission stages (`filled && tailed
         * && emitted`) and evaluates the retirement independently of the
         * chain: a failed stage still retires owned state, and any
         * failure faults without a success claim. The fourth stage (Get
         * result establishment) succeeds trivially on every vector here
         * (all rows are non-Get actions), so the three staged inputs
         * below compute the exact chained verdict. */
        int emitted = fill_ok && tail_ok && find_ok;
        long retired = p11_owner_start_remove(key, 1);
        if (!emitted || retired) {
            p11_object_fault();
            return 0;
        }
    }
    return 1;
}
static void object_producer_return_refusals_retire_owned_state(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    /* Missing side row: retired, refunded, faulted, no success. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!pair_delete(&OBJECT_START, &key));
    assert(!root_return_mirror(&key, 23, 1, 1, 1, 1, 1, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && (ctl.poison & OWNER_OBJECT_MISMATCH));
    assert(instance_counters_live.faults == 1);
    /* Non-ready (entry) phase: same retirement. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(!root_return_mirror(&key, 23, 1, 1, 1, 1, 1, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && !ctl.poison);
    assert(instance_counters_live.faults == 1);
    /* Attached-descriptor mismatch: retired with a fault verdict. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    assert(!root_return_mirror(&key, 21, 1, 1, 1, 1, 1, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && instance_counters_live.faults == 1);
    /* Retained-ABI mismatch: retired with a fault verdict. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    row(&OBJECT_START, &key)->value[28] = 2;
    assert(!root_return_mirror(&key, 23, 1, 1, 1, 1, 1, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && instance_counters_live.faults == 1);
    /* Image refusal: retired with a fault, never silent. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    assert(!root_return_mirror(&key, 23, 1, 0, 1, 1, 1, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && instance_counters_live.faults == 1);
    /* Failed fill/emission, each stage independently: retired
     * independently of emission success, faulted, no success claim and
     * no later read surface. */
    for (unsigned stage = 0; stage < 3; stage++) {
        int fill_ok = stage != 0, tail_ok = stage != 1, find_ok = stage != 2;
        reset(); object_setup();
        key.pid_tgid = pid_tgid();
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(!p11_owner_start_insert(&key, value));
        row(&OBJECT_START, &key)->value[31] = 2;
        assert(!root_return_mirror(&key, 23, 1, 1, 1, fill_ok, tail_ok, find_ok));
        assert(!row(&OBJECT_START, &key) && !row(&START, &key));
        assert(!ctl.outstanding && instance_counters_live.faults == 1);
    }
    /* Successful emission with failing retirement: no success claim, a
     * fault, and both rows kept (the side already scrubbed) for retry;
     * clearing the error converges. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    fail_object_side_delete = -16;
    assert(!root_return_mirror(&key, 23, 1, 1, 1, 1, 1, 1));
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    assert(object_bytes_zeroed(row(&OBJECT_START, &key)->value));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(instance_counters_live.faults == 1);
    fail_object_side_delete = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && ctl.abandoned_start == 1);
    /* Ring-full twin: reserve failure retires with settled accounting and
     * no fault (loss, not corruption); no result read runs before it. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    assert(!root_return_mirror(&key, 23, 1, 1, 0, 1, 1, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && !ctl.poison && !instance_counters_live.faults);
    /* Reserve failure with failing cleanup: production faults (the retire
     * error is corruption, not quiet loss); rows and lease are kept for
     * retry and converge once the error clears. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    fail_object_side_delete = -16;
    assert(!root_return_mirror(&key, 23, 1, 1, 0, 1, 1, 1));
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(instance_counters_live.faults == 1);
    fail_object_side_delete = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && ctl.abandoned_start == 1);
    /* Healthy positive: one record, one retirement, no fault. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    row(&OBJECT_START, &key)->value[31] = 2;
    assert(root_return_mirror(&key, 23, 1, 1, 1, 1, 1, 1));
    assert(!row(&OBJECT_START, &key) && !row(&START, &key));
    assert(!ctl.outstanding && !ctl.poison && !instance_counters_live.faults);
    /* Unproved ownership never authorizes forced deletion (stale row
     * under a recycled PID): the refusal is attempted but production
     * keeps every row. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    current_index = 1;
    assert(!root_return_mirror(&key, 23, 1, 1, 1, 1, 1, 1));
    assert(row(&OBJECT_START, &key) && row(&START, &key));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(instance_counters_live.faults == 1);
    puts("object custody return refusals passed");
}
static void object_producer_alloc_readback_failure_preserves_cleanup_authority(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    /* Side NOEXIST succeeds, the following readback lookup fails:
     * explicit failure, no publication, no orphan row, lease settled.
     * The side initially contains OBJECT_ZERO bytes (binding writes run
     * after the lookup), so this is a custody gap, never observed secret
     * retention. A left-behind orphan would be permanent: rollback
     * already refunded the lease, so no later cleanup-with-work can reach
     * the orphan sweep for this key. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    fail_object_side_lookup_once = 1;
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(p11_owner_start_insert(&key, value));
    assert(!row(&START, &key));
    assert(!row(&OBJECT_START, &key));
    assert(!p11_object_side_get(&key, 23, 0));
    assert(!ctl.outstanding && idle(0));
    assert(ctl.poison & OWNER_OBJECT_MISMATCH);
    /* Fail-closed: a same-key successor is refused (nothing settles a
     * poisoned control), and repeated cleanup converges visibly. */
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(p11_owner_start_insert(&key, value));
    assert(!row(&START, &key) && !row(&OBJECT_START, &key));
    assert(p11_owner_cleanup() == 1 && p11_owner_cleanup() == 1);
    assert(!ctl.outstanding && (ctl.poison & OWNER_OBJECT_MISMATCH));
    /* The rollback deletes only this live transaction key: a foreign row
     * under another live owner survives with its lease intact. */
    reset(); object_setup();
    current_index = 1;
    {
        struct owner_start_key other = { .pid_tgid = pid_tgid(), .slot = 7 };
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(!p11_owner_start_insert(&other, value));
        current_index = 0;
        key.pid_tgid = pid_tgid();
        fail_object_side_lookup_once = 1;
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(p11_owner_start_insert(&key, value));
        assert(!row(&START, &key) && !row(&OBJECT_START, &key));
        assert(row(&START, &other) && row(&OBJECT_START, &other));
        assert(owners[1].start_count == 1 && ctl.outstanding == 1);
        assert(p11_owner_cleanup() == 1 && ctl.outstanding == 1);
        assert(row(&START, &other) && row(&OBJECT_START, &other));
    }
    /* Normal allocation and repeated-cleanup positives. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(drain_via_query(&key, 23, 1) == 1);
    assert(!p11_owner_cleanup() && !ctl.outstanding && !ctl.poison);
    assert(!p11_owner_cleanup());
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    assert(drain_via_query(&key, 23, 1) == 1);
    assert(!ctl.poison);
    puts("object custody alloc readback passed");
}
static void object_producer_orphan_delete_failure_keeps_cleanup_authority(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    /* The readback-miss orphan sweep itself fails: the insert still fails
     * explicitly and authorizes nothing, but START, its count and its
     * lease are KEPT so a later cleanup can still reach the orphan. The
     * old rollback deleted START and settled the lease here, stranding a
     * permanent zeroed row with no retry route. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    fail_object_side_lookup_once = 1;
    fail_object_side_delete = -16;
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(p11_owner_start_insert(&key, value));
    assert(row(&START, &key));
    assert(row(&OBJECT_START, &key));
    assert(object_bytes_zeroed(row(&OBJECT_START, &key)->value));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(!idle(0));
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    /* Kept rows authorize nothing: the zeroed side cannot bind, and the
     * poisoned control refuses successors. */
    assert(!p11_object_side_get(&key, 23, 0));
    assert(!p11_object_side_get(&key, 23, 1));
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(p11_owner_start_insert(&key, value));
    assert(row(&START, &key) && row(&OBJECT_START, &key));
    /* Repeated cleanup with the error still injected keeps both rows and
     * the lease for a later retry. */
    assert(p11_owner_cleanup() == 1);
    assert(row(&START, &key) && row(&OBJECT_START, &key));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1);
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    /* Clearing the injected error lets teardown cleanup retire both rows
     * and settle the lease; the poison stays visible (never cleared). */
    fail_object_side_delete = 0;
    deleted_side_seen = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &key) && !row(&OBJECT_START, &key));
    assert(!ctl.outstanding && idle(0));
    assert(ctl.abandoned_start == 1);
    assert(ctl.poison & OWNER_STATE_DELETE_FAILED);
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    /* Repeated attempts converge visibly: still failed, never refunded
     * twice, nothing resurrected. */
    assert(p11_owner_cleanup() == 1);
    assert(!ctl.outstanding && (ctl.poison & OWNER_STATE_DELETE_FAILED));
    assert(p11_owner_start_remove(&key, 1));
    assert(!ctl.outstanding);
    /* A sibling owner survives the failed key's whole arc with its rows
     * and lease intact, and keeps them after the failed key settles. */
    reset(); object_setup();
    current_index = 1;
    {
        struct owner_start_key other = { .pid_tgid = pid_tgid(), .slot = 7 };
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(!p11_owner_start_insert(&other, value));
        current_index = 0;
        key.pid_tgid = pid_tgid();
        fail_object_side_lookup_once = 1;
        fail_object_side_delete = -16;
        memset(value, 0, sizeof(value)); object_write_start(value, 24);
        assert(p11_owner_start_insert(&key, value));
        assert(row(&START, &key) && row(&OBJECT_START, &key));
        assert(row(&START, &other) && row(&OBJECT_START, &other));
        assert(owners[0].start_count == 1 && owners[1].start_count == 1);
        assert(ctl.outstanding == 2);
        fail_object_side_delete = 0;
        assert(p11_owner_cleanup() == 1);
        assert(!row(&START, &key) && !row(&OBJECT_START, &key));
        assert(row(&START, &other) && row(&OBJECT_START, &other));
        assert(owners[1].start_count == 1 && ctl.outstanding == 1);
        assert(p11_owner_cleanup() == 1);
        assert(row(&START, &other) && owners[1].start_count == 1);
        assert(ctl.outstanding == 1);
    }
    puts("object custody orphan delete failure passed");
}
static void object_producer_empty_lease_refund_failure_remains_visible(void)
{
    /* Reconciles the historical "empty-lease settle" shorthand from the
     * slice-D completion review: that note named no concrete defect. This
     * reproducer injects refund/control failure around release_empty and
     * proves the CURRENT behavior fail-closed (no defect reproduced; the
     * shorthand alone identifies none): rows retire, the failure stays
     * visible, no lease is refunded twice, and the sibling lease is
     * undamaged. Behavior pinned. */
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    struct owner_start_key other = { .pid_tgid = 0, .slot = 3 };
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    current_index = 1;
    other.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value));
    assert(!p11_owner_start_insert(&other, value));
    current_index = 0;
    /* The injection lands mid-transaction (see pair_delete): corrupting
     * the count any earlier would rightly refuse at entry validation
     * instead of reaching the refund line under test. */
    zero_outstanding_on_delete = 1;
    deleted_side_seen = 0;
    assert(p11_owner_start_remove(&key, 1));
    assert(!row(&START, &key) && !row(&OBJECT_START, &key));
    assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
    assert(idle(0));
    assert(ctl.poison & OWNER_REFUND_FAILED);
    assert(ctl.outstanding == 0);
    assert(row(&START, &other));
    assert(owners[1].flags == OWNER_LEASED && owners[1].start_count == 1);
    assert(p11_owner_cleanup() == 1);
    assert(ctl.outstanding == 0 && (ctl.poison & OWNER_REFUND_FAILED));
    assert(row(&START, &other) && owners[1].start_count == 1);
    assert(p11_owner_start_remove(&key, 1));
    assert(ctl.outstanding == 0 && (ctl.poison & OWNER_REFUND_FAILED));
    /* The poisoned control refuses the healthy sibling too: designed
     * fail-closed (its accounting is intact, only service is refused). */
    assert(p11_owner_start_remove(&other, 1));
    assert(row(&START, &other));
    assert(owners[1].flags == OWNER_LEASED && owners[1].start_count == 1);
    assert(ctl.outstanding == 0);
    puts("object custody empty refund passed");
}
static void object_owner_sweep_adjacent_lookup_preserves_custody(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    /* An orphaned side row hidden from the teardown sweep by a lookup miss
     * is preserved intact, never deleted blindly: a NULL lookup is
     * indistinguishable from absence, so the sweep cannot fault on it. In
     * production the kernel lookup never spuriously misses; this pins the
     * injected boundary. Later live work on the same owner sweeps the
     * orphan exactly once with exact accounting. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    memset(value, 0, sizeof(value)); object_write_start(value, 24);
    assert(!p11_owner_start_insert(&key, value));
    memset(row(&OBJECT_START, &key)->value + 32, 0xA5, 64);
    assert(!pair_delete(&START, &key));
    owners[0].start_count--;
    hide_side_slot = 7;
    deleted_side_seen = 0;
    assert(!p11_owner_cleanup());
    assert(row(&OBJECT_START, &key));
    assert(!deleted_side_seen);
    assert(!ctl.outstanding && idle(0) && !ctl.poison);
    {
        unsigned char expect[64];
        memset(expect, 0xA5, sizeof(expect));
        assert(!memcmp(row(&OBJECT_START, &key)->value + 32, expect, sizeof(expect)));
    }
    hide_side_slot = -1;
    {
        struct owner_start_key live = { .pid_tgid = pid_tgid(), .slot = 5 };
        memset(value, 0, sizeof(value));
        assert(!p11_owner_start_insert(&live, value));
        deleted_side_seen = 0;
        assert(row(&START, &live) && owners[0].start_count == 1);
        assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
        assert(!row(&OBJECT_START, &key) && !row(&START, &live));
        assert(deleted_side_seen && object_bytes_zeroed(deleted_side));
        assert(ctl.abandoned_start == 2);
        assert(!ctl.outstanding && !ctl.poison);
    }
    puts("object custody sweep adjacent passed");
}

static void object_producer_cleanup_idle_returns_zero(void)
{
    struct owner_start_key key = { .pid_tgid = 0, .slot = 7 };
    /* Idle owner with no live START settles exactly zero. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    assert(!ctl.outstanding && owners[0].start_count == 0);
    assert(!row(&START, &key));
    assert(p11_owner_cleanup() == 0);
    assert(!ctl.outstanding && !ctl.poison && ctl.abandoned_start == 0);
    assert(p11_owner_cleanup() == 0);
    assert(ctl.abandoned_start == 0);
    /* Discovery-only abandonment still settles zero: only live STARTs report 2. */
    reset(); object_setup();
    key.pid_tgid = pid_tgid();
    {
        struct owner_discovery_key dkey = discovery_key(9, 1);
        memset(value, 0, sizeof(value));
        assert(!p11_owner_discovery_insert(&dkey, value, 1));
        assert(owners[0].start_count == 0 && !row(&START, &key));
        assert(ctl.outstanding == 1);
        assert(p11_owner_cleanup() == 0);
        assert(!ctl.outstanding && !ctl.poison);
        assert(ctl.abandoned_start == 0 && ctl.abandoned_discovery == 1);
    }
    puts("object custody idle cleanup passed");
}
#endif
#ifdef P11SCOPE_HOST_OWNER_LOOP
static void counter_bank_owner_high_slot(void)
{
    reset(); object_setup();
    struct owner_start_key high = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
    struct owner_start_key outside = start_key(P11SCOPE_OWNER_SLOT_BOUND);
    assert(p11_owner_start_aggregate(&high, 17) == 1);
    assert(p11_owner_start_get(&high, 1));
    struct thread_owner before = owners[0];
    assert(!p11_owner_start_aggregate(&outside, 19));
    assert(!row(&START, &outside));
    assert(!memcmp(&before, &owners[0], sizeof(before)));
    assert(ctl.outstanding == 1 && !ctl.poison);
    assert(row(&START, &high) && owners[0].start_count == 1);
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(bank_loop_calls == 2 && !row(&START, &high));
    assert(ctl.abandoned_start == 1 && !ctl.outstanding && idle(0));
    assert(owners[0].start_count == 0);
    assert(!p11_owner_cleanup());
    assert(bank_loop_calls == 2 && ctl.abandoned_start == 1);
}

static void counter_bank_owner_start_failures(void)
{
    struct owner_start_key high;
    reset(); object_setup(); high = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
    assert(p11_owner_start_aggregate(&high, 17) == 1);
    fail_start_delete = -16;
    assert(p11_owner_cleanup() == 1);
    /* The failure occurs at the last callback: a full helper count alone
     * cannot distinguish successful completion from explicit callback failure. */
    assert(bank_loop_calls == 1 && row(&START, &high));
    assert(owners[0].start_count == 1 && ctl.outstanding == 1 && ctl.poison);
    assert(!ctl.abandoned_start);
    fail_start_delete = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &high) && !ctl.outstanding && idle(0));
    assert(ctl.abandoned_start == 1 && ctl.poison);

    reset(); object_setup(); high = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
    assert(p11_owner_start_aggregate(&high, 17) == 1);
    bank_hide_start_slot = P11SCOPE_OWNER_SLOT_BOUND - 1;
    assert(p11_owner_cleanup() == 1);
    assert(bank_loop_calls == 1 && row(&START, &high));
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].start_count == 1);
    assert(!ctl.abandoned_start);

    reset(); object_setup(); high = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
    assert(p11_owner_start_aggregate(&high, 17) == 1);
    owners[0].start_count = 2;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&START, &high) && ctl.abandoned_start == 1);
    assert(ctl.poison && ctl.outstanding == 1 && owners[0].start_count == 1);
}

static struct owner_start_key counter_bank_owner_orphan(void)
{
    reset(); object_setup();
    struct owner_start_key high = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
    assert(p11_owner_start_aggregate(&high, 17) == 1);
    assert(!pair_delete(&START, &high));
    owners[0].start_count--;
    unsigned char side[432];
    memset(side, 0xA5, sizeof(side));
    assert(!update(&OBJECT_START, &high, side, 1));
    struct owner_start_key foreign = high;
    foreign.pid_tgid = current_number[1];
    assert(!update(&OBJECT_START, &foreign, side, 1));
    require_scrubbed_side_delete = 1;
    return high;
}

static void counter_bank_owner_orphan_failures(void)
{
    struct owner_start_key high = counter_bank_owner_orphan();
    struct owner_start_key foreign = high;
    foreign.pid_tgid = current_number[1];
    assert(!p11_owner_cleanup());
    assert(bank_loop_calls == 2 && !row(&OBJECT_START, &high));
    assert(deleted_side_seen && checked_side_deletes == 1);
    assert(object_bytes_zeroed(deleted_side));
    assert(!ctl.outstanding && !ctl.poison && ctl.abandoned_start == 1);
    assert(row(&OBJECT_START, &foreign));
    for (unsigned i = 0; i < 432; i++)
        assert(row(&OBJECT_START, &foreign)->value[i] == 0xA5);

    high = counter_bank_owner_orphan();
    fail_object_side_delete = -16;
    assert(p11_owner_cleanup() == 1);
    assert(bank_loop_calls == 2 && row(&OBJECT_START, &high));
    assert(object_bytes_zeroed(row(&OBJECT_START, &high)->value));
    assert(checked_side_deletes == 1 && ctl.poison && ctl.outstanding == 1);
    assert(!owners[0].start_count && !ctl.abandoned_start && !idle(0));
    fail_object_side_delete = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!row(&OBJECT_START, &high) && !ctl.outstanding);
    assert(ctl.poison && ctl.abandoned_start == 1 && idle(0));
}

static void counter_bank_owner_incomplete_loops(void)
{
    for (unsigned phase = 1; phase <= 2; phase++) {
        for (unsigned short_result = 0; short_result <= 1; short_result++) {
            struct owner_start_key high;
            if (phase == 1) {
                reset(); object_setup(); high = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
                assert(p11_owner_start_aggregate(&high, 17) == 1);
            } else {
                high = counter_bank_owner_orphan();
            }
            if (short_result) bank_loop_short_on = phase;
            else bank_loop_error_on = phase;
            assert(p11_owner_cleanup() == 1);
            assert(bank_loop_calls == phase && ctl.poison && ctl.outstanding == 1);
            assert(owners[0].flags && owners[0].original_pid_tgid && !idle(0));
            assert(!ctl.abandoned_start);
            if (phase == 1) {
                assert(owners[0].start_count == 1 && row(&START, &high));
            } else {
                /* Even count 0 cannot authorize release after an uncompleted
                 * orphan sweep. The last side remains intact and owned. */
                assert(!owners[0].start_count && row(&OBJECT_START, &high));
                for (unsigned i = 0; i < 432; i++)
                    assert(row(&OBJECT_START, &high)->value[i] == 0xA5);
            }
        }
    }
    /* The first sweep may remove every START before it reports a short
     * result. A count of zero cannot then hide the still-owned high orphan
     * or release its physical-task lease before the second sweep. */
    reset(); object_setup();
    struct owner_start_key low = start_key(0);
    struct owner_start_key high = start_key(P11SCOPE_OWNER_SLOT_BOUND - 1);
    unsigned char side[432];
    memset(side, 0xA5, sizeof(side));
    assert(p11_owner_start_aggregate(&low, 17) == 1);
    assert(!update(&OBJECT_START, &high, side, 1));
    bank_loop_short_on = 1;
    assert(p11_owner_cleanup() == 1);
    assert(bank_loop_calls == 1 && !row(&START, &low));
    assert(!owners[0].start_count && owners[0].flags);
    assert(owners[0].original_pid_tgid == pid_tgid() && ctl.outstanding == 1);
    assert(ctl.poison && ctl.abandoned_start == 1);
    assert(row(&OBJECT_START, &high));
    for (unsigned i = 0; i < 432; i++)
        assert(row(&OBJECT_START, &high)->value[i] == 0xA5);

    /* A short orphan sweep can remove every observed row and still fail to
     * prove the full bound. Retain the lease until a later complete sweep. */
    reset(); object_setup();
    low = start_key(0);
    assert(p11_owner_start_aggregate(&low, 17) == 1);
    assert(!pair_delete(&START, &low));
    owners[0].start_count--;
    assert(!update(&OBJECT_START, &low, side, 1));
    require_scrubbed_side_delete = 1;
    bank_loop_short_on = 2;
    assert(p11_owner_cleanup() == 1);
    assert(bank_loop_calls == 2 && !row(&OBJECT_START, &low));
    assert(!owners[0].start_count && owners[0].flags && !idle(0));
    assert(ctl.outstanding == 1 && ctl.poison && ctl.abandoned_start == 1);
    bank_loop_short_on = 0;
    assert(p11_owner_cleanup() == 1);
    assert(!ctl.outstanding && idle(0) && ctl.abandoned_start == 1);
    assert(p11_owner_cleanup() == 1 && ctl.abandoned_start == 1);
}

#if P11SCOPE_OWNER_SLOT_BOUND == 2112U
static void wide_owner_full_bound(void)
{
    reset(); object_setup();
    memset(value, 0, sizeof(value));
    object_write_start(value, 24);
    for (u32 slot = 0; slot < 2112; slot++) {
        struct owner_start_key key = start_key(slot);
        assert(!p11_owner_start_insert(&key, value));
    }
    assert(owners[0].start_count == 2112 && ctl.outstanding == 1);
    require_scrubbed_side_delete = 1;
    /* A de-threaded exec still retires keys under the retained original ID. */
    current_number[0]++;
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(bank_loop_calls == 2 && checked_side_deletes == 2112);
    assert(ctl.abandoned_start == 2112 && !ctl.poison && !ctl.outstanding && idle(0));
    for (u32 slot = 0; slot < 2112; slot++) {
        struct owner_start_key key = { .pid_tgid = (42ULL << 32) | 100, .slot = slot };
        assert(!row(&START, &key) && !row(&OBJECT_START, &key));
    }
}
#endif

#ifdef P11SCOPE_BANK_TIMING_SUITES
/* Publishes one live route for `slot` under `transaction`, with its commit
 * and live inner. Mirrors every check the timing route() performs. */
static void bank_publish_route(u32 slot, u64 transaction, u32 first, u32 end)
{
    u32 bank = slot >> 9, cell = slot & 511;
    struct bank_route meta = {
        .transaction = transaction, .first = first, .end = end,
        .bank = bank, .cell = cell, .inner_id = 1, .reserved_zero = 0,
    };
    struct bank_commit commit = { .first = first, .end = end, .configuration = BANK_CONFIG };
    assert(first < end && end <= 8192);
    assert(slot >= first && slot < end);
    assert(!update(&COUNTER_BANK_META, &slot, &meta, 1));
    assert(!update(&COUNTER_BANK_COMMIT, &transaction, &commit, 1));
    bank_inners[bank].live = 1;
}

static struct bank_inner_value *bank_cell(u32 slot)
{
    return (struct bank_inner_value *)&bank_inners[slot >> 9].cells[slot & 511];
}

/* Saturating add of a delta, mirroring counter_policy::add_counter_with. */
static void bank_timing_add_saturates(void)
{
    reset();
    u64 cell = ~0ULL - 1;
    assert(bank_add(&cell, 2) == BANK_SATURATED && cell == ~0ULL);
    assert(bank_add(&cell, 0) == BANK_ADDED && cell == ~0ULL);
    assert(bank_add(&cell, 1) == BANK_SATURATED && cell == ~0ULL);
    assert(!cas_attempts);
    cell = 10;
    assert(bank_add(&cell, 5) == BANK_ADDED && cell == 15);
    /* Eight attempts, then contention: seven losses still succeed. */
    cell = 100;
    cas_interference_cell = &cell;
    cas_failures_remaining = 7;
    assert(bank_add(&cell, 4) == BANK_ADDED && cell == 105);
    assert(cas_attempts == 8);
    /* Eight losses exhaust the bound and report contention distinctly. */
    cell = 100;
    cas_failures_remaining = 8;
    assert(bank_add(&cell, 4) == BANK_CONTENDED);
    assert(cas_attempts == 16);
    /* A contended add never applies its delta: only the interferer wrote. */
    assert(cell == 100 && cell != 104);
}

/* Exact maximum with eight attempts and contention, mirroring
 * counter_policy::max_counter_with. */
static void bank_timing_max_exact_eight_and_contention(void)
{
    reset();
    u64 cell = 10;
    assert(bank_max(&cell, 25) == BANK_MAX_RAISED && cell == 25);
    assert(!cas_attempts);
    /* Covered candidates never write, even under armed interference. */
    cas_interference_cell = &cell;
    cas_failures_remaining = ~0U;
    assert(bank_max(&cell, 25) == BANK_MAX_KEPT);
    assert(bank_max(&cell, 9) == BANK_MAX_KEPT);
    assert(cell == 25 && !cas_attempts);
    /* Seven losses still raise on the eighth attempt. */
    cas_failures_remaining = 7;
    assert(bank_max(&cell, 40) == BANK_MAX_RAISED && cell == 40);
    assert(cas_attempts == 8);
    /* Eight losses exhaust the bound; the cell keeps its old maximum. */
    cell = 25;
    cas_failures_remaining = 8;
    assert(bank_max(&cell, 40) == BANK_MAX_CONTENDED);
    assert(cas_attempts == 16);
    assert(cell == 25 && cell != 40);
    /* A concurrent raise observed mid-retry is kept with no second CAS. */
    cell = 10;
    cas_failures_remaining = 1;
    assert(bank_max(&cell, 11) == BANK_MAX_KEPT);
    assert(cell == 11 && cas_attempts == 17);
}

/* The return path reads the entry timestamp BEFORE removing START. */
static void bank_timing_ts_before_remove(void)
{
    reset(); object_setup();
    scrub_start_on_delete = 1;
    bank_publish_route(7, 1, 0, 512);
    assert(!p11_bank_enter_timed(7, pid_tgid(), 1000));
    struct owner_start_key key = start_key(7);
    assert(p11_owner_start_get(&key, 1));
    assert(bank_cell(7)->entered == 1);
    assert(!p11_bank_complete_timed(7, pid_tgid(), 0, 1, 2500));
    assert(!p11_owner_start_get(&key, 0));
    assert(bank_cell(7)->returned == 1);
    assert(bank_cell(7)->errors == 0);
    assert(bank_cell(7)->total_ns == 1500);
    assert(bank_cell(7)->max_ns == 1500);
#ifdef P11SCOPE_BANK_MODE_LATENCY
    assert(bank_cell(7)->buckets[bank_bucket(1500)] == 1);
    for (unsigned b = 0; b < 32; b++)
        if (b != bank_bucket(1500))
            assert(bank_cell(7)->buckets[b] == 0);
#endif
    assert(bank_fault_cell == 0);
    assert(!bank_health_cells[0] && !bank_health_cells[1]);
    struct bank_rv_key rv = { .slot = 7, .pad = 0, .rv = 0 };
    u64 *rv_cell = lookup(&RV_COUNTS, &rv);
    assert(rv_cell && *rv_cell == 1);
    /* A backward clock saturates the delta instead of wrapping. */
    assert(!p11_bank_enter_timed(7, pid_tgid(), 5000));
    assert(!p11_bank_complete_timed(7, pid_tgid(), 0x204, 1, 1000));
    assert(bank_cell(7)->returned == 2);
    assert(bank_cell(7)->errors == 0);
    assert(bank_cell(7)->total_ns == 1500);
    assert(bank_cell(7)->max_ns == 1500);
#ifdef P11SCOPE_BANK_MODE_LATENCY
    assert(bank_cell(7)->buckets[0] == 1);
#endif
    /* Absence is not settlement: nothing is accounted or faulted. */
    assert(!p11_bank_complete_timed(7, pid_tgid(), 0, 1, 9999));
    assert(bank_cell(7)->returned == 2);
    assert(bank_fault_cell == 0);
    /* An unscouted return retires START and faults scope, uncounted. */
    assert(!p11_bank_enter_timed(7, pid_tgid(), 100));
    assert(bank_cell(7)->entered == 3);
    assert(!p11_bank_complete_timed(7, pid_tgid(), 0, 0, 200));
    assert(!p11_owner_start_get(&key, 0));
    assert(bank_cell(7)->returned == 2);
    assert(bank_fault_cell == BANK_SCOPE_FAULT);
    assert(!bank_health_cells[0] && !bank_health_cells[1]);
    /* Bank-1 geometry: extent 512..1024 routes slot 513 to bank 1, cell 1. */
    reset(); object_setup();
    scrub_start_on_delete = 1;
    bank_publish_route(513, 2, 512, 1024);
    assert(!p11_bank_enter_timed(513, pid_tgid(), 2000));
    key = start_key(513);
    assert(p11_owner_start_get(&key, 1));
    assert(bank_cell(513)->entered == 1);
    assert(!p11_bank_complete_timed(513, pid_tgid(), 0, 1, 3500));
    assert(!p11_owner_start_get(&key, 0));
    assert(bank_cell(513)->returned == 1);
    assert(bank_cell(513)->errors == 0);
    assert(bank_cell(513)->total_ns == 1500);
    assert(bank_cell(513)->max_ns == 1500);
    assert(bank_fault_cell == 0);
    assert(!bank_health_cells[0] && !bank_health_cells[1]);
    /* Full-bound extent: 7680..8192 routes slot 8191 to bank 15, cell 511.
     * The extent end touches 8192 exactly, so a route that rejects
     * end == 8192 fails here. */
    reset(); object_setup();
    scrub_start_on_delete = 1;
    bank_publish_route(8191, 3, 7680, 8192);
    assert(!p11_bank_enter_timed(8191, pid_tgid(), 2000));
    key = start_key(8191);
    assert(p11_owner_start_get(&key, 1));
    assert(bank_cell(8191)->entered == 1);
    assert(!p11_bank_complete_timed(8191, pid_tgid(), 0, 1, 3500));
    assert(!p11_owner_start_get(&key, 0));
    assert(bank_cell(8191)->returned == 1);
    assert(bank_cell(8191)->errors == 0);
    assert(bank_cell(8191)->total_ns == 1500);
    assert(bank_cell(8191)->max_ns == 1500);
    assert(bank_fault_cell == 0);
    assert(!bank_health_cells[0] && !bank_health_cells[1]);
}

/* The entry root accounts entry only: no bucket writes (latency buckets
 * stay untouched; timestamps mode has no buckets). */
static void bank_timing_enter_writes_no_buckets(void)
{
    reset(); object_setup();
    bank_publish_route(7, 1, 0, 512);
    assert(!p11_bank_enter_timed(7, pid_tgid(), 1000));
    assert(bank_cell(7)->entered == 1);
    assert(bank_cell(7)->returned == 0);
    assert(bank_cell(7)->total_ns == 0);
    assert(bank_cell(7)->max_ns == 0);
#ifdef P11SCOPE_BANK_MODE_LATENCY
    for (unsigned b = 0; b < 32; b++)
        assert(bank_cell(7)->buckets[b] == 0);
#endif
    assert(bank_fault_cell == 0);
}

/* The entry root stores the clock value it was given. */
static void bank_timing_enter_stores_clock(void)
{
    reset(); object_setup();
    bank_publish_route(7, 1, 0, 512);
    assert(!p11_bank_enter_timed(7, pid_tgid(), 424242));
    struct owner_start_key key = start_key(7);
    unsigned char *row = p11_owner_start_get(&key, 1);
    assert(row);
    assert(*(u64 *)(row + OBJECT_CALL_START_TS_OFF) == 424242);
}
#endif
#endif
#ifdef P11SCOPE_INVENTORY_ONLY
static void inventory_contract(void)
{
    reset();
    struct owner_discovery_key key = discovery_key(7, 1);
    /* Numeric capacity is tested through admission, not only a macro. */
    ctl.outstanding = 64;
    assert(p11_owner_discovery_insert(&key, value, 1));
    assert(!creates && ctl.outstanding == 64 && ctl.admission_failures == 1);
    ctl.outstanding = 63;
    assert(!p11_owner_discovery_insert(&key, value, 1));
    assert(ctl.outstanding == 64);
    assert(!p11_owner_discovery_remove(&key, 1));
    assert(ctl.outstanding == 63);

    for (unsigned operation = 0; operation < 4; operation++) {
        reset();
        assert(!p11_owner_discovery_insert(&key, value, 1));
        owners[0].start_count = 1;
        if (operation == 0) assert(!p11_owner_discovery_get(&key, 1));
        else if (operation == 1) assert(p11_owner_discovery_insert(&key, value, 2));
        else if (operation == 2) assert(p11_owner_discovery_remove(&key, 1));
        else p11_owner_cleanup();
        assert((ctl.poison & OWNER_BAD_RECORD) && ctl.outstanding == 1);
        assert(row(&DISCOVERY_STATE, &key) && !ctl.abandoned_start);
    }
    reset();
    assert(!p11_owner_discovery_insert(&key, value, 1));
    ctl.poison = OWNER_CLASSIFIER_FAILED;
    assert(!p11_owner_discovery_get(&key, 1));
    p11_owner_cleanup();
    assert(ctl.poison && !ctl.outstanding && ctl.abandoned_discovery == 1);
    assert(!ctl.abandoned_start);
}
int main(void)
{
    cas_boundaries(); accounting_contention(); threaded_contention(); idle_owner_retention();
    lease_boundary(); classifier(); inventory_contract(); directory(); discovery_foreign_owner();
    puts("task-owner inventory: real discovery capacity, transactions, poison and cleanup passed");
}
#else
#ifdef P11SCOPE_OBJECT_JOURNAL
static void journal_removal_hook(void)
{
    struct owner_start_key key = { .pid_tgid = (42ULL << 32) | 100, .slot = 5 };
    reset();
    assert(!p11_owner_start_insert(&key, value));
    owners[0].journal_thread = 7;
    assert(!p11_owner_start_remove(&key, 1));
    assert(journal_settle_calls == 1 && journal_settle_reason == 0);
    assert(journal_finish_calls == 1 && journal_finish_committed == 1);
    assert(journal_settle_key.pid_tgid == key.pid_tgid && journal_settle_key.slot == key.slot);
    assert(!row(&START, &key) && !ctl.outstanding);
    for (u32 reason = 1; reason <= 9; reason++) {
        reset();
        assert(!p11_owner_start_insert(&key, value));
        owners[0].journal_thread = 7;
        assert(!p11_owner_start_remove_reason(&key, 1, reason));
        assert(journal_settle_calls == 1 && journal_settle_reason == reason);
        assert(journal_finish_calls == 1 && journal_finish_committed == 1);
        assert(!row(&START, &key) && !ctl.outstanding);
    }
    reset();
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_owner_start_remove(&key, 1));
    assert(!journal_settle_calls && !journal_finish_calls);
    reset();
    assert(!p11_owner_start_insert(&key, value));
    owners[0].journal_thread = 7;
    assert(p11_owner_start_insert(&key, value));
    assert(journal_settle_calls == 1 && journal_settle_reason == 1);
    assert(journal_finish_calls == 1 && journal_finish_committed == 1);
    reset();
    assert(!p11_owner_start_insert(&key, value));
    owners[0].journal_thread = 7;
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(journal_settle_calls == 1 && journal_settle_reason == 6);
    assert(journal_finish_calls == 1 && journal_finish_committed == 1);
    reset();
    assert(!p11_owner_start_insert(&key, value));
    owners[0].journal_thread = 7;
    journal_prepare_state = JOURNAL_SETTLE_BLOCKED;
    assert(p11_owner_start_remove(&key, 1));
    assert(row(&START, &key) && ctl.outstanding == 1 && !journal_finish_calls);
    journal_prepare_state = JOURNAL_SETTLE_SILENT;
    assert(!p11_owner_start_remove(&key, 1));
    assert(journal_settle_calls == 2 && journal_finish_calls == 1);
    reset();
    assert(!p11_owner_start_insert(&key, value));
    owners[0].journal_thread = 7;
    fail_start_delete = 1;
    assert(p11_owner_start_remove(&key, 1));
    assert(journal_finish_calls == 1 && journal_finish_committed == 0);
    assert(row(&START, &key) && ctl.outstanding == 1);
}
#endif
/* 6.05 step 1(d): the journal lifetime words are minted once, never
 * recycled, and preserved across idle and exec/exit cleanup while lease
 * state clears; no non-journal leaf mints them. Drives the production
 * task_owner.c insert/remove/cleanup bodies. */
static void journal_custody_never_reused(void)
{
    /* Non-inventory region only (inventory-only objects carry no journal
     * words; that absence is pinned by the ABI static asserts in
     * task_owner.h). */
    struct owner_start_key key = { .pid_tgid = (42ULL << 32) | 100, .slot = 7, .pad = 0 };
    reset();
    /* A full call cycle mints nothing: custody stays unminted (zero)
     * without the journal producer. */
    assert(!p11_owner_start_insert(&key, value));
    assert(!p11_owner_start_remove(&key, 1));
    assert(!owners[0].journal_thread && !owners[0].journal_sequence);
    assert(!owners[0].flags && !owners[0].original_pid_tgid);
    /* The one mint (modeled here: the producer mints once per retained
     * row; the mint itself belongs to object_journal, not this unit). */
    owners[0].journal_thread = 7;
    owners[0].journal_sequence = 3;
    /* Re-lease over minted custody: the stash path restores the minted
     * words instead of resetting them. */
    assert(!p11_owner_start_insert(&key, value));
    assert(owners[0].journal_thread == 7 && owners[0].journal_sequence == 3);
    assert(owners[0].flags == OWNER_LEASED && ctl.outstanding == 1);
    assert(!p11_owner_start_remove(&key, 1));
    assert(!owners[0].flags && !owners[0].original_pid_tgid && !owners[0].start_count);
    assert(!ctl.outstanding && !ctl.poison);
    assert(owners[0].journal_thread == 7 && owners[0].journal_sequence == 3);
    /* Exec/exit cleanup with a live START abandons the call but preserves
     * the lifetime words while the lease clears. */
    assert(!p11_owner_start_insert(&key, value));
    assert(p11_owner_cleanup() == P11_OWNER_CLEANUP_ABANDONED_START);
    assert(!ctl.poison && !ctl.outstanding);
    assert(owners[0].journal_thread == 7 && owners[0].journal_sequence == 3);
    assert(!owners[0].flags && !owners[0].original_pid_tgid && !owners[0].start_count);
    assert(ctl.abandoned_start == 1);
    /* Idle cleanup is a no-op that preserves custody too. */
    assert(!p11_owner_cleanup());
    assert(owners[0].journal_thread == 7 && owners[0].journal_sequence == 3);
    assert(!ctl.poison && !ctl.outstanding);
}
int main(int argc, char **argv)
{
    if (argc == 2) {
#ifdef P11SCOPE_OBJECT_JOURNAL
        if (!strcmp(argv[1], "journal_removal_hook")) { journal_removal_hook(); return 0; }
#endif
        if (!strcmp(argv[1], "classifier")) classifier();
        else if (!strcmp(argv[1], "transactions")) transactions();
        else if (!strcmp(argv[1], "directory")) directory();
        else if (!strcmp(argv[1], "lifecycle")) lifecycle();
        else if (!strcmp(argv[1], "poison")) poisoned_reads();
        else if (!strcmp(argv[1], "discovery-foreign")) discovery_foreign_owner();
        else if (!strcmp(argv[1], "capacity")) capacity_collision();
        else if (!strcmp(argv[1], "absence")) ordinary_absence();
        else if (!strcmp(argv[1], "cas")) cas_boundaries();
        else if (!strcmp(argv[1], "contention")) accounting_contention();
        else if (!strcmp(argv[1], "threads")) threaded_contention();
        else if (!strcmp(argv[1], "idle")) idle_owner_retention();
        else if (!strcmp(argv[1], "lease")) lease_boundary();
        else if (!strcmp(argv[1], "journal_custody_never_reused")) journal_custody_never_reused();
        else if (!strcmp(argv[1], "object_producer_owner_terminal_matrix")) object_producer_owner_terminal_matrix();
        else if (!strcmp(argv[1], "object_producer_side_state_n_and_n_plus_one")) object_producer_side_state_n_and_n_plus_one();
        else if (!strcmp(argv[1], "object_producer_missing_side_state_faults_before_return")) object_producer_missing_side_state_faults_before_return();
        else if (!strcmp(argv[1], "object_producer_cleanup_result_reaches_exec_exit_fault")) object_producer_cleanup_result_reaches_exec_exit_fault();
        else if (!strcmp(argv[1], "object_producer_scrub_preserves_whole_side_and_neighbors")) object_producer_scrub_preserves_whole_side_and_neighbors();
        else if (!strcmp(argv[1], "object_producer_return_refusals_retire_owned_state")) object_producer_return_refusals_retire_owned_state();
        else if (!strcmp(argv[1], "object_producer_alloc_readback_failure_preserves_cleanup_authority")) object_producer_alloc_readback_failure_preserves_cleanup_authority();
        else if (!strcmp(argv[1], "object_producer_orphan_delete_failure_keeps_cleanup_authority")) object_producer_orphan_delete_failure_keeps_cleanup_authority();
        else if (!strcmp(argv[1], "object_producer_empty_lease_refund_failure_remains_visible")) object_producer_empty_lease_refund_failure_remains_visible();
        else if (!strcmp(argv[1], "object_owner_sweep_adjacent_lookup_preserves_custody")) object_owner_sweep_adjacent_lookup_preserves_custody();
        else if (!strcmp(argv[1], "object_seeded_start_construction")) object_seeded_start_construction();
        else if (!strcmp(argv[1], "object_aggregate_start_construction")) object_aggregate_start_construction();
        else if (!strcmp(argv[1], "object_seeded_start_failures")) object_seeded_start_failures();
        else if (!strcmp(argv[1], "object_producer_cleanup_idle_returns_zero")) object_producer_cleanup_idle_returns_zero();
#ifdef P11SCOPE_HOST_OWNER_LOOP
        else if (!strcmp(argv[1], "counter_bank_owner_high_slot")) counter_bank_owner_high_slot();
        else if (!strcmp(argv[1], "counter_bank_owner_start_failures")) counter_bank_owner_start_failures();
        else if (!strcmp(argv[1], "counter_bank_owner_orphan_failures")) counter_bank_owner_orphan_failures();
        else if (!strcmp(argv[1], "counter_bank_owner_incomplete_loops")) counter_bank_owner_incomplete_loops();
#if P11SCOPE_OWNER_SLOT_BOUND == 2112U
        else if (!strcmp(argv[1], "wide_owner_full_bound")) wide_owner_full_bound();
#endif
#endif
#ifdef P11SCOPE_BANK_TIMING_SUITES
        else if (!strcmp(argv[1], "bank_timing_add_saturates")) bank_timing_add_saturates();
        else if (!strcmp(argv[1], "bank_timing_max_exact_eight_and_contention")) bank_timing_max_exact_eight_and_contention();
        else if (!strcmp(argv[1], "bank_timing_ts_before_remove")) bank_timing_ts_before_remove();
        else if (!strcmp(argv[1], "bank_timing_enter_writes_no_buckets")) bank_timing_enter_writes_no_buckets();
        else if (!strcmp(argv[1], "bank_timing_enter_stores_clock")) bank_timing_enter_stores_clock();
#endif
        else assert(0);
    } else {
        cas_boundaries(); accounting_contention(); threaded_contention(); idle_owner_retention();
        lease_boundary(); classifier(); transactions(); directory(); lifecycle(); poisoned_reads(); capacity_collision(); ordinary_absence(); discovery_foreign_owner();
        object_producer_owner_terminal_matrix(); object_producer_side_state_n_and_n_plus_one();
        object_producer_missing_side_state_faults_before_return(); object_producer_cleanup_result_reaches_exec_exit_fault();
        object_producer_scrub_preserves_whole_side_and_neighbors();
        object_producer_return_refusals_retire_owned_state(); object_producer_alloc_readback_failure_preserves_cleanup_authority();
        object_producer_orphan_delete_failure_keeps_cleanup_authority();
        object_producer_empty_lease_refund_failure_remains_visible(); object_owner_sweep_adjacent_lookup_preserves_custody();
        object_seeded_start_construction(); object_seeded_start_failures(); object_aggregate_start_construction();
        object_producer_cleanup_idle_returns_zero(); journal_custody_never_reused();
    }
    puts("task-owner: actual helper classifier, transactions, directory and lifecycle controls passed");
}

#endif
