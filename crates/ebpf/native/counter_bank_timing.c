/* SPDX-License-Identifier: GPL-2.0-only */
/* Format2 timing bank bridge: 16x512 cells, START16384/RV65536, one mode per
 * build selected by -DP11SCOPE_BANK_MODE_TIMESTAMPS or
 * -DP11SCOPE_BANK_MODE_LATENCY. Frozen twin of counter_bank_proof.c: that
 * file is byte-pinned by the C3 control, so the shared route/fault/RV shape
 * is duplicated here rather than refactored. Keep the two route bodies in
 * sync by inspection; the A2.4 production artifact set owns convergence.
 * The legacy per-slot aggregate map is separate and untouched by these
 * roots: this file must not name it (pinned by a host source test).
 * Map helpers arrive through task_owner.h (owner_map_*), so the host
 * harness wires bank maps through the same reset() seam as START. */
#if defined(P11SCOPE_BANK_MODE_TIMESTAMPS) && defined(P11SCOPE_BANK_MODE_LATENCY)
#error "exactly one bank timing mode must be selected"
#endif
#if !defined(P11SCOPE_BANK_MODE_TIMESTAMPS) && !defined(P11SCOPE_BANK_MODE_LATENCY)
#error "a bank timing mode (-DP11SCOPE_BANK_MODE_TIMESTAMPS or -DP11SCOPE_BANK_MODE_LATENCY) is required"
#endif
#include "task_owner.h"
#define INLINE inline __attribute__((always_inline))
#define UINT(name, value) int (*name)[value]
#define TYPE(name, value) typeof(value) *name
#define ARRAY(name, value) typeof(value) *name[]
#define READ_ONLY_PROG (1U << 7)
#define BANK_ROUTE_FAULT 1ULL
#define BANK_START_FAULT 2ULL
#define BANK_RV_FAULT 4ULL
#define BANK_SCOPE_FAULT 8ULL
/* Exact fixed layout/capacity binding, not a collection generation. One
 * word per mode; the reader pins the same three words. */
#ifdef P11SCOPE_BANK_MODE_LATENCY
#define BANK_CONFIG 0x0200012800100200ULL
#else
#define BANK_CONFIG 0x0200002800100200ULL
#endif
#ifdef P11SCOPE_BANK_MODE_LATENCY
_Static_assert(BANK_CONFIG == 0x0200012800100200ULL, "latency growth-v2 word");
#else
_Static_assert(BANK_CONFIG == 0x0200002800100200ULL, "timestamps growth-v2 word");
#endif
_Static_assert(P11SCOPE_OWNER_SLOT_BOUND == 8192U, "bank owner bound must match cleanup");
/* The return path reads the original entry timestamp at this offset BEFORE
 * removing START. Offset 0 is pinned against the shared seed layout, not
 * assumed. */
_Static_assert(OBJECT_CALL_START_TS_OFF == 0U, "entry timestamp leads CallStart");
_Static_assert(__builtin_offsetof(struct call_start_seed, ts_ns) == OBJECT_CALL_START_TS_OFF,
              "seed timestamp offset");

struct bank_inner_value {
    u64 entered;
    u64 returned;
    u64 errors;
    u64 total_ns;
    u64 max_ns;
#ifdef P11SCOPE_BANK_MODE_LATENCY
    u64 buckets[32];
#endif
};
struct bank_route {
    u64 transaction;
    u32 first, end, bank, cell, inner_id, reserved_zero;
};
struct bank_commit { u32 first, end; u64 configuration; };
struct bank_rv_key { u32 slot; u32 pad; u64 rv; };
#ifdef P11SCOPE_BANK_MODE_LATENCY
_Static_assert(sizeof(struct bank_inner_value) == 296, "latency ABI");
#else
_Static_assert(sizeof(struct bank_inner_value) == 40, "timestamps ABI");
#endif
_Static_assert(__builtin_offsetof(struct bank_inner_value, entered) == 0, "entered");
_Static_assert(__builtin_offsetof(struct bank_inner_value, returned) == 8, "returned");
_Static_assert(__builtin_offsetof(struct bank_inner_value, errors) == 16, "errors");
_Static_assert(__builtin_offsetof(struct bank_inner_value, total_ns) == 24, "total_ns");
_Static_assert(__builtin_offsetof(struct bank_inner_value, max_ns) == 32, "max_ns");
#ifdef P11SCOPE_BANK_MODE_LATENCY
_Static_assert(__builtin_offsetof(struct bank_inner_value, buckets) == 40, "buckets");
#endif
_Static_assert(sizeof(struct bank_route) == 32, "format2 route ABI");
_Static_assert(__builtin_offsetof(struct bank_route, transaction) == 0, "route transaction");
_Static_assert(__builtin_offsetof(struct bank_route, first) == 8, "route first");
_Static_assert(__builtin_offsetof(struct bank_route, end) == 12, "route end");
_Static_assert(__builtin_offsetof(struct bank_route, bank) == 16, "route bank");
_Static_assert(__builtin_offsetof(struct bank_route, cell) == 20, "route cell");
_Static_assert(__builtin_offsetof(struct bank_route, inner_id) == 24, "route inner ID");
_Static_assert(__builtin_offsetof(struct bank_route, reserved_zero) == 28, "route reserved");
_Static_assert(sizeof(struct bank_commit) == 16, "format2 commit ABI");
_Static_assert(__builtin_offsetof(struct bank_commit, first) == 0, "commit first");
_Static_assert(__builtin_offsetof(struct bank_commit, end) == 4, "commit end");
_Static_assert(__builtin_offsetof(struct bank_commit, configuration) == 8, "commit configuration");
_Static_assert(sizeof(struct bank_rv_key) == 16, "existing full-width RV key ABI");
_Static_assert(__builtin_offsetof(struct bank_rv_key, rv) == 8, "full-width RV position");

/* `values` is a zero-length pointer array describing the inner template;
 * no initialized entry publishes a bank or allocates a real bank. */
struct bank_inner_template {
    UINT(type, 6); /* PERCPU_ARRAY */
    UINT(max_entries, 512);
    TYPE(key, u32);
    TYPE(value, struct bank_inner_value);
};
struct {
    UINT(type, 13); /* HASH_OF_MAPS */
    UINT(max_entries, 16);
    UINT(map_flags, READ_ONLY_PROG);
    TYPE(key, u32);
    ARRAY(values, struct bank_inner_template);
} COUNTER_BANKS SEC(".maps");
struct {
    UINT(type, 1);
    UINT(max_entries, 8192);
    UINT(map_flags, READ_ONLY_PROG);
    TYPE(key, u32);
    TYPE(value, struct bank_route);
} COUNTER_BANK_META SEC(".maps");
struct {
    UINT(type, 1);
    UINT(max_entries, 8192);
    UINT(map_flags, READ_ONLY_PROG);
    TYPE(key, u64);
    TYPE(value, struct bank_commit);
} COUNTER_BANK_COMMIT SEC(".maps");
struct {
    UINT(type, 6);
    UINT(max_entries, 1);
    TYPE(key, u32);
    TYPE(value, u64);
} COUNTER_BANK_FAULT SEC(".maps");

extern unsigned char COUNTER_HEALTH;
extern unsigned char RV_COUNTS;
extern u32 p11_owner_start_aggregate(const struct owner_start_key *, u64);
extern void *p11_owner_start_get(const struct owner_start_key *, u32);
extern long p11_owner_start_remove(const struct owner_start_key *, u32);

static INLINE void fault(u64 reason)
{
    u32 zero = 0;
    u64 *cell = owner_map_lookup(&COUNTER_BANK_FAULT, &zero);
    if (cell)
        __sync_fetch_and_or(cell, reason);
}

static INLINE void unhealthy(u32 disposition)
{
    u64 *cell = owner_map_lookup(&COUNTER_HEALTH, &disposition);
    if (cell)
        *(volatile u64 *)cell = 1;
}

enum bank_add_update { BANK_ADDED = 0, BANK_SATURATED = 1, BANK_CONTENDED = 2 };
enum bank_max_update { BANK_MAX_RAISED = 0, BANK_MAX_KEPT = 1, BANK_MAX_CONTENDED = 2 };

/* The same bounded saturating-add policy as counter_policy::add_counter_with:
 * eight CAS attempts, no wrap, saturated and contended reported distinctly
 * so the caller can raise the matching sticky health cell. */
static INLINE u32 bank_add(u64 *cell, u64 delta)
{
#pragma unroll
    for (u32 attempt = 0; attempt < 8; attempt++) {
        u64 before = *(volatile u64 *)cell;
        u64 after = before + delta;
        if (after < before)
            after = ~0ULL;
        if (__sync_val_compare_and_swap(cell, before, after) == before)
            return delta > ~0ULL - before ? BANK_SATURATED : BANK_ADDED;
    }
    return BANK_CONTENDED;
}

/* The same bounded exact-maximum policy as counter_policy::max_counter_with:
 * no write when the cell already covers the candidate, eight CAS attempts,
 * contention reported distinctly. A maximum never saturates. */
static INLINE u32 bank_max(u64 *cell, u64 candidate)
{
#pragma unroll
    for (u32 attempt = 0; attempt < 8; attempt++) {
        u64 before = *(volatile u64 *)cell;
        if (candidate <= before)
            return BANK_MAX_KEPT;
        if (__sync_val_compare_and_swap(cell, before, candidate) == before)
            return BANK_MAX_RAISED;
    }
    return BANK_MAX_CONTENDED;
}

/* Saturating single increment over bank_add: eight CAS attempts, no wrap,
 * independent saturated/contended sticky cells. */
static INLINE void increment(u64 *cell)
{
    u32 update = bank_add(cell, 1);
    if (update == BANK_SATURATED)
        unhealthy(0);
    else if (update == BANK_CONTENDED)
        unhealthy(1);
}

/* Bucket index for a duration. Mirrors p11scope_ebpf_common::bucket_of: 0
 * maps to bucket 0, otherwise the 1-based bit length clamped into the
 * last bucket, so a pathologically long call is still counted. The
 * unrolled chain keeps every bound a constant; the explicit clamp before
 * indexing is what the object checker's single clamp/index proof reads. */
static INLINE u32 bank_bucket(u64 delta)
{
    u32 bucket;
    if (delta >= (1ULL << 31))
        bucket = 31;
    else if (delta >= (1ULL << 30))
        bucket = 31;
    else if (delta >= (1ULL << 29))
        bucket = 30;
    else if (delta >= (1ULL << 28))
        bucket = 29;
    else if (delta >= (1ULL << 27))
        bucket = 28;
    else if (delta >= (1ULL << 26))
        bucket = 27;
    else if (delta >= (1ULL << 25))
        bucket = 26;
    else if (delta >= (1ULL << 24))
        bucket = 25;
    else if (delta >= (1ULL << 23))
        bucket = 24;
    else if (delta >= (1ULL << 22))
        bucket = 23;
    else if (delta >= (1ULL << 21))
        bucket = 22;
    else if (delta >= (1ULL << 20))
        bucket = 21;
    else if (delta >= (1ULL << 19))
        bucket = 20;
    else if (delta >= (1ULL << 18))
        bucket = 19;
    else if (delta >= (1ULL << 17))
        bucket = 18;
    else if (delta >= (1ULL << 16))
        bucket = 17;
    else if (delta >= (1ULL << 15))
        bucket = 16;
    else if (delta >= (1ULL << 14))
        bucket = 15;
    else if (delta >= (1ULL << 13))
        bucket = 14;
    else if (delta >= (1ULL << 12))
        bucket = 13;
    else if (delta >= (1ULL << 11))
        bucket = 12;
    else if (delta >= (1ULL << 10))
        bucket = 11;
    else if (delta >= (1ULL << 9))
        bucket = 10;
    else if (delta >= (1ULL << 8))
        bucket = 9;
    else if (delta >= (1ULL << 7))
        bucket = 8;
    else if (delta >= (1ULL << 6))
        bucket = 7;
    else if (delta >= (1ULL << 5))
        bucket = 6;
    else if (delta >= (1ULL << 4))
        bucket = 5;
    else if (delta >= (1ULL << 3))
        bucket = 4;
    else if (delta >= (1ULL << 2))
        bucket = 3;
    else if (delta >= (1ULL << 1))
        bucket = 2;
    else if (delta >= (1ULL << 0))
        bucket = 1;
    else
        bucket = 0;
    if (bucket > 31)
        bucket = 31;
    return bucket;
}

/* Publication is append-only and immutable in the later owning controller.
 * Each route names its original transaction; there is no latest-txn gate.
 * A commit activates only its complete immutable logical extent. */
static INLINE struct bank_inner_value *route(u32 slot, u32 *inactive)
{
    *inactive = 0;
    if (slot >= 8192)
        return (void *)0;
    struct bank_route *meta = owner_map_lookup(&COUNTER_BANK_META, &slot);
    if (!meta) {
        *inactive = 1;
        return (void *)0;
    }
    u64 transaction = meta->transaction;
    u32 first = meta->first, end = meta->end;
    u32 bank = slot >> 9, cell = slot & 511;
    if (!transaction || !meta->inner_id || meta->reserved_zero || first >= end ||
        slot < first || slot >= end || end > 8192 ||
        meta->bank != bank || meta->cell != cell)
        return (void *)0;
    struct bank_commit *commit = owner_map_lookup(&COUNTER_BANK_COMMIT, &transaction);
    if (!commit) {
        *inactive = 1;
        return (void *)0;
    }
    if (commit->first != first || commit->end != end || commit->configuration != BANK_CONFIG)
        return (void *)0;
    void *inner = owner_map_lookup(&COUNTER_BANKS, &bank);
    if (!inner)
        return (void *)0;
    return owner_map_lookup(inner, &cell);
}

/* Scalar-only BTF boundary. Inactive staging never calls START. The
 * existing owner constructor supplies all admission/rollback debt. The
 * clock value arrives as `ts` from the Rust roots, which own the only
 * clock read; this file performs none. */
__attribute__((noinline)) u32 p11_bank_enter_timed(u32 slot, u64 pid_tgid, u64 ts)
{
    u32 inactive;
    struct bank_inner_value *stats = route(slot, &inactive);
    if (!stats) {
        if (!inactive)
            fault(BANK_ROUTE_FAULT);
        return 0;
    }
    increment(&stats->entered);
    struct owner_start_key key = { .pid_tgid = pid_tgid, .slot = slot, .pad = 0 };
    if (p11_owner_start_aggregate(&key, ts) != 1)
        fault(BANK_START_FAULT);
    return 0;
}

static INLINE void completed_rv(u32 slot, u64 rv)
{
    struct bank_rv_key key = { .slot = slot, .pad = 0, .rv = rv };
    u64 *cell = owner_map_lookup(&RV_COUNTS, &key);
    if (cell) {
        increment(cell);
        return;
    }
    u64 one = 1;
    if (!owner_map_update(&RV_COUNTS, &key, &one, 1)) /* BPF_NOEXIST */
        return;
    cell = owner_map_lookup(&RV_COUNTS, &key);
    if (cell)
        increment(cell);
    else
        fault(BANK_RV_FAULT);
}

__attribute__((noinline)) u32 p11_bank_complete_timed(u32 slot, u64 pid_tgid,
                                                     u64 rv, u32 account, u64 now)
{
    struct owner_start_key key = { .pid_tgid = pid_tgid, .slot = slot, .pad = 0 };
    unsigned char *start = p11_owner_start_get(&key, 0);
    /* Optional absence is not settlement: no remove/refund/counter/health
     * success certificate. A lost admitted START retains its owner debt,
     * which mandatory exec/exit cleanup detects without a false refund. */
    if (!start)
        return 0;
    /* The entry timestamp is read BEFORE removal; after removal the START
     * pointer is stale and its bytes are unusable. */
    u64 ts = *(u64 *)(start + OBJECT_CALL_START_TS_OFF);
    u64 marker = *(u64 *)(start + OBJECT_CALL_START_MARKER_OFF);
    u32 inactive;
    struct bank_inner_value *stats = route(key.slot, &inactive);
    /* Retire real custody before any routing poison. No START pointer is
     * used after removal or as routing authority. */
    if (p11_owner_start_remove(&key, 1)) {
        fault(BANK_START_FAULT);
        return 0;
    }
    if (!stats || marker) {
        fault(BANK_ROUTE_FAULT);
        return 0;
    }
    if (!account) {
        fault(BANK_SCOPE_FAULT);
        return 0;
    }
    increment(&stats->returned);
    if (rv != 0 && rv != 0x204)
        increment(&stats->errors);
    u64 delta = now >= ts ? now - ts : 0;
    u32 total_update = bank_add(&stats->total_ns, delta);
    if (total_update == BANK_SATURATED)
        unhealthy(0);
    else if (total_update == BANK_CONTENDED)
        unhealthy(1);
    if (bank_max(&stats->max_ns, delta) == BANK_MAX_CONTENDED)
        unhealthy(1);
#ifdef P11SCOPE_BANK_MODE_LATENCY
    {
        u32 bucket = bank_bucket(delta);
        increment(&stats->buckets[bucket]);
    }
#endif
    completed_rv(key.slot, rv);
    return 0;
}
