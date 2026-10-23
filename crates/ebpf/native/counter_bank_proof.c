/* SPDX-License-Identifier: GPL-2.0-only */
/* Unselected fixed two-bank Counts bridge. Logical IDs remain 0/1 inside
 * the existing native512/START16384/RV4096 universe. This does not grow a
 * hot RV map or authorize any Session attachment/public selector. */
typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
#define INLINE inline __attribute__((always_inline))
#define UINT(name, value) int (*name)[value]
#define TYPE(name, value) typeof(value) *name
#define ARRAY(name, value) typeof(value) *name[]
#define READ_ONLY_PROG (1U << 7)
#define BANK_ROUTE_FAULT 1ULL
#define BANK_START_FAULT 2ULL
#define BANK_RV_FAULT 4ULL
#define BANK_SCOPE_FAULT 8ULL
/* Exact fixed layout/capacity binding, not a collection generation. */
#define BANK_CONFIG 0x18000102ULL

struct bank_counts { u64 entered; u64 returned; u64 errors; };
struct bank_metadata { u64 transaction; u64 bank_mask; u32 logical_slot; u32 cells; };
struct bank_commit { u64 bank_mask; u64 configuration; };
struct owner_start_key { u64 pid_tgid; u32 slot; u32 pad; };
struct bank_rv_key { u32 slot; u32 pad; u64 rv; };
_Static_assert(sizeof(struct bank_counts) == 24, "Counts ABI");
_Static_assert(sizeof(struct bank_metadata) == 24, "immutable bank metadata ABI");
_Static_assert(sizeof(struct bank_commit) == 16, "exact-set commit ABI");
_Static_assert(sizeof(struct owner_start_key) == 16, "existing START key ABI");
_Static_assert(sizeof(struct bank_rv_key) == 16, "existing full-width RV key ABI");
_Static_assert(__builtin_offsetof(struct owner_start_key, slot) == 8, "START logical slot");
_Static_assert(__builtin_offsetof(struct owner_start_key, pad) == 12, "START zero padding");
_Static_assert(__builtin_offsetof(struct bank_rv_key, rv) == 8, "full-width RV position");

/* `values` is a zero-length pointer array describing the inner template;
 * no initialized entry publishes a bank or allocates an actual second bank. */
struct bank_inner_template {
    UINT(type, 6); /* PERCPU_ARRAY */
    UINT(max_entries, 1);
    TYPE(key, u32);
    TYPE(value, struct bank_counts);
};
struct {
    UINT(type, 13); /* HASH_OF_MAPS */
    UINT(max_entries, 2);
    UINT(map_flags, READ_ONLY_PROG);
    TYPE(key, u32);
    ARRAY(values, struct bank_inner_template);
} COUNTER_BANKS SEC(".maps");
struct {
    UINT(type, 1);
    UINT(max_entries, 2);
    UINT(map_flags, READ_ONLY_PROG);
    TYPE(key, u32);
    TYPE(value, struct bank_metadata);
} COUNTER_BANK_META SEC(".maps");
struct {
    UINT(type, 1);
    UINT(max_entries, 2);
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
static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;

static INLINE void fault(u64 reason)
{
    u32 zero = 0;
    u64 *cell = lookup(&COUNTER_BANK_FAULT, &zero);
    if (cell)
        __sync_fetch_and_or(cell, reason);
}

static INLINE void unhealthy(u32 disposition)
{
    u64 *cell = lookup(&COUNTER_HEALTH, &disposition);
    if (cell)
        *(volatile u64 *)cell = 1;
}

/* The same bounded saturating-one policy as counter_policy::add_counter_with:
 * eight CAS attempts, no wrap, independent saturated/contended sticky cells. */
static INLINE void increment(u64 *cell)
{
#pragma unroll
    for (u32 attempt = 0; attempt < 8; attempt++) {
        u64 before = *(volatile u64 *)cell;
        u64 after = before == ~0ULL ? before : before + 1;
        if (__sync_val_compare_and_swap(cell, before, after) == before) {
            if (before == ~0ULL)
                unhealthy(0);
            return;
        }
    }
    unhealthy(1);
}

/* Publication is append-only and immutable in the later owning controller.
 * Each bank names its own transaction; there is no latest-transaction gate.
 * The commit mask exactly names the staged subset of these two fixed banks. */
static INLINE struct bank_counts *route(u32 slot, u32 *inactive)
{
    *inactive = 0;
    if (slot >= 2)
        return (void *)0;
    struct bank_metadata *meta = lookup(&COUNTER_BANK_META, &slot);
    if (!meta) {
        *inactive = 1;
        return (void *)0;
    }
    u64 transaction = meta->transaction;
    u64 mask = meta->bank_mask;
    if (!transaction || !mask || (mask & ~3ULL) || !(mask & (1ULL << slot)) ||
        meta->logical_slot != slot || meta->cells != 1)
        return (void *)0;
    struct bank_commit *commit = lookup(&COUNTER_BANK_COMMIT, &transaction);
    if (!commit) {
        *inactive = 1;
        return (void *)0;
    }
    if (commit->bank_mask != mask || commit->configuration != BANK_CONFIG)
        return (void *)0;
    void *inner = lookup(&COUNTER_BANKS, &slot);
    if (!inner)
        return (void *)0;
    u32 zero = 0;
    return lookup(inner, &zero);
}

/* Scalar-only BTF boundary. Inactive staging never calls START or touches
 * STATS. The existing owner constructor supplies all admission/rollback debt. */
__attribute__((noinline)) u32 p11_bank_enter(u32 slot, u64 pid_tgid)
{
    u32 inactive;
    struct bank_counts *counts = route(slot, &inactive);
    if (!counts) {
        if (!inactive)
            fault(BANK_ROUTE_FAULT);
        return 0;
    }
    increment(&counts->entered);
    struct owner_start_key key = { .pid_tgid = pid_tgid, .slot = slot, .pad = 0 };
    if (p11_owner_start_aggregate(&key, 0) != 1)
        fault(BANK_START_FAULT);
    return 0;
}

static INLINE void completed_rv(u32 slot, u64 rv)
{
    struct bank_rv_key key = { .slot = slot, .pad = 0, .rv = rv };
    u64 *cell = lookup(&RV_COUNTS, &key);
    if (cell) {
        increment(cell);
        return;
    }
    u64 one = 1;
    if (!update(&RV_COUNTS, &key, &one, 1)) /* BPF_NOEXIST */
        return;
    cell = lookup(&RV_COUNTS, &key);
    if (cell)
        increment(cell);
    else
        fault(BANK_RV_FAULT);
}

__attribute__((noinline)) u32 p11_bank_complete(u32 slot, u64 pid_tgid,
                                               u64 rv, u32 account)
{
    struct owner_start_key key = { .pid_tgid = pid_tgid, .slot = slot, .pad = 0 };
    unsigned char *start = p11_owner_start_get(&key, 0);
    /* Optional absence is not settlement: no remove/refund/counter/health
     * success certificate. A lost admitted START retains its owner debt,
     * which mandatory exec/exit cleanup detects without a false refund. */
    if (!start)
        return 0;
    u64 marker = *(u64 *)(start + 264); /* existing CallStart.object_required */
    u32 inactive;
    struct bank_counts *counts = route(key.slot, &inactive);
    /* Retire real custody before any routing poison. No START pointer or
     * CallStart.slot_id is used after removal or as routing authority. */
    if (p11_owner_start_remove(&key, 1)) {
        fault(BANK_START_FAULT);
        return 0;
    }
    if (!counts || marker) {
        fault(BANK_ROUTE_FAULT);
        return 0;
    }
    if (!account) {
        fault(BANK_SCOPE_FAULT);
        return 0;
    }
    increment(&counts->returned);
    if (rv)
        increment(&counts->errors);
    completed_rv(key.slot, rv);
    return 0;
}
