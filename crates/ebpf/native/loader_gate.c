/* SPDX-License-Identifier: GPL-2.0-only */
/* T-L2c token-keyed loader gate (see loader_gate.h). Single-owner by
 * construction: only the attach path admits a slot, only the owning
 * producer reports its end, and only the native acknowledgement empties
 * a retired row once userspace arms reuse with the T-L3 flag. Same-slot
 * admit/retire transitions are
 * NOT atomic -- they are check-then-write sequences, so two concurrent
 * same-slot admits (or two concurrent retires) can both succeed. A
 * sequential double admission refuses, but that refusal is not a
 * concurrency primitive and must never be read as one. Concurrent
 * admissions of distinct slots touch disjoint rows and are safe.
 * Activation proof obligation (no production callers exist yet): the
 * activation call sites must prove at most one in-flight admit per slot
 * and at most one end-report per admitted row -- slot allocation
 * serialized through the registries, exactly one owning producer per
 * admitted row. Until that proof lands, concurrent same-slot use is a
 * caller protocol fault with an undefined gate outcome. */
#include "loader_gate.h"

/* Exact under contention: a non-fetch atomic add never loses an increment.
 * The result is never consumed, so it lowers to the non-fetch BPF atomic. */
static __always_inline void gate_count(u64 *cell)
{
    if (*(volatile u64 *)cell != ~0ULL)
        __sync_fetch_and_add(cell, 1);
}

static __always_inline struct loader_gate_control *gate_control(void)
{
    u32 key = 0;
    struct loader_gate_control *ctl = loader_gate_map_lookup(&LOADER_GATE_CTL, &key);
    if (!ctl)
        return (void *)0;
    if (ctl->limit != LOADER_GATE_SLOTS)
        return (void *)0;
    return ctl;
}

/* Strict refusal accounting: -1 and counted after the cutover, -2 and
 * untracked before it. */
static __always_inline long gate_refuse(struct loader_gate_control *ctl)
{
    if (*(volatile u64 *)&ctl->cutover) {
        gate_count(&ctl->refusals);
        return -1;
    }
    return -2;
}

/* Bounded gauge updates: 4 CAS tries keep concurrent admits and retires
 * from losing a live row without an unbounded retry loop. The peak only
 * ever moves up, so a lost race merely delays it. */
#define GATE_GAUGE_TRIES 4

static __always_inline void gate_retained_add(struct loader_gate_control *ctl)
{
    int i;
    u64 live, seen;

    gate_count(&ctl->retained);
    live = *(volatile u64 *)&ctl->retained;
    for (i = 0; i < GATE_GAUGE_TRIES; i++) {
        seen = *(volatile u64 *)&ctl->retained_peak;
        if (live <= seen)
            break;
        if (__sync_val_compare_and_swap(&ctl->retained_peak, seen, live) == seen)
            break;
    }
}

static __always_inline void gate_retained_drop(struct loader_gate_control *ctl)
{
    int i;
    u64 live;

    for (i = 0; i < GATE_GAUGE_TRIES; i++) {
        live = *(volatile u64 *)&ctl->retained;
        if (live == 0)
            break;
        if (__sync_val_compare_and_swap(&ctl->retained, live, live - 1) == live)
            break;
    }
}

/* Resolve the ARMED row for a token cookie. 0 with *row_out set on
 * success; a refusal otherwise. Stale, foreign, burned, malformed and
 * old-format cookies all land here. */
static __always_inline long gate_resolve(struct loader_gate_control *ctl, u64 cookie,
                                         struct loader_gate_row **row_out)
{
    u64 generation;
    u32 slot;
    struct loader_gate_row *row;

    if (!cookie || cookie > LOADER_GATE_TOKEN_MAX)
        return gate_refuse(ctl);
    generation = cookie >> 8;
    if (!generation)
        return gate_refuse(ctl);
    slot = (u32)(cookie & 0xff);
    row = loader_gate_map_lookup(&LOADER_GATE, &slot);
    if (!row || row->state != LOADER_GATE_ARMED || row->generation != generation)
        return gate_refuse(ctl);
    *row_out = row;
    return 0;
}

__attribute__((noinline)) long p11_loader_gate_admit(u32 slot, u64 generation)
{
    struct loader_gate_control *ctl = gate_control();
    struct loader_gate_row *row;
    u32 key;

    if (!ctl)
        return -1;
    /* Generation 0 is never issued and the token must fit 40 bits, so the
     * generation fits 32 bits. */
    if (slot >= LOADER_GATE_SLOTS || !generation || generation > 0xffffffffULL)
        return gate_refuse(ctl);
    key = slot;
    row = loader_gate_map_lookup(&LOADER_GATE, &key);
    /* Only EMPTY admits: sequential ARMED double-admits and RETIRED
     * re-admits refuse, so no identity recycles before acknowledgement.
     * Callers must still serialize same-slot admits (see above): this
     * check-then-write is not atomic under concurrency. */
    if (!row || row->state != LOADER_GATE_EMPTY)
        return gate_refuse(ctl);
    row->generation = generation;
    row->state = LOADER_GATE_ARMED;
    row->disposition = LOADER_GATE_DISP_NONE;
    gate_count(&ctl->admitted);
    gate_retained_add(ctl);
    return 0;
}

__attribute__((noinline)) long p11_loader_gate_lookup(u64 cookie)
{
    struct loader_gate_control *ctl = gate_control();
    struct loader_gate_row *row;
    long resolved;

    if (!ctl)
        return -1;
    /* gate_resolve already accounted the refusal; propagate it as-is. */
    resolved = gate_resolve(ctl, cookie, &row);
    if (resolved)
        return resolved;
    return (long)(cookie & 0xff);
}

__attribute__((noinline)) long p11_loader_gate_note_producer_end(u64 cookie, u32 reason)
{
    struct loader_gate_control *ctl = gate_control();
    struct loader_gate_row *row;
    u32 disposition;

    if (!ctl)
        return -1;
    disposition = p11_loader_gate_disposition_for_reason(reason);
    /* Unknown reasons never retire: the disposition is unowned. */
    if (!disposition)
        return gate_refuse(ctl);
    /* gate_resolve already accounted the refusal; propagate it as-is. */
    {
        long resolved = gate_resolve(ctl, cookie, &row);
        if (resolved)
            return resolved;
    }
    row->disposition = disposition;
    row->state = LOADER_GATE_RETIRED;
    gate_count(&ctl->retired);
    gate_retained_drop(ctl);
    return 0;
}

__attribute__((noinline)) long p11_loader_gate_cutover(void)
{
    struct loader_gate_control *ctl = gate_control();
    u64 observed;

    if (!ctl)
        return -1;
    observed = __sync_val_compare_and_swap(&ctl->cutover, 0, 1);
    return observed == 0 ? 0 : -1;
}

__attribute__((noinline)) long p11_loader_gate_ack(u64 cookie)
{
    struct loader_gate_control *ctl = gate_control();
    struct loader_gate_row *row;
    u32 slot;

    if (!ctl)
        return -1;
    if (!cookie || cookie > LOADER_GATE_TOKEN_MAX || (cookie >> 8) == 0)
        return gate_refuse(ctl);
    slot = (u32)(cookie & 0xff);
    if (slot >= LOADER_GATE_SLOTS)
        return gate_refuse(ctl);
    row = loader_gate_map_lookup(&LOADER_GATE, &slot);
    if (!row)
        return gate_refuse(ctl);
    /* Strict first: malformed, wrong-state, wrong-generation and
     * corrupted-disposition cookies refuse counted, so only a
     * well-formed unarmed acknowledgement falls through to -2. */
    if (row->state != LOADER_GATE_RETIRED || row->generation != (cookie >> 8) ||
        row->disposition == LOADER_GATE_DISP_NONE)
        return gate_refuse(ctl);
    if (!row->acked)
        return -2;
    row->generation = 0;
    row->state = LOADER_GATE_EMPTY;
    row->disposition = LOADER_GATE_DISP_NONE;
    row->acked = 0;
    gate_count(&ctl->reclaims);
    return 0;
}

__attribute__((noinline)) long p11_loader_gate_row_generation(u32 slot, u64 *generation_out)
{
    struct loader_gate_control *ctl = gate_control();
    struct loader_gate_row *row;
    u32 key;

    if (!ctl || !generation_out)
        return -1;
    if (slot >= LOADER_GATE_SLOTS)
        return -1;
    key = slot;
    row = loader_gate_map_lookup(&LOADER_GATE, &key);
    if (!row)
        return -1;
    if (row->state != LOADER_GATE_ARMED && row->state != LOADER_GATE_RETIRED)
        return -1;
    *generation_out = row->generation;
    return 0;
}

__attribute__((noinline)) long p11_loader_gate_cutover_latched(void)
{
    struct loader_gate_control *ctl = gate_control();

    if (!ctl)
        return -1;
    return *(volatile u64 *)&ctl->cutover ? 1 : 0;
}

#ifdef GATE_HOST_CAS_HOOK
/* Host-only contention hook: fail the next gate_cas_fail_budget
 * saturating-counter CAS attempts so the exhaustion twin can prove
 * every unsettled update is reported, never lost silently. Claim,
 * reclaim, retire and cutover CAS stay real; only counting-cell CAS
 * routes through this wrapper. Never defined for BPF. */
int gate_cas_fail_budget = 0;
static __always_inline u64 gate_sat_cas(u64 *ptr, u64 old, u64 desired)
{
    if (gate_cas_fail_budget > 0) {
        gate_cas_fail_budget--;
        return old ^ 1;
    }
    return __sync_val_compare_and_swap(ptr, old, desired);
}
#endif

/* INERT SCAFFOLD (test commit): always refuses. The probe-hit
 * transaction lands with the repair; the hit twins below fail against
 * this stub at their first behavioral needle. */
__attribute__((noinline)) long p11_loader_gate_hit(u32 slot, u64 generation)
{
    (void)slot;
    (void)generation;
    return -1;
}
