/* SPDX-License-Identifier: GPL-2.0-only */
/* T-L2c token-keyed loader gate (see loader_gate.h). Single-owner by
 * construction: only the attach path admits a slot, only the owning
 * producer reports its end, and only the T-L3 acknowledgement (not this
 * packet) empties a retired row. Same-slot admit/retire transitions are
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
