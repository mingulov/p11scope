/* SPDX-License-Identifier: GPL-2.0-only */
/* T-L2c token-keyed loader gate (see loader_gate.h). The probe path is
 * serialized in-kernel: concurrent same-token and successor-generation
 * hits meet on the per-slot claim (generation CAS, then state CAS), so
 * exactly one winner counts each admission and each reclaim. A serial
 * floor per row (last_gen) refuses stale generations even on emptied
 * rows, so no userspace allocation order can resurrect a reclaimed
 * incarnation. Direct admit/retire/ack keep their strict sequential
 * contracts and fail closed on protocol faults; all counting cells
 * saturate through one bounded protocol that reports every unsettled
 * update instead of wrapping or losing silently. */
#include "loader_gate.h"

#ifdef GATE_HOST_CAS_HOOK
/* Host-only contention hook: while gate_cas_fail_all is set, every
 * saturating-counter CAS fails so the exhaustion twin can prove
 * settled updates still land through the fallback and every unsettled
 * update reports, never wraps or vanishes. Claim, reclaim, retire and
 * cutover CAS stay real; only counting-cell CAS routes through this
 * wrapper. Never defined for BPF. */
int gate_cas_fail_all = 0;
/* Host-only interleave hook: while gate_fallback_interleave_drop is set,
 * the retained-cell fallback simulates a reclaim landing between the
 * add and the re-read, so the interleave twin proves the re-read can
 * understate the peak. Single-threaded and deterministic; never defined
 * for BPF. */
int gate_fallback_interleave_drop = 0;
static __always_inline u64 gate_sat_cas(u64 *ptr, u64 old, u64 desired)
{
    if (gate_cas_fail_all)
        return old ^ 1;
    return __sync_val_compare_and_swap(ptr, old, desired);
}
#endif

/* Bounded accounting: 8 CAS tries settle every counting-cell update;
 * the fallback below tolerates fewer than 1024 in-flight same-cell
 * adds, which no host reaches for one cell in one race window. */
#define GATE_ACCOUNT_TRIES 8
#define GATE_SAT_HEADROOM 1024

#ifdef GATE_HOST_CAS_HOOK
#define GATE_SAT_CAS gate_sat_cas
#else
#define GATE_SAT_CAS(ptr, old, desired) __sync_val_compare_and_swap(ptr, old, desired)
#endif

/* Report a contention event the bounded protocol could not settle.
 * Saturates like every other cell; a report skipped within headroom
 * of the ceiling needs 2^64 prior contention events and stays
 * undisclosed beyond this comment. */
static __always_inline void gate_report_loss(struct loader_gate_control *ctl)
{
    u64 *losses = &ctl->update_losses;
    u64 old, seen = 0;
    int tries;

    for (tries = 0; tries < GATE_ACCOUNT_TRIES; tries++) {
        old = *(volatile u64 *)losses;
        seen = old;
        if (old == ~0ULL)
            return;
        if (GATE_SAT_CAS(losses, old, old + 1) == old)
            return;
    }
    if (seen < ~0ULL - GATE_SAT_HEADROOM)
        __sync_fetch_and_add(losses, 1);
}

/* Saturating increment. Returns 1 with the exact post-increment value
 * on the CAS-winner path; returns 2 with a re-read post-value on the
 * headroom-fallback path (BPF cannot use a fetch-add result at the
 * link CPU, so the fallback add settles silently and the value is
 * re-read: exact absent a concurrent drop, never above the true
 * maximum). Returns 0 with the saturated ceiling when the cell
 * already saturates or the near-ceiling update skips (the skip
 * reports through update_losses, never wraps, never vanishes). */
static __always_inline int gate_sat_inc(struct loader_gate_control *ctl, u64 *cell,
                                        u64 *out)
{
    u64 old, seen = 0;
    int tries;

    for (tries = 0; tries < GATE_ACCOUNT_TRIES; tries++) {
        old = *(volatile u64 *)cell;
        seen = old;
        if (old == ~0ULL) {
            *out = old;
            return 0;
        }
        if (GATE_SAT_CAS(cell, old, old + 1) == old) {
            *out = old + 1;
            return 1;
        }
    }
    /* Exhausted: every failure is another thread's success. With
     * headroom below the ceiling the single fallback add cannot reach
     * the maximum; within headroom of the ceiling skip and report.
     * The fallback result stays dead (BPF selects no fetch form at
     * the link CPU) and the post-value is re-read instead. */
    if (seen < ~0ULL - GATE_SAT_HEADROOM) {
        __sync_fetch_and_add(cell, 1);
#ifdef GATE_HOST_CAS_HOOK
        if (gate_fallback_interleave_drop && cell == &ctl->retained)
            __sync_fetch_and_sub(cell, 1);
#endif
        *out = *(volatile u64 *)cell;
        return 2;
    }
    gate_report_loss(ctl);
    *out = ~0ULL;
    return 0;
}

/* Counting-cell increment for callers that need no post-value. */
static __always_inline void gate_count(struct loader_gate_control *ctl, u64 *cell)
{
    u64 out = 0;

    gate_sat_inc(ctl, cell, &out);
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
        gate_count(ctl, &ctl->refusals);
        return -1;
    }
    return -2;
}

/* Raise the peak to at least newval, the post-increment live count
 * from the gauge add: carried exact on the CAS-winner path, re-read
 * on the headroom-fallback path. A concurrent reclaim cannot hide
 * the crossing on the CAS path because the raiser carries the value,
 * not a re-read; on the fallback path a reclaim landing between the
 * add and the re-read can understate the raise (never overstate it),
 * which the caller reports as a loss, and the peak still never falls. */
static __always_inline void gate_peak_raise(struct loader_gate_control *ctl, u64 newval)
{
    int tries;

    for (tries = 0; tries < GATE_ACCOUNT_TRIES; tries++) {
        u64 peak = *(volatile u64 *)&ctl->retained_peak;
        if (peak >= newval)
            return;
        if (GATE_SAT_CAS(&ctl->retained_peak, peak, newval) == peak)
            return;
    }
    gate_report_loss(ctl);
}

/* Retained add with peak tracking: the CAS-winner path carries the
 * exact post-value to the peak, while the headroom-fallback re-read
 * may understate under a concurrent reclaim, so the fallback reports
 * one loss to keep zero losses meaning exact. */
static __always_inline void gate_retained_add(struct loader_gate_control *ctl)
{
    u64 out = 0;
    int rc = gate_sat_inc(ctl, &ctl->retained, &out);

    if (!rc)
        return;
    if (rc == 2)
        gate_report_loss(ctl);
    gate_peak_raise(ctl, out);
}

static __always_inline void gate_retained_drop(struct loader_gate_control *ctl)
{
    int tries;

    for (tries = 0; tries < GATE_ACCOUNT_TRIES; tries++) {
        u64 live = *(volatile u64 *)&ctl->retained;
        if (live == 0)
            return;
        if (GATE_SAT_CAS(&ctl->retained, live, live - 1) == live)
            return;
    }
    gate_report_loss(ctl);
}

/* True when gen is strictly ahead of floor in u32 serial arithmetic:
 * (gen - floor) mod 2^32 in [1, 2^31). */
static __always_inline int gate_gen_ahead(u32 gen, u32 floor)
{
    u32 delta = gen - floor;

    return delta != 0 && delta < 0x80000000U;
}

/* Per-slot claim: refuse generations at or under the serial floor,
 * CAS generation 0->gen (the atomic admission decision), then CAS
 * state EMPTY->ARMED (spinning while an acknowledged reclaim stores
 * EMPTY). Returns 1 claimed, 0 lost (stale floor or a peer holding a
 * nonzero generation), -1 rolled back after spin exhaustion (reported,
 * the caller refuses). The floor stays inside the claim so resolving
 * hits on live rows never consult it: only admission does. */
static __always_inline int gate_claim_row(struct loader_gate_control *ctl,
                                          struct loader_gate_row *row, u64 gen)
{
    int tries;
    u32 last = *(volatile u32 *)&row->last_gen;

    if (last != 0 && !gate_gen_ahead((u32)gen, last))
        return 0;
    if (__sync_val_compare_and_swap(&row->generation, 0, gen) != 0)
        return 0;
    /* Four store-waits: the acknowledged reclaim stores EMPTY on a
     * straight line right after its own CAS, so the wait always
     * settles short of preemption. */
    for (tries = 0; tries < 4; tries++) {
        u64 state = *(volatile u64 *)&row->state;
        u64 check = *(volatile u64 *)&row->generation;
        if (check != gen)
            return -1;
        /* Value CAS on the 64-bit state: BPF selects cmpxchg only
         * at 64 bits. Only success matters here; like the
         * generation, reclaim and cutover CAS, this one stays real
         * under the counting-cell failure hook. */
        if (state == LOADER_GATE_EMPTY &&
            __sync_val_compare_and_swap(&row->state, LOADER_GATE_EMPTY,
                                        LOADER_GATE_ARMED) == LOADER_GATE_EMPTY)
            return 1;
    }
    /* Spin exhausted: roll the generation back so the row is claimable
     * again. A failed rollback means the generation already moved on
     * (nothing to roll back); either way the caller refuses. */
    __sync_val_compare_and_swap(&row->generation, gen, 0);
    gate_report_loss(ctl);
    return -1;
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
    if (!row)
        return gate_refuse(ctl);
    /* Only unclaimed rows admit: the claim winner arms, every loser
     * refuses, so no identity recycles before acknowledgement. */
    if (gate_claim_row(ctl, row, generation) != 1)
        return gate_refuse(ctl);
    row->disposition = LOADER_GATE_DISP_NONE;
    row->last_gen = (u32)generation;
    gate_count(ctl, &ctl->admitted);
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
    /* One winner retires: the loser meets a retired row and refuses,
     * matching the sequential double-retire verdict. Retired rows stay
     * charged until the acknowledged reclaim drops the gauge. The
     * 64-bit value CAS is the BPF-selectable spelling of the same
     * single-winner transition; it stays real under the
     * counting-cell failure hook. */
    if (__sync_val_compare_and_swap(&row->state, LOADER_GATE_ARMED,
                                    LOADER_GATE_RETIRED) != LOADER_GATE_ARMED)
        return gate_refuse(ctl);
    row->disposition = disposition;
    gate_count(ctl, &ctl->retired);
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
    u64 generation, gen, state;
    u32 last;

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
    generation = cookie >> 8;
    /* Strict first: malformed, wrong-state, wrong-generation and
     * corrupted-disposition cookies refuse counted, so only a
     * well-formed unarmed acknowledgement falls through to -2. A zero
     * generation under our own last mark means a peer already
     * reclaimed: success, uncounted, so concurrent reuse never
     * double-counts a reclaim (reclaim races are normal here, not
     * caller faults). */
    gen = *(volatile u64 *)&row->generation;
    state = *(volatile u64 *)&row->state;
    last = *(volatile u32 *)&row->last_gen;
    if (gen == 0)
        return last == (u32)generation ? 0 : gate_refuse(ctl);
    if (gen != generation)
        return (last == (u32)generation && state == LOADER_GATE_RETIRED)
                   ? 0
                   : gate_refuse(ctl);
    if (state != LOADER_GATE_RETIRED || row->disposition == LOADER_GATE_DISP_NONE)
        return gate_refuse(ctl);
    if (!row->acked)
        return -2;
    /* Pre-clear before the reclaim CAS so no same-generation ack can
     * validate on these words mid-reclaim; the stores are idempotent
     * across losing peers. The CAS below is the single linearization
     * point of the reclaim. */
    row->disposition = LOADER_GATE_DISP_NONE;
    row->acked = 0;
    if (__sync_val_compare_and_swap(&row->generation, generation, 0) != generation) {
        gen = *(volatile u64 *)&row->generation;
        state = *(volatile u64 *)&row->state;
        last = *(volatile u32 *)&row->last_gen;
        if (gen == 0)
            return last == (u32)generation ? 0 : gate_refuse(ctl);
        if (gen != generation)
            return (last == (u32)generation && state == LOADER_GATE_RETIRED)
                       ? 0
                       : gate_refuse(ctl);
        return gate_refuse(ctl);
    }
    row->state = LOADER_GATE_EMPTY;
    gate_count(ctl, &ctl->reclaims);
    gate_retained_drop(ctl);
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
    /* A zero generation on a retired row is the reclaim transient (the
     * CAS won, the EMPTY store is in flight): report it closed, never
     * hand out generation 0 as a capability. */
    if (row->generation == 0)
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

/* Loss-path spin: our generation holds the row but the state is not
 * ARMED yet (a peer claim still arming, or a stale read). Settles on
 * ARMED (peer admitted) or on our own stable retired row (pending);
 * anything else fails closed and reported. */
static __always_inline long gate_hit_spin(struct loader_gate_control *ctl,
                                          struct loader_gate_row *row, u32 slot,
                                          u64 gen)
{
    int tries;

    for (tries = 0; tries < 4; tries++) {
        u64 g = *(volatile u64 *)&row->generation;
        u64 st = *(volatile u64 *)&row->state;
        u32 last = *(volatile u32 *)&row->last_gen;
        if (g == gen && st == LOADER_GATE_ARMED)
            return (long)slot;
        if (g == gen && st == LOADER_GATE_RETIRED && last == (u32)gen)
            return -2;
        if (g != gen)
            break;
    }
    gate_report_loss(ctl);
    return gate_refuse(ctl);
}

/* Loss-path tail after a lost claim: single read, then at most one
 * spin or one reuse attempt (allow_reuse bounds the recursion: the
 * reuse retry never reuses again and refuses instead). */
static __always_inline long gate_hit_tail(struct loader_gate_control *ctl,
                                          struct loader_gate_row *row, u32 slot,
                                          u64 gen, int allow_reuse)
{
    u64 g = *(volatile u64 *)&row->generation;
    u64 st = *(volatile u64 *)&row->state;
    u32 last = *(volatile u32 *)&row->last_gen;
    u64 pred;
    long acked;

    if (g == gen && st == LOADER_GATE_ARMED)
        return (long)slot;
    if (g == gen && st == LOADER_GATE_RETIRED && last == (u32)gen)
        return -2;
    if (g == gen)
        return gate_hit_spin(ctl, row, slot, gen);
    if (g == 0 || st != LOADER_GATE_RETIRED || !allow_reuse)
        return gate_refuse(ctl);
    /* Foreign retired predecessor: reclaim it, then claim once. The
     * acknowledgement's own -1 is already counted; only propagate it. */
    pred = (g << 8) | slot;
    acked = p11_loader_gate_ack(pred);
    if (acked == -2)
        return -2;
    if (acked != 0)
        return -1;
    if (gate_claim_row(ctl, row, gen) == 1) {
        row->disposition = LOADER_GATE_DISP_NONE;
        row->last_gen = (u32)gen;
        gate_count(ctl, &ctl->admitted);
        gate_retained_add(ctl);
        return (long)slot;
    }
    return gate_hit_tail(ctl, row, slot, gen, 0);
}

__attribute__((noinline)) long p11_loader_gate_hit(u32 slot, u64 generation)
{
    struct loader_gate_control *ctl = gate_control();
    struct loader_gate_row *row;
    u32 key;

    if (!ctl)
        return -1;
    if (slot >= LOADER_GATE_SLOTS || !generation || generation > 0xffffffffULL)
        return gate_refuse(ctl);
    key = slot;
    row = loader_gate_map_lookup(&LOADER_GATE, &key);
    if (!row)
        return gate_refuse(ctl);
    if (gate_claim_row(ctl, row, generation) == 1) {
        row->disposition = LOADER_GATE_DISP_NONE;
        row->last_gen = (u32)generation;
        gate_count(ctl, &ctl->admitted);
        gate_retained_add(ctl);
        return (long)slot;
    }
    return gate_hit_tail(ctl, row, slot, generation, 1);
}
