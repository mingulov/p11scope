/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_LOADER_GATE_H
#define P11SCOPE_LOADER_GATE_H
/* T-L2c token-keyed loader gate: the BPF/native side of the cookie contract
 * pinned in src/discovery/loader_lifetime.rs (`loader_attach_cookie` is
 * exactly the 40-bit token bits). The gate admits one generation per slot,
 * resolves token cookies to slots, retires rows with the owned
 * producer disposition (END / NO_END / ABANDON) derived from the
 * START-removal reason, and empties retired rows through the native
 * acknowledgement once userspace arms per-row reuse. Retired rows never
 * re-admit: no token or map identity recycles before acknowledgement.
 * Unknown cookies fail closed: untracked (-2) before the cutover,
 * counted refusals (-1) after it. An unacknowledged retired row answers
 * -2 (never counted) at any cutover state: the third -2, alongside the
 * absent no-op and the pre-cutover refusal.
 *
 * The cutover is a one-way latch, not a format detector: several
 * old-format cookies are numerically identical to live tokens, and no code
 * at this seam can tell the formats apart. Read as 40-bit tokens
 * `(generation << 8) | slot`, the full collision set is: every old-format
 * absent cookie is a generation-2 token for its case slot
 * (`(1<<9)|(c-1)` == `(2<<8)|(c-1)`); every old-format present cookie with
 * `0 <= delta < 2^31` is a generation-`2*delta+1` token for its case slot
 * (delta 0 / generation 1 is just the first of these); negative or
 * `>= 2^31` deltas overflow 40 bits and refuse. Even generations >= 4
 * have no old twin. The atomic cutover is therefore only safe after every
 * old-format producer has drained through an owned disposition (proved by
 * the twin harnesses, required by activation): under-scoping the drain
 * set to delta-0 producers strands live twins.
 *
 * Not yet compiled into any BPF object and not yet consulted by any
 * producer: activation wires the maps and call sites. Host harnesses
 * execute this unit with stub map storage. */

typedef unsigned int u32;
typedef unsigned long long u64;
#define __always_inline inline __attribute__((always_inline))

/* Loader storage slots. Must equal the production registry bound and the
 * model bound: reuse recycles storage, never identity. */
#define LOADER_GATE_SLOTS 256U
/* Tokens are nonzero 40-bit `(generation << 8) | slot` values. */
#define LOADER_GATE_TOKEN_MAX 0xffffffffffULL

/* Row states: EMPTY admits, ARMED resolves, RETIRED refuses everything
 * until the native acknowledgement consumes the T-L3 flag and empties
 * exactly that row for one successor generation. */
#define LOADER_GATE_EMPTY 0U
#define LOADER_GATE_ARMED 1U
#define LOADER_GATE_RETIRED 2U

/* Owned producer dispositions. NONE means no producer has ended. */
#define LOADER_GATE_DISP_NONE 0U
#define LOADER_GATE_DISP_END 1U
#define LOADER_GATE_DISP_NO_END 2U
#define LOADER_GATE_DISP_ABANDON 3U

/* START-removal reasons consumed from task_owner.h. That header is the
 * single source of truth: when it precedes this one, the literals below
 * static-assert against it; otherwise the pinned literals stand alone. */
#define P11_LOADER_START_REASON_RETURN 0U
#define P11_LOADER_START_REASON_COLLISION 1U
#define P11_LOADER_START_REASON_EXEC_EXIT 6U
#ifdef P11SCOPE_TASK_OWNER_H
_Static_assert(P11_OWNER_START_REASON_RETURN == P11_LOADER_START_REASON_RETURN,
               "gate RETURN reason must match task_owner.h");
_Static_assert(P11_OWNER_START_REASON_COLLISION == P11_LOADER_START_REASON_COLLISION,
               "gate COLLISION reason must match task_owner.h");
_Static_assert(P11_OWNER_START_REASON_EXEC_EXIT == P11_LOADER_START_REASON_EXEC_EXIT,
               "gate EXEC_EXIT reason must match task_owner.h");
#endif

/* Rows are BPF-owned except acked: userspace sets it once per retired
 * generation after its T-L3 acknowledgement completes, and the native
 * acknowledgement consumes (validates plus clears) it. Single-word and
 * write-once: a BPF read racing the set sees 0 (retry later) or 1
 * (proceed), both safe. The retired generation in the ack cookie is the
 * capability; the T-L3 completion ordering is the caller's proof.
 * last_gen is the serial floor: the newest generation admitted here (0
 * while no generation has ever retired, since generation 0 is never
 * issued). An empty row admits only a generation strictly ahead of the
 * floor in u32 serial arithmetic, so a stale hit can never resurrect
 * a reclaimed incarnation, including across the u32 wrap. */
struct loader_gate_row {
    u64 generation;
    /* 64-bit state: BPF selects cmpxchg only at 64 bits, and the
     * claim (EMPTY->ARMED) and retire (ARMED->RETIRED) transitions
     * each need exactly one compare-and-swap winner. */
    u64 state;
    u32 disposition;
    u32 acked;
    u32 last_gen;
};
/* Loader publishes limit=256, all other fields zero, before links, then
 * freezes userspace mutation. BPF alone mutates while linked; no reset.
 * The L4b loader cells are admitted (arms), reclaims, retained_peak and
 * refusals; retired stays an end-report diagnostic. All counting cells
 * saturate, never wrap. update_losses counts contention events the
 * bounded accounting protocol could not settle (a skipped near-ceiling
 * increment, a lost gauge drop, a lost peak raise): nonzero means the
 * gauges may over- or understate and must be read as bounds, never as
 * exact facts. Contention-free operation never increments it. */
struct loader_gate_control {
    u64 limit;
    u64 cutover;
    u64 admitted;
    u64 refusals;
    u64 retired;
    u64 reclaims;
    u64 retained;
    u64 retained_peak;
    u64 update_losses;
};
_Static_assert(sizeof(struct loader_gate_row) == 32, "gate row ABI");
_Static_assert(__builtin_offsetof(struct loader_gate_row, generation) == 0, "gate generation");
_Static_assert(__builtin_offsetof(struct loader_gate_row, state) == 8, "gate state");
_Static_assert(__builtin_offsetof(struct loader_gate_row, disposition) == 16, "gate disposition");
_Static_assert(__builtin_offsetof(struct loader_gate_row, acked) == 20, "gate acked");
_Static_assert(__builtin_offsetof(struct loader_gate_row, last_gen) == 24, "gate last generation");
_Static_assert(sizeof(struct loader_gate_control) == 72, "gate control ABI");
_Static_assert(__builtin_offsetof(struct loader_gate_control, limit) == 0, "gate limit");
_Static_assert(__builtin_offsetof(struct loader_gate_control, cutover) == 8, "gate cutover");
_Static_assert(__builtin_offsetof(struct loader_gate_control, admitted) == 16, "gate admitted");
_Static_assert(__builtin_offsetof(struct loader_gate_control, refusals) == 24, "gate refusals");
_Static_assert(__builtin_offsetof(struct loader_gate_control, retired) == 32, "gate retired");
_Static_assert(__builtin_offsetof(struct loader_gate_control, reclaims) == 40, "gate reclaims");
_Static_assert(__builtin_offsetof(struct loader_gate_control, retained) == 48, "gate retained");
_Static_assert(__builtin_offsetof(struct loader_gate_control, retained_peak) == 56, "gate peak");
_Static_assert(__builtin_offsetof(struct loader_gate_control, update_losses) == 64, "gate losses");

/* Future real Rust map symbols; only their addresses enter map helpers.
 * The Rust maps land with activation; until then the host harnesses
 * define these bytes and route lookups to stub storage. */
extern unsigned char LOADER_GATE;
extern unsigned char LOADER_GATE_CTL;

static void *(*loader_gate_map_lookup)(void *, const void *) = (void *)1;

/* Exact START-removal reason to owned-disposition mapping. Unknown
 * reasons map to NONE: the caller must refuse, never retire. */
static __always_inline u32 p11_loader_gate_disposition_for_reason(u32 reason)
{
    if (reason == P11_LOADER_START_REASON_RETURN)
        return LOADER_GATE_DISP_END;
    if (reason == P11_LOADER_START_REASON_COLLISION)
        return LOADER_GATE_DISP_NO_END;
    if (reason == P11_LOADER_START_REASON_EXEC_EXIT)
        return LOADER_GATE_DISP_ABANDON;
    return LOADER_GATE_DISP_NONE;
}

/* Arm one slot for a nonzero 32-bit generation. 0 armed, -1 strict
 * refusal (counted), -2 pre-cutover refusal (untracked). Sequentially, a
 * row that is not EMPTY never re-admits; concurrent same-slot admits are
 * a caller protocol fault (single-owner proof obligation, loader_gate.c). */
long p11_loader_gate_admit(u32 slot, u64 generation);
/* Resolve a token cookie to its slot. Negative on every refusal. */
long p11_loader_gate_lookup(u64 cookie);
/* Record the owned producer disposition and retire the row. 0 retired,
 * negative on every refusal; the row is untouched unless 0 returns. */
long p11_loader_gate_note_producer_end(u64 cookie, u32 reason);
/* Latch the atomic cutover. 0 on the flip, -1 once already cut. */
long p11_loader_gate_cutover(void);
/* Empty exactly the acknowledged RETIRED row for one successor
 * generation. 0 emptied (reclaims counts it); -2 when the row is
 * retired but userspace has not armed reuse yet (never counted, at any
 * cutover state); the strict refusal rule for malformed, foreign,
 * wrong-generation, wrong-state and corrupted-disposition cookies;
 * -1 on a missing or malformed control. The row is untouched unless
 * 0 returns. */
long p11_loader_gate_ack(u64 cookie);
/* Read one row's generation for the acknowledgement capability: 0 with
 * *generation_out set for an ARMED or RETIRED row, -1 for EMPTY, an
 * out-of-range slot, or a missing or malformed control. The BPF hit
 * path names the row's own generation back to the acknowledgement, so
 * the generation match stays a TOCTOU guard, never a guess. */
long p11_loader_gate_row_generation(u32 slot, u64 *generation_out);
/* Read the cutover latch for the producer's decode selection: 1 once
 * latched, 0 before, -1 on a missing or malformed control. The hit
 * path decodes old-format cookies before the latch and tokens after;
 * nothing admits before the latch. */
long p11_loader_gate_cutover_latched(void);
/* Probe-hit transaction: resolve-or-admit-or-reuse with exactly-once
 * accounting. Returns the slot (>= 0) when this hit resolves: freshly
 * admitted, admitted by a same-generation peer, or claimed after the
 * transaction reclaims a retired predecessor. Returns -2 when the slot
 * holds this generation retired but unarmed (acknowledgement-pending,
 * never counted, at any cutover state). Otherwise the strict refusal
 * rule applies (-1 counted after the cutover, -2 untracked before it):
 * malformed slot/generation, a stale generation under the floor, a
 * foreign live row and an ABA-recycled row all refuse. Concurrent
 * same-token and successor-generation hits serialize on the per-slot
 * claim; only one winner counts each admission and each reclaim, so
 * healthy and pending hits keep refusals at zero. */
long p11_loader_gate_hit(u32 slot, u64 generation);
#endif
