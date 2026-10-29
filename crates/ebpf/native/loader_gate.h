/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_LOADER_GATE_H
#define P11SCOPE_LOADER_GATE_H
/* T-L2c token-keyed loader gate: the BPF/native side of the cookie contract
 * pinned in src/discovery/loader_lifetime.rs (`loader_attach_cookie` is
 * exactly the 40-bit token bits). The gate admits one generation per slot,
 * resolves token cookies to slots, and retires rows with the owned
 * producer disposition (END / NO_END / ABANDON) derived from the
 * START-removal reason. Retired rows never re-admit: no token or map
 * identity recycles before acknowledgement (the ack entry point is a T-L3
 * seam, not this packet). Unknown cookies fail closed: untracked (-2)
 * before the cutover, counted refusals (-1) after it.
 *
 * The cutover is a one-way latch, not a format detector: an old-format
 * present cookie with a zero delta is numerically identical to the
 * generation-1 adapter token for the same case, so the atomic cutover is
 * only safe after every old-format producer has drained through an owned
 * disposition (proved by the twin harnesses, required by activation).
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
 * until the T-L3 acknowledgement empties the row. */
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

struct loader_gate_row {
    u64 generation;
    u32 state;
    u32 disposition;
};
/* Loader publishes limit=256, all other fields zero, before links, then
 * freezes userspace mutation. BPF alone mutates while linked; no reset. */
struct loader_gate_control {
    u64 limit;
    u64 cutover;
    u64 admitted;
    u64 refusals;
    u64 retired;
};
_Static_assert(sizeof(struct loader_gate_row) == 16, "gate row ABI");
_Static_assert(__builtin_offsetof(struct loader_gate_row, generation) == 0, "gate generation");
_Static_assert(__builtin_offsetof(struct loader_gate_row, state) == 8, "gate state");
_Static_assert(__builtin_offsetof(struct loader_gate_row, disposition) == 12, "gate disposition");
_Static_assert(sizeof(struct loader_gate_control) == 40, "gate control ABI");
_Static_assert(__builtin_offsetof(struct loader_gate_control, limit) == 0, "gate limit");
_Static_assert(__builtin_offsetof(struct loader_gate_control, cutover) == 8, "gate cutover");
_Static_assert(__builtin_offsetof(struct loader_gate_control, admitted) == 16, "gate admitted");
_Static_assert(__builtin_offsetof(struct loader_gate_control, refusals) == 24, "gate refusals");
_Static_assert(__builtin_offsetof(struct loader_gate_control, retired) == 32, "gate retired");

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
 * refusal (counted), -2 pre-cutover refusal (untracked). A row that is
 * not EMPTY never re-admits. */
long p11_loader_gate_admit(u32 slot, u64 generation);
/* Resolve a token cookie to its slot. Negative on every refusal. */
long p11_loader_gate_lookup(u64 cookie);
/* Record the owned producer disposition and retire the row. 0 retired,
 * negative on every refusal; the row is untouched unless 0 returns. */
long p11_loader_gate_note_producer_end(u64 cookie, u32 reason);
/* Latch the atomic cutover. 0 on the flip, -1 once already cut. */
long p11_loader_gate_cutover(void);
#endif
