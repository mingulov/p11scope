/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_OBJECT_JOURNAL_H
#define P11SCOPE_OBJECT_JOURNAL_H

/* H8 slice-A inactive custody: the object journal's native side-map,
 * lifetime mint and ring-leaf skeleton. Inactive: no live root calls
 * any leaf below yet; the host fixture in
 * tests/fixtures/object-journal/ executes this exact code. Slice B
 * wires the entry/return/exit transactions; until then these leaves
 * prove ABI, layout and failure-closure only. Inventory-only objects
 * carry no journal maps, hooks or reads. */
#include "task_owner.h"

#ifndef P11SCOPE_INVENTORY_ONLY

/* Prototype lifetime ticket bound: capture-lifetime, never reset, never
 * refilled. Matches the consumer floor-table experiment, not START. */
#define JOURNAL_THREAD_LIMIT 16448ULL
/* Bounded mint retries: a lost CAS race retries a finite number of
 * times, then fails closed (the caller raises loss). */
#define JOURNAL_MINT_CAS_BOUND 8U
/* JOURNAL_START sizing: the same START limit in every object. */
#if defined(P11SCOPE_SMALL_STATE_MAPS)
#define JOURNAL_START_LIMIT 1U
#else
#define JOURNAL_START_LIMIT 16384U
#endif

/* Finite side-row phases. */
#define JOURNAL_PHASE_PREPARING 1U
#define JOURNAL_PHASE_BEGUN 2U
#define JOURNAL_PHASE_RETURNING 3U

static __always_inline int journal_phase_valid(u64 phase)
{
    return phase == JOURNAL_PHASE_PREPARING || phase == JOURNAL_PHASE_BEGUN ||
        phase == JOURNAL_PHASE_RETURNING;
}

/* Non-LRU side row keyed by the exact native call identity plus phase.
 * A phase advance is a delete plus an insert; the side row never moves
 * under its own key. */
struct journal_start_key {
    u64 thread;
    u64 sequence;
    u64 phase;
};

/* Side row value (16 B): the START slot this row shadows plus reserved
 * flags. Slice B fills transaction semantics; the ABI shape is frozen
 * here so map payload stays reviewable. */
struct journal_start_value {
    u64 slot;
    u64 flags;
};

struct journal_control {
    u64 next_thread;
    u64 poison;
    u64 admission_failures;
};

_Static_assert(sizeof(struct journal_start_key) == 24, "journal key ABI");
_Static_assert(sizeof(struct journal_start_value) == 16, "journal value ABI");
_Static_assert(sizeof(struct journal_control) == 24, "journal control ABI");
_Static_assert(__builtin_offsetof(struct journal_start_key, sequence) == 8, "journal seq");
_Static_assert(__builtin_offsetof(struct journal_start_key, phase) == 16, "journal phase");
_Static_assert(__builtin_offsetof(struct journal_start_value, flags) == 8, "journal vflags");
_Static_assert(JOURNAL_START_LIMIT == 16384U || JOURNAL_START_LIMIT == 1U, "journal limit");

/* Prototype wire header shared with object_journal.rs: exact
 * little-endian repr(C), zero padding, finite validators. Lengths are
 * the full record bytes; the ring adds its own 8 B header. */
#define JOURNAL_VERSION 1U
#define JOURNAL_KIND_BEGIN 1U
#define JOURNAL_KIND_END 2U
#define JOURNAL_KIND_ABANDON 3U
#define JOURNAL_BEGIN_BYTES 224U
#define JOURNAL_END_FULL_BYTES 632U
#define JOURNAL_END_COMPACT_BYTES 472U
#define JOURNAL_ABANDON_BYTES 64U
#define JOURNAL_COMMON_BYTES 24U
#define JOURNAL_FLAG_NO_END 1U
#define JOURNAL_FLAG_ABSENT_TAIL 2U

/* Whether one header describes an exact version/kind/length/flag
 * combination over a nonzero identity. Mirrors the Rust validators;
 * the fixture cross-checks every combination both sides accept. */
static __always_inline int journal_header_valid(u64 bytes, u64 kind, u64 flags, u64 reserved,
                                                u64 thread, u64 sequence)
{
    if (!thread || !sequence || reserved)
        return 0;
    switch (kind) {
    case JOURNAL_KIND_BEGIN:
        return bytes == JOURNAL_BEGIN_BYTES && (flags == 0 || flags == JOURNAL_FLAG_NO_END);
    case JOURNAL_KIND_END:
        return (bytes == JOURNAL_END_FULL_BYTES || bytes == JOURNAL_END_COMPACT_BYTES) &&
            (flags == 0 || flags == JOURNAL_FLAG_ABSENT_TAIL);
    case JOURNAL_KIND_ABANDON:
        return bytes == JOURNAL_ABANDON_BYTES && flags == 0;
    default:
        return 0;
    }
}

/* Ring helpers, same dual-use shape as the owner map helpers: real
 * helper IDs under BPF, stubbed by the host fixture. */
static void *(*journal_ring_reserve)(void *, u64, u64) = (void *)131;
static void (*journal_ring_submit)(void *, u64) = (void *)132;
static void (*journal_ring_discard)(void *, u64) = (void *)133;

/* Skeleton leaves. 0/-1 status; nonzero ticket/sequence on success, 0
 * on refusal (caller raises loss before provider execution or
 * discard). */
u64 p11_journal_mint_thread(struct journal_control *ctl);
u64 p11_journal_thread(struct thread_owner *owner, struct journal_control *ctl);
u64 p11_journal_next_sequence(struct thread_owner *owner);
int p11_journal_side_insert(void *map, const struct journal_start_key *key,
                            const struct journal_start_value *value);
void *p11_journal_side_lookup(void *map, const struct journal_start_key *key);
int p11_journal_side_remove(void *map, const struct journal_start_key *key);
int p11_journal_header_init(void *record, u64 bytes, u64 kind, u64 flags, u64 thread,
                            u64 sequence);
void *p11_journal_reserve(void *ring, u64 bytes);
void p11_journal_submit(void *record);
void p11_journal_discard(void *record);

#endif /* P11SCOPE_INVENTORY_ONLY */
#endif
