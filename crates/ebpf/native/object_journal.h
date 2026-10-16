/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_OBJECT_JOURNAL_H
#define P11SCOPE_OBJECT_JOURNAL_H

/* H8 inactive custody: the object journal's native side-map,
 * lifetime mint, ring leaves and entry/return/exit transactions.
 * Inactive: no live root calls anything below yet; the host fixture
 * in tests/fixtures/object-journal/ executes this exact code.
 * Inventory-only objects carry no journal maps, hooks or reads. */
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

/* Non-LRU JOURNAL_START side map: the H8 plan StartKey-to-
 * identity/phase contract. Keyed by the existing 16 B START key
 * (pid_tgid plus slot); the 24 B value carries the call's journal
 * identity and finite phase. A phase advance updates the value under
 * its stable START key; the side row never moves. */
struct journal_start_value {
    u64 thread;
    u64 sequence;
    u64 phase;
};

struct journal_control {
    u64 next_thread;
    u64 poison;
    u64 admission_failures;
};

_Static_assert(sizeof(struct owner_start_key) == 16, "journal key ABI");
_Static_assert(sizeof(struct journal_start_value) == 24, "journal value ABI");
_Static_assert(sizeof(struct journal_control) == 24, "journal control ABI");
_Static_assert(__builtin_offsetof(struct journal_start_value, sequence) == 8, "journal seq");
_Static_assert(__builtin_offsetof(struct journal_start_value, phase) == 16, "journal phase");
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

/* Header-init words in one struct: a BPF subprogram takes at most
 * five scalar arguments, so the six header words cross as one
 * pointer. */
struct journal_header_spec {
    u64 bytes;
    u64 kind;
    u64 flags;
    u64 thread;
    u64 sequence;
};

_Static_assert(sizeof(struct journal_header_spec) == 40, "header spec ABI");

/* Leaves. 0/-1 status; nonzero ticket/sequence on success, 0 on
 * refusal (caller raises loss before provider execution or
 * discard). */
u64 p11_journal_mint_thread(struct journal_control *ctl);
u64 p11_journal_thread(struct thread_owner *owner, struct journal_control *ctl);
u64 p11_journal_next_sequence(struct thread_owner *owner);
int p11_journal_side_insert(void *map, const struct owner_start_key *key,
                            const struct journal_start_value *value);
void *p11_journal_side_lookup(void *map, const struct owner_start_key *key);
int p11_journal_side_remove(void *map, const struct owner_start_key *key);
int p11_journal_header_init(void *record, const struct journal_header_spec *spec);
void *p11_journal_reserve(void *ring, u64 bytes);
void p11_journal_submit(void *record);
void p11_journal_discard(void *record);

/* Inactive entry/return/exit journal legs over one physical owner's
 * side row. The combined transactions below call these beside the
 * START and OBJECT_START legs of the same owner transaction; every
 * failure returns to the root, which raises loss (transactions never
 * emit a fault call themselves, so cleanup stays a flat sequence).
 *
 * Entry validates the leased owner against the START key, mints the
 * call's thread/sequence words, and NOEXIST-inserts the PREPARING
 * row. A failed insert consumes the minted words (tickets never
 * recycle) and reports -1 before provider execution. Mark-begun
 * commits the row to BEGUN once its BEGIN is valid; return advances
 * an exactly-matching BEGUN row to RETURNING; removal deletes the
 * settled row. Thread/sequence arguments are the caller's retained
 * BEGIN facts, never the owner's live words (which already advanced
 * past this call): a later equal numeric key never joins. Removal
 * takes the frozen per-slot policy's required bit: a missing
 * required row is loss (-1), a missing optional row is healthy
 * absence (-2). */
int p11_journal_entry(struct thread_owner *owner, struct journal_control *ctl, void *map,
                      const struct owner_start_key *key);
int p11_journal_mark_begun(void *map, const struct owner_start_key *key, u64 thread,
                           u64 sequence);
int p11_journal_return(struct thread_owner *owner, void *map,
                       const struct owner_start_key *key, u64 thread, u64 sequence);
int p11_journal_remove(struct thread_owner *owner, void *map,
                       const struct owner_start_key *key, u32 required);

/* H7 legs these transactions sequence beside the journal legs
 * (task_owner.c; declared here at the use site). */
long p11_owner_start_insert(const struct owner_start_key *key, const void *value);
long p11_owner_start_remove(const struct owner_start_key *key, u32 required);
void *p11_owner_start_get(const struct owner_start_key *key, u32 required);

/* Combined-transaction fault propagation: the leg that failed, written
 * to the transaction's fault cell BEFORE any unwind, discard or
 * return, so the root raises the checked fault before provider
 * execution/return/discard even when the unwind itself fails. First
 * fault wins; 0 means no fault. */
#define JOURNAL_FAULT_NONE 0U
#define JOURNAL_FAULT_START_LEG 1U
#define JOURNAL_FAULT_JOURNAL_LEG 2U
#define JOURNAL_FAULT_PUBLISH 3U

/* One combined transaction's workspace: the legs' maps and rows plus
 * the publication template, the retained BEGIN facts and the fault
 * cell. Roots fill the fields their operation documents. A BPF
 * subprogram takes at most five arguments, so each transaction takes
 * this one pointer. */
struct journal_txn {
    struct journal_control *jctl; /* entry: mint control */
    void *journal_map; /* all: JOURNAL_START side map */
    void *ring; /* all: publication ring */
    const struct owner_start_key *key; /* all */
    const void *start_value; /* entry: 288 B START value (its marker
                              * drives the OBJECT_START leg) */
    const struct journal_header_spec *spec; /* publication template:
                                             * entry carries kind/bytes/
                                             * flags with zero identity
                                             * (identity comes from the
                                             * inserted row); return and
                                             * remove-unsettled carry
                                             * the full header matching
                                             * the retained facts */
    u64 *fault_out; /* all: fault propagation cell */
    u64 thread; /* return/remove: retained BEGIN facts for exact match */
    u64 sequence; /* return/remove: retained BEGIN facts */
    u32 required; /* remove: the frozen per-slot required bit */
};

_Static_assert(sizeof(struct journal_txn) == 80, "txn ABI");

/* Inactive COMBINED START/OBJECT_START transactions: one call sequences
 * the H7 START leg (which retires the OBJECT_START subordinate beside
 * its START row), the H8 journal leg and the BEGIN/END/ABANDON ring
 * publication, with fault propagation to the root. The owner is
 * derived from current task storage inside the transaction (roots
 * cannot obtain the pointer otherwise) and key-bound before the
 * journal legs run. 0 settled, -1 loss/refusal (fault cell set),
 * remove-only -2 healthy absence (no fault). Publication reserves the
 * spec's bytes, writes the validated 24 B common header, zeroes the
 * remaining body (prototype: fact fill is future-root work) and
 * submits; failures fault BEFORE discard and unwind.
 *
 * Entry inserts START (with its OBJECT_START subordinate), inserts the
 * PREPARING journal row, publishes BEGIN and commits the row to
 * BEGUN. Any leg failure unwinds the earlier legs (journal row first,
 * then START) and reports -1 before provider execution; a failed
 * journal unwind keeps both rows for exit cleanup instead of
 * orphaning the journal row under a released lease.
 *
 * Return verifies the live START row, advances the exactly-matching
 * BEGUN row to RETURNING and publishes END. Forward-only: once the
 * advance commits, a publish failure faults (covering the lost END)
 * and the row stays RETURNING for silent retirement — never a second
 * disposition, never a rollback.
 *
 * Remove retires one call for START removal with cleanup ordering:
 * the journal row settles BEFORE the START leg runs, so a
 * contradicted row is scrubbed (zeroed in place, then deleted)
 * BEFORE the lease is released. Unsettled (PREPARING/BEGUN) rows
 * publish ABANDON first — one original key disposition: END xor
 * ABANDON; RETURNING rows retire silently (their END published, or
 * its loss faulted). Forward-only: cleanup always settles; a failed
 * journal deletion keeps the lease for retry instead of orphaning
 * the row. */
int p11_journal_combined_entry(struct journal_txn *txn);
int p11_journal_combined_return(struct journal_txn *txn);
int p11_journal_combined_remove(struct journal_txn *txn);

#endif /* P11SCOPE_INVENTORY_ONLY */
#endif
