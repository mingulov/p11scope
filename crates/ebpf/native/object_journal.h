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

/* Finite wire gates mirrored from the Rust validators (the oracle):
 * layouts (object_wire OBJECT_LAYOUT_*), descriptor bound
 * (MAX_DESCRIPTORS, exclusive), handle statuses (VALUE plus the finite
 * max; VALUE requires a nonzero word, every other status a zero word),
 * entry-stamp bits (STAMP_VALID plus the five finite condition bits),
 * capture bits (mechanism/output masks plus the three finite bits),
 * the H7 CALL event type and the finite ABANDON reason range. Deep
 * checks (attribute lists, the H7 object tail, the function catalog)
 * stay userspace: the oracle proves them over every published record. */
#define JOURNAL_LAYOUT_LP64 1U
#define JOURNAL_LAYOUT_ILP32 2U
#define JOURNAL_DESCRIPTOR_MAX 105U
#define JOURNAL_HANDLE_VALUE 1U
#define JOURNAL_HANDLE_STATUS_MAX 9U
#define JOURNAL_STAMP_VALID 0x8000U
#define JOURNAL_STAMP_MASK 0x801FU
#define JOURNAL_CAPTURE_MASK 0x7FU
#define JOURNAL_EVENT_CALL 0U
#define JOURNAL_REASON_MIN 1U
#define JOURNAL_REASON_MAX 9U
/* The 608-byte H7 completed payload behind an END, and the compact
 * form's omitted zero span (Event bytes 120..280). */
#define JOURNAL_END_PAYLOAD_BYTES 608U
#define JOURNAL_COMPACT_OMIT_START 120U
#define JOURNAL_COMPACT_OMIT_END 280U

/* Root-supplied BEGIN facts: the entry evidence the BEGIN body
 * carries, retained by the root from the entry probe. Identity
 * (thread/sequence) is NOT here: it comes from the inserted row, and
 * the slot/pid words must exactly match the transaction key (a
 * confused root's facts never frame another key's call). Byte-exact
 * with the Rust ValidatedJournalBegin layout. */
struct journal_begin_facts {
    u64 pid_tgid;
    u64 image_cookie;
    u64 image_exec;
    u64 entry_ns;
    u64 entry_ip;
    unsigned char entry_stamp[16];
    u64 session_word;
    u64 input_words[2];
    u32 slot;
    u32 descriptor;
    u64 entry_mechanism;
    u32 capture;
    unsigned char layout;
    unsigned char session_status;
    unsigned char input_status[2];
    unsigned char requested[2][36];
    u64 slot_id;
    u64 call_flags;
    u32 user_type;
};

/* Root-supplied ABANDON facts: the retained BEGIN evidence the
 * ABANDON body carries. Identity comes from the retained facts; the
 * slot/pid words must exactly match the transaction key. */
struct journal_abandon_facts {
    u64 pid_tgid;
    u64 image_cookie;
    u64 image_exec;
    u64 entry_ns;
    u32 slot;
    u32 reason;
};

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
 * to the transaction's fault cell BEFORE any unwind, custody handoff
 * or return, so the root raises the checked fault before provider
 * execution/return/discard even when the unwind itself fails. First
 * fault wins; 0 means no fault. Cells are caller-owned and sticky: a
 * transaction never clears a nonzero incoming cell (a fresh probe
 * passes a fresh cell). Entry and return refuse before effects on a
 * tainted cell; remove still settles forward but reports the earlier
 * fault instead of success — cleanup never erases a prior failure.
 * The cell reports the fault; the checked RAISE (and any discard) is
 * the root's act — nothing below the root discards (see `uncommitted`
 * below). */
#define JOURNAL_FAULT_NONE 0U
#define JOURNAL_FAULT_START_LEG 1U
#define JOURNAL_FAULT_JOURNAL_LEG 2U
#define JOURNAL_FAULT_PUBLISH 3U

/* One combined transaction's workspace: the legs' maps and rows plus
 * the publication template, the root-supplied record facts, the
 * retained BEGIN facts and the fault cell. Roots fill the fields
 * their operation documents. A BPF subprogram takes at most five
 * arguments, so each transaction takes this one pointer. */
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
    const struct journal_begin_facts *begin; /* entry: BEGIN body facts */
    const void *end_payload; /* return: 608 B H7 completed payload */
    const struct journal_abandon_facts *abandon; /* remove: ABANDON facts */
    void *uncommitted; /* out: the uncommitted reservation, returned to
                        * the REAL ROOT. Nothing below the root discards:
                        * on any path holding a reservation it will not
                        * submit, the transaction reports the fault, hands
                        * the reservation back here, unwinds/settles its
                        * legs and returns -1. The root then raises the
                        * checked fault BEFORE discarding it. NULL when
                        * nothing is outstanding (roots zero the
                        * workspace; each transaction clears it on entry). */
};

_Static_assert(sizeof(struct journal_txn) == 112, "txn ABI");

/* Inactive COMBINED START/OBJECT_START transactions: one call sequences
 * the H7 START leg (which retires the OBJECT_START subordinate beside
 * its START row), the H8 journal leg and the BEGIN/END/ABANDON ring
 * publication, with fault propagation to the root. The owner is
 * derived from current task storage inside the transaction (roots
 * cannot obtain the pointer otherwise) and key-bound before the
 * journal legs run. 0 settled, -1 loss/refusal (fault cell set),
 * remove-only -2 healthy absence (no fault). Every published record
 * is a VALID wire transaction: the validated 24 B common header plus
 * a body framed from the root's facts behind the finite native gates
 * (stamp, descriptor, layout, capture, handle, reason, END base and
 * compact eligibility); the Rust validators accept every submitted
 * record (pinned by test). Publication reserves first and submits
 * only after the required cleanup commits; fill failures hand the
 * uncommitted reservation back to the root (`uncommitted` above) for
 * ROOT-SIDE fault-then-discard — no helper at or below the combined
 * level discards.
 *
 * Operation-specific kinds at the entry points: entry accepts only a
 * BEGIN template, return only END, remove only ABANDON when it
 * publishes (a wrong-kind template faults PUBLISH — entry and return
 * refuse before effects; forward-only remove still retires but
 * submits nothing).
 *
 * Entry refuses before effects on a busy key (an occupant in START or
 * the journal side map ends the call with a START/JOURNAL leg fault
 * and nothing unwound — never a collide-unwind that releases the
 * owner under a retained journal row), inserts START (with its
 * OBJECT_START subordinate), inserts the PREPARING journal row,
 * reserves and fills BEGIN, submits it, and commits the row to
 * BEGUN. Any leg failure unwinds the earlier legs (journal row first,
 * then START) and reports -1 before provider execution; a failed
 * journal unwind keeps both rows for exit cleanup instead of
 * orphaning the journal row under a released lease.
 *
 * Return verifies the live START row, reserves and fills END,
 * advances the exactly-matching BEGUN row to RETURNING (an already
 * RETURNING match resumes without re-advancing, so a retry after a
 * failed START removal never double-advances), retires START with
 * its OBJECT_START subordinate, and only then submits END: the
 * terminal submits after the required cleanup commits, never while
 * custody is still owned. Forward-only: a failure after the advance
 * faults and the row stays RETURNING for silent retirement — the END
 * submits exactly once, on the attempt whose cleanup commits; never
 * a second disposition, never a rollback.
 *
 * Remove retires one call for START removal with cleanup ordering:
 * the journal row settles BEFORE the START leg runs, so a
 * contradicted row is scrubbed (zeroed in place, then deleted)
 * BEFORE the lease is released. Unsettled (PREPARING/BEGUN) rows
 * reserve ABANDON, delete the journal row, run the START leg, and
 * only then submit — the terminal submits after ALL required cleanup
 * commits (every leg, including START); otherwise the fault raises
 * and the reservation returns to the root WITHOUT publishing. One
 * original key disposition: END xor ABANDON. RETURNING rows retire
 * silently (their END published, or its loss faulted) with the START
 * leg optional (return already retired it; its absence is healthy,
 * never loss or poison). Forward-only: cleanup always settles; a
 * failed journal deletion keeps the lease for retry instead of
 * orphaning the row. */
int p11_journal_combined_entry(struct journal_txn *txn);
int p11_journal_combined_return(struct journal_txn *txn);
int p11_journal_combined_remove(struct journal_txn *txn);

#endif /* P11SCOPE_INVENTORY_ONLY */
#endif
