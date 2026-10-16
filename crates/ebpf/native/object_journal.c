/* SPDX-License-Identifier: GPL-2.0-only */
/* H8 slice-A inactive custody implementation. See object_journal.h. */
#include "object_journal.h"

#ifndef P11SCOPE_INVENTORY_ONLY

struct {
    __uint(type, 1);
    __uint(max_entries, JOURNAL_START_LIMIT);
    __type(key, struct owner_start_key);
    __type(value, struct journal_start_value);
} JOURNAL_START SEC(".maps");
struct {
    __uint(type, 2);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct journal_control);
} JOURNAL_CTL SEC(".maps");

/* One mint attempt step shared by the bounded retry loop. */
static __always_inline u64 mint_once(struct journal_control *ctl)
{
    u64 old = *(volatile u64 *)&ctl->next_thread;
    if (*(volatile u64 *)&ctl->poison)
        return 0;
    /* Saturated, wrapped or corrupted: fail closed (caller raises
     * loss). The bound never resets and tickets never recycle. */
    if (old >= JOURNAL_THREAD_LIMIT || old == ~0ULL) {
        if (old == ~0ULL)
            __sync_fetch_and_or(&ctl->poison, 1);
        if (*(volatile u64 *)&ctl->admission_failures != ~0ULL)
            __sync_fetch_and_add(&ctl->admission_failures, 1);
        return 0;
    }
    if (__sync_val_compare_and_swap(&ctl->next_thread, old, old + 1) != old)
        return ~0ULL;
    /* old < 16,448, so the ticket is a nonzero never-recycled word. */
    return old + 1;
}

__attribute__((noinline)) u64 p11_journal_mint_thread(struct journal_control *ctl)
{
    u32 i;
    if (!ctl)
        return 0;
    for (i = 0; i < JOURNAL_MINT_CAS_BOUND; i++) {
        u64 ticket = mint_once(ctl);
        if (ticket != ~0ULL)
            return ticket;
    }
    if (*(volatile u64 *)&ctl->admission_failures != ~0ULL)
        __sync_fetch_and_add(&ctl->admission_failures, 1);
    return 0;
}

/* The row's ticket, minting once on first journal use. Same-task-only
 * writers install the row word; cross-task contention lives on the
 * control counter above. A row previously created by loader work mints
 * here exactly like a fresh row. */
__attribute__((noinline)) u64 p11_journal_thread(struct thread_owner *owner,
                                                 struct journal_control *ctl)
{
    u64 ticket;
    if (!owner || !ctl)
        return 0;
    if (owner->journal_thread)
        return owner->journal_thread;
    ticket = p11_journal_mint_thread(ctl);
    if (!ticket)
        return 0;
    owner->journal_thread = ticket;
    return ticket;
}

/* Checked per-task sequence advance: one per affecting entry. Wrap
 * fails closed (the caller raises loss before provider execution). */
__attribute__((noinline)) u64 p11_journal_next_sequence(struct thread_owner *owner)
{
    if (!owner)
        return 0;
    if (owner->journal_sequence == ~0ULL)
        return 0;
    owner->journal_sequence++;
    return owner->journal_sequence;
}

/* START-key shape: nonzero carrier, in-bound slot, zero padding.
 * The owner binding (key pid_tgid against the leased owner) is
 * checked by the transactions, which hold the owner. */
static __always_inline int side_key_valid(const struct owner_start_key *key)
{
    return key && key->pid_tgid && key->slot < P11SCOPE_OWNER_SLOT_BOUND && !key->pad;
}

static __always_inline int side_value_valid(const struct journal_start_value *value)
{
    return value && value->thread && value->sequence &&
        journal_phase_valid(value->phase);
}

/* The leased owner this key must bind to: leased flags plus exact
 * pid_tgid agreement. A key for another owner (or a released one)
 * never touches this map. */
static __always_inline int side_owner_binds(const struct thread_owner *owner,
                                            const struct owner_start_key *key)
{
    return owner && key && owner->flags == OWNER_LEASED &&
        key->pid_tgid == owner->original_pid_tgid;
}

/* NOEXIST insertion: no overwrite, no independent lease, no LRU
 * eviction. A present row is the caller's collision to dispose, never
 * a silent replace. */
__attribute__((noinline)) int p11_journal_side_insert(void *map,
                                                      const struct owner_start_key *key,
                                                      const struct journal_start_value *value)
{
    if (!map || !side_key_valid(key) || !side_value_valid(value))
        return -1;
    return owner_map_update(map, key, value, 1) ? -1 : 0;
}

__attribute__((noinline)) void *p11_journal_side_lookup(void *map,
                                                        const struct owner_start_key *key)
{
    if (!map || !side_key_valid(key))
        return (void *)0;
    return owner_map_lookup(map, key);
}

__attribute__((noinline)) int p11_journal_side_remove(void *map,
                                                      const struct owner_start_key *key)
{
    if (!map || !side_key_valid(key))
        return -1;
    return owner_map_delete(map, key) ? -1 : 0;
}

/* Advance one exactly-matching row to a new finite phase. The row
 * must exist with the caller's retained thread/sequence and the
 * expected phase; anything else refuses without touching the map, so
 * a later equal numeric key never joins an earlier call's row. */
static __always_inline int side_advance(void *map, const struct owner_start_key *key,
                                        u64 thread, u64 sequence, u64 from, u64 to)
{
    struct journal_start_value *found;
    struct journal_start_value next;
    if (!map || !side_key_valid(key) || !thread || !sequence)
        return -1;
    found = owner_map_lookup(map, key);
    if (!found || found->thread != thread || found->sequence != sequence ||
        found->phase != from)
        return -1;
    next.thread = thread;
    next.sequence = sequence;
    next.phase = to;
    return owner_map_update(map, key, &next, 2) ? -1 : 0;
}

/* The preparing transaction: validate the leased owner against the
 * START key, mint the call's thread/sequence words, NOEXIST-insert
 * the PREPARING row. 0 inserted, -1 refused (caller raises loss
 * before provider execution). */
__attribute__((noinline)) int p11_journal_entry(struct thread_owner *owner,
                                                struct journal_control *ctl, void *map,
                                                const struct owner_start_key *key)
{
    struct journal_start_value value;
    /* A poisoned control admits no new custody even when the ticket
     * is already minted; settlement (return/removal) still proceeds
     * below so poison never strands rows. */
    if (!ctl || *(volatile u64 *)&ctl->poison || !map || !side_key_valid(key) ||
        !side_owner_binds(owner, key))
        return -1;
    value.thread = p11_journal_thread(owner, ctl);
    if (!value.thread)
        return -1;
    value.sequence = p11_journal_next_sequence(owner);
    if (!value.sequence)
        return -1;
    value.phase = JOURNAL_PHASE_PREPARING;
    return p11_journal_side_insert(map, key, &value);
}

/* Commit one PREPARING row to BEGUN once its BEGIN is valid. */
__attribute__((noinline)) int p11_journal_mark_begun(void *map, const struct owner_start_key *key,
                                                     u64 thread, u64 sequence)
{
    return side_advance(map, key, thread, sequence, JOURNAL_PHASE_PREPARING,
                        JOURNAL_PHASE_BEGUN);
}

/* The return transaction: the bound owner's exactly-matching BEGUN
 * row advances to RETURNING. */
__attribute__((noinline)) int p11_journal_return(struct thread_owner *owner, void *map,
                                                 const struct owner_start_key *key, u64 thread,
                                                 u64 sequence)
{
    if (!side_owner_binds(owner, key))
        return -1;
    return side_advance(map, key, thread, sequence, JOURNAL_PHASE_BEGUN,
                        JOURNAL_PHASE_RETURNING);
}

/* The removal transaction: settle one side row for START removal. 0
 * removed, -2 healthy absence (optional row, nothing held), -1 loss.
 * A present row with a contradicted phase still retires (scrubbed,
 * never orphaned) but reports -1; only a failed deletion keeps the
 * row for retry. */
__attribute__((noinline)) int p11_journal_remove(struct thread_owner *owner, void *map,
                                                 const struct owner_start_key *key, u32 required)
{
    struct journal_start_value *found;
    if (!map || !side_key_valid(key) || !side_owner_binds(owner, key) || (required != 0 && required != 1))
        return -1;
    found = owner_map_lookup(map, key);
    if (!found)
        return required ? -1 : -2;
    if (!found->thread || !found->sequence || !journal_phase_valid(found->phase)) {
        found->thread = 0;
        found->sequence = 0;
        found->phase = 0;
        if (owner_map_delete(map, key))
            return -1;
        return -1;
    }
    return owner_map_delete(map, key) ? -1 : 0;
}

/* Write one validated 24 B common header. Native little-endian x86-64;
 * every combination this accepts the Rust validators accept too. */
__attribute__((noinline)) int p11_journal_header_init(void *record,
                                                      const struct journal_header_spec *spec)
{
    unsigned char *out;
    if (!record || !spec)
        return -1;
    if (!journal_header_valid(spec->bytes, spec->kind, spec->flags, 0, spec->thread,
                              spec->sequence))
        return -1;
    out = record;
    out[0] = JOURNAL_VERSION & 0xff;
    out[1] = (JOURNAL_VERSION >> 8) & 0xff;
    out[2] = spec->bytes & 0xff;
    out[3] = (spec->bytes >> 8) & 0xff;
    out[4] = spec->kind & 0xff;
    out[5] = spec->flags & 0xff;
    out[6] = 0;
    out[7] = 0;
    __builtin_memcpy(out + 8, &spec->thread, 8);
    __builtin_memcpy(out + 16, &spec->sequence, 8);
    return 0;
}

/* Ring-leaf skeleton: pure pass-through to the ring helpers. Ordering
 * (fault before discard, submit after commit) belongs to the slice-B
 * roots; these leaves only pin the call shape for review. */
__attribute__((noinline)) void *p11_journal_reserve(void *ring, u64 bytes)
{
    return journal_ring_reserve(ring, bytes, 0);
}

__attribute__((noinline)) void p11_journal_submit(void *record)
{
    journal_ring_submit(record, 0);
}

__attribute__((noinline)) void p11_journal_discard(void *record)
{
    journal_ring_discard(record, 0);
}

/* The current task's leased owner, key-bound for the journal legs.
 * Roots cannot obtain this pointer; the transactions derive it from
 * task storage after the START leg guarantees (entry) or beside the
 * START row they retire (return/remove). */
static __always_inline struct thread_owner *txn_owner(const struct owner_start_key *key)
{
    struct thread_owner *owner;
    if (!side_key_valid(key))
        return (void *)0;
    owner = p11_owner_current();
    if (!side_owner_binds(owner, key))
        return (void *)0;
    return owner;
}

/* Reserve one record: the retained reservation, or NULL with the
 * fault cell set (first fault wins — a tainted cell keeps its earlier
 * fault). Nothing exists to discard on this path. */
static __always_inline void *txn_reserve(void *ring, u64 bytes, u64 *fault_out)
{
    void *record = p11_journal_reserve(ring, bytes);
    if (!record && *fault_out == JOURNAL_FAULT_NONE)
        *fault_out = JOURNAL_FAULT_PUBLISH;
    return record;
}

/* Bounded byte copy for record bodies (BPF-safe: constant bounds at
 * every call site). */
static __always_inline void txn_copy(unsigned char *dst, const unsigned char *src, u64 len)
{
    u64 i;
    for (i = 0; i < len; i++)
        dst[i] = src[i];
}

/* One H7 handle word gate: finite status, VALUE iff nonzero, ilp32
 * narrow. Mirrors the validator's handle rule. */
static __always_inline int txn_word_ok(unsigned char status, u64 word, unsigned char layout)
{
    if (status > JOURNAL_HANDLE_STATUS_MAX)
        return 0;
    if (layout == JOURNAL_LAYOUT_ILP32 && word > 0xffffffffULL)
        return 0;
    if (status == JOURNAL_HANDLE_VALUE)
        return word != 0;
    return word == 0;
}

/* Frame one BEGIN body from the root's facts behind the finite gates.
 * Offsets mirror ValidatedJournalBegin byte-exactly. Returns
 * JOURNAL_FAULT_NONE filled, or JOURNAL_FAULT_PUBLISH. */
static __always_inline u64 txn_fill_begin(unsigned char *record,
                                          const struct journal_begin_facts *facts,
                                          const struct owner_start_key *key)
{
    unsigned stamp_flags;
    if (!record || !facts || !key)
        return JOURNAL_FAULT_PUBLISH;
    if (facts->layout != JOURNAL_LAYOUT_LP64 && facts->layout != JOURNAL_LAYOUT_ILP32)
        return JOURNAL_FAULT_PUBLISH;
    stamp_flags = (unsigned)facts->entry_stamp[14] |
        ((unsigned)facts->entry_stamp[15] << 8);
    if (!(stamp_flags & JOURNAL_STAMP_VALID) || (stamp_flags & ~JOURNAL_STAMP_MASK))
        return JOURNAL_FAULT_PUBLISH;
    if (!facts->descriptor || facts->descriptor >= JOURNAL_DESCRIPTOR_MAX)
        return JOURNAL_FAULT_PUBLISH;
    if (facts->capture & ~JOURNAL_CAPTURE_MASK)
        return JOURNAL_FAULT_PUBLISH;
    if (!txn_word_ok(facts->session_status, facts->session_word, facts->layout) ||
        !txn_word_ok(facts->input_status[0], facts->input_words[0], facts->layout) ||
        !txn_word_ok(facts->input_status[1], facts->input_words[1], facts->layout))
        return JOURNAL_FAULT_PUBLISH;
    /* Exact match: a confused root's facts never frame another key. */
    if (facts->slot != key->slot || facts->pid_tgid != key->pid_tgid)
        return JOURNAL_FAULT_PUBLISH;
    txn_copy(record + 24, (const unsigned char *)&facts->pid_tgid, 8);
    txn_copy(record + 32, (const unsigned char *)&facts->image_cookie, 8);
    txn_copy(record + 40, (const unsigned char *)&facts->image_exec, 8);
    txn_copy(record + 48, (const unsigned char *)&facts->entry_ns, 8);
    txn_copy(record + 56, (const unsigned char *)&facts->entry_ip, 8);
    txn_copy(record + 64, facts->entry_stamp, 16);
    txn_copy(record + 80, (const unsigned char *)&facts->session_word, 8);
    txn_copy(record + 88, (const unsigned char *)&facts->input_words[0], 8);
    txn_copy(record + 96, (const unsigned char *)&facts->input_words[1], 8);
    txn_copy(record + 104, (const unsigned char *)&facts->slot, 4);
    txn_copy(record + 108, (const unsigned char *)&facts->descriptor, 4);
    txn_copy(record + 112, (const unsigned char *)&facts->entry_mechanism, 8);
    txn_copy(record + 120, (const unsigned char *)&facts->capture, 4);
    record[124] = facts->layout;
    record[125] = facts->session_status;
    record[126] = facts->input_status[0];
    record[127] = facts->input_status[1];
    txn_copy(record + 128, facts->requested[0], 36);
    txn_copy(record + 164, facts->requested[1], 36);
    txn_copy(record + 200, (const unsigned char *)&facts->slot_id, 8);
    txn_copy(record + 208, (const unsigned char *)&facts->call_flags, 8);
    txn_copy(record + 216, (const unsigned char *)&facts->user_type, 4);
    record[220] = 0;
    record[221] = 0;
    record[222] = 0;
    record[223] = 0;
    return JOURNAL_FAULT_NONE;
}

/* Frame one ABANDON body from the root's facts. Returns
 * JOURNAL_FAULT_NONE filled, or JOURNAL_FAULT_PUBLISH. */
static __always_inline u64 txn_fill_abandon(unsigned char *record,
                                            const struct journal_abandon_facts *facts,
                                            const struct owner_start_key *key)
{
    if (!record || !facts || !key)
        return JOURNAL_FAULT_PUBLISH;
    if (facts->reason < JOURNAL_REASON_MIN || facts->reason > JOURNAL_REASON_MAX)
        return JOURNAL_FAULT_PUBLISH;
    if (facts->slot != key->slot || facts->pid_tgid != key->pid_tgid)
        return JOURNAL_FAULT_PUBLISH;
    txn_copy(record + 24, (const unsigned char *)&facts->pid_tgid, 8);
    txn_copy(record + 32, (const unsigned char *)&facts->image_cookie, 8);
    txn_copy(record + 40, (const unsigned char *)&facts->image_exec, 8);
    txn_copy(record + 48, (const unsigned char *)&facts->slot, 4);
    txn_copy(record + 52, (const unsigned char *)&facts->reason, 4);
    txn_copy(record + 56, (const unsigned char *)&facts->entry_ns, 8);
    return JOURNAL_FAULT_NONE;
}

/* Frame one END body from the root's 608-byte H7 completed payload:
 * the event base must be CALL with affiliation at most 1, an
 * absent-tail END needs an all-zero tail, and the compact form needs
 * the omitted span zeroed (eligibility, checked before packing).
 * Returns JOURNAL_FAULT_NONE filled, or JOURNAL_FAULT_PUBLISH. */
static __always_inline u64 txn_fill_end(unsigned char *record, const void *payload, u64 bytes,
                                        u64 flags)
{
    const unsigned char *in = payload;
    u32 event_type;
    u64 affiliation;
    u64 i;
    if (!record || !in)
        return JOURNAL_FAULT_PUBLISH;
    txn_copy((unsigned char *)&event_type, in + 284, 4);
    if (event_type != JOURNAL_EVENT_CALL)
        return JOURNAL_FAULT_PUBLISH;
    txn_copy((unsigned char *)&affiliation, in + 320, 8);
    if (affiliation > 1)
        return JOURNAL_FAULT_PUBLISH;
    if (flags & JOURNAL_FLAG_ABSENT_TAIL) {
        for (i = 368; i < JOURNAL_END_PAYLOAD_BYTES; i++)
            if (in[i])
                return JOURNAL_FAULT_PUBLISH;
    }
    if (bytes == JOURNAL_END_FULL_BYTES) {
        for (i = 0; i < JOURNAL_END_PAYLOAD_BYTES; i++)
            record[JOURNAL_COMMON_BYTES + i] = in[i];
    } else if (bytes == JOURNAL_END_COMPACT_BYTES) {
        for (i = JOURNAL_COMPACT_OMIT_START; i < JOURNAL_COMPACT_OMIT_END; i++)
            if (in[i])
                return JOURNAL_FAULT_PUBLISH;
        for (i = 0; i < JOURNAL_COMPACT_OMIT_START; i++)
            record[JOURNAL_COMMON_BYTES + i] = in[i];
        for (i = JOURNAL_COMPACT_OMIT_END; i < JOURNAL_END_PAYLOAD_BYTES; i++)
            record[JOURNAL_COMMON_BYTES + JOURNAL_COMPACT_OMIT_START + (i - JOURNAL_COMPACT_OMIT_END)] =
                in[i];
    } else {
        return JOURNAL_FAULT_PUBLISH;
    }
    return JOURNAL_FAULT_NONE;
}

/* Fill one reserved record: the validated header plus the kind's gated
 * body. Returns JOURNAL_FAULT_NONE filled, or the fault code. Never
 * touches the fault cell, never submits, never discards: on a fault
 * the combined function reports the fault cell and hands the
 * uncommitted reservation back to the REAL ROOT (`uncommitted`), which
 * raises the checked fault BEFORE discarding it. Nothing at or below
 * the combined level discards. */
static __always_inline u64 txn_fill(void *record, const struct journal_txn *txn, u64 thread,
                                    u64 sequence)
{
    struct journal_header_spec hdr;
    unsigned char *out = record;
    if (!record || !txn || !txn->spec || !txn->key)
        return JOURNAL_FAULT_PUBLISH;
    hdr.bytes = txn->spec->bytes;
    hdr.kind = txn->spec->kind;
    hdr.flags = txn->spec->flags;
    hdr.thread = thread;
    hdr.sequence = sequence;
    if (p11_journal_header_init(out, &hdr))
        return JOURNAL_FAULT_PUBLISH;
    if (hdr.kind == JOURNAL_KIND_BEGIN) {
        if (!txn->begin)
            return JOURNAL_FAULT_PUBLISH;
        return txn_fill_begin(out, txn->begin, txn->key);
    }
    if (hdr.kind == JOURNAL_KIND_END)
        return txn_fill_end(out, txn->end_payload, hdr.bytes, hdr.flags);
    if (hdr.kind == JOURNAL_KIND_ABANDON) {
        if (!txn->abandon)
            return JOURNAL_FAULT_PUBLISH;
        return txn_fill_abandon(out, txn->abandon, txn->key);
    }
    return JOURNAL_FAULT_PUBLISH;
}

__attribute__((noinline)) int p11_journal_combined_entry(struct journal_txn *txn)
{
    struct thread_owner *owner;
    struct journal_start_value *row;
    void *record;
    u64 fault;
    if (!txn || !txn->fault_out)
        return -1;
    if (*txn->fault_out != JOURNAL_FAULT_NONE)
        return -1;
    *txn->fault_out = JOURNAL_FAULT_NONE;
    txn->uncommitted = (void *)0;
    if (!txn->jctl || !txn->journal_map || !txn->ring || !txn->key || !txn->start_value ||
        !txn->spec || !txn->begin) {
        *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        return -1;
    }
    /* The template carries kind/bytes/flags only: identity comes from
     * the inserted row, never smuggled in. Operation-specific kinds:
     * entry publishes BEGIN only — an END or ABANDON template refuses
     * before effects, never a cross-operation publication. */
    if (txn->spec->thread || txn->spec->sequence ||
        txn->spec->kind != JOURNAL_KIND_BEGIN) {
        *txn->fault_out = JOURNAL_FAULT_PUBLISH;
        return -1;
    }
    if (!side_key_valid(txn->key)) {
        *txn->fault_out = JOURNAL_FAULT_START_LEG;
        return -1;
    }
    /* Busy-key refusal before effects: an occupant in START or the
     * journal side map ends the call here — the H7 insert (which
     * unwinds a collided row) never runs, so a collision never
     * releases the owner under a retained journal row. Pure queries;
     * nothing is leased, inserted or counted. */
    if (owner_map_lookup(&START, txn->key)) {
        *txn->fault_out = JOURNAL_FAULT_START_LEG;
        return -1;
    }
    if (owner_map_lookup(txn->journal_map, txn->key)) {
        *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        return -1;
    }
    /* START leg first (with its OBJECT_START subordinate); it unwinds
     * itself on failure and the journal is untouched yet. */
    if (p11_owner_start_insert(txn->key, txn->start_value)) {
        *txn->fault_out = JOURNAL_FAULT_START_LEG;
        return -1;
    }
    owner = txn_owner(txn->key);
    if (!owner || p11_journal_entry(owner, txn->jctl, txn->journal_map, txn->key)) {
        *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        p11_owner_start_remove(txn->key, 1);
        return -1;
    }
    /* BEGIN publication from the inserted row's own words: reserve,
     * fill, submit, then commit. A readback miss leaves no reservation
     * (nothing to hand back); a fill failure reports the fault cell
     * and hands the uncommitted reservation back to the root — the
     * root raises the checked fault BEFORE discarding it — then unwinds
     * the legs (a H7-side key/row mismatch here cannot smuggle identity
     * into the ring, and post-pre-check any present row is ours). */
    row = p11_journal_side_lookup(txn->journal_map, txn->key);
    if (!row) {
        *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        goto unwind;
    }
    record = txn_reserve(txn->ring, txn->spec->bytes, txn->fault_out);
    if (!record)
        goto unwind;
    fault = txn_fill(record, txn, row->thread, row->sequence);
    if (fault != JOURNAL_FAULT_NONE) {
        *txn->fault_out = fault;
        txn->uncommitted = record;
        goto unwind;
    }
    p11_journal_submit(record);
    /* The published BEGIN is valid: commit to BEGUN. A failed commit
     * faults with the row PREPARING; exit cleanup abandons it (BEGIN
     * then ABANDON is the coherent pair, not two terminals). */
    if (p11_journal_mark_begun(txn->journal_map, txn->key, row->thread, row->sequence)) {
        *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        return -1;
    }
    return 0;
unwind:
    /* Journal row first, then START; a failed journal unwind keeps
     * both rows for exit cleanup instead of orphaning the journal
     * row under a released lease. */
    if (p11_journal_side_remove(txn->journal_map, txn->key))
        return -1;
    p11_owner_start_remove(txn->key, 1);
    return -1;
}

__attribute__((noinline)) int p11_journal_combined_return(struct journal_txn *txn)
{
    struct thread_owner *owner;
    struct journal_start_value *row;
    void *record;
    u64 fault;
    if (!txn || !txn->fault_out)
        return -1;
    if (*txn->fault_out != JOURNAL_FAULT_NONE)
        return -1;
    *txn->fault_out = JOURNAL_FAULT_NONE;
    txn->uncommitted = (void *)0;
    if (!txn->journal_map || !txn->ring || !txn->key || !txn->spec || !txn->end_payload) {
        *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        return -1;
    }
    /* The spec must name the retained call exactly, and the operation
     * publishes END only — a BEGIN or ABANDON template refuses before
     * effects, never a cross-operation publication. */
    if (txn->spec->kind != JOURNAL_KIND_END || txn->spec->thread != txn->thread ||
        txn->spec->sequence != txn->sequence) {
        *txn->fault_out = JOURNAL_FAULT_PUBLISH;
        return -1;
    }
    /* The live START row must still hold this call (a raw presence
     * query: quiet refusal, never H7 poison): a vanished START never
     * returns through its orphaned journal row. */
    if (!owner_map_lookup(&START, txn->key)) {
        *txn->fault_out = JOURNAL_FAULT_START_LEG;
        return -1;
    }
    /* Reserve and fill the END before the advance commits: a publish
     * failure reports the fault, hands the uncommitted reservation back
     * to the root (checked fault raises before its discard), and leaves
     * the row BEGUN for exit cleanup (BEGIN then ABANDON), never a
     * faulted END. */
    record = txn_reserve(txn->ring, txn->spec->bytes, txn->fault_out);
    if (!record)
        return -1;
    fault = txn_fill(record, txn, txn->thread, txn->sequence);
    if (fault != JOURNAL_FAULT_NONE) {
        *txn->fault_out = fault;
        txn->uncommitted = record;
        return -1;
    }
    /* The required cleanup commits: advance, then retire START with
     * its OBJECT_START subordinate. An already-RETURNING match resumes
     * (a retry after a failed START removal never double-advances). */
    row = p11_journal_side_lookup(txn->journal_map, txn->key);
    owner = txn_owner(txn->key);
    if (row && row->phase == JOURNAL_PHASE_RETURNING && row->thread == txn->thread &&
        row->sequence == txn->sequence) {
        /* Resume: the advance committed on an earlier attempt. */
    } else if (!owner ||
               p11_journal_return(owner, txn->journal_map, txn->key, txn->thread,
                                  txn->sequence)) {
        *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        txn->uncommitted = record;
        return -1;
    }
    if (p11_owner_start_remove(txn->key, 1)) {
        *txn->fault_out = JOURNAL_FAULT_START_LEG;
        txn->uncommitted = record;
        return -1;
    }
    /* Cleanup committed: submit the terminal exactly once, on the
     * attempt whose cleanup commits. Forward-only after the advance:
     * never a second disposition, never a rollback. */
    p11_journal_submit(record);
    return 0;
}

__attribute__((noinline)) int p11_journal_combined_remove(struct journal_txn *txn)
{
    struct journal_start_value *row;
    long start_rc;
    int journal_rc;
    int start_ok;
    int start_optional = 0;
    int journal_deleted = 0;
    int tainted;
    void *record = (void *)0;
    u64 fault;
    if (!txn || !txn->fault_out)
        return -1;
    /* A tainted cell stays tainted: cleanup still settles forward
     * below, but the report preserves the earlier fault instead of
     * success — cleanup never erases a prior failure. The handoff is
     * an out-field: always cleared on entry. */
    tainted = (*txn->fault_out != JOURNAL_FAULT_NONE);
    if (!tainted)
        *txn->fault_out = JOURNAL_FAULT_NONE;
    txn->uncommitted = (void *)0;
    if (!txn->journal_map || !txn->ring || !txn->key || (txn->required != 0 && txn->required != 1)) {
        if (!tainted)
            *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        return -1;
    }
    /* Journal row settles BEFORE the START leg runs: cleanup ordering.
     * A contradicted row (bad words, bad phase, or identity against
     * the retained facts) is scrubbed in place, then deleted — the
     * scrub lands before the lease is released. */
    row = p11_journal_side_lookup(txn->journal_map, txn->key);
    if (!row) {
        if (txn->required) {
            if (!tainted)
                *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
            journal_rc = -1;
        } else {
            journal_rc = -2;
        }
        goto start_leg;
    }
    if (!row->thread || !row->sequence || !journal_phase_valid(row->phase) ||
        row->thread != txn->thread || row->sequence != txn->sequence) {
        row->thread = 0;
        row->sequence = 0;
        row->phase = 0;
        if (p11_journal_side_remove(txn->journal_map, txn->key)) {
            /* The scrubbed row stays with its lease for retry; the
             * START leg must not orphan it under a release. */
            if (!tainted)
                *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
            return -1;
        }
        if (!tainted)
            *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        journal_rc = -1;
        goto start_leg;
    }
    if (row->phase != JOURNAL_PHASE_RETURNING) {
        /* Unsettled: reserve the ABANDON (ABANDON kind only — a wrong-kind
         * template faults PUBLISH but still retires, submitting
         * nothing), delete the journal row, run the START leg, and only
         * then submit: the terminal submits after ALL required cleanup
         * commits. A fill failure reports the fault and hands the
         * reservation back to the root; the row still deletes and the
         * START leg still runs (cleanup settles forward-only). */
        if (!txn->spec || !txn->abandon || txn->spec->kind != JOURNAL_KIND_ABANDON ||
            txn->spec->thread != txn->thread || txn->spec->sequence != txn->sequence) {
            if (!tainted)
                *txn->fault_out = JOURNAL_FAULT_PUBLISH;
        } else {
            record = txn_reserve(txn->ring, txn->spec->bytes, txn->fault_out);
            if (record) {
                fault = txn_fill(record, txn, txn->thread, txn->sequence);
                if (fault != JOURNAL_FAULT_NONE) {
                    if (!tainted)
                        *txn->fault_out = fault;
                    txn->uncommitted = record;
                    record = 0;
                }
            }
        }
        if (p11_journal_side_remove(txn->journal_map, txn->key)) {
            /* The journal cleanup failed: report the fault FIRST (first
             * fault wins — a fill failure already reported stays), hand
             * the uncommitted reservation back to the root, and keep
             * the lease for retry; the START leg must not orphan the
             * row under a release, and the ABANDON never submits. */
            if (*txn->fault_out == JOURNAL_FAULT_NONE)
                *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
            if (record)
                txn->uncommitted = record;
            return -1;
        }
        journal_deleted = 1;
        journal_rc = (*txn->fault_out == JOURNAL_FAULT_NONE) ? 0 : -1;
        goto start_leg;
    }
    /* RETURNING: the END published (or its loss faulted); retire
     * silently — never a second disposition. Return already retired
     * START, so the START leg runs optional below (its absence is
     * healthy, never loss or poison). */
    if (p11_journal_side_remove(txn->journal_map, txn->key)) {
        if (!tainted)
            *txn->fault_out = JOURNAL_FAULT_JOURNAL_LEG;
        return -1;
    }
    journal_rc = 0;
    start_optional = 1;
start_leg:
    /* The START leg retires OBJECT_START beside START and releases an
     * emptied lease. First fault wins; -2 only when both sides are
     * healthily absent under an optional removal. */
    if (start_optional)
        start_rc = p11_owner_start_remove(txn->key, 0);
    else
        start_rc = p11_owner_start_remove(txn->key, txn->required);
    start_ok = (start_rc == 0) || (start_rc == -2 && (!txn->required || start_optional));
    /* The terminal submits only after ALL required cleanup commits —
     * the journal row deleted above plus this START leg. Otherwise the
     * fault reports (first wins) and the reservation returns to the
     * root WITHOUT publishing. */
    if (record) {
        if (journal_deleted && start_ok) {
            p11_journal_submit(record);
        } else {
            if (*txn->fault_out == JOURNAL_FAULT_NONE)
                *txn->fault_out =
                    journal_deleted ? JOURNAL_FAULT_START_LEG : JOURNAL_FAULT_JOURNAL_LEG;
            txn->uncommitted = record;
        }
    }
    if (tainted)
        return -1;
    if (journal_rc == -2 && !txn->required && start_rc == -2)
        return -2;
    if (journal_rc == -1 || !start_ok) {
        if (*txn->fault_out == JOURNAL_FAULT_NONE)
            *txn->fault_out = JOURNAL_FAULT_START_LEG;
        return -1;
    }
    return 0;
}

#endif /* P11SCOPE_INVENTORY_ONLY */
