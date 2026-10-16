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

#endif /* P11SCOPE_INVENTORY_ONLY */
