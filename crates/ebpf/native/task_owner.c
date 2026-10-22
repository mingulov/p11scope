/* SPDX-License-Identifier: GPL-2.0-only */
/* Package G capacity contract: P11SCOPE_OWNER_SLOT_BOUND is
 * NATIVE_OWNER_SLOT_BOUND == MAX_SLOTS in the selected Detailed object. The lookup checks
 * (p11_owner_start_get/remove), the start-count bound (valid_owner,
 * p11_owner_start_insert) and the exec/exit cleanup loop (p11_owner_cleanup)
 * pin the same value; update them together or not at all. The
 * capacity_contract test suite enforces this. */
#include "task_owner.h"

struct {
    __uint(type, 29);
    __uint(map_flags, 1);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, struct thread_owner);
} THREAD_OWNER SEC(".maps");
struct {
    __uint(type, 2);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct owner_control);
} OWNER_CTL SEC(".maps");

/* Exact under contention: a non-fetch atomic add never loses an increment
 * (a single compare-exchange silently dropped it whenever another CPU won).
 * The result is never consumed, so it lowers to the non-fetch BPF atomic. */
static __always_inline void count(u64 *cell)
{
    if (*(volatile u64 *)cell != ~0ULL)
        __sync_fetch_and_add(cell, 1);
}

static __always_inline void poison(struct owner_control *ctl, u64 reason)
{
    __sync_fetch_and_or(&ctl->poison, reason);
    count(&ctl->reclamation_failures);
}

static __always_inline void bookkeeping(struct owner_control *ctl, u64 detail)
{
    poison(ctl, OWNER_BOOKKEEPING_FAILED | detail);
}

static __always_inline struct owner_control *control(void)
{
    u32 key = 0;
    struct owner_control *ctl = owner_map_lookup(&OWNER_CTL, &key);
    if (!ctl)
        return (void *)0;
    if (ctl->limit != OWNER_LIMIT || *(volatile u64 *)&ctl->outstanding > OWNER_CONTROL_BOUND) {
        poison(ctl, OWNER_BAD_CONTROL);
        return (void *)0;
    }
    return ctl;
}

static __always_inline int healthy(struct owner_control *ctl)
{
    return ctl && !*(volatile u64 *)&ctl->poison;
}

__attribute__((always_inline)) u32 p11_owner_healthy(void)
{
    return healthy(control());
}

/* Every non-nested PKCS#11 call reserves at entry and refunds at return, so
 * this one shared count is the hottest cell in the object. No step here may
 * fail because another CPU touched the count: a bounded compare-exchange loop
 * did, and its refund side poisoned the whole capture under ordinary
 * multi-threaded load. Both sides use non-fetch atomic adds whose results are
 * never consumed (the only atomic-add form this toolchain lowers correctly).
 *
 * Admission claims one unit and keeps it only if the count it then reads is
 * within the limit; otherwise it undoes exactly its own unit. Every kept claim
 * read a count including every other live kept claim, so kept claims never
 * exceed OWNER_LIMIT, while in-flight claims may transiently exceed it (see
 * OWNER_CONTROL_BOUND). */
static __always_inline int reserve_local(struct owner_control *ctl)
{
    if (*(volatile u64 *)&ctl->outstanding >= OWNER_LIMIT) {
        count(&ctl->admission_failures);
        return 0;
    }
    __sync_fetch_and_add(&ctl->outstanding, 1);
    if (*(volatile u64 *)&ctl->outstanding > OWNER_LIMIT) {
        __sync_fetch_and_add(&ctl->outstanding, (u64)-1);
        count(&ctl->admission_failures);
        return 0;
    }
    return 1;
}

/* The caller settles a lease it holds, so the count includes that lease and
 * cannot be zero unless the accounting is already broken: only that, never
 * contention, poisons. The pre-check never lets a refund wrap the count. */
static __always_inline int refund_local(struct owner_control *ctl)
{
    u64 old = *(volatile u64 *)&ctl->outstanding;
    if (!old || old > OWNER_CONTROL_BOUND) {
        poison(ctl, OWNER_REFUND_FAILED);
        return 0;
    }
    __sync_fetch_and_add(&ctl->outstanding, (u64)-1);
    return 1;
}

/* BPF global functions deliberately take no map-value pointers across their
 * ABI. Keeping the accounting out of its transaction callers gives older
 * verifiers one bounded state frontier per accounting operation. In the BPF
 * object the reservation is made inside p11_owner_lease (its one global
 * boundary), so this entry point is not exported there; the native owner
 * harness drives the same reserve_local body through it. */
__attribute__((noinline)) u32 p11_owner_reserve(void)
{
    struct owner_control *ctl = control();
    if (!ctl)
        return 0;
    return reserve_local(ctl);
}

/* Cleanup must be able to settle an existing lease after a terminal poison.
 * control() validates the frozen scalar bounds but healthy() is intentionally
 * not consulted here. */
__attribute__((noinline)) u32 p11_owner_refund(void)
{
    struct owner_control *ctl = control();
    if (!ctl)
        return 0;
    return refund_local(ctl);
}

/* The current task's owner row for key-binding by the journal
 * transactions: roots cannot name task storage, so this one global
 * boundary reads it. Returns the row (leased or idle) or NULL when
 * the task is gone or holds no row; callers validate before use
 * (never trusted, never consumed across probes). A returned task-
 * storage pointer is what map helpers return, so verifiers track it;
 * the body stays one task lookup plus one storage get. */
__attribute__((noinline)) struct thread_owner *p11_owner_current(void)
{
    struct task_struct *task = owner_current_task();
    if (!task)
        return (void *)0;
    return owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
}

static __always_inline int valid_owner(struct owner_control *ctl, struct thread_owner *owner)
{
    if (!*(volatile u64 *)&ctl->outstanding ||
        owner->flags != OWNER_LEASED || !owner->original_pid_tgid ||
#ifdef P11SCOPE_INVENTORY_ONLY
        owner->start_count != 0 ||
#else
        owner->start_count > P11SCOPE_OWNER_SLOT_BOUND ||
#endif
        (owner->selection_domains & ~owner->occupied)) {
        poison(ctl, OWNER_BAD_RECORD);
        return 0;
    }
    return 1;
}

/* The owner lease transaction as one global scalar boundary: the current task
 * ends up holding a valid leased owner (already leased, an idle retained one
 * re-leased, or a fresh one created), or nothing, with the refusal accounted.
 * Its create/reuse branches are explored once by the verifier instead of once
 * per caller path, which older verifiers (5.15) need to stay under their
 * instruction budget. No map-value pointer crosses its ABI. */
__attribute__((noinline)) u32 p11_owner_lease(void)
{
    struct owner_control *ctl = control();
    struct task_struct *task;
    struct thread_owner *owner;
    if (!ctl || !healthy(ctl))
        return 0;
    task = owner_current_task();
    if (!task) {
        poison(ctl, OWNER_LOOKUP_UNKNOWN);
        return 0;
    }
    owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
    if (owner && owner->flags)
        return valid_owner(ctl, owner);
    if (!reserve_local(ctl))
        return 0;
    if (!owner) {
        /* First call of this thread: NULL initialization requests
         * kernel-zeroed map storage, not a whole-struct stack argument. A
         * failed CREATE installed no new value for this lease. The storage
         * is then retained idle between calls, so this allocation (and its
         * RCU-deferred free) never recurs per call, where it could run the
         * allocator dry. */
        owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 1);
        if (!owner) {
            count(&ctl->admission_failures);
            refund_local(ctl);
            return 0;
        }
        if (owner->flags) {
            /* A busy initial probe may have hidden an existing owner. Its
             * lease and keys remain untouched; refund only our speculative
             * reservation. */
            if (!refund_local(ctl) || !valid_owner(ctl, owner))
                return 0;
            return healthy(ctl);
        }
        /* CREATE after a missed lookup can return existing idle
         * storage, which BPF cannot distinguish from fresh storage:
         * both read flags == 0 here. The zero loop below must clear
         * lease state either way, so the journal lifetime words are
         * stashed first and restored after: fresh storage restores
         * zeros (unminted), existing idle storage keeps its minted
         * words. Idle, poison and exec/exit paths never run this
         * loop; they clear lease state through release_empty while
         * the lifetime words persist. */
#ifndef P11SCOPE_INVENTORY_ONLY
        u64 journal_thread = owner->journal_thread;
        u64 journal_sequence = owner->journal_sequence;
#endif
        volatile u64 *words = (volatile u64 *)owner;
        for (u32 i = 0; i < sizeof(struct thread_owner) / 8; i++)
            words[i] = 0;
#ifndef P11SCOPE_INVENTORY_ONLY
        owner->journal_thread = journal_thread;
        owner->journal_sequence = journal_sequence;
#endif
    }
    /* A fresh or idle owner: current-task-only writers and frozen userspace
     * mutation are prerequisites. Idle means every field was cleared by the
     * release that returned its lease; anything else is a corrupt record. */
    if (owner->original_pid_tgid || owner->start_count || owner->occupied ||
        owner->selection_domains) {
        poison(ctl, OWNER_BAD_RECORD);
        refund_local(ctl);
        return 0;
    }
    owner->original_pid_tgid = owner_pid_tgid();
    owner->flags = OWNER_LEASED;
    return valid_owner(ctl, owner) && healthy(ctl);
}

static __always_inline struct thread_owner *get_owner(struct owner_control *ctl, int create)
{
    struct task_struct *task;
    struct thread_owner *owner;
    if (!healthy(ctl))
        return (void *)0;
    if (create && !p11_owner_lease())
        return (void *)0;
    task = owner_current_task();
    if (!task) {
        poison(ctl, OWNER_LOOKUP_UNKNOWN);
        return (void *)0;
    }
    owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
    if (owner && owner->flags)
        return valid_owner(ctl, owner) ? owner : (void *)0;
    if (!create) {
        /* An absent or idle owner holds no rows. This is refusal, never a
         * non-lifecycle absence certificate. No numeric-key lookup/deletion
         * or speculative refund follows a miss. */
        poison(ctl, OWNER_LOOKUP_UNKNOWN);
        return (void *)0;
    }
    /* The lease holds, but its owner is unreadable here (a busy task-storage
     * lookup). The lease stays with its idle rows and is settled by this
     * thread's next release or by exit cleanup; nothing is refunded twice. */
    count(&ctl->admission_failures);
    return (void *)0;
}

/* Return the lease of an owner that holds nothing. The storage is retained
 * idle (flags 0, all fields zero) instead of deleted: no per-call delete, no
 * per-call create on the next call. The discovery cells are already zero:
 * directory_clear zeroes each cell it frees. */
static __always_inline int release_empty(struct owner_control *ctl, struct thread_owner *owner)
{
    (void)ctl; /* The lease is returned through the bounded global refund. */
    if (owner->start_count || owner->occupied)
        return 1;
    owner->selection_domains = 0;
    owner->original_pid_tgid = 0;
    owner->flags = 0;
    return p11_owner_refund();
}

#ifndef P11SCOPE_INVENTORY_ONLY
static __always_inline int start_key_valid(struct thread_owner *owner,
                                          const struct owner_start_key *key)
{
    return key && key->slot < P11SCOPE_OWNER_SLOT_BOUND && !key->pad &&
        key->pid_tgid == owner->original_pid_tgid;
}

/* One aligned word from a START value. Map values and the BPF stack value
 * are 8-aligned and every call-site offset is a multiple of 8, so this is
 * a single load with no stack temporary; the host harness aligns its rows
 * the same way. */
static __always_inline u64 start_u64(const void *start_value, u32 offset)
{
    return *(const u64 *)((const unsigned char *)start_value + offset);
}

/* Mirror of object_wire::validate_start_marker against the frozen table: 0
 * ordinary, 1 required (index and action out), -1 invalid. */
static __always_inline int object_marker_verdict(u64 marker, u32 *index_out,
                                                 unsigned char *action_out)
{
    u32 row_key;
    const struct object_descriptor_row *row;
    if (!marker)
        return 0;
    /* Fused unsigned range checks: (v - lo) wraps huge exactly when v is
     * below lo, so one comparison covers both ends. Exact for every input;
     * each fused check saves one jump per sweep slot. */
    if (marker - 2 > OBJECT_DESCRIPTORS_COUNT - 2)
        return -1;
    row_key = (u32)(marker - 1);
    row = owner_map_lookup(&OBJECT_DESCRIPTORS, &row_key);
    if (!row)
        return -1;
    if (row->function != row_key - 1)
        return -1;
    if ((unsigned int)row->action - 1U > OBJECT_ACTION_MAX - 1U)
        return -1;
    if ((unsigned int)row->guard - 1U > OBJECT_GUARD_MAX - 1U)
        return -1;
    *index_out = row_key;
    *action_out = row->action;
    return 1;
}

/* The side row's immutable binding must equal the live START row: selected
 * descriptor, entry image and entry time. */
static __always_inline int object_binding_matches(const void *side, const void *start_value,
                                                  u32 index)
{
    const struct object_start *o = side;
    /* Xor-accumulated equality: exact (xor is zero iff equal), one jump
     * instead of three &&s. All reads are safe: both rows are validated
     * before this runs. */
    u64 diff = (u64)(o->descriptor_index ^ index);
    diff |= o->task_cookie ^ start_u64(start_value, OBJECT_CALL_START_IMAGE_OFF);
    diff |= o->exec_id ^ start_u64(start_value, OBJECT_CALL_START_IMAGE_OFF + 8);
    diff |= o->entry_ns ^ start_u64(start_value, OBJECT_CALL_START_TS_OFF);
    return diff == 0;
}

/* Zero a subordinate value before its deletion so no retained pointer or
 * length survives in a readable row, even when the deletion then fails. */
static __always_inline void object_scrub_side(void *side)
{
    volatile u64 *words = side;
    u32 i;
    /* Fixed 432-byte row: keep all volatile stores in order, without a
     * second verifier loop inside each of the 512-slot cleanup sweeps. */
#pragma clang loop unroll(full)
    for (i = 0; i < OBJECT_START_WORDS; i++)
        words[i] = 0;
}

/* Scrub then delete an identified side row. 0 deleted, -1 failed (poisoned,
 * the row is kept for retry). */
static __always_inline int object_side_delete(struct owner_control *ctl,
                                              const struct owner_start_key *key, void *side)
{
    object_scrub_side(side);
    if (owner_map_delete(&OBJECT_START, key)) {
        poison(ctl, OWNER_STATE_DELETE_FAILED);
        return -1;
    }
    return 0;
}

/* Settle one subordinate row for START removal. 0 means the side row is
 * settled (or healthily absent) and START deletion may proceed with a
 * success report. 1 means the side state contradicted its START
 * (bookkeeping recorded, identifiable storage scrubbed): the caller still
 * deletes START so no required row is orphaned, but reports failure. -1
 * means the side row could not be deleted: START is kept for retry. */
static __always_inline int object_side_for_remove(struct owner_control *ctl,
                                                  const void *start_value,
                                                  const struct owner_start_key *key)
{
    u32 index = 0;
    unsigned char action = 0;
    int verdict = object_marker_verdict(start_u64(start_value, OBJECT_CALL_START_MARKER_OFF),
                                        &index, &action);
    void *side = owner_map_lookup(&OBJECT_START, key);
    (void)action;
    if (verdict < 0) {
        if (side && object_side_delete(ctl, key, side))
            return -1;
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        return 1;
    }
    if (!verdict) {
        if (!side)
            return 0;
        if (object_side_delete(ctl, key, side))
            return -1;
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        return 1;
    }
    if (!side || !object_binding_matches(side, start_value, index)) {
        if (side && object_side_delete(ctl, key, side))
            return -1;
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        return 1;
    }
    if (((const struct object_start *)side)->phase != OBJECT_PHASE_ENTRY &&
        ((const struct object_start *)side)->phase != OBJECT_PHASE_READY &&
        ((const struct object_start *)side)->phase != OBJECT_PHASE_RETURNING) {
        if (object_side_delete(ctl, key, side))
            return -1;
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        return 1;
    }
    return object_side_delete(ctl, key, side) ? -1 : 0;
}

/* Roll back a START row this transaction just inserted. A failed deletion
 * keeps its count for teardown; otherwise the count and an emptied lease
 * are settled exactly as the ordinary insert failure path settles them. */
static __always_inline void object_rollback_insert(struct owner_control *ctl,
                                                   struct thread_owner *owner,
                                                   const struct owner_start_key *key)
{
    if (owner_map_delete(&START, key)) {
        poison(ctl, OWNER_STATE_DELETE_FAILED);
        return;
    }
    owner->start_count--;
    release_empty(ctl, owner);
}

/* Establish the subordinate side row for a required marker after the START
 * row was inserted. Ordinary markers need nothing. Any side failure rolls
 * back the START row and reports loss; the marker is never downgraded to
 * ordinary to hide it. */
static __always_inline long object_side_alloc(struct owner_control *ctl,
                                              struct thread_owner *owner,
                                              const struct owner_start_key *key,
                                              const void *value)
{
    u32 index = 0;
    unsigned char action = 0;
    int verdict = object_marker_verdict(start_u64(value, OBJECT_CALL_START_MARKER_OFF),
                                        &index, &action);
    u32 zero_key = 0;
    const volatile u64 *zero;
    struct object_start *side;
    long rc;
    u32 i;
    if (!verdict)
        return 0;
    if (verdict < 0) {
        object_rollback_insert(ctl, owner, key);
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        return -1;
    }
    zero = owner_map_lookup(&OBJECT_ZERO, &zero_key);
    if (!zero) {
        object_rollback_insert(ctl, owner, key);
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        return -1;
    }
    for (i = 0; i < OBJECT_START_WORDS; i++) {
        if (zero[i]) {
            object_rollback_insert(ctl, owner, key);
            bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
            return -1;
        }
    }
    rc = owner_map_update(&OBJECT_START, key, (const void *)zero, 1);
    if (rc) {
        object_rollback_insert(ctl, owner, key);
        /* A conflicting row is never replaced; any other failure is a
         * refused admission, not corruption. */
        if (rc == -17)
            bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        else
            count(&ctl->admission_failures);
        return rc;
    }
    side = owner_map_lookup(&OBJECT_START, key);
    if (!side) {
        /* H7-E2: readback miss after a successful insert rolls the orphan
         * side row back by this live transaction key (the held lease
         * proves it) instead of wedging the key until teardown. The row
         * still holds OBJECT_ZERO bytes (binding writes run after this
         * lookup), so no scrub is needed; -2 only means the row is already
         * gone. A failed orphan deletion keeps START, its count and its
         * lease (failed-deletion rows are always kept for retry, as in
         * object_side_for_remove): rolling back here would strand a
         * permanent zeroed row with its retry route settled away. */
        long orphan = owner_map_delete(&OBJECT_START, key);
        if (orphan && orphan != -2) {
            poison(ctl, OWNER_STATE_DELETE_FAILED);
            bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
            return -1;
        }
        object_rollback_insert(ctl, owner, key);
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        return -1;
    }
    /* Immutable descriptor/image/time binding; entry-in-progress phase. The
     * entry ABI is recorded by the entry probe through the query row once
     * this transaction succeeds. */
    side->descriptor_index = index;
    side->action = action;
    side->task_cookie = start_u64(value, OBJECT_CALL_START_IMAGE_OFF);
    side->exec_id = start_u64(value, OBJECT_CALL_START_IMAGE_OFF + 8);
    side->entry_ns = start_u64(value, OBJECT_CALL_START_TS_OFF);
    side->phase = OBJECT_PHASE_ENTRY;
    return 0;
}

#endif
/* An exact hash absence permits only an optional ordinary no-op. A readable
 * owner is still checked for contradictions. NULL here says nothing about
 * owner absence; no deletion/refund/bookkeeping settlement follows it. */
static __always_inline struct thread_owner *peek_absent_owner(struct owner_control *ctl)
{
    struct task_struct *task = owner_current_task();
    if (!task)
        return (void *)0;
    struct thread_owner *owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
    /* An idle owner is absence: it holds no lease and no rows. */
    return owner && owner->flags && valid_owner(ctl, owner) ? owner : (void *)0;
}

#ifndef P11SCOPE_INVENTORY_ONLY
__attribute__((noinline)) void *p11_owner_start_get(const struct owner_start_key *key, u32 required)
{
    struct owner_control *ctl = control();
    if (!healthy(ctl) || !key || key->slot >= P11SCOPE_OWNER_SLOT_BOUND || key->pad)
        return (void *)0;
    if (!required && !owner_map_lookup(&START, key)) {
        /* START count cannot identify which particular absent slot is owed. */
        peek_absent_owner(ctl);
        return (void *)0;
    }
    struct thread_owner *owner = get_owner(ctl, 0);
    if (!owner)
        return (void *)0;
    if (!start_key_valid(owner, key)) {
        bookkeeping(ctl, OWNER_START_KEY_MISMATCH);
        return (void *)0;
    }
    if (!owner->start_count) {
        bookkeeping(ctl, OWNER_START_COUNT_MISMATCH);
        return (void *)0;
    }
    void *value = owner_map_lookup(&START, key);
    if (!value)
        bookkeeping(ctl, OWNER_START_ROW_MISSING);
    return value;
}

static __always_inline long remove_start(struct owner_control *ctl, struct thread_owner *owner,
                                         const struct owner_start_key *key)
{
    void *start_value = owner_map_lookup(&START, key);
    int side;
    if (!start_value) {
        bookkeeping(ctl, OWNER_START_ROW_MISSING);
        return -1;
    }
    if (!owner->start_count) {
        bookkeeping(ctl, OWNER_START_COUNT_MISMATCH);
        return -1;
    }
    /* Subordinate custody retires with its START: scrub the side value,
     * delete it, then delete START and refund below. A contradicted side
     * row still retires its START (no orphaned required rows) but reports
     * failure; only a failed side deletion keeps START for retry. */
    side = object_side_for_remove(ctl, start_value, key);
    if (side < 0)
        return -1;
    long rc = owner_map_delete(&START, key);
    if (rc) {
        poison(ctl, OWNER_STATE_DELETE_FAILED);
        return rc;
    }
    owner->start_count--;
    /* Branchless nonzero-to--1: (s|-s) has bit63 set exactly when s != 0.
     * All-unsigned, so no overflow UB; a comparison would compile to a jump. */
    {
        unsigned long mag = (unsigned long)side | (0UL - (unsigned long)side);
        return -(long)(mag >> 63);
    }
}

__attribute__((noinline)) long p11_owner_start_remove(const struct owner_start_key *key, u32 required)
{
    struct owner_control *ctl = control();
    if (!healthy(ctl) || !key || key->slot >= P11SCOPE_OWNER_SLOT_BOUND || key->pad)
        return -1;
    if (!required && !owner_map_lookup(&START, key)) {
        peek_absent_owner(ctl);
        return healthy(ctl) ? -2 : -1;
    }
    struct thread_owner *owner = get_owner(ctl, 0);
    if (!owner)
        return -1;
    if (!start_key_valid(owner, key)) {
        bookkeeping(ctl, OWNER_START_KEY_MISMATCH);
        return -1;
    }
    long rc = remove_start(ctl, owner, key);
    if (rc) {
        /* A contradicted side row still retired its START above; settle an
         * emptied lease while reporting the failure. A kept row (a failed
         * deletion) leaves the lease untouched for retry. */
        release_empty(ctl, owner);
        return rc;
    }
    if (!release_empty(ctl, owner))
        return -1;
    return rc;
}

__attribute__((noinline)) long p11_owner_start_insert(const struct owner_start_key *key, const void *value)
{
    struct owner_control *ctl = control();
    struct thread_owner *owner = get_owner(ctl, 1);
    if (!owner)
        return -1;
    if (!start_key_valid(owner, key) || !value) {
        count(&ctl->admission_failures);
        release_empty(ctl, owner);
        return -1;
    }
    if (owner->start_count >= P11SCOPE_OWNER_SLOT_BOUND) {
        /* At the slot bound a nested entry still invalidates its own old
         * invocation. Do not leave it available for an ambiguous return. */
        count(&ctl->admission_failures);
        remove_start(ctl, owner, key);
        return -1;
    }
    owner->start_count++;
    long rc = owner_map_update(&START, key, value, 1);
    if (!rc)
        return object_side_alloc(ctl, owner, key, value);
    owner->start_count--;
    count(&ctl->admission_failures);
    /* NOEXIST ambiguity invalidates only a record under this physical owner.
     * A collision with an empty owner is uncertainty, never numeric authority. */
    if (owner_map_lookup(&START, key))
        remove_start(ctl, owner, key);
    release_empty(ctl, owner);
    return rc;
}

/* Construct START directly in owned map storage. The zero source is larger
 * than START, but the START map's fixed value size copies exactly 288 bytes.
 * Final timestamp/image/marker precede subordinate allocation, so every
 * checked side query sees the original immutable binding. The pointer never
 * escapes an incomplete or rolled-back transaction. */
static __always_inline void *begin_owned_start(const struct owner_start_key *key,
                                               const struct call_start_seed *seed,
                                               u64 aggregate_ts, u32 aggregate)
{
    struct owner_control *ctl = control();
    struct thread_owner *owner = get_owner(ctl, 1);
    u32 zero_key = 0;
    const volatile u64 *zero;
    unsigned char *value;
    long rc;
    if (!owner)
        return (void *)0;
    if (!start_key_valid(owner, key) || (!aggregate && (!seed || !seed->task_cookie))) {
        count(&ctl->admission_failures);
        release_empty(ctl, owner);
        return (void *)0;
    }
    if (owner->start_count >= P11SCOPE_OWNER_SLOT_BOUND) {
        count(&ctl->admission_failures);
        remove_start(ctl, owner, key);
        return (void *)0;
    }
    zero = owner_map_lookup(&OBJECT_ZERO, &zero_key);
    if (!zero) {
        bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
        release_empty(ctl, owner);
        return (void *)0;
    }
    for (u32 i = 0; i < OBJECT_START_WORDS; i++) {
        if (zero[i]) {
            bookkeeping(ctl, OWNER_OBJECT_MISMATCH);
            release_empty(ctl, owner);
            return (void *)0;
        }
    }
    owner->start_count++;
    rc = owner_map_update(&START, key, (const void *)zero, 1);
    if (rc) {
        owner->start_count--;
        count(&ctl->admission_failures);
        /* Preserve the existing physical-owner NOEXIST ambiguity rule. */
        if (owner_map_lookup(&START, key))
            remove_start(ctl, owner, key);
        release_empty(ctl, owner);
        return (void *)0;
    }
    value = owner_map_lookup(&START, key);
    if (!value) {
        /* This transaction owns the newly inserted key even if readback
         * failed. Failed deletion keeps count/lease for teardown retry. */
        object_rollback_insert(ctl, owner, key);
        bookkeeping(ctl, OWNER_START_ROW_MISSING);
        return (void *)0;
    }
    *(u64 *)(value + OBJECT_CALL_START_TS_OFF) = aggregate ? aggregate_ts : seed->ts_ns;
    if (!aggregate) {
        *(u64 *)(value + OBJECT_CALL_START_IMAGE_OFF) = seed->task_cookie;
        *(u64 *)(value + OBJECT_CALL_START_IMAGE_OFF + 8) = seed->exec_id;
        *(u64 *)(value + OBJECT_CALL_START_MARKER_OFF) = seed->object_required;
        if (object_side_alloc(ctl, owner, key, value))
            return (void *)0;
    }
    return value;
}

__attribute__((noinline)) void *p11_owner_start_begin(const struct owner_start_key *key,
                                                     const struct call_start_seed *seed)
{
    return begin_owned_start(key, seed, 0, 0);
}

/* Aggregate has no image or semantic marker. Its fixed scalar wrapper shares
 * accounting/rollback but never mints identity or allocates a side row. */
__attribute__((noinline)) u32 p11_owner_start_aggregate(const struct owner_start_key *key,
                                                       u64 timestamp)
{
    return begin_owned_start(key, (void *)0, timestamp, 1) != (void *)0;
}

/* Validated live subordinate row, or NULL. This query validates but records
 * nothing itself, so a following retire is never blocked by the query's own
 * poison (only the shared owner lookup may record lookup failure, as on all
 * owner paths). Every caller MUST follow with p11_owner_start_remove on the
 * same key in the same probe: the return drain queries with required=0,
 * checks attached-descriptor and retained-ABI agreement itself, then
 * retires through the ordinary removal (which re-validates marker, side
 * and binding and records once): query plus retire is the drain, in one
 * task with no interleaving mutation. Entry records the retained ABI
 * through this row and abandons through the same removal; return-phase
 * fill queries with required=1. Both modes require bound custody when a
 * row is claimed: the marker is required, the binding matches the live
 * START, and the phase is sane (entry, ready or returning). required=1
 * additionally requires ready: only ready authorizes reads. A healthy
 * ordinary call has no side row: quiet NULL, unless a side row leaked onto
 * it. Attached descriptor disagreement and non-ready phases refuse quietly
 * (per-call loss, not corruption). An absent row under required=0 is a
 * quiet NULL after the same absent-owner inspection the START get
 * performs. */
__attribute__((noinline)) void *p11_object_side_get(const struct owner_start_key *key,
                                                    u32 descriptor, u32 required)
{
    struct owner_control *ctl = control();
    struct thread_owner *owner;
    void *start_value;
    void *side;
    u32 index = 0;
    unsigned char action = 0;
    unsigned char phase;
    if (!healthy(ctl) || !key || key->slot >= P11SCOPE_OWNER_SLOT_BOUND || key->pad)
        return (void *)0;
    if (!required && !owner_map_lookup(&OBJECT_START, key)) {
        /* START count cannot identify which particular absent slot is owed. */
        peek_absent_owner(ctl);
        return (void *)0;
    }
    owner = get_owner(ctl, 0);
    if (!owner)
        return (void *)0;
    if (!start_key_valid(owner, key))
        return (void *)0;
    start_value = owner_map_lookup(&START, key);
    if (!start_value)
        return (void *)0;
    {
        int verdict = object_marker_verdict(start_u64(start_value, OBJECT_CALL_START_MARKER_OFF),
                                            &index, &action);
        if (verdict < 0)
            return (void *)0;
        if (!verdict)
            return (void *)0;
    }
    /* Attached-descriptor disagreement is per-call loss, not corruption:
     * refuse quietly and let the caller fault. */
    if (index != descriptor)
        return (void *)0;
    side = owner_map_lookup(&OBJECT_START, key);
    if (!side || !object_binding_matches(side, start_value, index))
        return (void *)0;
    phase = ((const struct object_start *)side)->phase;
    if (phase != OBJECT_PHASE_ENTRY && phase != OBJECT_PHASE_READY &&
        phase != OBJECT_PHASE_RETURNING)
        return (void *)0;
    if (required && phase != OBJECT_PHASE_READY)
        return (void *)0;
    return side;
}

#endif
static __always_inline int discovery_key_valid(struct thread_owner *owner,
                                               const struct owner_discovery_key *key)
{
    return key && key->pid_tgid == owner->original_pid_tgid &&
        (key->domain == 1 || key->domain == 2);
}

static __always_inline int directory_find(struct thread_owner *owner,
                                         const struct owner_discovery_key *key)
{
    for (u32 i = 0; i < 64; i++) {
        u64 bit = 1ULL << i;
        if ((owner->occupied & bit) && owner->discovery_cookies[i] == key->cookie &&
            ((owner->selection_domains & bit) != 0) == (key->domain == 2))
            return (int)i;
    }
    return -1;
}

static __always_inline void directory_clear(struct thread_owner *owner, u32 index)
{
    if (index < 64) {
        u64 bit = 1ULL << index;
        owner->occupied &= ~bit;
        owner->selection_domains &= ~bit;
        owner->discovery_cookies[index] = 0;
    }
}

static __always_inline void inspect_absent_discovery(struct owner_control *ctl,
                                                     const struct owner_discovery_key *key)
{
    struct thread_owner *owner = peek_absent_owner(ctl);
    if (owner && discovery_key_valid(owner, key) && directory_find(owner, key) >= 0)
        bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
}

__attribute__((noinline)) void *p11_owner_discovery_get(const struct owner_discovery_key *key, u32 required)
{
    struct owner_control *ctl = control();
    if (!healthy(ctl) || !key || (key->domain != 1 && key->domain != 2))
        return (void *)0;
    if (!required && !owner_map_lookup(&DISCOVERY_STATE, key)) {
        inspect_absent_discovery(ctl, key);
        return (void *)0;
    }
    struct thread_owner *owner = get_owner(ctl, 0);
    if (!owner)
        return (void *)0;
    if (!discovery_key_valid(owner, key) || directory_find(owner, key) < 0) {
        bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
        return (void *)0;
    }
    void *value = owner_map_lookup(&DISCOVERY_STATE, key);
    if (!value)
        bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
    return value;
}

static __always_inline long remove_discovery(struct owner_control *ctl,
                                             struct thread_owner *owner,
                                             const struct owner_discovery_key *key,
                                             u32 index)
{
    long rc = owner_map_delete(&DISCOVERY_STATE, key);
    if (rc) {
        poison(ctl, OWNER_STATE_DELETE_FAILED);
        return rc == -2 ? -1 : rc;
    }
    directory_clear(owner, index);
    return 0;
}

__attribute__((noinline)) long p11_owner_discovery_remove(const struct owner_discovery_key *key, u32 required)
{
    struct owner_control *ctl = control();
    if (!healthy(ctl) || !key || (key->domain != 1 && key->domain != 2))
        return -1;
    if (!required && !owner_map_lookup(&DISCOVERY_STATE, key)) {
        inspect_absent_discovery(ctl, key);
        return healthy(ctl) ? -2 : -1;
    }
    struct thread_owner *owner = get_owner(ctl, 0);
    if (!owner)
        return -1;
    if (!discovery_key_valid(owner, key)) {
        bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
        return -1;
    }
    int index = directory_find(owner, key);
    if (index < 0) {
        bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
        return -1;
    }
    long rc = remove_discovery(ctl, owner, key, (u32)index);
    if (rc)
        return rc;
    if (!release_empty(ctl, owner))
        return -1;
    return rc;
}

__attribute__((noinline)) long p11_owner_discovery_insert(const struct owner_discovery_key *key,
                                 const void *value, u64 flags)
{
    struct owner_control *ctl = control();
    struct thread_owner *owner = get_owner(ctl, flags == 1);
    if (!owner)
        return -1;
    if (!discovery_key_valid(owner, key) || !value || (flags != 1 && flags != 2)) {
        count(&ctl->admission_failures);
        release_empty(ctl, owner);
        return -1;
    }
    int index = directory_find(owner, key);
    if (index >= 0) {
        if (flags == 2) {
            long rc = owner_map_update(&DISCOVERY_STATE, key, value, 2);
            if (rc) {
                count(&ctl->admission_failures);
                if (rc == -2)
                    bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
            }
            return rc;
        }
        count(&ctl->admission_failures);
        remove_discovery(ctl, owner, key, (u32)index);
        release_empty(ctl, owner);
        return -17;
    }
    if (flags == 2) {
        bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
        return -1;
    }
    for (u32 i = 0; i < 64; i++) {
        u64 bit = 1ULL << i;
        if (owner->occupied & bit)
            continue;
        owner->discovery_cookies[i] = key->cookie;
        owner->occupied |= bit;
        if (key->domain == 2)
            owner->selection_domains |= bit;
        long rc = owner_map_update(&DISCOVERY_STATE, key, value, 1);
        if (!rc)
            return 0;
        directory_clear(owner, i);
        count(&ctl->admission_failures);
        /* An unindexed numeric collision cannot authorize its deletion. */
        if (owner_map_lookup(&DISCOVERY_STATE, key))
            bookkeeping(ctl, OWNER_DIRECTORY_MISMATCH);
        release_empty(ctl, owner);
        return rc;
    }
    count(&ctl->admission_failures);
    return -1;
}

/* Called ONLY by the mandatory current-task raw exec/exit hooks. The actual
 * atomic CAS0->0 is the linearization point, not a plain or cached load.
 * Returns 0 for healthy proven cleanup (or a healthy no-op) and 1 for
 * failure or unproven cleanup. Poison is never cleared and a failed
 * release is never masked: settling rows after poison still reports 1. */
__attribute__((noinline)) u32 p11_owner_cleanup(void)
{
    struct owner_control *ctl = control();
    if (!ctl)
        return 1;
    if (__sync_val_compare_and_swap(&ctl->outstanding, 0, 0) == 0)
        return healthy(ctl) ? 0 : 1;
    struct task_struct *task = owner_current_task();
    if (!task) {
        poison(ctl, OWNER_LOOKUP_UNKNOWN);
        return 1;
    }
    struct thread_owner *owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
    if (!owner) {
        long rc = owner_storage_delete(&THREAD_OWNER, task);
        if (rc != -2)
            poison(ctl, OWNER_CLASSIFIER_FAILED);
        return healthy(ctl) ? 0 : 1;
    }
    /* An idle owner holds no lease, rows or directory cells: nothing to
     * settle. Its storage stays with the task (exec) or is freed with it (exit). */
    if (!owner->flags && !owner->original_pid_tgid && !owner->start_count &&
        !owner->occupied && !owner->selection_domains)
        return healthy(ctl) ? 0 : 1;
    if (!valid_owner(ctl, owner))
        return 1;
#ifndef P11SCOPE_INVENTORY_ONLY
    struct owner_start_key start = { .pid_tgid = owner->original_pid_tgid, .slot = 0, .pad = 0 };
    for (u32 i = 0; i < P11SCOPE_OWNER_SLOT_BOUND; i++) {
        start.slot = i;
        if (owner_map_lookup(&START, &start)) {
            long rc = remove_start(ctl, owner, &start);
            /* Retirement is tested directly (no materialized flag): one
             * jump per slot. No carried accumulator: per-iteration
             * scalars multiply verifier states instead. */
            if (!owner_map_lookup(&START, &start)) {
                count(&ctl->abandoned_start);
                /* A contradicted row still retired: settle an emptied
                 * lease instead of stranding it until the next hook. The
                 * success path releases once below. */
                if (rc)
                    release_empty(ctl, owner);
            }
            if (rc)
                return 1;
        }
    }
    if (owner->start_count) {
        bookkeeping(ctl, OWNER_START_COUNT_MISMATCH);
        return 1;
    }
    /* Orphaned side rows (START gone without its subordinate) hold no live
     * call; scrub and delete them under these proven retained keys. A bare
     * numeric key never authorizes this sweep. Inline by design: no
     * carried accumulator (per-iteration scalars multiply verifier
     * states) and no outlined worker (no verification gain). */
    for (u32 i = 0; i < P11SCOPE_OWNER_SLOT_BOUND; i++) {
        void *orphan;
        start.slot = i;
        orphan = owner_map_lookup(&OBJECT_START, &start);
        if (orphan) {
            object_scrub_side(orphan);
            if (owner_map_delete(&OBJECT_START, &start)) {
                poison(ctl, OWNER_STATE_DELETE_FAILED);
                return 1;
            }
            count(&ctl->abandoned_start);
        }
    }
#endif
    struct owner_discovery_key key = { .pid_tgid = owner->original_pid_tgid };
    for (u32 i = 0; i < 64; i++) {
        u64 bit = 1ULL << i;
        if (!(owner->occupied & bit))
            continue;
        key.cookie = owner->discovery_cookies[i];
        key.domain = (owner->selection_domains & bit) ? 2 : 1;
        if (remove_discovery(ctl, owner, &key, i))
            return 1;
        count(&ctl->abandoned_discovery);
    }
    if (!release_empty(ctl, owner))
        return 1;
    return healthy(ctl) ? 0 : 1;
}
