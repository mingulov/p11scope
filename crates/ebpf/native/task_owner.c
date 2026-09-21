/* SPDX-License-Identifier: GPL-2.0-only */
/* Package G capacity contract: the 512 slot literal below is
 * NATIVE_OWNER_SLOT_BOUND == MAX_SLOTS. The lookup checks
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

static __always_inline void count(u64 *cell)
{
    u64 old = *(volatile u64 *)cell;
    if (old != ~0ULL)
        __sync_val_compare_and_swap(cell, old, old + 1);
}

static __always_inline void poison(struct owner_control *ctl, u64 reason)
{
    __sync_fetch_and_or(&ctl->poison, reason);
    count(&ctl->reclamation_failures);
}

static __always_inline struct owner_control *control(void)
{
    u32 key = 0;
    struct owner_control *ctl = owner_map_lookup(&OWNER_CTL, &key);
    if (!ctl)
        return (void *)0;
    if (ctl->limit != OWNER_LIMIT || ctl->outstanding > OWNER_LIMIT) {
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

static __always_inline int reserve_local(struct owner_control *ctl)
{
#pragma unroll
    for (int i = 0; i < OWNER_CAS_TRIES; i++) {
        u64 old = *(volatile u64 *)&ctl->outstanding;
        if (old >= OWNER_LIMIT)
            break;
        if (__sync_val_compare_and_swap(&ctl->outstanding, old, old + 1) == old)
            return 1;
    }
    count(&ctl->admission_failures);
    return 0;
}

static __always_inline int refund_local(struct owner_control *ctl)
{
#pragma unroll
    for (int i = 0; i < OWNER_CAS_TRIES; i++) {
        u64 old = *(volatile u64 *)&ctl->outstanding;
        if (!old || old > OWNER_LIMIT)
            break;
        if (__sync_val_compare_and_swap(&ctl->outstanding, old, old - 1) == old)
            return 1;
    }
    poison(ctl, OWNER_REFUND_FAILED);
    return 0;
}

/* BPF global functions deliberately take no map-value pointers across their
 * ABI. Keeping these retry loops out of their transaction callers gives older
 * verifiers one bounded state frontier per accounting operation. */
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

static __always_inline int valid_owner(struct owner_control *ctl, struct thread_owner *owner)
{
    if (!*(volatile u64 *)&ctl->outstanding ||
        owner->flags != OWNER_LEASED || !owner->original_pid_tgid ||
        owner->start_count > 512 || (owner->selection_domains & ~owner->occupied)) {
        poison(ctl, OWNER_BAD_RECORD);
        return 0;
    }
    return 1;
}

static __always_inline struct thread_owner *get_owner(struct owner_control *ctl, int create)
{
    struct task_struct *task;
    struct thread_owner *owner;
    if (!healthy(ctl))
        return (void *)0;
    task = owner_current_task();
    if (!task) {
        poison(ctl, OWNER_LOOKUP_UNKNOWN);
        return (void *)0;
    }
    owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
    if (owner)
        return valid_owner(ctl, owner) ? owner : (void *)0;
    if (!create) {
        /* This is refusal, never a non-lifecycle absence certificate. No
         * numeric-key lookup/deletion or speculative refund follows a miss. */
        poison(ctl, OWNER_LOOKUP_UNKNOWN);
        return (void *)0;
    }
    if (!p11_owner_reserve())
        return (void *)0;
    /* NULL initialization requests kernel-zeroed map storage, not a 544-byte
     * stack argument. A failed CREATE installed no new value for this lease. */
    owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 1);
    if (!owner) {
        count(&ctl->admission_failures);
        p11_owner_refund();
        return (void *)0;
    }
    if (owner->flags) {
        /* A busy initial probe may have hidden an existing owner. Its lease
         * and keys remain untouched; refund only our speculative reservation. */
        if (!p11_owner_refund() || !valid_owner(ctl, owner))
            return (void *)0;
        return healthy(ctl) ? owner : (void *)0;
    }
    /* Current-task-only writers and frozen userspace mutation are prerequisites.
     * Initialize the newly created value in place, including all directory cells. */
    volatile u64 *words = (volatile u64 *)owner;
    for (u32 i = 0; i < 68; i++)
        words[i] = 0;
    owner->original_pid_tgid = owner_pid_tgid();
    owner->flags = OWNER_LEASED;
    return valid_owner(ctl, owner) && healthy(ctl) ? owner : (void *)0;
}

static __always_inline int release_empty(struct owner_control *ctl, struct thread_owner *owner)
{
    if (owner->start_count || owner->occupied)
        return 1;
    if (owner_storage_delete(&THREAD_OWNER, owner_current_task()) != 0) {
        poison(ctl, OWNER_DELETE_FAILED);
        return 0;
    }
    /* owner is invalid after successful deletion. Refund only now. */
    return p11_owner_refund();
}

static __always_inline int start_key_valid(struct thread_owner *owner,
                                          const struct owner_start_key *key)
{
    return key && key->slot < 512 && !key->pad &&
        key->pid_tgid == owner->original_pid_tgid;
}

/* An exact hash absence permits only an optional ordinary no-op. A readable
 * owner is still checked for contradictions. NULL here says nothing about
 * owner absence; no deletion/refund/bookkeeping settlement follows it. */
static __always_inline struct thread_owner *peek_absent_owner(struct owner_control *ctl)
{
    struct task_struct *task = owner_current_task();
    if (!task)
        return (void *)0;
    struct thread_owner *owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
    return owner && valid_owner(ctl, owner) ? owner : (void *)0;
}

__attribute__((noinline)) void *p11_owner_start_get(const struct owner_start_key *key, u32 required)
{
    struct owner_control *ctl = control();
    if (!healthy(ctl) || !key || key->slot >= 512 || key->pad)
        return (void *)0;
    if (!required && !owner_map_lookup(&START, key)) {
        /* START count cannot identify which particular absent slot is owed. */
        peek_absent_owner(ctl);
        return (void *)0;
    }
    struct thread_owner *owner = get_owner(ctl, 0);
    if (!owner)
        return (void *)0;
    if (!start_key_valid(owner, key) || !owner->start_count) {
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
        return (void *)0;
    }
    void *value = owner_map_lookup(&START, key);
    if (!value)
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
    return value;
}

static __always_inline long remove_start(struct owner_control *ctl, struct thread_owner *owner,
                                         const struct owner_start_key *key)
{
    if (!owner_map_lookup(&START, key)) {
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
        return -1;
    }
    if (!owner->start_count) {
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
        return -1;
    }
    long rc = owner_map_delete(&START, key);
    if (rc) {
        poison(ctl, OWNER_STATE_DELETE_FAILED);
        return rc;
    }
    owner->start_count--;
    return 0;
}

__attribute__((noinline)) long p11_owner_start_remove(const struct owner_start_key *key, u32 required)
{
    struct owner_control *ctl = control();
    if (!healthy(ctl) || !key || key->slot >= 512 || key->pad)
        return -1;
    if (!required && !owner_map_lookup(&START, key)) {
        peek_absent_owner(ctl);
        return healthy(ctl) ? -2 : -1;
    }
    struct thread_owner *owner = get_owner(ctl, 0);
    if (!owner)
        return -1;
    if (!start_key_valid(owner, key)) {
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
        return -1;
    }
    long rc = remove_start(ctl, owner, key);
    if (rc)
        return rc;
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
    if (owner->start_count >= 512) {
        /* At the slot bound a nested entry still invalidates its own old
         * invocation. Do not leave it available for an ambiguous return. */
        count(&ctl->admission_failures);
        remove_start(ctl, owner, key);
        return -1;
    }
    owner->start_count++;
    long rc = owner_map_update(&START, key, value, 1);
    if (!rc)
        return 0;
    owner->start_count--;
    count(&ctl->admission_failures);
    /* NOEXIST ambiguity invalidates only a record under this physical owner.
     * A collision with an empty owner is uncertainty, never numeric authority. */
    if (owner_map_lookup(&START, key))
        remove_start(ctl, owner, key);
    release_empty(ctl, owner);
    return rc;
}

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
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
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
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
        return (void *)0;
    }
    void *value = owner_map_lookup(&DISCOVERY_STATE, key);
    if (!value)
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
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
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
        return -1;
    }
    int index = directory_find(owner, key);
    if (index < 0) {
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
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
                    poison(ctl, OWNER_BOOKKEEPING_FAILED);
            }
            return rc;
        }
        count(&ctl->admission_failures);
        remove_discovery(ctl, owner, key, (u32)index);
        release_empty(ctl, owner);
        return -17;
    }
    if (flags == 2) {
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
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
            poison(ctl, OWNER_BOOKKEEPING_FAILED);
        release_empty(ctl, owner);
        return rc;
    }
    count(&ctl->admission_failures);
    return -1;
}

/* Called ONLY by the mandatory current-task raw exec/exit hooks. The actual
 * atomic CAS0->0 is the linearization point, not a plain or cached load. */
__attribute__((noinline)) void p11_owner_cleanup(void)
{
    struct owner_control *ctl = control();
    if (!ctl)
        return;
    if (__sync_val_compare_and_swap(&ctl->outstanding, 0, 0) == 0)
        return;
    struct task_struct *task = owner_current_task();
    if (!task) {
        poison(ctl, OWNER_LOOKUP_UNKNOWN);
        return;
    }
    struct thread_owner *owner = owner_storage_get(&THREAD_OWNER, task, (void *)0, 0);
    if (!owner) {
        long rc = owner_storage_delete(&THREAD_OWNER, task);
        if (rc != -2)
            poison(ctl, OWNER_CLASSIFIER_FAILED);
        return;
    }
    if (!valid_owner(ctl, owner))
        return;
    struct owner_start_key start = { .pid_tgid = owner->original_pid_tgid, .slot = 0, .pad = 0 };
    for (u32 i = 0; i < 512; i++) {
        start.slot = i;
        if (owner_map_lookup(&START, &start)) {
            if (remove_start(ctl, owner, &start))
                return;
            count(&ctl->abandoned_start);
        }
    }
    if (owner->start_count) {
        poison(ctl, OWNER_BOOKKEEPING_FAILED);
        return;
    }
    struct owner_discovery_key key = { .pid_tgid = owner->original_pid_tgid };
    for (u32 i = 0; i < 64; i++) {
        u64 bit = 1ULL << i;
        if (!(owner->occupied & bit))
            continue;
        key.cookie = owner->discovery_cookies[i];
        key.domain = (owner->selection_domains & bit) ? 2 : 1;
        if (remove_discovery(ctl, owner, &key, i))
            return;
        count(&ctl->abandoned_discovery);
    }
    release_empty(ctl, owner);
}
