/* SPDX-License-Identifier: GPL-2.0-only */
#include "image_identity.h"

#ifdef IMAGE_HOST_CAS_HOOK
/* Host-only contention hook: while image_cas_fail_all is set, every
 * identity saturating-counter CAS fails so the exhaustion twin can
 * prove settled updates still land through the fallback and every
 * unsettled update reports. Ticket-issue and fold-mark CAS stay real;
 * only counting-cell CAS routes through this wrapper. Never defined
 * for BPF. */
int image_cas_fail_all = 0;
static __always_inline u64 image_sat_cas(u64 *ptr, u64 old, u64 desired)
{
    if (image_cas_fail_all)
        return old ^ 1;
    return __sync_val_compare_and_swap(ptr, old, desired);
}
#endif

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, u64);
} TASK_COOKIE SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct control);
} COOKIE_CTL SEC(".maps");

#ifdef P11SCOPE_LOADER_GATE
/* Production bank B: same shapes as bank A. The proof's B ticket maps
 * extern to these once the gate define is on, so proof issues feed
 * the shared watermarks the L4b producer sums. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, u64);
} TASK_COOKIE_B SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct control);
} COOKIE_CTL_B SEC(".maps");

/* The SELECT flip word: current bank plus prepared bits and the L4b
 * image cells. Single-word flip needs no torn-read recheck; the
 * prepared bits are write-once per bank in the single-cut design. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct image_bank_select);
} IMAGE_BANK_SELECT SEC(".maps");
#endif

struct cookie_result {
    u64 cookie;
    u64 incarnation;
    u32 status;
    u32 bank;
};

static __always_inline struct control *get_control(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&COOKIE_CTL, &key);
}

#ifndef P11SCOPE_LOADER_GATE
/* Exact under contention: a non-fetch atomic add (result never consumed)
 * never drops an increment the way a single lost compare-exchange did.
 * Single-bank legacy builds only; bank builds count through the
 * bounded saturating protocol above. */
static __always_inline void finite_increment(u64 *counter)
{
    if (*(volatile u64 *)counter != U64_MAX_VALUE)
        __sync_fetch_and_add(counter, 1);
}
#endif

#ifdef P11SCOPE_LOADER_GATE
static __always_inline struct image_bank_select *bank_select_word(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&IMAGE_BANK_SELECT, &key);
}

/* Bounded identity accounting, mirroring the loader gate: 8 CAS tries
 * settle every counting-cell update; the fallback below tolerates
 * fewer than 1024 in-flight unit adds plus the at most two in-flight
 * fold retires (one per bank, each claim-CAS-exclusive). */
#define IMAGE_SAT_HEADROOM 65536

#ifdef IMAGE_HOST_CAS_HOOK
#define IMAGE_SAT_CAS image_sat_cas
#else
#define IMAGE_SAT_CAS(ptr, old, desired) __sync_val_compare_and_swap(ptr, old, desired)
#endif

/* Report an identity-accounting update the bounded protocol could not
 * settle. Saturates like every other cell; a report skipped within
 * headroom of the ceiling needs 2^64 prior contention events and stays
 * undisclosed beyond this comment. */
static __always_inline void identity_report_loss(struct image_bank_select *select)
{
    u64 *losses = &select->update_losses;
    u64 old, seen = 0;
    int tries;

    for (tries = 0; tries < COOKIE_CAS_TRIES; tries++) {
        old = *(volatile u64 *)losses;
        seen = old;
        if (old == U64_MAX_VALUE)
            return;
        if (IMAGE_SAT_CAS(losses, old, old + 1) == old)
            return;
    }
    if (seen < U64_MAX_VALUE - IMAGE_SAT_HEADROOM)
        __sync_fetch_and_add(losses, 1);
}

/* Saturating increment. Returns 1 with the exact post-increment value
 * when the increment lands (CAS winner or headroom fallback); returns
 * 0 with the saturated ceiling when the cell already saturates or the
 * near-ceiling update skips (the skip reports through update_losses,
 * never wraps, never vanishes). */
static __always_inline int identity_sat_inc(struct image_bank_select *select, u64 *cell,
                                            u64 *out)
{
    u64 old, seen = 0;
    int tries;

    for (tries = 0; tries < COOKIE_CAS_TRIES; tries++) {
        old = *(volatile u64 *)cell;
        seen = old;
        if (old == U64_MAX_VALUE) {
            *out = old;
            return 0;
        }
        if (IMAGE_SAT_CAS(cell, old, old + 1) == old) {
            *out = old + 1;
            return 1;
        }
    }
    /* Exhausted: every failure is another thread's success. With
     * headroom below the ceiling the single fallback add cannot reach
     * the maximum; within headroom of the ceiling skip and report. */
    if (seen < U64_MAX_VALUE - IMAGE_SAT_HEADROOM) {
        *out = __sync_fetch_and_add(cell, 1) + 1;
        return 1;
    }
    identity_report_loss(select);
    *out = U64_MAX_VALUE;
    return 0;
}

/* Counting-cell increment for callers that need no post-value. */
static __always_inline void identity_count(struct image_bank_select *select, u64 *cell)
{
    u64 out = 0;

    identity_sat_inc(select, cell, &out);
}

/* Saturating add of a fold retire amount (at most one bank budget, so
 * the headroom check below cannot underflow). Same settle/report
 * contract as the increment; the proposal clamps at the ceiling so a
 * retire past the maximum saturates instead of wrapping. */
static __always_inline void identity_add(struct image_bank_select *select, u64 *cell,
                                         u64 amount)
{
    u64 old, seen = 0, proposed;
    int tries;

    for (tries = 0; tries < COOKIE_CAS_TRIES; tries++) {
        old = *(volatile u64 *)cell;
        seen = old;
        if (old == U64_MAX_VALUE)
            return;
        proposed = (old > U64_MAX_VALUE - amount) ? U64_MAX_VALUE : old + amount;
        if (IMAGE_SAT_CAS(cell, old, proposed) == old)
            return;
    }
    if (seen <= U64_MAX_VALUE - amount - IMAGE_SAT_HEADROOM) {
        __sync_fetch_and_add(cell, amount);
        return;
    }
    identity_report_loss(select);
}

/* A control row usable for issuance accounting: published limit with a
 * watermark inside the budget. Missing or corrupt rows fail closed. */
static __always_inline int bank_control_valid(struct control *control)
{
    if (!control)
        return 0;
    return control->limit == IMAGE_IDENTITY_TICKET_LIMIT &&
        control->next_ticket <= IMAGE_IDENTITY_TICKET_LIMIT;
}

/* Fold the claimed bank exactly once: the folded-CAS winner retires
 * the frozen watermark into folded_issued and counts the fold. Empty
 * banks are fresh (never a fold); corrupt or missing controls defer
 * the fold to a later admission. The Session's drain proof (no
 * in-flight selectors of the claimed bank) keeps next_ticket frozen
 * from the claim, so the single read retires exactly. */
static __always_inline void identity_help_fold(struct image_bank_select *select,
                                               struct control *controls[2])
{
#pragma unroll
    for (u32 slot = 0; slot < IMAGE_BANK_SLOTS; slot++) {
        struct control *control = controls[slot];
        u64 retired;
        if (select->prepared[slot] || select->folded[slot] != 0)
            continue;
        if (!bank_control_valid(control))
            continue;
        retired = control->next_ticket;
        if (retired == 0)
            continue;
        if (__sync_val_compare_and_swap(&select->folded[slot], 0, 1) != 0)
            continue;
        identity_add(select, &select->folded_issued, retired);
        identity_count(select, &select->folds);
    }
}

/* Complete the loader-authorized re-prepare wait-free: whoever zeroes
 * the frozen watermark (or observes it zeroed) clears the fold mark,
 * so nobody ever waits on a descheduled peer. An issue-CAS racing the
 * zero either fails (and rejoins the live epoch through the normal
 * retry) or lands after it (a valid new-epoch issue); only the
 * zero-CAS winner transitions a nonzero watermark to zero, so the
 * zeroing applies exactly once. */
static __always_inline void identity_help_reprepare(struct image_bank_select *select,
                                                    struct control *controls[2])
{
#pragma unroll
    for (u32 slot = 0; slot < IMAGE_BANK_SLOTS; slot++) {
        struct control *control = controls[slot];
        u64 seen;
        if (!select->prepared[slot] || select->folded[slot] != 1)
            continue;
        if (!bank_control_valid(control))
            continue;
        seen = control->next_ticket;
        if (seen == 0) {
            select->folded[slot] = 0;
            continue;
        }
        if (__sync_val_compare_and_swap(&control->next_ticket, seen, 0) == seen) {
            select->folded[slot] = 0;
            continue;
        }
        /* Lost the zero: either a peer zeroed (clear if it has not
         * yet) or a live issue already advanced past it (already
         * cleared). Re-read both; clear only the zeroed-pending. */
        if (control->next_ticket == 0 && select->folded[slot] == 1)
            select->folded[slot] = 0;
    }
}

/* Saturating sum for the read-only watermark: no counter bumped, no
 * loss reported (observers cannot perturb the issuance they read). */
static __always_inline u64 identity_sat_sum(u64 a, u64 b)
{
    if (a > U64_MAX_VALUE - b)
        return U64_MAX_VALUE;
    return a + b;
}

/* Count a quota or no-slot refusal. A missing SELECT has no cell, so
 * like the gate's missing control it refuses uncounted. */
static __always_inline void bank_refuse(struct image_bank_select *select)
{
    if (select)
        identity_count(select, &select->refusals);
}

__attribute__((noinline)) u32 p11_image_bank_select(void)
{
    struct image_bank_select *select;
    u64 bank;

    select = bank_select_word();
    if (!select)
        return IMAGE_BANK_NO_SLOT;
    bank = select->bank;
    if (bank >= IMAGE_BANK_SLOTS)
        return IMAGE_BANK_NO_SLOT;
    if (!select->prepared[bank])
        return IMAGE_BANK_NO_SLOT;
    return (u32)bank;
}

__attribute__((noinline)) u32 p11_image_bank_cut(u64 target)
{
    struct image_bank_select *select;
    u64 bank;

    if (target >= IMAGE_BANK_SLOTS)
        return IMAGE_BANK_NO_SLOT;
    select = bank_select_word();
    if (!select)
        return IMAGE_BANK_NO_SLOT;
    bank = select->bank;
    if (bank == target)
        return (u32)target;
    if (bank >= IMAGE_BANK_SLOTS || !select->prepared[target])
        return IMAGE_BANK_NO_SLOT;
    if (__sync_val_compare_and_swap(&select->bank, bank, target) != bank) {
        if (select->bank == target)
            return (u32)target;
        return IMAGE_BANK_NO_SLOT;
    }
    identity_count(select, &select->cuts);
    return (u32)target;
}
#endif

#ifdef P11SCOPE_LOADER_GATE
/* Bank-aware allocator: select first (no storage touched on a bad
 * SELECT), help pending folds and re-prepares unconditionally, then
 * fast-path the current bank with the retained bank as fallback. A
 * quota cuts to the other bank when it is prepared, fresh
 * (fold-complete), healthy and roomy with a valid epoch; any other
 * quota refuses honestly. Returned tickets stay local; the issuing
 * (or retaining) bank and its observed incarnation travel alongside
 * for the identity entry to qualify. */
static __always_inline struct cookie_result cookie_for(struct task_struct *task)
{
    struct cookie_result result = {
        .cookie = 0, .incarnation = 0,
        .status = COOKIE_STATUS_BAD_TASK, .bank = 0,
    };
    struct image_bank_select *select;
    struct control *controls[2];
    struct control *control;
    void *storage_map;
    u64 *cell;
    u64 epochs[2];
    u32 bank;
    u32 source;
    u32 key = 0;

    if (!task)
        return result;

    select = bank_select_word();
    bank = p11_image_bank_select();
    /* Same value as NO_SLOT, spelled as a bound so the verifier keeps
     * bank (and bank-derived indexes) inside the two slots. */
    if (bank >= IMAGE_BANK_SLOTS) {
        bank_refuse(select);
        result.status = COOKIE_STATUS_BAD_CONFIG;
        return result;
    }
    controls[0] = bpf_map_lookup_elem(&COOKIE_CTL, &key);
    controls[1] = bpf_map_lookup_elem(&COOKIE_CTL_B, &key);
    /* Lifecycle help is unconditional: a corrupt current bank never
     * blocks another bank's fold or re-prepare. */
    identity_help_fold(select, controls);
    identity_help_reprepare(select, controls);
    control = (bank == 0) ? controls[0] : controls[1];
    if (!control) {
        result.status = COOKIE_STATUS_NO_CONTROL;
        return result;
    }
    if (!bank_control_valid(control)) {
        identity_count(select, &control->unavailable);
        result.status = COOKIE_STATUS_BAD_CONFIG;
        return result;
    }
    /* Epochs before cells: a loader cycle cannot fit between these
     * loads and the probes below (it spans a userspace round trip),
     * while the bump alone could follow a cell read, so incarnation-
     * first keeps the (cell, epoch) pair coherent. */
    epochs[0] = select->incarnation[0];
    epochs[1] = select->incarnation[1];
    if (bank == 0) {
        storage_map = &TASK_COOKIE;
    } else {
        storage_map = &TASK_COOKIE_B;
    }
    source = bank;
    cell = bpf_task_storage_get(storage_map, task, (void *)0, 0);
    if (!cell) {
        void *retained = (bank == 0) ? (void *)&TASK_COOKIE_B : (void *)&TASK_COOKIE;
        cell = bpf_task_storage_get(retained, task, (void *)0, 0);
        if (cell)
            source = (bank == 0) ? 1 : 0;
    }
    if (cell) {
        struct control *origin = (source == 0) ? controls[0] : controls[1];
        u64 source_epoch = (source == 0) ? epochs[0] : epochs[1];
        if (!origin) {
            result.status = COOKIE_STATUS_NO_CONTROL;
            return result;
        }
        if (!bank_control_valid(origin)) {
            identity_count(select, &origin->unavailable);
            result.status = COOKIE_STATUS_BAD_CONFIG;
            return result;
        }
        /* Domain before row: an overflowed epoch refuses even a
         * stored cell, so no qualifier can wrap into an alias. */
        if (source_epoch >= IMAGE_IDENTITY_INCARNATION_LIMIT) {
            identity_count(select, &origin->unavailable);
            result.status = COOKIE_STATUS_BAD_CONFIG;
            return result;
        }
        if (*cell) {
            result.cookie = *cell;
            result.bank = source;
            result.incarnation = source_epoch;
            result.status = COOKIE_STATUS_OK;
        } else {
            identity_count(select, &origin->unavailable);
            result.status = COOKIE_STATUS_ZERO_CELL;
        }
        return result;
    }

#pragma unroll
    for (int attempt = 0; attempt < COOKIE_CAS_TRIES; attempt++) {
        u64 ticket;
        u64 observed;
        u64 proposed;
        u64 epoch;

        /* Fresh epochs every attempt (constant indexes, branch-
         * selected bank): a loader cycle completing mid-loop must
         * not issue under the previous epoch. */
        epochs[0] = select->incarnation[0];
        epochs[1] = select->incarnation[1];
        epoch = (bank == 0) ? epochs[0] : epochs[1];
        if (epoch >= IMAGE_IDENTITY_INCARNATION_LIMIT) {
            identity_count(select, &control->unavailable);
            result.status = COOKIE_STATUS_BAD_CONFIG;
            return result;
        }
        ticket = control->next_ticket;
        if (ticket >= control->limit) {
            u32 other = (bank == 0) ? 1 : 0;
            struct control *target = (other == 0) ? controls[0] : controls[1];
            u64 target_prepared = (other == 0) ? select->prepared[0] : select->prepared[1];
            u64 target_folded = (other == 0) ? select->folded[0] : select->folded[1];
            u64 target_epoch = (other == 0) ? epochs[0] : epochs[1];
            /* Short-circuit keeps the target dereferences behind the
             * validity check, so a missing target refuses uncounted. */
            int fresh = target_prepared && target_folded == 0 &&
                bank_control_valid(target) && target->next_ticket < target->limit &&
                target_epoch < IMAGE_IDENTITY_INCARNATION_LIMIT;
            if (fresh && p11_image_bank_cut(other) == other) {
                bank = other;
                if (bank == 0)
                    storage_map = &TASK_COOKIE;
                else
                    storage_map = &TASK_COOKIE_B;
                control = target;
                continue;
            }
            identity_count(select, &control->unavailable);
            bank_refuse(select);
            result.status = COOKIE_STATUS_QUOTA;
            return result;
        }

        observed = __sync_val_compare_and_swap(&control->next_ticket,
                                                ticket, ticket + 1);
        if (observed != ticket)
            continue;

        proposed = ticket + 1;
        cell = bpf_task_storage_get(storage_map, task, &proposed,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (cell) {
            if (*cell) {
                result.cookie = *cell;
                result.bank = bank;
                result.incarnation = epoch;
                result.status = COOKIE_STATUS_OK;
            } else {
                identity_count(select, &control->unavailable);
                result.status = COOKIE_STATUS_ZERO_CELL;
            }
            return result;
        }

        cell = bpf_task_storage_get(storage_map, task, (void *)0, 0);
        if (cell && *cell) {
            result.cookie = *cell;
            result.bank = bank;
            result.incarnation = epoch;
            result.status = COOKIE_STATUS_OK;
            return result;
        }

        identity_count(select, &control->create_failures);
        identity_count(select, &control->unavailable);
        result.status = COOKIE_STATUS_CREATE_FAILED;
        return result;
    }

    identity_count(select, &control->retry_exhausted);
    identity_count(select, &control->unavailable);
    result.status = COOKIE_STATUS_RETRY_EXHAUSTED;
    return result;
}
#else
static __always_inline struct cookie_result cookie_for(struct task_struct *task)
{
    struct cookie_result result = {
        .cookie = 0, .incarnation = 0,
        .status = COOKIE_STATUS_BAD_TASK, .bank = 0,
    };
    u64 *cell;
    struct control *control;

    if (!task)
        return result;

    control = get_control();
    if (!control) {
        result.status = COOKIE_STATUS_NO_CONTROL;
        return result;
    }
    if (control->limit != IMAGE_IDENTITY_TICKET_LIMIT ||
        control->next_ticket > IMAGE_IDENTITY_TICKET_LIMIT) {
        finite_increment(&control->unavailable);
        result.status = COOKIE_STATUS_BAD_CONFIG;
        return result;
    }

    cell = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
    if (cell) {
        if (*cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
        } else {
            finite_increment(&control->unavailable);
            result.status = COOKIE_STATUS_ZERO_CELL;
        }
        return result;
    }

#pragma unroll
    for (int attempt = 0; attempt < COOKIE_CAS_TRIES; attempt++) {
        u64 ticket = control->next_ticket;
        u64 observed;
        u64 proposed;

        if (ticket >= control->limit) {
            finite_increment(&control->unavailable);
            result.status = COOKIE_STATUS_QUOTA;
            return result;
        }

        observed = __sync_val_compare_and_swap(&control->next_ticket,
                                                ticket, ticket + 1);
        if (observed != ticket)
            continue;

        proposed = ticket + 1;
        cell = bpf_task_storage_get(&TASK_COOKIE, task, &proposed,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (cell) {
            if (*cell) {
                result.cookie = *cell;
                result.status = COOKIE_STATUS_OK;
            } else {
                finite_increment(&control->unavailable);
                result.status = COOKIE_STATUS_ZERO_CELL;
            }
            return result;
        }

        cell = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
        if (cell && *cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
            return result;
        }

        finite_increment(&control->create_failures);
        finite_increment(&control->unavailable);
        result.status = COOKIE_STATUS_CREATE_FAILED;
        return result;
    }

    finite_increment(&control->retry_exhausted);
    finite_increment(&control->unavailable);
    result.status = COOKIE_STATUS_RETRY_EXHAUSTED;
    return result;
}
#endif

/* Same typed task supplies both fields. Volatile aligned u64 is READ_ONCE-equivalent
 * on the selected x86-64 kernels; exec_id zero is valid, status is separate. */
static __always_inline u32 identity_for(struct task_struct *task,
                                        struct image_identity *out)
{
    struct cookie_result result;
    if (!out)
        return COOKIE_STATUS_BAD_TASK;
    *(volatile u64 *)&out->task_cookie = 0;
    *(volatile u64 *)&out->exec_id = 0;
    result = cookie_for(task);
    if (result.status != COOKIE_STATUS_OK)
        return result.status;
#ifdef P11SCOPE_LOADER_GATE
    /* The allocator observed this epoch with the ticket, so no
     * re-read can skew the qualifier across a loader cycle. */
    out->task_cookie = image_identity_qualify(result.cookie, result.bank, result.incarnation);
#else
    out->task_cookie = result.cookie;
#endif
    out->exec_id = *(volatile u64 *)&task->self_exec_id;
    return COOKIE_STATUS_OK;
}

/* Inline across native units so typed task pointers stay in their root's
 * verifier context. The allocator and identity read remain the same body. */
__attribute__((always_inline)) u32 p11_link_task_identity(struct task_struct *task,
                                                        struct image_identity *out)
{
    return identity_for(task, out);
}

__attribute__((noinline)) u32 p11_link_current_identity(struct image_identity *out)
{
    if (!out)
        return COOKIE_STATUS_BAD_TASK;
    struct task_struct *current = bpf_get_current_task_btf();
    struct task_struct *leader;
    *(volatile u64 *)&out->task_cookie = 0;
    *(volatile u64 *)&out->exec_id = 0;
    if (!current)
        return COOKIE_STATUS_BAD_TASK;
    leader = current->group_leader;
    return identity_for(leader, out);
}

/* Private EXEC witness: task incarnation only. Reuse the same bounded
 * allocator without identity_for's self_exec_id read. Callers acquire this
 * only after scope admission and a successful lifecycle ring reservation. */
__attribute__((noinline)) u64 p11_link_current_cookie(void)
{
    struct task_struct *current = bpf_get_current_task_btf();
    struct cookie_result result;
    if (!current)
        return 0;
    result = cookie_for(current->group_leader);
    if (result.status != COOKIE_STATUS_OK || !result.cookie ||
        result.cookie > IMAGE_IDENTITY_TICKET_LIMIT)
        return 0;
    return result.cookie;
}

#ifdef P11SCOPE_LOADER_GATE
/* T-L2 typed-task ticket query: the cookie-only domain for an explicit
 * task, without identity_for's self_exec_id read. The ticket number is
 * the cookie: burned tickets advance the watermark but never issue, and
 * no issued number is ever reused. */
__attribute__((noinline)) u32 p11_link_task_ticket(struct task_struct *task, u64 *ticket_out)
{
    struct cookie_result result;
    if (!ticket_out)
        return COOKIE_STATUS_BAD_TASK;
    *ticket_out = 0;
    if (!task)
        return COOKIE_STATUS_BAD_TASK;
    result = cookie_for(task);
    if (result.status != COOKIE_STATUS_OK)
        return result.status;
    *ticket_out = result.cookie;
    return COOKIE_STATUS_OK;
}

/* T-L2 issuance watermark: factual observation for incarnation pairing
 * and the later L4b producer. Read-only: never spends a ticket and never
 * bumps a counter, so observers cannot perturb the issuance they read.
 * tickets_issued is the derived sum of folded_issued and the live
 * watermarks, monotonic across cuts and incarnations by construction.
 * A retired-pending bank contributes through folded_issued, so its
 * still-intact watermark is excluded rather than double counted.
 * Exact whenever no fold is in flight; a concurrent fold's
 * claim-then-retire window can transiently undercount. */
__attribute__((noinline)) u32 p11_image_identity_issued(u64 *watermark_out)
{
    struct image_bank_select *select;
    struct control *control;
    struct control *control_b;
    u64 total;
    u32 key = 0;
    if (!watermark_out)
        return COOKIE_STATUS_BAD_TASK;
    *watermark_out = 0;
    control = get_control();
    if (!control)
        return COOKIE_STATUS_NO_CONTROL;
    if (!bank_control_valid(control))
        return COOKIE_STATUS_BAD_CONFIG;
    control_b = bpf_map_lookup_elem(&COOKIE_CTL_B, &key);
    if (!control_b)
        return COOKIE_STATUS_NO_CONTROL;
    if (!bank_control_valid(control_b))
        return COOKIE_STATUS_BAD_CONFIG;
    /* A missing SELECT refuses like the ticket path: without the
     * retired count any sum would silently undercount. */
    select = bank_select_word();
    if (!select)
        return COOKIE_STATUS_BAD_CONFIG;
    total = select->folded_issued;
    if (select->folded[0] != 1)
        total = identity_sat_sum(total, control->next_ticket);
    if (select->folded[1] != 1)
        total = identity_sat_sum(total, control_b->next_ticket);
    *watermark_out = total;
    return COOKIE_STATUS_OK;
}
#endif

char LICENSE[] SEC("license") = "GPL";
