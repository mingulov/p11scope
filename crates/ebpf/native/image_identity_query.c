/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Detailed-only negative continuity and a lookup-only same-object query.
 * No task/mm pointer is retained or emitted. Nodes never leave either hash. */
#include "image_identity_query.h"
#ifdef P11SCOPE_LOADER_GATE
/* The qualifier and select layout come from the issuer header, never from
 * a duplicated constant. Invisible without the gate define. */
#include "image_identity.h"
#endif
#ifndef P11SCOPE_IMAGE_QUERY_HOST_TEST
#define IMG_BTF __attribute__((preserve_access_index))
#else
#define IMG_BTF
#endif
struct task_struct___p11image {
    struct task_struct___p11image *group_leader;
    u64 self_exec_id;
    unsigned int flags;
} IMG_BTF;
struct image_iter_meta { void *seq; u64 session_id; u64 seq_num; };
struct image_iter_task { struct image_iter_meta *meta; struct task_struct___p11image *task; };
struct {
    IMG_UINT(type, 1);
    IMG_UINT(map_flags, 1 | 16); /* NO_PREALLOC | WRONLY for owned FD */
    IMG_UINT(max_entries, IMG_LIMIT);
    IMG_TYPE(key, u64);
    IMG_TYPE(value, struct image_continuity);
} IMAGE_CONTINUITY IMG_SEC(".maps");
struct {
    IMG_UINT(type, 1);
    IMG_UINT(map_flags, 1 | 16);
    IMG_UINT(max_entries, IMG_LIMIT);
    IMG_TYPE(key, u64);
    IMG_TYPE(value, u64);
} IMAGE_TGID_INDEX IMG_SEC(".maps");
struct {
    IMG_UINT(type, 1);
    IMG_UINT(map_flags, 1 | (1 << 7)); /* immutable during each run */
    IMG_UINT(max_entries, IMG_REQUEST_LIMIT);
    IMG_TYPE(key, u64);
    IMG_TYPE(value, struct image_query_request);
} IMAGE_QUERY_REQUESTS IMG_SEC(".maps");
struct {
    IMG_UINT(type, 2);
    IMG_UINT(max_entries, 1);
    IMG_TYPE(key, u32);
    IMG_TYPE(value, struct image_query_control);
} IMAGE_QUERY_CTL IMG_SEC(".maps");
extern unsigned char TASK_COOKIE;
#ifdef P11SCOPE_LOADER_GATE
extern unsigned char TASK_COOKIE_B;
extern unsigned char IMAGE_BANK_SELECT;
#endif
extern unsigned char INSTANCE_GEN;
extern unsigned char CONFIG;
static void *(*image_lookup)(void *, const void *) = (void *)1;
static long (*image_update)(void *, const void *, const void *, u64) = (void *)2;
static u64 (*image_pid_tgid)(void) = (void *)14;
static u64 (*image_ktime)(void) = (void *)5;
static void *(*image_storage_get)(void *, void *, void *, u64) = (void *)156;
static long (*image_seq_write)(void *, const void *, u32) = (void *)127;
#ifdef P11SCOPE_IMAGE_QUERY_HOST_TEST
#define IMG_READ(cell) __atomic_load_n(&(cell), __ATOMIC_SEQ_CST)
#define IMG_STORE(cell, value) __atomic_store_n(&(cell), (value), __ATOMIC_SEQ_CST)
#else
#define IMG_READ(cell) (*(volatile u64 *)&(cell))
#define IMG_STORE(cell, value) (*(volatile u64 *)&(cell) = (value))
#endif
#define IMG_BARRIER() __asm__ __volatile__("" ::: "memory")
#ifndef IMG_AFTER_LOCK
#define IMG_AFTER_LOCK() ((void)0)
#endif
#ifndef IMG_AFTER_INDEX_MISS
#define IMG_AFTER_INDEX_MISS() ((void)0)
#endif
#ifndef IMG_AFTER_INDEX_PUBLICATION
#define IMG_AFTER_INDEX_PUBLICATION() ((void)0)
#endif
#ifndef IMG_BEFORE_INDEX_CAS
#define IMG_BEFORE_INDEX_CAS() ((void)0)
#endif
#ifndef IMG_AFTER_INDEX_CAS
#define IMG_AFTER_INDEX_CAS(prior, expected) ((void)0)
#endif
static IMG_INLINE u64 *image_coverage(void)
{
    u32 key = IMG_GEN_COVERAGE;
    return image_lookup(&INSTANCE_GEN, &key);
}
static IMG_INLINE void image_fail(void)
{
    u64 *cell = image_coverage();
    if (cell) {
        /* Permanent failure wins in both orderings against the sole enabler. */
        (void)__sync_val_compare_and_swap(cell, IMG_DISABLED, IMG_FAILED);
        (void)__sync_val_compare_and_swap(cell, IMG_ENABLED, IMG_FAILED);
    }
}
static IMG_INLINE int image_allowed(void)
{
    u32 zero = 0;
    u64 *flags = image_lookup(&CONFIG, &zero);
    if (!flags || (IMG_READ(*flags) & (1ULL << 4)) ||
        !(IMG_READ(*flags) & ((1ULL << 2) | (1ULL << 3))))
        return 0;
    u64 *cell = image_coverage();
    return cell && IMG_READ(*cell) == IMG_ENABLED;
}
static IMG_INLINE int image_cookie_valid(u64 cookie)
{
#ifdef P11SCOPE_LOADER_GATE
    if (cookie && cookie <= IMG_LIMIT)
        return 1;
    /* Qualified bank-B identity at incarnation 0: bit 15 set, bits 16+
     * clear, ticket 1..16384. Decoded exactly as image_identity.c issues
     * it; the qualified keys keep same-number A/B cookies disjoint.
     * Malformed, unqualified-out-of-range and foreign cookies (any nonzero
     * incarnation, including a re-prepared bank A) still fail below. */
    {
        u64 ticket = cookie & ((1ULL << 15) - 1);
        if ((cookie >> 15) == 1 && ticket && ticket <= IMG_LIMIT)
            return 1;
    }
    return 0;
#else
    return cookie && cookie <= IMG_LIMIT;
#endif
}
static IMG_INLINE int image_index(u64 tgid, u64 cookie)
{
    u64 *cell = image_lookup(&IMAGE_TGID_INDEX, &tgid);
    if (cell && IMG_READ(*cell) == cookie)
        return 1;
    IMG_AFTER_INDEX_MISS();
    /* Check before mutation. Never conceal a lost invalidation locator. */
    if (image_lookup(&IMAGE_CONTINUITY, &cookie)) {
        /* Another authentic first publisher may have completed both maps
         * since our earlier lookup. Validate its locator without repair. */
        cell = image_lookup(&IMAGE_TGID_INDEX, &tgid);
        if (cell && IMG_READ(*cell) == cookie)
            return 1;
        image_fail();
        return 0;
    }
    if (!cell) {
        long rc = image_update(&IMAGE_TGID_INDEX, &tgid, &cookie, 1);
        if (rc && rc != -17) /* EEXIST loser must inspect actual state */
            return 0;
        cell = image_lookup(&IMAGE_TGID_INDEX, &tgid);
        if (!cell)
            return 0;
    }
#pragma unroll
    for (int i = 0; i < IMG_CAS_TRIES; i++) {
        u64 seen = IMG_READ(*cell);
        if (!image_cookie_valid(seen)) {
            image_fail();
            return 0;
        }
        if (seen == cookie)
            return 1;
        if (seen > cookie)
            return 0;
        IMG_BEFORE_INDEX_CAS();
        u64 prior = __sync_val_compare_and_swap(cell, seen, cookie);
        IMG_AFTER_INDEX_CAS(prior, seen);
        if (prior == seen)
            return IMG_READ(*cell) == cookie;
    }
    return 0;
}
static IMG_INLINE int image_snapshot(struct image_continuity *record,
                                      u64 exec_id, u64 *sequence)
{
    u64 seq = IMG_READ(record->seq);
    if (!seq || (seq & 1))
        return 0;
    IMG_BARRIER();
    u64 id = IMG_READ(record->exec_id);
    u64 state = IMG_READ(record->state);
    IMG_BARRIER();
    if (IMG_READ(record->seq) != seq || id != exec_id || state != IMG_READY)
        return 0;
    *sequence = seq;
    return 1;
}
static IMG_INLINE int image_write(struct image_continuity *record, u64 exec_id,
                                  int poison)
{
#pragma unroll
    for (int i = 0; i < IMG_CAS_TRIES; i++) {
        u64 seq = IMG_READ(record->seq);
        if (!seq || (seq & 1) || seq > (~0ULL - 2))
            break;
        if (__sync_val_compare_and_swap(&record->seq, seq, seq + 1) != seq)
            continue;
        IMG_AFTER_LOCK();
        IMG_BARRIER();
        u64 old_id = IMG_READ(record->exec_id);
        u64 state = IMG_READ(record->state);
        int valid = (state == IMG_READY || state == IMG_POISONED);
        if (valid && poison) {
            /* Do not compare with the replacing task's current exec ID. */
            IMG_STORE(record->state, IMG_POISONED);
        } else if (valid && exec_id > old_id) {
            IMG_STORE(record->exec_id, exec_id);
            IMG_STORE(record->state, IMG_READY);
        } else {
            valid = 0;
        }
        IMG_BARRIER();
        IMG_STORE(record->seq, seq + 2);
        if (!valid && poison)
            image_fail();
        return valid;
    }
    /* A lost invalidator permanently fails; a contended positive entry
     * withholds its stamp without revoking other completed authority. */
    if (poison)
        image_fail();
    return 0;
}
static IMG_INLINE u32 image_seed(u64 tgid, u64 cookie, u64 exec_id)
{
    if (!image_allowed())
        return 0;
    if (!tgid || tgid > 0xffffffffULL || !image_cookie_valid(cookie)) {
        image_fail();
        return 0;
    }
    if (!image_index(tgid, cookie))
        return 0;
    IMG_AFTER_INDEX_PUBLICATION();
    struct image_continuity *record = image_lookup(&IMAGE_CONTINUITY, &cookie);
    if (!record) {
        struct image_continuity initial = { 2, exec_id, IMG_READY };
        long rc = image_update(&IMAGE_CONTINUITY, &cookie, &initial, 1);
        if (rc && rc != -17)
            return 0;
        record = image_lookup(&IMAGE_CONTINUITY, &cookie);
        if (!record)
            return 0;
    }
    u64 sequence = 0;
    if (!image_snapshot(record, exec_id, &sequence)) {
        if (!image_write(record, exec_id, 0) ||
            !image_snapshot(record, exec_id, &sequence))
            return 0;
    }
    u64 *index = image_lookup(&IMAGE_TGID_INDEX, &tgid);
    if (!index || IMG_READ(*index) != cookie) {
        image_fail();
        return 0;
    }
    return image_allowed();
}
/* Ordinary call entry retains its original same-current-task provenance. */
__attribute__((always_inline)) u32 p11_image_entry(u64 tgid, u64 cookie, u64 exec_id)
{
    if (tgid != (image_pid_tgid() >> 32)) {
        if (image_allowed())
            image_fail();
        return 0;
    }
    return image_seed(tgid, cookie, exec_id);
}
/* Only a closed selected Session may use the remote iterator transaction.
 * Its earlier exec invalidator makes late READY permanently nonauthoritative. */
extern u32 p11_selected_bootstrap_allowed(u32 tgid);
extern u32 p11_selected_invalidate_tgid(u32 tgid);
__attribute__((always_inline)) u32 p11_image_selected_seed(u64 tgid, u64 cookie, u64 exec_id)
{
    if (!tgid || tgid > 0xffffffffULL || !p11_selected_bootstrap_allowed((u32)tgid))
        return 0;
    return image_seed(tgid, cookie, exec_id) &&
        p11_selected_bootstrap_allowed((u32)tgid);
}
IMG_SEC("fentry/exec_mm_release")
int p11_image_exec_release(u64 *ctx)
{
    (void)ctx; /* Never read either pointer argument or task storage. */
    /* Mandatory negative action even before a bootstrap locator exists. */
    (void)p11_selected_invalidate_tgid((u32)(image_pid_tgid() >> 32));
    if (!image_allowed())
        return 0;
    u64 tgid = image_pid_tgid() >> 32;
    if (!tgid) {
        image_fail();
        return 0;
    }
    u64 *index = image_lookup(&IMAGE_TGID_INDEX, &tgid);
    if (!index)
        return 0;
    u64 cookie = IMG_READ(*index);
    if (!image_cookie_valid(cookie)) {
        image_fail();
        return 0;
    }
    struct image_continuity *record = image_lookup(&IMAGE_CONTINUITY, &cookie);
    if (record)
        (void)image_write(record, 0, 1);
    return 0;
}
/* 7.3 removed exec_mm_release, merging exit and exec release into
 * mm_exit_exec_release, which also fires on thread exit and must not poison
 * live continuity. Newer kernels hook the exec_mmap exit instead: one
 * argument, so the return value is ctx[1]. The release call
 * mm_exit_exec_release (fs/exec.c:859) sits where exec_mm_release used to
 * (v7.2:857); the only earlier failure is the -ENOMEM from
 * alloc_task_exec_state (:853), before anything is released. The two later
 * failures, down_write_killable (:861-863) and mmap_read_lock_killable
 * (:871-874), both come after point_of_no_return (:1161) and de_thread
 * (:1164): fatal-signal-only, and otherwise bprm_execve forces SIGSEGV
 * (:1887-1888), so the task never runs the old image again and skipping
 * invalidation there is safe. Poison only on success (0). Same invalidation
 * as the legacy hook above; a separate program so the legacy bytes never
 * move. */
IMG_SEC("fexit/exec_mmap")
int p11_image_mmap_release(u64 *ctx)
{
    if ((int)ctx[1] != 0)
        return 0;
    /* Mandatory negative action even before a bootstrap locator exists. */
    (void)p11_selected_invalidate_tgid((u32)(image_pid_tgid() >> 32));
    if (!image_allowed())
        return 0;
    u64 tgid = image_pid_tgid() >> 32;
    if (!tgid) {
        image_fail();
        return 0;
    }
    u64 *index = image_lookup(&IMAGE_TGID_INDEX, &tgid);
    if (!index)
        return 0;
    u64 cookie = IMG_READ(*index);
    if (!image_cookie_valid(cookie)) {
        image_fail();
        return 0;
    }
    struct image_continuity *record = image_lookup(&IMAGE_CONTINUITY, &cookie);
    if (record)
        (void)image_write(record, 0, 1);
    return 0;
}
/* Every callback, including skipped/nonleader callbacks, spends a visit.
 * END must be withheld on failure: task_seq_stop ignores the return code. */
IMG_SEC("iter/task")
int p11_image_query(struct image_iter_task *ctx)
{
    if (!image_allowed())
        return 0;
    u32 zero = 0;
    struct image_query_control *ctl = image_lookup(&IMAGE_QUERY_CTL, &zero);
    if (!ctl || !ctx || !ctx->meta || !ctx->meta->seq)
        return 0;
    if (!ctl->generation || !ctl->count || ctl->count > IMG_REQUEST_LIMIT ||
        !ctl->visit_limit || ctl->visit_limit > IMG_VISIT_LIMIT || ctl->failed ||
        ctl->visits >= ctl->visit_limit || image_ktime() >= ctl->deadline_ns) {
        IMG_STORE(ctl->failed, 1);
        return 1;
    }
    IMG_STORE(ctl->visits, IMG_READ(ctl->visits) + 1);
    struct image_query_row row;
    row.generation = ctl->generation;
    row.cookie = 0;
    row.exec_id = 0;
    row.sequence = 0;
    row.slot = 0;
    row.status = IMG_ROW_END;
    /* Keep this checked callback value across helpers: a context reload is
     * nullable again to the verifier. Fields below are still read afresh. */
    struct task_struct___p11image *task = ctx->task;
    if (!task) {
        if (ctl->emitted != ctl->count || !image_allowed()) {
            IMG_STORE(ctl->failed, 1);
            return 1;
        }
        row.exec_id = ctl->emitted;
        row.sequence = ctl->visits;
        row.slot = (u32)ctl->count;
        if (image_seq_write(ctx->meta->seq, &row, sizeof(row)))
            IMG_STORE(ctl->failed, 1);
        return 0;
    }
    /* Epoch before cell: the qualifier below must match the ticket's bank
     * and incarnation, exactly as the issuer binds them. A missing select
     * word skips the callback; it never fails coverage. */
#ifdef P11SCOPE_LOADER_GATE
    u32 select_key = 0;
    struct image_bank_select *select = image_lookup(&IMAGE_BANK_SELECT, &select_key);
    u64 epoch_a = select ? IMG_READ(select->incarnation[0]) : 0;
    u64 epoch_b = select ? IMG_READ(select->incarnation[1]) : 0;
#endif
    u64 *cell = image_storage_get(&TASK_COOKIE, task, 0, 0);
#ifdef P11SCOPE_LOADER_GATE
    u64 bank = 0;
    if (!cell) {
        cell = image_storage_get(&TASK_COOKIE_B, task, 0, 0);
        bank = 1;
    }
    if (!cell || !select)
        return 0;
    u64 fresh_first = IMG_READ(*cell);
    if (!fresh_first || fresh_first > IMG_LIMIT)
        return 0;
    u64 epoch = bank ? epoch_b : epoch_a;
    if (epoch >= IMAGE_IDENTITY_INCARNATION_LIMIT)
        return 0;
    u64 cookie = image_identity_qualify(fresh_first, bank, epoch);
    if (!image_cookie_valid(cookie))
        return 0;
    void *fresh_map = bank ? (void *)&TASK_COOKIE_B : (void *)&TASK_COOKIE;
#else
    if (!cell)
        return 0;
    u64 cookie = IMG_READ(*cell);
    if (!image_cookie_valid(cookie))
        return 0;
#endif
    struct image_query_request *request = image_lookup(&IMAGE_QUERY_REQUESTS, &cookie);
    if (!request || request->generation != ctl->generation || request->cookie != cookie ||
        request->slot >= ctl->count)
        return 0;
    row.cookie = cookie;
    row.slot = (u32)request->slot;
    row.status = IMG_ROW_UNKNOWN;
    /* Selected-task reads follow immutable request/cookie matching. */
    struct task_struct___p11image *leader = task->group_leader;
    u64 exec_id = IMG_READ(task->self_exec_id);
    struct image_continuity *record = image_lookup(&IMAGE_CONTINUITY, &cookie);
    if (leader == task && !(task->flags & 0x00200000U) && record &&
        image_snapshot(record, exec_id, &row.sequence)) {
        IMG_BARRIER();
        /* The fresh re-read follows the ticket's own bank and compares the
         * raw stored ticket. Without the gate this expands to the original
         * two lines, parenthesis for parenthesis. */
#ifdef P11SCOPE_LOADER_GATE
#define IMG_FRESH_MAP fresh_map
#define IMG_FRESH_WANT fresh_first
#else
#define IMG_FRESH_MAP (&TASK_COOKIE)
#define IMG_FRESH_WANT cookie
#endif
        u64 *fresh = image_storage_get(IMG_FRESH_MAP, task, 0, 0);
        if (fresh && IMG_READ(*fresh) == IMG_FRESH_WANT &&
            task->group_leader == leader && IMG_READ(task->self_exec_id) == exec_id &&
            IMG_READ(record->seq) == row.sequence && image_allowed()) {
            row.exec_id = exec_id;
            row.status = IMG_ROW_READY;
        }
#undef IMG_FRESH_MAP
#undef IMG_FRESH_WANT
    }
    if (image_seq_write(ctx->meta->seq, &row, sizeof(row))) {
        IMG_STORE(ctl->failed, 1);
        return 1;
    }
    IMG_STORE(ctl->emitted, IMG_READ(ctl->emitted) + 1);
    return 0;
}
