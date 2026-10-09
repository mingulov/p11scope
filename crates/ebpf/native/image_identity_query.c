/* SPDX-License-Identifier: GPL-2.0-only */
/* Detailed-only negative continuity and a lookup-only same-object query.
 * No task/mm pointer is retained or emitted. Nodes never leave either hash. */
#include "image_identity_query.h"
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
    return cookie && cookie <= IMG_LIMIT;
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
__attribute__((always_inline)) u32 p11_image_entry(u64 tgid, u64 cookie, u64 exec_id)
{
    if (!image_allowed())
        return 0;
    if (!tgid || tgid > 0xffffffffULL || !image_cookie_valid(cookie) ||
        tgid != (image_pid_tgid() >> 32)) {
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
IMG_SEC("fentry/exec_mm_release")
int p11_image_exec_release(u64 *ctx)
{
    (void)ctx; /* Never read either pointer argument or task storage. */
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
    if (!ctx->task) {
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
    u64 *cell = image_storage_get(&TASK_COOKIE, ctx->task, 0, 0);
    if (!cell)
        return 0;
    u64 cookie = IMG_READ(*cell);
    if (!image_cookie_valid(cookie))
        return 0;
    struct image_query_request *request = image_lookup(&IMAGE_QUERY_REQUESTS, &cookie);
    if (!request || request->generation != ctl->generation || request->cookie != cookie ||
        request->slot >= ctl->count)
        return 0;
    row.cookie = cookie;
    row.slot = (u32)request->slot;
    row.status = IMG_ROW_UNKNOWN;
    /* Selected-task reads follow immutable request/cookie matching. */
    struct task_struct___p11image *leader = ctx->task->group_leader;
    u64 exec_id = IMG_READ(ctx->task->self_exec_id);
    struct image_continuity *record = image_lookup(&IMAGE_CONTINUITY, &cookie);
    if (leader == ctx->task && !(ctx->task->flags & 0x00200000U) && record &&
        image_snapshot(record, exec_id, &row.sequence)) {
        IMG_BARRIER();
        u64 *fresh = image_storage_get(&TASK_COOKIE, ctx->task, 0, 0);
        if (fresh && IMG_READ(*fresh) == cookie &&
            ctx->task->group_leader == leader && IMG_READ(ctx->task->self_exec_id) == exec_id &&
            IMG_READ(record->seq) == row.sequence && image_allowed()) {
            row.exec_id = exec_id;
            row.status = IMG_ROW_READY;
        }
    }
    if (image_seq_write(ctx->meta->seq, &row, sizeof(row))) {
        IMG_STORE(ctl->failed, 1);
        return 1;
    }
    IMG_STORE(ctl->emitted, IMG_READ(ctl->emitted) + 1);
    return 0;
}
