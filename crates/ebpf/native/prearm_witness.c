/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Pre-arm mapping-instant witness (WU-13 P-C phase 2, addendum §4). Standalone
 * startup object: an unmap latch, departure accounting, a cgroup
 * out-migration latch and one iter/task_vma presence walk. Every sensor
 * ignores the observer's own address space; every failure input reads as a
 * window. RED stub: program bodies return 0 until P2-1 GREEN. */
#include "prearm_witness.h"

#ifndef P11SCOPE_PREARM_WITNESS_HOST_TEST
#define PW_BTF __attribute__((preserve_access_index))
#else
#define PW_BTF
#endif

/* Minimal CO-RE shapes with the ___p11pw flavor (see instance_epoch.c). */
struct kernfs_node___p11pw {
    u64 id;
} PW_BTF;
struct cgroup_subsys_state___p11pw {
    struct cgroup_subsys_state___p11pw *parent;
    struct cgroup___p11pw *cgroup;
} PW_BTF;
struct cgroup___p11pw {
    struct kernfs_node___p11pw *kn;
    struct cgroup_subsys_state___p11pw self;
} PW_BTF;
struct css_set___p11pw {
    struct cgroup_subsys_state___p11pw *dfl_cgrp;
} PW_BTF;
struct super_block___p11pw {
    u32 s_dev;
} PW_BTF;
struct inode___p11pw {
    unsigned long i_ino;
    struct super_block___p11pw *i_sb;
} PW_BTF;
struct file___p11pw {
    struct inode___p11pw *f_inode;
} PW_BTF;
typedef struct {
    int counter;
} pw_atomic_t;
struct mm_struct___p11pw {
    pw_atomic_t mm_users;
    int map_count;
} PW_BTF;
struct vm_area_struct___p11pw {
    struct mm_struct___p11pw *vm_mm;
    struct file___p11pw *vm_file;
} PW_BTF;
struct task_struct___p11pw {
    struct mm_struct___p11pw *mm;
    int pid;
    int tgid;
    unsigned int flags;
    struct css_set___p11pw *cgroups;
} PW_BTF;

/* Iterator context (task, vma); the walk writes no bytes. */
struct pw_iter_task_vma {
    void *meta;
    struct task_struct___p11pw *task;
    struct vm_area_struct___p11pw *vma;
};

struct {
    PW_UINT(type, PW_MAP_ARRAY);
    PW_UINT(map_flags, PW_F_RDONLY_PROG);
    PW_UINT(max_entries, 1);
    PW_TYPE(key, u32);
    PW_TYPE(value, struct pw_cfg);
} PW_CFG PW_SEC(".maps");

struct {
    PW_UINT(type, PW_MAP_HASH);
    PW_UINT(map_flags, PW_F_RDONLY_PROG);
    PW_UINT(max_entries, PW_SLOTS);
    PW_TYPE(key, struct pw_watched_key);
    PW_TYPE(value, u32);
} PW_WATCHED PW_SEC(".maps");

struct {
    PW_UINT(type, PW_MAP_ARRAY);
    PW_UINT(max_entries, PW_CALIB_ENTRIES);
    PW_TYPE(key, u32);
    PW_TYPE(value, struct pw_calib_slot);
} PW_CALIB PW_SEC(".maps");

struct {
    PW_UINT(type, PW_MAP_ARRAY);
    PW_UINT(max_entries, 1);
    PW_TYPE(key, u32);
    PW_TYPE(value, struct pw_state);
} PW_STATE PW_SEC(".maps");

struct {
    PW_UINT(type, PW_MAP_HASH);
    PW_UINT(map_flags, PW_F_NO_PREALLOC);
    PW_UINT(max_entries, PW_DEPARTED_ENTRIES);
    PW_TYPE(key, u64);
    PW_TYPE(value, struct pw_departed);
} PW_DEPARTED PW_SEC(".maps");

struct {
    PW_UINT(type, PW_MAP_HASH);
    PW_UINT(map_flags, PW_F_NO_PREALLOC);
    PW_UINT(max_entries, PW_VISITED_ENTRIES);
    PW_TYPE(key, u64);
    PW_TYPE(value, u8);
} PW_VISITED PW_SEC(".maps");

struct {
    PW_UINT(type, PW_MAP_ARRAY);
    PW_UINT(max_entries, 1);
    PW_TYPE(key, u32);
    PW_TYPE(value, u64);
} PW_SELF PW_SEC(".maps");

struct {
    PW_UINT(type, PW_MAP_ARRAY);
    PW_UINT(max_entries, 1);
    PW_TYPE(key, u32);
    PW_TYPE(value, struct pw_run);
} PW_RUN PW_SEC(".maps");

static void *(*pw_map_lookup)(void *map, const void *key) = (void *)1;
static long (*pw_map_update)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*pw_map_delete)(void *map, const void *key) = (void *)3;
static u64 (*pw_pid_tgid)(void) = (void *)14;
static void *(*pw_current_task)(void) = (void *)158;
static long (*pw_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;

#ifndef P11SCOPE_PREARM_WITNESS_HOST_TEST
#define PW_READ(dst, src) \
    pw_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))
#else
#define PW_READ(dst, src) pw_probe_read_kernel(&(dst), sizeof(dst), &(src))
#endif

static PW_INLINE struct pw_cfg *pw_cfg(void)
{
    u32 key = 0;
    return pw_map_lookup(&PW_CFG, &key);
}

static PW_INLINE struct pw_state *pw_state(void)
{
    u32 key = 0;
    return pw_map_lookup(&PW_STATE, &key);
}

static PW_INLINE u64 pw_self_mm(void)
{
    u32 key = 0;
    u64 *cell = pw_map_lookup(&PW_SELF, &key);
    return cell ? *cell : 0;
}

static PW_INLINE struct pw_run *pw_run(void)
{
    u32 key = 0;
    return pw_map_lookup(&PW_RUN, &key);
}

static PW_INLINE void pw_add(u64 *cell)
{
    __sync_fetch_and_add(cell, 1);
}

static PW_INLINE void pw_or(u64 *cell, u64 bits)
{
    __sync_fetch_and_or(cell, bits);
}

static PW_INLINE void pw_busy_inc(struct pw_state *s)
{
    __sync_fetch_and_add(&s->busy, 1);
}

static PW_INLINE void pw_busy_dec(struct pw_state *s)
{
    __sync_fetch_and_sub(&s->busy, 1);
}

static PW_INLINE void pw_fault(struct pw_state *s)
{
    if (s)
        pw_add(&s->faults);
}

/* Scope membership: 1 member, 0 non-member, -1 fault (faults++ done).
 * For --pid compares tgid; --system always true; --cgroup walks the
 * default-hierarchy parent chain for at most 64 levels. */
static PW_INLINE int pw_member(struct task_struct___p11pw *task, struct pw_cfg *cfg,
                               struct pw_state *s)
{
    if (cfg->scope_kind == PW_SCOPE_SYSTEM)
        return 1;
    if (cfg->scope_kind == PW_SCOPE_PID) {
        int tgid = 0;
        if (PW_READ(tgid, task->tgid)) {
            pw_fault(s);
            return -1;
        }
        return tgid == (int)cfg->target_tgid ? 1 : 0;
    }
    if (cfg->scope_kind == PW_SCOPE_CGROUP) {
        struct css_set___p11pw *css = 0;
        struct cgroup_subsys_state___p11pw *css_state = 0;
        struct cgroup___p11pw *cgrp = 0;
        if (PW_READ(css, task->cgroups) || !css) {
            if (!css && !PW_READ(css, task->cgroups)) {
                /* NULL css set: treat as non-member without fault? No:
                 * a task always has css_set; NULL is a fault. */
            }
            pw_fault(s);
            return -1;
        }
        if (PW_READ(css_state, css->dfl_cgrp) || !css_state) {
            pw_fault(s);
            return -1;
        }
        if (PW_READ(cgrp, css_state->cgroup) || !cgrp) {
            pw_fault(s);
            return -1;
        }
#pragma unroll
        for (int depth = 0; depth < PW_CGROUP_MAX_DEPTH; depth++) {
            struct kernfs_node___p11pw *kn = 0;
            u64 id = 0;
            if (PW_READ(kn, cgrp->kn) || !kn) {
                pw_fault(s);
                return -1;
            }
            if (PW_READ(id, kn->id)) {
                pw_fault(s);
                return -1;
            }
            if (id == cfg->cgroup_id)
                return 1;
            /* Parent through cgrp->self.parent->cgroup. NULL parent ends. */
            {
                struct cgroup_subsys_state___p11pw *parent = 0;
                struct cgroup___p11pw *next = 0;
                if (PW_READ(parent, cgrp->self.parent)) {
                    pw_fault(s);
                    return -1;
                }
                if (!parent)
                    return 0;
                if (PW_READ(next, parent->cgroup) || !next) {
                    pw_fault(s);
                    return -1;
                }
                cgrp = next;
            }
        }
        /* More than 64 levels: fault (addendum §4.4). */
        pw_fault(s);
        return -1;
    }
    /* Unknown scope kind: non-member. */
    return 0;
}

/* Unmap latch (addendum §4.1). */
static PW_INLINE int pw_unmap_one(u64 vma_addr)
{
    struct vm_area_struct___p11pw *vma = (struct vm_area_struct___p11pw *)vma_addr;
    struct pw_cfg *cfg;
    struct pw_state *s;
    struct file___p11pw *file = 0;
    struct inode___p11pw *inode = 0;
    struct super_block___p11pw *sb = 0;
    struct mm_struct___p11pw *mm = 0;
    struct task_struct___p11pw *current = 0;
    struct mm_struct___p11pw *current_mm = 0;
    struct pw_watched_key key = { 0, 0 };
    unsigned long ino = 0;
    u32 dev = 0;
    unsigned int task_flags = 0;
    int users = 0;
    u32 *slotp;
    u32 slot;
    u64 self;

    s = pw_state();
    if (!s)
        return 0;
    pw_busy_inc(s);
    cfg = pw_cfg();
    if (!cfg) {
        pw_busy_dec(s);
        return 0;
    }
    if (!vma_addr) {
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(file, vma->vm_file)) {
        pw_fault(s);
        pw_busy_dec(s);
        return 0;
    }
    if (!file) {
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(inode, file->f_inode) || !inode) {
        pw_fault(s);
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(sb, inode->i_sb) || !sb) {
        pw_fault(s);
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(dev, sb->s_dev) || PW_READ(ino, inode->i_ino)) {
        pw_fault(s);
        pw_busy_dec(s);
        return 0;
    }
    key.s_dev = dev;
    key.i_ino = ino;
    /* Calibration: record the file key and observer mm. */
    {
        u32 tid = (u32)pw_pid_tgid();
        if (cfg->calib_tid != 0 && cfg->calib_tid == tid) {
            u32 index = cfg->calib_index;
            if (index < PW_SLOTS) {
                struct pw_calib_slot *slotrec = pw_map_lookup(&PW_CALIB, &index);
                if (slotrec && *(volatile u64 *)&slotrec->hits == 0) {
                    struct mm_struct___p11pw *calib_mm = 0;
                    if (PW_READ(calib_mm, vma->vm_mm) || !calib_mm) {
                        pw_fault(s);
                        pw_busy_dec(s);
                        return 0;
                    }
                    slotrec->s_dev = key.s_dev;
                    slotrec->i_ino = key.i_ino;
                    slotrec->hits = 1;
                    {
                        u32 selfkey = 0;
                        u64 *selfcell = pw_map_lookup(&PW_SELF, &selfkey);
                        if (selfcell)
                            *selfcell = (u64)(unsigned long)calib_mm;
                    }
                    pw_busy_dec(s);
                    return 0;
                }
            }
        }
    }
    if (!cfg->active) {
        pw_busy_dec(s);
        return 0;
    }
    slotp = pw_map_lookup(&PW_WATCHED, &key);
    if (!slotp) {
        pw_busy_dec(s);
        return 0;
    }
    slot = *slotp;
    if (slot >= PW_SLOTS) {
        pw_fault(s);
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(mm, vma->vm_mm) || !mm) {
        pw_fault(s);
        pw_busy_dec(s);
        return 0;
    }
    self = pw_self_mm();
    if ((u64)(unsigned long)mm == self) {
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(users, mm->mm_users.counter)) {
        pw_or(&s->latch_slots, 1ULL << slot);
        pw_busy_dec(s);
        return 0;
    }
    if (users == 0) {
        u64 mmkey = (u64)(unsigned long)mm;
        struct pw_departed *e = pw_map_lookup(&PW_DEPARTED, &mmkey);
        if (e)
            pw_or(&e->torn_mask, 1ULL << slot);
        pw_busy_dec(s);
        return 0;
    }
    current = pw_current_task();
    if (!current) {
        pw_or(&s->latch_slots, 1ULL << slot);
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(task_flags, current->flags) || (task_flags & PW_PF_KTHREAD)) {
        pw_or(&s->latch_slots, 1ULL << slot);
        pw_busy_dec(s);
        return 0;
    }
    if (PW_READ(current_mm, current->mm) || current_mm != mm) {
        pw_or(&s->latch_slots, 1ULL << slot);
        pw_busy_dec(s);
        return 0;
    }
    {
        int m = pw_member(current, cfg, s);
        if (m < 0) {
            pw_busy_dec(s);
            return 0;
        }
        if (m == 1) {
            pw_or(&s->latch_slots, 1ULL << slot);
            pw_busy_dec(s);
            return 0;
        }
    }
    if (users != 1) {
        pw_or(&s->latch_slots, 1ULL << slot);
        pw_busy_dec(s);
        return 0;
    }
    {
        u64 mmkey = (u64)(unsigned long)mm;
        struct pw_departed *e = pw_map_lookup(&PW_DEPARTED, &mmkey);
        if (e) {
            pw_or(&s->latch_slots, 1ULL << slot);
            pw_busy_dec(s);
            return 0;
        }
    }
    pw_busy_dec(s);
    return 0;
}

/* Departure accounting (addendum §4.2). Shared by exit/exec/mm_release. */
static PW_INLINE int pw_depart_one(u64 tsk_addr, u64 mm_addr)
{
    struct task_struct___p11pw *tsk = (struct task_struct___p11pw *)tsk_addr;
    struct pw_cfg *cfg;
    struct pw_state *s;
    u64 self;
    u64 mmkey;

    s = pw_state();
    if (!s)
        return 0;
    pw_busy_inc(s);
    cfg = pw_cfg();
    if (!cfg) {
        pw_busy_dec(s);
        return 0;
    }
    if (!tsk_addr || !mm_addr) {
        pw_busy_dec(s);
        return 0;
    }
    mmkey = mm_addr;
    self = pw_self_mm();
    if (mmkey == self) {
        u32 selfidx = PW_CALIB_SELF_INDEX;
        struct pw_calib_slot *slotrec = pw_map_lookup(&PW_CALIB, &selfidx);
        if (slotrec)
            pw_add(&slotrec->hits);
        pw_busy_dec(s);
        return 0;
    }
    if (!cfg->active) {
        pw_busy_dec(s);
        return 0;
    }
    {
        int m = pw_member(tsk, cfg, s);
        if (m < 0) {
            pw_busy_dec(s);
            return 0;
        }
        if (m == 0) {
            pw_busy_dec(s);
            return 0;
        }
    }
    {
        u8 *v = pw_map_lookup(&PW_VISITED, &mmkey);
        if (v) {
            pw_busy_dec(s);
            return 0;
        }
    }
    {
        struct pw_departed *e = pw_map_lookup(&PW_DEPARTED, &mmkey);
        if (!e) {
            struct pw_departed init = { 0, 0, 0 };
            u64 seq = __sync_fetch_and_add(&s->seq, 1) + 1;
            init.word = PW_DEP_PENDING | (seq << PW_DEP_SEQ_SHIFT);
            if (pw_map_update(&PW_DEPARTED, &mmkey, &init, PW_NOEXIST) == 0) {
                pw_add(&s->pending_in);
                pw_busy_dec(s);
                return 0;
            }
            e = pw_map_lookup(&PW_DEPARTED, &mmkey);
            if (!e) {
                pw_fault(s);
                pw_busy_dec(s);
                return 0;
            }
        }
        /* Re-pend: PENDING|x -> PENDING|max(x, s); CLEARED -> PENDING. */
        {
            u64 seq = __sync_fetch_and_add(&s->seq, 1) + 1;
#pragma unroll
            for (int i = 0; i < PW_CAS_TRIES; i++) {
                u64 old = *(volatile u64 *)&e->word;
                u64 st = old & PW_DEP_STATE_MASK;
                u64 oldseq = old >> PW_DEP_SEQ_SHIFT;
                u64 newseq = oldseq > seq ? oldseq : seq;
                u64 want;
                if (st == PW_DEP_DONE) {
                    pw_busy_dec(s);
                    return 0;
                }
                want = PW_DEP_PENDING | (newseq << PW_DEP_SEQ_SHIFT);
                if (__sync_val_compare_and_swap(&e->word, old, want) == old) {
                    if (st == PW_DEP_CLEARED)
                        pw_add(&s->pending_in);
                    pw_busy_dec(s);
                    return 0;
                }
            }
            e->stuck = 1;
            pw_add(&s->stuck);
            pw_busy_dec(s);
            return 0;
        }
    }
}

/* Teardown completion (addendum §4.3). */
static PW_INLINE int pw_torn_one(u64 mm_addr)
{
    struct pw_state *s;
    struct pw_cfg *cfg;
    u64 mmkey;

    s = pw_state();
    if (!s)
        return 0;
    pw_busy_inc(s);
    cfg = pw_cfg();
    if (!cfg || !cfg->active) {
        pw_busy_dec(s);
        return 0;
    }
    if (!mm_addr) {
        pw_busy_dec(s);
        return 0;
    }
    mmkey = mm_addr;
    {
        struct pw_departed *e = pw_map_lookup(&PW_DEPARTED, &mmkey);
        if (e) {
            u64 old = *(volatile u64 *)&e->word;
            if ((old & PW_DEP_STATE_MASK) == PW_DEP_PENDING) {
                u64 want = PW_DEP_DONE | (old & ~(u64)PW_DEP_STATE_MASK);
                if (__sync_val_compare_and_swap(&e->word, old, want) == old) {
                    if (e->torn_mask)
                        pw_or(&s->torn_slots, e->torn_mask);
                    pw_add(&s->pending_out);
                }
            }
        }
        pw_map_delete(&PW_DEPARTED, &mmkey);
        pw_map_delete(&PW_VISITED, &mmkey);
    }
    pw_busy_dec(s);
    return 0;
}

/* Cgroup out-migration latch (addendum §4.4). */
static PW_INLINE int pw_migrate_one(u64 leader_addr)
{
    struct task_struct___p11pw *leader = (struct task_struct___p11pw *)leader_addr;
    struct pw_state *s;
    struct pw_cfg *cfg;

    s = pw_state();
    if (!s)
        return 0;
    pw_busy_inc(s);
    cfg = pw_cfg();
    if (!cfg || !cfg->active) {
        pw_busy_dec(s);
        return 0;
    }
    /* Migrations matter only for --cgroup (leaving the scope); --pid and
     * --system membership is unaffected by cgroup moves. */
    if (cfg->scope_kind != PW_SCOPE_CGROUP) {
        pw_busy_dec(s);
        return 0;
    }
    if (!leader_addr) {
        pw_busy_dec(s);
        return 0;
    }
    {
        int m = pw_member(leader, cfg, s);
        if (m == 1)
            pw_add(&s->migrations);
    }
    pw_busy_dec(s);
    return 0;
}

static PW_INLINE void pw_walk_finalize(struct pw_run *r, struct pw_state *s)
{
    int complete;
    if (!r || r->task == 0)
        return;
    pw_add(&s->walk_runs);
    complete = r->member && r->count == r->map_count && r->count > 0;
    if (!complete)
        return;
    {
        u8 one = 1;
        pw_map_update(&PW_VISITED, &r->mm, &one, 0);
    }
    {
        struct pw_departed *e = pw_map_lookup(&PW_DEPARTED, &r->mm);
        if (!e)
            return;
        if (*(volatile u64 *)&e->stuck)
            return;
        {
            u64 old = *(volatile u64 *)&e->word;
            if ((old & PW_DEP_STATE_MASK) != PW_DEP_PENDING)
                return;
            if ((old >> PW_DEP_SEQ_SHIFT) > r->start_seq)
                return;
            {
                u64 want = PW_DEP_CLEARED | (old & ~(u64)PW_DEP_STATE_MASK);
                if (__sync_val_compare_and_swap(&e->word, old, want) == old)
                    pw_add(&s->pending_out);
            }
        }
    }
}

/* Presence walk (addendum §4.5). */
static PW_INLINE int pw_walk_one(struct pw_iter_task_vma *ctx)
{
    struct pw_cfg *cfg;
    struct pw_state *s;
    struct pw_run *r;

    s = pw_state();
    if (!s)
        return 0;
    cfg = pw_cfg();
    r = pw_run();
    if (!cfg || !r)
        return 0;
    /* Walk runs without busy: it executes in userspace's read syscall,
     * single-threaded per link, so no quiescence tracking is needed.
     * (Busy is for the async fentry/fexit hooks.) */
    if (!ctx->task) {
        pw_walk_finalize(r, s);
        r->task = 0;
        r->mm = 0;
        r->count = 0;
        pw_add(&s->walk_end);
        return 0;
    }
    if (!ctx->vma)
        return 0;
    /* Locals first: nested `ctx->vma->field` inside PW_READ breaks helper
     * lowering (verifier `call unknown#...`); the identity iterator copies
     * ctx fields to locals before probing. */
    {
        struct task_struct___p11pw *task = ctx->task;
        struct vm_area_struct___p11pw *vma = ctx->vma;
        if ((u64)(unsigned long)task != r->task) {
            struct mm_struct___p11pw *mm = 0;
            u64 self;
            int is_pidfd;
            int member = 0;
            pw_walk_finalize(r, s);
            if (PW_READ(mm, vma->vm_mm) || !mm) {
                pw_fault(s);
                r->task = (u64)(unsigned long)task;
                r->mm = 0;
                r->start_seq = *(volatile u64 *)&s->seq;
                r->count = 0;
                r->map_count = 0;
                r->member = 0;
                return 0;
            }
            self = pw_self_mm();
            is_pidfd = cfg->scope_kind == PW_SCOPE_PID ? 1 : 0;
            if ((u64)(unsigned long)mm != self) {
                if (is_pidfd) {
                    member = 1;
                } else {
                    int m = pw_member(task, cfg, s);
                    if (m == 1)
                        member = 1;
                    else
                        member = 0;
                }
            }
            r->task = (u64)(unsigned long)task;
            r->mm = (u64)(unsigned long)mm;
            r->start_seq = *(volatile u64 *)&s->seq;
            r->count = 0;
            r->map_count = 0;
            r->member = (u64)member;
        }
    }
    pw_add(&s->walk_vmas);
    r->count++;
    {
        struct mm_struct___p11pw *mm = (struct mm_struct___p11pw *)(unsigned long)r->mm;
        int map_count = 0;
        if (!mm || PW_READ(map_count, mm->map_count)) {
            pw_fault(s);
        } else {
            r->map_count = (u64)map_count;
        }
    }
    {
        struct vm_area_struct___p11pw *vma = ctx->vma;
        struct file___p11pw *file = 0;
        struct inode___p11pw *inode = 0;
        struct super_block___p11pw *sb = 0;
        unsigned long ino = 0;
        u32 dev = 0;
        struct pw_watched_key key;
        u32 *slotp;
        if (!vma)
            return 0;
        if (PW_READ(file, vma->vm_file)) {
            pw_fault(s);
            return 0;
        }
        if (!file)
            return 0;
        if (PW_READ(inode, file->f_inode) || !inode) {
            pw_fault(s);
            return 0;
        }
        if (PW_READ(sb, inode->i_sb) || !sb) {
            pw_fault(s);
            return 0;
        }
        if (PW_READ(dev, sb->s_dev) || PW_READ(ino, inode->i_ino)) {
            pw_fault(s);
            return 0;
        }
        key.s_dev = dev;
        key.i_ino = ino;
        slotp = pw_map_lookup(&PW_WATCHED, &key);
        if (slotp && *slotp >= PW_SLOTS)
            pw_fault(s);
        else if (slotp && r->member && *slotp < PW_SLOTS)
            pw_or(&s->found_slots, 1ULL << *slotp);
    }
    return 0;
}

PW_SEC("fentry/uprobe_munmap")
int p11_pw_unmap(u64 *ctx)
{
    return pw_unmap_one(ctx[0]);
}

PW_SEC("fentry/exit_mm_release")
int p11_pw_depart_exit(u64 *ctx)
{
    return pw_depart_one(ctx[0], ctx[1]);
}

PW_SEC("fentry/exec_mm_release")
int p11_pw_depart_exec(u64 *ctx)
{
    return pw_depart_one(ctx[0], ctx[1]);
}

PW_SEC("fentry/mm_exit_exec_release")
int p11_pw_depart(u64 *ctx)
{
    return pw_depart_one(ctx[0], ctx[1]);
}

PW_SEC("fexit/exit_mmap")
int p11_pw_torn(u64 *ctx)
{
    return pw_torn_one(ctx[0]);
}

PW_SEC("fentry/cgroup_migrate")
int p11_pw_migrate(u64 *ctx)
{
    return pw_migrate_one(ctx[0]);
}

PW_SEC("iter/task_vma")
int p11_pw_walk(struct pw_iter_task_vma *ctx)
{
    return pw_walk_one(ctx);
}
