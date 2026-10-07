/* SPDX-License-Identifier: GPL-2.0-only */
#include "vma_identity.h"

/* Kernel-only anchor maps: observer fds are `BPF_F_WRONLY`, so syscall reads
 * fail with `EPERM` while the programs keep hash access (F3, I6). Inode
 * addresses never leave these two maps: records carry slots, never pointers. */
struct {
    __uint(type, P11_IDENT_MAP_HASH);
    __uint(map_flags, P11_IDENT_F_WRONLY);
    __uint(max_entries, P11_IDENT_ANCHOR_SLOTS);
    __type(key, u64);
    __type(value, struct p11_anchor_entry);
} anchors SEC(".maps");

struct {
    __uint(type, P11_IDENT_MAP_ARRAY);
    __uint(map_flags, P11_IDENT_F_WRONLY);
    __uint(max_entries, P11_IDENT_ANCHOR_SLOTS);
    __type(key, u32);
    __type(value, u64);
} anchor_slots SEC(".maps");

struct {
    __uint(type, P11_IDENT_MAP_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct p11_identity_config);
} config SEC(".maps");

struct {
    __uint(type, P11_IDENT_MAP_ARRAY);
    __uint(map_flags, P11_IDENT_F_MMAPABLE);
    __uint(max_entries, P11_IDENT_SCOPE_WORDS);
    __type(key, u32);
    __type(value, u64);
} scope_bitmap SEC(".maps");

static __always_inline struct p11_identity_config *ident_config(void)
{
    u32 key = 0;
    return p11_map_lookup(&config, &key);
}

static __always_inline void *ident_seq(struct p11_iter_task_vma *ctx)
{
    if (!ctx->meta)
        return (void *)0;
    return ctx->meta->seq;
}

/* Field-by-field init: the record has no padding, so every byte is set. */
static __always_inline void emit(struct p11_iter_task_vma *ctx, u8 kind, u32 a, u64 start,
                                 u64 end, u32 verdict, u32 gen)
{
    struct p11_vma_identity_record record;
    void *seq = ident_seq(ctx);
    if (!seq)
        return;
    record.magic = P11_IDENT_MAGIC;
    record.version = P11_IDENT_VERSION;
    record.kind = kind;
    record.a = a;
    record.start = start;
    record.end = end;
    record.verdict = verdict;
    record.gen = gen;
    /* The return is ignored on purpose: a full buffer discards this show and
     * the kernel replays the object (F4). A nonzero program return would turn
     * into `-EAGAIN` and fail the read instead. */
    p11_seq_write(seq, &record, P11_IDENT_RECORD_LEN);
}

static __always_inline void emit_end(struct p11_iter_task_vma *ctx)
{
    struct p11_identity_config *cfg = ident_config();
    /* Without config the gen cannot match and the parser rejects the run;
     * that is the fail-closed path for an unconfigured object. */
    u32 gen = cfg ? (u32)cfg->gen : 0;
    emit(ctx, P11_IDENT_KIND_END, 0, 0, 0, 0, gen);
}

static __always_inline int is_leader(struct task_struct *task)
{
    int pid = 0;
    int tgid = 0;
    P11_READ(pid, task->pid);
    P11_READ(tgid, task->tgid);
    /* A negative tgid is impossible; comparing first keeps the verifier from
     * seeing a negative-to-unsigned contradiction on the bitmap index. */
    if (tgid < 0 || pid != tgid)
        return 0;
    return 1;
}

/* Anchor run (§3.4): once per pass over the observer's own arena. Idempotent
 * under F4 replays: a replayed call finds its own current-gen entry and
 * re-emits `OK`, while the discarded show keeps the stream single. */
SEC("iter/task_vma")
int p11_anchor_vma(struct p11_iter_task_vma *ctx)
{
    struct p11_identity_config *cfg;
    struct vm_area_struct *vma = ctx->vma;
    struct task_struct *task = ctx->task;
    struct file *vm_file = (void *)0;
    unsigned long start = 0;
    unsigned long end = 0;
    u64 addr = 0;
    u64 off;
    u64 old;
    u64 *slot_cell;
    u64 base;
    u64 len;
    u64 gen;
    u32 slots;
    u32 slot;

    if (!vma) {
        emit_end(ctx);
        return 0;
    }
    if (!task || !is_leader(task))
        return 0;
    cfg = ident_config();
    if (!cfg)
        return 0;
    base = cfg->arena_base;
    len = cfg->arena_len;
    slots = cfg->slots;
    gen = cfg->gen;
    P11_READ(start, vma->vm_start);
    P11_READ(end, vma->vm_end);
    if (start < base || start >= base + len)
        return 0;
    P11_READ(vm_file, vma->vm_file);
    if (!vm_file)
        return 0;
    /* `vm_start` identifies the slot exactly: even pages hold anchors, odd
     * pages are anonymous guard. A misaligned or oversized file VMA inside
     * the reservation, or one past the installed slots, is `BAD_SHAPE`, never
     * a silent slot alias. */
    off = start - base;
    /* Compared in 64 bits before truncation: a corrupt oversized arena must
     * report `BAD_SHAPE`, never alias a truncated slot. */
    if (end - start != P11_IDENT_PAGE || off % P11_IDENT_ANCHOR_STRIDE != 0 ||
        off / P11_IDENT_ANCHOR_STRIDE >= slots) {
        emit(ctx, P11_IDENT_KIND_ANCHOR, (u32)(off / P11_IDENT_ANCHOR_STRIDE), 0, 0,
             P11_IDENT_ANCHOR_BAD_SHAPE, (u32)gen);
        return 0;
    }
    slot = (u32)(off / P11_IDENT_ANCHOR_STRIDE);
    P11_READ(addr, vm_file->f_inode);
    if (!addr) {
        emit(ctx, P11_IDENT_KIND_ANCHOR, slot, 0, 0, P11_IDENT_ANCHOR_BAD_SHAPE, (u32)gen);
        return 0;
    }
    slot_cell = p11_map_lookup(&anchor_slots, &slot);
    if (!slot_cell) {
        emit(ctx, P11_IDENT_KIND_ANCHOR, slot, 0, 0, P11_IDENT_ANCHOR_BAD_SHAPE, (u32)gen);
        return 0;
    }
    /* Clear stale: only a previous generation's entry may go; a current-gen
     * entry under another slot is a live `DUP` alias, never garbage. */
    old = *slot_cell;
    if (old != 0 && old != addr) {
        struct p11_anchor_entry *stale = p11_map_lookup(&anchors, &old);
        if (stale && stale->gen != gen)
            p11_map_delete(&anchors, &old);
    }
    {
        struct p11_anchor_entry *found = p11_map_lookup(&anchors, &addr);
        if (found && found->gen == gen && found->slot != slot) {
            emit(ctx, P11_IDENT_KIND_ANCHOR, slot, found->slot, 0, P11_IDENT_ANCHOR_DUP,
                 (u32)gen);
        } else {
            struct p11_anchor_entry value;
            value.slot = slot;
            value.pad = 0;
            value.gen = gen;
            if (p11_map_update(&anchors, &addr, &value, P11_IDENT_UPDATE_ANY) == 0) {
                emit(ctx, P11_IDENT_KIND_ANCHOR, slot, 0, 0, P11_IDENT_ANCHOR_OK,
                     (u32)gen);
            } else {
                emit(ctx, P11_IDENT_KIND_ANCHOR, slot, 0, 0, P11_IDENT_ANCHOR_FULL,
                     (u32)gen);
            }
        }
    }
    *slot_cell = addr;
    return 0;
}

/* Target run (§4): leaders in this pass's scope bitmap with a file VMA. No
 * map writes, so replays are free. */
SEC("iter/task_vma")
int p11_identity_vma(struct p11_iter_task_vma *ctx)
{
    struct p11_identity_config *cfg;
    struct vm_area_struct *vma = ctx->vma;
    struct task_struct *task = ctx->task;
    struct p11_anchor_entry *found;
    struct file *vm_file = (void *)0;
    unsigned long start = 0;
    unsigned long end = 0;
    u64 addr = 0;
    u64 *word_cell;
    u64 gen;
    int tgid = 0;
    int pid = 0;
    u32 tgid_u;
    u32 word;
    u32 verdict;

    if (!vma) {
        emit_end(ctx);
        return 0;
    }
    if (!task)
        return 0;
    P11_READ(pid, task->pid);
    P11_READ(tgid, task->tgid);
    if (tgid < 0 || pid != tgid)
        return 0;
    tgid_u = (u32)tgid;
    word = tgid_u >> 6;
    if (word >= P11_IDENT_SCOPE_WORDS)
        return 0;
    word_cell = p11_map_lookup(&scope_bitmap, &word);
    if (!word_cell || !(*word_cell & (1ULL << (tgid_u & 63))))
        return 0;
    P11_READ(vm_file, vma->vm_file);
    if (!vm_file)
        return 0;
    /* The `VM_EXEC` test only shrinks the stream; without the field (the
     * CO-RE fallback) every file VMA is emitted and userspace still picks
     * the ranges (I7). */
    if (p11_field_exists(vma->vm_flags)) {
        unsigned long flags = 0;
        P11_READ(flags, vma->vm_flags);
        if (!(flags & P11_IDENT_VM_EXEC))
            return 0;
    }
    cfg = ident_config();
    if (!cfg)
        return 0;
    gen = cfg->gen;
    P11_READ(addr, vm_file->f_inode);
    if (!addr)
        return 0;
    found = p11_map_lookup(&anchors, &addr);
    verdict = (found && found->gen == gen) ? found->slot : P11_IDENT_NONE;
    P11_READ(start, vma->vm_start);
    P11_READ(end, vma->vm_end);
    emit(ctx, P11_IDENT_KIND_VMA, tgid_u, start, end, verdict, (u32)gen);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
