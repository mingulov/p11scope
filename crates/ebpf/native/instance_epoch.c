/* SPDX-License-Identifier: GPL-2.0-only */
/* Task 3 Stage A load-instance continuity witness (Detailed only).
 *
 * Every file-VMA lifecycle transition passes through the kernel's uprobe
 * bookkeeping: uprobe_mmap (creation, post-adjust), uprobe_munmap (removal,
 * zap, pre-adjust, teardown) and copy_vma (move, including MREMAP_DONTUNMAP,
 * whose old VMA sees no uprobe_munmap; hooked at exit on its new VMA). A change of a watched provider file
 * bumps that process's per-file epoch; anything not localizable bumps the
 * file's global epoch; an unrecoverable condition bumps the fault generation.
 * Stamps taken at call entry and return carry the three low words, and
 * userspace joins a call to a load instance only when both stamps equal a
 * stable scan. All writes are non-fetch adds or bounded compare-exchanges
 * (F1). The hooks read kernel metadata only and emit nothing. */
#include "instance_epoch.h"

#ifndef P11SCOPE_INSTANCE_HOST_TEST
#define INST_BTF __attribute__((preserve_access_index))
#else
#define INST_BTF
#endif

/* Minimal CO-RE shapes: field names, never fixed target offsets. The
 * `___p11inst` flavor keeps them distinct from every other native unit's
 * same-named partial shape after bitcode linking (an unflavored second
 * `task_struct` would let BTF dedup resolve `mm` against another unit's
 * field list); CO-RE matching strips the flavor. */
struct task_struct; /* the typed fork hook's opaque child */
struct super_block___p11inst {
    u32 s_dev;
} INST_BTF;
struct inode___p11inst {
    unsigned long i_ino;
    struct super_block___p11inst *i_sb;
} INST_BTF;
struct file___p11inst {
    struct inode___p11inst *f_inode;
} INST_BTF;
typedef struct {
    int counter;
} inst_atomic_t;
struct mm_struct___p11inst {
    inst_atomic_t mm_users;
} INST_BTF;
struct vm_area_struct___p11inst {
    unsigned long vm_start;
    struct mm_struct___p11inst *vm_mm;
    struct file___p11inst *vm_file;
} INST_BTF;
struct task_struct___p11inst {
    struct mm_struct___p11inst *mm;
    struct task_struct___p11inst *group_leader;
    unsigned int flags;
} INST_BTF;

struct {
    INST_UINT(type, 1); /* HASH */
    INST_UINT(map_flags, 1U << 7); /* BPF_F_RDONLY_PROG: userspace writes only */
    INST_UINT(max_entries, INST_FILE_SLOTS);
    INST_TYPE(key, struct instance_file_key);
    INST_TYPE(value, u32);
} WATCHED_FILES INST_SEC(".maps");

struct {
    INST_UINT(type, 2); /* ARRAY */
    INST_UINT(map_flags, 1U << 7);
    INST_UINT(max_entries, P11SCOPE_INSTANCE_SLOT_BOUND);
    INST_TYPE(key, u32);
    INST_TYPE(value, u32);
} SLOT_FILE INST_SEC(".maps");

struct {
    INST_UINT(type, 29); /* TASK_STORAGE */
    INST_UINT(map_flags, 1); /* BPF_F_NO_PREALLOC */
    INST_UINT(max_entries, 0);
    INST_TYPE(key, int);
    INST_TYPE(value, struct instance_record);
} PROC_EPOCH INST_SEC(".maps");

struct {
    INST_UINT(type, 2);
    INST_UINT(max_entries, INST_FILE_SLOTS);
    INST_TYPE(key, u32);
    INST_TYPE(value, u64);
} G_EPOCH INST_SEC(".maps");

struct {
    INST_UINT(type, 2);
    INST_UINT(map_flags, 1024); /* BPF_F_MMAPABLE */
    INST_UINT(max_entries, INST_GEN_CELLS);
    INST_TYPE(key, u32);
    INST_TYPE(value, u64);
} INSTANCE_GEN INST_SEC(".maps");

/* The entry half of each in-flight call's continuity, keyed like START.
 * LRU: an entry orphaned by a call that never returns (thread exit, START
 * cleanup) is reclaimed by the kernel; an evicted live entry reads as absent
 * at return, which never joins. */
struct {
    INST_UINT(type, 9); /* LRU_HASH */
    INST_UINT(max_entries, INST_START_ENTRIES);
    INST_TYPE(key, struct instance_start_key);
    INST_TYPE(value, struct instance_entry);
} INSTANCE_START INST_SEC(".maps");

struct {
    INST_UINT(type, 2);
    INST_UINT(max_entries, 1);
    INST_TYPE(key, u32);
    INST_TYPE(value, struct instance_calib);
} INSTANCE_CALIB INST_SEC(".maps");

struct {
    INST_UINT(type, 2);
    INST_UINT(max_entries, 1);
    INST_TYPE(key, u32);
    INST_TYPE(value, struct instance_counters);
} INSTANCE_COUNT INST_SEC(".maps");

static void *(*inst_map_lookup)(void *map, const void *key) = (void *)1;
static long (*inst_map_update)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*inst_map_delete)(void *map, const void *key) = (void *)3;
static u64 (*inst_pid_tgid)(void) = (void *)14;
static long (*inst_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;
static struct instance_record *(*inst_storage_get)(void *map, void *task, void *value,
                                                   u64 flags) = (void *)156;
static void *(*inst_current_task)(void) = (void *)158;

/* Stores LLVM must not merge into a memset call: the Rust `memset` is a
 * global function that 5.15 refuses a stack pointer argument from here. */
#define INST_PUT(lvalue, value) (*(volatile typeof(lvalue) *)&(lvalue) = (value))

#ifndef P11SCOPE_INSTANCE_HOST_TEST
#define INST_READ(dst, src) \
    inst_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))
#else
#define INST_READ(dst, src) inst_probe_read_kernel(&(dst), sizeof(dst), &(src))
#endif

/* Discarded result: lowers to a non-fetch BPF atomic add (F1). */
static INST_INLINE void inst_add(u64 *cell)
{
    __sync_fetch_and_add(cell, 1);
}

static INST_INLINE struct instance_counters *inst_counters(void)
{
    u32 key = 0;
    return inst_map_lookup(&INSTANCE_COUNT, &key);
}

static INST_INLINE void inst_count(u64 *cell)
{
    if (cell)
        inst_add(cell);
}

/* The fault generation ends every incarnation. A bounded CAS raise: a lost
 * race means another raise already moved the cell, which is the same fact. */
static INST_INLINE void inst_fault(struct instance_counters *counters)
{
    u32 key = INST_GEN_FAULT;
    u64 *gen = inst_map_lookup(&INSTANCE_GEN, &key);

    if (counters)
        inst_add(&counters->faults);
    if (!gen)
        return;
#pragma unroll
    for (int i = 0; i < INST_CAS_TRIES; i++) {
        u64 seen = *(volatile u64 *)gen;
        if (__sync_val_compare_and_swap(gen, seen, seen + 1) == seen)
            return;
    }
}

/* Sticky capture-wide refusal bits, raised with a bounded CAS. */
static INST_INLINE void inst_sticky(u64 bits)
{
    u32 key = INST_GEN_STICKY;
    u64 *cell = inst_map_lookup(&INSTANCE_GEN, &key);

    if (!cell)
        return;
#pragma unroll
    for (int i = 0; i < INST_CAS_TRIES; i++) {
        u64 seen = *(volatile u64 *)cell;
        if ((seen & bits) == bits)
            return;
        if (__sync_val_compare_and_swap(cell, seen, seen | bits) == seen)
            return;
    }
}

/* The per-file global epoch: every mutation of a watched file that cannot be
 * attributed to one process record lands here and ends that file's
 * incarnations in every process. */
static INST_INLINE void inst_global(u32 slot, struct instance_counters *counters)
{
    u64 *cell = inst_map_lookup(&G_EPOCH, &slot);

    if (!cell) {
        inst_fault(counters);
        return;
    }
    inst_add(cell);
    if (counters)
        inst_add(&counters->global_bumps);
}

/* Sets record flag bits with a bounded CAS; exhaustion means the caller must
 * fall back to the global epoch (returns 0). */
static INST_INLINE int inst_set_flags(struct instance_record *rec, u64 bits)
{
#pragma unroll
    for (int i = 0; i < INST_CAS_TRIES; i++) {
        u64 seen = *(volatile u64 *)&rec->flags;
        if ((seen & bits) == bits)
            return 1;
        if (__sync_val_compare_and_swap(&rec->flags, seen, seen | bits) == seen)
            return 1;
    }
    return 0;
}

/* Index of `slot` in the record, claiming a free cell with CAS 0->slot+1.
 * Returns INST_RECORD_SLOTS when the record has no room. */
static INST_INLINE u32 inst_claim(struct instance_record *rec, u32 slot)
{
    u64 want = (u64)slot + 1;
#pragma unroll
    for (u32 i = 0; i < INST_RECORD_SLOTS; i++) {
        u64 seen = *(volatile u64 *)&rec->slot_plus1[i];
        if (seen == want)
            return i;
        if (seen == 0) {
            seen = __sync_val_compare_and_swap(&rec->slot_plus1[i], 0, want);
            if (seen == 0 || seen == want)
                return i;
        }
    }
    return INST_RECORD_SLOTS;
}

static INST_INLINE void inst_calibrate(u64 vma_addr, u64 dev, u64 ino,
                                       struct instance_counters *counters)
{
    u32 key = 0;
    struct instance_calib *calib = inst_map_lookup(&INSTANCE_CALIB, &key);
    struct vm_area_struct___p11inst *vma = (struct vm_area_struct___p11inst *)vma_addr;
    unsigned long start = 0;

    if (!calib)
        return;
    if (!*(volatile u32 *)&calib->tid || *(volatile u32 *)&calib->tid != (u32)inst_pid_tgid())
        return;
    if (*(volatile u64 *)&calib->hits)
        return;
    if (INST_READ(start, vma->vm_start))
        return;
    calib->vm_start = start;
    calib->dev = dev;
    calib->ino = ino;
    inst_add(&calib->hits);
    if (counters)
        inst_add(&counters->calib_hits);
}

/* One file-VMA lifecycle transition. `calibrate` only on creation. */
static INST_INLINE int inst_note_vma(u64 vma_addr, int calibrate)
{
    struct vm_area_struct___p11inst *vma = (struct vm_area_struct___p11inst *)vma_addr;
    struct instance_counters *counters;
    struct instance_file_key key = { 0, 0 };
    struct instance_record *rec;
    struct task_struct___p11inst *current;
    struct task_struct___p11inst *leader;
    struct file___p11inst *file = 0;
    struct inode___p11inst *inode = 0;
    struct super_block___p11inst *sb = 0;
    struct mm_struct___p11inst *mm = 0;
    struct mm_struct___p11inst *current_mm = 0;
    unsigned long ino = 0;
    u32 dev = 0;
    unsigned int task_flags = 0;
    int users = 0;
    u32 *slotp;
    u32 slot;
    u32 index;

    if (!vma_addr)
        return 0;
    if (INST_READ(file, vma->vm_file) || !file)
        return 0;
    if (INST_READ(inode, file->f_inode) || !inode)
        return 0;
    if (INST_READ(sb, inode->i_sb) || !sb)
        return 0;
    if (INST_READ(dev, sb->s_dev) || INST_READ(ino, inode->i_ino))
        return 0;
    key.dev = dev;
    key.ino = ino;
    counters = inst_counters();
    if (calibrate)
        inst_calibrate(vma_addr, key.dev, key.ino, counters);
    slotp = inst_map_lookup(&WATCHED_FILES, &key);
    if (!slotp)
        return 0;
    slot = *slotp;
    if (slot >= INST_FILE_SLOTS) {
        inst_fault(counters);
        return 0;
    }
    inst_count(counters ? &counters->watched_hits : 0);
    if (INST_READ(mm, vma->vm_mm) || !mm) {
        inst_global(slot, counters);
        return 0;
    }
    if (INST_READ(users, mm->mm_users.counter)) {
        inst_global(slot, counters);
        return 0;
    }
    /* exit_mmap or old-mm teardown after exec: no task can run in this mm. */
    if (users == 0) {
        inst_count(counters ? &counters->teardown_skips : 0);
        return 0;
    }
    current = inst_current_task();
    if (!current) {
        inst_global(slot, counters);
        return 0;
    }
    if (INST_READ(task_flags, current->flags) || (task_flags & INST_PF_KTHREAD)) {
        /* A kernel thread — possibly borrowing this mm through
         * kthread_use_mm, which sets task->mm without an mm_users
         * reference — or unreadable flags: not localizable. */
        inst_count(counters ? &counters->remote : 0);
        inst_global(slot, counters);
        return 0;
    }
    if (INST_READ(current_mm, current->mm) || current_mm != mm) {
        /* Remote zap/truncate: not localizable. */
        inst_count(counters ? &counters->remote : 0);
        inst_global(slot, counters);
        return 0;
    }
    leader = current->group_leader;
    if (!leader) {
        inst_global(slot, counters);
        return 0;
    }
    /* Pre-attachment sharers carry no SHARED_MM mark: marking happens on
     * forks observed after attachment. Localize only when the single
     * mm_users read above returned 1; any other count globalizes.
     * Ownership proof. mm_users counts every user task with task->mm ==
     * this mm (exactly one reference each, taken at fork, dropped in
     * exit_mm) plus transient kernel mmget holders, who only inflate the
     * count. The PF_KTHREAD check above proved current is a user task and
     * the current_mm check proved current is one of those users; current
     * cannot exit while it runs this hook — so an observed 1 is current's
     * own reference, and no other user-task reference exists at the
     * instant of the read:
     * - Zombies and exiting tasks: a task past exit_mm holds no reference
     *   and can never mutate or stamp again (it has no mm); a task still
     *   before exit_mm holds one and would have been counted. The
     *   exit_mm-before-release window (a zombie leader still counted in
     *   nr_threads) cannot mask a live sharer: zombies hold no reference,
     *   and nr_threads is not consulted at all.
     * - Concurrent fork/share: a new mm user can only be created by
     *   clone/fork from an existing user (CLONE_VM shares the caller's
     *   mm). At the read instant the only user is current, which is
     *   executing this hook rather than a clone — so no new user can
     *   appear before the mutation is decided. Preemption changes nothing:
     *   a new user still needs a clone from an existing user, and the only
     *   one is current. A clone that completed before the read is already
     *   counted (and a post-attachment CLONE_VM non-thread child is
     *   SHARED_MM-marked anyway); a thread created after the read shares
     *   this same leader record and sees the bump.
     * - Kthread borrow (kthread_use_mm/use_mm) takes an mm_count
     *   reference, never mm_users — but it DOES set the borrower's
     *   task->mm to the borrowed mm, so a borrower passes the
     *   current-mm check while the sole mm_users reference belongs to
     *   another group. (The old "borrowers have task->mm == NULL"
     *   premise was false.) Borrowers are kernel threads, so the
     *   PF_KTHREAD check above globalizes them — and any task whose
     *   flags cannot be read — before the count is consulted. A
     *   borrower's mutation therefore always lands in the global
     *   epoch, never in a user record and never in a stamp. Only user
     *   tasks with task->mm == mm can reach this point, and each of
     *   those holds one mm_users.
     * - Transient mmget (mmget_not_zero, e.g. a concurrent /proc
     *   reader): such references CAN appear asynchronously after the
     *   read — the old "no async references" assumption was false —
     *   but they change nothing. A bare mmget holder runs no hook in
     *   this mm's context and takes no stamp, so it can neither
     *   execute a localizable mutation nor witness one. Only tasks
     *   that mutate through this mm matter — users (only current, at
     *   the read instant) and borrowers (excluded above) — while
     *   remote zappers take the remote path. A transient holder
     *   present AT the read only inflates the count into a spurious
     *   (conservative) globalization.
     * So the mutation is observable only within current's thread group —
     * single live thread, no external sharer — and the group-leader record
     * is complete. There is no second read to race: one atomic count, one
     * decision. Cost: multi-threaded processes and transient mmget holders
     * (a concurrent /proc reader) globalize spuriously — conservative, and
     * the fork mark below stays as defense in depth. */
    if (users != 1) {
        inst_count(counters ? &counters->shared : 0);
        inst_global(slot, counters);
        return 0;
    }
    rec = inst_storage_get(&PROC_EPOCH, leader, 0, 1 /* F_CREATE */);
    if (!rec) {
        inst_count(counters ? &counters->storage_null : 0);
        inst_global(slot, counters);
        return 0;
    }
    if (*(volatile u64 *)&rec->flags & INST_RECORD_SHARED_MM) {
        /* A CLONE_VM sharer: its mm is another process's too. */
        inst_count(counters ? &counters->shared : 0);
        inst_global(slot, counters);
        return 0;
    }
    index = inst_claim(rec, slot);
    if (index >= INST_RECORD_SLOTS) {
        inst_count(counters ? &counters->overflow : 0);
        if (!inst_set_flags(rec, INST_RECORD_OVERFLOW))
            inst_fault(counters);
        inst_global(slot, counters);
        return 0;
    }
    inst_add(&rec->epoch[index & (INST_RECORD_SLOTS - 1)]);
    inst_count(counters ? &counters->local_bumps : 0);
    return 0;
}

INST_SEC("fentry/uprobe_mmap")
int p11_inst_vma_map(u64 *ctx)
{
    return inst_note_vma(ctx[0], 1);
}

INST_SEC("fentry/uprobe_munmap")
int p11_inst_vma_unmap(u64 *ctx)
{
    return inst_note_vma(ctx[0], 0);
}

/* copy_vma(struct vm_area_struct **vmap, addr, len, pgoff, bool *need_rmap_locks)
 * returns the new VMA (same vm_file, same vm_mm), or NULL when nothing was
 * created. The kernel admits no pointer-to-pointer fentry argument, so this
 * is an fexit on the return slot (ctx[5]); it still runs under mremap's mmap
 * write lock, before any locked maps reader can see the move. A different
 * argument count makes the verifier refuse the load: fail closed. */
INST_SEC("fexit/copy_vma")
int p11_inst_vma_copy(u64 *ctx)
{
    return inst_note_vma(ctx[5], 0);
}

/* Fork: a CLONE_VM child that is not a thread shares its parent's mm, so
 * its own mutations must not be localized to its record. A non-exported
 * noinline subprogram of the typed task_newtask root: bpf-linker internalizes
 * it, so the verifier checks it in the caller's context (the child stays a
 * trusted task) while the root's own lowering stays separate. Marking
 * failure raises the fault generation: never an unmarked sharer silently. */
__attribute__((noinline)) u32 p11_instance_fork(struct task_struct *child, u64 clone_flags)
{
    struct instance_record init;
    struct instance_record *rec;

    if (!(clone_flags & INST_CLONE_VM) || (clone_flags & INST_CLONE_THREAD))
        return 0;
#pragma unroll
    for (int i = 0; i < INST_RECORD_SLOTS; i++) {
        INST_PUT(init.slot_plus1[i], 0);
        INST_PUT(init.epoch[i], 0);
    }
    INST_PUT(init.exec_attach_gen, 0);
    INST_PUT(init.flags, INST_RECORD_SHARED_MM);
    rec = child ? inst_storage_get(&PROC_EPOCH, child, &init, 1) : 0;
    if (!rec || !inst_set_flags(rec, INST_RECORD_SHARED_MM)) {
        /* An unmarked sharer would localize mutations of another process's
         * mm to its own record for the rest of its life: no later epoch can
         * repair that, so routing is disabled for the capture. */
        inst_sticky(INST_STICKY_FORK_UNMARKED);
        inst_fault(inst_counters());
        return 0;
    }
    return 1;
}

/* Exec: a new mm. Clear SHARED_MM (a vfork child that exec'd owns its own mm
 * again) and stamp the attach generation for Stage B bootstrap. Never
 * creates a record: absent means epoch 0, and exec_attach_gen 0. */
__attribute__((noinline)) u32 p11_instance_exec(void)
{
    struct task_struct___p11inst *current = inst_current_task();
    struct task_struct___p11inst *leader;
    struct instance_record *rec;
    u32 key = INST_GEN_ATTACH;
    u64 *attach;

    if (!current)
        return 0;
    leader = current->group_leader;
    if (!leader)
        return 0;
    rec = inst_storage_get(&PROC_EPOCH, leader, 0, 0);
    if (!rec)
        return 0;
#pragma unroll
    for (int i = 0; i < INST_CAS_TRIES; i++) {
        u64 seen = *(volatile u64 *)&rec->flags;
        if (!(seen & INST_RECORD_SHARED_MM))
            break;
        if (__sync_val_compare_and_swap(&rec->flags, seen, seen & ~INST_RECORD_SHARED_MM) == seen)
            break;
    }
    attach = inst_map_lookup(&INSTANCE_GEN, &key);
    if (attach)
        *(volatile u64 *)&rec->exec_attach_gen = *(volatile u64 *)attach;
    return 1;
}

/* The continuity stamp for the caller of endpoint `endpoint_slot`; reads
 * only map cells and the caller's record. Inlined into the two helpers so no
 * call chain grows below the probes' frames. */
static INST_INLINE u32 inst_stamp(u32 endpoint_slot, struct instance_stamp *out)
{
    struct task_struct___p11inst *current;
    struct task_struct___p11inst *leader;
    struct instance_record *rec;
    u32 key = INST_GEN_FAULT;
    u32 *file;
    u64 *cell;
    u32 slot;
    u32 want;
    u64 flags;

    if (!out)
        return 0;
    INST_PUT(out->epoch, 0);
    INST_PUT(out->global, 0);
    INST_PUT(out->fault, 0);
    INST_PUT(out->file_slot_plus1, 0);
    INST_PUT(out->flags, INST_STAMP_VALID);
    if (endpoint_slot >= P11SCOPE_INSTANCE_SLOT_BOUND) {
        out->flags |= INST_STAMP_NO_FILE;
        return 1;
    }
    file = inst_map_lookup(&SLOT_FILE, &endpoint_slot);
    if (!file) {
        out->flags |= INST_STAMP_NO_FILE;
        return 1;
    }
    want = *(volatile u32 *)file;
    if (want == 0 || want > INST_FILE_SLOTS) {
        out->flags |= INST_STAMP_NO_FILE;
        return 1;
    }
    slot = want - 1;
    out->file_slot_plus1 = (u16)want;
    cell = inst_map_lookup(&INSTANCE_GEN, &key);
    if (cell)
        out->fault = (u32) * (volatile u64 *)cell;
    else
        out->flags |= INST_STAMP_LOCAL_FAULT;
    cell = inst_map_lookup(&G_EPOCH, &slot);
    if (cell)
        out->global = (u32) * (volatile u64 *)cell;
    else
        out->flags |= INST_STAMP_LOCAL_FAULT;
    current = inst_current_task();
    if (!current) {
        out->flags |= INST_STAMP_NO_TASK;
        return 1;
    }
    leader = current->group_leader;
    if (!leader) {
        out->flags |= INST_STAMP_NO_TASK;
        return 1;
    }
    rec = inst_storage_get(&PROC_EPOCH, leader, 0, 0);
    if (!rec)
        return 1; /* never mutated a watched file: local epoch 0 */
    flags = *(volatile u64 *)&rec->flags & INST_RECORD_FLAG_MASK;
    out->flags |= (u16)flags;
#pragma unroll
    for (u32 i = 0; i < INST_RECORD_SLOTS; i++) {
        if (*(volatile u64 *)&rec->slot_plus1[i] == want) {
            out->epoch = (u32) * (volatile u64 *)&rec->epoch[i];
            break;
        }
    }
    return 1;
}

static INST_INLINE void inst_copy_key(struct instance_start_key *dst,
                                      const struct instance_start_key *src)
{
    INST_PUT(dst->pid_tgid, src->pid_tgid);
    INST_PUT(dst->slot, src->slot);
    INST_PUT(dst->pad, src->pad);
}

/* Entry half: record the private probed address and the entry stamp under
 * the call's START key (whose `slot` is the endpoint slot). A failed update
 * deletes any stale entry for the key, so the return sees absence. */
__attribute__((noinline)) u32 p11_instance_entry(const struct instance_start_key *key, u64 ip)
{
    struct instance_start_key k;
    struct instance_entry entry;

    if (!key)
        return 0;
    /* A global function's pointer argument is generic memory; 5.15 map
     * helpers take keys only from the stack (or a map value). */
    inst_copy_key(&k, key);
    entry.entry_ip = ip;
    inst_stamp(k.slot, &entry.entry_stamp);
    if (inst_map_update(&INSTANCE_START, &k, &entry, 0 /* BPF_ANY */)) {
        inst_map_delete(&INSTANCE_START, &k);
        return 0;
    }
    return 1;
}

/* Return half: fill the reserved record's private tail completely (every
 * byte, on every path), consuming the call's INSTANCE_START entry. */
__attribute__((noinline)) u32 p11_instance_return(const struct instance_start_key *key,
                                                  struct instance_continuity *out)
{
    struct instance_start_key k;
    struct instance_entry *entry;

    if (!out)
        return 0;
    INST_PUT(out->entry_ip, 0);
    INST_PUT(out->entry_stamp.epoch, 0);
    INST_PUT(out->entry_stamp.global, 0);
    INST_PUT(out->entry_stamp.fault, 0);
    INST_PUT(out->entry_stamp.file_slot_plus1, 0);
    INST_PUT(out->entry_stamp.flags, 0);
    if (!key) {
        inst_stamp(P11SCOPE_INSTANCE_SLOT_BOUND, &out->return_stamp);
        return 0;
    }
    inst_copy_key(&k, key);
    inst_stamp(k.slot, &out->return_stamp);
    entry = inst_map_lookup(&INSTANCE_START, &k);
    if (!entry)
        return 0;
    out->entry_ip = entry->entry_ip;
    out->entry_stamp.epoch = entry->entry_stamp.epoch;
    out->entry_stamp.global = entry->entry_stamp.global;
    out->entry_stamp.fault = entry->entry_stamp.fault;
    out->entry_stamp.file_slot_plus1 = entry->entry_stamp.file_slot_plus1;
    out->entry_stamp.flags = entry->entry_stamp.flags;
    inst_map_delete(&INSTANCE_START, &k);
    return 1;
}
