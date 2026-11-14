/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Run-tree first-map stop. The first time a run member (any task in the
 * run cgroup except the owned child) maps an executable file that this
 * capture has not cleared, the hook records one pending stop for the
 * member's tgid and sends one SIGSTOP. The mapping itself completes; the
 * member stops on its way back to userspace, before it runs any code of
 * that file. Userspace then inspects the file, attaches the probes of a
 * provider it proves, clears the file (no later mapper stops on it),
 * deletes the pending row and resumes the member. Every refusal (table
 * full, helper refused, unreadable identity) counts and lets the member
 * run on unprotected; nothing here can hold a member that userspace does
 * not know about, because the row is inserted before the signal and
 * withdrawn when the signal is refused. */
#include "member_stop.h"

#define MS_BTF __attribute__((preserve_access_index))

/* Minimal CO-RE shapes with the ___p11ms flavor (see instance_epoch.c). */
struct super_block___p11ms {
    u32 s_dev;
} MS_BTF;
struct inode___p11ms {
    unsigned long i_ino;
    struct super_block___p11ms *i_sb;
} MS_BTF;
struct file___p11ms {
    struct inode___p11ms *f_inode;
} MS_BTF;
struct vm_area_struct___p11ms {
    unsigned long vm_flags;
    struct file___p11ms *vm_file;
} MS_BTF;

struct {
    MS_UINT(type, MS_MAP_ARRAY);
    MS_UINT(map_flags, MS_F_RDONLY_PROG);
    MS_UINT(max_entries, 1);
    MS_TYPE(key, u32);
    MS_TYPE(value, struct ms_cfg);
} MS_CFG MS_SEC(".maps");

struct {
    MS_UINT(type, MS_MAP_CGROUP_ARRAY);
    MS_UINT(max_entries, 1);
    MS_TYPE(key, u32);
    MS_TYPE(value, u32);
} MS_CGROUP MS_SEC(".maps");

struct {
    MS_UINT(type, MS_MAP_HASH);
    MS_UINT(max_entries, MS_STOP_ENTRIES);
    MS_TYPE(key, u32);
    MS_TYPE(value, struct ms_stop);
} MS_STOPS MS_SEC(".maps");

struct {
    MS_UINT(type, MS_MAP_LRU_HASH);
    MS_UINT(max_entries, MS_CLEARED_ENTRIES);
    MS_TYPE(key, struct ms_file);
    MS_TYPE(value, u8);
} MS_CLEARED MS_SEC(".maps");

struct {
    MS_UINT(type, MS_MAP_PERCPU_ARRAY);
    MS_UINT(max_entries, MS_COUNTERS);
    MS_TYPE(key, u32);
    MS_TYPE(value, u64);
} MS_COUNTS MS_SEC(".maps");

static void *(*ms_map_lookup)(void *map, const void *key) = (void *)1;
static long (*ms_map_update)(void *map, const void *key, const void *value, u64 flags) = (void *)2;
static long (*ms_map_delete)(void *map, const void *key) = (void *)3;
static u64 (*ms_ktime_ns)(void) = (void *)5;
static u64 (*ms_pid_tgid)(void) = (void *)14;
static long (*ms_under_cgroup)(void *map, u32 index) = (void *)37;
static long (*ms_send_signal)(u32 sig) = (void *)109;
static long (*ms_probe_read_kernel)(void *dst, u32 size, const void *src) = (void *)113;

#define MS_READ(dst, src) \
    ms_probe_read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

static MS_INLINE void ms_count(u32 index)
{
    u64 *cell = ms_map_lookup(&MS_COUNTS, &index);
    if (cell)
        *cell += 1;
}

/* Reads the mapped file's identity; 0 when every read succeeded. */
static MS_INLINE int ms_file_identity(struct vm_area_struct___p11ms *vma, struct ms_file *out)
{
    struct file___p11ms *file = (void *)0;
    struct inode___p11ms *inode = (void *)0;
    struct super_block___p11ms *sb = (void *)0;
    unsigned long ino = 0;
    u32 dev = 0;

    if (MS_READ(file, vma->vm_file) || !file)
        return 1;
    if (MS_READ(inode, file->f_inode) || !inode)
        return 1;
    if (MS_READ(ino, inode->i_ino))
        return 1;
    if (MS_READ(sb, inode->i_sb) || !sb)
        return 1;
    if (MS_READ(dev, sb->s_dev))
        return 1;
    out->dev = dev;
    out->ino = ino;
    return 0;
}

MS_SEC("fentry/uprobe_mmap")
int p11_member_map_stop(u64 *ctx)
{
    struct vm_area_struct___p11ms *vma = (void *)ctx[0];
    struct ms_stop stop = {};
    struct ms_cfg *cfg;
    unsigned long flags = 0;
    void *file = (void *)0;
    u32 zero = 0;
    u32 tgid;
    long rc;

    cfg = ms_map_lookup(&MS_CFG, &zero);
    if (!cfg || !cfg->active || !vma)
        return 0;
    if (MS_READ(flags, vma->vm_flags) || !(flags & MS_VM_EXEC))
        return 0;
    if (MS_READ(file, vma->vm_file) || !file)
        return 0;
    if (ms_under_cgroup(&MS_CGROUP, 0) != 1)
        return 0;
    tgid = (u32)(ms_pid_tgid() >> 32);
    if (tgid == 0 || tgid == cfg->exempt_tgid)
        return 0;
    if (ms_file_identity(vma, &stop.file)) {
        ms_count(MS_COUNT_IDENTITY_UNREAD);
        return 0;
    }
    if (ms_map_lookup(&MS_CLEARED, &stop.file))
        return 0;
    stop.hook_ts_ns = ms_ktime_ns();
    rc = ms_map_update(&MS_STOPS, &tgid, &stop, MS_NOEXIST);
    if (rc == -MS_EEXIST)
        return 0;
    if (rc) {
        ms_count(MS_COUNT_TABLE_FULL);
        return 0;
    }
    if (ms_send_signal(MS_SIGSTOP)) {
        ms_map_delete(&MS_STOPS, &tgid);
        ms_count(MS_COUNT_SIGNAL_FAILED);
        return 0;
    }
    ms_count(MS_COUNT_REQUESTED);
    return 0;
}

char LICENSE[] MS_SEC("license") = "GPL";
