/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Run-tree first-map stop. Standalone object loaded only by an owned,
 * pause-armed `run` on its cgroup scope. The hook reads kernel VMA/file
 * metadata only (VM_EXEC, the file's inode number and superblock device):
 * no syscall argument, user address, path, payload or memory content is
 * read or emitted. Shared by the BPF build and the userspace mirror in
 * `src/attach/member_stop.rs`, which pins every layout below. */
#ifndef P11SCOPE_MEMBER_STOP_H
#define P11SCOPE_MEMBER_STOP_H

typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned char u8;

#define MS_SEC(name) __attribute__((section(name), used))
#define MS_INLINE inline __attribute__((always_inline))
#define MS_UINT(name, value) int (*name)[value]
#define MS_TYPE(name, value) typeof(value) *name

/* Capacities: mirrored as MEMBER_STOP_ENTRIES / MEMBER_CLEARED_ENTRIES /
 * MEMBER_STOP_COUNTERS in ebpf-common. */
#define MS_STOP_ENTRIES 1024U
#define MS_CLEARED_ENTRIES 16384U
#define MS_COUNTERS 4U

/* Counter indices (MEMBER_STOP_COUNTER_* in ebpf-common). */
#define MS_COUNT_REQUESTED 0U
#define MS_COUNT_TABLE_FULL 1U
#define MS_COUNT_SIGNAL_FAILED 2U
#define MS_COUNT_IDENTITY_UNREAD 3U

/* BPF map types (stable UAPI numbers; no linux/bpf.h in the object). */
#define MS_MAP_HASH 1U
#define MS_MAP_ARRAY 2U
#define MS_MAP_PERCPU_ARRAY 6U
#define MS_MAP_CGROUP_ARRAY 8U
#define MS_MAP_LRU_HASH 9U
/* BPF_F_RDONLY_PROG: the config row is userspace-written only. */
#define MS_F_RDONLY_PROG (1U << 7)
/* BPF_NOEXIST. */
#define MS_NOEXIST 1ULL
/* -EEXIST from a no-overwrite insert: a stop is already pending. */
#define MS_EEXIST 17
/* linux/mm.h VM_EXEC. */
#define MS_VM_EXEC 0x4UL
/* SIGSTOP. */
#define MS_SIGSTOP 19U

/* MS_CFG value (ARRAY 1, userspace writer): `active` gates every stop,
 * `exempt_tgid` is the owned child, whose own pause chain owns it. */
struct ms_cfg {
    u32 active;
    u32 exempt_tgid;
};
_Static_assert(sizeof(struct ms_cfg) == 8, "config ABI");

/* Kernel file identity: raw superblock s_dev and i_ino. */
struct ms_file {
    u64 dev;
    u64 ino;
};
_Static_assert(sizeof(struct ms_file) == 16, "file key ABI");

/* MS_STOPS value: the file whose mapping requested the stop and the
 * monotonic time of the request. */
struct ms_stop {
    struct ms_file file;
    u64 hook_ts_ns;
};
_Static_assert(sizeof(struct ms_stop) == 24, "stop ABI");
_Static_assert(__builtin_offsetof(struct ms_stop, hook_ts_ns) == 16, "stop time");

#endif
