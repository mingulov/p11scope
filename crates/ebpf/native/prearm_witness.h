/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Pre-arm mapping-instant witness (WU-13 P-C phase 2). The hooks read kernel
 * VMA/file/mm/task/cgroup metadata only: no syscall argument, user address,
 * path, payload or memory content is read or emitted. Shared by the BPF build
 * and the host-compiled regression harness. */
#ifndef P11SCOPE_PREARM_WITNESS_H
#define P11SCOPE_PREARM_WITNESS_H

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned char u8;

#define PW_SEC(name) __attribute__((section(name), used))
#define PW_INLINE inline __attribute__((always_inline))
#define PW_UINT(name, value) int (*name)[value]
#define PW_TYPE(name, value) typeof(value) *name

/* Slot and map capacities (addendum §4.0). */
#define PW_SLOTS 64U
#define PW_DEPARTED_ENTRIES 16384U
#define PW_VISITED_ENTRIES 65536U
/* Departure re-pend CAS rounds (addendum §4.2). */
#define PW_CAS_TRIES 4
/* Cgroup parent-chain walk bound (addendum §4.4). */
#define PW_CGROUP_MAX_DEPTH 64
/* sched.h PF_KTHREAD. */
#define PW_PF_KTHREAD 0x00200000U

/* Scope kinds for pw_cfg.scope_kind. */
#define PW_SCOPE_PID 1U
#define PW_SCOPE_CGROUP 2U
#define PW_SCOPE_SYSTEM 3U

/* Departed-entry states in the low 2 bits of pw_departed.word. */
#define PW_DEP_PENDING 0ULL
#define PW_DEP_CLEARED 1ULL
#define PW_DEP_DONE 2ULL
#define PW_DEP_STATE_MASK 3ULL
#define PW_DEP_SEQ_SHIFT 2

/* BPF map type numbers (avoid linux/bpf.h in the host harness). */
#define PW_MAP_HASH 1U
#define PW_MAP_ARRAY 2U
/* BPF_F_RDONLY_PROG. */
#define PW_F_RDONLY_PROG (1U << 7)
/* BPF_F_NO_PREALLOC. */
#define PW_F_NO_PREALLOC (1U << 0)
/* BPF_NOEXIST for map_update. */
#define PW_NOEXIST 1ULL

/* PW_CFG value (ARRAY 1, userspace writer). */
struct pw_cfg {
    u32 active;
    u32 scope_kind;
    u32 target_tgid;
    u32 calib_tid;
    u64 cgroup_id;
    u32 calib_index;
    u32 pad;
};
_Static_assert(sizeof(struct pw_cfg) == 32, "pw_cfg ABI");
_Static_assert(__builtin_offsetof(struct pw_cfg, active) == 0, "cfg active");
_Static_assert(__builtin_offsetof(struct pw_cfg, scope_kind) == 4, "cfg scope");
_Static_assert(__builtin_offsetof(struct pw_cfg, target_tgid) == 8, "cfg tgid");
_Static_assert(__builtin_offsetof(struct pw_cfg, calib_tid) == 12, "cfg calib_tid");
_Static_assert(__builtin_offsetof(struct pw_cfg, cgroup_id) == 16, "cfg cgroup");
_Static_assert(__builtin_offsetof(struct pw_cfg, calib_index) == 24, "cfg index");

/* PW_WATCHED key: kernel (s_dev, i_ino). Value is a u32 slot 0..63. */
struct pw_watched_key {
    u64 s_dev;
    u64 i_ino;
};
_Static_assert(sizeof(struct pw_watched_key) == 16, "watched key ABI");

/* PW_CALIB slot (ARRAY, kernel writer). Index PW_SLOTS holds the
 * self-departs calibration counter in `hits` (s_dev/i_ino zero). */
struct pw_calib_slot {
    u64 hits;
    u64 s_dev;
    u64 i_ino;
};
#define PW_CALIB_ENTRIES (PW_SLOTS + 1U)
#define PW_CALIB_SELF_INDEX PW_SLOTS
_Static_assert(sizeof(struct pw_calib_slot) == 24, "calib ABI");

/* PW_STATE value (ARRAY 1, kernel writer). */
struct pw_state {
    u64 busy;
    u64 seq;
    u64 latch_slots;
    u64 torn_slots;
    u64 found_slots;
    u64 migrations;
    u64 pending_in;
    u64 pending_out;
    u64 faults;
    u64 stuck;
    u64 walk_end;
    u64 walk_runs;
    u64 walk_vmas;
};
_Static_assert(sizeof(struct pw_state) == 104, "state ABI");
_Static_assert(__builtin_offsetof(struct pw_state, busy) == 0, "state busy");
_Static_assert(__builtin_offsetof(struct pw_state, seq) == 8, "state seq");
_Static_assert(__builtin_offsetof(struct pw_state, latch_slots) == 16, "state latch");
_Static_assert(__builtin_offsetof(struct pw_state, walk_vmas) == 96, "state vmas");

/* PW_DEPARTED value (HASH, kernel writer). `word` packs state:2 | seq:62. */
struct pw_departed {
    u64 word;
    u64 torn_mask;
    u64 stuck;
};
_Static_assert(sizeof(struct pw_departed) == 24, "departed ABI");

/* PW_RUN value (ARRAY 1, walk writer). Kernel pointers, never read by userspace. */
struct pw_run {
    u64 task;
    u64 mm;
    u64 start_seq;
    u64 count;
    u64 map_count;
    u64 member;
    u64 watched;
};
_Static_assert(sizeof(struct pw_run) == 56, "run ABI");

#endif
