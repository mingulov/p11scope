/* SPDX-License-Identifier: GPL-2.0-only */
/* Task 3 Stage A: per-(process, provider file) load-instance continuity
 * witness. The hooks read kernel VMA/file/mm metadata only: no syscall
 * argument, user address, path or memory content is read or emitted. Shared
 * by the Detailed BPF build and the host-compiled regression harness. */
#ifndef P11SCOPE_INSTANCE_EPOCH_H
#define P11SCOPE_INSTANCE_EPOCH_H

typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define INST_SEC(name) __attribute__((section(name), used))
#define INST_INLINE inline __attribute__((always_inline))
#define INST_UINT(name, value) int (*name)[value]
#define INST_TYPE(name, value) typeof(value) *name

/* INSTANCE_START capacity: the default START capacity (in-flight calls).
 * The small-state build shrinks it to one entry so LRU eviction is
 * injectable live (any two overlapping in-flight calls evict). It is the
 * only shrunken bound: FILE_SLOTS, RECORD_SLOTS and the slot bound keep
 * production values because userspace mirrors them (ebpf-common has no
 * small-state variant for them; shrinking one side would desync the ABI).
 *
 * N10 sizing: INSTANCE_START faces START's load plus orphans — entries
 * recorded before store_start whose START insert then fails, return-path
 * early exits (unmatched START, scope loss, remove failures) that never
 * consume, and ABANDON START removals without a return. An orphan is
 * overwritten by its key's next call or reclaimed by the LRU, so live
 * capacity is 16384 minus transient orphans; under high refusal rates
 * live entries evict into Unstamped (a fail-closed availability cost,
 * never a join). */
#ifdef P11SCOPE_SMALL_STATE_MAPS
#define INST_START_ENTRIES 1U
#else
#define INST_START_ENTRIES 16384U
#endif
#ifndef P11SCOPE_INSTANCE_SLOT_BOUND
#define P11SCOPE_INSTANCE_SLOT_BOUND 512U
#endif
#define INST_FILE_SLOTS 1024U
#define INST_RECORD_SLOTS 8
#define INST_CAS_TRIES 8
#define INST_CLONE_VM 0x00000100ULL
#define INST_CLONE_THREAD 0x00010000ULL
/* sched.h PF_KTHREAD: a kernel thread, which may borrow an mm without an
 * mm_users reference (kthread_use_mm). Borrowers never localize. */
#define INST_PF_KTHREAD 0x00200000U

/* Stamp flags; the record flag bits equal their stamp bits. Tracks
 * p11scope_ebpf_common::instance; change both together. */
#define INST_STAMP_VALID ((u16)1 << 15)
#define INST_STAMP_NO_FILE ((u16)1 << 0)
#define INST_STAMP_NO_TASK ((u16)1 << 1)
#define INST_STAMP_SHARED_MM ((u16)1 << 2)
#define INST_STAMP_OVERFLOW ((u16)1 << 3)
#define INST_STAMP_LOCAL_FAULT ((u16)1 << 4)
#define INST_RECORD_SHARED_MM (1ULL << 2)
#define INST_RECORD_OVERFLOW (1ULL << 3)
#define INST_RECORD_LOCAL_FAULT (1ULL << 4)
#define INST_RECORD_FLAG_MASK \
    (INST_RECORD_SHARED_MM | INST_RECORD_OVERFLOW | INST_RECORD_LOCAL_FAULT)

#define INST_GEN_FAULT 0U
#define INST_GEN_ATTACH 1U
#define INST_GEN_STICKY 2U
#define INST_GEN_CELLS 3U
/* INSTANCE_GEN[STICKY] bits: conditions that disable routing for the rest
 * of the capture (a later epoch cannot repair them). */
#define INST_STICKY_FORK_UNMARKED 1ULL

struct instance_stamp {
    u32 epoch;
    u32 global;
    u32 fault;
    u16 file_slot_plus1;
    u16 flags;
};
/* Matches ebpf-common StartKey: the in-flight call's pairing key. */
struct instance_start_key {
    u64 pid_tgid;
    u32 slot;
    u32 pad;
};
/* INSTANCE_START value (ebpf-common InstanceEntry). */
struct instance_entry {
    u64 entry_ip;
    struct instance_stamp entry_stamp;
};
/* EventRecord tail (ebpf-common InstanceContinuity). */
struct instance_continuity {
    u64 entry_ip;
    struct instance_stamp entry_stamp;
    struct instance_stamp return_stamp;
};
/* 64-bit cells only: this toolchain lowers 64-bit compare-exchange and
 * non-fetch add; 32-bit atomics need -mcpu=v3, which F1 forbids. */
struct instance_record {
    u64 slot_plus1[INST_RECORD_SLOTS];
    u64 epoch[INST_RECORD_SLOTS];
    u64 flags;
    u64 exec_attach_gen;
};
struct instance_file_key {
    u64 dev;
    u64 ino;
};
struct instance_calib {
    u32 tid;
    u32 pad;
    u64 vm_start;
    u64 dev;
    u64 ino;
    u64 hits;
};
struct instance_counters {
    u64 watched_hits;
    u64 local_bumps;
    u64 global_bumps;
    u64 remote;
    u64 shared;
    u64 storage_null;
    u64 overflow;
    u64 teardown_skips;
    u64 faults;
    u64 calib_hits;
};
_Static_assert(sizeof(struct instance_stamp) == 16, "stamp ABI");
_Static_assert(__builtin_offsetof(struct instance_stamp, file_slot_plus1) == 12, "stamp slot");
_Static_assert(__builtin_offsetof(struct instance_stamp, flags) == 14, "stamp flags");
_Static_assert(sizeof(struct instance_start_key) == 16, "start key ABI");
_Static_assert(sizeof(struct instance_entry) == 24, "entry ABI");
_Static_assert(sizeof(struct instance_continuity) == 40, "continuity ABI");
_Static_assert(__builtin_offsetof(struct instance_continuity, return_stamp) == 24, "continuity ret");
_Static_assert(sizeof(struct instance_record) == 144, "record ABI");
_Static_assert(__builtin_offsetof(struct instance_record, epoch) == 64, "record epoch");
_Static_assert(__builtin_offsetof(struct instance_record, flags) == 128, "record flags");
_Static_assert(__builtin_offsetof(struct instance_record, exec_attach_gen) == 136, "record gen");
_Static_assert(sizeof(struct instance_file_key) == 16, "key ABI");
_Static_assert(sizeof(struct instance_calib) == 40, "calib ABI");
_Static_assert(sizeof(struct instance_counters) == 80, "counters ABI");

#endif
