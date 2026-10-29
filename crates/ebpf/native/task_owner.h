/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef P11SCOPE_TASK_OWNER_H
#define P11SCOPE_TASK_OWNER_H

typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
#define OWNER_LEASED 1U
#ifndef P11SCOPE_OWNER_SLOT_BOUND
#ifdef P11SCOPE_COUNTER_BANK_PROOF
#define P11SCOPE_OWNER_SLOT_BOUND 8192U
#else
#define P11SCOPE_OWNER_SLOT_BOUND 512U
#endif
#endif
#ifdef P11SCOPE_COUNTER_BANK_PROOF
_Static_assert(P11SCOPE_OWNER_SLOT_BOUND == 8192U, "bank owner bound must match cleanup");
#endif
#if defined(P11SCOPE_INVENTORY_ONLY)
#define OWNER_LIMIT 64ULL
#elif defined(P11SCOPE_SMALL_STATE_MAPS)
#define OWNER_LIMIT 65ULL
#else
#define OWNER_LIMIT 16448ULL
#endif
/* Admission claims with a non-fetch atomic add and undoes an over-limit claim,
 * so in-flight over-limit claims can transiently raise `outstanding` above
 * OWNER_LIMIT. Each task runs at most one claim at a time (no owner program
 * nests inside another on one task), so the excess is below PID_MAX_LIMIT
 * (2^22 on 64-bit). A count past this bound is corruption (a wrapped
 * underflow), never contention. */
#define OWNER_TRANSIENT_CLAIMS (1ULL << 22)
#define OWNER_CONTROL_BOUND (OWNER_LIMIT + OWNER_TRANSIENT_CLAIMS)
#define OWNER_BAD_CONTROL 1ULL
#define OWNER_LOOKUP_UNKNOWN 2ULL
#define OWNER_BAD_RECORD 4ULL
#define OWNER_DELETE_FAILED 8ULL
#define OWNER_BOOKKEEPING_FAILED 16ULL
#define OWNER_REFUND_FAILED 32ULL
#define OWNER_CLASSIFIER_FAILED 64ULL
#define OWNER_STATE_DELETE_FAILED 128ULL
/* Exactly which bookkeeping invariant failed; always set together with
 * OWNER_BOOKKEEPING_FAILED so the family bit keeps its meaning. */
#define OWNER_START_KEY_MISMATCH 256ULL
#define OWNER_START_COUNT_MISMATCH 512ULL
#define OWNER_START_ROW_MISSING 1024ULL
#define OWNER_DIRECTORY_MISMATCH 2048ULL
/* A subordinate object row contradicted its START (marker, descriptor,
 * binding or phase). Always set together with OWNER_BOOKKEEPING_FAILED. */
#define OWNER_OBJECT_MISMATCH 4096ULL
/* p11_owner_cleanup outcomes: 0 healthy, 1 failure, 2 a healthy settle
 * that abandoned at least one live START at thread exit. Only 1 is
 * failure; the exit root dirties the leader marker row on 2. */
#define P11_OWNER_CLEANUP_ABANDONED_START 2U

struct task_struct;
struct thread_owner {
    u64 original_pid_tgid;
    u64 discovery_cookies[64];
    u64 occupied;
    u64 selection_domains;
    u32 start_count;
    u32 flags;
#ifndef P11SCOPE_INVENTORY_ONLY
    /* H8 slice-A inactive custody: physical-task lifetime identity for the
     * object journal. Minted once per retained task-storage row (zero
     * means unminted), never recycled, preserved across idle and
     * exec/exit cleanup while lease state clears. Inactive: no live
     * root reads or writes these yet. Inventory-only objects carry no
     * journal words. */
    u64 journal_thread;
    u64 journal_sequence;
#endif
};
/* A thread's owner task storage is created once and retained. flags ==
 * OWNER_LEASED while it holds a lease (START rows or discovery state); flags
 * == 0 with every other field zero while idle between calls. Only exec/exit
 * cleanup removes rows, and the kernel frees the storage with the task.
 * Loader publishes limit=OWNER_LIMIT, all other fields zero before links,
 * then freezes userspace mutation. Poison and debt are terminal, never reset. */
struct owner_control {
    u64 limit;
    u64 outstanding;
    u64 poison;
    u64 admission_failures;
    u64 reclamation_failures;
    u64 abandoned_start;
    u64 abandoned_discovery;
};
struct owner_start_key { u64 pid_tgid; u32 slot; u32 pad; };
#define P11_OWNER_START_REASON_RETURN 0U
#define P11_OWNER_START_REASON_COLLISION 1U
#define P11_OWNER_START_REASON_EXEC_EXIT 6U
#ifndef P11SCOPE_INVENTORY_ONLY
#define JOURNAL_SETTLE_EMPTY 0U
#define JOURNAL_SETTLE_SILENT 1U
#define JOURNAL_SETTLE_ABANDON 2U
#define JOURNAL_SETTLE_BLOCKED 3U
struct journal_settle_words {
    unsigned char record[64];
    u32 state;
    u32 pad;
};
_Static_assert(sizeof(struct journal_settle_words) == 72, "journal settle workspace ABI");
_Static_assert(__builtin_offsetof(struct journal_settle_words, state) == 64, "settle state");
#endif
#if defined(P11SCOPE_OBJECT_JOURNAL) && !defined(P11SCOPE_INVENTORY_ONLY)
/* Optional journal settlement adds no consumed scalar result or new failure
 * branch to ordinary physical cleanup. Existing exported signatures stay intact. */
u32 p11_journal_settle_prepare(const struct owner_start_key *key, u32 reason,
                               struct journal_settle_words *out);
u32 p11_journal_settle_finish(struct journal_settle_words *words, u32 cleanup_committed);
long p11_owner_start_remove_reason(const struct owner_start_key *key, u32 required, u32 reason);
#endif
#if defined(P11SCOPE_LOADER_GATE) && !defined(P11SCOPE_INVENTORY_ONLY)
/* T-L2 loader retirement: START removal plus the owned gate disposition
 * report (see task_owner.c). Host harnesses define P11SCOPE_LOADER_GATE;
 * no production build does, so production objects are unchanged. */
long p11_owner_start_remove_loader(const struct owner_start_key *key, u32 required, u32 reason,
                                   u64 loader_cookie);
#endif
struct owner_discovery_key { u64 pid_tgid; u64 cookie; u64 domain; };
#ifdef P11SCOPE_INVENTORY_ONLY
_Static_assert(sizeof(struct thread_owner) == 544, "owner ABI");
#else
_Static_assert(sizeof(struct thread_owner) == 560, "owner ABI");
_Static_assert(__builtin_offsetof(struct thread_owner, journal_thread) == 544, "journal thread");
_Static_assert(__builtin_offsetof(struct thread_owner, journal_sequence) == 552, "journal sequence");
#endif
_Static_assert(__builtin_offsetof(struct thread_owner, discovery_cookies) == 8, "cookies");
_Static_assert(__builtin_offsetof(struct thread_owner, occupied) == 520, "occupied");
_Static_assert(__builtin_offsetof(struct thread_owner, selection_domains) == 528, "domains");
_Static_assert(__builtin_offsetof(struct thread_owner, start_count) == 536, "START count");
_Static_assert(__builtin_offsetof(struct thread_owner, flags) == 540, "lease");
_Static_assert(sizeof(struct owner_control) == 56, "control ABI");
_Static_assert(__builtin_offsetof(struct owner_control, limit) == 0, "limit");
_Static_assert(__builtin_offsetof(struct owner_control, outstanding) == 8, "outstanding");
_Static_assert(__builtin_offsetof(struct owner_control, poison) == 16, "poison");
_Static_assert(__builtin_offsetof(struct owner_control, admission_failures) == 24, "admission");
_Static_assert(__builtin_offsetof(struct owner_control, reclamation_failures) == 32, "reclamation");
_Static_assert(__builtin_offsetof(struct owner_control, abandoned_start) == 40, "abandoned START");
_Static_assert(__builtin_offsetof(struct owner_control, abandoned_discovery) == 48, "abandoned discovery");
_Static_assert(sizeof(struct owner_start_key) == 16, "START key ABI");
_Static_assert(sizeof(struct owner_discovery_key) == 24, "discovery key ABI");
_Static_assert(__builtin_offsetof(struct owner_start_key, slot) == 8, "START slot");
_Static_assert(__builtin_offsetof(struct owner_start_key, pad) == 12, "START padding");
_Static_assert(__builtin_offsetof(struct owner_discovery_key, cookie) == 8, "discovery cookie");
_Static_assert(__builtin_offsetof(struct owner_discovery_key, domain) == 16, "discovery domain");

/* H7 slice B subordinate custody: one 432-byte ObjectStart row per required
 * object call, keyed by the START key under the same physical owner. The
 * layouts below mirror ebpf-common object_wire byte-exactly; the static
 * asserts pin the shared table. Inventory builds exclude this. */
#ifndef P11SCOPE_INVENTORY_ONLY
#define OBJECT_DESCRIPTORS_COUNT 105U
#define OBJECT_START_BYTES 432U
#define OBJECT_START_WORDS 54U
#define OBJECT_ACTION_MAX 12U
#define OBJECT_GUARD_MAX 2U
#define OBJECT_PHASE_ENTRY 1U
#define OBJECT_PHASE_READY 2U
#define OBJECT_PHASE_RETURNING 3U
#define OBJECT_CALL_START_TS_OFF 0U
#define OBJECT_CALL_START_MARKER_OFF 264U
#define OBJECT_CALL_START_IMAGE_OFF 272U
/* The one original timestamp is also S1's duration origin and the future
 * native BEGIN.entry_ns. Construction must not acquire a replacement clock. */
struct call_start_seed {
    u64 ts_ns;
    u64 task_cookie;
    u64 exec_id;
    u64 object_required;
};
_Static_assert(sizeof(struct call_start_seed) == 32, "START seed ABI");
_Static_assert(_Alignof(struct call_start_seed) == 8, "START seed alignment");
_Static_assert(__builtin_offsetof(struct call_start_seed, ts_ns) == 0, "seed timestamp");
_Static_assert(__builtin_offsetof(struct call_start_seed, task_cookie) == 8, "seed image");
_Static_assert(__builtin_offsetof(struct call_start_seed, exec_id) == 16, "seed exec");
_Static_assert(__builtin_offsetof(struct call_start_seed, object_required) == 24, "seed marker");
struct object_descriptor_row {
    u32 function;
    unsigned char input_args[2];
    unsigned char result_args[2];
    unsigned char template_args[4];
    unsigned char find_capacity_arg;
    unsigned char find_count_arg;
    unsigned char action;
    unsigned char guard;
};
struct object_attr_slot {
    u64 value_ptr;
    u64 entry_capacity;
    u64 returned_len;
    unsigned char kind;
    unsigned char slot_index;
    unsigned char status;
    unsigned char reserved[5];
};
struct object_attr_list {
    unsigned char cells[32];
    unsigned char inspected;
    unsigned char flags;
    unsigned char reserved[2];
};
struct object_start {
    u64 task_cookie;
    u64 exec_id;
    u64 entry_ns;
    u32 descriptor_index;
    unsigned char layout;
    unsigned char action;
    unsigned char derive;
    unsigned char phase;
    u64 inputs[2];
    u64 result_ptrs[2];
    u64 get_template_base;
    u64 inspected_header_end;
    u64 find_capacity;
    u64 find_count_ptr;
    struct object_attr_slot slots[8];
    struct object_attr_list requested[2];
    unsigned char input_statuses[2];
    unsigned char result_statuses[2];
    unsigned short flags;
    unsigned char get_inspected;
    unsigned char reserved;
};
_Static_assert(sizeof(struct object_descriptor_row) == 16, "object descriptor ABI");
_Static_assert(sizeof(struct object_attr_slot) == 32, "object slot ABI");
_Static_assert(sizeof(struct object_attr_list) == 36, "object list ABI");
_Static_assert(sizeof(struct object_start) == 432, "object start ABI");
_Static_assert(__builtin_offsetof(struct object_start, entry_ns) == 16, "object time");
_Static_assert(__builtin_offsetof(struct object_start, descriptor_index) == 24, "object index");
_Static_assert(__builtin_offsetof(struct object_start, layout) == 28, "object layout");
_Static_assert(__builtin_offsetof(struct object_start, inputs) == 32, "object inputs");
_Static_assert(__builtin_offsetof(struct object_start, result_ptrs) == 48, "object results");
_Static_assert(__builtin_offsetof(struct object_start, get_template_base) == 64, "object get");
_Static_assert(__builtin_offsetof(struct object_start, inspected_header_end) == 72, "object span");
_Static_assert(__builtin_offsetof(struct object_start, find_capacity) == 80, "object capacity");
_Static_assert(__builtin_offsetof(struct object_start, find_count_ptr) == 88, "object count");
_Static_assert(__builtin_offsetof(struct object_start, slots) == 96, "object slots");
_Static_assert(__builtin_offsetof(struct object_start, requested) == 352, "object requested");
_Static_assert(__builtin_offsetof(struct object_start, input_statuses) == 424, "object input status");
_Static_assert(__builtin_offsetof(struct object_start, result_statuses) == 426, "object result status");
_Static_assert(__builtin_offsetof(struct object_start, flags) == 428, "object flags");
_Static_assert(__builtin_offsetof(struct object_start, get_inspected) == 430, "object inspected");
_Static_assert(__builtin_offsetof(struct object_start, reserved) == 431, "object reserved");
#endif

/* Existing real Rust map symbols; only their addresses enter map helpers. */
#ifndef P11SCOPE_INVENTORY_ONLY
extern unsigned char START;
extern unsigned char OBJECT_START;
extern unsigned char OBJECT_DESCRIPTORS;
extern unsigned char OBJECT_ZERO;
#endif
extern unsigned char DISCOVERY_STATE;
/* The current task's owner row, or NULL when the task is gone or holds
 * none (task_owner.c; the journal transactions key-bind it before
 * their legs run). */
struct thread_owner *p11_owner_current(void);
static void *(*owner_map_lookup)(void *, const void *) = (void *)1;
static long (*owner_map_update)(void *, const void *, const void *, u64) = (void *)2;
static long (*owner_map_delete)(void *, const void *) = (void *)3;
static u64 (*owner_pid_tgid)(void) = (void *)14;
static void *(*owner_storage_get)(void *, struct task_struct *, void *, u64) = (void *)156;
static long (*owner_storage_delete)(void *, struct task_struct *) = (void *)157;
static struct task_struct *(*owner_current_task)(void) = (void *)158;
#endif
