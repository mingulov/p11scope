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
#define OWNER_CAS_TRIES 8
#if defined(P11SCOPE_INVENTORY_ONLY)
#define OWNER_LIMIT 64ULL
#elif defined(P11SCOPE_SMALL_STATE_MAPS)
#define OWNER_LIMIT 65ULL
#else
#define OWNER_LIMIT 16448ULL
#endif
#define OWNER_BAD_CONTROL 1ULL
#define OWNER_LOOKUP_UNKNOWN 2ULL
#define OWNER_BAD_RECORD 4ULL
#define OWNER_DELETE_FAILED 8ULL
#define OWNER_BOOKKEEPING_FAILED 16ULL
#define OWNER_REFUND_FAILED 32ULL
#define OWNER_CLASSIFIER_FAILED 64ULL
#define OWNER_STATE_DELETE_FAILED 128ULL

struct task_struct;
struct thread_owner {
    u64 original_pid_tgid;
    u64 discovery_cookies[64];
    u64 occupied;
    u64 selection_domains;
    u32 start_count;
    u32 flags;
};
/* Loader publishes limit=OWNER_LIMIT, all other fields zero before links,
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
struct owner_discovery_key { u64 pid_tgid; u64 cookie; u64 domain; };
_Static_assert(sizeof(struct thread_owner) == 544, "owner ABI");
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

/* Existing real Rust map symbols; only their addresses enter map helpers. */
#ifndef P11SCOPE_INVENTORY_ONLY
extern unsigned char START;
#endif
extern unsigned char DISCOVERY_STATE;
static void *(*owner_map_lookup)(void *, const void *) = (void *)1;
static long (*owner_map_update)(void *, const void *, const void *, u64) = (void *)2;
static long (*owner_map_delete)(void *, const void *) = (void *)3;
static u64 (*owner_pid_tgid)(void) = (void *)14;
static void *(*owner_storage_get)(void *, struct task_struct *, void *, u64) = (void *)156;
static long (*owner_storage_delete)(void *, struct task_struct *) = (void *)157;
static struct task_struct *(*owner_current_task)(void) = (void *)158;
#endif
