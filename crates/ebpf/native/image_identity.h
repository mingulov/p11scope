/* SPDX-License-Identifier: GPL-2.0-only */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
#ifndef P11SCOPE_IMAGE_IDENTITY_H
#define P11SCOPE_IMAGE_IDENTITY_H

typedef unsigned int u32;
typedef unsigned long long u64;
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_F_NO_PREALLOC 1
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
#define CLONE_THREAD 0x00010000ULL
#define IMAGE_IDENTITY_TICKET_LIMIT 16384ULL
#define COOKIE_CAS_TRIES 8
#define U64_MAX_VALUE (~0ULL)

enum cookie_status {
    COOKIE_STATUS_OK = 1,
    COOKIE_STATUS_NO_CONTROL = 2,
    COOKIE_STATUS_BAD_CONFIG = 3,
    COOKIE_STATUS_BAD_TASK = 4,
    COOKIE_STATUS_QUOTA = 5,
    COOKIE_STATUS_RETRY_EXHAUSTED = 6,
    COOKIE_STATUS_CREATE_FAILED = 7,
    COOKIE_STATUS_ZERO_CELL = 8,
};

/* Minimal CO-RE shape: field names, never fixed target offsets. */
struct task_struct {
    int tgid;
    struct task_struct *group_leader;
    u64 self_exec_id;
} __attribute__((preserve_access_index));

struct image_identity { u64 task_cookie; u64 exec_id; };
/* Matches ebpf-common ImageIdentityControl. Loader publishes limit=16384,
 * other fields zero, before links. BPF alone mutates while linked; no reset. */
struct control {
    u64 limit;
    u64 next_ticket;
    u64 unavailable;
    u64 create_failures;
    u64 retry_exhausted;
};
_Static_assert(sizeof(struct image_identity) == 16, "identity ABI");
_Static_assert(sizeof(struct control) == 40, "control ABI");
_Static_assert(__builtin_offsetof(struct control, next_ticket) == 8, "ticket offset");
_Static_assert(__builtin_offsetof(struct control, unavailable) == 16, "unavailable offset");
_Static_assert(__builtin_offsetof(struct control, create_failures) == 24, "create offset");
_Static_assert(__builtin_offsetof(struct control, retry_exhausted) == 32, "retry offset");

/* Native-unit bridge; the definition is always inlined into its caller. */
u32 p11_link_task_identity(struct task_struct *task, struct image_identity *out);
/* Cookie only; zero is unavailable. No exec-ID or target-memory read. */
u64 p11_link_current_cookie(void);
#ifdef P11SCOPE_LOADER_GATE
/* T-L2 ticket-query extends (see image_identity.c). Host harnesses and
 * gate-1 production builds (P11SCOPE_LOADER_GATE=1) define
 * P11SCOPE_LOADER_GATE; gate-0 production builds do not, so they carry
 * no code, map or symbol changes from this extend -- only DWARF line
 * info shifts where the guarded source lines sit. */
u32 p11_link_task_ticket(struct task_struct *task, u64 *ticket_out);
u32 p11_image_identity_issued(u64 *watermark_out);
/* Production bank promotion: one cut from bank A to bank B. Second-bank
 * maps live in image_identity.c; the SELECT flip word below carries the
 * current bank, per-slot prepared bits and the L4b image cells. The
 * loader publishes bank=0, prepared={1,0}, cuts=0, refusals=0 before
 * links. The Session prepares B (prepared[1]=1) before A fills; the
 * first A-quota then cuts to B exactly once and the issue lands there,
 * so a prepared cut refuses nothing. A quota cuts back the same way
 * once the other bank is re-prepared; any other quota (unprepared,
 * stale, full or corrupt target) refuses honestly.
 * tickets_issued is derived (folded_issued plus the live watermarks,
 * pending-fold banks excluded), never a cell.
 * Continuity/index maps stay single-bank (A): B tickets are never
 * seeded there, so no key can alias across banks. */
#define IMAGE_BANK_SLOTS 2U
#define IMAGE_BANK_NO_SLOT 2U
/* Incarnations are 48-bit: bit 16 + 48 fills the u64 exactly, so an
 * incarnation at or past 2^48 would wrap the qualifier into an alias. */
#define IMAGE_IDENTITY_INCARNATION_LIMIT (1ULL << 48)
/* Lifecycle: after the cut the Session proves the retired bank drained
 * (a Session-side drain proof, owned outside this unit), then clears
 * that bank's prepared bit as the fold claim. The kernel folds the
 * bank exactly once (retiring its issued count into folded_issued),
 * the Session re-asserts prepared, and the kernel re-prepares the
 * slot under a fresh incarnation. Admission helps fold and re-prepare
 * work on its path, so the transitions complete idempotently under
 * concurrency; a cut to a stale bank refuses until the Session drives
 * the claim cycle. update_losses reports identity-accounting updates
 * the bounded protocol could not settle. */
struct image_bank_select {
    u64 bank;
    u64 prepared[2];
    u64 cuts;
    u64 refusals;
    u64 incarnation[2];
    u64 folded[2];
    u64 folds;
    u64 folded_issued;
    u64 update_losses;
};
/* Qualified identity cookie: the local ticket in bits 0..14, the bank
 * in bit 15, the incarnation in bits 16+. Bank A incarnation 0 keeps
 * legacy cookies identical to tickets; every other (bank,
 * incarnation) issues disjoint cookies while each bank keeps its
 * 1..16384 local budget. The ticket query and the EXEC binding keep
 * returning the local ticket; only the task identity carries the
 * qualifier. Incarnations past the 48-bit range refuse (BAD_CONFIG)
 * instead of wrapping into an alias; stored-cell re-queries probe first
 * and read the source epoch after (safe today because incarnations are
 * immutable until P3b enables re-prepare), while fresh issues bind the
 * guard value read before the ticket CAS, so the qualifier always
 * matches the ticket's epoch. */
static __always_inline u64 image_identity_qualify(u64 ticket, u64 bank, u64 incarnation)
{
    return ticket | (bank << 15) | (incarnation << 16);
}
_Static_assert(sizeof(struct image_bank_select) == 96, "bank select ABI");
_Static_assert(__builtin_offsetof(struct image_bank_select, bank) == 0, "bank current");
_Static_assert(__builtin_offsetof(struct image_bank_select, prepared) == 8, "bank prepared");
_Static_assert(__builtin_offsetof(struct image_bank_select, cuts) == 24, "bank cuts");
_Static_assert(__builtin_offsetof(struct image_bank_select, refusals) == 32, "bank refusals");
_Static_assert(__builtin_offsetof(struct image_bank_select, incarnation) == 40, "bank incarnation");
_Static_assert(__builtin_offsetof(struct image_bank_select, folded) == 56, "bank folded");
_Static_assert(__builtin_offsetof(struct image_bank_select, folds) == 72, "bank folds");
_Static_assert(__builtin_offsetof(struct image_bank_select, folded_issued) == 80, "bank folded issued");
_Static_assert(__builtin_offsetof(struct image_bank_select, update_losses) == 88, "bank losses");
/* Current prepared bank, or IMAGE_BANK_NO_SLOT when SELECT is missing,
 * malformed or names an unprepared bank. */
u32 p11_image_bank_select(void);
/* Flip to a prepared bank exactly once. Returns the bank: the target on
 * the flip (cuts counts the winner only) and idempotently when already
 * there; IMAGE_BANK_NO_SLOT for a bad target, a missing SELECT or an
 * unprepared bank. */
u32 p11_image_bank_cut(u64 target);
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static u64 *(*bpf_task_storage_get)(void *map, struct task_struct *task,
                                 u64 *value, u64 flags) = (void *)156;
static struct task_struct *(*bpf_get_current_task_btf)(void) = (void *)158;
#endif
