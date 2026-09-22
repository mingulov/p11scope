/* SPDX-License-Identifier: GPL-2.0-only */
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

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static u64 *(*bpf_task_storage_get)(void *map, struct task_struct *task,
                                 u64 *value, u64 flags) = (void *)156;
static struct task_struct *(*bpf_get_current_task_btf)(void) = (void *)158;
#endif
