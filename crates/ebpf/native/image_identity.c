#include "image_identity.h"

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 0);
    __type(key, int);
    __type(value, u64);
} TASK_COOKIE SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct control);
} COOKIE_CTL SEC(".maps");

struct cookie_result {
    u64 cookie;
    u32 status;
};

extern u32 p11_link_fork_allowed(void);
extern u32 p11_root_propagate_thread(struct task_struct *child, u64 clone_flags);
extern u32 p11_link_emit_fork(u32 child_tgid, u64 clone_flags,
                              const struct image_identity *parent,
                              const struct image_identity *child);

static __always_inline struct control *get_control(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&COOKIE_CTL, &key);
}

static __always_inline void finite_increment(u64 *counter)
{
    u64 old = *counter;
    if (old != U64_MAX_VALUE)
        __sync_val_compare_and_swap(counter, old, old + 1);
}

static __always_inline struct cookie_result cookie_for(struct task_struct *task)
{
    struct cookie_result result = { .cookie = 0, .status = COOKIE_STATUS_BAD_TASK };
    u64 *cell;
    struct control *control;

    if (!task)
        return result;

    control = get_control();
    if (!control) {
        result.status = COOKIE_STATUS_NO_CONTROL;
        return result;
    }
    if (control->limit != IMAGE_IDENTITY_TICKET_LIMIT ||
        control->next_ticket > IMAGE_IDENTITY_TICKET_LIMIT) {
        finite_increment(&control->unavailable);
        result.status = COOKIE_STATUS_BAD_CONFIG;
        return result;
    }

    cell = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
    if (cell) {
        if (*cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
        } else {
            finite_increment(&control->unavailable);
            result.status = COOKIE_STATUS_ZERO_CELL;
        }
        return result;
    }

#pragma unroll
    for (int attempt = 0; attempt < COOKIE_CAS_TRIES; attempt++) {
        u64 ticket = control->next_ticket;
        u64 observed;
        u64 proposed;

        if (ticket >= control->limit) {
            finite_increment(&control->unavailable);
            result.status = COOKIE_STATUS_QUOTA;
            return result;
        }

        observed = __sync_val_compare_and_swap(&control->next_ticket,
                                                ticket, ticket + 1);
        if (observed != ticket)
            continue;

        proposed = ticket + 1;
        cell = bpf_task_storage_get(&TASK_COOKIE, task, &proposed,
                                    BPF_LOCAL_STORAGE_GET_F_CREATE);
        if (cell) {
            if (*cell) {
                result.cookie = *cell;
                result.status = COOKIE_STATUS_OK;
            } else {
                finite_increment(&control->unavailable);
                result.status = COOKIE_STATUS_ZERO_CELL;
            }
            return result;
        }

        cell = bpf_task_storage_get(&TASK_COOKIE, task, (void *)0, 0);
        if (cell && *cell) {
            result.cookie = *cell;
            result.status = COOKIE_STATUS_OK;
            return result;
        }

        finite_increment(&control->create_failures);
        finite_increment(&control->unavailable);
        result.status = COOKIE_STATUS_CREATE_FAILED;
        return result;
    }

    finite_increment(&control->retry_exhausted);
    finite_increment(&control->unavailable);
    result.status = COOKIE_STATUS_RETRY_EXHAUSTED;
    return result;
}

/* Same typed task supplies both fields. Volatile aligned u64 is READ_ONCE-equivalent
 * on the selected x86-64 kernels; exec_id zero is valid, status is separate. */
static __always_inline u32 identity_for(struct task_struct *task,
                                        struct image_identity *out)
{
    struct cookie_result result;
    if (!out)
        return COOKIE_STATUS_BAD_TASK;
    *(volatile u64 *)&out->task_cookie = 0;
    *(volatile u64 *)&out->exec_id = 0;
    result = cookie_for(task);
    if (result.status != COOKIE_STATUS_OK)
        return result.status;
    out->task_cookie = result.cookie;
    out->exec_id = *(volatile u64 *)&task->self_exec_id;
    return COOKIE_STATUS_OK;
}

__attribute__((noinline)) u32 p11_link_current_identity(struct image_identity *out)
{
    if (!out)
        return COOKIE_STATUS_BAD_TASK;
    struct task_struct *current = bpf_get_current_task_btf();
    struct task_struct *leader;
    *(volatile u64 *)&out->task_cookie = 0;
    *(volatile u64 *)&out->exec_id = 0;
    if (!current)
        return COOKIE_STATUS_BAD_TASK;
    leader = current->group_leader;
    return identity_for(leader, out);
}

SEC("tp_btf/task_newtask")
int task_newtask(u64 *ctx)
{
    u64 clone_flags;
    struct task_struct *current;
    struct task_struct *leader;
    struct task_struct *child;
    struct image_identity parent_identity;
    struct image_identity child_identity;
    u32 child_tgid;

    if (!ctx)
        return 0;
    clone_flags = ctx[1];
    child = (struct task_struct *)(unsigned long)ctx[0];
    (void)p11_root_propagate_thread(child, clone_flags);
    if (clone_flags & CLONE_THREAD)
        return 0;
    if (!p11_link_fork_allowed())
        return 0;

    current = bpf_get_current_task_btf();
    if (!current || !child)
        return 0;

    leader = current->group_leader;
    if (child->tgid <= 0)
        return 0;
    child_tgid = (u32)child->tgid;
    if (identity_for(leader, &parent_identity) != COOKIE_STATUS_OK ||
        identity_for(child, &child_identity) != COOKIE_STATUS_OK)
        return 0;

    (void)p11_link_emit_fork(child_tgid, clone_flags, &parent_identity, &child_identity);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
