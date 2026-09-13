/* Test-only read-only task-storage iterator. */
typedef unsigned int u32;
typedef unsigned long long u64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define BPF_MAP_TYPE_TASK_STORAGE 29
#define BPF_F_NO_PREALLOC 1

struct seq_file;
struct task_struct {
    int pid;
    int tgid;
} __attribute__((preserve_access_index));
struct bpf_iter_meta {
    struct seq_file *seq;
    u64 session_id;
    u64 seq_num;
};
struct bpf_iter__task {
    struct bpf_iter_meta *meta;
    struct task_struct *task;
};

struct thread_owner_value {
    unsigned char bytes[544];
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 0);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} TASK_COOKIE SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, u32);
    __type(value, struct thread_owner_value);
    __uint(max_entries, 0);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} THREAD_OWNER SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 0);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ROOT_AFFILIATION SEC(".maps");

static void *(*bpf_task_storage_get)(void *, struct task_struct *, void *, u64) =
    (void *)156;
static long (*bpf_seq_write)(struct seq_file *, const void *, u32) = (void *)127;

struct frame_header {
    unsigned char magic[8];
    u32 kind;
    u32 map_slot;
    u32 pid;
    u32 tid;
    u32 value_len;
};

static __attribute__((always_inline)) int emit(struct seq_file *seq,
                                                struct task_struct *task,
                                                void *map, u32 slot,
                                                u32 value_len)
{
    void *value = bpf_task_storage_get(map, task, (void *)0, 0);
    struct frame_header header = {
        .magic = {'P', '1', '1', 'T', 'S', 'R', '1', '\0'},
        .kind = 1,
        .map_slot = slot,
        .pid = __builtin_preserve_access_index(task->tgid),
        .tid = __builtin_preserve_access_index(task->pid),
        .value_len = value_len,
    };

    if (!value)
        return 0;
    if (bpf_seq_write(seq, &header, sizeof(header)) < 0)
        return -1;
    /* Write directly from task storage; THREAD_OWNER never touches the stack. */
    if (bpf_seq_write(seq, value, value_len) < 0)
        return -1;
    return 0;
}

SEC("iter/task")
int dump_task_storage(struct bpf_iter__task *ctx)
{
    struct task_struct *task = ctx->task;

    if (!task)
        return 0;
    /* A bpf_iter program may return only 0 or 1, and the verifier rejects the
     * whole object otherwise (-EINVAL, "At program exit the register R0 ...
     * should have been in [0, 1]"). The two values are not success/failure:
     * 0 keeps this task's written bytes, 1 DISCARDS them and declines the
     * retry. So 0 is correct on every path here, including the one emit()
     * reports nonzero.
     *
     * emit() only returns nonzero when bpf_seq_write() overflowed, which is
     * backpressure rather than an error: the kernel drops this task's partial
     * output and runs the program again for the SAME task on the next read()
     * (see bpf_seq_write in linux/bpf.h -- "The same object will be tried
     * again"). Returning early merely stops writing bytes the kernel is
     * already discarding; returning 1 would turn that retry into permanent
     * data loss, and returning -1 stopped the object loading at all.
     */
    if (emit(ctx->meta->seq, task, &TASK_COOKIE, 0, 8))
        return 0;
    if (emit(ctx->meta->seq, task, &THREAD_OWNER, 1, 544))
        return 0;
    if (emit(ctx->meta->seq, task, &ROOT_AFFILIATION, 2, 8))
        return 0;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
