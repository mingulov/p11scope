#define SEC(s) __attribute__((section(s), used))
#define UINT(n, v) int (*n)[v]
#define TYPE(n, t) t *n
struct legacy_map { unsigned type, key_size, value_size, max_entries, flags, id, pinning; };
struct legacy_map LEGACY SEC("maps") = {1, 4, 8, 3, 0, 0, 0};
static struct { UINT(type, 29); UINT(map_flags, 1); TYPE(key, int); TYPE(value, unsigned long long); } NATIVE SEC(".maps");
SEC("uprobe") int probe(void *ctx) { return 0; }
char LICENSE[] SEC("license") = "GPL";
#ifdef HELPERS
__attribute__((visibility("hidden"), noinline, used))
void *memset(void *dest, int value, unsigned long count) { return dest; }
#define HELPER(name) __attribute__((noinline, used)) int name(void) { return 0; }
HELPER(p11_link_current_identity)
HELPER(p11_link_emit_fork)
HELPER(p11_link_fork_allowed)
/* Task 3 Stage A continuity halves (native instance_epoch.c). */
HELPER(p11_instance_entry)
HELPER(p11_instance_return)
HELPER(p11_instance_exec)
#ifdef OWNER_GLOBAL
#define OWNER_LINKAGE
#else
#define OWNER_LINKAGE static
#endif
/* Volatile inputs and distinct operations retain real out-of-line callsites. */
#define OWNER(name, index) OWNER_LINKAGE __attribute__((noinline)) \
    int name(volatile int *ctx) { return ctx[index]; }
OWNER(p11_owner_cleanup, 0)
OWNER(p11_owner_start_get, 1)
OWNER(p11_owner_start_insert, 2)
OWNER(p11_owner_start_remove, 3)
OWNER(p11_owner_discovery_get, 4)
OWNER(p11_owner_discovery_insert, 5)
OWNER(p11_owner_discovery_remove, 6)
#ifdef OWNER_HEALTHY
OWNER(p11_owner_healthy, 7)
#endif
#define ROOT_HELPER(name, index) static __attribute__((noinline)) \
    int name(volatile int *ctx) { return ctx[index]; }
ROOT_HELPER(p11_root_propagate_thread, 8)
ROOT_HELPER(p11_root_current_tag, 9)
ROOT_HELPER(p11_root_current_exit, 10)
SEC("tp_btf/task_newtask") int task_newtask(void *ctx) {
    int result = p11_owner_start_get(ctx) + p11_owner_start_insert(ctx)
        + p11_owner_start_remove(ctx) + p11_owner_discovery_get(ctx)
        + p11_owner_discovery_insert(ctx) + p11_owner_discovery_remove(ctx);
    result += p11_root_propagate_thread(ctx) + p11_root_current_tag(ctx);
#ifdef OWNER_HEALTHY
    result += p11_owner_healthy(ctx);
#endif
    return result;
}
SEC("raw_tp/sched_process_exec") int sched_process_exec(void *ctx) { return p11_owner_cleanup(ctx); }
SEC("raw_tp/sched_process_exit") int sched_process_exit(void *ctx) {
    return p11_owner_cleanup(ctx) + p11_root_current_exit(ctx);
}
/* Task 3 Stage A continuity witness hooks (Detailed objects only). */
SEC("fentry/uprobe_mmap") int p11_inst_vma_map(void *ctx) { return 0; }
SEC("fentry/uprobe_munmap") int p11_inst_vma_unmap(void *ctx) { return 0; }
SEC("fexit/copy_vma") int p11_inst_vma_copy(void *ctx) { return 0; }
#endif
