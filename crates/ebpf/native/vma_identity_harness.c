/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host behavioral harness for `p11_anchor_vma` (W3-1 fix round 3, items
 * 3W1F3-01/02). Compiles the REAL `vma_identity.c` for host with stub
 * maps and captured emits: the BPF helper pointers are renamed to
 * host-owned function pointers (assigned in `main` before any program
 * runs), `P11_READ` becomes a byte copy (exactly what the probe read
 * delivers), and `p11_field_exists` is true (the driven anchor path
 * never consults it; the sole use is the target-run `VM_EXEC`
 * pre-filter at `vma_identity.c:296`, undriven here). Zero
 * production-C changes: this TU only adds
 * preprocessor renames around the real sources, so a guard regression
 * in `vma_identity.c` fails these scenarios. Built and driven by the
 * `anchor_host_harness_replay_and_arena_behavior` test; never shipped.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#undef __always_inline
#define p11_map_lookup host_lookup_ptr
#define p11_map_update host_update_ptr
#define p11_map_delete host_delete_ptr
#define p11_probe_read_kernel host_probe_ptr
#define p11_seq_write host_seq_ptr
#include "vma_identity.h"
#undef P11_READ
#define P11_READ(dst, src) memcpy(&(dst), &(src), sizeof(dst))
#undef p11_field_exists
#define p11_field_exists(field) 1
#include "vma_identity.c"

/* ---- Stub maps: BPF lookup/update/delete semantics over host memory. ---- */
#define HOST_ANCHOR_MAX 1024
static struct {
    u64 key;
    struct p11_anchor_entry value;
    int used;
} host_hash[HOST_ANCHOR_MAX];
static u64 host_slots[HOST_ANCHOR_MAX];
static u64 host_observed[HOST_ANCHOR_MAX];
static struct p11_identity_config host_config;
static u64 host_scope[P11_IDENT_SCOPE_WORDS];

static void *host_impl_lookup(void *map, const void *key)
{
    if (map == (void *)&anchors) {
        u64 want = 0;
        int i;
        memcpy(&want, key, sizeof want);
        for (i = 0; i < HOST_ANCHOR_MAX; i++) {
            if (host_hash[i].used && host_hash[i].key == want)
                return &host_hash[i].value;
        }
        return (void *)0;
    }
    if (map == (void *)&anchor_slots || map == (void *)&anchor_observed ||
        map == (void *)&scope_bitmap) {
        u32 index = 0;
        u32 bound = P11_IDENT_ANCHOR_SLOTS;
        u64 *cells = host_slots;
        memcpy(&index, key, sizeof index);
        if (map == (void *)&anchor_observed) {
            cells = host_observed;
        } else if (map == (void *)&scope_bitmap) {
            cells = host_scope;
            bound = P11_IDENT_SCOPE_WORDS;
        }
        if (index >= bound)
            return (void *)0;
        return &cells[index];
    }
    if (map == (void *)&config) {
        u32 index = 0;
        memcpy(&index, key, sizeof index);
        if (index != 0)
            return (void *)0;
        return &host_config;
    }
    return (void *)0;
}

static long host_impl_update(void *map, const void *key, const void *value, u64 flags)
{
    (void)flags; /* the anchor program only uses UPDATE_ANY */
    if (map == (void *)&anchors) {
        u64 want = 0;
        int i;
        memcpy(&want, key, sizeof want);
        for (i = 0; i < HOST_ANCHOR_MAX; i++) {
            if (host_hash[i].used && host_hash[i].key == want) {
                memcpy(&host_hash[i].value, value, sizeof host_hash[i].value);
                return 0;
            }
        }
        for (i = 0; i < HOST_ANCHOR_MAX; i++) {
            if (!host_hash[i].used) {
                host_hash[i].used = 1;
                host_hash[i].key = want;
                memcpy(&host_hash[i].value, value, sizeof host_hash[i].value);
                return 0;
            }
        }
        return -1; /* FULL: the map refused the insert */
    }
    {
        void *cell = host_impl_lookup(map, key);
        u64 size = 8;
        if (!cell)
            return -1;
        if (map == (void *)&config)
            size = sizeof host_config;
        memcpy(cell, value, size);
        return 0;
    }
}

static long host_impl_delete(void *map, const void *key)
{
    if (map == (void *)&anchors) {
        u64 want = 0;
        int i;
        memcpy(&want, key, sizeof want);
        for (i = 0; i < HOST_ANCHOR_MAX; i++) {
            if (host_hash[i].used && host_hash[i].key == want) {
                host_hash[i].used = 0;
                return 0;
            }
        }
    }
    return -1;
}

/* ---- Captured emits. ---- */
#define HOST_CAPTURE_MAX 64
static struct p11_vma_identity_record host_capture[HOST_CAPTURE_MAX];
static int host_capture_n;

static long host_impl_seq_write(void *seq, const void *data, u32 len)
{
    (void)seq;
    if (len != P11_IDENT_RECORD_LEN || host_capture_n >= HOST_CAPTURE_MAX)
        return -1;
    memcpy(&host_capture[host_capture_n++], data, len);
    return 0;
}

/* ---- Observation driver. ---- */
static struct p11_iter_meta host_meta;
static struct task_struct host_task;
static struct vm_area_struct host_vma;
static struct file host_file;
static struct p11_iter_task_vma host_ctx;

static void host_reset(u64 gen, u64 base, u64 len, u32 slots, u32 observer)
{
    memset(host_hash, 0, sizeof host_hash);
    memset(host_slots, 0, sizeof host_slots);
    memset(host_observed, 0, sizeof host_observed);
    memset(host_scope, 0, sizeof host_scope);
    memset(&host_config, 0, sizeof host_config);
    host_config.gen = gen;
    host_config.arena_base = base;
    host_config.arena_len = len;
    host_config.slots = slots;
    host_config.observer_tgid = observer;
    host_capture_n = 0;
}

/* Feed one VMA observation to the anchor program; returns the capture
 * index of its first newly emitted record. */
static int host_observe(u64 start, u64 end, u64 inode, int tgid)
{
    int first;
    host_task.pid = tgid;
    host_task.tgid = tgid;
    host_file.f_inode = (struct inode *)(uintptr_t)inode;
    host_vma.vm_start = (unsigned long)start;
    host_vma.vm_end = (unsigned long)end;
    host_vma.vm_flags = P11_IDENT_VM_EXEC;
    host_vma.vm_file = &host_file;
    host_meta.seq = (void *)0x1; /* nonzero: emits proceed */
    host_meta.session_id = 0;
    host_meta.seq_num = 0;
    host_ctx.meta = &host_meta;
    host_ctx.task = &host_task;
    host_ctx.vma = &host_vma;
    first = host_capture_n;
    p11_anchor_vma(&host_ctx);
    return first;
}

/* Anonymous-VMA variant: no `vm_file`, silently skipped by the program. */
static int host_observe_anon(u64 start, u64 end, int tgid)
{
    int first;
    host_task.pid = tgid;
    host_task.tgid = tgid;
    host_vma.vm_start = (unsigned long)start;
    host_vma.vm_end = (unsigned long)end;
    host_vma.vm_flags = P11_IDENT_VM_EXEC;
    host_vma.vm_file = (struct file *)0;
    host_meta.seq = (void *)0x1;
    host_meta.session_id = 0;
    host_meta.seq_num = 0;
    host_ctx.meta = &host_meta;
    host_ctx.task = &host_task;
    host_ctx.vma = &host_vma;
    first = host_capture_n;
    p11_anchor_vma(&host_ctx);
    return first;
}

static const struct p11_anchor_entry *host_anchor_find(u64 addr)
{
    return host_impl_lookup((void *)&anchors, &addr);
}

static int host_anchors_used(void)
{
    int used = 0;
    int i;
    for (i = 0; i < HOST_ANCHOR_MAX; i++)
        used += host_hash[i].used ? 1 : 0;
    return used;
}

static void host_print_record(int index)
{
    const struct p11_vma_identity_record *r = &host_capture[index];
    printf("EMIT #%d kind=%u a=%u start=0x%llx end=0x%llx verdict=%u gen=%u\n", index,
           (unsigned)r->kind, (unsigned)r->a, (unsigned long long)r->start,
           (unsigned long long)r->end, (unsigned)r->verdict, (unsigned)r->gen);
}

static int host_failures;
#define HOST_CHECK(cond, name)                                                                     \
    do {                                                                                           \
        if (cond) {                                                                                \
            printf("ASSERT %s\n", name);                                                          \
        } else {                                                                                   \
            printf("FAIL %s\n", name);                                                            \
            host_failures++;                                                                       \
        }                                                                                          \
    } while (0)

/*
 * (a) X→DUP→drop→Y-remap→replay: the overflow-discarded DUP keeps its
 * side effects, so the remap replay must CONFLICT (never a second OK)
 * and install nothing.
 */
static void scenario_replay_remap_conflict(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    const u64 y = 0xFFFF888000002000ULL;
    const struct p11_anchor_entry *found;
    int dup_at;
    int replay_at;
    host_reset(7, base, 1024 * stride, 1024, 100);
    host_observe(base, base + page, x, 100);
    host_print_record(0);
    HOST_CHECK(host_capture_n == 1 && host_capture[0].verdict == P11_IDENT_ANCHOR_OK &&
                   host_capture[0].a == 0,
               "slot0_installs_x");
    dup_at = host_capture_n;
    host_observe(base + 1023 * stride, base + 1023 * stride + page, x, 100);
    host_print_record(dup_at);
    HOST_CHECK(host_capture_n - dup_at == 1 &&
                   host_capture[dup_at].verdict == P11_IDENT_ANCHOR_DUP &&
                   host_capture[dup_at].a == 1023 && host_capture[dup_at].start == 0,
               "dup_aliases_slot0");
    /* Overflow: the DUP emission is discarded, its side effects kept. */
    host_capture_n = dup_at;
    printf("DROP dup emission (overflow simulation)\n");
    replay_at = host_capture_n;
    host_observe(base + 1023 * stride, base + 1023 * stride + page, y, 100);
    host_print_record(replay_at);
    HOST_CHECK(host_capture_n - replay_at == 1 &&
                   host_capture[replay_at].verdict == P11_IDENT_ANCHOR_CONFLICT &&
                   host_capture[replay_at].a == 1023,
               "conflict_on_remap_replay");
    HOST_CHECK(host_capture_n - replay_at == 1 &&
                   host_capture[replay_at].verdict != P11_IDENT_ANCHOR_OK,
               "no_second_ok");
    found = host_anchor_find(y);
    HOST_CHECK(found == (void *)0, "y_not_installed");
    found = host_anchor_find(x);
    HOST_CHECK(found != (void *)0 && found->slot == 0 && found->gen == 7,
               "x_still_rooted_at_slot0");
    HOST_CHECK(host_slots[1023] == x && host_observed[1023] == 8, "slot1023_bookkeeping_kept");
    printf("MAP slot_cell[1023]=0x%llx observed[1023]=%llu\n",
           (unsigned long long)host_slots[1023], (unsigned long long)host_observed[1023]);
}

/* (b) Legitimate between-pass change: a fresh generation reinstalls the
 * slot cleanly (OK, never CONFLICT), clearing the stale entry. */
static void scenario_between_pass_change(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    const u64 y = 0xFFFF888000002000ULL;
    const struct p11_anchor_entry *found;
    host_reset(7, base, 8 * stride, 8, 100);
    host_observe(base + 5 * stride, base + 5 * stride + page, x, 100);
    host_print_record(0);
    HOST_CHECK(host_capture_n == 1 && host_capture[0].verdict == P11_IDENT_ANCHOR_OK &&
                   host_capture[0].a == 5,
               "ok_first_install");
    /* Fresh pass: same maps, new generation. */
    host_config.gen = 8;
    host_capture_n = 0;
    host_observe(base + 5 * stride, base + 5 * stride + page, y, 100);
    host_print_record(0);
    HOST_CHECK(host_capture_n == 1 && host_capture[0].verdict == P11_IDENT_ANCHOR_OK &&
                   host_capture[0].a == 5,
               "ok_on_between_pass_change");
    HOST_CHECK(host_anchor_find(x) == (void *)0, "stale_x_cleared");
    found = host_anchor_find(y);
    HOST_CHECK(found != (void *)0 && found->slot == 5 && found->gen == 8,
               "y_installed_at_slot5");
    HOST_CHECK(host_slots[5] == y && host_observed[5] == 9, "bookkeeping_follows_new_gen");
}

/* (c) Same-address replay is idempotent: a second OK, maps unchanged. */
static void scenario_same_address_replay(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    const struct p11_anchor_entry *found;
    int replay_at;
    host_reset(7, base, 8 * stride, 8, 100);
    host_observe(base + 2 * stride, base + 2 * stride + page, x, 100);
    HOST_CHECK(host_capture_n == 1 && host_capture[0].verdict == P11_IDENT_ANCHOR_OK,
               "ok_first_install");
    replay_at = host_capture_n;
    host_observe(base + 2 * stride, base + 2 * stride + page, x, 100);
    host_print_record(replay_at);
    HOST_CHECK(host_capture_n - replay_at == 1 &&
                   host_capture[replay_at].verdict == P11_IDENT_ANCHOR_OK &&
                   host_capture[replay_at].a == 2,
               "ok_on_same_address_replay");
    found = host_anchor_find(x);
    HOST_CHECK(found != (void *)0 && found->slot == 2 && found->gen == 7 &&
                   host_anchors_used() == 1 && host_slots[2] == x && host_observed[2] == 8,
               "anchors_unchanged");
}

/* (d) A fresh generation after CONFLICT installs cleanly. */
static void scenario_fresh_gen_after_conflict(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    const u64 y = 0xFFFF888000002000ULL;
    const struct p11_anchor_entry *found;
    int replay_at;
    host_reset(7, base, 1024 * stride, 1024, 100);
    host_observe(base, base + page, x, 100);
    host_observe(base + 1023 * stride, base + 1023 * stride + page, x, 100);
    host_capture_n = 1; /* drop the DUP emission */
    replay_at = host_capture_n;
    host_observe(base + 1023 * stride, base + 1023 * stride + page, y, 100);
    HOST_CHECK(host_capture_n - replay_at == 1 &&
                   host_capture[replay_at].verdict == P11_IDENT_ANCHOR_CONFLICT,
               "conflict_in_old_gen");
    host_config.gen = 8;
    host_capture_n = 0;
    replay_at = host_capture_n;
    host_observe(base + 1023 * stride, base + 1023 * stride + page, y, 100);
    host_print_record(replay_at);
    HOST_CHECK(host_capture_n - replay_at == 1 &&
                   host_capture[replay_at].verdict == P11_IDENT_ANCHOR_OK &&
                   host_capture[replay_at].a == 1023,
               "ok_after_conflict_in_fresh_gen");
    found = host_anchor_find(y);
    HOST_CHECK(found != (void *)0 && found->slot == 1023 && found->gen == 8 &&
                   host_slots[1023] == y && host_observed[1023] == 9,
               "y_installed_cleanly");
}

/* (e) A VMA starting inside the reservation but extending past its end
 * is a shape failure, never an install. */
static void scenario_straddle_bad_shape(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    host_reset(7, base, 4 * stride, 4, 100);
    host_observe(base + 2 * stride, base + 4 * stride + page, x, 100);
    host_print_record(0);
    HOST_CHECK(host_capture_n == 1 &&
                   host_capture[0].verdict == P11_IDENT_ANCHOR_BAD_SHAPE &&
                   host_capture[0].a == 2,
               "bad_shape_on_straddle");
    HOST_CHECK(host_anchors_used() == 0 && host_slots[2] == 0 && host_observed[2] == 0,
               "nothing_installed");
}

/* (e2) A page-sized, aligned, in-slots VMA that still extends past the
 * reservation end isolates the `end > base + len` disjunct: every
 * other guard passes (length is exactly a page, offset is
 * stride-aligned, the slot is installed), so only the containment
 * predicate can reject it. Deleting that disjunct installs slot 1. */
static void scenario_straddle_contained_length(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    host_reset(7, base, 9000, 4, 100);
    host_observe(base + stride, base + stride + page, x, 100);
    host_print_record(0);
    HOST_CHECK(host_capture_n == 1 &&
                   host_capture[0].verdict == P11_IDENT_ANCHOR_BAD_SHAPE &&
                   host_capture[0].a == 1,
               "bad_shape_on_contained_length_straddle");
    HOST_CHECK(host_anchors_used() == 0 && host_slots[1] == 0 && host_observed[1] == 0,
               "contained_length_straddle_installs_nothing");
}

/* (f) Misaligned / oversized / past-slots / zero-inode shapes fail;
 * anonymous VMAs are silently skipped; nothing installs anywhere. */
static void scenario_shape_cases(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    int at;
    host_reset(7, base, 4 * stride, 4, 100);
    at = host_observe(base + 1, base + 1 + page, x, 100);
    HOST_CHECK(host_capture_n - at == 1 &&
                   host_capture[at].verdict == P11_IDENT_ANCHOR_BAD_SHAPE,
               "bad_shape_on_misaligned");
    HOST_CHECK(host_anchors_used() == 0, "no_install_on_misaligned");
    at = host_observe(base, base + 2 * page, x, 100);
    HOST_CHECK(host_capture_n - at == 1 &&
                   host_capture[at].verdict == P11_IDENT_ANCHOR_BAD_SHAPE,
               "bad_shape_on_oversized");
    HOST_CHECK(host_anchors_used() == 0, "no_install_on_oversized");
    host_reset(7, base, 16 * stride, 4, 100);
    at = host_observe(base + 10 * stride, base + 10 * stride + page, x, 100);
    host_print_record(at);
    HOST_CHECK(host_capture_n - at == 1 &&
                   host_capture[at].verdict == P11_IDENT_ANCHOR_BAD_SHAPE &&
                   host_capture[at].a == 10,
               "bad_shape_past_slots");
    HOST_CHECK(host_anchors_used() == 0, "no_install_past_slots");
    host_reset(7, base, 4 * stride, 4, 100);
    at = host_observe(base, base + page, 0, 100);
    HOST_CHECK(host_capture_n - at == 1 &&
                   host_capture[at].verdict == P11_IDENT_ANCHOR_BAD_SHAPE &&
                   host_capture[at].a == 0,
               "bad_shape_on_zero_inode");
    HOST_CHECK(host_anchors_used() == 0, "no_install_on_zero_inode");
    at = host_observe_anon(base, base + page, 100);
    HOST_CHECK(host_capture_n - at == 0, "anon_silently_skipped");
    HOST_CHECK(host_anchors_used() == 0 && host_slots[0] == 0 && host_observed[0] == 0,
               "nothing_installed_anywhere");
}

/* (g) A contained valid VMA installs. */
static void scenario_contained_install(void)
{
    const u64 base = 0x7F0000000000ULL;
    const u64 stride = P11_IDENT_ANCHOR_STRIDE;
    const u64 page = P11_IDENT_PAGE;
    const u64 x = 0xFFFF888000001000ULL;
    const struct p11_anchor_entry *found;
    host_reset(7, base, 4 * stride, 4, 100);
    host_observe(base + 3 * stride, base + 3 * stride + page, x, 100);
    host_print_record(0);
    HOST_CHECK(host_capture_n == 1 && host_capture[0].verdict == P11_IDENT_ANCHOR_OK &&
                   host_capture[0].a == 3,
               "ok_on_contained_install");
    found = host_anchor_find(x);
    HOST_CHECK(found != (void *)0 && found->slot == 3 && found->gen == 7 &&
                   host_slots[3] == x && host_observed[3] == 8,
               "contained_vma_installed");
}

static const struct {
    const char *name;
    void (*run)(void);
} scenarios[] = {
    {"replay-remap-conflict", scenario_replay_remap_conflict},
    {"between-pass-change", scenario_between_pass_change},
    {"same-address-replay", scenario_same_address_replay},
    {"fresh-gen-after-conflict", scenario_fresh_gen_after_conflict},
    {"straddle-bad-shape", scenario_straddle_bad_shape},
    {"straddle-contained-length", scenario_straddle_contained_length},
    {"shape-cases", scenario_shape_cases},
    {"contained-install", scenario_contained_install},
};

static int run_one(const char *name, void (*run)(void))
{
    host_failures = 0;
    printf("SCENARIO %s START\n", name);
    run();
    printf("SCENARIO %s %s\n", name, host_failures == 0 ? "PASS" : "FAIL");
    return host_failures == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    unsigned i;
    host_lookup_ptr = host_impl_lookup;
    host_update_ptr = host_impl_update;
    host_delete_ptr = host_impl_delete;
    host_seq_ptr = host_impl_seq_write;
    (void)host_probe_ptr;
    if (argc != 2) {
        fprintf(stderr, "usage: %s <scenario|all>\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "all") == 0) {
        int failed = 0;
        for (i = 0; i < sizeof scenarios / sizeof scenarios[0]; i++)
            failed += run_one(scenarios[i].name, scenarios[i].run);
        printf("ALL %s\n", failed == 0 ? "PASS" : "FAIL");
        return failed == 0 ? 0 : 1;
    }
    for (i = 0; i < sizeof scenarios / sizeof scenarios[0]; i++) {
        if (strcmp(argv[1], scenarios[i].name) == 0)
            return run_one(scenarios[i].name, scenarios[i].run);
    }
    fprintf(stderr, "unknown scenario %s\n", argv[1]);
    return 2;
}
