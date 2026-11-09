/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com> */
/* Host regression harness for the real pre-arm witness hooks. Every external
 * helper is scripted; every assertion is on production code. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define P11SCOPE_PREARM_WITNESS_HOST_TEST 1
/* Scripted compare-exchange: the next `cas_lose` rounds are lost races. */
static int cas_lose;
static unsigned long long cas_calls;
#define __sync_val_compare_and_swap(cell, old, replacement) \
    test_cas((unsigned long long *)(cell), (old), (replacement))
static unsigned long long __attribute__((unused))
test_cas(unsigned long long *cell, unsigned long long old, unsigned long long replacement)
{
    unsigned long long seen = *cell;
    cas_calls++;
    if (cas_lose > 0) {
        cas_lose--;
        return seen + 1 == old ? seen + 2 : seen + 1; /* never `old` */
    }
    if (seen == old)
        *cell = replacement;
    return seen;
}
#include "prearm_witness.c"

/* Scripted maps. */
static struct pw_cfg cfg;
static u32 watched_slot = 3;
static int watched_present = 1;
static struct pw_watched_key watched_key = { 0x00800025ULL, 4242ULL };
static struct pw_calib_slot calib[PW_CALIB_ENTRIES];
static struct pw_state state;
static u64 self_mm;
static struct pw_run run;

/* Departed map: small scripted table. */
#define TEST_DEPARTED_N 8
static u64 departed_keys[TEST_DEPARTED_N];
static struct pw_departed departed_vals[TEST_DEPARTED_N];
static int departed_used[TEST_DEPARTED_N];
static int departed_insert_fail;
static int departed_full;
/* Visited map: small scripted set. */
#define TEST_VISITED_N 8
static u64 visited_keys[TEST_VISITED_N];
static u8 visited_vals[TEST_VISITED_N];
static int visited_used[TEST_VISITED_N];

/* Fault injection. */
static int read_fail_at = -1;
static int reads;
static u64 fake_pid_tgid = (77ULL << 32) | 78ULL;
static struct task_struct___p11pw *fake_current;

/* Fake kernel objects. */
static struct super_block___p11pw sb = { 0x00800025U };
static struct inode___p11pw inode = { 4242UL, &sb };
static struct inode___p11pw other_inode = { 9999UL, &sb };
static struct file___p11pw file = { &inode };
static struct file___p11pw other_file = { &other_inode };
static struct mm_struct___p11pw mm = { { 1 }, 10 };
static struct mm_struct___p11pw other_mm = { { 1 }, 5 };
static struct mm_struct___p11pw teardown_mm = { { 0 }, 0 };
static struct css_set___p11pw css;
static struct cgroup_subsys_state___p11pw dfl_css;
static struct kernfs_node___p11pw kn_target = { 12345ULL };
static struct kernfs_node___p11pw kn_other = { 99999ULL };
static struct kernfs_node___p11pw kn_parent = { 11111ULL };
static struct cgroup___p11pw cgrp_target;
static struct cgroup___p11pw cgrp_other;
static struct cgroup___p11pw cgrp_parent;
static struct task_struct___p11pw task_member = { &mm, 100, 100, 0, &css };
static struct task_struct___p11pw task_thread = { &mm, 101, 100, 0, &css };
static struct task_struct___p11pw task_other = { &other_mm, 200, 200, 0, &css };
static struct task_struct___p11pw task_kthread = { &mm, 300, 300, PW_PF_KTHREAD, &css };
static struct vm_area_struct___p11pw vma = { &mm, &file };
static struct vm_area_struct___p11pw other_vma = { &mm, &other_file };
static struct vm_area_struct___p11pw nullfile_vma = { &mm, 0 };

static long scripted_probe_read(void *dst, u32 size, const void *src)
{
    if (reads == read_fail_at) {
        reads++;
        return -1;
    }
    reads++;
    memcpy(dst, src, size);
    return 0;
}

static u64 scripted_pid_tgid(void)
{
    return fake_pid_tgid;
}

static void *scripted_current(void)
{
    return fake_current;
}

static void *scripted_lookup(void *map, const void *key)
{
    u32 index = *(const u32 *)key;
    if (map == &PW_CFG)
        return index == 0 ? &cfg : 0;
    if (map == &PW_WATCHED) {
        const struct pw_watched_key *k = key;
        return watched_present && k->s_dev == watched_key.s_dev &&
                       k->i_ino == watched_key.i_ino
                   ? &watched_slot
                   : 0;
    }
    if (map == &PW_CALIB)
        return index < PW_CALIB_ENTRIES ? &calib[index] : 0;
    if (map == &PW_STATE)
        return index == 0 ? &state : 0;
    if (map == &PW_DEPARTED) {
        u64 mmkey = *(const u64 *)key;
        for (int i = 0; i < TEST_DEPARTED_N; i++)
            if (departed_used[i] && departed_keys[i] == mmkey)
                return &departed_vals[i];
        return 0;
    }
    if (map == &PW_VISITED) {
        u64 mmkey = *(const u64 *)key;
        for (int i = 0; i < TEST_VISITED_N; i++)
            if (visited_used[i] && visited_keys[i] == mmkey)
                return &visited_vals[i];
        return 0;
    }
    if (map == &PW_SELF)
        return index == 0 ? &self_mm : 0;
    if (map == &PW_RUN)
        return index == 0 ? &run : 0;
    assert(!"unexpected map");
    return 0;
}

static long scripted_update(void *map, const void *key, const void *value, u64 flags)
{
    if (map == &PW_DEPARTED) {
        u64 mmkey = *(const u64 *)key;
        if (departed_insert_fail)
            return -12;
        for (int i = 0; i < TEST_DEPARTED_N; i++)
            if (departed_used[i] && departed_keys[i] == mmkey) {
                if (flags == PW_NOEXIST)
                    return -17; /* EEXIST */
                memcpy(&departed_vals[i], value, sizeof(departed_vals[i]));
                return 0;
            }
        if (departed_full)
            return -12;
        for (int i = 0; i < TEST_DEPARTED_N; i++)
            if (!departed_used[i]) {
                departed_used[i] = 1;
                departed_keys[i] = mmkey;
                memcpy(&departed_vals[i], value, sizeof(departed_vals[i]));
                return 0;
            }
        return -12;
    }
    if (map == &PW_VISITED) {
        u64 mmkey = *(const u64 *)key;
        for (int i = 0; i < TEST_VISITED_N; i++)
            if (visited_used[i] && visited_keys[i] == mmkey) {
                memcpy(&visited_vals[i], value, sizeof(visited_vals[i]));
                return 0;
            }
        for (int i = 0; i < TEST_VISITED_N; i++)
            if (!visited_used[i]) {
                visited_used[i] = 1;
                visited_keys[i] = mmkey;
                memcpy(&visited_vals[i], value, sizeof(visited_vals[i]));
                return 0;
            }
        return -12; /* full: caller ignores */
    }
    assert(!"unexpected update map");
    return -1;
}

static long scripted_delete(void *map, const void *key)
{
    if (map == &PW_DEPARTED) {
        u64 mmkey = *(const u64 *)key;
        for (int i = 0; i < TEST_DEPARTED_N; i++)
            if (departed_used[i] && departed_keys[i] == mmkey) {
                departed_used[i] = 0;
                return 0;
            }
        return -2;
    }
    if (map == &PW_VISITED) {
        u64 mmkey = *(const u64 *)key;
        for (int i = 0; i < TEST_VISITED_N; i++)
            if (visited_used[i] && visited_keys[i] == mmkey) {
                visited_used[i] = 0;
                return 0;
            }
        return -2;
    }
    assert(!"unexpected delete map");
    return -1;
}

static void reset_all(void)
{
    memset(&cfg, 0, sizeof(cfg));
    memset(calib, 0, sizeof(calib));
    memset(&state, 0, sizeof(state));
    self_mm = 0;
    memset(&run, 0, sizeof(run));
    memset(departed_used, 0, sizeof(departed_used));
    memset(visited_used, 0, sizeof(visited_used));
    watched_present = 1;
    watched_slot = 3;
    departed_insert_fail = 0;
    departed_full = 0;
    read_fail_at = -1;
    reads = 0;
    cas_lose = 0;
    cas_calls = 0;
    fake_current = &task_member;
    fake_pid_tgid = (77ULL << 32) | 78ULL;
    mm.mm_users.counter = 1;
    mm.map_count = 10;
    other_mm.mm_users.counter = 1;
    /* Cgroup chain: dfl_css -> cgrp_target (kn_target), parent cgrp_parent. */
    cgrp_target.kn = &kn_target;
    cgrp_target.self.parent = &cgrp_parent.self;
    cgrp_target.self.cgroup = &cgrp_target;
    cgrp_parent.kn = &kn_parent;
    cgrp_parent.self.parent = 0;
    cgrp_parent.self.cgroup = &cgrp_parent;
    cgrp_other.kn = &kn_other;
    cgrp_other.self.parent = 0;
    cgrp_other.self.cgroup = &cgrp_other;
    dfl_css.parent = 0;
    dfl_css.cgroup = &cgrp_target;
    css.dfl_cgrp = &dfl_css;
    task_member.mm = &mm;
    task_member.cgroups = &css;
    task_member.flags = 0;
    vma.vm_mm = &mm;
    vma.vm_file = &file;
    file.f_inode = &inode;
    inode.i_sb = &sb;
    inode.i_ino = 4242UL;
    sb.s_dev = 0x00800025U;
    pw_map_lookup = scripted_lookup;
    pw_map_update = scripted_update;
    pw_map_delete = scripted_delete;
    pw_pid_tgid = scripted_pid_tgid;
    pw_current_task = scripted_current;
    pw_probe_read_kernel = scripted_probe_read;
}

static void check_busy_zero(const char *where)
{
    assert(state.busy == 0 && "busy unbalanced");
    (void)where;
}

/* Unmap tests. */

static void test_unmap_read_faults(void)
{
    /* 5 reads before lookup: vm_file, f_inode, i_sb, s_dev, i_ino. */
    for (int fail = 0; fail < 5; fail++) {
        reset_all();
        cfg.active = 1;
        read_fail_at = fail;
        u64 ctx[3] = { (u64)(unsigned long)&vma, 0, 0 };
        assert(p11_pw_unmap(ctx) == 0);
        assert(state.faults == 1);
        assert(state.latch_slots == 0);
        check_busy_zero("unmap fault");
    }
}

static void test_unmap_calibration(void)
{
    reset_all();
    cfg.active = 0;
    cfg.calib_tid = 78;
    cfg.calib_index = 3;
    fake_pid_tgid = (77ULL << 32) | 78ULL;
    u64 ctx[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx) == 0);
    assert(calib[3].hits == 1);
    assert(calib[3].s_dev == 0x00800025ULL);
    assert(calib[3].i_ino == 4242ULL);
    assert(self_mm == (u64)(unsigned long)&mm);
    assert(state.latch_slots == 0);
    check_busy_zero("unmap calib");
    /* Second calibration attempt does not overwrite (hits != 0). */
    reads = 0;
    assert(p11_pw_unmap(ctx) == 0);
    assert(calib[3].hits == 1);
}

static void test_unmap_inactive(void)
{
    reset_all();
    cfg.active = 0;
    u64 ctx[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx) == 0);
    assert(state.latch_slots == 0 && state.faults == 0);
    check_busy_zero("unmap inactive");
    /* NULL vm_file (anonymous VMA) -> no effect, no fault. */
    reset_all();
    cfg.active = 1;
    u64 ctx2[3] = { (u64)(unsigned long)&nullfile_vma, 0, 0 };
    assert(p11_pw_unmap(ctx2) == 0);
    assert(state.latch_slots == 0 && state.faults == 0);
    check_busy_zero("unmap nullfile");
}

static void test_unmap_unwatched_and_bad_slot(void)
{
    reset_all();
    cfg.active = 1;
    u64 ctx[3] = { (u64)(unsigned long)&other_vma, 0, 0 };
    assert(p11_pw_unmap(ctx) == 0);
    assert(state.latch_slots == 0 && state.faults == 0);
    check_busy_zero("unmap unwatched");
    reset_all();
    cfg.active = 1;
    watched_slot = 99;
    u64 ctx2[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx2) == 0);
    assert(state.faults == 1 && state.latch_slots == 0);
    check_busy_zero("unmap bad slot");
    /* Slot 64 is the first out-of-range value (valid 0..63). */
    reset_all();
    cfg.active = 1;
    watched_slot = 64;
    u64 ctx3[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx3) == 0);
    assert(state.faults == 1 && state.latch_slots == 0);
    check_busy_zero("unmap slot 64");
}

static void test_unmap_self_skip(void)
{
    reset_all();
    cfg.active = 1;
    self_mm = (u64)(unsigned long)&mm;
    u64 ctx[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx) == 0);
    assert(state.latch_slots == 0 && state.faults == 0);
    check_busy_zero("unmap self");
}

static void test_unmap_teardown(void)
{
    /* Teardown without departed entry: no latch, no torn. */
    reset_all();
    cfg.active = 1;
    vma.vm_mm = &teardown_mm;
    u64 ctx[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx) == 0);
    assert(state.latch_slots == 0);
    check_busy_zero("unmap teardown w/o entry");
    /* Teardown with departed entry: torn_mask set, no latch yet. */
    reset_all();
    cfg.active = 1;
    vma.vm_mm = &teardown_mm;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&teardown_mm;
    departed_vals[0].word = PW_DEP_PENDING | (5ULL << PW_DEP_SEQ_SHIFT);
    departed_vals[0].torn_mask = 0;
    departed_vals[0].stuck = 0;
    u64 ctx2[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx2) == 0);
    assert(state.latch_slots == 0);
    assert(departed_vals[0].torn_mask == (1ULL << 3));
    check_busy_zero("unmap teardown w/ entry");
}

static void test_unmap_latches(void)
{
    /* kthread -> latch. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 100;
    fake_current = &task_kthread;
    /* kthread borrows mm but mm_users is 1; kthread check latches first. */
    u64 ctx[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx) == 0);
    assert(state.latch_slots == (1ULL << 3));
    check_busy_zero("unmap kthread");
    /* Remote (current->mm != M) -> latch. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 200;
    fake_current = &task_other; /* task_other.mm is other_mm, vma.mm is mm */
    u64 ctx2[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx2) == 0);
    assert(state.latch_slots == (1ULL << 3));
    check_busy_zero("unmap remote");
    /* Member -> latch. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 100;
    fake_current = &task_member;
    u64 ctx3[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx3) == 0);
    assert(state.latch_slots == (1ULL << 3));
    check_busy_zero("unmap member");
    /* users != 1 -> latch (non-member, 2 users). */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 999;
    mm.mm_users.counter = 2;
    fake_current = &task_other;
    task_other.mm = &mm; /* own mm, but 2 users */
    u64 ctx4[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx4) == 0);
    assert(state.latch_slots == (1ULL << 3));
    check_busy_zero("unmap users!=1");
    /* Departed entry -> latch (non-member, 1 user, entry exists). */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 999;
    fake_current = &task_other;
    task_other.mm = &mm;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (1ULL << PW_DEP_SEQ_SHIFT);
    u64 ctx5[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx5) == 0);
    assert(state.latch_slots == (1ULL << 3));
    check_busy_zero("unmap departed");
}

static void test_unmap_single_nonmember_skip(void)
{
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 999;
    fake_current = &task_other;
    task_other.mm = &mm;
    mm.mm_users.counter = 1;
    u64 ctx[3] = { (u64)(unsigned long)&vma, 0, 0 };
    assert(p11_pw_unmap(ctx) == 0);
    assert(state.latch_slots == 0 && state.faults == 0);
    check_busy_zero("unmap skip");
}

/* Depart tests. */

static void test_depart_self(void)
{
    reset_all();
    cfg.active = 1;
    self_mm = (u64)(unsigned long)&mm;
    u64 ctx[2] = { (u64)(unsigned long)&task_member, (u64)(unsigned long)&mm };
    assert(p11_pw_depart(ctx) == 0);
    assert(calib[PW_CALIB_SELF_INDEX].hits == 1);
    assert(state.pending_in == 0);
    check_busy_zero("depart self");
}

static void test_depart_inactive_nonmember_visited(void)
{
    reset_all();
    cfg.active = 0;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 100;
    u64 ctx[2] = { (u64)(unsigned long)&task_member, (u64)(unsigned long)&mm };
    assert(p11_pw_depart(ctx) == 0);
    assert(state.pending_in == 0);
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 999;
    assert(p11_pw_depart(ctx) == 0);
    assert(state.pending_in == 0);
    check_busy_zero("depart nonmember");
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    visited_used[0] = 1;
    visited_keys[0] = (u64)(unsigned long)&mm;
    assert(p11_pw_depart(ctx) == 0);
    assert(state.pending_in == 0);
    check_busy_zero("depart visited");
}

static void test_depart_insert_paths(void)
{
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    u64 ctx[2] = { (u64)(unsigned long)&task_member, (u64)(unsigned long)&mm };
    assert(p11_pw_depart(ctx) == 0);
    assert(state.pending_in == 1);
    assert(departed_used[0] && departed_keys[0] == (u64)(unsigned long)&mm);
    assert((departed_vals[0].word & PW_DEP_STATE_MASK) == PW_DEP_PENDING);
    check_busy_zero("depart insert");
    /* EEXIST path: entry exists, re-pend keeps max seq. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (10ULL << PW_DEP_SEQ_SHIFT);
    state.seq = 5; /* lower than existing: max kept */
    assert(p11_pw_depart(ctx) == 0);
    assert((departed_vals[0].word >> PW_DEP_SEQ_SHIFT) >= 10ULL);
    check_busy_zero("depart eexist");
    /* Insert failure -> fault. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    departed_insert_fail = 1;
    assert(p11_pw_depart(ctx) == 0);
    assert(state.faults == 1 && state.pending_in == 0);
    check_busy_zero("depart insert fail");
}

static void test_depart_repend_done_stuck(void)
{
    u64 ctx[2] = { (u64)(unsigned long)&task_member, (u64)(unsigned long)&mm };
    /* Re-pend from CLEARED: pending_in++. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_CLEARED | (3ULL << PW_DEP_SEQ_SHIFT);
    assert(p11_pw_depart(ctx) == 0);
    assert((departed_vals[0].word & PW_DEP_STATE_MASK) == PW_DEP_PENDING);
    assert(state.pending_in == 1);
    check_busy_zero("depart repend");
    /* DONE untouched. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_DONE | (7ULL << PW_DEP_SEQ_SHIFT);
    assert(p11_pw_depart(ctx) == 0);
    assert((departed_vals[0].word & PW_DEP_STATE_MASK) == PW_DEP_DONE);
    assert(state.pending_in == 0);
    check_busy_zero("depart done");
    /* CAS exhaustion -> stuck. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (1ULL << PW_DEP_SEQ_SHIFT);
    cas_lose = 100;
    assert(p11_pw_depart(ctx) == 0);
    assert(departed_vals[0].stuck == 1);
    assert(state.stuck == 1);
    check_busy_zero("depart stuck");
}

/* Torn tests. */

static void test_torn_paths(void)
{
    u64 ctx[1] = { (u64)(unsigned long)&mm };
    reset_all();
    cfg.active = 1;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (2ULL << PW_DEP_SEQ_SHIFT);
    departed_vals[0].torn_mask = (1ULL << 3);
    visited_used[0] = 1;
    visited_keys[0] = (u64)(unsigned long)&mm;
    assert(p11_pw_torn(ctx) == 0);
    assert(state.torn_slots == (1ULL << 3));
    assert(state.pending_out == 1);
    assert(!departed_used[0] && !visited_used[0]);
    check_busy_zero("torn pending+mask");
    reset_all();
    cfg.active = 1;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (2ULL << PW_DEP_SEQ_SHIFT);
    departed_vals[0].torn_mask = 0;
    assert(p11_pw_torn(ctx) == 0);
    assert(state.torn_slots == 0);
    assert(state.pending_out == 1);
    assert(!departed_used[0]);
    check_busy_zero("torn pending nomask");
    reset_all();
    cfg.active = 1;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_CLEARED | (2ULL << PW_DEP_SEQ_SHIFT);
    departed_vals[0].torn_mask = (1ULL << 3);
    assert(p11_pw_torn(ctx) == 0);
    assert(state.torn_slots == 0 && state.pending_out == 0);
    assert(!departed_used[0]);
    check_busy_zero("torn cleared");
}

/* Migrate tests. */

static void test_migrate_paths(void)
{
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_CGROUP;
    cfg.cgroup_id = 12345ULL;
    u64 ctx[3] = { (u64)(unsigned long)&task_member, 0, 0 };
    assert(p11_pw_migrate(ctx) == 0);
    assert(state.migrations == 1);
    check_busy_zero("migrate member");
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_CGROUP;
    cfg.cgroup_id = 12345ULL;
    dfl_css.cgroup = &cgrp_other;
    u64 ctx2[3] = { (u64)(unsigned long)&task_member, 0, 0 };
    assert(p11_pw_migrate(ctx2) == 0);
    assert(state.migrations == 0);
    check_busy_zero("migrate nonmember");
}

static void test_migrate_depth_fault(void)
{
    /* Chain deeper than 64 -> fault. Build a 70-deep chain. */
    static struct cgroup___p11pw chain[70];
    static struct kernfs_node___p11pw kn[70];
    for (int i = 0; i < 70; i++) {
        kn[i].id = 50000ULL + (u64)i;
        chain[i].kn = &kn[i];
        chain[i].self.cgroup = &chain[i];
        chain[i].self.parent = i + 1 < 70 ? &chain[i + 1].self : 0;
    }
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_CGROUP;
    cfg.cgroup_id = 12345ULL;
    dfl_css.cgroup = &chain[0];
    u64 ctx[3] = { (u64)(unsigned long)&task_member, 0, 0 };
    assert(p11_pw_migrate(ctx) == 0);
    assert(state.faults == 1 && state.migrations == 0);
    check_busy_zero("migrate depth");
}

static void test_migrate_read_fault(void)
{
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_CGROUP;
    cfg.cgroup_id = 12345ULL;
    read_fail_at = 0; /* task->cgroups read fails */
    u64 ctx[3] = { (u64)(unsigned long)&task_member, 0, 0 };
    assert(p11_pw_migrate(ctx) == 0);
    assert(state.faults == 1);
    check_busy_zero("migrate readfault");
}

/* Walk tests. */

static struct pw_iter_task_vma walk_ctx(void *task, void *vma)
{
    struct pw_iter_task_vma ctx;
    ctx.meta = 0;
    ctx.task = task;
    ctx.vma = vma;
    return ctx;
}

static void test_walk_read_faults(void)
{
    /* PID scope: 7 reads through the lookup (vm_mm, map_count, vm_file,
     * f_inode, i_sb, s_dev, i_ino). Every failure faults; a vm_file
     * failure never silently misses. */
    for (int fail = 0; fail < 7; fail++) {
        reset_all();
        cfg.active = 1;
        cfg.scope_kind = PW_SCOPE_PID;
        cfg.target_tgid = 100;
        read_fail_at = fail;
        struct pw_iter_task_vma c = walk_ctx(&task_member, &vma);
        assert(p11_pw_walk(&c) == 0);
        assert(state.faults == 1);
        if (fail == 2)
            assert(state.found_slots == 0);
        check_busy_zero("walk fault");
    }
    /* Cgroup member: vm_file is read 7 (vm_mm + 5 member reads +
     * map_count). Same fault, no silent miss. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_CGROUP;
    cfg.cgroup_id = 12345ULL;
    read_fail_at = 7;
    struct pw_iter_task_vma c = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c) == 0);
    assert(state.faults == 1);
    assert(state.found_slots == 0);
    check_busy_zero("walk vm_file cgroup");
}

static void test_walk_found_and_member(void)
{
    /* Member FOUND for a non-exec watched VMA. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 100;
    struct pw_iter_task_vma c1 = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c1) == 0);
    assert(state.found_slots == (1ULL << 3));
    check_busy_zero("walk found");
    /* Non-member never FOUND (cgroup scope; pidfd walks trust the link). */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_CGROUP;
    cfg.cgroup_id = 12345ULL;
    dfl_css.cgroup = &cgrp_other;
    struct pw_iter_task_vma c2 = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c2) == 0);
    assert(state.found_slots == 0);
    check_busy_zero("walk nonmember");
    /* Observer run never FOUND. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    self_mm = (u64)(unsigned long)&mm;
    struct pw_iter_task_vma c3 = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c3) == 0);
    assert(state.found_slots == 0);
    check_busy_zero("walk observer");
    /* Slot 64 is the first out-of-range value (valid 0..63): the
     * walk faults like the unmap path instead of silently missing. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_PID;
    cfg.target_tgid = 100;
    watched_slot = 64;
    struct pw_iter_task_vma c4 = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c4) == 0);
    assert(state.faults == 1 && state.found_slots == 0);
    check_busy_zero("walk bad slot");
}

static void test_walk_runs_and_clear(void)
{
    /* Complete run -> visited plus clear only when last_seq <= start_seq. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    mm.map_count = 1;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (2ULL << PW_DEP_SEQ_SHIFT);
    departed_vals[0].stuck = 0;
    state.seq = 5; /* start_seq will be >= 5, so 2 <= start: clear */
    struct pw_iter_task_vma c1 = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c1) == 0);
    /* END finalizes the last run. */
    struct pw_iter_task_vma end = walk_ctx(0, 0);
    assert(p11_pw_walk(&end) == 0);
    assert(state.walk_end == 1);
    assert(state.walk_runs >= 1);
    assert((departed_vals[0].word & PW_DEP_STATE_MASK) == PW_DEP_CLEARED);
    assert(state.pending_out == 1);
    check_busy_zero("walk clear");
    /* Incomplete run -> no clear (map_count 2, only 1 callback). */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    mm.map_count = 2;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (1ULL << PW_DEP_SEQ_SHIFT);
    state.seq = 5;
    struct pw_iter_task_vma c2 = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c2) == 0);
    struct pw_iter_task_vma end2 = walk_ctx(0, 0);
    assert(p11_pw_walk(&end2) == 0);
    assert((departed_vals[0].word & PW_DEP_STATE_MASK) == PW_DEP_PENDING);
    assert(state.pending_out == 0);
    check_busy_zero("walk incomplete");
    /* Stuck entry never clears. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    mm.map_count = 1;
    departed_used[0] = 1;
    departed_keys[0] = (u64)(unsigned long)&mm;
    departed_vals[0].word = PW_DEP_PENDING | (1ULL << PW_DEP_SEQ_SHIFT);
    departed_vals[0].stuck = 1;
    state.seq = 5;
    struct pw_iter_task_vma c3 = walk_ctx(&task_member, &vma);
    assert(p11_pw_walk(&c3) == 0);
    struct pw_iter_task_vma end3 = walk_ctx(0, 0);
    assert(p11_pw_walk(&end3) == 0);
    assert((departed_vals[0].word & PW_DEP_STATE_MASK) == PW_DEP_PENDING);
    check_busy_zero("walk stuck");
}

static void test_walk_zombie_and_double_end(void)
{
    /* Zombie leader's thread with pid != tgid gets its own run. */
    reset_all();
    cfg.active = 1;
    cfg.scope_kind = PW_SCOPE_SYSTEM;
    mm.map_count = 1;
    struct pw_iter_task_vma c1 = walk_ctx(&task_thread, &vma);
    assert(p11_pw_walk(&c1) == 0);
    struct pw_iter_task_vma end = walk_ctx(0, 0);
    assert(p11_pw_walk(&end) == 0);
    assert(state.walk_runs >= 1);
    check_busy_zero("walk zombie thread");
    /* A second END is visible as walk_end == 2. */
    reset_all();
    cfg.active = 1;
    struct pw_iter_task_vma e1 = walk_ctx(0, 0);
    assert(p11_pw_walk(&e1) == 0);
    struct pw_iter_task_vma e2 = walk_ctx(0, 0);
    assert(p11_pw_walk(&e2) == 0);
    assert(state.walk_end == 2);
    check_busy_zero("walk double end");
}

int main(void)
{
    test_unmap_read_faults();
    test_unmap_calibration();
    test_unmap_inactive();
    test_unmap_unwatched_and_bad_slot();
    test_unmap_self_skip();
    test_unmap_teardown();
    test_unmap_latches();
    test_unmap_single_nonmember_skip();
    test_depart_self();
    test_depart_inactive_nonmember_visited();
    test_depart_insert_paths();
    test_depart_repend_done_stuck();
    test_torn_paths();
    test_migrate_paths();
    test_migrate_depth_fault();
    test_migrate_read_fault();
    test_walk_read_faults();
    test_walk_found_and_member();
    test_walk_runs_and_clear();
    test_walk_zombie_and_double_end();
    printf("prearm witness harness: all controls verified\n");
    return 0;
}
