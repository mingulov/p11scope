/* Host regression harness for the real Task 3 Stage A hooks (instance_epoch.c).
 * Every helper is a scripted fake; every assertion is on production code. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define P11SCOPE_INSTANCE_HOST_TEST 1
/* Scripted compare-exchange: the next `cas_lose` rounds are lost races. */
static int cas_lose;
static unsigned long long cas_calls;
#define __sync_val_compare_and_swap(cell, old, replacement) \
    test_cas((unsigned long long *)(cell), (old), (replacement))
static unsigned long long test_cas(unsigned long long *cell, unsigned long long old,
                                   unsigned long long replacement)
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
#include "instance_epoch.c"

/* The image-continuity unit's result at the authentic entry boundary.
 * The epoch unit must withhold and erase stamps when this authority refuses. */
static int image_entry_ok = 1;
u32 p11_image_entry(u64 tgid, u64 cookie, u64 exec_id)
{
    assert(tgid == 77 && cookie == 1 && exec_id == 0);
    return image_entry_ok;
}

/* F5: small-state must shrink INSTANCE_START (LRU-eviction injection);
 * the default capacity is unchanged. */
#ifdef P11SCOPE_SMALL_STATE_MAPS
_Static_assert(INST_START_ENTRIES == 1, "small-state INSTANCE_START capacity");
#else
_Static_assert(INST_START_ENTRIES == 16384, "default INSTANCE_START capacity");
#endif

static u32 watched_slot = 5;
static int watched_present = 1;
static struct instance_file_key watched_key = { 0x00800025, 4242 };
static u32 slot_file[P11SCOPE_INSTANCE_SLOT_BOUND];
static u64 g_epoch[INST_FILE_SLOTS];
static int g_epoch_missing;
static u64 gen[INST_GEN_CELLS];
static int gen_missing;
static struct instance_calib calib;
static struct instance_counters counters;
static struct instance_record records[4];
static int record_present[4];
static int storage_fail;
static int storage_creates;
static u64 pid_tgid = (77ULL << 32) | 78;
static int read_fail_at = -1;
static int reads;

static struct super_block___p11inst sb = { 0x00800025 };
static struct inode___p11inst inode = { 4242, &sb };
static struct inode___p11inst other_inode = { 9999, &sb };
static struct file___p11inst file = { &inode };
static struct file___p11inst other_file = { &other_inode };
static struct mm_struct___p11inst mm = { { 1 } };
static struct mm_struct___p11inst other_mm = { { 1 } };
static struct task_struct___p11inst leader;
static struct task_struct___p11inst thread = { &mm, &leader, 0 };
static struct task_struct___p11inst child;
static struct task_struct___p11inst borrower;
static struct task_struct___p11inst *current_task = &thread;
static struct vm_area_struct___p11inst vma = { 0x7f0000001000UL, &mm, &file };
static struct vm_area_struct___p11inst other_vma = { 0x7f0000009000UL, &mm, &other_file };

static struct instance_start_key start_keys[4];
static struct instance_entry start_values[4];
static int start_used[4];
static int start_update_fail;
static int start_deletes;

static long update(void *map, const void *key, const void *value, u64 flags)
{
    assert(map == &INSTANCE_START && flags == 0);
    if (start_update_fail)
        return -12;
    int slot = -1;
    for (int i = 0; i < 4; i++)
        if (start_used[i] && !memcmp(&start_keys[i], key, sizeof(start_keys[i])))
            slot = i;
    for (int i = 0; slot < 0 && i < 4; i++)
        if (!start_used[i])
            slot = i;
    assert(slot >= 0);
    start_used[slot] = 1;
    memcpy(&start_keys[slot], key, sizeof(start_keys[slot]));
    memcpy(&start_values[slot], value, sizeof(start_values[slot]));
    return 0;
}

static long delete(void *map, const void *key)
{
    assert(map == &INSTANCE_START);
    start_deletes++;
    for (int i = 0; i < 4; i++)
        if (start_used[i] && !memcmp(&start_keys[i], key, sizeof(start_keys[i]))) {
            start_used[i] = 0;
            return 0;
        }
    return -2;
}

static void *lookup(void *map, const void *key)
{
    u32 index = *(const u32 *)key;
    if (map == &WATCHED_FILES) {
        const struct instance_file_key *k = key;
        return watched_present && k->dev == watched_key.dev && k->ino == watched_key.ino
                   ? &watched_slot : 0;
    }
    if (map == &SLOT_FILE)
        return index < P11SCOPE_INSTANCE_SLOT_BOUND ? &slot_file[index] : 0;
    if (map == &G_EPOCH)
        return !g_epoch_missing && index < INST_FILE_SLOTS ? &g_epoch[index] : 0;
    if (map == &INSTANCE_GEN)
        return !gen_missing && index < INST_GEN_CELLS ? &gen[index] : 0;
    if (map == &INSTANCE_CALIB)
        return index == 0 ? &calib : 0;
    if (map == &INSTANCE_COUNT)
        return index == 0 ? &counters : 0;
    if (map == &INSTANCE_START) {
        const struct instance_start_key *k = key;
        for (int i = 0; i < 4; i++)
            if (start_used[i] && !memcmp(&start_keys[i], k, sizeof(*k)))
                return &start_values[i];
        return 0;
    }
    assert(!"unexpected map");
    return 0;
}

static int task_index(void *task)
{
    if (task == &leader)
        return 0;
    if (task == &child)
        return 1;
    if (task == &thread)
        return 2;
    if (task == &borrower)
        return 3;
    assert(!"storage on an unexpected task");
    return -1;
}

static struct instance_record *storage(void *map, void *task, void *init, u64 flags)
{
    int index = task_index(task);
    assert(map == &PROC_EPOCH);
    assert(index != 2 && "records live on the group leader only");
    if (record_present[index])
        return &records[index];
    if (!flags || storage_fail)
        return 0;
    storage_creates++;
    record_present[index] = 1;
    if (init)
        memcpy(&records[index], init, sizeof(records[index]));
    else
        memset(&records[index], 0, sizeof(records[index]));
    return &records[index];
}

static int interleave_armed;
static long probe(void *dst, u32 size, const void *src)
{
    if (reads++ == read_fail_at) {
        memset(dst, 0, size);
        return -14;
    }
    memcpy(dst, src, size);
    /* A scripted concurrent clone landing after the single mm_users read
     * (index 6): actual users 3->4. There is no second read to race, so
     * the decision made on the observed count must stand. */
    if (interleave_armed && reads == 7) {
        mm.mm_users.counter = 4;
        interleave_armed = 0;
    }
    return 0;
}

static u64 tgid(void) { return pid_tgid; }
static void *task(void) { return current_task; }

static void reset(void)
{
    memset(g_epoch, 0, sizeof(g_epoch));
    memset(gen, 0, sizeof(gen));
    memset(&calib, 0, sizeof(calib));
    memset(&counters, 0, sizeof(counters));
    memset(records, 0, sizeof(records));
    memset(record_present, 0, sizeof(record_present));
    memset(slot_file, 0, sizeof(slot_file));
    memset(start_used, 0, sizeof(start_used));
    start_update_fail = 0;
    watched_slot = 5;
    watched_present = 1;
    g_epoch_missing = gen_missing = storage_fail = storage_creates = 0;
    cas_lose = 0;
    read_fail_at = -1;
    reads = 0;
    interleave_armed = 0;
    mm.mm_users.counter = 1;
    thread.mm = &mm;
    thread.group_leader = &leader;
    thread.flags = 0;
    leader.flags = 0;
    child.flags = 0;
    borrower.mm = 0;
    borrower.group_leader = 0;
    borrower.flags = 0;
    current_task = &thread;
    image_entry_ok = 1;
}

static void map_hook(struct vm_area_struct___p11inst *v)
{
    u64 ctx[1] = { (u64)(unsigned long)v };
    assert(p11_inst_vma_map(ctx) == 0);
}

static void unmap_hook(struct vm_area_struct___p11inst *v)
{
    u64 ctx[3] = { (u64)(unsigned long)v, 0, 0 };
    assert(p11_inst_vma_unmap(ctx) == 0);
}

static void copy_hook(struct vm_area_struct___p11inst *created)
{
    /* fexit context: five arguments, then the returned new VMA. */
    u64 ctx[6] = { 0xdead, 1, 2, 3, 4, (u64)(unsigned long)created };
    assert(p11_inst_vma_copy(ctx) == 0);
}

/* The stamp as the return half writes it into a reserved record tail. */
static struct instance_stamp stamp(u32 endpoint)
{
    struct instance_continuity out;
    struct instance_start_key absent = { 0xdeadULL, endpoint, 0 };
    memset(&out, 0xa5, sizeof(out));
    assert(p11_instance_return(&absent, &out) == 0);
    assert(out.entry_ip == 0 && out.entry_stamp.flags == 0 && out.entry_stamp.epoch == 0);
    return out.return_stamp;
}

int main(void)
{
    inst_map_lookup = lookup;
    inst_map_update = update;
    inst_map_delete = delete;
    inst_pid_tgid = tgid;
    inst_probe_read_kernel = probe;
    inst_storage_get = storage;
    inst_current_task = task;
    leader.group_leader = &leader;
    leader.mm = &mm;

    /* A disabled/poisoned image may never leave a joinable entry stamp. */
    reset();
    struct instance_start_key refused_call = { (77ULL << 32) | 78, 3, 0 };
    image_entry_ok = 0;
    assert(p11_instance_entry(&refused_call, 0x1230, 1, 0) == 0);
    assert(!start_used[0] && start_deletes == 1);
    reset();

    /* Unwatched file: nothing moves, nothing is created. */
    reset();
    map_hook(&other_vma);
    unmap_hook(&other_vma);
    assert(!storage_creates && !counters.watched_hits && !g_epoch[5]);

    /* Own mm, watched file: the leader's per-file epoch moves, locally. */
    reset();
    map_hook(&vma);
    assert(storage_creates == 1 && record_present[0]);
    assert(records[0].slot_plus1[0] == 6 && records[0].epoch[0] == 1);
    unmap_hook(&vma);
    copy_hook(&vma);
    assert(records[0].epoch[0] == 3 && counters.local_bumps == 3 && counters.watched_hits == 3);
    copy_hook(0); /* copy_vma failed: nothing was created */
    assert(records[0].epoch[0] == 3 && counters.watched_hits == 3);
    assert(!g_epoch[5] && !gen[INST_GEN_FAULT]);

    /* Teardown (mm_users == 0): skipped, never a bump. */
    reset();
    mm.mm_users.counter = 0;
    unmap_hook(&vma);
    assert(counters.teardown_skips == 1 && !storage_creates && !g_epoch[5]);

    /* Remote mm: the global epoch moves. */
    reset();
    thread.mm = &other_mm;
    unmap_hook(&vma);
    assert(counters.remote == 1 && g_epoch[5] == 1 && counters.global_bumps == 1 && !storage_creates);
    thread.mm = 0;
    unmap_hook(&vma);
    assert(counters.remote == 2 && g_epoch[5] == 2);

    /* A kthread_use_mm borrower: task->mm is this mm (borrowed) while the
     * single mm_users reference belongs to another group — so it passes
     * the current-mm check and must still globalize via PF_KTHREAD. The
     * owner's record and stamps are untouched; the global epoch carries
     * the mutation. */
    reset();
    borrower.mm = &mm;
    borrower.group_leader = &borrower;
    borrower.flags = INST_PF_KTHREAD;
    record_present[0] = 1;
    records[0].slot_plus1[0] = 6;
    records[0].epoch[0] = 1;
    slot_file[3] = 6;
    struct instance_stamp before = stamp(3);
    current_task = &borrower;
    unmap_hook(&vma);
    assert(counters.remote == 1 && g_epoch[5] == 1 && counters.global_bumps == 1);
    assert(!record_present[3] && !counters.local_bumps && !storage_creates);
    assert(records[0].epoch[0] == 1);
    current_task = &thread;
    struct instance_stamp after = stamp(3);
    assert(before.epoch == 1 && after.epoch == 1);
    assert(before.global == 0 && after.global == 1);
    /* A borrower without the kthread bit is indistinguishable from the
     * owner by shape alone: the flags field is the whole exclusion. */
    reset();
    borrower.mm = &mm;
    borrower.group_leader = &borrower;
    current_task = &borrower;
    map_hook(&vma);
    assert(counters.local_bumps == 1 && !g_epoch[5]);
    current_task = &thread;

    /* No current task, no leader, storage failure: global, never silent. */
    reset();
    current_task = 0;
    map_hook(&vma);
    assert(g_epoch[5] == 1);
    current_task = &thread;
    thread.group_leader = 0;
    map_hook(&vma);
    assert(g_epoch[5] == 2);
    thread.group_leader = &leader;
    storage_fail = 1;
    map_hook(&vma);
    assert(g_epoch[5] == 3 && counters.storage_null == 1);

    /* Unreadable vm_mm/mm_users/task flags/current-mm: global. Unreadable
     * file metadata: no identity, so no watched file can be named (reads
     * 0..4 are file side, 5 is vm_mm, 6 mm_users, 7 flags, 8 current-mm). */
    for (int at = 0; at < 9; at++) {
        reset();
        read_fail_at = at;
        map_hook(&vma);
        if (at < 5)
            assert(!g_epoch[5] && !counters.watched_hits);
        else
            assert(g_epoch[5] == 1 && !storage_creates);
    }

    /* A slot past the file bound, or a missing G_EPOCH cell: fault. */
    reset();
    watched_slot = INST_FILE_SLOTS;
    map_hook(&vma);
    assert(gen[INST_GEN_FAULT] == 1 && counters.faults == 1);
    reset();
    thread.mm = &other_mm;
    g_epoch_missing = 1;
    map_hook(&vma);
    assert(gen[INST_GEN_FAULT] == 1);

    /* A CLONE_VM sharer's mutations never localize. */
    reset();
    record_present[0] = 1;
    records[0].flags = INST_RECORD_SHARED_MM;
    map_hook(&vma);
    assert(counters.shared == 1 && g_epoch[5] == 1 && !records[0].slot_plus1[0]);

    /* Ownership is a single mm_users read: 1 localizes, anything else
     * globalizes. A pre-attachment sharer (2 users), the zombie-equality
     * values (2 users behind a zombie leader), and the interleaved-clone
     * actuals (4 users) never localize, with or without the
     * post-attachment mark. */
    for (int users = 2; users <= 4; users++) {
        reset();
        mm.mm_users.counter = users;
        map_hook(&vma);
        assert(counters.shared == 1 && g_epoch[5] == 1 && !records[0].slot_plus1[0]);
        assert(!storage_creates);
    }
    /* A concurrent clone landing after the single read cannot localize:
     * the decision was already made on the observed count. */
    reset();
    mm.mm_users.counter = 3;
    interleave_armed = 1;
    map_hook(&vma);
    assert(counters.shared == 1 && g_epoch[5] == 1 && !storage_creates);
    /* An unreadable ownership count fails closed (read 6 is also covered
     * by the loop above; pinned again here for the message). So do
     * unreadable task flags (read 7): borrowers fail closed too. */
    reset();
    read_fail_at = 6;
    map_hook(&vma);
    assert(g_epoch[5] == 1 && !storage_creates);
    reset();
    read_fail_at = 7;
    map_hook(&vma);
    assert(g_epoch[5] == 1 && counters.remote == 1 && !storage_creates);

    /* Record overflow: 8 files fit; the 9th goes global and marks OVERFLOW. */
    reset();
    for (u32 s = 0; s < INST_RECORD_SLOTS; s++) {
        watched_slot = 100 + s;
        map_hook(&vma);
    }
    watched_slot = 200;
    map_hook(&vma);
    assert(counters.overflow == 1 && g_epoch[200] == 1);
    assert(records[0].flags & INST_RECORD_OVERFLOW);
    for (u32 s = 0; s < INST_RECORD_SLOTS; s++)
        assert(records[0].slot_plus1[s] == 101 + s && records[0].epoch[s] == 1);
    /* ...and if OVERFLOW cannot be recorded, the fault generation moves. */
    records[0].flags = 0;
    cas_lose = INST_CAS_TRIES;
    map_hook(&vma);
    assert(counters.faults == 1 && gen[INST_GEN_FAULT] == 1 && g_epoch[200] == 2);

    /* Calibration: only the armed tid, only once, only on creation. */
    reset();
    watched_present = 0;
    calib.tid = 78;
    unmap_hook(&vma);
    assert(!calib.hits);
    map_hook(&vma);
    assert(calib.hits == 1 && calib.vm_start == vma.vm_start);
    assert(calib.dev == 0x00800025 && calib.ino == 4242 && counters.calib_hits == 1);
    calib.vm_start = 0;
    map_hook(&vma);
    assert(calib.hits == 1 && calib.vm_start == 0);
    reset();
    calib.tid = 79;
    map_hook(&vma);
    assert(!calib.hits);

    /* Fork: a CLONE_VM non-thread child is marked; others are not. */
    reset();
    assert(p11_instance_fork((struct task_struct *)&child, INST_CLONE_VM) == 1);
    assert(record_present[1] && records[1].flags == INST_RECORD_SHARED_MM);
    reset();
    assert(p11_instance_fork((struct task_struct *)&child, INST_CLONE_VM | INST_CLONE_THREAD) == 0);
    assert(p11_instance_fork((struct task_struct *)&child, 0) == 0);
    assert(!storage_creates && !gen[INST_GEN_STICKY]);
    /* Marking failure (no storage, no child, lost CAS): sticky + fault. */
    storage_fail = 1;
    assert(p11_instance_fork((struct task_struct *)&child, INST_CLONE_VM) == 0);
    assert(gen[INST_GEN_STICKY] == INST_STICKY_FORK_UNMARKED && gen[INST_GEN_FAULT] == 1);
    reset();
    assert(p11_instance_fork(0, INST_CLONE_VM) == 0);
    assert(gen[INST_GEN_STICKY] == INST_STICKY_FORK_UNMARKED && gen[INST_GEN_FAULT] == 1);
    reset();
    record_present[1] = 1;
    cas_lose = INST_CAS_TRIES;
    assert(p11_instance_fork((struct task_struct *)&child, INST_CLONE_VM) == 0);
    assert(gen[INST_GEN_STICKY] == INST_STICKY_FORK_UNMARKED && gen[INST_GEN_FAULT] == 1);

    /* Exec: clears SHARED_MM, stamps the attach generation, creates nothing. */
    reset();
    assert(p11_instance_exec() == 0 && !storage_creates);
    record_present[0] = 1;
    records[0].flags = INST_RECORD_SHARED_MM | INST_RECORD_OVERFLOW;
    gen[INST_GEN_ATTACH] = 9;
    assert(p11_instance_exec() == 1);
    assert(records[0].flags == INST_RECORD_OVERFLOW && records[0].exec_attach_gen == 9);

    /* Stamps. */
    reset();
    struct instance_stamp s = stamp(P11SCOPE_INSTANCE_SLOT_BOUND);
    assert(s.flags == (INST_STAMP_VALID | INST_STAMP_NO_FILE) && !s.epoch && !s.file_slot_plus1);
    s = stamp(3);
    assert(s.flags == (INST_STAMP_VALID | INST_STAMP_NO_FILE));
    slot_file[3] = INST_FILE_SLOTS + 1;
    s = stamp(3);
    assert(s.flags == (INST_STAMP_VALID | INST_STAMP_NO_FILE));
    slot_file[3] = 6;
    gen[INST_GEN_FAULT] = 0x100000002ULL; /* low words only */
    g_epoch[5] = 7;
    s = stamp(3);
    assert(s.flags == INST_STAMP_VALID && s.file_slot_plus1 == 6);
    assert(s.fault == 2 && s.global == 7 && s.epoch == 0 && !storage_creates);
    /* Another watched file claims record cell 0 first: the stamp must read
     * the cell of this endpoint's file, never just the first one. */
    watched_slot = 9;
    map_hook(&vma);
    map_hook(&vma);
    map_hook(&vma);
    watched_slot = 5;
    map_hook(&vma);
    map_hook(&vma);
    assert(records[0].slot_plus1[0] == 10 && records[0].slot_plus1[1] == 6);
    s = stamp(3);
    assert(s.epoch == 2 && s.flags == INST_STAMP_VALID);
    records[0].flags |= INST_RECORD_SHARED_MM;
    s = stamp(3);
    assert(s.flags == (INST_STAMP_VALID | INST_STAMP_SHARED_MM));
    records[0].flags = 0;
    gen_missing = 1;
    s = stamp(3);
    assert(s.flags & INST_STAMP_LOCAL_FAULT);
    gen_missing = 0;
    g_epoch_missing = 1;
    s = stamp(3);
    assert(s.flags & INST_STAMP_LOCAL_FAULT);
    g_epoch_missing = 0;
    current_task = 0;
    s = stamp(3);
    assert(s.flags == (INST_STAMP_VALID | INST_STAMP_NO_TASK));
    current_task = &thread;
    struct instance_continuity tail_none;
    assert(p11_instance_return(0, 0) == 0);
    memset(&tail_none, 0xa5, sizeof(tail_none));
    assert(p11_instance_return(0, &tail_none) == 0);
    assert(tail_none.entry_ip == 0 && (tail_none.return_stamp.flags & INST_STAMP_NO_FILE));

    /* Entry/return halves: the return copies exactly the entry's private
     * address and stamp, adds its own stamp, and consumes the entry. */
    reset();
    slot_file[3] = 6;
    map_hook(&vma); /* epoch 1 */
    struct instance_start_key call = { (77ULL << 32) | 78, 3, 0 };
    assert(p11_instance_entry(&call, 0x7f0000001230ULL, 1, 0) == 1);
    assert(start_used[0] && start_values[0].entry_ip == 0x7f0000001230ULL);
    assert(start_values[0].entry_stamp.epoch == 1);
    struct instance_continuity tail;
    memset(&tail, 0xa5, sizeof(tail));
    assert(p11_instance_return(&call, &tail) == 1);
    assert(tail.entry_ip == 0x7f0000001230ULL && tail.entry_stamp.epoch == 1);
    assert(tail.entry_stamp.flags == INST_STAMP_VALID && tail.return_stamp.epoch == 1);
    assert(!memcmp(&tail.entry_stamp, &tail.return_stamp, sizeof(tail.entry_stamp)));
    assert(!start_used[0]);
    /* A mutation during the call: the halves differ (a straddle). */
    assert(p11_instance_entry(&call, 0x7f0000001230ULL, 1, 0) == 1);
    unmap_hook(&vma);
    assert(p11_instance_return(&call, &tail) == 1);
    assert(tail.entry_stamp.epoch == 1 && tail.return_stamp.epoch == 2);
    /* A failed entry update removes any stale entry for the key. */
    assert(p11_instance_entry(&call, 0x1111, 1, 0) == 1);
    start_update_fail = 1;
    start_deletes = 0;
    assert(p11_instance_entry(&call, 0x2222, 1, 0) == 0);
    assert(start_deletes == 1 && !start_used[0]);
    start_update_fail = 0;
    memset(&tail, 0xa5, sizeof(tail));
    assert(p11_instance_return(&call, &tail) == 0);
    assert(tail.entry_ip == 0 && tail.entry_stamp.flags == 0);
    assert(tail.return_stamp.flags == INST_STAMP_VALID && tail.return_stamp.epoch == 2);
    assert(p11_instance_entry(0, 1, 1, 0) == 0);

    /* BEGIN loss: the kernel evicts a live entry (LRU pressure on a full
     * table) between the halves; the return faults instead of settling. */
    reset();
    slot_file[3] = 6;
    map_hook(&vma); /* epoch 1 */
    struct instance_start_key victim = { (77ULL << 32) | 78, 3, 0 };
    assert(p11_instance_entry(&victim, 0x7f0000001230ULL, 1, 0) == 1);
    assert(start_used[0] && start_values[0].entry_ip == 0x7f0000001230ULL);
    /* The harness plays the kernel's eviction role: the slot is reclaimed
     * out from under the in-flight call. */
    start_used[0] = 0;
    start_deletes = 0;
    memset(&tail, 0xa5, sizeof(tail));
    assert(p11_instance_return(&victim, &tail) == 0);
    assert(tail.entry_ip == 0 && tail.entry_stamp.flags == 0);
    assert(tail.entry_stamp.epoch == 0 && tail.entry_stamp.fault == 0);
    assert(start_deletes == 0);
    assert(tail.return_stamp.flags == INST_STAMP_VALID && tail.return_stamp.epoch == 1);

    /* The fault raise retries a lost race, and stays bounded. */
    reset();
    cas_calls = 0;
    cas_lose = 1;
    inst_fault(&counters);
    assert(cas_calls == 2 && gen[INST_GEN_FAULT] == 1 && counters.faults == 1);
    cas_calls = 0;
    cas_lose = 1000;
    inst_fault(&counters);
    assert(cas_calls == INST_CAS_TRIES && gen[INST_GEN_FAULT] == 1);
    cas_lose = 0;

    puts("instance epoch hooks: local/global/fault/sticky/calibration/stamp paths verified");
    return 0;
}
