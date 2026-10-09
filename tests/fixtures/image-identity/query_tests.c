/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Calls the production entry, pre-mm invalidator and iterator. Helpers are
 * scripted; shared cells use real atomic accesses, including host writers. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
static void pause_writer(void);
static void pause_index_miss(void);
static void pause_index_publication(void);
static void pause_index_cas(void);
static void index_cas_result(unsigned long long prior, unsigned long long expected);
#define IMG_AFTER_LOCK() pause_writer()
#define IMG_AFTER_INDEX_MISS() pause_index_miss()
#define IMG_AFTER_INDEX_PUBLICATION() pause_index_publication()
#define IMG_BEFORE_INDEX_CAS() pause_index_cas()
#define IMG_AFTER_INDEX_CAS(prior, expected) index_cas_result(prior, expected)
#define P11SCOPE_IMAGE_QUERY_HOST_TEST 1
#include "image_identity_query.c"
unsigned char TASK_COOKIE, INSTANCE_GEN, CONFIG;
static u64 coverage, flags, index_cookie, record_key, indexed_tgid, cookie, now;
static int index_present, record_present, index_fail, record_fail, storage_busy;
static unsigned int index_updates, record_updates, storage_reads, writes;
static struct image_continuity continuity;
static struct image_continuity retired_continuity;
static u64 retired_key, index_race_cookie;
static int retired_present, record_race;
static struct image_query_control control;
static struct image_query_request request;
static struct image_query_row rows[8];
static struct task_struct___p11image task;
static int hold_writer, writer_locked, release_writer;
static int hold_index_miss, index_missed, release_index_miss;
static int hold_publication, published, release_publication;
static int write_fail_at, mutate_on_fresh, deadline_after_write;
static unsigned int write_attempts;
static pthread_mutex_t map_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_barrier_t cas_barrier;
static int hold_cas, cas_arrivals, cas_losses;
static void pause_index_cas(void)
{
    if (!__atomic_load_n(&hold_cas, __ATOMIC_SEQ_CST)) return;
    if (__atomic_fetch_add(&cas_arrivals, 1, __ATOMIC_SEQ_CST) < 2)
        (void)pthread_barrier_wait(&cas_barrier);
}
static void index_cas_result(u64 prior, u64 expected)
{
    if (prior != expected) __atomic_fetch_add(&cas_losses, 1, __ATOMIC_SEQ_CST);
}
static void pause_index_publication(void)
{
    if (!__sync_bool_compare_and_swap(&hold_publication, 1, 0)) return;
    __atomic_store_n(&published, 1, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&release_publication, __ATOMIC_SEQ_CST)) sched_yield();
}
static void pause_index_miss(void)
{
    if (!__sync_bool_compare_and_swap(&hold_index_miss, 1, 0)) return;
    __atomic_store_n(&index_missed, 1, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&release_index_miss, __ATOMIC_SEQ_CST)) sched_yield();
}
static void pause_writer(void)
{
    if (!__atomic_load_n(&hold_writer, __ATOMIC_SEQ_CST)) return;
    __atomic_store_n(&writer_locked, 1, __ATOMIC_SEQ_CST);
    while (!__atomic_load_n(&release_writer, __ATOMIC_SEQ_CST)) sched_yield();
}
static void *lookup(void *map, const void *key)
{
    if (map == &INSTANCE_GEN) { assert(*(u32 *)key == 3); return &coverage; }
    if (map == &CONFIG) { assert(*(u32 *)key == 0); return &flags; }
    if (map == &IMAGE_TGID_INDEX || map == &IMAGE_CONTINUITY) {
        assert(!pthread_mutex_lock(&map_lock));
        void *result = map == &IMAGE_TGID_INDEX ?
            (index_present && *(u64 *)key == indexed_tgid ? (void *)&index_cookie : 0) :
            (record_present && *(u64 *)key == record_key ? &continuity :
             retired_present && *(u64 *)key == retired_key ? &retired_continuity : 0);
        assert(!pthread_mutex_unlock(&map_lock));
        return result;
    }
    if (map == &IMAGE_QUERY_CTL) return &control;
    if (map == &IMAGE_QUERY_REQUESTS)
        return *(u64 *)key == request.cookie ? &request : 0;
    assert(!"unexpected map"); return 0;
}
static long update_locked(void *map, const void *key, const void *value, u64 mode)
{
    assert(mode == 1); /* No replacement or deletion is permitted. */
    if (map == &IMAGE_TGID_INDEX) {
        index_updates++;
        if (index_fail) return index_fail;
        if (index_race_cookie) {
            indexed_tgid = *(u64 *)key; index_cookie = index_race_cookie;
            index_present = 1; return -17;
        }
        if (index_present) return -17;
        indexed_tgid = *(u64 *)key; index_cookie = *(u64 *)value; index_present = 1;
        return 0;
    }
    assert(map == &IMAGE_CONTINUITY);
    record_updates++;
    /* Ready cannot precede complete index_cookie publication. */
    assert(index_present && IMG_READ(index_cookie) == *(u64 *)key);
    if (record_fail) return record_fail;
    if (record_present && record_key == *(u64 *)key) return -17;
    if (record_present) {
        assert(!retired_present);
        retired_key = record_key; retired_continuity = continuity; retired_present = 1;
    }
    record_key = *(u64 *)key; memcpy(&continuity, value, sizeof(continuity));
    record_present = 1; return record_race ? -17 : 0;
}
static long update(void *map, const void *key, const void *value, u64 mode)
{
    assert(!pthread_mutex_lock(&map_lock));
    long result = update_locked(map, key, value, mode);
    assert(!pthread_mutex_unlock(&map_lock));
    return result;
}
static u64 pid(void) { return (77ULL << 32) | 78; }
static u64 clock_now(void) { return now; }
static void *storage(void *map, void *selected, void *initial, u64 mode)
{
    storage_reads++;
    assert(map == &TASK_COOKIE && selected == &task && !initial && !mode);
    if (storage_reads == 2) {
        if (mutate_on_fresh == 1) cookie++;
        if (mutate_on_fresh == 2) task.self_exec_id++;
        if (mutate_on_fresh == 3) IMG_STORE(continuity.seq, IMG_READ(continuity.seq) + 2);
    }
    return storage_busy ? 0 : &cookie;
}
static long emit(void *seq, const void *row, u32 size)
{
    assert(seq == rows && size == sizeof(rows[0]) && writes < 8);
    if ((int)write_attempts++ == write_fail_at) return -5;
    memcpy(&rows[writes++], row, size);
    if (deadline_after_write) now = control.deadline_ns;
    return 0;
}
static void reset(void)
{
    coverage = IMG_ENABLED; flags = 1 << 2; now = 1; cookie = 1;
    index_present = record_present = index_fail = record_fail = storage_busy = 0;
    retired_present = record_race = 0; index_race_cookie = retired_key = 0;
    write_fail_at = -1; mutate_on_fresh = deadline_after_write = 0;
    hold_publication = 0;
    hold_cas = cas_arrivals = cas_losses = 0;
    index_updates = record_updates = storage_reads = writes = 0;
    memset(&continuity, 0, sizeof(continuity)); memset(rows, 0, sizeof(rows));
    task.group_leader = &task; task.self_exec_id = 0; task.flags = 0;
    request = (struct image_query_request){ 3, 1, 0 };
    control = (struct image_query_control){ 3, 100, 8, 1, 0, 0, 0 };
}
static void query(void)
{
    control.visits = control.emitted = control.failed = 0;
    writes = storage_reads = write_attempts = 0;
    memset(rows, 0, sizeof(rows));
    struct image_iter_meta meta = { rows, 0, 0 };
    struct image_iter_task ctx = { &meta, &task };
    (void)p11_image_query(&ctx);
    ctx.task = 0;
    (void)p11_image_query(&ctx);
}
static void *poison(void *arg)
{
    (void)arg;
    (void)p11_image_exec_release(0);
    return 0;
}
static void *renew(void *arg)
{
    (void)arg;
    assert(image_write(&continuity, 1, 0));
    return 0;
}
struct entry_attempt { u64 selected_cookie; u32 result; };
static void *first_entry(void *arg)
{
    struct entry_attempt *attempt = arg;
    attempt->result = p11_image_entry(77, attempt->selected_cookie, 0);
    return 0;
}
static void first_publication_race(int older_index)
{
    reset();
    u64 selected_cookie = older_index ? 2 : 1;
    if (older_index) {
        index_present = 1; indexed_tgid = 77; index_cookie = 1;
    }
    hold_index_miss = 1; index_missed = release_index_miss = 0;
    struct entry_attempt attempt = { selected_cookie, 0 };
    pthread_t worker;
    assert(!pthread_create(&worker, 0, first_entry, &attempt));
    while (!__atomic_load_n(&index_missed, __ATOMIC_SEQ_CST)) sched_yield();
    assert(p11_image_entry(77, selected_cookie, 0));
    __atomic_store_n(&release_index_miss, 1, __ATOMIC_SEQ_CST);
    assert(!pthread_join(worker, 0));
    assert(attempt.result && coverage == IMG_ENABLED);
    cookie = selected_cookie; request.cookie = selected_cookie; query();
    assert(writes == 2 && rows[0].status == IMG_ROW_READY && rows[1].status == IMG_ROW_END);
}
static void index_precedes_any_ready(void)
{
    reset(); hold_publication = 1; published = release_publication = 0;
    struct entry_attempt attempt = { 1, 0 };
    pthread_t worker;
    assert(!pthread_create(&worker, 0, first_entry, &attempt));
    while (!__atomic_load_n(&published, __ATOMIC_SEQ_CST)) sched_yield();
    assert(index_present && !record_present);
    query();
    assert(writes == 2 && rows[0].status == IMG_ROW_UNKNOWN && rows[1].status == IMG_ROW_END);
    assert(!record_present); /* A query cannot finish the entry's publication. */
    __atomic_store_n(&release_publication, 1, __ATOMIC_SEQ_CST);
    assert(!pthread_join(worker, 0));
    assert(attempt.result && record_present && coverage == IMG_ENABLED);
    query(); assert(writes == 2 && rows[0].status == IMG_ROW_READY);
}
static void concurrent_first_publishers_contend_on_real_cas(void)
{
    reset(); index_present = 1; indexed_tgid = 77; index_cookie = 1;
    hold_cas = 1;
    assert(!pthread_barrier_init(&cas_barrier, 0, 2));
    struct entry_attempt attempts[2] = { { 2, 0 }, { 2, 0 } };
    pthread_t workers[2];
    for (int i = 0; i < 2; i++) assert(!pthread_create(&workers[i], 0, first_entry, &attempts[i]));
    for (int i = 0; i < 2; i++) assert(!pthread_join(workers[i], 0));
    assert(!pthread_barrier_destroy(&cas_barrier));
    hold_cas = 0;
    assert(attempts[0].result && attempts[1].result && cas_arrivals == 2 && cas_losses == 1);
    assert(coverage == IMG_ENABLED && IMG_READ(index_cookie) == 2);
    cookie = request.cookie = 2; query();
    assert(writes == 2 && rows[0].status == IMG_ROW_READY && rows[1].status == IMG_ROW_END);
}
int main(int argc, char **argv)
{
    image_lookup = lookup; image_update = update; image_pid_tgid = pid;
    image_storage_get = storage; image_seq_write = emit; image_ktime = clock_now;
    if (argc > 1) {
        assert(argc == 2 && !strcmp(argv[1], "older-index-race"));
        first_publication_race(1);
        return 0;
    }
    first_publication_race(0);
    first_publication_race(1);
    index_precedes_any_ready();
    concurrent_first_publishers_contend_on_real_cas();
    reset(); query(); /* Query/fork-only cookie never creates Ready. */
    assert(!record_present && !index_present && writes == 2 && rows[0].status == IMG_ROW_UNKNOWN);
    reset(); assert(p11_image_entry(77, 1, 0)); query();
    assert(writes == 2 && rows[0].status == IMG_ROW_READY && rows[1].status == IMG_ROW_END);
    assert(rows[0].exec_id == 0 && continuity.seq == 2 && index_cookie == 1);
    /* The pre-mm hook works despite busy task storage and zero misses. */
    storage_busy = 1; storage_reads = 0;
    p11_image_exec_release((u64 *)0xdead);
    assert(!storage_reads && continuity.state == IMG_POISONED && continuity.exec_id == 0);
    assert(!p11_image_entry(77, 1, 0)); /* same-ID failed-exec/ptrace ABA stays poisoned */
    storage_busy = 0; query();
    assert(writes == 2 && rows[0].status == IMG_ROW_UNKNOWN && rows[1].status == IMG_ROW_END);
    p11_image_exec_release(0); assert(!p11_image_entry(77, 1, 0));
    assert(continuity.exec_id == 0 && coverage == IMG_ENABLED);
    storage_busy = 0; task.self_exec_id = 1;
    assert(p11_image_entry(77, 1, 1) && continuity.state == IMG_READY);
    assert(!p11_image_entry(77, 1, 0)); /* decreased ID refuses */
    /* Unobserved newer image's failed exec preserves the indexed stored ID. */
    task.self_exec_id = 2; p11_image_exec_release(0);
    assert(continuity.exec_id == 1 && p11_image_entry(77, 1, 2));
    /* Missing or foreign index_cookie with an existing record fails BEFORE mutation. */
    index_present = 0; index_updates = 0;
    assert(!p11_image_entry(77, 1, 2));
    assert(coverage == IMG_FAILED && index_updates == 0 && !index_present);
    reset(); assert(p11_image_entry(77, 1, 0)); index_cookie = 2; index_updates = 0;
    assert(!p11_image_entry(77, 1, 0) && coverage == IMG_FAILED && !index_updates && index_cookie == 2);
    /* Index and record capacity/insertion failures withhold fresh authority. */
    for (int failure = -12; failure <= -11; failure++) {
        reset(); index_fail = failure; assert(!p11_image_entry(77, 1, 0));
        assert(!record_present);
        reset(); record_fail = failure; assert(!p11_image_entry(77, 1, 0));
        assert(index_present && !record_present); p11_image_exec_release(0);
        assert(coverage == IMG_ENABLED); record_fail = 0; assert(p11_image_entry(77, 1, 0));
    }
    /* NOEXIST races inspect the real winner; they never overwrite it. */
    reset(); index_race_cookie = 1; record_race = 1;
    assert(p11_image_entry(77, 1, 0) && record_present);
    reset(); index_race_cookie = 2;
    assert(!p11_image_entry(77, 1, 0) && index_cookie == 2 && !record_present);
    /* No-index_cookie unrelated exec allocates nothing; scope flags are irrelevant. */
    reset(); p11_image_exec_release(0);
    assert(!index_present && !record_present && !index_updates && !record_updates);
    assert(p11_image_entry(77, 1, 0)); flags |= 1; p11_image_exec_release(0);
    assert(continuity.state == IMG_POISONED);
    /* Replacement cookie advances an old index_cookie; delayed smaller publisher loses. */
    reset(); assert(p11_image_entry(77, 1, 0));
    assert(p11_image_entry(77, 2, 0) && index_cookie == 2 && record_key == 2);
    assert(retired_present && retired_key == 1 && retired_continuity.state == IMG_READY);
    p11_image_exec_release(0);
    assert(continuity.state == IMG_POISONED && retired_continuity.state == IMG_READY);
    assert(!p11_image_entry(77, 1, 0) && index_cookie == 2);
    /* Aggregate/query policy guards precede all target storage reads/writes. */
    reset(); flags = 1 << 4; query(); p11_image_exec_release(0);
    assert(!p11_image_entry(77, 1, 0) && !storage_reads && !writes && !index_updates);
    reset(); coverage = IMG_DISABLED; assert(!p11_image_entry(77, 1, 0)); query();
    assert(!storage_reads && !writes && !index_present);
    image_fail(); assert(coverage == IMG_FAILED);
    assert(__sync_val_compare_and_swap(&coverage, IMG_DISABLED, IMG_ENABLED) == IMG_FAILED);
    reset(); image_fail(); assert(coverage == IMG_FAILED);
    /* Busy fresh query stays unknown; it never falls back through the index_cookie. */
    reset(); assert(p11_image_entry(77, 1, 0)); storage_busy = 1; query();
    assert(!writes && control.failed && continuity.state == IMG_READY);
    /* Every callback and the terminal callback spend the original budget. */
    reset(); assert(p11_image_entry(77, 1, 0)); control.visit_limit = 1; query();
    assert(writes == 1 && rows[0].status == IMG_ROW_READY && control.failed);
    reset(); assert(p11_image_entry(77, 1, 0)); now = 100; query();
    assert(!writes && control.failed);
    reset(); assert(p11_image_entry(77, 1, 0)); deadline_after_write = 1; query();
    assert(writes == 1 && rows[0].status == IMG_ROW_READY && control.failed);
    for (int position = 0; position < 2; position++) {
        reset(); assert(p11_image_entry(77, 1, 0)); write_fail_at = position; query();
        assert(writes == (unsigned int)position && control.failed);
        assert(rows[1].status != IMG_ROW_END); /* No stale END from another run. */
    }
    for (int change = 1; change <= 3; change++) {
        reset(); assert(p11_image_entry(77, 1, 0)); mutate_on_fresh = change; query();
        assert(writes == 2 && rows[0].status == IMG_ROW_UNKNOWN && rows[1].status == IMG_ROW_END);
    }
    reset(); cookie = 2; control.visit_limit = 1; query();
    assert(control.visits == 1 && !writes && control.failed); /* skipped callback charged */
    reset(); assert(p11_image_entry(77, 1, 0));
    struct task_struct___p11image other;
    task.group_leader = &other; query();
    assert(control.visits == 2 && writes == 2 && rows[0].status == IMG_ROW_UNKNOWN);
    /* Torn/exhausted invalidation fails permanently. */
    reset(); assert(p11_image_entry(77, 1, 0)); continuity.seq = 3; p11_image_exec_release(0);
    assert(coverage == IMG_FAILED);
    reset(); assert(p11_image_entry(77, 1, 0)); continuity.seq = ~0ULL - 1;
    p11_image_exec_release(0); assert(coverage == IMG_FAILED);
    /* A real concurrent writer poisons; no volatile host data race is used. */
    reset(); assert(p11_image_entry(77, 1, 0));
    pthread_t worker; assert(!pthread_create(&worker, 0, poison, 0));
    assert(!pthread_join(worker, 0)); assert(!p11_image_entry(77, 1, 0));
    /* Concurrent post-exec entry cannot acquire a positive writer lock.
     * Withhold only its stamp; completed authority survives contention. */
    reset(); assert(p11_image_entry(77, 1, 0));
    hold_writer = 1; writer_locked = release_writer = 0;
    assert(!pthread_create(&worker, 0, renew, 0));
    while (!__atomic_load_n(&writer_locked, __ATOMIC_SEQ_CST)) sched_yield();
    assert(!p11_image_entry(77, 1, 1) && coverage == IMG_ENABLED);
    __atomic_store_n(&release_writer, 1, __ATOMIC_SEQ_CST);
    assert(!pthread_join(worker, 0)); hold_writer = 0;
    assert(p11_image_entry(77, 1, 1) && coverage == IMG_ENABLED);
    /* An invalidator racing that same real lock cannot silently lose poison. */
    reset(); assert(p11_image_entry(77, 1, 0));
    hold_writer = 1; writer_locked = release_writer = 0;
    assert(!pthread_create(&worker, 0, renew, 0));
    while (!__atomic_load_n(&writer_locked, __ATOMIC_SEQ_CST)) sched_yield();
    p11_image_exec_release(0);
    assert(coverage == IMG_FAILED);
    __atomic_store_n(&release_writer, 1, __ATOMIC_SEQ_CST);
    assert(!pthread_join(worker, 0)); hold_writer = 0;
    assert(!p11_image_entry(77, 1, 1) && coverage == IMG_FAILED);
    puts("image continuity: entry/index_cookie/poison/query/limits verified");
}
