/* SPDX-License-Identifier: GPL-3.0-or-later */
/* H8-D atomic birth marker fixture: executes the actual production
 * publication/dirty/readback/admission implementation from
 * crates/ebpf/native/journal_marker.{c,h} over real instance_record
 * rows. Only thread scheduling is injected; there is no second marker
 * algorithm. Inactive: no live root calls these leaves. */
#define P11SCOPE_JOURNAL_MARKER_NO_MAPS
#include "journal_marker.h"
/* CAS-loss injection for the exhaustion probe below: only atomic
 * interference is injected; there is no second admission algorithm. */
static u64 *cas_victim;
static unsigned cas_losses_remaining;
static u64 admit_controlled_cas(u64 *cell, u64 old, u64 replacement);
#define __sync_val_compare_and_swap admit_controlled_cas
#include "journal_marker.c"
#undef __sync_val_compare_and_swap
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int failures;

static u64 admit_controlled_cas(u64 *cell, u64 old, u64 replacement)
{
    if (cell == cas_victim && cas_losses_remaining) {
        /* Another CPU won the race: the cell advances past our
         * observed word, so our compare fails. */
        cas_losses_remaining--;
        *cell = old + 1;
        return old + 1;
    }
    return __sync_val_compare_and_swap(cell, old, replacement);
}

#define EXPECT(cond, ...)                                                                          \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d: ", __func__, __LINE__);                                    \
            fprintf(stderr, __VA_ARGS__);                                                           \
            fprintf(stderr, "\n");                                                                 \
        }                                                                                          \
    } while (0)

static void check_layout(void)
{
    EXPECT(sizeof(struct instance_record) == 152, "record is 152 B, got %zu",
           sizeof(struct instance_record));
    EXPECT(offsetof(struct instance_record, journal_bootstrap) == 144, "marker at 144, got %zu",
           offsetof(struct instance_record, journal_bootstrap));
    EXPECT(sizeof(struct journal_admission_control) == 16, "control row is 16 B, got %zu",
           sizeof(struct journal_admission_control));
    EXPECT(P11_JOURNAL_MARKER_ADMIT_CAP == 16384ULL, "admit cap is 16384");
}

static void check_publish_and_read(void)
{
    struct instance_record rec;
    u64 exec = 0;

    memset(&rec, 0, sizeof(rec));
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_UNPUBLISHED_READ,
           "fresh storage reads unpublished");
    EXPECT(p11_journal_marker_publish(&rec, 7) == 1, "fresh publish wins");
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_READY, "reads READY");
    EXPECT(exec == 7, "READY names exec 7, got %llu", (unsigned long long)exec);
    EXPECT(p11_journal_marker_publish(&rec, 7) == 1, "same-exec republish is idempotent");
    EXPECT(p11_journal_marker_publish(&rec, 9) == 1, "re-exec publishes over READY(old)");
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_READY, "reads READY");
    EXPECT(exec == 9, "READY names exec 9, got %llu", (unsigned long long)exec);
    /* Garbage words fail closed and never publish. */
    rec.journal_bootstrap = 3;
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_INVALID,
           "low-bits-3 word is invalid");
    EXPECT(p11_journal_marker_publish(&rec, 11) == 0, "publish over garbage fails");
    rec.journal_bootstrap = 4;
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_INVALID,
           "high-bits-set unpublished shape is invalid");
    EXPECT(p11_journal_marker_publish(&rec, 11) == 0, "publish over garbage fails");
    EXPECT(rec.journal_bootstrap == 4, "failed publish changes nothing");
}

static void check_dirty_sticks(void)
{
    struct instance_record rec;
    u64 exec = 0;

    memset(&rec, 0, sizeof(rec));
    EXPECT(p11_journal_marker_publish(&rec, 7) == 1, "publish wins");
    p11_journal_marker_dirty(&rec);
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_DIRTY_READ,
           "gap dirties the marker");
    EXPECT(p11_journal_marker_publish(&rec, 7) == 0, "publish over DIRTY fails");
    EXPECT(p11_journal_marker_publish(&rec, 8) == 0, "re-exec over DIRTY fails");
    p11_journal_marker_dirty(&rec);
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_DIRTY_READ,
           "DIRTY is idempotent");
    /* A gap on fresh storage marks too. */
    memset(&rec, 0, sizeof(rec));
    p11_journal_marker_dirty(&rec);
    EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_DIRTY_READ,
           "fresh storage dirties");
}

static void check_admit(void)
{
    struct journal_admission_control ctl = {0, 0};
    u64 ready7 = (7ULL << 2) | 2ULL;

    EXPECT(p11_journal_marker_admit(&ctl, ready7, 7) == 1, "READY(7) admits for exec 7");
    EXPECT(ctl.spent == 1 && ctl.failed == 0, "admission spends one permit");
    EXPECT(p11_journal_marker_admit(&ctl, ready7, 8) == 0, "wrong exec refuses");
    EXPECT(ctl.failed == 1, "refusal trips the failed latch");
    EXPECT(p11_journal_marker_admit(&ctl, ready7, 7) == 0, "latched failure sticks");
    /* Cap: the 16,384th permit spends, the next trips the latch. */
    ctl.spent = 16383;
    ctl.failed = 0;
    EXPECT(p11_journal_marker_admit(&ctl, ready7, 7) == 1, "permit 16384 spends");
    EXPECT(ctl.spent == 16384 && ctl.failed == 0, "cap reached unlatched");
    EXPECT(p11_journal_marker_admit(&ctl, ready7, 7) == 0, "permit 16385 refuses");
    EXPECT(ctl.failed == 1, "cap refusal trips the failed latch");
    /* Non-READY markers refuse: unpublished, DIRTY, garbage. */
    ctl.spent = 0;
    ctl.failed = 0;
    EXPECT(p11_journal_marker_admit(&ctl, 0, 7) == 0, "unpublished refuses");
    EXPECT(ctl.failed == 1, "unpublished trips the latch");
    ctl.failed = 0;
    EXPECT(p11_journal_marker_admit(&ctl, 1, 7) == 0, "DIRTY refuses");
    EXPECT(ctl.failed == 1, "DIRTY trips the latch");
    ctl.failed = 0;
    EXPECT(p11_journal_marker_admit(&ctl, 3, 7) == 0, "garbage refuses");
    EXPECT(ctl.failed == 1, "garbage trips the latch");
}

struct admit_race_arg {
    struct journal_admission_control *ctl;
    u64 marker;
    u64 exec;
    unsigned attempts;
    unsigned won;
};

static pthread_barrier_t admit_gate;

static void *race_admit(void *arg)
{
    struct admit_race_arg *race = arg;
    unsigned i;

    /* The gate releases every racer into the admission window
     * together, so the critical sections genuinely overlap. */
    pthread_barrier_wait(&admit_gate);
    for (i = 0; i < race->attempts; i++)
        race->won += (unsigned)p11_journal_marker_admit(race->ctl, race->marker, race->exec);
    return 0;
}

static void check_admit_race(void)
{
    /* N7: admission at the bound is an atomic reservation with a
     * failure latch. Two CPUs observing 16,383 must not both admit:
     * exactly the remaining permits win, spent never exceeds the cap,
     * and the over-admission attempt fails loudly (failed latched),
     * never silently. */
    static struct journal_admission_control ctl;
    u64 ready7 = (7ULL << 2) | 2ULL;
    struct admit_race_arg args[8];
    pthread_t threads[8];
    unsigned t, i, won;
    int round;

    /* Tight race at the last permit: 2 threads x 5000 rounds from
     * spent=16383 admit exactly once per round. */
    won = 0;
    assert(pthread_barrier_init(&admit_gate, 0, 2) == 0);
    for (round = 0; round < 5000; round++) {
        ctl.spent = 16383;
        ctl.failed = 0;
        for (t = 0; t < 2; t++) {
            args[t].ctl = &ctl;
            args[t].marker = ready7;
            args[t].exec = 7;
            args[t].attempts = 1;
            args[t].won = 0;
            assert(pthread_create(&threads[t], 0, race_admit, &args[t]) == 0);
        }
        assert(pthread_join(threads[0], 0) == 0);
        assert(pthread_join(threads[1], 0) == 0);
        won += args[0].won + args[1].won;
        if (args[0].won + args[1].won != 1)
            break;
        EXPECT(ctl.spent == 16384, "round %d: spent is 16384, got %llu", round,
               (unsigned long long)ctl.spent);
        EXPECT(ctl.failed == 1, "round %d: the loser trips the latch", round);
        if (ctl.spent != 16384 || ctl.failed != 1)
            break;
    }
    EXPECT(won == 5000, "last-permit race admits exactly once per round, won %u/5000", won);
    assert(pthread_barrier_destroy(&admit_gate) == 0);
    /* Sequential fill: one thread admits exactly the full cap with
     * no latch, and the 16385th attempt refuses loudly. Deterministic
     * exact-cap proof without contention. */
    ctl.spent = 0;
    ctl.failed = 0;
    won = 0;
    for (i = 0; i < 16384; i++)
        won += (unsigned)p11_journal_marker_admit(&ctl, ready7, 7);
    EXPECT(won == 16384, "sequential fill admits exactly the cap, won %u", won);
    EXPECT(ctl.spent == 16384, "sequential fill spends exactly the cap, spent %llu",
           (unsigned long long)ctl.spent);
    EXPECT(ctl.failed == 0, "sequential fill trips no latch");
    EXPECT(p11_journal_marker_admit(&ctl, ready7, 7) == 0, "permit 16385 refuses");
    EXPECT(ctl.failed == 1, "cap refusal trips the failed latch");
    /* Single-shot contention: 2048 rounds of an 8-way single-attempt
     * race admit exactly the full cap with no latch. Each round is an
     * isolated race (joined before the next starts), and a single-shot
     * attempt can lose at most one race per rival win — 7 losses max,
     * so 32-retry exhaustion is impossible by construction while every
     * round still exercises genuine atomic contention. */
    ctl.spent = 0;
    ctl.failed = 0;
    won = 0;
    assert(pthread_barrier_init(&admit_gate, 0, 8) == 0);
    for (round = 0; round < 2048; round++) {
        for (t = 0; t < 8; t++) {
            args[t].ctl = &ctl;
            args[t].marker = ready7;
            args[t].exec = 7;
            args[t].attempts = 1;
            args[t].won = 0;
            assert(pthread_create(&threads[t], 0, race_admit, &args[t]) == 0);
        }
        for (t = 0; t < 8; t++)
            assert(pthread_join(threads[t], 0) == 0);
        for (t = 0; t < 8; t++)
            won += args[t].won;
        if (ctl.failed != 0)
            break;
    }
    EXPECT(won == 16384, "single-shot contention admits exactly the cap, won %u", won);
    EXPECT(ctl.spent == 16384, "single-shot contention spends exactly the cap, spent %llu",
           (unsigned long long)ctl.spent);
    EXPECT(ctl.failed == 0, "single-shot contention trips no latch");
    assert(pthread_barrier_destroy(&admit_gate) == 0);
    /* Saturated hammer: 8 threads x 3000 attempts. Under saturation an
     * attempt CAN exhaust 32 consecutive races, and the H8 failure
     * protocol latches on exhaustion — so saturation may strand
     * below-cap permits (the plan's finite availability cost,
     * disclosed and measured, never silent). Safety still holds
     * exactly: every win spent exactly one permit (no lost updates,
     * no phantom wins), spent never exceeds the cap (never
     * over-admits), and the latch explains any shortfall. */
    ctl.spent = 0;
    ctl.failed = 0;
    assert(pthread_barrier_init(&admit_gate, 0, 8) == 0);
    for (t = 0; t < 8; t++) {
        args[t].ctl = &ctl;
        args[t].marker = ready7;
        args[t].exec = 7;
        args[t].attempts = 3000;
        args[t].won = 0;
        assert(pthread_create(&threads[t], 0, race_admit, &args[t]) == 0);
    }
    for (t = 0; t < 8; t++)
        assert(pthread_join(threads[t], 0) == 0);
    won = 0;
    for (i = 0; i < 8; i++)
        won += args[i].won;
    EXPECT(won == ctl.spent, "hammer accounts every win, won %u spent %llu", won,
           (unsigned long long)ctl.spent);
    EXPECT(ctl.spent <= 16384, "hammer never over-admits, spent %llu",
           (unsigned long long)ctl.spent);
    EXPECT(ctl.failed == 1, "hammer trips the latch");
    assert(pthread_barrier_destroy(&admit_gate) == 0);
}

static void check_admit_exhaustion_latches(void)
{
    /* C7 remainder: the H8 failure protocol latches `failed`
     * permanently on exhausted admission CAS — the mint precedent's
     * unlatched contention refusal does not apply here. Mirrors the
     * reviewer's injected 32-loss probe: 32 consecutive lost races
     * refuse with spent advanced and the latch set. */
    struct journal_admission_control ctl = {0, 0};
    u64 ready7 = (7ULL << 2) | 2ULL;
    cas_victim = &ctl.spent;
    cas_losses_remaining = 32;
    EXPECT(p11_journal_marker_admit(&ctl, ready7, 7) == 0, "exhausted admission refuses");
    EXPECT(ctl.spent == 32, "32 lost races advanced spent, got %llu",
           (unsigned long long)ctl.spent);
    EXPECT(ctl.failed == 1, "exhaustion latches failed permanently, got %llu",
           (unsigned long long)ctl.failed);
    cas_victim = NULL;
    /* The latch sticks: later admissions refuse without spending. */
    EXPECT(p11_journal_marker_admit(&ctl, ready7, 7) == 0, "latched control refuses");
    EXPECT(ctl.spent == 32, "latched refusal spends nothing, spent %llu",
           (unsigned long long)ctl.spent);
}

static void check_null_closed(void)
{
    u64 exec = 0;

    EXPECT(p11_journal_marker_publish(0, 7) == 0, "NULL publish fails");
    EXPECT(p11_journal_marker_read(0, &exec) == P11_JOURNAL_MARKER_INVALID,
           "NULL read is invalid");
    EXPECT(p11_journal_marker_admit(0, 0, 7) == 0, "NULL admit fails");
    p11_journal_marker_dirty(0);
}

struct race_arg {
    struct instance_record *rec;
    u64 exec;
    int won;
};

static void *race_publish(void *arg)
{
    struct race_arg *race = arg;

    race->won = p11_journal_marker_publish(race->rec, race->exec);
    return 0;
}

static void *race_dirty(void *arg)
{
    p11_journal_marker_dirty(arg);
    return 0;
}

static void check_publish_race(void)
{
    struct instance_record rec;
    struct race_arg a = {&rec, 7, 0}, b = {&rec, 7, 0};
    pthread_t ta, tb;
    u64 exec = 0;
    int i, readback;

    /* Same-exec publishers race on fresh storage: both win (idempotent)
     * and the word is that exec's READY. */
    for (i = 0; i < 64; i++) {
        memset(&rec, 0, sizeof(rec));
        a.won = 0;
        b.won = 0;
        assert(pthread_create(&ta, 0, race_publish, &a) == 0);
        assert(pthread_create(&tb, 0, race_publish, &b) == 0);
        assert(pthread_join(ta, 0) == 0);
        assert(pthread_join(tb, 0) == 0);
        EXPECT(a.won && b.won, "same-exec racers both win (a=%d b=%d)", a.won, b.won);
        EXPECT(p11_journal_marker_read(&rec, &exec) == P11_JOURNAL_MARKER_READY,
               "raced word reads READY");
        EXPECT(exec == 7, "word names exec 7, got %llu", (unsigned long long)exec);
    }
    /* Publish races a scope gap: the word is atomic (READY or DIRTY,
     * never torn or unpublished) and the readback decides. */
    for (i = 0; i < 64; i++) {
        memset(&rec, 0, sizeof(rec));
        assert(pthread_create(&ta, 0, race_publish, &a) == 0);
        assert(pthread_create(&tb, 0, race_dirty, &rec) == 0);
        assert(pthread_join(ta, 0) == 0);
        assert(pthread_join(tb, 0) == 0);
        readback = p11_journal_marker_read(&rec, &exec);
        EXPECT(readback == P11_JOURNAL_MARKER_READY || readback == P11_JOURNAL_MARKER_DIRTY_READ,
               "raced word is READY or DIRTY, got %d", readback);
        if (readback == P11_JOURNAL_MARKER_READY)
            EXPECT(exec == 7, "READY names exec 7, got %llu", (unsigned long long)exec);
    }
}

int main(void)
{
    check_layout();
    check_publish_and_read();
    check_dirty_sticks();
    check_admit();
    check_admit_race();
    check_admit_exhaustion_latches();
    check_null_closed();
    check_publish_race();
    if (!failures)
        printf("journal-marker: all checks passed\n");
    return failures != 0;
}
