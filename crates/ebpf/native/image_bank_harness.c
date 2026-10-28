/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Host driver for the image dispatcher/bank rollover model: compiles the
 * REAL image_bank.c for host with stub map storage and runs one scripted
 * interleaving per argv scenario. Each scenario prints "ASSERT <name>" per
 * passed check and "SCENARIO <name> PASS" at the end, and exits nonzero on
 * any failed check. Driven by tests/image_bank_standalone.rs; never
 * shipped. The threaded scenario serializes bank calls with a host mutex,
 * which models kernel atomic ordering for the count-once property.
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#undef __always_inline
#include "image_bank.c"

_Static_assert(IMAGE_IDENTITY_TICKET_LIMIT == 16384, "proof uses the real limit");
_Static_assert(P11_BANK_CUT_HEADROOM == 1024, "plan headroom H");

static struct p11_bank_domain G;
static int failures;

#define CHECK(cond, name)                                            \
    do {                                                             \
        if (cond) {                                                  \
            printf("ASSERT %s\n", name);                             \
        } else {                                                     \
            printf("FAIL %s (line %d)\n", name, __LINE__);           \
            failures++;                                              \
        }                                                            \
    } while (0)

static void scenario_exhaustion(void)
{
    struct p11_bank_identity id;
    enum p11_bank_status st;
    uint32_t leader;
    int i;
    uint32_t joined;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    for (leader = 1; leader <= 16000; leader++) {
        if (p11_bank_enter(&G, leader, leader, &id) != P11_BANK_OK ||
            p11_bank_leave(&G, leader, &id) != P11_BANK_OK) {
            printf("FAIL fill leader %u (line %d)\n", leader, __LINE__);
            failures++;
            return;
        }
    }
    for (i = 0; i < 384; i++)
        p11_bank_burn(&G);
    CHECK(G.maps[0].next_ticket == 16384, "next_ticket_reaches_16384");
    CHECK(G.maps[0].admitted + G.maps[0].burned == 16384, "successful_plus_burned_is_16384");
    CHECK(G.maps[0].burned == 384, "burns_reported_384");
    st = p11_bank_enter(&G, 60000, 60000, &id);
    CHECK(st == P11_BANK_QUOTA, "next_attempt_quota");
    CHECK(G.maps[0].unavailable == 1, "unavailable_plus_one");
    CHECK(G.maps[0].leader_ticket[60000] == 0, "refused_has_no_identity");
    CHECK(!p11_bank_join(&G, 0, 1, 16384, &joined),
          "burned_ticket_has_no_record");
    CHECK(G.maps[0].next_ticket == 16384, "refused_attempt_spends_no_ticket");
}

static void scenario_cut(void)
{
    struct p11_bank_identity id;
    uint64_t a_next;
    uint32_t leader;
    uint32_t b_inc;
    uint32_t joined;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    for (leader = 1; leader <= 100; leader++) {
        p11_bank_enter(&G, leader, leader, &id);
        p11_bank_leave(&G, leader, &id);
    }
    /* One A return held across the cut. */
    p11_bank_enter(&G, 101, 50000, &id);
    a_next = G.maps[0].next_ticket;
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "cut_setup_prepared");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "cut_setup_cut");
    b_inc = G.maps[1].incarnation;
    CHECK(p11_bank_enter(&G, 16385, 50001, &id) == P11_BANK_OK &&
              id.bank == 1 && id.ticket == 1 &&
              id.incarnation == G.maps[1].incarnation &&
              id.incarnation != 1,
          "b_ticket_1_in_new_incarnation");
    p11_bank_leave(&G, 50001, &id);
    CHECK(G.maps[0].next_ticket == a_next, "a_next_ticket_unchanged");
    CHECK(p11_bank_join(&G, 1, b_inc, 1, &joined) && joined == 16385,
          "leader_16385_holds_b_identity");
    CHECK(!G.maps[0].admission_open && G.maps[0].admitted == 101, "a_admission_frozen");
    CHECK(G.maps[0].admitted + G.maps[1].admitted == 102, "bank_counts_sum_to_ledger");
    {
        uint64_t a_before = G.maps[0].completed;

        CHECK(p11_bank_leave(&G, 50000, &id) == P11_BANK_OK && id.bank == 0 &&
                  G.maps[0].completed == a_before + 1 && G.maps[1].completed == 1,
              "a_completion_only_via_routed_return");
    }
}

struct worker_arg {
    unsigned int index;
    pthread_mutex_t *lock;
    pthread_barrier_t *barrier;
    unsigned long *enters_ok;
    unsigned long *leaves_ok;
};

static void *concurrent_worker(void *arg)
{
    struct worker_arg *w = (struct worker_arg *)arg;
    struct p11_bank_identity id;
    unsigned int i;

    for (i = 0; i < 10000; i++) {
        uint32_t call = w->index * 10000 + i;
        uint32_t leader = (call % 100) + 1;

        if (i == 5000) {
            pthread_barrier_wait(w->barrier);
            pthread_barrier_wait(w->barrier);
        }
        pthread_mutex_lock(w->lock);
        if (p11_bank_enter(&G, leader, call, &id) == P11_BANK_OK) {
            (*w->enters_ok)++;
            if (p11_bank_leave(&G, call, &id) == P11_BANK_OK)
                (*w->leaves_ok)++;
        }
        pthread_mutex_unlock(w->lock);
    }
    return NULL;
}

static void scenario_concurrent(void)
{
    struct p11_bank_identity id;
    pthread_mutex_t lock;
    pthread_barrier_t barrier;
    pthread_t threads[4];
    struct worker_arg args[4];
    unsigned long enters_ok = 0;
    unsigned long leaves_ok = 0;
    unsigned int t;
    uint32_t leader;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    /* Setup admissions hold their routes so the exact worker counts below
     * see zero setup pollution; they drain after the count asserts. */
    for (leader = 1; leader <= 100; leader++)
        p11_bank_enter(&G, leader, leader + 50000, &id);
    pthread_mutex_init(&lock, NULL);
    pthread_barrier_init(&barrier, NULL, 5);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "concurrent_setup_prepared");
    for (t = 0; t < 4; t++) {
        args[t].index = t;
        args[t].lock = &lock;
        args[t].barrier = &barrier;
        args[t].enters_ok = &enters_ok;
        args[t].leaves_ok = &leaves_ok;
        pthread_create(&threads[t], NULL, concurrent_worker, &args[t]);
    }
    /* First halves run in A; cut; second halves run in B. */
    pthread_barrier_wait(&barrier);
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "concurrent_setup_cut");
    pthread_barrier_wait(&barrier);
    for (t = 0; t < 4; t++)
        pthread_join(threads[t], NULL);
    pthread_barrier_destroy(&barrier);
    pthread_mutex_destroy(&lock);
    CHECK(G.maps[0].completed + G.maps[1].completed == 40000 && enters_ok == 40000 &&
              leaves_ok == 40000,
          "forty_thousand_counted");
    CHECK(G.maps[0].completed == 20000 && G.maps[1].completed == 20000,
          "twenty_thousand_per_bank");
    CHECK(G.both_counted == 0, "zero_counted_by_both");
    CHECK(enters_ok == leaves_ok, "zero_accepted_but_uncounted");
    for (leader = 1; leader <= 100; leader++)
        p11_bank_leave(&G, leader + 50000, &id);
    CHECK(p11_bank_close_zero(&G, 0), "setup_routes_drain_after_workers");
}

static void scenario_held_return(void)
{
    struct p11_bank_identity id;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    p11_bank_enter(&G, 5, 899, &id);
    p11_bank_leave(&G, 899, &id);
    p11_bank_enter(&G, 5, 900, &id);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "held_setup_prepared");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "held_setup_cut");
    CHECK(!p11_bank_close_zero(&G, 0), "a_not_reclaimable_while_held");
    CHECK(p11_bank_leave(&G, 900, &id) == P11_BANK_OK && id.bank == 0,
          "return_completes_through_a_route");
    CHECK(G.maps[0].completed == 2, "counted_in_a");
    CHECK(p11_bank_close_zero(&G, 0), "release_reaches_closed_zero");
}

static void scenario_late(void)
{
    struct p11_bank_identity id;
    uint32_t old_inc;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    old_inc = G.maps[0].incarnation;
    p11_bank_enter(&G, 3, 300, &id);
    p11_bank_leave(&G, 300, &id);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "late_setup_prepare_b");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "late_setup_cut");
    CHECK(p11_bank_reclaim(&G, 0) == P11_BANK_OK, "late_setup_reclaim_a");
    CHECK(p11_bank_prepare(&G, 0) == P11_BANK_OK, "late_setup_prepare_aprime");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "late_setup_cut_back");
    p11_bank_enter(&G, 9, 301, &id);
    p11_bank_leave(&G, 301, &id);
    CHECK(p11_bank_callback(&G, 0, old_inc, 1) == P11_BANK_REFUSED,
          "late_callback_refused");
    CHECK(G.successor_mutations == 0, "zero_successor_mutations");
    CHECK(p11_bank_callback(&G, 0, G.maps[0].incarnation, 1) == P11_BANK_OK &&
              G.successor_mutations == 1,
          "current_callback_mutates_once");
    CHECK(G.gate_ref[0] == 0 && G.gate_ref[1] == 0, "ref_balanced");
}

static void scenario_route_delete(void)
{
    struct p11_bank_identity id;

    p11_bank_init(&G, P11_BANK_ROUTE_R1);
    p11_bank_enter(&G, 11, 699, &id);
    p11_bank_leave(&G, 699, &id);
    p11_bank_enter(&G, 11, 700, &id);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "r1_setup_prepared");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "r1_setup_cut");
    G.fail_route_delete = 1;
    CHECK(p11_bank_leave(&G, 700, &id) == P11_BANK_DELETE_FAILED &&
              !p11_bank_close_zero(&G, 0),
          "delete_failure_pins_a");
    CHECK(p11_bank_reclaim(&G, 0) == P11_BANK_PINNED &&
              strcmp(G.last_refusal, "not-closed-zero") == 0 &&
              p11_bank_prepare(&G, 0) == P11_BANK_PINNED &&
              strcmp(G.last_refusal, "slot-occupied") == 0,
          "rollover_blocked_with_named_refusal");
    CHECK(G.select_bank == 1 && G.maps[1].completed == 0 && G.maps[0].completed == 1,
          "no_fold_while_pinned");
    G.fail_route_delete = 0;
    CHECK(p11_bank_leave(&G, 700, &id) == P11_BANK_OK && id.bank == 0 &&
              p11_bank_close_zero(&G, 0),
          "retry_drains_and_unpins");
}

static void scenario_third_preparation(void)
{
    struct p11_bank_identity id;
    long gate_before[2];
    uint64_t next_before;
    uint32_t leader;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    for (leader = 1; leader <= 10; leader++) {
        p11_bank_enter(&G, leader, leader, &id);
        p11_bank_leave(&G, leader, &id);
    }
    p11_bank_enter(&G, 1, 800, &id);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "third_setup_prepared");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "third_setup_cut");
    CHECK(p11_bank_prepare(&G, 0) == P11_BANK_PINNED &&
              strcmp(G.last_refusal, "slot-occupied") == 0,
          "third_preparation_refuses_named");
    G.fail_tailcall = 1;
    gate_before[0] = G.gate_ref[0];
    gate_before[1] = G.gate_ref[1];
    next_before = G.maps[1].next_ticket;
    CHECK(p11_bank_enter(&G, 50, 801, &id) == P11_BANK_TAILCALL_FAILED &&
              G.gate_ref[0] == gate_before[0] && G.gate_ref[1] == gate_before[1] &&
              G.maps[1].next_ticket == next_before &&
              G.maps[1].leader_ticket[50] == 0,
          "tailcall_failure_releases_refs");
    G.fail_tailcall = 0;
    CHECK(p11_bank_enter(&G, 50, 801, &id) == P11_BANK_OK && id.bank == 1 &&
              p11_bank_leave(&G, 801, &id) == P11_BANK_OK && G.maps[1].completed == 1,
          "current_bank_usable_after_refusal");
}

static void scenario_second_rollover(void)
{
    struct p11_bank_identity id;
    uint64_t old_map;
    uint32_t old_inc;
    uint32_t new_inc;
    uint32_t joined = 0;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    old_map = G.maps[0].map_id;
    old_inc = G.maps[0].incarnation;
    p11_bank_enter(&G, 2, 200, &id);
    p11_bank_leave(&G, 200, &id);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "aprime_setup_prepare_b");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "aprime_setup_cut");
    CHECK(p11_bank_reclaim(&G, 0) == P11_BANK_OK, "aprime_setup_reclaim_a");
    CHECK(G.retired_count == 1 && G.retired_maps[0] == old_map && G.progs[0] == 0,
          "a_maps_gone_after_reclaim");
    CHECK(p11_bank_prepare(&G, 0) == P11_BANK_OK, "aprime_setup_prepare_aprime");
    CHECK(G.maps[0].map_id != old_map, "aprime_map_ids_differ");
    new_inc = G.maps[0].incarnation;
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "aprime_setup_cut_back");
    p11_bank_enter(&G, 2, 201, &id);
    p11_bank_leave(&G, 201, &id);
    CHECK(id.ticket == 1 && !p11_bank_join(&G, 0, old_inc, 1, &joined) &&
              p11_bank_join(&G, 0, new_inc, 1, &joined) && joined == 2,
          "aprime_ticket_1_never_joins_a_ticket_1");
    CHECK(G.maps[0].completed == 1, "aprime_useful");
}

static void scenario_omitted(void)
{
    struct p11_bank_identity id;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "omitted_setup_prepared");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "omitted_setup_cut");
    CHECK(p11_bank_leave(&G, 4242, &id) == P11_BANK_REFUSED, "omitted_route_refuses");
    CHECK(G.maps[0].completed == 0 && G.maps[1].completed == 0, "no_fabricated_return");
    CHECK(p11_bank_enter(&G, 8, 4243, &id) == P11_BANK_OK &&
              p11_bank_leave(&G, 4243, &id) == P11_BANK_OK && id.bank == 1 &&
              G.maps[1].completed == 1,
          "useful_new_bank_twin_counts");
}

static void scenario_exec(void)
{
    struct p11_bank_identity id;
    unsigned int mask;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    p11_bank_enter(&G, 20, 2000, &id);
    p11_bank_leave(&G, 2000, &id);
    p11_bank_query_hold(&G, 0);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "exec_setup_prepared");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "exec_setup_cut");
    mask = p11_bank_exec_invalidate(&G, 20);
    CHECK(mask == 0x3 && G.maps[0].exec_invalid[20] != 0 &&
              G.maps[1].exec_invalid[20] != 0,
          "invalidator_covers_both_banks");
    p11_bank_enter(&G, 20, 2001, &id);
    p11_bank_leave(&G, 2001, &id);
    CHECK(p11_bank_query_invalidated(&G, 1, 20), "delayed_query_sees_invalidated");
    p11_bank_query_release(&G, 0);
    CHECK(p11_bank_close_zero(&G, 0), "leases_drain_after_release");
}

static void scenario_saturation(void)
{
    struct p11_bank_identity id;
    uint32_t leader;
    unsigned long admitted = 0;
    unsigned long refused = 0;
    unsigned long orphans = 0;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    for (leader = 1; leader <= 15360; leader++) {
        p11_bank_enter(&G, leader, leader, &id);
        p11_bank_leave(&G, leader, &id);
    }
    CHECK(G.maps[0].next_ticket == 15360, "saturation_setup_at_headroom_edge");
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "saturation_setup_prepared");
    /* Burst of 1524 before the flip completes: 1024 fit, 500 refuse. */
    for (leader = 20000; leader < 21524; leader++) {
        if (p11_bank_enter(&G, leader, leader, &id) == P11_BANK_OK) {
            admitted++;
            p11_bank_leave(&G, leader, &id);
        } else {
            refused++;
            if (G.maps[0].leader_ticket[leader] != 0)
                orphans++;
        }
    }
    CHECK(admitted == 1024, "burst_admits_headroom_only");
    CHECK(refused == 500, "quota_refusals_counted");
    CHECK(G.maps[0].unavailable == 500, "unavailable_delta_equals_refused");
    CHECK(orphans == 0, "refused_have_no_identity");
    CHECK(admitted + refused == 1524 && G.maps[0].next_ticket == 16384 &&
              G.maps[0].admitted == 16384 && p11_bank_cut(&G) == P11_BANK_OK &&
              p11_bank_enter(&G, 30000, 30000, &id) == P11_BANK_OK && id.ticket == 1 &&
              id.bank == 1,
          "no_silent_loss");
}

static void scenario_reused_call(void)
{
    struct p11_bank_identity first;
    struct p11_bank_identity second;
    uint64_t next_before;
    uint64_t admitted_before;
    uint32_t joined;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    CHECK(p11_bank_enter(&G, 1, 100, &first) == P11_BANK_OK,
          "reused_setup_first_ok");
    next_before = G.maps[0].next_ticket;
    admitted_before = G.maps[0].admitted;
    CHECK(p11_bank_enter(&G, 2, 100, &second) == P11_BANK_BAD,
          "reused_call_id_refuses");
    CHECK(G.maps[0].next_ticket == next_before,
          "refused_reuse_spends_no_ticket");
    CHECK(G.maps[0].admitted == admitted_before, "refused_reuse_admits_nothing");
    CHECK(G.maps[0].leader_ticket[2] == 0, "refused_reuse_installs_no_binding");
    CHECK(p11_bank_join(&G, 0, 1, 1, &joined) && joined == 1,
          "first_binding_untouched");
    CHECK(G.gate_ref[0] == 0 && G.gate_ref[1] == 0, "refused_reuse_balances_gate");
    CHECK(p11_bank_leave(&G, 100, &first) == P11_BANK_OK &&
              G.maps[0].completed == 1,
          "first_call_still_completes");
}

static void scenario_select_flip_admit(void)
{
    struct p11_bank_identity first;
    struct p11_bank_identity out;
    struct p11_bank_identity other;
    struct p11_bank_identity counted;
    struct p11_bank_route *held;
    uint8_t selected;
    uint8_t plain;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    CHECK(p11_bank_enter(&G, 7, 7000, &first) == P11_BANK_OK &&
              first.bank == 0 && first.incarnation == 1 && first.ticket == 1,
          "select_admit_setup_held_a_call");
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "select_admit_setup_prepared");
    /* The flip lands inside the next select, between the gate take
     * and the recheck: the dispatcher must back its stale ref out
     * and route the call to the current bank. */
    G.flip_before_recheck = 1;
    selected = p11_bank_select(&G);
    CHECK(selected == 1, "selected_bank_is_post_flip_current");
    CHECK(G.select_bank == 1 && G.flip_before_recheck == 0, "flip_fired_inside_select");
    CHECK(G.gate_ref[0] == 0, "stale_bank_backed_out");
    CHECK(G.gate_ref[1] == 1, "current_bank_holds_the_ref");
    CHECK(p11_bank_admit(&G, 7, 7001, selected, &out) == P11_BANK_OK &&
              out.bank == 1 && out.incarnation == G.maps[1].incarnation &&
              out.ticket == 1,
          "admitted_identity_is_current_bank");
    plain = p11_bank_select(&G);
    CHECK(plain == 1, "steady_select_stays_current");
    CHECK(p11_bank_admit(&G, 8, 7002, plain, &other) == P11_BANK_OK,
          "second_bank_identity_admits");
    CHECK(!(first.incarnation == out.incarnation && first.ticket == out.ticket),
          "no_identity_collision_across_banks");
    held = &G.start0[7000];
    CHECK(held->present && held->bank == 0 && held->incarnation == 1 &&
              held->ticket == 1,
          "held_route_keeps_fixed_incarnation");
    CHECK(p11_bank_leave(&G, 7000, &counted) == P11_BANK_OK && counted.bank == 0,
          "select_admit_setup_leave_a");
    CHECK(p11_bank_leave(&G, 7001, &counted) == P11_BANK_OK && counted.bank == 1,
          "raced_call_completes_in_current_bank");
    CHECK(p11_bank_leave(&G, 7002, &counted) == P11_BANK_OK && counted.bank == 1,
          "select_admit_setup_leave_b");
    CHECK(G.maps[0].completed == 1 && G.maps[1].completed == 2,
          "select_admit_counts_split");
    CHECK(G.gate_ref[0] == 0 && G.gate_ref[1] == 0, "select_admit_gates_balanced");
}

static void scenario_select_flip_closed_zero(void)
{
    struct p11_bank_identity out;
    struct p11_bank_identity counted;
    uint8_t selected;

    p11_bank_init(&G, P11_BANK_ROUTE_R0);
    CHECK(p11_bank_prepare(&G, 1) == P11_BANK_OK, "select_close_setup_prepared");
    /* A selected-but-unadmitted call holds A's gate across the flip:
     * A must not read closed-zero until that ref drains. */
    selected = p11_bank_select(&G);
    CHECK(selected == 0, "select_close_setup_selected_a");
    CHECK(G.gate_ref[0] == 1, "selected_call_holds_a_ref");
    CHECK(p11_bank_cut(&G) == P11_BANK_OK, "flip_published");
    CHECK(!p11_bank_close_zero_admission(&G, 0), "not_closed_zero_while_selected");
    CHECK(p11_bank_close_zero_admission(&G, 0) == p11_bank_close_zero(&G, 0),
          "admission_check_agrees_with_leased_check");
    CHECK(p11_bank_admit(&G, 9, 7100, selected, &out) == P11_BANK_OK &&
              out.bank == 0 && out.incarnation == 1 && out.ticket == 1,
          "selected_call_admits_with_a_incarnation");
    CHECK(!p11_bank_close_zero_admission(&G, 0), "live_call_blocks_close_zero");
    CHECK(!p11_bank_close_zero(&G, 0), "live_call_blocks_leased_close_zero");
    CHECK(p11_bank_leave(&G, 7100, &counted) == P11_BANK_OK && counted.bank == 0,
          "selected_call_completes_in_a");
    CHECK(G.maps[0].completed == 1, "select_close_counts_in_a");
    CHECK(p11_bank_close_zero_admission(&G, 0), "release_reaches_admission_closed_zero");
    CHECK(p11_bank_close_zero(&G, 0), "release_reaches_leased_closed_zero");
    CHECK(G.gate_ref[0] == 0 && G.gate_ref[1] == 0, "select_close_gates_balanced");
}

int main(int argc, char **argv)
{
    const char *scenario;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <scenario>\n", argv[0]);
        return 2;
    }
    scenario = argv[1];
    if (strcmp(scenario, "exhaustion-without-next-bank") == 0)
        scenario_exhaustion();
    else if (strcmp(scenario, "cut-moves-new-admissions-only") == 0)
        scenario_cut();
    else if (strcmp(scenario, "concurrent-cut-counts-once") == 0)
        scenario_concurrent();
    else if (strcmp(scenario, "held-return-follows-route") == 0)
        scenario_held_return();
    else if (strcmp(scenario, "late-incarnation-refused") == 0)
        scenario_late();
    else if (strcmp(scenario, "route-delete-failure-pins-bank") == 0)
        scenario_route_delete();
    else if (strcmp(scenario, "third-preparation-refuses") == 0)
        scenario_third_preparation();
    else if (strcmp(scenario, "second-rollover-reuses-slot") == 0)
        scenario_second_rollover();
    else if (strcmp(scenario, "omitted-route-refuses") == 0)
        scenario_omitted();
    else if (strcmp(scenario, "exec-invalidator-spans-cut") == 0)
        scenario_exec();
    else if (strcmp(scenario, "saturation-burst-refuses-counted") == 0)
        scenario_saturation();
    else if (strcmp(scenario, "reused-call-id-refuses") == 0)
        scenario_reused_call();
    else if (strcmp(scenario, "select-flip-admit") == 0)
        scenario_select_flip_admit();
    else if (strcmp(scenario, "select-flip-closed-zero") == 0)
        scenario_select_flip_closed_zero();
    else {
        fprintf(stderr, "unknown scenario: %s\n", scenario);
        return 2;
    }
    if (failures == 0)
        printf("SCENARIO %s PASS\n", scenario);
    return failures != 0;
}
