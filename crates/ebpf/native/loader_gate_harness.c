/* SPDX-License-Identifier: GPL-2.0-only */
/* T-L2/T-L2c host harness: executes the real loader_gate.c with stub map
 * storage and drives producer-shaped admit/lookup/retire/cutover scenarios.
 * Only the map helpers are stubbed; there is no second gate algorithm. */
#include "loader_gate.h"
/* Weak so the pre-implementation scenarios fail at the actual missing
 * acknowledgement assertion, without a link error masquerading as
 * runtime RED (same trick as the ticket fixture). The declarations
 * precede the implementation include, like the ticket fixture. */
extern long p11_loader_gate_ack(u64 cookie) __attribute__((weak));
extern long p11_loader_gate_row_generation(u32 slot, u64 *generation_out)
    __attribute__((weak));
extern long p11_loader_gate_cutover_latched(void) __attribute__((weak));
#include "loader_gate.c"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#ifdef GATE_HOST_CAS_HOOK
extern int gate_cas_fail_all;
#endif

unsigned char LOADER_GATE, LOADER_GATE_CTL;
static struct loader_gate_row gate_rows[LOADER_GATE_SLOTS];
static struct loader_gate_control gate_ctl;
static int ctl_present = 1;

static void *gate_lookup(void *map, const void *key)
{
    if (map == &LOADER_GATE_CTL)
        return ctl_present ? &gate_ctl : (void *)0;
    if (map == &LOADER_GATE) {
        u32 slot;
        memcpy(&slot, key, sizeof(slot));
        return slot < LOADER_GATE_SLOTS ? &gate_rows[slot] : (void *)0;
    }
    return (void *)0;
}

static void gate_reset(void)
{
    memset(gate_rows, 0, sizeof(gate_rows));
    memset(&gate_ctl, 0, sizeof(gate_ctl));
    gate_ctl.limit = LOADER_GATE_SLOTS;
    ctl_present = 1;
    loader_gate_map_lookup = gate_lookup;
}

#define CHECK(cond, name) do { \
    if (!(cond)) { \
        printf("SCENARIO %s FAIL " name "\n", scenario); \
        return 1; \
    } \
    printf("ASSERT " name "\n"); \
} while (0)

#define TOKEN(gen, slot) ((((u64)(gen)) << 8) | (u64)(slot))

/* Healthy twin: a generation-1 adapter token admits and resolves. */
static int admit_lookup_healthy(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_admit(5, 1) == 0, "admit_slot5_gen1_zero");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 5)) == 5, "lookup_token_resolves_slot5");
    CHECK(gate_rows[5].state == LOADER_GATE_ARMED, "row5_armed");
    CHECK(gate_rows[5].generation == 1, "row5_generation1");
    CHECK(gate_ctl.admitted == 1, "admitted_counted_once");
    CHECK(gate_ctl.refusals == 0, "no_refusals");
    return 0;
}

/* Failure twins after the cutover: stale, foreign, burned, malformed and
 * oversized cookies all refuse closed with counted refusals. */
static int refuse_twins(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_admit(7, 2) == 0, "admit_slot7_gen2_zero");
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_lookup(TOKEN(2, 7)) == 7, "live_token_resolves");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 7)) == -1, "burned_gen1_refuses");
    CHECK(p11_loader_gate_lookup(TOKEN(3, 7)) == -1, "future_gen3_refuses");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 9)) == -1, "foreign_slot_refuses");
    CHECK(p11_loader_gate_lookup(0) == -1, "zero_refuses");
    CHECK(p11_loader_gate_lookup(5) == -1, "gen0_refuses");
    CHECK(p11_loader_gate_lookup(0xff) == -1, "gen0_wide_refuses");
    CHECK(p11_loader_gate_lookup(0x10000000000ULL) == -1, "over_40_bits_refuses");
    CHECK(p11_loader_gate_lookup(0xffffffffffffffffULL) == -1, "u64max_refuses");
    CHECK(p11_loader_gate_lookup(0xffffffffffULL) == -1, "unadmitted_widest_refuses");
    CHECK(gate_rows[7].state == LOADER_GATE_ARMED, "live_row_stays_armed");
    CHECK(gate_ctl.refusals == 9, "nine_refusals_counted");
    return 0;
}

/* Old-format cookies fail closed at lookup after the atomic cutover. */
static int old_format_after_cutover(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_admit(1, 1) == 0, "admit_slot1_gen1_zero");
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 1)) == 1, "token_still_resolves");
    /* Old-format absent cookie for context 1: (1 << 9) | 0. */
    CHECK(p11_loader_gate_lookup(0x200) == -1, "old_absent_refuses");
    /* Old-format present cookie, delta 5, context 1: (5 << 9) | 0x100. */
    CHECK(p11_loader_gate_lookup(0xb00) == -1, "old_delta_refuses");
    /* Old-format absent cookie for context 2: (1 << 9) | 1. */
    CHECK(p11_loader_gate_lookup(0x201) == -1, "old_absent_ctx2_refuses");
    /* Delta-0 present cookie for context 1 is the numeric twin of token
     * (gen 1, slot 0); slot 0 is empty here, so it refuses as foreign. */
    CHECK(p11_loader_gate_lookup(0x100) == -1, "twin_slot_empty_refuses");
    CHECK(gate_ctl.refusals == 4, "four_refusals_counted");
    return 0;
}

/* The twin hazard, pinned at the native seam: a delta-0 old-format cookie
 * is indistinguishable from its generation-1 token, so the cutover
 * requires every old-format producer to drain first. */
static int old_format_twin_requires_quiescence(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_admit(0, 1) == 0, "admit_slot0_gen1_zero");
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_lookup(0x100) == 0, "twin_resolves_indistinguishable");
    return 0;
}

/* Every old-format absent cookie is a generation-2 twin: (1<<9)|(c-1)
 * reads as token (gen 2, slot c-1) and resolves while that row is armed. */
static int old_absent_gen2_resolves(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_admit(0, 2) == 0, "admit_slot0_gen2_zero");
    CHECK(p11_loader_gate_admit(2, 2) == 0, "admit_slot2_gen2_zero");
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    /* Old-format absent cookie for context 1: (1 << 9) | 0. */
    CHECK(p11_loader_gate_lookup(0x200) == 0, "absent_ctx1_resolves_slot0");
    /* Old-format absent cookie for context 3: (1 << 9) | 2. */
    CHECK(p11_loader_gate_lookup(0x202) == 2, "absent_ctx3_resolves_slot2");
    CHECK(gate_ctl.refusals == 0, "twins_refuse_nothing");
    return 0;
}

/* Every old-format present cookie with 0 <= d < 2^31 is a generation-2d+1
 * twin: (d<<9)|(1<<8)|(c-1) reads as token (gen 2d+1, slot c-1). */
static int old_delta1_gen3_resolves(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_admit(0, 3) == 0, "admit_slot0_gen3_zero");
    CHECK(p11_loader_gate_admit(2, 11) == 0, "admit_slot2_gen11_zero");
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    /* Old-format present cookie, delta 1, context 1: (1 << 9) | 0x100. */
    CHECK(p11_loader_gate_lookup(0x300) == 0, "delta1_ctx1_resolves_slot0");
    /* Old-format present cookie, delta 5, context 3: (5 << 9) | 0x102. */
    CHECK(p11_loader_gate_lookup(0xb02) == 2, "delta5_ctx3_resolves_slot2");
    CHECK(gate_ctl.refusals == 0, "twins_refuse_nothing");
    return 0;
}

/* Every START-removal reason retires with its owned disposition, and no
 * token or map identity recycles before acknowledgement. */
static int retire_no_recycle(const char *scenario)
{
    static const u32 reasons[3] = { 0, 1, 6 };
    static const u32 disps[3] = {
        LOADER_GATE_DISP_END, LOADER_GATE_DISP_NO_END, LOADER_GATE_DISP_ABANDON
    };
    unsigned i;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    for (i = 0; i < 3; i++) {
        u32 slot = 10 + i;
        u64 cookie = TOKEN(1, slot);
        CHECK(p11_loader_gate_admit(slot, 1) == 0, "retire_admit_zero");
        CHECK(p11_loader_gate_note_producer_end(cookie, reasons[i]) == 0,
              "retire_report_zero");
        CHECK(gate_rows[slot].state == LOADER_GATE_RETIRED, "row_retired");
        CHECK(gate_rows[slot].disposition == disps[i], "disposition_owned");
        CHECK(p11_loader_gate_lookup(cookie) == -1, "retired_lookup_refuses");
        CHECK(p11_loader_gate_admit(slot, 1) == -1, "same_gen_no_recycle");
        CHECK(p11_loader_gate_admit(slot, 2) == -1, "next_gen_no_recycle");
    }
    CHECK(gate_ctl.retired == 3, "three_retired_counted");
    CHECK(gate_ctl.admitted == 3, "three_admitted_counted");
    return 0;
}

/* Reason mapping is exact; unknown reasons never retire a row. */
static int reason_map(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_disposition_for_reason(0) == LOADER_GATE_DISP_END,
          "return_maps_end");
    CHECK(p11_loader_gate_disposition_for_reason(1) == LOADER_GATE_DISP_NO_END,
          "collision_maps_no_end");
    CHECK(p11_loader_gate_disposition_for_reason(6) == LOADER_GATE_DISP_ABANDON,
          "exec_exit_maps_abandon");
    CHECK(p11_loader_gate_disposition_for_reason(2) == LOADER_GATE_DISP_NONE,
          "reason2_maps_none");
    CHECK(p11_loader_gate_disposition_for_reason(5) == LOADER_GATE_DISP_NONE,
          "reason5_maps_none");
    CHECK(p11_loader_gate_disposition_for_reason(7) == LOADER_GATE_DISP_NONE,
          "reason7_maps_none");
    CHECK(p11_loader_gate_disposition_for_reason(99) == LOADER_GATE_DISP_NONE,
          "reason99_maps_none");
    CHECK(p11_loader_gate_admit(4, 1) == 0, "admit_slot4_gen1_zero");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 4), 99) == -1,
          "unknown_reason_refuses");
    CHECK(gate_rows[4].state == LOADER_GATE_ARMED, "row_stays_armed");
    CHECK(gate_rows[4].disposition == LOADER_GATE_DISP_NONE, "no_disposition");
    CHECK(gate_ctl.retired == 0, "nothing_retired");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 4), 0) == 0,
          "owned_end_after_refusal_zero");
    CHECK(gate_rows[4].disposition == LOADER_GATE_DISP_END, "end_owned");
    return 0;
}

/* Prepared-cancellation debt is preserved: an admitted row with no producer
 * stays armed and occupied; no cancel path frees it silently. */
static int admit_without_producer_keeps_debt(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_admit(9, 1) == 0, "admit_slot9_gen1_zero");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 9)) == 9, "armed_resolves");
    CHECK(p11_loader_gate_admit(9, 1) == -2, "double_admit_untracked");
    CHECK(gate_rows[9].state == LOADER_GATE_ARMED, "row_still_armed");
    CHECK(gate_ctl.admitted == 1, "admitted_once");
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 9)) == 9, "armed_past_cutover");
    return 0;
}

/* The cutover is a one-way latch; pre-cutover unknowns are untracked (-2),
 * post-cutover unknowns are counted refusals (-1). */
static int cutover_latch(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_lookup(TOKEN(1, 12)) == -2, "pre_cutover_untracked");
    CHECK(gate_ctl.refusals == 0, "pre_cutover_uncounted");
    CHECK(p11_loader_gate_cutover() == 0, "first_cutover_zero");
    CHECK(p11_loader_gate_cutover() == -1, "second_cutover_refuses");
    CHECK(gate_ctl.cutover == 1, "latch_holds");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 12)) == -1, "post_cutover_refusal");
    CHECK(gate_ctl.refusals == 1, "post_cutover_counted");
    CHECK(p11_loader_gate_admit(12, 1) == 0, "admit_past_cutover_zero");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 12)) == 12, "armed_resolves");
    return 0;
}

/* L4b loader cells: arms count admits, retained charges live and
 * retired-unacknowledged rows until the acknowledged reclaim (final
 * occupancy is arms minus reclaims), the peak is monotonic across
 * retire/reclaim cycles. */
static int l4b_counters(const char *scenario)
{
    gate_reset();
    CHECK(&p11_loader_gate_ack, "ack_present");
    CHECK(p11_loader_gate_admit(0, 1) == 0, "admit_slot0");
    CHECK(p11_loader_gate_admit(1, 1) == 0, "admit_slot1");
    CHECK(p11_loader_gate_admit(2, 1) == 0, "admit_slot2");
    CHECK(gate_ctl.admitted == 3, "arms_counted");
    CHECK(gate_ctl.retained == 3, "retained_tracks_live");
    CHECK(gate_ctl.retained_peak == 3, "peak_tracks_max");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 0), 0) == 0, "retire_slot0");
    CHECK(gate_ctl.retired == 1, "retired_counted");
    CHECK(gate_ctl.retained == 3, "retained_tracks_retire");
    CHECK(gate_ctl.retained_peak == 3, "peak_survives_retire");
    gate_rows[0].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(1, 0)) == 0, "ack_slot0");
    CHECK(gate_ctl.reclaims == 1, "reclaims_counted");
    CHECK(gate_rows[0].state == LOADER_GATE_EMPTY, "row_emptied");
    CHECK(p11_loader_gate_admit(0, 2) == 0, "successor_admits");
    CHECK(gate_ctl.retained == 3, "retained_tracks_readmit");
    CHECK(gate_ctl.retained_peak == 3, "peak_survives_cycles");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 1), 1) == 0, "retire_slot1");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 2), 6) == 0, "retire_slot2");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(2, 0), 0) == 0, "retire_slot0_gen2");
    CHECK(gate_ctl.retired == 4, "retired_counts_all");
    CHECK(gate_ctl.retained == 3, "retained_charges_unacked");
    gate_rows[0].acked = 1;
    gate_rows[1].acked = 1;
    gate_rows[2].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(2, 0)) == 0, "ack_slot0_gen2");
    CHECK(p11_loader_gate_ack(TOKEN(1, 1)) == 0, "ack_slot1");
    CHECK(p11_loader_gate_ack(TOKEN(1, 2)) == 0, "ack_slot2");
    CHECK(gate_ctl.reclaims == 4, "reclaims_count_all");
    CHECK(gate_ctl.retained == 0, "retained_drains");
    CHECK(gate_ctl.retained_peak == 3, "peak_never_falls");
    return 0;
}

/* Every counting cell saturates at U64_MAX and never wraps; the
 * retained gauge floors at zero on a caller-fault retire. */
static int counter_saturation(const char *scenario)
{
    gate_reset();
    CHECK(&p11_loader_gate_ack, "ack_present");
    gate_ctl.admitted = ~0ULL - 1;
    CHECK(p11_loader_gate_admit(0, 1) == 0, "admit_at_ceiling");
    CHECK(gate_ctl.admitted == ~0ULL, "admitted_saturates");
    CHECK(p11_loader_gate_admit(1, 1) == 0, "admit_past_ceiling");
    CHECK(gate_ctl.admitted == ~0ULL, "admitted_never_wraps");
    gate_ctl.refusals = ~0ULL - 1;
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_lookup(TOKEN(9, 9)) == -1, "refuse_at_ceiling");
    CHECK(gate_ctl.refusals == ~0ULL, "refusals_saturate");
    CHECK(p11_loader_gate_lookup(TOKEN(9, 9)) == -1, "refuse_past_ceiling");
    CHECK(gate_ctl.refusals == ~0ULL, "refusals_never_wrap");
    gate_ctl.retired = ~0ULL - 1;
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 0), 0) == 0, "retire_at_ceiling");
    CHECK(gate_ctl.retired == ~0ULL, "retired_saturates");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 1), 0) == 0, "retire_past_ceiling");
    CHECK(gate_ctl.retired == ~0ULL, "retired_never_wraps");
    gate_ctl.reclaims = ~0ULL - 1;
    gate_rows[0].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(1, 0)) == 0, "ack_at_ceiling");
    CHECK(gate_ctl.reclaims == ~0ULL, "reclaims_saturate");
    gate_rows[1].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(1, 1)) == 0, "ack_past_ceiling");
    CHECK(gate_ctl.reclaims == ~0ULL, "reclaims_never_wrap");
    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero_again");
    gate_rows[5].state = LOADER_GATE_ARMED;
    gate_rows[5].generation = 1;
    gate_rows[5].disposition = LOADER_GATE_DISP_NONE;
    CHECK(gate_ctl.retained == 0, "retained_zero_before_fault");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 5), 0) == 0, "fault_retire_zero");
    CHECK(gate_rows[5].state == LOADER_GATE_RETIRED, "fault_row_retired");
    CHECK(gate_ctl.retained == 0, "retained_floor_holds");
    return 0;
}

/* A retired row refuses until the native acknowledgement consumes the
 * T-L3 flag; exactly one successor generation admits after. Ack-pending
 * answers the third -2 (never counted) at any cutover state, while
 * wrong-state, wrong-generation and corrupted rows refuse counted. */
static int native_ack(const char *scenario)
{
    u64 row_gen = 0;
    gate_reset();
    CHECK(&p11_loader_gate_ack, "ack_present");
    CHECK(&p11_loader_gate_row_generation, "row_gen_present");
    CHECK(&p11_loader_gate_cutover_latched, "latch_present");
    CHECK(p11_loader_gate_cutover_latched() == 0, "latch_reads_unlatched");
    CHECK(p11_loader_gate_admit(4, 1) == 0, "admit_slot4");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 4), 0) == 0, "retire_slot4");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 4)) == -2, "retired_lookup_refuses_pre_cutover");
    CHECK(p11_loader_gate_admit(4, 2) == -2, "readmit_refuses_pre_ack");
    CHECK(gate_ctl.refusals == 0, "retired_refuses_until_ack");
    CHECK(p11_loader_gate_ack(TOKEN(1, 4)) == -2, "ack_pending_pre_cutover");
    CHECK(gate_ctl.refusals == 0, "ack_pending_untracked");
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_ack(TOKEN(1, 4)) == -2, "ack_pending_post_cutover");
    CHECK(gate_ctl.refusals == 0, "ack_pending_uncounted_post_cutover");
    gate_rows[4].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(1, 4)) == 0, "ack_empties_exact_row");
    CHECK(gate_rows[4].state == LOADER_GATE_EMPTY, "row_empty");
    CHECK(gate_rows[4].generation == 0, "generation_cleared");
    CHECK(gate_rows[4].disposition == LOADER_GATE_DISP_NONE, "disposition_cleared");
    CHECK(gate_rows[4].acked == 0, "flag_consumed");
    CHECK(gate_ctl.reclaims == 1, "reclaim_counted");
    CHECK(p11_loader_gate_admit(4, 2) == 0, "successor_admits_once");
    CHECK(p11_loader_gate_row_generation(4, &row_gen) == 0, "row_gen_successor");
    CHECK(row_gen == 2, "row_gen_value");
    CHECK(p11_loader_gate_row_generation(6, &row_gen) == -1, "row_gen_empty_refuses");
    CHECK(p11_loader_gate_cutover_latched() == 1, "latch_reads_latched");
    CHECK(p11_loader_gate_admit(4, 3) == -1, "double_admit_refuses");
    CHECK(gate_ctl.refusals == 1, "double_admit_counted");
    CHECK(p11_loader_gate_admit(5, 1) == 0, "admit_slot5");
    gate_rows[5].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(1, 5)) == -1, "armed_ack_refuses_counted");
    CHECK(gate_rows[5].state == LOADER_GATE_ARMED, "armed_row_untouched");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 5), 0) == 0, "retire_slot5");
    CHECK(p11_loader_gate_ack(TOKEN(2, 5)) == -1, "gen_mismatch_refuses");
    CHECK(gate_rows[5].state == LOADER_GATE_RETIRED, "retired_row_untouched");
    gate_rows[5].disposition = LOADER_GATE_DISP_NONE;
    CHECK(p11_loader_gate_ack(TOKEN(1, 5)) == -1, "corrupt_disp_refuses");
    CHECK(gate_ctl.refusals == 4, "ack_refusals_counted");
    gate_ctl.limit = 0;
    CHECK(p11_loader_gate_ack(TOKEN(1, 5)) == -1, "bad_control_ack_refuses");
    CHECK(gate_rows[5].state == LOADER_GATE_RETIRED, "corrupt_row_untouched");
    CHECK(p11_loader_gate_row_generation(5, &row_gen) == -1, "row_gen_bad_control");
    CHECK(p11_loader_gate_cutover_latched() == -1, "latch_bad_control");
    return 0;
}

/* Probe-hit transaction: fresh admission, peer resolve, foreign
 * refusal, pending reuse and armed successor reuse through the exact
 * producer call sequence. Healthy and pending hits keep refusals at
 * zero; only genuine rejections count, exactly once. */
static int hit_transaction(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_hit(5, 1) == 5, "hit_admits_fresh");
    CHECK(gate_rows[5].state == LOADER_GATE_ARMED, "hit_row_armed");
    CHECK(gate_ctl.admitted == 1, "hit_admitted_once");
    CHECK(gate_ctl.refusals == 0, "hit_fresh_no_refusals");
    CHECK(p11_loader_gate_hit(5, 1) == 5, "hit_peer_resolves");
    CHECK(gate_ctl.admitted == 1, "hit_peer_uncounted");
    CHECK(p11_loader_gate_hit(5, 9) == -1, "hit_foreign_counted");
    CHECK(gate_ctl.refusals == 1, "hit_one_refusal");
    CHECK(gate_rows[5].generation == 1, "hit_row_undisturbed");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 5), 0) == 0, "hit_retire_zero");
    CHECK(p11_loader_gate_hit(5, 1) == -2, "hit_pending_uncounted");
    CHECK(gate_ctl.refusals == 1, "hit_pending_no_count");
    gate_rows[5].acked = 1;
    CHECK(p11_loader_gate_hit(5, 2) == 5, "hit_reuse_admits_successor");
    CHECK(gate_rows[5].state == LOADER_GATE_ARMED, "hit_successor_armed");
    CHECK(gate_rows[5].generation == 2, "hit_successor_gen2");
    CHECK(gate_ctl.admitted == 2, "hit_two_admitted");
    CHECK(gate_ctl.reclaims == 1, "hit_one_reclaim");
    CHECK(gate_ctl.refusals == 1, "hit_reuse_no_new_refusal");
    CHECK(p11_loader_gate_hit(300, 1) == -1, "hit_bad_slot_counted");
    CHECK(p11_loader_gate_hit(6, 0) == -1, "hit_gen0_counted");
    CHECK(gate_ctl.refusals == 3, "hit_refusals_exact");
    gate_reset();
    CHECK(p11_loader_gate_hit(7, 1) == 7, "hit_pre_cutover_admits");
    CHECK(p11_loader_gate_hit(7, 9) == -2, "hit_pre_cutover_untracked");
    CHECK(gate_ctl.refusals == 0, "hit_pre_cutover_uncounted");
    return 0;
}

/* Stale floor: a retired generation never resurrects on its emptied
 * row, the successor admits over the floor, and the u32 wrap admits
 * generation 1 over a max floor while the old max refuses. */
static int hit_stale_floor(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_hit(3, 5) == 3, "floor_admit_gen5");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(5, 3), 0) == 0, "floor_retire");
    gate_rows[3].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(5, 3)) == 0, "floor_ack");
    CHECK(gate_rows[3].state == LOADER_GATE_EMPTY, "floor_empty");
    CHECK(p11_loader_gate_hit(3, 5) == -1, "stale_refused_after_reclaim");
    CHECK(gate_rows[3].state == LOADER_GATE_EMPTY, "stale_row_stays_empty");
    CHECK(p11_loader_gate_hit(3, 6) == 3, "successor_admits_over_floor");
    CHECK(gate_ctl.refusals == 1, "floor_one_refusal");
    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero_again");
    gate_rows[9].last_gen = 0xffffffffU;
    CHECK(p11_loader_gate_hit(9, 1) == 9, "wrap_gen1_admits");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 9), 0) == 0, "wrap_retire");
    gate_rows[9].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(1, 9)) == 0, "wrap_ack");
    CHECK(p11_loader_gate_hit(9, 0xffffffffU) == -1, "wrap_old_refuses");
    CHECK(gate_rows[9].state == LOADER_GATE_EMPTY, "wrap_row_stays_empty");
    return 0;
}

/* Malformed control fails closed without touching rows. */
static int bad_control(const char *scenario)
{
    gate_reset();
    gate_ctl.limit = 0;
    CHECK(p11_loader_gate_admit(2, 1) == -1, "bad_limit_admit_refuses");
    CHECK(p11_loader_gate_lookup(TOKEN(1, 2)) == -1, "bad_limit_lookup_refuses");
    CHECK(p11_loader_gate_cutover() == -1, "bad_limit_cutover_refuses");
    CHECK(gate_rows[2].state == LOADER_GATE_EMPTY, "row_untouched");
    gate_ctl.limit = LOADER_GATE_SLOTS;
    ctl_present = 0;
    CHECK(p11_loader_gate_lookup(TOKEN(1, 2)) == -1, "missing_ctl_refuses");
    CHECK(p11_loader_gate_cutover() == -1, "missing_ctl_cutover_refuses");
    return 0;
}

/* Thread plumbing: each thread records its own verdict slot (joined
 * before any read, so no atomics); barrier starts make the races real
 * while final counts stay deterministic under exactly-once. */
struct hit_thread_arg {
    u32 slot;
    u64 gen;
    long result;
    pthread_barrier_t *barrier;
};

static void *hit_thread(void *arg_raw)
{
    struct hit_thread_arg *arg = arg_raw;
    (void)pthread_barrier_wait(arg->barrier);
    arg->result = p11_loader_gate_hit(arg->slot, arg->gen);
    return 0;
}

/* Eight threads race one token: all resolve, exactly one admission
 * counts, refusals stay zero, the gauge counts once. */
static int hit_concurrent_same_token(const char *scenario)
{
    enum { N = 8 };
    pthread_barrier_t barrier;
    pthread_t threads[N];
    struct hit_thread_arg args[N];
    int i;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(pthread_barrier_init(&barrier, 0, N) == 0, "barrier_init");
    for (i = 0; i < N; i++) {
        args[i].slot = 11;
        args[i].gen = 1;
        args[i].result = -99;
        args[i].barrier = &barrier;
        CHECK(pthread_create(&threads[i], 0, hit_thread, &args[i]) == 0,
              "thread_spawn");
    }
    for (i = 0; i < N; i++)
        CHECK(pthread_join(threads[i], 0) == 0, "thread_join");
    CHECK(pthread_barrier_destroy(&barrier) == 0, "barrier_destroy");
    for (i = 0; i < N; i++)
        CHECK(args[i].result == 11, "same_token_all_resolve");
    CHECK(gate_ctl.admitted == 1, "same_token_admitted_once");
    CHECK(gate_ctl.refusals == 0, "same_token_no_refusals");
    CHECK(gate_ctl.retained == 1 && gate_ctl.retained_peak == 1,
          "same_token_gauge_once");
    CHECK(gate_ctl.update_losses == 0, "same_token_no_loss");
    return 0;
}

/* Four threads race the successor generation of a retired-and-armed
 * row: all resolve, one reclaim and one admission count, refusals
 * stay zero. */
static int hit_successor_race(const char *scenario)
{
    enum { N = 4 };
    pthread_barrier_t barrier;
    pthread_t threads[N];
    struct hit_thread_arg args[N];
    int i;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_hit(13, 1) == 13, "successor_seed_admits");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 13), 0) == 0,
          "successor_seed_retires");
    gate_rows[13].acked = 1;
    CHECK(pthread_barrier_init(&barrier, 0, N) == 0, "barrier_init");
    for (i = 0; i < N; i++) {
        args[i].slot = 13;
        args[i].gen = 2;
        args[i].result = -99;
        args[i].barrier = &barrier;
        CHECK(pthread_create(&threads[i], 0, hit_thread, &args[i]) == 0,
              "thread_spawn");
    }
    for (i = 0; i < N; i++)
        CHECK(pthread_join(threads[i], 0) == 0, "thread_join");
    CHECK(pthread_barrier_destroy(&barrier) == 0, "barrier_destroy");
    for (i = 0; i < N; i++)
        CHECK(args[i].result == 13, "successor_all_resolve");
    CHECK(gate_ctl.admitted == 2, "successor_admitted_once");
    CHECK(gate_ctl.reclaims == 1, "successor_reclaim_once");
    CHECK(gate_ctl.refusals == 0, "successor_no_refusals");
    CHECK(gate_ctl.retained == 1, "successor_gauge_one");
    CHECK(gate_ctl.update_losses == 0, "successor_no_loss");
    return 0;
}

/* Ordered admission/reclaim crossings: the flag orders the pair, so the
 * peak must equal the true maximum live count in both orders. */
static volatile int interleave_go;

struct admit_signal_arg {
    u32 slot;
    u64 gen;
    long result;
};

struct wait_ack_arg {
    u64 cookie;
    long result;
};

static void *admit_then_signal(void *arg_raw)
{
    struct admit_signal_arg *arg = arg_raw;
    arg->result = p11_loader_gate_hit(arg->slot, arg->gen);
    interleave_go = 1;
    return 0;
}

static void *wait_then_ack(void *arg_raw)
{
    struct wait_ack_arg *arg = arg_raw;
    while (!interleave_go)
        ;
    arg->result = p11_loader_gate_ack(arg->cookie);
    return 0;
}

struct ack_signal_arg {
    u64 cookie;
    long result;
};

struct wait_admit_arg {
    u32 slot;
    u64 gen;
    long result;
};

static void *ack_then_signal(void *arg_raw)
{
    struct ack_signal_arg *arg = arg_raw;
    arg->result = p11_loader_gate_ack(arg->cookie);
    interleave_go = 1;
    return 0;
}

static void *wait_then_admit(void *arg_raw)
{
    struct wait_admit_arg *arg = arg_raw;
    while (!interleave_go)
        ;
    arg->result = p11_loader_gate_hit(arg->slot, arg->gen);
    return 0;
}

static int admission_reclaim_interleave(const char *scenario)
{
    pthread_t first, second;
    struct admit_signal_arg admit_arg;
    struct wait_ack_arg ack_arg;
    struct ack_signal_arg ack_arg2;
    struct wait_admit_arg admit_arg2;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_hit(50, 1) == 50, "interleave_setup_admits");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 50), 0) == 0,
          "interleave_setup_retires");
    gate_rows[50].acked = 1;
    CHECK(gate_ctl.retained == 1 && gate_ctl.retained_peak == 1,
          "interleave_setup_gauge_one");
    interleave_go = 0;
    admit_arg.slot = 51;
    admit_arg.gen = 1;
    admit_arg.result = -99;
    ack_arg.cookie = TOKEN(1, 50);
    ack_arg.result = -99;
    CHECK(pthread_create(&first, 0, admit_then_signal, &admit_arg) == 0,
          "thread_spawn");
    CHECK(pthread_create(&second, 0, wait_then_ack, &ack_arg) == 0,
          "thread_spawn");
    CHECK(pthread_join(first, 0) == 0, "thread_join");
    CHECK(pthread_join(second, 0) == 0, "thread_join");
    CHECK(admit_arg.result == 51, "ordered_admit_first_resolves");
    CHECK(ack_arg.result == 0, "ordered_ack_second_empties");
    CHECK(gate_ctl.retained == 1 && gate_ctl.retained_peak == 2,
          "ordered_admit_then_ack_peak_two");
    CHECK(gate_ctl.admitted == 2 && gate_ctl.reclaims == 1 &&
              gate_ctl.refusals == 0 && gate_ctl.update_losses == 0,
          "ordered_forward_counts_exact");

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero_again");
    CHECK(p11_loader_gate_hit(52, 1) == 52, "interleave_setup_admits_again");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 52), 0) == 0,
          "interleave_setup_retires_again");
    gate_rows[52].acked = 1;
    interleave_go = 0;
    ack_arg2.cookie = TOKEN(1, 52);
    ack_arg2.result = -99;
    admit_arg2.slot = 53;
    admit_arg2.gen = 1;
    admit_arg2.result = -99;
    CHECK(pthread_create(&first, 0, ack_then_signal, &ack_arg2) == 0,
          "thread_spawn");
    CHECK(pthread_create(&second, 0, wait_then_admit, &admit_arg2) == 0,
          "thread_spawn");
    CHECK(pthread_join(first, 0) == 0, "thread_join");
    CHECK(pthread_join(second, 0) == 0, "thread_join");
    CHECK(ack_arg2.result == 0, "ordered_ack_first_empties");
    CHECK(admit_arg2.result == 53, "ordered_admit_second_resolves");
    CHECK(gate_ctl.retained == 1 && gate_ctl.retained_peak == 1,
          "ordered_ack_then_admit_peak_one");
    return 0;
}

struct bulk_arg {
    u32 base;
    long failed;
};

static void *bulk_admit(void *arg_raw)
{
    struct bulk_arg *arg = arg_raw;
    u32 s;
    arg->failed = 0;
    for (s = 0; s < 4; s++) {
        if (p11_loader_gate_hit(arg->base + s, 1) != (long)(arg->base + s))
            arg->failed = 1;
    }
    return 0;
}

static void *bulk_retire(void *arg_raw)
{
    struct bulk_arg *arg = arg_raw;
    u32 s;
    arg->failed = 0;
    for (s = 0; s < 4; s++) {
        if (p11_loader_gate_note_producer_end(TOKEN(1, arg->base + s), 0))
            arg->failed = 1;
    }
    return 0;
}

static void *bulk_ack(void *arg_raw)
{
    struct bulk_arg *arg = arg_raw;
    u32 s;
    arg->failed = 0;
    for (s = 0; s < 4; s++) {
        if (p11_loader_gate_ack(TOKEN(1, arg->base + s)))
            arg->failed = 1;
    }
    return 0;
}

/* Sixteen threads drive 64 slots through admit/retire/ack phases (join
 * separated): every count settles exactly with no update loss, and
 * retired rows stay charged until their acknowledged reclaim. */
static int gauge_contention(const char *scenario)
{
    enum { N = 16 };
    pthread_t threads[N];
    struct bulk_arg args[N];
    int i;
    u32 s;

    int join_failed = 0;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    for (i = 0; i < N; i++) {
        args[i].base = (u32)(4 * i);
        args[i].failed = 0;
        CHECK(pthread_create(&threads[i], 0, bulk_admit, &args[i]) == 0,
              "thread_spawn");
    }
    /* Join every thread before any failing check: an early return with
     * live joinable threads races process teardown and segfaults. */
    for (i = 0; i < N; i++) {
        if (pthread_join(threads[i], 0))
            join_failed = 1;
    }
    CHECK(!join_failed, "thread_join");
    for (i = 0; i < N; i++)
        CHECK(!args[i].failed, "contended_admit_all_resolve");
    CHECK(gate_ctl.admitted == 64, "contended_admitted_exact");
    CHECK(gate_ctl.retained == 64 && gate_ctl.retained_peak == 64,
          "contended_peak_exact");
    CHECK(gate_ctl.update_losses == 0, "contended_no_loss");
    for (i = 0; i < N; i++) {
        args[i].failed = 0;
        CHECK(pthread_create(&threads[i], 0, bulk_retire, &args[i]) == 0,
              "thread_spawn");
    }
    join_failed = 0;
    for (i = 0; i < N; i++) {
        if (pthread_join(threads[i], 0))
            join_failed = 1;
    }
    CHECK(!join_failed, "thread_join");
    for (i = 0; i < N; i++)
        CHECK(!args[i].failed, "contended_retire_all_zero");
    CHECK(gate_ctl.retired == 64, "contended_retired_exact");
    CHECK(gate_ctl.retained == 64, "retired_stays_charged");
    for (s = 0; s < 64; s++)
        gate_rows[s].acked = 1;
    for (i = 0; i < N; i++) {
        args[i].failed = 0;
        CHECK(pthread_create(&threads[i], 0, bulk_ack, &args[i]) == 0,
              "thread_spawn");
    }
    join_failed = 0;
    for (i = 0; i < N; i++) {
        if (pthread_join(threads[i], 0))
            join_failed = 1;
    }
    CHECK(!join_failed, "thread_join");
    for (i = 0; i < N; i++)
        CHECK(!args[i].failed, "contended_ack_all_zero");
    CHECK(gate_ctl.reclaims == 64, "contended_reclaim_exact");
    CHECK(gate_ctl.retained == 0, "contended_retained_drains");
    CHECK(gate_ctl.retained_peak == 64, "contended_peak_never_falls");
    CHECK(gate_ctl.update_losses == 0, "contended_no_loss_at_end");
    return 0;
}

/* Saturation under contention: eight threads admit at the admitted
 * ceiling and refuse at the refusals ceiling; operations still take
 * their verdicts while both cells stop exactly at the maximum. */
static int saturation_contention(const char *scenario)
{
    enum { N = 8 };
    pthread_barrier_t barrier;
    pthread_t threads[N];
    struct hit_thread_arg args[N];
    int i;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    gate_ctl.admitted = ~0ULL - 1;
    CHECK(pthread_barrier_init(&barrier, 0, N) == 0, "barrier_init");
    for (i = 0; i < N; i++) {
        args[i].slot = (u32)(30 + i);
        args[i].gen = 1;
        args[i].result = -99;
        args[i].barrier = &barrier;
        CHECK(pthread_create(&threads[i], 0, hit_thread, &args[i]) == 0,
              "thread_spawn");
    }
    for (i = 0; i < N; i++)
        CHECK(pthread_join(threads[i], 0) == 0, "thread_join");
    CHECK(pthread_barrier_destroy(&barrier) == 0, "barrier_destroy");
    for (i = 0; i < N; i++)
        CHECK(args[i].result == 30 + i, "saturated_admit_succeeds");
    CHECK(gate_ctl.admitted == ~0ULL, "admitted_exact_max");
    gate_ctl.refusals = ~0ULL - 1;
    CHECK(pthread_barrier_init(&barrier, 0, N) == 0, "barrier_init");
    for (i = 0; i < N; i++) {
        args[i].slot = (u32)(30 + i);
        args[i].gen = 9;
        args[i].result = -99;
        args[i].barrier = &barrier;
        CHECK(pthread_create(&threads[i], 0, hit_thread, &args[i]) == 0,
              "thread_spawn");
    }
    for (i = 0; i < N; i++)
        CHECK(pthread_join(threads[i], 0) == 0, "thread_join");
    CHECK(pthread_barrier_destroy(&barrier) == 0, "barrier_destroy");
    for (i = 0; i < N; i++)
        CHECK(args[i].result == -1, "saturated_refuse_verdicts");
    CHECK(gate_ctl.refusals == ~0ULL, "refusals_exact_max");
    CHECK(gate_ctl.update_losses == 0, "saturation_no_loss");
    return 0;
}

/* Delayed acknowledgement: nine retired-unacknowledged rows stay
 * charged with zero live rows, reuse waits uncounted, and the
 * acknowledged reclaims drain the gauge exactly. */
static int delayed_ack_retained(const char *scenario)
{
    u32 s;
    u32 armed = 0;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    for (s = 0; s < 9; s++) {
        CHECK(p11_loader_gate_admit(s, 1) == 0, "delayed_setup_admits");
        CHECK(p11_loader_gate_note_producer_end(TOKEN(1, s), 0) == 0,
              "delayed_setup_retires");
    }
    CHECK(gate_ctl.retained == 9, "retired_nine_charged");
    CHECK(gate_ctl.retained_peak == 9, "peak_nine_despite_zero_armed");
    for (s = 0; s < 9; s++) {
        if (gate_rows[s].state == LOADER_GATE_ARMED)
            armed++;
    }
    CHECK(armed == 0, "zero_armed_while_charged");
    for (s = 0; s < 9; s++)
        CHECK(p11_loader_gate_hit(s, 2) == -2, "reuse_pending_uncounted");
    CHECK(gate_ctl.refusals == 0, "delayed_no_refusals");
    for (s = 0; s < 9; s++) {
        gate_rows[s].acked = 1;
        CHECK(p11_loader_gate_ack(TOKEN(1, s)) == 0, "delayed_ack_drains");
    }
    CHECK(gate_ctl.retained == 0, "delayed_retained_drains");
    CHECK(gate_ctl.reclaims == 9, "delayed_reclaims_nine");
    CHECK(gate_ctl.retained_peak == 9, "delayed_peak_never_falls");
    return 0;
}

/* Quarantine: nine retired-never-armed rows stay charged beside nine
 * live rows; quarantined reuse waits forever while fresh traffic
 * resolves, all without refusals. */
static int quarantine_retained(const char *scenario)
{
    u32 s;
    u32 armed = 0;

    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    for (s = 10; s < 19; s++) {
        CHECK(p11_loader_gate_admit(s, 1) == 0, "quarantine_setup_admits");
        CHECK(p11_loader_gate_note_producer_end(TOKEN(1, s), 0) == 0,
              "quarantine_setup_retires");
    }
    CHECK(gate_ctl.retained == 9, "quarantine_nine_charged");
    for (s = 20; s < 29; s++)
        CHECK(p11_loader_gate_admit(s, 1) == 0, "quarantine_fresh_admits");
    CHECK(gate_ctl.retained == 18, "eighteen_retained_nine_armed");
    for (s = 10; s < 29; s++) {
        if (gate_rows[s].state == LOADER_GATE_ARMED)
            armed++;
    }
    CHECK(armed == 9, "nine_armed_out_of_range");
    for (s = 10; s < 19; s++)
        CHECK(p11_loader_gate_hit(s, 2) == -2, "quarantine_pending_forever");
    for (s = 20; s < 29; s++)
        CHECK(p11_loader_gate_hit(s, 1) == (long)s, "fresh_unaffected");
    CHECK(gate_ctl.refusals == 0, "quarantine_no_refusals");
    return 0;
}

#ifdef GATE_HOST_CAS_HOOK
/* Exhaustion twin: with every saturating-counter CAS forced to fail,
 * settled updates still land through the fallback, and every
 * unsettled update reports through update_losses instead of wrapping
 * or vanishing. */
static int cas_exhaustion_counts(const char *scenario)
{
    gate_reset();
    CHECK(p11_loader_gate_cutover() == 0, "cutover_zero");
    CHECK(p11_loader_gate_admit(40, 1) == 0, "exhaust_setup_admits");
    gate_cas_fail_all = 1;
    CHECK(p11_loader_gate_hit(40, 9) == -1, "exhaust_foreign_refuses");
    CHECK(gate_ctl.refusals == 1, "fallback_settles_count");
    CHECK(gate_ctl.update_losses == 0, "fallback_no_loss");
    gate_ctl.refusals = ~0ULL - 1;
    CHECK(p11_loader_gate_hit(40, 9) == -1, "exhaust_refuses_again");
    CHECK(gate_ctl.refusals == ~0ULL - 1, "skip_holds_ceiling");
    CHECK(gate_ctl.update_losses == 1, "skip_reports_loss");
    CHECK(p11_loader_gate_hit(41, 1) == 41, "exhaust_admit_succeeds");
    CHECK(gate_ctl.retained == 2, "exhaust_gauge_counts");
    CHECK(gate_ctl.retained_peak == 1, "exhaust_peak_holds");
    CHECK(gate_ctl.update_losses == 2, "peak_loss_reported");
    CHECK(p11_loader_gate_note_producer_end(TOKEN(1, 40), 0) == 0,
          "exhaust_retire");
    gate_rows[40].acked = 1;
    CHECK(p11_loader_gate_ack(TOKEN(1, 40)) == 0, "exhaust_ack_empties");
    CHECK(gate_rows[40].state == LOADER_GATE_EMPTY, "exhaust_row_empty");
    CHECK(gate_ctl.retained == 2, "exhaust_drop_overcounts");
    CHECK(gate_ctl.update_losses == 3, "drop_loss_reported");
    CHECK(gate_ctl.reclaims == 1, "exhaust_reclaim_counted");
    return 0;
}
#endif

int main(int argc, char **argv)
{
    static const struct {
        const char *name;
        int (*run)(const char *scenario);
    } scenarios[] = {
        { "admit-lookup-healthy", admit_lookup_healthy },
        { "refuse-twins", refuse_twins },
        { "old-format-after-cutover", old_format_after_cutover },
        { "old-format-twin-requires-quiescence", old_format_twin_requires_quiescence },
        { "old-absent-gen2-resolves", old_absent_gen2_resolves },
        { "old-delta1-gen3-resolves", old_delta1_gen3_resolves },
        { "retire-no-recycle", retire_no_recycle },
        { "reason-map", reason_map },
        { "admit-without-producer-keeps-debt", admit_without_producer_keeps_debt },
        { "cutover-latch", cutover_latch },
        { "bad-control", bad_control },
        { "l4b-counters", l4b_counters },
        { "counter-saturation", counter_saturation },
        { "native-ack", native_ack },
        { "hit-transaction", hit_transaction },
        { "hit-stale-floor", hit_stale_floor },
        { "hit-concurrent-same-token", hit_concurrent_same_token },
        { "hit-successor-race", hit_successor_race },
        { "admission-reclaim-interleave", admission_reclaim_interleave },
        { "gauge-contention", gauge_contention },
        { "saturation-contention", saturation_contention },
        { "delayed-ack-retained", delayed_ack_retained },
        { "quarantine-retained", quarantine_retained },
#ifdef GATE_HOST_CAS_HOOK
        { "cas-exhaustion-counts", cas_exhaustion_counts },
#endif
    };
    unsigned i;

    loader_gate_map_lookup = gate_lookup;
    if (argc != 2)
        return 2;
    for (i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
        if (!strcmp(argv[1], scenarios[i].name)) {
            if (scenarios[i].run(argv[1]))
                return 1;
            printf("SCENARIO %s PASS\n", argv[1]);
            return 0;
        }
    }
    return 2;
}
