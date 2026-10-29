/* SPDX-License-Identifier: GPL-2.0-only */
/* T-L2/T-L2c host harness: executes the real loader_gate.c with stub map
 * storage and drives producer-shaped admit/lookup/retire/cutover scenarios.
 * Only the map helpers are stubbed; there is no second gate algorithm. */
#include "loader_gate.h"
#include "loader_gate.c"
#include <stdio.h>
#include <string.h>

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
