//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! T-L2/T-L2c native seam: the real `crates/ebpf/native/loader_gate.c` is
//! compiled for host through `loader_gate_harness.c` with stub map storage
//! and driven through admit/lookup/retire/cutover scenarios, and the real
//! `image_identity.c` ticket-query extends are driven through
//! `tests/fixtures/image-identity/ticket_query_tests.c`. Kernel facts
//! (verifier, load, attach) are proven in later stages, not here.
//! Unprivileged and permanent.

/// Shared by path with the build script and other harnesses, which use the
/// helpers this file does not call; the allowance covers only that module.
#[path = "../build_support/clang_resolve.rs"]
#[allow(dead_code)]
mod clang_resolve;

use std::path::{Path, PathBuf};

/// Compile one real native unit for host through its harness. Returns the
/// work dir (for cleanup) and the scenario binary.
fn compile_harness(source_file: &str, tag: &str, scenario: &str) -> (PathBuf, PathBuf) {
    let native = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/ebpf/native");
    let source = if source_file.contains('/') {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(source_file)
    } else {
        native.join(source_file)
    };
    assert!(
        source.is_file(),
        "harness source {} must exist",
        source.display()
    );
    let work = std::env::temp_dir().join(format!(
        "p11scope-loader-gate-{tag}-{scenario}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&work).expect("harness work dir");
    let binary = work.join("harness");
    let cwd = std::env::current_dir().expect("cwd");
    let compiler = clang_resolve::resolve_executable_in(
        "clang-18",
        &std::env::var_os("PATH").unwrap_or_default(),
        &cwd,
    )
    .expect("host harness needs an executable clang-18 on PATH");
    let mut command = std::process::Command::new(&compiler);
    command
        .args([
            "-O1",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wno-unknown-attributes",
            "-pthread",
        ])
        .arg("-I")
        .arg(&native)
        .arg(&source)
        .arg("-o")
        .arg(&binary);
    if tag == "owner-gate" || tag == "tickets" || tag == "tickets-hook" {
        command.arg("-DP11SCOPE_LOADER_GATE");
    }
    if tag == "gate-hook" {
        command.arg("-DGATE_HOST_CAS_HOOK");
    }
    if tag == "tickets-hook" {
        command.arg("-DIMAGE_HOST_CAS_HOOK");
    }
    let compile = command.output().expect("spawn host cc for the harness");
    assert!(
        compile.status.success(),
        "harness must compile -Werror-clean: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    (work, binary)
}

/// Run one harness scenario: the binary exits nonzero on any failed check,
/// and the ASSERT lines below pin the evidence shape so a vacuous PASS
/// cannot slip through.
fn run_scenario(binary: &Path, scenario: &str, asserts: &[&str]) {
    let run = std::process::Command::new(binary)
        .arg(scenario)
        .output()
        .expect("run harness scenario");
    let stdout = String::from_utf8_lossy(&run.stdout).into_owned();
    assert!(
        run.status.success(),
        "harness scenario {scenario} must pass:\n{stdout}\n{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        stdout.contains(&format!("SCENARIO {scenario} PASS")),
        "scenario {scenario} must print PASS:\n{stdout}"
    );
    for needle in asserts {
        assert!(
            stdout.contains(needle),
            "scenario {scenario} must show {needle}:\n{stdout}"
        );
    }
}

fn drive_gate(scenario: &str, asserts: &[&str]) {
    let (work, binary) = compile_harness("loader_gate_harness.c", "gate", scenario);
    run_scenario(&binary, scenario, asserts);
    let _ = std::fs::remove_dir_all(&work);
}

fn drive_gate_hook(scenario: &str, asserts: &[&str]) {
    let (work, binary) = compile_harness("loader_gate_harness.c", "gate-hook", scenario);
    run_scenario(&binary, scenario, asserts);
    let _ = std::fs::remove_dir_all(&work);
}

fn drive_tickets(scenario: &str, asserts: &[&str]) {
    let (work, binary) = compile_harness(
        "tests/fixtures/image-identity/ticket_query_tests.c",
        "tickets",
        scenario,
    );
    run_scenario(&binary, scenario, asserts);
    let _ = std::fs::remove_dir_all(&work);
}

fn drive_tickets_hook(scenario: &str, asserts: &[&str]) {
    let (work, binary) = compile_harness(
        "tests/fixtures/image-identity/ticket_query_tests.c",
        "tickets-hook",
        scenario,
    );
    run_scenario(&binary, scenario, asserts);
    let _ = std::fs::remove_dir_all(&work);
}

/// T-L2c healthy twin: a generation-1 adapter token admits and resolves.
#[test]
fn loader_gate_harness_admit_lookup_healthy() {
    drive_gate(
        "admit-lookup-healthy",
        &[
            "ASSERT admit_slot5_gen1_zero",
            "ASSERT lookup_token_resolves_slot5",
            "ASSERT row5_armed",
            "ASSERT admitted_counted_once",
        ],
    );
}

/// T-L2c failure twins: stale, foreign, burned, malformed and oversized
/// cookies refuse closed with counted refusals.
#[test]
fn loader_gate_harness_refuse_twins() {
    drive_gate(
        "refuse-twins",
        &[
            "ASSERT burned_gen1_refuses",
            "ASSERT future_gen3_refuses",
            "ASSERT foreign_slot_refuses",
            "ASSERT zero_refuses",
            "ASSERT over_40_bits_refuses",
            "ASSERT nine_refusals_counted",
        ],
    );
}

/// Old-format cookies fail closed at lookup after the atomic cutover.
#[test]
fn loader_gate_harness_old_format_after_cutover() {
    drive_gate(
        "old-format-after-cutover",
        &[
            "ASSERT old_absent_refuses",
            "ASSERT old_delta_refuses",
            "ASSERT twin_slot_empty_refuses",
            "ASSERT four_refusals_counted",
        ],
    );
}

/// The twin hazard at the native seam: a delta-0 old-format cookie is
/// indistinguishable from its generation-1 token.
#[test]
fn loader_gate_harness_old_format_twin_requires_quiescence() {
    drive_gate(
        "old-format-twin-requires-quiescence",
        &["ASSERT twin_resolves_indistinguishable"],
    );
}

/// Every old-format absent cookie is a generation-2 twin of its case slot.
#[test]
fn loader_gate_harness_old_absent_gen2_resolves() {
    drive_gate(
        "old-absent-gen2-resolves",
        &[
            "ASSERT absent_ctx1_resolves_slot0",
            "ASSERT absent_ctx3_resolves_slot2",
            "ASSERT twins_refuse_nothing",
        ],
    );
}

/// Every old-format present cookie with 0 <= d < 2^31 is a
/// generation-2d+1 twin of its case slot.
#[test]
fn loader_gate_harness_old_delta1_gen3_resolves() {
    drive_gate(
        "old-delta1-gen3-resolves",
        &[
            "ASSERT delta1_ctx1_resolves_slot0",
            "ASSERT delta5_ctx3_resolves_slot2",
            "ASSERT twins_refuse_nothing",
        ],
    );
}

/// Every START-removal reason retires with its owned disposition; no
/// identity recycles before acknowledgement.
#[test]
fn loader_gate_harness_retire_no_recycle() {
    drive_gate(
        "retire-no-recycle",
        &[
            "ASSERT disposition_owned",
            "ASSERT retired_lookup_refuses",
            "ASSERT same_gen_no_recycle",
            "ASSERT next_gen_no_recycle",
            "ASSERT three_retired_counted",
        ],
    );
}

/// Reason mapping is exact; unknown reasons never retire a row.
#[test]
fn loader_gate_harness_reason_map() {
    drive_gate(
        "reason-map",
        &[
            "ASSERT return_maps_end",
            "ASSERT collision_maps_no_end",
            "ASSERT exec_exit_maps_abandon",
            "ASSERT reason99_maps_none",
            "ASSERT unknown_reason_refuses",
            "ASSERT row_stays_armed",
        ],
    );
}

/// Prepared-cancellation debt is preserved: an admitted row with no
/// producer stays armed and occupied.
#[test]
fn loader_gate_harness_admit_without_producer_keeps_debt() {
    drive_gate(
        "admit-without-producer-keeps-debt",
        &[
            "ASSERT armed_resolves",
            "ASSERT double_admit_untracked",
            "ASSERT row_still_armed",
            "ASSERT armed_past_cutover",
        ],
    );
}

/// The cutover is a one-way latch with strict post-cutover accounting.
#[test]
fn loader_gate_harness_cutover_latch() {
    drive_gate(
        "cutover-latch",
        &[
            "ASSERT pre_cutover_untracked",
            "ASSERT second_cutover_refuses",
            "ASSERT latch_holds",
            "ASSERT post_cutover_counted",
        ],
    );
}

/// Malformed control fails closed without touching rows.
#[test]
fn loader_gate_harness_bad_control() {
    drive_gate(
        "bad-control",
        &[
            "ASSERT bad_limit_admit_refuses",
            "ASSERT missing_ctl_refuses",
            "ASSERT row_untouched",
        ],
    );
}

/// Ticket-query healthy twin: per-task queries observe factual issuance;
/// the watermark tracks every spent ticket including burns.
#[test]
fn loader_ticket_harness_query_healthy() {
    drive_tickets(
        "ticket-query-healthy",
        &[
            "ASSERT watermark_tracks_burns",
            "ASSERT burned_ticket_never_issues",
            "ASSERT tickets_strictly_increasing",
        ],
    );
}

/// Ticket-query failure twins: malformed inputs refuse with exact
/// statuses and spend nothing.
#[test]
fn loader_ticket_harness_query_failures() {
    drive_tickets(
        "ticket-query-failures",
        &[
            "ASSERT null_inputs_bad_task",
            "ASSERT no_control_refuses_quiet",
            "ASSERT bad_config_spends_nothing_readonly",
            "ASSERT zero_cell_and_quota_exact",
        ],
    );
}

/// G17-shaped crossing: issuance reaches exactly 16,384, then refuses.
#[test]
fn loader_ticket_harness_crosses_16384() {
    drive_tickets(
        "ticket-crosses-16384",
        &[
            "ASSERT watermark_reaches_16384",
            "ASSERT next_attempt_quota",
        ],
    );
}

/// The ticket query never reads self_exec_id (no-access page proof).
#[test]
fn loader_ticket_harness_ignores_exec_id() {
    drive_tickets(
        "ticket-ignores-exec-id",
        &["ASSERT ticket_query_ignores_exec_id"],
    );
}

/// L4b loader cells: arms count admits, retained charges live and
/// retired-unacknowledged rows until the acknowledged reclaim, the peak
/// is monotonic across retire/reclaim cycles.
#[test]
fn loader_gate_harness_l4b_counters() {
    drive_gate(
        "l4b-counters",
        &[
            "ASSERT arms_counted",
            "ASSERT retained_tracks_live",
            "ASSERT peak_tracks_max",
            "ASSERT reclaims_counted",
            "ASSERT peak_never_falls",
        ],
    );
}

/// Every counting cell saturates at U64_MAX and never wraps; the
/// retained gauge floors at zero on a caller-fault retire.
#[test]
fn loader_gate_harness_counter_saturation() {
    drive_gate(
        "counter-saturation",
        &[
            "ASSERT admitted_never_wraps",
            "ASSERT refusals_never_wrap",
            "ASSERT reclaims_never_wrap",
            "ASSERT retained_floor_holds",
        ],
    );
}

/// A retired row refuses until the native acknowledgement consumes the
/// T-L3 flag; exactly one successor generation admits after.
#[test]
fn loader_gate_harness_native_ack() {
    drive_gate(
        "native-ack",
        &[
            "ASSERT retired_refuses_until_ack",
            "ASSERT ack_pending_uncounted_post_cutover",
            "ASSERT ack_empties_exact_row",
            "ASSERT successor_admits_once",
            "ASSERT row_gen_value",
            "ASSERT latch_reads_latched",
            "ASSERT ack_refusals_counted",
        ],
    );
}

/// G17-shaped cut: with B prepared, the 16,385th birth cuts to B
/// exactly once; B quota refuses honestly with counted refusals.
#[test]
fn loader_ticket_harness_bank_cut_once() {
    drive_tickets(
        "bank-cut-once",
        &[
            "ASSERT cut_flips_to_b_once",
            "ASSERT total_crosses_16384",
            "ASSERT b_quota_honest",
            "ASSERT bank_refusals_saturate",
        ],
    );
}

/// Retained routes: a pre-cut ticket still resolves from its bank
/// after the cut, and A storage is undisturbed by B traffic.
#[test]
fn loader_ticket_harness_bank_query_routes() {
    drive_tickets(
        "bank-query-routes",
        &[
            "ASSERT pre_cut_ticket_retained",
            "ASSERT post_cut_new_bank_b",
            "ASSERT a_storage_undisturbed",
        ],
    );
}

/// Probe-hit transaction through the exact producer call sequence:
/// healthy and pending hits keep refusals zero, genuine rejections
/// count exactly once.
#[test]
fn loader_gate_harness_hit_transaction() {
    drive_gate(
        "hit-transaction",
        &[
            "ASSERT hit_admits_fresh",
            "ASSERT hit_peer_resolves",
            "ASSERT hit_pending_uncounted",
            "ASSERT hit_reuse_admits_successor",
            "ASSERT hit_refusals_exact",
            "ASSERT hit_pre_cutover_admits",
        ],
    );
}

/// Stale floor: retired generations never resurrect, successors admit
/// over the floor, the u32 wrap admits generation 1 over a max floor.
#[test]
fn loader_gate_harness_hit_stale_floor() {
    drive_gate(
        "hit-stale-floor",
        &[
            "ASSERT stale_refused_after_reclaim",
            "ASSERT successor_admits_over_floor",
            "ASSERT wrap_gen1_admits",
            "ASSERT wrap_old_refuses",
        ],
    );
}

/// Eight threads race one token: all resolve, one admission counts.
#[test]
fn loader_gate_harness_hit_concurrent_same_token() {
    drive_gate(
        "hit-concurrent-same-token",
        &[
            "ASSERT same_token_all_resolve",
            "ASSERT same_token_admitted_once",
            "ASSERT same_token_no_refusals",
        ],
    );
}

/// Four threads race a successor generation: all resolve, one reclaim
/// and one admission count.
#[test]
fn loader_gate_harness_hit_successor_race() {
    drive_gate(
        "hit-successor-race",
        &[
            "ASSERT successor_all_resolve",
            "ASSERT successor_admitted_once",
            "ASSERT successor_reclaim_once",
            "ASSERT successor_no_refusals",
        ],
    );
}

/// Ordered admission/reclaim crossings: the peak equals the true
/// maximum live count in both orders.
#[test]
fn loader_gate_harness_admission_reclaim_interleave() {
    drive_gate(
        "admission-reclaim-interleave",
        &[
            "ASSERT ordered_admit_then_ack_peak_two",
            "ASSERT ordered_ack_then_admit_peak_one",
        ],
    );
}

/// Sixteen threads drive 64 slots through admit/retire/ack: every
/// count settles exactly with no update loss.
#[test]
fn loader_gate_harness_gauge_contention() {
    drive_gate(
        "gauge-contention",
        &[
            "ASSERT contended_admit_all_resolve",
            "ASSERT contended_peak_exact",
            "ASSERT retired_stays_charged",
            "ASSERT contended_reclaim_exact",
        ],
    );
}

/// Saturation under contention: operations take their verdicts while
/// both cells stop exactly at the maximum.
#[test]
fn loader_gate_harness_saturation_contention() {
    drive_gate(
        "saturation-contention",
        &[
            "ASSERT saturated_admit_succeeds",
            "ASSERT admitted_exact_max",
            "ASSERT refusals_exact_max",
        ],
    );
}

/// Delayed acknowledgement: nine retired rows stay charged with zero
/// live rows, then drain exactly through acknowledged reclaims.
#[test]
fn loader_gate_harness_delayed_ack_retained() {
    drive_gate(
        "delayed-ack-retained",
        &[
            "ASSERT retired_nine_charged",
            "ASSERT peak_nine_despite_zero_armed",
            "ASSERT reuse_pending_uncounted",
            "ASSERT delayed_retained_drains",
        ],
    );
}

/// Quarantine: retired-never-armed rows stay charged beside live rows;
/// fresh traffic resolves while quarantined reuse waits.
#[test]
fn loader_gate_harness_quarantine_retained() {
    drive_gate(
        "quarantine-retained",
        &[
            "ASSERT quarantine_nine_charged",
            "ASSERT eighteen_retained_nine_armed",
            "ASSERT quarantine_pending_forever",
            "ASSERT fresh_unaffected",
        ],
    );
}

/// Forced CAS exhaustion: settled updates land through the fallback
/// and every unsettled update reports through update_losses.
#[test]
fn loader_gate_harness_cas_exhaustion_counts() {
    drive_gate_hook(
        "cas-exhaustion-counts",
        &[
            "ASSERT fallback_settles_count",
            "ASSERT skip_reports_loss",
            "ASSERT peak_loss_reported",
            "ASSERT drop_loss_reported",
        ],
    );
}

/// Fallback interleave: a reclaim between the fallback add and the
/// re-read understates the peak, and the fallback reports a loss.
#[test]
fn loader_gate_harness_retained_fallback_interleave() {
    drive_gate_hook(
        "retained-fallback-interleave",
        &[
            "ASSERT interleave_gauge_shows_drop",
            "ASSERT interleave_peak_understates",
            "ASSERT interleave_fallback_reports_loss",
            "ASSERT interleave_no_further_loss",
        ],
    );
}

/// Bank-qualified identity: A holds its identity while B reissues
/// the local ticket; identities stay distinct and stable.
#[test]
fn loader_ticket_harness_identity_distinct() {
    drive_tickets(
        "identity-distinct",
        &[
            "ASSERT identity_a_legacy_cookie",
            "ASSERT identity_b_disjoint",
            "ASSERT identity_a_survives_cut",
            "ASSERT identity_b_requery_stable",
            "ASSERT identity_ticket_stays_local",
            "ASSERT identity_watermark_monotonic",
        ],
    );
}

/// Full bank lifecycle: stale-cut refusal, exactly-once fold,
/// re-prepare under a fresh incarnation, reissue without repeats.
#[test]
fn loader_ticket_harness_bank_fold_lifecycle() {
    drive_tickets(
        "bank-fold-lifecycle",
        &[
            "ASSERT stale_cut_refuses_until_folded",
            "ASSERT fold_claim_retires_once",
            "ASSERT fold_never_repeats",
            "ASSERT reprepare_cuts_back_fresh",
            "ASSERT reissue_never_repeats_cookie",
            "ASSERT watermark_monotonic_across_incarnations",
        ],
    );
}

/// Eight threads race the fold claim and the re-prepare: each
/// applies once and reissued tickets stay distinct and disjoint.
#[test]
fn loader_ticket_harness_bank_reprepare_race() {
    drive_tickets(
        "bank-reprepare-race",
        &[
            "ASSERT concurrent_fold_once",
            "ASSERT concurrent_reprepare_once",
            "ASSERT concurrent_reissue_disjoint",
        ],
    );
}

/// Exec/return isolation at the seam: each bank's exec invalidates
/// only its own rows, returns join only identical identities.
#[test]
fn loader_ticket_harness_exec_return_isolation() {
    drive_tickets(
        "exec-return-isolation",
        &[
            "ASSERT exec_invalidates_only_own_bank",
            "ASSERT exec_isolation_symmetric",
            "ASSERT return_mismatches_across_banks",
        ],
    );
}

/// Forced CAS exhaustion: settled updates land through the fallback
/// and every unsettled update reports through update_losses.
#[test]
fn loader_ticket_harness_identity_cas_exhaustion() {
    drive_tickets_hook(
        "identity-cas-exhaustion",
        &[
            "ASSERT identity_fallback_settles",
            "ASSERT identity_skip_reports",
            "ASSERT identity_bank_refusal_settles",
            "ASSERT identity_folded_saturates",
            "ASSERT identity_watermark_saturates",
        ],
    );
}

/// Incarnation guard: the top incarnation still issues a qualified
/// identity; one past the 48-bit range refuses without wrapping.
#[test]
fn loader_ticket_harness_bank_incarnation_guard() {
    drive_tickets(
        "incarnation-guard",
        &[
            "ASSERT incarnation_top_issues",
            "ASSERT incarnation_overflow_refuses",
        ],
    );
}

/// Empty slots never fold: admissions leave fold marks alone when the
/// unprepared bank has no issuance to retire.
#[test]
fn loader_ticket_harness_bank_fold_skips_empty() {
    drive_tickets("fold-skips-empty", &["ASSERT fold_skips_empty"]);
}

/// EXEC binding stays local: the current-task cookie returns the
/// per-bank ticket on both banks, never the qualified identity.
#[test]
fn loader_ticket_harness_bank_binding_stays_local() {
    drive_tickets(
        "binding-stays-local",
        &[
            "ASSERT binding_b_stays_local",
            "ASSERT binding_a_stays_local",
        ],
    );
}

/// Bank-variant witness neutrality: failures through the EXEC witness
/// (`p11_link_current_cookie`, count=0) leave the shared health cells
/// flat in a bank build, while the ticket path still counts.
#[test]
fn loader_ticket_harness_bank_witness_neutrality() {
    drive_tickets(
        "bank-witness-neutrality",
        &[
            "ASSERT witness_healthy_flat",
            "ASSERT witness_quota_flat",
            "ASSERT witness_zero_cell_flat",
            "ASSERT witness_create_flat",
            "ASSERT witness_bad_config_flat",
            "ASSERT witness_retry_flat",
            "ASSERT witness_refusals_flat",
            "ASSERT ticket_refusals_count",
            "ASSERT ticket_quota_counts",
            "ASSERT ticket_create_counts",
            "ASSERT ticket_retry_counts",
        ],
    );
}

/// Pending-fold watermark: a healthy admission folds the claimed
/// bank, the retired count is excluded while pending, the retired
/// epoch still serves, and re-prepare completes without cutting.
#[test]
fn loader_ticket_harness_bank_fold_pending_excludes() {
    drive_tickets(
        "fold-pending-excludes",
        &[
            "ASSERT fold_runs_on_healthy_admission",
            "ASSERT pending_fold_excluded_from_watermark",
            "ASSERT retired_epoch_still_serves",
            "ASSERT reprepare_without_cut_stays",
        ],
    );
}

/// The incarnation guard refuses before spending a ticket.
#[test]
fn loader_ticket_harness_bank_guard_spends_nothing() {
    drive_tickets("guard-spends-nothing", &["ASSERT guard_spends_nothing"]);
}

/// A corrupt retained cell charges its owning bank, not the current one.
#[test]
fn loader_ticket_harness_bank_retained_zero_charges_source() {
    drive_tickets(
        "retained-zero-charges-source",
        &["ASSERT retained_zero_charges_source"],
    );
}

/// A retained re-query validates the source domain before serving.
#[test]
fn loader_ticket_harness_bank_retained_validates_source() {
    drive_tickets(
        "retained-validates-source",
        &["ASSERT retained_validates_source"],
    );
}

/// A quota never cuts into a prepared target with a corrupt epoch.
#[test]
fn loader_ticket_harness_bank_cut_refuses_corrupt_target() {
    drive_tickets(
        "cut-refuses-corrupt-target",
        &["ASSERT cut_refuses_corrupt_target"],
    );
}

/// Fold help runs even when the current bank refuses as corrupt.
#[test]
fn loader_ticket_harness_bank_fold_despite_corrupt_current() {
    drive_tickets(
        "fold-despite-corrupt-current",
        &["ASSERT fold_despite_corrupt_current"],
    );
}

/// Re-queries from an overflowed epoch refuse on both entries.
#[test]
fn loader_ticket_harness_bank_hit_overflow_refuses() {
    drive_tickets("hit-overflow-refuses", &["ASSERT hit_overflow_refuses"]);
}

/// Domain before row: the epoch guard fires before the zero-cell check.
#[test]
fn loader_ticket_harness_bank_guard_before_zero_cell() {
    drive_tickets("guard-before-zero-cell", &["ASSERT guard_before_zero_cell"]);
}

/// W2 publication twin: gate-1 issuance without the published select
/// word refuses BAD_CONFIG and spends nothing; the exact pinned
/// image issues ticket 1.
#[test]
fn loader_ticket_harness_select_publication_issues() {
    drive_tickets(
        "select-publication-issues",
        &[
            "ASSERT unpublished_select_word_refuses_bad_config",
            "ASSERT pinned_select_image_exact",
            "ASSERT published_select_word_issues_ticket",
        ],
    );
}

/// Selection validation: unpublished, corrupt or missing SELECT
/// refuses new issues; cut validates its target and prepared bit.
#[test]
fn loader_ticket_harness_bank_select_validation() {
    drive_tickets(
        "bank-select-validation",
        &[
            "ASSERT unpublished_select_refuses",
            "ASSERT missing_select_refuses",
            "ASSERT cut_flips_once_ready",
            "ASSERT bad_select_counted",
        ],
    );
}

/// The gate unit lowers to BPF bitcode warning-free under the exact BPF
/// object flags, so the host-only unit can never rot. Host-only; emits
/// LLVM bitcode to a temp dir, no BPF load, no attach. It then scores
/// the touched-function LLVM size against the stated tripwire bound.
#[test]
fn loader_gate_unit_compiles_to_bpf_bitcode() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let temporary = tempfile::tempdir().expect("loader gate modes directory");
    let target = if cfg!(target_endian = "big") {
        "bpfeb"
    } else {
        "bpfel"
    };
    let prefix = format!("-ffile-prefix-map={manifest}=/p11scope");
    for unit in ["loader_gate", "task_owner", "image_identity"] {
        let output_name = format!("{unit}-loader-gate.bc");
        let output_path = temporary.path().join(&output_name);
        let source = format!("{manifest}/crates/ebpf/native/{unit}.c");
        let output = std::process::Command::new("clang-18")
            .current_dir(temporary.path())
            .args([
                "-target",
                target,
                "-O2",
                "-g",
                "-gno-record-gcc-switches",
                "-fdebug-compilation-dir=/p11scope/native",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-emit-llvm",
                "-c",
            ])
            .arg(&prefix)
            .arg(&source)
            .arg("-DP11SCOPE_LOADER_GATE")
            .arg("-I")
            .arg(format!("{manifest}/crates/ebpf/native"))
            .arg("-o")
            .arg(&output_name)
            .output()
            .expect("compile loader gate unit");
        assert!(
            output.status.success(),
            "native {unit} gate compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output_path.exists(), "native {unit} gate bitcode emitted");
    }
    // The same units compile without the gate define: the gate-off
    // production flavors must never rot behind the new guarded code.
    for unit in ["loader_gate", "task_owner", "image_identity"] {
        let output_name = format!("{unit}-loader-gate-off.bc");
        let output_path = temporary.path().join(&output_name);
        let source = format!("{manifest}/crates/ebpf/native/{unit}.c");
        let output = std::process::Command::new("clang-18")
            .current_dir(temporary.path())
            .args([
                "-target",
                target,
                "-O2",
                "-g",
                "-gno-record-gcc-switches",
                "-fdebug-compilation-dir=/p11scope/native",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-emit-llvm",
                "-c",
            ])
            .arg(&prefix)
            .arg(&source)
            .arg("-I")
            .arg(format!("{manifest}/crates/ebpf/native"))
            .arg("-o")
            .arg(&output_name)
            .output()
            .expect("compile loader gate unit without the define");
        assert!(
            output.status.success(),
            "native {unit} gate-off compile: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output_path.exists(),
            "native {unit} gate-off bitcode emitted"
        );
    }
    assert_loader_producer_size_tripwire(temporary.path());
}

/// Count LLVM instructions in one named function of disassembled
/// bitcode: indented non-comment lines in its define body, excluding
/// debug intrinsics (they lower to nothing). Returns None when the
/// function is absent.
fn llvm_function_insns(disassembly: &str, name: &str) -> Option<usize> {
    let mut in_body = false;
    let mut count = 0usize;
    let mut found = false;
    let define_needle = format!("@{name}(");
    for line in disassembly.lines() {
        if !in_body {
            if line.starts_with("define ") && line.contains(&define_needle) {
                in_body = true;
                found = true;
            }
            continue;
        }
        if line == "}" {
            break;
        }
        let trimmed = line.trim_start();
        if line.len() == trimmed.len() {
            continue; // label or unindented directive
        }
        let trimmed = trimmed.trim_end();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.contains("@llvm.dbg.") {
            continue;
        }
        count += 1;
    }
    found.then_some(count)
}

/// F1: the loader producer selects its path before reserving.
/// `dl_debug_state_impl` holds no ring reservation across the
/// token/legacy branch: the token arm returns before any reserve, and
/// each arm reserves inside its own emitter. The old shape reserved a
/// legacy entry and leaked it on every token hit (neither submitted nor
/// discarded). This pins the source shape in CI; the compiled cfg-on
/// shape is proven by the repeatable MIR procedure in the P1 repair
/// evidence (dump the impl's MIR and show it holds no reserve call;
/// the LLVM link of that procedure failed in the toolchain), and the
/// cfg-on root enters the later verifier lane before activation.
#[test]
fn cfgon_producer_selects_path_before_reserving() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let source = std::fs::read_to_string(format!("{manifest}/crates/ebpf/src/main.rs"))
        .expect("BPF producer source must exist");
    let marker = "fn dl_debug_state_impl(ctx: ProbeContext) -> u32 {";
    let mut occurrences = source.match_indices(marker);
    let (start, _) = occurrences.next().expect("producer impl must exist");
    assert!(
        occurrences.next().is_none(),
        "producer impl marker must be unique"
    );
    let body = brace_matched_body(&source[start + marker.len() - 1..]);
    assert!(
        body.contains("loader_gate_latched_for_producer"),
        "impl must select the token path on the latch:\n{body}"
    );
    assert!(
        !body.contains("reserve_discovery"),
        "impl must hold no reservation across the branch:\n{body}"
    );
}

/// Extract one brace-matched `{...}` body, skipping line comments, block
/// comments and string literals so braces inside them cannot miscount.
/// Fails closed on char-literal braces and unterminated input: the test
/// must break loudly, never miscount silently.
fn brace_matched_body(text: &str) -> String {
    let bytes = text.as_bytes();
    assert!(
        !bytes.is_empty() && bytes[0] == b'{',
        "body must open a brace"
    );
    let mut depth = 0usize;
    let mut end = None;
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let next = bytes.get(index + 1).copied().unwrap_or(0);
        if byte == b'/' && next == b'/' {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if byte == b'/' && next == b'*' {
            index += 2;
            while index + 1 < bytes.len() && !(bytes[index] == b'*' && bytes[index + 1] == b'/') {
                index += 1;
            }
            assert!(index + 1 < bytes.len(), "unterminated block comment");
            index += 2;
            continue;
        }
        if byte == b'"' {
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\\' {
                    index += 2;
                    continue;
                }
                if bytes[index] == b'"' {
                    break;
                }
                index += 1;
            }
            assert!(index < bytes.len(), "unterminated string literal");
            index += 1;
            continue;
        }
        if byte == b'\'' {
            panic!("char literal in producer body: extend the matcher");
        }
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                end = Some(index + 1);
                break;
            }
        }
        index += 1;
    }
    let end = end.expect("producer body must close its brace");
    text[..end].to_owned()
}

/// LLVM size tripwire for the loader/image producer: disassemble the
/// gate-enabled unit bitcode, count LLVM instructions in the touched
/// BPF functions, and score the total against a stated self-baseline.
/// THIS IS A SIZE TRIPWIRE, NOT A VERIFIER BUDGET: it catches gross
/// code-size blowups in CI without a kernel. Verifier budgets for the
/// gate-1 roots are the `detailed-gate1/<root>` rows in
/// `tests/bpf-verifier-budgets.json`, measured from real kernel loads.
/// Baseline: touched total 9039 LLVM insns, measured on the tree that
/// fixed the gate-1 `p11_return` stack overflow (link frame 112 down to
/// 64 or below with the select and cut leaves inlined, so the return
/// path fits 512 with the link as its deepest frame); bound 9491 =
/// ceil(9039 x 1.05), the >=5% headroom rule. The ticket helper carries
/// the inlined cut step once per unrolled attempt, which is why the
/// baseline sits above the pre-fix sum. Do not raise this bound to
/// quiet the test: a breach means a touched function grew; shrink the
/// growth or re-baseline with a stated reason.
fn assert_loader_producer_size_tripwire(bitcode_dir: &Path) {
    const BASELINE_TOTAL: u64 = 9039;
    const BOUND: u64 = 9491; // ceil(9039 x 1.05): the >=5% headroom rule
    // Compile-time pin: the bound keeps >=5% headroom over the baseline.
    // A breach fails the build, never the test run.
    const {
        assert!(BOUND * 100 >= BASELINE_TOTAL * 105);
    }
    let touched: &[(&str, &[&str])] = &[
        (
            "loader_gate",
            &[
                "p11_loader_gate_ack",
                "p11_loader_gate_row_generation",
                "p11_loader_gate_cutover_latched",
                "p11_loader_gate_admit",
                "p11_loader_gate_note_producer_end",
                "p11_loader_gate_hit",
            ],
        ),
        (
            "image_identity",
            &[
                "p11_image_bank_select",
                "p11_image_bank_cut",
                "p11_link_task_ticket",
                "p11_image_identity_issued",
            ],
        ),
    ];
    let mut total = 0usize;
    for (unit, functions) in touched {
        let bitcode = bitcode_dir.join(format!("{unit}-loader-gate.bc"));
        let disassembly = std::process::Command::new("llvm-dis-18")
            .arg(&bitcode)
            .arg("-o")
            .arg("-")
            .output()
            .expect("disassemble loader gate bitcode");
        assert!(
            disassembly.status.success(),
            "native {unit} disassembly: {}",
            String::from_utf8_lossy(&disassembly.stderr)
        );
        let text = String::from_utf8(disassembly.stdout).expect("llvm disassembly is utf-8");
        for name in *functions {
            let count = llvm_function_insns(&text, name)
                .unwrap_or_else(|| panic!("touched BPF function {name} must be present"));
            println!("size tripwire: {unit}::{name} = {count} llvm insns");
            total += count;
        }
    }
    println!("size tripwire: touched total = {total} llvm insns, bound = {BOUND}");
    assert!(
        tripwire_scores_pass(total as u64, BOUND),
        "touched loader producer {total} llvm insns exceed the size-tripwire bound {BOUND} (baseline {BASELINE_TOTAL}); this is a size tripwire, not a verifier budget"
    );
    // Twin: the scorer must fail a grown total, so a passing probe
    // always has teeth. A lowered-bound run of this same test is the
    // live twin: it must fail on the unchanged tree.
    assert!(
        tripwire_scores_pass(BOUND, BOUND),
        "scorer passes at the bound"
    );
    assert!(
        !tripwire_scores_pass(BOUND + 1, BOUND),
        "scorer fails a grown total"
    );
}

/// Pure scorer for the size tripwire, so the twin exercises the exact
/// pass/fail boundary without bitcode.
fn tripwire_scores_pass(total: u64, bound: u64) -> bool {
    total <= bound
}
