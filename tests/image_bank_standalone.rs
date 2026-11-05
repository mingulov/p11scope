//! SPDX-License-Identifier: GPL-3.0-or-later
//! Host harness for the image dispatcher/bank rollover protocol (E1 logic
//! stage): the real `crates/ebpf/native/image_bank.c` is compiled for host
//! with stub map storage and driven through scripted interleavings covering
//! the exhaustion twin, the cut, dual counting, held returns, late
//! callbacks, failure modes, slot reuse, omitted routes, exec/query span and
//! saturation. Kernel facts (verifier, stack, memlock, overhead) are proven
//! in later stages, not here. Unprivileged and permanent.
//!
//! Route storage R0 (bank field inside the START value) is the variant under
//! test for every shared cell; the separate-table R1 backend exists only for
//! its unique delete-failure cell and is measured only if R0 fails a cell.

/// Shared by path with the build script and other harnesses, which use the
/// helpers this file does not call; the allowance covers only that module.
#[path = "../build_support/clang_resolve.rs"]
#[allow(dead_code)]
mod clang_resolve;

use std::path::{Path, PathBuf};

/// Compile the real `image_bank.c` for host through `image_bank_harness.c`.
/// Returns the work dir (for cleanup) and the scenario binary.
fn compile_harness(scenario: &str) -> (PathBuf, PathBuf) {
    let native = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/ebpf/native");
    for file in ["image_bank_harness.c", "image_bank.h", "image_bank.c"] {
        let source = native.join(file);
        assert!(
            source.is_file(),
            "harness source {} must exist",
            source.display()
        );
    }
    let source = native.join("image_bank_harness.c");
    let work = std::env::temp_dir().join(format!(
        "p11scope-image-bank-{scenario}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&work).expect("harness work dir");
    let binary = work.join("image_bank_harness");
    let cwd = std::env::current_dir().expect("cwd");
    let compiler = clang_resolve::resolve_executable_in(
        "clang-18",
        &std::env::var_os("PATH").unwrap_or_default(),
        &cwd,
    )
    .expect("host harness needs an executable clang-18 on PATH");
    let compile = std::process::Command::new(&compiler)
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
        .arg(&binary)
        .output()
        .expect("spawn host cc for the harness");
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

fn drive(scenario: &str, asserts: &[&str]) {
    let (work, binary) = compile_harness(scenario);
    run_scenario(&binary, scenario, asserts);
    let _ = std::fs::remove_dir_all(&work);
}

/// N6 exhaustion twin: without a prepared successor, `next_ticket` reaches
/// the real 16,384 limit with successful + burned tickets summing exactly,
/// burns reported, and the next attempt refused with QUOTA, `unavailable`
/// +1, no identity and no record claiming one.
#[test]
fn image_bank_harness_exhaustion_without_next_bank_refuses() {
    drive(
        "exhaustion-without-next-bank",
        &[
            "ASSERT next_ticket_reaches_16384",
            "ASSERT successful_plus_burned_is_16384",
            "ASSERT burns_reported_384",
            "ASSERT next_attempt_quota",
            "ASSERT unavailable_plus_one",
            "ASSERT refused_has_no_identity",
            "ASSERT burned_ticket_has_no_record",
            "ASSERT refused_attempt_spends_no_ticket",
        ],
    );
}

/// N7 cut: with B prepared, the first post-cut admission is B ticket 1 in a
/// new incarnation; A issuance is frozen; per-bank counts sum to the ledger;
/// A completions change only through routed returns.
#[test]
fn image_bank_harness_cut_moves_new_admissions_only() {
    drive(
        "cut-moves-new-admissions-only",
        &[
            "ASSERT b_ticket_1_in_new_incarnation",
            "ASSERT a_next_ticket_unchanged",
            "ASSERT leader_16385_holds_b_identity",
            "ASSERT a_admission_frozen",
            "ASSERT bank_counts_sum_to_ledger",
            "ASSERT a_completion_only_via_routed_return",
        ],
    );
}

/// N8 dual count: 4 threads x 10,000 calls across the cut count exactly
/// 40,000 (20,000 per bank), with zero double counts and zero
/// accepted-but-uncounted calls.
#[test]
fn image_bank_harness_concurrent_cut_counts_once() {
    drive(
        "concurrent-cut-counts-once",
        &[
            "ASSERT forty_thousand_counted",
            "ASSERT twenty_thousand_per_bank",
            "ASSERT zero_counted_by_both",
            "ASSERT zero_accepted_but_uncounted",
        ],
    );
}

/// N9 held return: a return held across the cut completes through its A
/// route and counts in A; A is not reclaimable while held; release reaches
/// closed-zero.
#[test]
fn image_bank_harness_held_return_follows_route() {
    drive(
        "held-return-follows-route",
        &[
            "ASSERT return_completes_through_a_route",
            "ASSERT counted_in_a",
            "ASSERT a_not_reclaimable_while_held",
            "ASSERT release_reaches_closed_zero",
        ],
    );
}

/// N10 late callback: an A-incarnation callback delayed past A-prime
/// preparation is refused by incarnation mismatch with zero successor
/// mutations and balanced refs.
#[test]
fn image_bank_harness_late_incarnation_refused() {
    drive(
        "late-incarnation-refused",
        &[
            "ASSERT late_callback_refused",
            "ASSERT zero_successor_mutations",
            "ASSERT current_callback_mutates_once",
            "ASSERT ref_balanced",
        ],
    );
}

/// N11 route-delete failure (R1 backend only; R0 has no route map): the
/// failed delete pins A, blocks rollover with a named refusal and no fold;
/// clearing the fault and retrying drains and unpins.
#[test]
fn image_bank_harness_route_delete_failure_pins_bank() {
    drive(
        "route-delete-failure-pins-bank",
        &[
            "ASSERT delete_failure_pins_a",
            "ASSERT rollover_blocked_with_named_refusal",
            "ASSERT no_fold_while_pinned",
            "ASSERT retry_drains_and_unpins",
        ],
    );
}

/// N11 failure modes: a third preparation while A is retained refuses with
/// a named refusal; a tail-call failure releases exactly its refs; the
/// current bank stays usable after the refused preparation.
#[test]
fn image_bank_harness_third_preparation_refuses() {
    drive(
        "third-preparation-refuses",
        &[
            "ASSERT third_preparation_refuses_named",
            "ASSERT tailcall_failure_releases_refs",
            "ASSERT current_bank_usable_after_refusal",
        ],
    );
}

/// N11 second rollover: A-prime reuses slot A as new map objects plus a
/// freshly loaded program after closed-zero; map ids differ, A's maps are
/// gone, A-prime ticket 1 never joins A ticket 1, and A-prime is useful.
#[test]
fn image_bank_harness_second_rollover_reuses_slot() {
    drive(
        "second-rollover-reuses-slot",
        &[
            "ASSERT aprime_map_ids_differ",
            "ASSERT a_maps_gone_after_reclaim",
            "ASSERT aprime_ticket_1_never_joins_a_ticket_1",
            "ASSERT aprime_useful",
        ],
    );
}

/// N13 omitted route: a return with no route refuses without a fabricated
/// return, and the useful-new-bank twin still counts.
#[test]
fn image_bank_harness_omitted_route_refuses() {
    drive(
        "omitted-route-refuses",
        &[
            "ASSERT omitted_route_refuses",
            "ASSERT no_fabricated_return",
            "ASSERT useful_new_bank_twin_counts",
        ],
    );
}

/// N14 exec/query span: an exec invalidation delayed across the cut covers
/// both banks, a delayed query observes it, and held leases drain on
/// release.
#[test]
fn image_bank_harness_exec_invalidator_spans_cut() {
    drive(
        "exec-invalidator-spans-cut",
        &[
            "ASSERT invalidator_covers_both_banks",
            "ASSERT delayed_query_sees_invalidated",
            "ASSERT leases_drain_after_release",
        ],
    );
}

/// N16 saturation: a burst larger than the H = 1024 headroom before the flip
/// completes yields counted QUOTA refusals (`unavailable` delta equals the
/// refused count), no identities for the refused and no silent loss.
#[test]
fn image_bank_harness_saturation_burst_refuses_counted() {
    drive(
        "saturation-burst-refuses-counted",
        &[
            "ASSERT burst_admits_headroom_only",
            "ASSERT quota_refusals_counted",
            "ASSERT unavailable_delta_equals_refused",
            "ASSERT refused_have_no_identity",
            "ASSERT no_silent_loss",
        ],
    );
}

/// Bank-switch race: a flip landing inside one select (between the gate
/// take and the recheck) must back the stale ref out and route the call
/// to the current bank with the current incarnation; no (incarnation,
/// ticket) pair is ever shared across banks.
#[test]
fn image_bank_harness_select_flip_admit() {
    drive(
        "select-flip-admit",
        &[
            "ASSERT selected_bank_is_post_flip_current",
            "ASSERT flip_fired_inside_select",
            "ASSERT stale_bank_backed_out",
            "ASSERT current_bank_holds_the_ref",
            "ASSERT admitted_identity_is_current_bank",
            "ASSERT steady_select_stays_current",
            "ASSERT second_bank_identity_admits",
            "ASSERT no_identity_collision_across_banks",
            "ASSERT held_route_keeps_fixed_incarnation",
            "ASSERT raced_call_completes_in_current_bank",
            "ASSERT select_admit_counts_split",
            "ASSERT select_admit_gates_balanced",
        ],
    );
}

/// Bank-switch race: a selected-but-unadmitted call holds its bank's gate
/// across the flip, so that bank must not read closed-zero until the ref
/// drains; the admitted call keeps its bank's fixed incarnation.
#[test]
fn image_bank_harness_select_flip_closed_zero() {
    drive(
        "select-flip-closed-zero",
        &[
            "ASSERT selected_call_holds_a_ref",
            "ASSERT flip_published",
            "ASSERT not_closed_zero_while_selected",
            "ASSERT admission_check_agrees_with_leased_check",
            "ASSERT selected_call_admits_with_a_incarnation",
            "ASSERT live_call_blocks_close_zero",
            "ASSERT live_call_blocks_leased_close_zero",
            "ASSERT selected_call_completes_in_a",
            "ASSERT select_close_counts_in_a",
            "ASSERT release_reaches_admission_closed_zero",
            "ASSERT release_reaches_leased_closed_zero",
            "ASSERT select_close_gates_balanced",
        ],
    );
}

/// F4 refusal order: a second leader entering on an already-used call id is
/// refused without spending a ticket, admitting a call or installing a
/// binding; the first call's binding is untouched and still completes.
#[test]
fn image_bank_harness_reused_call_id_refuses() {
    drive(
        "reused-call-id-refuses",
        &[
            "ASSERT reused_call_id_refuses",
            "ASSERT refused_reuse_spends_no_ticket",
            "ASSERT refused_reuse_admits_nothing",
            "ASSERT refused_reuse_installs_no_binding",
            "ASSERT first_binding_untouched",
            "ASSERT refused_reuse_balances_gate",
            "ASSERT first_call_still_completes",
        ],
    );
}
