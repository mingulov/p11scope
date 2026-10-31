//! SPDX-License-Identifier: GPL-3.0-or-later
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
    if tag == "owner-gate" || tag == "tickets" {
        command.arg("-DP11SCOPE_LOADER_GATE");
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

fn drive_tickets(scenario: &str, asserts: &[&str]) {
    let (work, binary) = compile_harness(
        "tests/fixtures/image-identity/ticket_query_tests.c",
        "tickets",
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

/// L4b loader cells: arms count admits, retained tracks live rows, the
/// peak is monotonic across retire/reclaim cycles.
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
/// LLVM bitcode to a temp dir, no BPF load, no attach.
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
    assert_loader_producer_verifier_probe(temporary.path());
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

/// Verifier-cost probe for the loader/image producer: disassemble the
/// gate-enabled unit bitcode, count LLVM instructions in the touched
/// BPF functions, and score the total against the existing loader-root
/// pin (minimum across kernels) further limited by the configured
/// headroom against the verifier limit. Both the numeric pin and the
/// headroom apply; no new numbers are pinned here. LLVM counts are a
/// documented proxy (gross-blowup tripwire), never a verifier proof:
/// genuinely new gate costs are measured and pinned from kernel data
/// in the later qualification stage.
fn assert_loader_producer_verifier_probe(bitcode_dir: &Path) {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let budgets_text =
        std::fs::read_to_string(format!("{manifest}/tests/bpf-verifier-budgets.json"))
            .expect("verifier budgets file must exist");
    let budgets: serde_json::Value =
        serde_json::from_str(&budgets_text).expect("verifier budgets must parse");
    let limit = budgets["limit"].as_u64().expect("verifier limit pin");
    let min_headroom = budgets["min_headroom_percent"]
        .as_f64()
        .expect("headroom pin");
    let root = &budgets["programs"]["detailed/dl_debug_state"];
    let pin = root
        .as_object()
        .expect("loader root pin")
        .values()
        .map(|value| value.as_u64().expect("per-kernel pin"))
        .min()
        .expect("at least one kernel pin");
    let bound = pin.min((limit as f64 * (1.0 - min_headroom / 100.0)) as u64);
    assert!(bound > 0, "pin bound must be positive");
    let touched: &[(&str, &[&str])] = &[
        (
            "loader_gate",
            &[
                "p11_loader_gate_ack",
                "p11_loader_gate_row_generation",
                "p11_loader_gate_cutover_latched",
                "p11_loader_gate_admit",
                "p11_loader_gate_note_producer_end",
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
            println!("verifier probe: {unit}::{name} = {count} llvm insns");
            total += count;
        }
    }
    println!("verifier probe: touched total = {total} llvm insns, bound = {bound}");
    assert!(
        total as u64 <= bound,
        "touched loader producer {total} llvm insns exceed the loader-root pin {bound}"
    );
}
