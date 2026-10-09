//! SPDX-License-Identifier: GPL-3.0-or-later
//! Human conclusions and publication ordering from real admitted snapshots.

use super::{compare::compare, input, model, render::render_text};
use crate::cli::InventoryDiffArgs;
use serde_json::{Value, json};
use std::io::{self, Write};

const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/inventory-diff/scan-current.json");

fn document() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn snapshot(value: &Value) -> input::Snapshot {
    input::parse_snapshot(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn report(before: &Value, after: &Value) -> model::DiffReport {
    compare(&snapshot(before), &snapshot(after))
}

fn text(report: &model::DiffReport) -> String {
    let mut output = Vec::new();
    render_text(report, &mut output).unwrap();
    String::from_utf8(output).unwrap()
}

fn counted(value: &mut Value, count: u64, lossy: bool) {
    value["edges"][0]["entries"]["count"] = json!(count);
    value["edges"][0]["entries"]["observation"] = json!("observed");
    value["edges"][0]["entries"]["coverage"]["state"] = json!("counted");
    value["edges"][0]["entries"]["coverage"]["lossy"] = json!(lossy);
}

#[test]
fn application_and_module_paths_are_resolved_and_basename_collisions_stay_separate() {
    let mut before = document();
    before["callers"][0]["image"]["exe"]["path"] = json!("/opt/one/driver");
    let mut caller = before["callers"][0].clone();
    caller["id"] = json!("c1");
    caller["pid"] = json!(4243);
    caller["image"]["exe"]["path"] = json!("/opt/two/driver");
    before["callers"].as_array_mut().unwrap().push(caller);
    let mut edge = before["edges"][0].clone();
    edge["caller"] = json!("c1");
    before["edges"].as_array_mut().unwrap().push(edge);
    let mut after = before.clone();
    after["modules"][0]["paths"] = json!(["/changed/m0.so"]);
    let report = report(&before, &after);
    assert_eq!(report.summary.application_groups_changed, 2);
    let output = text(&report);
    for expected in [
        "2 application groups changed",
        "/opt/one/driver",
        "/opt/two/driver",
        "/scale/m0.so",
        "/changed/m0.so",
        "m0.so",
        "4242",
        "4243",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
    assert!(!output.contains("exe_path_ref"));
}

#[test]
fn independent_counts_loss_and_saturation_agree_with_the_typed_report() {
    let mut before = document();
    counted(&mut before, 128, false);
    let mut after = before.clone();
    counted(&mut after, 24, true);
    after["edges"][0]["entries"]["saturated"] = json!(true);
    let report = report(&before, &after);
    let row = &report.application_changes[0];
    assert_eq!(
        report.before.evidence.edges[row.before[0].0].entries.count,
        128
    );
    assert_eq!(
        report.after.evidence.edges[row.after[0].0].entries.count,
        24
    );
    let output = text(&report);
    for expected in [
        "Before",
        "After",
        "at least 128 entries observed",
        "at least 24 entries observed",
        "lossy",
        "saturated",
        "independent observation windows",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
    assert!(!output.contains("-104"));
    assert!(!output.contains("throughput"));
}

#[test]
fn quiet_witnessed_pending_and_missing_coverage_have_distinct_honest_meanings() {
    for (state, reason, expected) in [
        (
            Some("watched_no_use"),
            None,
            "No use observed during recorded watch coverage",
        ),
        (
            Some("witnessed"),
            None,
            "Use witnessed; entry count unavailable",
        ),
        (
            Some("unknown"),
            Some("pending_first_use"),
            "pending_first_use",
        ),
        (Some("future_coverage"), None, "Coverage unknown"),
        (None, None, "Coverage unknown"),
    ] {
        let before = document();
        let mut after = before.clone();
        after["modules"][0]["paths"] = json!(["/changed/m0.so"]);
        after["edges"][0]["entries"]["coverage"]["state"] = json!(state);
        after["edges"][0]["entries"]["coverage"]["reason"] = json!(reason);
        if state.is_none() {
            after["edges"][0]["entries"]
                .as_object_mut()
                .unwrap()
                .remove("coverage");
        }
        let output = text(&report(&before, &after));
        assert!(output.contains(expected), "{state:?}: {output}");
        assert!(
            !output.contains("0 entries observed"),
            "{state:?}: {output}"
        );
        assert!(!output.contains("no crypto use"), "{state:?}: {output}");
    }
}

#[test]
fn new_semantic_labels_are_displayed_as_unknown_instead_of_success() {
    let before = document();
    let mut after = before.clone();
    after["edges"][0]["semantics"] = json!("future_success");
    let report = report(&before, &after);
    let output = text(&report);
    assert!(
        output.contains("Semantic availability unknown (reported label: future_success)"),
        "{output}"
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(
        json["after"]["evidence"]["edges"][0]["semantics"],
        "future_success"
    );
}

#[test]
fn unknown_executables_and_digests_remain_useful_without_guessing() {
    let before = document();
    let mut after = before.clone();
    after["callers"][0]["image"]["exe"]["path"] = Value::Null;
    after["modules"][0]["identity"]["sha256"] = Value::Null;
    let report = report(&before, &after);
    // The unresolved edge retains its caller; there is no separate caller row.
    assert_eq!(report.summary.unresolved_observations, 2);
    let output = text(&report);
    for expected in [
        "Unknown executable",
        "4242",
        "/scale/m0.so",
        "Content digest unknown",
        "After",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
}

#[test]
fn unchanged_reports_still_explain_partial_scope_gaps_and_semantic_boundaries() {
    let value = document();
    let report = report(&value, &value);
    assert_eq!(report.summary.application_groups_changed, 0);
    let output = text(&report);
    for expected in [
        "No differences in the compared inventory observations",
        "scope completeness",
        "host/boot continuity",
        "process",
        "physical",
        "unknown",
        "PARTIAL",
        "fixture coverage unknown",
        "scan fixture has no usage producer",
        "semantic capture withheld",
        "Instance and detailed semantic changes are not compared",
        "Not observed after does not prove removal",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
}

#[test]
fn observation_windows_refusals_native_loss_and_gap_repeats_stay_separate() {
    let mut before = document();
    before["gaps"][0]["repeats"] = json!(3);
    before["budgets"]["callers"]["refused"] = json!(2);
    before["observation"]["lifecycle"] = json!({"records": 4, "ring_loss": 7, "malformed": 1,
        "failed_quanta": 2, "recovery_rescans": 3});
    let mut after = before.clone();
    after["observation"]["started_ns"] = json!(300);
    after["observation"]["ended_ns"] = json!(400);
    after["gaps_suppressed"] = json!(5);
    after["observation"]["native_witnesses"]["pending"] = json!(6);
    let output = text(&report(&before, &after));
    for expected in [
        "100",
        "200",
        "300",
        "400",
        "ring loss 7",
        "pending 6",
        "callers: 2",
        "repeats 3",
        "suppressed gaps 5",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
}

#[test]
fn untrusted_text_is_escaped_and_long_identities_survive_eighty_columns() {
    let before = document();
    let mut after = before.clone();
    let long_path = format!("/opt/{}/driver", "p".repeat(190));
    after["callers"][0]["image"]["exe"]["path"] = json!(long_path);
    after["modules"][0]["admission"]["note"] = json!("note\n\t\x1b\u{009b}");
    after["gaps"][0]["reason"] = json!("reason\r\x1b");
    let output = text(&report(&before, &after));
    assert!(
        output.lines().all(|line| line.chars().count() <= 80),
        "{output}"
    );
    let joined = output.lines().map(str::trim).collect::<String>();
    assert!(
        joined.contains(&long_path),
        "identity disappeared: {output}"
    );
    for expected in ["note\\n\\t\\u{1b}\\u{9b}", "reason\\r\\u{1b}"] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
    assert!(!output.chars().any(|c| c.is_control() && c != '\n'));
}

#[test]
fn shared_admission_details_are_not_reprinted_for_every_edge() {
    let mut before = document();
    before["modules"][0]["admission"]["note"] = json!("SHARED_ADMISSION_DETAILS");
    before["gaps"] = json!([]);
    let mut callers = Vec::new();
    let mut edges = Vec::new();
    for index in 0..20 {
        let mut caller = before["callers"][0].clone();
        caller["id"] = json!(format!("c{index}"));
        caller["pid"] = json!(5000 + index);
        caller["image"]["exe"]["path"] = json!(format!("/bin/app{index}"));
        let mut edge = before["edges"][0].clone();
        edge["caller"] = json!(format!("c{index}"));
        callers.push(caller);
        edges.push(edge);
    }
    before["callers"] = json!(callers);
    before["edges"] = json!(edges);
    let mut after = before.clone();
    after["modules"][0]["paths"] = json!(["/new/m0.so"]);
    let output = text(&report(&before, &after));
    assert_eq!(
        output.matches("SHARED_ADMISSION_DETAILS").count(),
        2,
        "one per side: {output}"
    );
    assert!(output.contains("/bin/app19"));
}

struct CountingWriter {
    accepted: usize,
    ceiling: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.accepted + bytes.len() > self.ceiling {
            return Err(io::Error::other("human rendering amplified shared labels"));
        }
        self.accepted += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn long_module_name_fanout_does_not_expand_a_shared_path_per_edge() {
    let mut before = document();
    let module_name = "m".repeat(12_000);
    before["modules"][0]["paths"] = json!([format!("/old/{module_name}")]);
    let mut callers = Vec::new();
    let mut edges = Vec::new();
    for index in 0..20 {
        let mut caller = before["callers"][0].clone();
        caller["id"] = json!(format!("c{index}"));
        caller["pid"] = json!(6000 + index);
        caller["image"]["exe"]["path"] = json!(format!("/bin/app{index}"));
        let mut edge = before["edges"][0].clone();
        edge["caller"] = json!(format!("c{index}"));
        callers.push(caller);
        edges.push(edge);
    }
    before["callers"] = json!(callers);
    before["edges"] = json!(edges);
    let mut after = before.clone();
    after["modules"][0]["paths"] = json!([format!("/new/{module_name}")]);
    let report = report(&before, &after); // Both documents pass the unchanged reader.
    assert_eq!(report.summary.application_groups_changed, 20);
    let mut writer = CountingWriter {
        accepted: 0,
        ceiling: 150_000,
    };
    render_text(&report, &mut writer).unwrap();
    assert!(writer.accepted > 24_000, "full paths must survive");
    let output = text(&report).lines().map(str::trim).collect::<String>();
    assert!(output.contains(&format!("/old/{module_name}")));
    assert!(output.contains(&format!("/new/{module_name}")));
}

#[test]
fn unresolved_edge_fanout_does_not_repeat_a_shared_long_executable_path() {
    let before = document();
    let mut after = before.clone();
    let long_path = format!("/bin/{}/driver", "a".repeat(12_000));
    after["callers"][0]["image"]["exe"]["path"] = json!(long_path);
    let mut modules = Vec::new();
    let mut edges = Vec::new();
    for index in 0..20 {
        let mut module = after["modules"][0].clone();
        module["id"] = json!(format!("m{index}"));
        module["identity"]["inode"] = json!(100000 + index);
        module["identity"]["sha256"] = Value::Null;
        module["paths"] = json!([format!("/lib/m{index}.so")]);
        let mut edge = after["edges"][0].clone();
        edge["module"] = json!(format!("m{index}"));
        modules.push(module);
        edges.push(edge);
    }
    after["modules"] = json!(modules);
    after["edges"] = json!(edges);
    let report = report(&before, &after);
    assert_eq!(report.summary.unresolved_observations, 40);
    let mut writer = CountingWriter {
        accepted: 0,
        ceiling: 100_000,
    };
    render_text(&report, &mut writer).unwrap();
    let output = text(&report).lines().map(str::trim).collect::<String>();
    assert!(output.contains(&long_path));
    assert!(output.contains("/lib/m19.so"));
}

fn caller_fanout_document(field: &str, payload: &str) -> Value {
    let mut value = document();
    value["gaps"] = json!([]);
    value["callers"][0][field] = json!(payload);
    let mut modules = Vec::new();
    let mut edges = Vec::new();
    for index in 0..20 {
        let mut module = value["modules"][0].clone();
        module["id"] = json!(format!("m{index}"));
        module["identity"]["inode"] = json!(100_000 + index);
        module["paths"] = json!([format!("/lib/m{index}.so")]);
        let mut edge = value["edges"][0].clone();
        edge["module"] = json!(format!("m{index}"));
        edge["entries"]["count"] = json!(1_000 + index);
        edge["entries"]["observation"] = json!("observed");
        edge["entries"]["coverage"]["state"] = json!("counted");
        edge["entries"]["coverage"]["lossy"] = json!(false);
        modules.push(module);
        edges.push(edge);
    }
    value["modules"] = json!(modules);
    value["edges"] = json!(edges);
    for resource in ["modules", "edges", "inventory_attach_modules"] {
        value["budgets"][resource]["occupied"] = json!(20);
    }
    value
}

fn assert_shared_caller_field_is_not_amplified(field: &str) {
    let payload = format!("SHARED_{field}_{}", "x".repeat(12_000));
    let value = caller_fanout_document(field, &payload);
    let report = report(&value, &value); // Admission uses the real bounded reader.
    assert_eq!(report.before.evidence.callers.len(), 1);
    assert_eq!(report.before.evidence.caller_occurrences.len(), 1);
    assert_eq!(report.before.evidence.edge_occurrences.len(), 20);
    let mut writer = CountingWriter {
        accepted: 0,
        ceiling: 180_000,
    };
    render_text(&report, &mut writer).unwrap();
    let output = text(&report).lines().map(str::trim).collect::<String>();
    assert_eq!(
        output.matches(&payload).count(),
        2,
        "one full fact per side"
    );
    for index in 0..20 {
        assert!(output.contains(&format!("/lib/m{index}.so")));
        assert_eq!(
            output
                .matches(&format!("at least {} entries observed", 1_000 + index))
                .count(),
            2,
            "edge observations must survive on both sides"
        );
    }
    if field == "lifecycle" {
        assert!(output.contains(&format!("{payload} (unknown label)")));
    }
}

#[test]
fn review_r1_shared_caller_reason_does_not_expand_per_edge() {
    assert_shared_caller_field_is_not_amplified("lifecycle_reason");
}

#[test]
fn review_r1_shared_caller_start_time_unit_does_not_expand_per_edge() {
    assert_shared_caller_field_is_not_amplified("start_time_unit");
}

#[test]
fn review_r1_shared_unknown_caller_lifecycle_does_not_expand_per_edge() {
    assert_shared_caller_field_is_not_amplified("lifecycle");
}

#[test]
fn review_r2_module_only_admission_change_explains_both_endpoint_values() {
    let mut before = document();
    before["edges"] = json!([]);
    before["gaps"] = json!([]);
    let mut after = before.clone();
    after["modules"][0]["admission"]["endpoints"] = json!(5);
    let report = report(&before, &after);
    assert!(report.application_changes.is_empty());
    assert!(report.module_path_changes.is_empty());
    assert_eq!(report.module_contents[0].changes, ["admission"]);
    let output = text(&report);
    for expected in [
        "Module content",
        "Changed observations: admission",
        "/scale/m0.so",
        "Endpoints: 4",
        "Endpoints: 5",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
    assert!(!output.contains("No differences in the compared inventory observations"));
    assert!(
        text(&super::compare::compare(
            &snapshot(&before),
            &snapshot(&before)
        ))
        .contains("No differences in the compared inventory observations")
    );
}

#[test]
fn review_r2_module_only_admission_history_change_explains_each_side() {
    let mut before = document();
    before["edges"] = json!([]);
    before["gaps"] = json!([]);
    before["modules"][0]["admission"]["history"] = json!([
        {"from": "unresolved", "to": "admitted", "at_ns": 110}
    ]);
    let mut after = before.clone();
    after["modules"][0]["admission"]["history"][0]["from"] = json!("refused");
    after["modules"][0]["admission"]["history"][0]["at_ns"] = json!(120);
    let report = report(&before, &after);
    assert!(report.application_changes.is_empty());
    assert_eq!(report.module_contents[0].changes, ["admission"]);
    let output = text(&report);
    for expected in [
        "Changed observations: admission",
        "unresolved -> admitted at 110",
        "refused -> admitted at 120",
    ] {
        assert!(output.contains(expected), "missing {expected:?}: {output}");
    }
}

fn history_documents(before_unit: &str, after_unit: &str) -> (Value, Value) {
    let mut before = document();
    before["edges"] = json!([]);
    before["gaps"] = json!([]);
    before["clock"]["unit"] = json!(before_unit);
    before["modules"][0]["admission"]["history"] = json!([
        {"from": "unresolved", "to": "admitted", "at_ns": 110}
    ]);
    let mut after = before.clone();
    after["clock"]["unit"] = json!(after_unit);
    after["modules"][0]["admission"]["history"][0] = json!({
        "from": "refused", "to": "admitted", "at_ns": 120
    });
    (before, after)
}

#[test]
fn review_r3_history_timestamps_keep_unknown_units_on_their_own_side() {
    let (before, after) = history_documents("future_ticks", "ns");
    let report = report(&before, &after);
    assert!(
        report
            .limitations
            .iter()
            .any(|code| code == "unknown_clock_unit")
    );
    let output = text(&report);
    assert!(output.contains("unresolved -> admitted at 110 (clock unit unknown)"));
    assert!(!output.contains("unresolved -> admitted at 110 ns"));
    assert!(output.contains("refused -> admitted at 120 ns"));
    assert!(output.contains("future_ticks"));
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["before"]["clock"]["unit"], "future_ticks");
    assert_eq!(json["after"]["clock"]["unit"], "ns");
    assert_eq!(
        json["before"]["evidence"]["modules"][0]["admission"]["history"][0]["at_ns"],
        110
    );
    assert_eq!(
        json["after"]["evidence"]["modules"][0]["admission"]["history"][0]["at_ns"],
        120
    );
}

#[test]
fn review_r3_known_nanosecond_history_keeps_the_published_unit() {
    let (before, after) = history_documents("ns", "ns");
    let report = report(&before, &after);
    let output = text(&report);
    assert!(output.contains("unresolved -> admitted at 110 ns"));
    assert!(output.contains("refused -> admitted at 120 ns"));
    assert!(!output.contains("clock unit unknown"));
}

#[test]
fn review_r3_shared_unknown_clock_unit_is_not_repeated_per_transition() {
    let unit = format!("SHARED_UNKNOWN_CLOCK_UNIT_{}", "x".repeat(12_000));
    let (mut before, _) = history_documents(&unit, &unit);
    before["modules"][0]["admission"]["history"] = json!(
        (0..20)
            .map(|index| json!({"from": "unresolved", "to": "admitted", "at_ns": 1_000 + index}))
            .collect::<Vec<_>>()
    );
    let report = report(&before, &before);
    let mut writer = CountingWriter {
        accepted: 0,
        ceiling: 100_000,
    };
    render_text(&report, &mut writer).unwrap();
    let output = text(&report).lines().map(str::trim).collect::<String>();
    assert_eq!(
        output.matches(&unit).count(),
        2,
        "raw clock unit once per side"
    );
    for index in 0..20 {
        assert_eq!(
            output
                .matches(&format!("at {} (clock unit unknown)", 1_000 + index))
                .count(),
            2,
            "all raw recorded timestamps must survive on both sides"
        );
        assert!(!output.contains(&format!("at {} ns", 1_000 + index)));
    }
}

fn args() -> (tempfile::TempDir, InventoryDiffArgs) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, FIXTURE).unwrap();
    std::fs::write(&after, FIXTURE).unwrap();
    (
        dir,
        InventoryDiffArgs {
            before,
            after,
            json: true,
            out: None,
        },
    )
}

struct FailingWriter {
    kind: io::ErrorKind,
    flush_only: bool,
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.flush_only {
            Ok(bytes.len())
        } else {
            Err(self.kind.into())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(self.kind.into())
    }
}

#[test]
fn injectable_writer_handles_write_and_flush_failure_kinds_honestly() {
    let (_dir, args) = args();
    for flush_only in [false, true] {
        let mut closed = FailingWriter {
            kind: io::ErrorKind::BrokenPipe,
            flush_only,
        };
        assert_eq!(super::run_with_writer(&args, &mut closed).unwrap(), 0);
        let mut failed = FailingWriter {
            kind: io::ErrorKind::StorageFull,
            flush_only,
        };
        let error = super::run_with_writer(&args, &mut failed).unwrap_err();
        assert!(format!("{error:#}").contains("stdout"));
    }
}

#[test]
fn publication_precedes_any_stdout_attempt_even_when_stdout_fails() {
    let (dir, mut args) = args();
    let path = dir.path().join("report.json");
    args.out = Some(path.clone());
    struct VerifySaved<'a>(&'a std::path::Path);
    impl Write for VerifySaved<'_> {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            let saved: Value = serde_json::from_slice(&std::fs::read(self.0).unwrap()).unwrap();
            assert_eq!(saved["schema"], "p11scope/inventory-diff/v1");
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    assert_eq!(
        super::run_with_writer(&args, &mut VerifySaved(&path)).unwrap(),
        0
    );
}

#[test]
fn destination_replaced_by_an_input_hardlink_at_precommit_is_refused() {
    let (dir, mut args) = args();
    let path = dir.path().join("report.json");
    std::fs::write(&path, b"old report").unwrap();
    args.out = Some(path.clone());
    let mut output = Vec::new();
    let error = super::run_with_writer_before_commit(&args, &mut output, || {
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&args.before, &path).unwrap();
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("input alias"), "{error:#}");
    assert!(output.is_empty());
    assert_eq!(std::fs::read(&args.before).unwrap(), FIXTURE);
    assert_eq!(std::fs::read(&args.after).unwrap(), FIXTURE);
    assert_eq!(std::fs::read(&path).unwrap(), FIXTURE);
}

#[test]
fn retained_input_descriptor_detects_alias_after_the_original_path_is_replaced() {
    let (dir, mut args) = args();
    let path = dir.path().join("report.json");
    let retained = dir.path().join("retained-input.json");
    std::fs::write(&path, b"old report").unwrap();
    args.out = Some(path.clone());
    let mut output = Vec::new();
    let error = super::run_with_writer_before_commit(&args, &mut output, || {
        std::fs::rename(&args.before, &retained).unwrap();
        std::fs::write(&args.before, b"replacement input").unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&retained, &path).unwrap();
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("input alias"), "{error:#}");
    assert!(output.is_empty());
    assert_eq!(std::fs::read(&retained).unwrap(), FIXTURE);
    assert_eq!(std::fs::read(&args.before).unwrap(), b"replacement input");
    assert_eq!(std::fs::read(&args.after).unwrap(), FIXTURE);
}
