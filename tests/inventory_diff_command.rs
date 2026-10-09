//! SPDX-License-Identifier: GPL-3.0-or-later
//! Offline public-command contracts; every input is owned or read-only.

use serde_json::{Value, json};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const FIXTURE: &[u8] = include_bytes!("fixtures/inventory-diff/scan-current.json");

fn document() -> Value {
    serde_json::from_slice(FIXTURE).unwrap()
}

fn inputs() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, FIXTURE).unwrap();
    std::fs::write(&after, FIXTURE).unwrap();
    (dir, before, after)
}

fn command(before: &Path, after: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_p11scope"));
    command.args(["inventory", "diff"]).arg(before).arg(after);
    command.stdin(Stdio::null());
    command
}

fn success(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}

#[test]
fn different_content_is_informational_and_names_the_application_and_module() {
    let (_dir, before, after) = inputs();
    let mut changed = document();
    changed["modules"][0]["identity"]["sha256"] = json!("b".repeat(64));
    std::fs::write(&after, serde_json::to_vec(&changed).unwrap()).unwrap();
    let output = command(&before, &after).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "1 application group changed",
        "/bin/driver",
        "m0.so",
        "/scale/m0.so",
        "Different module content observed at this path",
        "Not observed after does not prove removal",
    ] {
        assert!(text.contains(expected), "missing {expected:?}: {text}");
    }
    let output = command(&before, &after).arg("--json").output().unwrap();
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "p11scope/inventory-diff/v1");
    assert_eq!(report["summary"]["application_groups_changed"], 1);
    assert_eq!(report["summary"]["content_before_only"], 1);
    assert_eq!(report["summary"]["content_after_only"], 1);
    assert_eq!(report["summary"]["module_paths_changed"], 1);
    assert!(output.stdout.ends_with(b"\n"));
    assert!(!output.stdout.ends_with(b"\n\n"));
    assert!(output.stderr.is_empty());
}

#[test]
fn unchanged_and_partial_evidence_still_exit_zero_with_honest_limits() {
    let (_dir, before, after) = inputs();
    let output = command(&before, &after).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "No differences in the compared inventory observations",
        "scope completeness",
        "unknown",
        "independent observation windows",
        "Instance and detailed semantic changes are not compared",
        "fixture coverage unknown",
    ] {
        assert!(text.contains(expected), "missing {expected:?}: {text}");
    }
    assert!(!text.contains("machine unchanged"));
    assert!(!text.as_bytes().contains(&0x1b));
}

#[test]
fn review_r1_caller_fanout_keeps_the_complete_text_document_bounded() {
    let (_dir, before, after) = inputs();
    let mut value = document();
    value["gaps"] = json!([]);
    let mut payloads = Vec::new();
    for field in ["lifecycle_reason", "start_time_unit", "lifecycle"] {
        let payload = format!("FULL_{field}_{}", "x".repeat(12_000));
        value["callers"][0][field] = json!(payload);
        payloads.push(payload);
    }
    let mut modules = Vec::new();
    let mut edges = Vec::new();
    for index in 0..20 {
        let mut module = value["modules"][0].clone();
        module["id"] = json!(format!("m{index}"));
        module["identity"]["inode"] = json!(100_000 + index);
        module["paths"] = json!([format!("/lib/m{index}.so")]);
        let mut edge = value["edges"][0].clone();
        edge["module"] = json!(format!("m{index}"));
        modules.push(module);
        edges.push(edge);
    }
    value["modules"] = json!(modules);
    value["edges"] = json!(edges);
    for resource in ["modules", "edges", "inventory_attach_modules"] {
        value["budgets"][resource]["occupied"] = json!(20);
    }
    let bytes = serde_json::to_vec(&value).unwrap();
    std::fs::write(&before, &bytes).unwrap();
    std::fs::write(&after, &bytes).unwrap();
    let output = command(&before, &after).output().unwrap();
    success(&output);
    assert!(
        output.stdout.len() < 180_000,
        "whole text buffer amplified pooled caller facts: {} bytes",
        output.stdout.len()
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let joined = text.lines().map(str::trim).collect::<String>();
    for payload in &payloads {
        assert_eq!(
            joined.matches(payload).count(),
            2,
            "full evidence once per side"
        );
    }
    for index in 0..20 {
        assert!(joined.contains(&format!("/lib/m{index}.so")));
    }
    let output = command(&before, &after).arg("--json").output().unwrap();
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["before"]["evidence"]["callers"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        report["before"]["evidence"]["edge_occurrences"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
    for (field, payload) in ["lifecycle_reason", "start_time_unit", "lifecycle"]
        .into_iter()
        .zip(payloads)
    {
        assert_eq!(report["before"]["evidence"]["callers"][0][field], payload);
        assert_eq!(report["after"]["evidence"]["callers"][0][field], payload);
    }
}

#[test]
fn review_r2_module_only_admission_change_is_visible_in_the_default_report() {
    let (_dir, before, after) = inputs();
    let mut value = document();
    value["edges"] = json!([]);
    value["gaps"] = json!([]);
    std::fs::write(&before, serde_json::to_vec(&value).unwrap()).unwrap();
    value["modules"][0]["admission"]["endpoints"] = json!(5);
    std::fs::write(&after, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = command(&before, &after).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Changed observations: admission",
        "/scale/m0.so",
        "Endpoints: 4",
        "Endpoints: 5",
    ] {
        assert!(text.contains(expected), "missing {expected:?}: {text}");
    }
    assert!(!text.contains("No differences in the compared inventory observations"));
    let output = command(&before, &after).arg("--json").output().unwrap();
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["module_contents"][0]["changes"],
        json!(["admission"])
    );
    assert_eq!(report["application_changes"], json!([]));
    assert_eq!(report["module_path_changes"], json!([]));
    assert_eq!(
        report["before"]["evidence"]["modules"][0]["admission"]["endpoints"],
        4
    );
    assert_eq!(
        report["after"]["evidence"]["modules"][0]["admission"]["endpoints"],
        5
    );
}

fn history_inputs(unit: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let (dir, before, after) = inputs();
    let mut value = document();
    value["edges"] = json!([]);
    value["gaps"] = json!([]);
    value["clock"]["unit"] = json!(unit);
    value["modules"][0]["admission"]["history"] = json!([
        {"from": "unresolved", "to": "admitted", "at_ns": 110}
    ]);
    std::fs::write(&before, serde_json::to_vec(&value).unwrap()).unwrap();
    value["modules"][0]["admission"]["history"][0] = json!({
        "from": "refused", "to": "admitted", "at_ns": 120
    });
    std::fs::write(&after, serde_json::to_vec(&value).unwrap()).unwrap();
    (dir, before, after)
}

#[test]
fn review_r3_unknown_clock_history_keeps_raw_values_and_unit_uncertainty() {
    let (_dir, before, after) = history_inputs("future_ticks");
    let output = command(&before, &after).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "unresolved -> admitted at 110 (clock unit unknown)",
        "refused -> admitted at 120 (clock unit unknown)",
        "future_ticks",
        "unknown_clock_unit",
    ] {
        assert!(text.contains(expected), "missing {expected:?}: {text}");
    }
    assert!(!text.contains("admitted at 110 ns"));
    assert!(!text.contains("admitted at 120 ns"));
    let output = command(&before, &after).arg("--json").output().unwrap();
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    for side in ["before", "after"] {
        assert_eq!(report[side]["clock"]["unit"], "future_ticks");
    }
    assert!(
        report["limitations"]
            .as_array()
            .unwrap()
            .contains(&json!("unknown_clock_unit"))
    );
    assert_eq!(
        report["before"]["evidence"]["modules"][0]["admission"]["history"][0]["at_ns"],
        110
    );
    assert_eq!(
        report["after"]["evidence"]["modules"][0]["admission"]["history"][0]["at_ns"],
        120
    );
}

#[test]
fn review_r3_known_nanosecond_history_preserves_the_published_unit() {
    let (_dir, before, after) = history_inputs("ns");
    let output = command(&before, &after).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("unresolved -> admitted at 110 ns"));
    assert!(text.contains("refused -> admitted at 120 ns"));
    assert!(!text.contains("clock unit unknown"));
}

#[test]
fn scoped_help_is_offline_and_publishes_input_bounds() {
    for help in ["--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
            .args(["inventory", "diff", help])
            .output()
            .unwrap();
        success(&output);
        let text = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "inventory diff",
            "BEFORE",
            "AFTER",
            "--json",
            "64 MiB",
            "250,000",
            "16,384",
            "64",
            "2,000,000",
        ] {
            assert!(text.contains(expected), "missing {expected:?}: {text}");
        }
        assert!(!text.contains("--pid"));
        assert!(!text.contains("CAP_BPF"));
    }
}

#[test]
fn usage_errors_are_two_and_do_not_read_inputs() {
    for words in [
        vec!["inventory", "diff"],
        vec!["inventory", "diff", "a"],
        vec!["inventory", "diff", "a", "b", "c"],
        vec!["inventory", "diff", "a", "b", "--json", "--json"],
        vec!["inventory", "diff", "a", "b", "-o"],
        vec!["inventory", "diff", "a", "b", "-o", "x", "-o", "y"],
        vec!["inventory", "diff", "a", "b", "-o", "-"],
        vec!["inventory", "diff", "-", "b"],
        vec!["inventory", "diff", "a", "b", "--pid", "7"],
        vec!["inventory", "diff", "a", "b", "--system"],
        vec!["inventory", "diff", "a", "b", "--capture", "scan"],
        vec!["inventory", "diff", "a", "b", "--duration", "1s"],
        vec!["inventory", "diff", "a", "b", "--dashboard"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
            .args(&words)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{words:?}: {output:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn os_paths_and_the_option_terminator_preserve_input_bytes() {
    let (dir, before, after) = inputs();
    let name = OsString::from_vec(b"before-\xff.json".to_vec());
    let non_utf8 = dir.path().join(&name);
    std::fs::rename(&before, &non_utf8).unwrap();
    let dash = dir.path().join("-after.json");
    std::fs::rename(&after, &dash).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .current_dir(dir.path())
        .args(["inventory", "diff", "--json", "--"])
        .arg(name)
        .arg("-after.json")
        .output()
        .unwrap();
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["summary"]["application_groups_changed"], 0);
}

#[test]
fn malformed_input_diagnostics_escape_side_path_and_field() {
    let (dir, before, after) = inputs();
    let bad = dir.path().join("after\n\x1b.json");
    std::fs::rename(&after, &bad).unwrap();
    let mut value = document();
    value["schema"] = json!("wrong\n\x1b");
    std::fs::write(&bad, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = command(&before, &bad).output().unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(
        diagnostic.contains("after") && diagnostic.contains("schema"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("\\n") && diagnostic.contains("\\u{1b}"),
        "{diagnostic}"
    );
    assert_eq!(diagnostic.lines().count(), 1, "{diagnostic}");
    assert!(!diagnostic.as_bytes().contains(&0x1b));
}

#[test]
fn text_escapes_labels_but_json_preserves_decoded_data() {
    let (_dir, before, after) = inputs();
    let mut value = document();
    value["callers"][0]["image"]["exe"]["path"] = json!("/bin/app\n\x1b[31m");
    value["modules"][0]["paths"] = json!(["/lib/module\t\r.so"]);
    value["modules"][0]["admission"]["note"] = json!("why\n\x1b");
    std::fs::write(&after, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = command(&before, &after).output().unwrap();
    success(&output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("/bin/app\\n\\u{1b}[31m"), "{text}");
    assert!(text.contains("/lib/module\\t\\r.so"), "{text}");
    assert!(!text.as_bytes().contains(&0x1b));
    let output = command(&before, &after).arg("--json").output().unwrap();
    success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["comparison"]["application_paths"]
            .as_array()
            .unwrap()
            .contains(&json!("/bin/app\n\x1b[31m"))
    );
}

#[test]
fn saved_report_equals_the_json_stdout_document() {
    let (dir, before, after) = inputs();
    let out = dir.path().join("report.json");
    std::fs::write(&out, b"old report").unwrap();
    let output = command(&before, &after)
        .arg("--json")
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    success(&output);
    assert_eq!(std::fs::read(&out).unwrap(), output.stdout);
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["schema"],
        "p11scope/inventory-diff/v1"
    );
}

#[test]
fn output_aliases_are_refused_without_changing_either_input() {
    let (dir, before, after) = inputs();
    let hardlink = dir.path().join("hardlink.json");
    let symlink = dir.path().join("symlink.json");
    std::fs::hard_link(&after, &hardlink).unwrap();
    std::os::unix::fs::symlink(&before, &symlink).unwrap();
    let normalized = dir.path().join("child/../before.json");
    std::fs::create_dir(dir.path().join("child")).unwrap();
    for out in [&before, &after, &hardlink, &symlink, &normalized] {
        let output = command(&before, &after)
            .arg("-o")
            .arg(out)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "{out:?}: {output:?}");
        let reason = String::from_utf8(output.stderr).unwrap();
        assert!(
            reason.contains("input") && reason.contains("alias"),
            "{reason}"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read(&before).unwrap(), FIXTURE);
        assert_eq!(std::fs::read(&after).unwrap(), FIXTURE);
    }
}

#[test]
fn invalid_after_input_preserves_an_existing_report() {
    let (dir, before, after) = inputs();
    let out = dir.path().join("report.json");
    std::fs::write(&out, b"old report").unwrap();
    std::fs::write(&after, b"{\"schema\": \"wrong\"}").unwrap();
    let output = command(&before, &after)
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(out).unwrap(), b"old report");
}

#[test]
fn unusable_report_directory_keeps_existing_reports_and_inputs() {
    let (dir, before, after) = inputs();
    let old = dir.path().join("old.json");
    std::fs::write(&old, b"old report").unwrap();
    let output = command(&before, &after)
        .arg("-o")
        .arg(old.join("report.json"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read(old).unwrap(), b"old report");
    assert_eq!(std::fs::read(before).unwrap(), FIXTURE);
    assert_eq!(std::fs::read(after).unwrap(), FIXTURE);
}

#[test]
fn closed_stdout_is_success_after_the_requested_report_is_saved() {
    let (dir, before, after) = inputs();
    let out = dir.path().join("report.json");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = command(&before, &after)
        .arg("--json")
        .arg("-o")
        .arg(&out)
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    success(&output);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(out).unwrap()).unwrap()["schema"],
        "p11scope/inventory-diff/v1"
    );
}

#[test]
fn closed_stdout_without_a_report_is_also_success() {
    let (_dir, before, after) = inputs();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = command(&before, &after)
        .arg("--json")
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    success(&output);
}

#[test]
fn non_broken_pipe_stdout_errors_fail() {
    let (_dir, before, after) = inputs();
    let full = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let output = command(&before, &after)
        .arg("--json")
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8(output.stderr).unwrap().contains("stdout"));
}

#[test]
fn a_stopped_stdout_reader_hits_the_existing_inactivity_bound() {
    let (_dir, before, after) = inputs();
    let mut value = document();
    let mut modules = Vec::new();
    for index in 0..12 {
        let mut module = value["modules"][0].clone();
        module["id"] = json!(format!("m{index}"));
        module["identity"]["inode"] = json!(100000 + index);
        module["admission"]["note"] = json!("n".repeat(12_000));
        modules.push(module);
    }
    value["modules"] = json!(modules);
    std::fs::write(&after, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut child = command(&before, &after)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(9) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("offline stdout blocked beyond its inactivity bound");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let output = child.wait_with_output().unwrap();
    assert_eq!(status.code(), Some(1), "{output:?}");
    let reason = String::from_utf8(output.stderr).unwrap();
    assert!(
        reason.contains("stdout") && reason.contains("progress"),
        "{reason}"
    );
}
