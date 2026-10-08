//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual scan command controls; installed native cells use the same driver.

use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn control_mode(case: &str, without_report: bool) {
    static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = SERIAL
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let evidence = tempfile::tempdir().unwrap().keep();
    let mut command = Command::new("python3");
    command
        .arg("-I")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/inventory-output-drive.py"
        ))
        .args([
            "--binary",
            env!("CARGO_BIN_EXE_p11scope"),
            "--capture",
            "scan",
            "--case",
            case,
            "--evidence-dir",
        ])
        .arg(&evidence);
    if without_report {
        command.env("P11SCOPE_INVENTORY_OUTPUT_NO_REPORT", "1");
    }
    let output = command.output().unwrap();
    let receipt = std::fs::read(evidence.join("control.json")).unwrap_or_default();
    assert!(
        output.status.success(),
        "{case}: {}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&receipt)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
    assert_eq!(receipt["success"], true);
    assert_eq!(receipt["capture"], "scan");
    assert!(
        receipt["cells"]
            .as_array()
            .is_some_and(|cells| !cells.is_empty())
    );
    println!(
        "inventory-output-control {case}: evidence={}, {receipt}",
        evidence.display()
    );
}

fn control(case: &str) {
    control_mode(case, false);
}

#[test]
fn pipe_stall() {
    control("pipe-stall");
}
#[test]
fn tty_stall() {
    control("tty-stall");
}
#[test]
fn tty_shared_stderr() {
    control("tty-shared-stderr");
}
#[test]
fn dashboard_json_stall() {
    control("dashboard-json-stall");
}
#[test]
fn xoff_resume() {
    control("xoff-resume");
}
#[test]
fn large_slow() {
    control("large-slow");
}
#[test]
fn signal_baseline() {
    control("signal-baseline");
}
#[test]
fn signal_stall() {
    control("signal-stall");
}
#[test]
fn signal_progress() {
    control("signal-progress");
}

// These additional controls establish eligible stdout behavior where the
// environment refuses trusted -o/event ancestors. Required independent-report
// cells above remain strict and pending; these cannot substitute for them.
#[test]
fn pipe_stall_without_report() {
    control_mode("pipe-stall", true);
}
#[test]
fn tty_stall_without_report() {
    control_mode("tty-stall", true);
}
#[test]
fn tty_shared_stderr_without_report() {
    control_mode("tty-shared-stderr", true);
}
#[test]
fn dashboard_json_stall_without_report() {
    control_mode("dashboard-json-stall", true);
}
#[test]
fn xoff_resume_without_report() {
    control_mode("xoff-resume", true);
}
#[test]
fn large_slow_without_report() {
    control_mode("large-slow", true);
}
#[test]
fn signal_baseline_without_report() {
    control_mode("signal-baseline", true);
}
#[test]
fn signal_stall_without_report() {
    control_mode("signal-stall", true);
}
#[test]
fn signal_progress_without_report() {
    control_mode("signal-progress", true);
}
