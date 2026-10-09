//! SPDX-License-Identifier: GPL-3.0-or-later
//! The same offline journey also accepts an explicit installed binary path.

use std::process::Command;

fn driver(arguments: &[&str]) {
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "tests/fixtures/cross-command-drive.py"])
        .args(arguments)
        .output()
        .expect("execute offline cross-command journey");
    assert!(
        output.status.success(),
        "offline journey: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn help_to_saved_inventory_diff_with_known_change_partial_and_safe_output() {
    driver(&["--binary", env!("CARGO_BIN_EXE_p11scope")]);
}

#[test]
fn offline_journey_failure_controls_reject_false_success() {
    driver(&["--self-test"]);
}

#[test]
fn ordinary_help_inspect_helper_and_scan_dashboard_journey() {
    let binary = env!("CARGO_BIN_EXE_p11scope");
    let helper = std::path::Path::new(binary).with_file_name("p11scope-discover");
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            "tests/fixtures/ordinary-command-drive.py",
            "--binary",
            binary,
        ])
        .arg("--helper")
        .arg(helper)
        .arg("--dashboard")
        .output()
        .expect("execute ordinary operator journey with workspace helper built");
    assert!(
        output.status.success(),
        "ordinary journey: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn ordinary_journey_rejects_wrong_physical_identity() {
    let output = Command::new("python3")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args([
            "-I",
            "tests/fixtures/ordinary-command-drive.py",
            "--self-test",
        ])
        .output()
        .expect("execute ordinary journey identity control");
    assert!(output.status.success(), "{output:?}");
}
