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
