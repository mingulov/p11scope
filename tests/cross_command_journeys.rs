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

// U6 installed journeys (G22). Each selector always runs its synthetic twin
// red-green matrix: the committed gate fails if any twin inverts. With
// P11SCOPE_U6_DRY_RUN=1 the selector proves wiring without capturing; with
// the full installed seam it runs the live installed cells (the later gate).
// P11SCOPE_U6_RED_PROOF is proof-only (never set by the installed gate).

fn u6_driver(journey: &str, mode: &str, binary: Option<&str>) -> std::process::Output {
    let mut command = Command::new("python3");
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "tests/fixtures/u6-installed-drive.py"])
        .args(["--journey", journey, mode]);
    if let Some(path) = binary {
        command.args(["--binary", path]);
    }
    command
        .output()
        .expect("execute U6 installed journey driver")
}

fn u6_live(journey: &str, installed: &str) {
    // Installed live execution: every input arrives explicitly. A partial
    // seam fails closed; nothing is silently substituted or skipped.
    const PASSTHROUGH: &[(&str, &str)] = &[
        ("P11SCOPE_U6_SOURCE_REVISION", "--source-revision"),
        ("P11SCOPE_U6_OUT", "--out"),
        ("P11SCOPE_U6_C8_BASE", "--c8-base"),
        ("P11SCOPE_U6_COORDINATOR", "--workload-coordinator"),
        ("P11SCOPE_U6_PROVIDER", "--provider"),
        ("P11SCOPE_U6_CALLER", "--caller"),
        ("P11SCOPE_U6_MANIFEST_HELPER", "--manifest-helper"),
        ("P11SCOPE_U6_HELPER_REVISION", "--helper-source-revision"),
        ("P11SCOPE_U6_UID", "--uid"),
        ("P11SCOPE_U6_GID", "--gid"),
        ("P11SCOPE_U6_CELLS", "--cells"),
        ("P11SCOPE_U6_BEFORE", "--before"),
        ("P11SCOPE_U6_AFTER", "--after"),
        ("P11SCOPE_U6_PAIR_PREBUILT", "--pair-prebuilt"),
    ];
    let mut command = Command::new("python3");
    command
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["-I", "tests/fixtures/u6-installed-drive.py"])
        .args(["--journey", journey, "--binary", installed]);
    for &(env, flag) in PASSTHROUGH {
        if let Ok(value) = std::env::var(env) {
            command.args([flag, value.as_str()]);
        }
    }
    if let Ok(manifests) = std::env::var("P11SCOPE_U6_MANIFESTS") {
        for manifest in manifests.split(':') {
            command.args(["--manifest", manifest]);
        }
    }
    let output = command.output().expect("execute U6 installed live cells");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{journey} installed live cells failed: stdout={stdout} stderr={stderr}"
    );
    println!("u6 {journey} installed live cells passed");
}

fn u6_assert_twins(journey: &str) {
    // The twin matrix is the always-on gate: it must select every twin and
    // every red twin must fail inside the matrix (an inversion fails here).
    let output = u6_driver(journey, "--self-test", Some(env!("CARGO_BIN_EXE_p11scope")));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{journey} twin matrix failed: stdout={stdout} stderr={stderr}"
    );
    assert!(
        stdout.contains("\"mode\": \"self-test\"") && stdout.contains("\"twins\""),
        "{journey} twin matrix emitted no twin receipt: {stdout}"
    );
    let twins = stdout.matches("\"twin\":").count();
    assert!(
        twins >= 3,
        "{journey} twin matrix selected too few twins: {twins}"
    );
    println!("u6 {journey} twin matrix: {twins} twins green/red as declared");
}

fn u6_selector(journey: &str) {
    u6_assert_twins(journey);
    if std::env::var("P11SCOPE_U6_DRY_RUN").as_deref() == Ok("1") {
        let installed = std::env::var("P11SCOPE_U6_INSTALLED_BINARY").ok();
        let binary = installed
            .as_deref()
            .unwrap_or(env!("CARGO_BIN_EXE_p11scope"));
        if installed.is_none() {
            eprintln!("u6 {journey} dry-run: no installed seam; Cargo binary is a shape stand-in");
        }
        let output = u6_driver(journey, "--dry-run", Some(binary));
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{journey} dry-run failed: stdout={stdout} stderr={stderr}"
        );
        assert!(
            stdout.contains("\"mode\": \"dry-run\""),
            "{journey} dry-run emitted no plan: {stdout}"
        );
        println!("u6 {journey} dry-run wiring proven");
        return;
    }
    match std::env::var("P11SCOPE_U6_INSTALLED_BINARY") {
        // The later installed gate: the driver fails closed on any partial
        // seam, mismatch or unrunnable twin. Never runs unprivileged here.
        Ok(installed) => u6_live(journey, &installed),
        Err(_) => {
            eprintln!(
                "SKIP u6 {journey} live cells: P11SCOPE_U6_INSTALLED_BINARY is absent; \
                 twin matrix above is the committed gate"
            );
        }
    }
}

#[test]
fn installed_all_modes_match_owned_ledger() {
    u6_selector("ledger");
}

#[test]
fn installed_named_trace_positive_and_false_name_controls() {
    u6_selector("named-trace");
}
