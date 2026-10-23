//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual scan command controls; installed native cells use the same driver.

use std::collections::BTreeSet;
use std::os::unix::fs::MetadataExt as _;
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
    let mut provider_ids = BTreeSet::new();
    for cell in receipt["cells"].as_array().unwrap() {
        let root = evidence.join(cell["label"].as_str().unwrap());
        let target: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("target.json")).unwrap()).unwrap();
        let pid = target["pid"].as_u64().unwrap();
        let providers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "so"))
            .collect();
        assert_eq!(
            providers.len(),
            if matches!(case, "large-slow" | "signal-progress") {
                96
            } else {
                1
            },
            "each cell has its complete owned provider inputs"
        );
        for provider in &providers {
            let metadata = std::fs::metadata(provider).unwrap();
            assert!(
                provider_ids.insert((metadata.dev(), metadata.ino())),
                "provider copies must retain distinct physical identities across cells"
            );
        }
        if without_report && cell["exit"] != 0 {
            continue; // A refused partial stdout document cannot supply scope evidence.
        }
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join(if without_report {
                "stdout.bin"
            } else {
                "report.json"
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(document["scope"], format!("pid:{pid}"));
        // Immediate capture cancellation can correctly commit an empty report.
        // The staged signal-progress cell and natural captures retain positives.
        if case == "signal-baseline" || case == "signal-stall" && cell["label"] == "baseline-one" {
            continue;
        }
        let caller = document["callers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|caller| caller["pid"] == pid)
            .expect("the actual owned workload was observed");
        for provider in &providers {
            let module = document["modules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|module| {
                    module["paths"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|path| path.as_str() == Some(provider.to_str().unwrap()))
                })
                .expect("an actual owned provider was observed");
            assert!(document["edges"].as_array().unwrap().iter().any(|edge| {
                edge["caller"] == caller["id"]
                    && edge["module"] == module["id"]
                    && edge["mapping"]["state"] == "mapped"
            }));
        }
    }
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

#[test]
fn additive_inline_identity_preserves_legacy_event_fields() {
    #[derive(serde::Deserialize)]
    struct LegacyEdge {
        caller: String,
        module: String,
        entries: serde_json::Value,
    }
    let legacy = r#"{"caller":"c7","module":"m2","entries":{"count":9}}"#;
    let additive = r#"{"caller":"c7","module":"m2","entries":{"count":9},"identity_context":{"version":1,"caller":{"id":"c7","status":"unavailable"},"module":{"id":"m2","status":"unavailable"}}}"#;
    for record in [legacy, additive] {
        let edge: LegacyEdge = serde_json::from_str(record).unwrap();
        assert_eq!(edge.caller, "c7");
        assert_eq!(edge.module, "m2");
        assert_eq!(edge.entries["count"], 9);
    }
    // A retained suffix with only legacy records still has no name authority.
    let old: serde_json::Value = serde_json::from_str(legacy).unwrap();
    assert!(old.get("identity_context").is_none());
}
