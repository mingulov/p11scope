//! SPDX-License-Identifier: GPL-3.0-or-later
//! A second SIGINT while teardown is still settling must publish the `-o`
//! report before exiting 130: the public contract promises the report is
//! written at the quiescence point, before any probe link closes, and stays
//! intact across the abandon (`docs/usage.md`). Regression test for the
//! H7-entry gate `second-sigint` failure, where `sigint2.json` was missing.
//!
//! Privileged: the abandon path needs a real BPF attach session. Run as
//! root: `cargo test --test run_abandon_report -- --ignored
//! --test-threads=1`.

use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Distinctive argv[0] for the signal-ignoring child, so the stray check can
/// find a child the product failed to settle without matching anything else.
const STRAY_MARKER: &str = "abandon-probe-sleep";

/// Poll a growing file for a needle without forking (a forking wait would
/// admit newcomer processes mid-capture, the way the shell qualifier's
/// `sleep 0.1` polls do). Returns the full bytes observed.
fn wait_for(path: &std::path::Path, needle: &str, timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    while Instant::now() < deadline {
        bytes.clear();
        if let Ok(mut file) = std::fs::File::open(path)
            && file.read_to_end(&mut bytes).is_ok()
            && String::from_utf8_lossy(&bytes).contains(needle)
        {
            return bytes;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bytes
}

/// True when any live process still runs under the marker argv[0].
fn stray_child_present() -> bool {
    let Ok(proc) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in proc.flatten() {
        let name = entry.file_name();
        if !name.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let cmdline = entry.path().join("cmdline");
        let Ok(bytes) = std::fs::read(&cmdline) else {
            continue;
        };
        if bytes.starts_with(STRAY_MARKER.as_bytes()) {
            return true;
        }
    }
    false
}

#[test]
#[ignore = "privileged: loads BPF; run as root with --ignored --test-threads=1"]
fn second_sigint_during_teardown_publishes_truthful_report_and_exits_130() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "run as root: the abandon path needs a real attach session"
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let out = dir.path().join("abandoned.json");
    let stderr_path = dir.path().join("stderr");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    // Mirror the public `second-sigint` cell: the child ignores INT/TERM so
    // settlement is still in flight when the second SIGINT lands (the 5s
    // TERM grace dwarfs the 1s signal spacing).
    let mut observer = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["run", "-o"])
        .arg(&out)
        .args([
            "--",
            "bash",
            "-c",
            &format!("trap '' INT TERM; exec -a {STRAY_MARKER} sleep 60"),
        ])
        .stdout(Stdio::null())
        .stderr(stderr_file)
        .spawn()
        .expect("spawn p11scope run");
    let pid = observer.id() as libc::pid_t;
    let signal = |sig: libc::c_int| {
        assert_eq!(
            unsafe { libc::kill(pid, sig) },
            0,
            "signal {sig} to observer: {}",
            std::io::Error::last_os_error()
        );
    };
    wait_for(
        &stderr_path,
        "p11scope: capturing:",
        Duration::from_secs(60),
    );
    let diagnostics = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        diagnostics.contains("p11scope: capturing:"),
        "observer never reached capture: {diagnostics}"
    );
    // Let the live loop drain several ticks, so the report's drain samples
    // prove the document came from this capture.
    std::thread::sleep(Duration::from_secs(2));
    signal(libc::SIGINT);
    std::thread::sleep(Duration::from_secs(1));
    signal(libc::SIGINT);
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = observer.try_wait().expect("wait for observer") {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "observer still running 120s after the second SIGINT"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    // Exit 130 like any shell-interrupted command (SG-I7).
    assert_eq!(
        status.code(),
        Some(130),
        "abandon exit: {status:?}\n{diagnostics}"
    );
    let diagnostics = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        diagnostics.contains("p11scope: cleanup incomplete"),
        "stderr must say cleanup incomplete:\n{diagnostics}"
    );
    assert!(
        !diagnostics.contains("panicked"),
        "no panic on the abandon path:\n{diagnostics}"
    );
    // The published report: valid JSON with the profile schema. Either
    // seal path may run — quiescence may prove before the second signal
    // (normal publish, detach abandons after) or fail (error-path
    // publish) — so the test pins what both owe: PARTIAL (the
    // provider-free child leaves observation causes on every path) and
    // the owner-ruling-B consistency between `drain_proven` and the
    // stop-gate evidence.
    let text = std::fs::read_to_string(&out).expect("abandon must publish the -o report");
    let report: serde_json::Value =
        serde_json::from_str(&text).expect("abandon report must be valid JSON");
    assert_eq!(
        report.get("schema").and_then(serde_json::Value::as_str),
        Some("p11scope/observed-profile/v3"),
        "abandon report schema"
    );
    let evidence = report
        .get("evidence")
        .expect("abandon report carries evidence");
    assert_eq!(
        evidence
            .get("completeness")
            .and_then(serde_json::Value::as_str),
        Some("PARTIAL"),
        "an abandoned teardown cannot seal COMPLETE"
    );
    let stop = evidence
        .get("stop_quiescence")
        .expect("abandon report carries stop-gate evidence");
    let proven = stop.get("state").and_then(serde_json::Value::as_str) == Some("proven")
        && stop
            .get("post_q_events")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
        && stop
            .get("post_q_discovery")
            .and_then(serde_json::Value::as_bool)
            == Some(false);
    assert_eq!(
        evidence
            .get("drain_proven")
            .and_then(serde_json::Value::as_bool),
        Some(proven),
        "drain_proven must match the stop-gate evidence: {stop}"
    );
    assert!(
        evidence
            .get("scheduling")
            .and_then(|s| s.get("inter_drain_gap"))
            .and_then(|g| g.get("samples"))
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|samples| samples > 0),
        "report must carry this capture's live-loop drain samples"
    );
    assert!(
        !stray_child_present(),
        "the owned signal-ignoring child must be settled, not left running"
    );
}
