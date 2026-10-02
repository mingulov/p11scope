//! SPDX-License-Identifier: GPL-3.0-or-later
//! Public-command dashboard + event-stream tests (U0/U1 behaviors).
//!
//! Dashboard mode over owned fixtures (multi-provider, multi-caller),
//! non-TTY refusal-or-degrade honesty (a dashboard forced onto a pipe
//! degrades to snapshots, never ANSI-corrupted JSON), the interactive
//! PTY run (frame, `q`-quit, terminal restoration), and the JSONL
//! observation-event stream at command level (rotation, conservation,
//! hard errors).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture_source(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn matrix_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/discover/tests/fixture/version_matrix.c")
}

fn gcc(dir: &Path, out: &str, source: &Path, args: &[&str], libs: &[&str]) -> PathBuf {
    let bin = dir.join(out);
    let mut cmd = Command::new("gcc");
    cmd.args(args).arg("-o").arg(&bin).arg(source).args(libs);
    assert!(
        cmd.status().unwrap().success(),
        "gcc failed for {out}: {cmd:?}"
    );
    bin
}

/// An owned provider-mapping fixture process (a catalog-driver with
/// real dlopened providers), terminated and reaped on drop.
struct Driver {
    child: Option<std::process::Child>,
    pid: u32,
}

impl Driver {
    fn spawn(dir: &Path, name: &str, providers: &[&str]) -> Self {
        let driver = gcc(
            dir,
            &format!("{name}-driver"),
            &fixture_source("catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let mut libs = Vec::new();
        for soname in providers {
            libs.push(gcc(
                dir,
                soname,
                &matrix_source(),
                &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
                &[],
            ));
        }
        let ready = dir.join(format!("{name}.ready"));
        let _ = std::fs::remove_file(&ready);
        let child = Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg("--sleep")
            .arg("120")
            .args(&libs)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(&ready)
                && let Some(pid) = text.split_whitespace().nth(1)
            {
                break pid.parse::<u32>().unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "fixture {name} never became ready"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(pid, child.id(), "ready pid is the spawned driver");
        Self {
            child: Some(child),
            pid,
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        unsafe {
            libc::kill(child.id() as i32, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) if Instant::now() >= deadline => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn observer(pid: u32, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .arg("inventory")
        .arg("--pid")
        .arg(pid.to_string())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

#[test]
fn dashboard_on_pipe_degrades_to_snapshots_never_ansi() {
    let dir = tmp("inventory-dashboard-degrade");
    let _driver = Driver::spawn(&dir, "degrade", &["dg-p1.so", "dg-p2.so"]);
    // Multi-provider, one caller: both providers map the owned pid.
    let output = observer(_driver.pid, &["--dashboard"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "degraded run exits 0: {stderr}");
    assert!(
        stderr.contains("degraded to pager snapshots"),
        "honest degrade notice: {stderr}"
    );
    assert!(
        !output.stdout.contains(&0x1b),
        "no ANSI on the degraded pipe"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with(&format!("inventory pid:{}", _driver.pid)),
        "{stdout}"
    );
    // The owned edges render with the full dashboard state columns.
    for soname in ["dg-p1.so", "dg-p2.so"] {
        assert!(stdout.contains(soname), "owned {soname} visible: {stdout}");
    }
    assert!(stdout.contains("presence mapped"), "{stdout}");
    assert!(stdout.contains("capture armed"), "{stdout}");
    assert!(stdout.contains("activity quiet"), "{stdout}");
    assert!(
        stdout.contains("unknown (semantic capture withheld)"),
        "{stdout}"
    );
    assert!(stdout.contains("budgets:"), "{stdout}");
}

#[test]
fn dashboard_json_on_pipe_is_clean_and_parseable() {
    let dir = tmp("inventory-dashboard-json");
    let _driver = Driver::spawn(&dir, "json", &["dj-p1.so"]);
    let output = observer(_driver.pid, &["--dashboard", "--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "degraded JSON run exits 0: {stderr}"
    );
    assert!(
        stderr.contains("degraded"),
        "honest degrade notice: {stderr}"
    );
    assert!(!output.stdout.contains(&0x1b), "no ANSI in JSON bytes");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["schema"], "p11scope/inventory/v1");
    let callers = document["callers"].as_array().unwrap();
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0]["pid"], _driver.pid);
    let modules = document["modules"].as_array().unwrap();
    assert!(
        modules.iter().any(|module| module["paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|path| path.as_str().unwrap().ends_with("dj-p1.so"))),
        "owned provider in the document"
    );
}

#[test]
fn dashboard_multi_caller_system_subset_over_owned_fixtures() {
    let dir = tmp("inventory-dashboard-system");
    let _a = Driver::spawn(&dir, "sysa", &["sa-p1.so"]);
    let _b = Driver::spawn(&dir, "sysb", &["sb-p1.so"]);
    // Whole-machine dashboard, degraded to a snapshot on the pipe:
    // the owned multi-caller subset is asserted, the rest of the
    // machine may appear freely.
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .arg("inventory")
        .arg("--system")
        .arg("--max-scan-pids")
        .arg("4096")
        .arg("--dashboard")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "system degraded run exits 0: {stderr}"
    );
    assert!(!output.stdout.contains(&0x1b), "no ANSI on the pipe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for pid in [_a.pid, _b.pid] {
        assert!(
            stdout.contains(&format!("pid {pid}")),
            "owned caller {pid} visible"
        );
    }
    for soname in ["sa-p1.so", "sb-p1.so"] {
        assert!(stdout.contains(soname), "owned {soname} visible");
    }
}

#[test]
fn event_stream_command_level_with_rotation_and_conservation() {
    let dir = tmp("inventory-dashboard-events");
    let _driver = Driver::spawn(&dir, "events", &["ev-p1.so"]);
    let stream = dir.join("events.jsonl");
    // First: no rotation (wide threshold) — stream gaps equal the
    // document gaps exactly.
    let output = observer(
        _driver.pid,
        &[
            "--json",
            "--event-log",
            stream.to_str().unwrap(),
            "--event-rotate-bytes",
            "1M",
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "event run exits 0: {stderr}");
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    let body = std::fs::read_to_string(&stream).unwrap();
    let lines: Vec<Value> = body
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(!lines.is_empty());
    for line in &lines {
        assert_eq!(line["schema"], "p11scope/inventory-events/v1");
    }
    let kinds: Vec<&str> = lines
        .iter()
        .map(|line| line["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"started"), "{kinds:?}");
    assert!(kinds.contains(&"pass_committed"), "{kinds:?}");
    assert!(kinds.contains(&"ended"), "{kinds:?}");
    let stream_gaps: Vec<&Value> = lines
        .iter()
        .filter(|line| line["kind"] == "gap_recorded")
        .map(|line| &line["event"])
        .collect();
    let document_gaps = document["gaps"].as_array().unwrap();
    assert_eq!(stream_gaps.len(), document_gaps.len());
    for (stream, snapshot) in stream_gaps.iter().zip(document_gaps.iter()) {
        assert_eq!(stream, &snapshot);
    }
    // Second: a tiny threshold forces rotation + eviction; exact
    // conservation (retained + accounted == emitted) holds.
    let stream2 = dir.join("events2.jsonl");
    let output = observer(
        _driver.pid,
        &[
            "--json",
            "--event-log",
            stream2.to_str().unwrap(),
            "--event-rotate-bytes",
            "1K",
            "--event-max-files",
            "2",
        ],
    );
    assert!(output.status.success(), "rotating run exits 0: {stderr}");
    let mut all: Vec<Value> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "events2.jsonl" || name.starts_with("events2.jsonl.") {
            for line in std::fs::read_to_string(entry.path()).unwrap().lines() {
                all.push(serde_json::from_str(line).unwrap());
            }
        }
    }
    assert!(all.iter().any(|line| line["kind"] == "rotated"), "rotated");
    let emitted = all
        .iter()
        .map(|line| line["seq"].as_u64().unwrap())
        .max()
        .unwrap()
        + 1;
    let accounted: u64 = all
        .iter()
        .filter(|line| line["kind"] == "retention_evicted")
        .map(|line| {
            line["event"]["evicted_events"].as_u64().unwrap()
                + line["event"]["covered_events"].as_u64().unwrap()
        })
        .sum();
    assert_eq!(
        all.len() as u64 + accounted,
        emitted,
        "retained + accounted == emitted"
    );
}

#[test]
fn unwritable_event_log_is_a_hard_error() {
    let dir = tmp("inventory-dashboard-event-err");
    let _driver = Driver::spawn(&dir, "eventerr", &["ee-p1.so"]);
    let output = observer(
        _driver.pid,
        &["--event-log", "/proc/nonexistent-dir/events.jsonl"],
    );
    assert!(!output.status.success(), "unwritable stream fails");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("event stream"), "{stderr}");
    assert!(output.stdout.is_empty(), "no report on hard error");
}

#[test]
fn dashboard_interactive_over_pty_exits_clean() {
    let dir = tmp("inventory-dashboard-pty");
    let _driver = Driver::spawn(&dir, "pty", &["pty-p1.so", "pty-p2.so"]);
    // The stdlib-pty driver (single-threaded fork, deadlines, kill on
    // timeout) owns the terminal: frame, `q`-quit, restoration.
    let output = Command::new("python3")
        .arg(fixture_source("dashboard-pty-drive.py"))
        .arg(env!("CARGO_BIN_EXE_p11scope"))
        .arg(_driver.pid.to_string())
        .arg("60")
        .arg("90")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "pty drive passed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("PASS"), "{stdout}");
}
