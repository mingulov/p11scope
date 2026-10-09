//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual public-binary usage/refusal controls. Positive executable population
//! belongs to root's separately owned installed capture lane, never a fake feed.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn run(args: &[&str]) -> (i32, String, String) {
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_p11scope"))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "public command exceeded its owned deadline: {args:?}"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .0
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    (status.code().unwrap(), stdout, stderr)
}

#[test]
fn trace_identity_public_help_preserves_trace_entrypoints() {
    for args in [&["trace", "--help"][..], &["run", "--trace", "--help"][..]] {
        let (code, stdout, stderr) = run(args);
        assert_eq!(code, 0, "{stderr}");
        assert!(stdout.contains("--duration"), "{stdout}");
        if args[0] == "trace" {
            assert!(stdout.contains("--max-events"), "{stdout}");
        } else {
            assert!(stdout.contains("--trace"), "{stdout}");
        }
        assert!(
            !stdout.contains("task_cookie") && !stdout.contains("exec_id"),
            "{stdout}"
        );
    }
}

#[test]
fn trace_identity_public_zero_pid_refuses_before_capture() {
    let (code, stdout, stderr) = run(&["trace", "--pid", "0"]);
    assert_eq!(code, 2, "{stderr}");
    assert!(
        stderr.contains("--pid must be greater than zero"),
        "{stderr}"
    );
    assert!(stdout.is_empty(), "{stdout}");
    assert!(!stderr.contains("capture_ready"));
}

#[test]
fn trace_identity_public_owned_trace_metrics_refusal_never_starts_target() {
    let dir = tempfile::tempdir().unwrap();
    let started = dir.path().join("target-started");
    let (code, stdout, stderr) = run(&[
        "run",
        "--trace",
        "--mode",
        "metrics",
        "--",
        "/usr/bin/touch",
        started.to_str().unwrap(),
    ]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("has no --mode"), "{stderr}");
    assert!(stdout.is_empty(), "{stdout}");
    assert!(
        !started.exists(),
        "the refused trace must not start its owned command"
    );
}
