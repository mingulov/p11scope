//! SPDX-License-Identifier: GPL-3.0-or-later
//! Capture diagnostics must not park the observer on a stalled stderr,
//! nor let diagnostic delivery change the exit status (Sol-full F3).
//!
//! The refusal below fails fast before discovery runs — the required
//! host gate refuses without proven Multi capability, and the bad `-o`
//! path refuses where the gate proceeds — so the only stderr traffic is
//! the refusal itself plus a startup notice on eligible hosts. Under a full
//! or closed (EPIPE) stderr these diagnostics must shed instead of parking,
//! and the exit stays the refusal's 1 on every host. (A capture that
//! reaches discovery additionally prints discovery's own summary, whose
//! blocking writes live in `discovery/engine.rs`, outside this change;
//! the loop/attach/pause emissions are pinned by the
//! `capture_diagnostics_never_use_blocking_stderr_writes` shape test to
//! route through the same bounded helper.)

use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[path = "support/multi_host.rs"]
mod multi_host;

// The pipe belongs only to this test and its child. Fill it, then restore its
// original blocking flags: production must avoid waiting without changing them.
fn diagnostic_pipe(full: bool) -> (std::fs::File, std::fs::File) {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    let reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let mut writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    if full {
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        loop {
            match writer.write(&[b'x'; 4096]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("filling owned diagnostic pipe: {error}"),
            }
        }
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags) },
            0
        );
    }
    (reader, writer)
}

/// A `-o` path that can never open: the refusal fires before discovery.
fn unopenable_output() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("capture-stderr-absent-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("out.json")
}

fn refusal_args(kind: &str, out: &std::path::Path) -> Vec<String> {
    vec![
        kind.to_string(),
        "--system".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ]
}

#[test]
fn full_or_closed_stderr_preserves_capture_exit_status() {
    let host_refusal = multi_host::refusal();
    let out = unopenable_output();
    let mut observed = Vec::new();
    for kind in ["profile", "trace"] {
        // Baseline: the same refusal with a healthy stderr. It exits 1 on
        // every host before discovery. The required Multi gate precedes
        // the startup notice; a draining reader must receive the exact
        // named host refusal or the eligible-host startup notice.
        let baseline = Command::new(env!("CARGO_BIN_EXE_p11scope"))
            .args(refusal_args(kind, &out))
            .stdin(Stdio::null())
            .output()
            .expect("run baseline refusal");
        assert_eq!(baseline.status.code(), Some(1), "{kind} baseline");
        let baseline_stderr = String::from_utf8(baseline.stderr).expect("stderr is UTF-8");
        match &host_refusal {
            Some(reason) => assert_eq!(baseline_stderr, format!("p11scope: {reason}\n")),
            None => assert!(
                baseline_stderr.contains("no --duration given"),
                "{kind} baseline lost its startup notice: {baseline_stderr}"
            ),
        }
        for full in [false, true] {
            let (reader, writer) = diagnostic_pipe(full);
            let retained_writer = writer.try_clone().unwrap();
            let flags = unsafe { libc::fcntl(retained_writer.as_raw_fd(), libc::F_GETFL) };
            assert!(flags >= 0);
            let reader = full.then_some(reader); // Otherwise close the reader before spawn.
            let mut child = Command::new(env!("CARGO_BIN_EXE_p11scope"))
                .args(refusal_args(kind, &out))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(writer)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    child.wait().unwrap();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            drop(reader);
            assert_eq!(
                unsafe { libc::fcntl(retained_writer.as_raw_fd(), libc::F_GETFL) },
                flags,
                "diagnostic changed inherited fd flags"
            );
            observed.push((kind, full, status.and_then(|status| status.code())));
        }
    }
    assert!(
        observed.iter().all(|(_, _, code)| *code == Some(1)),
        "full/closed stderr exits: {observed:?}"
    );
}
