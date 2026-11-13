//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Capture diagnostics must not park the observer on a stalled stderr,
//! nor let diagnostic delivery change the exit status (Sol-full F3).
//!
//! The refusal below fails fast before discovery runs — the required
//! host gate refuses without proven Multi capability, and the bad `-o`
//! path refuses where the gate proceeds — so the only stderr traffic is
//! the refusal itself plus a startup notice on eligible hosts. Under a full
//! or closed (EPIPE) stderr these diagnostics must shed instead of parking,
//! and the exit stays the refusal's 1 on every host. (A capture that
//! reaches discovery additionally prints discovery's own summary; since
//! v070-stderr-stall every production `eprintln!` routes through the same
//! bounded helper, and the loop/attach/pause emissions are pinned by the
//! `capture_diagnostics_never_use_blocking_stderr_writes` shape test.)

use std::io::Write as _;
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use support::DieWithParent as _;

#[path = "support/multi_host.rs"]
mod multi_host;

#[allow(dead_code)]
mod support;

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
                .die_with_parent()
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

/// v070-stderr-stall: the `--system` startup notes (thread-knob lines) fire
/// before the host refusal; on a full stderr they must shed instead of
/// parking the process. Pre-fix they used blocking `eprintln!` writes, so a
/// stalled stderr held the run before its first bounded diagnostic and the
/// refusal never arrived (the watchdog below kills the parked child).
#[test]
fn full_stderr_with_startup_note_preserves_fast_refusal() {
    let out = unopenable_output();
    let args = [
        "inventory".to_string(),
        "--system".to_string(),
        "--capture".to_string(),
        "native".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    // Baseline: healthy stderr carries the knob note plus the refusal.
    let baseline = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(&args)
        .env("P11SCOPE_SHARD_THREADS", "8")
        .stdin(Stdio::null())
        .output()
        .expect("run baseline refusal");
    assert_eq!(baseline.status.code(), Some(1), "inventory baseline");
    let baseline_stderr = String::from_utf8(baseline.stderr).expect("stderr is UTF-8");
    assert!(
        baseline_stderr.contains("P11SCOPE_SHARD_THREADS=8"),
        "the knob note must fire before the refusal: {baseline_stderr}"
    );
    // Full pipe, no reader: the note sheds and the refusal still exits 1.
    let (reader, writer) = diagnostic_pipe(true);
    let mut child = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(&args)
        .env("P11SCOPE_SHARD_THREADS", "8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(writer)
        .die_with_parent()
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
        status.and_then(|status| status.code()),
        Some(1),
        "a full stderr parked the startup note instead of shedding it"
    );
}

/// v070-stderr-stall fix1 (codex F1): under descriptor exhaustion the
/// startup diagnostics must still reach a writable stderr. With stdout on
/// `/dev/null`, stderr a regular file and `RLIMIT_NOFILE=4`, startup
/// preservation consumes the last spare fd, so the diagnostic transport
/// can allocate nothing new; it borrows the inherited stderr for the
/// immediate write instead of exiting silently. Pre-fix this child left
/// zero stderr bytes.
#[test]
fn fd_exhaustion_with_startup_note_preserves_a_visible_refusal() {
    use std::os::unix::process::CommandExt as _;
    let out = unopenable_output();
    let args = [
        "inventory".to_string(),
        "--system".to_string(),
        "--capture".to_string(),
        "native".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    // Healthy control: the knob note plus the refusal, exit 1.
    let baseline = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(&args)
        .env("P11SCOPE_SHARD_THREADS", "8")
        .stdin(Stdio::null())
        .output()
        .expect("run baseline refusal");
    assert_eq!(baseline.status.code(), Some(1), "inventory baseline");
    let baseline_stderr = String::from_utf8(baseline.stderr).expect("stderr is UTF-8");
    assert!(
        baseline_stderr.contains("P11SCOPE_SHARD_THREADS=8"),
        "the knob note must fire before the refusal: {baseline_stderr}"
    );
    // Exhausted descriptors: stdout on /dev/null, stderr a writable
    // regular file, `RLIMIT_NOFILE=4` in the child only.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("capture-stderr-lowfd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let stderr_path = dir.join("stderr.txt");
    let stderr_file = std::fs::File::create(&stderr_path).unwrap();
    let null_in = std::fs::File::open("/dev/null").unwrap();
    let null_out = std::fs::File::create("/dev/null").unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_p11scope"));
    cmd.args(&args)
        .env("P11SCOPE_SHARD_THREADS", "8")
        .stdin(Stdio::from(null_in))
        .stdout(Stdio::from(null_out))
        .stderr(Stdio::from(stderr_file))
        .die_with_parent();
    // SAFETY: the hook runs after fork before exec; `setrlimit` is
    // async-signal-safe, allocates nothing and touches no parent memory.
    unsafe {
        cmd.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: 4,
                rlim_max: 4,
            };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
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
    assert_eq!(
        status.and_then(|status| status.code()),
        Some(1),
        "a low-fd startup must still exit with the refusal's 1"
    );
    let stderr_bytes = std::fs::read(&stderr_path).unwrap();
    assert!(
        !stderr_bytes.is_empty(),
        "a low-fd startup left zero stderr bytes instead of a visible refusal"
    );
    let stderr_text = String::from_utf8_lossy(&stderr_bytes);
    assert!(
        stderr_text.contains("p11scope:"),
        "a low-fd startup must leave a visible refusal: {stderr_text:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
