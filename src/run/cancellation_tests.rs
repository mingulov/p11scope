//! SPDX-License-Identifier: GPL-3.0-or-later
//! The capture loops' actual cancellation diagnostic over real stderr pipes.

use super::*;
use std::io::Read as _;
use std::process::{Command, Stdio};

const CHILD_MODE: &str = "P11SCOPE_CANCEL_MARKER_CHILD";

fn marker_child() -> Option<std::ffi::OsString> {
    let mode = std::env::var_os(CHILD_MODE)?;
    report_capture_cancel(Some(libc::SIGINT), 42);
    // Avoid libtest's own terminal writes: only the production emitter is
    // under test, and a blocked diagnostic must not prevent this exit.
    std::process::exit(if mode == "healthy" || mode == "blocked" {
        0
    } else {
        2
    });
}

fn child_command(test: &str, mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .env(CHILD_MODE, mode)
        .stdout(Stdio::null());
    command
}

#[test]
fn live_loop_cancel_marker_writes_exact_stderr_line() {
    let _ = marker_child();
    let output = child_command(
        "run::cancellation_tests::live_loop_cancel_marker_writes_exact_stderr_line",
        "healthy",
    )
    .output()
    .unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stderr,
        b"p11scope: cancel: loop exited on signal 2 after 42 ticks\n"
    );
}

#[test]
fn live_loop_cancel_marker_does_not_wait_for_full_stderr_pipe() {
    let _ = marker_child();
    let mut raw = [-1; 2];
    // SAFETY: raw is writable storage for exactly two owned descriptors.
    assert_eq!(unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: successful pipe2 initialized these two distinct descriptors.
    let mut reader = unsafe { File::from_raw_fd(raw[0]) };
    let mut writer = unsafe { File::from_raw_fd(raw[1]) };
    // A real full pipe with a reader still present, not EPIPE or a short
    // writable prefix. Its inherited open description remains blocking.
    // SAFETY: writer is an owned pipe descriptor; setting its size is local.
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
        4096
    );
    writer.write_all(&[b'B'; 4096]).unwrap();
    let retained_writer = writer.try_clone().unwrap();
    // SAFETY: retained_writer is an owned descriptor for the original pipe.
    let flags = unsafe { libc::fcntl(retained_writer.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(flags & libc::O_NONBLOCK, 0);
    let mut child = child_command(
        "run::cancellation_tests::live_loop_cancel_marker_does_not_wait_for_full_stderr_pipe",
        "blocked",
    )
    .stderr(Stdio::from(writer))
    .spawn()
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let completed = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            break None;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    // SAFETY: retained_writer stays open until after this flags query.
    assert_eq!(
        unsafe { libc::fcntl(retained_writer.as_raw_fd(), libc::F_GETFL) },
        flags
    );
    drop(retained_writer);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert!(
        completed.is_some_and(|status| status.success()),
        "capture cancellation diagnostic waited on full stderr"
    );
    assert_eq!(bytes, vec![b'B'; 4096]);
}
