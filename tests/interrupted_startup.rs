//! SPDX-License-Identifier: GPL-3.0-or-later
//! M-1 (docs/reviews/2026-09-26-claude-gap-analysis/B-cli-ux-docs.md): a
//! stop signal that lands after the `-o` temp file exists but before the
//! capture attached must end the observer cleanly: no signal death, no
//! `.p11scope.<pid>.*.tmp` litter, and a message naming the interruption.
//!
//! The signal is sent the moment inotify reports the temp file, which is
//! inside the startup window (discovery) on any host; unprivileged-safe,
//! since nothing attaches before the interruption is honoured.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

struct SleepTarget(std::process::Child);

impl Drop for SleepTarget {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Blocks until a `.p11scope.*` entry is created in the watched directory,
/// or `deadline` passes. Returns whether it appeared.
fn wait_for_temp_creation(inotify: libc::c_int, deadline: Instant) -> bool {
    let mut buffer = [0u8; 4096];
    while Instant::now() < deadline {
        let mut poll = libc::pollfd {
            fd: inotify,
            events: libc::POLLIN,
            revents: 0,
        };
        let left = deadline.saturating_duration_since(Instant::now());
        if unsafe { libc::poll(&mut poll, 1, left.as_millis().max(1) as libc::c_int) } <= 0 {
            continue;
        }
        let read = unsafe { libc::read(inotify, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read <= 0 {
            continue;
        }
        let mut offset = 0usize;
        while offset + std::mem::size_of::<libc::inotify_event>() <= read as usize {
            let event: libc::inotify_event =
                unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast()) };
            let start = offset + std::mem::size_of::<libc::inotify_event>();
            let name = &buffer[start..start + event.len as usize];
            if name.starts_with(b".p11scope.") {
                return true;
            }
            offset = start + event.len as usize;
        }
    }
    false
}

#[test]
fn a_stop_signal_during_startup_leaves_no_temp_file_and_names_the_interruption() {
    let target = SleepTarget(
        Command::new("sleep")
            .arg("311.27")
            .spawn()
            .expect("spawn sleep target"),
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let inotify = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    assert!(inotify >= 0, "{}", std::io::Error::last_os_error());
    let watched = CString::new(dir.path().as_os_str().as_bytes()).unwrap();
    assert!(unsafe { libc::inotify_add_watch(inotify, watched.as_ptr(), libc::IN_CREATE) } >= 0);

    let out = dir.path().join("observed.json");
    let observer = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args([
            "profile",
            "--pid",
            &target.0.id().to_string(),
            "--duration",
            "1",
            "-o",
        ])
        .arg(&out)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn p11scope");
    let appeared = wait_for_temp_creation(inotify, Instant::now() + Duration::from_secs(30));
    unsafe { libc::close(inotify) };
    assert!(appeared, "the -o temp file never appeared");
    assert_eq!(
        unsafe { libc::kill(observer.id() as libc::pid_t, libc::SIGINT) },
        0
    );
    let output = observer.wait_with_output().expect("wait for p11scope");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        output.status.signal(),
        None,
        "killed by a signal instead of stopping cleanly: {stderr}"
    );
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("interrupted by SIGINT"), "{stderr}");
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "startup interruption left {left:?}");
}
