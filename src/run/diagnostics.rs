//! SPDX-License-Identifier: GPL-3.0-or-later
//! Cleanup progress is optional diagnostics, never a blocking dependency.

use std::io::{self, Write};
use std::os::fd::AsRawFd as _;

pub(super) fn terminal_diagnostics() -> Box<dyn Write> {
    match crate::sink::stdout_transport_on_fd(io::stderr().as_raw_fd()) {
        Ok(writer) => Box::new(writer),
        // Optional diagnostics have no blocking fallback. This discards
        // only progress text; the cleanup driver still returns its actual
        // owned join/interruption/failure result to the caller.
        Err(_) => Box::new(io::sink()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CHILD: &str = "P11SCOPE_CLEANUP_DIAGNOSTIC_CHILD";
    const LINE: &[u8] = b"p11scope: cleanup completed, 5/5 links released, 0 s\n";

    fn child() {
        if std::env::var_os(CHILD).is_some() {
            std::io::stdout().write_all(b"DIAGNOSTIC_CHILD\n").unwrap();
            std::io::stdout().flush().unwrap();
            let _ = terminal_diagnostics().write_all(LINE);
            std::process::exit(0);
        }
    }

    fn command(test: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        let module = module_path!().split_once("::").unwrap().1;
        command
            .args(["--exact", &format!("{module}::{test}"), "--nocapture"])
            .env(CHILD, "1")
            .stdout(Stdio::piped());
        command
    }

    #[test]
    fn healthy_cleanup_diagnostics_keep_the_exact_completion_line() {
        child();
        let output = command("healthy_cleanup_diagnostics_keep_the_exact_completion_line")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(
            output
                .stdout
                .windows(b"DIAGNOSTIC_CHILD\n".len())
                .any(|bytes| bytes == b"DIAGNOSTIC_CHILD\n")
        );
        assert_eq!(output.stderr, LINE);
    }

    #[test]
    fn full_stderr_cannot_hold_completed_cleanup_open() {
        child();
        let mut raw = [-1; 2];
        // SAFETY: raw has storage for two descriptors returned by pipe2.
        assert_eq!(unsafe { libc::pipe2(raw.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: successful pipe2 supplied two distinct owned descriptors.
        let mut reader = unsafe { std::fs::File::from_raw_fd(raw[0]) };
        let mut writer = unsafe { std::fs::File::from_raw_fd(raw[1]) };
        // SAFETY: writer is an owned pipe; only its local capacity changes.
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
            4096
        );
        writer.write_all(&[b'B'; 4096]).unwrap();
        let retained = writer.try_clone().unwrap();
        // SAFETY: retained owns the original shared pipe description.
        let flags = unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_NONBLOCK, 0);
        let mut process = command("full_stderr_cannot_hold_completed_cleanup_open")
            .stderr(Stdio::from(writer))
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let completed = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                process.kill().unwrap();
                process.wait().unwrap();
                break None;
            }
            std::thread::sleep(Duration::from_millis(2));
        };
        // SAFETY: retained stays open through this flags query.
        assert_eq!(
            unsafe { libc::fcntl(retained.as_raw_fd(), libc::F_GETFL) },
            flags
        );
        drop(retained);
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        let mut child_stdout = Vec::new();
        process
            .stdout
            .take()
            .unwrap()
            .read_to_end(&mut child_stdout)
            .unwrap();
        assert!(
            child_stdout
                .windows(b"DIAGNOSTIC_CHILD\n".len())
                .any(|bytes| bytes == b"DIAGNOSTIC_CHILD\n")
        );
        assert!(
            completed.is_some_and(|status| status.success()),
            "cleanup diagnostic blocked after ownership had settled"
        );
        assert_eq!(bytes, vec![b'B'; 4096]);
    }
}
