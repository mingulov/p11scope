//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, stopped subjects for tests that need a stable process mapping lifetime.

/// An acknowledged, stopped process whose mappings cannot change while a
/// fixture selects or pins them. The guard retains all child custody until Drop.
pub(super) struct OwnedMapper(pub(super) std::process::Child);

impl OwnedMapper {
    pub(super) fn ready() -> Self {
        use std::process::{Command, Stdio};

        // The shell's read builtin creates no descendant. Stop it only after
        // its userspace acknowledgement, then observe the actual stopped state.
        let child = Command::new("sh")
            .args(["-c", "printf 'ready\\n'; read -r ignored"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        Self::from_child(child, std::time::Duration::from_secs(5)).unwrap()
    }

    pub(super) fn from_child(
        child: std::process::Child,
        timeout: std::time::Duration,
    ) -> Result<Self, String> {
        use std::io::Read as _;
        use std::os::fd::AsRawFd as _;

        let mut owned = Self(child);
        let deadline = std::time::Instant::now() + timeout;
        let mut output = owned
            .0
            .stdout
            .take()
            .ok_or("fixture has no readiness pipe")?;
        for expected in b"ready\n" {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero()
                || !poll_fd(output.as_raw_fd(), remaining).map_err(|error| error.to_string())?
            {
                return Err("fixture readiness deadline expired".into());
            }
            let mut byte = [0];
            output
                .read_exact(&mut byte)
                .map_err(|error| error.to_string())?;
            if byte[0] != *expected {
                return Err("unexpected fixture readiness acknowledgement".into());
            }
        }
        // SAFETY: this unprivileged fixture owns this live, unreaped child.
        if unsafe { libc::kill(owned.pid() as i32, libc::SIGSTOP) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        loop {
            if std::time::Instant::now() >= deadline {
                return Err("fixture stop acknowledgement deadline expired".into());
            }
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: one valid siginfo output for an owned child. WNOWAIT
            // preserves exit custody for Child::wait in Drop, including errors.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    owned.pid(),
                    info.as_mut_ptr(),
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error.to_string());
            }
            // SAFETY: zero-initialized storage, filled by successful waitid.
            let info = unsafe { info.assume_init() };
            if unsafe { info.si_pid() } != 0 {
                if info.si_code == libc::CLD_STOPPED && unsafe { info.si_status() } == libc::SIGSTOP
                {
                    return Ok(owned);
                }
                return Err("fixture exited before its stop acknowledgement".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    pub(super) fn pid(&self) -> u32 {
        self.0.id()
    }
}

impl Drop for OwnedMapper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub(super) fn poll_fd(fd: i32, timeout: std::time::Duration) -> std::io::Result<bool> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd names one initialized descriptor for this process.
        let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
        if result > 0 {
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
    }
}
