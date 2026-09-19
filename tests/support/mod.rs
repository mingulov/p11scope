//! SPDX-License-Identifier: GPL-3.0-or-later
use std::io::{self, BufRead as _, BufReader, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(5);
const SLEEP_ARGUMENT: &str = "287.4139";

pub struct ChildGuard {
    pub child: Child,
    live: bool,
}

impl ChildGuard {
    pub fn new(child: Child) -> Self {
        Self { child, live: true }
    }

    fn wait_until(&mut self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.live = false;
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        if let Some(status) = self.wait_until(READY_TIMEOUT)? {
            return Ok(status);
        }
        let timeout = "setsid wrapper did not exit before the readiness deadline";
        self.terminate().map_err(|cleanup| {
            io::Error::other(format!("{timeout}; bounded cleanup failed: {cleanup}"))
        })?;
        Err(io::Error::new(io::ErrorKind::TimedOut, timeout))
    }

    fn is_alive(&mut self) -> io::Result<bool> {
        if self.live && self.child.try_wait()?.is_some() {
            self.live = false;
        }
        Ok(self.live)
    }

    fn terminate_with(
        &mut self,
        kill: impl FnOnce(&mut Child) -> io::Result<()>,
    ) -> io::Result<()> {
        if !self.is_alive()? {
            return Ok(());
        }
        kill(&mut self.child)?;
        self.wait_until(READY_TIMEOUT)?.map(|_| ()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "direct child did not exit before the cleanup deadline",
            )
        })
    }

    pub fn terminate(&mut self) -> io::Result<()> {
        self.terminate_with(Child::kill)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub fn poll_fd(fd: i32, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
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
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

fn process_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, tail) = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed proc stat"))?;
    tail.split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proc stat has no start time"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc start time"))
}

fn process_parent(pid: u32) -> io::Result<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))?
        .lines()
        .find_map(|line| line.strip_prefix("PPid:").map(str::trim))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "proc status has no PPid"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid proc parent pid"))
}

fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open accepts only the numeric PID and zero flags.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: a successful pidfd_open returned one new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn pidfd_signal(pidfd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: pidfd is owned and valid; siginfo is null and flags are zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub struct SameUidNonDescendant {
    pid: u32,
    pidfd: OwnedFd,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LaunchFailure {
    BeforeGo,
    AfterGo,
}

impl SameUidNonDescendant {
    pub fn spawn() -> io::Result<Self> {
        Self::spawn_with_failure(None)
    }

    fn spawn_with_failure(failure: Option<LaunchFailure>) -> io::Result<Self> {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/non-descendant.sh");
        let mut wrapper = ChildGuard::new(
            Command::new("setsid")
                .arg("--fork")
                .arg("sh")
                .arg(script)
                .arg(SLEEP_ARGUMENT)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        let wrapper_pid = wrapper.child.id();
        let mut channel = wrapper.child.stdin.take().expect("piped stdin");
        let stdout = wrapper.child.stdout.take().expect("piped stdout");
        if !poll_fd(stdout.as_raw_fd(), READY_TIMEOUT)? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "detached target did not report its identity",
            ));
        }
        let mut report = String::new();
        BufReader::new(stdout).read_line(&mut report)?;
        let mut fields = report.split_whitespace();
        let pid: u32 = fields
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing reported PID"))?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid reported PID"))?;
        let reported_start: u64 = fields
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing start time"))?
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid start time"))?;
        if fields.next().is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected detached-target identity fields",
            ));
        }
        let pidfd = pidfd_open(pid)?;
        if process_start_time(pid)? != reported_start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "detached-target generation changed before pidfd acquisition",
            ));
        }
        let target = Self { pid, pidfd };
        if failure == Some(LaunchFailure::BeforeGo) {
            drop(channel);
            let error = match poll_fd(target.pidfd.as_raw_fd(), READY_TIMEOUT) {
                Ok(true) => io::Error::other("injected launch cancellation before go"),
                Ok(false) => io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cancelled pre-release target did not exit",
                ),
                Err(error) => error,
            };
            return Err(target.cleanup_after_error(error));
        }
        if let Err(error) = channel.write_all(b"go\n") {
            return Err(target.cleanup_after_error(error));
        }
        drop(channel);
        if failure == Some(LaunchFailure::AfterGo) {
            return Err(
                target.cleanup_after_error(io::Error::other("injected launch failure after go"))
            );
        }
        match wrapper.wait() {
            Ok(status) if status.success() => {}
            Ok(_) => {
                return Err(target.cleanup_after_error(io::Error::other("setsid wrapper failed")));
            }
            Err(error) => return Err(target.cleanup_after_error(error)),
        }
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            match target.is_alive() {
                Ok(true) => {}
                Ok(false) => {
                    return Err(target.cleanup_after_error(io::Error::other(
                        "detached target exited before readiness",
                    )));
                }
                Err(error) => return Err(target.cleanup_after_error(error)),
            }
            if std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .and_then(|path| path.file_name().map(|name| name == "sleep"))
                == Some(true)
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(target.cleanup_after_error(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "detached target did not exec sleep before readiness deadline",
                )));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let parent = match process_parent(pid) {
            Ok(parent) => parent,
            Err(error) => return Err(target.cleanup_after_error(error)),
        };
        if parent == std::process::id() || parent == wrapper_pid {
            return Err(target.cleanup_after_error(io::Error::other(
                "target is still a test-process descendant",
            )));
        }
        Ok(target)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn is_alive(&self) -> io::Result<bool> {
        Ok(!poll_fd(self.pidfd.as_raw_fd(), Duration::ZERO)?)
    }

    pub fn terminate(&mut self) -> io::Result<()> {
        if self.is_alive()? {
            pidfd_signal(&self.pidfd, libc::SIGKILL)?;
        }
        if poll_fd(self.pidfd.as_raw_fd(), READY_TIMEOUT)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "detached target did not exit after pidfd signal",
            ))
        }
    }

    fn cleanup_after_error(mut self, error: io::Error) -> io::Error {
        match self.terminate() {
            Ok(()) => error,
            Err(cleanup) => io::Error::other(format!(
                "{error}; bounded detached-target cleanup failed: {cleanup}"
            )),
        }
    }
}

impl Drop for SameUidNonDescendant {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

pub struct MatchingDecoy(ChildGuard);

impl MatchingDecoy {
    pub fn spawn() -> io::Result<Self> {
        Command::new("sleep")
            .arg(SLEEP_ARGUMENT)
            .spawn()
            .map(ChildGuard::new)
            .map(Self)
    }

    pub fn is_alive(&mut self) -> io::Result<bool> {
        self.0.is_alive()
    }
}

pub fn is_sleep(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "sleep")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_child_kill_failure_returns_without_an_unbounded_wait() {
        let child = Command::new("sleep").arg(SLEEP_ARGUMENT).spawn().unwrap();
        let mut child = ChildGuard::new(child);
        let started = Instant::now();
        let error = child
            .terminate_with(|_| Err(io::Error::from(io::ErrorKind::PermissionDenied)))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(child.is_alive().unwrap());
        child.terminate().unwrap();
    }

    #[test]
    fn launch_cancellation_paths_leave_the_matching_decoy_alive() {
        let mut decoy = MatchingDecoy::spawn().unwrap();
        for (failure, reason) in [
            (
                LaunchFailure::BeforeGo,
                "injected launch cancellation before go",
            ),
            (LaunchFailure::AfterGo, "injected launch failure after go"),
        ] {
            let error = SameUidNonDescendant::spawn_with_failure(Some(failure))
                .err()
                .expect("injected launch failure");
            assert_eq!(error.to_string(), reason, "launch cleanup must succeed");
            assert!(decoy.is_alive().unwrap(), "failure cleanup touched decoy");
        }
    }
}
