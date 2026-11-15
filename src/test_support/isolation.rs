//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Shared test-only process isolation: re-executed single-test children and
//! guarded `RLIMIT_NOFILE` changes.

use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Environment gate naming the isolated child's key (the test name or mode).
pub(crate) const CHILD_ENV: &str = "P11SCOPE_TEST_ISOLATED_CHILD";
/// Environment gate recording the exact test being re-executed.
const TEST_ENV: &str = "P11SCOPE_TEST_ISOLATED_TEST";

const DEFAULT_CHILD_TIMEOUT: Duration = Duration::from_secs(120);

/// Builds the re-executed child command for `test`, gated by `key`.
pub(crate) fn command(test: &str, key: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test binary path is known"));
    command.args(["--exact", test, "--nocapture", "--test-threads=1"]);
    command.env(CHILD_ENV, key).env(TEST_ENV, test);
    command
}

/// The child key when this process is the re-executed child for `test`.
pub(crate) fn child_key(test: &str) -> Option<String> {
    let key = std::env::var_os(CHILD_ENV)?;
    let recorded = std::env::var_os(TEST_ENV)?;
    (recorded == test).then(|| key.to_string_lossy().into_owned())
}

/// True only inside the re-executed child for `test` and `key`.
pub(crate) fn in_child(test: &str, key: &str) -> bool {
    child_key(test).as_deref() == Some(key)
}

/// Runs the body in an isolated child, returning true there and false after a
/// verified successful parent-side run.
pub(crate) fn enter(test: &str, key: &str) -> bool {
    enter_with_timeout(test, key, DEFAULT_CHILD_TIMEOUT)
}

/// [`enter`] with an explicit child deadline.
pub(crate) fn enter_with_timeout(test: &str, key: &str, timeout: Duration) -> bool {
    if in_child(test, key) {
        return true;
    }
    run_child_with_timeout(test, key, timeout, |_| {});
    false
}

/// Runs `test` in a child and fails unless exactly that one test passed.
pub(crate) fn run_child(test: &str, key: &str) -> Output {
    run_child_with_timeout(test, key, DEFAULT_CHILD_TIMEOUT, |_| {})
}

/// [`run_child`] with a bounded wait and caller command configuration.
pub(crate) fn run_child_with_timeout(
    test: &str,
    key: &str,
    timeout: Duration,
    configure: impl FnOnce(&mut Command),
) -> Output {
    let mut command = command(test, key);
    configure(&mut command);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn isolated test child");
    let stdout = child.stdout.take().expect("child stdout");
    let stderr = child.stderr.take().expect("child stderr");
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stdout), &mut bytes)
            .expect("read child stdout");
        bytes
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::BufReader::new(stderr), &mut bytes)
            .expect("read child stderr");
        bytes
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll isolated test child") {
            break status;
        }
        if Instant::now() >= deadline {
            let pid = child.id();
            let _ = child.kill();
            let _ = child.wait();
            panic!("isolated child {test} timed out after {timeout:?} (owned_pid={pid})");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let output = Output {
        status,
        stdout: stdout_reader.join().expect("child stdout reader"),
        stderr: stderr_reader.join().expect("child stderr reader"),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "isolated child {test} failed: status={} stdout={stdout:?} stderr={:?}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("running 1 test") && stdout.contains("1 passed"),
        "isolated child {test} selected no test or did not pass: stdout={stdout:?} stderr={:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

static FD_LIMIT_SERIAL: Mutex<()> = Mutex::new(());

/// A temporarily changed soft `RLIMIT_NOFILE`, serialized suite-wide and
/// restored on drop.
pub(crate) struct FdLimitGuard {
    saved: libc::rlimit,
    restored: bool,
    _serial: MutexGuard<'static, ()>,
}

impl FdLimitGuard {
    /// The current `RLIMIT_NOFILE` values (read-only).
    pub(crate) fn current() -> libc::rlimit {
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one initialized writable rlimit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) },
            0
        );
        current
    }

    fn guarded(limits: impl FnOnce(&libc::rlimit) -> (libc::rlim_t, libc::rlim_t)) -> Self {
        let serial = FD_LIMIT_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let saved = Self::current();
        let (soft, hard) = limits(&saved);
        let next = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        // SAFETY: setrlimit writes this process's own configured limits;
        // the guard restores the saved values on drop.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) }, 0);
        Self {
            saved,
            restored: false,
            _serial: serial,
        }
    }

    /// Raises the soft limit to the hard limit.
    pub(crate) fn raise_soft_to_hard() -> Self {
        Self::guarded(|saved| (saved.rlim_max, saved.rlim_max))
    }

    /// Raises the soft limit to at least `need`, within the hard limit.
    pub(crate) fn raise_soft_to_at_least(need: libc::rlim_t) -> Self {
        Self::guarded(|saved| {
            assert!(
                saved.rlim_max >= need,
                "the hard fd limit is below the needed {need}"
            );
            (saved.rlim_cur.max(need), saved.rlim_max)
        })
    }

    /// Lowers only the soft limit; the hard limit is retained.
    pub(crate) fn lower_soft(soft: libc::rlim_t) -> Self {
        Self::guarded(|saved| {
            assert!(
                saved.rlim_cur > soft,
                "the lowered limit must sit below the current one"
            );
            (soft, saved.rlim_max)
        })
    }

    /// Lowers the soft limit to at most `max`; the hard limit is retained.
    pub(crate) fn lower_soft_at_most(max: libc::rlim_t) -> Self {
        Self::guarded(|saved| (saved.rlim_cur.min(max), saved.rlim_max))
    }

    /// Sets the soft limit within the retained hard limit.
    pub(crate) fn set_soft(soft: libc::rlim_t) -> Self {
        Self::guarded(|saved| {
            assert!(
                soft <= saved.rlim_max,
                "the soft fd limit cannot exceed the hard limit"
            );
            (soft, saved.rlim_max)
        })
    }

    /// Lowers both limits irreversibly; only safe in an isolated child.
    pub(crate) fn lower_both(soft: libc::rlim_t) -> Self {
        Self::guarded(|saved| {
            assert!(
                saved.rlim_max >= soft,
                "the hard fd limit is below the lowered {soft}"
            );
            (soft, soft)
        })
    }

    /// Restores the saved limits now, panicking on refusal.
    pub(crate) fn restore(&mut self) {
        if !self.restored {
            // SAFETY: restoring the exact saved limits.
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.saved) },
                0
            );
            self.restored = true;
        }
    }
}

impl Drop for FdLimitGuard {
    fn drop(&mut self) {
        if !self.restored {
            // SAFETY: best-effort restore of the exact saved limits; an
            // irreversible child lowering may refuse, and a panic here
            // would abort the harness.
            let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.saved) };
            self.restored = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_runner_rejects_zero_selection() {
        let result = std::panic::catch_unwind(|| {
            run_child(
                "test_support::isolation::tests::this_test_does_not_exist",
                "zero-selection",
            );
        });
        assert!(
            result.is_err(),
            "a child that selected zero tests must fail the parent"
        );
    }

    #[test]
    fn fd_limit_guard_restores_the_sampled_limits() {
        let before = FdLimitGuard::current();
        let mut guard = FdLimitGuard::set_soft(before.rlim_cur);
        guard.restore();
        let after = FdLimitGuard::current();
        assert_eq!(after.rlim_cur, before.rlim_cur);
        assert_eq!(after.rlim_max, before.rlim_max);
    }
}
