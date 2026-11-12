//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Capture-process file-descriptor budget (scan-1k guard round): raise the
//! `RLIMIT_NOFILE` soft limit toward the hard limit at startup, and hold a
//! fixed reserve so fanotify/file learning and later attaches never run the
//! table into `EMFILE`. When the reserve would be breached, views wait for
//! the next tick instead of failing.

use std::path::Path;

/// Fds that must stay free under the soft limit before another process view
/// may open: one fanotify group fd, a late provider attach burst (a full
/// single-module uprobe set is dozens of links; the G0 wall snapshot holds
/// 166 links across every module), and transient opens (the `/proc/self/fd`
/// enumeration itself plus short-lived maps/stat reads). The startup rlimit
/// raise makes this bind only where the hard limit is tiny too.
pub(crate) const FD_RESERVE: u64 = 128;

/// The soft-limit target for the startup raise: the hard limit, literally
/// (standard practice). The `max` only guards an insane `getrlimit` result
/// (`soft > hard` never happens); it never lowers.
pub(crate) fn nofile_soft_target(soft: u64, hard: u64) -> u64 {
    hard.max(soft)
}

/// What the startup raise did. Never fatal: a refused raise keeps the old
/// soft limit and carries the reason for the `-v` line.
#[derive(Debug)]
pub(crate) struct RaiseNofileOutcome {
    pub raised: bool,
    pub previous_soft: u64,
    pub effective_soft: u64,
    pub hard: u64,
    pub error: Option<String>,
}

/// [`raise_nofile_soft_to_hard`] with its two syscalls injected (tests).
pub(crate) fn raise_nofile_soft_with(
    get: impl FnOnce() -> Result<(u64, u64), String>,
    set_soft: impl FnOnce(u64) -> Result<(), String>,
) -> RaiseNofileOutcome {
    let (soft, hard) = match get() {
        Ok(limits) => limits,
        Err(error) => {
            return RaiseNofileOutcome {
                raised: false,
                previous_soft: 0,
                effective_soft: 0,
                hard: 0,
                error: Some(error),
            };
        }
    };
    let target = nofile_soft_target(soft, hard);
    if target == soft {
        return RaiseNofileOutcome {
            raised: false,
            previous_soft: soft,
            effective_soft: soft,
            hard,
            error: None,
        };
    }
    match set_soft(target) {
        Ok(()) => RaiseNofileOutcome {
            raised: true,
            previous_soft: soft,
            effective_soft: target,
            hard,
            error: None,
        },
        Err(error) => RaiseNofileOutcome {
            raised: false,
            previous_soft: soft,
            effective_soft: soft,
            hard,
            error: Some(error),
        },
    }
}

/// Raise the `RLIMIT_NOFILE` soft limit to the hard limit once, at startup,
/// before the scan opens anything. One pidfd per retained view plus the
/// fixed BPF/pin set crosses soft 1024 at ~700 views (guard-round G0); the
/// raise is what lets a 1k-capped capture keep fanotify and later attaches
/// off `EMFILE`.
pub(crate) fn raise_nofile_soft_to_hard() -> RaiseNofileOutcome {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one initialized writable rlimit; no limit changes.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) } != 0 {
        let error = std::io::Error::last_os_error().to_string();
        return raise_nofile_soft_with(|| Err(error), |_| Ok(()));
    }
    let soft = current.rlim_cur;
    let hard = current.rlim_max;
    raise_nofile_soft_with(
        || Ok((soft, hard)),
        |target| {
            let next = libc::rlimit {
                rlim_cur: target,
                rlim_max: hard,
            };
            // SAFETY: setrlimit with a valid rlimit; soft <= hard by
            // construction (the target is the hard limit), so raising the
            // soft limit is always permitted.
            if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &next) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(())
        },
    )
}

/// One `-v` line naming what the startup raise did: the effective soft
/// limit always, the raise or the refusal reason beside it.
pub(crate) fn nofile_startup_line(outcome: &RaiseNofileOutcome) -> String {
    if let Some(error) = &outcome.error {
        return format!(
            "p11scope: rlimit-nofile soft={} hard={} (raise refused: {error}; continuing)",
            outcome.effective_soft, outcome.hard
        );
    }
    if outcome.raised {
        return format!(
            "p11scope: rlimit-nofile soft={} hard={} (raised from {})",
            outcome.effective_soft, outcome.hard, outcome.previous_soft
        );
    }
    format!(
        "p11scope: rlimit-nofile soft={} hard={} (already at the hard limit)",
        outcome.effective_soft, outcome.hard
    )
}

/// True when fewer than `reserve` fds remain under `soft_limit`: the next
/// views must wait for the next tick instead of opening. An unlimited soft
/// limit never breaches (the subtraction saturates far above any reserve).
pub(crate) fn fd_reserve_breached(open_fds: u64, soft_limit: u64, reserve: u64) -> bool {
    soft_limit.saturating_sub(open_fds) < reserve
}

/// Count the entries of an fd directory (the `/proc/self/fd` reader seam:
/// production passes `/proc/self/fd`, tests a fixture dir). `None` when the
/// directory cannot be listed.
pub(crate) fn open_fd_count_in(dir: &Path) -> Option<usize> {
    let mut count = 0usize;
    for entry in std::fs::read_dir(dir).ok()? {
        entry.ok()?;
        count = count.checked_add(1)?;
    }
    Some(count)
}

/// This process's open fd count via `/proc/self/fd`, counted conservatively
/// (the enumeration fd itself is listed). Follows the `FdSnapshot` reader
/// in `attach::counter_banks`.
pub(crate) fn open_fd_count() -> Option<u64> {
    u64::try_from(open_fd_count_in(Path::new("/proc/self/fd"))?).ok()
}

/// The live reserve check: true when the next views must wait for the next
/// tick. Fail-closed: an unreadable limit or count also waits (a delay,
/// never an `EMFILE`).
pub(crate) fn fd_reserve_breached_now() -> bool {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one initialized writable rlimit; no limit changes.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return true;
    }
    let (soft, open) = match open_fd_count() {
        Some(open) => (limit.rlim_cur, open),
        None => return true,
    };
    fd_reserve_breached(open, soft, FD_RESERVE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Healthy: a soft limit below the hard limit raises to the hard limit
    /// (fedora: soft 1024, hard 524288).
    #[test]
    fn nofile_target_raises_soft_to_hard() {
        assert_eq!(nofile_soft_target(1024, 524288), 524288);
    }

    /// Failure pair: an already-maxed soft limit stays put (no raise).
    #[test]
    fn nofile_target_holds_when_already_at_hard() {
        assert_eq!(nofile_soft_target(524288, 524288), 524288);
    }

    /// An unlimited hard limit raises soft to unlimited too: the brief pins
    /// soft-to-hard literally (standard practice; the kernel still bounds
    /// the table by `fs.nr_open`/`fs.file-max`), so a 1024 soft limit with
    /// an unlimited hard limit must not keep the fd wall.
    #[test]
    fn nofile_target_raises_to_an_unlimited_hard_limit() {
        assert_eq!(
            nofile_soft_target(1024, libc::RLIM_INFINITY),
            libc::RLIM_INFINITY
        );
    }

    /// Healthy: the raise applies the hard limit and reports it effective.
    #[test]
    fn nofile_raise_reports_the_effective_limit() {
        let outcome = raise_nofile_soft_with(
            || Ok((1024, 524288)),
            |target| {
                assert_eq!(target, 524288);
                Ok(())
            },
        );
        assert!(outcome.raised, "{outcome:?}");
        assert_eq!(outcome.effective_soft, 524288);
        assert_eq!(outcome.hard, 524288);
        assert!(outcome.error.is_none(), "{outcome:?}");
    }

    /// Failure pair: a refused `setrlimit` keeps the old soft limit and
    /// carries the reason instead of raising.
    #[test]
    fn nofile_raise_failure_keeps_the_old_soft_limit() {
        let outcome = raise_nofile_soft_with(
            || Ok((1024, 524288)),
            |_| Err("operation not permitted".to_string()),
        );
        assert!(!outcome.raised, "{outcome:?}");
        assert_eq!(outcome.effective_soft, 1024);
        assert!(outcome.error.is_some(), "{outcome:?}");
    }

    /// Healthy: ample headroom above the reserve admits the next views.
    #[test]
    fn fd_reserve_admits_when_headroom_covers_it() {
        assert!(!fd_reserve_breached(500, 524288, FD_RESERVE));
        assert!(!fd_reserve_breached(0, 1024, FD_RESERVE));
    }

    /// Failure pair: at or past the reserve the next views must wait for
    /// the next tick instead of failing on `EMFILE`.
    #[test]
    fn fd_reserve_breaches_before_emfile() {
        assert!(fd_reserve_breached(1024, 1024, FD_RESERVE));
        assert!(fd_reserve_breached(1024 - FD_RESERVE + 1, 1024, FD_RESERVE));
        assert!(!fd_reserve_breached(1024 - FD_RESERVE, 1024, FD_RESERVE));
    }

    /// Healthy: counting lists exactly the directory entries.
    #[test]
    fn open_fd_count_lists_directory_entries() {
        let dir = std::env::temp_dir().join(format!("fd-budget-count-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["0", "1", "2"] {
            std::fs::write(dir.join(name), []).unwrap();
        }
        assert_eq!(open_fd_count_in(&dir), Some(3));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Failure pair: an unreadable directory yields no count (fail-closed:
    /// the caller treats it as breached).
    #[test]
    fn open_fd_count_missing_directory_yields_none() {
        let dir = std::env::temp_dir().join(format!(
            "fd-budget-absent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert_eq!(open_fd_count_in(&dir), None);
    }
}
