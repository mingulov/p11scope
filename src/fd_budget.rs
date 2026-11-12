//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Capture-process file-descriptor budget (scan-1k guard round): raise the
//! `RLIMIT_NOFILE` soft limit toward the hard limit at startup, and hold a
//! fixed reserve so fanotify/file learning and later attaches never run the
//! table into `EMFILE`. When the reserve would be breached, views wait for
//! the next tick instead of failing.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

/// Fds that must stay free under the soft limit before another process view
/// may open: one fanotify group fd, a late provider attach burst (a full
/// single-module uprobe set is dozens of links; the G0 wall snapshot holds
/// 166 links across every module), and transient opens (the `/proc/self/fd`
/// enumeration itself plus short-lived maps/stat reads). The startup rlimit
/// raise makes this bind only where the hard limit is tiny too.
pub(crate) const FD_RESERVE: u64 = 128;

/// Concurrent library handles a capture may hold at once (view-collapse
/// fix6 A2, owner 20:20): scan pins, manifest pins and pre-arm pins hold
/// one fd per physical file (see `share_scan_pins_with_retained`), and
/// their distinct held files never exceed this. Past it, admissions wait
/// for the next tick under the counted named gap below, never dropped.
/// The lifetime number of distinct libraries stays unlimited: handles
/// release when their view drops (or their duplicate closes at share
/// time) and every pass recounts from the live sets.
pub(crate) const MAX_CONCURRENT_LIBRARY_HANDLES: usize = 1000;

/// True when `held` distinct library handles reach the concurrent `cap`:
/// the next admissions must wait for the next tick. Production passes
/// [`MAX_CONCURRENT_LIBRARY_HANDLES`]; tests script small caps.
pub(crate) fn library_handle_budget_exhausted(held: usize, cap: usize) -> bool {
    held >= cap
}

/// The fixed subject of the over-budget deferral gap: admissions held
/// back by the concurrent library-handle cap.
pub(crate) const LIBRARY_HANDLE_BUDGET_SUBJECT: &str = "library handles";

/// The fixed reasons beside it, per admission loop (mirroring the fd
/// reserve's initial/live pair): the cap, the wait, never a drop.
pub(crate) const LIBRARY_HANDLE_BUDGET_REASON_INITIAL: &str = "capture library-handle budget exhausted (1000 concurrent handles); remaining processes deferred to the next tick";
pub(crate) const LIBRARY_HANDLE_BUDGET_REASON_LIVE: &str = "capture library-handle budget exhausted (1000 concurrent handles); remaining new processes deferred to the next tick";

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

/// One tick's (or one discovery pass's) file-descriptor reserve reading:
/// the open count and soft limit sampled once before the loop, plus the
/// views opened and scan pins retained since. Call sites sample once per
/// tick and count their own opens instead of re-reading `/proc` per pid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FdReserveTick {
    open: u64,
    soft: u64,
    opened: u64,
}

impl FdReserveTick {
    /// A reading over injected counts (tests).
    pub(crate) fn from_counts(open: u64, soft: u64) -> Self {
        Self {
            open,
            soft,
            opened: 0,
        }
    }

    /// Sample the live reading: the soft limit plus this process's open
    /// count via `/proc/self/fd`, counted conservatively (the enumeration
    /// fd itself is listed; follows the `FdSnapshot` reader in
    /// `attach::counter_banks`). `None` when either cannot be read (fail
    /// open at the call site: proceed, report once, never defer).
    pub(crate) fn sample() -> Option<Self> {
        Self::sample_in(Path::new("/proc/self/fd"))
    }

    /// [`sample`] with the fd directory injected (tests).
    pub(crate) fn sample_in(fd_dir: &Path) -> Option<Self> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one initialized writable rlimit; no limit changes.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return None;
        }
        let open = u64::try_from(open_fd_count_in(fd_dir)?).ok()?;
        Some(Self::from_counts(open, limit.rlim_cur))
    }

    /// True when fewer than the reserve remains under the soft limit after
    /// this tick's own opens: the next views must wait for the next tick.
    /// Saturating: absurd counts breach, never wrap into admission.
    pub(crate) fn breached(&self) -> bool {
        fd_reserve_breached(self.open.saturating_add(self.opened), self.soft, FD_RESERVE)
    }

    /// Count one view opened since the snapshot (conservative within the
    /// tick: drops are not subtracted; the fresh snapshot bounds the drift
    /// every tick). The scan pins the admission retains are debited
    /// separately through [`note_opened_n`].
    pub(crate) fn note_opened(&mut self) {
        self.opened = self.opened.saturating_add(1);
    }

    /// Count `count` further persistent fds opened since the snapshot:
    /// the scan pins an admission retains beside its view's pidfd.
    /// Saturating, like [`note_opened`]: absurd counts breach, never
    /// wrap into admission.
    pub(crate) fn note_opened_n(&mut self, count: u64) {
        self.opened = self.opened.saturating_add(count);
    }
}

/// True when the next views must wait for the next tick. Fail open: an
/// unreadable snapshot never defers (the caller proceeds and reports once
/// under [`UNREADABLE_SUBJECT`]).
pub(crate) fn reserve_defers(sample: Option<&FdReserveTick>) -> bool {
    sample.is_some_and(FdReserveTick::breached)
}

/// The fixed subject of the one unreadable-snapshot report: the reserve
/// guard went blind and views proceed without it.
pub(crate) const UNREADABLE_SUBJECT: &str = "capture file-descriptor reserve";

/// The fixed reason beside it: no pids, paths or run detail beyond the
/// `/proc/self/fd` source itself.
pub(crate) const UNREADABLE_REASON: &str = "the capture's open file count could not be read (/proc/self/fd), so the file-descriptor reserve guard is blind; views proceed without it";

/// The one unreadable-snapshot report per process: `/proc` unreadable once
/// stays unreadable, so every later tick must not file another gap.
static UNREADABLE_REPORTED: AtomicBool = AtomicBool::new(false);

/// Claim the one unreadable-snapshot report: true on the first unreadable
/// snapshot, false after. Pure over the caller's slot, so the twin pins
/// the once-only shape without touching the process flag.
pub(crate) fn claim_unreadable_report(slot: &AtomicBool) -> bool {
    !slot.swap(true, Ordering::SeqCst)
}

/// Claim the process-wide report (production call sites).
pub(crate) fn note_unreadable_reported() -> bool {
    claim_unreadable_report(&UNREADABLE_REPORTED)
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

    /// Failure pair: an unreadable directory yields no count (fail-open:
    /// the caller proceeds and reports once under the fixed name, never
    /// defers).
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

    /// Healthy: a breached snapshot still defers the rest to the next tick
    /// (the guard guards); at exactly the reserve it admits.
    #[test]
    fn reserve_defers_when_headroom_below_reserve() {
        let soft = 1024u64;
        let breached = FdReserveTick::from_counts(soft - FD_RESERVE + 1, soft);
        assert!(reserve_defers(Some(&breached)));
        let admitted = FdReserveTick::from_counts(soft - FD_RESERVE, soft);
        assert!(!reserve_defers(Some(&admitted)));
    }

    /// Failure pair: an unreadable snapshot never defers (fail open): the
    /// scan proceeds without the reserve guard instead of deferring every
    /// process on every tick.
    #[test]
    fn reserve_proceeds_when_snapshot_unreadable() {
        assert!(!reserve_defers(None));
    }

    /// Healthy: the tick snapshot counts exactly the fd directory entries
    /// and judges by the same pure predicate.
    #[test]
    fn tick_snapshot_counts_directory_entries() {
        let dir = std::env::temp_dir().join(format!("fd-budget-tick-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["0", "1", "2"] {
            std::fs::write(dir.join(name), []).unwrap();
        }
        let tick = FdReserveTick::sample_in(&dir).expect("a readable dir snapshots");
        assert_eq!(tick.open, 3);
        assert_eq!(
            tick.breached(),
            fd_reserve_breached(3, tick.soft, FD_RESERVE)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Failure pair: an unreadable fd directory yields no snapshot (fail
    /// open at the call site, never a deferred tick).
    #[test]
    fn tick_snapshot_unreadable_yields_none() {
        let dir = std::env::temp_dir().join(format!(
            "fd-budget-tick-absent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(FdReserveTick::sample_in(&dir).is_none());
    }

    /// Healthy: views opened during the tick count against the reserve, so
    /// one snapshot guards the whole tick without re-reading `/proc`.
    #[test]
    fn tick_counter_trips_reserve_as_views_open() {
        let soft = 1024u64;
        let mut tick = FdReserveTick::from_counts(soft - FD_RESERVE, soft);
        assert!(!tick.breached());
        tick.note_opened();
        assert_eq!(tick.opened, 1);
        assert!(tick.breached());
    }

    /// Failure pair: absurd counts saturate instead of wrapping past the
    /// reserve (no overflow panic in debug, no wrap into admission).
    #[test]
    fn tick_counter_saturates_on_absurd_counts() {
        let mut tick = FdReserveTick::from_counts(u64::MAX, u64::MAX);
        assert!(tick.breached());
        tick.note_opened();
        assert!(tick.breached());
    }

    /// Healthy: one admission debits its view plus the scan pins it
    /// retains, so the once-per-tick estimate tracks every persistent
    /// fd without re-reading `/proc`.
    #[test]
    fn tick_counter_debits_view_plus_retained_pins() {
        let soft = 1024u64;
        let mut tick = FdReserveTick::from_counts(soft - FD_RESERVE, soft);
        assert!(!tick.breached());
        tick.note_opened();
        tick.note_opened_n(2);
        assert_eq!(tick.opened, 3);
        assert!(tick.breached());
    }

    /// Failure pair: the pin debit saturates instead of wrapping past
    /// the reserve (no overflow panic in debug, no wrap into admission).
    #[test]
    fn tick_pin_debit_saturates_on_absurd_counts() {
        let mut tick = FdReserveTick::from_counts(0, 1000);
        tick.note_opened_n(u64::MAX);
        assert_eq!(tick.opened, u64::MAX);
        assert!(tick.breached());
    }

    /// View-collapse fix5 F2 (codex
    /// `reviewed_fd_snapshot_must_count_retained_scan_pins`): each
    /// admission retains its view's pidfd plus its scan pins, and the
    /// once-per-tick estimate must debit both. With soft AND hard
    /// `RLIMIT_NOFILE` at 512 (a host whose hard limit itself is small,
    /// where the startup raise cannot help), admissions holding one
    /// pidfd plus one real scan pin must defer while the 128-fd reserve
    /// still holds — never reach `EMFILE`. Runs in an isolated child:
    /// lowering the hard limit is process-global and irreversible.
    #[test]
    fn reviewed_fd_snapshot_must_count_retained_scan_pins() {
        const CHILD: &str = "P11SCOPE_FD_PIN_RESERVE_CHILD";
        const COMPLETED: &str = "P11SCOPE_FD_PIN_RESERVE_COMPLETED";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "fd_budget::tests::reviewed_fd_snapshot_must_count_retained_scan_pins",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "pin-reserve child failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line == COMPLETED),
                "pin-reserve child did not complete its assertions:\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one initialized writable rlimit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) },
            0
        );
        assert!(
            current.rlim_max >= 512,
            "the box must allow a 512 hard fd limit for the pin-reserve child"
        );
        let lowered = libc::rlimit {
            rlim_cur: 512,
            rlim_max: 512,
        };
        // SAFETY: lowering both limits in the isolated child; the child
        // exits after its assertions, so the irreversible hard-limit drop
        // never escapes to siblings.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        let mut tick = FdReserveTick::sample().expect("a readable snapshot under 512");
        assert_eq!(tick.soft, 512);
        let dir = tempfile::tempdir().expect("a pin file directory");
        let pin_path = dir.path().join("pin.so");
        std::fs::write(&pin_path, b"pin").expect("a pin file");
        let mut held_views: Vec<std::fs::File> = Vec::new();
        let mut held_pins = Vec::new();
        let mut admitted = 0u32;
        let deferred = loop {
            if reserve_defers(Some(&tick)) {
                break true;
            }
            // One admission: its pidfd plus one real retained scan pin,
            // debited through the production path.
            let pidfd = std::fs::File::open("/dev/null")
                .expect("a pidfd stand-in must open before the reserve trips");
            held_views.push(pidfd);
            tick.note_opened();
            let pins = crate::discovery::identity::test_fixture::real_scan_pin(
                &pin_path,
                None,
                0,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
            held_pins.push(pins);
            crate::discovery::engine::note_retained_scan_pins(
                Some(&mut tick),
                held_pins.last_mut().expect("just pushed"),
                std::iter::empty::<&crate::discovery::identity::PinnedObjects>(),
            );
            admitted = admitted.saturating_add(1);
            assert!(admitted < 2000, "the reserve never deferred");
        };
        assert!(deferred, "admissions must defer, never fail");
        assert!(admitted > 0, "the guard must admit under headroom");
        let open = open_fd_count_in(std::path::Path::new("/proc/self/fd"))
            .expect("a readable count after the loop");
        assert!(
            open as u64 + FD_RESERVE <= 512 + 4,
            "held {open} fds against soft 512 with reserve {FD_RESERVE}: the estimate undercounted"
        );
        println!("\n{COMPLETED}");
    }

    /// View-collapse fix5 F2 healthy control: pidfd-only admissions (no
    /// scan pins) under the same 512/512 ceiling hold the reserve with
    /// the view debit alone. Passes before and after the pin-debit fix:
    /// it proves the child harness reaches deferral without `EMFILE`
    /// when the accounting is complete.
    #[test]
    fn reviewed_fd_snapshot_pidfd_only_views_hold_reserve() {
        const CHILD: &str = "P11SCOPE_FD_PIDFD_ONLY_CHILD";
        const COMPLETED: &str = "P11SCOPE_FD_PIDFD_ONLY_COMPLETED";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "fd_budget::tests::reviewed_fd_snapshot_pidfd_only_views_hold_reserve",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "pidfd-only child failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line == COMPLETED),
                "pidfd-only child did not complete its assertions:\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        let mut current = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes one initialized writable rlimit.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) },
            0
        );
        assert!(
            current.rlim_max >= 512,
            "the box must allow a 512 hard fd limit for the pidfd-only child"
        );
        let lowered = libc::rlimit {
            rlim_cur: 512,
            rlim_max: 512,
        };
        // SAFETY: lowering both limits in the isolated child; the child
        // exits after its assertions.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lowered) }, 0);
        let mut tick = FdReserveTick::sample().expect("a readable snapshot under 512");
        assert_eq!(tick.soft, 512);
        let mut held: Vec<std::fs::File> = Vec::new();
        let mut admitted = 0u32;
        let deferred = loop {
            if reserve_defers(Some(&tick)) {
                break true;
            }
            let pidfd = std::fs::File::open("/dev/null")
                .expect("a pidfd stand-in must open before the reserve trips");
            held.push(pidfd);
            tick.note_opened();
            admitted = admitted.saturating_add(1);
            assert!(admitted < 2000, "the reserve never deferred");
        };
        assert!(deferred, "admissions must defer, never fail");
        assert!(admitted > 0, "the guard must admit under headroom");
        let open = open_fd_count_in(std::path::Path::new("/proc/self/fd"))
            .expect("a readable count after the loop");
        assert!(
            open as u64 + FD_RESERVE <= 512 + 4,
            "held {open} fds against soft 512 with reserve {FD_RESERVE}"
        );
        println!("\n{COMPLETED}");
    }

    /// Healthy: the unreadable snapshot reports under its fixed name, once.
    #[test]
    fn unreadable_report_claims_once_under_its_fixed_name() {
        assert_eq!(UNREADABLE_SUBJECT, "capture file-descriptor reserve");
        assert_eq!(
            UNREADABLE_REASON,
            "the capture's open file count could not be read (/proc/self/fd), so the \
             file-descriptor reserve guard is blind; views proceed without it"
        );
        let slot = std::sync::atomic::AtomicBool::new(false);
        assert!(
            claim_unreadable_report(&slot),
            "the first unreadable snapshot reports"
        );
    }

    /// Failure pair: after the claim, repeated unreadable snapshots report
    /// nothing more (no per-tick gap spam while `/proc` stays unreadable).
    #[test]
    fn unreadable_report_stays_silent_after_the_claim() {
        let slot = std::sync::atomic::AtomicBool::new(false);
        assert!(claim_unreadable_report(&slot));
        assert!(!claim_unreadable_report(&slot));
        assert!(!claim_unreadable_report(&slot));
    }

    /// View-collapse fix6 A2 (owner 20:20): the handle limit is
    /// concurrent — at most 1000 library handles held at once, while the
    /// lifetime number of distinct libraries stays unlimited.
    #[test]
    fn library_handle_budget_holds_a_thousand_concurrent_handles() {
        assert_eq!(MAX_CONCURRENT_LIBRARY_HANDLES, 1000);
        assert!(!library_handle_budget_exhausted(
            999,
            MAX_CONCURRENT_LIBRARY_HANDLES
        ));
        assert!(library_handle_budget_exhausted(
            1000,
            MAX_CONCURRENT_LIBRARY_HANDLES
        ));
        assert!(library_handle_budget_exhausted(
            1001,
            MAX_CONCURRENT_LIBRARY_HANDLES
        ));
    }

    /// Failure pair: the gate defers at any cap, so the admission twin's
    /// small test cap exercises the same boundary the thousand does.
    #[test]
    fn library_handle_budget_defers_at_any_cap() {
        assert!(!library_handle_budget_exhausted(0, 2));
        assert!(!library_handle_budget_exhausted(1, 2));
        assert!(library_handle_budget_exhausted(2, 2));
        assert!(library_handle_budget_exhausted(3, 2));
    }
}
