//! Bounded Linux process identity tracking for node-wide captures.

use crate::semantics::ProcessKey;
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const MAX_TRACKED: usize = 16_384;
const RESERVED_FDS: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrackingEvidence {
    pub fallbacks: u64,
    pub failures: u64,
    pub evictions: u64,
}

pub struct Identified {
    pub key: ProcessKey,
    pub retired: Option<ProcessKey>,
}

enum Mode {
    PidFd(OwnedFd),
    ProcStat,
    Untracked,
}

struct Record {
    key: ProcessKey,
    start_time: Option<u64>,
    last_seen: u64,
    mode: Mode,
}

pub struct Tracker {
    records: BTreeMap<u32, Record>,
    pidfd_limit: usize,
    process_limit: usize,
    sequence: u64,
    evidence: TrackingEvidence,
}

impl Tracker {
    pub fn new() -> Self {
        let limit = raise_nofile().unwrap_or(RESERVED_FDS);
        Self::with_limits(
            limit.saturating_sub(RESERVED_FDS).min(MAX_TRACKED),
            MAX_TRACKED,
        )
    }

    pub fn with_limits(pidfd_limit: usize, process_limit: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            pidfd_limit: pidfd_limit.min(process_limit),
            process_limit,
            sequence: 0,
            evidence: TrackingEvidence::default(),
        }
    }

    pub fn identify(&mut self, pid: u32) -> Identified {
        self.sequence = self.sequence.wrapping_add(1);
        if let Some(record) = self.records.get_mut(&pid) {
            let alive = match &record.mode {
                Mode::PidFd(fd) => !pidfd_ready(fd).unwrap_or(false),
                Mode::ProcStat => process_start_time(pid).ok() == record.start_time,
                Mode::Untracked => true,
            };
            if alive {
                record.last_seen = self.sequence;
                return Identified {
                    key: record.key,
                    retired: None,
                };
            }
        }

        let mut retired = self.records.remove(&pid).map(|record| record.key);
        if self.records.len() >= self.process_limit {
            if let Some(evicted) = self.least_recent_pid() {
                let key = self.records.remove(&evicted).unwrap().key;
                retired = retired.or(Some(key));
                self.evidence.evictions += 1;
            }
        }

        self.make_pidfd_room();
        let start_time = process_start_time(pid).ok();
        let mode = if self.pidfd_count() < self.pidfd_limit {
            match pidfd_open(pid) {
                Ok(fd) => Mode::PidFd(fd),
                Err(_) if start_time.is_some() => {
                    self.evidence.fallbacks += 1;
                    Mode::ProcStat
                }
                Err(_) => {
                    self.evidence.failures += 1;
                    Mode::Untracked
                }
            }
        } else if start_time.is_some() {
            self.evidence.fallbacks += 1;
            Mode::ProcStat
        } else {
            self.evidence.failures += 1;
            Mode::Untracked
        };
        let generation = start_time.unwrap_or((1u64 << 63) | self.sequence);
        let key = ProcessKey { pid, generation };
        self.records.insert(
            pid,
            Record {
                key,
                start_time,
                last_seen: self.sequence,
                mode,
            },
        );
        Identified { key, retired }
    }

    pub fn poll_exited(&mut self) -> Vec<ProcessKey> {
        let dead: Vec<u32> = self
            .records
            .iter()
            .filter_map(|(pid, record)| {
                let dead = match &record.mode {
                    Mode::PidFd(fd) => pidfd_ready(fd).unwrap_or(false),
                    Mode::ProcStat => process_start_time(*pid).ok() != record.start_time,
                    Mode::Untracked => false,
                };
                dead.then_some(*pid)
            })
            .collect();
        dead.into_iter()
            .filter_map(|pid| self.records.remove(&pid).map(|r| r.key))
            .collect()
    }

    pub fn retire(&mut self, key: ProcessKey) {
        if self
            .records
            .get(&key.pid)
            .is_some_and(|record| record.key == key)
        {
            self.records.remove(&key.pid);
        }
    }

    pub fn evidence(&self) -> TrackingEvidence {
        self.evidence
    }

    fn make_pidfd_room(&mut self) {
        if self.pidfd_count() < self.pidfd_limit || self.pidfd_limit == 0 {
            return;
        }
        let candidate = self
            .records
            .iter()
            .filter(|(_, record)| matches!(record.mode, Mode::PidFd(_)))
            .min_by_key(|(_, record)| record.last_seen)
            .map(|(pid, _)| *pid);
        if let Some(pid) = candidate {
            let record = self.records.get_mut(&pid).unwrap();
            if record.start_time.is_some() {
                record.mode = Mode::ProcStat;
                self.evidence.fallbacks += 1;
            }
        }
    }

    fn pidfd_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| matches!(record.mode, Mode::PidFd(_)))
            .count()
    }

    fn least_recent_pid(&self) -> Option<u32> {
        self.records
            .iter()
            .min_by_key(|(_, record)| record.last_seen)
            .map(|(pid, _)| *pid)
    }
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Capture-local process-generation identity. It is deliberately unrelated to the
/// numeric PID and is never serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProcessViewId(pub u32);

/// Identity of the mount namespace in which one process view was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MountNamespaceId {
    pub device: u64,
    pub inode: u64,
}

fn mount_namespace_id(pid: u32) -> Result<MountNamespaceId, String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = std::fs::metadata(format!("/proc/{pid}/ns/mnt"))
        .map_err(|error| format!("cannot identify process mount namespace: {error}"))?;
    Ok(MountNamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn ensure_same_mount_namespace(
    retained: MountNamespaceId,
    current: MountNamespaceId,
) -> Result<(), String> {
    if current == retained {
        Ok(())
    } else {
        Err("process mount namespace changed during discovery".into())
    }
}

fn open_then_mountinfo_checked<T>(
    mut ensure_retained: impl FnMut() -> Result<(), String>,
    open: impl FnOnce() -> Result<T, String>,
    read_mountinfo: impl FnOnce() -> Result<String, String>,
) -> Result<(T, String), String> {
    ensure_retained()?;
    let opened = open()?;
    ensure_retained()?;
    let mountinfo = read_mountinfo()?;
    ensure_retained()?;
    Ok((opened, mountinfo))
}

fn run_while_same_with<T>(
    mut still_the_same: impl FnMut() -> bool,
    action: impl FnOnce() -> T,
) -> Result<T, String> {
    if !still_the_same() {
        return Err("process generation changed before target access".into());
    }
    let result = action();
    if !still_the_same() {
        return Err("process generation changed during target access".into());
    }
    Ok(result)
}

/// One accepted process generation and its filesystem view. Task 4 uses the pin
/// through scan/open/hash; the later lifecycle task can retain this value and recheck
/// it before subtracting this view's claims.
pub struct ProcessView {
    id: ProcessViewId,
    mount_namespace: MountNamespaceId,
    pin: PidPin,
    admitted_ns: u64,
}

fn validated_with_admission_time<T>(
    validate: impl FnOnce() -> Result<T, String>,
    now_ns: impl FnOnce() -> Option<u64>,
) -> Result<(T, u64), String> {
    let retained = validate()?;
    let admitted_ns =
        now_ns().ok_or_else(|| "cannot read monotonic process-view admission time".to_string())?;
    Ok((retained, admitted_ns))
}

impl ProcessView {
    pub fn open(id: ProcessViewId, pid: u32) -> Result<Self, String> {
        let ((pin, mount_namespace), admitted_ns) = validated_with_admission_time(
            || {
                let pin = PidPin::open(pid)?;
                let mount_namespace = mount_namespace_id(pid)?;
                if !pin.still_the_same() {
                    return Err(format!(
                        "pid {pid} exited while its mount namespace was identified"
                    ));
                }
                Ok((pin, mount_namespace))
            },
            crate::attach::monotonic_ns,
        )?;
        Ok(Self {
            id,
            mount_namespace,
            pin,
            admitted_ns,
        })
    }

    pub fn id(&self) -> ProcessViewId {
        self.id
    }

    pub fn pid(&self) -> u32 {
        self.pin.pid()
    }

    pub fn mount_namespace(&self) -> MountNamespaceId {
        self.mount_namespace
    }

    pub(crate) fn admitted_ns(&self) -> u64 {
        self.admitted_ns
    }

    pub(crate) fn matches_lifecycle_event(&self, pid: u32, hook_ts_ns: u64) -> bool {
        self.pid() == pid && hook_ts_ns >= self.admitted_ns
    }

    pub fn still_the_same(&self) -> bool {
        self.pin.still_the_same()
    }

    pub(crate) fn original_exited(&self) -> Result<bool, String> {
        self.pin.original_exited()
    }

    pub(crate) fn run_while_same<T>(&self, action: impl FnOnce() -> T) -> Result<T, String> {
        run_while_same_with(|| self.still_the_same(), action)
    }

    fn ensure_retained(&self) -> Result<(), String> {
        let exited = || {
            format!(
                "pid {} exited while its mount namespace was being checked",
                self.pid()
            )
        };
        if !self.still_the_same() {
            return Err(exited());
        }
        let current = mount_namespace_id(self.pid())?;
        if !self.still_the_same() {
            return Err(exited());
        }
        ensure_same_mount_namespace(self.mount_namespace, current)
    }

    /// Opens one object through this retained process view before reading the
    /// matching mount table. The fd keeps its mount alive while its exact `mnt_id`
    /// is resolved, and both process generation and mount namespace are rechecked.
    pub(crate) fn open_then_mountinfo<T>(
        &self,
        open: impl FnOnce() -> Result<T, String>,
    ) -> Result<(T, String), String> {
        open_then_mountinfo_checked(
            || self.ensure_retained(),
            open,
            || {
                std::fs::read_to_string(format!("/proc/{}/mountinfo", self.pid())).map_err(
                    |error| format!("cannot read pid {}'s mount table: {error}", self.pid()),
                )
            },
        )
    }
}

pub fn stale_view_ids(views: &[ProcessView]) -> Vec<ProcessViewId> {
    views
        .iter()
        .filter(|view| !view.still_the_same())
        .map(ProcessView::id)
        .collect()
}

/// A process identity that survives PID reuse. `pidfd_open` is exact; the
/// `/proc/<pid>/stat` start time is the documented fallback where pidfds are
/// unavailable. Both already back `Tracker`; `PidPin` exposes them for the
/// discovery path, which must drop any per-pid action whose target was recycled.
pub struct PidPin {
    pid: u32,
    pidfd: Option<OwnedFd>,
    start_time: Option<u64>,
}

impl PidPin {
    pub fn open(pid: u32) -> Result<Self, String> {
        let start_time = process_start_time(pid).ok();
        let pidfd = pidfd_open(pid).ok();
        if pidfd.is_none() && start_time.is_none() {
            return Err(format!(
                "cannot pin pid {pid}: no pidfd and no /proc/{pid}/stat"
            ));
        }
        Ok(Self {
            pid,
            pidfd,
            start_time,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// False when the process exited or the pid was reused since `open`.
    pub fn still_the_same(&self) -> bool {
        match &self.pidfd {
            Some(fd) => pidfd_still_same_with(|| pidfd_ready(fd)),
            None => process_start_time(self.pid).ok() == self.start_time,
        }
    }

    pub(crate) fn original_exited(&self) -> Result<bool, String> {
        let exited = match &self.pidfd {
            Some(fd) => pidfd_exited_with(|| pidfd_ready(fd)),
            None => proc_generation_exited(
                self.start_time
                    .ok_or_else(|| "fallback process pin has no start time".to_string())?,
                process_start_time(self.pid),
            ),
        };
        exited.map_err(|error| {
            format!(
                "cannot check whether original pid {} exited: {error}",
                self.pid
            )
        })
    }

    /// Proves that this pin retained the original pidfd and that the kernel
    /// still grants signal authority for that exact process generation.
    pub(crate) fn probe_signal_authority(&self) -> Result<(), String> {
        self.send_signal(0)
    }

    /// Sends through the retained original pidfd. A `/proc` fallback pin is
    /// identity evidence only and can never become signal authority.
    pub(crate) fn send_signal(&self, signal: i32) -> Result<(), String> {
        let fd = self
            .pidfd
            .as_ref()
            .ok_or_else(|| "process pin has no original pidfd signal authority".to_string())?;
        pidfd_send_signal(fd, signal)
            .map_err(|error| format!("pidfd signal {signal} for pid {} failed: {error}", self.pid))
    }

    pub(crate) fn wait_ready(&self, timeout: Option<std::time::Duration>) -> io::Result<bool> {
        let fd = self
            .pidfd
            .as_ref()
            .ok_or_else(|| io::Error::other("process pin has no original pidfd"))?;
        let timeout_ms = match timeout {
            None => -1,
            Some(duration) => i32::try_from(duration.as_millis()).unwrap_or(i32::MAX),
        };
        pidfd_ready_with_timeout(fd, timeout_ms)
    }
}

fn pidfd_still_same_with(ready: impl FnOnce() -> io::Result<bool>) -> bool {
    matches!(ready(), Ok(false))
}

fn pidfd_exited_with(ready: impl FnOnce() -> io::Result<bool>) -> io::Result<bool> {
    ready()
}

fn proc_generation_exited(retained: u64, current: io::Result<u64>) -> io::Result<bool> {
    match current {
        Ok(current) => Ok(current != retained),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

fn raise_nofile() -> io::Result<usize> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid writable rlimit pointer and constant resource id.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let raised = libc::rlimit {
        rlim_cur: limit.rlim_max,
        rlim_max: limit.rlim_max,
    };
    // Best effort: a constrained runtime may reject the raise; retain the
    // current soft limit and continue with a smaller pidfd budget.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } == 0 {
        Ok(limit.rlim_max.min(usize::MAX as libc::rlim_t) as usize)
    } else {
        Ok(limit.rlim_cur.min(usize::MAX as libc::rlim_t) as usize)
    }
}

fn pidfd_open(pid: u32) -> io::Result<OwnedFd> {
    // SAFETY: Linux pidfd_open syscall takes scalar pid/flags and returns a new fd.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: successful syscall returned a uniquely owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn pidfd_ready(fd: &OwnedFd) -> io::Result<bool> {
    pidfd_ready_with_timeout(fd, 0)
}

fn pidfd_ready_with_timeout(fd: &OwnedFd, timeout_ms: i32) -> io::Result<bool> {
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd and a finite or conventional infinite timeout.
    let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result > 0 && pollfd.revents & libc::POLLIN != 0)
    }
}

fn pidfd_send_signal(fd: &OwnedFd, signal: i32) -> io::Result<()> {
    // SAFETY: fd is the retained pidfd; siginfo is null and flags are zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
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

/// Whether this pid names no process at all right now. It is the only exit
/// proof available for a generation that was never pinned: a pid that still
/// answers is not proven gone — it may even have been reused — so a caller
/// that cannot prove the end keeps its loss.
pub(crate) fn generation_gone(pid: u32) -> bool {
    gone_from(process_start_time(pid))
}

fn gone_from(start_time: io::Result<u64>) -> bool {
    start_time.is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn process_start_time(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat comm"))?;
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat starttime"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stat starttime"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::Command;
    use std::time::{Duration, Instant};

    #[test]
    fn mountinfo_is_read_only_after_the_fd_is_open_with_retained_rechecks() {
        let events = RefCell::new(Vec::new());
        let (opened, mountinfo) = open_then_mountinfo_checked(
            || {
                events.borrow_mut().push("check");
                Ok(())
            },
            || {
                events.borrow_mut().push("open");
                Ok(17)
            },
            || {
                events.borrow_mut().push("mountinfo");
                Ok("17 1 8:1 / / rw - ext4 /dev/root rw\n".into())
            },
        )
        .unwrap();

        assert_eq!(opened, 17);
        assert!(mountinfo.starts_with("17 1 8:1"));
        assert_eq!(
            *events.borrow(),
            ["check", "open", "check", "mountinfo", "check"],
            "a table read before the fd open, or without both later rechecks, can authorize the wrong mount"
        );
    }

    #[test]
    fn a_changed_mount_namespace_after_open_is_rejected_before_table_use() {
        let retained = MountNamespaceId {
            device: 1,
            inode: 11,
        };
        let changed = MountNamespaceId {
            device: 1,
            inode: 12,
        };
        let checks = Cell::new(0);
        let table_reads = Cell::new(0);
        let error = open_then_mountinfo_checked(
            || {
                let current = if checks.get() == 0 { retained } else { changed };
                checks.set(checks.get() + 1);
                ensure_same_mount_namespace(retained, current)
            },
            || Ok(()),
            || {
                table_reads.set(table_reads.get() + 1);
                Ok(String::new())
            },
        )
        .expect_err("a namespace switch after open must fail closed");

        assert!(error.contains("mount namespace changed"), "{error}");
        assert_eq!(checks.get(), 2, "the fd open needs an immediate recheck");
        assert_eq!(
            table_reads.get(),
            0,
            "a changed view must not supply a table"
        );
    }

    /// Mutation caught: deleting either generation check around a target operation
    /// would let the caller continue to its next `/proc/<pid>` action after reuse.
    #[test]
    fn a_generation_change_stops_before_the_next_target_action() {
        let checks = Cell::new(0);
        let actions = Cell::new(0);
        let first = run_while_same_with(
            || {
                checks.set(checks.get() + 1);
                checks.get() == 1
            },
            || actions.set(actions.get() + 1),
        );
        let mut later_action = false;
        if first.is_ok() {
            later_action = true;
        }

        assert!(
            first.is_err(),
            "a change during the action must fail closed"
        );
        assert_eq!(checks.get(), 2, "the action needs pre/post checks");
        assert_eq!(actions.get(), 1, "only the guarded action may have run");
        assert!(
            !later_action,
            "no later target action may follow the mismatch"
        );
    }

    /// Mutation caught: treating a failed pidfd readiness check as `Ok(false)`
    /// would authorize a process generation whose identity could not be verified.
    #[test]
    fn a_pidfd_poll_error_is_never_generation_evidence() {
        assert!(pidfd_still_same_with(|| Ok(false)));
        assert!(!pidfd_still_same_with(|| Ok(true)));
        assert!(!pidfd_still_same_with(|| {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        }));
    }

    #[test]
    fn original_exit_probe_distinguishes_exit_from_transport_failure() {
        assert!(!pidfd_exited_with(|| Ok(false)).unwrap());
        assert!(pidfd_exited_with(|| Ok(true)).unwrap());
        assert_eq!(
            pidfd_exited_with(|| Err(io::Error::from(io::ErrorKind::Interrupted)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );

        assert!(!proc_generation_exited(10, Ok(10)).unwrap());
        assert!(proc_generation_exited(10, Ok(11)).unwrap());
        assert!(
            proc_generation_exited(10, Err(io::Error::from(io::ErrorKind::NotFound)),).unwrap()
        );
        assert_eq!(
            proc_generation_exited(10, Err(io::Error::from(io::ErrorKind::PermissionDenied)))
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn original_pidfd_is_the_only_signal_authority() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        let pin = PidPin::open(child.id()).unwrap();
        pin.probe_signal_authority().unwrap();
        pin.send_signal(libc::SIGTERM).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM));

        let fallback = PidPin {
            pid: std::process::id(),
            pidfd: None,
            start_time: process_start_time(std::process::id()).ok(),
        };
        assert!(fallback.probe_signal_authority().is_err());
        assert!(fallback.send_signal(0).is_err());
    }

    #[test]
    fn low_pidfd_budget_demotes_without_global_failure() {
        let mut child = Command::new("sleep").arg("1").spawn().unwrap();
        let mut tracker = Tracker::with_limits(1, 4);
        tracker.identify(std::process::id());
        tracker.identify(child.id());
        assert!(tracker.evidence().fallbacks >= 1);
        assert_eq!(tracker.evidence().failures, 0);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn whole_process_exit_becomes_a_retirement() {
        let mut child = Command::new("sleep").arg("1").spawn().unwrap();
        let pid = child.id();
        let mut tracker = Tracker::with_limits(4, 4);
        let key = tracker.identify(pid).key;
        child.kill().unwrap();
        child.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if tracker.poll_exited().contains(&key) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "pidfd/fallback did not observe child exit"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn process_view_records_its_monotonic_admission_boundary() {
        let before = crate::attach::monotonic_ns().unwrap();
        let view = ProcessView::open(ProcessViewId(7), std::process::id()).unwrap();
        let after = crate::attach::monotonic_ns().unwrap();

        assert!((before..=after).contains(&view.admitted_ns()));
    }

    #[test]
    fn lifecycle_event_must_follow_this_exact_view_admission() {
        let view = ProcessView::open(ProcessViewId(8), std::process::id()).unwrap();

        assert!(!view.matches_lifecycle_event(view.pid(), view.admitted_ns().saturating_sub(1),));
        assert!(!view.matches_lifecycle_event(view.pid().wrapping_add(1), u64::MAX));
        assert!(view.matches_lifecycle_event(view.pid(), view.admitted_ns()));
    }

    #[test]
    fn admission_clock_is_read_only_after_identity_validation() {
        let order = Cell::new(0);
        let (retained, admitted_ns) = validated_with_admission_time(
            || {
                order.set(1);
                Ok("new generation")
            },
            || {
                assert_eq!(order.get(), 1);
                Some(2)
            },
        )
        .unwrap();

        assert_eq!(retained, "new generation");
        assert_eq!(admitted_ns, 2);
        assert!(1 < admitted_ns, "an older generation event is excluded");
    }

    /// fix5 review, finding 4. Exit proof has to *be* proof: a `/proc` entry
    /// that is refused (hidepid, a foreign user) or unparsable says nothing
    /// about whether the process is still there, and every other suppression
    /// in this family degrades to "still a loss" on error. Only NotFound —
    /// the pid names no process — is the proof.
    #[test]
    fn only_a_missing_process_is_proof_of_exit() {
        assert!(gone_from(Err(io::Error::from(io::ErrorKind::NotFound))));
        assert!(!gone_from(Ok(12345)));
        assert!(
            !gone_from(Err(io::Error::from_raw_os_error(libc::EACCES))),
            "a refused /proc entry is not an exit"
        );
        assert!(
            !gone_from(Err(io::Error::new(io::ErrorKind::InvalidData, "stat comm"))),
            "an unparsable stat line is not an exit"
        );
        assert!(
            !generation_gone(std::process::id()),
            "this process is alive"
        );
    }

    #[test]
    fn overall_budget_evicts_lru_only() {
        let mut tracker = Tracker::with_limits(0, 1);
        let first = tracker.identify(std::process::id()).key;
        let second = tracker.identify(u32::MAX).key;
        assert_eq!(tracker.evidence().evictions, 1);
        assert_eq!(tracker.identify(u32::MAX).key, second);
        assert_ne!(first, second);
    }
}
