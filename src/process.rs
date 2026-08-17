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

/// One accepted process generation and its filesystem view. Task 4 uses the pin
/// through scan/open/hash; the later lifecycle task can retain this value and recheck
/// it before subtracting this view's claims.
pub struct ProcessView {
    id: ProcessViewId,
    mount_namespace: MountNamespaceId,
    pin: PidPin,
}

impl ProcessView {
    pub fn open(id: ProcessViewId, pid: u32) -> Result<Self, String> {
        let pin = PidPin::open(pid)?;
        let mount_namespace = mount_namespace_id(pid)?;
        if !pin.still_the_same() {
            return Err(format!(
                "pid {pid} exited while its mount namespace was identified"
            ));
        }
        Ok(Self {
            id,
            mount_namespace,
            pin,
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

    pub fn still_the_same(&self) -> bool {
        self.pin.still_the_same()
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
            Some(fd) => !pidfd_ready(fd).unwrap_or(false),
            None => process_start_time(self.pid).ok() == self.start_time,
        }
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
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for a nonblocking poll.
    let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result > 0)
    }
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
    fn overall_budget_evicts_lru_only() {
        let mut tracker = Tracker::with_limits(0, 1);
        let first = tracker.identify(std::process::id()).key;
        let second = tracker.identify(u32::MAX).key;
        assert_eq!(tracker.evidence().evictions, 1);
        assert_eq!(tracker.identify(u32::MAX).key, second);
        assert_ne!(first, second);
    }
}
