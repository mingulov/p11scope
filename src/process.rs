//! SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded Linux process identity tracking for node-wide captures.

use crate::discovery::scan::{CaptureWorkBudget, read_mountinfo};
use crate::semantics::ProcessKey;
#[cfg(test)]
use std::collections::BTreeMap;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

pub(crate) const MAX_TRACKED: usize = 16_384;
#[cfg(test)]
const RESERVED_FDS: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrackingEvidence {
    pub fallbacks: u64,
    pub failures: u64,
    pub evictions: u64,
}

// SYSPLAN residual F-44: the pid-keyed acquisition ladder (`identify` /
// `poll_exited` / `Mode` / `Record`) is legacy test support, not a
// production path — `history_tests.rs` pins that production trackers never
// touch it, and wiring production through its `Untracked` fallback would
// resurrect the F-16 fallback the revalidation retired. It is `cfg(test)`
// so the shipped binary contains none of it; the `retire` dead end (zero
// callers anywhere) is deleted outright. Live pidfd use survives intact in
// `PidPin`, the production pin path below.
#[cfg(test)]
pub struct Identified {
    pub key: ProcessKey,
    pub retired: Option<ProcessKey>,
}

#[cfg(test)]
enum Mode {
    PidFd(OwnedFd),
    ProcStat,
    Untracked,
}

#[cfg(test)]
struct Record {
    key: ProcessKey,
    start_time: Option<u64>,
    last_seen: u64,
    mode: Mode,
}

pub struct Tracker {
    history: crate::history::Registry,
    // Optional control provenance; producer event admission never calls it.
    #[cfg(test)]
    _control_adapter: Option<Box<dyn crate::history::TaskMembership>>,
    #[cfg(test)]
    records: BTreeMap<u32, Record>,
    #[cfg(test)]
    pidfd_limit: usize,
    #[cfg(test)]
    process_limit: usize,
    #[cfg(test)]
    sequence: u64,
    evidence: TrackingEvidence,
}

impl Tracker {
    #[cfg(test)]
    pub fn new() -> Self {
        let limit = raise_nofile().unwrap_or(RESERVED_FDS);
        Self::with_limits(
            limit.saturating_sub(RESERVED_FDS).min(MAX_TRACKED),
            MAX_TRACKED,
        )
    }

    #[cfg(test)]
    pub fn with_limits(pidfd_limit: usize, process_limit: usize) -> Self {
        Self {
            history: crate::history::Registry::disabled(),
            _control_adapter: None,
            records: BTreeMap::new(),
            pidfd_limit: pidfd_limit.min(process_limit),
            process_limit,
            sequence: 0,
            evidence: TrackingEvidence::default(),
        }
    }

    /// One private consumer context owns one retained EVENTS map. Its domain
    /// is supplied by that context; it grants historical semantics only.
    pub(crate) fn for_producer(domain: crate::events::EventsDomain, limit: usize) -> Self {
        // Every return/entry link pair burns fds against RLIMIT_NOFILE, and
        // the capture path never ran through Tracker::new, so raise here:
        // a 1024 soft limit dies near slot 256 otherwise.
        let _ = raise_nofile();
        Self {
            history: crate::history::Registry::new(domain, limit),
            #[cfg(test)]
            _control_adapter: None,
            #[cfg(test)]
            records: BTreeMap::new(),
            #[cfg(test)]
            pidfd_limit: 0,
            #[cfg(test)]
            process_limit: 0,
            #[cfg(test)]
            sequence: 0,
            evidence: TrackingEvidence::default(),
        }
    }
    /// Existing proof harness constructor: optional control adapter is retained
    /// separately, with no event-driven candidate lookup or liveness sampling.
    #[cfg(test)]
    pub(crate) fn with_membership(
        domain: u64,
        limit: usize,
        _fd_limit: usize,
        adapter: Box<dyn crate::history::TaskMembership>,
    ) -> Self {
        let mut tracker =
            Self::for_producer(crate::events::EventsDomain::test_standin(domain), limit);
        tracker._control_adapter = Some(adapter);
        tracker
    }
    #[cfg(test)]
    pub(crate) fn producer_domain(&self) -> u64 {
        self.history.domain()
    }
    pub(crate) fn admit_history(
        &mut self,
        domain: u64,
        pid: u32,
        image: p11scope_ebpf_common::ImageIdentity,
    ) -> (Option<ProcessKey>, Vec<ProcessKey>) {
        self.history.admit(domain, pid, image)
    }
    pub(crate) fn history_call(&mut self, key: ProcessKey) {
        self.history.mark_call(key);
    }
    pub(crate) fn history_root(&mut self, key: ProcessKey, affiliation: u64) {
        self.history.mark_root(key, affiliation);
    }
    pub(crate) fn check_root_event(&self, domain: u64, affiliation: u64) -> anyhow::Result<()> {
        self.history.check_root(domain, affiliation)
    }
    pub(crate) fn complete_root(
        &mut self,
        tail: &crate::events::ConsumedOriginalRootTail,
    ) -> anyhow::Result<Vec<ProcessKey>> {
        self.history.complete_root(tail)
    }
    pub(crate) fn history_birth(&mut self, parent: ProcessKey, child: ProcessKey) -> bool {
        self.history.birth(parent, child)
    }
    #[cfg(test)]
    pub(crate) fn confirm_history_retirement(&mut self, key: ProcessKey) -> Option<ProcessKey> {
        self.history.confirm_retirement(key)
    }

    #[cfg(test)]
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
        if self.records.len() >= self.process_limit
            && let Some(evicted) = self.least_recent_pid()
        {
            let key = self.records.remove(&evicted).unwrap().key;
            retired = retired.or(Some(key));
            self.evidence.evictions = self.evidence.evictions.saturating_add(1);
        }

        self.make_pidfd_room();
        let start_time = process_start_time(pid).ok();
        let mode = if self.pidfd_count() < self.pidfd_limit {
            match pidfd_open(pid) {
                Ok(fd) => Mode::PidFd(fd),
                Err(_) if start_time.is_some() => {
                    self.evidence.fallbacks = self.evidence.fallbacks.saturating_add(1);
                    Mode::ProcStat
                }
                Err(_) => {
                    self.evidence.failures = self.evidence.failures.saturating_add(1);
                    Mode::Untracked
                }
            }
        } else if start_time.is_some() {
            self.evidence.fallbacks = self.evidence.fallbacks.saturating_add(1);
            Mode::ProcStat
        } else {
            self.evidence.failures = self.evidence.failures.saturating_add(1);
            Mode::Untracked
        };
        let generation = start_time.unwrap_or((1u64 << 63) | self.sequence);
        let key = ProcessKey {
            pid,
            generation,
            domain: 0,
            exec_id: 0,
        };
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

    #[cfg(test)]
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

    pub fn evidence(&self) -> TrackingEvidence {
        self.evidence
    }

    #[cfg(test)]
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
                self.evidence.fallbacks = self.evidence.fallbacks.saturating_add(1);
            }
        }
    }

    #[cfg(test)]
    fn pidfd_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| matches!(record.mode, Mode::PidFd(_)))
            .count()
    }

    #[cfg(test)]
    fn least_recent_pid(&self) -> Option<u32> {
        self.records
            .iter()
            .min_by_key(|(_, record)| record.last_seen)
            .map(|(pid, _)| *pid)
    }
}

#[cfg(test)]
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

#[cfg(test)]
thread_local! {
    static MOUNTINFO_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// How many `/proc/<pid>/mountinfo` tables this thread has read through a
/// retained process view (H-3 seam).
#[cfg(test)]
pub(crate) fn mountinfo_reads_for_test() -> u64 {
    MOUNTINFO_READS.with(std::cell::Cell::get)
}

/// Opens and reads one retained view's mount table, charged to `budget`. The
/// table fd is returned open: it stays pollable for later changes.
fn read_view_mountinfo(
    pid: u32,
    budget: &mut CaptureWorkBudget,
) -> Result<(std::fs::File, String), String> {
    let table = std::fs::File::open(format!("/proc/{pid}/mountinfo"))
        .map_err(|error| format!("cannot open pid {pid}'s mount table: {error}"))?;
    #[cfg(test)]
    MOUNTINFO_READS.with(|reads| reads.set(reads.get() + 1));
    let text = read_mountinfo(&table, budget)
        .map_err(|error| format!("cannot read pid {pid}'s mount table: {error}"))?;
    Ok((table, text))
}

/// Whether the mount namespace behind an open `/proc/<pid>/mountinfo` changed
/// since the fd was opened or last polled: the kernel reports
/// `POLLPRI|POLLERR` exactly then (proc(5), `mounts_poll`). A failed poll
/// counts as a change.
fn mount_table_changed(table: &std::fs::File) -> bool {
    let mut poll = libc::pollfd {
        fd: table.as_raw_fd(),
        events: libc::POLLPRI,
        revents: 0,
    };
    // SAFETY: one valid pollfd for an fd this function borrows, zero timeout.
    let ready = unsafe { libc::poll(&mut poll, 1, 0) };
    ready != 0 || poll.revents & (libc::POLLPRI | libc::POLLERR | libc::POLLNVAL) != 0
}

/// Reports whether this process's mount table changed after it was created,
/// so a test counting mount-table reads can tell a real change (which must be
/// read again) from a redundant read.
#[cfg(test)]
pub(crate) struct MountChangeWitness(std::fs::File);

#[cfg(test)]
impl MountChangeWitness {
    pub(crate) fn new() -> Self {
        Self(std::fs::File::open("/proc/self/mountinfo").unwrap())
    }

    pub(crate) fn changed(&self) -> bool {
        mount_table_changed(&self.0)
    }
}

/// One retained view's mount table, read once and reused for as long as the
/// kernel reports its mount namespace unchanged (H-3). A scan used to read
/// and parse `/proc/<pid>/mountinfo` once per mapped object.
///
/// Reuse is exact, not a heuristic: the table fd stays open, and
/// `/proc/<pid>/mountinfo` reports `POLLPRI` once the namespace's mount table
/// changes after the fd was opened or last polled (proc(5); the kernel's
/// `mounts_poll`). Every use first proves "unchanged since read" with a
/// zero-timeout poll, after the object was opened, so the answer is as fresh
/// as a table read after the open — the property `open_then_mountinfo`
/// exists for. Any change, or a failed poll, reads the table again. One
/// cache serves one view: another view, or a view of another pid, reads its
/// own table.
pub(crate) struct MountTableCache {
    table: Option<CachedMountTable>,
    changed: fn(&std::fs::File) -> bool,
}

struct CachedMountTable {
    owner: (ProcessViewId, u32),
    file: std::fs::File,
    text: String,
}

impl Default for MountTableCache {
    fn default() -> Self {
        Self {
            table: None,
            changed: mount_table_changed,
        }
    }
}

impl MountTableCache {
    /// A cache whose change detector is `changed` instead of `poll(2)`.
    #[cfg(test)]
    pub(crate) fn with_change_detector_for_test(changed: fn(&std::fs::File) -> bool) -> Self {
        Self {
            table: None,
            changed,
        }
    }

    /// Forgets the table, so the next use reads a fresh one.
    pub(crate) fn invalidate(&mut self) {
        self.table = None;
    }

    fn refresh(
        &mut self,
        owner: (ProcessViewId, u32),
        budget: &mut CaptureWorkBudget,
    ) -> Result<(), String> {
        if let Some(table) = &self.table
            && table.owner == owner
            && !(self.changed)(&table.file)
        {
            return Ok(());
        }
        self.table = None;
        let (file, text) = read_view_mountinfo(owner.1, budget)?;
        self.table = Some(CachedMountTable { owner, file, text });
        Ok(())
    }

    fn text(&self) -> &str {
        self.table.as_ref().map_or("", |table| table.text.as_str())
    }
}

fn open_then_mountinfo_checked<T, M>(
    mut ensure_retained: impl FnMut() -> Result<(), String>,
    open: impl FnOnce() -> Result<T, String>,
    read_mountinfo: impl FnOnce() -> Result<M, String>,
) -> Result<(T, M), String> {
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

    #[cfg(test)]
    pub(crate) fn first_use_birth_ticks(&self) -> Option<u64> {
        self.pin.start_time
    }

    pub(crate) fn admitted_ns(&self) -> u64 {
        self.admitted_ns
    }

    /// The `/proc` start time the view's pin retained (clock ticks since
    /// boot), `None` when it was unreadable: the generation a projection
    /// joins against the caller incarnation.
    pub(crate) fn start_time(&self) -> Option<u64> {
        self.pin.start_time()
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

    pub(crate) fn original_generation_state(&self) -> Result<OriginalGenerationState, String> {
        self.pin.original_generation_state()
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
        budget: &mut CaptureWorkBudget,
    ) -> Result<(T, String), String> {
        open_then_mountinfo_checked(
            || self.ensure_retained(),
            open,
            || read_view_mountinfo(self.pid(), budget).map(|(_, text)| text),
        )
    }

    /// [`Self::open_then_mountinfo`] against `mounts`, which reads this view's
    /// table once and proves it unchanged — after `open` — on every later use.
    pub(crate) fn open_then_cached_mountinfo<'c, T>(
        &self,
        open: impl FnOnce() -> Result<T, String>,
        mounts: &'c mut MountTableCache,
        budget: &mut CaptureWorkBudget,
    ) -> Result<(T, &'c str), String> {
        let owner = (self.id(), self.pid());
        let (opened, ()) = open_then_mountinfo_checked(
            || self.ensure_retained(),
            open,
            || mounts.refresh(owner, budget),
        )?;
        Ok((opened, mounts.text()))
    }
}

pub fn stale_view_ids(views: &[ProcessView]) -> Vec<ProcessViewId> {
    views
        .iter()
        .filter(|view| !view.still_the_same())
        .map(ProcessView::id)
        .collect()
}

#[cfg(test)]
pub(crate) fn reused_process_view_for_test(
    id: ProcessViewId,
    pid: u32,
) -> Result<ProcessView, String> {
    let mut view = ProcessView::open(id, pid)?;
    let retained = process_start_time(pid)
        .map_err(|error| format!("cannot build reused-pid test view: {error}"))?
        .wrapping_add(1);
    view.pin = PidPin {
        pid,
        pidfd: None,
        start_time: Some(retained),
    };
    Ok(view)
}

#[cfg(test)]
pub(crate) fn unprovable_process_view_for_test(
    id: ProcessViewId,
    pid: u32,
) -> Result<ProcessView, String> {
    let mut view = ProcessView::open(id, pid)?;
    view.pin = PidPin {
        pid,
        pidfd: None,
        start_time: None,
    };
    Ok(view)
}

/// A view pinned by `/proc` start time only, for the no-executable loader
/// test: the child is killed into a zombie AFTER this opens, so
/// `/proc/PID/exe` readlinks ENOENT while the retained start time still
/// matches and `still_the_same()` stays true (the kthread shape — a live
/// generation with no executable — without needing a kernel thread).
#[cfg(test)]
pub(crate) fn start_time_pinned_process_view_for_test(
    id: ProcessViewId,
    pid: u32,
) -> Result<ProcessView, String> {
    let mut view = ProcessView::open(id, pid)?;
    let retained = process_start_time(pid)
        .map_err(|error| format!("cannot build start-time-pinned test view: {error}"))?;
    view.pin = PidPin {
        pid,
        pidfd: None,
        start_time: Some(retained),
    };
    Ok(view)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OriginalGenerationState {
    Current,
    Exited,
    Reused,
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

/// The kernel's current pid ceiling: a pid above it never named a process.
/// `None` when the sysctl is unreadable — the failure text then falls back
/// to the in-range wording, which stays true either way.
fn max_pid() -> Option<u32> {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Explains why `pid` could not be pinned without naming the `pidfd`/`/proc`
/// plumbing: an above-maximum pid is a typo, while an in-range pid with no
/// live process either exited before attach or is an in-range typo — each
/// names the check to run next.
fn pin_failure(pid: u32) -> String {
    match max_pid() {
        Some(max) if pid > max => format!(
            "cannot pin pid {pid}: no such pid (above this host's maximum {max}); check for a typo"
        ),
        _ => format!(
            "cannot pin pid {pid}: no live process with that pid (it exited, or the pid is a typo); check with `ps -p {pid}`"
        ),
    }
}

impl PidPin {
    pub fn open(pid: u32) -> Result<Self, String> {
        let start_time = process_start_time(pid).ok();
        let pidfd = pidfd_open(pid).ok();
        if pidfd.is_none() && start_time.is_none() {
            return Err(pin_failure(pid));
        }
        Ok(Self {
            pid,
            pidfd,
            start_time,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_proc_only(pid: u32) -> Self {
        Self {
            pid,
            pidfd: None,
            start_time: Some(1),
        }
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The `/proc` start time retained at `open` (clock ticks since boot),
    /// the same basis caller incarnations carry; `None` when unreadable.
    pub(crate) fn start_time(&self) -> Option<u64> {
        self.start_time
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

    pub(crate) fn original_generation_state(&self) -> Result<OriginalGenerationState, String> {
        let pidfd_ready = self.pidfd.as_ref().map(pidfd_ready);
        original_generation_state_with(pidfd_ready, self.start_time, || {
            process_start_time(self.pid)
        })
        .map_err(|error| {
            format!(
                "cannot classify the original generation of pid {}: {error}",
                self.pid
            )
        })
    }

    /// Proves that this pin retained the original pidfd and that the kernel
    /// still grants signal authority for that exact process generation.
    pub(crate) fn probe_signal_authority(&self) -> Result<(), String> {
        self.send_signal(0)
    }

    pub(crate) fn pidfd(&self) -> io::Result<BorrowedFd<'_>> {
        self.pidfd
            .as_ref()
            .map(AsFd::as_fd)
            .ok_or_else(|| io::Error::other("process pin has no original pidfd"))
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

fn original_generation_state_with(
    pidfd_ready: Option<io::Result<bool>>,
    retained_start: Option<u64>,
    current_start: impl FnOnce() -> io::Result<u64>,
) -> io::Result<OriginalGenerationState> {
    let pidfd_exited = match pidfd_ready {
        Some(Ok(false)) => return Ok(OriginalGenerationState::Current),
        Some(Ok(true)) => true,
        Some(Err(error)) => return Err(error),
        None => false,
    };

    match current_start() {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(OriginalGenerationState::Exited)
        }
        Err(error) => Err(error),
        Ok(current) => {
            let retained = retained_start.ok_or_else(|| {
                io::Error::other(
                    "cannot distinguish original exit from PID reuse without a start time",
                )
            })?;
            if current != retained {
                Ok(OriginalGenerationState::Reused)
            } else if pidfd_exited {
                Ok(OriginalGenerationState::Exited)
            } else {
                Ok(OriginalGenerationState::Current)
            }
        }
    }
}

pub(crate) fn raise_nofile() -> io::Result<usize> {
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
    } else if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
        Err(io::Error::other(format!(
            "original pidfd poll failed: revents={:#x}",
            pollfd.revents
        )))
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

/// True when `pid` names a zombie: the generation exited but its parent
/// has not reaped it, so `/proc/<pid>/stat` still parses while the
/// process is dead. Any read or parse failure answers false — an
/// unreadable pid is merely unknown here, and `generation_gone` covers
/// the reaped case. The inventory adapter treats zombies as exited:
/// without this, an unreaped target (the observer is often its parent)
/// re-admits every pass under a fresh caller ID.
pub(crate) fn process_is_zombie(pid: u32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some(end) = stat.rfind(')') else {
        return false;
    };
    stat[end + 1..]
        .split_whitespace()
        .next()
        .is_some_and(|state| state == "Z")
}

fn gone_from(start_time: io::Result<u64>) -> bool {
    start_time.is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
}

pub(crate) fn process_start_time(pid: u32) -> io::Result<u64> {
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
                Ok::<String, String>("17 1 8:1 / / rw - ext4 /dev/root rw\n".into())
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
    fn root_fence_owned_poll_error_is_not_a_timeout() {
        // Own both pipe ends: dropping the reader makes poll report POLLERR.
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let fd: OwnedFd = writer.into();
        assert!(pidfd_ready_with_timeout(&fd, 0).is_err());
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

    /// Mutation caught: classifying a changed `/proc` start time as an exit
    /// would grant a later process at the reused numeric PID terminal authority.
    #[test]
    fn original_generation_state_distinguishes_exit_from_pid_reuse() {
        let current_reads = Cell::new(0);
        assert_eq!(
            original_generation_state_with(Some(Ok(false)), None, || {
                current_reads.set(current_reads.get() + 1);
                Ok(10)
            })
            .unwrap(),
            OriginalGenerationState::Current
        );
        assert_eq!(
            current_reads.get(),
            0,
            "a live pidfd is already exact generation evidence"
        );

        assert_eq!(
            original_generation_state_with(None, Some(10), || Ok(10)).unwrap(),
            OriginalGenerationState::Current
        );
        assert_eq!(
            original_generation_state_with(None, Some(10), || Ok(11)).unwrap(),
            OriginalGenerationState::Reused
        );
        assert_eq!(
            original_generation_state_with(None, Some(10), || {
                Err(io::Error::from(io::ErrorKind::NotFound))
            })
            .unwrap(),
            OriginalGenerationState::Exited
        );
        assert_eq!(
            original_generation_state_with(Some(Ok(true)), Some(10), || Ok(10)).unwrap(),
            OriginalGenerationState::Exited,
            "an exited pidfd can still have a same-generation zombie in /proc"
        );

        assert_eq!(
            original_generation_state_with(
                Some(Err(io::Error::from(io::ErrorKind::Interrupted))),
                Some(10),
                || Ok(10)
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        assert_eq!(
            original_generation_state_with(None, Some(10), || {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            original_generation_state_with(None, None, || Ok(10))
                .unwrap_err()
                .kind(),
            io::ErrorKind::Other,
            "missing retained start time is unknown, never exit"
        );
    }

    #[test]
    fn original_pidfd_is_the_only_signal_authority() {
        let mut child = Command::new("sleep").arg("10").spawn().unwrap();
        let pin = PidPin::open(child.id()).unwrap();
        pin.probe_signal_authority().unwrap();
        assert_eq!(
            pin.pidfd().unwrap().as_raw_fd(),
            pin.pidfd.as_ref().unwrap().as_raw_fd()
        );
        pin.send_signal(libc::SIGTERM).unwrap();
        let status = child.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM));

        let fallback = PidPin {
            pid: std::process::id(),
            pidfd: None,
            start_time: process_start_time(std::process::id()).ok(),
        };
        assert!(fallback.probe_signal_authority().is_err());
        assert_eq!(fallback.pidfd().unwrap_err().kind(), io::ErrorKind::Other);
        assert!(fallback.send_signal(0).is_err());
    }

    #[test]
    fn nofile_raise_is_monotonic_and_reports_a_usable_budget() {
        fn soft_limit() -> libc::rlim_t {
            let mut limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: same valid-pointer pattern as raise_nofile.
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
                0
            );
            limit.rlim_cur
        }
        let before = soft_limit();
        let budget = raise_nofile().expect("raise reports a budget");
        assert!(
            soft_limit() >= before,
            "raise must never shrink the soft limit"
        );
        assert!(
            budget >= RESERVED_FDS,
            "budget must cover reserved fds: {budget}"
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

    /// Real `pidfd_open` denial through a kernel seccomp filter. The filter
    /// checks the native x86-64 syscall ABI, so the regression is x86-64 only.
    #[cfg(target_arch = "x86_64")]
    mod pidfd_denial {
        use super::*;

        const PIDFD_DENIAL_HELPER: &str = "process::tests::pidfd_denial::pidfd_denial_helper";
        const PIDFD_DENIAL_ERRNO: &str = "P11SCOPE_TEST_PIDFD_DENIAL_ERRNO";
        const PIDFD_DENIAL_TARGET: &str = "P11SCOPE_TEST_PIDFD_DENIAL_TARGET";
        const PIDFD_DENIAL_START: &str = "P11SCOPE_TEST_PIDFD_DENIAL_START";
        const PIDFD_DENIAL_TOKEN: &str = "P11SCOPE_TEST_PIDFD_DENIAL_TOKEN";
        const PIDFD_DENIAL_ACK: &str = "pidfd-denial-ack";
        const PIDFD_DENIAL_DEADLINE: Duration = Duration::from_secs(30);

        /// Kills and reaps an owned child on every path that has not already
        /// consumed its wait status, so a failed assertion leaks no process.
        struct ReapOnDrop(Option<std::process::Child>);

        impl ReapOnDrop {
            fn child(&mut self) -> &mut std::process::Child {
                self.0.as_mut().expect("the child is still owned")
            }

            fn reap(&mut self) -> std::process::ExitStatus {
                let status = self.child().wait().expect("reap the owned child");
                self.0 = None;
                status
            }
        }

        impl Drop for ReapOnDrop {
            fn drop(&mut self) {
                if let Some(mut child) = self.0.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        /// Makes `pidfd_open` fail with `errno` for the calling thread and the
        /// threads it creates. Every other native syscall is allowed. A non-x86-64
        /// audit arch such as i386 kills the process; x32 shares the x86-64 audit
        /// arch and is not distinguished, which this helper never uses.
        fn deny_pidfd_open(errno: i32) -> io::Result<()> {
            const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
            // `struct seccomp_data` field offsets.
            const NR: u32 = 0;
            const ARCH: u32 = 4;
            let errno = u32::try_from(errno)
                .ok()
                .filter(|errno| *errno <= libc::SECCOMP_RET_DATA)
                .ok_or_else(|| io::Error::other(format!("errno {errno} does not fit seccomp")))?;
            let stmt = |code: u32, k: u32| libc::sock_filter {
                code: code as u16,
                jt: 0,
                jf: 0,
                k,
            };
            let jump = |k: u32, jt: u8, jf: u8| libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt,
                jf,
                k,
            };
            // Jump offsets are relative to the next instruction.
            let mut filter = [
                stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, ARCH),
                jump(AUDIT_ARCH_X86_64, 1, 0),
                stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_KILL_PROCESS),
                stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, NR),
                jump(libc::SYS_pidfd_open as u32, 0, 1),
                stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ERRNO | errno),
                stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
            ];
            let program = libc::sock_fprog {
                len: filter.len() as u16,
                filter: filter.as_mut_ptr(),
            };
            // SAFETY: constant prctl option; it restricts only this thread and
            // its future children.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `program` points at `filter`, which outlives the call; the
            // kernel copies the program before returning.
            let installed = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    libc::SECCOMP_SET_MODE_FILTER,
                    0,
                    &raw const program,
                )
            };
            if installed != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// One field of this thread's status, `None` when the kernel lacks it
        /// (`Seccomp_filters` appeared in Linux 5.9).
        fn thread_status_field(field: &str) -> Option<String> {
            std::fs::read_to_string("/proc/thread-self/status")
                .expect("read this thread's status")
                .lines()
                .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
                .map(|value| value.trim().to_string())
        }

        fn assert_fallback_has_no_signal_authority(pin: &PidPin) {
            let refused = "process pin has no original pidfd signal authority";
            assert_eq!(pin.probe_signal_authority().unwrap_err(), refused);
            assert_eq!(pin.send_signal(0).unwrap_err(), refused);
            assert_eq!(pin.pidfd().unwrap_err().kind(), io::ErrorKind::Other);
            assert_eq!(
                pin.wait_ready(Some(Duration::ZERO)).unwrap_err().kind(),
                io::ErrorKind::Other
            );
        }

        /// The confined half of the pidfd-denial regression. It runs in a fresh
        /// exec of this test binary so the seccomp filter never reaches the
        /// parent, and reports each verified phase back with the parent's token.
        #[test]
        #[ignore = "private seccomp helper; invoked by real_pidfd_denial_preserves_proc_identity_without_signal_authority"]
        fn pidfd_denial_helper() {
            let env = |name: &str| {
                std::env::var(name).unwrap_or_else(|_| panic!("the parent test supplies {name}"))
            };
            let errno: i32 = env(PIDFD_DENIAL_ERRNO).parse().unwrap();
            let target: u32 = env(PIDFD_DENIAL_TARGET).parse().unwrap();
            let start: u64 = env(PIDFD_DENIAL_START).parse().unwrap();
            let token = env(PIDFD_DENIAL_TOKEN);
            assert!(
                [libc::EPERM, libc::ENOSYS].contains(&errno),
                "unexpected denial errno {errno}"
            );
            let ack = |phase: &str| {
                use std::io::Write as _;
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{PIDFD_DENIAL_ACK} {token} {errno} {phase}").unwrap();
                stdout.flush().unwrap();
            };
            let await_phase = |phase: &str| {
                let mut line = String::new();
                std::io::stdin()
                    .read_line(&mut line)
                    .expect("read the parent's next phase");
                assert_eq!(
                    line.trim_end(),
                    format!("{token} {phase}"),
                    "the parent must request the {phase} phase"
                );
            };

            // The runner may already be confined (a container's default
            // profile); require this filter on top rather than none before it.
            let filters = || {
                thread_status_field("Seccomp_filters")
                    .map(|count| count.parse::<u64>().expect("a filter count"))
            };
            let before = filters();
            deny_pidfd_open(errno).expect("install the pidfd_open seccomp filter");
            assert_eq!(
                thread_status_field("Seccomp").as_deref(),
                Some("2"),
                "the filter confines this thread"
            );
            assert_eq!(
                filters(),
                before.map(|count| count + 1),
                "exactly this filter was added"
            );
            // SAFETY: scalar pid/flags; a descriptor returned despite the filter
            // is never used and dies with this helper.
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, target, 0) };
            assert_eq!(
                (raw, io::Error::last_os_error().raw_os_error()),
                (-1, Some(errno)),
                "the raw pidfd_open canary must receive the selected errno"
            );
            assert_eq!(
                process_start_time(target).expect("/proc/PID/stat stays readable"),
                start,
                "the helper reads the target's real start time"
            );

            // Production code, not a substituted pin or reader.
            let view = ProcessView::open(ProcessViewId(1), target)
                .expect("the /proc fallback admits a live target without a pidfd");
            assert!(
                view.pin.pidfd.is_none(),
                "denied pidfd_open retains no pidfd"
            );
            assert_eq!(view.pin.start_time, Some(start));
            assert!(view.still_the_same());
            assert_eq!(view.original_exited(), Ok(false));
            assert_eq!(
                view.original_generation_state(),
                Ok(OriginalGenerationState::Current)
            );
            assert_fallback_has_no_signal_authority(&view.pin);
            let pin = PidPin::open(target).expect("PidPin falls back to /proc identity");
            assert!(pin.pidfd.is_none());
            assert_eq!(pin.start_time, Some(start));
            assert_fallback_has_no_signal_authority(&pin);
            ack("live");

            // The parent proved exit without reaping. The /proc fallback cannot
            // tell this zombie from its live generation, so it must keep
            // answering "same generation": a cleanup oracle built on it then
            // rejects the unreaped child instead of reporting it cleaned up.
            await_phase("zombie");
            assert!(process_is_zombie(target), "the parent killed the target");
            assert_eq!(process_start_time(target).ok(), Some(start));
            assert!(view.still_the_same());
            assert_eq!(view.original_exited(), Ok(false));
            assert_eq!(
                view.original_generation_state(),
                Ok(OriginalGenerationState::Current)
            );
            assert_fallback_has_no_signal_authority(&view.pin);
            ack("zombie");

            await_phase("reaped");
            assert!(
                !view.still_the_same(),
                "a reaped generation is not retained"
            );
            assert_eq!(view.original_exited(), Ok(true));
            assert_eq!(stale_view_ids(std::slice::from_ref(&view)), [view.id()]);
            match process_start_time(target) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    assert_eq!(
                        view.original_generation_state(),
                        Ok(OriginalGenerationState::Exited)
                    );
                    assert!(
                        PidPin::open(target).is_err(),
                        "no pidfd and no /proc entry leaves nothing to pin"
                    );
                }
                // A new process took the PID between reap and this check.
                Ok(current) if current != start => assert_eq!(
                    view.original_generation_state(),
                    Ok(OriginalGenerationState::Reused)
                ),
                other => panic!("the reaped target's /proc identity persisted: {other:?}"),
            }
            assert_fallback_has_no_signal_authority(&view.pin);
            ack("reaped");
        }

        /// The parent half: owns the target and the confined helper, drives the
        /// target through live, exited-unreaped and reaped, and requires every
        /// phase acknowledgement before the helper may exit successfully.
        struct PidfdDenialHelper {
            child: ReapOnDrop,
            lines: std::sync::mpsc::Receiver<String>,
            transcript: Vec<String>,
            stderr: std::fs::File,
            token: String,
            errno: i32,
        }

        impl PidfdDenialHelper {
            fn spawn(errno: i32, target: u32, start: u64) -> Self {
                use std::process::Stdio;

                let token = format!(
                    "{}-{target}-{errno}-{}",
                    std::process::id(),
                    crate::attach::monotonic_ns().expect("a monotonic token suffix")
                );
                let stderr = tempfile::tempfile().expect("a helper stderr capture");
                let mut child = ReapOnDrop(Some(
                    Command::new(std::env::current_exe().expect("this test binary"))
                        .args([
                            "--exact",
                            PIDFD_DENIAL_HELPER,
                            "--ignored",
                            "--nocapture",
                            "--test-threads=1",
                        ])
                        .env_clear()
                        .env(PIDFD_DENIAL_ERRNO, errno.to_string())
                        .env(PIDFD_DENIAL_TARGET, target.to_string())
                        .env(PIDFD_DENIAL_START, start.to_string())
                        .env(PIDFD_DENIAL_TOKEN, &token)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(stderr.try_clone().expect("share the stderr capture"))
                        .spawn()
                        .expect("re-exec the pidfd-denial helper"),
                ));
                let stdout = child.child().stdout.take().expect("piped helper stdout");
                let (sender, lines) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    use std::io::BufRead as _;
                    for line in std::io::BufReader::new(stdout).lines() {
                        let Ok(line) = line else { return };
                        if sender.send(line).is_err() {
                            return;
                        }
                    }
                });
                Self {
                    child,
                    lines,
                    transcript: Vec::new(),
                    stderr,
                    token,
                    errno,
                }
            }

            fn failure(&mut self, why: &str) -> String {
                use std::io::{Read as _, Seek as _};

                let mut stderr = String::new();
                let _ = self.stderr.rewind();
                let _ = self.stderr.read_to_string(&mut stderr);
                format!(
                    "pidfd-denial helper (errno {}): {why}\nstdout:\n{}\nstderr:\n{stderr}",
                    self.errno,
                    self.transcript.join("\n")
                )
            }

            fn next_line(&mut self, deadline: Instant) -> Option<String> {
                let wait = deadline.saturating_duration_since(Instant::now());
                match self.lines.recv_timeout(wait) {
                    Ok(line) => {
                        self.transcript.push(line.clone());
                        Some(line)
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        let why = "timed out waiting for helper output";
                        panic!("{}", self.failure(why))
                    }
                }
            }

            fn expect_ack(&mut self, phase: &str) {
                let expected = format!("{PIDFD_DENIAL_ACK} {} {} {phase}", self.token, self.errno);
                let deadline = Instant::now() + PIDFD_DENIAL_DEADLINE;
                loop {
                    let Some(line) = self.next_line(deadline) else {
                        let why = format!("helper output ended before the {phase} acknowledgement");
                        panic!("{}", self.failure(&why));
                    };
                    // `--nocapture` prints the first acknowledgement after
                    // libtest's unterminated `test NAME ... ` prefix.
                    if let Some(at) = line.find(PIDFD_DENIAL_ACK) {
                        if line[at..] != expected {
                            let why = format!("expected `{expected}`, got `{line}`");
                            panic!("{}", self.failure(&why));
                        }
                        return;
                    }
                }
            }

            fn request(&mut self, phase: &str) {
                use std::io::Write as _;

                let line = format!("{} {phase}\n", self.token);
                let stdin = self
                    .child
                    .child()
                    .stdin
                    .as_mut()
                    .expect("piped helper stdin");
                if let Err(error) = stdin
                    .write_all(line.as_bytes())
                    .and_then(|()| stdin.flush())
                {
                    let why = format!("cannot request the {phase} phase: {error}");
                    panic!("{}", self.failure(&why));
                }
            }

            /// Requires the helper's own test harness to report exactly one
            /// passing test, then a successful exit, within the deadline.
            fn finish(mut self) {
                let deadline = Instant::now() + PIDFD_DENIAL_DEADLINE;
                while self.next_line(deadline).is_some() {}
                let summary = "test result: ok. 1 passed; 0 failed";
                if !self.transcript.iter().any(|line| line.starts_with(summary)) {
                    panic!(
                        "{}",
                        self.failure("the helper did not run exactly one test")
                    );
                }
                loop {
                    match self.child.child().try_wait() {
                        Ok(Some(_)) => break,
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Ok(None) => panic!("{}", self.failure("the helper did not exit")),
                        Err(error) => panic!("{}", self.failure(&format!("try_wait: {error}"))),
                    }
                }
                let status = self.child.reap();
                if !status.success() {
                    panic!("{}", self.failure(&format!("helper exited with {status}")));
                }
            }
        }

        /// Without exiting or reaping: `Some(si_code)` once the owned child has
        /// exited, `None` while it still runs.
        fn exited_unreaped(pid: u32) -> io::Result<Option<i32>> {
            loop {
                let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                // SAFETY: valid output for an owned child. WNOHANG cannot block
                // and WNOWAIT leaves the wait status for Child::wait.
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid,
                        info.as_mut_ptr(),
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                // SAFETY: zero-initialized storage, filled by successful waitid.
                let info = unsafe { info.assume_init() };
                return Ok((unsafe { info.si_pid() } == pid as i32).then_some(info.si_code));
            }
        }

        fn run_pidfd_denial_case(errno: i32) {
            use std::process::Stdio;

            // `cat` blocks on its owned stdin: spawn returns after exec, so the
            // target is ready without any sleep.
            let mut target = ReapOnDrop(Some(
                Command::new("cat")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .spawn()
                    .expect("spawn the ready target"),
            ));
            let pid = target.child().id();
            let start = process_start_time(pid).expect("the parent reads the real start time");
            let exit_witness =
                pidfd_open(pid).expect("the parent stays unconfined and can open a pidfd");

            let mut helper = PidfdDenialHelper::spawn(errno, pid, start);
            helper.expect_ack("live");
            assert_eq!(
                exited_unreaped(pid).unwrap(),
                None,
                "the confined helper must not have signalled the target"
            );

            target.child().kill().expect("SIGKILL the owned target");
            let deadline_ms = PIDFD_DENIAL_DEADLINE.as_millis() as i32;
            assert!(
                pidfd_ready_with_timeout(&exit_witness, deadline_ms).unwrap(),
                "the target must exit within the deadline"
            );
            assert_eq!(exited_unreaped(pid).unwrap(), Some(libc::CLD_KILLED));
            helper.request("zombie");
            helper.expect_ack("zombie");

            let status = target.reap();
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            assert_eq!(
                exited_unreaped(pid).unwrap_err().raw_os_error(),
                Some(libc::ECHILD),
                "the target is reaped"
            );
            helper.request("reaped");
            helper.expect_ack("reaped");
            helper.finish();
        }

        /// Real `pidfd_open` denial, not an injected pin: a confined helper
        /// receives EPERM, then ENOSYS, from a kernel seccomp filter and must
        /// still pin the target through production `/proc` identity, follow it
        /// through exit and reaping, and never gain signal authority. ENOSYS
        /// models a missing syscall; it does not claim coverage of old kernels.
        #[test]
        fn real_pidfd_denial_preserves_proc_identity_without_signal_authority() {
            for errno in [libc::EPERM, libc::ENOSYS] {
                run_pidfd_denial_case(errno);
            }
        }
    }
}
