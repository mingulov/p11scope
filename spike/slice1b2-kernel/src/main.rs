#[path = "../common.rs"]
pub mod common;

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::CStr;
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

unsafe impl aya::Pod for common::StateKey {}
unsafe impl aya::Pod for common::StartState {}

const GATE_A_PROGRAMS: [&str; 4] = [
    "function_list_entry",
    "function_list_return",
    "interface_list_entry",
    "interface_list_return",
];

const GATE_B_PROGRAMS: [&str; 2] = ["signal_return", "late_hit"];

pub fn decode_discovery_record(bytes: &[u8]) -> Result<common::DiscoveryRecord, &'static str> {
    if bytes.len() != std::mem::size_of::<common::DiscoveryRecord>() {
        return Err("discovery record length is not 896 bytes");
    }
    let mut aligned = std::mem::MaybeUninit::<common::DiscoveryRecord>::uninit();
    // SAFETY: the exact-length check makes the destination large enough; the
    // repr(C) record contains only integer/byte fields, so every bit pattern is valid.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            aligned.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
        Ok(aligned.as_ptr().read_unaligned())
    }
}

pub fn decode_signal_record(bytes: &[u8]) -> Result<common::SignalRecord, &'static str> {
    if bytes.len() != std::mem::size_of::<common::SignalRecord>() {
        return Err("signal record length is not 32 bytes");
    }
    let mut aligned = std::mem::MaybeUninit::<common::SignalRecord>::uninit();
    // SAFETY: the exact-length check makes the destination large enough; the
    // repr(C) record contains only integer/byte fields, so every bit pattern is valid.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            aligned.as_mut_ptr().cast::<u8>(),
            bytes.len(),
        );
        Ok(aligned.as_ptr().read_unaligned())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReadOutcome {
    pub usable_n: u8,
    pub pointers_attempted: u8,
    pub completed_prefix: u8,
    pub read_failures: u64,
    pub truncations: u64,
}

pub fn discovery_read_outcome(
    attempted: u8,
    completed: u8,
    read_failed: bool,
    truncated: bool,
) -> ReadOutcome {
    ReadOutcome {
        usable_n: if read_failed { 0 } else { completed },
        pointers_attempted: attempted,
        completed_prefix: completed,
        read_failures: u64::from(read_failed),
        truncations: u64::from(truncated),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameClass {
    ExactStandard,
    Other,
    Null,
    Unreadable,
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordFacts {
    pub usable_n: u8,
    pub pointers_attempted: u8,
    pub completed_prefix: u8,
    pub name_class: NameClass,
    pub all_usable_pointers_nonzero: bool,
    pub all_usable_pointers_equal_fixture: bool,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum GateACaseId {
    Full104,
    GuardAfter7,
    UnreadableTable,
    UnreadablePp,
    Interfaces17,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateACaseFacts {
    pub case: GateACaseId,
    pub entry_attach_attempts: u8,
    pub entry_attach_accepted: bool,
    pub return_attach_attempts: u8,
    pub return_attach_accepted: bool,
    pub entry_link_detached: bool,
    pub return_link_detached: bool,
    pub records: Vec<RecordFacts>,
    pub counters_before: [u64; 5],
    pub counters_after: [u64; 5],
    pub start_empty: bool,
}

pub fn gate_a_case_pass(facts: &GateACaseFacts) -> bool {
    let not_applicable = |usable_n, attempted, completed| RecordFacts {
        usable_n,
        pointers_attempted: attempted,
        completed_prefix: completed,
        name_class: NameClass::NotApplicable,
        all_usable_pointers_nonzero: true,
        all_usable_pointers_equal_fixture: true,
    };
    let interface = |usable_n, attempted, completed, name_class| RecordFacts {
        usable_n,
        pointers_attempted: attempted,
        completed_prefix: completed,
        name_class,
        all_usable_pointers_nonzero: true,
        all_usable_pointers_equal_fixture: true,
    };
    let (expected_records, expected_delta) = match facts.case {
        GateACaseId::Full104 => (vec![not_applicable(104, 104, 104)], [0, 0, 0, 0, 0]),
        GateACaseId::GuardAfter7 => (vec![not_applicable(0, 8, 7)], [0, 1, 0, 0, 0]),
        GateACaseId::UnreadableTable | GateACaseId::UnreadablePp => {
            (vec![not_applicable(0, 0, 0)], [0, 1, 0, 0, 0])
        }
        GateACaseId::Interfaces17 => {
            let mut records = (0..12)
                .map(|_| interface(104, 104, 104, NameClass::ExactStandard))
                .collect::<Vec<_>>();
            records.extend([
                interface(0, 8, 7, NameClass::ExactStandard),
                interface(0, 0, 0, NameClass::Other),
                interface(0, 0, 0, NameClass::Null),
                interface(0, 0, 0, NameClass::Unreadable),
            ]);
            (records, [0, 2, 0, 1, 0])
        }
    };
    let Some(delta) = facts
        .counters_after
        .iter()
        .zip(facts.counters_before)
        .map(|(after, before)| after.checked_sub(before))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    facts.entry_attach_attempts == 1
        && facts.entry_attach_accepted
        && facts.return_attach_attempts == 1
        && facts.return_attach_accepted
        && facts.entry_link_detached
        && facts.return_link_detached
        && facts.start_empty
        && facts.records == expected_records
        && delta.as_slice() == expected_delta
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SignalTimingFacts {
    pub hook_ts_ns: u64,
    pub send_signal_rc: i64,
    pub stop_request_accepted: bool,
    pub expected_task_count: u32,
    pub winner_records: u64,
    pub coalesced_records: u64,
    pub signal_helper_calls: u64,
    pub winner_case_id: u8,
    pub coalesced_case_id: u8,
    pub stopped_snapshot_1_count: u32,
    pub stopped_snapshot_2_count: u32,
    pub stopped_snapshot_1_exact_expected_task_set: bool,
    pub stopped_snapshot_1_all_tasks_stopped: bool,
    pub stopped_snapshot_2_exact_expected_task_set: bool,
    pub stopped_snapshot_2_all_tasks_stopped: bool,
    pub confirmation_sample_indexes: Option<(usize, usize)>,
    pub samples: Vec<StopSnapshot>,
    pub pre_stop_marker_observed: bool,
    pub drain_empty: bool,
    pub required_attach_keys: u64,
    pub post_attach_task_count: u32,
    pub post_attach_exact_expected_task_set: bool,
    pub post_attach_all_tasks_stopped: bool,
    pub post_attach_marker_observed: bool,
    pub attached_while_stopped: u64,
    pub queue_empty_before_resume: bool,
    pub markers_after_resume: u32,
    pub signal_attach_attempts: u8,
    pub signal_attach_accepted: bool,
    pub late_attach_attempts: u8,
    pub late_attach_accepted: bool,
    pub signal_link_detached: bool,
    pub late_link_detached: bool,
    pub last_attach_ts_ns: u64,
    pub attach_gap_ms: f64,
    pub pidfd_resume_attempts: u8,
    pub pidfd_resume_rc: i64,
    pub resume_via_original_pidfd: bool,
    pub owner_removed: bool,
    pub final_start_entries: u64,
    pub post_resume_marker_observed: bool,
    pub late_hits: u64,
    pub child_exit: i32,
    pub reaped: bool,
}

pub fn signal_oracle_pass(facts: &SignalTimingFacts) -> bool {
    let Some(gap_ns) = facts.last_attach_ts_ns.checked_sub(facts.hook_ts_ns) else {
        return false;
    };
    let expected_gap_ms = gap_ns as f64 / 1_000_000.0;
    facts.hook_ts_ns != 0
        && facts.send_signal_rc == 0
        && facts.stop_request_accepted
        && facts.expected_task_count == 2
        && facts.winner_records == 1
        && facts.coalesced_records == 1
        && facts.signal_helper_calls == 1
        && facts.winner_case_id != facts.coalesced_case_id
        && ((facts.winner_case_id == 1 && facts.coalesced_case_id == 2)
            || (facts.winner_case_id == 2 && facts.coalesced_case_id == 1))
        && facts.stopped_snapshot_1_count == facts.expected_task_count
        && facts.stopped_snapshot_2_count == facts.expected_task_count
        && facts.stopped_snapshot_1_exact_expected_task_set
        && facts.stopped_snapshot_1_all_tasks_stopped
        && facts.stopped_snapshot_2_exact_expected_task_set
        && facts.stopped_snapshot_2_all_tasks_stopped
        && facts.confirmation_sample_indexes.is_some()
        && !facts.pre_stop_marker_observed
        && facts.drain_empty
        && facts.required_attach_keys == 2
        && facts.post_attach_task_count == facts.expected_task_count
        && facts.post_attach_exact_expected_task_set
        && facts.post_attach_all_tasks_stopped
        && !facts.post_attach_marker_observed
        && facts.attached_while_stopped == 2
        && facts.queue_empty_before_resume
        && facts.signal_attach_attempts == 2
        && facts.signal_attach_accepted
        && facts.late_attach_attempts == 2
        && facts.late_attach_accepted
        && facts.signal_link_detached
        && facts.late_link_detached
        && facts.attach_gap_ms.is_finite()
        && (facts.attach_gap_ms - expected_gap_ms).abs() <= f64::EPSILON
        && facts.pidfd_resume_attempts == 1
        && facts.pidfd_resume_rc == 0
        && facts.resume_via_original_pidfd
        && facts.owner_removed
        && facts.final_start_entries == 0
        && facts.post_resume_marker_observed
        && facts.markers_after_resume == 2
        && facts.late_hits == 2
        && facts.child_exit == 0
        && facts.reaped
}

pub fn parse_task_state(stat: &str) -> Result<u8, &'static str> {
    let start = stat.rfind(") ").ok_or("stat comm delimiter")? + 2;
    let state = stat.as_bytes().get(start).copied().ok_or("stat state")?;
    if state.is_ascii_alphabetic() {
        Ok(state)
    } else {
        Err("stat state")
    }
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.mode(0o700).create(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.mode() & 0o777 != 0o700 {
        return Err(io::Error::other("new output directory is not private"));
    }
    Ok(())
}

pub fn create_private_file(path: &Path) -> io::Result<File> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.mode() & 0o777 != 0o600 {
        return Err(io::Error::other("new evidence file is not private"));
    }
    Ok(file)
}

pub fn make_manifest_read_only(file: &File) -> io::Result<()> {
    file.sync_all()?;
    file.set_permissions(std::fs::Permissions::from_mode(0o400))
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupFacts {
    pub may_be_stopped: bool,
    pub resume_attempts: u8,
    pub resume_via_original_pidfd: bool,
    pub kill_via_original_pidfd: bool,
    pub reaped: bool,
}

pub fn cleanup_oracle_pass(facts: CleanupFacts) -> bool {
    facts.resume_attempts <= 1
        && (facts.resume_attempts == 0 || facts.resume_via_original_pidfd)
        && (!facts.may_be_stopped || facts.resume_attempts == 1)
        && facts.kill_via_original_pidfd
        && facts.reaped
}

#[derive(Debug)]
pub struct SpawnFailure {
    pub pidfd_error: io::Error,
    pub kill_succeeded: bool,
    pub reaped: bool,
}

impl fmt::Display for SpawnFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "pidfd_open failed; gated-child cleanup recorded")
    }
}

pub struct ChildGuard {
    child: Child,
    original_pidfd: OwnedFd,
    release_writer: OwnedFd,
    may_be_stopped: bool,
    resume_attempted: bool,
    reaped: bool,
}

impl ChildGuard {
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn mark_may_be_stopped(&mut self) {
        self.may_be_stopped = true;
    }

    pub fn release(&self) -> io::Result<()> {
        write_byte(self.release_writer.as_raw_fd(), 1)
    }

    pub fn resume_once(&mut self) -> io::Result<()> {
        if self.resume_attempted {
            return Err(io::Error::other("child resume was already attempted"));
        }
        self.resume_attempted = true;
        let result = pidfd_send_signal(self.original_pidfd.as_raw_fd(), libc::SIGCONT);
        if result.is_ok() {
            self.may_be_stopped = false;
        }
        result
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }

    fn terminate(&mut self) -> CleanupFacts {
        let may_be_stopped = self.may_be_stopped;
        let mut facts = CleanupFacts {
            may_be_stopped,
            ..CleanupFacts::default()
        };
        if self.reaped {
            facts.reaped = true;
            return facts;
        }
        if self.may_be_stopped && !self.resume_attempted {
            self.resume_attempted = true;
            facts.resume_attempts = 1;
            facts.resume_via_original_pidfd = true;
            if pidfd_send_signal(self.original_pidfd.as_raw_fd(), libc::SIGCONT).is_ok() {
                self.may_be_stopped = false;
            }
        }
        facts.kill_via_original_pidfd = true;
        let _ = pidfd_send_signal(self.original_pidfd.as_raw_fd(), libc::SIGKILL);
        self.reaped = self.child.wait().is_ok();
        facts.reaped = self.reaped;
        facts
    }
}

pub fn spawn_pinned_child_with<F>(
    command: &mut Command,
    open_pidfd: F,
) -> Result<ChildGuard, SpawnFailure>
where
    F: FnOnce(u32) -> io::Result<OwnedFd>,
{
    let (release_reader, release_writer) =
        pipe_pair(libc::O_CLOEXEC).map_err(|error| SpawnFailure {
            pidfd_error: error,
            kill_succeeded: false,
            reaped: false,
        })?;
    command.stdin(Stdio::from(release_reader));
    let mut child = command.spawn().map_err(|error| SpawnFailure {
        pidfd_error: error,
        kill_succeeded: false,
        reaped: false,
    })?;
    match open_pidfd(child.id()) {
        Ok(original_pidfd) => Ok(ChildGuard {
            child,
            original_pidfd,
            release_writer,
            may_be_stopped: false,
            resume_attempted: false,
            reaped: false,
        }),
        Err(pidfd_error) => {
            let kill_succeeded = child.kill().is_ok();
            drop(release_writer);
            let reaped = child.wait().is_ok();
            Err(SpawnFailure {
                pidfd_error,
                kill_succeeded,
                reaped,
            })
        }
    }
}

pub fn spawn_pinned_child(command: &mut Command) -> Result<ChildGuard, SpawnFailure> {
    spawn_pinned_child_with(command, |pid| {
        // SAFETY: pidfd_open takes the owned child's numeric pid and scalar flags,
        // returning a new descriptor on success.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: the successful syscall returned a uniquely owned descriptor.
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    })
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

trait PauseOwnerMap {
    fn insert_armed(&mut self, key: &common::StateKey) -> Result<(), &'static str>;
    fn remove_owner(&mut self, key: &common::StateKey) -> Result<(), &'static str>;
    fn entry_count(&self) -> Result<u64, &'static str>;
}

impl PauseOwnerMap
    for aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>
{
    fn insert_armed(&mut self, key: &common::StateKey) -> Result<(), &'static str> {
        self.insert(
            key,
            common::StartState {
                arg0: common::PAUSE_ARMED,
                arg1: 0,
            },
            common::BPF_NOEXIST_FLAG,
        )
        .map(|_| ())
        .map_err(|_| "start map insert")
    }

    fn remove_owner(&mut self, key: &common::StateKey) -> Result<(), &'static str> {
        self.remove(key).map(|_| ()).map_err(|_| "start map remove")
    }

    fn entry_count(&self) -> Result<u64, &'static str> {
        let mut count = 0u64;
        for key in self.keys() {
            let _ = key.map_err(|_| "start map read")?;
            count += 1;
        }
        Ok(count)
    }
}

/// State machine for the START group-key entry (§5.2). The runner removes the entry
/// through the guard on every exit path — `close_after_resume()` immediately after
/// the single successful original-pidfd resume (before markers/exit), or the
/// post-cleanup `disarm_for_cleanup()` (ordered after ChildGuard cleanup, so a
/// stopped child is resumed exactly once first). The guard never resumes a child.
struct PauseOwnerGuard {
    key: common::StateKey,
    armed: bool,
    closed: bool,
}

impl PauseOwnerGuard {
    fn new(key: common::StateKey) -> Self {
        Self {
            key,
            armed: true,
            closed: false,
        }
    }

    fn close_after_resume<M: PauseOwnerMap>(&mut self, map: &mut M) -> Result<bool, &'static str> {
        if self.closed {
            return Ok(true);
        }
        map.remove_owner(&self.key)?;
        self.closed = true;
        self.armed = false;
        Ok(true)
    }

    fn start_entries<M: PauseOwnerMap>(&self, map: &M) -> Result<u64, &'static str> {
        map.entry_count()
    }

    fn needs_removal(&self) -> bool {
        self.armed && !self.closed
    }

    fn disarm_for_cleanup<M: PauseOwnerMap>(&mut self, map: &mut M) {
        if self.needs_removal() {
            let _ = map.remove_owner(&self.key);
        }
        self.armed = false;
    }
}

fn pipe_pair(flags: i32) -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to two writable integers; pipe2 initializes both on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), flags) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn pidfd_send_signal(pidfd: i32, signal: i32) -> io::Result<()> {
    // SAFETY: pidfd is retained by ChildGuard; siginfo is null and flags are zero.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
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

fn write_byte(fd: i32, byte: u8) -> io::Result<()> {
    // SAFETY: byte lives for the one-byte write; fd is an owned pipe descriptor.
    let result = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    if result == 1 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancelled {
    Sigint,
    Sigterm,
}

static CANCELLATION_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

extern "C" fn cancellation_handler(signal: i32) {
    let fd = CANCELLATION_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte = signal as u8;
        // SAFETY: async-signal-safe write of one byte to the installed pipe.
        let _ = unsafe { libc::write(fd, (&byte as *const u8).cast(), 1) };
    }
}

pub struct Cancellation {
    read: OwnedFd,
    write: OwnedFd,
    old_sigint: libc::sigaction,
    old_sigterm: libc::sigaction,
}

impl Cancellation {
    pub fn install() -> io::Result<Self> {
        let (read, write) = pipe_pair(libc::O_CLOEXEC | libc::O_NONBLOCK)?;
        CANCELLATION_WRITE_FD
            .compare_exchange(-1, write.as_raw_fd(), Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| io::Error::other("cancellation is already installed"))?;
        // SAFETY: zero is a valid initial sigaction before all used fields are assigned.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = cancellation_handler as usize;
        action.sa_flags = 0;
        // SAFETY: sigemptyset initializes the embedded signal mask.
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        // SAFETY: storage is initialized by sigaction on success.
        let mut old_sigint: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: action and old action pointers remain valid for the syscall.
        if unsafe { libc::sigaction(libc::SIGINT, &action, &mut old_sigint) } != 0 {
            CANCELLATION_WRITE_FD.store(-1, Ordering::SeqCst);
            return Err(io::Error::last_os_error());
        }
        // SAFETY: storage is initialized by sigaction on success.
        let mut old_sigterm: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: action and old action pointers remain valid for the syscall.
        if unsafe { libc::sigaction(libc::SIGTERM, &action, &mut old_sigterm) } != 0 {
            // SAFETY: restoring the immediately preceding valid action.
            unsafe { libc::sigaction(libc::SIGINT, &old_sigint, std::ptr::null_mut()) };
            CANCELLATION_WRITE_FD.store(-1, Ordering::SeqCst);
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            read,
            write,
            old_sigint,
            old_sigterm,
        })
    }

    pub fn wait(&self, timeout: Duration) -> io::Result<Cancelled> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
            let mut pollfd = libc::pollfd {
                fd: self.read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pollfd is one initialized element and remains valid for the call.
            let result = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "cancellation wait timed out",
                ));
            }
            let mut byte = 0u8;
            // SAFETY: byte is writable for the one-byte read; read fd is retained.
            if unsafe { libc::read(self.read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) } == 1 {
                return match i32::from(byte) {
                    libc::SIGINT => Ok(Cancelled::Sigint),
                    libc::SIGTERM => Ok(Cancelled::Sigterm),
                    _ => Err(io::Error::other("unknown cancellation signal")),
                };
            }
        }
    }

    fn check(&self) -> io::Result<Option<Cancelled>> {
        let mut pollfd = libc::pollfd {
            fd: self.read.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // SAFETY: pollfd is one initialized element and remains valid for the call.
            let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                return Ok(None);
            }
            let mut byte = 0u8;
            // SAFETY: byte is writable for one byte and the read descriptor remains owned.
            let read =
                unsafe { libc::read(self.read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) };
            if read == 1 {
                return match i32::from(byte) {
                    libc::SIGINT => Ok(Some(Cancelled::Sigint)),
                    libc::SIGTERM => Ok(Some(Cancelled::Sigterm)),
                    _ => Err(io::Error::other("unknown cancellation signal")),
                };
            }
            if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
        }
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        CANCELLATION_WRITE_FD.store(-1, Ordering::SeqCst);
        // SAFETY: both actions were returned by successful sigaction calls.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.old_sigint, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &self.old_sigterm, std::ptr::null_mut());
        }
        let _ = self.write.as_raw_fd();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemberKind {
    Regular,
    Symlink,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryMember {
    pub path: String,
    pub git_mode: u32,
    pub kind: MemberKind,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceManifest {
    pub source_commit: String,
    pub source_archive_sha256: String,
    pub members: BTreeMap<String, InventoryMember>,
}

impl SourceManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| "invalid source manifest JSON")?;
        let object = value
            .as_object()
            .ok_or("source manifest must be an object")?;
        if object.len() != 3
            || !object.contains_key("source_commit")
            || !object.contains_key("source_archive_sha256")
            || !object.contains_key("members")
        {
            return Err("source manifest has unexpected fields".into());
        }
        let source_commit = object["source_commit"]
            .as_str()
            .filter(|value| valid_hex(value, 40))
            .ok_or("invalid source commit")?
            .to_owned();
        let source_archive_sha256 = object["source_archive_sha256"]
            .as_str()
            .filter(|value| valid_hex(value, 64))
            .ok_or("invalid source archive digest")?
            .to_owned();
        let values = object["members"]
            .as_array()
            .ok_or("source members must be an array")?;
        let mut members = BTreeMap::new();
        for value in values {
            let member = value.as_object().ok_or("source member must be an object")?;
            if member.len() != 4
                || !member.contains_key("path")
                || !member.contains_key("git_mode")
                || !member.contains_key("type")
                || !member.contains_key("sha256")
            {
                return Err("source member has unexpected fields".into());
            }
            let path = member["path"]
                .as_str()
                .filter(|path| safe_archive_path(path))
                .ok_or("unsafe source member path")?
                .to_owned();
            let git_mode = u32::try_from(
                member["git_mode"]
                    .as_u64()
                    .ok_or("invalid source member mode")?,
            )
            .map_err(|_| "invalid source member mode")?;
            let kind = match member["type"].as_str() {
                Some("regular") if git_mode == 0o100644 || git_mode == 0o100755 => {
                    MemberKind::Regular
                }
                Some("symlink") if git_mode == 0o120000 => MemberKind::Symlink,
                _ => return Err("source member type and mode disagree".into()),
            };
            let sha256 = member["sha256"]
                .as_str()
                .filter(|value| valid_hex(value, 64))
                .ok_or("invalid source member digest")?
                .to_owned();
            let item = InventoryMember {
                path: path.clone(),
                git_mode,
                kind,
                sha256,
            };
            if members.insert(path, item).is_some() {
                return Err("duplicate source member".into());
            }
        }
        if members.is_empty() {
            return Err("source manifest inventory is empty".into());
        }
        Ok(Self {
            source_commit,
            source_archive_sha256,
            members,
        })
    }

    pub fn verify_bundle(
        &self,
        archive: &[u8],
        inventory: &[InventoryMember],
    ) -> Result<(), String> {
        if sha256_hex(archive) != self.source_archive_sha256 {
            return Err("source archive digest mismatch".into());
        }
        let mut actual = BTreeMap::new();
        for member in inventory {
            if !safe_archive_path(&member.path)
                || !valid_hex(&member.sha256, 64)
                || actual.insert(member.path.clone(), member.clone()).is_some()
            {
                return Err("invalid extracted source inventory".into());
            }
        }
        if actual != self.members {
            return Err("extracted source inventory mismatch".into());
        }
        Ok(())
    }
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_archive_path(value: &str) -> bool {
    let mut components = value.split('/');
    components.next() == Some("source")
        && components.clone().next().is_some()
        && components.all(|component| !matches!(component, "" | "." | ".."))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapFact {
    pub map: String,
    pub map_type: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub logical_value_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompareFacts {
    pub gate_a_cases: Vec<GateACaseFacts>,
    pub maps: Vec<MapFact>,
    pub signal_runs: Vec<SignalTimingFacts>,
}

pub fn compare_oracles(facts: &CompareFacts) -> bool {
    let expected_maps = [
        ("COUNTERS", "array", 4, 8, 5, 40),
        ("DISCOVERY", "ringbuf", 0, 0, 65_536, 65_536),
        ("EVENTS", "ringbuf", 0, 0, 262_144, 262_144),
        ("START", "hash", 16, 16, 64, 1_024),
    ];
    let mut maps = BTreeMap::new();
    for map in &facts.maps {
        if maps.insert(map.map.as_str(), map).is_some() {
            return false;
        }
    }
    let maps_match = maps.len() == expected_maps.len()
        && expected_maps.iter().all(
            |&(name, map_type, key_size, value_size, max_entries, logical_value_bytes)| {
                maps.get(name).is_some_and(|fact| {
                    fact.map_type == map_type
                        && fact.key_size == key_size
                        && fact.value_size == value_size
                        && fact.max_entries == max_entries
                        && fact.logical_value_bytes == logical_value_bytes
                })
            },
        );
    let mut cases = BTreeMap::new();
    for case in &facts.gate_a_cases {
        if cases.insert(case.case, case).is_some() {
            return false;
        }
    }
    maps_match
        && cases.len() == 5
        && cases.values().all(|case| gate_a_case_pass(case))
        && facts.signal_runs.len() == 20
        && facts.signal_runs.iter().all(signal_oracle_pass)
}

pub fn discovery_json_projection(record: &RecordFacts) -> serde_json::Value {
    serde_json::json!({
        "usable_n": record.usable_n,
        "pointers_attempted": record.pointers_attempted,
        "completed_prefix": record.completed_prefix,
        "name_class": match record.name_class {
            NameClass::ExactStandard => "exact_standard",
            NameClass::Other => "other",
            NameClass::Null => "null",
            NameClass::Unreadable => "unreadable",
            NameClass::NotApplicable => "not_applicable",
        },
        "all_usable_pointers_nonzero": record.all_usable_pointers_nonzero,
        "all_usable_pointers_equal_fixture": record.all_usable_pointers_equal_fixture,
    })
}

pub fn validate_backing_chain(
    json: &[u8],
    runtime: &Path,
    retained: &Path,
    official: &Path,
    retained_mode: u32,
) -> Result<(), String> {
    if retained_mode != 0o444 {
        return Err("retained overlay mode is not 0444".into());
    }
    if [runtime, retained, official]
        .iter()
        .any(|path| !path.is_absolute())
    {
        return Err("backing chain path is not absolute".into());
    }
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|_| "invalid backing chain JSON")?;
    let chain = value
        .as_array()
        .filter(|chain| chain.len() == 3)
        .ok_or("backing chain must contain exactly three images")?;
    let expected = [runtime, retained, official];
    for (index, (entry, path)) in chain.iter().zip(expected).enumerate() {
        let entry = entry
            .as_object()
            .ok_or("backing chain entry is not an object")?;
        if entry.get("filename").and_then(serde_json::Value::as_str)
            != Some(path.to_str().ok_or("backing chain path is not UTF-8")?)
            || entry.get("format").and_then(serde_json::Value::as_str) != Some("qcow2")
        {
            return Err("backing chain image mismatch".into());
        }
        if index < 2 {
            let next = expected[index + 1]
                .to_str()
                .ok_or("backing chain path is not UTF-8")?;
            if entry
                .get("backing-filename")
                .and_then(serde_json::Value::as_str)
                != Some(next)
                || entry
                    .get("backing-filename-format")
                    .and_then(serde_json::Value::as_str)
                    != Some("qcow2")
            {
                return Err("backing chain link mismatch".into());
            }
        } else if entry.contains_key("backing-filename") {
            return Err("official image unexpectedly has a backing image".into());
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceGate {
    A,
    B,
}

pub fn validate_evidence_export(path: &Path, gate: EvidenceGate) -> Result<(), String> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| "evidence directory metadata unavailable")?;
    if !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("evidence directory is not private and caller-owned".into());
    }
    let varying = match gate {
        EvidenceGate::A => "gate-a-cases.jsonl",
        EvidenceGate::B => "signal-timing.jsonl",
    };
    let expected = [
        "environment.txt",
        "manifest-digests.txt",
        "runner-status.txt",
        "verifier-results.jsonl",
        "verifier.log",
        varying,
    ];
    let mut files = BTreeMap::new();
    for entry in std::fs::read_dir(path).map_err(|_| "cannot enumerate evidence directory")? {
        let entry = entry.map_err(|_| "cannot enumerate evidence entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "non-UTF-8 evidence name")?;
        if files.insert(name, entry.path()).is_some() {
            return Err("duplicate evidence name".into());
        }
    }
    if files.len() != expected.len() || expected.iter().any(|name| !files.contains_key(*name)) {
        return Err("evidence inventory mismatch".into());
    }
    let mut total = 0u64;
    for (name, file) in files {
        let metadata =
            std::fs::symlink_metadata(file).map_err(|_| "evidence file metadata unavailable")?;
        if !metadata.is_file()
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("evidence file is not private, regular, and caller-owned".into());
        }
        let ceiling = if name == "verifier.log" {
            8 * 1024 * 1024
        } else if name.ends_with(".jsonl") {
            4 * 1024 * 1024
        } else {
            64 * 1024
        };
        if metadata.len() > ceiling {
            return Err("evidence file exceeds its fixed size ceiling".into());
        }
        total = total
            .checked_add(metadata.len())
            .ok_or("evidence size overflow")?;
    }
    if total > 16 * 1024 * 1024 {
        return Err("evidence export exceeds total size ceiling".into());
    }
    Ok(())
}

#[derive(Clone)]
struct GateMetadata {
    source_commit: String,
    source_manifest_sha256: String,
    execution_manifest_sha256: String,
    build_evidence_sha256: String,
    bpf_sha256: String,
    runner_sha256: String,
    fixture_sha256: String,
    kernel_release: String,
    arch: String,
    glibc_version: String,
    lane: String,
    run_id: String,
}

impl GateMetadata {
    fn record(
        &self,
        pass: bool,
        failure_category: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        self.record_for_gate("A", pass, failure_category)
    }

    fn record_for_gate(
        &self,
        gate: &str,
        pass: bool,
        failure_category: &str,
    ) -> serde_json::Map<String, serde_json::Value> {
        let mut value = serde_json::Map::new();
        value.insert("schema_version".into(), 1.into());
        value.insert("source_commit".into(), self.source_commit.clone().into());
        value.insert(
            "source_manifest_sha256".into(),
            self.source_manifest_sha256.clone().into(),
        );
        value.insert(
            "execution_manifest_sha256".into(),
            self.execution_manifest_sha256.clone().into(),
        );
        value.insert(
            "build_evidence_sha256".into(),
            self.build_evidence_sha256.clone().into(),
        );
        value.insert("bpf_sha256".into(), self.bpf_sha256.clone().into());
        value.insert("runner_sha256".into(), self.runner_sha256.clone().into());
        value.insert("fixture_sha256".into(), self.fixture_sha256.clone().into());
        value.insert("kernel_release".into(), self.kernel_release.clone().into());
        value.insert("arch".into(), self.arch.clone().into());
        value.insert("glibc_version".into(), self.glibc_version.clone().into());
        value.insert("lane".into(), self.lane.clone().into());
        value.insert("run_id".into(), self.run_id.clone().into());
        value.insert("gate".into(), gate.into());
        value.insert("pass".into(), pass.into());
        value.insert("failure_category".into(), failure_category.into());
        value
    }
}

struct GateAPaths {
    source_manifest: PathBuf,
    build_evidence: PathBuf,
    execution_manifest: PathBuf,
    bpf: PathBuf,
    fixture: PathBuf,
    out: PathBuf,
}

fn parse_gate_a_args(args: &[String]) -> Result<GateAPaths, &'static str> {
    if args.len() != 12 {
        return Err("gate-a arguments");
    }
    let mut values = BTreeMap::new();
    for pair in args.chunks_exact(2) {
        if !matches!(
            pair[0].as_str(),
            "--source-manifest"
                | "--build-evidence"
                | "--execution-manifest"
                | "--bpf"
                | "--fixture"
                | "--out"
        ) || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("gate-a arguments");
        }
    }
    let path = |name| {
        values
            .get(name)
            .map(PathBuf::from)
            .ok_or("gate-a arguments")
    };
    Ok(GateAPaths {
        source_manifest: path("--source-manifest")?,
        build_evidence: path("--build-evidence")?,
        execution_manifest: path("--execution-manifest")?,
        bpf: path("--bpf")?,
        fixture: path("--fixture")?,
        out: path("--out")?,
    })
}

fn parse_gate_b_args(args: &[String]) -> Result<GateAPaths, &'static str> {
    if args.first().map(String::as_str) != Some("--runs")
        || args.get(1).map(String::as_str) != Some("20")
    {
        return Err("gate-b arguments");
    }
    parse_gate_a_args(&args[2..]).map_err(|_| "gate-b arguments")
}

fn read_regular(path: &Path, ceiling: u64) -> Result<Vec<u8>, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "input metadata")?;
    if !metadata.is_file() || metadata.len() > ceiling {
        return Err("input is not a bounded regular file");
    }
    std::fs::read(path).map_err(|_| "input read")
}

fn json_string<'a>(value: &'a serde_json::Value, name: &str) -> Result<&'a str, &'static str> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .and_then(serde_json::Value::as_str)
        .ok_or("manifest field")
}

fn kernel_release() -> Result<String, &'static str> {
    // SAFETY: uname initializes the provided structure on success.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err("uname");
    }
    // SAFETY: uname fields are NUL-terminated C strings.
    Ok(unsafe { CStr::from_ptr(uts.release.as_ptr()) }
        .to_str()
        .map_err(|_| "kernel release")?
        .to_owned())
}

fn glibc_version() -> Result<String, &'static str> {
    // SAFETY: glibc returns a process-lifetime NUL-terminated version string.
    let version = unsafe { CStr::from_ptr(libc::gnu_get_libc_version()) };
    Ok(format!(
        "glibc {}",
        version.to_str().map_err(|_| "glibc version")?
    ))
}

fn kernel_matches(actual: &str, prefix: &str) -> bool {
    actual == prefix
        || actual
            .strip_prefix(prefix)
            .is_some_and(|tail| tail.starts_with('.') || tail.starts_with('-'))
}

#[allow(clippy::type_complexity)]
fn validate_gate_provenance(
    paths: &GateAPaths,
) -> Result<(GateMetadata, Vec<u8>, File, BTreeMap<String, u64>), &'static str> {
    if unsafe { libc::geteuid() } != 0 || std::env::consts::ARCH != "x86_64" {
        return Err("guest identity");
    }
    let source_bytes = read_regular(&paths.source_manifest, 4 * 1024 * 1024)?;
    let build_bytes = read_regular(&paths.build_evidence, 16 * 1024 * 1024)?;
    let execution_bytes = read_regular(&paths.execution_manifest, 1024 * 1024)?;
    let bpf_bytes = read_regular(&paths.bpf, 16 * 1024 * 1024)?;
    let runner_bytes = read_regular(
        &std::env::current_exe().map_err(|_| "runner path")?,
        64 * 1024 * 1024,
    )?;
    let mut fixture = File::open(&paths.fixture).map_err(|_| "fixture open")?;
    let mut fixture_bytes = Vec::new();
    fixture
        .read_to_end(&mut fixture_bytes)
        .map_err(|_| "fixture read")?;
    if fixture_bytes.len() > 64 * 1024 * 1024 {
        return Err("fixture size");
    }
    let source: serde_json::Value =
        serde_json::from_slice(&source_bytes).map_err(|_| "source manifest")?;
    let execution: serde_json::Value =
        serde_json::from_slice(&execution_bytes).map_err(|_| "execution manifest")?;
    let source_sha256 = sha256_hex(&source_bytes);
    let build_sha256 = sha256_hex(&build_bytes);
    let execution_sha256 = sha256_hex(&execution_bytes);
    let bpf_sha256 = sha256_hex(&bpf_bytes);
    let runner_sha256 = sha256_hex(&runner_bytes);
    let fixture_sha256 = sha256_hex(&fixture_bytes);
    for (name, actual) in [
        ("source_manifest_sha256", source_sha256.as_str()),
        ("build_evidence_sha256", build_sha256.as_str()),
        ("bpf_sha256", bpf_sha256.as_str()),
        ("runner_sha256", runner_sha256.as_str()),
        ("fixture_sha256", fixture_sha256.as_str()),
    ] {
        if json_string(&execution, name)? != actual {
            return Err("execution manifest digest mismatch");
        }
    }
    if json_string(&source, "bpf_sha256")? != bpf_sha256 {
        return Err("source manifest BPF mismatch");
    }
    let source_commit = json_string(&source, "source_commit")?;
    if !valid_hex(source_commit, 40) || json_string(&execution, "source_commit")? != source_commit {
        return Err("source commit mismatch");
    }
    let kernel = kernel_release()?;
    let glibc = glibc_version()?;
    let lane = if kernel_matches(&kernel, "5.15") && glibc == "glibc 2.35" {
        "5.15"
    } else if kernel_matches(&kernel, "6.8") && glibc == "glibc 2.39" {
        "6.8"
    } else {
        return Err("guest kernel or glibc identity");
    };
    let mut offsets = BTreeMap::new();
    for symbol in [
        "spike_get_function_list",
        "spike_get_interface_list",
        "spike_pointer_target",
    ] {
        let offset = p11scope_manifest::elf::symbol_file_offset(&fixture, symbol)
            .map_err(|_| "fixture ELF")?
            .ok_or("fixture symbol")?;
        offsets.insert(symbol.to_owned(), offset);
    }
    Ok((
        GateMetadata {
            source_commit: source_commit.to_owned(),
            source_manifest_sha256: source_sha256,
            execution_manifest_sha256: execution_sha256,
            build_evidence_sha256: build_sha256,
            bpf_sha256,
            runner_sha256,
            fixture_sha256,
            kernel_release: kernel,
            arch: "x86_64".into(),
            glibc_version: glibc,
            lane: lane.into(),
            run_id: format!("interim-{lane}-a"),
        },
        bpf_bytes,
        fixture,
        offsets,
    ))
}

#[allow(clippy::type_complexity)]
fn validate_gate_b_provenance(
    paths: &GateAPaths,
) -> Result<(GateMetadata, Vec<u8>, File, BTreeMap<String, u64>), &'static str> {
    let (mut metadata, bpf, fixture, mut offsets) = validate_gate_provenance(paths)?;
    for symbol in [
        "spike_stop_hook",
        "spike_stop_hook_b",
        "spike_late_target",
        "spike_late_target_b",
    ] {
        let offset = p11scope_manifest::elf::symbol_file_offset(&fixture, symbol)
            .map_err(|_| "fixture ELF")?
            .ok_or("fixture symbol")?;
        offsets.insert(symbol.to_owned(), offset);
    }
    metadata.run_id = format!("interim-{}-b", metadata.lane);
    Ok((metadata, bpf, fixture, offsets))
}

fn write_json_line(file: &mut File, value: serde_json::Value) -> Result<(), &'static str> {
    serde_json::to_writer(&mut *file, &value).map_err(|_| "JSON write")?;
    file.write_all(b"\n").map_err(|_| "JSON write")
}

fn map_fact_from_info(name: &str, info: &aya::maps::MapInfo) -> Result<MapFact, &'static str> {
    let map_type = match info.map_type().map_err(|_| "map info")? {
        aya::maps::MapType::RingBuf => "ringbuf",
        aya::maps::MapType::Hash => "hash",
        aya::maps::MapType::Array => "array",
        _ => return Err("map type"),
    };
    let logical_value_bytes = if map_type == "ringbuf" {
        u64::from(info.max_entries())
    } else {
        u64::from(info.value_size()) * u64::from(info.max_entries())
    };
    Ok(MapFact {
        map: name.into(),
        map_type: map_type.into(),
        key_size: info.key_size(),
        value_size: info.value_size(),
        max_entries: info.max_entries(),
        logical_value_bytes,
    })
}

fn map_info(map: &aya::maps::Map) -> Result<aya::maps::MapInfo, &'static str> {
    match map {
        aya::maps::Map::Array(map)
        | aya::maps::Map::HashMap(map)
        | aya::maps::Map::RingBuf(map) => map.info().map_err(|_| "map info"),
        _ => Err("map type"),
    }
}

fn verifier_error_chain(error: &(dyn Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(error) = source {
        text.push_str("\ncaused_by=");
        text.push_str(&error.to_string());
        source = error.source();
    }
    text
}

fn runtime_symbol_address_from_maps(
    maps: &str,
    expected_device: &str,
    expected_inode: u64,
    symbol_offset: u64,
) -> Result<u64, &'static str> {
    let parse_device = |value: &str| {
        let (major, minor) = value.split_once(':')?;
        Some((
            u64::from_str_radix(major, 16).ok()?,
            u64::from_str_radix(minor, 16).ok()?,
        ))
    };
    let expected_device = parse_device(expected_device).ok_or("fixture device")?;
    for line in maps.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5
            || !fields[1].contains('x')
            || parse_device(fields[3]) != Some(expected_device)
            || fields[4].parse::<u64>().ok() != Some(expected_inode)
        {
            continue;
        }
        let Some((start, end)) = fields[0].split_once('-') else {
            continue;
        };
        let Ok(start) = u64::from_str_radix(start, 16) else {
            continue;
        };
        let Ok(end) = u64::from_str_radix(end, 16) else {
            continue;
        };
        let Ok(file_offset) = u64::from_str_radix(fields[2], 16) else {
            continue;
        };
        if symbol_offset >= file_offset && symbol_offset - file_offset < end - start {
            return Ok(start + symbol_offset - file_offset);
        }
    }
    Err("fixture executable mapping")
}

fn runtime_symbol_address(
    pid: u32,
    symbol_offset: u64,
    fixture: &File,
) -> Result<u64, &'static str> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).map_err(|_| "process maps")?;
    let metadata = fixture.metadata().map_err(|_| "fixture metadata")?;
    let device = format!(
        "{:x}:{:x}",
        libc::major(metadata.dev()),
        libc::minor(metadata.dev())
    );
    runtime_symbol_address_from_maps(&maps, &device, metadata.ino(), symbol_offset)
}

fn read_counters(
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
) -> Result<[u64; 5], &'static str> {
    let mut values = [0u64; 5];
    for (index, value) in values.iter_mut().enumerate() {
        *value = counters
            .get(&(index as u32), 0)
            .map_err(|_| "counter read")?;
    }
    Ok(values)
}

fn raw_records(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
) -> Result<Vec<common::DiscoveryRecord>, &'static str> {
    let mut records = Vec::new();
    while let Some(item) = ring.next() {
        records.push(decode_discovery_record(&item)?);
    }
    Ok(records)
}

fn record_facts(record: &common::DiscoveryRecord, expected_pointer: u64) -> RecordFacts {
    let pointers = &record.pointers[..usize::from(record.usable_n)];
    RecordFacts {
        usable_n: record.usable_n,
        pointers_attempted: record.pointers_attempted,
        completed_prefix: record.completed_prefix,
        name_class: match record.name_class {
            1 => NameClass::ExactStandard,
            2 => NameClass::Other,
            3 => NameClass::Null,
            4 => NameClass::Unreadable,
            _ => NameClass::NotApplicable,
        },
        all_usable_pointers_nonzero: pointers.iter().all(|pointer| *pointer != 0),
        all_usable_pointers_equal_fixture: pointers
            .iter()
            .all(|pointer| *pointer == expected_pointer),
    }
}

fn attach_program(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    offset: u64,
    fixture: &Path,
    child_pid: u32,
    cookie: u64,
) -> Result<aya::programs::uprobe::UProbeLinkId, &'static str> {
    use aya::programs::UProbe;
    use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
    let program: &mut UProbe = ebpf
        .program_mut(program_name)
        .ok_or("program missing")?
        .try_into()
        .map_err(|_| "program type")?;
    let scope = UProbeScope::OneProcess(NonZeroU32::new(child_pid).ok_or("child pid is zero")?);
    let point = UProbeAttachPoint {
        location: UProbeAttachLocation::AbsoluteOffset(offset),
        cookie: Some(cookie),
    };
    program
        .attach(point, fixture, scope)
        .map_err(|_| "program attach")
}

fn detach_program(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    link: aya::programs::uprobe::UProbeLinkId,
) -> Result<(), &'static str> {
    let program: &mut aya::programs::UProbe = ebpf
        .program_mut(program_name)
        .ok_or("program missing")?
        .try_into()
        .map_err(|_| "program type")?;
    program.detach(link).map_err(|_| "program detach")
}

fn cancellation_failure(cancellation: &Cancellation) -> Result<(), &'static str> {
    match cancellation.check().map_err(|_| "cancellation pipe")? {
        Some(Cancelled::Sigint) => Err("cancelled_sigint"),
        Some(Cancelled::Sigterm) => Err("cancelled_sigterm"),
        None => Ok(()),
    }
}

fn poll_readable(
    fd: i32,
    cancellation: &Cancellation,
    timeout: Duration,
    timeout_reason: &'static str,
) -> Result<(), &'static str> {
    let deadline = Instant::now() + timeout;
    loop {
        cancellation_failure(cancellation)?;
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(timeout_reason);
        }
        let timeout_ms = i32::try_from(remaining.as_millis().max(1)).unwrap_or(i32::MAX);
        let mut pollfds = [
            libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancellation.read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: pollfds contains two initialized entries and remains valid for the call.
        let result = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout_ms) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err("poll");
        }
        cancellation_failure(cancellation)?;
        if pollfds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            return Ok(());
        }
    }
}

fn read_expected_byte(
    fd: i32,
    expected: u8,
    cancellation: &Cancellation,
    timeout: Duration,
    timeout_reason: &'static str,
) -> Result<(), &'static str> {
    poll_readable(fd, cancellation, timeout, timeout_reason)?;
    loop {
        cancellation_failure(cancellation)?;
        let mut byte = 0u8;
        // SAFETY: byte is writable for one byte and fd remains owned by the caller.
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read == 1 && byte == expected {
            return Ok(());
        }
        if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err("pipe byte");
    }
}

fn drain_marker(fd: i32, cancellation: &Cancellation) -> Result<bool, &'static str> {
    let mut observed = false;
    loop {
        cancellation_failure(cancellation)?;
        let mut byte = 0u8;
        // SAFETY: byte is writable for one byte and fd is a live nonblocking pipe.
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read == 1 {
            if byte != b'M' && byte != b'N' {
                return Err("marker byte");
            }
            observed = true;
            continue;
        }
        if read == 0 {
            return Ok(observed);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() == io::ErrorKind::WouldBlock {
            return Ok(observed);
        }
        return Err("marker read");
    }
}

/// Reads the two post-resume markers ('M' main thread, 'N' worker) in any order.
/// Returns how many distinct markers were observed within the timeout.
fn read_markers_after_resume(
    fd: i32,
    cancellation: &Cancellation,
) -> Result<(bool, bool), &'static str> {
    let mut seen_m = false;
    let mut seen_n = false;
    while !(seen_m && seen_n) {
        poll_readable(
            fd,
            cancellation,
            Duration::from_secs(5),
            "post-resume marker timeout",
        )?;
        cancellation_failure(cancellation)?;
        let mut byte = 0u8;
        // SAFETY: byte is writable for one byte and fd is a live nonblocking pipe.
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read == 1 && byte == b'M' && !seen_m {
            seen_m = true;
            continue;
        }
        if read == 1 && byte == b'N' && !seen_n {
            seen_n = true;
            continue;
        }
        if read < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if read == 1 {
            return Err("marker byte");
        }
        return Err("pipe byte");
    }
    Ok((seen_m, seen_n))
}

fn clear_cloexec(fd: i32) -> Result<(), &'static str> {
    // SAFETY: F_GETFD/F_SETFD operate on the caller-owned descriptor and scalar flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } != 0 {
        return Err("fixture pipe flags");
    }
    Ok(())
}

fn monotonic_ns() -> Result<u64, &'static str> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time points to writable storage for CLOCK_MONOTONIC.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } != 0 {
        return Err("monotonic clock");
    }
    u64::try_from(time.tv_sec)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000_000_000))
        .and_then(|seconds| {
            u64::try_from(time.tv_nsec)
                .ok()
                .and_then(|nanos| seconds.checked_add(nanos))
        })
        .ok_or("monotonic clock")
}

fn task_states(pid: u32) -> Result<BTreeMap<u32, u8>, &'static str> {
    let mut tasks = BTreeMap::new();
    let directory = std::fs::read_dir(format!("/proc/{pid}/task")).map_err(|_| "task list")?;
    for entry in directory {
        let entry = entry.map_err(|_| "task list")?;
        let tid = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or("task id")?;
        let stat = std::fs::read_to_string(entry.path().join("stat")).map_err(|_| "task stat")?;
        if tasks.insert(tid, parse_task_state(&stat)?).is_some() {
            return Err("task set");
        }
    }
    Ok(tasks)
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct StopSnapshot {
    elapsed_us: u64,
    count: u32,
    exact_expected_task_set: bool,
    all_tasks_stopped: bool,
    state_counts: [u32; 9],
}

fn stop_snapshot(pid: u32, expected: &BTreeMap<u32, u8>) -> Result<StopSnapshot, &'static str> {
    let actual = task_states(pid)?;
    let mut snapshot = StopSnapshot {
        elapsed_us: 0,
        count: u32::try_from(actual.len()).map_err(|_| "task count")?,
        exact_expected_task_set: actual.keys().eq(expected.keys()),
        all_tasks_stopped: !actual.is_empty() && actual.values().all(|state| *state == b'T'),
        state_counts: [0; 9],
    };
    for state in actual.values() {
        let bucket = b"RSDTtZXI"
            .iter()
            .position(|known| *known == *state)
            .unwrap_or(8);
        snapshot.state_counts[bucket] += 1;
    }
    Ok(snapshot)
}

const STOP_WAIT_CEILING_US: u64 = 100_000;

fn confirm(samples: &[StopSnapshot]) -> Option<(usize, usize)> {
    for index in 0..samples.len().saturating_sub(1) {
        let first = &samples[index];
        let second = &samples[index + 1];
        if first.exact_expected_task_set
            && first.all_tasks_stopped
            && second.exact_expected_task_set
            && second.all_tasks_stopped
            && second.elapsed_us.saturating_sub(first.elapsed_us) >= 1_000
            && second.elapsed_us <= STOP_WAIT_CEILING_US
        {
            return Some((index, index + 1));
        }
    }
    None
}

fn sample_value(snapshot: &StopSnapshot) -> serde_json::Value {
    serde_json::json!({
        "elapsed_us": snapshot.elapsed_us,
        "task_count": snapshot.count,
        "exact_expected_task_set": snapshot.exact_expected_task_set,
        "all_tasks_stopped": snapshot.all_tasks_stopped,
        "state_counts": snapshot.state_counts,
    })
}

fn wait_signal_record(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    cancellation: &Cancellation,
) -> Result<common::SignalRecord, &'static str> {
    let deadline_ns = monotonic_ns()?
        .checked_add(5_000_000_000)
        .ok_or("monotonic clock")?;
    wait_signal_record_until(ring, cancellation, deadline_ns, "signal record timeout")
}

fn wait_signal_record_until(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    cancellation: &Cancellation,
    deadline_ns: u64,
    timeout_reason: &'static str,
) -> Result<common::SignalRecord, &'static str> {
    loop {
        cancellation_failure(cancellation)?;
        if let Some(item) = ring.next() {
            return decode_signal_record(&item);
        }
        let now_ns = monotonic_ns()?;
        if now_ns >= deadline_ns {
            return Err(timeout_reason);
        }
        let timeout_ms = i32::try_from((deadline_ns - now_ns) / 1_000_000).unwrap_or(i32::MAX);
        let timeout_ms = timeout_ms.clamp(1, 5_000);
        let mut pollfds = [
            libc::pollfd {
                fd: ring.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: cancellation.read.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: pollfds contains initialized entries and remains valid for the call.
        let result = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout_ms) };
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err("poll");
        }
    }
}

fn drain_signal_ring_to_empty(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
) -> Result<u64, &'static str> {
    let mut drained = 0u64;
    while let Some(item) = ring.next() {
        decode_signal_record(&item)?;
        drained += 1;
    }
    Ok(drained)
}

type GateACaseFailure = Box<(GateACaseFacts, &'static str)>;

fn gate_a_case_failure(facts: GateACaseFacts, reason: &'static str) -> GateACaseFailure {
    Box::new((facts, reason))
}

#[allow(clippy::too_many_arguments)]
fn run_gate_a_case(
    ebpf: &mut aya::Ebpf,
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
    start: &aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>,
    fixture: &Path,
    offsets: &BTreeMap<String, u64>,
    fixture_file: &File,
    case: GateACaseId,
    case_number: u8,
) -> Result<GateACaseFacts, GateACaseFailure> {
    let (case_name, entry_name, return_name, target_name, expected_kind) = match case {
        GateACaseId::Full104 => (
            "FULL_104",
            "function_list_entry",
            "function_list_return",
            "spike_get_function_list",
            1,
        ),
        GateACaseId::GuardAfter7 => (
            "GUARD_AFTER_7",
            "function_list_entry",
            "function_list_return",
            "spike_get_function_list",
            1,
        ),
        GateACaseId::UnreadableTable => (
            "UNREADABLE_TABLE",
            "function_list_entry",
            "function_list_return",
            "spike_get_function_list",
            1,
        ),
        GateACaseId::UnreadablePp => (
            "UNREADABLE_PP",
            "function_list_entry",
            "function_list_return",
            "spike_get_function_list",
            1,
        ),
        GateACaseId::Interfaces17 => (
            "INTERFACE",
            "interface_list_entry",
            "interface_list_return",
            "spike_get_interface_list",
            2,
        ),
    };
    let mut facts = GateACaseFacts {
        case,
        entry_attach_attempts: 0,
        entry_attach_accepted: false,
        return_attach_attempts: 0,
        return_attach_accepted: false,
        entry_link_detached: false,
        return_link_detached: false,
        records: Vec::new(),
        counters_before: [0; 5],
        counters_after: [0; 5],
        start_empty: false,
    };
    macro_rules! partial {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(reason) => return Err(gate_a_case_failure(facts, reason)),
            }
        };
    }
    if !partial!(raw_records(ring)).is_empty() {
        return Err(gate_a_case_failure(facts, "record surplus before case"));
    }
    facts.counters_before = partial!(read_counters(counters));
    facts.counters_after = facts.counters_before;
    let mut command = Command::new(fixture);
    command
        .arg("--gate-a")
        .arg(case_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = partial!(spawn_pinned_child(&mut command).map_err(|_| "gated child"));
    let pointer_offset = *partial!(offsets.get("spike_pointer_target").ok_or("fixture offset"));
    // fork() returns before the child's exec() completes; until then /proc/<pid>/maps
    // still shows the runner image, so resolve the fixture mapping with a bounded retry
    let expected_pointer = partial!({
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            match runtime_symbol_address(child.pid(), pointer_offset, fixture_file) {
                Ok(address) => break Ok(address),
                Err(reason @ ("process maps" | "fixture executable mapping")) => {
                    if std::time::Instant::now() >= deadline {
                        break Err(reason);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(reason) => break Err(reason),
            }
        }
    });
    let target_offset = *partial!(offsets.get(target_name).ok_or("fixture offset"));
    facts.entry_attach_attempts = 1;
    let entry_link = partial!(attach_program(
        ebpf,
        entry_name,
        target_offset,
        fixture,
        child.pid(),
        u64::from(case_number),
    ));
    facts.entry_attach_accepted = true;
    facts.return_attach_attempts = 1;
    let return_link = match attach_program(
        ebpf,
        return_name,
        target_offset,
        fixture,
        child.pid(),
        u64::from(case_number),
    ) {
        Ok(link) => {
            facts.return_attach_accepted = true;
            link
        }
        Err(error) => {
            facts.entry_link_detached = detach_program(ebpf, entry_name, entry_link).is_ok();
            return Err(gate_a_case_failure(facts, error));
        }
    };
    let release = child.release();
    let child_status = if release.is_ok() {
        child.wait().map_err(|_| "child wait")
    } else {
        Err("child release")
    };
    facts.return_link_detached = detach_program(ebpf, return_name, return_link).is_ok();
    facts.entry_link_detached = detach_program(ebpf, entry_name, entry_link).is_ok();
    let child_status = partial!(child_status);
    if !child_status.success() {
        return Err(gate_a_case_failure(facts, "fixture child status"));
    }
    let records = partial!(raw_records(ring));
    if records.iter().enumerate().any(|(index, record)| {
        record.case_id != case_number
            || record.kind != expected_kind
            || (case == GateACaseId::Interfaces17 && usize::from(record.interface_index) != index)
    }) {
        return Err(gate_a_case_failure(facts, "record identity"));
    }
    facts.records = records
        .iter()
        .map(|record| record_facts(record, expected_pointer))
        .collect();
    facts.counters_after = partial!(read_counters(counters));
    facts.start_empty = start.keys().next().is_none();
    Ok(facts)
}

fn gate_a_case_json(
    metadata: &GateMetadata,
    facts: &GateACaseFacts,
    pass: bool,
    runtime_failure_reason: Option<&str>,
) -> serde_json::Value {
    let mut value = metadata.record(
        pass,
        if runtime_failure_reason.is_some() {
            "runtime"
        } else if pass {
            "none"
        } else {
            "oracle"
        },
    );
    if let Some(reason) = runtime_failure_reason {
        value.insert("runtime_failure_reason".into(), reason.into());
    }
    value.insert("record_type".into(), "case".into());
    value.insert(
        "case".into(),
        match facts.case {
            GateACaseId::Full104 => "FULL_104",
            GateACaseId::GuardAfter7 => "GUARD_AFTER_7",
            GateACaseId::UnreadableTable => "UNREADABLE_TABLE",
            GateACaseId::UnreadablePp => "UNREADABLE_PP",
            GateACaseId::Interfaces17 => "INTERFACE",
        }
        .into(),
    );
    value.insert(
        "entry_attach_attempts".into(),
        facts.entry_attach_attempts.into(),
    );
    value.insert(
        "entry_attach_accepted".into(),
        facts.entry_attach_accepted.into(),
    );
    value.insert(
        "return_attach_attempts".into(),
        facts.return_attach_attempts.into(),
    );
    value.insert(
        "return_attach_accepted".into(),
        facts.return_attach_accepted.into(),
    );
    value.insert(
        "entry_link_detached".into(),
        facts.entry_link_detached.into(),
    );
    value.insert(
        "return_link_detached".into(),
        facts.return_link_detached.into(),
    );
    value.insert("start_empty".into(), facts.start_empty.into());
    value.insert("record_count".into(), facts.records.len().into());
    value.insert(
        "counters_before".into(),
        serde_json::json!(facts.counters_before),
    );
    value.insert(
        "counters_after".into(),
        serde_json::json!(facts.counters_after),
    );
    value.insert(
        "counter_deltas".into(),
        serde_json::json!(
            facts
                .counters_after
                .iter()
                .zip(facts.counters_before)
                .map(|(after, before)| after.saturating_sub(before))
                .collect::<Vec<_>>()
        ),
    );
    value.insert(
        "records".into(),
        serde_json::Value::Array(
            facts
                .records
                .iter()
                .map(discovery_json_projection)
                .collect(),
        ),
    );
    serde_json::Value::Object(value)
}

fn run_gate_a(paths: GateAPaths) -> Result<bool, &'static str> {
    // SAFETY: setting a process-local restrictive umask has no memory-safety preconditions.
    unsafe { libc::umask(0o077) };
    create_private_dir(&paths.out).map_err(|_| "output directory")?;
    let mut environment =
        create_private_file(&paths.out.join("environment.txt")).map_err(|_| "environment file")?;
    let mut manifest_digests = create_private_file(&paths.out.join("manifest-digests.txt"))
        .map_err(|_| "manifest digest file")?;
    let mut verifier_log =
        create_private_file(&paths.out.join("verifier.log")).map_err(|_| "verifier log")?;
    let mut verifier_results = create_private_file(&paths.out.join("verifier-results.jsonl"))
        .map_err(|_| "verifier results")?;
    let mut cases_file =
        create_private_file(&paths.out.join("gate-a-cases.jsonl")).map_err(|_| "case results")?;
    let mut runner_status =
        create_private_file(&paths.out.join("runner-status.txt")).map_err(|_| "runner status")?;

    let (metadata, bpf_bytes, fixture_file, offsets) = validate_gate_provenance(&paths)?;
    writeln!(
        environment,
        "kernel_release={}\narch={}\nglibc_version={}\nlane={}",
        metadata.kernel_release, metadata.arch, metadata.glibc_version, metadata.lane
    )
    .map_err(|_| "environment write")?;
    writeln!(
        manifest_digests,
        "source_manifest_sha256={}\nexecution_manifest_sha256={}\nbuild_evidence_sha256={}\nbpf_sha256={}\nrunner_sha256={}\nfixture_sha256={}",
        metadata.source_manifest_sha256,
        metadata.execution_manifest_sha256,
        metadata.build_evidence_sha256,
        metadata.bpf_sha256,
        metadata.runner_sha256,
        metadata.fixture_sha256
    )
    .map_err(|_| "manifest digest write")?;

    let mut loader = aya::EbpfLoader::new();
    loader.verifier_log_level(aya::VerifierLogLevel::VERBOSE | aya::VerifierLogLevel::STATS);
    let mut ebpf = match loader.load(&bpf_bytes) {
        Ok(ebpf) => ebpf,
        Err(error) => {
            writeln!(
                verifier_log,
                "object=interim outcome=rejected\n{}",
                verifier_error_chain(&error)
            )
            .map_err(|_| "verifier write")?;
            writeln!(runner_status, "status=FAIL\nfailure_category=object_load")
                .map_err(|_| "runner status write")?;
            return Ok(false);
        }
    };

    let mut all_loaded = true;
    for program_name in GATE_A_PROGRAMS {
        let result = (|| -> Result<(), Box<dyn Error>> {
            let program: &mut aya::programs::UProbe = ebpf
                .program_mut(program_name)
                .ok_or("program missing")?
                .try_into()?;
            program.load()?;
            Ok(())
        })();
        let accepted = result.is_ok();
        all_loaded &= accepted;
        let mut value = metadata.record(accepted, if accepted { "none" } else { "verifier" });
        value.insert("program".into(), program_name.into());
        value.insert("load_attempted".into(), true.into());
        value.insert("accepted".into(), accepted.into());
        value.insert(
            "success_log_contract".into(),
            if accepted {
                "accepted_line_only"
            } else {
                "rejection_error_chain"
            }
            .into(),
        );
        write_json_line(&mut verifier_results, serde_json::Value::Object(value))?;
        if let Err(error) = result {
            writeln!(
                verifier_log,
                "program={program_name} outcome=rejected error_chain={}",
                verifier_error_chain(error.as_ref())
            )
            .map_err(|_| "verifier write")?;
        } else {
            writeln!(
                verifier_log,
                "program={program_name} outcome=accepted success_verifier_text=unavailable_aya_0_14"
            )
            .map_err(|_| "verifier write")?;
        }
    }

    let mut map_facts = Vec::new();
    for name in ["EVENTS", "DISCOVERY", "START", "COUNTERS"] {
        let info = map_info(ebpf.map(name).ok_or("map missing")?)?;
        let fact = map_fact_from_info(name, &info)?;
        let mut value = metadata.record(false, "pending");
        value.insert("record_type".into(), "map".into());
        value.insert("map".into(), fact.map.clone().into());
        value.insert("map_type".into(), fact.map_type.clone().into());
        value.insert("key_size".into(), fact.key_size.into());
        value.insert("value_size".into(), fact.value_size.into());
        value.insert("max_entries".into(), fact.max_entries.into());
        value.insert(
            "logical_value_bytes".into(),
            fact.logical_value_bytes.into(),
        );
        write_json_line(&mut cases_file, serde_json::Value::Object(value))?;
        map_facts.push(fact);
    }
    if !all_loaded {
        writeln!(runner_status, "status=FAIL\nfailure_category=verifier")
            .map_err(|_| "runner status write")?;
        return Ok(false);
    }

    let mut ring = aya::maps::RingBuf::try_from(ebpf.take_map("DISCOVERY").ok_or("discovery map")?)
        .map_err(|_| "discovery ring")?;
    let counters =
        aya::maps::Array::<_, u64>::try_from(ebpf.take_map("COUNTERS").ok_or("counter map")?)
            .map_err(|_| "counter map")?;
    let start = aya::maps::HashMap::<_, common::StateKey, common::StartState>::try_from(
        ebpf.take_map("START").ok_or("start map")?,
    )
    .map_err(|_| "start map")?;
    let mut case_facts = Vec::new();
    for (number, case) in [
        GateACaseId::Full104,
        GateACaseId::GuardAfter7,
        GateACaseId::UnreadableTable,
        GateACaseId::UnreadablePp,
        GateACaseId::Interfaces17,
    ]
    .into_iter()
    .enumerate()
    {
        let facts = match run_gate_a_case(
            &mut ebpf,
            &mut ring,
            &counters,
            &start,
            &paths.fixture,
            &offsets,
            &fixture_file,
            case,
            number as u8 + 1,
        ) {
            Ok(facts) => facts,
            Err(error) => {
                let (facts, error) = *error;
                write_json_line(
                    &mut cases_file,
                    gate_a_case_json(&metadata, &facts, false, Some(error)),
                )?;
                writeln!(verifier_log, "runtime_failure={error}")
                    .map_err(|_| "runtime failure write")?;
                writeln!(runner_status, "status=FAIL\nfailure_category=runtime")
                    .map_err(|_| "runner status write")?;
                return Ok(false);
            }
        };
        let pass = gate_a_case_pass(&facts);
        write_json_line(
            &mut cases_file,
            gate_a_case_json(&metadata, &facts, pass, None),
        )?;
        case_facts.push(facts);
    }
    let pass = map_facts
        == [
            MapFact {
                map: "EVENTS".into(),
                map_type: "ringbuf".into(),
                key_size: 0,
                value_size: 0,
                max_entries: 262_144,
                logical_value_bytes: 262_144,
            },
            MapFact {
                map: "DISCOVERY".into(),
                map_type: "ringbuf".into(),
                key_size: 0,
                value_size: 0,
                max_entries: 65_536,
                logical_value_bytes: 65_536,
            },
            MapFact {
                map: "START".into(),
                map_type: "hash".into(),
                key_size: 16,
                value_size: 16,
                max_entries: 64,
                logical_value_bytes: 1_024,
            },
            MapFact {
                map: "COUNTERS".into(),
                map_type: "array".into(),
                key_size: 4,
                value_size: 8,
                max_entries: 5,
                logical_value_bytes: 40,
            },
        ]
        && case_facts.iter().all(gate_a_case_pass)
        && read_counters(&counters)? == [0, 5, 0, 1, 0]
        && start.keys().next().is_none();
    writeln!(
        runner_status,
        "status={}\nfailure_category={}",
        if pass { "PASS" } else { "FAIL" },
        if pass { "none" } else { "oracle" }
    )
    .map_err(|_| "runner status write")?;
    Ok(pass)
}

fn signal_timing_json(
    metadata: &GateMetadata,
    run: u8,
    facts: &SignalTimingFacts,
    pass: bool,
    runtime_failure_reason: Option<&str>,
) -> serde_json::Value {
    let mut value = metadata.record_for_gate(
        "B",
        pass,
        if runtime_failure_reason.is_some() {
            "runtime"
        } else if pass {
            "none"
        } else {
            "oracle"
        },
    );
    if let Some(reason) = runtime_failure_reason {
        value.insert("runtime_failure_reason".into(), reason.into());
    }
    value.insert("signal_run".into(), run.into());
    macro_rules! insert_facts {
        ($($field:ident),+ $(,)?) => {
            $(value.insert(stringify!($field).into(), serde_json::json!(facts.$field));)+
        };
    }
    insert_facts!(
        hook_ts_ns,
        send_signal_rc,
        stop_request_accepted,
        expected_task_count,
        winner_records,
        coalesced_records,
        signal_helper_calls,
        winner_case_id,
        coalesced_case_id,
        stopped_snapshot_1_count,
        stopped_snapshot_2_count,
        stopped_snapshot_1_exact_expected_task_set,
        stopped_snapshot_1_all_tasks_stopped,
        stopped_snapshot_2_exact_expected_task_set,
        stopped_snapshot_2_all_tasks_stopped,
        pre_stop_marker_observed,
        drain_empty,
        required_attach_keys,
        post_attach_task_count,
        post_attach_exact_expected_task_set,
        post_attach_all_tasks_stopped,
        post_attach_marker_observed,
        attached_while_stopped,
        queue_empty_before_resume,
        markers_after_resume,
        signal_attach_attempts,
        signal_attach_accepted,
        late_attach_attempts,
        late_attach_accepted,
        signal_link_detached,
        late_link_detached,
        last_attach_ts_ns,
        attach_gap_ms,
        pidfd_resume_attempts,
        pidfd_resume_rc,
        resume_via_original_pidfd,
        owner_removed,
        final_start_entries,
        post_resume_marker_observed,
        late_hits,
        child_exit,
        reaped,
    );
    value.insert(
        "stop_wait_ceiling_us".into(),
        serde_json::json!(STOP_WAIT_CEILING_US),
    );
    value.insert(
        "confirmation_sample_indexes".into(),
        match facts.confirmation_sample_indexes {
            Some((first, second)) => serde_json::json!([first, second]),
            None => serde_json::Value::Null,
        },
    );
    value.insert(
        "samples".into(),
        serde_json::Value::Array(facts.samples.iter().map(sample_value).collect::<Vec<_>>()),
    );
    serde_json::Value::Object(value)
}

type StartMap = aya::maps::HashMap<aya::maps::MapData, common::StateKey, common::StartState>;

#[allow(clippy::too_many_arguments)]
fn run_gate_b_case(
    ebpf: &mut aya::Ebpf,
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    counters: &aya::maps::Array<aya::maps::MapData, u64>,
    start: &mut StartMap,
    fixture: &Path,
    offsets: &BTreeMap<String, u64>,
    cancellation: &Cancellation,
    _run: u8,
) -> (SignalTimingFacts, Option<&'static str>) {
    let mut facts = SignalTimingFacts::default();
    let mut child = None;
    let mut signal_links = Vec::new();
    let mut late_links = Vec::new();
    let mut owner: Option<PauseOwnerGuard> = None;
    let result = (|| -> Result<(), &'static str> {
        cancellation_failure(cancellation)?;
        if ring.next().is_some() {
            return Err("signal record surplus");
        }
        let counters_before = read_counters(counters)?;
        let (ready_reader, ready_writer) =
            pipe_pair(libc::O_CLOEXEC | libc::O_NONBLOCK).map_err(|_| "fixture pipes")?;
        let (marker_reader, marker_writer) =
            pipe_pair(libc::O_CLOEXEC | libc::O_NONBLOCK).map_err(|_| "fixture pipes")?;
        clear_cloexec(ready_writer.as_raw_fd())?;
        clear_cloexec(marker_writer.as_raw_fd())?;
        let mut command = Command::new(fixture);
        command
            .arg("--signal")
            .arg(ready_writer.as_raw_fd().to_string())
            .arg(marker_writer.as_raw_fd().to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        child = match spawn_pinned_child(&mut command) {
            Ok(guard) => Some(guard),
            Err(error) => {
                facts.reaped = error.reaped;
                return Err("gated child");
            }
        };
        drop(ready_writer);
        drop(marker_writer);
        let guard = child.as_mut().ok_or("gated child")?;
        cancellation_failure(cancellation)?;
        pidfd_send_signal(guard.original_pidfd.as_raw_fd(), 0).map_err(|_| "pidfd authority")?;

        read_expected_byte(
            ready_reader.as_raw_fd(),
            b'R',
            cancellation,
            Duration::from_secs(5),
            "fixture ready timeout",
        )?;
        cancellation_failure(cancellation)?;
        let expected = task_states(guard.pid())?;
        facts.expected_task_count = u32::try_from(expected.len()).map_err(|_| "task count")?;
        if facts.expected_task_count != 2 {
            return Ok(());
        }

        // arm: insert ARMED under the group key before releasing the child (§5.2)
        let owner_key = common::StateKey {
            pid_tgid: u64::from(guard.pid()) << 32,
            attach_cookie: u64::MAX,
        };
        start.insert_armed(&owner_key)?;
        owner = Some(PauseOwnerGuard::new(owner_key));

        // attach signal_return at BOTH stop hooks (cookies 1 = A, 2 = B), then release
        for (target, cookie) in [
            ("spike_stop_hook", common::SIGNAL_COOKIE_A),
            ("spike_stop_hook_b", common::SIGNAL_COOKIE_B),
        ] {
            facts.signal_attach_attempts += 1;
            match attach_program(
                ebpf,
                "signal_return",
                *offsets.get(target).ok_or("fixture offset")?,
                fixture,
                guard.pid(),
                cookie,
            ) {
                Ok(link) => signal_links.push(link),
                Err(_) => return Ok(()),
            }
        }
        facts.signal_attach_accepted = true;

        guard.mark_may_be_stopped();
        guard.release().map_err(|_| "child release")?;
        // read exactly two records; the second must arrive inside the same causal window
        let rec_a = wait_signal_record(ring, cancellation)?;
        let causal_deadline_ns = rec_a
            .hook_ts_ns
            .checked_add(STOP_WAIT_CEILING_US * 1_000)
            .ok_or("deadline overflow")?;
        let rec_b = wait_signal_record_until(
            ring,
            cancellation,
            causal_deadline_ns,
            "second signal record timeout",
        )?;
        for record in [&rec_a, &rec_b] {
            let record_pid = (record.pid_tgid >> 32) as u32;
            let record_tid = record.pid_tgid as u32;
            if (record.case_id != 1 && record.case_id != 2)
                || record_pid != guard.pid()
                || !expected.contains_key(&record_tid)
                || record.reserved_zero != [0; 7]
            {
                return Err("signal record identity");
            }
        }
        if rec_a.case_id == rec_b.case_id {
            return Err("signal record identity");
        }
        let second_record_late = rec_a
            .hook_ts_ns
            .min(rec_b.hook_ts_ns)
            .checked_add(STOP_WAIT_CEILING_US * 1_000)
            .ok_or("deadline overflow")?
            < monotonic_ns()?;
        let winner = [&rec_a, &rec_b]
            .into_iter()
            .filter(|record| record.send_signal_rc != common::COALESCED_NO_HELPER)
            .count();
        facts.winner_records = winner as u64;
        facts.coalesced_records = 2 - winner as u64;
        facts.signal_helper_calls = winner as u64;
        let (win, lost) = if rec_a.send_signal_rc != common::COALESCED_NO_HELPER {
            (rec_a, rec_b)
        } else {
            (rec_b, rec_a)
        };
        facts.winner_case_id = win.case_id;
        facts.coalesced_case_id = lost.case_id;
        facts.hook_ts_ns = win.hook_ts_ns;
        facts.send_signal_rc = win.send_signal_rc;
        facts.stop_request_accepted = win.send_signal_rc == 0;

        // observe: >= 1 ms cadence, absolute deadline hook_ts + 100 ms, sample stamped AFTER its /proc reads complete
        let deadline_ns = facts
            .hook_ts_ns
            .checked_add(STOP_WAIT_CEILING_US * 1_000)
            .ok_or("deadline overflow")?;
        let mut samples: Vec<StopSnapshot> = Vec::with_capacity(101);
        loop {
            cancellation_failure(cancellation)?;
            if monotonic_ns()? > deadline_ns || samples.len() >= 101 {
                break;
            }
            let mut snap = stop_snapshot(guard.pid(), &expected)?;
            let done = monotonic_ns()?;
            snap.elapsed_us = done.checked_sub(facts.hook_ts_ns).ok_or("clock reversal")? / 1_000;
            samples.push(snap);
            if confirm(&samples).is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        facts.samples = samples;
        let confirmed = confirm(&facts.samples);
        facts.confirmation_sample_indexes = confirmed;
        let (first, second) = match confirmed {
            Some((i, j)) => (facts.samples[i], facts.samples[j]),
            None => {
                let last = facts.samples.len();
                (
                    facts
                        .samples
                        .get(last.saturating_sub(2))
                        .copied()
                        .unwrap_or_default(),
                    facts.samples.last().copied().unwrap_or_default(),
                )
            }
        };
        facts.stopped_snapshot_1_count = first.count;
        facts.stopped_snapshot_1_exact_expected_task_set = first.exact_expected_task_set;
        facts.stopped_snapshot_1_all_tasks_stopped = first.all_tasks_stopped;
        facts.stopped_snapshot_2_count = second.count;
        facts.stopped_snapshot_2_exact_expected_task_set = second.exact_expected_task_set;
        facts.stopped_snapshot_2_all_tasks_stopped = second.all_tasks_stopped;
        facts.pre_stop_marker_observed = drain_marker(marker_reader.as_raw_fd(), cancellation)?;
        if !facts.stop_request_accepted
            || second_record_late
            || confirmed.is_none()
            || facts.pre_stop_marker_observed
        {
            return Ok(());
        }

        // drain-to-empty: with all tasks stopped there is no exact-child producer left
        facts.drain_empty = drain_signal_ring_to_empty(ring)? == 0;
        facts.required_attach_keys = 2;
        for (target, cookie) in [
            ("spike_late_target", common::SIGNAL_COOKIE_A),
            ("spike_late_target_b", common::SIGNAL_COOKIE_B),
        ] {
            facts.late_attach_attempts += 1;
            match attach_program(
                ebpf,
                "late_hit",
                *offsets.get(target).ok_or("fixture offset")?,
                fixture,
                guard.pid(),
                cookie,
            ) {
                Ok(link) => {
                    late_links.push(link);
                    facts.attached_while_stopped += 1;
                }
                Err(_) => return Ok(()),
            }
        }
        facts.late_attach_accepted = facts.attached_while_stopped == 2;
        facts.last_attach_ts_ns = monotonic_ns()?;
        facts.attach_gap_ms = facts
            .last_attach_ts_ns
            .checked_sub(facts.hook_ts_ns)
            .map_or(0.0, |gap| gap as f64 / 1_000_000.0);

        cancellation_failure(cancellation)?;
        let third = stop_snapshot(guard.pid(), &expected)?;
        facts.post_attach_task_count = third.count;
        facts.post_attach_exact_expected_task_set = third.exact_expected_task_set;
        facts.post_attach_all_tasks_stopped = third.all_tasks_stopped;
        facts.post_attach_marker_observed = drain_marker(marker_reader.as_raw_fd(), cancellation)?;
        if !third.exact_expected_task_set
            || !third.all_tasks_stopped
            || facts.post_attach_marker_observed
        {
            return Ok(());
        }
        facts.queue_empty_before_resume = drain_signal_ring_to_empty(ring)? == 0;

        facts.pidfd_resume_attempts = 1;
        facts.resume_via_original_pidfd = true;
        if guard.resume_once().is_err() {
            facts.pidfd_resume_rc = -1;
            return Ok(());
        }
        facts.pidfd_resume_rc = 0;
        // §5.2: REQUESTED is removed immediately after the one successful original-pidfd
        // resume — before waiting for markers/exit
        facts.owner_removed = owner
            .as_mut()
            .ok_or("start map remove")?
            .close_after_resume(start)?;
        facts.final_start_entries = owner
            .as_ref()
            .ok_or("start map read")?
            .start_entries(start)?;

        match read_markers_after_resume(marker_reader.as_raw_fd(), cancellation) {
            Ok((seen_m, seen_n)) => {
                facts.markers_after_resume = u32::from(seen_m) + u32::from(seen_n);
                facts.post_resume_marker_observed = seen_m && seen_n;
            }
            Err(reason @ ("cancelled_sigint" | "cancelled_sigterm" | "cancellation pipe")) => {
                return Err(reason);
            }
            Err(_) => return Ok(()),
        }
        poll_readable(
            guard.original_pidfd.as_raw_fd(),
            cancellation,
            Duration::from_secs(5),
            "child exit timeout",
        )?;
        let status = guard.wait().map_err(|_| "child wait")?;
        facts.reaped = true;
        facts.child_exit = status.code().unwrap_or(-1);
        let counters_after = read_counters(counters)?;
        facts.late_hits = counters_after[4].saturating_sub(counters_before[4]);
        if ring.next().is_some() {
            return Err("signal record surplus");
        }
        Ok(())
    })();

    if !late_links.is_empty() {
        let mut all_detached = true;
        for link in late_links.drain(..) {
            all_detached &= detach_program(ebpf, "late_hit", link).is_ok();
        }
        facts.late_link_detached = all_detached;
    }
    if !signal_links.is_empty() {
        let mut all_detached = true;
        for link in signal_links.drain(..) {
            all_detached &= detach_program(ebpf, "signal_return", link).is_ok();
        }
        facts.signal_link_detached = all_detached;
    }
    if let Some(guard) = child.as_mut()
        && !guard.reaped
    {
        let cleanup = guard.terminate();
        if cleanup.resume_attempts == 1 && facts.pidfd_resume_attempts == 0 {
            facts.pidfd_resume_attempts = 1;
            facts.resume_via_original_pidfd = cleanup.resume_via_original_pidfd;
            facts.pidfd_resume_rc = if guard.may_be_stopped { -1 } else { 0 };
        }
        facts.reaped = cleanup.reaped;
        facts.child_exit = -1;
    }
    if let Some(owner) = owner.as_mut() {
        owner.disarm_for_cleanup(start);
    }
    (facts, result.err())
}

fn run_gate_b(paths: GateAPaths) -> Result<bool, &'static str> {
    // SAFETY: setting a process-local restrictive umask has no memory-safety preconditions.
    unsafe { libc::umask(0o077) };
    create_private_dir(&paths.out).map_err(|_| "output directory")?;
    let mut environment =
        create_private_file(&paths.out.join("environment.txt")).map_err(|_| "environment file")?;
    let mut manifest_digests = create_private_file(&paths.out.join("manifest-digests.txt"))
        .map_err(|_| "manifest digest file")?;
    let mut verifier_log =
        create_private_file(&paths.out.join("verifier.log")).map_err(|_| "verifier log")?;
    let mut verifier_results = create_private_file(&paths.out.join("verifier-results.jsonl"))
        .map_err(|_| "verifier results")?;
    let mut timings = create_private_file(&paths.out.join("signal-timing.jsonl"))
        .map_err(|_| "signal timing results")?;
    let mut runner_status =
        create_private_file(&paths.out.join("runner-status.txt")).map_err(|_| "runner status")?;
    let cancellation = Cancellation::install().map_err(|_| "cancellation pipe")?;

    let (metadata, bpf_bytes, _fixture_file, offsets) = validate_gate_b_provenance(&paths)?;
    writeln!(
        environment,
        "kernel_release={}\narch={}\nglibc_version={}\nlane={}",
        metadata.kernel_release, metadata.arch, metadata.glibc_version, metadata.lane
    )
    .map_err(|_| "environment write")?;
    writeln!(
        manifest_digests,
        "source_manifest_sha256={}\nexecution_manifest_sha256={}\nbuild_evidence_sha256={}\nbpf_sha256={}\nrunner_sha256={}\nfixture_sha256={}",
        metadata.source_manifest_sha256,
        metadata.execution_manifest_sha256,
        metadata.build_evidence_sha256,
        metadata.bpf_sha256,
        metadata.runner_sha256,
        metadata.fixture_sha256
    )
    .map_err(|_| "manifest digest write")?;

    let mut loader = aya::EbpfLoader::new();
    loader.verifier_log_level(aya::VerifierLogLevel::VERBOSE | aya::VerifierLogLevel::STATS);
    let mut ebpf = loader.load(&bpf_bytes).map_err(|_| "object load")?;
    let mut all_loaded = true;
    for program_name in GATE_B_PROGRAMS {
        let result = (|| -> Result<(), Box<dyn Error>> {
            let program: &mut aya::programs::UProbe = ebpf
                .program_mut(program_name)
                .ok_or("program missing")?
                .try_into()?;
            program.load()?;
            Ok(())
        })();
        let accepted = result.is_ok();
        all_loaded &= accepted;
        let mut value =
            metadata.record_for_gate("B", accepted, if accepted { "none" } else { "verifier" });
        value.insert("program".into(), program_name.into());
        value.insert("load_attempted".into(), true.into());
        value.insert("accepted".into(), accepted.into());
        value.insert(
            "success_log_contract".into(),
            if accepted {
                "accepted_line_only"
            } else {
                "rejection_error_chain"
            }
            .into(),
        );
        write_json_line(&mut verifier_results, serde_json::Value::Object(value))?;
        if let Err(error) = result {
            writeln!(
                verifier_log,
                "program={program_name} outcome=rejected error_chain={}",
                verifier_error_chain(error.as_ref())
            )
            .map_err(|_| "verifier write")?;
        } else {
            writeln!(
                verifier_log,
                "program={program_name} outcome=accepted success_verifier_text=unavailable_aya_0_14"
            )
            .map_err(|_| "verifier write")?;
        }
    }
    if !all_loaded {
        writeln!(runner_status, "status=FAIL\nfailure_category=verifier")
            .map_err(|_| "runner status write")?;
        return Ok(false);
    }

    let mut ring = aya::maps::RingBuf::try_from(ebpf.take_map("DISCOVERY").ok_or("discovery map")?)
        .map_err(|_| "discovery ring")?;
    let counters =
        aya::maps::Array::<_, u64>::try_from(ebpf.take_map("COUNTERS").ok_or("counter map")?)
            .map_err(|_| "counter map")?;
    let mut start = aya::maps::HashMap::try_from(ebpf.take_map("START").ok_or("start map")?)
        .map_err(|_| "start map")?;
    let mut completed = 0u8;
    let mut final_category = "none";
    for run in 1..=20 {
        let (facts, runtime_failure_reason) = run_gate_b_case(
            &mut ebpf,
            &mut ring,
            &counters,
            &mut start,
            &paths.fixture,
            &offsets,
            &cancellation,
            run,
        );
        let pass = runtime_failure_reason.is_none() && signal_oracle_pass(&facts);
        write_json_line(
            &mut timings,
            signal_timing_json(&metadata, run, &facts, pass, runtime_failure_reason),
        )?;
        completed = run;
        if runtime_failure_reason.is_some() || !pass {
            final_category = if runtime_failure_reason.is_some() {
                "runtime"
            } else {
                "oracle"
            };
            break;
        }
    }
    let pass = completed == 20 && final_category == "none";
    writeln!(
        runner_status,
        "status={}\nfailure_category={}",
        if pass { "PASS" } else { "FAIL" },
        final_category
    )
    .map_err(|_| "runner status write")?;
    Ok(pass)
}

fn self_check() -> Result<(), &'static str> {
    let kernel = kernel_release()?;
    let glibc = glibc_version()?;
    if std::env::consts::ARCH != "x86_64"
        || !((kernel_matches(&kernel, "5.15") && glibc == "glibc 2.35")
            || (kernel_matches(&kernel, "6.8") && glibc == "glibc 2.39"))
    {
        return Err("guest identity");
    }
    Ok(())
}

/// One finite JSON line per program: no raw verifier text beyond a 2 KiB tail.
fn diag_line(
    program: &str,
    outcome: Result<Option<u32>, (Option<i32>, String)>,
    duration_ms: u128,
) -> String {
    let mut v = serde_json::Map::new();
    v.insert("program".into(), program.into());
    v.insert(
        "duration_ms".into(),
        u64::try_from(duration_ms).unwrap_or(u64::MAX).into(),
    );
    match outcome {
        Ok(insns) => {
            v.insert("accepted".into(), true.into());
            v.insert("verified_insns".into(), insns.into()); // None on 5.15 (bpf_prog_info field added in 5.16)
        }
        Err((errno, log)) => {
            v.insert("accepted".into(), false.into());
            v.insert("errno".into(), errno.into());
            v.insert("log_bytes".into(), (log.len() as u64).into());
            let tail: String = log
                .chars()
                .rev()
                .take(2048)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            v.insert("log_tail".into(), tail.into());
        }
    }
    serde_json::Value::Object(v).to_string()
}

/// Diagnostic-only (D2) Gate A verdict lane: one STATS-only load per program,
/// never the frozen VERBOSE | STATS gate. Records the first-attempt errno that
/// Aya's retry loop would otherwise discard, plus bounded verifier stats.
fn run_gate_a_diag(bpf_path: &str, out_dir: &str) -> Result<bool, &'static str> {
    std::fs::create_dir_all(out_dir).map_err(|_| "out dir")?;
    let bytes = std::fs::read(bpf_path).map_err(|_| "bpf read")?;
    let mut sink =
        std::fs::File::create(format!("{out_dir}/diag.jsonl")).map_err(|_| "diag file")?;
    let mut loader = aya::EbpfLoader::new();
    loader.verifier_log_level(aya::VerifierLogLevel::STATS); // no per-insn text; failure reason + stats only
    let mut ebpf = loader.load(&bytes).map_err(|_| "object load")?;
    let mut all = true;
    for name in GATE_A_PROGRAMS {
        let started = Instant::now();
        let outcome: Result<Option<u32>, (Option<i32>, String)> = match ebpf.program_mut(name) {
            None => Err((None, "program missing".into())),
            Some(program) => match <&mut aya::programs::UProbe>::try_from(program) {
                Err(error) => Err((None, error.to_string())),
                Ok(program) => match program.load() {
                    Ok(()) => Ok(program
                        .info()
                        .ok()
                        .and_then(|info| info.verified_instruction_count())),
                    Err(aya::programs::ProgramError::LoadError {
                        io_error,
                        verifier_log,
                    }) => Err((io_error.raw_os_error(), verifier_log.to_string())),
                    Err(other) => Err((None, other.to_string())),
                },
            },
        };
        all &= outcome.is_ok();
        writeln!(
            sink,
            "{}",
            diag_line(name, outcome, started.elapsed().as_millis())
        )
        .map_err(|_| "diag write")?;
    }
    Ok(all)
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("--self-check") if args.len() == 2 => self_check().map(|()| true),
        Some("gate-a") => parse_gate_a_args(&args[2..]).and_then(run_gate_a),
        Some("gate-b") => parse_gate_b_args(&args[2..]).and_then(run_gate_b),
        Some("gate-a-diag") if args.len() == 4 => run_gate_a_diag(&args[2], &args[3]),
        _ => Err("usage"),
    };
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(error) => {
            eprintln!("slice1b2-runner: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::mem::{align_of, offset_of, size_of};
    use std::os::unix::process::ExitStatusExt as _;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn gate_a_diag_line_has_finite_fields() {
        let line = diag_line(
            "interface_list_return",
            Err((
                Some(7),
                "processed 1000001 insns (limit 1000000) max_states_per_insn 4 total_states 25000 peak_states 2000 mark_read 90"
                    .to_string(),
            )),
            1234,
        );
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["program"], "interface_list_return");
        assert_eq!(v["accepted"], false);
        assert_eq!(v["errno"], 7);
        assert_eq!(v["duration_ms"], 1234);
        assert!(
            v["log_tail"]
                .as_str()
                .unwrap()
                .contains("processed 1000001 insns")
        );
        assert!(v["log_bytes"].as_u64().unwrap() < 4096);
    }

    #[test]
    fn gate_a_diag_line_accepted_line_has_no_errno_and_tails_at_2k() {
        let long = "x".repeat(5000);
        let line = diag_line("function_list_return", Ok(Some(4421)), 9);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["accepted"], true);
        assert_eq!(v["verified_insns"], 4421);
        assert!(v.get("errno").is_none() || v["errno"].is_null());
        let rejected = diag_line("p", Err((None, long)), 1);
        let v: serde_json::Value = serde_json::from_str(&rejected).unwrap();
        assert_eq!(v["errno"], serde_json::Value::Null);
        assert_eq!(v["log_bytes"], 5000u64);
        assert_eq!(v["log_tail"].as_str().unwrap().len(), 2048);
    }

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    static VM_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(label: &str) -> Self {
            let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("slice1b2-{label}-{}-{serial}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(usable_n: u8, attempted: u8, completed: u8, name_class: NameClass) -> RecordFacts {
        RecordFacts {
            usable_n,
            pointers_attempted: attempted,
            completed_prefix: completed,
            name_class,
            all_usable_pointers_nonzero: true,
            all_usable_pointers_equal_fixture: true,
        }
    }

    fn gate_case(
        case: GateACaseId,
        records: Vec<RecordFacts>,
        expected_delta: [u64; 5],
    ) -> GateACaseFacts {
        let before = [10, 20, 30, 40, 50];
        GateACaseFacts {
            case,
            entry_attach_attempts: 1,
            entry_attach_accepted: true,
            return_attach_attempts: 1,
            return_attach_accepted: true,
            entry_link_detached: true,
            return_link_detached: true,
            records,
            counters_before: before,
            counters_after: std::array::from_fn(|index| before[index] + expected_delta[index]),
            start_empty: true,
        }
    }

    fn valid_gate_a_cases() -> Vec<GateACaseFacts> {
        let mut interfaces = (0..12)
            .map(|_| record(104, 104, 104, NameClass::ExactStandard))
            .collect::<Vec<_>>();
        interfaces.extend([
            record(0, 8, 7, NameClass::ExactStandard),
            record(0, 0, 0, NameClass::Other),
            record(0, 0, 0, NameClass::Null),
            record(0, 0, 0, NameClass::Unreadable),
        ]);
        vec![
            gate_case(
                GateACaseId::Full104,
                vec![record(104, 104, 104, NameClass::NotApplicable)],
                [0, 0, 0, 0, 0],
            ),
            gate_case(
                GateACaseId::GuardAfter7,
                vec![record(0, 8, 7, NameClass::NotApplicable)],
                [0, 1, 0, 0, 0],
            ),
            gate_case(
                GateACaseId::UnreadableTable,
                vec![record(0, 0, 0, NameClass::NotApplicable)],
                [0, 1, 0, 0, 0],
            ),
            gate_case(
                GateACaseId::UnreadablePp,
                vec![record(0, 0, 0, NameClass::NotApplicable)],
                [0, 1, 0, 0, 0],
            ),
            gate_case(GateACaseId::Interfaces17, interfaces, [0, 2, 0, 1, 0]),
        ]
    }

    fn test_gate_metadata() -> GateMetadata {
        GateMetadata {
            source_commit: "a".repeat(40),
            source_manifest_sha256: "b".repeat(64),
            execution_manifest_sha256: "c".repeat(64),
            build_evidence_sha256: "d".repeat(64),
            bpf_sha256: "e".repeat(64),
            runner_sha256: "f".repeat(64),
            fixture_sha256: "1".repeat(64),
            kernel_release: "5.15.0-test".into(),
            arch: "x86_64".into(),
            glibc_version: "glibc 2.35".into(),
            lane: "5.15".into(),
            run_id: "test-run".into(),
        }
    }

    #[test]
    fn runtime_failure_record_retains_partial_attach_and_detach_facts() {
        let facts = GateACaseFacts {
            case: GateACaseId::Full104,
            entry_attach_attempts: 1,
            entry_attach_accepted: true,
            return_attach_attempts: 1,
            return_attach_accepted: false,
            entry_link_detached: true,
            return_link_detached: false,
            records: Vec::new(),
            counters_before: [0; 5],
            counters_after: [0; 5],
            start_empty: false,
        };
        let value = gate_a_case_json(&test_gate_metadata(), &facts, false, Some("return attach"));
        assert_eq!(value["failure_category"], "runtime");
        assert_eq!(value["runtime_failure_reason"], "return attach");
        assert_eq!(value["entry_attach_attempts"], 1);
        assert_eq!(value["entry_attach_accepted"], true);
        assert_eq!(value["return_attach_attempts"], 1);
        assert_eq!(value["return_attach_accepted"], false);
        assert_eq!(value["entry_link_detached"], true);
        assert_eq!(value["return_link_detached"], false);
    }

    fn valid_signal() -> SignalTimingFacts {
        SignalTimingFacts {
            hook_ts_ns: 1_000_000,
            send_signal_rc: 0,
            stop_request_accepted: true,
            expected_task_count: 2,
            winner_records: 1,
            coalesced_records: 1,
            signal_helper_calls: 1,
            winner_case_id: 1,
            coalesced_case_id: 2,
            stopped_snapshot_1_count: 2,
            stopped_snapshot_2_count: 2,
            stopped_snapshot_1_exact_expected_task_set: true,
            stopped_snapshot_1_all_tasks_stopped: true,
            stopped_snapshot_2_exact_expected_task_set: true,
            stopped_snapshot_2_all_tasks_stopped: true,
            confirmation_sample_indexes: Some((0, 1)),
            samples: vec![
                StopSnapshot {
                    elapsed_us: 2_000,
                    count: 2,
                    exact_expected_task_set: true,
                    all_tasks_stopped: true,
                    state_counts: [0, 0, 0, 2, 0, 0, 0, 0, 0],
                },
                StopSnapshot {
                    elapsed_us: 3_100,
                    count: 2,
                    exact_expected_task_set: true,
                    all_tasks_stopped: true,
                    state_counts: [0, 0, 0, 2, 0, 0, 0, 0, 0],
                },
            ],
            pre_stop_marker_observed: false,
            drain_empty: true,
            required_attach_keys: 2,
            post_attach_task_count: 2,
            post_attach_exact_expected_task_set: true,
            post_attach_all_tasks_stopped: true,
            post_attach_marker_observed: false,
            attached_while_stopped: 2,
            queue_empty_before_resume: true,
            markers_after_resume: 2,
            signal_attach_attempts: 2,
            signal_attach_accepted: true,
            late_attach_attempts: 2,
            late_attach_accepted: true,
            signal_link_detached: true,
            late_link_detached: true,
            last_attach_ts_ns: 2_000_000,
            attach_gap_ms: 1.0,
            pidfd_resume_attempts: 1,
            pidfd_resume_rc: 0,
            resume_via_original_pidfd: true,
            owner_removed: true,
            final_start_entries: 0,
            post_resume_marker_observed: true,
            late_hits: 2,
            child_exit: 0,
            reaped: true,
        }
    }

    fn passing_facts() -> SignalTimingFacts {
        valid_signal()
    }

    fn valid_maps() -> Vec<MapFact> {
        vec![
            MapFact {
                map: "EVENTS".into(),
                map_type: "ringbuf".into(),
                key_size: 0,
                value_size: 0,
                max_entries: 262_144,
                logical_value_bytes: 262_144,
            },
            MapFact {
                map: "DISCOVERY".into(),
                map_type: "ringbuf".into(),
                key_size: 0,
                value_size: 0,
                max_entries: 65_536,
                logical_value_bytes: 65_536,
            },
            MapFact {
                map: "START".into(),
                map_type: "hash".into(),
                key_size: 16,
                value_size: 16,
                max_entries: 64,
                logical_value_bytes: 1_024,
            },
            MapFact {
                map: "COUNTERS".into(),
                map_type: "array".into(),
                key_size: 4,
                value_size: 8,
                max_entries: 5,
                logical_value_bytes: 40,
            },
        ]
    }

    #[test]
    fn discovery_record_is_exactly_896_bytes_without_implicit_padding() {
        use common::{DiscoveryRecord, SignalRecord, StartState, StateKey};

        assert_eq!(size_of::<DiscoveryRecord>(), 896);
        assert_eq!(align_of::<DiscoveryRecord>(), 8);
        assert_eq!(offset_of!(DiscoveryRecord, hook_ts_ns), 0);
        assert_eq!(offset_of!(DiscoveryRecord, pid_tgid), 8);
        assert_eq!(offset_of!(DiscoveryRecord, table_ptr), 16);
        assert_eq!(offset_of!(DiscoveryRecord, interface_flags), 24);
        assert_eq!(offset_of!(DiscoveryRecord, pointers), 32);
        assert_eq!(offset_of!(DiscoveryRecord, kind), 864);
        assert_eq!(offset_of!(DiscoveryRecord, case_id), 865);
        assert_eq!(offset_of!(DiscoveryRecord, interface_index), 866);
        assert_eq!(offset_of!(DiscoveryRecord, name_class), 867);
        assert_eq!(offset_of!(DiscoveryRecord, status_flags), 868);
        assert_eq!(offset_of!(DiscoveryRecord, usable_n), 869);
        assert_eq!(offset_of!(DiscoveryRecord, pointers_attempted), 870);
        assert_eq!(offset_of!(DiscoveryRecord, completed_prefix), 871);
        assert_eq!(offset_of!(DiscoveryRecord, version_major), 872);
        assert_eq!(offset_of!(DiscoveryRecord, version_minor), 873);
        assert_eq!(offset_of!(DiscoveryRecord, reserved_zero), 874);
        assert_eq!(offset_of!(DiscoveryRecord, symbol_id), 876);
        assert_eq!(offset_of!(DiscoveryRecord, announced_count), 880);
        assert_eq!(offset_of!(DiscoveryRecord, reserved_tail_zero), 884);
        assert_eq!(size_of::<SignalRecord>(), 32);
        assert_eq!(align_of::<SignalRecord>(), 8);
        assert_eq!((size_of::<StateKey>(), align_of::<StateKey>()), (16, 8));
        assert_eq!((size_of::<StartState>(), align_of::<StartState>()), (16, 8));

        let mut bytes = [0u8; 896];
        bytes[..8].copy_from_slice(&42u64.to_le_bytes());
        bytes[869] = 104;
        let decoded = decode_discovery_record(&bytes).unwrap();
        assert_eq!(decoded.hook_ts_ns, 42);
        assert_eq!(decoded.usable_n, 104);
        assert!(decode_discovery_record(&bytes[..895]).is_err());
        let mut oversized = bytes.to_vec();
        oversized.push(0);
        assert!(decode_discovery_record(&oversized).is_err());

        let mut signal_bytes = [0u8; 32];
        signal_bytes[..8].copy_from_slice(&99u64.to_le_bytes());
        signal_bytes[16..24].copy_from_slice(&(-7i64).to_le_bytes());
        signal_bytes[24] = 3;
        let signal = decode_signal_record(&signal_bytes).unwrap();
        assert_eq!(signal.hook_ts_ns, 99);
        assert_eq!(signal.send_signal_rc, -7);
        assert_eq!(signal.case_id, 3);
        assert!(decode_signal_record(&signal_bytes[..31]).is_err());
    }

    #[test]
    fn failed_read_forces_usable_n_zero_without_truncation() {
        assert_eq!(
            discovery_read_outcome(8, 7, true, false),
            ReadOutcome {
                usable_n: 0,
                pointers_attempted: 8,
                completed_prefix: 7,
                read_failures: 1,
                truncations: 0,
            }
        );
        assert_eq!(discovery_read_outcome(104, 104, false, false).usable_n, 104);
        assert_eq!(discovery_read_outcome(16, 16, false, true).truncations, 1);
    }

    #[test]
    fn gate_a_oracle_requires_exact_per_case_deltas() {
        let cases = valid_gate_a_cases();
        assert!(cases.iter().all(gate_a_case_pass));
        for (case_index, case) in cases.iter().enumerate() {
            for counter in 0..5 {
                let mut changed = case.clone();
                changed.counters_after[counter] += 1;
                assert!(
                    !gate_a_case_pass(&changed),
                    "case {case_index} accepted changed counter {counter}"
                );
            }
        }
    }

    #[test]
    fn signal_oracle_rechecks_stop_and_marker_after_attach() {
        let valid = valid_signal();
        assert!(signal_oracle_pass(&valid));
        let mut changed = valid.clone();
        changed.post_attach_exact_expected_task_set = false;
        assert!(!signal_oracle_pass(&changed));
        let mut changed = valid.clone();
        changed.post_attach_all_tasks_stopped = false;
        assert!(!signal_oracle_pass(&changed));
        let mut changed = valid;
        changed.post_attach_marker_observed = true;
        assert!(!signal_oracle_pass(&changed));
    }

    #[test]
    fn signal_oracle_rejects_each_binding_timing_mutation() {
        let valid = valid_signal();
        for mutation in 0..30 {
            let mut changed = valid.clone();
            match mutation {
                0 => changed.hook_ts_ns = 0,
                1 => changed.send_signal_rc = -1,
                2 => changed.stop_request_accepted = false,
                3 => changed.expected_task_count = 3,
                4 => changed.stopped_snapshot_1_count = 1,
                5 => changed.stopped_snapshot_2_count = 1,
                6 => changed.stopped_snapshot_1_exact_expected_task_set = false,
                7 => changed.stopped_snapshot_1_all_tasks_stopped = false,
                8 => changed.stopped_snapshot_2_exact_expected_task_set = false,
                9 => changed.stopped_snapshot_2_all_tasks_stopped = false,
                10 => changed.pre_stop_marker_observed = true,
                11 => changed.post_attach_task_count = 1,
                12 => changed.post_attach_exact_expected_task_set = false,
                13 => changed.post_attach_all_tasks_stopped = false,
                14 => changed.post_attach_marker_observed = true,
                15 => changed.signal_attach_attempts = 0,
                16 => changed.signal_attach_attempts = 3,
                17 => changed.signal_attach_accepted = false,
                18 => changed.late_attach_attempts = 0,
                19 => changed.late_attach_attempts = 3,
                20 => changed.late_attach_accepted = false,
                21 => changed.signal_link_detached = false,
                22 => changed.late_link_detached = false,
                23 => changed.last_attach_ts_ns = changed.hook_ts_ns - 1,
                24 => changed.attach_gap_ms = 2.0,
                25 => changed.pidfd_resume_attempts = 2,
                26 => changed.pidfd_resume_rc = -1,
                27 => changed.resume_via_original_pidfd = false,
                28 => changed.post_resume_marker_observed = false,
                29 => changed.late_hits = 0,
                _ => unreachable!(),
            }
            assert!(
                !signal_oracle_pass(&changed),
                "accepted binding signal mutation {mutation}"
            );
        }
        for mutate in [
            |facts: &mut SignalTimingFacts| facts.late_hits = 0,
            |facts: &mut SignalTimingFacts| facts.child_exit = 1,
            |facts: &mut SignalTimingFacts| facts.reaped = false,
        ] {
            let mut changed = valid.clone();
            mutate(&mut changed);
            assert!(!signal_oracle_pass(&changed));
        }
    }

    #[test]
    fn confirmation_requires_two_all_t_samples_1ms_apart_before_deadline() {
        let s = |elapsed_us: u64, ok: bool| StopSnapshot {
            elapsed_us,
            count: 2,
            exact_expected_task_set: ok,
            all_tasks_stopped: ok,
            state_counts: [0; 9],
        };
        assert_eq!(confirm(&[s(1000, false), s(2000, false)]), None);
        assert_eq!(
            confirm(&[s(1000, false), s(2100, true), s(3200, true)]),
            Some((1, 2))
        );
        assert_eq!(confirm(&[s(1000, true), s(1500, true)]), None);
        assert_eq!(confirm(&[s(99_000, true), s(100_500, true)]), None);
        assert_eq!(
            confirm(&[s(1000, true), s(2000, false), s(3000, true), s(4100, true)]),
            Some((2, 3))
        );
    }

    #[test]
    fn signal_oracle_requires_one_winner_one_coalesced_and_closed_drain() {
        let mut facts = passing_facts();
        assert!(signal_oracle_pass(&facts));
        facts.coalesced_records = 0;
        assert!(!signal_oracle_pass(&facts));
        facts.coalesced_records = 1;
        facts.winner_records = 2;
        assert!(!signal_oracle_pass(&facts));
        facts.winner_records = 1;
        facts.drain_empty = false;
        assert!(!signal_oracle_pass(&facts));
        facts.drain_empty = true;
        facts.attached_while_stopped = 1;
        assert!(!signal_oracle_pass(&facts));
        facts.attached_while_stopped = 2;
        facts.final_start_entries = 1;
        assert!(!signal_oracle_pass(&facts));
        facts.final_start_entries = 0;
        // the CAS is symmetric: either thread may win, both finite case IDs
        // must appear exactly once across the winner and coalescer
        facts.winner_case_id = 2;
        facts.coalesced_case_id = 1;
        assert!(signal_oracle_pass(&facts));
        facts.coalesced_case_id = 2;
        assert!(!signal_oracle_pass(&facts));
        facts.coalesced_case_id = 1;
        facts.winner_case_id = 3;
        assert!(!signal_oracle_pass(&facts));
    }

    struct FakeStartMap(Vec<(common::StateKey, common::StartState)>);

    impl FakeStartMap {
        fn new() -> Self {
            Self(Vec::new())
        }
    }

    impl PauseOwnerMap for FakeStartMap {
        fn insert_armed(&mut self, key: &common::StateKey) -> Result<(), &'static str> {
            self.0.push((
                *key,
                common::StartState {
                    arg0: common::PAUSE_ARMED,
                    arg1: 0,
                },
            ));
            Ok(())
        }

        fn remove_owner(&mut self, key: &common::StateKey) -> Result<(), &'static str> {
            self.0.retain(|(existing, _)| existing != key);
            Ok(())
        }

        fn entry_count(&self) -> Result<u64, &'static str> {
            Ok(self.0.len() as u64)
        }
    }

    fn armed_fake(key: common::StateKey) -> FakeStartMap {
        let mut map = FakeStartMap::new();
        map.insert_armed(&key).unwrap();
        map
    }

    #[test]
    fn pause_owner_guard_removes_entry_on_every_exit_path() {
        let key = common::StateKey {
            pid_tgid: 42 << 32,
            attach_cookie: u64::MAX,
        };
        // (i) attach failure after arming: cleanup disarm removes the armed entry
        let mut map = armed_fake(key);
        let mut owner = PauseOwnerGuard::new(key);
        assert!(owner.needs_removal());
        owner.disarm_for_cleanup(&mut map);
        assert_eq!(map.entry_count().unwrap(), 0);
        // (ii) cancellation during observation: same cleanup path, never resumes
        let mut map = armed_fake(key);
        let mut owner = PauseOwnerGuard::new(key);
        owner.disarm_for_cleanup(&mut map);
        assert_eq!(map.entry_count().unwrap(), 0);
        // (iii) unconfirmed attempt: entry removed after cleanup
        let mut map = armed_fake(key);
        let mut owner = PauseOwnerGuard::new(key);
        assert!(!owner.closed);
        owner.disarm_for_cleanup(&mut map);
        assert_eq!(map.entry_count().unwrap(), 0);
        // (iv) happy path: close_after_resume removes the entry before markers are read
        let mut map = armed_fake(key);
        let mut owner = PauseOwnerGuard::new(key);
        assert!(owner.close_after_resume(&mut map).unwrap());
        let entries_after_close = owner.start_entries(&map).unwrap();
        owner.disarm_for_cleanup(&mut map);
        assert_eq!(entries_after_close, 0);
        assert_eq!(map.entry_count().unwrap(), 0);
    }

    #[test]
    fn stat_parser_uses_last_close_paren_space() {
        let stat = "321 (worker) with ) chars) T 1 2 3 4";
        assert_eq!(parse_task_state(stat), Ok(b'T'));
        assert!(parse_task_state("321 (unterminated S 1 2").is_err());
    }

    #[test]
    fn manifest_and_output_paths_are_create_new_private() {
        let temp = TestDir::new("private");
        let output = temp.path().join("evidence");
        create_private_dir(&output).unwrap();
        assert_eq!(std::fs::metadata(&output).unwrap().mode() & 0o777, 0o700);
        assert!(create_private_dir(&output).is_err());

        let evidence = output.join("gate.jsonl");
        let file = create_private_file(&evidence).unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        assert!(create_private_file(&evidence).is_err());

        let manifest = output.join("source-elf.manifest");
        let file = create_private_file(&manifest).unwrap();
        make_manifest_read_only(&file).unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o400);
    }

    #[test]
    fn cleanup_oracle_requires_original_pidfd_one_resume() {
        let valid = CleanupFacts {
            may_be_stopped: true,
            resume_attempts: 1,
            resume_via_original_pidfd: true,
            kill_via_original_pidfd: true,
            reaped: true,
        };
        assert!(cleanup_oracle_pass(valid));
        assert!(!cleanup_oracle_pass(CleanupFacts {
            resume_attempts: 0,
            ..valid
        }));
        assert!(!cleanup_oracle_pass(CleanupFacts {
            resume_attempts: 2,
            ..valid
        }));
        assert!(!cleanup_oracle_pass(CleanupFacts {
            resume_via_original_pidfd: false,
            ..valid
        }));

        let unstopped = CleanupFacts {
            may_be_stopped: false,
            resume_attempts: 0,
            resume_via_original_pidfd: false,
            kill_via_original_pidfd: true,
            reaped: true,
        };
        assert!(cleanup_oracle_pass(unstopped));
        assert!(!cleanup_oracle_pass(CleanupFacts {
            resume_attempts: 2,
            ..unstopped
        }));
        assert!(!cleanup_oracle_pass(CleanupFacts {
            resume_attempts: 1,
            ..unstopped
        }));
        assert!(cleanup_oracle_pass(CleanupFacts {
            resume_attempts: 1,
            resume_via_original_pidfd: true,
            ..unstopped
        }));
    }

    #[test]
    fn pidfd_open_failure_kills_and_reaps_the_gated_child() {
        let temp = TestDir::new("pidfd-failure");
        let marker = temp.path().join("released");
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("IFS= read -r _; printf released >\"$1\"")
            .arg("sh")
            .arg(&marker);
        let error = spawn_pinned_child_with(&mut command, |_| {
            Err(io::Error::from_raw_os_error(libc::EMFILE))
        })
        .err()
        .expect("pidfd failure must be returned");
        assert_eq!(error.pidfd_error.raw_os_error(), Some(libc::EMFILE));
        assert!(error.kill_succeeded);
        assert!(error.reaped);
        assert!(!marker.exists(), "the gated child reached its call path");
    }

    #[test]
    fn successful_original_pidfd_resume_disarms_stopped_cleanup() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("IFS= read -r _; sleep 30");
        let mut guard = spawn_pinned_child(&mut command).unwrap();
        guard.mark_may_be_stopped();
        pidfd_send_signal(guard.original_pidfd.as_raw_fd(), libc::SIGSTOP).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", guard.pid())).unwrap();
            if parse_task_state(&stat).unwrap() == b'T' {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "child did not enter stopped state"
            );
            thread::sleep(Duration::from_millis(10));
        }
        guard.resume_once().unwrap();
        assert!(guard.resume_attempted);
        assert!(
            !guard.may_be_stopped,
            "successful original-pidfd resume must disarm stopped cleanup"
        );
    }

    #[test]
    fn failure_after_stop_resumes_once_then_kills_and_reaps_with_original_pidfd() {
        let mut command = Command::new("sh");
        command.arg("-c").arg("IFS= read -r _; sleep 30");
        let mut guard = spawn_pinned_child(&mut command).unwrap();
        guard.mark_may_be_stopped();
        pidfd_send_signal(guard.original_pidfd.as_raw_fd(), libc::SIGSTOP).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while parse_task_state(
            &std::fs::read_to_string(format!("/proc/{}/stat", guard.pid())).unwrap(),
        )
        .unwrap()
            != b'T'
        {
            assert!(Instant::now() < deadline, "child did not stop");
            thread::sleep(Duration::from_millis(10));
        }
        let pid = guard.pid();
        let cleanup = guard.terminate();
        assert!(cleanup_oracle_pass(cleanup));
        assert_eq!(cleanup.resume_attempts, 1);
        assert!(cleanup.resume_via_original_pidfd);
        assert!(cleanup.kill_via_original_pidfd);
        assert!(cleanup.reaped);
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    fn signal_child(signal: Cancelled, ready: &Path, marker: &Path) {
        let cancellation = Cancellation::install().unwrap();
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("IFS= read -r _; printf released >\"$1\"")
            .arg("sh")
            .arg(marker);
        let mut guard = spawn_pinned_child(&mut command).unwrap();
        guard.mark_may_be_stopped();
        let child_pid = guard.pid();
        std::fs::write(ready, b"ready").unwrap();
        assert_eq!(cancellation.wait(Duration::from_secs(5)).unwrap(), signal);
        drop(guard);
        let rc = unsafe { libc::kill(child_pid as i32, 0) };
        assert_eq!(rc, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
        assert!(!marker.exists());
    }

    #[test]
    fn sigint_sigterm_return_through_child_guard() {
        if let Some(value) = std::env::var_os("SLICE1B2_SIGNAL_CHILD") {
            let signal = match value.to_str().unwrap() {
                "SIGINT" => Cancelled::Sigint,
                "SIGTERM" => Cancelled::Sigterm,
                other => panic!("unexpected signal child {other}"),
            };
            signal_child(
                signal,
                Path::new(&std::env::var_os("SLICE1B2_READY").unwrap()),
                Path::new(&std::env::var_os("SLICE1B2_MARKER").unwrap()),
            );
            return;
        }

        for (name, signal) in [("SIGINT", libc::SIGINT), ("SIGTERM", libc::SIGTERM)] {
            let temp = TestDir::new(name);
            let ready = temp.path().join("ready");
            let marker = temp.path().join("marker");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("tests::sigint_sigterm_return_through_child_guard")
                .arg("--nocapture")
                .env("SLICE1B2_SIGNAL_CHILD", name)
                .env("SLICE1B2_READY", &ready)
                .env("SLICE1B2_MARKER", &marker)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ready.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(ready.exists(), "signal child did not become ready");
            assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
            let status = child.wait().unwrap();
            assert!(
                status.success(),
                "{name} bypassed normal cleanup: status={status:?} signal={:?}",
                status.signal()
            );
            assert!(!marker.exists());
        }
    }

    #[test]
    fn source_manifest_binds_archive_and_extracted_inventory() {
        let manifest = SourceManifest::parse(
            br#"{
                "source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "source_archive_sha256":"ffafba2e642d1140e4f89b3fce5c001817234ea494378196f5e4afa6f7c44524",
                "members":[
                    {"path":"source/alpha","git_mode":33188,"type":"regular","sha256":"8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"},
                    {"path":"source/link","git_mode":40960,"type":"symlink","sha256":"34a04005bcaf206eec990bd9637d9fdb6725e0a0c0d4aebf003f17f4c956eb5c"}
                ]
            }"#,
        )
        .unwrap();
        for invalid_path in [
            "",
            ".",
            "..",
            "/source/alpha",
            "source",
            "source/",
            "source//alpha",
            "source/./alpha",
            "source/../alpha",
            "source/alpha/",
            "source/alpha//beta",
            "source/alpha/./beta",
            "source/alpha/../beta",
        ] {
            let json = format!(
                r#"{{
                    "source_commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "source_archive_sha256":"ffafba2e642d1140e4f89b3fce5c001817234ea494378196f5e4afa6f7c44524",
                    "members":[{{"path":"{invalid_path}","git_mode":33188,"type":"regular","sha256":"8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8"}}]
                }}"#
            );
            assert!(
                SourceManifest::parse(json.as_bytes()).is_err(),
                "accepted aliased source member path {invalid_path:?}"
            );
        }
        let inventory = vec![
            InventoryMember {
                path: "source/alpha".into(),
                git_mode: 0o100644,
                kind: MemberKind::Regular,
                sha256: "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8".into(),
            },
            InventoryMember {
                path: "source/link".into(),
                git_mode: 0o120000,
                kind: MemberKind::Symlink,
                sha256: "34a04005bcaf206eec990bd9637d9fdb6725e0a0c0d4aebf003f17f4c956eb5c".into(),
            },
        ];
        assert!(manifest.verify_bundle(b"archive-v1", &inventory).is_ok());
        assert!(manifest.verify_bundle(b"archive-v2", &inventory).is_err());
        let mut changed = inventory.clone();
        changed[0].sha256.replace_range(0..1, "0");
        assert!(manifest.verify_bundle(b"archive-v1", &changed).is_err());
        assert!(
            manifest
                .verify_bundle(b"archive-v1", &inventory[..1])
                .is_err()
        );
    }

    #[test]
    fn compare_rejects_each_privacy_safe_oracle_fact_mutation() {
        let valid = CompareFacts {
            gate_a_cases: valid_gate_a_cases(),
            maps: valid_maps(),
            signal_runs: vec![valid_signal(); 20],
        };
        assert!(compare_oracles(&valid));
        let mut short = valid.clone();
        short.signal_runs.pop();
        assert!(!compare_oracles(&short));
        let mut long = valid.clone();
        long.signal_runs.push(valid_signal());
        assert!(!compare_oracles(&long));

        for case_index in 0..valid.gate_a_cases.len() {
            for mutate in 0..9 {
                let mut changed = valid.clone();
                let case = &mut changed.gate_a_cases[case_index];
                match mutate {
                    0 => {
                        case.case = match case.case {
                            GateACaseId::Full104 => GateACaseId::GuardAfter7,
                            _ => GateACaseId::Full104,
                        }
                    }
                    1 => case.entry_attach_attempts += 1,
                    2 => case.entry_attach_accepted = false,
                    3 => case.return_attach_attempts += 1,
                    4 => case.return_attach_accepted = false,
                    5 => case.entry_link_detached = false,
                    6 => case.return_link_detached = false,
                    7 => case.start_empty = false,
                    8 => {
                        case.records.pop();
                    }
                    _ => unreachable!(),
                }
                assert!(
                    !compare_oracles(&changed),
                    "accepted case mutation {case_index}/{mutate}"
                );
            }
            for counter in 0..5 {
                let mut changed = valid.clone();
                changed.gate_a_cases[case_index].counters_before[counter] += 1;
                assert!(
                    !compare_oracles(&changed),
                    "accepted case counter-before mutation {case_index}/{counter}"
                );
                let mut changed = valid.clone();
                changed.gate_a_cases[case_index].counters_after[counter] += 1;
                assert!(
                    !compare_oracles(&changed),
                    "accepted case counter-after mutation {case_index}/{counter}"
                );
            }
            for record_index in 0..valid.gate_a_cases[case_index].records.len() {
                for field in 0..6 {
                    let mut changed = valid.clone();
                    let record = &mut changed.gate_a_cases[case_index].records[record_index];
                    match field {
                        0 => record.usable_n = record.usable_n.wrapping_add(1),
                        1 => record.pointers_attempted = record.pointers_attempted.wrapping_add(1),
                        2 => record.completed_prefix = record.completed_prefix.wrapping_add(1),
                        3 => {
                            record.name_class = match record.name_class {
                                NameClass::ExactStandard => NameClass::Other,
                                NameClass::Other => NameClass::Null,
                                NameClass::Null => NameClass::Unreadable,
                                NameClass::Unreadable | NameClass::NotApplicable => {
                                    NameClass::ExactStandard
                                }
                            }
                        }
                        4 => record.all_usable_pointers_nonzero = false,
                        5 => record.all_usable_pointers_equal_fixture = false,
                        _ => unreachable!(),
                    }
                    assert!(
                        !compare_oracles(&changed),
                        "accepted case record mutation {case_index}/{record_index}/{field}"
                    );
                }
            }
        }

        for map_index in 0..valid.maps.len() {
            for field in 0..6 {
                let mut changed = valid.clone();
                let map = &mut changed.maps[map_index];
                match field {
                    0 => map.map.push('X'),
                    1 => map.map_type.push('X'),
                    2 => map.key_size += 1,
                    3 => map.value_size += 1,
                    4 => map.max_entries += 1,
                    5 => map.logical_value_bytes += 1,
                    _ => unreachable!(),
                }
                assert!(
                    !compare_oracles(&changed),
                    "accepted map mutation {map_index}/{field}"
                );
            }
        }

        for field in 0..30 {
            let mut changed = valid.clone();
            let signal = &mut changed.signal_runs[0];
            match field {
                0 => signal.hook_ts_ns += 1,
                1 => signal.send_signal_rc = -1,
                2 => signal.stop_request_accepted = false,
                3 => signal.expected_task_count += 1,
                4 => signal.stopped_snapshot_1_count += 1,
                5 => signal.stopped_snapshot_2_count += 1,
                6 => signal.stopped_snapshot_1_exact_expected_task_set = false,
                7 => signal.stopped_snapshot_1_all_tasks_stopped = false,
                8 => signal.stopped_snapshot_2_exact_expected_task_set = false,
                9 => signal.stopped_snapshot_2_all_tasks_stopped = false,
                10 => signal.pre_stop_marker_observed = true,
                11 => signal.post_attach_task_count += 1,
                12 => signal.post_attach_exact_expected_task_set = false,
                13 => signal.post_attach_all_tasks_stopped = false,
                14 => signal.post_attach_marker_observed = true,
                15 => signal.signal_attach_attempts += 1,
                16 => signal.signal_attach_accepted = false,
                17 => signal.late_attach_attempts += 1,
                18 => signal.late_attach_accepted = false,
                19 => signal.signal_link_detached = false,
                20 => signal.late_link_detached = false,
                21 => signal.last_attach_ts_ns += 1,
                22 => signal.attach_gap_ms += 0.5,
                23 => signal.pidfd_resume_attempts += 1,
                24 => signal.pidfd_resume_rc = -1,
                25 => signal.resume_via_original_pidfd = false,
                26 => signal.post_resume_marker_observed = false,
                27 => signal.late_hits += 1,
                28 => signal.child_exit = 1,
                29 => signal.reaped = false,
                _ => unreachable!(),
            }
            assert!(
                !compare_oracles(&changed),
                "accepted signal mutation {field}"
            );
        }

        let projected = discovery_json_projection(&valid.gate_a_cases[0].records[0]);
        let object = projected.as_object().unwrap();
        for forbidden in [
            "pid",
            "tid",
            "pid_tgid",
            "table_ptr",
            "pointers",
            "name",
            "path",
        ] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[test]
    fn runtime_overlay_requires_exact_0444_backing_chain() {
        let json = br#"[
            {"filename":"/run/runtime.qcow2","format":"qcow2","backing-filename":"/retained/overlay.qcow2","backing-filename-format":"qcow2"},
            {"filename":"/retained/overlay.qcow2","format":"qcow2","backing-filename":"/retained/official.qcow2","backing-filename-format":"qcow2"},
            {"filename":"/retained/official.qcow2","format":"qcow2"}
        ]"#;
        assert!(
            validate_backing_chain(
                json,
                Path::new("/run/runtime.qcow2"),
                Path::new("/retained/overlay.qcow2"),
                Path::new("/retained/official.qcow2"),
                0o444,
            )
            .is_ok()
        );
        assert!(
            validate_backing_chain(
                json,
                Path::new("/run/runtime.qcow2"),
                Path::new("/retained/overlay.qcow2"),
                Path::new("/retained/official.qcow2"),
                0o644,
            )
            .is_err()
        );
        let relative = String::from_utf8(json.to_vec())
            .unwrap()
            .replace("/retained/overlay.qcow2", "overlay.qcow2");
        assert!(
            validate_backing_chain(
                relative.as_bytes(),
                Path::new("/run/runtime.qcow2"),
                Path::new("/retained/overlay.qcow2"),
                Path::new("/retained/official.qcow2"),
                0o444,
            )
            .is_err()
        );
    }

    #[test]
    fn vm_runner_serializes_and_enforces_three_exact_free_space_gates() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("vm-disabled");
        let bin = temp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let df = bin.join("df");
        std::fs::write(&df, "#!/bin/sh\nprintf 'Avail\\n%s\\n' \"$DF_AVAILABLE\"\n").unwrap();
        std::fs::set_permissions(&df, std::fs::Permissions::from_mode(0o755)).unwrap();
        let body = "source \"$1\"; require_free_bytes before-overlay \"$2\"";
        let path = format!("{}:/usr/bin:/bin", bin.display());
        let exact = Command::new("bash")
            .arg("-c")
            .arg(body)
            .arg("bash")
            .arg(script)
            .arg(temp.path())
            .env("PATH", &path)
            .env("DF_AVAILABLE", "2147483648")
            .output()
            .unwrap();
        assert!(exact.status.success());
        assert_eq!(exact.stdout, b"before-overlay=2147483648\n");
        let short = Command::new("bash")
            .arg("-c")
            .arg(body)
            .arg("bash")
            .arg(script)
            .arg(temp.path())
            .env("PATH", &path)
            .env("DF_AVAILABLE", "2147483647")
            .output()
            .unwrap();
        assert!(!short.status.success());
        assert_eq!(short.stdout, b"before-overlay=2147483647\n");

        let existing = temp.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        let disabled = Command::new(script)
            .arg("vm-start")
            .arg("jammy")
            .arg(&existing)
            .output()
            .unwrap();
        assert_eq!(disabled.status.code(), Some(64));
        assert_eq!(
            disabled.stderr,
            b"vm-start unavailable until complete lifecycle is implemented\n"
        );
        assert!(std::fs::read_dir(&existing).unwrap().next().is_none());

        let export = temp.path().join("export");
        std::fs::create_dir(&export).unwrap();
        let lifecycle = Command::new(script)
            .arg("gate-a-lane")
            .arg("jammy")
            .arg(temp.path())
            .arg(&existing)
            .arg(&export)
            .output()
            .unwrap();
        assert_eq!(lifecycle.status.code(), Some(64));
        assert_eq!(
            lifecycle.stderr,
            b"gate-a-lane requires new run and export directories\n"
        );
    }

    #[test]
    fn gate_a_verifier_execution_has_a_strictly_larger_outer_ssh_bound() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-timeout");
        let bin = temp.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let timeout = bin.join("timeout");
        std::fs::write(&timeout, "#!/bin/sh\nprintf '%s\\n' \"$1\"\n").unwrap();
        std::fs::set_permissions(&timeout, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; gate_ssh /known-hosts 2222 true")
            .arg("bash")
            .arg(script)
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "gate SSH failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"150s\n");
    }

    fn fake_gate_bundle(path: &Path) {
        std::fs::create_dir(path).unwrap();
        for name in [
            "source-elf.manifest",
            "build-evidence.txt",
            "execution.manifest",
            "slice1b2-kernel-ebpf",
            "slice1b2-fixture",
            "slice1b2-runner",
        ] {
            std::fs::write(path.join(name), name).unwrap();
        }
    }

    fn shell_output(script: &str, body: &str, args: &[&OsStr]) -> std::process::Output {
        let mut command = Command::new("bash");
        command.arg("-c").arg(body).arg("bash").arg(script);
        command.args(args).output().unwrap()
    }

    fn fake_canonical_gate_export(path: &Path, verifier_count: usize, category: &str) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let programs = [
            "function_list_entry",
            "function_list_return",
            "interface_list_entry",
            "interface_list_return",
        ];
        let verifier = programs[..verifier_count]
            .iter()
            .enumerate()
            .map(|(index, program)| {
                let accepted = category != "verifier" || index != verifier_count - 1;
                serde_json::json!({
                    "program": program,
                    "accepted": accepted,
                    "load_attempted": true,
                    "success_log_contract": if accepted { "accepted_line_only" } else { "rejection_error_chain" },
                    "pass": accepted,
                    "failure_category": if accepted { "none" } else { "verifier" },
                })
                .to_string()
                    + "\n"
            })
            .collect::<String>();
        let map_facts = [
            ("EVENTS", "ringbuf", 0, 0, 262_144, 262_144),
            ("DISCOVERY", "ringbuf", 0, 0, 65_536, 65_536),
            ("START", "hash", 16, 16, 64, 1_024),
            ("COUNTERS", "array", 4, 8, 5, 40),
        ];
        let mut cases = map_facts
            .iter()
            .map(
                |(map, map_type, key_size, value_size, max_entries, logical_value_bytes)| {
                    serde_json::json!({
                        "record_type": "map", "map": map, "map_type": map_type,
                        "key_size": key_size, "value_size": value_size,
                        "max_entries": max_entries, "logical_value_bytes": logical_value_bytes,
                        "pass": false, "failure_category": "pending",
                    })
                    .to_string()
                        + "\n"
                },
            )
            .collect::<String>();
        let case_names = [
            "FULL_104",
            "GUARD_AFTER_7",
            "UNREADABLE_TABLE",
            "UNREADABLE_PP",
            "INTERFACE",
        ];
        let case_count = match category {
            "verifier" => 0,
            "runtime" => 2,
            _ => case_names.len(),
        };
        for (index, case) in case_names[..case_count].iter().enumerate() {
            let failed = (category == "runtime" && index + 1 == case_count)
                || (category == "oracle" && index == 2);
            let final_case = case_count == case_names.len() && index + 1 == case_count;
            let (before, after, deltas) = if final_case {
                ([0, 4, 0, 1, 0], [0, 5, 0, 1, 0], [0, 1, 0, 0, 0])
            } else {
                ([0; 5], [0; 5], [0; 5])
            };
            let mut value = serde_json::json!({
                "record_type": "case", "case": case,
                "entry_attach_attempts": 1, "entry_attach_accepted": true,
                "return_attach_attempts": 1, "return_attach_accepted": true,
                "entry_link_detached": true, "return_link_detached": true,
                "start_empty": true, "record_count": 0,
                "counters_before": before, "counters_after": after,
                "counter_deltas": deltas, "records": [],
                "pass": !failed,
                "failure_category": if failed { category } else { "none" },
            });
            if category == "runtime" && failed {
                value["runtime_failure_reason"] = "child wait".into();
            }
            cases.push_str(&value.to_string());
            cases.push('\n');
        }
        let status = if category == "none" { "PASS" } else { "FAIL" };
        for (name, contents) in [
            ("environment.txt", "kernel_release=test\n".to_owned()),
            ("manifest-digests.txt", "bpf_sha256=test\n".to_owned()),
            ("verifier.log", "program=test outcome=accepted\n".to_owned()),
            ("verifier-results.jsonl", verifier),
            ("gate-a-cases.jsonl", cases),
            (
                "runner-status.txt",
                format!("status={status}\nfailure_category={category}\n"),
            ),
        ] {
            let file = path.join(name);
            std::fs::write(&file, contents).unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn shell_validate_gate_export(script: &str, path: &Path, expected_rc: u8) -> bool {
        Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; validate_local_export a \"$2\" \"$3\"")
            .arg("bash")
            .arg(script)
            .arg(path)
            .arg(expected_rc.to_string())
            .status()
            .unwrap()
            .success()
    }

    fn signal_timing_value(run: usize, facts: &SignalTimingFacts) -> serde_json::Value {
        let mut value = serde_json::json!({
            "signal_run": run,
            "hook_ts_ns": facts.hook_ts_ns,
            "send_signal_rc": facts.send_signal_rc,
            "stop_request_accepted": facts.stop_request_accepted,
            "expected_task_count": facts.expected_task_count,
            "winner_records": facts.winner_records,
            "coalesced_records": facts.coalesced_records,
            "signal_helper_calls": facts.signal_helper_calls,
            "winner_case_id": facts.winner_case_id,
            "coalesced_case_id": facts.coalesced_case_id,
            "stopped_snapshot_1_count": facts.stopped_snapshot_1_count,
            "stopped_snapshot_2_count": facts.stopped_snapshot_2_count,
            "stopped_snapshot_1_exact_expected_task_set": facts.stopped_snapshot_1_exact_expected_task_set,
            "stopped_snapshot_1_all_tasks_stopped": facts.stopped_snapshot_1_all_tasks_stopped,
            "stopped_snapshot_2_exact_expected_task_set": facts.stopped_snapshot_2_exact_expected_task_set,
            "stopped_snapshot_2_all_tasks_stopped": facts.stopped_snapshot_2_all_tasks_stopped,
            "stop_wait_ceiling_us": 100_000,
            "confirmation_sample_indexes": facts.confirmation_sample_indexes,
            "samples": facts.samples.iter().map(|snapshot| serde_json::json!({
                "elapsed_us": snapshot.elapsed_us,
                "task_count": snapshot.count,
                "exact_expected_task_set": snapshot.exact_expected_task_set,
                "all_tasks_stopped": snapshot.all_tasks_stopped,
                "state_counts": snapshot.state_counts,
            })).collect::<Vec<_>>(),
            "pre_stop_marker_observed": facts.pre_stop_marker_observed,
            "drain_empty": facts.drain_empty,
            "required_attach_keys": facts.required_attach_keys,
        });
        let extra = serde_json::json!({
            "post_attach_task_count": facts.post_attach_task_count,
            "post_attach_exact_expected_task_set": facts.post_attach_exact_expected_task_set,
            "post_attach_all_tasks_stopped": facts.post_attach_all_tasks_stopped,
            "post_attach_marker_observed": facts.post_attach_marker_observed,
            "attached_while_stopped": facts.attached_while_stopped,
            "queue_empty_before_resume": facts.queue_empty_before_resume,
            "markers_after_resume": facts.markers_after_resume,
            "signal_attach_attempts": facts.signal_attach_attempts,
            "signal_attach_accepted": facts.signal_attach_accepted,
            "late_attach_attempts": facts.late_attach_attempts,
            "late_attach_accepted": facts.late_attach_accepted,
            "signal_link_detached": facts.signal_link_detached,
            "late_link_detached": facts.late_link_detached,
            "last_attach_ts_ns": facts.last_attach_ts_ns,
            "attach_gap_ms": facts.attach_gap_ms,
            "pidfd_resume_attempts": facts.pidfd_resume_attempts,
            "pidfd_resume_rc": facts.pidfd_resume_rc,
            "resume_via_original_pidfd": facts.resume_via_original_pidfd,
            "owner_removed": facts.owner_removed,
            "final_start_entries": facts.final_start_entries,
            "post_resume_marker_observed": facts.post_resume_marker_observed,
            "late_hits": facts.late_hits,
            "child_exit": facts.child_exit,
            "reaped": facts.reaped,
            "pass": signal_oracle_pass(facts),
            "failure_category": if signal_oracle_pass(facts) { "none" } else { "oracle" },
        });
        for (name, field) in extra.as_object().unwrap() {
            value
                .as_object_mut()
                .unwrap()
                .insert(name.clone(), field.clone());
        }
        value
    }

    fn fake_canonical_gate_b_export(
        path: &Path,
        verifier_count: usize,
        runs: usize,
        category: &str,
    ) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let programs = ["signal_return", "late_hit"];
        let verifier = programs[..verifier_count]
            .iter()
            .enumerate()
            .map(|(index, program)| {
                let accepted = category != "verifier" || index + 1 != verifier_count;
                serde_json::json!({
                    "program": program,
                    "accepted": accepted,
                    "load_attempted": true,
                    "success_log_contract": if accepted { "accepted_line_only" } else { "rejection_error_chain" },
                    "pass": accepted,
                    "failure_category": if accepted { "none" } else { "verifier" },
                })
                .to_string()
                    + "\n"
            })
            .collect::<String>();
        let timing = (1..=runs)
            .map(|run| signal_timing_value(run, &valid_signal()).to_string() + "\n")
            .collect::<String>();
        let status = if category == "none" { "PASS" } else { "FAIL" };
        for (name, contents) in [
            ("environment.txt", "kernel_release=test\n".to_owned()),
            ("manifest-digests.txt", "bpf_sha256=test\n".to_owned()),
            ("verifier.log", "program=test outcome=accepted\n".to_owned()),
            ("verifier-results.jsonl", verifier),
            ("signal-timing.jsonl", timing),
            (
                "runner-status.txt",
                format!("status={status}\nfailure_category={category}\n"),
            ),
        ] {
            let file = path.join(name);
            std::fs::write(&file, contents).unwrap();
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn shell_validate_gate_b_export(script: &str, path: &Path, expected_rc: u8) -> bool {
        Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; validate_local_export b \"$2\" \"$3\"")
            .arg("bash")
            .arg(script)
            .arg(path)
            .arg(expected_rc.to_string())
            .status()
            .unwrap()
            .success()
    }

    fn shell_validate_gate_b_semantics(script: &str, path: &Path, expected_rc: u8) -> bool {
        Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; validate_gate_b_semantics \"$2\" \"$3\"")
            .arg("bash")
            .arg(script)
            .arg(path)
            .arg(expected_rc.to_string())
            .status()
            .unwrap()
            .success()
    }

    #[test]
    fn canonical_gate_export_requires_four_verifier_records_and_matching_final_status() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-export-semantics");
        let valid = temp.path().join("valid");
        fake_canonical_gate_export(&valid, 4, "none");
        assert!(shell_validate_gate_export(script, &valid, 0));

        let short = temp.path().join("short");
        fake_canonical_gate_export(&short, 3, "none");
        assert!(!shell_validate_gate_export(script, &short, 0));

        let mismatch = temp.path().join("mismatch");
        fake_canonical_gate_export(&mismatch, 4, "none");
        assert!(!shell_validate_gate_export(script, &mismatch, 1));
    }

    #[test]
    fn canonical_gate_categories_require_consistent_finite_records() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-export-categories");
        for category in ["verifier", "runtime", "oracle"] {
            let path = temp.path().join(category);
            fake_canonical_gate_export(&path, 4, category);
            assert!(shell_validate_gate_export(script, &path, 1), "{category}");
        }

        for (category, source) in [
            ("verifier", "oracle"),
            ("runtime", "oracle"),
            ("oracle", "none"),
        ] {
            let path = temp.path().join(format!("contradictory-{category}"));
            fake_canonical_gate_export(&path, 4, source);
            std::fs::write(
                path.join("runner-status.txt"),
                format!("status=FAIL\nfailure_category={category}\n"),
            )
            .unwrap();
            assert!(!shell_validate_gate_export(script, &path, 1), "{category}");
        }
    }

    #[test]
    fn oracle_fail_accepts_map_counter_or_start_witness_but_not_exact_aggregate() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-oracle-aggregate");
        let mut accepted = Vec::new();
        for witness in ["map", "counter", "start"] {
            let path = temp.path().join(witness);
            fake_canonical_gate_export(&path, 4, "none");
            let cases_path = path.join("gate-a-cases.jsonl");
            let mut records = std::fs::read_to_string(&cases_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            match witness {
                "map" => {
                    records[0]["max_entries"] = 131_072.into();
                    records[0]["logical_value_bytes"] = 131_072.into();
                }
                "counter" => {
                    let last = records.last_mut().unwrap();
                    last["counters_after"][1] = 4.into();
                    last["counter_deltas"][1] = 0.into();
                }
                "start" => records.last_mut().unwrap()["start_empty"] = false.into(),
                _ => unreachable!(),
            }
            let contents = records
                .iter()
                .map(|record| record.to_string() + "\n")
                .collect::<String>();
            std::fs::write(&cases_path, contents).unwrap();
            std::fs::write(
                path.join("runner-status.txt"),
                "status=FAIL\nfailure_category=oracle\n",
            )
            .unwrap();
            accepted.push((witness, shell_validate_gate_export(script, &path, 1)));
        }
        assert_eq!(
            accepted,
            [("map", true), ("counter", true), ("start", true)]
        );
    }

    #[test]
    fn gate_b_semantics_recompute_all_runs_and_reject_contradictions() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-b-semantics");
        let valid = temp.path().join("valid");
        fake_canonical_gate_b_export(&valid, 2, 20, "none");
        assert!(shell_validate_gate_b_export(script, &valid, 0));

        let verifier_failure = temp.path().join("valid-verifier-failure");
        fake_canonical_gate_b_export(&verifier_failure, 2, 20, "verifier");
        std::fs::write(verifier_failure.join("signal-timing.jsonl"), "").unwrap();
        assert!(shell_validate_gate_b_export(script, &verifier_failure, 1));

        let runtime_failure = temp.path().join("valid-runtime-failure");
        fake_canonical_gate_b_export(&runtime_failure, 2, 1, "none");
        let timing = runtime_failure.join("signal-timing.jsonl");
        let mut record: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&timing).unwrap().trim()).unwrap();
        record["pass"] = false.into();
        record["failure_category"] = "runtime".into();
        record["runtime_failure_reason"] = "task stat".into();
        std::fs::write(&timing, record.to_string() + "\n").unwrap();
        std::fs::write(
            runtime_failure.join("runner-status.txt"),
            "status=FAIL\nfailure_category=runtime\n",
        )
        .unwrap();
        assert!(shell_validate_gate_b_export(script, &runtime_failure, 1));
        let runtime_reasons = shell_lines(script, "source \"$1\"; gate_b_runtime_reasons", &[]);
        assert_eq!(runtime_reasons.len(), 35);
        assert_eq!(
            runtime_reasons
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            runtime_reasons.len()
        );
        let production_source = std::fs::read_to_string(file!()).unwrap();
        let production_source = production_source.split_once("#[cfg(test)]").unwrap().0;
        for reason in &runtime_reasons {
            assert!(
                production_source.contains(&format!("\"{reason}\"")),
                "validator reason is not produced by Gate B: {reason}"
            );
            record["runtime_failure_reason"] = reason.clone().into();
            std::fs::write(&timing, record.to_string() + "\n").unwrap();
            assert!(
                shell_validate_gate_b_semantics(script, &runtime_failure, 1),
                "rejected reachable Gate B runtime reason: {reason}"
            );
        }
        record["runtime_failure_reason"] = "unknown runtime reason".into();
        std::fs::write(&timing, record.to_string() + "\n").unwrap();
        assert!(!shell_validate_gate_b_semantics(
            script,
            &runtime_failure,
            1
        ));

        let oracle_failure = temp.path().join("valid-oracle-failure");
        fake_canonical_gate_b_export(&oracle_failure, 2, 1, "none");
        let timing = oracle_failure.join("signal-timing.jsonl");
        let mut record: serde_json::Value =
            serde_json::from_str(std::fs::read_to_string(&timing).unwrap().trim()).unwrap();
        record["late_hits"] = 0.into();
        record["pass"] = false.into();
        record["failure_category"] = "oracle".into();
        std::fs::write(&timing, record.to_string() + "\n").unwrap();
        std::fs::write(
            oracle_failure.join("runner-status.txt"),
            "status=FAIL\nfailure_category=oracle\n",
        )
        .unwrap();
        assert!(shell_validate_gate_b_export(script, &oracle_failure, 1));

        for runs in [19, 21] {
            let path = temp.path().join(format!("runs-{runs}"));
            fake_canonical_gate_b_export(&path, 2, runs, "none");
            assert!(
                !shell_validate_gate_b_export(script, &path, 0),
                "accepted {runs} Gate B runs"
            );
        }
        for verifier_count in [1, 2] {
            let path = temp.path().join(format!("verifier-{verifier_count}"));
            fake_canonical_gate_b_export(&path, verifier_count, 20, "none");
            if verifier_count == 2 {
                let verifier = path.join("verifier-results.jsonl");
                let mut records = std::fs::read_to_string(&verifier)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                    .collect::<Vec<_>>();
                records[1]["accepted"] = false.into();
                records[1]["pass"] = false.into();
                records[1]["failure_category"] = "verifier".into();
                records[1]["success_log_contract"] = "rejection_error_chain".into();
                std::fs::write(
                    verifier,
                    records
                        .iter()
                        .map(|record| record.to_string() + "\n")
                        .collect::<String>(),
                )
                .unwrap();
            }
            assert!(
                !shell_validate_gate_b_export(script, &path, 0),
                "accepted contradictory verifier evidence {verifier_count}"
            );
        }

        let contradictory = temp.path().join("contradictory-category");
        fake_canonical_gate_b_export(&contradictory, 2, 20, "none");
        std::fs::write(
            contradictory.join("runner-status.txt"),
            "status=FAIL\nfailure_category=verifier\n",
        )
        .unwrap();
        assert!(!shell_validate_gate_b_export(script, &contradictory, 1));

        for mutation in 0..43 {
            let path = temp.path().join(format!("mutation-{mutation}"));
            fake_canonical_gate_b_export(&path, 2, 20, "none");
            let timing = path.join("signal-timing.jsonl");
            let mut records = std::fs::read_to_string(&timing)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .collect::<Vec<_>>();
            let record = &mut records[0];
            match mutation {
                0 => record["hook_ts_ns"] = 0.into(),
                1 => record["send_signal_rc"] = (-1).into(),
                2 => record["stop_request_accepted"] = false.into(),
                3 => record["expected_task_count"] = 3.into(),
                4 => record["stopped_snapshot_1_count"] = 1.into(),
                5 => record["stopped_snapshot_2_count"] = 1.into(),
                6 => record["stopped_snapshot_1_exact_expected_task_set"] = false.into(),
                7 => record["stopped_snapshot_1_all_tasks_stopped"] = false.into(),
                8 => record["stopped_snapshot_2_exact_expected_task_set"] = false.into(),
                9 => record["stopped_snapshot_2_all_tasks_stopped"] = false.into(),
                10 => record["pre_stop_marker_observed"] = true.into(),
                11 => record["post_attach_task_count"] = 1.into(),
                12 => record["post_attach_exact_expected_task_set"] = false.into(),
                13 => record["post_attach_all_tasks_stopped"] = false.into(),
                14 => record["post_attach_marker_observed"] = true.into(),
                15 => record["signal_attach_attempts"] = 0.into(),
                16 => record["signal_attach_attempts"] = 3.into(),
                17 => record["signal_attach_accepted"] = false.into(),
                18 => record["late_attach_attempts"] = 0.into(),
                19 => record["late_attach_attempts"] = 3.into(),
                20 => record["late_attach_accepted"] = false.into(),
                21 => record["signal_link_detached"] = false.into(),
                22 => record["late_link_detached"] = false.into(),
                23 => record["last_attach_ts_ns"] = 999_999.into(),
                24 => record["attach_gap_ms"] = 2.0.into(),
                25 => record["pidfd_resume_attempts"] = 0.into(),
                26 => record["pidfd_resume_attempts"] = 2.into(),
                27 => record["pidfd_resume_rc"] = (-1).into(),
                28 => record["resume_via_original_pidfd"] = false.into(),
                29 => record["post_resume_marker_observed"] = false.into(),
                30 => record["late_hits"] = 0.into(),
                31 => record["late_hits"] = 3.into(),
                32 => {
                    record["child_exit"] = 1.into();
                    record["reaped"] = false.into();
                }
                33 => record["winner_records"] = 2.into(),
                34 => record["coalesced_records"] = 0.into(),
                35 => record["drain_empty"] = false.into(),
                36 => record["attached_while_stopped"] = 1.into(),
                37 => record["final_start_entries"] = 1.into(),
                38 => record["owner_removed"] = false.into(),
                39 => record["queue_empty_before_resume"] = false.into(),
                40 => record["markers_after_resume"] = 1.into(),
                41 => record["winner_case_id"] = 2.into(),
                42 => record["confirmation_sample_indexes"] = serde_json::Value::Null,
                _ => unreachable!(),
            }
            std::fs::write(
                timing,
                records
                    .iter()
                    .map(|record| record.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            assert!(
                !shell_validate_gate_b_export(script, &path, 0),
                "accepted Gate B mutation {mutation}"
            );
        }
    }

    #[test]
    fn gate_b_remote_export_omits_gate_a_semantics() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let output = Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; remote_export_script b")
            .arg("bash")
            .arg(script)
            .output()
            .unwrap();
        assert!(output.status.success());
        let generated = String::from_utf8(output.stdout).unwrap();
        assert!(generated.contains("gate=b"));
        assert!(generated.contains("signal-timing.jsonl"));
        assert!(!generated.contains("gate-a-cases.jsonl"));
        let mut syntax = Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        syntax
            .stdin
            .take()
            .unwrap()
            .write_all(generated.as_bytes())
            .unwrap();
        assert!(syntax.wait().unwrap().success());
    }

    #[test]
    fn canonical_validation_failure_does_not_publish_gate_outcome() {
        let _serial = VM_TEST_LOCK.lock().unwrap();
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-invalid-outcome");
        let bundle = temp.path().join("bundle");
        let run = temp.path().join("run");
        let export = temp.path().join("export");
        fake_gate_bundle(&bundle);
        let body = concat!(
            "source \"$1\"; shift; validate_execution_bundle() { return 0; }; ",
            "private_start_lane() { mkdir -m 0700 \"$2\"; PRIVATE_RUN_DIR=$2; PRIVATE_KNOWN_HOSTS=/known; PRIVATE_PORT=2222; PRIVATE_LANE_OWNED=1; }; ",
            "strict_ssh() { return 0; }; cmp() { return 0; }; scp_argv() { printf '%s\\0' /bin/true; }; ",
            "gate_ssh() { return 0; }; export_evidence() { mkdir -m 0700 \"$5\"; }; ",
            "validate_local_export() { return 64; }; private_finish_lane() { return 0; }; ",
            "set +e; gate_a_lane jammy \"$1\" \"$2\" \"$3\"; printf 'rc=%s\\n' \"$?\""
        );
        let output = shell_output(
            script,
            body,
            &[bundle.as_os_str(), run.as_os_str(), export.as_os_str()],
        );
        assert!(output.status.success());
        assert_eq!(output.stdout, b"rc=64\n");
        assert!(!run.join("gate-a.outcome").exists());
    }

    #[test]
    fn gate_a_timeout_is_quiesced_not_exported_and_cleaned_up() {
        let _serial = VM_TEST_LOCK.lock().unwrap();
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-timeout-outcome");
        let bundle = temp.path().join("bundle");
        let run = temp.path().join("run");
        let export = temp.path().join("export");
        let bin = temp.path().join("bin");
        let timeout_log = temp.path().join("timeouts.txt");
        fake_gate_bundle(&bundle);
        std::fs::create_dir(&bin).unwrap();
        let timeout = bin.join("timeout");
        std::fs::write(
            &timeout,
            "#!/bin/sh\nprintf '%s\\n' \"$1\" >>\"$TIMEOUT_LOG\"\nshift\nexec \"$@\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&timeout, std::fs::Permissions::from_mode(0o755)).unwrap();
        let body = concat!(
            "source \"$1\"; shift; ",
            "validate_execution_bundle() { return 0; }; ",
            "private_start_lane() { mkdir -m 0700 \"$2\"; PRIVATE_RUN_DIR=$2; PRIVATE_KNOWN_HOSTS=/known; PRIVATE_PORT=2222; PRIVATE_LANE_OWNED=1; return 0; }; ",
            "strict_ssh() { return 0; }; cmp() { return 0; }; ",
            "scp_argv() { printf '%s\\0' /bin/true; }; ",
            "gate_ssh() { printf '%s\\n' \"$*\" >\"$PRIVATE_RUN_DIR/remote-command.txt\"; return 124; }; ",
            "quiesce_gate_runner() { : >\"$PRIVATE_RUN_DIR/quiesced\"; return 0; }; ",
            "export_evidence() { : >\"$PRIVATE_RUN_DIR/export-called\"; return 0; }; ",
            "validate_local_export() { : >\"$PRIVATE_RUN_DIR/validate-called\"; return 0; }; ",
            "private_finish_lane() { : >\"$PRIVATE_RUN_DIR/cleaned\"; return 0; }; ",
            "set +e; gate_a_lane jammy \"$1\" \"$2\" \"$3\"; rc=$?; set +e; printf 'rc=%s\\n' \"$rc\""
        );
        let mut command = Command::new("bash");
        command
            .arg("-c")
            .arg(body)
            .arg("bash")
            .arg(script)
            .args([&bundle, &run, &export])
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("TIMEOUT_LOG", &timeout_log);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "timeout lane failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"rc=2\n");
        assert_eq!(std::fs::read(run.join("gate-a.status")).unwrap(), b"124\n");
        assert_eq!(
            std::fs::read(run.join("gate-a.outcome")).unwrap(),
            b"TIMEOUT\n"
        );
        assert!(run.join("quiesced").exists());
        assert!(run.join("cleaned").exists());
        assert!(!run.join("export-called").exists());
        assert!(!run.join("validate-called").exists());
        assert!(!export.exists());
        assert_eq!(
            std::fs::read_to_string(timeout_log).unwrap(),
            "120s\n120s\n120s\n120s\n120s\n120s\n"
        );
        let remote = std::fs::read_to_string(run.join("remote-command.txt")).unwrap();
        assert!(remote.contains(
            "sudo -n timeout --signal=TERM --kill-after=5s 120s /var/tmp/p11scope-slice1b2/bundle/slice1b2-runner gate-a"
        ));
    }

    #[test]
    fn gate_b_timeout_is_quiesced_not_exported_and_cleaned_up() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-b-timeout-outcome");
        let bundle = temp.path().join("bundle");
        let run = temp.path().join("run");
        let export = temp.path().join("export");
        fake_gate_bundle(&bundle);
        let body = concat!(
            "source \"$1\"; shift; ",
            "validate_execution_bundle() { return 0; }; ",
            "private_start_lane() { mkdir -m 0700 \"$2\"; PRIVATE_RUN_DIR=$2; PRIVATE_KNOWN_HOSTS=/known; PRIVATE_PORT=2222; PRIVATE_LANE_OWNED=1; return 0; }; ",
            "strict_ssh() { return 0; }; cmp() { return 0; }; ",
            "scp_argv() { printf '%s\\0' /bin/true; }; ",
            "gate_ssh() { printf '%s\\n' \"$*\" >\"$PRIVATE_RUN_DIR/remote-command.txt\"; return 124; }; ",
            "quiesce_gate_runner() { : >\"$PRIVATE_RUN_DIR/quiesced\"; return 0; }; ",
            "export_evidence() { : >\"$PRIVATE_RUN_DIR/export-called\"; return 0; }; ",
            "validate_local_export() { : >\"$PRIVATE_RUN_DIR/validate-called\"; return 0; }; ",
            "private_finish_lane() { : >\"$PRIVATE_RUN_DIR/cleaned\"; return 0; }; ",
            "set +e; gate_b_lane jammy \"$1\" \"$2\" \"$3\"; rc=$?; set +e; printf 'rc=%s\\n' \"$rc\""
        );
        let output = {
            let _serial = VM_TEST_LOCK.lock().unwrap();
            shell_output(
                script,
                body,
                &[bundle.as_os_str(), run.as_os_str(), export.as_os_str()],
            )
        };
        assert!(output.status.success());
        assert_eq!(output.stdout, b"rc=2\n");
        assert_eq!(std::fs::read(run.join("gate-b.status")).unwrap(), b"124\n");
        assert_eq!(
            std::fs::read(run.join("gate-b.outcome")).unwrap(),
            b"TIMEOUT\n"
        );
        assert!(run.join("quiesced").exists());
        assert!(run.join("cleaned").exists());
        assert!(!run.join("export-called").exists());
        assert!(!run.join("validate-called").exists());
        assert!(!export.exists());
        let remote = std::fs::read_to_string(run.join("remote-command.txt")).unwrap();
        assert!(remote.contains(
            "sudo -n timeout --signal=TERM --kill-after=5s 120s /var/tmp/p11scope-slice1b2/bundle/slice1b2-runner gate-b --runs 20"
        ));
    }

    #[test]
    fn lane_cleanup_runs_when_start_fails_after_daemon_pidfile() {
        let _serial = VM_TEST_LOCK.lock().unwrap();
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("post-daemon-cleanup");
        let bundle = temp.path().join("bundle");
        let run = temp.path().join("run");
        let export = temp.path().join("export");
        fake_gate_bundle(&bundle);
        let body = concat!(
            "source \"$1\"; shift; ",
            "validate_execution_bundle() { return 0; }; ",
            "private_start_lane() { mkdir -m 0700 \"$2\"; PRIVATE_RUN_DIR=$2; PRIVATE_LANE_OWNED=1; PRIVATE_QEMU_PID=; printf '12345\\n' >\"$2/qemu.pid\"; return 64; }; ",
            "private_finish_lane() { : >\"$PRIVATE_RUN_DIR/cleaned\"; return 0; }; ",
            "set +e; gate_a_lane jammy \"$1\" \"$2\" \"$3\"; rc=$?; set +e; printf 'rc=%s\\n' \"$rc\""
        );
        let output = shell_output(
            script,
            body,
            &[bundle.as_os_str(), run.as_os_str(), export.as_os_str()],
        );
        assert!(output.status.success());
        assert_eq!(output.stdout, b"rc=64\n");
        assert!(run.join("cleaned").exists());
    }

    #[test]
    fn cleanup_pid_recovery_requires_exact_qemu_runtime_process() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("qemu-pid-recovery");
        let run = temp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        let runtime = run.join("runtime.qcow2");
        std::fs::write(&runtime, b"runtime").unwrap();
        let mut qemu = Command::new("bash")
            .arg("-c")
            .arg(concat!(
                "exec -a qemu-system-x86_64 /bin/sh -c ",
                "'while :; do /bin/sleep 1; done' ",
                "\"file=$1,if=virtio,format=qcow2\" ",
                "user,id=n1,hostfwd=tcp:127.0.0.1:2222-:22 ",
                "\"file:$2/runtime.serial.log\" \"$2/qemu.pid\""
            ))
            .arg("bash")
            .arg(&runtime)
            .arg(&run)
            .spawn()
            .unwrap();
        std::fs::write(run.join("qemu.pid"), format!("{}\n", qemu.id())).unwrap();
        let mut recovered = None;
        for _ in 0..50 {
            let output = Command::new("bash")
                .arg("-c")
                .arg(concat!(
                    "source \"$1\"; PRIVATE_RUN_DIR=$2; PRIVATE_PORT=2222; PRIVATE_QEMU_PID=; ",
                    "private_recover_qemu_pid && printf '%s\\n' \"$PRIVATE_QEMU_PID\""
                ))
                .arg("bash")
                .arg(script)
                .arg(&run)
                .output()
                .unwrap();
            if output.status.success() {
                recovered = Some(output.stdout);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = qemu.kill();
        let _ = qemu.wait();
        assert_eq!(recovered.unwrap(), format!("{}\n", qemu.id()).as_bytes());

        std::fs::write(run.join("qemu.pid"), format!("{}\n", std::process::id())).unwrap();
        let unrelated = Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; PRIVATE_RUN_DIR=$2; PRIVATE_PORT=2222; PRIVATE_QEMU_PID=; private_recover_qemu_pid")
            .arg("bash")
            .arg(script)
            .arg(&run)
            .status()
            .unwrap();
        assert!(!unrelated.success());
    }

    #[test]
    fn cleanup_never_waits_or_signals_a_failed_qemu_identity() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("qemu-pid-refusal");
        let run = temp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        let events = temp.path().join("events");
        let body = concat!(
            "source \"$1\"; PRIVATE_LANE_OWNED=1; PRIVATE_RUN_DIR=$2; ",
            "PRIVATE_QEMU_PID=$$; PRIVATE_KNOWN_HOSTS=/known; PRIVATE_PORT=2222; ",
            "EVENT_LOG=$3; sleep() { printf 'sleep\\n' >>\"$EVENT_LOG\"; }; ",
            "kill() { printf 'kill\\n' >>\"$EVENT_LOG\"; }; ",
            "strict_ssh() { return 255; }; set +e; private_finish_lane; exit 0"
        );
        let output = shell_output(script, body, &[run.as_os_str(), events.as_os_str()]);
        assert!(output.status.success());
        assert!(!events.exists(), "invalid PID was waited or signaled");
    }

    #[test]
    fn cleanup_revalidates_qemu_identity_before_forced_kill() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("qemu-pid-revalidate");
        let run = temp.path().join("run");
        std::fs::create_dir(&run).unwrap();
        let events = temp.path().join("events");
        let body = concat!(
            "source \"$1\"; PRIVATE_LANE_OWNED=1; PRIVATE_RUN_DIR=$2; PRIVATE_QEMU_PID=$$; ",
            "PRIVATE_KNOWN_HOSTS=/known; PRIVATE_PORT=2222; recoveries=0; ",
            "private_recover_qemu_pid() { recoveries=$((recoveries + 1)); ",
            "if (( recoveries == 1 )); then return 0; fi; PRIVATE_QEMU_PID=; return 64; }; ",
            "strict_ssh() { return 255; }; sleep() { :; }; ",
            "EVENT_LOG=$3; kill() { printf 'kill\\n' >>\"$EVENT_LOG\"; }; set +e; private_finish_lane; ",
            "printf '%s\\n' \"$recoveries\" >\"$3.recoveries\"; exit 0"
        );
        let output = shell_output(script, body, &[run.as_os_str(), events.as_os_str()]);
        assert!(output.status.success());
        assert!(!events.exists(), "stale PID was forcibly signaled");
        assert!(
            std::fs::read_to_string(events.with_extension("recoveries"))
                .unwrap()
                .trim()
                .parse::<u32>()
                .unwrap()
                >= 2
        );
    }

    #[test]
    fn cleanup_defers_int_and_term_until_finish_completes() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        for (name, signal) in [("INT", libc::SIGINT), ("TERM", libc::SIGTERM)] {
            let temp = TestDir::new("cleanup-signal");
            let started = temp.path().join("started");
            let release = temp.path().join("release");
            let finished = temp.path().join("finished");
            let body = concat!(
                "source \"$1\"; PRIVATE_LANE_OWNED=1; PRIVATE_LANE_CLEANUP=idle; ",
                "PRIVATE_LANE_INTERRUPTED=0; PRIVATE_FINISH_RC=0; private_arm_lane_traps; ",
                "STARTED=$2; RELEASE=$3; FINISHED=$4; private_finish_lane() { ",
                ": >\"$STARTED\"; while [[ ! -e $RELEASE ]]; do /bin/sleep 0.01; done; ",
                ": >\"$FINISHED\"; return 0; }; ",
                "set +e; private_cleanup_lane; rc=$?; private_disarm_lane_traps; ",
                "printf 'rc=%s\\n' \"$rc\""
            );
            let child = Command::new("bash")
                .arg("-c")
                .arg(body)
                .arg("bash")
                .arg(script)
                .args([&started, &release, &finished])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            for _ in 0..200 {
                if started.exists() {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            assert!(started.exists(), "{name} cleanup did not start");
            assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
            thread::sleep(Duration::from_millis(25));
            std::fs::write(&release, b"release").unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{name}");
            assert_eq!(output.stdout, b"rc=64\n", "{name}");
            assert!(finished.exists(), "{name} abandoned cleanup");
        }
    }

    #[test]
    fn exit_trap_cleans_up_after_post_copy_host_failure() {
        let _serial = VM_TEST_LOCK.lock().unwrap();
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("post-copy-cleanup");
        let bundle = temp.path().join("bundle");
        let run = temp.path().join("run");
        let export = temp.path().join("export");
        fake_gate_bundle(&bundle);
        let body = concat!(
            "set -e; source \"$1\"; shift; ",
            "validate_execution_bundle() { return 0; }; ",
            "private_start_lane() { mkdir -m 0700 \"$2\"; PRIVATE_RUN_DIR=$2; PRIVATE_KNOWN_HOSTS=/known; PRIVATE_PORT=2222; PRIVATE_LANE_OWNED=1; return 0; }; ",
            "strict_ssh() { return 0; }; scp_argv() { printf '%s\\0' /bin/true; }; ",
            "sha256sum() { return 1; }; ",
            "private_finish_lane() { : >\"$PRIVATE_RUN_DIR/cleaned\"; return 0; }; ",
            "gate_a_lane jammy \"$1\" \"$2\" \"$3\""
        );
        let output = shell_output(
            script,
            body,
            &[bundle.as_os_str(), run.as_os_str(), export.as_os_str()],
        );
        assert!(!output.status.success());
        assert!(run.join("cleaned").exists());
    }

    #[test]
    fn provisioning_exit_trap_cleans_up_after_post_copy_failure() {
        let _serial = VM_TEST_LOCK.lock().unwrap();
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("provision-post-copy-cleanup");
        let archive = temp.path().join("source.tar");
        let manifest = temp.path().join("manifest.json");
        let run = temp.path().join("run");
        let build = temp.path().join("build");
        std::fs::write(&archive, b"archive").unwrap();
        std::fs::write(&manifest, b"manifest").unwrap();
        let body = concat!(
            "set -e; source \"$1\"; shift; ",
            "validate_source_inputs() { return 0; }; ",
            "sha256sum() { printf '4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10  fake\\n'; }; ",
            "private_start_lane() { mkdir -m 0700 \"$2\"; PRIVATE_RUN_DIR=$2; PRIVATE_KNOWN_HOSTS=/known; PRIVATE_PORT=2222; PRIVATE_LANE_OWNED=1; return 0; }; ",
            "strict_ssh() { return 0; }; strict_ssh_long() { return 0; }; ",
            "scp_argv() { printf '%s\\0' /bin/true; }; ",
            "chmod() { return 1; }; ",
            "private_finish_lane() { : >\"$PRIVATE_RUN_DIR/cleaned\"; return 0; }; ",
            "provision_jammy \"$1\" \"$2\" expected \"$3\" \"$4\""
        );
        let output = shell_output(
            script,
            body,
            &[
                archive.as_os_str(),
                manifest.as_os_str(),
                run.as_os_str(),
                build.as_os_str(),
            ],
        );
        assert!(!output.status.success());
        assert!(run.join("cleaned").exists());
    }

    #[test]
    fn vm_cleanup_cannot_launder_an_intermediate_postcheck_failure() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("vm-cleanup-failure");
        let retained = temp.path().join("retained.qcow2");
        let official = temp.path().join("official.qcow2");
        std::fs::write(&retained, b"retained").unwrap();
        std::fs::write(&official, b"official").unwrap();
        std::fs::set_permissions(&retained, std::fs::Permissions::from_mode(0o444)).unwrap();
        let status = Command::new("bash")
            .arg("-c")
            .arg(concat!(
                "source \"$1\"; ",
                "PRIVATE_QEMU_PID=; PRIVATE_RUN_DIR=$2; PRIVATE_RETAINED=$3; ",
                "PRIVATE_OFFICIAL=$4; private_finish_lane"
            ))
            .arg("bash")
            .arg(script)
            .arg(temp.path())
            .arg(&retained)
            .arg(&official)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!status.success());
    }

    fn shell_lines(script: &str, body: &str, args: &[&OsStr]) -> Vec<String> {
        let mut command = Command::new("bash");
        command.arg("-c").arg(body).arg("bash").arg(script);
        command.args(args);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn build_fixture_strict_mode_reaches_self_check() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("strict-fixture");
        let wrapper = temp.path().join("bin");
        std::fs::create_dir(&wrapper).unwrap();
        let real_objdump = String::from_utf8(
            Command::new("sh")
                .arg("-c")
                .arg("command -v objdump")
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let objdump = wrapper.join("objdump");
        std::fs::write(
            &objdump,
            format!(
                "#!/bin/sh\n{} \"$@\"\nawk 'BEGIN {{ for (i=0; i<262144; i++) print \"padding\" }}'\n",
                real_objdump.trim()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&objdump, std::fs::Permissions::from_mode(0o755)).unwrap();
        let output = Command::new(script)
            .arg("build-fixture")
            .arg(temp.path().join("fixture"))
            .env(
                "PATH",
                format!("{}:{}", wrapper.display(), std::env::var("PATH").unwrap()),
            )
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "strict build failed: status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"fixture-self-check: OK\n");
    }

    #[test]
    fn source_and_execution_bundles_refuse_reuse() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("bundle-reuse");
        let build = Command::new(script)
            .arg("build-bpf")
            .arg(temp.path())
            .output()
            .unwrap();
        assert_eq!(build.status.code(), Some(64));
        assert_eq!(build.stderr, b"build-bpf requires a new output directory\n");
        let freeze = Command::new(script)
            .arg("freeze-execution")
            .arg(temp.path())
            .arg(temp.path())
            .arg(temp.path())
            .output()
            .unwrap();
        assert_eq!(freeze.status.code(), Some(64));
        assert_eq!(
            freeze.stderr,
            b"freeze-execution requires a new bundle directory\n"
        );
    }

    #[test]
    fn gate_a_fixture_exposes_five_single_release_cases() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("gate-a-fixture");
        let fixture = temp.path().join("fixture");
        let build = Command::new(script)
            .arg("build-fixture")
            .arg(&fixture)
            .output()
            .unwrap();
        assert!(
            build.status.success(),
            "fixture build failed: {}",
            String::from_utf8_lossy(&build.stderr)
        );

        for case in [
            "FULL_104",
            "GUARD_AFTER_7",
            "UNREADABLE_TABLE",
            "UNREADABLE_PP",
            "INTERFACE",
        ] {
            let mut child = Command::new(&fixture)
                .arg("--gate-a")
                .arg(case)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            thread::sleep(Duration::from_millis(25));
            assert!(
                child.try_wait().unwrap().is_none(),
                "{case} exited before its release byte"
            );
            child.stdin.take().unwrap().write_all(b"X").unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{case} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(
                output.stdout,
                format!("fixture-gate-a: OK case={case}\n").as_bytes()
            );
        }
    }

    #[test]
    fn ebpf_source_freezes_six_program_four_map_signal_contract() {
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ebpf/src/main.rs"))
                .unwrap();
        for program in [
            "function_list_entry",
            "function_list_return",
            "interface_list_entry",
            "interface_list_return",
            "signal_return",
            "late_hit",
        ] {
            assert_eq!(source.matches(&format!("pub fn {program}(")).count(), 1);
        }
        for map in ["EVENTS", "DISCOVERY", "START", "COUNTERS"] {
            assert_eq!(source.matches(&format!("static {map}:")).count(), 1);
        }
        assert_eq!(
            source.matches("#[uprobe]\npub fn ").count()
                + source.matches("#[uretprobe]\npub fn ").count(),
            6,
            "an extra public BPF program must be rejected"
        );
        assert_eq!(
            source.matches("#[map]\nstatic ").count(),
            4,
            "an extra BPF map must be rejected"
        );
        assert!(source.contains("RingBuf::with_byte_size(262_144, 0)"));
        assert!(source.contains("RingBuf::with_byte_size(65_536, 0)"));
        assert!(source.contains("HashMap::with_max_entries(64, 0)"));
        assert!(source.contains("Array::with_max_entries(5, 0)"));
        assert!(source.contains("while pointer_index < 104"));
        assert!(source.contains("while interface_index < 16"));
        assert!(source.contains("#[inline(never)]\nfn emit_interface("));
        assert!(source.contains("if !emit_interface("));
        let invocation = source
            .split("zero_words!(words;")
            .nth(1)
            .expect("zero_words! invocation")
            .split(')')
            .next()
            .unwrap();
        let mut indexes: Vec<usize> = invocation
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().unwrap())
            .collect();
        let raw_len = indexes.len();
        indexes.sort_unstable();
        indexes.dedup();
        assert_eq!(raw_len, 112, "each index exactly once");
        assert_eq!(
            indexes,
            (0..112).collect::<Vec<_>>(),
            "complete index set 0..=111"
        );
        assert!(source.contains("core::ptr::write_volatile($words.add($k), 0u64)"));
        assert!(!source.contains("while word < 112"));
        assert!(source.contains("DISCOVERY.reserve::<SignalRecord>(0)"));
        assert!(source.contains("increment_counter(LATE_HITS)"));
        assert!(source.contains("#![feature(core_intrinsics)]"));
        assert!(source.contains("#![allow(internal_features)]"));
        let signal = source.find("pub fn signal_return(").unwrap();
        let signal_end = source[signal..].find("pub fn late_hit(").unwrap() + signal;
        let signal_source = &source[signal..signal_end];
        let reserve = signal_source
            .find("DISCOVERY.reserve::<SignalRecord>(0)")
            .unwrap();
        let zeroing = signal_source
            .find("core::ptr::write_volatile(words.add(0)")
            .unwrap();
        let cas = signal_source
            .find("core::intrinsics::atomic_cxchg")
            .unwrap();
        let send = signal_source.find("helpers::bpf_send_signal(19)").unwrap();
        let submit = signal_source.find("entry.submit(0);").unwrap();
        assert_eq!(
            signal_source
                .matches("helpers::bpf_send_signal(19)")
                .count(),
            1,
            "the signal helper must appear exactly once in signal_return"
        );
        assert_eq!(
            signal_source
                .matches("core::ptr::write_volatile(words.add(")
                .count(),
            4,
            "four flat zero words initialize the reserved entry"
        );
        assert!(
            reserve < zeroing && zeroing < cas && cas < send && send < submit,
            "order must be reserve -> zero words -> CAS -> single signal -> submit"
        );
        assert!(signal_source.contains("pause_owner_key()"));
        assert!(signal_source.contains("PAUSE_ARMED"));
        assert!(signal_source.contains("PAUSE_REQUESTED"));
        assert!(signal_source.contains("COALESCED_NO_HELPER"));
        assert!(
            source.contains("START.insert(&key, &state, aya_ebpf::bindings::BPF_NOEXIST as u64)")
        );
        assert!(!source.contains("BPF_ANY"));
        assert_eq!(
            source
                .matches("// SAFETY: reserve owns one writable 896-byte entry;")
                .count(),
            1
        );
        let discovery_unsafe_start = source.find("unsafe {\n        zero_words!(words;").unwrap();
        let discovery_unsafe_end =
            source[discovery_unsafe_start..].find("\n    }").unwrap() + discovery_unsafe_start;
        let discovery_submit = source.find("entry.submit(0);").unwrap();
        assert!(
            discovery_submit > discovery_unsafe_end,
            "submit must remain outside raw initialization"
        );

        let host = std::fs::read_to_string(file!()).unwrap();
        let declaration = ["const GATE_A_", "PROGRAMS: [&str; 4] = ["].concat();
        let load_writer = ["write_json_line(&mut verifier_", "results"].concat();
        let child_loop = ["for (number, case) in ", "["].concat();
        let declaration = host.find(&declaration).unwrap();
        let load_loop = host.find("for program_name in GATE_A_PROGRAMS").unwrap();
        let load_result = host[load_loop..].find(&load_writer).unwrap() + load_loop;
        let child_loop = host[load_result..].find(&child_loop).unwrap() + load_result;
        assert!(declaration < load_loop && load_loop < load_result && load_result < child_loop);
        let gate_b_declaration = host.find("const GATE_B_PROGRAMS: [&str; 2]").unwrap();
        let gate_b_load_loop = host.find("for program_name in GATE_B_PROGRAMS").unwrap();
        let gate_b_load_result =
            host[gate_b_load_loop..].find(&load_writer).unwrap() + gate_b_load_loop;
        let gate_b_child_loop = host[gate_b_load_result..]
            .find("for run in 1..=20")
            .unwrap()
            + gate_b_load_result;
        assert!(
            gate_b_declaration < gate_b_load_loop
                && gate_b_load_loop < gate_b_load_result
                && gate_b_load_result < gate_b_child_loop
        );
        assert_eq!(
            host.matches(&["write_json_line(&mut verifier_", "results"].concat())
                .count(),
            2,
            "each gate's pre-child load loop must be its only verifier-result writer"
        );
        let case_start = host.find("fn run_gate_b_case(").unwrap();
        let gate_start = host[case_start..].find("fn run_gate_b(").unwrap() + case_start;
        let case_source = &host[case_start..gate_start];
        assert!(case_source.contains("if !late_links.is_empty()"));
        assert!(case_source.contains("detach_program(ebpf, \"late_hit\", link)"));
        assert!(case_source.contains("if !signal_links.is_empty()"));
        assert!(case_source.contains("detach_program(ebpf, \"signal_return\", link)"));
        assert!(case_source.contains("disarm_for_cleanup(start)"));
        let self_check = host[gate_start..].find("fn self_check(").unwrap() + gate_start;
        let gate_source = &host[gate_start..self_check];
        assert!(gate_source.contains("if runtime_failure_reason.is_some() || !pass"));
        assert!(gate_source.contains("break;"));
    }

    #[test]
    fn runtime_symbol_address_uses_exact_fixture_mapping() {
        let maps = concat!(
            "1000-2000 r-xp 00000000 08:01 41 /private/wrong\n",
            "4000-5000 r-xp 00001000 08:02 42 /private/fixture\n",
        );
        assert_eq!(
            runtime_symbol_address_from_maps(maps, "08:02", 42, 0x1a20),
            Ok(0x4a20)
        );
        assert!(runtime_symbol_address_from_maps(maps, "08:02", 43, 0x1a20).is_err());
    }

    #[test]
    fn ssh_argv_exclusively_pins_approved_ed25519_host() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("ssh");
        let known = temp.path().join("known_hosts");
        let lines = shell_lines(
            script,
            "source \"$1\"; shift; ssh_argv \"$1\" 2222 | tr '\\0' '\\n'",
            &[known.as_os_str()],
        );
        assert_eq!(
            lines,
            vec![
                "ssh",
                "-vv",
                "-i",
                "/tmp/p11scope-slice1b2-vms/id_ed25519",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                &format!("UserKnownHostsFile={}", known.display()),
                "-o",
                "GlobalKnownHostsFile=/dev/null",
                "-o",
                "HostKeyAlgorithms=ssh-ed25519",
                "-p",
                "2222",
            ]
        );
        let lanes = shell_lines(
            script,
            "source \"$1\"; lane_config jammy; lane_config noble",
            &[],
        );
        assert_eq!(
            lanes[0],
            "/tmp/p11scope-slice1b2-vms/jammy/overlay.qcow2|/tmp/p11scope-slice1b2-vms/jammy/serial.log|2222|SHA256:GD2UX29+dul1JSEIm9k1XjotD9Exr1j9vrTgG92wQEY"
        );
        assert_eq!(
            lanes[1],
            "/tmp/p11scope-slice1b2-vms/noble/overlay.qcow2|/tmp/p11scope-slice1b2-vms/noble/serial.log|2223|SHA256:lJncGXZAZRDW+QEdhkWpCyhco+DDPxnYB8J6IEha1aQ"
        );
    }

    #[test]
    fn qemu_preflight_requires_exact_retained_tool_versions() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("qemu-preflight");
        let system = temp.path().join("qemu-system-x86_64");
        let image = temp.path().join("qemu-img");
        std::fs::write(
            &system,
            "#!/bin/sh\nprintf '%s\\n' 'QEMU emulator version 8.2.2 (pinned)'\n",
        )
        .unwrap();
        std::fs::write(
            &image,
            "#!/bin/sh\nprintf '%s\\n' 'qemu-img version 8.2.2 (pinned)'\n",
        )
        .unwrap();
        for path in [&system, &image] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let path = format!("{}:/usr/bin:/bin", temp.path().display());
        let accepted = Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; qemu_preflight")
            .arg("bash")
            .arg(script)
            .env("PATH", &path)
            .status()
            .unwrap();
        assert!(accepted.success());

        std::fs::write(
            &image,
            "#!/bin/sh\nprintf '%s\\n' 'qemu-img version 9.0.0 (wrong)'\n",
        )
        .unwrap();
        let rejected = Command::new("bash")
            .arg("-c")
            .arg("source \"$1\"; qemu_preflight")
            .arg("bash")
            .arg(script)
            .env("PATH", path)
            .status()
            .unwrap();
        assert!(!rejected.success());
    }

    #[test]
    fn provisioning_rejects_overrides_and_requires_new_private_tool_homes() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("provision");
        let rustup = temp.path().join("rustup");
        let cargo = temp.path().join("cargo");
        let body = "source \"$1\"; provision_preflight \"$2\" \"$3\"";

        let disabled = Command::new(script)
            .arg("provision-jammy")
            .env("RUSTFLAGS", "refuse-before-network")
            .output()
            .unwrap();
        assert_eq!(disabled.status.code(), Some(64));
        assert_eq!(disabled.stderr, b"provision-jammy arguments\n");

        let rejected = Command::new("bash")
            .arg("-c")
            .arg(body)
            .arg("bash")
            .arg(script)
            .arg(&rustup)
            .arg(&cargo)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("RUSTFLAGS", "-C target-cpu=native")
            .status()
            .unwrap();
        assert!(!rejected.success());
        assert!(!rustup.exists() && !cargo.exists());

        let accepted = Command::new("bash")
            .arg("-c")
            .arg(body)
            .arg("bash")
            .arg(script)
            .arg(&rustup)
            .arg(&cargo)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()
            .unwrap();
        assert!(accepted.success());
        for home in [&rustup, &cargo] {
            let metadata = std::fs::metadata(home).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o700);
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert!(std::fs::read_dir(home).unwrap().next().is_none());
        }

        let reused = Command::new("bash")
            .arg("-c")
            .arg(body)
            .arg("bash")
            .arg(script)
            .arg(&rustup)
            .arg(&cargo)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status()
            .unwrap();
        assert!(!reused.success());
    }

    #[test]
    fn evidence_export_requires_fixed_private_inventory() {
        for (gate, varying) in [
            (EvidenceGate::A, "gate-a-cases.jsonl"),
            (EvidenceGate::B, "signal-timing.jsonl"),
        ] {
            let temp = TestDir::new("export");
            let export = temp.path().join("evidence");
            std::fs::create_dir(&export).unwrap();
            std::fs::set_permissions(&export, std::fs::Permissions::from_mode(0o700)).unwrap();
            for name in [
                "environment.txt",
                "manifest-digests.txt",
                "verifier.log",
                "verifier-results.jsonl",
                varying,
                "runner-status.txt",
            ] {
                let path = export.join(name);
                std::fs::write(&path, b"bounded\n").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            assert!(validate_evidence_export(&export, gate).is_ok());
            let extra = export.join("raw-pointers.bin");
            std::fs::write(&extra, b"forbidden").unwrap();
            std::fs::set_permissions(&extra, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(validate_evidence_export(&export, gate).is_err());
            std::fs::remove_file(extra).unwrap();
            std::fs::set_permissions(
                export.join("verifier.log"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(validate_evidence_export(&export, gate).is_err());
        }
    }
}
