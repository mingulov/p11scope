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

#[derive(Clone, Debug, PartialEq)]
pub struct SignalTimingFacts {
    pub hook_ts_ns: u64,
    pub send_signal_rc: i64,
    pub stop_request_accepted: bool,
    pub expected_task_count: u32,
    pub stopped_snapshot_1_count: u32,
    pub stopped_snapshot_2_count: u32,
    pub stopped_snapshot_1_exact_expected_task_set: bool,
    pub stopped_snapshot_1_all_tasks_stopped: bool,
    pub stopped_snapshot_2_exact_expected_task_set: bool,
    pub stopped_snapshot_2_all_tasks_stopped: bool,
    pub pre_stop_marker_observed: bool,
    pub post_attach_task_count: u32,
    pub post_attach_exact_expected_task_set: bool,
    pub post_attach_all_tasks_stopped: bool,
    pub post_attach_marker_observed: bool,
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
        && facts.stopped_snapshot_1_count == facts.expected_task_count
        && facts.stopped_snapshot_2_count == facts.expected_task_count
        && facts.stopped_snapshot_1_exact_expected_task_set
        && facts.stopped_snapshot_1_all_tasks_stopped
        && facts.stopped_snapshot_2_exact_expected_task_set
        && facts.stopped_snapshot_2_all_tasks_stopped
        && !facts.pre_stop_marker_observed
        && facts.post_attach_task_count == facts.expected_task_count
        && facts.post_attach_exact_expected_task_set
        && facts.post_attach_all_tasks_stopped
        && !facts.post_attach_marker_observed
        && facts.signal_attach_attempts == 1
        && facts.signal_attach_accepted
        && facts.late_attach_attempts == 1
        && facts.late_attach_accepted
        && facts.signal_link_detached
        && facts.late_link_detached
        && facts.attach_gap_ms.is_finite()
        && (facts.attach_gap_ms - expected_gap_ms).abs() <= f64::EPSILON
        && facts.pidfd_resume_attempts == 1
        && facts.pidfd_resume_rc == 0
        && facts.resume_via_original_pidfd
        && facts.post_resume_marker_observed
        && facts.late_hits == 1
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
        pidfd_send_signal(self.original_pidfd.as_raw_fd(), libc::SIGCONT)
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
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
        if self.reaped {
            return;
        }
        if self.may_be_stopped && !self.resume_attempted {
            self.resume_attempted = true;
            let _ = pidfd_send_signal(self.original_pidfd.as_raw_fd(), libc::SIGCONT);
        }
        let _ = pidfd_send_signal(self.original_pidfd.as_raw_fd(), libc::SIGKILL);
        self.reaped = self.child.wait().is_ok();
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
        value.insert("gate".into(), "A".into());
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
) -> Result<GateACaseFacts, &'static str> {
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
    if !raw_records(ring)?.is_empty() {
        return Err("record surplus before case");
    }
    let before = read_counters(counters)?;
    let mut command = Command::new(fixture);
    command
        .arg("--gate-a")
        .arg(case_name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = spawn_pinned_child(&mut command).map_err(|_| "gated child")?;
    let expected_pointer = runtime_symbol_address(
        child.pid(),
        *offsets
            .get("spike_pointer_target")
            .ok_or("fixture offset")?,
        fixture_file,
    )?;
    let target_offset = *offsets.get(target_name).ok_or("fixture offset")?;
    let entry_link = attach_program(
        ebpf,
        entry_name,
        target_offset,
        fixture,
        child.pid(),
        u64::from(case_number),
    )?;
    let return_link = match attach_program(
        ebpf,
        return_name,
        target_offset,
        fixture,
        child.pid(),
        u64::from(case_number),
    ) {
        Ok(link) => link,
        Err(error) => {
            let _ = detach_program(ebpf, entry_name, entry_link);
            return Err(error);
        }
    };
    child.release().map_err(|_| "child release")?;
    let child_status = child.wait().map_err(|_| "child wait")?;
    let return_detached = detach_program(ebpf, return_name, return_link).is_ok();
    let entry_detached = detach_program(ebpf, entry_name, entry_link).is_ok();
    if !child_status.success() {
        return Err("fixture child status");
    }
    let records = raw_records(ring)?;
    if records.iter().enumerate().any(|(index, record)| {
        record.case_id != case_number
            || record.kind != expected_kind
            || (case == GateACaseId::Interfaces17 && usize::from(record.interface_index) != index)
    }) {
        return Err("record identity");
    }
    let after = read_counters(counters)?;
    let start_empty = start.keys().next().is_none();
    Ok(GateACaseFacts {
        case,
        entry_attach_attempts: 1,
        entry_attach_accepted: true,
        return_attach_attempts: 1,
        return_attach_accepted: true,
        entry_link_detached: entry_detached,
        return_link_detached: return_detached,
        records: records
            .iter()
            .map(|record| record_facts(record, expected_pointer))
            .collect(),
        counters_before: before,
        counters_after: after,
        start_empty,
    })
}

fn gate_a_case_json(
    metadata: &GateMetadata,
    facts: &GateACaseFacts,
    pass: bool,
) -> serde_json::Value {
    let mut value = metadata.record(pass, if pass { "none" } else { "oracle" });
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

    let programs = [
        "function_list_entry",
        "function_list_return",
        "interface_list_entry",
        "interface_list_return",
    ];
    let mut all_loaded = true;
    for program_name in programs {
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
                writeln!(verifier_log, "runtime_failure={error}")
                    .map_err(|_| "runtime failure write")?;
                writeln!(runner_status, "status=FAIL\nfailure_category=runtime")
                    .map_err(|_| "runner status write")?;
                return Ok(false);
            }
        };
        let pass = gate_a_case_pass(&facts);
        write_json_line(&mut cases_file, gate_a_case_json(&metadata, &facts, pass))?;
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

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("--self-check") if args.len() == 2 => self_check().map(|()| true),
        Some("gate-a") => parse_gate_a_args(&args[2..]).and_then(run_gate_a),
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

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

    fn valid_signal() -> SignalTimingFacts {
        SignalTimingFacts {
            hook_ts_ns: 1_000_000,
            send_signal_rc: 0,
            stop_request_accepted: true,
            expected_task_count: 2,
            stopped_snapshot_1_count: 2,
            stopped_snapshot_2_count: 2,
            stopped_snapshot_1_exact_expected_task_set: true,
            stopped_snapshot_1_all_tasks_stopped: true,
            stopped_snapshot_2_exact_expected_task_set: true,
            stopped_snapshot_2_all_tasks_stopped: true,
            pre_stop_marker_observed: false,
            post_attach_task_count: 2,
            post_attach_exact_expected_task_set: true,
            post_attach_all_tasks_stopped: true,
            post_attach_marker_observed: false,
            signal_attach_attempts: 1,
            signal_attach_accepted: true,
            late_attach_attempts: 1,
            late_attach_accepted: true,
            signal_link_detached: true,
            late_link_detached: true,
            last_attach_ts_ns: 2_000_000,
            attach_gap_ms: 1.0,
            pidfd_resume_attempts: 1,
            pidfd_resume_rc: 0,
            resume_via_original_pidfd: true,
            post_resume_marker_observed: true,
            late_hits: 1,
            child_exit: 0,
            reaped: true,
        }
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
    fn gate_a_verifier_execution_has_a_distinct_120_second_bound() {
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
        assert_eq!(output.stdout, b"120s\n");
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
    fn ebpf_source_freezes_four_program_verifier_contract() {
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/ebpf/src/main.rs"))
                .unwrap();
        for program in [
            "function_list_entry",
            "function_list_return",
            "interface_list_entry",
            "interface_list_return",
        ] {
            assert_eq!(source.matches(&format!("pub fn {program}(")).count(), 1);
        }
        for map in ["EVENTS", "DISCOVERY", "START", "COUNTERS"] {
            assert_eq!(source.matches(&format!("static {map}:")).count(), 1);
        }
        assert!(source.contains("RingBuf::with_byte_size(262_144, 0)"));
        assert!(source.contains("RingBuf::with_byte_size(65_536, 0)"));
        assert!(source.contains("HashMap::with_max_entries(64, 0)"));
        assert!(source.contains("Array::with_max_entries(5, 0)"));
        assert!(source.contains("while pointer_index < 104"));
        assert!(source.contains("while interface_index < 16"));
        assert!(source.contains("while word < 112"));
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
        let unsafe_start = source
            .find("unsafe {\n        let mut word = 0usize;")
            .unwrap();
        let unsafe_end = source[unsafe_start..].find("\n    }").unwrap() + unsafe_start;
        let submit = source.find("entry.submit(0);").unwrap();
        assert!(
            submit > unsafe_end,
            "submit must remain outside raw initialization"
        );
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
