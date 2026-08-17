#[path = "../common.rs"]
pub mod common;

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

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
    (!facts.may_be_stopped || (facts.resume_attempts == 1 && facts.resume_via_original_pidfd))
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
    let path = Path::new(value);
    let mut components = path.components();
    !path.is_absolute()
        && matches!(components.next(), Some(std::path::Component::Normal(name)) if name == "source")
        && components.clone().next().is_some()
        && components.all(|component| matches!(component, std::path::Component::Normal(_)))
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
        && !facts.signal_runs.is_empty()
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

fn main() {}

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
            signal_runs: vec![valid_signal()],
        };
        assert!(compare_oracles(&valid));

        for case_index in 0..valid.gate_a_cases.len() {
            for mutate in 0..9 {
                let mut changed = valid.clone();
                let case = &mut changed.gate_a_cases[case_index];
                match mutate {
                    0 => case.entry_attach_attempts += 1,
                    1 => case.entry_attach_accepted = false,
                    2 => case.return_attach_attempts += 1,
                    3 => case.return_attach_accepted = false,
                    4 => case.entry_link_detached = false,
                    5 => case.return_link_detached = false,
                    6 => case.start_empty = false,
                    7 => case.records[0].all_usable_pointers_nonzero = false,
                    8 => case.records[0].all_usable_pointers_equal_fixture = false,
                    _ => unreachable!(),
                }
                assert!(
                    !compare_oracles(&changed),
                    "accepted case mutation {case_index}/{mutate}"
                );
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

        for field in 0..18 {
            let mut changed = valid.clone();
            let signal = &mut changed.signal_runs[0];
            match field {
                0 => signal.stop_request_accepted = false,
                1 => signal.stopped_snapshot_1_exact_expected_task_set = false,
                2 => signal.stopped_snapshot_1_all_tasks_stopped = false,
                3 => signal.stopped_snapshot_2_exact_expected_task_set = false,
                4 => signal.stopped_snapshot_2_all_tasks_stopped = false,
                5 => signal.pre_stop_marker_observed = true,
                6 => signal.post_attach_exact_expected_task_set = false,
                7 => signal.post_attach_all_tasks_stopped = false,
                8 => signal.post_attach_marker_observed = true,
                9 => signal.signal_attach_attempts += 1,
                10 => signal.signal_attach_accepted = false,
                11 => signal.late_attach_attempts += 1,
                12 => signal.late_attach_accepted = false,
                13 => signal.signal_link_detached = false,
                14 => signal.late_link_detached = false,
                15 => signal.resume_via_original_pidfd = false,
                16 => signal.post_resume_marker_observed = false,
                17 => signal.reaped = false,
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
        let source =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh")).unwrap();
        assert!(source.contains("/tmp/p11scope-slice1b2-spike-vm.lock"));
        assert!(source.contains("flock -n"));
        assert!(source.contains("available >= 2147483648"));
        assert_eq!(
            source.matches("require_free_bytes before-overlay").count(),
            1
        );
        assert_eq!(source.matches("require_free_bytes before-boot").count(), 1);
        assert_eq!(
            source
                .matches("require_free_bytes after-shutdown-export")
                .count(),
            1
        );
        let overlay = source.find("require_free_bytes before-overlay").unwrap();
        let boot = source.find("require_free_bytes before-boot").unwrap();
        let final_gate = source
            .find("require_free_bytes after-shutdown-export")
            .unwrap();
        assert!(overlay < boot && boot < final_gate);
        assert!(source.contains("-no-reboot"));
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
    fn provisioning_rejects_overrides_and_requires_new_private_tool_homes() {
        let script = concat!(env!("CARGO_MANIFEST_DIR"), "/run.sh");
        let temp = TestDir::new("provision");
        let rustup = temp.path().join("rustup");
        let cargo = temp.path().join("cargo");
        let body = "source \"$1\"; provision_preflight \"$2\" \"$3\"";

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
