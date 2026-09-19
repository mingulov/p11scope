//! SPDX-License-Identifier: GPL-3.0-or-later
//! The owned-child lifecycle and the capture loops the binary runs.
//!
//! There is exactly one profile loop and one trace loop here, shared by
//! `profile`, `trace`, and `run`: `capture` drives them against an external
//! `--pid`/`--cgroup` target, `run_owned` drives the same two loops against a
//! child this process forked, paused, and reaps. Only `run_owned`,
//! `OwnedRunOutcome`, and `capture` are re-exported from `src/lib.rs`; the
//! child, the pause coordinator, its clocks, maps, drains, guards and injected
//! actions stay crate-private.

use crate::attach::{CapturePolicy, Scope, Session};
use crate::cli::{self, CaptureArgs, Kind, RunArgs, ScopeArg};
use crate::discovery::attribution;
use crate::discovery::engine::Engine;
use crate::discovery::pause::{
    ArmResult, PauseCoordinator, PauseError, PauseStatus, SessionPauseIo,
};
use crate::output::AtomicFile;
use crate::process::{PidPin, ProcessView, ProcessViewId};
use crate::{metrics, process, render, scope, semantics, trace, uretprobe_hazard};
use anyhow::{Context as _, Result, anyhow};
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::io::{Seek as _, SeekFrom, Write};
use std::num::NonZeroU64;
use std::ops::ControlFlow;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
mod root_fence_runtime;

const TERM_GRACE: Duration = Duration::from_secs(5);
const EXEC_HANDOFF_TIMEOUT: Duration = Duration::from_secs(5);
const WAIT_SLICE: Duration = Duration::from_millis(10);
const FINAL_KILL_GRACE: Duration = Duration::from_secs(5);
static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChildOutcome {
    Exited(i32),
    TimedOutRunning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ForwardAction {
    Forwarded,
    Escalated,
}

#[derive(Debug)]
pub(crate) struct ExecFailure {
    pub(crate) errno: i32,
    pub(crate) exit_code: i32,
}

impl std::fmt::Display for ExecFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "exec failed with errno {} and exit status {}",
            self.errno, self.exit_code
        )
    }
}

impl std::error::Error for ExecFailure {}

#[derive(Debug)]
pub(crate) enum ExecHandoffError {
    Exec(ExecFailure),
    Cancelled(i32),
    Deadline,
    Io {
        phase: &'static str,
        source: io::Error,
    },
}

impl std::fmt::Display for ExecHandoffError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exec(failure) => failure.fmt(formatter),
            Self::Cancelled(signal) => {
                write!(formatter, "exec handoff cancelled by signal {signal}")
            }
            Self::Deadline => formatter.write_str("exec handoff deadline expired"),
            Self::Io { phase, source } => write!(formatter, "exec handoff {phase}: {source}"),
        }
    }
}

impl std::error::Error for ExecHandoffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Exec(failure) => Some(failure),
            Self::Io { source, .. } => Some(source),
            Self::Cancelled(_) | Self::Deadline => None,
        }
    }
}

#[derive(Debug)]
enum ExecDrain {
    Pending,
    EmptyEof,
    Errno(i32),
}

fn drain_exec_with(
    bytes: &mut [u8; std::mem::size_of::<i32>()],
    used: &mut usize,
    mut read: impl FnMut(&mut [u8]) -> io::Result<usize>,
) -> Result<ExecDrain, ExecHandoffError> {
    loop {
        match read(&mut bytes[*used..]) {
            Ok(0) if *used == 0 => return Ok(ExecDrain::EmptyEof),
            Ok(0) => {
                return Err(ExecHandoffError::Io {
                    phase: "exec protocol",
                    source: io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("short exec errno frame ({used}/4 bytes)"),
                    ),
                });
            }
            Ok(read) if read <= bytes.len() - *used => {
                *used += read;
                if *used == bytes.len() {
                    return Ok(ExecDrain::Errno(i32::from_ne_bytes(*bytes)));
                }
            }
            Ok(_) => {
                return Err(ExecHandoffError::Io {
                    phase: "exec read",
                    source: io::Error::other("exec reader returned more bytes than requested"),
                });
            }
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {
                return Ok(ExecDrain::Pending);
            }
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => {
                return Ok(ExecDrain::Pending);
            }
            Err(source) => {
                return Err(ExecHandoffError::Io {
                    phase: "exec read",
                    source,
                });
            }
        }
    }
}

fn write_release_with(
    deadline: Instant,
    mut cancelled: impl FnMut() -> Option<i32>,
    mut write: impl FnMut() -> io::Result<usize>,
) -> Result<(), ExecHandoffError> {
    loop {
        if let Some(signal) = cancelled() {
            return Err(ExecHandoffError::Cancelled(signal));
        }
        if Instant::now() >= deadline {
            return Err(ExecHandoffError::Deadline);
        }
        match write() {
            Ok(1) => return Ok(()),
            Ok(_) => {
                return Err(ExecHandoffError::Io {
                    phase: "release write",
                    source: io::Error::new(io::ErrorKind::WriteZero, "short release write"),
                });
            }
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(source) => {
                return Err(ExecHandoffError::Io {
                    phase: "release write",
                    source,
                });
            }
        }
    }
}

fn poll_handoff_with(
    deadline: Instant,
    mut cancelled: impl FnMut() -> Option<i32>,
    mut poll: impl FnMut(i32) -> io::Result<[i16; 2]>,
) -> Result<[i16; 2], ExecHandoffError> {
    loop {
        if let Some(signal) = cancelled() {
            return Err(ExecHandoffError::Cancelled(signal));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ExecHandoffError::Deadline);
        }
        let timeout = remaining.min(WAIT_SLICE);
        let timeout_ms = i32::try_from(timeout.as_millis().max(1)).unwrap_or(i32::MAX);
        match poll(timeout_ms) {
            Ok(revents) => return Ok(revents),
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(source) => {
                return Err(ExecHandoffError::Io {
                    phase: "poll",
                    source,
                });
            }
        }
    }
}

fn retry_reap_with(
    deadline: Option<Instant>,
    mut reap: impl FnMut() -> io::Result<Option<i32>>,
) -> io::Result<Option<i32>> {
    loop {
        match reap() {
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "reap retry deadline expired after EINTR",
                    ));
                }
            }
            result => return result,
        }
    }
}

fn exact_exit_after_error_with(
    error: io::Error,
    deadline: Option<Instant>,
    reap: impl FnMut() -> io::Result<Option<i32>>,
) -> io::Result<i32> {
    match retry_reap_with(deadline, reap) {
        Ok(Some(code)) => Ok(code),
        Ok(None) => Err(error),
        Err(reap) => Err(io::Error::other(format!(
            "{error}; exact original-child reap also failed: {reap}"
        ))),
    }
}

fn initial_settlement_probe_with(
    initial: io::Result<Option<i32>>,
    active: Option<io::Result<()>>,
    deadline: Option<Instant>,
    reap: impl FnMut() -> io::Result<Option<i32>>,
) -> io::Result<Option<i32>> {
    match initial? {
        Some(code) => Ok(Some(code)),
        None => match active.expect("an empty initial reap has an active-generation result") {
            Ok(()) => Ok(None),
            Err(error) => exact_exit_after_error_with(error, deadline, reap).map(Some),
        },
    }
}

fn initial_signal_forward_with(
    forward: io::Result<ForwardAction>,
    deadline: Option<Instant>,
    reap: impl FnMut() -> io::Result<Option<i32>>,
) -> io::Result<Option<i32>> {
    match forward {
        Ok(_) => Ok(None),
        Err(error) => exact_exit_after_error_with(error, deadline, reap).map(Some),
    }
}

#[derive(Debug)]
pub(crate) struct PreparedExecutable {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    interpreter: PathBuf,
    interpreter_file: File,
    interpreter_identity: FileIdentity,
    abi: ElfAbi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    ctime: i64,
    ctime_ns: i64,
}

impl FileIdentity {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            ctime: metadata.ctime(),
            ctime_ns: metadata.ctime_nsec(),
        }
    }
}

impl PreparedExecutable {
    /// Resolves normal PATH spelling in the parent, then accepts only a direct
    /// conventional x86 ELF with one same-ABI absolute PT_INTERP. Shebang and non-ELF forms
    /// deliberately return `None` and use ordinary live discovery.
    pub(crate) fn resolve(program: &OsStr) -> io::Result<Option<Self>> {
        let path = resolve_program(program)?;
        let file = File::open(&path)?;
        let metadata = file.metadata()?;
        let snapshot = match ElfSnapshot::read(&file) {
            Ok(snapshot) => snapshot,
            Err(_) => return Ok(None),
        };
        let Some(interpreter) = snapshot.interpreter() else {
            return Ok(None);
        };
        let interpreter = PathBuf::from(OsStr::from_bytes(interpreter));
        if !interpreter.is_absolute() {
            return Ok(None);
        }
        let interpreter_file = File::open(&interpreter)?;
        let interpreter_metadata = interpreter_file.metadata()?;
        let interpreter_snapshot = match ElfSnapshot::read(&interpreter_file) {
            Ok(snapshot) => snapshot,
            Err(_) => return Ok(None),
        };
        if interpreter_snapshot.abi() != snapshot.abi() {
            return Ok(None);
        }
        Ok(Some(Self {
            path,
            file,
            identity: FileIdentity::of(&metadata),
            interpreter,
            interpreter_file,
            interpreter_identity: FileIdentity::of(&interpreter_metadata),
            abi: snapshot.abi(),
        }))
    }

    #[allow(dead_code)] // asserted by this module's own resolution tests
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn interpreter(&self) -> &Path {
        &self.interpreter
    }

    #[allow(dead_code)] // asserted by this module's own resolution tests
    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub(crate) fn interpreter_file(&self) -> &File {
        &self.interpreter_file
    }

    pub(crate) fn abi(&self) -> ElfAbi {
        self.abi
    }

    pub(crate) fn unchanged(&self) -> io::Result<bool> {
        Ok(
            FileIdentity::of(&std::fs::metadata(&self.path)?) == self.identity
                && FileIdentity::of(&self.file.metadata()?) == self.identity
                && FileIdentity::of(&std::fs::metadata(&self.interpreter)?)
                    == self.interpreter_identity
                && FileIdentity::of(&self.interpreter_file.metadata()?)
                    == self.interpreter_identity,
        )
    }
}

fn resolve_program(program: &OsStr) -> io::Result<PathBuf> {
    if program.as_bytes().contains(&b'/') {
        return std::fs::canonicalize(program);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    for directory in std::env::split_paths(&path) {
        let candidate = directory.join(program);
        if candidate.is_file() {
            return std::fs::canonicalize(candidate);
        }
    }
    Err(io::Error::from(io::ErrorKind::NotFound))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChildIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
    clear_groups: bool,
}

impl ChildIdentity {
    fn for_invoker() -> io::Result<Self> {
        let mut uids = [0; 3];
        let mut gids = [0; 3];
        // SAFETY: each call receives three valid output pointers.
        if unsafe { libc::getresuid(&mut uids[0], &mut uids[1], &mut uids[2]) } != 0
            || unsafe { libc::getresgid(&mut gids[0], &mut gids[1], &mut gids[2]) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let identity = Self::from_ids(
            uids,
            gids,
            std::env::var_os("SUDO_UID").as_deref(),
            std::env::var_os("SUDO_GID").as_deref(),
        )?;
        if identity.clear_groups {
            validate_account_pair(identity.uid, identity.gid)?;
        }
        Ok(identity)
    }

    fn from_ids(
        uids: [libc::uid_t; 3],
        gids: [libc::gid_t; 3],
        sudo_uid: Option<&OsStr>,
        sudo_gid: Option<&OsStr>,
    ) -> io::Result<Self> {
        if uids != [uids[1]; 3] || gids != [gids[1]; 3] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "refusing owned child with set-id observer credentials",
            ));
        }
        if uids[1] != 0 {
            if gids[1] == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing owned child with root group credentials",
                ));
            }
            return Ok(Self {
                uid: uids[1],
                gid: gids[1],
                clear_groups: false,
            });
        }
        let parse = |name: &str, value: Option<&OsStr>| -> io::Result<u32> {
            let value = value
                .filter(|value| {
                    !value.as_bytes().is_empty() && value.as_bytes().iter().all(u8::is_ascii_digit)
                })
                .and_then(|value| value.to_str())
                .and_then(|value| value.parse().ok())
                .filter(|value| *value != 0 && *value != u32::MAX)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("root observer requires a valid non-root {name}"),
                    )
                })?;
            Ok(value)
        };
        Ok(Self {
            uid: parse("SUDO_UID", sudo_uid)?,
            gid: parse("SUDO_GID", sudo_gid)?,
            clear_groups: true,
        })
    }
}

fn validate_account_pair(uid: libc::uid_t, gid: libc::gid_t) -> io::Result<()> {
    let mut account = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0; 16 * 1024];
    // SAFETY: account, buffer, and result are valid writable storage for getpwuid_r.
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut account,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    if result.is_null() || account.pw_gid != gid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SUDO_UID/SUDO_GID do not name one existing account",
        ));
    }
    Ok(())
}

fn child_environment(
    identity: ChildIdentity,
    variables: impl IntoIterator<Item = (OsString, OsString)>,
) -> io::Result<Vec<CString>> {
    let variables: Vec<_> = variables.into_iter().collect();
    let selected: Vec<(OsString, OsString)> = if identity.clear_groups {
        let mut selected = vec![
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
        ];
        for allowed in ["TERM", "TZ", "SOFTHSM2_CONF"] {
            if let Some((name, value)) = variables.iter().find(|(name, _)| name == allowed) {
                selected.push((name.clone(), value.clone()));
            }
        }
        selected
    } else {
        variables
    };
    selected
        .into_iter()
        .map(|(name, value)| {
            let mut entry = name.into_vec();
            entry.push(b'=');
            entry.extend(value.into_vec());
            CString::new(entry).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "environment contains NUL")
            })
        })
        .collect()
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

unsafe fn last_errno() -> i32 {
    // SAFETY: errno storage is thread-local and readable in this post-fork thread.
    unsafe { *libc::__errno_location() }
}

unsafe fn harden_owned_child(identity: ChildIdentity) -> std::result::Result<(), i32> {
    if unsafe { libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(unsafe { last_errno() });
    }
    if identity.clear_groups
        && unsafe { libc::syscall(libc::SYS_setgroups, 0, std::ptr::null::<libc::gid_t>()) } != 0
    {
        return Err(unsafe { last_errno() });
    }
    if unsafe {
        libc::syscall(
            libc::SYS_setresgid,
            identity.gid,
            identity.gid,
            identity.gid,
        )
    } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_setresuid,
                identity.uid,
                identity.uid,
                identity.uid,
            )
        } != 0
    {
        return Err(unsafe { last_errno() });
    }
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_prctl,
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(unsafe { last_errno() });
    }
    let mut uids = [0; 3];
    let mut gids = [0; 3];
    let mut actual_caps = [CapData {
        effective: u32::MAX,
        permitted: u32::MAX,
        inheritable: u32::MAX,
    }; 2];
    if unsafe {
        libc::syscall(
            libc::SYS_getresuid,
            uids.as_mut_ptr(),
            uids.as_mut_ptr().add(1),
            uids.as_mut_ptr().add(2),
        )
    } != 0
        || unsafe {
            libc::syscall(
                libc::SYS_getresgid,
                gids.as_mut_ptr(),
                gids.as_mut_ptr().add(1),
                gids.as_mut_ptr().add(2),
            )
        } != 0
        || unsafe { libc::syscall(libc::SYS_capget, &mut header, actual_caps.as_mut_ptr()) } != 0
    {
        return Err(unsafe { last_errno() });
    }
    if uids != [identity.uid; 3]
        || gids != [identity.gid; 3]
        || (identity.clear_groups
            && unsafe { libc::syscall(libc::SYS_getgroups, 0, std::ptr::null::<libc::gid_t>()) }
                != 0)
        || actual_caps
            .iter()
            .any(|caps| caps.effective != 0 || caps.permitted != 0 || caps.inheritable != 0)
        || unsafe { libc::syscall(libc::SYS_prctl, libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } != 1
    {
        return Err(libc::EPERM);
    }
    Ok(())
}

/// Owns exactly one fork generation until it is reaped or deliberately handed
/// back still running. The child enters a private session before blocking on
/// the CLOEXEC pre-exec barrier.
pub(crate) struct OwnedChild {
    pid: u32,
    pin: std::sync::Arc<PidPin>,
    generation: NonZeroU64,
    release_writer: Option<OwnedFd>,
    exec_reader: Option<OwnedFd>,
    prepared: Option<PreparedExecutable>,
    released: bool,
    reaped: bool,
    reaped_exit_code: Option<i32>,
    handed_off: bool,
    interrupt_count: u8,
    settlement_deadline: Option<Instant>,
}

impl OwnedChild {
    pub(crate) fn spawn(program: OsString, args: Vec<OsString>) -> io::Result<Self> {
        let identity = ChildIdentity::for_invoker()?;
        let resolved = resolve_program(&program)?;
        let launch_file = File::open(&resolved)?;
        let metadata = launch_file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owned command must be a regular executable file",
            ));
        }
        if let Err(error) = ElfSnapshot::read(&launch_file) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "owned command must be an ELF executable: {error}; invoke scripts through an interpreter"
                ),
            ));
        }
        let prepared = PreparedExecutable::resolve(resolved.as_os_str())
            .ok()
            .flatten();
        let program = CString::new(program.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "program contains NUL"))?;
        let args: Vec<CString> = std::iter::once(program.clone())
            .chain(
                args.into_iter()
                    .map(|arg| {
                        CString::new(arg.as_bytes()).map_err(|_| {
                            io::Error::new(io::ErrorKind::InvalidInput, "argument contains NUL")
                        })
                    })
                    .collect::<io::Result<Vec<_>>>()?,
            )
            .collect();
        let argv: Vec<*const libc::c_char> = args
            .iter()
            .map(|arg| arg.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let environment = child_environment(identity, std::env::vars_os())?;
        let envp: Vec<*const libc::c_char> = environment
            .iter()
            .map(|entry| entry.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let launch_proc_path = CString::new(format!("/proc/self/fd/{}", launch_file.as_raw_fd()))
            .expect("a decimal file descriptor path cannot contain NUL");
        let (release_reader, release_writer) = pipe_pair()?;
        let (exec_reader, exec_writer) = pipe_pair()?;
        set_nonblocking(&exec_reader)?;
        // Allocate before fork so exhaustion cannot create an unguarded child.
        let generation = allocate_generation()?;

        // SAFETY: all allocations and C strings were prepared above. The child
        // executes only async-signal-safe syscalls before exec/_exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                libc::close(release_writer.as_raw_fd());
                libc::close(exec_reader.as_raw_fd());
                if libc::setsid() < 0 {
                    child_exec_failure_errno(exec_writer.as_raw_fd(), last_errno());
                }
                if libc::syscall(
                    libc::SYS_close_range,
                    3u32,
                    u32::MAX,
                    libc::CLOSE_RANGE_CLOEXEC,
                ) != 0
                {
                    child_exec_failure_errno(exec_writer.as_raw_fd(), last_errno());
                }
                if let Err(errno) = harden_owned_child(identity) {
                    child_exec_failure_errno(exec_writer.as_raw_fd(), errno);
                }
                let mut byte = 0u8;
                loop {
                    let read =
                        libc::read(release_reader.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                    if read == 1 {
                        break;
                    }
                    if read == 0 {
                        libc::_exit(127);
                    }
                    let errno = last_errno();
                    if errno != libc::EINTR {
                        child_exec_failure_errno(exec_writer.as_raw_fd(), errno);
                    }
                }
                libc::execve(launch_proc_path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                child_exec_failure_errno(exec_writer.as_raw_fd(), last_errno());
            }
        }

        drop(release_reader);
        drop(exec_writer);
        let pid = pid as u32;
        let pin = match PidPin::open(pid).and_then(|pin| pin.probe_signal_authority().map(|_| pin))
        {
            Ok(pin) => pin,
            Err(error) => {
                drop(release_writer);
                drop(exec_reader);
                // The unreaped fork child cannot be numerically reused. This
                // cleanup is the only path before an original pidfd exists.
                let cleanup = kill_and_reap_fork_child(pid);
                return Err(match cleanup {
                    Ok(()) => io::Error::other(error),
                    Err(cleanup) => io::Error::other(format!(
                        "{error}; cleaning up the original fork child also failed: {cleanup}"
                    )),
                });
            }
        };
        Ok(Self {
            pid,
            pin: std::sync::Arc::new(pin),
            generation,
            release_writer: Some(release_writer),
            exec_reader: Some(exec_reader),
            prepared,
            released: false,
            reaped: false,
            reaped_exit_code: None,
            handed_off: false,
            interrupt_count: 0,
            settlement_deadline: None,
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn seed_pin(&self) -> std::sync::Arc<PidPin> {
        self.pin.clone()
    }

    pub(crate) fn pin(&self) -> &PidPin {
        &self.pin
    }

    pub(crate) fn generation(&self) -> NonZeroU64 {
        self.generation
    }

    pub(crate) fn prepared_executable(&self) -> Option<&PreparedExecutable> {
        self.prepared.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn release(&mut self) -> Result<(), ExecHandoffError> {
        self.release_until(Instant::now() + EXEC_HANDOFF_TIMEOUT, || None)
    }

    pub(crate) fn release_until(
        &mut self,
        deadline: Instant,
        cancelled: impl FnMut() -> Option<i32>,
    ) -> Result<(), ExecHandoffError> {
        self.release_until_with_pending(deadline, cancelled, || {})
    }

    fn release_until_with_pending(
        &mut self,
        deadline: Instant,
        mut cancelled: impl FnMut() -> Option<i32>,
        mut pending: impl FnMut(),
    ) -> Result<(), ExecHandoffError> {
        if self.released {
            return Ok(());
        }
        let writer = self
            .release_writer
            .take()
            .ok_or_else(|| ExecHandoffError::Io {
                phase: "state",
                source: io::Error::other("release was already attempted without acknowledgement"),
            })?;
        let reader = self
            .exec_reader
            .take()
            .ok_or_else(|| ExecHandoffError::Io {
                phase: "state",
                source: io::Error::other("unreleased child has no exec pipe"),
            })?;
        if let Some(signal) = cancelled() {
            return Err(ExecHandoffError::Cancelled(signal));
        }
        if Instant::now() >= deadline {
            return Err(ExecHandoffError::Deadline);
        }
        let byte = 1u8;
        write_release_with(deadline, &mut cancelled, || {
            // SAFETY: writer is live and byte is valid for one-byte write.
            let written =
                unsafe { libc::write(writer.as_raw_fd(), (&byte as *const u8).cast(), 1) };
            if written >= 0 {
                Ok(written as usize)
            } else {
                Err(io::Error::last_os_error())
            }
        })?;
        drop(writer);
        let mut bytes = [0u8; std::mem::size_of::<i32>()];
        let mut used = 0;
        loop {
            let drained = drain_exec_with(&mut bytes, &mut used, |buffer| {
                // SAFETY: the remaining byte range is writable and reader is live.
                let read = unsafe {
                    libc::read(reader.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len())
                };
                if read >= 0 {
                    Ok(read as usize)
                } else {
                    Err(io::Error::last_os_error())
                }
            })?;
            match drained {
                ExecDrain::Errno(errno) => {
                    return Err(ExecHandoffError::Exec(ExecFailure {
                        errno,
                        exit_code: 127,
                    }));
                }
                ExecDrain::EmptyEof => {
                    if let Some(signal) = cancelled() {
                        return Err(ExecHandoffError::Cancelled(signal));
                    }
                    self.released = true;
                    return Ok(());
                }
                ExecDrain::Pending => pending(),
            }
            let mut pollfds = [
                libc::pollfd {
                    fd: reader.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self
                        .pin
                        .pidfd()
                        .map_err(|source| ExecHandoffError::Io {
                            phase: "pidfd access",
                            source,
                        })?
                        .as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let revents = poll_handoff_with(deadline, &mut cancelled, |timeout_ms| {
                // SAFETY: pollfds is a live two-entry array for this call.
                let polled =
                    unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout_ms) };
                if polled >= 0 {
                    Ok([pollfds[0].revents, pollfds[1].revents])
                } else {
                    Err(io::Error::last_os_error())
                }
            })?;
            for (pollfd, revents) in pollfds.iter().zip(revents) {
                if revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
                    return Err(ExecHandoffError::Io {
                        phase: "poll",
                        source: io::Error::other(format!(
                            "descriptor {} reported revents {:#x}",
                            pollfd.fd, revents
                        )),
                    });
                }
            }
        }
    }

    pub(crate) fn revalidate_after_exec(&self) -> io::Result<bool> {
        let Some(prepared) = &self.prepared else {
            return Ok(false);
        };
        if !self.pin.still_the_same() || !prepared.unchanged()? {
            return Ok(false);
        }
        let metadata = std::fs::metadata(format!("/proc/{}/exe", self.pid))?;
        Ok(FileIdentity::of(&metadata) == prepared.identity)
    }

    pub(crate) fn wait_for(
        &mut self,
        duration: Option<Duration>,
        kill_on_timeout: bool,
    ) -> io::Result<ChildOutcome> {
        if self.reaped {
            return Err(io::Error::other("owned child was already reaped"));
        }
        let deadline = duration.and_then(|duration| Instant::now().checked_add(duration));
        if self.wait_ready_until(deadline)? {
            return self
                .try_reap_until(deadline)?
                .map(ChildOutcome::Exited)
                .ok_or_else(|| {
                    io::Error::other("pidfd was ready without a reapable child status")
                });
        }
        if !kill_on_timeout {
            return Ok(ChildOutcome::TimedOutRunning);
        }
        self.terminate_and_reap().map(ChildOutcome::Exited)
    }

    pub(crate) fn forward_signal(&mut self, signal: i32) -> io::Result<ForwardAction> {
        self.ensure_active_generation()?;
        if signal == libc::SIGINT {
            self.interrupt_count = self.interrupt_count.saturating_add(1);
            if self.interrupt_count > 1 {
                signal_group(self.pid, libc::SIGKILL)?;
                return Ok(ForwardAction::Escalated);
            }
        }
        signal_group(self.pid, signal)?;
        Ok(ForwardAction::Forwarded)
    }

    pub(crate) fn terminate_and_reap(&mut self) -> io::Result<i32> {
        self.terminate_with_grace(TERM_GRACE)
    }

    fn terminate_with_grace(&mut self, grace: Duration) -> io::Result<i32> {
        if self.reaped {
            return Err(io::Error::other("owned child was already reaped"));
        }
        self.begin_settlement(grace.saturating_add(FINAL_KILL_GRACE));
        let initial = self.try_reap();
        let active = if matches!(&initial, Ok(None)) {
            Some(self.ensure_active_generation())
        } else {
            None
        };
        let deadline = self.settlement_deadline;
        if let Some(code) =
            initial_settlement_probe_with(initial, active, deadline, || self.try_reap())?
        {
            return Ok(code);
        }
        // Same resume-first as the signal path: a stopped child cannot
        // observe SIGTERM and would burn the grace window into SIGKILL.
        self.resume_if_stopped();
        let term_deadline = self.phase_deadline(grace);
        if let Err(group) = signal_group(self.pid, libc::SIGTERM) {
            if self.wait_ready_until(Some(term_deadline))?
                && let Some(code) = self.try_reap_until(Some(term_deadline))?
            {
                return if self.released {
                    Err(io::Error::other(format!(
                        "owned process-group SIGTERM failed before exact child reap: {group}"
                    )))
                } else {
                    Ok(code)
                };
            }
            if self.released {
                return Err(group);
            }
            return self.kill_and_reap_tail();
        }
        if self.wait_ready_until(Some(term_deadline))? {
            return self.try_reap_until(Some(term_deadline))?.ok_or_else(|| {
                io::Error::other("pidfd was ready without a reapable child status after SIGTERM")
            });
        }
        self.kill_and_reap_tail()
    }

    fn kill_and_reap_tail(&mut self) -> io::Result<i32> {
        self.begin_settlement(FINAL_KILL_GRACE);
        if let Some(code) = self.try_reap()? {
            return Ok(code);
        }
        let group_error = signal_group(self.pid, libc::SIGKILL).err();
        let direct_error = self.pin.send_signal(libc::SIGKILL).err();
        if let Some(error) = direct_error {
            if let Some(code) = self.try_reap()? {
                return if self.released && group_error.is_some() {
                    Err(io::Error::other(format!(
                        "owned process-group SIGKILL failed after exact child exit: {}",
                        group_error.unwrap()
                    )))
                } else {
                    Ok(code)
                };
            }
            return Err(io::Error::other(format!(
                "direct original-pidfd SIGKILL failed: {error}{}",
                group_error
                    .map(|group| format!("; process-group SIGKILL also failed: {group}"))
                    .unwrap_or_default()
            )));
        }
        if !self.wait_ready_until(self.settlement_deadline)? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original child did not become reapable before the settlement deadline",
            ));
        }
        let code = self
            .try_reap_until(self.settlement_deadline)?
            .ok_or_else(|| {
                io::Error::other("pidfd was ready without a reapable child status after SIGKILL")
            })?;
        if self.released
            && let Some(group) = group_error
        {
            return Err(io::Error::other(format!(
                "owned process-group SIGKILL failed after exact child reap: {group}"
            )));
        }
        Ok(code)
    }

    fn reap_after_escalation(&mut self) -> io::Result<i32> {
        self.begin_settlement(FINAL_KILL_GRACE);
        if !self.wait_ready_until(self.settlement_deadline)? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child reap timeout",
            ));
        }
        self.try_reap_until(self.settlement_deadline)?
            .ok_or_else(|| {
                io::Error::other("pidfd was ready without a reapable child status after escalation")
            })
    }

    pub(crate) fn still_running(&self) -> bool {
        !self.reaped && self.pin.still_the_same()
    }

    /// SIGCONT the owned child through its pidfd, best effort. A child
    /// held in T cannot observe SIGTERM/SIGINT, so every graceful settle
    /// path resumes first; on a running child this is a no-op, and on an
    /// exited child the error is ignored.
    fn resume_if_stopped(&self) {
        let _ = self.pin.send_signal(libc::SIGCONT);
    }

    pub(crate) fn is_reaped(&self) -> bool {
        self.reaped
    }

    /// Task 8 uses this only after pause authorization, links, and stop debt
    /// are closed. Drop then intentionally leaves the running process alone.
    pub(crate) fn hand_off_running(&mut self) -> io::Result<u32> {
        if !self.released || !self.still_running() {
            return Err(io::Error::other(
                "only a released, still-running owned child can be handed off",
            ));
        }
        self.handed_off = true;
        Ok(self.pid)
    }

    fn begin_settlement(&mut self, budget: Duration) -> Instant {
        *self.settlement_deadline.get_or_insert_with(|| {
            Instant::now()
                .checked_add(budget)
                .unwrap_or_else(Instant::now)
        })
    }

    fn phase_deadline(&self, budget: Duration) -> Instant {
        let phase = Instant::now()
            .checked_add(budget)
            .unwrap_or_else(Instant::now);
        self.settlement_deadline
            .map_or(phase, |settlement| settlement.min(phase))
    }

    fn wait_ready_until(&self, deadline: Option<Instant>) -> io::Result<bool> {
        loop {
            let timeout =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            match self.pin.wait_ready(timeout) {
                Ok(true) => return Ok(true),
                Ok(false) => return Ok(false),
                Err(error) if error.raw_os_error() == Some(libc::EINTR) => {
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Ok(false);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn try_reap(&mut self) -> io::Result<Option<i32>> {
        // SAFETY: zeroed siginfo_t is the documented waitid output buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let pidfd = self.pin.pidfd()?;
        // SAFETY: P_PIDFD identifies the retained original child descriptor;
        // WNOHANG makes this an exact nonblocking reap attempt.
        if unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: waitid initialized the CLD_* siginfo union fields when si_pid is nonzero.
        let pid = unsafe { info.si_pid() };
        if pid == 0 {
            return Ok(None);
        }
        let status = unsafe { info.si_status() };
        let code = match info.si_code {
            libc::CLD_EXITED => status,
            libc::CLD_KILLED | libc::CLD_DUMPED => 128 + status,
            other => {
                return Err(io::Error::other(format!(
                    "unexpected waitid child status code {other}"
                )));
            }
        };
        self.reaped = true;
        self.reaped_exit_code = Some(code);
        Ok(Some(code))
    }

    fn try_reap_until(&mut self, deadline: Option<Instant>) -> io::Result<Option<i32>> {
        retry_reap_with(deadline, || self.try_reap())
    }

    fn ensure_active_generation(&self) -> io::Result<()> {
        if self.reaped || !self.pin.still_the_same() {
            Err(io::Error::other(
                "owned child generation is no longer active",
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped || self.handed_off {
            return;
        }
        // Closing an unreleased barrier makes the child exit 127. If it does
        // not, kill the owned process group and reap the exact fork child.
        self.release_writer.take();
        self.exec_reader.take();
        if self.try_reap().ok().flatten().is_some() {
            return;
        }
        self.begin_settlement(FINAL_KILL_GRACE);
        let _ = signal_group(self.pid, libc::SIGKILL);
        let _ = self.pin.send_signal(libc::SIGKILL);
        if self
            .wait_ready_until(self.settlement_deadline)
            .unwrap_or(false)
        {
            let _ = self.try_reap_until(self.settlement_deadline);
        }
    }
}

fn allocate_generation() -> io::Result<NonZeroU64> {
    let generation = NEXT_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1).filter(|next| *next != 0)
        })
        .map_err(|_| io::Error::other("owned pause generation space exhausted"))?;
    NonZeroU64::new(generation)
        .ok_or_else(|| io::Error::other("owned pause generation must be nonzero"))
}

fn pipe_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to two writable integers; pipe2 initializes both.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    // SAFETY: F_GETFL reads flags for the live descriptor.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: F_SETFL updates only status flags and preserves every existing flag.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe fn child_exec_failure_errno(fd: i32, errno: i32) -> ! {
    let errno = errno.to_ne_bytes();
    // SAFETY: this child-only error path writes one fixed stack buffer then exits.
    unsafe {
        let mut written = 0;
        while written < errno.len() {
            let result = libc::write(fd, errno[written..].as_ptr().cast(), errno.len() - written);
            if result > 0 {
                written += result as usize;
                continue;
            }
            if result < 0 && *libc::__errno_location() == libc::EINTR {
                continue;
            }
            break;
        }
        libc::_exit(127);
    }
}

fn kill_and_reap_fork_child(pid: u32) -> io::Result<()> {
    // The exact fork child is still unreaped, so its numeric PID cannot have
    // been reused. This is intentionally not a general signal fallback.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    reap_fork_child(pid, Instant::now() + FINAL_KILL_GRACE)
}

fn reap_fork_child(pid: u32, deadline: Instant) -> io::Result<()> {
    loop {
        // SAFETY: this process is the parent of the exact unreaped fork child.
        let waited =
            unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) };
        if waited == pid as libc::pid_t {
            return Ok(());
        }
        if waited < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original fork child cleanup deadline expired",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn signal_group(pid: u32, signal: i32) -> io::Result<()> {
    // SAFETY: the child called setsid before its barrier, so -pid selects only
    // the process group owned by this child lifecycle.
    if unsafe { libc::kill(-(pid as libc::pid_t), signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureEnd {
    DurationExpired,
    TargetExit,
    Signal,
    LimitReached,
    Error,
}

impl CaptureEnd {
    fn allows_handoff(self, kill_on_timeout: bool) -> bool {
        matches!(self, Self::DurationExpired) && !kill_on_timeout
    }
}

/// Both operator stop signals end a capture the same clean way. SIGTERM is
/// what a supervisor (systemd, a container runtime, `timeout`) sends, and
/// its default disposition would kill the process mid-write.
const STOP_SIGNALS: [libc::c_int; 2] = [libc::SIGINT, libc::SIGTERM];

/// Installs handlers that only ever update atomic signal state — no allocation,
/// no I/O, no locks, and no child signaling or cleanup. Every capture loop
/// polls this state cooperatively, the same way it polls `--duration`
/// elapsing, so Ctrl-C (or SIGTERM) ends a capture the same clean way: stop
/// polling, print the final frame, write `-o` if given — never torn down
/// mid-write.
///
/// `signal_hook::low_level::register` is used instead of a hand-rolled
/// `libc::signal` handler: the callback is the signal-safe minimum, while the
/// capture loop retains the first identity and counts repeated Ctrl-C.
struct SignalState {
    state: AtomicU64,
}

impl SignalState {
    fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
        }
    }

    fn observe(&self, signal: libc::c_int) {
        let _ = self
            .state
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |state| {
                let first = state & 0xff;
                let count = (state >> 8) & 3;
                let first = if first == 0 { signal as u64 } else { first };
                let count = if signal == libc::SIGINT {
                    count.saturating_add(1).min(2)
                } else {
                    count
                };
                Some((state & HANDOFF_CLAIMED) | first | (count << 8))
            });
    }

    fn first_signal(&self) -> Option<libc::c_int> {
        match self.state.load(Ordering::SeqCst) & 0xff {
            0 => None,
            signal => Some(signal as libc::c_int),
        }
    }

    fn sigint_deliveries(&self) -> u8 {
        ((self.state.load(Ordering::SeqCst) >> 8) & 3) as u8
    }

    fn interrupted(&self) -> bool {
        self.first_signal().is_some()
    }

    /// Atomically claims the clean-duration handoff boundary. A signal
    /// observed before this CAS wins; a signal observed after it is after the
    /// child has been authorized for handoff.
    fn claim_handoff(&self) -> bool {
        self.state
            .compare_exchange(0, HANDOFF_CLAIMED, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

const HANDOFF_CLAIMED: u64 = 1 << 10;

fn install_stop_flag() -> Result<Arc<SignalState>> {
    let state = Arc::new(SignalState::new());
    for signal in STOP_SIGNALS {
        let observed = Arc::clone(&state);
        // SAFETY: the callback performs only atomic operations.
        unsafe { signal_hook::low_level::register(signal, move || observed.observe(signal)) }
            .with_context(|| format!("installing handler for signal {signal}"))?;
    }
    Ok(state)
}

/// Whether a capture loop should stop this tick: interrupted (Ctrl-C or
/// SIGTERM) or `--duration` elapsed. A pure function so the stop path is
/// directly testable without sending a real signal — set the state,
/// confirm this returns `true` regardless of `elapsed`/`duration`.
fn should_stop(interrupted: &SignalState, elapsed: Duration, duration: Option<Duration>) -> bool {
    interrupted.interrupted() || duration.is_some_and(|d| elapsed >= d)
}

/// `profile` and `trace` against an external target: decide the policy,
/// discover and pin what is in scope, install the stop flag, then run the same
/// loop `run` runs — with no owned child, so no pause is ever possible.
pub fn capture(a: &CaptureArgs) -> Result<()> {
    let kind = a.kind;
    let policy = capture_policy(kind, a.metrics, a.unsafe_requested)?;
    let (scope, named_view) = match &a.scope {
        ScopeArg::Pid(p) => {
            let view = ProcessView::open(ProcessViewId(0), *p)
                .map_err(|error| anyhow!("--pid {p}: {error}"))?;
            (Scope::Pid(*p), Some(view))
        }
        ScopeArg::Cgroup(c) => (scope::cgroup(c)?, None),
        // No named view and no cgroup path: discovery sweeps /proc itself.
        ScopeArg::System => (Scope::System, None),
    };
    if kind == Kind::Trace && a.duration.is_none() {
        eprintln!(
            "p11scope: no --duration given; trace streams until interrupted (Ctrl-C) or the \
             process exits"
        );
    }
    warn_unsafe_policy(policy);
    let accepted = preflight_uretprobe_hazard(
        match &a.scope {
            ScopeArg::Pid(pid) => Some(*pid),
            ScopeArg::Cgroup(_) | ScopeArg::System => None,
        },
        a.allow_confined_uretprobe,
    )?;
    let accepted_uretprobe_risk = accepted;
    let mut engine = Engine::discover(a, &scope, named_view)?;
    // Zero modules is not an error (spec §4.10): the capture still runs, still
    // writes its report, and says here how to find out why it found nothing.
    if engine.plan().modules.is_empty() {
        eprintln!("{}", no_modules_hint(&a.scope));
    }
    let stop = install_stop_flag()?;
    // Before the attach: a bad `-o` path must fail before any probe is on.
    let out = OutputSink::open(kind, a.out.as_deref())?;
    let mut session = engine
        .start_session(policy, a.ring_bytes)
        .context("starting attach session")?;
    run_loop(
        &mut engine,
        &mut session,
        &scope,
        kind,
        policy,
        a.duration,
        a.max_events,
        out,
        &stop,
        None,
        a.drain_interval,
        a.ring_bytes,
    )?;
    // `--pid` cannot read a non-child's exit status, so the honest report is
    // the pairing of two facts we do have: the target went away, and this
    // capture knowingly attached uretprobes a measured-affected kernel kills
    // confined targets for. Saying nothing here would leave the operator with
    // a capture whose calls are all in flight and no reason given.
    if accepted_uretprobe_risk && engine.expected_target_exit() {
        eprintln!(
            "p11scope: WARNING: the target exited during this capture, which attached uretprobes \
             to a syscall-confined target on a kernel measured to kill one for exactly that. \
             p11scope cannot read a non-child's exit status, so this is not proof — but calls \
             left in flight with no returns are that death's fingerprint"
        );
    }
    Ok(())
}

fn capture_policy(kind: Kind, metrics: bool, unsafe_requested: bool) -> Result<CapturePolicy> {
    let mode = match (kind, metrics) {
        (Kind::Trace, _) => "trace",
        (Kind::Profile, true) => "metrics",
        (Kind::Profile, false) => "profile",
    };
    CapturePolicy::from_cli(
        mode,
        unsafe_requested,
        cfg!(feature = "unsafe-unvalidated-metadata"),
    )
}

/// The `-o` sink, opened by the caller *before* the attach so a bad path fails
/// early rather than after a session is loaded and probes are on. The profile
/// report is published atomically; the trace stream is appended to as lines
/// arrive.
enum OutputSink {
    None,
    Profile(Box<AtomicFile>),
    Trace(std::fs::File),
}

impl OutputSink {
    fn open(kind: Kind, out: Option<&Path>) -> Result<Self> {
        match (kind, out) {
            (_, None) => Ok(Self::None),
            (Kind::Profile, Some(path)) => AtomicFile::create(path)
                .map(|file| Self::Profile(Box::new(file)))
                .map_err(anyhow::Error::msg),
            (Kind::Trace, Some(path)) => crate::output::create_private_stream(path)
                .map(Self::Trace)
                .map_err(anyhow::Error::msg)
                .context("creating trace output"),
        }
    }
}

/// Picks the loop `kind` selects. The only place either loop is entered, so
/// there is exactly one profile loop and one trace loop in this binary.
#[allow(clippy::too_many_arguments)]
fn run_loop(
    engine: &mut Engine,
    session: &mut Session,
    scope: &Scope,
    kind: Kind,
    policy: CapturePolicy,
    duration: Option<Duration>,
    max_events: Option<u64>,
    out: OutputSink,
    interrupted: &SignalState,
    owned: Option<&mut Owned>,
    drain_interval: Option<Duration>,
    ring_bytes: Option<u32>,
) -> Result<render::Evidence> {
    report_attach_failures(session);
    let drain = resolve_drain_cadence(kind, drain_interval);
    match kind {
        Kind::Profile => {
            let out = match out {
                OutputSink::Profile(file) => Some(*file),
                _ => None,
            };
            capture_profile(
                engine,
                session,
                scope,
                policy,
                duration,
                out,
                interrupted,
                owned,
                drain,
                ring_bytes,
            )
        }
        Kind::Trace => {
            let out = match out {
                OutputSink::Trace(file) => Some(file),
                _ => None,
            };
            capture_trace(
                engine,
                session,
                scope,
                policy,
                duration,
                max_events,
                out,
                interrupted,
                owned,
                drain,
            )
        }
    }
}

/// What `run` reports back to its caller. `evidence` is the exact finalized
/// capture evidence the document was rendered from.
#[derive(Debug, Clone)]
pub struct OwnedRunOutcome {
    /// The child's status as a shell would report it (128 + signal when
    /// signalled). `None` exactly when `--duration` expired without
    /// `--kill-on-timeout` and the child was handed back still running.
    pub child_exit_code: Option<i32>,
    /// Mirrors `evidence.child_still_running`.
    pub child_still_running: bool,
    /// The child this run owned. A handed-back child must be nameable or the
    /// operator cannot find what `run` left alive. Not a rendered field.
    pub child_pid: u32,
    pub evidence: render::Evidence,
}

/// The owned child and the coordinator that protects its live windows, plus
/// the settled child disposition the final evidence reports. Crate-private:
/// nothing here is reachable from outside the library.
struct Owned {
    child: Option<OwnedChild>,
    pending_handoff: Option<OwnedChild>,
    coordinator: PauseCoordinator,
    policy: cli::PausePolicy,
    kill_on_timeout: bool,
    pid: u32,
    exit_code: Option<i32>,
    still_running: bool,
}

/// Non-cloneable terminal authority: exact original reap AND that owner's
/// successful loader acknowledgement. The original child stays owned until
/// reduction completes or this optional retirement is explicitly abandoned.
pub(crate) struct OriginalRootExit {
    _child: OwnedChild,
    seed: crate::attach::RootSeed,
}
impl OriginalRootExit {
    fn take(
        child: &mut Option<OwnedChild>,
        seed: &mut Option<crate::attach::RootSeed>,
    ) -> Result<Option<Self>> {
        let (Some(owner), Some(ack)) = (child.as_ref(), seed.as_ref()) else {
            return Ok(None);
        };
        anyhow::ensure!(
            ack.acknowledges(owner),
            "root seed acknowledges a different original owner"
        );
        owner.pin().pidfd()?;
        if !owner.is_reaped() || owner.handed_off {
            return Ok(None);
        }
        Ok(Some(Self {
            _child: child.take().unwrap(),
            seed: seed.take().unwrap(),
        }))
    }
    pub(crate) fn domain(&self) -> &crate::events::EventsDomain {
        self.seed.domain()
    }
    #[cfg(test)]
    pub(crate) fn test_reaped(domain: crate::events::EventsDomain) -> Self {
        // A controlled fresh child and actual P_PIDFD reap; only the map/seed
        // acknowledgement is synthetic, never kernel qualification.
        let mut child = OwnedChild::spawn("/bin/true".into(), vec![]).unwrap();
        let ack = crate::attach::RootSeed::test_acknowledgement(&child, domain);
        child.release().unwrap();
        child.terminate_and_reap().unwrap();
        Self::take(&mut Some(child), &mut Some(ack))
            .unwrap()
            .unwrap()
    }
}

fn pause_failure(error: PauseError) -> anyhow::Error {
    anyhow!("pause: {error}")
}

impl Owned {
    /// Closes the pause epoch and settles the child, *before* any terminal
    /// evidence is built: `child_still_running` is a fact the final document
    /// reports, never a guess made after it was written. Resume comes first,
    /// so a child still held by an accepted stop is never waited on.
    fn finish(
        &mut self,
        engine: &mut Engine,
        session: &mut Session,
        end: CaptureEnd,
        signals: &SignalState,
    ) -> Result<()> {
        let Some(child) = self.child.as_ref() else {
            return Ok(());
        };
        let observation = child.pin().original_exited().map_err(anyhow::Error::msg);
        engine.finish_owned_selection_coverage(
            end == CaptureEnd::TargetExit && matches!(observation, Ok(true)),
        );
        let cleanup = {
            let marker = marker_never_seen();
            let cancelled = cancelled_by(signals);
            let mut io = SessionPauseIo::new(engine, session, child, &marker, &cancelled);
            self.coordinator.cleanup(&mut io)
        };
        let settled = settle_owned_child(
            &mut self.child,
            end,
            cleanup.is_ok(),
            self.kill_on_timeout,
            signals,
            &mut self.pending_handoff,
            &mut self.exit_code,
            &mut self.still_running,
        );
        // Both outcomes are retained: a cleanup failure must not be lost
        // behind a reap failure, or the other way round (design §10.3).
        combine_finish_errors(
            observation.map(|_| ()),
            combine_finish_errors(cleanup.map_err(pause_failure), settled),
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn settle_owned_child(
    retained: &mut Option<OwnedChild>,
    end: CaptureEnd,
    cleanup_ok: bool,
    kill_on_timeout: bool,
    signals: &SignalState,
    pending: &mut Option<OwnedChild>,
    exit_code: &mut Option<i32>,
    still_running: &mut bool,
) -> Result<()> {
    let end = if end == CaptureEnd::DurationExpired && signals.interrupted() {
        CaptureEnd::Signal
    } else {
        end
    };
    // An expired `--duration` is the only end that may hand back a live
    // child, and only after coordinator cleanup succeeds.
    let can_hand_off = cleanup_ok && end.allows_handoff(kill_on_timeout) && signals.claim_handoff();
    if can_hand_off {
        let outcome = stage_handoff(retained, pending)?;
        match outcome {
            ChildOutcome::Exited(code) => {
                *exit_code = Some(code);
                *still_running = false;
            }
            ChildOutcome::TimedOutRunning => {
                *exit_code = None;
                *still_running = true;
            }
        }
        return Ok(());
    }
    let child = retained
        .as_mut()
        .context("owned child missing during settlement")?;
    let settled: Result<ChildOutcome> =
        if (end == CaptureEnd::Signal || signals.interrupted()) && child.still_running() {
            settle_after_signal(child, signals)
        } else {
            child
                .terminate_and_reap()
                .map(ChildOutcome::Exited)
                .map_err(|error| anyhow!("run: reaping the owned child: {error}"))
        };
    record_settlement_result(child, settled, exit_code, still_running)
}

fn record_settlement_result(
    child: &OwnedChild,
    settled: Result<ChildOutcome>,
    exit_code: &mut Option<i32>,
    still_running: &mut bool,
) -> Result<()> {
    match settled {
        Ok(ChildOutcome::Exited(code)) => {
            *exit_code = Some(code);
            *still_running = false;
            Ok(())
        }
        Ok(ChildOutcome::TimedOutRunning) => {
            *exit_code = None;
            *still_running = true;
            Ok(())
        }
        Err(error) => {
            if child.is_reaped() {
                *exit_code = child.reaped_exit_code;
                *still_running = false;
            }
            Err(anyhow!("run: reaping the owned child: {error}"))
        }
    }
}

fn stage_handoff(
    retained: &mut Option<OwnedChild>,
    pending: &mut Option<OwnedChild>,
) -> Result<ChildOutcome> {
    let child = retained
        .as_mut()
        .context("owned child missing during handoff")?;
    match child
        .wait_for(Some(Duration::ZERO), false)
        .map_err(|error| anyhow!("run: waiting for the owned child: {error}"))?
    {
        outcome @ ChildOutcome::TimedOutRunning => {
            *pending = retained.take();
            Ok(outcome)
        }
        outcome => Ok(outcome),
    }
}

fn commit_handoff(pending: &mut Option<OwnedChild>) -> Result<()> {
    let Some(child) = pending.as_mut() else {
        return Ok(());
    };
    child
        .hand_off_running()
        .map(|_| ())
        .map_err(|error| anyhow!("run: handing back the owned child: {error}"))?;
    pending.take();
    Ok(())
}

fn settle_after_signal(child: &mut OwnedChild, signals: &SignalState) -> Result<ChildOutcome> {
    settle_after_signal_with_grace(child, signals, TERM_GRACE)
}

fn settle_after_signal_with_grace(
    child: &mut OwnedChild,
    signals: &SignalState,
    grace: Duration,
) -> Result<ChildOutcome> {
    child.begin_settlement(grace.saturating_mul(2).saturating_add(FINAL_KILL_GRACE));
    let signal = signals
        .first_signal()
        .ok_or_else(|| anyhow!("run: signal settlement lost the first signal identity"))?;
    // A child held in T (pause, or anything else) cannot observe the
    // forwarded signal; resume it first so SIGTERM can land instead of
    // pending through both grace windows into SIGKILL. Best effort and a
    // no-op on a running child.
    child.resume_if_stopped();
    let forward = child.forward_signal(signal);
    let deadline = child.settlement_deadline;
    if let Some(code) = initial_signal_forward_with(forward, deadline, || child.try_reap())
        .map_err(|error| anyhow!("run: forwarding signal {signal}: {error}"))?
    {
        return Ok(ChildOutcome::Exited(code));
    }
    let mut deadline = child.phase_deadline(grace);
    let mut second_sigint_forwarded = false;
    let mut fallback_term_forwarded = false;
    loop {
        if signal == libc::SIGINT && !second_sigint_forwarded && signals.sigint_deliveries() >= 2 {
            match child.forward_signal(libc::SIGINT) {
                Ok(ForwardAction::Escalated) => {
                    return child
                        .reap_after_escalation()
                        .map(ChildOutcome::Exited)
                        .map_err(|error| anyhow!("run: settling after signal: {error}"));
                }
                Ok(ForwardAction::Forwarded) => second_sigint_forwarded = true,
                Err(error) => {
                    if let ChildOutcome::Exited(code) = child
                        .wait_for(Some(Duration::ZERO), false)
                        .map_err(|reap| anyhow!("run: waiting after signal: {reap}"))?
                    {
                        return Ok(ChildOutcome::Exited(code));
                    }
                    return Err(anyhow!("run: forwarding second SIGINT: {error}"));
                }
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if fallback_term_forwarded {
                break;
            }
            if let Err(error) = child.forward_signal(libc::SIGTERM) {
                // A child can exit between the grace wait and fallback TERM.
                // Reap it at this phase boundary instead of reporting a
                // forwarding failure for a natural exit.
                if let ChildOutcome::Exited(code) = child
                    .wait_for(Some(Duration::ZERO), false)
                    .map_err(|reap| anyhow!("run: waiting after signal: {reap}"))?
                {
                    return Ok(ChildOutcome::Exited(code));
                }
                return Err(anyhow!("run: forwarding fallback SIGTERM: {error}"));
            }
            fallback_term_forwarded = true;
            deadline = child.phase_deadline(grace);
            continue;
        }
        match child
            .wait_for(Some(remaining.min(Duration::from_millis(10))), false)
            .map_err(|error| anyhow!("run: waiting after signal: {error}"))?
        {
            ChildOutcome::Exited(code) => return Ok(ChildOutcome::Exited(code)),
            ChildOutcome::TimedOutRunning => {}
        }
    }
    child
        .kill_and_reap_tail()
        .map(ChildOutcome::Exited)
        .map_err(|error| anyhow!("run: settling after signal: {error}"))
}

fn abort_pending_handoff(pending: &mut Option<OwnedChild>) -> Result<()> {
    let Some(mut child) = pending.take() else {
        return Ok(());
    };
    child
        .terminate_and_reap()
        .map(|_| ())
        .map_err(|error| anyhow!("run: aborting pending handoff: {error}"))
}

fn also_failed(primary: anyhow::Error, secondary: anyhow::Error, what: &str) -> anyhow::Error {
    primary.context(format!("{what} also failed: {secondary:#}"))
}

fn combine_handoff_failure(primary: anyhow::Error, abort: Result<()>) -> anyhow::Error {
    match abort {
        Ok(()) => primary,
        Err(abort) => also_failed(primary, abort, "aborting pending handoff"),
    }
}

fn combine_setup_failure(primary: anyhow::Error, child: &mut OwnedChild) -> anyhow::Error {
    match child.terminate_and_reap() {
        Ok(_) => primary,
        Err(cleanup) => primary.context(format!(
            "settling the original child after setup failure also failed: {cleanup}"
        )),
    }
}

fn combine_preflight_failure_with(
    primary: anyhow::Error,
    mut detach: impl FnMut() -> Result<()>,
    mut settle: impl FnMut() -> Result<()>,
) -> anyhow::Error {
    let primary = combine_detach::<()>(Err(primary), detach()).unwrap_err();
    combine_finish_errors(Err(primary), settle()).unwrap_err()
}

fn combine_finish_errors(cleanup: Result<()>, settled: Result<()>) -> Result<()> {
    match (cleanup, settled) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(cleanup), Err(settled)) => {
            Err(also_failed(cleanup, settled, "owned child settlement"))
        }
    }
}

fn combine_capture_failure(
    mut capture: anyhow::Error,
    finish: Result<()>,
    detach: Result<()>,
) -> anyhow::Error {
    if let Err(error) = finish {
        capture = also_failed(capture, error, "owned cleanup/settlement");
    }
    if let Err(error) = detach {
        capture = also_failed(capture, error, "detaching capture producers");
    }
    capture
}

fn combine_detach<T>(terminal: Result<T>, detach: Result<()>) -> Result<T> {
    match (terminal, detach) {
        (result, Ok(())) => result,
        (Ok(_), Err(detach)) => Err(anyhow!("run: detaching capture producers: {detach:#}")),
        (Err(terminal), Err(detach)) => {
            Err(also_failed(terminal, detach, "detaching capture producers"))
        }
    }
}

fn finish_capture_error(
    error: anyhow::Error,
    engine: &mut Engine,
    session: &mut Session,
    owned: Option<&mut Owned>,
    signals: &SignalState,
) -> anyhow::Error {
    let finish = match owned {
        Some(owned) => owned.finish(engine, session, CaptureEnd::Error, signals),
        None => Ok(()),
    };
    let detach = session.detach_producers();
    combine_capture_failure(error, finish, detach)
}

fn finish_capture_loop(
    result: Result<CaptureEnd>,
    engine: &mut Engine,
    session: &mut Session,
    mut owned: Option<&mut Owned>,
    signals: &SignalState,
) -> Result<CaptureEnd> {
    let end = match result {
        Ok(end) => end,
        Err(error) => return Err(finish_capture_error(error, engine, session, owned, signals)),
    };
    if let Some(owned) = owned.take()
        && let Err(error) = owned.finish(engine, session, end, signals)
    {
        return Err(finish_capture_error(error, engine, session, None, signals));
    }
    Ok(end)
}

/// A marker probe is not wired in this slice, so the coordinator is told the
/// protected marker was never reached. ponytail: fixed `false` until the Gate B
/// protected-marker probe lands; swap for the real read then.
fn marker_never_seen() -> impl Fn() -> std::result::Result<bool, String> {
    || Ok(false)
}

/// The coordinator's cancellation signal is the same stop flag the loops poll,
/// so an accepted stop is never slept through inside a bounded pause cycle.
fn cancelled_by(interrupted: &SignalState) -> impl Fn() -> std::result::Result<bool, String> + '_ {
    move || Ok(interrupted.interrupted())
}

/// The one narrow public production facade `p11scope run` uses: it owns the
/// child from fork to reap (or to a deliberate still-running hand-off),
/// applies the pause policy, runs live discovery and the capture loop, and
/// writes the final artifact.
pub fn run_owned(args: &RunArgs) -> Result<OwnedRunOutcome> {
    let stop = install_stop_flag()?;
    let outcome = run_owned_inner(args, stop.clone());
    match (args.pause, outcome) {
        // `always` never falls back to a successful unpaused run: whatever
        // could not be completed, the refusal says pause was required.
        (cli::PausePolicy::Always, Err(error)) => Err(always_wrap(&stop, error)),
        (_, outcome) => outcome,
    }
}

/// Names the `always` failure for what it was: a signalled run was
/// interrupted mid-capture, only an unsignalled one refused.
fn always_wrap(interrupted: &SignalState, error: anyhow::Error) -> anyhow::Error {
    if let Some(signal) = interrupted.first_signal() {
        return error.context(format!(
            "run --pause always: interrupted by {} while pause protection was active",
            stop_signal_name(signal)
        ));
    }
    error.context(
        "run --pause always: required pause protection could not be completed, so the run \
         refused rather than capturing unpaused",
    )
}

fn stop_signal_name(signal: libc::c_int) -> String {
    match signal {
        libc::SIGINT => "SIGINT".to_string(),
        libc::SIGTERM => "SIGTERM".to_string(),
        other => format!("signal {other}"),
    }
}

fn run_owned_inner(args: &RunArgs, stop: Arc<SignalState>) -> Result<OwnedRunOutcome> {
    let policy = capture_policy(args.kind, args.metrics, args.unsafe_requested)?;
    warn_unsafe_policy(policy);
    let mut command = args.command.iter().map(OsString::from);
    let program = command
        .next()
        .ok_or_else(|| anyhow!("run: no command to exec"))?;
    // An exec failure is its own finite category (design §10.3). Resolving the
    // command first means a command that cannot run is refused by name before
    // anything is forked, attached, or released past its barrier.
    resolve_program(&program)
        .map_err(|error| anyhow!("run: exec {}: {error}", Path::new(&program).display()))?;

    let mut child = OwnedChild::spawn(program, command.collect())
        .map_err(|error| anyhow!("run: starting the owned child: {error}"))?;
    let pid = child.pid();
    let view = ProcessView::open(ProcessViewId(0), pid).map_err(|error| {
        combine_setup_failure(anyhow!("run: opening the owned child: {error}"), &mut child)
    })?;
    let scope = Scope::Pid(pid);
    let capture_args = CaptureArgs {
        kind: args.kind,
        modules: args.modules.clone(),
        manifests: args.manifests.clone(),
        hooks: args.hooks.clone(),
        scope: ScopeArg::Pid(pid),
        metrics: args.metrics,
        duration: args.duration,
        out: args.out.clone(),
        max_events: args.max_events,
        max_scan_pids: args.max_scan_pids,
        ring_bytes: args.ring_bytes,
        drain_interval: args.drain_interval,
        unsafe_requested: args.unsafe_requested,
        allow_confined_uretprobe: args.allow_confined_uretprobe,
    };
    // Initial capture still uses the one `discover_plan` pass and keeps its
    // accepted state inside `Engine`; nothing below rescans or reopens.
    let mut engine = Engine::discover(&capture_args, &scope, Some(view))
        .map_err(|error| combine_setup_failure(error, &mut child))?;
    // The stop flag arrives from `run_owned`, which keeps its own clone so a
    // signalled `always` failure can be named an interruption, not a refusal.
    // Before the attach, and before the child crosses its barrier: a bad `-o`
    // path must never cost a released child or a loaded session.
    let out = OutputSink::open(args.kind, args.out.as_deref())
        .map_err(|error| combine_setup_failure(error, &mut child))?;

    // `start_owned_session` arms the pre-exec loader context before the
    // barrier when exact PT_INTERP binding is safe, and otherwise leaves
    // `initial_set_capture = none` with sticky `PARTIAL`.
    let mut session = engine
        .start_owned_session(policy, &mut child, args.ring_bytes)
        .context("starting attach session")
        .map_err(|error| combine_setup_failure(error, &mut child))?;

    let preflight = {
        let marker = marker_never_seen();
        let cancelled = cancelled_by(&stop);
        let mut io = SessionPauseIo::new(&mut engine, &mut session, &child, &marker, &cancelled);
        PauseCoordinator::preflight(args.pause, &child, &mut io).map_err(pause_failure)
    };
    let coordinator = match preflight {
        Ok(coordinator) => coordinator,
        Err(error) => {
            return Err(combine_preflight_failure_with(
                error,
                || session.detach_producers(),
                || {
                    child
                        .terminate_and_reap()
                        .map(|_| ())
                        .map_err(|error| anyhow!("run: settling the original child: {error}"))
                },
            ));
        }
    };
    let mut owned = Owned {
        child: Some(child),
        pending_handoff: None,
        coordinator,
        policy: args.pause,
        kill_on_timeout: args.kill_on_timeout,
        pid,
        exit_code: None,
        still_running: false,
    };

    // Arm before the barrier: the owned window has to be protected from the
    // child's first loader event, not from the first tick after it. Owned is
    // already constructed so an arm failure uses coordinator-first cleanup.
    {
        let marker = marker_never_seen();
        let cancelled = cancelled_by(&stop);
        let child = owned
            .child
            .as_ref()
            .expect("owned child is present before arm");
        let mut io = SessionPauseIo::new(&mut engine, &mut session, child, &marker, &cancelled);
        if let Err(error) = owned.coordinator.arm(&mut io) {
            return Err(finish_capture_error(
                pause_failure(error),
                &mut engine,
                &mut session,
                Some(&mut owned),
                &stop,
            ));
        }
    }

    let release = owned
        .child
        .as_mut()
        .expect("owned child is present before release")
        .release_until(Instant::now() + EXEC_HANDOFF_TIMEOUT, || {
            stop.first_signal()
        })
        .map_err(|failure| anyhow!("run: {failure}"));
    if let Err(error) = release {
        return Err(finish_capture_error(
            error,
            &mut engine,
            &mut session,
            Some(&mut owned),
            &stop,
        ));
    }
    {
        let marker = marker_never_seen();
        let cancelled = cancelled_by(&stop);
        let child = owned
            .child
            .as_ref()
            .expect("owned child is present after release");
        let mut io = SessionPauseIo::new(&mut engine, &mut session, child, &marker, &cancelled);
        if let Err(error) = owned.coordinator.revalidate_after_release(&mut io) {
            if error.required() || error.lifecycle() {
                return Err(finish_capture_error(
                    pause_failure(error),
                    &mut engine,
                    &mut session,
                    Some(&mut owned),
                    &stop,
                ));
            }
            retire_pause_policy(error)?;
        }
    }

    let evidence = run_loop(
        &mut engine,
        &mut session,
        &scope,
        args.kind,
        policy,
        args.duration,
        args.max_events,
        out,
        &stop,
        Some(&mut owned),
        args.drain_interval,
        args.ring_bytes,
    )
    .map_err(|error| {
        combine_handoff_failure(error, abort_pending_handoff(&mut owned.pending_handoff))
    })?;
    if let Err(error) = commit_handoff(&mut owned.pending_handoff) {
        return Err(combine_handoff_failure(
            error,
            abort_pending_handoff(&mut owned.pending_handoff),
        ));
    }
    // A signalled death is reported as one. `run` owns this child, so its
    // status is available and folding a SIGSYS into a bare exit code would be
    // the tool hiding a kill it may itself have caused (uretprobe_hazard §1).
    if let Some(code) = owned.exit_code
        && let Some(explanation) =
            uretprobe_hazard::describe_owned_child_death(code, evidence.attached_probes)
    {
        eprintln!("p11scope: {explanation}");
    }
    Ok(OwnedRunOutcome {
        child_exit_code: owned.exit_code,
        child_still_running: owned.still_running,
        child_pid: owned.pid,
        evidence,
    })
}

/// Refuses before a single probe is installed when this kernel would kill the
/// target for carrying a uretprobe, and warns instead when the operator has
/// accepted that.
///
/// `target` is the one pid a `--pid` capture probes; `None` means the scope
/// attaches process-wide, so the processes that would run the trampoline
/// cannot be enumerated. `run` deliberately does not call this: its child arms
/// any filter after exec, which is after attach, so there is nothing to read
/// yet — that path reports the death instead.
fn preflight_uretprobe_hazard(target: Option<u32>, overridden: bool) -> Result<bool> {
    match uretprobe_hazard::evaluate(target, overridden) {
        uretprobe_hazard::Action::Proceed => Ok(false),
        uretprobe_hazard::Action::ProceedUnderOverride(reason) => {
            eprintln!(
                "p11scope: WARNING: {reason}. Continuing because \
                 --allow-uretprobe-on-confined-target was given"
            );
            Ok(true)
        }
        uretprobe_hazard::Action::Refuse(reason) => Err(anyhow!(
            "refusing to attach: {reason}. Re-run with \
             --allow-uretprobe-on-confined-target to accept that risk, or capture on a kernel \
             that exempts the trampoline — scripts/matrix/verify-uretprobe-seccomp.sh \
             classifies the one you are on"
        )),
    }
}

/// Zero modules is not an error; point the operator at the discovery diagnostics.
fn no_modules_hint(scope: &ScopeArg) -> String {
    match scope {
        ScopeArg::Pid(pid) => format!(
            "p11scope: no PKCS#11 modules discovered in pid {pid}; run \
             `p11scope inspect --pid {pid}` or `p11scope doctor --pid {pid}` to see why"
        ),
        ScopeArg::Cgroup(path) => format!(
            "p11scope: no PKCS#11 modules discovered in cgroup {0}; run \
             `p11scope inspect --pid <n>` for a process in it or \
             `p11scope doctor --cgroup {0}` to see why",
            path.display()
        ),
        ScopeArg::System => "p11scope: no PKCS#11 modules discovered system-wide; run \
             `p11scope inspect --pid <n>` for a process using PKCS#11 or \
             `p11scope doctor` to see why"
            .to_string(),
    }
}

/// Prints every attach failure — shared by `profile` and `trace`, which
/// each attach the same way. A capture that attached at least one probe
/// still gets each per-slot failure printed (it is real evidence of a
/// PARTIAL capture, kept as-is). But when literally nothing attached,
/// N copies of the same generic per-slot line leave the operator to
/// work out on their own that this means "the environment can't do BPF
/// attach at all" — so that case also gets one synthesized, actionable
/// summary line naming the likely causes, not just a wall of identical
/// failures. This is in addition to `Session::start`'s own hint (fired
/// only when the *earlier* map-creation/program-load stage fails
/// outright); this one covers the case where that stage succeeds but
/// every individual uprobe attach is refused (e.g. `perf_event_open`
/// blocked by `perf_event_paranoid`).
fn report_attach_failures(session: &Session) {
    for (idx, msg) in session.attach_failures() {
        eprintln!("{}", format_attach_failure(*idx, msg));
    }
    if session.attached_probes() == 0 {
        if let Some((_, first)) = session.attach_failures().first() {
            eprintln!(
                "{}",
                format_total_attach_refusal(
                    session.attach_failures().len(),
                    session.attached_probes() + session.attach_failures().len(),
                    first
                )
            );
        }
    }
}

/// The per-slot attach diagnostic. The failure message embeds the module's
/// `/proc/<pid>/maps` filename (attach.rs builds it from `slot.object_path`),
/// which the target controls, so this terminal boundary escapes control bytes
/// — the stored `attach_failures` evidence keeps the raw string.
fn format_attach_failure(slot: u32, message: &str) -> String {
    format!(
        "attach failed (slot {slot}): {}",
        render::escape_controls(message)
    )
}

/// The zero-probes summary; `first` is the first per-slot failure message and
/// carries the same target-controlled path bytes.
fn format_total_attach_refusal(failed: usize, attempted: usize, first: &str) -> String {
    format!(
        "p11scope: {failed}/{attempted} attach attempts failed, every one the same way — this \
         almost always means the environment cannot attach BPF uprobes at all: missing \
         CAP_BPF/CAP_SYS_ADMIN (or root), a kernel lockdown mode, or a restrictive \
         kernel.perf_event_paranoid sysctl. First underlying error: {}",
        render::escape_controls(first)
    )
}

/// Gives unsafe rendering the same diagnostic shape expectations that
/// `Session::start` published to `MECH_SHAPE`.
fn load_mech_shapes(state: &mut semantics::State) -> Result<()> {
    let registry = pkcs11_types::mechanism_registry::MechanismRegistry::load(None)
        .map_err(|e| anyhow!("loading mechanism registry: {e}"))?;
    state.set_mech_shapes(crate::shapes::expected_shapes(&registry));
    Ok(())
}

fn warn_unsafe_policy(policy: CapturePolicy) {
    if policy.uses_unsafe_decoders() {
        eprintln!(
            "p11scope: WARNING: unsafe-unvalidated-metadata follows caller-supplied pointer \
             topology and is only for trusted, ABI-valid workloads"
        );
    }
}

fn identify_tracked(
    domain: u64,
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    ev: &p11scope_ebpf_common::Event,
) -> Option<semantics::ProcessKey> {
    if !state.accepts_domain(domain) || ev.event_type != p11scope_ebpf_common::event_type::CALL {
        state.reject_history(ev);
        return None;
    }
    let (key, retired) = tracker.admit_history(domain, (ev.pid_tgid >> 32) as u32, ev.image);
    for old in retired {
        state.retire_process(old);
    }
    if let Some(key) = key {
        tracker.history_call(key);
        tracker.history_root(key, ev.root_affiliation);
    } else {
        state.reject_history(ev);
    }
    key
}
/// Legacy test-only injected retirement. Production requires the non-cloneable
/// completed root-tail token below.
#[cfg(test)]
fn apply_confirmed_retirement(
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    key: semantics::ProcessKey,
) {
    if let Some(key) = tracker.confirm_history_retirement(key) {
        state.retire_process(key);
    }
}
fn apply_original_root_retirement(
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    tail: crate::events::ConsumedOriginalRootTail,
) -> Result<()> {
    anyhow::ensure!(
        state.accepts_domain(tail.domain()),
        "foreign root retirement state"
    );
    for key in tracker.complete_root(&tail)? {
        state.retire_process(key);
    }
    Ok(())
}

enum OriginalRootDrain {
    Absent,
    Completed {
        malformed: u64,
        tail: Box<crate::events::ConsumedOriginalRootTail>,
    },
    Cancelled {
        malformed: u64,
        remaining: usize,
    },
}

/// The only production root-tail orchestration. A live handoff or an unowned
/// session has no witness. No ordinary EVENTS read occurs while this tail is
/// active, and all failure returns explicitly abandon optional retirement.
fn drain_original_root_events(
    session: &mut Session,
    owned: Option<&mut Owned>,
    signals: &SignalState,
    reduce: impl FnMut(u64, p11scope_ebpf_common::Event) -> Result<()>,
) -> Result<OriginalRootDrain> {
    let Some(owned) = owned else {
        return Ok(OriginalRootDrain::Absent);
    };
    let mut seed = session.take_root_seed();
    let Some(exit) = OriginalRootExit::take(&mut owned.child, &mut seed)
        .context("root_tail_incomplete: original ownership")?
    else {
        return Ok(OriginalRootDrain::Absent);
    };
    let tail = crate::events::OwnedRootTail::new(
        exit,
        Instant::now() + crate::events::ROOT_TAIL_FENCE_TIMEOUT,
    );
    let mut drain = session
        .event_drain()
        .context("root_tail_incomplete: EVENTS reader")?;
    drain_original_root_events_from(&mut drain, tail, signals, reduce)
}

fn drain_original_root_events_from<S: crate::events::BoundedRecordSource>(
    drain: &mut crate::events::EventDrain<S>,
    mut tail: crate::events::OwnedRootTail,
    signals: &SignalState,
    mut reduce: impl FnMut(u64, p11scope_ebpf_common::Event) -> Result<()>,
) -> Result<OriginalRootDrain> {
    drain.begin_root_tail(&mut tail)?;
    let domain = drain.domain_id();
    loop {
        if let Some(remaining) = tail.cancellation(signals.interrupted(), Instant::now())? {
            // The original child and domain stay retained until this explicit
            // abandonment; this outcome cannot carry a retirement token.
            return Ok(OriginalRootDrain::Cancelled {
                malformed: drain.malformed(),
                remaining,
            });
        }
        match drain.poll_root_tail(&mut tail, crate::events::LIVE_POLL_QUANTUM, |ev| {
            reduce(domain, ev)
        })? {
            crate::events::RootTailProgress::Reached => {
                if let Some(remaining) = tail.cancellation(signals.interrupted(), Instant::now())? {
                    return Ok(OriginalRootDrain::Cancelled {
                        malformed: drain.malformed(),
                        remaining,
                    });
                }
                return Ok(OriginalRootDrain::Completed {
                    malformed: drain.malformed(),
                    tail: Box::new(tail.complete()?),
                });
            }
            crate::events::RootTailProgress::Yielded => {}
            crate::events::RootTailProgress::Pending => {
                std::thread::sleep(Duration::from_millis(1))
            }
        }
    }
}

/// The existing profile and trace finalization paths share this root-error gate.
fn terminal_after_root<T>(
    root: Result<OriginalRootDrain>,
    diagnostics: &mut dyn Write,
    finalize: impl FnOnce((u64, Option<crate::events::ConsumedOriginalRootTail>)) -> Result<T>,
) -> Result<T> {
    let (malformed, completed, diagnostic) = match root? {
        OriginalRootDrain::Absent => (0, None, Ok(())),
        OriginalRootDrain::Completed { malformed, tail } => (malformed, Some(*tail), Ok(())),
        OriginalRootDrain::Cancelled {
            malformed,
            remaining,
        } => (
            malformed,
            None,
            writeln!(
                diagnostics,
                "p11scope: root_tail_incomplete: cancelled; remaining={remaining}"
            )
            .context("writing incomplete root-tail diagnostic"),
        ),
    };
    // Even a diagnostic write failure must not hide a concurrent genuine
    // finalization/output error. The existing finalizer owns both output paths.
    match (finalize((malformed, completed)), diagnostic) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(diagnostic)) => {
            Err(error.context(format!("root-tail diagnostic also failed: {diagnostic:#}")))
        }
    }
}

fn observe_fork(
    domain: u64,
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    scope: &Scope,
    ev: &p11scope_ebpf_common::Event,
) -> bool {
    use p11scope_ebpf_common::event_type;
    if !matches!(
        ev.event_type,
        event_type::FORK | event_type::FORK_INTO_CGROUP
    ) {
        return false;
    }
    // System scope admits fork children exactly like cgroup scope: the whole
    // machine is in scope, so no destination check can fail.
    let multi_scope = matches!(scope, Scope::Cgroup { .. } | Scope::System);
    if ev.root_affiliation == 0 && (ev.event_type == event_type::FORK_INTO_CGROUP || !multi_scope) {
        return true;
    }
    let parent_pid = (ev.pid_tgid >> 32) as u32;
    if !state.accepts_domain(domain)
        || parent_pid == 0
        || ev.session == 0
        || ev.session > u64::from(u32::MAX)
        || ev.session as u32 == parent_pid
        || ev.image.task_cookie == 0
        || ev.child_image.task_cookie == 0
        || ev.image.task_cookie == ev.child_image.task_cookie
    {
        state.reject_history(ev);
        return true;
    }
    let (parent, retired) = tracker.admit_history(domain, (ev.pid_tgid >> 32) as u32, ev.image);
    for old in retired {
        state.retire_process(old);
    }
    if let Some(parent) = parent {
        tracker.history_root(parent, ev.root_affiliation);
    }
    if ev.event_type == event_type::FORK_INTO_CGROUP || !multi_scope {
        return true;
    }
    let (child, retired) = tracker.admit_history(domain, ev.session as u32, ev.child_image);
    for old in retired {
        state.retire_process(old);
    }
    if let (Some(parent), Some(child)) = (parent, child) {
        if tracker.history_birth(parent, child) {
            state.fork_process(parent, child);
            return true;
        }
    }
    state.reject_history(ev);
    true
}

fn initial_tracking_evidence(
    scope: &Scope,
    process_creation_tracking_unavailable: bool,
    lifecycle_tracking_unavailable: bool,
) -> bool {
    match scope {
        Scope::Pid(_) => lifecycle_tracking_unavailable,
        Scope::Cgroup { .. } | Scope::System => {
            process_creation_tracking_unavailable || lifecycle_tracking_unavailable
        }
    }
}

/// One tick's discovery step, and the one place the pause policy changes the
/// capture cadence.
///
/// `pause=never` — and any explicit policy that could not (or may no longer)
/// arm — keeps the existing refresh cadence through `Engine::drain_discovery`.
/// An ARMED explicit pause instead delegates to the coordinator, whose own
/// 1 ms bounded loop owns the window; it returns to this loop only after owner
/// closure, and the caller does not sleep while an owner is open, so an
/// accepted stop is never slept through.
///
/// Each drain owns its taken map handle for the duration of the call and
/// returns it before the caller does anything else: there is never a second
/// simultaneous ring reader, and no thread, channel, epoll, or async runtime
/// is involved.
fn drain_discovery_tick(
    engine: &mut Engine,
    session: &mut Session,
    owned: Option<&mut Owned>,
    interrupted: &SignalState,
) -> Result<(bool, bool)> {
    let Some(owned) = owned else {
        return Ok((engine.drain_discovery(session)?, false));
    };
    if owned.policy == cli::PausePolicy::Never {
        return Ok((engine.drain_discovery(session)?, false));
    }
    let serviced = {
        let marker = marker_never_seen();
        let cancelled = cancelled_by(interrupted);
        let child = owned
            .child
            .as_ref()
            .expect("the owned child is retained until finalization");
        let mut io = SessionPauseIo::new(engine, session, child, &marker, &cancelled);
        // Re-arming is idempotent while the epoch is open and refused once the
        // coordinator has retired the policy, which is exactly when the
        // ordinary cadence takes over again.
        match owned.coordinator.arm(&mut io) {
            Ok(ArmResult::Disabled) => Ok(None),
            Ok(ArmResult::Armed) => owned
                .coordinator
                .service(&mut io)
                .map(|()| Some(io.plan_changed())),
            Err(error) => Err(error),
        }
    };
    match serviced {
        Ok(Some(changed)) => Ok((changed, true)),
        Ok(None) => Ok((engine.drain_discovery(session)?, false)),
        Err(error) => {
            retire_pause_policy(error)?;
            Ok((engine.drain_discovery(session)?, false))
        }
    }
}

/// `auto` is explicit best effort: a nonfatal coordinator failure has already
/// retired the policy and accounted itself as one partial attempt, so the
/// capture continues on the ordinary cadence and renders `pause: partial`
/// rather than failing. A required (`always`) or lifecycle failure is never
/// downgraded that way — it stops the command after safe cleanup (§10.3).
fn retire_pause_policy(error: PauseError) -> Result<()> {
    if error.required() || error.lifecycle() {
        return Err(pause_failure(error));
    }
    // The pause error chain can quote discovery-batch application failures,
    // which handle target-named records; escape at this terminal boundary too.
    eprintln!(
        "p11scope: pause: {}; the capture continues unpaused and reports pause: partial",
        render::escape_controls(&error.to_string())
    );
    Ok(())
}

/// Classifies the first terminal condition observed on a capture tick. Signal
/// wins over duration or target exit when both become visible together.
fn capture_end(
    engine: &Engine,
    owned: Option<&Owned>,
    interrupted: &SignalState,
    elapsed: Duration,
    duration: Option<Duration>,
) -> Result<Option<CaptureEnd>> {
    if interrupted.interrupted() {
        return Ok(Some(CaptureEnd::Signal));
    }
    let original_exited = owned
        .and_then(|owned| owned.child.as_ref())
        .map(|child| child.pin().original_exited().map_err(anyhow::Error::msg))
        .transpose()?
        .unwrap_or(false);
    Ok(if original_exited || engine.expected_target_exit() {
        Some(CaptureEnd::TargetExit)
    } else if should_stop(interrupted, elapsed, duration) {
        Some(CaptureEnd::DurationExpired)
    } else {
        None
    })
}

/// How long to wait before the next tick. An open pause owner replaces the
/// ordinary refresh cadence with the coordinator's own bounded cycle, so a
/// stopped child is serviced in milliseconds instead of waiting out a frame.
fn tick_sleep(paused: bool, cadence: Duration) {
    std::thread::sleep(if paused {
        Duration::from_millis(1)
    } else {
        cadence
    });
}

const PROFILE_CADENCE: Duration = Duration::from_secs(1);
const TRACE_CADENCE: Duration = Duration::from_millis(200);
const DEFAULT_TRACE_MAX_EVENTS: u64 = 10_000_000;

fn resolve_trace_max_events(max_events: Option<u64>) -> u64 {
    max_events.unwrap_or(DEFAULT_TRACE_MAX_EVENTS)
}

fn resolve_drain_cadence(kind: Kind, drain_interval: Option<Duration>) -> Duration {
    drain_interval.unwrap_or(match kind {
        Kind::Profile => PROFILE_CADENCE,
        Kind::Trace => TRACE_CADENCE,
    })
}

pub(crate) fn resolve_ring_bytes(ring_bytes: Option<u32>) -> u32 {
    ring_bytes.unwrap_or(p11scope_ebpf_common::RING_BYTES)
}

struct CaptureConsumers<'state> {
    state: &'state mut semantics::State,
    tracker: &'state mut process::Tracker,
    tracer: Option<&'state mut trace::Tracer>,
    malformed_records: &'state mut u64,
}

type ProfileTickContext<'tick, 'owned> = (
    &'tick mut Engine,
    &'tick mut Session,
    &'tick mut Option<&'owned mut Owned>,
);

type ProfileTerminalContext<
    'engine,
    'session,
    'owned_ref,
    'owned,
    'stdout_ref,
    'stdout_object,
    'stdout_open,
    'output,
> = (
    &'engine mut Engine,
    &'session mut Session,
    &'owned_ref mut Option<&'owned mut Owned>,
    &'stdout_ref mut (dyn Write + 'stdout_object),
    &'stdout_open mut bool,
    &'output mut Option<AtomicFile>,
);

type TraceTickContext<
    'engine,
    'session,
    'owned_ref,
    'owned,
    'remaining,
    'loss,
    'stdout_ref,
    'stdout_object,
    'stdout_open,
    'out_file,
> = (
    &'engine mut Engine,
    &'session mut Session,
    &'owned_ref mut Option<&'owned mut Owned>,
    &'remaining mut Option<u64>,
    &'loss mut u64,
    &'stdout_ref mut (dyn Write + 'stdout_object),
    &'stdout_open mut bool,
    &'out_file mut Option<std::fs::File>,
);

#[derive(Debug)]
enum CaptureTick<T> {
    Continue { paused: bool, snapshot: T },
    End(CaptureEnd),
}

fn capture_tick_with<'state, C, T>(
    context: &mut C,
    consumers: &mut CaptureConsumers<'state>,
    discovery: impl for<'tick> FnOnce(
        &'tick mut C,
    ) -> Result<(bool, bool, &'tick crate::plan::AttachPlan)>,
    end: impl FnOnce(&mut C) -> Result<Option<CaptureEnd>>,
    drain: impl FnOnce(&mut C, &mut CaptureConsumers<'state>) -> Result<Option<CaptureEnd>>,
    snapshot: impl FnOnce(&mut C, &CaptureConsumers<'state>) -> Result<T>,
    check: impl FnOnce(&mut C) -> Result<()>,
) -> Result<CaptureTick<T>> {
    let paused = {
        let (plan_changed, paused, plan) = discovery(context)?;
        if plan_changed {
            consumers.state.sync_plan(plan);
            if let Some(tracer) = consumers.tracer.as_deref_mut() {
                tracer.sync_plan(plan);
            }
        }
        paused
    };
    if let Some(end) = end(context)? {
        return Ok(CaptureTick::End(end));
    }
    if let Some(end) = drain(context, consumers)? {
        return Ok(CaptureTick::End(end));
    }
    let snapshot = snapshot(context, consumers)?;
    check(context)?;
    Ok(CaptureTick::Continue { paused, snapshot })
}

fn finish_capture_with<C, T>(
    context: &mut C,
    loop_result: Result<CaptureEnd>,
    finish: impl FnOnce(&mut C, Result<CaptureEnd>) -> Result<CaptureEnd>,
    detach: impl FnOnce(&mut C) -> Result<()>,
    terminal: impl FnOnce(&mut C, CaptureEnd, bool) -> Result<T>,
) -> Result<T> {
    let end = finish(context, loop_result)?;
    let detach_result = detach(context);
    let terminal_result = terminal(context, end, detach_result.is_ok());
    combine_detach(terminal_result, detach_result)
}

// Explicit phase callbacks keep the terminal sequence visible at each caller.
#[allow(clippy::too_many_arguments)]
fn drain_capture_terminal_with<'state, C, T>(
    context: &mut C,
    consumers: &mut CaptureConsumers<'state>,
    detached: bool,
    diagnostics: &mut dyn Write,
    discovery: impl for<'phase> FnOnce(
        &'phase mut C,
        bool,
    ) -> Result<(bool, &'phase crate::plan::AttachPlan)>,
    root: impl FnOnce(
        &mut C,
        &mut CaptureConsumers<'state>,
    ) -> (Result<OriginalRootDrain>, Option<anyhow::Error>),
    drain: impl FnOnce(&mut C, &mut CaptureConsumers<'state>) -> Result<()>,
    snapshot_and_publish: impl FnOnce(&mut C, &CaptureConsumers<'state>) -> Result<T>,
) -> Result<T> {
    {
        let (plan_changed, plan) = discovery(context, detached)?;
        if plan_changed {
            consumers.state.sync_plan(plan);
            if let Some(tracer) = consumers.tracer.as_deref_mut() {
                tracer.sync_plan(plan);
            }
        }
    }
    let (root_result, mut root_write_error) = root(context, consumers);
    let root_result = root_result
        .map_err(|error| combine_trace_errors(Err(error), root_write_error.take()).unwrap_err());
    terminal_after_root(root_result, diagnostics, |(malformed, completed)| {
        *consumers.malformed_records += malformed;
        let retirement = if let Some(completed) = completed {
            apply_original_root_retirement(consumers.tracker, consumers.state, completed)
        } else {
            Ok(())
        };
        combine_trace_errors(retirement, root_write_error)?;
        drain(context, consumers)?;
        snapshot_and_publish(context, consumers)
    })
}

#[allow(clippy::too_many_arguments)]
fn capture_profile(
    engine: &mut Engine,
    session: &mut Session,
    scope: &Scope,
    policy: CapturePolicy,
    duration: Option<Duration>,
    mut output: Option<AtomicFile>,
    interrupted: &SignalState,
    mut owned: Option<&mut Owned>,
    drain: Duration,
    ring_bytes: Option<u32>,
) -> Result<render::Evidence> {
    // Opened by the caller before the attach; published by `commit()` only
    // once the final report is written.
    let has_output = output.is_some();
    let mut stdout_sink = std::io::stdout().lock();
    let stdout: &mut dyn Write = &mut stdout_sink;
    let profile = policy.uses_events();
    let mode = if profile { "profile" } else { "metrics" };

    // Only `--mode profile` decodes the event stream; `--mode metrics` never
    // drains the ring buffer, so it stays the lighter, maps-only level.
    let domain = session.events_domain();
    let mut state = semantics::State::for_capture(engine.plan(), policy, domain.clone());
    let mut process_tracker = process::Tracker::for_producer(domain, 16_384);
    if policy.uses_unsafe_decoders() {
        if let Err(error) = load_mech_shapes(&mut state) {
            return Err(finish_capture_error(
                error,
                engine,
                session,
                owned.as_deref_mut(),
                interrupted,
            ));
        }
    }
    let drain_events = |session: &mut Session,
                        state: &mut semantics::State,
                        tracker: &mut process::Tracker|
     -> Result<u64> {
        select_and_drain_events(session, Session::live_poll_quantum, |session, quantum| {
            let mut drain = session.event_drain()?;
            drain_profile_events(&mut drain, state, tracker, scope, quantum)
        })
    };
    let mut malformed_records: u64 = 0;
    let capture_tracking_degraded = initial_tracking_evidence(
        scope,
        session.process_creation_tracking_unavailable().is_some(),
        session.lifecycle_tracking_unavailable().is_some(),
    );
    let mut stdout_open = true;
    let wall_start = SystemTime::now();
    let clock = Instant::now();
    let mut last_frame = Instant::now() - drain;
    #[rustfmt::skip]
    let loop_result = (|| -> Result<CaptureEnd> {
    loop {
        let elapsed = clock.elapsed();
        let tick = {
            let mut context = (&mut *engine, &mut *session, &mut owned);
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut process_tracker,
                tracer: None,
                malformed_records: &mut malformed_records,
            };
            capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut ProfileTickContext<'_, '_>| {
                    let (plan_changed, paused) = drain_discovery_tick(
                        context.0,
                        context.1,
                        context.2.as_deref_mut(),
                        interrupted,
                    )?;
                    Ok((plan_changed, paused, context.0.plan()))
                },
                |context| capture_end(
                    context.0,
                    context.2.as_deref(),
                    interrupted,
                    elapsed,
                    duration,
                ),
                |context, consumers| {
                    if profile {
                        *consumers.malformed_records += drain_events(
                            context.1,
                            consumers.state,
                            consumers.tracker,
                        )?;
                    }
                    Ok(None)
                },
                |context, _| {
                    let mut kernel_evidence = metrics::kernel_evidence(context.1)?;
                    if !profile {
                        kernel_evidence.ring_loss = 0;
                    }
                    let reports = metrics::read(context.1, context.0.plan())?;
                    Ok((reports, kernel_evidence))
                },
                |context| {
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map(|_| ())
                        .map_err(anyhow::Error::msg)
                },
            )?
        };
        let (paused, (reports, kernel_evidence)) = match tick {
            CaptureTick::Continue { paused, snapshot } => (paused, snapshot),
            CaptureTick::End(end) => break Ok(end),
        };

        if last_frame.elapsed() >= drain {
            last_frame = Instant::now();
            let ev = evidence_for(
                engine,
                engine.capture_facts(),
                session.attached_probes(),
                session.dynamic_per_offset_attached(),
                session.attach_failures(),
                &reports,
                kernel_evidence,
                process_tracker.evidence(),
                malformed_records,
                &state,
                engine.pinned().provider_changed(),
                profile,
                owned.as_deref().map_or_else(Default::default, |owned| owned.coordinator.counters()),
                owned.as_deref().map(|owned| owned.still_running),
                capture_tracking_degraded,
            );
            let frame = render::live(
                &reports,
                &ev,
                elapsed,
                &engine.capture_facts().heading(),
                mode,
                policy,
            );
            write_stdout(
                stdout,
                &mut stdout_open,
                format!("\x1b[2J\x1b[H{frame}").as_bytes(),
            )?;
            flush_stdout(stdout, &mut stdout_open)?;
            if !stdout_open && !has_output {
                break Ok(CaptureEnd::Error);
            }
        }
        tick_sleep(paused, drain);
    }
    })();
    let mut finish_context = (&mut *engine, &mut *session, &mut owned);
    finish_capture_with(
        &mut finish_context,
        loop_result,
        |context, result| {
            finish_capture_loop(
                result,
                context.0,
                context.1,
                context.2.as_deref_mut(),
                interrupted,
            )
        },
        |context| context.1.detach_producers(),
        |context, _end, detached| {
            let mut terminal_context = (
                &mut *context.0,
                &mut *context.1,
                &mut *context.2,
                &mut *stdout,
                &mut stdout_open,
                &mut output,
            );
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut process_tracker,
                tracer: None,
                malformed_records: &mut malformed_records,
            };
            drain_capture_terminal_with(
                &mut terminal_context,
                &mut consumers,
                detached,
                &mut std::io::stderr(),
                |context: &mut ProfileTerminalContext<'_, '_, '_, '_, '_, '_, '_, '_>, detached| {
                    let plan_changed = if detached {
                        context.0.drain_discovery_terminal(context.1)?
                    } else {
                        context.0.drain_discovery_terminal_bounded_from(context.1)?
                    };
                    Ok((plan_changed, context.0.plan()))
                },
                |context, consumers| {
                    if profile {
                        (
                            drain_original_root_events(
                                context.1,
                                context.2.as_deref_mut(),
                                interrupted,
                                |domain, event| {
                                    reduce_profile_event(
                                        domain,
                                        consumers.tracker,
                                        consumers.state,
                                        scope,
                                        event,
                                    )
                                },
                            ),
                            None,
                        )
                    } else {
                        (Ok(OriginalRootDrain::Absent), None)
                    }
                },
                |context, consumers| {
                    if profile {
                        *consumers.malformed_records +=
                            drain_events(context.1, consumers.state, consumers.tracker)?;
                    }
                    Ok(())
                },
                |context, consumers| {
                    let reports = metrics::read(context.1, context.0.plan())?;
                    let mut kernel_evidence = metrics::kernel_evidence(context.1)?;
                    if !profile {
                        kernel_evidence.ring_loss = 0;
                    }
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map_err(anyhow::Error::msg)?;
                    context.0.settle_terminal_drain();
                    let mut ev = evidence_for(
                        context.0,
                        context.0.capture_facts(),
                        context.1.attached_probes(),
                        context.1.dynamic_per_offset_attached(),
                        context.1.attach_failures(),
                        &reports,
                        kernel_evidence,
                        consumers.tracker.evidence(),
                        *consumers.malformed_records,
                        consumers.state,
                        context.0.pinned().provider_changed(),
                        profile,
                        context
                            .2
                            .as_deref()
                            .map_or_else(Default::default, |owned| owned.coordinator.counters()),
                        context.2.as_deref().map(|owned| owned.still_running),
                        capture_tracking_degraded,
                    );
                    ev.mark_terminal_drain_unproven();
                    let facts = context.0.capture_facts();
                    let frame = render::live(
                        &reports,
                        &ev,
                        clock.elapsed(),
                        &facts.heading(),
                        mode,
                        policy,
                    );
                    write_stdout(
                        context.3,
                        context.4,
                        format!("\x1b[2J\x1b[H{frame}").as_bytes(),
                    )?;
                    flush_stdout(context.3, context.4)?;

                    if let Some(mut out_file) = context.5.take() {
                        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
                            .unwrap_or_default()
                            .trim()
                            .to_string();
                        let started = fmt_rfc3339(wall_start);
                        let ended = fmt_rfc3339(SystemTime::now());
                        let capture = render::CaptureMeta {
                            started: &started,
                            ended: &ended,
                            kernel: &kernel,
                            policy,
                            scope: scope.kind(),
                            ring_bytes: resolve_ring_bytes(ring_bytes),
                            drain_interval_ms: drain.as_millis() as u64,
                        };
                        let j = if profile {
                            render::profile_json(&reports, &ev, consumers.state, &capture)
                        } else {
                            render::json(&reports, &ev, &capture)
                        };
                        write_json_report(out_file.file(), &j)?;
                        out_file.commit().map_err(anyhow::Error::msg)?;
                    }
                    Ok(ev)
                },
            )
        },
    )
}

/// Writes the `-o` report — the same call whether the loop above it
/// exited because `--duration` elapsed or because SIGINT set
/// `interrupted`: finalization does not know or care which. Factored out
/// so that fact is directly testable without standing up a real attach session.
fn write_json_report(file: &mut std::fs::File, j: &serde_json::Value) -> Result<()> {
    file.set_len(0).context("truncating profile output")?;
    file.seek(SeekFrom::Start(0))
        .context("seeking profile output")?;
    serde_json::to_writer_pretty(&mut *file, j).context("writing profile output")?;
    file.flush().context("flushing profile output")?;
    file.sync_all().context("syncing profile output")
}

/// `p11scope trace`: one line per completed call, printed as it arrives,
/// instead of `profile`'s periodic aggregate frame. A separate
/// subcommand rather than a `--mode` — its transport (drain-and-print
/// every tick, no periodic full-screen redraw) and time-bounding differ
/// enough that folding it into `profile`'s loop would tangle both.
#[allow(clippy::too_many_arguments)]
fn capture_trace(
    engine: &mut Engine,
    session: &mut Session,
    scope: &Scope,
    policy: CapturePolicy,
    duration: Option<Duration>,
    max_events: Option<u64>,
    out: Option<std::fs::File>,
    interrupted: &SignalState,
    mut owned: Option<&mut Owned>,
    drain: Duration,
) -> Result<render::Evidence> {
    let trace_limit = resolve_trace_max_events(max_events);
    let mut remaining = Some(trace_limit);
    // A line stream, not a published artifact: opened by the caller before the
    // attach, then appended to as lines arrive.
    let mut out_sink = out;
    let out_file = &mut out_sink;
    let mut stdout_sink = std::io::stdout().lock();
    let stdout: &mut dyn Write = &mut stdout_sink;

    let domain = session.events_domain();
    let mut state = semantics::State::for_capture(engine.plan(), policy, domain.clone());
    let mut process_tracker = process::Tracker::for_producer(domain, 16_384);
    if policy.uses_unsafe_decoders()
        && let Err(error) = load_mech_shapes(&mut state)
    {
        return Err(finish_capture_error(
            error,
            engine,
            session,
            owned.as_deref_mut(),
            interrupted,
        ));
    }
    let mut tracer = trace::Tracer::new(engine.plan());

    let mut stdout_open = true;
    let mut malformed_records: u64 = 0;
    let capture_tracking_degraded = initial_tracking_evidence(
        scope,
        session.process_creation_tracking_unavailable().is_some(),
        session.lifecycle_tracking_unavailable().is_some(),
    );
    let mut last_reported_loss: u64 = 0;
    if let Err(error) = emit_trace_line(
        &trace::capture_line(policy),
        stdout,
        &mut stdout_open,
        out_file,
    ) {
        return Err(finish_capture_error(
            error,
            engine,
            session,
            owned.as_deref_mut(),
            interrupted,
        ));
    }
    let clock = Instant::now();
    #[rustfmt::skip]
    let loop_result = (|| -> Result<CaptureEnd> {
    loop {
        let elapsed = clock.elapsed();
        let tick = {
            let mut context = (
                &mut *engine,
                &mut *session,
                &mut owned,
                &mut remaining,
                &mut last_reported_loss,
                &mut *stdout,
                &mut stdout_open,
                &mut *out_file,
            );
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut process_tracker,
                tracer: Some(&mut tracer),
                malformed_records: &mut malformed_records,
            };
            capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut TraceTickContext<
                    '_,
                    '_,
                    '_,
                    '_,
                    '_,
                    '_,
                    '_,
                    '_,
                    '_,
                    '_,
                >| {
                    let (plan_changed, paused) = drain_discovery_tick(
                        context.0,
                        context.1,
                        context.2.as_deref_mut(),
                        interrupted,
                    )?;
                    Ok((plan_changed, paused, context.0.plan()))
                },
                |context| capture_end(
                    context.0,
                    context.2.as_deref(),
                    interrupted,
                    elapsed,
                    duration,
                ),
                |context, consumers| {
                    *consumers.malformed_records += drain_trace_events(
                        context.1,
                        context.3,
                        consumers.state,
                        consumers.tracker,
                        scope,
                        consumers.tracer.as_deref_mut().expect("trace consumer"),
                        context.5,
                        context.6,
                        context.7,
                    )?;
                    Ok((*context.3 == Some(0)).then_some(CaptureEnd::LimitReached))
                },
                |context, _| {
                    report_trace_loss(
                        context.1,
                        context.4,
                        context.5,
                        context.6,
                        context.7,
                    )
                },
                |context| {
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map(|_| ())
                        .map_err(anyhow::Error::msg)
                },
            )?
        };
        let paused = match tick {
            CaptureTick::Continue { paused, snapshot: () } => paused,
            CaptureTick::End(end) => break Ok(end),
        };
        flush_stdout(stdout, &mut stdout_open)?;
        if let Some(f) = out_file.as_mut() {
            f.flush().context("flushing trace output file")?;
        }
        if !stdout_open && out_file.is_none() {
            break Ok(CaptureEnd::Error);
        }
        tick_sleep(paused, drain);
    }
    })();

    let mut finish_context = (&mut *engine, &mut *session, &mut owned);
    finish_capture_with(
        &mut finish_context,
        loop_result,
        |context, result| {
            finish_capture_loop(
                result,
                context.0,
                context.1,
                context.2.as_deref_mut(),
                interrupted,
            )
        },
        |context| context.1.detach_producers(),
        |context, end, detached| {
            let mut terminal_context = (
                &mut *context.0,
                &mut *context.1,
                &mut *context.2,
                &mut remaining,
                &mut last_reported_loss,
                &mut *stdout,
                &mut stdout_open,
                &mut *out_file,
            );
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut process_tracker,
                tracer: Some(&mut tracer),
                malformed_records: &mut malformed_records,
            };
            drain_capture_terminal_with(
                &mut terminal_context,
                &mut consumers,
                detached,
                &mut std::io::stderr(),
                |context: &mut TraceTickContext<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
                 detached| {
                    let plan_changed = if detached {
                        context.0.drain_discovery_terminal(context.1)?
                    } else {
                        context.0.drain_discovery_terminal_bounded_from(context.1)?
                    };
                    Ok((plan_changed, context.0.plan()))
                },
                |context, consumers| {
                    let mut root_write_error = None;
                    let root_result = drain_original_root_events(
                        context.1,
                        context.2.as_deref_mut(),
                        interrupted,
                        |domain, event| {
                            reduce_trace_event(
                                domain,
                                context.3,
                                consumers.state,
                                consumers.tracker,
                                scope,
                                consumers.tracer.as_deref_mut().expect("trace consumer"),
                                context.5,
                                context.6,
                                context.7,
                                &mut root_write_error,
                                event,
                            )
                        },
                    );
                    (root_result, root_write_error)
                },
                |context, consumers| {
                    *consumers.malformed_records += drain_trace_events(
                        context.1,
                        context.3,
                        consumers.state,
                        consumers.tracker,
                        scope,
                        consumers.tracer.as_deref_mut().expect("trace consumer"),
                        context.5,
                        context.6,
                        context.7,
                    )?;
                    Ok(())
                },
                |context, consumers| {
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map_err(anyhow::Error::msg)?;
                    report_trace_loss(context.1, context.4, context.5, context.6, context.7)?;
                    let reports = metrics::read(context.1, context.0.plan())?;
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map_err(anyhow::Error::msg)?;
                    context.0.settle_terminal_drain();
                    let trace_truncated = end == CaptureEnd::LimitReached || *context.3 == Some(0);
                    let mut evidence = evidence_for(
                        context.0,
                        context.0.capture_facts(),
                        context.1.attached_probes(),
                        context.1.dynamic_per_offset_attached(),
                        context.1.attach_failures(),
                        &reports,
                        metrics::kernel_evidence(context.1)?,
                        consumers.tracker.evidence(),
                        *consumers.malformed_records,
                        consumers.state,
                        context.0.pinned().provider_changed(),
                        true,
                        context
                            .2
                            .as_deref()
                            .map_or_else(Default::default, |owned| owned.coordinator.counters()),
                        context.2.as_deref().map(|owned| owned.still_running),
                        capture_tracking_degraded,
                    );
                    evidence.mark_terminal_drain_unproven();
                    if trace_truncated {
                        emit_trace_line(
                            &trace::truncated_line(trace_limit),
                            context.5,
                            context.6,
                            context.7,
                        )?;
                    }
                    emit_trace_terminal(
                        &reports,
                        consumers.tracer.as_deref().expect("trace consumer"),
                        &trace::evidence_line(&evidence, policy, trace_truncated),
                        context.5,
                        context.6,
                        context.7,
                    )?;
                    if *consumers.malformed_records > 0 {
                        eprintln!(
                            "p11scope: {} malformed ring-buffer records discarded this capture",
                            *consumers.malformed_records
                        );
                    }
                    if let Some(file) = context.7.as_mut() {
                        file.flush().context("flushing trace output file")?;
                    }
                    Ok(evidence)
                },
            )
        },
    )
}

fn terminal_trace_count_line(reports: &[metrics::SlotReport], tracer: &trace::Tracer) -> String {
    trace::count_evidence_line(reports, tracer.raw_calls())
}

fn emit_trace_terminal<W: Write>(
    reports: &[metrics::SlotReport],
    tracer: &trace::Tracer,
    evidence_line: &str,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<()> {
    emit_trace_line(
        &terminal_trace_count_line(reports, tracer),
        stdout,
        stdout_open,
        out_file,
    )?;
    emit_trace_line(evidence_line, stdout, stdout_open, out_file)
}

/// Prints (and, if given, appends to the `-o` file) every rendered line.
fn emit_trace_line<W: Write>(
    line: &str,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<()> {
    write_stdout(stdout, stdout_open, format!("{line}\n").as_bytes())?;
    if let Some(f) = out_file {
        writeln!(f, "{line}").context("writing trace output file")?;
    }
    Ok(())
}

fn write_stdout(writer: &mut dyn Write, open: &mut bool, bytes: &[u8]) -> Result<()> {
    if !*open {
        return Ok(());
    }
    match writer.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
            *open = false;
            Ok(())
        }
        Err(error) => Err(error).context("writing stdout"),
    }
}

fn flush_stdout(writer: &mut dyn Write, open: &mut bool) -> Result<()> {
    if !*open {
        return Ok(());
    }
    match writer.flush() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => {
            *open = false;
            Ok(())
        }
        Err(error) => Err(error).context("flushing stdout"),
    }
}

fn emit_bounded_trace_event<W: Write, F: FnOnce() -> String>(
    remaining: &mut Option<u64>,
    render: F,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> (bool, Option<anyhow::Error>) {
    if matches!(*remaining, Some(0)) {
        return (false, None);
    }
    let line = render();
    let error = emit_trace_line(&line, stdout, stdout_open, out_file).err();
    if error.is_none()
        && let Some(remaining) = remaining.as_mut()
    {
        *remaining = (*remaining).saturating_sub(1);
    }
    (true, error)
}

/// One profile poll: `Some(quantum)` on the live ring, `None` once the
/// producers are detached and the drain is finite. Returns the malformed
/// count so far.
fn select_and_drain_events<C, T>(
    context: &mut C,
    select: impl FnOnce(&C) -> Option<usize>,
    drain: impl FnOnce(&mut C, Option<usize>) -> Result<T>,
) -> Result<T> {
    let quantum = select(context);
    drain(context, quantum)
}

fn reduce_profile_event(
    domain: u64,
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    scope: &Scope,
    ev: p11scope_ebpf_common::Event,
) -> Result<()> {
    tracker.check_root_event(domain, ev.root_affiliation)?;
    if !observe_fork(domain, tracker, state, scope, &ev)
        && let Some(process) = identify_tracked(domain, tracker, state, &ev)
    {
        state.observe_process(process, &ev);
    }
    Ok(())
}

fn drain_profile_events<S: crate::events::RecordSource>(
    drain: &mut crate::events::EventDrain<S>,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    scope: &Scope,
    quantum: Option<usize>,
) -> Result<u64> {
    let domain = drain.domain_id();
    let mut failure = None;
    drain.poll(quantum, |ev| {
        if let Err(error) = reduce_profile_event(domain, tracker, state, scope, ev) {
            failure = Some(error);
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(drain.malformed())
}

/// Drains what the ring buffer currently holds — one quantum on the live
/// ring, whole after detach — rendering and emitting one line per completed
/// call. Returns the malformed-record count from this drain, to accumulate at
/// the call site.
#[allow(clippy::too_many_arguments)]
fn drain_trace_events<W: Write>(
    session: &mut Session,
    remaining: &mut Option<u64>,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    scope: &Scope,
    tracer: &mut trace::Tracer,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<u64> {
    select_and_drain_events(session, Session::live_poll_quantum, |session, quantum| {
        let mut drain = session.event_drain()?;
        drain_trace_events_from(
            &mut drain,
            remaining,
            state,
            tracker,
            scope,
            tracer,
            stdout,
            stdout_open,
            out_file,
            quantum,
        )
    })
}

fn combine_trace_errors(reduction: Result<()>, write_error: Option<anyhow::Error>) -> Result<()> {
    match (reduction, write_error) {
        (Ok(()), None) => Ok(()),
        (Err(error), None) | (Ok(()), Some(error)) => Err(error),
        (Err(reduction), Some(output)) => {
            Err(reduction.context(format!("trace output also failed: {output:#}")))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reduce_trace_event<W: Write>(
    domain: u64,
    remaining: &mut Option<u64>,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    scope: &Scope,
    tracer: &mut trace::Tracer,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
    write_error: &mut Option<anyhow::Error>,
    ev: p11scope_ebpf_common::Event,
) -> Result<()> {
    tracker.check_root_event(domain, ev.root_affiliation)?;
    tracer.count_raw_call(&ev);
    if observe_fork(domain, tracker, state, scope, &ev) {
        return Ok(());
    }
    let process = identify_tracked(domain, tracker, state, &ev);
    if write_error.is_some() {
        if let Some(process) = process {
            state.observe_process(process, &ev);
        }
    } else {
        let (emitted, error) = emit_bounded_trace_event(
            remaining,
            || match process {
                Some(process) => tracer.on_event_process(&ev, process, state),
                None => tracer.on_rejected_history(&ev),
            },
            stdout,
            stdout_open,
            out_file,
        );
        *write_error = error;
        if !emitted {
            if let Some(process) = process {
                state.observe_process(process, &ev);
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drain_trace_events_from<S: crate::events::RecordSource, W: Write>(
    drain: &mut crate::events::EventDrain<S>,
    remaining: &mut Option<u64>,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    scope: &Scope,
    tracer: &mut trace::Tracer,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
    quantum: Option<usize>,
) -> Result<u64> {
    let mut write_error = None;
    let mut reduction_error = None;
    let domain = drain.domain_id();
    drain.poll(quantum, |ev| {
        if let Err(error) = reduce_trace_event(
            domain,
            remaining,
            state,
            tracker,
            scope,
            tracer,
            stdout,
            stdout_open,
            out_file,
            &mut write_error,
            ev,
        ) {
            reduction_error = Some(error);
            return ControlFlow::Break(());
        }
        // Live only: the last permitted line ends the capture, and what is
        // still queued waits for the post-detach terminal drain, which reads
        // the ring whole for semantics regardless of the limit.
        if quantum.is_some() && matches!(*remaining, Some(0)) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    });
    combine_trace_errors(reduction_error.map_or(Ok(()), Err), write_error)?;
    Ok(drain.malformed())
}

/// Emits `LOST n events` when the ring buffer's loss counter has grown
/// since the last report — mandatory whenever it is nonzero, so a trace
/// that dropped events never ends silently.
fn report_trace_loss<W: Write>(
    session: &Session,
    last_reported_loss: &mut u64,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<()> {
    let lost = metrics::lost_events(session)?;
    if lost > *last_reported_loss {
        if let Some(line) = trace::lost_line(lost) {
            emit_trace_line(&line, stdout, stdout_open, out_file)?;
        }
        *last_reported_loss = lost;
    }
    Ok(())
}

/// Evidence built from the plan (skips, aliases, surface/vendor gaps), the
/// session (attach failures), the current reports (in-flight count), and
/// (profile mode only — always 0 in metrics mode) the ring-buffer/semantic
/// gap counters. Calls `.verdict()` itself before returning, so callers
/// must not call it again.
#[allow(clippy::too_many_arguments)]
fn evidence_for(
    engine: &Engine,
    facts: render::CaptureFacts,
    attached_probes: usize,
    dynamic_per_offset_attached: bool,
    attach_failures: &[(u32, String)],
    reports: &[metrics::SlotReport],
    kernel_evidence: metrics::KernelEvidence,
    tracking_evidence: process::TrackingEvidence,
    malformed_records: u64,
    state: &semantics::State,
    provider_changed: bool,
    include_selection: bool,
    pause: crate::discovery::pause::PauseCounters,
    child_still_running: Option<bool>,
    capture_tracking_degraded: bool,
) -> render::Evidence {
    let semantic = state.semantic_evidence();
    // The frozen consumer map (plan Task 8 Step 2), in one place:
    //  * metrics and function attribution read the capture aggregate owners
    //    that `reports` already carries;
    //  * semantic attachment decisions read the active topology, which is
    //    `engine.plan()` and is deliberately NOT what evidence is built from;
    //  * final evidence, discovery, and the module heading read the sanitized
    //    capture facts below;
    //  * the coordinator's fields come only from its own finite aggregate.
    // Loader and pause identities are discarded before this point: nothing in
    // `facts` or `pause` can name a process, a path, or a proof.
    let plan = engine.plan();
    // Internal-only, stderr-only, `skip-attribution` builds only: which site
    // raised each record the document is about to publish.
    attribution::report(&plan.skipped);
    let [
        discovery_ring_loss,
        discovery_state_failures,
        discovery_read_failures,
        discovery_truncated,
    ] = facts.discovery_losses();
    let pause_status = pause.status();
    let pid_descendant_gaps = engine.pid_descendant_gaps();
    let mut interface_selection = if include_selection {
        engine.interface_selection()
    } else {
        Default::default()
    };
    if pid_descendant_gaps > 0 {
        interface_selection.mark_descendant_gap();
    }
    let mut ev = render::Evidence {
        table_entries: facts.table_entries(),
        slots: facts.slots(),
        attached_probes,
        attach_failures: attach_failures.iter().map(|(_, msg)| msg.clone()).collect(),
        aliased: plan
            .slots
            .iter()
            .filter(|s| s.aliased)
            .map(|s| s.names.clone())
            .collect(),
        skipped: plan
            .skipped
            .iter()
            .map(render::capture_skipped_out)
            .collect(),
        semantic_unverified_slots: plan
            .slots
            .iter()
            .filter(|slot| !slot.semantic_authorized)
            .count(),
        in_flight_at_end: reports.iter().map(|r| r.in_flight).sum(),
        surfaces: plan.surfaces.clone(),
        vendor_interfaces: plan.vendor_interfaces,
        interface_list: plan.interface_list.clone(),
        event_loss: kernel_evidence.ring_loss,
        start_insert_failures: kernel_evidence.start_insert_failures,
        unmatched_returns: kernel_evidence.unmatched_returns,
        rv_update_failures: kernel_evidence.rv_update_failures,
        abi_refusals: kernel_evidence.abi_refusals,
        cgroup_scope_failures: kernel_evidence.cgroup_scope_failures,
        semantic_capture_failures: kernel_evidence.semantic_capture_failures
            + semantic.semantic_capture_failures,
        unregistered_mechanisms: kernel_evidence.unregistered_mechanisms,
        template_tail_failures: kernel_evidence.template_tail_failures,
        process_tracking_fallbacks: tracking_evidence.fallbacks,
        process_tracking_failures: tracking_evidence
            .failures
            .saturating_add(u64::from(capture_tracking_degraded)),
        process_tracking_evictions: tracking_evidence.evictions,
        state_reconciliations: semantic.state_reconciliations,
        session_cancel_ambiguities: semantic.session_cancel_ambiguities,
        session_cancel_unknown_flags: semantic.session_cancel_unknown_flags,
        operation_state_imports: semantic.operation_state_imports,
        auth_state_ambiguities: semantic.auth_state_ambiguities,
        async_target_failures: semantic.async_target_failures,
        async_orphans: semantic.async_orphans,
        async_duplicates: semantic.async_duplicates,
        async_evictions: semantic.async_evictions,
        fork_state_ambiguities: semantic.fork_state_ambiguities,
        semantic_state_drops: semantic.semantic_state_drops,
        semantic_history_drops: semantic.semantic_history_drops,
        pending_at_end: state.pending_at_end(),
        malformed_records,
        orphan_ops: state.orphan_ops(),
        unmatched_closes: state.unmatched_closes(),
        shape_decode_failures: state.shape_decode_failures(),
        shape_decode_total_failures: state.total_shape_decode_failures(),
        templates_truncated: state.templates_truncated(),
        provider_changed,
        attach_gap_ms: facts.attach_gap_ms(),
        pause: match pause_status {
            PauseStatus::None => "none",
            PauseStatus::Sigstop => "sigstop",
            PauseStatus::Partial => "partial",
        },
        pause_attempts: pause.attempts,
        pause_confirmed: pause.confirmed,
        pause_partial: pause.partial,
        child_still_running,
        discovery_ring_loss,
        discovery_state_failures,
        discovery_read_failures,
        discovery_truncated,
        task_uprobe_link_losses: facts.task_uprobe_link_losses(),
        loader_discovery: facts.loader_discovery(),
        interface_selection,
        attach_mechanisms: if include_selection {
            attach_mechanisms(attached_probes, dynamic_per_offset_attached)
        } else {
            Vec::new()
        },
        pid_descendant_gaps,
        multi_rebuild_gaps: 0,
        // Design §5.7: a live-learned attach key is protected only inside a
        // confirmed pause owner's window. A nonzero debug-state hit counter is
        // what says a live window happened at all; the design forbids
        // publishing a count, so this only gates the verdict.
        unprotected_live_windows: usize::from(
            facts.loader_discovery().hits > 0 && pause_status != PauseStatus::Sigstop,
        ),
        module_unresolved_slots: reports
            .iter()
            .filter(|report| report.module_unresolved)
            .count(),
        discovery: facts.discovery().clone(),
        completeness: "UNKNOWN",
    };
    ev.verdict_with_selection(include_selection);
    ev
}

fn attach_mechanisms(
    attached_probes: usize,
    dynamic_per_offset_attached: bool,
) -> Vec<&'static str> {
    if attached_probes == 0 && !dynamic_per_offset_attached {
        Vec::new()
    } else {
        vec!["per-offset"]
    }
}

/// `SystemTime` → an RFC3339-ish UTC timestamp, no `chrono` dependency.
/// Civil-from-days conversion per Howard Hinnant's `civil_from_days`.
fn fmt_rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

#[cfg(test)]
#[path = "run/capture_loop_tests.rs"]
mod capture_loop_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::fd::{AsFd as _, BorrowedFd};
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static ACTUAL_SIGNAL_TEST: Mutex<()> = Mutex::new(());

    fn spawn(program: &str, args: &[&str]) -> OwnedChild {
        OwnedChild::spawn(
            OsString::from(program),
            args.iter().map(OsString::from).collect(),
        )
        .unwrap()
    }

    fn wait_for_session_leader(child: &OwnedChild) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while unsafe { libc::getsid(child.pid() as libc::pid_t) } != child.pid() as libc::pid_t {
            assert!(
                Instant::now() < deadline,
                "child never entered its private session"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_until(mut predicate: impl FnMut() -> bool, message: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !predicate() {
            assert!(Instant::now() < deadline, "{message}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn duplicate_fd(fd: BorrowedFd<'_>) -> OwnedFd {
        // SAFETY: F_DUPFD_CLOEXEC duplicates the retained live descriptor and
        // returns a separately owned descriptor on success.
        let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
        assert!(
            duplicate >= 0,
            "duplicating the original pidfd: {}",
            io::Error::last_os_error()
        );
        // SAFETY: successful F_DUPFD_CLOEXEC returned a new owned descriptor.
        unsafe { OwnedFd::from_raw_fd(duplicate) }
    }

    fn original_child_is_stopped(pidfd: BorrowedFd<'_>) -> bool {
        // SAFETY: zeroed siginfo_t is the documented waitid output buffer.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: P_PIDFD consumes only the borrowed descriptor value and
        // WNOWAIT observes without consuming the eventual exit status.
        let waited = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
            )
        };
        assert_eq!(
            waited,
            0,
            "observing stopped original child: {}",
            io::Error::last_os_error()
        );
        // SAFETY: waitid initialized the CLD_STOPPED siginfo union fields.
        unsafe {
            info.si_pid() != 0
                && info.si_code == libc::CLD_STOPPED
                && info.si_status() == libc::SIGSTOP
        }
    }

    fn release_for_cancellation_regression(
        child: &mut OwnedChild,
        deadline: Instant,
        signals: &SignalState,
        pending: impl FnMut(),
    ) -> String {
        match child.release_until_with_pending(deadline, || signals.first_signal(), pending) {
            Ok(()) => "exec".into(),
            Err(ExecHandoffError::Exec(error)) => format!("exec-error({})", error.errno),
            Err(ExecHandoffError::Cancelled(signal)) => format!("cancelled({signal})"),
            Err(ExecHandoffError::Deadline) => "deadline".into(),
            Err(ExecHandoffError::Io { phase, source }) => format!("io({phase}: {source})"),
        }
    }

    fn rescue_original_pidfd(fd: i32, rescued: &std::sync::atomic::AtomicBool) -> io::Result<()> {
        rescued.store(true, Ordering::SeqCst);
        // SAFETY: the caller supplies the retained original pidfd; the syscall
        // borrows it only for this exact-child signal operation.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if sent == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[test]
    fn stopped_preexec_release_observes_actual_sigterm_before_rescue() {
        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        let signals = install_stop_flag().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("ran");
        let mut child = spawn("/usr/bin/touch", &[marker.to_str().unwrap()]);
        wait_for_session_leader(&child);
        let rescue_pidfd = duplicate_fd(child.pin().pidfd().unwrap());
        child.pin().send_signal(libc::SIGSTOP).unwrap();
        wait_until(
            || original_child_is_stopped(rescue_pidfd.as_fd()),
            "the original child never entered the stopped pre-exec state",
        );
        assert!(!marker.exists());

        let release_returned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let rescued = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cleanup_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release_returned_for_rescue = Arc::clone(&release_returned);
        let rescued_for_thread = Arc::clone(&rescued);
        let cleanup_done_for_rescue = Arc::clone(&cleanup_done);
        let rescue = std::thread::spawn(move || -> io::Result<()> {
            let release_deadline = Instant::now() + Duration::from_millis(150);
            while !release_returned_for_rescue.load(Ordering::SeqCst)
                && Instant::now() < release_deadline
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            if !release_returned_for_rescue.load(Ordering::SeqCst) {
                rescue_original_pidfd(rescue_pidfd.as_raw_fd(), &rescued_for_thread)?;
            }
            let cleanup_deadline = Instant::now() + Duration::from_secs(2);
            while !cleanup_done_for_rescue.load(Ordering::SeqCst)
                && Instant::now() < cleanup_deadline
            {
                std::thread::sleep(Duration::from_millis(1));
            }
            if !cleanup_done_for_rescue.load(Ordering::SeqCst) {
                rescue_original_pidfd(rescue_pidfd.as_raw_fd(), &rescued_for_thread)?;
            }
            Ok(())
        });

        let (released_tx, released_rx) = std::sync::mpsc::sync_channel(1);
        let (pending_tx, pending_rx) = std::sync::mpsc::sync_channel(1);
        let signals_for_release = Arc::clone(&signals);
        let release_returned_for_thread = Arc::clone(&release_returned);
        let release = std::thread::spawn(move || {
            let result = release_for_cancellation_regression(
                &mut child,
                Instant::now() + Duration::from_secs(1),
                &signals_for_release,
                || {
                    let _ = pending_tx.try_send(());
                },
            );
            release_returned_for_thread.store(true, Ordering::SeqCst);
            released_tx.send((result, child)).unwrap();
        });
        pending_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("release never reached the actual exec-reader pending boundary");
        // SAFETY: SIGTERM is handled by the installed atomic-only handler.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        let (result, mut child) = released_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("release did not return even after retained-pidfd rescue");
        assert_eq!(signals.first_signal(), Some(libc::SIGTERM));
        let exit = settle_after_signal_with_grace(&mut child, &signals, Duration::from_millis(20))
            .expect("settling the exact original child after release cancellation");
        cleanup_done.store(true, Ordering::SeqCst);
        release.join().unwrap();
        rescue.join().unwrap().unwrap();

        assert!(
            !rescued.load(Ordering::SeqCst),
            "old release loop required retained-original-pidfd rescue; result after rescue was {result}"
        );
        assert_eq!(result, "cancelled(15)");
        assert_eq!(exit, ChildOutcome::Exited(128 + libc::SIGKILL));
        assert!(child.is_reaped());
        assert!(!marker.exists());
    }

    #[test]
    fn rescue_accounting_precedes_and_retains_signal_failure() {
        let rescued = std::sync::atomic::AtomicBool::new(false);
        let error = rescue_original_pidfd(-1, &rescued).unwrap_err();
        assert!(rescued.load(Ordering::SeqCst));
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn pending_cancellation_never_releases_the_owned_command() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("ran");
        let mut child = spawn("/usr/bin/touch", &[marker.to_str().unwrap()]);
        let signals = SignalState::new();
        signals.observe(libc::SIGINT);

        assert!(matches!(
            child.release_until(Instant::now() + Duration::from_secs(1), || signals
                .first_signal()),
            Err(ExecHandoffError::Cancelled(libc::SIGINT))
        ));
        let exit = child
            .terminate_with_grace(Duration::from_millis(20))
            .unwrap();

        assert!([127, 128 + libc::SIGTERM, 128 + libc::SIGKILL].contains(&exit));
        assert!(child.is_reaped());
        assert!(!child.released);
        assert!(!marker.exists());
        assert!(child.hand_off_running().is_err());
    }

    #[test]
    fn stopped_preexec_handoff_deadline_is_independent_and_settles_exact_child() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("ran");
        let mut child = spawn("/usr/bin/touch", &[marker.to_str().unwrap()]);
        wait_for_session_leader(&child);
        child.pin().send_signal(libc::SIGSTOP).unwrap();
        wait_until(
            || original_child_is_stopped(child.pin().pidfd().unwrap()),
            "the original child never stopped behind the barrier",
        );
        let started = Instant::now();
        assert!(matches!(
            child.release_until(started + Duration::from_millis(40), || None),
            Err(ExecHandoffError::Deadline)
        ));
        assert!(started.elapsed() < Duration::from_millis(500));
        assert!(!child.released);
        assert!(child.hand_off_running().is_err());

        assert_eq!(
            child
                .terminate_with_grace(Duration::from_millis(20))
                .unwrap(),
            128 + libc::SIGKILL
        );
        assert!(child.is_reaped());
        assert!(!marker.exists());
    }

    #[test]
    fn actual_handoff_helpers_preserve_errno_and_retry_without_renewing_deadlines() {
        let mut interrupted_reads = 0;
        let mut interrupted_bytes = [0u8; 4];
        let mut interrupted_used = 0;
        assert!(matches!(
            drain_exec_with(&mut interrupted_bytes, &mut interrupted_used, |_| {
                interrupted_reads += 1;
                if interrupted_reads > 1 {
                    panic!("read EINTR retried without returning to the bounded loop");
                }
                Err(io::Error::from_raw_os_error(libc::EINTR))
            })
            .unwrap(),
            ExecDrain::Pending
        ));
        for attempt in 0..3 {
            assert!(matches!(
                drain_exec_with(&mut interrupted_bytes, &mut interrupted_used, |_| Err(
                    io::Error::from_raw_os_error(libc::EINTR)
                ),)
                .unwrap(),
                ExecDrain::Pending
            ));
            let polled = poll_handoff_with(
                Instant::now() + Duration::from_secs(1),
                || (attempt == 2).then_some(libc::SIGTERM),
                |_| Ok([libc::POLLIN, 0]),
            );
            if attempt == 2 {
                assert!(matches!(
                    polled,
                    Err(ExecHandoffError::Cancelled(libc::SIGTERM))
                ));
            } else {
                assert_eq!(polled.unwrap(), [libc::POLLIN, 0]);
            }
        }

        let errno = libc::EACCES.to_ne_bytes();
        let mut reads = std::collections::VecDeque::from([
            Err(io::Error::from_raw_os_error(libc::EINTR)),
            Ok(errno[..2].to_vec()),
            Err(io::Error::from_raw_os_error(libc::EAGAIN)),
            Ok(errno[2..].to_vec()),
        ]);
        let mut bytes = [0u8; 4];
        let mut used = 0;
        let mut read = |buffer: &mut [u8]| match reads.pop_front().unwrap() {
            Ok(data) => {
                buffer[..data.len()].copy_from_slice(&data);
                Ok(data.len())
            }
            Err(error) => Err(error),
        };
        assert!(matches!(
            drain_exec_with(&mut bytes, &mut used, &mut read).unwrap(),
            ExecDrain::Pending
        ));
        assert!(matches!(
            drain_exec_with(&mut bytes, &mut used, &mut read).unwrap(),
            ExecDrain::Pending
        ));
        assert!(matches!(
            drain_exec_with(&mut bytes, &mut used, &mut read).unwrap(),
            ExecDrain::Errno(libc::EACCES)
        ));

        let mut partial = [0u8; 4];
        let mut partial_used = 0;
        let mut reads = std::collections::VecDeque::from([vec![1], Vec::new()]);
        let error = drain_exec_with(&mut partial, &mut partial_used, |buffer| {
            let data = reads.pop_front().unwrap();
            buffer[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        })
        .unwrap_err();
        assert!(matches!(
            error,
            ExecHandoffError::Io {
                phase: "exec protocol",
                source
            } if source.kind() == io::ErrorKind::UnexpectedEof
        ));

        let mut writes = 0;
        write_release_with(
            Instant::now() + Duration::from_secs(1),
            || None,
            || {
                writes += 1;
                if writes < 3 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok(1)
                }
            },
        )
        .unwrap();
        assert_eq!(writes, 3);

        let mut polls = 0;
        assert_eq!(
            poll_handoff_with(
                Instant::now() + Duration::from_secs(1),
                || None,
                |_| {
                    polls += 1;
                    if polls < 3 {
                        Err(io::Error::from_raw_os_error(libc::EINTR))
                    } else {
                        Ok([libc::POLLIN, 0])
                    }
                },
            )
            .unwrap(),
            [libc::POLLIN, 0]
        );
        assert_eq!(polls, 3);

        let deadline = Instant::now() + Duration::from_millis(2);
        let error = poll_handoff_with(
            deadline,
            || None,
            |_| Err(io::Error::from_raw_os_error(libc::EINTR)),
        )
        .unwrap_err();
        assert!(matches!(error, ExecHandoffError::Deadline));
        assert!(Instant::now() < deadline + Duration::from_millis(100));

        assert!(matches!(
            write_release_with(
                Instant::now() + Duration::from_secs(1),
                || Some(libc::SIGTERM),
                || panic!("pending cancellation wrote the barrier")
            ),
            Err(ExecHandoffError::Cancelled(libc::SIGTERM))
        ));

        let mut reaps = 0;
        assert_eq!(
            retry_reap_with(Some(Instant::now() + Duration::from_secs(1)), || {
                reaps += 1;
                if reaps < 3 {
                    Err(io::Error::from_raw_os_error(libc::EINTR))
                } else {
                    Ok(Some(137))
                }
            })
            .unwrap(),
            Some(137)
        );
        assert_eq!(reaps, 3);
        assert_eq!(
            retry_reap_with(Some(Instant::now() + Duration::from_secs(1)), || {
                Err(io::Error::from_raw_os_error(libc::ECHILD))
            })
            .unwrap_err()
            .raw_os_error(),
            Some(libc::ECHILD)
        );
        let reap_deadline = Instant::now() + Duration::from_millis(2);
        assert_eq!(
            retry_reap_with(Some(reap_deadline), || {
                Err(io::Error::from_raw_os_error(libc::EINTR))
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(Instant::now() < reap_deadline + Duration::from_millis(100));
    }

    #[test]
    fn exact_exit_races_reap_through_the_original_pidfd() {
        let deadline = Some(Instant::now() + Duration::from_secs(1));
        assert_eq!(
            initial_settlement_probe_with(
                Ok(None),
                Some(Err(io::Error::other("generation changed after exit"))),
                deadline,
                || Ok(Some(23)),
            )
            .unwrap(),
            Some(23)
        );
        assert_eq!(
            initial_signal_forward_with(
                Err(io::Error::other("group vanished before initial signal")),
                deadline,
                || Ok(Some(143)),
            )
            .unwrap(),
            Some(143)
        );

        let unresolved = initial_settlement_probe_with(
            Ok(None),
            Some(Err(io::Error::other("generation still unresolved"))),
            deadline,
            || Ok(None),
        )
        .unwrap_err();
        assert_eq!(unresolved.to_string(), "generation still unresolved");

        let combined = initial_signal_forward_with(
            Err(io::Error::other("initial signal still unresolved")),
            deadline,
            || Err(io::Error::from_raw_os_error(libc::ECHILD)),
        )
        .unwrap_err();
        let rendered = combined.to_string();
        assert!(
            rendered.contains("initial signal still unresolved"),
            "{rendered}"
        );
        assert!(rendered.contains("exact original-child reap"), "{rendered}");
    }

    #[test]
    fn preflight_failure_detaches_before_settlement_and_keeps_every_error() {
        let order = std::sync::Mutex::new(Vec::new());
        let error = combine_preflight_failure_with(
            anyhow!("preflight failed"),
            || {
                order.lock().unwrap().push("detach");
                Err(anyhow!("detach failed"))
            },
            || {
                order.lock().unwrap().push("settle");
                Err(anyhow!("settlement failed"))
            },
        );

        assert_eq!(*order.lock().unwrap(), ["detach", "settle"]);
        let rendered = format!("{error:#}");
        assert!(rendered.contains("preflight failed"), "{rendered}");
        assert!(rendered.contains("detach failed"), "{rendered}");
        assert!(rendered.contains("settlement failed"), "{rendered}");
    }

    #[test]
    fn attach_failure_diagnostics_escape_target_controls() {
        let message = format_attach_failure(3, "p11_hook at /opt/p\u{1b}[2Jevil\r.so+0x10: EPERM");
        assert_eq!(
            message,
            r"attach failed (slot 3): p11_hook at /opt/p\u{1b}[2Jevil\r.so+0x10: EPERM"
        );
        assert!(!message.contains('\u{1b}') && !message.contains('\r'));
    }

    #[test]
    fn total_attach_refusal_summary_escapes_target_controls() {
        let message = format_total_attach_refusal(2, 2, "at /opt/p\u{1b}[2Jevil\r.so: EPERM");
        assert!(message.starts_with("p11scope: 2/2 attach attempts failed"));
        assert!(message.ends_with(r"First underlying error: at /opt/p\u{1b}[2Jevil\r.so: EPERM"));
        assert!(!message.contains('\u{1b}') && !message.contains('\r'));
    }

    #[test]
    fn forked_child_is_a_session_leader_and_exec_waits_for_the_private_barrier() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("ran");
        let mut child = spawn(
            "/bin/sh",
            &["-c", &format!("printf ran > {}", marker.display())],
        );

        wait_for_session_leader(&child);
        std::thread::sleep(Duration::from_millis(10));
        assert!(
            !marker.exists(),
            "the command crossed the private barrier early"
        );
        assert_ne!(child.generation().get(), 0);
        child.pin().probe_signal_authority().unwrap();

        child.release().unwrap();
        assert_eq!(
            child.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(0)
        );
        assert_eq!(std::fs::read_to_string(marker).unwrap(), "ran");
    }

    #[test]
    fn owned_child_execs_with_no_new_privileges() {
        let directory = tempfile::tempdir().unwrap();
        let status = directory.path().join("status");
        let mut child = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!("cat /proc/self/status > {}", status.display()),
            ],
        );

        child.release().unwrap();
        assert_eq!(
            child.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(0)
        );
        let status = std::fs::read_to_string(status).unwrap();
        assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
        for capability in ["CapInh", "CapPrm", "CapEff", "CapAmb"] {
            assert!(
                status
                    .lines()
                    .any(|line| line == format!("{capability}:\t0000000000000000")),
                "owned child retained {capability}"
            );
        }
    }

    #[test]
    fn owned_child_identity_is_the_invoking_user_and_never_implicit_root() {
        let nonroot = ChildIdentity::from_ids(
            [1000; 3],
            [1001; 3],
            Some(OsStr::new("not-an-id")),
            Some(OsStr::new("also-not-an-id")),
        )
        .unwrap();
        assert_eq!(
            nonroot,
            ChildIdentity {
                uid: 1000,
                gid: 1001,
                clear_groups: false,
            }
        );

        let sudo = ChildIdentity::from_ids(
            [0; 3],
            [0; 3],
            Some(OsStr::new("1000")),
            Some(OsStr::new("1001")),
        )
        .unwrap();
        assert_eq!(
            sudo,
            ChildIdentity {
                uid: 1000,
                gid: 1001,
                clear_groups: true,
            }
        );

        assert!(ChildIdentity::from_ids([0; 3], [0; 3], None, None).is_err());
        assert!(
            ChildIdentity::from_ids(
                [0; 3],
                [0; 3],
                Some(OsStr::new("+1000")),
                Some(OsStr::new("1000")),
            )
            .is_err()
        );
        assert!(
            ChildIdentity::from_ids(
                [0; 3],
                [0; 3],
                Some(OsStr::new("0")),
                Some(OsStr::new("1000")),
            )
            .is_err()
        );
        for spoofed in ["", "4294967295", " 1000", "1000 "] {
            assert!(
                ChildIdentity::from_ids(
                    [0; 3],
                    [0; 3],
                    Some(OsStr::new(spoofed)),
                    Some(OsStr::new("1000")),
                )
                .is_err(),
                "spoofed SUDO_UID {spoofed:?} must be refused"
            );
        }
        assert!(
            ChildIdentity::from_ids(
                [1000; 3],
                [0; 3],
                Some(OsStr::new("1000")),
                Some(OsStr::new("1000")),
            )
            .is_err()
        );
        assert!(
            ChildIdentity::from_ids(
                [1000, 0, 0],
                [1000; 3],
                Some(OsStr::new("1000")),
                Some(OsStr::new("1000")),
            )
            .is_err()
        );
    }

    #[test]
    fn privileged_child_environment_is_an_allowlist() {
        let identity = ChildIdentity {
            uid: 1000,
            gid: 1000,
            clear_groups: true,
        };
        let environment = child_environment(
            identity,
            [
                (OsString::from("PATH"), OsString::from("/root/bin")),
                (OsString::from("SSH_AUTH_SOCK"), OsString::from("/secret")),
                (OsString::from("API_TOKEN"), OsString::from("secret")),
                (OsString::from("TERM"), OsString::from("xterm")),
                (
                    OsString::from("SOFTHSM2_CONF"),
                    OsString::from("/tmp/softhsm2.conf"),
                ),
            ],
        )
        .unwrap();
        let environment: Vec<_> = environment
            .iter()
            .map(|entry| entry.to_str().unwrap())
            .collect();
        assert_eq!(
            environment,
            [
                "PATH=/usr/bin:/bin",
                "LANG=C",
                "LC_ALL=C",
                "TERM=xterm",
                "SOFTHSM2_CONF=/tmp/softhsm2.conf",
            ]
        );
    }

    #[test]
    fn owned_child_executes_the_opened_inode_after_path_retarget() {
        let directory = tempfile::tempdir().unwrap();
        let command = directory.path().join("command");
        let replacement = directory.path().join("replacement");
        std::fs::copy("/bin/true", &command).unwrap();
        std::fs::copy("/bin/false", &replacement).unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();

        let mut child = OwnedChild::spawn(command.clone().into_os_string(), Vec::new()).unwrap();
        std::fs::rename(replacement, command).unwrap();
        child.release().unwrap();
        assert_eq!(
            child.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(0)
        );
    }

    #[test]
    fn owned_child_direct_sleep_avoids_multicall_applet_misdispatch() {
        let mut child = spawn("/bin/sleep", &["0"]);
        child.release().unwrap();
        assert_eq!(
            child.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(0)
        );
    }

    #[test]
    fn owned_child_exec_closes_the_launch_descriptor() {
        let executable = std::fs::metadata("/bin/sleep").unwrap();
        let mut child = spawn("/bin/sleep", &["10"]);
        child.release().unwrap();
        assert!(child.still_running(), "sleep exited before fd inspection");

        for descriptor in std::fs::read_dir(format!("/proc/{}/fd", child.pid())).unwrap() {
            let descriptor = descriptor.unwrap();
            let metadata = match descriptor.path().metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => panic!(
                    "inspecting owned child descriptor {}: {error}",
                    descriptor.path().display()
                ),
            };
            assert_ne!(
                (metadata.dev(), metadata.ino()),
                (executable.dev(), executable.ino()),
                "the opened executable descriptor survived exec"
            );
        }
        assert!(child.still_running(), "sleep exited during fd inspection");

        child.terminate_and_reap().unwrap();
    }

    #[test]
    fn owned_child_exec_preserves_no_new_privs() {
        let mut child = spawn("/bin/sleep", &["10"]);
        child.release().unwrap();

        let status = std::fs::read_to_string(format!("/proc/{}/status", child.pid())).unwrap();
        let no_new_privs = status
            .lines()
            .find_map(|line| line.strip_prefix("NoNewPrivs:"))
            .map(str::trim);
        assert_eq!(no_new_privs, Some("1"));

        child.terminate_and_reap().unwrap();
    }

    #[test]
    fn owned_child_does_not_inherit_unrelated_descriptors() {
        let mut fds = [-1; 2];
        // SAFETY: fds points to two writable integers; pipe initializes both.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe returned two distinct owned descriptors.
        let inherited = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("leaked");
        let mut child = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!(
                    "if [ -e /proc/self/fd/{} ]; then printf leaked > {}; fi",
                    inherited.as_raw_fd(),
                    marker.display()
                ),
            ],
        );

        child.release().unwrap();
        assert_eq!(
            child.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(0)
        );
        assert!(!marker.exists(), "owned child inherited an unrelated fd");
    }

    #[test]
    fn exec_errno_exit_status_and_signal_status_are_exact() {
        assert_eq!(
            OwnedChild::spawn("/definitely/missing/p11scope-task7".into(), Vec::new())
                .err()
                .expect("missing executable must be refused before fork")
                .raw_os_error(),
            Some(libc::ENOENT)
        );

        let mut normal = spawn("/bin/sh", &["-c", "exit 23"]);
        normal.release().unwrap();
        assert_eq!(
            normal.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(23)
        );

        let mut signalled = spawn("/bin/sh", &["-c", "kill -TERM $$"]);
        signalled.release().unwrap();
        assert_eq!(
            signalled.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(128 + libc::SIGTERM)
        );
    }

    #[test]
    fn owned_child_launch_errors_preserve_elf_reason_and_script_guidance() {
        let directory = tempfile::tempdir().unwrap();
        let x32 = [
            0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 62, 0, 1, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 52, 0, 32, 0, 0, 0, 40, 0, 0, 0, 0, 0,
        ];
        for (name, bytes) in [
            ("x32", x32.as_slice()),
            ("malformed-elf", b"\x7fELF".as_slice()),
            ("script", b"#!/bin/sh\nexit 0\n".as_slice()),
        ] {
            let command = directory.path().join(name);
            std::fs::write(&command, bytes).unwrap();
            std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
            let reason = ElfSnapshot::read(&File::open(&command).unwrap()).unwrap_err();
            if name == "x32" {
                assert!(reason.contains("x32"), "{reason}");
            }

            let error = OwnedChild::spawn(command.into_os_string(), Vec::new())
                .err()
                .expect("unsupported executable must be refused before fork");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains(&reason), "{name}: {error}");
            if name == "script" {
                assert!(
                    error
                        .to_string()
                        .contains("invoke scripts through an interpreter"),
                    "{error}"
                );
            }
        }
    }

    #[test]
    fn release_error_defers_settlement_for_owned_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let command = directory.path().join("command");
        std::fs::copy("/bin/true", &command).unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = OwnedChild::spawn(command.clone().into_os_string(), Vec::new()).unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o000)).unwrap();

        let failure = child.release().unwrap_err();
        let ExecHandoffError::Exec(failure) = failure else {
            panic!("actual exec failure was misclassified: {failure}");
        };
        assert_eq!(failure.errno, libc::EACCES);
        assert_eq!(failure.exit_code, 127);
        assert!(
            !child.is_reaped(),
            "run-owned release errors must wait for coordinator cleanup before settlement"
        );
    }

    #[test]
    fn duration_handoff_stays_pending_until_finalization_commits_it() {
        let mut child = spawn("/bin/sleep", &["10"]);
        let pid = child.pid();
        child.release().unwrap();
        let mut pending = None;
        let outcome = stage_handoff(&mut Some(child), &mut pending).unwrap();
        assert_eq!(outcome, ChildOutcome::TimedOutRunning);
        assert!(pending.is_some());
        assert!(!pending.as_ref().unwrap().handed_off);

        commit_handoff(&mut pending).unwrap();
        assert!(pending.is_none());
        unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
    }

    #[test]
    fn terminal_failure_aborts_staged_handoff_and_reaps_child() {
        let mut child = spawn("/bin/sleep", &["10"]);
        let pid = child.pid();
        child.release().unwrap();
        let mut pending = None;
        assert_eq!(
            stage_handoff(&mut Some(child), &mut pending).unwrap(),
            ChildOutcome::TimedOutRunning
        );

        let error = combine_handoff_failure(
            anyhow!("terminal failed"),
            abort_pending_handoff(&mut pending),
        );
        let rendered = format!("{error:#}");
        assert!(rendered.contains("terminal failed"), "{rendered}");
        assert!(pending.is_none(), "pending handoff was not aborted");

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        assert_eq!(waited, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );

        let synthetic = combine_handoff_failure(
            anyhow!("commit failed"),
            Err(anyhow!("aborting pending handoff failed")),
        );
        let synthetic_rendered = format!("{synthetic:#}");
        assert!(
            synthetic_rendered.contains("commit failed"),
            "{synthetic_rendered}"
        );
        assert!(
            synthetic_rendered.contains("aborting pending handoff failed"),
            "{synthetic_rendered}"
        );
    }

    #[test]
    fn root_fence_seed_requires_exact_owner_and_reap_and_retains_until_abort() {
        let domain = crate::events::EventsDomain::test_standin(88);
        let mut child = Some(spawn("/bin/true", &[]));
        let weak = std::sync::Arc::downgrade(&child.as_ref().unwrap().pin);
        let mut seed = Some(crate::attach::RootSeed::test_acknowledgement(
            child.as_ref().unwrap(),
            domain,
        ));
        assert!(
            OriginalRootExit::take(&mut child, &mut seed)
                .unwrap()
                .is_none()
        );
        let mut other = Some(spawn("/bin/true", &[]));
        assert!(OriginalRootExit::take(&mut other, &mut seed).is_err());
        child.as_mut().unwrap().release().unwrap();
        assert!(
            child
                .as_ref()
                .unwrap()
                .pin()
                .wait_ready(Some(Duration::from_secs(1)))
                .unwrap()
        );
        assert!(
            OriginalRootExit::take(&mut child, &mut seed)
                .unwrap()
                .is_none(),
            "readiness before the exact reap must not mint the witness"
        );
        child.as_mut().unwrap().terminate_and_reap().unwrap();
        let mut code = None;
        let mut running = true;
        let error = record_settlement_result(
            child.as_ref().unwrap(),
            Err(anyhow!("group-signaling failed")),
            &mut code,
            &mut running,
        )
        .unwrap_err();
        assert!(error.to_string().contains("group-signaling failed"));
        assert!(code.is_some());
        assert!(!running);
        let exit = OriginalRootExit::take(&mut child, &mut seed)
            .unwrap()
            .unwrap();
        assert!(child.is_none() && seed.is_none());
        assert!(weak.upgrade().is_some());
        drop(exit);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn root_fence_live_handoff_and_unseeded_reap_have_no_witness() {
        let mut child = Some(spawn("/bin/sleep", &["10"]));
        let mut seed = Some(crate::attach::RootSeed::test_acknowledgement(
            child.as_ref().unwrap(),
            crate::events::EventsDomain::test_standin(90),
        ));
        child.as_mut().unwrap().release().unwrap();
        let mut pending = None;
        assert_eq!(
            stage_handoff(&mut child, &mut pending).unwrap(),
            ChildOutcome::TimedOutRunning
        );
        assert!(
            OriginalRootExit::take(&mut child, &mut seed)
                .unwrap()
                .is_none()
        );
        assert!(pending.as_ref().unwrap().still_running());
        let mut child = Some(spawn("/bin/true", &[]));
        child.as_mut().unwrap().terminate_and_reap().unwrap();
        assert!(
            OriginalRootExit::take(&mut child, &mut None)
                .unwrap()
                .is_none()
        );
        assert!(child.as_ref().unwrap().is_reaped());
    }

    #[test]
    fn root_fence_proc_fallback_refuses_and_completed_token_retains_owner() {
        let domain = crate::events::EventsDomain::test_standin(91);
        let mut child = Some(spawn("/bin/true", &[]));
        child.as_mut().unwrap().terminate_and_reap().unwrap();
        let original = child.as_ref().unwrap().pin.clone();
        child.as_mut().unwrap().pin =
            std::sync::Arc::new(PidPin::test_proc_only(child.as_ref().unwrap().pid()));
        let mut seed = Some(crate::attach::RootSeed::test_acknowledgement(
            child.as_ref().unwrap(),
            domain.clone(),
        ));
        assert!(OriginalRootExit::take(&mut child, &mut seed).is_err());
        child.as_mut().unwrap().pin = original;
        let weak = std::sync::Arc::downgrade(&child.as_ref().unwrap().pin);
        let mut seed = Some(crate::attach::RootSeed::test_acknowledgement(
            child.as_ref().unwrap(),
            domain.clone(),
        ));
        let exit = OriginalRootExit::take(&mut child, &mut seed)
            .unwrap()
            .unwrap();
        let mut tail =
            crate::events::OwnedRootTail::new(exit, Instant::now() + Duration::from_secs(1));
        let mut drain = crate::events::EventDrain::over_domain(
            crate::events::root_fence_tests::source([]),
            domain,
        );
        drain.begin_root_tail(&mut tail).unwrap();
        drain.poll_root_tail(&mut tail, 1, |_| Ok(())).unwrap();
        let completed = tail.complete().unwrap();
        drop(drain);
        assert!(weak.upgrade().is_some());
        drop(completed);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn root_fence_settlement_retains_original_owner_after_exact_reap() {
        let mut child = spawn("/bin/true", &[]);
        child.release().unwrap();
        let fd = child.pin().pidfd().unwrap().as_raw_fd();
        let mut pending = None;
        let mut exit_code = None;
        let mut running = false;
        let mut retained = Some(child);
        settle_owned_child(
            &mut retained,
            CaptureEnd::TargetExit,
            true,
            true,
            &SignalState::new(),
            &mut pending,
            &mut exit_code,
            &mut running,
        )
        .unwrap();
        assert!(exit_code.is_some());
        // Only lifetime observation of this test's own original descriptor.
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) },
            -1,
            "settlement dropped the original owner before its EVENTS fence"
        );
    }

    #[test]
    fn owned_disposition_records_every_capture_end_state() {
        let cases = [
            (
                "/bin/true",
                CaptureEnd::TargetExit,
                true,
                false,
                None,
                Some(0),
            ),
            (
                "/bin/sleep",
                CaptureEnd::Signal,
                true,
                false,
                Some(libc::SIGTERM),
                Some(128 + libc::SIGTERM),
            ),
            (
                "/bin/sleep",
                CaptureEnd::LimitReached,
                true,
                false,
                None,
                Some(128 + libc::SIGTERM),
            ),
            (
                "/bin/sleep",
                CaptureEnd::Error,
                true,
                false,
                None,
                Some(128 + libc::SIGTERM),
            ),
            (
                "/bin/sleep",
                CaptureEnd::DurationExpired,
                true,
                false,
                None,
                None,
            ),
            (
                "/bin/sleep",
                CaptureEnd::DurationExpired,
                false,
                false,
                None,
                Some(128 + libc::SIGTERM),
            ),
            (
                "/bin/sleep",
                CaptureEnd::DurationExpired,
                true,
                true,
                None,
                Some(128 + libc::SIGTERM),
            ),
        ];

        for (program, end, cleanup_ok, kill_on_timeout, signal, expected_exit) in cases {
            let mut args = Vec::new();
            if program == "/bin/sleep" {
                args.push("10".to_string());
            }
            let mut child = spawn(
                program,
                &args.iter().map(String::as_str).collect::<Vec<_>>(),
            );
            let pid = child.pid();
            child.release().unwrap();
            if end == CaptureEnd::TargetExit {
                wait_until(
                    || !child.still_running(),
                    "target fixture never reached its exit state",
                );
            }
            let signals = SignalState::new();
            if let Some(signal) = signal {
                signals.observe(signal);
            }
            let mut pending = None;
            let mut exit_code = None;
            let mut still_running = false;
            let mut retained = Some(child);
            settle_owned_child(
                &mut retained,
                end,
                cleanup_ok,
                kill_on_timeout,
                &signals,
                &mut pending,
                &mut exit_code,
                &mut still_running,
            )
            .unwrap();
            assert_eq!(exit_code, expected_exit, "{program} {end:?}");
            assert_eq!(still_running, expected_exit.is_none(), "{program} {end:?}");
            assert_eq!(
                pending.is_some(),
                end == CaptureEnd::DurationExpired && cleanup_ok && !kill_on_timeout
            );
            if let Some(pending) = pending {
                assert!(pending.still_running());
                assert_eq!(pending.pid(), pid);
            }
        }
    }

    #[test]
    fn signal_observed_before_handoff_rejects_the_handoff_boundary() {
        let signals = SignalState::new();
        signals.observe(libc::SIGTERM);
        assert!(!signals.claim_handoff());
    }

    #[test]
    fn path_absolute_shebang_retarget_and_exec_chain_prearm_classification_is_conservative() {
        let path = PreparedExecutable::resolve("sh".as_ref()).unwrap().unwrap();
        assert!(path.path().is_absolute());
        let _: &Path = path.interpreter();
        assert!(path.interpreter_file().metadata().is_ok());
        assert!(path.unchanged().unwrap());
        assert!(
            PreparedExecutable::resolve("/bin/sh".as_ref())
                .unwrap()
                .is_some()
        );

        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("script");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).unwrap();
        assert!(
            PreparedExecutable::resolve(script.as_os_str())
                .unwrap()
                .is_none()
        );

        let target = directory.path().join("target");
        std::fs::copy("/bin/true", &target).unwrap();
        let pinned = PreparedExecutable::resolve(target.as_os_str())
            .unwrap()
            .unwrap();
        let replacement = directory.path().join("replacement");
        std::fs::copy("/bin/false", &replacement).unwrap();
        std::fs::rename(&replacement, &target).unwrap();
        assert!(
            !pinned.unchanged().unwrap(),
            "a retargeted path must not pre-arm"
        );

        let sleeper_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(sleeper_dir.path());
        let sleeper = sleeper.to_str().unwrap();
        let mut direct = spawn(sleeper, &[]);
        direct.release().unwrap();
        assert!(direct.revalidate_after_exec().unwrap());
        direct.terminate_and_reap().unwrap();

        let mut chain = spawn("/bin/sh", &["-c", "exec /bin/sleep 1"]);
        chain.release().unwrap();
        let sleep_path = std::fs::canonicalize("/bin/sleep").unwrap();
        wait_until(
            || {
                std::fs::read_link(format!("/proc/{}/exe", chain.pid()))
                    .is_ok_and(|path| path == sleep_path)
            },
            "the shell never completed its second exec",
        );
        assert!(!chain.revalidate_after_exec().unwrap());
        chain.terminate_and_reap().unwrap();
    }

    /// Hermetic long-running child: this host's `/bin/sleep` is a uutils
    /// multicall shim that dispatches on AT_EXECFN, which fd-pinned exec
    /// (`execveat` + `AT_EMPTY_PATH`) leaves as an fd-based name — so it
    /// exits 1 with "unknown program" under the harness while GNU sleep
    /// elsewhere survives. Duration/settle tests need a child that simply
    /// lives until signalled, independent of host coreutils.
    fn build_sleeper(dir: &std::path::Path) -> std::path::PathBuf {
        let source = dir.join("sleeper.c");
        let binary = dir.join("sleeper");
        std::fs::write(
            &source,
            "#include <unistd.h>\nint main(void) { for (;;) sleep(60); return 0; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-O0", "-o"])
                .arg(&binary)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        binary
    }

    #[test]
    fn duration_and_forwarded_signals_have_one_owned_cleanup_route() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let sleeper = sleeper.to_str().unwrap();
        let mut running = spawn(sleeper, &[]);
        running.release().unwrap();
        assert_eq!(
            running
                .wait_for(Some(Duration::from_millis(10)), false)
                .unwrap(),
            ChildOutcome::TimedOutRunning
        );
        assert!(running.still_running());
        running
            .terminate_with_grace(Duration::from_millis(10))
            .unwrap();
        assert!(running.is_reaped());

        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("interrupt-ready");
        let mut interrupted = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!(
                    "trap '' INT; : > {}; while :; do sleep 1; done",
                    ready.display()
                ),
            ],
        );
        interrupted.release().unwrap();
        wait_until(
            || ready.exists(),
            "the SIGINT fixture never installed its trap",
        );
        assert_eq!(
            interrupted.forward_signal(libc::SIGINT).unwrap(),
            ForwardAction::Forwarded
        );
        assert_eq!(
            interrupted.forward_signal(libc::SIGINT).unwrap(),
            ForwardAction::Escalated
        );
        assert_eq!(
            interrupted.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(128 + libc::SIGKILL)
        );

        let mut terminated = spawn("/bin/sleep", &["10"]);
        terminated.release().unwrap();
        assert_eq!(
            terminated.forward_signal(libc::SIGTERM).unwrap(),
            ForwardAction::Forwarded
        );
        assert_eq!(
            terminated.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(128 + libc::SIGTERM)
        );

        let term_ready = directory.path().join("term-ready");
        let mut term_ignoring = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!(
                    "trap '' TERM; : > {}; while :; do sleep 1; done",
                    term_ready.display()
                ),
            ],
        );
        term_ignoring.release().unwrap();
        wait_until(
            || term_ready.exists(),
            "the TERM fixture never installed its trap",
        );
        assert_eq!(
            term_ignoring
                .terminate_with_grace(Duration::from_millis(10))
                .unwrap(),
            128 + libc::SIGKILL
        );
    }

    #[test]
    fn reap_only_after_escalated_signal_reaps_pidfd_ready_child() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let mut child = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!("trap '' INT; : > {}; while :; do :; done", ready.display()),
            ],
        );
        child.release().unwrap();
        wait_until(|| ready.exists(), "the SIGINT fixture never became ready");

        assert_eq!(
            child.forward_signal(libc::SIGINT).unwrap(),
            ForwardAction::Forwarded
        );
        assert_eq!(
            child.forward_signal(libc::SIGINT).unwrap(),
            ForwardAction::Escalated
        );
        wait_until(
            || child.pin.wait_ready(Some(Duration::ZERO)).unwrap(),
            "the escalated child pidfd never became ready",
        );

        assert_eq!(child.reap_after_escalation().unwrap(), 128 + libc::SIGKILL);
        assert!(child.is_reaped());
    }

    #[test]
    fn signal_settlement_forwards_the_second_sigint_as_escalation() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let first_signal = directory.path().join("first-signal");
        let mut child = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!(
                    "trap ': > {}' INT; : > {}; while :; do sleep 1; done",
                    first_signal.display(),
                    ready.display(),
                ),
            ],
        );
        child.release().unwrap();
        wait_until(|| ready.exists(), "the SIGINT fixture never became ready");

        let signals = Arc::new(SignalState::new());
        signals.observe(libc::SIGINT);
        let observed = Arc::clone(&signals);
        let sender = std::thread::spawn(move || {
            wait_until(
                || first_signal.exists(),
                "settlement never forwarded the first SIGINT",
            );
            observed.observe(libc::SIGINT);
        });
        assert_eq!(
            settle_after_signal(&mut child, &signals).unwrap(),
            ChildOutcome::Exited(128 + libc::SIGKILL)
        );
        sender.join().unwrap();
        assert_eq!(child.interrupt_count, 2);
    }

    #[test]
    fn signal_settlement_observes_second_sigint_during_fallback_term_grace() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let term = directory.path().join("term");
        let mut child = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!(
                    "trap '' INT; trap ': > {}' TERM; : > {}; while :; do :; done",
                    term.display(),
                    ready.display(),
                ),
            ],
        );
        child.release().unwrap();
        wait_until(|| ready.exists(), "the SIGINT fixture never became ready");

        let signals = Arc::new(SignalState::new());
        signals.observe(libc::SIGINT);
        let observed = Arc::clone(&signals);
        let sender = std::thread::spawn(move || {
            wait_until(
                || term.exists(),
                "settlement never forwarded fallback SIGTERM",
            );
            assert_eq!(
                observed.sigint_deliveries(),
                1,
                "the second SIGINT was recorded before fallback SIGTERM",
            );
            observed.observe(libc::SIGINT);
        });
        assert_eq!(
            settle_after_signal_with_grace(&mut child, &signals, Duration::from_millis(100))
                .unwrap(),
            ChildOutcome::Exited(128 + libc::SIGKILL)
        );
        sender.join().unwrap();
        assert_eq!(signals.sigint_deliveries(), 2);
        assert_eq!(child.interrupt_count, 2);
        assert!(child.is_reaped());
    }

    #[test]
    fn always_wrap_reports_interruption_not_refusal_when_signalled() {
        let signals = SignalState::new();
        signals.observe(libc::SIGTERM);
        let text = format!(
            "{:#}",
            always_wrap(&signals, anyhow!("pause: pause coordination cancelled"))
        );
        assert!(
            text.contains("interrupted by SIGTERM"),
            "a signalled run must not claim refusal: {text}"
        );
        assert!(
            !text.contains("refused rather than capturing unpaused"),
            "refusal text on a signal exit is false: {text}"
        );
    }

    #[test]
    fn always_wrap_keeps_refusal_text_without_signal() {
        let signals = SignalState::new();
        let text = format!(
            "{:#}",
            always_wrap(&signals, anyhow!("pause: something failed"))
        );
        assert!(
            text.contains("refused rather than capturing unpaused"),
            "genuine refusal text must be unchanged: {text}"
        );
    }

    #[test]
    fn signal_settlement_forwards_the_retained_sigterm_identity() {
        let mut child = spawn("/bin/sleep", &["10"]);
        child.release().unwrap();
        let signals = SignalState::new();
        signals.observe(libc::SIGTERM);
        assert_eq!(
            settle_after_signal(&mut child, &signals).unwrap(),
            ChildOutcome::Exited(128 + libc::SIGTERM)
        );
    }

    #[test]
    fn graceful_termination_resumes_a_stopped_child_before_sigterm() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let sleeper = sleeper.to_str().unwrap();
        let mut child = spawn(sleeper, &[]);
        child.release().unwrap();
        unsafe { libc::kill(child.pid() as libc::pid_t, libc::SIGSTOP) };
        wait_until(
            || child_is_stopped(child.pid()),
            "the fixture child never entered the stopped state",
        );

        // A stopped child cannot observe SIGTERM: without a resume-first
        // it burns the whole grace window and dies by SIGKILL (137).
        assert_eq!(child.terminate_and_reap().unwrap(), 128 + libc::SIGTERM);
    }

    fn child_is_stopped(pid: u32) -> bool {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        stat.split(' ').nth(2).is_some_and(|state| state == "T")
    }

    #[test]
    fn signal_settlement_resumes_a_stopped_child_before_forwarding_sigterm() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let sleeper = sleeper.to_str().unwrap();
        let mut child = spawn(sleeper, &[]);
        child.release().unwrap();
        // The pause path holds the owned child in T (SIGSTOP) while the
        // observer is signalled; settle must resume it first, because a
        // stopped child cannot observe the forwarded SIGTERM and would
        // otherwise burn both grace windows before SIGKILL.
        unsafe { libc::kill(child.pid() as libc::pid_t, libc::SIGSTOP) };
        wait_until(
            || child_is_stopped(child.pid()),
            "the fixture child never entered the stopped state",
        );

        let signals = SignalState::new();
        signals.observe(libc::SIGTERM);
        assert_eq!(
            settle_after_signal_with_grace(&mut child, &signals, Duration::from_millis(300))
                .unwrap(),
            ChildOutcome::Exited(128 + libc::SIGTERM)
        );
    }

    #[test]
    fn also_failed_keeps_both_causes_in_order() {
        // WINS: one "also failed" core behind the four combine_* helpers.
        let chained = also_failed(anyhow!("primary"), anyhow!("secondary"), "cleanup");
        let rendered = format!("{chained:#}");
        assert!(
            rendered.contains("cleanup also failed: secondary"),
            "{rendered}"
        );
        assert!(rendered.contains("primary"), "{rendered}");
    }

    #[test]
    fn capture_error_keeps_cleanup_and_settlement_context() {
        let finish = combine_finish_errors(
            Err(anyhow!("cleanup failed")),
            Err(anyhow!("settlement failed")),
        )
        .unwrap_err();
        let finish_rendered = format!("{finish:#}");
        assert!(
            finish_rendered.contains("cleanup failed"),
            "{finish_rendered}"
        );
        assert!(
            finish_rendered.contains("settlement failed"),
            "{finish_rendered}"
        );

        let error = combine_capture_failure(
            anyhow!("capture failed"),
            Err(finish),
            Err(anyhow!("detach failed")),
        );
        let rendered = format!("{error:#}");
        assert!(rendered.contains("capture failed"), "{rendered}");
        assert!(rendered.contains("cleanup failed"), "{rendered}");
        assert!(rendered.contains("settlement failed"), "{rendered}");
        assert!(rendered.contains("detach failed"), "{rendered}");

        let terminal = combine_detach::<()>(
            Err(anyhow!("terminal failed")),
            Err(anyhow!("detach failed")),
        );
        let terminal_rendered = format!("{:#}", terminal.unwrap_err());
        assert!(
            terminal_rendered.contains("terminal failed"),
            "{terminal_rendered}"
        );
        assert!(
            terminal_rendered.contains("detach failed"),
            "{terminal_rendered}"
        );
    }

    #[test]
    fn drop_closes_the_barrier_and_reaps_an_unreleased_child() {
        let unreleased_pid = {
            let child = spawn("/bin/sleep", &["10"]);
            child.pid()
        };
        let invalid_handoff_pid = {
            let mut child = spawn("/bin/sleep", &["10"]);
            let pid = child.pid();
            assert!(child.hand_off_running().is_err());
            pid
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while [unreleased_pid, invalid_handoff_pid]
            .into_iter()
            .any(|pid| std::path::Path::new(&format!("/proc/{pid}")).exists())
        {
            assert!(
                Instant::now() < deadline,
                "owned child was not reaped by drop"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// MED (forward_signal): a child that exited before the first forwarded
    /// signal settles as Exited, never as a forwarding error — its pin reads
    /// "no longer active", so settle reaps the natural exit instead.
    #[test]
    fn settle_after_signal_reaps_a_child_that_exited_first() {
        let mut child = spawn("/bin/true", &[]);
        child.release().unwrap();
        wait_until(
            || child.pin.wait_ready(Some(Duration::ZERO)).unwrap(),
            "the true fixture never exited",
        );
        let signals = SignalState::new();
        signals.observe(libc::SIGTERM);
        let outcome =
            settle_after_signal_with_grace(&mut child, &signals, Duration::from_millis(50))
                .expect("a pre-exited child settles as Exited, not as an error");
        assert_eq!(outcome, ChildOutcome::Exited(0));
    }

    #[test]
    fn completed_generation_cannot_authorize_a_later_child_action() {
        let mut child = spawn("/bin/true", &[]);
        child.release().unwrap();
        assert_eq!(
            child.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(0)
        );
        assert!(child.forward_signal(libc::SIGTERM).is_err());
        assert!(child.terminate_and_reap().is_err());
    }

    // ---- Slice 1b-2 error taxonomy (design §10.3) -----------------------

    fn run_args(pause: cli::PausePolicy, command: &[&str]) -> RunArgs {
        RunArgs {
            kind: Kind::Profile,
            modules: Vec::new(),
            manifests: Vec::new(),
            hooks: crate::discovery::hooks::HookRegistry::builtin(),
            metrics: false,
            duration: None,
            out: None,
            max_events: None,
            max_scan_pids: None,
            ring_bytes: None,
            drain_interval: None,
            unsafe_requested: false,
            allow_confined_uretprobe: false,
            pause,
            kill_on_timeout: false,
            command: command.iter().map(|a| a.to_string()).collect(),
        }
    }

    /// Design §10.3: exec, kill/reap, cancellation, pause, and environment
    /// failures stay distinct finite categories. They are not collapsed into
    /// one generic runtime failure, and none of them is answered with
    /// `PARTIAL` instead of a refusal.
    #[test]
    fn every_owned_run_error_category_is_named_and_distinct() {
        // exec: named as its own category before anything is forked.
        let exec = format!(
            "{:#}",
            run_owned(&run_args(
                cli::PausePolicy::Never,
                &["/definitely/missing/p11scope-taxonomy"],
            ))
            .expect_err("a command that cannot execute must refuse")
        );
        assert!(exec.contains("exec"), "{exec}");
        for other in ["pause", "attach session", "reaping", "handing back"] {
            assert!(!exec.contains(other), "exec was relabelled {other}: {exec}");
        }

        // kill/reap and cancellation: separate categories from each other and
        // from exec, each stated in the operator's own words.
        let mut child = OwnedChild::spawn("/bin/true".into(), Vec::new()).unwrap();
        child.release().unwrap();
        assert_eq!(
            child.wait_for(None, false).unwrap(),
            ChildOutcome::Exited(0)
        );
        let reap = child.wait_for(None, false).unwrap_err().to_string();
        let cancellation = child.forward_signal(libc::SIGTERM).unwrap_err().to_string();
        let exec_failure = ExecFailure {
            errno: libc::ENOENT,
            exit_code: 127,
        }
        .to_string();
        let categories = [reap.as_str(), cancellation.as_str(), exec_failure.as_str()];
        for (index, one) in categories.iter().enumerate() {
            assert!(!one.is_empty(), "an unnamed category is not a category");
            for other in &categories[index + 1..] {
                assert_ne!(one, other, "two categories rendered identically");
            }
        }
        assert!(reap.contains("reaped"), "{reap}");
        assert!(cancellation.contains("generation"), "{cancellation}");
        assert!(exec_failure.contains("exec"), "{exec_failure}");

        // A required pause adds its own category to whatever actually failed;
        // it never replaces it, and it never attaches to an unrelated failure.
        let capture_available = crate::doctor::verdict(&crate::doctor::probe(None, None)) == 0;
        if !capture_available {
            let never = format!(
                "{:#}",
                run_owned(&run_args(cli::PausePolicy::Never, &["/bin/true"]))
                    .expect_err("an unavailable capture lane must refuse")
            );
            assert!(never.contains("attach session"), "{never}");
            assert!(
                !never.contains("pause"),
                "an environment failure is not a pause failure: {never}"
            );
            let always = format!(
                "{:#}",
                run_owned(&run_args(cli::PausePolicy::Always, &["/bin/true"]))
                    .expect_err("an unavailable capture lane must refuse")
            );
            assert!(always.contains("pause"), "{always}");
            assert!(
                always.contains("attach session"),
                "the required-pause category must not hide the real cause: {always}"
            );
        }
    }

    // ---- capture-loop tests, moved with the loops from src/main.rs ----

    struct FailingWriter {
        kind: std::io::ErrorKind,
        fail_flush: bool,
    }

    struct FailAfterLines {
        allowed_lines: usize,
        bytes: Vec<u8>,
        attempts: Vec<Vec<u8>>,
    }

    impl Write for FailAfterLines {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.attempts.push(buf.to_vec());
            if self.bytes.iter().filter(|byte| **byte == b'\n').count() >= self.allowed_lines {
                return Err(std::io::Error::other("scripted write failure"));
            }
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            if self.fail_flush {
                Ok(0)
            } else {
                Err(std::io::Error::from(self.kind))
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::Error::from(self.kind))
            } else {
                Ok(())
            }
        }
    }

    fn call_event() -> p11scope_ebpf_common::Event {
        p11scope_ebpf_common::Event {
            event_type: p11scope_ebpf_common::event_type::CALL,
            pid_tgid: u64::from(std::process::id()) << 32,
            ..Default::default()
        }
    }

    /// One event past the quantum, then a record the live profile poll must
    /// never take: the loop's duration/signal check runs between quanta.
    #[test]
    fn a_live_profile_poll_returns_at_its_quantum_with_the_backlog_still_queued() {
        use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
        let plan = crate::plan::AttachPlan::from_slots(vec![]);
        let mut state = semantics::State::new(&plan);
        let mut tracker = process::Tracker::new();
        let events = (0..=LIVE_POLL_QUANTUM).map(|_| call_event());
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events(events, LIVE_POLL_QUANTUM), 1);

        let malformed = drain_profile_events(
            &mut drain,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            Some(LIVE_POLL_QUANTUM),
        )
        .unwrap();

        assert_eq!(malformed, 0);
        assert_eq!(drain.source().remaining(), 1);
    }

    #[test]
    fn cgroup_process_creation_inherits_once_and_tags_into_cgroup_no_inherit() {
        use crate::events::{EventDrain, ScriptedRecords};

        let event = p11scope_ebpf_common::Event {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 0,
            },
            child_image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 42,
                exec_id: 0,
            },
            event_type: p11scope_ebpf_common::event_type::FORK,
            pid_tgid: 41u64 << 32,
            session: 42,
            ..Default::default()
        };
        let plan = crate::plan::AttachPlan::from_slots(vec![crate::plan::Slot {
            index: 0,
            descriptor_index: crate::kinds::function_id("C_OpenSession").unwrap() + 1,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/opt/p11.so".into(),
            file_offset: 0x10,
            names: vec!["C_OpenSession".into()],
            aliased: false,
            semantics: crate::kinds::descriptor("C_OpenSession").unwrap(),
            semantic_authorized: true,
            semantic_ambiguous: false,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        }]);
        let mut state = semantics::State::new(&plan);
        let adapter = super::history_tests::Adapter::new();
        adapter.bind(41, 41);
        adapter.bind(42, 42);
        let mut tracker = process::Tracker::with_membership(1, 16, 16, Box::new(adapter));
        let parent_event = p11scope_ebpf_common::Event {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 0,
            },
            pid_tgid: 41u64 << 32,
            ..Default::default()
        };
        let parent_process = identify_tracked(
            tracker.producer_domain(),
            &mut tracker,
            &mut state,
            &parent_event,
        )
        .unwrap();
        state.observe_process(
            parent_process,
            &p11scope_ebpf_common::Event {
                event_type: p11scope_ebpf_common::event_type::CALL,
                pid_tgid: 41u64 << 32,
                session: 7,
                slot_id: 3,
                slot: 0,
                capture: p11scope_ebpf_common::capture::OUTPUT_NON_NULL,
                ..Default::default()
            },
        );
        assert!(state.pid_has_process_state(41));
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events([event], usize::MAX), 1);
        let scope = Scope::Cgroup {
            id: 1,
            path: "/".into(),
            dir: std::sync::Arc::new(std::fs::File::open("/").unwrap()),
        };

        assert_eq!(
            drain_profile_events(&mut drain, &mut state, &mut tracker, &scope, None,).unwrap(),
            0
        );
        assert!(
            state.pid_has_process_state(42),
            "cgroup scope retains existing semantic inheritance"
        );
        assert_eq!(drain.source().remaining(), 0, "fork records are handled");

        let into_event = p11scope_ebpf_common::Event {
            event_type: p11scope_ebpf_common::event_type::FORK_INTO_CGROUP,
            pid_tgid: 41u64 << 32,
            session: 43,
            ..Default::default()
        };
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events([into_event], usize::MAX), 1);
        assert_eq!(
            drain_profile_events(&mut drain, &mut state, &mut tracker, &scope, None,).unwrap(),
            0
        );
        assert!(
            !state.pid_has_process_state(43),
            "destination cgroup membership is unproven"
        );
    }

    fn trace_fixture() -> (semantics::State, process::Tracker, trace::Tracer) {
        let plan = crate::plan::AttachPlan::from_slots(vec![]);
        (
            semantics::State::new(&plan),
            process::Tracker::new(),
            trace::Tracer::new(&plan),
        )
    }

    /// `--max-events` is a stop, not a filter: at zero the live poll breaks
    /// and the run loop ends the capture; what is still queued waits for the
    /// post-detach terminal drain.
    #[test]
    fn a_live_trace_poll_stops_at_the_last_permitted_line() {
        use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
        let (mut state, mut tracker, mut tracer) = trace_fixture();
        let mut remaining = Some(2);
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut out_file: Option<Vec<u8>> = None;
        let events = (0..5).map(|_| call_event());
        let mut drain = EventDrain::over_test_domain(ScriptedRecords::events(events, 2), 1);

        let malformed = drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut tracer,
            &mut stdout,
            &mut stdout_open,
            &mut out_file,
            Some(LIVE_POLL_QUANTUM),
        )
        .unwrap();

        assert_eq!(malformed, 0);
        assert_eq!(remaining, Some(0));
        assert_eq!(stdout.iter().filter(|byte| **byte == b'\n').count(), 2);
        assert_eq!(
            drain.source().remaining(),
            3,
            "the rest waits for the terminal drain"
        );
    }

    /// The live trace poll also yields at the quantum while lines remain.
    #[test]
    fn a_live_trace_poll_returns_at_its_quantum_with_lines_still_permitted() {
        use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
        let (mut state, mut tracker, mut tracer) = trace_fixture();
        let mut remaining = Some(u64::MAX);
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut out_file: Option<Vec<u8>> = None;
        let events = (0..=LIVE_POLL_QUANTUM).map(|_| call_event());
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events(events, LIVE_POLL_QUANTUM), 1);

        drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut tracer,
            &mut stdout,
            &mut stdout_open,
            &mut out_file,
            Some(LIVE_POLL_QUANTUM),
        )
        .unwrap();

        assert_eq!(drain.source().remaining(), 1);
        assert_eq!(remaining, Some(u64::MAX - LIVE_POLL_QUANTUM as u64));
    }

    /// After detach the drain is finite and reads the ring whole: past the
    /// limit nothing more is printed, but every record still reaches semantics.
    #[test]
    fn the_terminal_trace_drain_reads_the_ring_whole_past_the_limit() {
        use crate::events::{EventDrain, ScriptedRecords};
        let (mut state, mut tracker, mut tracer) = trace_fixture();
        let mut remaining = Some(0);
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut out_file: Option<Vec<u8>> = None;
        let events = (0..crate::events::LIVE_POLL_QUANTUM + 5).map(|_| call_event());
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events(events, usize::MAX), 1);

        drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut tracer,
            &mut stdout,
            &mut stdout_open,
            &mut out_file,
            None,
        )
        .unwrap();

        assert!(stdout.is_empty());
        assert_eq!(remaining, Some(0));
        assert_eq!(drain.source().remaining(), 0);
    }

    #[test]
    fn terminal_trace_count_evidence_counts_before_limit_and_excludes_process_creation() {
        use crate::events::{EventDrain, ScriptedRecords};
        let (mut state, mut tracker, mut tracer) = trace_fixture();
        let reports = [metrics::SlotReport {
            names: vec!["C_Initialize".to_string()],
            aliased: false,
            semantic_authorized: true,
            module: None,
            module_ambiguous: false,
            module_unresolved: false,
            calls: 5,
            errors: 0,
            in_flight: 2,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; p11scope_ebpf_common::LATENCY_BUCKETS],
            rv_counts: std::collections::BTreeMap::new(),
        }];
        let mut remaining = Some(1);
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut out_file: Option<Vec<u8>> = None;
        let events = [
            call_event(),
            p11scope_ebpf_common::Event {
                event_type: p11scope_ebpf_common::event_type::FORK,
                ..Default::default()
            },
            p11scope_ebpf_common::Event {
                event_type: p11scope_ebpf_common::event_type::FORK_INTO_CGROUP,
                ..Default::default()
            },
            call_event(),
            call_event(),
        ];
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events(events, usize::MAX), 1);

        drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Cgroup {
                id: 0,
                path: PathBuf::from("/"),
                dir: Arc::new(File::open("/").unwrap()),
            },
            &mut tracer,
            &mut stdout,
            &mut stdout_open,
            &mut out_file,
            None,
        )
        .unwrap();

        assert_eq!(tracer.raw_calls(), 3);
        let value: serde_json::Value = serde_json::from_str(
            terminal_trace_count_line(&reports, &tracer)
                .strip_prefix("COUNT_EVIDENCE ")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "stats_entered": 7,
                "stats_returned": 5,
                "raw_calls": 3,
            })
        );
        assert_eq!(remaining, Some(0));
        assert!(stdout.iter().filter(|byte| **byte == b'\n').count() <= 1);
    }

    #[test]
    fn task_8d_terminal_trace_emission_orders_exact_count_before_evidence() {
        let (mut state, mut tracker, mut tracer) = trace_fixture();
        let reports = [metrics::SlotReport {
            names: vec!["C_Initialize".to_string()],
            aliased: false,
            semantic_authorized: true,
            module: None,
            module_ambiguous: false,
            module_unresolved: false,
            calls: 5,
            errors: 0,
            in_flight: 2,
            total_ns: 0,
            max_ns: 0,
            buckets: [0; p11scope_ebpf_common::LATENCY_BUCKETS],
            rv_counts: std::collections::BTreeMap::new(),
        }];
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut out_file = Some(Vec::new());
        let mut remaining = None;
        let mut drain = crate::events::EventDrain::over_test_domain(
            crate::events::ScriptedRecords::events([call_event()], usize::MAX),
            1,
        );
        drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut tracer,
            &mut Vec::new(),
            &mut true,
            &mut None::<Vec<u8>>,
            None,
        )
        .unwrap();

        emit_trace_terminal(
            &reports,
            &tracer,
            "EVIDENCE {}",
            &mut stdout,
            &mut stdout_open,
            &mut out_file,
        )
        .unwrap();

        assert_eq!(out_file.as_ref().unwrap(), &stdout);
        let lines = String::from_utf8(stdout).unwrap();
        let lines = lines.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[1], "EVIDENCE {}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(
                lines[0].strip_prefix("COUNT_EVIDENCE ").unwrap()
            )
            .unwrap(),
            serde_json::json!({
                "stats_entered": 7,
                "stats_returned": 5,
                "raw_calls": 1,
            })
        );
    }

    #[test]
    fn terminal_trace_stops_after_either_file_write_failure() {
        let (_, _, tracer) = trace_fixture();
        for allowed_lines in [0, 1] {
            let mut stdout = Vec::new();
            let mut stdout_open = true;
            let mut file = Some(FailAfterLines {
                allowed_lines,
                bytes: Vec::new(),
                attempts: Vec::new(),
            });
            assert!(
                emit_trace_terminal(
                    &[],
                    &tracer,
                    "EVIDENCE {}",
                    &mut stdout,
                    &mut stdout_open,
                    &mut file,
                )
                .is_err()
            );
            let file = file.unwrap();
            assert_eq!(
                file.bytes.iter().filter(|byte| **byte == b'\n').count(),
                allowed_lines
            );
            assert!(
                !String::from_utf8_lossy(&file.bytes)
                    .lines()
                    .any(|line| line == "EVIDENCE {}")
            );
            assert_eq!(
                file.attempts
                    .iter()
                    .any(|attempt| attempt.windows(11).any(|bytes| bytes == b"EVIDENCE {}")),
                allowed_lines == 1,
            );
        }
    }

    /// Both loops take their poll bound from the session — the quantum while
    /// the producers are live, whole only once `detach_producers` detached
    /// them all — so duration, signal and the line limit are checked between
    /// quanta and the terminal drain still reads the detached ring whole.
    #[test]
    fn every_events_poll_takes_its_bound_from_the_session() {
        use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
        for trace in [false, true] {
            let (mut state, mut tracker, mut tracer) = trace_fixture();
            let mut context = (
                false,
                EventDrain::over_test_domain(
                    ScriptedRecords::events(
                        (0..LIVE_POLL_QUANTUM + 2).map(|_| call_event()),
                        usize::MAX,
                    ),
                    1,
                ),
            );
            let selected = std::cell::Cell::new(0);
            for (detached, want) in [(false, 2), (true, 0)] {
                context.0 = detached;
                select_and_drain_events(
                    &mut context,
                    |context| {
                        selected.set(selected.get() + 1);
                        crate::events::poll_quantum(context.0)
                    },
                    |context, quantum| {
                        assert_eq!(selected.get(), if detached { 2 } else { 1 });
                        if trace {
                            drain_trace_events_from(
                                &mut context.1,
                                &mut None,
                                &mut state,
                                &mut tracker,
                                &Scope::Pid(7),
                                &mut tracer,
                                &mut Vec::new(),
                                &mut true,
                                &mut None::<Vec<u8>>,
                                quantum,
                            )
                        } else {
                            drain_profile_events(
                                &mut context.1,
                                &mut state,
                                &mut tracker,
                                &Scope::Pid(7),
                                quantum,
                            )
                        }
                    },
                )
                .unwrap();
                assert_eq!(context.1.source().remaining(), want);
            }
            assert_eq!(selected.get(), 2);
        }
    }

    #[test]
    fn terminal_capture_modes_wire_shared_finish_and_drain_helpers() {
        let source = include_str!("run.rs");
        let profile = source
            .split_once("fn capture_profile(")
            .unwrap()
            .1
            .split_once("fn capture_trace(")
            .unwrap()
            .0;
        let trace = source
            .split_once("fn capture_trace(")
            .unwrap()
            .1
            .split_once("fn terminal_trace_count_line")
            .unwrap()
            .0;
        for (function, body, consumer_mode) in [
            ("capture_profile", profile, "tracer: None,"),
            ("capture_trace", trace, "tracer: Some(&mut tracer),"),
        ] {
            assert_eq!(
                body.matches("finish_capture_with(").count(),
                1,
                "{function}"
            );
            assert_eq!(
                body.matches("drain_capture_terminal_with(").count(),
                1,
                "{function}"
            );
            let finish = body.find("finish_capture_with(").unwrap();
            let tail = &body[finish..];
            let detach = tail
                .find("|context| context.1.detach_producers(),")
                .expect("shared detach callback");
            let terminal = tail
                .find("drain_capture_terminal_with(")
                .expect("shared terminal helper");
            assert!(
                tail[..detach].contains("finish_capture_loop("),
                "real finish callback for {function}"
            );
            assert!(
                detach < terminal,
                "detach callback must be supplied before terminal callback for {function}"
            );
            assert!(
                tail[detach..terminal].contains(consumer_mode),
                "consumer mode for {function}"
            );
            let terminal = &tail[terminal..];
            let discovery = terminal
                .find("let plan_changed = if detached {")
                .expect("detach-aware terminal discovery");
            let plan = terminal
                .find("Ok((plan_changed, context.0.plan()))")
                .expect("actual engine plan handoff");
            let discovery = &terminal[discovery..plan];
            let (_, after_if) = discovery.split_once("if detached {").unwrap();
            let (success, after_else) = after_if.split_once("} else {").unwrap();
            let (failure, _) = after_else.split_once("};").unwrap();
            assert!(success.contains("context.0.drain_discovery_terminal(context.1)?"));
            assert!(!success.contains("drain_discovery_terminal_bounded_from"));
            assert!(
                failure.contains("context.0.drain_discovery_terminal_bounded_from(context.1)?")
            );
            assert!(!failure.contains("context.0.drain_discovery_terminal(context.1)?"));
        }
    }

    #[test]
    fn stdout_truncation_with_max_events_one_and_bounded_file_trace_is_cumulative() {
        let mut remaining = Some(1);
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut file = Some(Vec::new());

        let (emitted, error) = emit_bounded_trace_event(
            &mut remaining,
            || "event-1".to_string(),
            &mut stdout,
            &mut stdout_open,
            &mut file,
        );
        assert!(emitted);
        assert!(error.is_none());
        let (emitted, error) = emit_bounded_trace_event(
            &mut remaining,
            || "event-2".to_string(),
            &mut stdout,
            &mut stdout_open,
            &mut file,
        );
        assert!(!emitted);
        assert!(error.is_none());
        assert_eq!(remaining, Some(0));
        assert_eq!(stdout, b"event-1\n");
        assert_eq!(file.as_deref(), Some(&b"event-1\n"[..]));
    }

    /// build.rs must embed the real cross-compiled BPF object, never a
    /// placeholder byte array — a stub would silently break every attach.
    #[test]
    fn ebpf_object_is_a_real_bpf_elf() {
        let obj = crate::EBPF_OBJECT;
        assert!(obj.len() > 1000, "expected a real BPF object, not a stub");
        assert_eq!(&obj[..4], b"\x7fELF", "embedded object is not an ELF file");
    }

    #[test]
    fn fmt_rfc3339_matches_a_known_instant() {
        // 2024-01-01T00:00:00Z == 1704067200.
        assert_eq!(
            fmt_rfc3339(UNIX_EPOCH + Duration::from_secs(1_704_067_200)),
            "2024-01-01T00:00:00Z"
        );
        assert_eq!(fmt_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    /// Exercises the interrupt path directly, with no real signal sent:
    /// once the flag `signal_hook::flag::register` would set is set, a
    /// capture loop must stop on the very next tick regardless of
    /// `--duration` — the same "stop, then finalize" branch a real
    /// SIGINT drives.
    #[test]
    fn should_stop_on_interrupt_regardless_of_duration() {
        let interrupted = SignalState::new();
        assert!(!should_stop(&interrupted, Duration::from_secs(0), None));
        assert!(!should_stop(
            &interrupted,
            Duration::from_secs(0),
            Some(Duration::from_secs(3600))
        ));

        interrupted.observe(libc::SIGINT);
        assert!(
            should_stop(&interrupted, Duration::from_secs(0), None),
            "no --duration set at all"
        );
        assert!(
            should_stop(
                &interrupted,
                Duration::from_secs(0),
                Some(Duration::from_secs(3600))
            ),
            "must stop immediately even mid-way through a long --duration"
        );
    }

    #[test]
    fn should_stop_still_honors_duration_elapsing_without_an_interrupt() {
        let interrupted = SignalState::new();
        assert!(should_stop(
            &interrupted,
            Duration::from_secs(10),
            Some(Duration::from_secs(5))
        ));
        assert!(!should_stop(
            &interrupted,
            Duration::from_secs(4),
            Some(Duration::from_secs(5))
        ));
    }

    /// A real SIGTERM (raised in-process after the handler is installed) sets
    /// the same stop flag Ctrl-C sets, so `should_stop` returns true on the
    /// next tick instead of the default disposition killing the capture
    /// mid-write.
    #[test]
    fn sigterm_sets_the_stop_flag() {
        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        let stop = install_stop_flag().unwrap();
        assert!(!should_stop(&stop, Duration::ZERO, None));
        // SAFETY: raise() with a handled signal; the handler only sets atomics.
        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        assert!(should_stop(&stop, Duration::ZERO, None));
        assert_eq!(stop.first_signal(), Some(libc::SIGTERM));
        assert_eq!(stop.sigint_deliveries(), 0);
    }

    #[test]
    fn capture_end_only_allows_handoff_for_clean_duration_expiry() {
        assert!(CaptureEnd::DurationExpired.allows_handoff(false));
        assert!(!CaptureEnd::DurationExpired.allows_handoff(true));
        assert!(!CaptureEnd::LimitReached.allows_handoff(false));
        assert!(!CaptureEnd::TargetExit.allows_handoff(false));
        assert!(!CaptureEnd::Signal.allows_handoff(false));
        assert!(!CaptureEnd::Error.allows_handoff(false));
    }

    #[test]
    fn default_trace_bound_resolver_none_is_10m() {
        assert_eq!(resolve_trace_max_events(None), 10_000_000);
    }

    #[test]
    fn drain_cadence_defaults_to_the_mode_constant() {
        assert_eq!(resolve_drain_cadence(Kind::Profile, None), PROFILE_CADENCE);
        assert_eq!(resolve_drain_cadence(Kind::Trace, None), TRACE_CADENCE);
    }

    #[test]
    fn drain_cadence_override_wins_on_both_modes() {
        let custom = Duration::from_millis(50);
        assert_eq!(resolve_drain_cadence(Kind::Profile, Some(custom)), custom);
        assert_eq!(resolve_drain_cadence(Kind::Trace, Some(custom)), custom);
    }

    #[test]
    fn ring_bytes_default_is_the_bpf_constant() {
        assert_eq!(resolve_ring_bytes(None), p11scope_ebpf_common::RING_BYTES);
        assert_eq!(resolve_ring_bytes(Some(1 << 20)), 1 << 20);
    }

    #[test]
    fn task_8d_attach_mechanism_requires_a_successfully_owned_link() {
        assert!(attach_mechanisms(0, false).is_empty());
        assert_eq!(attach_mechanisms(0, true), ["per-offset"]);
        assert_eq!(attach_mechanisms(2, false), ["per-offset"]);
    }

    #[test]
    fn evidence_for_metrics_excludes_hidden_selection_at_the_call_boundary() {
        let (clean, truncated) = crate::discovery::engine::tests::selection_output_engines();
        let clean_state = semantics::State::new(clean.plan());
        let truncated_state = semantics::State::new(truncated.plan());
        let build = |engine: &Engine, state: &semantics::State, include_selection| {
            evidence_for(
                engine,
                engine.capture_facts(),
                0,
                false,
                &[],
                &[],
                metrics::KernelEvidence::default(),
                process::TrackingEvidence::default(),
                0,
                state,
                false,
                include_selection,
                Default::default(),
                None,
                false,
            )
        };

        let clean_metrics = build(&clean, &clean_state, false);
        let truncated_metrics = build(&truncated, &truncated_state, false);
        assert_eq!(truncated_metrics.completeness, clean_metrics.completeness);
        assert_eq!(
            truncated_metrics.interface_selection,
            render::InterfaceSelection::default()
        );
        let capture = render::CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "test",
            policy: CapturePolicy::AggregateOnly,
            scope: "pid",
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let document = render::json(&[], &truncated_metrics, &capture);
        for field in [
            "interface_selection",
            "attach_mechanisms",
            "pid_descendant_gaps",
            "multi_rebuild_gaps",
        ] {
            assert!(document["evidence"].get(field).is_none(), "{field}");
        }

        let profile = build(&truncated, &truncated_state, true);
        assert!(profile.interface_selection.selection_truncated);
        assert_eq!(profile.completeness, "PARTIAL");

        assert_eq!(
            clean.interface_selection().providers[0].coverage,
            "absent_covered"
        );
        let gap_profile = build(&clean, &clean_state, true);
        assert_eq!(
            gap_profile.interface_selection.providers[0].coverage,
            "absent_covered"
        );
        assert_eq!(gap_profile.pid_descendant_gaps, 0);
    }

    #[test]
    fn evidence_for_projects_finite_pause_and_child_disposition_across_renderers() {
        use crate::discovery::pause::PauseCounters;

        let (engine, _) = crate::discovery::engine::tests::selection_output_engines();
        let state = semantics::State::new(engine.plan());
        let mut facts = engine.capture_facts();
        facts.loader_discovery.hits = 17;
        for (pause, status, unprotected) in [
            (PauseCounters::default(), "none", 1),
            (
                PauseCounters {
                    attempts: 5,
                    confirmed: 5,
                    partial: 0,
                },
                "sigstop",
                0,
            ),
            (
                PauseCounters {
                    attempts: 5,
                    confirmed: 2,
                    partial: 3,
                },
                "partial",
                1,
            ),
        ] {
            for child_still_running in [None, Some(false), Some(true)] {
                let evidence = evidence_for(
                    &engine,
                    facts.clone(),
                    0,
                    false,
                    &[],
                    &[],
                    metrics::KernelEvidence::default(),
                    process::TrackingEvidence::default(),
                    0,
                    &state,
                    false,
                    true,
                    pause,
                    child_still_running,
                    false,
                );
                assert_eq!(evidence.pause, status);
                assert_eq!(evidence.unprotected_live_windows, unprotected);
                assert_eq!(evidence.child_still_running, child_still_running);
                let profile = render::versioned_evidence(&evidence);
                let metrics = render::json(
                    &[],
                    &evidence,
                    &render::CaptureMeta {
                        started: "t0",
                        ended: "t1",
                        kernel: "test",
                        policy: CapturePolicy::AggregateOnly,
                        scope: "pid",
                        ring_bytes: p11scope_ebpf_common::RING_BYTES,
                        drain_interval_ms: 1000,
                    },
                )["evidence"]
                    .clone();
                let terminal: serde_json::Value = serde_json::from_str(
                    trace::evidence_line(&evidence, CapturePolicy::Allowlisted, false)
                        .strip_prefix("EVIDENCE ")
                        .unwrap(),
                )
                .unwrap();
                for document in [&profile, &metrics, &terminal] {
                    assert_eq!(document["pause"], status);
                    assert_eq!(document["pause_attempts"], pause.attempts);
                    assert_eq!(document["pause_confirmed"], pause.confirmed);
                    assert_eq!(document["pause_partial"], pause.partial);
                    match child_still_running {
                        Some(running) => {
                            assert_eq!(document["child_still_running"], running);
                        }
                        None => assert!(document.get("child_still_running").is_none()),
                    }
                }
            }
        }
    }

    #[test]
    fn evidence_for_keeps_distinct_discovery_losses_across_all_renderers() {
        let (engine, _) = crate::discovery::engine::tests::selection_output_engines();
        let state = semantics::State::new(engine.plan());
        let mut facts = engine.capture_facts();
        facts.discovery_ring_loss = 1;
        facts.discovery_state_failures = 2;
        facts.discovery_read_failures = 3;
        facts.discovery_truncated = 4;
        facts.task_uprobe_link_losses = 5;
        let evidence = evidence_for(
            &engine,
            facts,
            0,
            false,
            &[],
            &[],
            metrics::KernelEvidence::default(),
            process::TrackingEvidence::default(),
            0,
            &state,
            false,
            true,
            Default::default(),
            None,
            false,
        );
        let capture = render::CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "test",
            policy: CapturePolicy::Allowlisted,
            scope: "pid",
            ring_bytes: p11scope_ebpf_common::RING_BYTES,
            drain_interval_ms: 1000,
        };
        let profile = render::versioned_evidence(&evidence);
        let metrics = render::json(&[], &evidence, &capture)["evidence"].clone();
        let terminal: serde_json::Value = serde_json::from_str(
            trace::evidence_line(&evidence, CapturePolicy::Allowlisted, false)
                .strip_prefix("EVIDENCE ")
                .unwrap(),
        )
        .unwrap();
        for document in [&profile, &metrics, &terminal] {
            assert_eq!(document["discovery_ring_loss"], 1);
            assert_eq!(document["discovery_state_failures"], 2);
            assert_eq!(document["discovery_read_failures"], 3);
            assert_eq!(document["discovery_truncated"], 4);
            assert_eq!(document["task_uprobe_link_losses"], 5);
            assert_eq!(document["completeness"], "PARTIAL");
        }
    }

    #[test]
    fn lifecycle_attach_degradation_is_reported_and_forces_partial() {
        let (engine, _) = crate::discovery::engine::tests::selection_output_engines();
        let state = semantics::State::new(engine.plan());
        let evidence = evidence_for(
            &engine,
            engine.capture_facts(),
            0,
            false,
            &[],
            &[],
            metrics::KernelEvidence::default(),
            process::TrackingEvidence::default(),
            0,
            &state,
            false,
            true,
            Default::default(),
            None,
            true,
        );

        assert_eq!(evidence.pid_descendant_gaps, 0);
        assert_eq!(evidence.process_tracking_failures, 1);
        assert_eq!(evidence.completeness, "PARTIAL");
        let profile = render::versioned_evidence(&evidence);
        assert_eq!(profile["pid_descendant_gaps"], 0);
        assert_eq!(profile["process_tracking_failures"], 1);
        let terminal = trace::evidence_line(&evidence, CapturePolicy::Allowlisted, false);
        assert!(terminal.contains("\"pid_descendant_gaps\":0"), "{terminal}");
        assert!(
            terminal.contains("\"completeness\":\"PARTIAL\""),
            "{terminal}"
        );
        assert!(
            !terminal.contains("tracefs"),
            "raw lifecycle diagnostics leaked"
        );
    }

    #[test]
    fn pid_scope_process_creation_tracking_is_not_required_or_counted() {
        assert!(!initial_tracking_evidence(&Scope::Pid(41), true, false));
    }

    #[test]
    fn cgroup_creator_events_are_hints_and_never_count_descendant_gaps() {
        let scope = Scope::Cgroup {
            id: 1,
            path: PathBuf::from("/sys/fs/cgroup/test"),
            dir: Arc::new(File::open("/dev/null").unwrap()),
        };
        let plan = crate::plan::build_from_reconciled_modules(&[]);
        let mut state = semantics::State::new(&plan);
        let mut tracker = process::Tracker::with_limits(0, 16);
        for event_type in [
            p11scope_ebpf_common::event_type::FORK,
            p11scope_ebpf_common::event_type::FORK_INTO_CGROUP,
        ] {
            let mut event: p11scope_ebpf_common::Event = unsafe { std::mem::zeroed() };
            event.event_type = event_type;
            event.pid_tgid = u64::from(std::process::id()) << 32;
            event.session = u64::from(std::process::id());
            assert!(observe_fork(
                tracker.producer_domain(),
                &mut tracker,
                &mut state,
                &scope,
                &event,
            ));
        }
    }

    #[test]
    fn unavailable_cgroup_creation_boundary_does_not_precount_a_creator_gap() {
        let scope = Scope::Cgroup {
            id: 1,
            path: PathBuf::from("/sys/fs/cgroup/test"),
            dir: Arc::new(File::open("/dev/null").unwrap()),
        };
        assert!(initial_tracking_evidence(&scope, true, false));
    }

    #[test]
    fn system_scope_counts_creation_and_lifecycle_tracking_like_cgroup_scope() {
        assert!(initial_tracking_evidence(&Scope::System, true, false));
        assert!(initial_tracking_evidence(&Scope::System, false, true));
        assert!(!initial_tracking_evidence(&Scope::System, false, false));
    }

    #[test]
    fn system_scope_admits_fork_children_without_a_destination_check() {
        // One fork-safe C_OpenSession slot so the parent can hold an open
        // session the child must inherit.
        let names = vec!["C_OpenSession".to_string()];
        let (descriptor_index, semantic_ambiguous) = crate::kinds::descriptor_index(&names);
        let plan = crate::plan::AttachPlan::from_slots(vec![crate::plan::Slot {
            index: 0,
            descriptor_index,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/opt/p11.so".into(),
            file_offset: 0,
            names,
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[descriptor_index as usize],
            semantic_authorized: true,
            semantic_ambiguous,
            fork_safe: true,
            module_ids: vec![crate::plan::ModuleId(0)],
        }]);
        let mut state = semantics::State::new(&plan);
        let mut tracker =
            process::Tracker::for_producer(crate::events::EventsDomain::test_standin(1), 16);
        let domain = tracker.producer_domain();
        let parent_image = p11scope_ebpf_common::ImageIdentity {
            task_cookie: 90,
            exec_id: 0,
        };
        let (parent, _) = tracker.admit_history(domain, 100, parent_image);
        let parent = parent.expect("parent generation admits");
        // Parent opens one session before forking.
        let mut call: p11scope_ebpf_common::Event = unsafe { std::mem::zeroed() };
        call.event_type = p11scope_ebpf_common::event_type::CALL;
        call.pid_tgid = 100u64 << 32;
        call.session = 7;
        call.slot = 0;
        call.rv = 0;
        call.image = parent_image;
        state.observe_process(parent, &call);
        assert_eq!(state.sessions().opened, 1);
        // Genuine birth: distinct child pid and distinct nonzero cookies.
        let mut fork: p11scope_ebpf_common::Event = unsafe { std::mem::zeroed() };
        fork.event_type = p11scope_ebpf_common::event_type::FORK;
        fork.pid_tgid = 100u64 << 32;
        fork.session = 200;
        fork.image = parent_image;
        fork.child_image = p11scope_ebpf_common::ImageIdentity {
            task_cookie: 20,
            exec_id: 0,
        };
        assert!(observe_fork(
            domain,
            &mut tracker,
            &mut state,
            &Scope::System,
            &fork
        ));
        assert_eq!(
            state.semantic_evidence().semantic_history_drops,
            0,
            "genuine fork must admit without history rejection"
        );
        assert_eq!(
            state.sessions().inherited,
            1,
            "child must inherit the parent open session"
        );
        // Birth is one-shot: replaying it must not duplicate the inheritance.
        assert!(observe_fork(
            domain,
            &mut tracker,
            &mut state,
            &Scope::System,
            &fork
        ));
        assert_eq!(state.sessions().inherited, 1);
        // Negative control: the old malformed shape (same pid, zero cookies)
        // is handled but records a rejection.
        let drops_before = state.semantic_evidence().semantic_history_drops;
        let mut malformed: p11scope_ebpf_common::Event = unsafe { std::mem::zeroed() };
        malformed.event_type = p11scope_ebpf_common::event_type::FORK;
        malformed.pid_tgid = 100u64 << 32;
        malformed.session = 100;
        assert!(observe_fork(
            domain,
            &mut tracker,
            &mut state,
            &Scope::System,
            &malformed
        ));
        assert_eq!(
            state.semantic_evidence().semantic_history_drops,
            drops_before + 1,
            "malformed fork must record a rejection"
        );
    }

    #[test]
    fn signal_state_retains_first_identity_and_saturates_sigint_deliveries() {
        let state = SignalState::new();
        state.observe(libc::SIGTERM);
        state.observe(libc::SIGINT);
        state.observe(libc::SIGINT);
        state.observe(libc::SIGINT);

        assert_eq!(state.first_signal(), Some(libc::SIGTERM));
        assert_eq!(state.sigint_deliveries(), 2);
    }

    /// Finding nothing is not an error, so the only thing that keeps the operator
    /// from a silent empty report is this line naming the two commands that explain.
    #[test]
    fn zero_modules_points_at_inspect_and_doctor() {
        let hint = no_modules_hint(&ScopeArg::Pid(42));
        assert!(
            hint.contains("no PKCS#11 modules discovered in pid 42"),
            "{hint}"
        );
        assert!(hint.contains("p11scope inspect --pid 42"), "{hint}");
        assert!(hint.contains("p11scope doctor --pid 42"), "{hint}");
        let hint = no_modules_hint(&ScopeArg::Cgroup("/sys/fs/cgroup/x".into()));
        assert!(hint.contains("cgroup /sys/fs/cgroup/x"), "{hint}");
        assert!(hint.contains("p11scope inspect --pid"), "{hint}");
        assert!(
            hint.contains("p11scope doctor --cgroup /sys/fs/cgroup/x"),
            "{hint}"
        );
        let hint = no_modules_hint(&ScopeArg::System);
        assert!(hint.contains("system-wide"), "{hint}");
        assert!(hint.contains("p11scope inspect --pid"), "{hint}");
        assert!(hint.contains("p11scope doctor"), "{hint}");
    }

    /// `inspect` propagates a hard error for a pid that names nothing; it must reach
    /// the operator as one line and exit 1, never as a panic or a backtrace dump.
    #[test]
    fn inspect_on_a_nonexistent_pid_is_one_line_and_not_a_panic() {
        // Above /proc/sys/kernel/pid_max on every supported kernel.
        let error = crate::inspect::run(
            0x7fff_fff0,
            &[],
            &crate::discovery::hooks::HookRegistry::builtin(),
            false,
        )
        .expect_err("a pid that names nothing cannot be inspected");
        let rendered = format!("{error:#}");
        assert_eq!(rendered.lines().count(), 1, "{rendered}");
        assert!(rendered.contains("2147483632"), "{rendered}");
    }

    /// The finalization a stopped loop runs into: `-o` publication produces
    /// valid JSON and replaces stale content atomically (adapted from the
    /// previous shutdown-path test).
    #[test]
    fn shutdown_path_publishes_valid_json_over_a_stale_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut permissions = std::fs::metadata(dir.path()).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(dir.path(), permissions).unwrap();
        let path = dir.path().join("observed.json");
        std::fs::write(&path, b"stale trailing bytes that must disappear").unwrap();
        let j = serde_json::json!({"schema": "p11scope/observed-profile/v3", "evidence": {}});
        let mut out = AtomicFile::create(&path).unwrap();
        write_json_report(out.file(), &j).expect("shutdown finalization must write the report");
        out.commit().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["schema"], "p11scope/observed-profile/v3");
    }

    /// The unsafe policy is refused by `CapturePolicy::from_cli` on the parsed
    /// arguments alone — before the manifest path is ever opened.
    #[cfg(not(feature = "unsafe-unvalidated-metadata"))]
    #[test]
    fn policy_output_unsafe_flag_is_refused_before_manifest_loading() {
        let a = cli::parse_capture(
            Kind::Profile,
            [
                "--unsafe-unvalidated-metadata",
                "--manifest",
                "/definitely/not/a/manifest.json",
                "--pid",
                "1",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap();
        let error = CapturePolicy::from_cli(
            "profile",
            a.unsafe_requested,
            cfg!(feature = "unsafe-unvalidated-metadata"),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("Cargo feature"), "{rendered}");
        assert!(!rendered.contains("reading manifest"), "{rendered}");
    }

    #[test]
    fn broken_stdout_closes_only_that_sink_and_file_continues() {
        let mut stdout = FailingWriter {
            kind: std::io::ErrorKind::BrokenPipe,
            fail_flush: false,
        };
        let mut stdout_open = true;
        let mut file = Some(Vec::new());
        emit_trace_line("final", &mut stdout, &mut stdout_open, &mut file).unwrap();
        assert!(!stdout_open);
        assert_eq!(file.unwrap(), b"final\n");
    }

    #[test]
    fn trace_file_write_and_flush_errors_propagate() {
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut file = Some(FailingWriter {
            kind: std::io::ErrorKind::Other,
            fail_flush: false,
        });
        assert!(emit_trace_line("x", &mut stdout, &mut stdout_open, &mut file).is_err());

        let mut flush = FailingWriter {
            kind: std::io::ErrorKind::Other,
            fail_flush: true,
        };
        let mut open = true;
        assert!(flush_stdout(&mut flush, &mut open).is_err());
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod history_tests;

#[cfg(test)]
mod correction1_tests {
    use super::*;
    use crate::events::{EventDrain, ScriptedRecords};
    use crate::history::{Membership, TaskMembership};
    use p11scope_ebpf_common::{Event, ImageIdentity, capture, event_type};
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        os::fd::{AsRawFd, OwnedFd, RawFd},
        rc::Rc,
    };

    #[derive(Default)]
    struct MembershipScript {
        candidates: BTreeMap<u32, Arc<OwnedFd>>,
        samples: BTreeMap<RawFd, Membership>,
        queries: usize,
    }
    #[derive(Clone, Default)]
    struct Adapter(Rc<RefCell<MembershipScript>>);
    impl TaskMembership for Adapter {
        fn candidate(&mut self, pid: u32) -> Option<Arc<OwnedFd>> {
            self.0.borrow_mut().queries += 1;
            self.0.borrow().candidates.get(&pid).cloned()
        }
        fn sample(&mut self, original: &OwnedFd) -> Membership {
            self.0.borrow_mut().queries += 1;
            self.0
                .borrow()
                .samples
                .get(&original.as_raw_fd())
                .copied()
                .unwrap_or(Membership::Unavailable)
        }
    }
    impl Adapter {
        fn bind(&self, pid: u32, cookie: u64) -> Arc<OwnedFd> {
            let fd: OwnedFd = File::open("/dev/null").unwrap().into();
            let fd = Arc::new(fd);
            self.0.borrow_mut().candidates.insert(pid, fd.clone());
            self.set(&fd, Membership::Live { domain: 1, cookie });
            fd
        }
        fn set(&self, fd: &OwnedFd, sample: Membership) {
            self.0.borrow_mut().samples.insert(fd.as_raw_fd(), sample);
        }
    }
    fn plan(authorized: bool) -> crate::plan::AttachPlan {
        crate::plan::AttachPlan::from_slots(
            ["C_OpenSession", "C_Sign", "C_GetInfo"]
                .into_iter()
                .enumerate()
                .map(|(index, name)| crate::plan::Slot {
                    index: index as u32,
                    descriptor_index: crate::kinds::function_id(name).unwrap() + 1,
                    object: crate::plan::TEST_PINNED_OBJECT,
                    object_path: "/opt/p11.so".into(),
                    file_offset: index as u64 * 16,
                    names: vec![name.into()],
                    aliased: false,
                    semantics: if authorized {
                        crate::kinds::descriptor(name).unwrap()
                    } else {
                        p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
                    },
                    semantic_authorized: authorized,
                    semantic_ambiguous: false,
                    fork_safe: true,
                    module_ids: vec![crate::plan::ModuleId(0)],
                })
                .collect(),
        )
    }
    fn event(pid: u32, cookie: u64, slot: u32) -> Event {
        Event {
            image: ImageIdentity {
                task_cookie: cookie,
                exec_id: 0,
            },
            event_type: event_type::CALL,
            pid_tgid: u64::from(pid) << 32,
            session: 7,
            slot_id: 3,
            slot,
            capture: capture::OUTPUT_NON_NULL,
            ..Event::default()
        }
    }
    struct Consumer {
        state: semantics::State,
        tracker: process::Tracker,
        tracer: trace::Tracer,
        adapter: Adapter,
        trace: bool,
        output: Vec<u8>,
    }
    impl Consumer {
        fn new(trace: bool, authorized: bool) -> Self {
            let adapter = Adapter::default();
            let plan = plan(authorized);
            Self {
                state: semantics::State::new(&plan),
                tracker: process::Tracker::with_membership(1, 16, 16, Box::new(adapter.clone())),
                tracer: trace::Tracer::new(&plan),
                adapter,
                trace,
                output: Vec::new(),
            }
        }
        fn feed(&mut self, records: impl IntoIterator<Item = Event>) {
            self.feed_domain(self.tracker.producer_domain(), records);
        }
        fn feed_domain(&mut self, domain: u64, records: impl IntoIterator<Item = Event>) {
            let mut drain =
                EventDrain::over_test_domain(ScriptedRecords::events(records, usize::MAX), domain);
            let scope = Scope::Cgroup {
                id: 0,
                path: "/".into(),
                dir: Arc::new(File::open("/").unwrap()),
            };
            if self.trace {
                drain_trace_events_from(
                    &mut drain,
                    &mut None,
                    &mut self.state,
                    &mut self.tracker,
                    &scope,
                    &mut self.tracer,
                    &mut self.output,
                    &mut true,
                    &mut None::<Vec<u8>>,
                    Some(crate::events::LIVE_POLL_QUANTUM),
                )
                .unwrap();
            } else {
                drain_profile_events(
                    &mut drain,
                    &mut self.state,
                    &mut self.tracker,
                    &scope,
                    Some(crate::events::LIVE_POLL_QUANTUM),
                )
                .unwrap();
            }
            assert_eq!(drain.source().remaining(), 0);
        }
        fn vector(&self) -> (u64, u64, u64, u64, u64, u64) {
            let s = self.state.sessions();
            (
                s.opened,
                s.inherited,
                s.closed,
                s.opened
                    .saturating_add(s.inherited)
                    .saturating_sub(s.closed),
                s.peak_concurrent,
                self.state.pending_at_end(),
            )
        }
    }

    #[test]
    fn replacement_first_open_retains_unfenced_predecessor_in_both_drains() {
        for trace in [false, true] {
            let mut c = Consumer::new(trace, true);
            let old = c.adapter.bind(100, 90);
            let mut pending = event(100, 90, 1);
            pending.rv = pkcs11_types::CkRv::PENDING.0;
            c.feed([event(100, 90, 0), pending]);
            assert_eq!(c.vector(), (1, 0, 0, 1, 1, 1));
            let replacement = c.adapter.bind(100, 4);
            c.adapter.set(&old, Membership::Exited);
            // Actual capture drains before polling exits. No preceding poll here.
            c.feed([event(100, 4, 0)]);
            assert_eq!(c.vector(), (2, 0, 0, 2, 2, 1));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 0);
            assert!(c.tracker.poll_exited().is_empty());
            assert!(c.tracker.poll_exited().is_empty());
            assert_eq!(c.vector(), (2, 0, 0, 2, 2, 1));
            apply_confirmed_retirement(
                &mut c.tracker,
                &mut c.state,
                semantics::ProcessKey::history(1, 90, 0, 100),
            );
            c.feed([event(100, 90, 0)]);
            assert_eq!(c.vector(), (2, 0, 1, 1, 2, 0));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 1);
            c.adapter.set(&replacement, Membership::Exited);
            assert!(c.tracker.poll_exited().is_empty());
            assert!(c.tracker.poll_exited().is_empty());
            assert_eq!(c.vector(), (2, 0, 1, 1, 2, 0));
            apply_confirmed_retirement(
                &mut c.tracker,
                &mut c.state,
                semantics::ProcessKey::history(1, 4, 0, 100),
            );
            apply_confirmed_retirement(
                &mut c.tracker,
                &mut c.state,
                semantics::ProcessKey::history(1, 4, 0, 100),
            );
            assert_eq!(c.vector(), (2, 0, 2, 0, 2, 0));
            if trace {
                assert_eq!(c.tracer.raw_calls(), 4);
            }
        }
    }

    #[test]
    fn producer_admission_ignores_optional_control_samples_without_retiring() {
        for trace in [false, true] {
            for old_sample in [
                Membership::Live {
                    domain: 1,
                    cookie: 90,
                },
                Membership::Unavailable,
                Membership::Live {
                    domain: 2,
                    cookie: 90,
                },
            ] {
                let mut c = Consumer::new(trace, true);
                let old = c.adapter.bind(100, 90);
                c.adapter.bind(200, 20);
                c.feed([event(100, 90, 0), event(200, 20, 0)]);
                c.adapter.bind(100, 4);
                c.adapter.set(&old, old_sample);
                c.feed([event(100, 4, 0), event(100, 4, 2)]);
                assert!(c.tracker.poll_exited().is_empty());
                assert_eq!(c.vector(), (3, 0, 0, 3, 3, 0));
                assert_eq!(c.state.semantic_evidence().semantic_history_drops, 0);
                // Exit alone changes no semantic eligibility; all histories survive.
                c.adapter.set(&old, Membership::Exited);
                c.feed([event(100, 4, 2)]);
                assert_eq!(c.vector(), (3, 0, 0, 3, 3, 0));
            }
        }
    }

    #[test]
    fn replacement_first_birth_fork_keeps_independent_unfenced_old_child() {
        for trace in [false, true] {
            let mut c = Consumer::new(trace, true);
            c.adapter.bind(100, 90);
            let old_child = c.adapter.bind(200, 80);
            c.feed([event(100, 90, 0), event(200, 80, 0)]);
            c.adapter.bind(200, 4);
            c.adapter.set(&old_child, Membership::Exited);
            let mut birth = event(100, 90, 0);
            birth.event_type = event_type::FORK;
            birth.session = 200;
            birth.child_image = ImageIdentity {
                task_cookie: 4,
                exec_id: 0,
            };
            c.feed([birth]);
            assert_eq!(c.vector(), (2, 1, 0, 3, 3, 0));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 0);
            let key = semantics::ProcessKey::history(1, 4, 0, 200);
            assert!(c.state.session_pseudonym_process(key, 0, 7).is_some());
            c.feed([event(200, 4, 2), birth]);
            assert_eq!(c.vector(), (2, 1, 0, 3, 3, 0));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 1);
        }
    }

    #[test]
    fn authentic_unbound_and_closed_trace_preserves_unverified_provider_annotation() {
        for closed in [false, true] {
            let mut c = Consumer::new(true, false);
            if closed {
                let fd = c.adapter.bind(100, 90);
                c.feed([event(100, 90, 2)]);
                c.adapter.set(&fd, Membership::Exited);
                assert!(c.tracker.poll_exited().is_empty());
                apply_confirmed_retirement(
                    &mut c.tracker,
                    &mut c.state,
                    semantics::ProcessKey::history(1, 90, 0, 100),
                );
                c.output.clear();
            }
            let before = c.tracer.raw_calls();
            let mut ev = event(100, 90, 0);
            ev.capture |= capture::MECHANISM_VALUE;
            ev.mechanism = 1;
            c.feed([ev]);
            let line = String::from_utf8(c.output).unwrap();
            assert!(
                line.contains("C_OpenSession [semantics unverified]"),
                "{line}"
            );
            assert!(!line.contains("sess#"));
            assert!(!line.contains("CKM_"));
            assert_eq!(c.tracer.raw_calls(), before + 1);
            assert_eq!(
                c.state.semantic_evidence().semantic_history_drops,
                u64::from(closed)
            );
            assert_eq!(c.state.sessions().opened, 0);
            assert!(c.state.mechanisms().is_empty());
        }
    }

    #[test]
    fn correction2_unseeded_first_call_after_reap_or_unavailable_is_admitted() {
        for trace in [false, true] {
            for outcome in [Membership::Exited, Membership::Unavailable] {
                let mut c = Consumer::new(trace, true);
                let fd = c.adapter.bind(100, 90);
                c.adapter.set(&fd, outcome);
                c.feed([event(100, 90, 0)]);
                assert_eq!(c.vector(), (1, 0, 0, 1, 1, 0));
                assert_eq!(c.state.semantic_evidence().semantic_history_drops, 0);
                assert_eq!(
                    c.adapter.0.borrow().queries,
                    0,
                    "events grant no live/control binding"
                );
                if trace {
                    assert_eq!(c.tracer.raw_calls(), 1);
                }
            }
        }
    }

    #[test]
    fn correction2_first_fork_after_both_reaped_preserves_inheritance_once() {
        for trace in [false, true] {
            let mut c = Consumer::new(trace, true);
            let parent = c.adapter.bind(100, 90);
            let child = c.adapter.bind(200, 4);
            c.adapter.set(&parent, Membership::Exited);
            c.adapter.set(&child, Membership::Exited);
            c.feed([event(100, 90, 0)]);
            let mut birth = event(100, 90, 0);
            birth.event_type = event_type::FORK;
            birth.session = 200;
            birth.child_image = ImageIdentity {
                task_cookie: 4,
                exec_id: 0,
            };
            c.feed([birth]);
            assert_eq!(c.vector(), (1, 1, 0, 2, 2, 0));
            c.feed([event(200, 4, 2), birth]);
            assert_eq!(c.vector(), (1, 1, 0, 2, 2, 0));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 1);
            assert_eq!(c.adapter.0.borrow().queries, 0);
        }
    }

    #[test]
    fn correction2_first_fork_establishes_empty_parent_without_inventing_sessions() {
        for trace in [false, true] {
            let mut c = Consumer::new(trace, true);
            let mut birth = event(100, 90, 0);
            birth.event_type = event_type::FORK;
            birth.session = 200;
            birth.child_image = ImageIdentity {
                task_cookie: 4,
                exec_id: 0,
            };
            c.feed([birth]);
            assert_eq!(c.vector(), (0, 0, 0, 0, 0, 0));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 0);
            c.feed([event(200, 4, 0), birth]);
            assert_eq!(c.vector(), (1, 0, 0, 1, 1, 0));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 1);
        }
    }

    #[test]
    fn correction2_same_pid_live_original_does_not_activate_or_close_other_cookie() {
        for trace in [false, true] {
            let mut c = Consumer::new(trace, true);
            let original = c.adapter.bind(100, 90);
            c.feed([event(100, 90, 0)]);
            c.adapter.bind(100, 4);
            c.feed([event(100, 4, 0)]);
            assert_eq!(c.vector(), (2, 0, 0, 2, 2, 0));
            c.adapter.set(&original, Membership::Exited);
            assert!(c.tracker.poll_exited().is_empty());
            c.feed([event(100, 90, 2)]);
            assert_eq!(c.vector(), (2, 0, 0, 2, 2, 0));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 0);
            assert_eq!(c.adapter.0.borrow().queries, 0);
        }
    }

    #[test]
    fn correction2_invalid_closed_lower_exec_foreign_and_capacity_are_counted_once() {
        for trace in [false, true] {
            let mut c = Consumer::new(trace, true);
            c.tracker =
                process::Tracker::for_producer(crate::events::EventsDomain::test_standin(1), 1);
            c.feed([event(100, 90, 0)]);
            let mut successor = event(100, 90, 0);
            successor.image.exec_id = 1;
            c.feed([successor]);
            assert_eq!(c.vector(), (2, 0, 1, 1, 1, 0));
            // Foreign or old exact retirement cannot retire the retained successor.
            for key in [
                semantics::ProcessKey::history(2, 90, 1, 100),
                semantics::ProcessKey::history(1, 90, 0, 100),
            ] {
                apply_confirmed_retirement(&mut c.tracker, &mut c.state, key);
            }
            assert_eq!(c.vector(), (2, 0, 1, 1, 1, 0));
            for (index, (domain, ev)) in [
                (1, event(100, 90, 0)), // lower exec
                (1, event(100, 0, 0)),  // invalid zero cookie
                (2, successor),         // foreign source domain
                (1, event(100, 4, 0)),  // finite cookie budget exhausted
                (1, event(0, 90, 0)),   // malformed producer PID
            ]
            .into_iter()
            .enumerate()
            {
                c.feed_domain(domain, [ev]);
                assert_eq!(
                    c.state.semantic_evidence().semantic_history_drops,
                    index as u64 + 1
                );
                assert_eq!(c.vector(), (2, 0, 1, 1, 1, 0));
            }
            let key = semantics::ProcessKey::history(1, 90, 1, 100);
            apply_confirmed_retirement(&mut c.tracker, &mut c.state, key);
            apply_confirmed_retirement(&mut c.tracker, &mut c.state, key);
            assert_eq!(c.vector(), (2, 0, 2, 0, 1, 0));
            c.feed([successor]); // Explicitly Closed is permanent.
            c.feed_domain(0, [successor]);
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 7);
            assert_eq!(c.vector(), (2, 0, 2, 0, 1, 0));
            if trace {
                assert_eq!(c.tracer.raw_calls(), 9);
            }
        }
    }

    #[test]
    fn correction2_exit_without_fence_preserves_tail_and_pending_until_explicit_retirement() {
        for trace in [false, true] {
            let mut c = Consumer::new(trace, true);
            let fd = c.adapter.bind(100, 90);
            let mut pending = event(100, 90, 1);
            pending.rv = pkcs11_types::CkRv::PENDING.0;
            c.feed([event(100, 90, 0), pending]);
            c.adapter.set(&fd, Membership::Exited);
            assert!(c.tracker.poll_exited().is_empty());
            let mut tail = event(100, 90, 0);
            tail.session = 8;
            c.feed([tail]);
            assert_eq!(c.vector(), (2, 0, 0, 2, 2, 1));
            assert_eq!(c.state.semantic_evidence().semantic_history_drops, 0);
            // Explicit injected confirmation models the next owner's completed
            // fence, not a claim that this test implements a real ring cursor.
            let key = semantics::ProcessKey::history(1, 90, 0, 100);
            apply_confirmed_retirement(&mut c.tracker, &mut c.state, key);
            apply_confirmed_retirement(&mut c.tracker, &mut c.state, key);
            assert_eq!(c.vector(), (2, 0, 2, 0, 2, 0));
            assert_eq!(c.adapter.0.borrow().queries, 0);
        }
    }
}
