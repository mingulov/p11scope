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
    ArmResult, PauseCoordinator, PauseError, PauseIo, PauseStatus, SessionPauseIo,
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
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
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

/// The launch-file checks: a regular executable file, and ELF (scripts
/// must go through an interpreter). Shared by the fail-fast pre-fork
/// refusal and `OwnedChild::spawn`'s own guard, so the early refusal
/// never weakens the guard at the fork.
fn check_launch_file(launch_file: &File) -> io::Result<()> {
    let metadata = launch_file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "owned command must be a regular executable file",
        ));
    }
    if let Err(error) = ElfSnapshot::read(launch_file) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "owned command must be an ELF executable: {error}; invoke scripts through an interpreter"
            ),
        ));
    }
    Ok(())
}

/// Refuses a command that cannot run as an owned target by name, before
/// anything is forked. Name errors precede hazard errors: a script is
/// told about its interpreter before any kernel verdict is consulted.
fn check_owned_target_runnable(program: &OsStr) -> io::Result<()> {
    let resolved = resolve_program(program)?;
    let launch_file = File::open(&resolved)?;
    check_launch_file(&launch_file)
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
    /// The CLOEXEC exec pipe reached EOF with no errno frame, so the child
    /// has left this process's pre-exec image (it exec'd, or it died) and can
    /// no longer take a release byte and start the command late. Only such a
    /// child is ever resumed or asked to stop gracefully.
    exec_confirmed: bool,
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
        check_launch_file(&launch_file)?;
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
        // SAFETY: an all-zero sigaction is SIG_DFL with an empty mask and no
        // flags; prepared here so the child only passes it to sigaction.
        let default_action: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: as above, but naming SIG_IGN; prepared here for the same
        // reason, so restoring an inherited ignore stays signal-safe.
        let mut ignore_action: libc::sigaction = unsafe { std::mem::zeroed() };
        ignore_action.sa_sigaction = libc::SIG_IGN;
        // Read before the fork: the child takes no locks.
        let startup = startup_dispositions_for_child();

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
                // The observer's stop handlers belong to the observer, and the
                // command inherits exactly what the observer inherited:
                // restore the startup dispositions captured in `main`, so
                // until it execs this child neither runs a handler nor
                // swallows a stop signal meant to end it. SIGPIPE always
                // resets to the default: the runtime ignored it before
                // `main`, and the default matches `std::process::Command`.
                // Applied before setsid, so a session leader has already
                // settled them; exec resets caught signals anyway.
                for signal in STOP_SIGNALS {
                    let action = if startup.ignored(signal) {
                        &ignore_action
                    } else {
                        &default_action
                    };
                    if libc::sigaction(signal, action, std::ptr::null_mut()) != 0 {
                        child_exec_failure_errno(exec_writer.as_raw_fd(), last_errno());
                    }
                }
                if libc::sigaction(libc::SIGPIPE, &default_action, std::ptr::null_mut()) != 0 {
                    child_exec_failure_errno(exec_writer.as_raw_fd(), last_errno());
                }
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
            exec_confirmed: false,
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
        // From here the release byte is the child's to take. A handoff that
        // ends without a confirmed exec kills the child where it stands, so
        // nothing later (a resume included) lets it run the abandoned command.
        // An exec errno frame needs no kill: that child can only _exit(127).
        let awaited = self.await_exec(&reader, deadline, &mut cancelled, &mut pending);
        if let Err(error) = &awaited
            && !self.exec_confirmed
            && !matches!(error, ExecHandoffError::Exec(_))
        {
            self.abandon_unconfirmed_exec();
        }
        awaited
    }

    /// Waits on the exec pipe after the release byte was written: EOF with no
    /// errno frame confirms the exec, and an errno frame is an exec failure.
    fn await_exec(
        &mut self,
        reader: &OwnedFd,
        deadline: Instant,
        mut cancelled: impl FnMut() -> Option<i32>,
        mut pending: impl FnMut(),
    ) -> Result<(), ExecHandoffError> {
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
                    self.exec_confirmed = true;
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
        if !self.exec_confirmed {
            // Still this process's pre-exec fork: resuming it or asking it to
            // stop could let it take a written release byte and run the
            // command. Kill it where it stands.
            return self.kill_and_reap_tail();
        }
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

    /// SIGCONT the owned child through its pidfd, best effort, and only once
    /// its exec is confirmed. A child held in T cannot observe SIGTERM/SIGINT,
    /// so every graceful settle path resumes first; on a running child this
    /// is a no-op, and on an exited child the error is ignored. A pre-exec
    /// child is never resumed: with the release byte written, resuming it
    /// would run the command the handoff abandoned.
    fn resume_if_stopped(&self) {
        if self.exec_confirmed {
            let _ = self.pin.send_signal(libc::SIGCONT);
        }
    }

    /// The release byte left this process but no exec was confirmed: the
    /// child may be stopped, descheduled, or about to take the byte. A
    /// pending SIGKILL ends it before it next runs user code, so unless it
    /// had already finished exec'ing, the abandoned command never starts.
    /// Best effort and never a reap: settlement still reaps this exact child
    /// after coordinator cleanup, and kills it again if this did not land.
    fn abandon_unconfirmed_exec(&self) {
        let _ = signal_group(self.pid, libc::SIGKILL);
        let _ = self.pin.send_signal(libc::SIGKILL);
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

/// All three operator stop signals end a capture the same clean way. SIGTERM
/// is what a supervisor (systemd, a container runtime, `timeout`) sends,
/// SIGHUP is what a closed terminal or a dropped ssh session sends, and
/// every default disposition here would kill the process mid-write. SIGINT
/// and SIGTERM are always caught; SIGHUP is installed only over the default
/// disposition (see `install_stop_flag`), so an inherited ignore survives.
const STOP_SIGNALS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

/// Installs handlers that only ever update atomic signal state — no allocation,
/// no I/O, no locks, and no child signaling or cleanup. Every capture loop
/// polls this state cooperatively, the same way it polls `--duration`
/// elapsing, so Ctrl-C, SIGTERM, or a hangup ends a capture the same clean
/// way: stop polling, print the final frame, write `-o` if given — never
/// torn down mid-write.
///
/// `signal_hook::low_level::register` is used instead of a hand-rolled
/// `libc::signal` handler: the callback is the signal-safe minimum, while the
/// capture loop retains the first identity and counts repeated Ctrl-C.
/// The sink watches the same observation through `cancel_flag`, so a
/// slow-stdout flush sheds promptly instead of waiting out its budget.
struct SignalState {
    state: AtomicU64,
    cancel: Arc<AtomicBool>,
}

impl SignalState {
    fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The flag the stdout sink watches: set on the first observed stop
    /// signal, alongside the identity above. Signal-safe to share; the
    /// sink only loads it.
    fn cancel_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancel)
    }

    fn observe(&self, signal: libc::c_int) {
        self.cancel.store(true, Ordering::SeqCst);
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

/// Reads one signal's current disposition without changing it. A null new
/// action makes `sigaction` report only. An unreadable disposition (an
/// invalid signal, which the callers never pass) reports as the default,
/// which is the install-everything direction.
fn current_disposition(signal: libc::c_int) -> libc::sighandler_t {
    // SAFETY: zeroed sigaction is the documented output buffer, and a null
    // new action reads the current disposition without installing.
    let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
    let read = unsafe { libc::sigaction(signal, std::ptr::null(), &mut current) };
    if read != 0 {
        return libc::SIG_DFL;
    }
    current.sa_sigaction
}

/// Whether the hangup handler is installed over SIGHUP's observed
/// disposition. After `execve` only `SIG_DFL` and `SIG_IGN` can be
/// inherited; an inherited ignore (`nohup p11scope ...`) is preserved so
/// the capture keeps running after logout, and anything else — the default
/// in practice — takes the handler. A pure function so the decision is
/// directly unit-testable without sending a real hangup.
fn should_install_hangup_handler(disposition: libc::sighandler_t) -> bool {
    disposition != libc::SIG_IGN
}

/// The signal dispositions p11scope itself inherited, captured in `main`
/// before any handler is installed. The owned command restores exactly
/// these for every signal the observer changes, so the observed program
/// behaves as if started directly: an ignore (`nohup`, a backgrounded
/// non-interactive shell) stays ignored, a default stays default. SIGPIPE
/// is not captured — the Rust runtime overwrote the original before `main`
/// — and always resets to the default in the child, matching
/// `std::process::Command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StartupSignalDispositions {
    int_ignored: bool,
    term_ignored: bool,
    hup_ignored: bool,
}

impl StartupSignalDispositions {
    fn all_default() -> Self {
        Self {
            int_ignored: false,
            term_ignored: false,
            hup_ignored: false,
        }
    }

    fn ignored(&self, signal: libc::c_int) -> bool {
        match signal {
            libc::SIGINT => self.int_ignored,
            libc::SIGTERM => self.term_ignored,
            libc::SIGHUP => self.hup_ignored,
            _ => false,
        }
    }
}

/// Bit-packed startup dispositions: bit 0 is set once captured, bits 1-3
/// record SIGINT/SIGTERM/SIGHUP ignored. An atomic so the pre-fork read in
/// `OwnedChild::spawn` takes no lock.
static STARTUP_SIGNAL_DISPOSITIONS: AtomicU8 = AtomicU8::new(0);
const STARTUP_CAPTURED: u8 = 1 << 0;
const STARTUP_INT_IGNORED: u8 = 1 << 1;
const STARTUP_TERM_IGNORED: u8 = 1 << 2;
const STARTUP_HUP_IGNORED: u8 = 1 << 3;

/// Captures the dispositions p11scope itself inherited, for the owned
/// command to restore. Called once by `main` before any handler installs.
/// Anything but `SIG_IGN` reads as the default: after `execve` only the
/// two exist, and a caught disposition here would mean a late call, in
/// which case the child must still drop the handler.
pub fn capture_startup_signal_dispositions() {
    let mut packed = STARTUP_CAPTURED;
    if current_disposition(libc::SIGINT) == libc::SIG_IGN {
        packed |= STARTUP_INT_IGNORED;
    }
    if current_disposition(libc::SIGTERM) == libc::SIG_IGN {
        packed |= STARTUP_TERM_IGNORED;
    }
    if current_disposition(libc::SIGHUP) == libc::SIG_IGN {
        packed |= STARTUP_HUP_IGNORED;
    }
    STARTUP_SIGNAL_DISPOSITIONS.store(packed, Ordering::SeqCst);
}

/// The startup dispositions to restore in the fork child: the captured
/// inheritance, or all-default when the embedder never captured (library
/// use without `main` keeps the historical reset-to-default behavior).
fn startup_dispositions_for_child() -> StartupSignalDispositions {
    let packed = STARTUP_SIGNAL_DISPOSITIONS.load(Ordering::SeqCst);
    if packed & STARTUP_CAPTURED == 0 {
        return StartupSignalDispositions::all_default();
    }
    StartupSignalDispositions {
        int_ignored: packed & STARTUP_INT_IGNORED != 0,
        term_ignored: packed & STARTUP_TERM_IGNORED != 0,
        hup_ignored: packed & STARTUP_HUP_IGNORED != 0,
    }
}

#[cfg(test)]
fn clear_startup_signal_dispositions_for_test() {
    STARTUP_SIGNAL_DISPOSITIONS.store(0, Ordering::SeqCst);
}

fn install_stop_flag() -> Result<Arc<SignalState>> {
    let state = Arc::new(SignalState::new());
    for signal in STOP_SIGNALS {
        if signal == libc::SIGHUP && !should_install_hangup_handler(current_disposition(signal)) {
            continue;
        }
        // A hangup is recorded as SIGTERM: the same stop path, the same
        // forwarded signal, the same outcome and exit status.
        let recorded = if signal == libc::SIGHUP {
            libc::SIGTERM
        } else {
            signal
        };
        let observed = Arc::clone(&state);
        // SAFETY: the callback performs only atomic operations.
        unsafe { signal_hook::low_level::register(signal, move || observed.observe(recorded)) }
            .with_context(|| format!("installing handler for signal {signal}"))?;
    }
    Ok(state)
}

/// Whether a capture loop should stop this tick: interrupted (Ctrl-C,
/// SIGTERM, or a hangup, which is recorded as SIGTERM) or `--duration`
/// elapsed. A pure function so the stop path is directly testable without
/// sending a real signal — set the state, confirm this returns `true`
/// regardless of `elapsed`/`duration`.
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
        eprintln!("{}", no_duration_notice());
    }
    warn_unsafe_policy(policy);
    let accepted = preflight_uretprobe_hazard(
        match &a.scope {
            ScopeArg::Pid(pid) => Some(*pid),
            ScopeArg::Cgroup(_) | ScopeArg::System => None,
        },
        a.allow_confined_uretprobe,
    )?;
    let accepted_uretprobe_risk = accepted.is_some();
    // Durable, not just stderr (SYSPLAN residual F-01): the override flag +
    // hazard reason travel with the evidence this capture renders.
    let uretprobe_override = accepted.map(|reason| render::UretprobeOverride {
        flag: "--allow-uretprobe-on-confined-target",
        reason,
    });
    // Before the discovery scan: a bad `-o` path must fail fast (F-Scale-6)
    // instead of after a scan — and still before any probe is on. The profile
    // sink stays an atomically-published temp file; opening it early only
    // moves the trust failure earlier.
    let out = OutputSink::open(kind, a.out.as_deref())?;
    let mut engine = Engine::discover(a, &scope, named_view)?;
    // Zero modules is not an error (spec §4.10): the capture still runs, still
    // writes its report, and says here how to find out why it found nothing.
    if engine.plan().modules.is_empty() {
        eprintln!("{}", no_modules_hint(&a.scope));
    }
    let stop = install_stop_flag()?;
    let mut session = engine
        .start_session(policy, a.ring_bytes, a.attach_backend)
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
        uretprobe_override,
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

/// The no-duration notice (SYSPLAN residual F-17): "until interrupted" is
/// only half the story — the event cap still applies, so the notice names
/// the effective default rather than promising unbounded streaming.
fn no_duration_notice() -> String {
    format!(
        "p11scope: no --duration given; trace streams until interrupted (Ctrl-C) or the \
         process exits (event cap still applies: default {DEFAULT_TRACE_MAX_EVENTS} events, \
         --max-events to change)"
    )
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
    uretprobe_override: Option<render::UretprobeOverride>,
) -> Result<render::Evidence> {
    report_attach_failures(session);
    let drain = resolve_drain_cadence(kind, drain_interval);
    let evidence = match kind {
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
                uretprobe_override,
            )?
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
                uretprobe_override,
            )?
        }
    };
    engine.report_discovery_noise();
    Ok(evidence)
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
    settle_after_signal_with_grace_and(child, signals, grace, || {})
}

fn settle_after_signal_with_grace_and(
    child: &mut OwnedChild,
    signals: &SignalState,
    grace: Duration,
    mut after_fallback_term: impl FnMut(),
) -> Result<ChildOutcome> {
    child.begin_settlement(grace.saturating_mul(2).saturating_add(FINAL_KILL_GRACE));
    let signal = signals
        .first_signal()
        .ok_or_else(|| anyhow!("run: signal settlement lost the first signal identity"))?;
    if !child.exec_confirmed {
        // Graceful settlement is for a command that is running. A child whose
        // exec was never confirmed is still this process's pre-exec fork:
        // resuming or signalling it could let it take a written release byte
        // and run the command. Kill it where it stands.
        return child
            .kill_and_reap_tail()
            .map(ChildOutcome::Exited)
            .map_err(|error| anyhow!("run: settling after signal: {error}"));
    }
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
            after_fallback_term();
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
    // Name errors precede hazard errors: a script (or a non-executable)
    // is refused with its interpreter fix before any kernel verdict is
    // consulted, exactly as `spawn` would refuse it at the fork.
    check_owned_target_runnable(&program)
        .map_err(|error| anyhow!("run: starting the owned child: {error}"))?;
    // Before the fork: the owned child can install a seccomp filter after
    // attach, so no startup /proc reading can qualify it — only a kernel
    // proven to exempt the trampoline proceeds by default (F-01). An
    // initial unconfined status cannot qualify that future state.
    let uretprobe_override =
        preflight_uretprobe_hazard(None, args.allow_confined_uretprobe)?.map(|reason| {
            render::UretprobeOverride {
                flag: "--allow-uretprobe-on-confined-target",
                reason,
            }
        });

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
        attach_backend: args.attach_backend,
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
        .start_owned_session(policy, &mut child, args.ring_bytes, args.attach_backend)
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
        uretprobe_override,
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
    // A handed-back child is named on the terminal path (SYSPLAN residual
    // F-15): the evidence already carries `handoff_child_pid`, and the
    // operator reading stderr gets the same PID plus the handoff state.
    // Still exit 0 — a deliberate handoff is observer success.
    if owned.still_running {
        eprintln!("{}", format_handoff_note(owned.pid));
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
/// cannot be enumerated — or, for `run`, that the owned child arms any
/// filter after exec, which is after attach, so there is nothing to read
/// yet and only a proven-clean kernel proceeds. The death report stays as
/// the second layer for override runs.
fn preflight_uretprobe_hazard(target: Option<u32>, overridden: bool) -> Result<Option<String>> {
    match uretprobe_hazard::evaluate(target, overridden) {
        uretprobe_hazard::Action::Proceed => Ok(None),
        uretprobe_hazard::Action::ProceedUnderOverride(reason) => {
            eprintln!(
                "p11scope: WARNING: {reason}. Continuing because \
                 --allow-uretprobe-on-confined-target was given"
            );
            Ok(Some(reason.to_string()))
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

/// The live-handoff terminal note (SYSPLAN residual F-15): names the orphan
/// PID plus the handoff state, so a duration expiry without
/// `--kill-on-timeout` never exits 0 unnamed.
fn format_handoff_note(pid: u32) -> String {
    format!(
        "p11scope: duration expired without --kill-on-timeout; handed back live child \
         pid {pid} (handoff committed, still running outside this capture)"
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
    let drain = session
        .event_drain()
        .context("root_tail_incomplete: EVENTS reader")?;
    drain_original_root_events_from(drain, tail, signals, reduce)
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
                malformed: drain.take_malformed_delta(),
                remaining,
            });
        }
        match drain.poll_root_tail(&mut tail, crate::events::LIVE_POLL_QUANTUM, |ev| {
            reduce(domain, ev)
        })? {
            crate::events::RootTailProgress::Reached => {
                if let Some(remaining) = tail.cancellation(signals.interrupted(), Instant::now())? {
                    return Ok(OriginalRootDrain::Cancelled {
                        malformed: drain.take_malformed_delta(),
                        remaining,
                    });
                }
                return Ok(OriginalRootDrain::Completed {
                    malformed: drain.take_malformed_delta(),
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

/// The discovery pass a capture tick runs, when the gate admits one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryPass {
    /// The frame's full pass, once per drain interval: `drain_discovery_tick`.
    Frame,
    /// Between frames, the pause service alone, for a stop the helper has
    /// already requested: `service_pending_stop` (F-T4-2).
    PendingStop,
}

/// The capture tick's discovery gate.
///
/// The full pass runs once per frame. 64db33a took discovery, the
/// aggregate-map reads and the render off the per-tick drain path, where a
/// discovery sweep stalled event draining. A pause stop cannot wait for that
/// cadence. The helper's SIGSTOP starts a 500 ms causal deadline, and the
/// drain interval is 1 s by default and up to 60 s. A stop serviced at the
/// next frame misses the deadline, so its cycle fails (`auto` goes partial,
/// `always` aborts), and the child stays stopped until that frame. Between
/// frames the gate therefore asks `stop_pending`, and only there, and admits
/// the pause service alone when a stop is pending. With no frame due and no
/// stop pending, a tick runs no discovery.
fn discovery_due(
    since_frame: Duration,
    drain: Duration,
    stop_pending: impl FnOnce() -> bool,
) -> Option<DiscoveryPass> {
    if since_frame >= drain {
        Some(DiscoveryPass::Frame)
    } else if stop_pending() {
        Some(DiscoveryPass::PendingStop)
    } else {
        None
    }
}

/// One profile tick's frame decisions, all from one read of the time since
/// the last frame (F-T8-1). The gate hands that read to `discovery_due`. The
/// map snapshot and the render follow the same verdict, so a tick does the
/// whole frame (its discovery pass, a fresh snapshot, the render and the
/// frame-clock reset) or none of it.
///
/// Reading the clock again at the snapshot and at the render let a tick whose
/// work crossed the frame boundary (an event drain of up to 50 ms, or a
/// pending-stop service) render the frame and reset the clock without its
/// discovery pass. Under sustained load that skipped nearly every frame's
/// pass: ordinary discovery, the forced-sweep cadence, and the pause's
/// re-arm. Trace needs no such split: its frame pass is its only frame
/// decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfileFrame {
    /// The tick's one read, for the discovery gate.
    since_frame: Duration,
    /// Read the aggregate maps fresh instead of reusing the cached snapshot.
    fresh_snapshot: bool,
    /// Render the frame and reset the frame clock.
    render: bool,
}

fn profile_frame_decisions(
    mut since_frame: impl FnMut() -> Duration,
    drain: Duration,
) -> ProfileFrame {
    let since_frame = since_frame();
    let frame_due = since_frame >= drain;
    ProfileFrame {
        since_frame,
        fresh_snapshot: frame_due,
        render: frame_due,
    }
}

/// The gate's between-frames question for an owned explicit pause: should
/// this tick service a pending stop? A pending operator stop wins: the tick
/// services nothing, the loop's end check ends the capture, and cleanup
/// resumes a held child and reports the stop it never confirmed. Otherwise
/// the coordinator answers, at the cost of one authorization read while an
/// epoch is armed and nothing while it is not.
fn pause_stop_due(coordinator: &PauseCoordinator, io: &mut impl PauseIo) -> bool {
    matches!(io.cancelled(), Ok(false)) && coordinator.stop_pending(io)
}

/// The pause coordinator's share of either discovery pass: arm, then service.
/// Re-arming is idempotent while the epoch is open and refused once the
/// coordinator has retired the policy. That refusal returns `Ok(false)`, and
/// it is exactly when the ordinary cadence takes over again.
fn service_pause(
    coordinator: &mut PauseCoordinator,
    io: &mut impl PauseIo,
) -> std::result::Result<bool, PauseError> {
    match coordinator.arm(io)? {
        ArmResult::Disabled => Ok(false),
        ArmResult::Armed => coordinator.service(io).map(|()| true),
    }
}

/// `pause_stop_due` for the capture loops. `never` and unowned captures
/// return before any I/O.
fn owned_stop_pending(
    engine: &mut Engine,
    session: &mut Session,
    owned: Option<&Owned>,
    interrupted: &SignalState,
) -> bool {
    let Some(owned) = owned.filter(|owned| owned.policy != cli::PausePolicy::Never) else {
        return false;
    };
    let Some(child) = owned.child.as_ref() else {
        return false;
    };
    let marker = marker_never_seen();
    let cancelled = cancelled_by(interrupted);
    let mut io = SessionPauseIo::new(engine, session, child, &marker, &cancelled);
    pause_stop_due(&owned.coordinator, &mut io)
}

/// A frame's discovery pass, and the one place the pause policy changes the
/// frame's discovery.
///
/// `pause=never` — and any explicit policy that could not (or may no longer)
/// arm — keeps the existing refresh cadence through `Engine::drain_discovery`.
/// An ARMED explicit pause instead delegates to the coordinator, whose own
/// 1 ms bounded loop owns the window; it returns to this loop only after owner
/// closure. A stop that lands between frames does not wait for this pass: the
/// gate (`discovery_due`) hands it to `service_pending_stop` on the next tick.
///
/// Each drain owns its taken map handle for the duration of the call and
/// returns it before the caller does anything else: there is never a second
/// simultaneous ring reader, and no thread, channel, or async runtime is
/// involved. The idle wait observes EVENTS readability with `poll` (wake on
/// data or timeout), which consumes nothing and adds no second reader.
fn drain_discovery_tick(
    engine: &mut Engine,
    session: &mut Session,
    owned: Option<&mut Owned>,
    interrupted: &SignalState,
    force_full: bool,
) -> Result<(bool, bool)> {
    let Some(owned) = owned else {
        return Ok((engine.drain_discovery_shallow(session, force_full)?, false));
    };
    if owned.policy == cli::PausePolicy::Never {
        return Ok((engine.drain_discovery_shallow(session, force_full)?, false));
    }
    let serviced = {
        let marker = marker_never_seen();
        let cancelled = cancelled_by(interrupted);
        let child = owned
            .child
            .as_ref()
            .expect("the owned child is retained until finalization");
        let mut io = SessionPauseIo::new(engine, session, child, &marker, &cancelled);
        service_pause(&mut owned.coordinator, &mut io)
            .map(|serviced| serviced.then(|| io.plan_changed()))
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

/// The pause I/O a capture tick drives: the coordinator's seam, plus whether
/// this tick's batch application changed the attach plan (the loop then
/// syncs its semantic consumers before draining events).
trait TickPauseIo: PauseIo {
    fn plan_changed(&self) -> bool;
}

impl TickPauseIo for SessionPauseIo<'_> {
    fn plan_changed(&self) -> bool {
        SessionPauseIo::plan_changed(self)
    }
}

/// The between-frames pass's whole pause step (F-T4-2), generic over the
/// pause I/O so the capture loops (session adapter) and the held-child tests
/// run the same code. It runs the frame pass's own pause entry,
/// `service_pause`, without the frame's ordinary discovery, so a disabled or
/// retired policy leaves discovery to the next frame. An error is retired
/// exactly as a frame retires it (`retire_pause_policy`: `always` or a
/// lifecycle failure ends the capture). The tick's `(plan_changed, paused)`
/// reports whatever the call applied either way.
fn pending_stop_pass(
    coordinator: &mut PauseCoordinator,
    io: &mut impl TickPauseIo,
) -> Result<(bool, bool)> {
    let paused = match service_pause(coordinator, io) {
        Ok(serviced) => serviced,
        Err(error) => {
            retire_pause_policy(error)?;
            false
        }
    };
    Ok((io.plan_changed(), paused))
}

/// `pending_stop_pass` for the capture loops, through the session adapter.
fn service_pending_stop(
    engine: &mut Engine,
    session: &mut Session,
    owned: Option<&mut Owned>,
    interrupted: &SignalState,
) -> Result<(bool, bool)> {
    let Some(owned) = owned else {
        return Ok((false, false));
    };
    let marker = marker_never_seen();
    let cancelled = cancelled_by(interrupted);
    let child = owned
        .child
        .as_ref()
        .expect("the owned child is retained until finalization");
    let mut io = SessionPauseIo::new(engine, session, child, &marker, &cancelled);
    pending_stop_pass(&mut owned.coordinator, &mut io)
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

/// Idle readiness timeout: with no backlog and no frame due, the loop
/// waits on EVENTS readability up to this long instead of idling out
/// the frame, so a burst landing mid-wait is drained on arrival rather
/// than after a full sleep (audit F1). The timeout also keeps the
/// frame, duration and signal cadence bounded when nothing arrives, and
/// with it the pause. While a pause epoch is armed, every tick between
/// frames asks the gate (`discovery_due`) for a pending stop, and a frame
/// tick services the pause in its own pass. A stopped child is therefore
/// serviced on the next tick, in milliseconds, instead of waiting out a
/// frame (F-T4-2).
/// Margin: one full timeout at the fastest measured unpaced burst
/// (A2b, 127648/s) admits 256 records, far under the default
/// 12483-record ring — but that bounds the REQUESTED wait only, never
/// the OS scheduling delay, which the ring must also absorb.
pub(crate) const READY_IDLE_POLL: Duration = Duration::from_millis(2);

/// Discovery frames between forced full inventory sweeps: shallow frames
/// skip a quiet sweep, and every Nth frame sweeps regardless, bounding
/// any deferral to N frame intervals.
pub(crate) const FULL_DISCOVERY_EVERY_N_FRAMES: u64 = 5;

/// Whether a frame forces a full inventory sweep: every Nth frame, with
/// the first forced sweep deferred past attach. Attach just completed a
/// full discovery, so forcing frame 1 re-sweeps cold seconds-old state
/// and blocks the drain path ~2.5s (the system max-gap spike); frame N
/// re-verifies warm instead.
fn force_full_frame(frame_tick: u64) -> bool {
    frame_tick % FULL_DISCOVERY_EVERY_N_FRAMES == 0
}

/// How long a tick sleeps: the pause slice still wins, a drain that
/// stopped with backlog queued sleeps nothing, and an idle tick waits
/// only until the next frame or readiness re-poll, whichever is first.
fn ready_sleep_duration(paused: bool, backlog: bool, frame_due_in: Duration) -> Duration {
    if paused {
        Duration::from_millis(1)
    } else if backlog {
        Duration::ZERO
    } else {
        frame_due_in.min(READY_IDLE_POLL)
    }
}

/// Idle wait with ring readiness: block until the EVENTS ring is
/// readable or `timeout` elapses, whichever comes first. A fixed sleep
/// is a requested wait, not a scheduling bound — a burst landing
/// mid-sleep waits out the whole sleep even though data is already
/// queued (audit F1). `poll` wakes on the first submitted record
/// instead (the eBPF side submits with flags 0, so every commit wakes
/// waiters), while the timeout preserves the frame, duration and
/// signal cadence of the old sleep. Still single-threaded with a
/// single ring consumer: polling observes readiness without consuming
/// anything, and tick order (discovery before semantic consumption)
/// is unchanged.
/// `poll` takes whole milliseconds; round a nonzero timeout up so a
/// sub-millisecond idle waits 1 ms instead of truncating to `poll(0)`
/// (return immediately, spinning the loop until the frame lands).
fn poll_timeout_ms(timeout: Duration) -> i32 {
    timeout.as_nanos().div_ceil(1_000_000).min(i32::MAX as u128) as i32
}

fn wait_until_ready(fd: BorrowedFd<'_>, timeout: Duration) {
    if timeout.is_zero() {
        return;
    }
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout_ms = poll_timeout_ms(timeout);
    // SAFETY: one initialized pollfd; the fd is the capture's EVENTS
    // map, open for the whole capture.
    if unsafe { libc::poll(&mut pollfd, 1, timeout_ms) } >= 0 {
        return;
    }
    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
        // A signal is pending; the next tick's checks observe it sooner
        // than the old full sleep would have allowed.
        return;
    }
    // Unreachable in practice (the map fd cannot fail while the capture
    // owns it): preserve the old sleep exactly rather than spin or
    // abort the capture on an unexpected error.
    std::thread::sleep(timeout);
}

/// The control-latency signal printed on stderr the moment a signalled
/// loop exits, before detach work: the harness timestamps its arrival.
fn cancel_marker(signal: Option<libc::c_int>, ticks: u64) -> String {
    format!(
        "p11scope: cancel: loop exited on signal {} after {ticks} ticks",
        signal.unwrap_or(-1)
    )
}

/// The loop-end marker for a target that exited mid-capture: the
/// measurement harness timestamps this stderr line as the actual
/// early-exit boundary (F-74), instead of assuming the full window.
fn target_exit_marker(ticks: u64) -> String {
    format!("p11scope: capture ended: target exited after {ticks} ticks")
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
    scheduling: &'state mut SchedulingAccumulator,
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
    'stdout_open,
    'output,
> = (
    &'engine mut Engine,
    &'session mut Session,
    &'owned_ref mut Option<&'owned mut Owned>,
    &'stdout_ref mut crate::sink::SinkWriter<crate::sink::StdoutInner>,
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
    'stdout_open,
    'out_file,
> = (
    &'engine mut Engine,
    &'session mut Session,
    &'owned_ref mut Option<&'owned mut Owned>,
    &'remaining mut Option<u64>,
    &'loss mut u64,
    &'stdout_ref mut crate::sink::SinkWriter<crate::sink::StdoutInner>,
    &'stdout_open mut bool,
    &'out_file mut Option<std::io::BufWriter<std::fs::File>>,
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
        &mut CaptureConsumers<'state>,
    ) -> Result<(bool, bool, &'tick crate::plan::AttachPlan)>,
    end: impl FnOnce(&mut C) -> Result<Option<CaptureEnd>>,
    drain: impl FnOnce(&mut C, &mut CaptureConsumers<'state>) -> Result<Option<CaptureEnd>>,
    snapshot: impl FnOnce(&mut C, &mut CaptureConsumers<'state>) -> Result<T>,
    check: impl FnOnce(&mut C) -> Result<()>,
) -> Result<CaptureTick<T>> {
    let paused = {
        let (plan_changed, paused, plan) = discovery(context, consumers)?;
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
        &mut CaptureConsumers<'state>,
        bool,
    ) -> Result<(bool, &'phase crate::plan::AttachPlan)>,
    root: impl FnOnce(
        &mut C,
        &mut CaptureConsumers<'state>,
    ) -> (Result<OriginalRootDrain>, Option<anyhow::Error>),
    drain: impl FnOnce(&mut C, &mut CaptureConsumers<'state>) -> Result<()>,
    snapshot_and_publish: impl FnOnce(&mut C, &mut CaptureConsumers<'state>) -> Result<T>,
) -> Result<T> {
    {
        let (plan_changed, plan) = discovery(context, consumers, detached)?;
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
    uretprobe_override: Option<render::UretprobeOverride>,
) -> Result<render::Evidence> {
    // Opened by the caller before the attach; published by `commit()` only
    // once the final report is written.
    let has_output = output.is_some();
    let mut stdout_sink = crate::sink::stdout_sink()?;
    stdout_sink.set_cancel_flag(interrupted.cancel_flag());
    let stdout: &mut crate::sink::SinkWriter<crate::sink::StdoutInner> = &mut stdout_sink;
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
    let clock = Instant::now();
    let drain_events = |session: &mut Session,
                        state: &mut semantics::State,
                        tracker: &mut process::Tracker,
                        acc: &mut SchedulingAccumulator|
     -> Result<u64> {
        let terminal = session.producers_detached();
        let budget = ReadyBudget::tick();
        let phase_start = Instant::now();
        let outcome = poll_ready(
            terminal,
            &budget,
            crate::events::LIVE_POLL_QUANTUM,
            &mut || interrupted.interrupted() || duration.is_some_and(|d| clock.elapsed() >= d),
            || {
                select_and_drain_events(session, Session::live_poll_quantum, |session, quantum| {
                    let drain = session.event_drain()?;
                    drain_profile_events(drain, state, tracker, scope, quantum)
                })
            },
        )?;
        acc.add_phase(SchedulingPhase::Drain, phase_start.elapsed());
        acc.note_drain_at(Instant::now());
        if terminal {
            acc.note_terminal_drain(outcome.may_remain);
        } else {
            acc.note_live_drain(&outcome);
        }
        Ok(outcome.malformed)
    };
    let mut malformed_records: u64 = 0;
    let capture_tracking_degraded = initial_tracking_evidence(
        scope,
        session.process_creation_tracking_unavailable().is_some(),
        session.lifecycle_tracking_unavailable().is_some(),
    );
    let mut stdout_open = true;
    let wall_start = SystemTime::now();
    let mut scheduling = SchedulingAccumulator::default();
    let mut last_sink_note = None;
    let mut last_frame = Instant::now() - drain;
    let mut frames = 0u64;
    let mut ticks = 0u64;
    let mut last_snapshot: Option<(Vec<metrics::SlotReport>, metrics::KernelEvidence)> = None;
    #[rustfmt::skip]
    let loop_result = (|| -> Result<CaptureEnd> {
    loop {
        stdout.begin_tick(crate::sink::SINK_TICK_BUDGET);
        ticks += 1;
        let elapsed = clock.elapsed();
        // One frame-clock read decides this tick's whole frame (F-T8-1).
        let tick_frame = profile_frame_decisions(|| last_frame.elapsed(), drain);
        let tick = {
            let mut context = (&mut *engine, &mut *session, &mut owned);
            let mut consumers = CaptureConsumers {
                state: &mut state,
                tracker: &mut process_tracker,
                tracer: None,
                malformed_records: &mut malformed_records,
                scheduling: &mut scheduling,
            };
            let frame_tick = &mut frames;
            let snapshot_cache = &mut last_snapshot;
            capture_tick_with(
                &mut context,
                &mut consumers,
                |context: &mut ProfileTickContext<'_, '_>, consumers: &mut CaptureConsumers<'_>| {
                    let Some(pass) = discovery_due(tick_frame.since_frame, drain, || {
                        owned_stop_pending(context.0, context.1, context.2.as_deref(), interrupted)
                    }) else {
                        return Ok((false, false, context.0.plan()));
                    };
                    let phase_start = Instant::now();
                    let (plan_changed, paused) = match pass {
                        DiscoveryPass::Frame => {
                            *frame_tick += 1;
                            let force_full = force_full_frame(*frame_tick);
                            drain_discovery_tick(
                                context.0,
                                context.1,
                                context.2.as_deref_mut(),
                                interrupted,
                                force_full,
                            )?
                        }
                        DiscoveryPass::PendingStop => service_pending_stop(
                            context.0,
                            context.1,
                            context.2.as_deref_mut(),
                            interrupted,
                        )?,
                    };
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Discovery, phase_start.elapsed());
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
                            consumers.scheduling,
                        )?;
                    }
                    Ok(None)
                },
                |context, consumers| {
                    if !tick_frame.fresh_snapshot {
                        if let Some((reports, kernel_evidence)) = snapshot_cache.as_ref() {
                            return Ok((reports.clone(), *kernel_evidence));
                        }
                    }
                    let phase_start = Instant::now();
                    let mut kernel_evidence = metrics::kernel_evidence(context.1)?;
                    if !profile {
                        kernel_evidence.ring_loss = 0;
                    }
                    let reports = metrics::read(context.1, context.0.plan())?;
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Maps, phase_start.elapsed());
                    *snapshot_cache = Some((reports.clone(), kernel_evidence));
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

        if tick_frame.render {
            last_frame = Instant::now();
            let render_start = Instant::now();
            let ev = evidence_for(
                engine,
                engine.capture_facts(),
                session.attached_probes(),
                session.dynamic_per_offset_attached(),
                session.static_multi_attached(),
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
                scheduling.snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64),
                uretprobe_override.clone(),
                owned
                    .as_deref()
                    .and_then(|owned| owned.still_running.then_some(owned.pid)),
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
            scheduling.add_phase(SchedulingPhase::Render, render_start.elapsed());
            if !stdout_open && !has_output {
                break Ok(CaptureEnd::Error);
            }
        }
        collect_sink_drops(
            stdout,
            &mut scheduling,
            &mut last_sink_note,
            Instant::now(),
        );
        wait_until_ready(
            session.events_readiness_fd(),
            ready_sleep_duration(
                paused,
                scheduling.last_drain_had_backlog(),
                drain.saturating_sub(last_frame.elapsed()),
            ),
        );
    }
    })();
    if matches!(loop_result, Ok(CaptureEnd::Signal)) {
        eprintln!("{}", cancel_marker(interrupted.first_signal(), ticks));
    }
    if matches!(loop_result, Ok(CaptureEnd::TargetExit)) {
        eprintln!("{}", target_exit_marker(ticks));
    }
    if profile {
        scheduling.note_loop_end(
            metrics::lost_events(session).unwrap_or(0),
            engine.capture_facts().discovery_losses()[0],
        );
    } else {
        scheduling.note_loop_end(0, engine.capture_facts().discovery_losses()[0]);
    }
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
                scheduling: &mut scheduling,
            };
            drain_capture_terminal_with(
                &mut terminal_context,
                &mut consumers,
                detached,
                &mut std::io::stderr(),
                |context: &mut ProfileTerminalContext<'_, '_, '_, '_, '_, '_, '_>,
                 consumers: &mut CaptureConsumers<'_>,
                 detached| {
                    let phase_start = Instant::now();
                    let plan_changed = if detached {
                        context.0.drain_discovery_terminal(context.1)?
                    } else {
                        context.0.drain_discovery_terminal_bounded_from(context.1)?
                    };
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Discovery, phase_start.elapsed());
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::DiscoveryTerminal, phase_start.elapsed());
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
                    context.3.begin_tick(crate::sink::SINK_TICK_BUDGET);
                    if profile {
                        *consumers.malformed_records += drain_events(
                            context.1,
                            consumers.state,
                            consumers.tracker,
                            consumers.scheduling,
                        )?;
                    }
                    collect_sink_drops(context.3, consumers.scheduling, &mut None, Instant::now());
                    Ok(())
                },
                |context, consumers| {
                    context.3.begin_tick(crate::sink::SINK_TICK_BUDGET);
                    let maps_start = Instant::now();
                    let reports = metrics::read(context.1, context.0.plan())?;
                    let mut kernel_evidence = metrics::kernel_evidence(context.1)?;
                    if !profile {
                        kernel_evidence.ring_loss = 0;
                    }
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Maps, maps_start.elapsed());
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map_err(anyhow::Error::msg)?;
                    context.0.settle_terminal_drain();
                    consumers.scheduling.note_terminal(
                        kernel_evidence.ring_loss,
                        context.0.capture_facts().discovery_losses()[0],
                    );
                    consumers.scheduling.add_phase(
                        SchedulingPhase::Detach,
                        Duration::from_millis(context.1.detach_wall_ms()),
                    );
                    let render_start = Instant::now();
                    let mut ev = evidence_for(
                        context.0,
                        context.0.capture_facts(),
                        context.1.attached_probes(),
                        context.1.dynamic_per_offset_attached(),
                        context.1.static_multi_attached(),
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
                        consumers
                            .scheduling
                            .snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64),
                        uretprobe_override.clone(),
                        context
                            .2
                            .as_deref()
                            .and_then(|owned| owned.still_running.then_some(owned.pid)),
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
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Render, render_start.elapsed());
                    collect_sink_drops(context.3, consumers.scheduling, &mut None, Instant::now());
                    ev.scheduling = consumers
                        .scheduling
                        .snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64);

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
                            render::profile_json(
                                &reports,
                                render::VersionedEvidence::wrap(&ev),
                                consumers.state,
                                &capture,
                            )
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
    uretprobe_override: Option<render::UretprobeOverride>,
) -> Result<render::Evidence> {
    let trace_limit = resolve_trace_max_events(max_events);
    let mut remaining = Some(trace_limit);
    // A line stream, not a published artifact: opened by the caller before the
    // attach, then appended to as lines arrive.
    let mut out_sink = out.map(buffered_sink);
    let out_file = &mut out_sink;
    let mut stdout_sink = crate::sink::stdout_sink()?;
    stdout_sink.set_cancel_flag(interrupted.cancel_flag());
    let stdout: &mut crate::sink::SinkWriter<crate::sink::StdoutInner> = &mut stdout_sink;

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
    let mut scheduling = SchedulingAccumulator::default();
    let mut last_sink_note = None;
    let mut last_frame = Instant::now() - drain;
    let mut frames = 0u64;
    let mut ticks = 0u64;
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
        stdout.begin_tick(crate::sink::SINK_TICK_BUDGET);
        ticks += 1;
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
                scheduling: &mut scheduling,
            };
            let frame_tick = &mut frames;
            let frame_clock = &mut last_frame;
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
                >,
                    consumers: &mut CaptureConsumers<'_>,
                | {
                    let Some(pass) = discovery_due(frame_clock.elapsed(), drain, || {
                        owned_stop_pending(context.0, context.1, context.2.as_deref(), interrupted)
                    }) else {
                        return Ok((false, false, context.0.plan()));
                    };
                    if pass == DiscoveryPass::Frame {
                        // Trace has no render block: the frame's discovery
                        // pass itself advances the frame clock. A pending-stop
                        // pass between frames leaves it alone.
                        *frame_clock = Instant::now();
                    }
                    let phase_start = Instant::now();
                    let (plan_changed, paused) = match pass {
                        DiscoveryPass::Frame => {
                            *frame_tick += 1;
                            let force_full = force_full_frame(*frame_tick);
                            drain_discovery_tick(
                                context.0,
                                context.1,
                                context.2.as_deref_mut(),
                                interrupted,
                                force_full,
                            )?
                        }
                        DiscoveryPass::PendingStop => service_pending_stop(
                            context.0,
                            context.1,
                            context.2.as_deref_mut(),
                            interrupted,
                        )?,
                    };
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Discovery, phase_start.elapsed());
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
                        consumers.scheduling,
                        &mut || {
                            interrupted.interrupted()
                                || duration.is_some_and(|d| clock.elapsed() >= d)
                        },
                    )?;
                    Ok((*context.3 == Some(0)).then_some(CaptureEnd::LimitReached))
                },
                |context, consumers| {
                    let phase_start = Instant::now();
                    let outcome = report_trace_loss(
                        context.1,
                        context.4,
                        context.5,
                        context.6,
                        context.7,
                    );
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Maps, phase_start.elapsed());
                    outcome
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
        collect_sink_drops(
            stdout,
            &mut scheduling,
            &mut last_sink_note,
            Instant::now(),
        );
        wait_until_ready(
            session.events_readiness_fd(),
            ready_sleep_duration(
                paused,
                scheduling.last_drain_had_backlog(),
                drain.saturating_sub(last_frame.elapsed()),
            ),
        );
    }
    })();
    if matches!(loop_result, Ok(CaptureEnd::Signal)) {
        eprintln!("{}", cancel_marker(interrupted.first_signal(), ticks));
    }
    if matches!(loop_result, Ok(CaptureEnd::TargetExit)) {
        eprintln!("{}", target_exit_marker(ticks));
    }

    scheduling.note_loop_end(
        metrics::lost_events(session).unwrap_or(0),
        engine.capture_facts().discovery_losses()[0],
    );
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
                scheduling: &mut scheduling,
            };
            drain_capture_terminal_with(
                &mut terminal_context,
                &mut consumers,
                detached,
                &mut std::io::stderr(),
                |context: &mut TraceTickContext<'_, '_, '_, '_, '_, '_, '_, '_, '_>,
                 consumers: &mut CaptureConsumers<'_>,
                 detached| {
                    let phase_start = Instant::now();
                    let plan_changed = if detached {
                        context.0.drain_discovery_terminal(context.1)?
                    } else {
                        context.0.drain_discovery_terminal_bounded_from(context.1)?
                    };
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Discovery, phase_start.elapsed());
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::DiscoveryTerminal, phase_start.elapsed());
                    Ok((plan_changed, context.0.plan()))
                },
                |context, consumers| {
                    context.5.begin_tick(crate::sink::SINK_TICK_BUDGET);
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
                    collect_sink_drops(context.5, consumers.scheduling, &mut None, Instant::now());
                    (root_result, root_write_error)
                },
                |context, consumers| {
                    context.5.begin_tick(crate::sink::SINK_TICK_BUDGET);
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
                        consumers.scheduling,
                        &mut || false,
                    )?;
                    collect_sink_drops(context.5, consumers.scheduling, &mut None, Instant::now());
                    Ok(())
                },
                |context, consumers| {
                    context.5.begin_tick(crate::sink::SINK_TICK_BUDGET);
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map_err(anyhow::Error::msg)?;
                    report_trace_loss(context.1, context.4, context.5, context.6, context.7)?;
                    let maps_start = Instant::now();
                    let reports = metrics::read(context.1, context.0.plan())?;
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Maps, maps_start.elapsed());
                    context
                        .0
                        .pinned()
                        .check_unchanged()
                        .map_err(anyhow::Error::msg)?;
                    context.0.settle_terminal_drain();
                    let trace_truncated = end == CaptureEnd::LimitReached || *context.3 == Some(0);
                    let maps_start = Instant::now();
                    let terminal_kernel = metrics::kernel_evidence(context.1)?;
                    consumers
                        .scheduling
                        .add_phase(SchedulingPhase::Maps, maps_start.elapsed());
                    consumers.scheduling.note_terminal(
                        terminal_kernel.ring_loss,
                        context.0.capture_facts().discovery_losses()[0],
                    );
                    consumers.scheduling.add_phase(
                        SchedulingPhase::Detach,
                        Duration::from_millis(context.1.detach_wall_ms()),
                    );
                    // Flush every pre-terminal byte BEFORE snapshotting, so
                    // the terminal records account all drops so far (F3:
                    // snapshotting first stranded the terminal flush's drops
                    // outside the emitted EVIDENCE).
                    flush_stdout(context.5, context.6)?;
                    collect_sink_drops(context.5, consumers.scheduling, &mut None, Instant::now());
                    let mut evidence = evidence_for(
                        context.0,
                        context.0.capture_facts(),
                        context.1.attached_probes(),
                        context.1.dynamic_per_offset_attached(),
                        context.1.static_multi_attached(),
                        context.1.attach_failures(),
                        &reports,
                        terminal_kernel,
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
                        consumers
                            .scheduling
                            .snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64),
                        uretprobe_override.clone(),
                        context
                            .2
                            .as_deref()
                            .and_then(|owned| owned.still_running.then_some(owned.pid)),
                    );
                    evidence.mark_terminal_drain_unproven();
                    if *consumers.malformed_records > 0 {
                        eprintln!(
                            "p11scope: {} malformed ring-buffer records discarded this capture",
                            *consumers.malformed_records
                        );
                    }
                    emit_trace_terminal_accounted(
                        &mut evidence,
                        policy,
                        trace_truncated,
                        trace_limit,
                        max_events.is_some(),
                        &reports,
                        consumers.tracer.as_deref().expect("trace consumer"),
                        consumers.scheduling,
                        context.5,
                        context.6,
                        context.7,
                    )?;
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

/// Byte-exact terminal sink total: the `-o` file's EVIDENCE record must
/// report exactly the bytes the file holds that stdout lacks. That is the
/// counted sink drops, plus the file/stdout EVIDENCE-record length delta
/// (the two records can differ by the terminal flush's own drops, which
/// shifts the digit width at a decimal boundary). `file_line_len` renders
/// the file record's length for a candidate total; the iteration only ever
/// grows (record length never shrinks as the total grows) within a range
/// bounded by the digit width, so it settles in a couple of rounds.
fn resolve_terminal_sink_total(
    counted: u64,
    stdout_line_len: usize,
    mut file_line_len: impl FnMut(u64) -> usize,
) -> u64 {
    let mut total = counted;
    for _ in 0..64 {
        let file_len = file_line_len(total);
        let next = counted.saturating_add((file_len as u64).saturating_sub(stdout_line_len as u64));
        if next == total {
            break;
        }
        total = next;
    }
    total
}

/// Terminal trace records with byte-exact sink accounting (F3). The
/// evidence snapshot the caller took already counts every pre-terminal
/// drop (the terminal closure flushes before snapshotting); this emits
/// the terminal records, flushes them, and finalizes the `-o` file's
/// EVIDENCE record AFTER that flush, so it accounts the terminal drops
/// too. The stdout copy keeps the pre-flush count — stdout under loss is
/// best-effort, and a record cannot report its own delivery fate — while
/// the file copy resolves the exact file/stdout byte difference. Without
/// drops both copies report identical drop counts.
#[allow(clippy::too_many_arguments)]
fn emit_trace_terminal_accounted<W: Write>(
    evidence: &mut render::Evidence,
    policy: CapturePolicy,
    trace_truncated: bool,
    trace_limit: u64,
    trace_limit_explicit: bool,
    reports: &[metrics::SlotReport],
    tracer: &trace::Tracer,
    scheduling: &mut SchedulingAccumulator,
    stdout: &mut crate::sink::SinkWriter<crate::sink::StdoutInner>,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<()> {
    if trace_truncated {
        emit_trace_line(
            &trace::truncated_line(trace_limit, trace_limit_explicit),
            stdout,
            stdout_open,
            out_file,
        )?;
    }
    // The stdout terminal records (COUNT plus the pre-flush EVIDENCE
    // copy) go through the shared terminal emitter, best-effort under
    // loss; the file receives COUNT now and its finalized EVIDENCE
    // record after the terminal flush below.
    let stdout_line = trace::evidence_line(evidence, policy, trace_truncated);
    let stdout_line_len = stdout_line.len() + 1; // trailing newline
    emit_trace_terminal(
        reports,
        tracer,
        &stdout_line,
        stdout,
        stdout_open,
        &mut None::<std::io::Sink>,
    )?;
    {
        let mut discard = std::io::sink();
        let mut discard_open = true;
        emit_trace_line(
            &terminal_trace_count_line(reports, tracer),
            &mut discard,
            &mut discard_open,
            out_file,
        )?;
    }
    // Fresh budget for the terminal records: the pre-terminal flush may
    // have spent the tick's. Bounded like every flush (and prompt under
    // cancellation), so the records still get a delivery chance.
    stdout.begin_tick(crate::sink::SINK_TICK_BUDGET);
    flush_stdout(stdout, stdout_open)?;
    collect_sink_drops(stdout, scheduling, &mut None, Instant::now());
    // Refresh from the accumulator — the profile terminal does the same —
    // then resolve the file record's exact total: counted drops plus any
    // file/stdout record-length delta from the terminal flush's own drops.
    evidence.scheduling = scheduling.snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64);
    let counted = evidence.scheduling.sink_dropped_bytes;
    let total = resolve_terminal_sink_total(counted, stdout_line_len, |candidate| {
        evidence.scheduling.sink_dropped_bytes = candidate;
        trace::evidence_line(evidence, policy, trace_truncated).len() + 1
    });
    evidence.scheduling.sink_dropped_bytes = total;
    if let Some(file) = out_file.as_mut() {
        writeln!(
            file,
            "{}",
            trace::evidence_line(evidence, policy, trace_truncated)
        )
        .context("writing trace output file")?;
        file.flush().context("flushing trace output file")?;
    }
    Ok(())
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

fn buffered_sink<W: Write>(writer: W) -> std::io::BufWriter<W> {
    std::io::BufWriter::with_capacity(crate::sink::SINK_BUFFER_BYTES, writer)
}

/// A stall note is due when this window dropped bytes and no note fired in
/// the last five seconds.
fn sink_note_due(drops: &crate::sink::SinkDrops, last_note: Option<Instant>, now: Instant) -> bool {
    drops.timeouts > 0
        && last_note
            .is_none_or(|noted| now.saturating_duration_since(noted) >= Duration::from_secs(5))
}

/// Drains a tick's sink drops into the accumulator and notes sustained
/// stalls on stderr (throttled): stdout's own evidence line is
/// best-effort under backpressure, so the note is the fallback record.
fn collect_sink_drops(
    sink: &mut crate::sink::SinkWriter<crate::sink::StdoutInner>,
    acc: &mut SchedulingAccumulator,
    last_note: &mut Option<Instant>,
    now: Instant,
) {
    let drops = sink.take_drops();
    acc.note_sink_drops(&drops);
    if sink_note_due(&drops, *last_note, now) {
        *last_note = Some(now);
        eprintln!(
            "p11scope: stdout stalled; dropped {} bytes in {} flush timeouts (policy {})",
            drops.dropped_bytes,
            drops.timeouts,
            crate::render::SINK_POLICY_BOUNDED_WAIT_DROP,
        );
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
/// producers are detached and the drain is finite. Returns the per-poll
/// malformed delta from the retained drain.
fn select_and_drain_events<C, T>(
    context: &mut C,
    select: impl FnOnce(&C) -> Option<usize>,
    drain: impl FnOnce(&mut C, Option<usize>) -> Result<T>,
) -> Result<T> {
    let quantum = select(context);
    drain(context, quantum)
}

/// Per-tick readiness budgets (Task 3.1 repair): finite records plus wall
/// time, so a hot ring yields to duration/signal checks, discovery, maps,
/// and frames instead of draining unboundedly.
pub(crate) const DRAIN_TICK_MAX_RECORDS: usize = 16384;
pub(crate) const DRAIN_TICK_WALL: Duration = Duration::from_millis(50);

/// One readiness drain: the single-quantum steps below, re-polled while
/// backlog remains. `may_remain` is live scheduling truth — the line
/// limit reports none, since the terminal drain owns what is still queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct ReadyOutcome {
    pub(crate) malformed: u64,
    pub(crate) repolls: u64,
    pub(crate) budget_exhausted: bool,
    pub(crate) may_remain: bool,
}

pub(crate) struct ReadyBudget {
    max_records: usize,
    wall: Duration,
    start: Instant,
}

impl ReadyBudget {
    fn tick() -> Self {
        Self {
            max_records: DRAIN_TICK_MAX_RECORDS,
            wall: DRAIN_TICK_WALL,
            start: Instant::now(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(max_records: usize, wall: Duration) -> Self {
        Self {
            max_records,
            wall,
            start: Instant::now(),
        }
    }

    fn exhausted(&self, taken: usize) -> bool {
        taken >= self.max_records || self.start.elapsed() >= self.wall
    }
}

/// Readiness loop over one-quantum steps: re-poll while backlog remains,
/// yield between quanta for interrupts/duration, stop at the per-tick
/// budget with the backlog flagged. The terminal drain takes exactly one
/// poll — its bound is explicit, and backlog past it is truncation.
/// The first poll always runs, so a tick always makes progress.
fn poll_ready(
    terminal: bool,
    budget: &ReadyBudget,
    quantum_records: usize,
    should_yield: &mut impl FnMut() -> bool,
    mut step: impl FnMut() -> Result<(u64, bool)>,
) -> Result<ReadyOutcome> {
    let mut outcome = ReadyOutcome::default();
    let mut taken = 0usize;
    loop {
        let (malformed, may_remain) = step()?;
        outcome.malformed = outcome.malformed.saturating_add(malformed);
        if !may_remain {
            outcome.may_remain = false;
            return Ok(outcome);
        }
        outcome.may_remain = true;
        if terminal {
            return Ok(outcome);
        }
        taken = taken.saturating_add(quantum_records);
        if should_yield() {
            return Ok(outcome);
        }
        if budget.exhausted(taken) {
            outcome.budget_exhausted = true;
            return Ok(outcome);
        }
        outcome.repolls = outcome.repolls.saturating_add(1);
    }
}

pub(crate) enum SchedulingPhase {
    Discovery,
    DiscoveryTerminal,
    Drain,
    Maps,
    Render,
    Detach,
}

/// Capture-lifetime consumer-scheduling counters. The loss splits are
/// sampled at loop end (capture phase) and at terminal start (detach
/// window); everything else accumulates per tick.
#[derive(Debug, Default)]
pub(crate) struct SchedulingAccumulator {
    drain_repolls: u64,
    drain_budget_exhaustions: u64,
    last_backlog: bool,
    last_drain_end: Option<Instant>,
    loop_ended: bool,
    max_inter_drain_gap_ms: u64,
    phase_discovery_ms: u64,
    phase_discovery_terminal_ms: u64,
    phase_drain_ms: u64,
    phase_maps_ms: u64,
    phase_render_ms: u64,
    phase_detach_ms: u64,
    capture_event_loss: u64,
    detach_event_loss: u64,
    capture_discovery_loss: u64,
    detach_discovery_loss: u64,
    terminal_drain_truncated: bool,
    sink_stall_ms: u64,
    sink_timeouts: u64,
    sink_dropped_bytes: u64,
}

impl SchedulingAccumulator {
    pub(crate) fn note_live_drain(&mut self, outcome: &ReadyOutcome) {
        self.drain_repolls = self.drain_repolls.saturating_add(outcome.repolls);
        if outcome.budget_exhausted {
            self.drain_budget_exhaustions = self.drain_budget_exhaustions.saturating_add(1);
        }
        self.last_backlog = outcome.may_remain;
    }

    pub(crate) fn note_terminal_drain(&mut self, may_remain: bool) {
        self.terminal_drain_truncated = may_remain;
        self.last_backlog = false;
    }

    pub(crate) fn note_sink_drops(&mut self, drops: &crate::sink::SinkDrops) {
        self.sink_stall_ms = self.sink_stall_ms.saturating_add(drops.stall_ms);
        self.sink_timeouts = self.sink_timeouts.saturating_add(drops.timeouts);
        self.sink_dropped_bytes = self.sink_dropped_bytes.saturating_add(drops.dropped_bytes);
    }

    pub(crate) fn note_drain_at(&mut self, now: Instant) {
        if self.loop_ended {
            return;
        }
        if let Some(last) = self.last_drain_end {
            let gap_ms = now.saturating_duration_since(last).as_millis();
            self.max_inter_drain_gap_ms = self
                .max_inter_drain_gap_ms
                .max(gap_ms.min(u128::from(u64::MAX)) as u64);
        }
        self.last_drain_end = Some(now);
    }

    pub(crate) fn add_phase(&mut self, phase: SchedulingPhase, elapsed: Duration) {
        let ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
        let slot = match phase {
            SchedulingPhase::Discovery => &mut self.phase_discovery_ms,
            SchedulingPhase::DiscoveryTerminal => &mut self.phase_discovery_terminal_ms,
            SchedulingPhase::Drain => &mut self.phase_drain_ms,
            SchedulingPhase::Maps => &mut self.phase_maps_ms,
            SchedulingPhase::Render => &mut self.phase_render_ms,
            SchedulingPhase::Detach => &mut self.phase_detach_ms,
        };
        *slot = slot.saturating_add(ms);
    }

    pub(crate) fn note_loop_end(&mut self, event_loss: u64, discovery_loss: u64) {
        self.capture_event_loss = event_loss;
        self.capture_discovery_loss = discovery_loss;
        self.loop_ended = true;
    }

    pub(crate) fn note_terminal(&mut self, event_loss: u64, discovery_loss: u64) {
        self.detach_event_loss = event_loss.saturating_sub(self.capture_event_loss);
        self.detach_discovery_loss = discovery_loss.saturating_sub(self.capture_discovery_loss);
    }

    pub(crate) fn last_drain_had_backlog(&self) -> bool {
        self.last_backlog
    }

    pub(crate) fn snapshot(&self, terminal_bound: u64) -> render::SchedulingEvidence {
        render::SchedulingEvidence {
            drain_repolls: self.drain_repolls,
            drain_budget_exhaustions: self.drain_budget_exhaustions,
            capture_event_loss: self.capture_event_loss,
            detach_event_loss: self.detach_event_loss,
            capture_discovery_loss: self.capture_discovery_loss,
            detach_discovery_loss: self.detach_discovery_loss,
            terminal_drain_bound: terminal_bound,
            terminal_drain_truncated: self.terminal_drain_truncated,
            sink_policy: render::SINK_POLICY_BOUNDED_WAIT_DROP,
            sink_stall_ms: self.sink_stall_ms,
            sink_timeouts: self.sink_timeouts,
            sink_dropped_bytes: self.sink_dropped_bytes,
            phase_ms: render::SchedulingPhaseMs {
                discovery: self.phase_discovery_ms,
                discovery_terminal: self.phase_discovery_terminal_ms,
                drain: self.phase_drain_ms,
                maps: self.phase_maps_ms,
                render: self.phase_render_ms,
                detach: self.phase_detach_ms,
            },
            max_inter_drain_gap_ms: self.max_inter_drain_gap_ms,
        }
    }
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
) -> Result<(u64, bool)> {
    let domain = drain.domain_id();
    let mut failure = None;
    let may_remain = drain.poll(quantum, |ev| {
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
    Ok((drain.take_malformed_delta(), may_remain))
}

/// Drains what the ring buffer currently holds — one quantum on the live
/// ring, whole after detach — rendering and emitting one line per completed
/// call. Returns the per-poll malformed-record delta from this drain, to
/// accumulate at the call site.
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
    acc: &mut SchedulingAccumulator,
    should_yield: &mut impl FnMut() -> bool,
) -> Result<u64> {
    let terminal = session.producers_detached();
    let budget = ReadyBudget::tick();
    let phase_start = Instant::now();
    let outcome = poll_ready(
        terminal,
        &budget,
        crate::events::LIVE_POLL_QUANTUM,
        should_yield,
        || {
            select_and_drain_events(session, Session::live_poll_quantum, |session, quantum| {
                let drain = session.event_drain()?;
                drain_trace_events_from(
                    drain,
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
        },
    )?;
    acc.add_phase(SchedulingPhase::Drain, phase_start.elapsed());
    acc.note_drain_at(Instant::now());
    if terminal {
        acc.note_terminal_drain(outcome.may_remain);
    } else {
        acc.note_live_drain(&outcome);
    }
    Ok(outcome.malformed)
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
) -> Result<(u64, bool)> {
    let mut write_error = None;
    let mut reduction_error = None;
    let domain = drain.domain_id();
    let may_remain = drain.poll(quantum, |ev| {
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
    // A reached live limit owns no more live work: the readiness loop must
    // not re-poll past it, and the terminal drain owns the remainder.
    let live_limited = quantum.is_some() && matches!(*remaining, Some(0));
    Ok((drain.take_malformed_delta(), may_remain && !live_limited))
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
    static_multi_attached: bool,
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
    scheduling: render::SchedulingEvidence,
    uretprobe_override: Option<render::UretprobeOverride>,
    handoff_child_pid: Option<u32>,
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
        active_slots: facts.active_slots(),
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
            attach_mechanisms(
                attached_probes,
                dynamic_per_offset_attached,
                static_multi_attached,
            )
        } else {
            Vec::new()
        },
        pid_descendant_gaps,
        multi_rebuild_gaps: engine.multi_rebuild_gaps(),
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
        scheduling,
        drain_proven: false,
        verdict_detail: render::VERDICT_CONCRETE_GAP,
        uretprobe_override,
        handoff_child_pid,
        p11scope_env: render::snapshot_process_env(),
        completeness: "UNKNOWN",
    };
    ev.verdict_with_selection(include_selection);
    ev
}

fn attach_mechanisms(
    attached_probes: usize,
    dynamic_per_offset_attached: bool,
    static_multi_attached: bool,
) -> Vec<&'static str> {
    // Sorted to match the capture oracle (`mechanisms == sorted(set)`):
    // static singles and dynamic loader/export probes report
    // "per-offset", static multi group links report "uprobe-multi".
    let mut mechanisms = Vec::new();
    if (attached_probes > 0 && !static_multi_attached) || dynamic_per_offset_attached {
        mechanisms.push("per-offset");
    }
    if static_multi_attached {
        mechanisms.push("uprobe-multi");
    }
    mechanisms
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
    use crate::attach::BackendSelection;
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

    /// F-T4-1: a handoff that fails after the release byte was written kills
    /// the pre-exec child on the spot. Nothing between that failure and
    /// settlement can let it take the byte and run the abandoned command:
    /// here an outside SIGCONT stands in for anything that resumes it while
    /// the coordinator cleans up. Covers a deadline and a cancellation that
    /// is observed only after the write.
    #[test]
    fn a_failed_handoff_kills_the_pre_exec_child_before_anything_can_resume_it() {
        for cancel in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let marker = directory.path().join("ran");
            let mut child = spawn("/usr/bin/touch", &[marker.to_str().unwrap()]);
            wait_for_session_leader(&child);
            let outside = duplicate_fd(child.pin().pidfd().unwrap());
            child.pin().send_signal(libc::SIGSTOP).unwrap();
            wait_until(
                || original_child_is_stopped(outside.as_fd()),
                "the pre-exec child never stopped behind its barrier",
            );

            let written = std::cell::Cell::new(false);
            // Both arms share the long deadline. The cancel=false arm
            // forces its Deadline the way the cancel=true arm forces its
            // cancellation: the pending hook runs only after the release
            // byte was written, so waiting it past the deadline reaches
            // the Deadline path deterministically instead of racing a
            // 40 ms stall through the checks before the write.
            let deadline = Instant::now() + Duration::from_millis(5_000);
            let result = child.release_until_with_pending(
                deadline,
                || (cancel && written.get()).then_some(libc::SIGTERM),
                || {
                    written.set(true);
                    if !cancel {
                        while Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                    }
                },
            );
            assert!(
                written.get(),
                "cancel={cancel}: the release byte was never written"
            );
            if cancel {
                assert!(
                    matches!(result, Err(ExecHandoffError::Cancelled(libc::SIGTERM))),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(ExecHandoffError::Deadline)),
                    "{result:?}"
                );
            }
            assert!(!child.released);

            // Something resumes the child before settlement runs. Best effort:
            // a child the handoff already killed may be gone.
            // SAFETY: the duplicated original pidfd is live for this call.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    outside.as_raw_fd(),
                    libc::SIGCONT,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            assert!(
                child
                    .pin()
                    .wait_ready(Some(Duration::from_secs(5)))
                    .unwrap(),
                "cancel={cancel}: the abandoned child neither died nor exited"
            );
            assert_eq!(
                child
                    .terminate_with_grace(Duration::from_millis(20))
                    .unwrap(),
                128 + libc::SIGKILL,
                "cancel={cancel}: the abandoned child must die by the handoff's SIGKILL"
            );
            assert!(
                !marker.exists(),
                "cancel={cancel}: the abandoned command ran"
            );
        }
    }

    /// F-T4-1: graceful settlement is for a running command. A child that
    /// never confirmed an exec (never released at all, and held in T from
    /// outside) is killed where it stands by both settlement paths. It is
    /// never resumed, and never sent a stop signal it would sit on through a
    /// grace window.
    #[test]
    fn an_unconfirmed_child_is_killed_where_it_stands_on_either_settlement_path() {
        for signal_path in [false, true] {
            let mut child = spawn("/bin/true", &[]);
            wait_for_session_leader(&child);
            let pidfd = duplicate_fd(child.pin().pidfd().unwrap());
            child.pin().send_signal(libc::SIGSTOP).unwrap();
            wait_until(
                || original_child_is_stopped(pidfd.as_fd()),
                "the pre-exec child never stopped behind its barrier",
            );

            let started = Instant::now();
            let code = if signal_path {
                let signals = SignalState::new();
                signals.observe(libc::SIGTERM);
                match settle_after_signal_with_grace(&mut child, &signals, TERM_GRACE).unwrap() {
                    ChildOutcome::Exited(code) => code,
                    ChildOutcome::TimedOutRunning => panic!("signal settlement left the child"),
                }
            } else {
                child.terminate_with_grace(TERM_GRACE).unwrap()
            };
            let elapsed = started.elapsed();

            assert_eq!(
                code,
                128 + libc::SIGKILL,
                "signal_path={signal_path}: an unconfirmed child dies by SIGKILL, unresumed"
            );
            assert!(
                elapsed < TERM_GRACE,
                "signal_path={signal_path}: settlement waited {elapsed:?} on an unconfirmed child"
            );
            assert!(child.is_reaped());
        }
    }

    /// The SIGINT and SIGTERM bits of one `/proc/<pid>/status` signal mask.
    fn stop_signal_bits(pid: &str, field: &str) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let mask = status
            .lines()
            .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
            .unwrap_or_else(|| panic!("/proc/{pid}/status has no {field}"));
        u64::from_str_radix(mask.trim(), 16).unwrap()
            & ((1 << (libc::SIGINT - 1)) | (1 << (libc::SIGTERM - 1)))
    }

    /// F-T4-1 hardening: the observer's stop handlers stay the observer's.
    /// The fork child resets SIGINT and SIGTERM to their default actions
    /// before it becomes a session leader, so a stop signal ends a pre-exec
    /// child instead of being swallowed by an inherited handler. exec resets
    /// caught signals anyway, so the command starts with the same
    /// dispositions either way.
    #[test]
    fn the_pre_exec_child_does_not_inherit_the_observer_stop_handlers() {
        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        let _stop = install_stop_flag().unwrap();
        let both = (1u64 << (libc::SIGINT - 1)) | (1u64 << (libc::SIGTERM - 1));
        assert_eq!(
            stop_signal_bits("self", "SigCgt"),
            both,
            "the observer catches both stop signals"
        );
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let mut child = spawn(sleeper.to_str().unwrap(), &[]);
        wait_for_session_leader(&child);
        let pid = child.pid().to_string();

        assert_eq!(
            stop_signal_bits(&pid, "SigCgt"),
            0,
            "the pre-exec child still runs the observer's stop handlers"
        );
        assert_eq!(stop_signal_bits(&pid, "SigIgn"), 0);
        child.release().unwrap();
        assert_eq!(
            stop_signal_bits(&pid, "SigCgt"),
            0,
            "the command catches a stop signal"
        );
        assert_eq!(
            stop_signal_bits(&pid, "SigIgn"),
            0,
            "the command ignores a stop signal"
        );
        assert_eq!(child.terminate_and_reap().unwrap(), 128 + libc::SIGTERM);
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
        let mut child = spawn(
            "/bin/sh",
            &[
                "-c",
                &format!(
                    "trap '' INT TERM; : > {}; while :; do :; done",
                    ready.display(),
                ),
            ],
        );
        child.release().unwrap();
        wait_until(|| ready.exists(), "the SIGINT fixture never became ready");

        let signals = Arc::new(SignalState::new());
        signals.observe(libc::SIGINT);
        let observed = Arc::clone(&signals);
        let mut fallback_terms = 0;
        assert_eq!(
            settle_after_signal_with_grace_and(
                &mut child,
                &signals,
                Duration::from_millis(100),
                || {
                    fallback_terms += 1;
                    assert_eq!(
                        observed.sigint_deliveries(),
                        1,
                        "the second SIGINT was recorded before fallback SIGTERM",
                    );
                    observed.observe(libc::SIGINT);
                },
            )
            .unwrap(),
            ChildOutcome::Exited(128 + libc::SIGKILL)
        );
        assert_eq!(
            fallback_terms, 1,
            "settlement did not enter fallback SIGTERM grace"
        );
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

    /// F-25's other shape: the child held in T also refuses to exit on
    /// SIGTERM. Settlement must resume it first, so the forwarded SIGTERM is
    /// actually delivered (its handler runs) instead of pending behind the
    /// stop, and then escalate to SIGKILL on its fixed budget: two grace
    /// windows plus the final kill grace, never a wait on the child itself.
    #[test]
    fn operator_stop_delivers_sigterm_to_a_held_child_then_escalates_within_the_bound() {
        let directory = tempfile::tempdir().unwrap();
        let ready = directory.path().join("ready");
        let term_seen = directory.path().join("term-seen");
        // The paths travel as positional parameters, never as script text.
        let mut child = spawn(
            "/bin/sh",
            &[
                "-c",
                "exec 2>/dev/null; trap ': > \"$2\"' TERM; : > \"$1\"; while :; do sleep 1; done",
                "sh",
                ready.to_str().unwrap(),
                term_seen.to_str().unwrap(),
            ],
        );
        child.release().unwrap();
        wait_until(
            || ready.exists(),
            "the TERM fixture never installed its handler",
        );
        let rescue_pidfd = duplicate_fd(child.pin().pidfd().unwrap());
        child.pin().send_signal(libc::SIGSTOP).unwrap();
        wait_until(
            || original_child_is_stopped(rescue_pidfd.as_fd()),
            "the fixture child never entered the stopped state",
        );

        let signals = Arc::new(SignalState::new());
        signals.observe(libc::SIGTERM);
        let grace = Duration::from_secs(1);
        let bound = grace.saturating_mul(2).saturating_add(FINAL_KILL_GRACE);
        let settling = Arc::clone(&signals);
        let (settled_tx, settled_rx) = std::sync::mpsc::channel();
        let started = Instant::now();
        let settle = std::thread::spawn(move || {
            let outcome = settle_after_signal_with_grace(&mut child, &settling, grace)
                .map_err(|error| format!("{error:#}"));
            settled_tx.send((outcome, child.is_reaped())).unwrap();
        });
        let settled = settled_rx.recv_timeout(bound);
        let elapsed = started.elapsed();
        if settled.is_err() {
            // Unwedge the harness before failing: kill the exact child.
            let _ = rescue_original_pidfd(
                rescue_pidfd.as_raw_fd(),
                &std::sync::atomic::AtomicBool::new(false),
            );
        }
        settle.join().unwrap();
        let (outcome, reaped) = settled.unwrap_or_else(|_| {
            panic!("settling a held child that survives SIGTERM overran its {bound:?} budget")
        });

        assert_eq!(outcome, Ok(ChildOutcome::Exited(128 + libc::SIGKILL)));
        assert!(reaped);
        assert!(
            term_seen.exists(),
            "the forwarded SIGTERM never reached the held child: it was not resumed first"
        );
        assert!(elapsed < bound, "settlement took {elapsed:?}");
    }

    /// The scripted half of a pause-held owned child: the authorization map,
    /// the discovery queue, the coordinator's monotonic clock, and a count of
    /// resumes. The clock advances by one tick per read, so no coordinator
    /// deadline (the 500 ms cleanup bound included) depends on scheduling.
    /// Everything else the shutdown test below drives is real — the
    /// coordinator, the owned child, its pidfd SIGCONT, its `/proc` task
    /// states, and the settlement path.
    ///
    /// The F-T4-2 tick tests add several scripted pieces, so they can confirm
    /// a full cycle, observe what a tick hands the capture loop, and price an
    /// idle tick:
    /// - a batch outcome (`required_complete`);
    /// - whether a batch with records changes the attach plan
    ///   (`batch_changes_plan`, reported through `plan_changed` per tick);
    /// - a successor stop on the first resume;
    /// - counts of the scripted I/O.
    ///
    /// All of these default to the shutdown test's behaviour.
    #[derive(Default)]
    struct HeldPause {
        authorization: Option<u64>,
        queue: std::collections::VecDeque<crate::discovery::pause::DiscoveryItem>,
        now_ns: u64,
        resumes: usize,
        required_complete: bool,
        batch_changes_plan: bool,
        plan_changed: bool,
        successor_on_resume: bool,
        hooks: Vec<u64>,
        resumed_at: Vec<u64>,
        authorization_reads: usize,
        dequeues: usize,
    }

    /// The helper's stop, as the kernel performs it: a loader hook in the
    /// owned child consumes the ARMED authorization (REQUESTED), queues its
    /// record stamped on the coordinator's clock (never older than the arm it
    /// consumed), and its SIGSTOP holds the child. Returns the hook timestamp
    /// that starts the stop's causal deadline.
    fn helper_stop(child: &OwnedChild, held: &mut HeldPause) -> u64 {
        held.authorization = Some(p11scope_ebpf_common::PAUSE_REQUESTED);
        // SAFETY: DiscoveryRecord is plain old data; all-zero is valid.
        let mut record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.pid_tgid = u64::from(child.pid()) << 32;
        record.hook_ts_ns = held.now_ns;
        held.queue
            .push_back(crate::discovery::pause::DiscoveryItem::Record(record));
        held.hooks.push(record.hook_ts_ns);
        child.pin().send_signal(libc::SIGSTOP).unwrap();
        wait_until(
            || original_child_is_stopped(child.pin().pidfd().unwrap()),
            "the helper's SIGSTOP never held the child",
        );
        record.hook_ts_ns
    }

    struct HeldPauseIo<'a> {
        child: &'a OwnedChild,
        held: &'a mut HeldPause,
        signals: &'a SignalState,
    }

    impl crate::discovery::pause::PauseIo for HeldPauseIo<'_> {
        fn now_ns(&mut self) -> std::result::Result<u64, String> {
            self.held.now_ns += 1;
            Ok(self.held.now_ns)
        }

        fn wait_one_ms(&mut self) -> std::result::Result<(), String> {
            self.held.now_ns += 1_000_000;
            Ok(())
        }

        fn task_states(
            &mut self,
            pid: u32,
        ) -> std::result::Result<std::collections::BTreeMap<u32, u8>, String> {
            crate::discovery::pause::read_task_states(pid)
        }

        fn dequeue(
            &mut self,
        ) -> std::result::Result<Option<crate::discovery::pause::DiscoveryItem>, String> {
            self.held.dequeues += 1;
            Ok(self.held.queue.pop_front())
        }

        fn arm(&mut self) -> std::result::Result<(), String> {
            self.held.authorization = Some(p11scope_ebpf_common::PAUSE_ARMED);
            Ok(())
        }

        fn authorization(&mut self) -> std::result::Result<Option<u64>, String> {
            self.held.authorization_reads += 1;
            Ok(self.held.authorization)
        }

        fn remove_authorization(&mut self) -> std::result::Result<Option<u64>, String> {
            Ok(self.held.authorization.take())
        }

        fn apply_batch(
            &mut self,
            records: Vec<p11scope_ebpf_common::DiscoveryRecord>,
            _: Option<u64>,
            _: bool,
            _: bool,
            _: &mut Option<crate::discovery::engine::TerminalBatch>,
        ) -> std::result::Result<
            crate::discovery::pause::PauseBatchOutcome,
            crate::discovery::pause::PauseBatchError,
        > {
            self.held.plan_changed |= self.held.batch_changes_plan && !records.is_empty();
            let mut outcome = crate::discovery::pause::PauseBatchOutcome::default();
            outcome.required_complete = self.held.required_complete;
            Ok(outcome)
        }

        fn account_unvalidated_records(&mut self, _: u64) {}

        fn reconcile_terminal_authority(
            &mut self,
            _: &mut Option<crate::discovery::engine::TerminalBatch>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }

        fn cleanup_terminal_batch_without_replay(
            &mut self,
            _: &mut Option<crate::discovery::engine::TerminalBatch>,
        ) -> std::result::Result<(), String> {
            Ok(())
        }

        fn revalidate_after_release(
            &mut self,
            _: bool,
        ) -> std::result::Result<crate::discovery::pause::PauseRevalidationOutcome, String>
        {
            Err("post-release revalidation is not part of shutdown".into())
        }

        fn marker_seen(&mut self) -> std::result::Result<bool, String> {
            Ok(false)
        }

        fn resume(&mut self) -> std::result::Result<(), String> {
            self.held.resumes += 1;
            self.held.resumed_at.push(self.held.now_ns);
            self.child.pin().send_signal(libc::SIGCONT)?;
            // A cascade: the child's next loader hook consumes the successor
            // the cycle installed before this resume, right after it.
            if std::mem::take(&mut self.held.successor_on_resume)
                && self.held.authorization == Some(p11scope_ebpf_common::PAUSE_ARMED)
            {
                helper_stop(self.child, self.held);
            }
            Ok(())
        }

        fn detach_pause_links(&mut self) -> std::result::Result<(), String> {
            Ok(())
        }

        fn same_generation(
            &mut self,
            pid: u32,
            generation: u64,
        ) -> std::result::Result<bool, String> {
            Ok(pid == self.child.pid()
                && generation == self.child.generation().get()
                && self.child.pin().still_the_same())
        }

        fn original_exited(&mut self) -> std::result::Result<bool, String> {
            self.child.pin().original_exited()
        }

        fn cancelled(&mut self) -> std::result::Result<bool, String> {
            Ok(self.signals.interrupted())
        }
    }

    impl TickPauseIo for HeldPauseIo<'_> {
        fn plan_changed(&self) -> bool {
            self.held.plan_changed
        }
    }

    /// F-25 end to end, without BPF: the kernel consumed the pause arm and the
    /// helper's SIGSTOP holds the owned child when the capture ends — by an
    /// operator SIGTERM, by `--duration`, or by a capture error — before any
    /// capture tick serviced the stop. The two steps `Owned::finish` runs
    /// (coordinator cleanup, then settlement) must resume the held child,
    /// report the stop that never confirmed (`auto`: partial; `always`: a
    /// required refusal), and settle the child well inside one TERM grace
    /// window: terminated, or handed back running — never left in T.
    #[test]
    fn shutdown_resumes_reports_and_settles_a_child_held_by_an_unserviced_pause() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        for policy in [cli::PausePolicy::Auto, cli::PausePolicy::Always] {
            for end in [
                CaptureEnd::Signal,
                CaptureEnd::DurationExpired,
                CaptureEnd::Error,
            ] {
                let case = format!("{policy:?}/{end:?}");
                let mut child = spawn(sleeper.to_str().unwrap(), &[]);
                let signals = SignalState::new();
                let mut held = HeldPause::default();
                let mut coordinator = {
                    let mut io = HeldPauseIo {
                        child: &child,
                        held: &mut held,
                        signals: &signals,
                    };
                    let mut coordinator =
                        PauseCoordinator::preflight(policy, &child, &mut io).unwrap();
                    assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
                    coordinator
                };
                child.release().unwrap();

                // The loader hook fires: the kernel's exchange consumes the
                // arm, the helper's record is queued, and its SIGSTOP holds
                // the child.
                held.authorization = Some(p11scope_ebpf_common::PAUSE_REQUESTED);
                // SAFETY: DiscoveryRecord is plain old data; all-zero is valid.
                let mut record: p11scope_ebpf_common::DiscoveryRecord =
                    unsafe { std::mem::zeroed() };
                record.pid_tgid = u64::from(child.pid()) << 32;
                // Stamped on the scripted clock at the arm's tick, as the
                // kernel stamps it after the exchange: never older than the arm.
                record.hook_ts_ns = held.now_ns;
                held.queue
                    .push_back(crate::discovery::pause::DiscoveryItem::Record(record));
                child.pin().send_signal(libc::SIGSTOP).unwrap();
                wait_until(
                    || original_child_is_stopped(child.pin().pidfd().unwrap()),
                    "the helper's SIGSTOP never held the child",
                );

                if end == CaptureEnd::Signal {
                    signals.observe(libc::SIGTERM);
                }
                let started = Instant::now();
                let cleanup = {
                    let mut io = HeldPauseIo {
                        child: &child,
                        held: &mut held,
                        signals: &signals,
                    };
                    coordinator.cleanup(&mut io)
                };
                assert!(
                    !original_child_is_stopped(child.pin().pidfd().unwrap()),
                    "{case}: the child is still held stopped after cleanup"
                );
                assert_eq!(
                    held.resumes, 1,
                    "{case}: cleanup resumes the held child once"
                );
                assert_eq!(held.authorization, None, "{case}");
                if policy == cli::PausePolicy::Auto {
                    assert!(cleanup.is_ok(), "{case}: {cleanup:?}");
                    assert_eq!(
                        coordinator.counters(),
                        crate::discovery::pause::PauseCounters {
                            attempts: 1,
                            confirmed: 0,
                            partial: 1,
                        },
                        "{case}: the stop that never confirmed must be reported as partial"
                    );
                    assert_eq!(coordinator.status(), PauseStatus::Partial, "{case}");
                } else {
                    let error = cleanup
                        .as_ref()
                        .expect_err("always refuses a stop that never confirmed");
                    assert!(error.required() && !error.lifecycle(), "{case}: {error}");
                    assert_eq!(coordinator.counters().confirmed, 0, "{case}");
                }

                let mut retained = Some(child);
                let mut pending = None;
                let mut exit_code = None;
                let mut still_running = false;
                settle_owned_child(
                    &mut retained,
                    end,
                    cleanup.is_ok(),
                    false,
                    &signals,
                    &mut pending,
                    &mut exit_code,
                    &mut still_running,
                )
                .unwrap();
                let elapsed = started.elapsed();

                assert!(
                    elapsed < TERM_GRACE,
                    "{case}: shutdown waited out a TERM grace window ({elapsed:?})"
                );
                if end == CaptureEnd::DurationExpired && cleanup.is_ok() {
                    // `--duration` without `--kill-on-timeout` hands it back.
                    assert_eq!(exit_code, None, "{case}");
                    assert!(still_running, "{case}");
                    let staged = pending.as_ref().expect("a staged running handoff");
                    assert!(
                        !original_child_is_stopped(staged.pin().pidfd().unwrap()),
                        "{case}: a handed-back child is never left stopped"
                    );
                    // Uncommitted: dropping the staged child kills and reaps it.
                } else {
                    assert_eq!(
                        exit_code,
                        Some(128 + libc::SIGTERM),
                        "{case}: the resumed child must die by the SIGTERM it was sent"
                    );
                    assert!(!still_running, "{case}");
                    assert!(retained.as_ref().unwrap().is_reaped(), "{case}");
                    assert!(pending.is_none(), "{case}");
                }
            }
        }
    }

    /// One capture tick's pause step, composed as both capture loops compose
    /// it for an owned explicit pause. The discovery gate asks `pause_stop_due`
    /// between frames only.
    /// - A pending stop runs the production between-frames step,
    ///   `pending_stop_pass`: all of `service_pending_stop` but its session
    ///   adapter.
    /// - A frame pass services an armed pause through the same `service_pause`
    ///   entry that `drain_discovery_tick` calls. That wrapper, and its ordinary
    ///   fallback for a disabled policy, need BPF and do not arise here.
    ///
    /// Returns the admitted pass and what the loop receives: the tick's
    /// `(plan_changed, paused)`, or `Err` when the capture ends.
    fn held_pause_tick(
        since_frame: Duration,
        drain: Duration,
        coordinator: &mut PauseCoordinator,
        io: &mut HeldPauseIo<'_>,
    ) -> (Option<DiscoveryPass>, Result<(bool, bool)>) {
        let pass = discovery_due(since_frame, drain, || pause_stop_due(coordinator, io));
        let handed = match pass {
            None => Ok((false, false)),
            Some(DiscoveryPass::PendingStop) => pending_stop_pass(coordinator, io),
            Some(DiscoveryPass::Frame) => {
                let serviced = service_pause(coordinator, io)
                    .unwrap_or_else(|error| panic!("a frame pass failed: {error}"));
                assert!(serviced, "a frame pass must service an armed pause");
                Ok((io.plan_changed(), true))
            }
        };
        (pass, handed)
    }

    /// One driven tick: the pass it admitted, then the `(plan_changed, paused)`
    /// it handed the loop (both false when it ended the capture).
    type HeldTick = (Option<DiscoveryPass>, bool, bool);

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HeldStop {
        /// One helper stop, landing just after a frame.
        One,
        /// The same, and the successor its cycle installs is consumed right
        /// after that cycle's resume, so `observe_resumed` only acknowledges it.
        Cascade,
        /// The cascade with the first stop serviced by a frame, so only the
        /// successor waits between frames.
        CascadeAfterFrame,
        /// One stop whose required attachment fails: a genuinely failed cycle.
        Failed,
        /// One stop, with an operator stop already pending on the tick.
        Signalled,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct HeldStopOutcome {
        case: HeldStop,
        policy: cli::PausePolicy,
        /// The first two ticks.
        first_ticks: [HeldTick; 2],
        /// A tick's pause failure ended the capture.
        ended_by_pause_failure: bool,
        /// Whether the child was still stopped after the last tick.
        held_after_ticks: bool,
        counters_after_ticks: crate::discovery::pause::PauseCounters,
        /// After the capture's cleanup: the counters the report renders, and
        /// whether cleanup refused the run.
        counters_after_cleanup: crate::discovery::pause::PauseCounters,
        cleanup_refused: bool,
        resumes: usize,
        /// The scripted I/O of the idle ticks after the first two.
        idle_authorization_reads: usize,
        idle_dequeues: usize,
    }

    /// F-T4-2 end to end, without BPF. A real owned child is held stopped by
    /// the helper's SIGSTOP, with REQUESTED and its record queued. The real
    /// coordinator is driven through one capture tick's pause step at the
    /// profile default drain interval, with `since_frame = 0` (the frame has
    /// just run). The scripted clock advances one idle wait per tick, and the
    /// ticks span the whole 500 ms causal budget.
    ///
    /// The first tick must service the stop: confirmed, and the child resumed
    /// (the kernel's waitid says so) before hook + 500 ms on the coordinator's
    /// clock. In a cascade, the next tick must service the successor as well.
    /// Afterwards an idle tick costs one authorization read while the
    /// successor stays armed, and nothing once the pause is disarmed. The
    /// semantics around it hold. A genuinely failed cycle still resumes the
    /// child and goes partial under `auto`, and ends the capture under
    /// `always`. A pending operator stop wins: the tick services nothing, and
    /// cleanup resumes the child and reports the stop (`auto` partial, `always`
    /// refused). Under the frame-only gate every stop stayed held through all
    /// the ticks and cleanup reported it unconfirmed.
    ///
    /// Each tick also records the `(plan_changed, paused)` it hands the loop.
    /// A pause batch normally changes the attach plan (a new provider). One
    /// `always` stop's batch attaches nothing new, because `always` stops on
    /// every load, already-attached ones included. That tick pauses without a
    /// plan change, so the pair's two halves can be told apart.
    #[test]
    fn a_pending_pause_stop_is_serviced_between_frames_within_its_causal_deadline() {
        use crate::cli::PausePolicy::{Always, Auto};
        use crate::discovery::pause::PauseCounters;
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let budget = crate::discovery::pause::CYCLE_NS;
        let idle_wait = u64::try_from(READY_IDLE_POLL.as_nanos()).unwrap();
        let ticks = usize::try_from(budget / idle_wait).unwrap();
        let drain = PROFILE_CADENCE;
        let cases = [
            (HeldStop::One, Auto),
            (HeldStop::Cascade, Auto),
            (HeldStop::CascadeAfterFrame, Auto),
            (HeldStop::Failed, Auto),
            (HeldStop::Signalled, Auto),
            (HeldStop::One, Always),
            (HeldStop::Failed, Always),
            (HeldStop::Signalled, Always),
        ];
        let mut observed = Vec::new();
        let mut deadlines = Vec::new();
        for (case, policy) in cases {
            let mut child = spawn(sleeper.to_str().unwrap(), &[]);
            let signals = SignalState::new();
            let mut held = HeldPause {
                required_complete: case != HeldStop::Failed,
                batch_changes_plan: (case, policy) != (HeldStop::One, Always),
                successor_on_resume: matches!(
                    case,
                    HeldStop::Cascade | HeldStop::CascadeAfterFrame
                ),
                ..HeldPause::default()
            };
            let mut coordinator = {
                let mut io = HeldPauseIo {
                    child: &child,
                    held: &mut held,
                    signals: &signals,
                };
                let mut coordinator = PauseCoordinator::preflight(policy, &child, &mut io).unwrap();
                assert_eq!(coordinator.arm(&mut io).unwrap(), ArmResult::Armed);
                coordinator
            };
            child.release().unwrap();
            helper_stop(&child, &mut held);
            if case == HeldStop::Signalled {
                signals.observe(libc::SIGTERM);
            }

            let idle: HeldTick = (None, false, false);
            let mut first_ticks = [idle; 2];
            let mut idle_from = None;
            let mut ended_by_pause_failure = false;
            for tick in 0..ticks {
                if tick == 2 {
                    idle_from = Some((held.authorization_reads, held.dequeues));
                }
                let since_frame = if tick == 0 && case == HeldStop::CascadeAfterFrame {
                    drain
                } else {
                    Duration::ZERO
                };
                // A fresh adapter per tick, as the loop builds one per pass.
                held.plan_changed = false;
                let mut io = HeldPauseIo {
                    child: &child,
                    held: &mut held,
                    signals: &signals,
                };
                let (pass, handed) = held_pause_tick(since_frame, drain, &mut coordinator, &mut io);
                held.now_ns += idle_wait;
                let (plan_changed, paused) = handed.as_ref().map_or((false, false), |pair| *pair);
                if let Some(record) = first_ticks.get_mut(tick) {
                    *record = (pass, plan_changed, paused);
                }
                if handed.is_err() {
                    ended_by_pause_failure = true;
                    break;
                }
            }
            let held_after_ticks = original_child_is_stopped(child.pin().pidfd().unwrap());
            let counters_after_ticks = coordinator.counters();
            let (idle_authorization_reads, idle_dequeues) = idle_from
                .map_or((0, 0), |(reads, dequeues)| {
                    (held.authorization_reads - reads, held.dequeues - dequeues)
                });

            // The capture ends: `Owned::finish` runs the coordinator's cleanup.
            let cleanup = {
                let mut io = HeldPauseIo {
                    child: &child,
                    held: &mut held,
                    signals: &signals,
                };
                coordinator.cleanup(&mut io)
            };
            if let Err(error) = &cleanup {
                assert!(
                    error.required() && !error.lifecycle(),
                    "{case:?}/{policy:?}: {error}"
                );
            }
            assert!(
                !original_child_is_stopped(child.pin().pidfd().unwrap()),
                "{case:?}/{policy:?}: the child is still held stopped after cleanup"
            );
            observed.push(HeldStopOutcome {
                case,
                policy,
                first_ticks,
                ended_by_pause_failure,
                held_after_ticks,
                counters_after_ticks,
                counters_after_cleanup: coordinator.counters(),
                cleanup_refused: cleanup.is_err(),
                resumes: held.resumes,
                idle_authorization_reads,
                idle_dequeues,
            });
            if matches!(
                case,
                HeldStop::One | HeldStop::Cascade | HeldStop::CascadeAfterFrame
            ) {
                deadlines.push((case, policy, held.hooks.clone(), held.resumed_at.clone()));
            }
            // Dropping the child kills and reaps it.
        }

        let idle: HeldTick = (None, false, false);
        let stop: HeldTick = (Some(DiscoveryPass::PendingStop), true, true);
        let confirmed = |stops| PauseCounters {
            attempts: stops,
            confirmed: stops,
            partial: 0,
        };
        let unconfirmed = |partial| PauseCounters {
            attempts: 1,
            confirmed: 0,
            partial,
        };
        let serviced =
            |case, policy, first_ticks, stops, idle_authorization_reads| HeldStopOutcome {
                case,
                policy,
                first_ticks,
                ended_by_pause_failure: false,
                held_after_ticks: false,
                counters_after_ticks: confirmed(stops),
                counters_after_cleanup: confirmed(stops),
                cleanup_refused: false,
                resumes: usize::try_from(stops).unwrap(),
                idle_authorization_reads,
                idle_dequeues: 0,
            };
        let expected = [
            serviced(HeldStop::One, Auto, [stop, idle], 1, ticks - 2),
            serviced(HeldStop::Cascade, Auto, [stop, stop], 2, 0),
            serviced(
                HeldStop::CascadeAfterFrame,
                Auto,
                [(Some(DiscoveryPass::Frame), true, true), stop],
                2,
                0,
            ),
            // The failed cycle resumes the child, counts one partial attempt
            // and retires re-arming; the capture continues.
            HeldStopOutcome {
                case: HeldStop::Failed,
                policy: Auto,
                first_ticks: [stop, idle],
                ended_by_pause_failure: false,
                held_after_ticks: false,
                counters_after_ticks: unconfirmed(1),
                counters_after_cleanup: unconfirmed(1),
                cleanup_refused: false,
                resumes: 1,
                idle_authorization_reads: 0,
                idle_dequeues: 0,
            },
            HeldStopOutcome {
                case: HeldStop::Signalled,
                policy: Auto,
                first_ticks: [idle, idle],
                ended_by_pause_failure: false,
                held_after_ticks: true,
                counters_after_ticks: PauseCounters::default(),
                counters_after_cleanup: unconfirmed(1),
                cleanup_refused: false,
                resumes: 1,
                idle_authorization_reads: 0,
                idle_dequeues: 0,
            },
            // Its batch attached nothing new: the tick pauses without a plan
            // change.
            serviced(
                HeldStop::One,
                Always,
                [(Some(DiscoveryPass::PendingStop), false, true), idle],
                1,
                ticks - 2,
            ),
            // The failed cycle resumes the child, and its required failure
            // ends the capture on that tick.
            HeldStopOutcome {
                case: HeldStop::Failed,
                policy: Always,
                first_ticks: [(Some(DiscoveryPass::PendingStop), false, false), idle],
                ended_by_pause_failure: true,
                held_after_ticks: false,
                counters_after_ticks: unconfirmed(0),
                counters_after_cleanup: unconfirmed(0),
                cleanup_refused: false,
                resumes: 1,
                idle_authorization_reads: 0,
                idle_dequeues: 0,
            },
            HeldStopOutcome {
                case: HeldStop::Signalled,
                policy: Always,
                first_ticks: [idle, idle],
                ended_by_pause_failure: false,
                held_after_ticks: true,
                counters_after_ticks: PauseCounters::default(),
                counters_after_cleanup: unconfirmed(0),
                cleanup_refused: true,
                resumes: 1,
                idle_authorization_reads: 0,
                idle_dequeues: 0,
            },
        ];
        assert_eq!(observed, expected);

        for (case, policy, hooks, resumed_at) in deadlines {
            assert_eq!(
                hooks.len(),
                resumed_at.len(),
                "{case:?}/{policy:?}: one resume per stop"
            );
            for (hook, resumed) in hooks.iter().zip(&resumed_at) {
                assert!(
                    *resumed <= hook + budget,
                    "{case:?}/{policy:?}: the stop hooked at {hook} ns was resumed at \
                     {resumed} ns, past its {budget} ns causal deadline"
                );
            }
        }
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

    /// Name errors precede hazard errors: the fail-fast target check
    /// refuses a script with its interpreter fix before any kernel
    /// verdict is consulted, exactly as `spawn` would at the fork.
    #[test]
    fn unrunnable_targets_are_refused_by_name_before_the_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hello.sh");
        std::fs::write(&script, "#!/bin/sh\necho hello\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let error = check_owned_target_runnable(script.as_os_str()).unwrap_err();
        let text = format!("{error}");
        assert!(text.contains("must be an ELF executable"), "{text}");
        assert!(
            text.contains("invoke scripts through an interpreter"),
            "{text}"
        );
        assert!(check_owned_target_runnable(std::ffi::OsStr::new("/bin/true")).is_ok());
    }

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
            attach_backend: BackendSelection::default(),
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
            // The hazard preflight refuses first: without BPF the kernel
            // cannot be proven to exempt the trampoline, so an owned
            // child is refused before anything is forked (F-01).
            let never = format!(
                "{:#}",
                run_owned(&run_args(cli::PausePolicy::Never, &["/bin/true"]))
                    .expect_err("an unavailable capture lane must refuse")
            );
            assert!(never.contains("refusing to attach"), "{never}");
            assert!(
                !never.contains("pause"),
                "an environment failure is not a pause failure: {never}"
            );
            // Behind the override, the environment failure keeps its own
            // category: the session still cannot start without BPF.
            let mut overridden = run_args(cli::PausePolicy::Never, &["/bin/true"]);
            overridden.allow_confined_uretprobe = true;
            let behind_override = format!(
                "{:#}",
                run_owned(&overridden).expect_err("an unavailable capture lane must refuse")
            );
            assert!(
                behind_override.contains("attach session"),
                "{behind_override}"
            );
            assert!(
                !behind_override.contains("pause"),
                "an environment failure is not a pause failure: {behind_override}"
            );
            let always = format!(
                "{:#}",
                run_owned(&run_args(cli::PausePolicy::Always, &["/bin/true"]))
                    .expect_err("an unavailable capture lane must refuse")
            );
            assert!(always.contains("pause"), "{always}");
            assert!(
                always.contains("refusing to attach"),
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

        let (malformed, may_remain) = drain_profile_events(
            &mut drain,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            Some(LIVE_POLL_QUANTUM),
        )
        .unwrap();

        assert_eq!(malformed, 0);
        assert!(may_remain, "the quantum stop reports its backlog");
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
            (0, false)
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
            (0, false)
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

        let (malformed, may_remain) = drain_trace_events_from(
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
        assert!(
            !may_remain,
            "a reached limit owns no more live work for the readiness loop"
        );
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

    /// May-remain re-poll: while the ring still has backlog and no bound
    /// binds, the readiness loop polls again instead of sleeping.
    #[test]
    fn readiness_poll_repolls_until_the_ring_reads_empty() {
        let script = std::cell::RefCell::new(vec![true, true, false].into_iter());
        let calls = std::cell::Cell::new(0);
        let budget = ReadyBudget::for_test(usize::MAX, Duration::from_secs(60));
        let outcome = poll_ready(false, &budget, 4096, &mut || false, || {
            calls.set(calls.get() + 1);
            Ok((1, script.borrow_mut().next().unwrap()))
        })
        .unwrap();

        assert_eq!(calls.get(), 3);
        assert_eq!(
            outcome,
            ReadyOutcome {
                malformed: 3,
                repolls: 2,
                budget_exhausted: false,
                may_remain: false,
            }
        );
    }

    /// Finite quanta: the per-tick record budget stops the loop with the
    /// backlog explicitly flagged, never an unbounded drain.
    #[test]
    fn readiness_poll_stops_at_its_record_budget_with_backlog_flagged() {
        let calls = std::cell::Cell::new(0);
        let budget = ReadyBudget::for_test(8192, Duration::from_secs(60));
        let outcome = poll_ready(false, &budget, 4096, &mut || false, || {
            calls.set(calls.get() + 1);
            Ok((0, true))
        })
        .unwrap();

        assert_eq!(calls.get(), 2);
        assert!(outcome.may_remain);
        assert!(outcome.budget_exhausted);
        assert_eq!(outcome.repolls, 1);
    }

    /// Fairness: an interrupt or elapsed duration stops the loop between
    /// quanta, and that yield is not a budget exhaustion.
    #[test]
    fn readiness_poll_yields_between_quanta_without_calling_it_exhaustion() {
        let calls = std::cell::Cell::new(0);
        let budget = ReadyBudget::for_test(usize::MAX, Duration::from_secs(60));
        let outcome = poll_ready(false, &budget, 4096, &mut || calls.get() >= 1, || {
            calls.set(calls.get() + 1);
            Ok((0, true))
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert!(outcome.may_remain);
        assert!(!outcome.budget_exhausted);
        assert_eq!(outcome.repolls, 0);
    }

    /// The terminal drain takes exactly one poll: its bound is explicit,
    /// and backlog past it is truncation, not a re-poll.
    #[test]
    fn readiness_poll_terminal_takes_one_poll_and_reports_truncation() {
        let calls = std::cell::Cell::new(0);
        let budget = ReadyBudget::for_test(usize::MAX, Duration::from_secs(60));
        let outcome = poll_ready(true, &budget, 65536, &mut || false, || {
            calls.set(calls.get() + 1);
            Ok((0, true))
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert!(outcome.may_remain);
        assert!(!outcome.budget_exhausted);
        assert_eq!(outcome.repolls, 0);
    }

    /// Wall-time budget: a hot ring stops the tick even when the record
    /// budget would allow more.
    #[test]
    fn readiness_poll_wall_budget_stops_a_hot_ring() {
        let calls = std::cell::Cell::new(0);
        let budget = ReadyBudget::for_test(usize::MAX, Duration::ZERO);
        let outcome = poll_ready(false, &budget, 4096, &mut || false, || {
            calls.set(calls.get() + 1);
            Ok((0, true))
        })
        .unwrap();

        assert_eq!(calls.get(), 1);
        assert!(outcome.may_remain);
        assert!(outcome.budget_exhausted);
    }

    /// The accumulator snapshot carries every scheduling counter, split,
    /// and phase timer into the published evidence shape.
    #[test]
    fn scheduling_snapshot_maps_counters_splits_and_phases() {
        let mut acc = SchedulingAccumulator::default();
        acc.note_live_drain(&ReadyOutcome {
            malformed: 0,
            repolls: 2,
            budget_exhausted: true,
            may_remain: true,
        });
        acc.add_phase(SchedulingPhase::Discovery, Duration::from_millis(7));
        acc.add_phase(SchedulingPhase::Drain, Duration::from_millis(3));
        acc.add_phase(SchedulingPhase::Detach, Duration::from_secs(61));
        let before = Instant::now();
        acc.note_drain_at(before);
        acc.note_drain_at(before + Duration::from_millis(40));
        acc.note_loop_end(10, 3);
        acc.note_terminal(14, 3);

        let ev = acc.snapshot(65536);

        assert_eq!(ev.drain_repolls, 2);
        assert_eq!(ev.drain_budget_exhaustions, 1);
        assert!(acc.last_drain_had_backlog());
        assert_eq!(ev.capture_event_loss, 10);
        assert_eq!(ev.detach_event_loss, 4);
        assert_eq!(ev.capture_discovery_loss, 3);
        assert_eq!(ev.detach_discovery_loss, 0);
        assert_eq!(ev.terminal_drain_bound, 65536);
        assert!(!ev.terminal_drain_truncated);
        assert_eq!(ev.phase_ms.discovery, 7);
        assert_eq!(ev.phase_ms.drain, 3);
        assert_eq!(ev.phase_ms.detach, 61_000);
        assert_eq!(ev.max_inter_drain_gap_ms, 40);
    }

    /// The inter-drain gap is a capture-loop quantity: drains after
    /// loop end (the undrained detach window, then the terminal drain)
    /// must not extend it — the detach window is separately counted
    /// (split) and timed (detach phase), and mixing it into the gap
    /// misleads the E-system-tick acceptance (57 s of detach reads as
    /// a 57 s drain stall).
    #[test]
    fn inter_drain_gap_freezes_at_loop_end() {
        let mut acc = SchedulingAccumulator::default();
        let before = Instant::now();
        acc.note_drain_at(before);
        acc.note_drain_at(before + Duration::from_millis(40));
        acc.note_loop_end(0, 0);
        acc.note_drain_at(before + Duration::from_secs(60));

        let ev = acc.snapshot(65536);

        assert_eq!(ev.max_inter_drain_gap_ms, 40);
    }

    /// Terminal discovery work meters separately from tick discovery:
    /// the post-detach terminal drain can dominate the cumulative
    /// timer on system runs, hiding the per-frame tick slice the
    /// G-discovery-tick-slice confirmation needs. The cumulative
    /// Discovery timer keeps counting both (no semantic break).
    #[test]
    fn terminal_discovery_meters_separately_from_tick_discovery() {
        let mut acc = SchedulingAccumulator::default();
        acc.add_phase(SchedulingPhase::Discovery, Duration::from_millis(7));
        acc.add_phase(
            SchedulingPhase::DiscoveryTerminal,
            Duration::from_millis(50),
        );
        acc.add_phase(SchedulingPhase::Discovery, Duration::from_millis(50));

        let ev = acc.snapshot(65536);

        assert_eq!(ev.phase_ms.discovery, 57);
        assert_eq!(ev.phase_ms.discovery_terminal, 50);
    }

    /// The first forced full sweep defers past attach: attach just
    /// completed a full discovery, so forcing frame 1 re-sweeps cold
    /// seconds-old state and blocks the drain path ~2.5s (the system
    /// max-gap spike, every run at +1.8s). Steady-state frequency is
    /// unchanged (every Nth frame still sweeps).
    #[test]
    fn first_forced_sweep_defers_past_attach() {
        assert!(!force_full_frame(1));
        assert!(!force_full_frame(4));
        assert!(force_full_frame(5));
        assert!(!force_full_frame(6));
        assert!(force_full_frame(10));
    }

    /// A terminal drain that stops at its bound reports truncation into
    /// the published evidence.
    #[test]
    fn terminal_truncation_reaches_the_scheduling_snapshot() {
        let mut acc = SchedulingAccumulator::default();
        acc.note_terminal_drain(true);

        let ev = acc.snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64);

        assert!(ev.terminal_drain_truncated);
        assert_eq!(ev.terminal_drain_bound, 65_536);
        assert!(!acc.last_drain_had_backlog());
    }

    /// No sleeps while backlog exists; the pause slice still wins; an
    /// idle tick re-polls for readiness instead of idling out the frame.
    #[test]
    fn ready_sleep_skips_only_on_backlog() {
        let frame_due_in = Duration::from_secs(1);
        assert_eq!(
            ready_sleep_duration(true, true, frame_due_in),
            Duration::from_millis(1)
        );
        assert_eq!(
            ready_sleep_duration(false, true, frame_due_in),
            Duration::ZERO
        );
        assert_eq!(
            ready_sleep_duration(false, false, frame_due_in),
            READY_IDLE_POLL
        );
        assert_eq!(
            ready_sleep_duration(false, false, Duration::from_millis(1)),
            Duration::from_millis(1)
        );
        assert_eq!(
            ready_sleep_duration(true, false, frame_due_in),
            Duration::from_millis(1)
        );
    }

    /// F-T4-2, the gate alone on scripted times. A frame ran at 0. The pause
    /// helper's hook fires 1 ms later and its stop stays pending from then on.
    /// The loop ticks every `READY_IDLE_POLL`, as an idle capture does. At
    /// every drain interval (trace's 200 ms, profile's 1 s, the 60 s maximum),
    /// the first tick after the hook must admit the pause service, well inside
    /// the stop's 500 ms causal budget. The frame-only gate waited for the
    /// next frame instead: 999 ms after the hook at the profile default. With
    /// no stop pending the gate still admits frames only, once per drain
    /// interval, and never asks the pause on a frame tick.
    #[test]
    fn a_pending_pause_stop_is_due_on_the_next_tick_at_any_drain_interval() {
        let budget = Duration::from_nanos(crate::discovery::pause::CYCLE_NS);
        let hook = Duration::from_millis(1);
        let drains = [TRACE_CADENCE, PROFILE_CADENCE, Duration::from_secs(60)];
        // The first tick the gate admits, its pass, and whether it asked for
        // the pause state although it was a frame tick.
        let first_due = |drain: Duration, hook: Option<Duration>| {
            let mut since_frame = Duration::ZERO;
            loop {
                since_frame += READY_IDLE_POLL;
                let mut asked = false;
                let pass = discovery_due(since_frame, drain, || {
                    asked = true;
                    hook.is_some_and(|hook| since_frame >= hook)
                });
                if let Some(pass) = pass {
                    return (since_frame, pass, asked && pass == DiscoveryPass::Frame);
                }
            }
        };

        let pending: Vec<_> = drains
            .iter()
            .map(|&drain| (drain, first_due(drain, Some(hook))))
            .collect();
        for (drain, (due, _, _)) in &pending {
            let waited = *due - hook;
            assert!(
                waited <= budget,
                "drain {drain:?}: the first due tick came {waited:?} after the hook, \
                 past the {budget:?} causal budget"
            );
        }
        for (drain, (due, pass, _)) in &pending {
            assert_eq!(
                *pass,
                DiscoveryPass::PendingStop,
                "drain {drain:?}: a pending stop between frames must admit the pause \
                 service alone, not a frame"
            );
            assert!(
                *due - hook <= READY_IDLE_POLL,
                "drain {drain:?}: the stop waited {:?}, more than one idle tick",
                *due - hook
            );
        }

        for drain in drains {
            let (due, pass, asked_on_frame) = first_due(drain, None);
            assert_eq!(
                (due, pass),
                (drain, DiscoveryPass::Frame),
                "drain {drain:?}: without a pending stop only the frame is due"
            );
            assert!(
                !asked_on_frame,
                "drain {drain:?}: a frame tick must not pay for the pause check"
            );
        }
    }

    /// Both capture loops idle on ring readiness, not on a fixed sleep: a
    /// revert of either loop body to `thread::sleep` keeps every
    /// behavioral unit test green (the loops only run live), so pin the
    /// call sites statically, sliced like
    /// `terminal_capture_modes_wire_shared_finish_and_drain_helpers`.
    #[test]
    fn capture_loops_idle_on_readiness() {
        let source = include_str!("run.rs");
        let profile = source
            .split_once("fn capture_profile(")
            .unwrap()
            .1
            .split_once("fn write_json_report")
            .unwrap()
            .0;
        let trace = source
            .split_once("fn capture_trace(")
            .unwrap()
            .1
            .split_once("fn terminal_trace_count_line")
            .unwrap()
            .0;
        for (function, body) in [("capture_profile", profile), ("capture_trace", trace)] {
            assert_eq!(
                body.matches("wait_until_ready(").count(),
                1,
                "{function} must idle on exactly one ring-readiness wait"
            );
            assert!(
                !body.contains("thread::sleep"),
                "{function} idles on a fixed sleep instead of ring readiness"
            );
        }
    }

    /// F-T4-2's loop wiring, which the BPF-free tick tests cannot reach. Both
    /// capture loops ask the one gate with the owned pending-stop check and
    /// send a pending stop to the between-frames service. A frame is counted,
    /// and trace's frame clock advanced, only on a frame pass, so a
    /// pending-stop pass leaves the frame and discovery cadence unchanged.
    /// Sliced like `capture_loops_idle_on_readiness`.
    #[test]
    fn capture_loops_service_a_pending_stop_between_frames() {
        let source = include_str!("run.rs");
        let tick_of = |start: &str, end: &str| {
            source
                .split_once(start)
                .unwrap()
                .1
                .split_once(end)
                .unwrap()
                .0
                .split_once("let tick = {")
                .unwrap()
                .1
                .split_once("let mut finish_context =")
                .unwrap()
                .0
        };
        let profile = tick_of("fn capture_profile(", "fn write_json_report");
        let trace = tick_of("fn capture_trace(", "fn terminal_trace_count_line");
        for (function, tick) in [("capture_profile", profile), ("capture_trace", trace)] {
            assert_eq!(
                tick.matches("discovery_due(").count(),
                1,
                "{function} must gate discovery once per tick"
            );
            assert!(
                tick.contains(
                    "owned_stop_pending(context.0, context.1, context.2.as_deref(), interrupted)"
                ),
                "{function} must ask the gate for a pending pause stop"
            );
            assert!(
                tick.contains("DiscoveryPass::PendingStop => service_pending_stop("),
                "{function} must service a pending stop between frames"
            );
            let frame = tick
                .split_once("DiscoveryPass::Frame => {")
                .and_then(|(_, rest)| rest.split_once("DiscoveryPass::PendingStop =>"))
                .unwrap_or_else(|| panic!("{function} must match the frame pass first"))
                .0;
            assert!(
                frame.contains("*frame_tick += 1;") && frame.contains("drain_discovery_tick("),
                "{function}: only a frame pass counts a frame and runs the full pass"
            );
            assert_eq!(tick.matches("*frame_tick += 1;").count(), 1, "{function}");
        }
        let reset = trace
            .split_once("if pass == DiscoveryPass::Frame {")
            .and_then(|(_, rest)| rest.split_once('}'))
            .expect("trace must advance its frame clock inside a frame-pass guard")
            .0;
        assert!(
            reset.contains("*frame_clock = Instant::now();"),
            "only trace's frame pass advances its frame clock"
        );
        assert_eq!(trace.matches("*frame_clock = Instant::now();").count(), 1);
    }

    /// F-T8-1, one tick on scripted clock reads. The gate reads the frame clock
    /// at drain − 1 ms, and the tick's work (a 30 ms event drain) then crosses
    /// the frame boundary, so any later read sees drain + 29 ms. With separate
    /// reads the snapshot and render decisions came from those later reads.
    /// The frame rendered and reset the clock with no discovery pass:
    /// `(false, true, true)`. With one read per tick, this tick skips the whole
    /// frame and the next tick does all of it.
    #[test]
    fn a_profile_tick_does_the_whole_frame_or_none_of_it() {
        let drain = PROFILE_CADENCE;
        let decide = |reads: [Duration; 3]| {
            let mut reads = reads.into_iter();
            let frame =
                profile_frame_decisions(|| reads.next().expect("at most three reads"), drain);
            let discovery =
                discovery_due(frame.since_frame, drain, || false) == Some(DiscoveryPass::Frame);
            (discovery, frame.fresh_snapshot, frame.render)
        };
        let crossing = drain + Duration::from_millis(29);
        assert_eq!(
            decide([drain - Duration::from_millis(1), crossing, crossing]),
            (false, false, false),
            "a tick that starts before the frame boundary does none of the frame"
        );
        let next = drain + Duration::from_millis(30);
        assert_eq!(
            decide([next, next, next]),
            (true, true, true),
            "the next tick does all of it"
        );
    }

    /// One scripted profile tick, offset from the loop's first tick.
    #[derive(Clone, Copy)]
    struct ScriptedTick {
        start: Duration,
        /// Its passes and its event drain. The gate reads the frame clock
        /// before this work; any later frame decision reads after it.
        work: Duration,
        stop_pending: bool,
    }

    /// What one scripted tick decided: its discovery pass, whether it read the
    /// maps fresh, and whether it rendered.
    type TickFrame = (Option<DiscoveryPass>, bool, bool);

    /// Drives scripted ticks through the production frame decisions, as
    /// `capture_profile` does. Each tick gets `profile_frame_decisions` for its
    /// frame, then `discovery_due` on its read for the pass. A render resets the
    /// frame clock at the tick's end, where the render block runs. The clock
    /// starts a full interval before the first tick, as `capture_profile` sets
    /// it.
    fn run_profile_ticks(drain: Duration, ticks: &[ScriptedTick]) -> Vec<TickFrame> {
        // Absolute times are shifted by one interval, so the clock starts at 0.
        let mut last_frame = Duration::ZERO;
        ticks
            .iter()
            .map(|tick| {
                let start = drain + tick.start;
                let mut reads = 0;
                let frame = profile_frame_decisions(
                    || {
                        reads += 1;
                        let at = if reads == 1 { start } else { start + tick.work };
                        at.saturating_sub(last_frame)
                    },
                    drain,
                );
                let pass = discovery_due(frame.since_frame, drain, || tick.stop_pending);
                if frame.render {
                    last_frame = start + tick.work;
                }
                (pass, frame.fresh_snapshot, frame.render)
            })
            .collect()
    }

    fn frame_passes(decided: &[TickFrame]) -> usize {
        decided
            .iter()
            .filter(|(pass, _, _)| *pass == Some(DiscoveryPass::Frame))
            .count()
    }

    fn assert_whole_profile_frames(decided: &[TickFrame]) {
        for (index, &(pass, fresh_snapshot, render)) in decided.iter().enumerate() {
            let frame = pass == Some(DiscoveryPass::Frame);
            assert!(
                frame == fresh_snapshot && frame == render,
                "tick {index}: pass {pass:?}, fresh snapshot {fresh_snapshot}, render {render}"
            );
        }
    }

    /// F-T8-1: busy 30 ms ticks back to back for 20 s at the 1 s profile
    /// default. Every frame must keep its discovery pass, at least 19. The
    /// separate reads gave one, the very first. Each later tick that crossed
    /// a boundary rendered and reset the clock without a pass, so the next
    /// rendering tick's gate always fell 10 ms short.
    #[test]
    fn busy_profile_ticks_keep_one_discovery_pass_per_frame() {
        let drain = PROFILE_CADENCE;
        let ms = Duration::from_millis;
        let busy: Vec<_> = (0u32..)
            .map(|k| ScriptedTick {
                start: ms(30) * k,
                work: ms(30),
                stop_pending: false,
            })
            .take_while(|tick| tick.start < Duration::from_secs(20))
            .collect();
        let decided = run_profile_ticks(drain, &busy);
        assert!(
            frame_passes(&decided) >= 19,
            "20 s of busy 30 ms ticks gave {} discovery passes",
            frame_passes(&decided)
        );
        assert_whole_profile_frames(&decided);
    }

    /// F-T8-1: a 200 ms pending-stop service straddles the frame boundary
    /// between idle 2 ms ticks. It must not cost the next tick its frame pass.
    #[test]
    fn a_profile_pending_stop_cannot_skip_the_next_frames_discovery() {
        let drain = PROFILE_CADENCE;
        let ms = Duration::from_millis;
        let idle = |start| ScriptedTick {
            start,
            work: Duration::ZERO,
            stop_pending: false,
        };
        let mut straddle: Vec<_> = (0u32..500).map(|k| idle(ms(2) * k)).collect();
        let service = straddle.len();
        straddle.push(ScriptedTick {
            start: ms(999),
            work: ms(200),
            stop_pending: true,
        });
        // The 1 ms pause slice follows the service, then 2 ms idle polls.
        straddle.extend((0u32..900).map(|k| idle(ms(1200) + ms(2) * k)));
        let decided = run_profile_ticks(drain, &straddle);
        assert_eq!(
            decided[service],
            (Some(DiscoveryPass::PendingStop), false, false),
            "the straddling service does none of the frame"
        );
        assert_eq!(
            decided[service + 1],
            (Some(DiscoveryPass::Frame), true, true),
            "the tick after the service runs the frame's discovery pass"
        );
        assert_whole_profile_frames(&decided);
        assert_eq!(frame_passes(&decided), 3, "frames at 0, 1.2 s and 2.2 s");
    }

    /// F-T8-1's loop wiring, which the scripted frame tests cannot reach. The
    /// profile loop reads its frame clock once per tick, through
    /// `profile_frame_decisions`, and its gate, snapshot and render all follow
    /// that one read. Its only other read sizes the idle wait. Sliced like
    /// `capture_loops_idle_on_readiness`.
    #[test]
    fn the_profile_loop_decides_each_frame_from_one_clock_read() {
        let source = include_str!("run.rs");
        let profile = source
            .split_once("fn capture_profile(")
            .unwrap()
            .1
            .split_once("fn write_json_report")
            .unwrap()
            .0;
        for (marker, decision) in [
            (
                "let tick_frame = profile_frame_decisions(|| last_frame.elapsed(), drain);",
                "the tick's one frame-clock read",
            ),
            (
                "discovery_due(tick_frame.since_frame, drain,",
                "the gate on that read",
            ),
            (
                "if !tick_frame.fresh_snapshot {",
                "the snapshot on that read",
            ),
            (
                "if tick_frame.render {",
                "the render and reset on that read",
            ),
            (
                "drain.saturating_sub(last_frame.elapsed())",
                "the idle wait",
            ),
        ] {
            assert_eq!(
                profile.matches(marker).count(),
                1,
                "capture_profile: {decision}"
            );
        }
        assert_eq!(
            profile.matches("last_frame.elapsed()").count(),
            2,
            "capture_profile reads its frame clock only for the tick's frame and the idle wait"
        );
    }

    /// Requested-wait margin at the default ring: one full idle timeout
    /// admits 2 ms x 128k/s = 256 records, far under the default ring.
    /// This bounds the REQUESTED wait only — it is not a scheduling
    /// proof (audit F1: the OS may deschedule past the timeout, and no
    /// arithmetic here observes that). The scheduling claim rests on the
    /// requalification campaign, not this bound.
    #[test]
    fn ready_idle_timeout_margin_at_default_ring() {
        const FASTEST_BURST_PER_S: u128 = 128_000;
        const RECORD_BYTES: u128 =
            (core::mem::size_of::<p11scope_ebpf_common::Event>() + 8) as u128;
        let capacity = u128::from(p11scope_ebpf_common::RING_BYTES) / RECORD_BYTES;
        let worst_case = READY_IDLE_POLL.as_millis() * FASTEST_BURST_PER_S / 1000;
        assert!(
            worst_case * 2 < capacity,
            "idle timeout admits {worst_case} records at {FASTEST_BURST_PER_S}/s, \
             without 2x margin under the {capacity}-record default ring"
        );
    }

    /// A pipe pair for readiness-wait tests: readable end borrowed, write
    /// end owned, both closed on drop.
    fn readiness_pipe() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        // SAFETY: fds points to two writable integers; pipe initializes both.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe returned two distinct owned descriptors.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn write_byte(writer: &OwnedFd) {
        // SAFETY: one initialized byte; the write end is open.
        assert_eq!(
            unsafe { libc::write(writer.as_raw_fd(), [7u8].as_ptr().cast(), 1) },
            1
        );
    }

    /// The readiness wait wakes on data, not on the timeout: a readable
    /// fd with a huge timeout returns immediately. A sleep-the-timeout
    /// implementation fails this (it would wait out the full timeout),
    /// which is exactly the audit F1 mutant this pins against.
    #[test]
    fn ready_wait_returns_early_on_readable_fd() {
        use std::os::fd::AsFd as _;
        let (reader, writer) = readiness_pipe();
        write_byte(&writer);
        let start = Instant::now();
        wait_until_ready(reader.as_fd(), Duration::from_secs(30));
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "readiness wait sat out the timeout on a readable fd"
        );
    }

    /// Data arriving mid-wait wakes the wait: a writer after ~100 ms with
    /// a 30 s timeout returns in well under the timeout.
    #[test]
    fn ready_wait_wakes_on_mid_wait_data() {
        use std::os::fd::AsFd as _;
        let (reader, writer) = readiness_pipe();
        let delayed = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            write_byte(&writer);
        });
        let start = Instant::now();
        wait_until_ready(reader.as_fd(), Duration::from_secs(30));
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "readiness wait missed data that arrived mid-wait"
        );
        delayed.join().unwrap();
    }

    /// An empty fd waits out (approximately) the timeout and returns, so
    /// the idle cadence is preserved when nothing arrives — and the wait
    /// never spins: it blocks for most of the timeout.
    #[test]
    fn ready_wait_empty_fd_times_out() {
        use std::os::fd::AsFd as _;
        let (reader, _writer) = readiness_pipe();
        let start = Instant::now();
        wait_until_ready(reader.as_fd(), Duration::from_millis(200));
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(100),
            "readiness wait returned without blocking on an empty fd: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "readiness wait overran its timeout: {elapsed:?}"
        );
    }

    /// The poll timeout rounds up: exact milliseconds pass through, a
    /// nonzero sub-millisecond timeout waits 1 ms rather than
    /// truncating to `poll(0)`, and only zero maps to zero (which
    /// `wait_until_ready` short-circuits before polling anyway).
    #[test]
    fn poll_timeout_rounds_sub_millisecond_up() {
        assert_eq!(poll_timeout_ms(Duration::ZERO), 0);
        assert_eq!(poll_timeout_ms(Duration::from_nanos(1)), 1);
        assert_eq!(poll_timeout_ms(Duration::from_micros(500)), 1);
        assert_eq!(poll_timeout_ms(Duration::from_millis(1)), 1);
        assert_eq!(poll_timeout_ms(Duration::from_millis(200)), 200);
        assert_eq!(poll_timeout_ms(Duration::from_secs(30)), 30_000);
        assert_eq!(poll_timeout_ms(Duration::MAX), i32::MAX);
    }

    /// Zero timeout never blocks, even on an empty fd: the backlog path
    /// keeps its no-sleep contract exactly.
    #[test]
    fn ready_wait_zero_timeout_never_blocks() {
        use std::os::fd::AsFd as _;
        let (reader, _writer) = readiness_pipe();
        let start = Instant::now();
        wait_until_ready(reader.as_fd(), Duration::ZERO);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "zero readiness wait blocked"
        );
    }

    /// The cancel marker is the harness's control-latency signal: exact
    /// text, signal number, and tick count, printed before detach work.
    #[test]
    fn cancel_marker_names_the_signal_and_tick_count() {
        assert_eq!(
            cancel_marker(Some(2), 42),
            "p11scope: cancel: loop exited on signal 2 after 42 ticks"
        );
    }

    #[test]
    fn target_exit_marker_names_the_tick_count() {
        assert_eq!(
            target_exit_marker(12),
            "p11scope: capture ended: target exited after 12 ticks"
        );
    }

    /// The sink watches the same observation the loop polls: the first
    /// observed stop signal raises the shared cancel flag (F4 wiring).
    #[test]
    fn observed_stop_signal_raises_the_shared_cancel_flag() {
        let interrupted = SignalState::new();
        let cancel = interrupted.cancel_flag();
        assert!(!cancel.load(Ordering::SeqCst));
        interrupted.observe(libc::SIGINT);
        assert!(cancel.load(Ordering::SeqCst));
        assert!(interrupted.interrupted());
    }

    /// End to end through the profile single-quantum step: two quanta of
    /// scripted backlog drain in one readiness tick with re-polls counted.
    #[test]
    fn live_profile_ready_loop_drains_two_quanta_of_backlog() {
        use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
        let plan = crate::plan::AttachPlan::from_slots(vec![]);
        let mut state = semantics::State::new(&plan);
        let mut tracker = process::Tracker::new();
        let events = (0..2 * LIVE_POLL_QUANTUM).map(|_| call_event());
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events(events, usize::MAX), 1);
        let budget = ReadyBudget::for_test(usize::MAX, Duration::from_secs(60));

        let outcome = poll_ready(false, &budget, LIVE_POLL_QUANTUM, &mut || false, || {
            drain_profile_events(
                &mut drain,
                &mut state,
                &mut tracker,
                &Scope::Pid(std::process::id()),
                Some(LIVE_POLL_QUANTUM),
            )
        })
        .unwrap();

        assert_eq!(drain.source().remaining(), 0);
        assert_eq!(outcome.repolls, 2);
        assert!(!outcome.may_remain);
        assert!(!outcome.budget_exhausted);
    }

    /// The line limit still ends live draining: reaching it reports no
    /// live backlog, so the readiness loop does not re-poll past it.
    #[test]
    fn live_trace_ready_loop_stops_at_the_line_limit() {
        use crate::events::{EventDrain, LIVE_POLL_QUANTUM, ScriptedRecords};
        let (mut state, mut tracker, mut tracer) = trace_fixture();
        let mut remaining = Some(2);
        let mut stdout = Vec::new();
        let mut stdout_open = true;
        let mut out_file: Option<Vec<u8>> = None;
        let events = (0..LIVE_POLL_QUANTUM + 3).map(|_| call_event());
        let mut drain =
            EventDrain::over_test_domain(ScriptedRecords::events(events, usize::MAX), 1);
        let budget = ReadyBudget::for_test(usize::MAX, Duration::from_secs(60));

        let outcome = poll_ready(false, &budget, LIVE_POLL_QUANTUM, &mut || false, || {
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
        })
        .unwrap();

        assert_eq!(remaining, Some(0));
        assert_eq!(outcome.repolls, 0);
        assert!(!outcome.may_remain);
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

    fn pipe_pair() -> (File, File) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: `pipe` succeeded, so both ends are open and owned here.
        unsafe {
            (
                std::os::fd::FromRawFd::from_raw_fd(fds[0]),
                std::os::fd::FromRawFd::from_raw_fd(fds[1]),
            )
        }
    }

    /// A slow sink with a bounded appetite: 1KB reads at ~20KB/s up to
    /// 4KB total, then parked until `done`, then a fast drain to EOF.
    /// The cap bounds what any test-thread stall can drain (the pipe
    /// stays lossy); the `parked` flag bounds what any reader-thread
    /// stall can drain during the terminal phase. Returns every byte the
    /// pipe delivered, so file/stdout subtraction is valid.
    fn spawn_slow_sink_reader(
        mut reader: File,
        parked: Arc<AtomicBool>,
        done: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<u64> {
        use std::io::Read as _;
        std::thread::spawn(move || {
            let mut delivered = 0u64;
            let mut taken = 0u64;
            let mut chunk = vec![0u8; 1024];
            loop {
                if done.load(Ordering::SeqCst) {
                    loop {
                        match reader.read(&mut chunk) {
                            Ok(0) => return delivered,
                            Ok(n) => delivered += n as u64,
                            Err(error) => panic!("slow-sink reader failed: {error}"),
                        }
                    }
                }
                if parked.load(Ordering::SeqCst) || taken >= 4096 {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                match reader.read(&mut chunk) {
                    Ok(0) => return delivered,
                    Ok(n) => {
                        delivered += n as u64;
                        taken += n as u64;
                    }
                    Err(error) => panic!("slow-sink reader failed: {error}"),
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        })
    }

    fn emit_pre_terminal_lines(
        stdout: &mut dyn Write,
        stdout_open: &mut bool,
        out_file: &mut Option<Vec<u8>>,
        lines: usize,
        line_len: usize,
    ) {
        for _ in 0..lines {
            emit_trace_line(&"A".repeat(line_len), stdout, stdout_open, out_file).unwrap();
        }
    }

    fn terminal_evidence_for(scheduling: render::SchedulingEvidence) -> render::Evidence {
        let (engine, _) = crate::discovery::engine::tests::selection_output_engines();
        let state = semantics::State::new(engine.plan());
        let mut evidence = evidence_for(
            &engine,
            engine.capture_facts(),
            0,
            false,
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
            scheduling,
            None,
            None,
        );
        evidence.mark_terminal_drain_unproven();
        evidence
    }

    fn parse_terminal_records(file: &[u8]) -> serde_json::Value {
        let text = String::from_utf8(file.to_vec()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let count_pos = lines
            .iter()
            .position(|line| line.starts_with("COUNT_EVIDENCE "));
        let evidence_pos = lines.iter().position(|line| line.starts_with("EVIDENCE "));
        let (Some(count_pos), Some(evidence_pos)) = (count_pos, evidence_pos) else {
            panic!("terminal records missing from {} lines", lines.len());
        };
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("EVIDENCE "))
                .count(),
            1,
            "expected exactly one EVIDENCE record"
        );
        assert_eq!(
            count_pos + 1,
            evidence_pos,
            "COUNT must immediately precede EVIDENCE"
        );
        serde_json::from_str(lines[evidence_pos].strip_prefix("EVIDENCE ").unwrap()).unwrap()
    }

    /// F3: the file's EVIDENCE record accounts every terminal drop,
    /// byte-exact against trace-file/stdout comparison. Production order
    /// (pre-terminal flush, snapshot, accounted emission) over a slow
    /// sink that drops in every phase: the reported total equals the
    /// actual missing bytes.
    #[test]
    fn terminal_trace_evidence_accounts_every_terminal_drop_byte_exact() {
        let (reader, writer) = pipe_pair();
        let mut sink =
            crate::sink::SinkWriter::new(crate::sink::StdoutInner::File(writer)).unwrap();
        let mut stdout_open = true;
        let mut file = Some(Vec::new());
        let mut scheduling = SchedulingAccumulator::default();
        sink.begin_tick(crate::sink::SINK_TICK_BUDGET);
        // 100KB past a 64KB pipe with no reader yet: the mid-write
        // auto-flush delivers a pipeful and drops the rest.
        emit_pre_terminal_lines(&mut sink, &mut stdout_open, &mut file, 100, 1000);
        let parked = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let reader = spawn_slow_sink_reader(reader, Arc::clone(&parked), Arc::clone(&done));
        // Production order: flush every pre-terminal byte, collect, and
        // only then snapshot.
        flush_stdout(&mut sink, &mut stdout_open).unwrap();
        collect_sink_drops(&mut sink, &mut scheduling, &mut None, Instant::now());
        parked.store(true, Ordering::SeqCst);
        let mut evidence =
            terminal_evidence_for(scheduling.snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64));
        let (_, _, tracer) = trace_fixture();
        emit_trace_terminal_accounted(
            &mut evidence,
            CapturePolicy::AggregateOnly,
            false,
            DEFAULT_TRACE_MAX_EVENTS,
            false,
            &[],
            &tracer,
            &mut scheduling,
            &mut sink,
            &mut stdout_open,
            &mut file,
        )
        .unwrap();
        done.store(true, Ordering::SeqCst);
        drop(sink);
        let stdout_bytes = reader.join().unwrap();
        let file = file.unwrap();

        let record = parse_terminal_records(&file);
        let reported = record["scheduling"]["sink_dropped_bytes"].as_u64().unwrap();
        let timeouts = record["scheduling"]["sink_timeouts"].as_u64().unwrap();
        let missing = file.len() as u64 - stdout_bytes;
        assert_eq!(
            reported, missing,
            "EVIDENCE sink_dropped_bytes ({reported}) != actual missing bytes ({missing})"
        );
        assert!(reported > 0, "fixture dropped nothing: test is vacuous");
        assert_eq!(timeouts, 3, "expected a drop in every phase");
        assert_eq!(
            record["scheduling"]["sink_policy"].as_str().unwrap(),
            render::SINK_POLICY_BOUNDED_WAIT_DROP,
        );
    }

    /// Sensitivity guard for the byte-exact test above: the OLD order
    /// (snapshot, emit, then flush) strands the final flush's drops
    /// outside the emitted EVIDENCE — the F3 defect shape. Production
    /// must not do this; uses only pre-existing fns.
    #[test]
    fn terminal_trace_old_order_strands_terminal_drops_outside_evidence() {
        let (reader, writer) = pipe_pair();
        let mut sink =
            crate::sink::SinkWriter::new(crate::sink::StdoutInner::File(writer)).unwrap();
        let mut stdout_open = true;
        let mut file = Some(Vec::new());
        let mut scheduling = SchedulingAccumulator::default();
        sink.begin_tick(crate::sink::SINK_TICK_BUDGET);
        emit_pre_terminal_lines(&mut sink, &mut stdout_open, &mut file, 100, 1000);
        // Old order: snapshot first (the accumulator is still empty —
        // the auto-flush drops sit in the sink, uncollected), emit, and
        // only then flush.
        let evidence =
            terminal_evidence_for(scheduling.snapshot(crate::events::TERMINAL_DRAIN_BOUND as u64));
        let (_, _, tracer) = trace_fixture();
        emit_trace_terminal(
            &[],
            &tracer,
            &trace::evidence_line(&evidence, CapturePolicy::AggregateOnly, false),
            &mut sink,
            &mut stdout_open,
            &mut file,
        )
        .unwrap();
        let parked = Arc::new(AtomicBool::new(false));
        let done = Arc::new(AtomicBool::new(false));
        let reader = spawn_slow_sink_reader(reader, parked, Arc::clone(&done));
        flush_stdout(&mut sink, &mut stdout_open).unwrap();
        collect_sink_drops(&mut sink, &mut scheduling, &mut None, Instant::now());
        done.store(true, Ordering::SeqCst);
        drop(sink);
        let stdout_bytes = reader.join().unwrap();
        let file = file.unwrap();

        let record = parse_terminal_records(&file);
        let reported = record["scheduling"]["sink_dropped_bytes"].as_u64().unwrap();
        let missing = file.len() as u64 - stdout_bytes;
        assert_eq!(reported, 0, "old order must snapshot before any collect");
        assert!(
            missing - reported > 20_000,
            "fixture strands nothing: sensitivity guard is vacuous"
        );
    }

    /// The terminal-total fixpoint: the file record's own length feeds
    /// back into the total it reports, settling across digit boundaries.
    #[test]
    fn resolve_terminal_sink_total_crosses_digit_boundaries() {
        // Record length = 90 fixed bytes + decimal digits of the total.
        fn fake_len(total: u64) -> usize {
            90 + total.to_string().len()
        }
        // No width change: the counted total stands.
        assert_eq!(resolve_terminal_sink_total(5, fake_len(5), fake_len), 5);
        assert_eq!(
            resolve_terminal_sink_total(100_005, fake_len(100_000), fake_len),
            100_005
        );
        // Terminal drops cross 99999 -> 100000: the file record grows one
        // byte, which is itself a missing byte.
        assert_eq!(
            resolve_terminal_sink_total(100_000, fake_len(99_999), fake_len),
            100_001
        );
        // Two widths up from the stdout copy: settles after two rounds.
        assert_eq!(
            resolve_terminal_sink_total(99_999, fake_len(9_999), fake_len),
            100_001
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
    /// the producers are live, the explicit terminal bound once
    /// `detach_producers` detached them all — so duration, signal and the
    /// line limit are checked between quanta and the terminal drain reads
    /// the detached ring within its explicit bound.
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

    /// Stall notes fire on drops, then stay quiet for five seconds so a
    /// sustained stall does not flood stderr.
    #[test]
    fn sink_notes_fire_once_per_quiet_window() {
        let drops = crate::sink::SinkDrops {
            timeouts: 1,
            dropped_bytes: 10,
            stall_ms: 250,
        };
        let idle = crate::sink::SinkDrops::default();
        let noted = Instant::now();
        assert!(sink_note_due(&drops, None, noted));
        assert!(!sink_note_due(&idle, None, noted));
        assert!(!sink_note_due(
            &drops,
            Some(noted),
            noted + Duration::from_secs(1)
        ));
        assert!(sink_note_due(
            &drops,
            Some(noted),
            noted + Duration::from_secs(5)
        ));
    }

    /// Buffering is transparent: bytes through a buffered sink flush out
    /// verbatim, so batching trace writes cannot garble the stream.
    #[test]
    fn buffered_sink_preserves_bytes_verbatim() {
        let mut direct = Vec::new();
        let mut buffered = buffered_sink(Vec::new());
        for line in ["CAPTURE privacy=allowlisted\n", "LOST 3 events\n"] {
            direct.write_all(line.as_bytes()).unwrap();
            buffered.write_all(line.as_bytes()).unwrap();
        }
        buffered.flush().unwrap();
        assert_eq!(buffered.into_inner().unwrap(), direct);
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

    /// Reads one signal's current disposition without changing it.
    fn signal_disposition(signal: libc::c_int) -> libc::sighandler_t {
        // SAFETY: zeroed sigaction is the documented output buffer, and a
        // null new action reads the current disposition without installing.
        let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
        let read = unsafe { libc::sigaction(signal, std::ptr::null(), &mut current) };
        assert_eq!(read, 0, "reading the disposition of signal {signal}");
        current.sa_sigaction
    }

    /// Sets one signal's disposition to `SIG_DFL` or `SIG_IGN` only.
    fn set_disposition(signal: libc::c_int, disposition: libc::sighandler_t) {
        // SAFETY: zeroed sigaction with an empty mask and no flags, naming
        // only the default or ignore disposition for a valid signal.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = disposition;
        let installed = unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) };
        assert_eq!(installed, 0, "setting signal {signal} to {disposition}");
    }

    /// Restores a saved disposition when the scope ends, even on failure,
    /// so one signal test cannot poison the next. Best effort: a restore
    /// failure must not panic from `Drop`.
    struct RestoreDisposition {
        signal: libc::c_int,
        previous: libc::sighandler_t,
    }

    impl Drop for RestoreDisposition {
        fn drop(&mut self) {
            // SAFETY: as in `set_disposition`; the saved value came from a
            // live `sigaction` read of the same signal.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = self.previous;
            unsafe {
                libc::sigaction(self.signal, &action, std::ptr::null_mut());
            }
        }
    }

    /// One full `/proc/<pid>/status` signal mask (`SigCgt`, `SigIgn`).
    fn signal_mask(pid: &str, field: &str) -> u64 {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let mask = status
            .lines()
            .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))
            .unwrap_or_else(|| panic!("/proc/{pid}/status has no {field}"));
        u64::from_str_radix(mask.trim(), 16).unwrap()
    }

    /// Whether this process currently ignores SIGHUP, via `/proc`.
    fn sighup_ignored_in_own_status() -> bool {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let mask = status
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .expect("/proc/self/status has no SigIgn");
        u64::from_str_radix(mask.trim(), 16).unwrap() & (1 << (libc::SIGHUP - 1)) != 0
    }

    /// F-T4-4: a real SIGHUP (raised in-process after the handler is
    /// installed) stops a capture through exactly the SIGTERM path: the
    /// same recorded identity, the same forwarded signal, the same exit
    /// status — and a child the pause holds stopped is resumed first, so
    /// it dies by the forwarded SIGTERM (143) instead of stranding in T
    /// or burning grace into SIGKILL (137).
    #[test]
    fn sighup_stops_the_capture_like_sigterm_and_resumes_a_held_child() {
        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        // Never depend on the runner's inherited dispositions: the suite
        // itself may run under a SIGHUP-ignoring parent. Only an ignore is
        // reset — signal_hook installs its OS handler once per process, so
        // a raw reset to default after another test installed would
        // silently disarm the hangup while the registry still claims it.
        if signal_disposition(libc::SIGHUP) == libc::SIG_IGN {
            set_disposition(libc::SIGHUP, libc::SIG_DFL);
        }
        let stop = install_stop_flag().unwrap();
        let caught = signal_disposition(libc::SIGHUP);
        assert!(
            caught != libc::SIG_DFL && caught != libc::SIG_IGN,
            "SIGHUP must be caught before a real hangup is raised at this process"
        );
        assert!(!should_stop(&stop, Duration::ZERO, None));
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let sleeper = sleeper.to_str().unwrap();
        let mut child = spawn(sleeper, &[]);
        child.release().unwrap();
        // SAFETY: signals the exact owned child only, never this process
        // group; the hangup below goes to this thread via raise().
        unsafe { libc::kill(child.pid() as libc::pid_t, libc::SIGSTOP) };
        wait_until(
            || child_is_stopped(child.pid()),
            "the fixture child never entered the stopped state",
        );
        // SAFETY: raise() with a handled signal; the handler only sets atomics.
        assert_eq!(unsafe { libc::raise(libc::SIGHUP) }, 0);
        assert!(should_stop(&stop, Duration::ZERO, None));
        assert_eq!(stop.first_signal(), Some(libc::SIGTERM));
        assert_eq!(stop.sigint_deliveries(), 0);
        assert!(stop.cancel_flag().load(Ordering::SeqCst));
        assert_eq!(
            settle_after_signal_with_grace(&mut child, &stop, Duration::from_millis(300)).unwrap(),
            ChildOutcome::Exited(128 + libc::SIGTERM)
        );
        assert!(child.is_reaped());
    }

    /// F-T4-4: the hangup-install decision installs over the default
    /// disposition and preserves an inherited ignore. Pure, so no real
    /// hangup is needed.
    #[test]
    fn hangup_handler_installs_over_the_default_disposition_only() {
        assert!(should_install_hangup_handler(libc::SIG_DFL));
        assert!(!should_install_hangup_handler(libc::SIG_IGN));
    }

    /// F-T4-4: an inherited SIGHUP ignore (`nohup`) survives the stop-flag
    /// install: the hangup handler is installed only over the default
    /// disposition, so the capture keeps running after logout. No real
    /// hangup is sent; the disposition is read back directly.
    #[test]
    fn inherited_sighup_ignore_survives_stop_flag_install() {
        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        let _restore = RestoreDisposition {
            signal: libc::SIGHUP,
            previous: signal_disposition(libc::SIGHUP),
        };
        set_disposition(libc::SIGHUP, libc::SIG_IGN);
        let _stop = install_stop_flag().unwrap();
        assert_eq!(
            signal_disposition(libc::SIGHUP),
            libc::SIG_IGN,
            "installing the stop flag must not replace an inherited SIGHUP ignore"
        );
        assert!(
            sighup_ignored_in_own_status(),
            "SigIgn lost the SIGHUP bit across the stop-flag install"
        );
    }

    /// F-T4-5: the owned command starts with SIGPIPE at its default. The
    /// Rust runtime ignores SIGPIPE and an ignored disposition survives
    /// `execve`, so without the reset the observed program sees EPIPE
    /// errors instead of dying by SIGPIPE (and a shell cannot un-ignore
    /// it) — unlike the same command under `std::process::Command`.
    #[test]
    fn owned_command_starts_with_default_sigpipe() {
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let sleeper = sleeper.to_str().unwrap();
        let mut child = spawn(sleeper, &[]);
        child.release().unwrap();
        assert_eq!(
            signal_mask(&child.pid().to_string(), "SigIgn") & (1 << (libc::SIGPIPE - 1)),
            0,
            "the owned command inherited the observer's ignored SIGPIPE"
        );
        child.terminate_and_reap().unwrap();
    }

    /// Clears the captured startup dispositions when the scope ends, even
    /// on failure, so one fidelity test cannot poison the next.
    struct ClearStartupDispositions;

    impl Drop for ClearStartupDispositions {
        fn drop(&mut self) {
            clear_startup_signal_dispositions_for_test();
        }
    }

    /// Fidelity rule: the owned command inherits exactly the dispositions
    /// p11scope itself inherited for every signal p11scope changes. Under
    /// an observer started with SIGHUP and SIGINT ignored, both stay
    /// ignored in the child; started normally, none are. SIGPIPE is the
    /// exception: it always resets to the default, matching
    /// `std::process::Command`. The stop-flag install itself is not run
    /// here: the child reads only the captured startup state.
    #[test]
    fn owned_command_inherits_ignored_stop_dispositions() {
        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        let _restore_int = RestoreDisposition {
            signal: libc::SIGINT,
            previous: signal_disposition(libc::SIGINT),
        };
        let _restore_hup = RestoreDisposition {
            signal: libc::SIGHUP,
            previous: signal_disposition(libc::SIGHUP),
        };
        let _clear_store = ClearStartupDispositions;
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let sleeper = sleeper.to_str().unwrap();

        // An observer started with SIGHUP and SIGINT ignored.
        set_disposition(libc::SIGINT, libc::SIG_IGN);
        set_disposition(libc::SIGHUP, libc::SIG_IGN);
        capture_startup_signal_dispositions();
        let mut ignored = spawn(sleeper, &[]);
        ignored.release().unwrap();
        let ignored_mask = signal_mask(&ignored.pid().to_string(), "SigIgn");
        assert_eq!(
            ignored_mask & (1 << (libc::SIGINT - 1)),
            1 << (libc::SIGINT - 1),
            "the owned command lost the observer's inherited SIGINT ignore"
        );
        assert_eq!(
            ignored_mask & (1 << (libc::SIGHUP - 1)),
            1 << (libc::SIGHUP - 1),
            "the owned command lost the observer's inherited SIGHUP ignore"
        );
        assert_eq!(
            ignored_mask & (1 << (libc::SIGTERM - 1)),
            0,
            "the owned command ignores SIGTERM it did not inherit ignored"
        );
        assert_eq!(
            ignored_mask & (1 << (libc::SIGPIPE - 1)),
            0,
            "SIGPIPE must reset to default even under an ignoring observer"
        );
        ignored.terminate_and_reap().unwrap();

        // The same child started normally: nothing ignored.
        set_disposition(libc::SIGINT, libc::SIG_DFL);
        set_disposition(libc::SIGHUP, libc::SIG_DFL);
        capture_startup_signal_dispositions();
        let mut normal = spawn(sleeper, &[]);
        normal.release().unwrap();
        let normal_mask = signal_mask(&normal.pid().to_string(), "SigIgn");
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGPIPE] {
            assert_eq!(
                normal_mask & (1 << (signal - 1)),
                0,
                "the normally started command ignores signal {signal}"
            );
        }
        normal.terminate_and_reap().unwrap();
    }

    /// Raw `sigaction` write for the forked fidelity observer, which must
    /// not panic: sets one signal to `SIG_DFL` or `SIG_IGN`, reporting
    /// success.
    fn try_set_disposition(signal: libc::c_int, disposition: libc::sighandler_t) -> bool {
        // SAFETY: zeroed sigaction with an empty mask and no flags, naming
        // only the default or ignore disposition for a valid signal.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = disposition;
        unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) == 0 }
    }

    /// Raw `sigaction` read for the forked fidelity observer: one signal's
    /// current disposition, or `None` when unreadable.
    fn try_signal_disposition(signal: libc::c_int) -> Option<libc::sighandler_t> {
        // SAFETY: zeroed sigaction is the documented output buffer, and a
        // null new action reads the current disposition without installing.
        let mut current: libc::sigaction = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigaction(signal, std::ptr::null(), &mut current) } != 0 {
            return None;
        }
        Some(current.sa_sigaction)
    }

    /// One `/proc/<pid>/status` signal mask for the forked fidelity
    /// observer, or `None` when the process is gone or the field is
    /// unreadable.
    fn try_signal_mask(pid: u32, field: &str) -> Option<u64> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        let mask = status
            .lines()
            .find_map(|line| line.strip_prefix(field)?.strip_prefix(':'))?;
        u64::from_str_radix(mask.trim(), 16).ok()
    }

    /// Best-effort pipe write for the forked fidelity observer: raw `write`
    /// on the borrowed descriptor, so no `File` borrow crosses the exit
    /// closures. Short writes and errors are ignored — the exit code alone
    /// fails the test; the report only carries diagnostics.
    fn observer_write(fd: libc::c_int, bytes: &[u8]) {
        let mut written = 0;
        while written < bytes.len() {
            // SAFETY: fd is the live pipe writer; the slice pointer and
            // length name the unwritten tail.
            let done =
                unsafe { libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written) };
            if done <= 0 {
                break;
            }
            written += done as usize;
        }
    }

    /// Session-leader wait for the forked fidelity observer: true once the
    /// pre-exec child has run `setsid` (after restoring its dispositions),
    /// false on a 2 s deadline.
    fn try_wait_for_session_leader(pid: u32) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        // SAFETY: getsid with a pid only.
        while unsafe { libc::getsid(pid as libc::pid_t) } != pid as libc::pid_t {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    /// The isolated observer's stand-in caught handler. `signal_hook`
    /// installs its trampoline once per signal per process: when the test
    /// binary already owns a signal, the fork child's `install_stop_flag`
    /// only appends a registry action and the OS disposition stays as the
    /// child set it. The child then pins this empty handler instead, so the
    /// observer's spawn-time dispositions are deterministic (caught) in
    /// every suite order. Nothing is ever delivered to it.
    extern "C" fn isolated_observer_caught_shim(_signal: libc::c_int) {}

    /// Pins the caught shim above on one signal for the forked fidelity
    /// observer, reporting success.
    fn pin_caught_shim(signal: libc::c_int) -> bool {
        // SAFETY: zeroed sigaction with an empty mask and no flags, naming
        // the empty shim for a valid signal.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = isolated_observer_caught_shim as libc::sighandler_t;
        unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) == 0 }
    }

    /// One isolated fidelity observer (G7): `phase` 1 plays an observer
    /// started with every stop signal ignored, `phase` 2 one started
    /// normally. Panic-free by construction like
    /// `sigkill_probe_intermediate`: this runs in a fork child that shares
    /// the test binary's address space, so every failure writes one
    /// diagnostic line and exits with a distinct code instead of unwinding
    /// into the harness. Exit 0 with the `OK` line on success; 11-19 fail
    /// phase 1, 21-29 phase 2.
    fn isolated_fidelity_observer(writer: File, sleeper: &Path, phase: u8) -> ! {
        use std::os::fd::AsRawFd as _;

        let fd = writer.as_raw_fd();
        let exit = |code: i32| -> ! {
            // SAFETY: _exit runs no destructors and flushes nothing.
            unsafe { libc::_exit(code) };
        };
        let fail = |code: i32, message: String| -> ! {
            observer_write(fd, message.as_bytes());
            exit(code);
        };
        // Each phase runs in its own fork child, which installs exactly
        // once: a caught disposition at entry means the test binary's
        // registry already owns that signal (only `signal_hook` installs
        // caught handlers in the test binary), so this child's install is
        // an OS no-op there by registry design and the shim below stands
        // in. Otherwise the install must take visibly — that strict check
        // is what would catch an install regression.
        let entry_caught = |signal: libc::c_int| {
            try_signal_disposition(signal).is_some_and(|disposition| {
                disposition != libc::SIG_DFL && disposition != libc::SIG_IGN
            })
        };
        let inherited = [
            entry_caught(libc::SIGINT),
            entry_caught(libc::SIGTERM),
            entry_caught(libc::SIGHUP),
        ];
        let stop_bits = (1u64 << (libc::SIGINT - 1))
            | (1u64 << (libc::SIGTERM - 1))
            | (1u64 << (libc::SIGHUP - 1));
        // Phase setup: the startup dispositions to capture, and whether the
        // spawned child must restore them ignored (phase 1) or all-default
        // (phase 2).
        let ignored = phase == 1;
        let (setup, base) = if ignored {
            (libc::SIG_IGN, 10)
        } else {
            (libc::SIG_DFL, 20)
        };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
            if !try_set_disposition(signal, setup) {
                fail(
                    base + 1,
                    format!("phase{phase}: cannot set signal {signal}\n"),
                );
            }
        }
        capture_startup_signal_dispositions();
        if install_stop_flag().is_err() {
            fail(
                base + 2,
                format!("phase{phase}: installing the stop flag failed\n"),
            );
        }
        // The test's premise: current dispositions at spawn differ from the
        // captured startup state (caught vs ignored in phase 1, caught vs
        // default in phase 2), so the spawn below tells restoring the
        // capture from rereading current state. HUP in phase 1 is the
        // exception the install guarantees: it always skips an ignore.
        let mut shimmed = Vec::new();
        for (index, signal) in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP]
            .into_iter()
            .enumerate()
        {
            if ignored && signal == libc::SIGHUP {
                if try_signal_disposition(signal) != Some(libc::SIG_IGN) {
                    fail(
                        base + 3,
                        format!("phase{phase}: the install replaced the HUP ignore\n"),
                    );
                }
                continue;
            }
            if !inherited[index] {
                let current = try_signal_disposition(signal);
                let caught = current.is_some_and(|disposition| {
                    disposition != libc::SIG_DFL && disposition != libc::SIG_IGN
                });
                if !caught {
                    fail(
                        base + 3,
                        format!("phase{phase}: premise broken for signal {signal}: {current:?}\n"),
                    );
                }
            } else if !pin_caught_shim(signal) {
                fail(
                    base + 3,
                    format!("phase{phase}: cannot shim signal {signal}\n"),
                );
            } else {
                shimmed.push(signal.to_string());
            }
        }
        if !shimmed.is_empty() {
            observer_write(
                fd,
                format!(
                    "phase{phase}: shimmed signals {} (test binary owns them)\n",
                    shimmed.join(",")
                )
                .as_bytes(),
            );
        }
        let mut child = match OwnedChild::spawn(OsString::from(sleeper.as_os_str()), Vec::new()) {
            Ok(child) => child,
            Err(error) => fail(base + 4, format!("phase{phase}: spawn failed: {error}\n")),
        };
        if !try_wait_for_session_leader(child.pid()) {
            fail(
                base + 5,
                format!("phase{phase}: the pre-exec child never led its session\n"),
            );
        }
        // Pre-exec the child has restored the capture but not exec'd: the
        // stop bits are ignored (phase 1) or clear (phase 2), and no stop
        // handler may be caught in either phase.
        let pre_ign = try_signal_mask(child.pid(), "SigIgn");
        let pre_cgt = try_signal_mask(child.pid(), "SigCgt");
        let pre_ok = match (pre_ign, pre_cgt) {
            (Some(ign), Some(cgt)) if cgt & stop_bits == 0 => {
                if ignored {
                    ign & stop_bits == stop_bits
                } else {
                    ign & stop_bits == 0
                }
            }
            _ => false,
        };
        if !pre_ok {
            fail(
                base + 6,
                format!("phase{phase}: pre-exec SigIgn={pre_ign:?} SigCgt={pre_cgt:?}\n"),
            );
        }
        if child.release().is_err() {
            fail(
                base + 7,
                format!("phase{phase}: releasing the child failed\n"),
            );
        }
        let post_ign = try_signal_mask(child.pid(), "SigIgn");
        let post_cgt = try_signal_mask(child.pid(), "SigCgt");
        let post_ok = match (post_ign, post_cgt) {
            (Some(ign), Some(cgt)) if cgt & stop_bits == 0 => {
                if ignored {
                    ign & stop_bits == stop_bits
                } else {
                    ign & stop_bits == 0
                }
            }
            _ => false,
        };
        if !post_ok {
            fail(
                base + 8,
                format!("phase{phase}: post-exec SigIgn={post_ign:?} SigCgt={post_cgt:?}\n"),
            );
        }
        if ignored {
            // This sleeper ignores SIGTERM by design under test: SIGKILL it
            // rather than burning the 5 s SIGTERM grace in cleanup.
            if child.pin().send_signal(libc::SIGKILL).is_err()
                || child.terminate_and_reap().is_err()
            {
                fail(
                    base + 9,
                    format!("phase{phase}: reaping the child failed\n"),
                );
            }
            observer_write(
                fd,
                b"OK phase1: ignored stops restored pre-exec and post-exec\n",
            );
        } else {
            if child.terminate_and_reap().is_err() {
                fail(
                    base + 9,
                    format!("phase{phase}: reaping the child failed\n"),
                );
            }
            observer_write(
                fd,
                b"OK phase2: normal dispositions all clear pre-exec and post-exec\n",
            );
        }
        exit(0)
    }

    /// G7: the owned command restores the captured startup ignores through
    /// the stop-flag install. The in-process fidelity test omits the install
    /// and never sets SIGTERM-ignore, so it cannot distinguish restoring
    /// captured startup state from rereading unchanged current dispositions.
    /// One fork child per phase plays the observer in isolation — ignored
    /// stops (phase 1) or normal dispositions (phase 2), capture, install,
    /// spawn — while this process only reaps and reports, so the test
    /// binary's dispositions and the `signal_hook` registry are never
    /// disturbed (pinned by the unchanged-disposition assertions).
    #[test]
    fn owned_command_restores_captured_ignores_through_the_stop_flag_install() {
        use std::io::Read as _;

        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        let own_before = [
            signal_disposition(libc::SIGINT),
            signal_disposition(libc::SIGTERM),
            signal_disposition(libc::SIGHUP),
        ];
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let mut reports = String::new();
        for phase in [1u8, 2u8] {
            let (mut reader, writer) = pipe_pair();
            // SAFETY: fork in a test thread holding the signal-test mutex,
            // so no other thread is inside the `signal_hook` registry the
            // child re-registers with; the child never touches a
            // test-harness lock and exits via _exit on every path.
            let observer = unsafe { libc::fork() };
            assert!(observer >= 0, "forking the isolated observer");
            if observer == 0 {
                drop(reader);
                isolated_fidelity_observer(writer, &sleeper, phase);
            }
            drop(writer);
            // Bounded reap: a wedged observer fails the test instead of
            // hanging the suite.
            let deadline = Instant::now() + Duration::from_secs(60);
            let status = loop {
                let mut status = 0;
                // SAFETY: observer names the direct fork child; status is a
                // live out-param; WNOWAIT-free WNOHANG only polls.
                let waited = unsafe { libc::waitpid(observer, &mut status, libc::WNOHANG) };
                assert!(
                    waited >= 0,
                    "reaping the isolated observer: {}",
                    io::Error::last_os_error()
                );
                if waited == observer {
                    break status;
                }
                if Instant::now() >= deadline {
                    // SAFETY: signaling the exact observer only, then reaping it.
                    unsafe {
                        libc::kill(observer, libc::SIGKILL);
                    }
                    reap_blocking(observer);
                    panic!("the isolated observer wedged; SIGKILLed after 60 s");
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let mut report = Vec::new();
            reader
                .read_to_end(&mut report)
                .expect("reading the observer report");
            let report = String::from_utf8_lossy(&report);
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "the phase{phase} observer failed with status {status:#x}: {report}"
            );
            reports.push_str(&report);
        }
        assert!(
            reports.contains("OK phase1") && reports.contains("OK phase2"),
            "the isolated observers exited 0 without both phase reports: {reports:?}"
        );
        let own_after = [
            signal_disposition(libc::SIGINT),
            signal_disposition(libc::SIGTERM),
            signal_disposition(libc::SIGHUP),
        ];
        assert_eq!(
            own_after, own_before,
            "the isolated observers disturbed the test binary's dispositions"
        );
    }

    /// The fork child drops the observer's hangup handler before it becomes
    /// a session leader: until it execs it must neither run the handler nor
    /// swallow a hangup meant to end it. The command then starts with
    /// SIGHUP at its default, like every other stop signal.
    #[test]
    fn the_pre_exec_child_does_not_inherit_the_observer_hangup_handler() {
        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        // As in the hangup stop test: reset only an ignore, never disarm
        // an already-installed handler behind the registry's back.
        if signal_disposition(libc::SIGHUP) == libc::SIG_IGN {
            set_disposition(libc::SIGHUP, libc::SIG_DFL);
        }
        let _stop = install_stop_flag().unwrap();
        let caught = signal_disposition(libc::SIGHUP);
        assert!(
            caught != libc::SIG_DFL && caught != libc::SIG_IGN,
            "the observer must catch SIGHUP for this fixture"
        );
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let mut child = spawn(sleeper.to_str().unwrap(), &[]);
        wait_for_session_leader(&child);
        let pid = child.pid().to_string();
        assert_eq!(
            signal_mask(&pid, "SigCgt") & (1 << (libc::SIGHUP - 1)),
            0,
            "the pre-exec child still runs the observer's hangup handler"
        );
        child.release().unwrap();
        assert_eq!(
            signal_mask(&pid, "SigCgt") & (1 << (libc::SIGHUP - 1)),
            0,
            "the command catches SIGHUP"
        );
        assert_eq!(
            signal_mask(&pid, "SigIgn") & (1 << (libc::SIGHUP - 1)),
            0,
            "the command ignores SIGHUP"
        );
        assert_eq!(child.terminate_and_reap().unwrap(), 128 + libc::SIGTERM);
    }

    /// Best-effort restore of the child-subreaper flag. Only the SIGKILL
    /// probe below sets it, and only while holding the signal-test mutex.
    struct SubreaperGuard;

    impl Drop for SubreaperGuard {
        fn drop(&mut self) {
            // SAFETY: prctl with only integer arguments.
            unsafe {
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0);
            }
        }
    }

    /// One `/proc/<pid>/stat` state letter, or `None` once the pid is gone.
    fn child_stat_state(pid: u32) -> Option<char> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        stat.split(' ').nth(2)?.chars().next()
    }

    /// Reaps a direct child, blocking. The caller guarantees the child is
    /// already dead or has an unstoppable signal pending.
    fn reap_blocking(pid: libc::pid_t) -> i32 {
        let mut status = 0;
        loop {
            // SAFETY: pid names a direct child; status is a live out-param.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == pid {
                return status;
            }
            assert_eq!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR),
                "reaping pid {pid} failed"
            );
        }
    }

    /// The SIGKILL probe's intermediate parent. Panic-free by construction:
    /// this runs in a fork child that shares the test binary's address
    /// space, so every failure exits with a distinct code instead of
    /// unwinding into the harness. Diverges (until SIGKILLed) on success.
    fn sigkill_probe_intermediate(mut writer: File, sleeper: &Path) -> ! {
        let exit = |code: i32| -> ! {
            // SAFETY: _exit runs no destructors and flushes nothing.
            unsafe { libc::_exit(code) };
        };
        let mut child = match OwnedChild::spawn(OsString::from(sleeper.as_os_str()), Vec::new()) {
            Ok(child) => child,
            Err(_) => exit(11),
        };
        if child.release().is_err() {
            exit(12);
        }
        if child.pin().send_signal(libc::SIGSTOP).is_err() {
            exit(13);
        }
        let pidfd = match child.pin().pidfd() {
            Ok(pidfd) => pidfd,
            Err(_) => exit(14),
        };
        let deadline = Instant::now() + Duration::from_secs(2);
        while !original_child_is_stopped(pidfd) {
            if Instant::now() >= deadline {
                exit(15);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let pid = child.pid().to_ne_bytes();
        if writer.write_all(&pid).is_err() {
            exit(16);
        }
        loop {
            // SAFETY: pause waits for a signal; the parent SIGKILLs us.
            unsafe { libc::pause() };
        }
    }

    /// F-T4-4 observation (no production change): what happens to a stopped
    /// owned child when the observer dies by SIGKILL. A forked intermediate
    /// plays the observer — it spawns, releases, and stops a sleeper in its
    /// own session, reports its pid, then waits to be SIGKILLed — while this
    /// process, briefly a subreaper, reaps the orphan and records whether the
    /// orphaned-process-group rule hung it up or left it stranded in T.
    #[test]
    fn sigkill_of_the_observer_strands_a_stopped_owned_child() {
        use std::io::Read as _;

        let _signal_guard = ACTUAL_SIGNAL_TEST.lock().unwrap();
        // SAFETY: prctl with only integer arguments.
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0,
            "this probe needs the subreaper flag to reap the orphan"
        );
        let _subreaper = SubreaperGuard;
        let fixture_dir = tempfile::tempdir().unwrap();
        let sleeper = build_sleeper(fixture_dir.path());
        let (reader, writer) = pipe_pair();
        // SAFETY: fork in a test thread; the child never touches a lock
        // (spawn takes none) and exits via _exit on every failure path.
        let parent = unsafe { libc::fork() };
        assert!(parent >= 0, "forking the probe intermediate");
        if parent == 0 {
            drop(reader);
            sigkill_probe_intermediate(writer, &sleeper);
        }
        drop(writer);
        let mut pid = [0u8; 4];
        let mut reader = reader;
        reader
            .read_exact(&mut pid)
            .expect("the probe intermediate died before reporting its stopped child");
        let orphan = u32::from_ne_bytes(pid);
        // SAFETY: signaling the exact intermediate only, then reaping it.
        assert_eq!(unsafe { libc::kill(parent, libc::SIGKILL) }, 0);
        let parent_status = reap_blocking(parent);
        assert!(
            libc::WIFSIGNALED(parent_status) && libc::WTERMSIG(parent_status) == libc::SIGKILL,
            "the probe intermediate was not SIGKILLed: status {parent_status:#x}"
        );

        // The orphaned-process-group rule, if it fires, delivers SIGHUP and
        // SIGCONT promptly at orphaning. Anything still stopped after this
        // window was stranded, not hung up.
        let deadline = Instant::now() + Duration::from_millis(500);
        let mut seen = Vec::new();
        let stranded = loop {
            match child_stat_state(orphan) {
                None => break false,
                Some(state) => {
                    if seen.last() != Some(&state) {
                        seen.push(state);
                    }
                    if Instant::now() >= deadline {
                        break state == 'T';
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        };
        assert!(
            stranded,
            "the orphaned stopped child did not stay stopped (states seen: {seen:?})"
        );

        // Cleanup, and the stranding proof: the orphan must be alive until
        // this SIGKILL lands, then reaped without residue.
        // SAFETY: signaling the exact orphan only.
        assert_eq!(
            unsafe { libc::kill(orphan as libc::pid_t, libc::SIGKILL) },
            0,
            "the stranded orphan died before cleanup"
        );
        let orphan_status = reap_blocking(orphan as libc::pid_t);
        assert!(
            libc::WIFSIGNALED(orphan_status) && libc::WTERMSIG(orphan_status) == libc::SIGKILL,
            "the stranded orphan did not die by the cleanup SIGKILL: status {orphan_status:#x}"
        );
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
        assert!(attach_mechanisms(0, false, false).is_empty());
        assert_eq!(attach_mechanisms(0, true, false), ["per-offset"]);
        assert_eq!(attach_mechanisms(2, false, false), ["per-offset"]);
    }

    #[test]
    fn attach_mechanism_reports_multi_for_group_links_sorted_with_dynamic() {
        assert_eq!(attach_mechanisms(2, false, true), ["uprobe-multi"]);
        assert_eq!(
            attach_mechanisms(2, true, true),
            ["per-offset", "uprobe-multi"]
        );
        assert_eq!(attach_mechanisms(2, true, false), ["per-offset"]);
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
                render::SchedulingEvidence::default(),
                None,
                None,
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
        assert_eq!(gap_profile.multi_rebuild_gaps, 0);
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
                    render::SchedulingEvidence::default(),
                    None,
                    None,
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
            render::SchedulingEvidence::default(),
            None,
            None,
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
            render::SchedulingEvidence::default(),
            None,
            None,
        );

        assert_eq!(evidence.pid_descendant_gaps, 0);
        assert_eq!(evidence.multi_rebuild_gaps, 0);
        assert_eq!(evidence.process_tracking_failures, 1);
        assert_eq!(evidence.completeness, "PARTIAL");
        let profile = render::versioned_evidence(&evidence);
        assert_eq!(profile["pid_descendant_gaps"], 0);
        assert_eq!(profile["multi_rebuild_gaps"], 0);
        assert_eq!(profile["process_tracking_failures"], 1);
        let terminal = trace::evidence_line(&evidence, CapturePolicy::Allowlisted, false);
        assert!(terminal.contains("\"pid_descendant_gaps\":0"), "{terminal}");
        assert!(terminal.contains("\"multi_rebuild_gaps\":0"), "{terminal}");
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

    // SYSPLAN residual F-15 (GREEN): the handoff note names the orphan PID
    // plus the handoff state.
    #[test]
    fn handoff_note_names_orphan_pid_and_state() {
        let note = format_handoff_note(4242);
        assert!(note.contains("4242"), "{note:?}");
        assert!(note.contains("still running"), "{note:?}");
        assert!(note.contains("--kill-on-timeout"), "{note:?}");
    }

    // SYSPLAN residual F-17 (GREEN): the no-duration notice names the
    // effective default cap, derived from the constant, not a copy.
    #[test]
    fn no_duration_notice_names_effective_default_cap() {
        let notice = no_duration_notice();
        assert!(
            notice.contains(&DEFAULT_TRACE_MAX_EVENTS.to_string()),
            "{notice:?}"
        );
        assert!(notice.contains("--max-events"), "{notice:?}");
    }
}
