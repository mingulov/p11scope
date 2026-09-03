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
use crate::{metrics, process, render, scope, semantics, trace};
use anyhow::{Context as _, Result, anyhow};
use p11scope_manifest::elf::ElfSnapshot;
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

const TERM_GRACE: Duration = Duration::from_secs(5);
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
pub(crate) struct PreparedExecutable {
    path: PathBuf,
    file: File,
    identity: FileIdentity,
    interpreter: PathBuf,
    interpreter_file: File,
    interpreter_identity: FileIdentity,
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
    /// x86-64 ELF with one absolute PT_INTERP. Shebang and non-ELF forms
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
        if ElfSnapshot::read(&interpreter_file).is_err() {
            return Ok(None);
        }
        Ok(Some(Self {
            path,
            file,
            identity: FileIdentity::of(&metadata),
            interpreter,
            interpreter_file,
            interpreter_identity: FileIdentity::of(&interpreter_metadata),
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
    pin: PidPin,
    generation: NonZeroU64,
    release_writer: Option<OwnedFd>,
    exec_reader: Option<OwnedFd>,
    prepared: Option<PreparedExecutable>,
    released: bool,
    reaped: bool,
    handed_off: bool,
    interrupt_count: u8,
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
        if ElfSnapshot::read(&launch_file).is_err() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "owned command must be an ELF executable; invoke scripts through an interpreter",
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
        let (release_reader, release_writer) = pipe_pair()?;
        let (exec_reader, exec_writer) = pipe_pair()?;
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
                libc::syscall(
                    libc::SYS_execveat,
                    launch_file.as_raw_fd(),
                    c"".as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                    libc::AT_EMPTY_PATH,
                );
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
                kill_and_reap_fork_child(pid);
                return Err(io::Error::other(error));
            }
        };
        Ok(Self {
            pid,
            pin,
            generation,
            release_writer: Some(release_writer),
            exec_reader: Some(exec_reader),
            prepared,
            released: false,
            reaped: false,
            handed_off: false,
            interrupt_count: 0,
        })
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
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

    pub(crate) fn release(&mut self) -> Result<(), ExecFailure> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        let writer = self
            .release_writer
            .take()
            .expect("unreleased child has barrier");
        let byte = 1u8;
        let written = loop {
            // SAFETY: writer is live and byte is valid for one-byte write.
            let written =
                unsafe { libc::write(writer.as_raw_fd(), (&byte as *const u8).cast(), 1) };
            if written >= 0 || io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                break written;
            }
        };
        drop(writer);
        if written != 1 {
            let errno = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            return Err(ExecFailure {
                errno,
                exit_code: 127,
            });
        }

        let reader = self
            .exec_reader
            .take()
            .expect("unreleased child has exec pipe");
        let mut bytes = [0u8; std::mem::size_of::<i32>()];
        let mut used = 0;
        loop {
            // SAFETY: the remaining byte range is writable and reader is live.
            let read = unsafe {
                libc::read(
                    reader.as_raw_fd(),
                    bytes[used..].as_mut_ptr().cast(),
                    bytes.len() - used,
                )
            };
            if read == 0 {
                break;
            }
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(ExecFailure {
                    errno: error.raw_os_error().unwrap_or(libc::EIO),
                    exit_code: 127,
                });
            }
            used += read as usize;
            if used == bytes.len() {
                break;
            }
        }
        drop(reader);
        if used == 0 {
            return Ok(());
        }
        let errno = if used == bytes.len() {
            i32::from_ne_bytes(bytes)
        } else {
            libc::EIO
        };
        // The child-side exec failure always exits 127. Leave the pidfd
        // unreaped so an owned run can close coordinator state first; callers
        // that do not have that coordinator still get safe Drop settlement.
        Err(ExecFailure {
            errno,
            exit_code: 127,
        })
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
        if self.pin.wait_ready(duration)? {
            return self.wait_blocking().map(ChildOutcome::Exited);
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
        if self.pin.wait_ready(Some(Duration::ZERO))? {
            return self.wait_blocking();
        }
        self.ensure_active_generation()?;
        signal_group(self.pid, libc::SIGTERM)?;
        if self.pin.wait_ready(Some(grace))? {
            return self.wait_blocking();
        }
        self.kill_and_reap_tail()
    }

    fn kill_and_reap_tail(&mut self) -> io::Result<i32> {
        if self.pin.wait_ready(Some(Duration::ZERO))? {
            return self.wait_blocking();
        }
        self.ensure_active_generation()?;
        signal_group(self.pid, libc::SIGKILL)?;
        if !self.pin.wait_ready(Some(Duration::from_secs(5)))? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child reap timeout",
            ));
        }
        self.wait_blocking()
    }

    fn reap_after_escalation(&mut self) -> io::Result<i32> {
        match self.wait_for(Some(Duration::from_secs(5)), false)? {
            ChildOutcome::Exited(code) => Ok(code),
            ChildOutcome::TimedOutRunning => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child reap timeout",
            )),
        }
    }

    pub(crate) fn still_running(&self) -> bool {
        !self.reaped && self.pin.still_the_same()
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

    fn wait_blocking(&mut self) -> io::Result<i32> {
        let mut status = 0;
        loop {
            // SAFETY: this process is the parent of the exact unreaped child.
            let waited = unsafe { libc::waitpid(self.pid as libc::pid_t, &mut status, 0) };
            if waited == self.pid as libc::pid_t {
                self.reaped = true;
                return Ok(wait_status(status));
            }
            if waited < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
        }
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
        if self
            .pin
            .wait_ready(Some(Duration::from_millis(50)))
            .unwrap_or(false)
        {
            let _ = self.wait_blocking();
            return;
        }
        let _ = signal_group(self.pid, libc::SIGKILL);
        let _ = self.pin.wait_ready(Some(Duration::from_secs(5)));
        let _ = self.wait_blocking();
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

fn kill_and_reap_fork_child(pid: u32) {
    // The exact fork child is still unreaped, so its numeric PID cannot have
    // been reused. This is intentionally not a general signal fallback.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    reap_fork_child(pid);
}

fn reap_fork_child(pid: u32) {
    loop {
        // SAFETY: this process is the parent of the exact unreaped fork child.
        let waited = unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), 0) };
        if waited == pid as libc::pid_t {
            return;
        }
        if waited < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return;
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

fn wait_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        127
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
    };
    if kind == Kind::Trace && a.duration.is_none() {
        eprintln!(
            "p11scope: no --duration given; trace streams until interrupted (Ctrl-C) or the \
             process exits"
        );
    }
    warn_unsafe_policy(policy);
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
        .start_session(policy)
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
    )?;
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
) -> Result<render::Evidence> {
    report_attach_failures(session);
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
        let Some(child) = self.child.take() else {
            return Ok(());
        };
        let natural_exit =
            end == CaptureEnd::TargetExit && child.pin().original_exited().unwrap_or(false);
        engine.finish_owned_selection_coverage(natural_exit);
        let cleanup = {
            let marker = marker_never_seen();
            let cancelled = cancelled_by(signals);
            let mut io = SessionPauseIo::new(engine, session, &child, &marker, &cancelled);
            self.coordinator.cleanup(&mut io)
        };
        let settled = settle_owned_child(
            child,
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
        combine_finish_errors(cleanup.map_err(pause_failure), settled)
    }
}

#[allow(clippy::too_many_arguments)]
fn settle_owned_child(
    mut child: OwnedChild,
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
    let settled: Result<ChildOutcome> = if can_hand_off {
        stage_handoff(child, pending)
    } else if (end == CaptureEnd::Signal || signals.interrupted()) && child.still_running() {
        settle_after_signal(&mut child, signals)
    } else {
        child
            .terminate_and_reap()
            .map(ChildOutcome::Exited)
            .map_err(|error| anyhow!("run: reaping the owned child: {error}"))
    };
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
        Err(error) => Err(anyhow!("run: reaping the owned child: {error}")),
    }
}

fn stage_handoff(mut child: OwnedChild, pending: &mut Option<OwnedChild>) -> Result<ChildOutcome> {
    match child
        .wait_for(Some(Duration::ZERO), false)
        .map_err(|error| anyhow!("run: waiting for the owned child: {error}"))?
    {
        outcome @ ChildOutcome::TimedOutRunning => {
            *pending = Some(child);
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
    let signal = signals
        .first_signal()
        .ok_or_else(|| anyhow!("run: signal settlement lost the first signal identity"))?;
    child
        .forward_signal(signal)
        .map_err(|error| anyhow!("run: forwarding signal {signal}: {error}"))?;
    let mut deadline = Instant::now() + grace;
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
            deadline = Instant::now() + grace;
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

fn combine_handoff_failure(primary: anyhow::Error, abort: Result<()>) -> anyhow::Error {
    match abort {
        Ok(()) => primary,
        Err(abort) => primary.context(format!("aborting pending handoff also failed: {abort:#}")),
    }
}

fn combine_finish_errors(cleanup: Result<()>, settled: Result<()>) -> Result<()> {
    match (cleanup, settled) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(cleanup), Err(settled)) => {
            Err(cleanup.context(format!("owned child settlement also failed: {settled:#}")))
        }
    }
}

fn combine_capture_failure(
    mut capture: anyhow::Error,
    finish: Result<()>,
    detach: Result<()>,
) -> anyhow::Error {
    if let Err(error) = finish {
        capture = capture.context(format!("owned cleanup/settlement also failed: {error:#}"));
    }
    if let Err(error) = detach {
        capture = capture.context(format!(
            "detaching capture producers also failed: {error:#}"
        ));
    }
    capture
}

fn combine_detach<T>(terminal: Result<T>, detach: Result<()>) -> Result<T> {
    match (terminal, detach) {
        (result, Ok(())) => result,
        (Ok(_), Err(detach)) => Err(anyhow!("run: detaching capture producers: {detach:#}")),
        (Err(terminal), Err(detach)) => Err(terminal.context(format!(
            "detaching capture producers also failed: {detach:#}"
        ))),
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
    let outcome = run_owned_inner(args);
    match (args.pause, outcome) {
        // `always` never falls back to a successful unpaused run: whatever
        // could not be completed, the refusal says pause was required.
        (cli::PausePolicy::Always, Err(error)) => Err(error.context(
            "run --pause always: required pause protection could not be completed, so the run \
             refused rather than capturing unpaused",
        )),
        (_, outcome) => outcome,
    }
}

fn run_owned_inner(args: &RunArgs) -> Result<OwnedRunOutcome> {
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
    let view = ProcessView::open(ProcessViewId(0), pid)
        .map_err(|error| anyhow!("run: opening the owned child: {error}"))?;
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
        unsafe_requested: args.unsafe_requested,
    };
    // Initial capture still uses the one `discover_plan` pass and keeps its
    // accepted state inside `Engine`; nothing below rescans or reopens.
    let mut engine = Engine::discover(&capture_args, &scope, Some(view))?;
    let stop = install_stop_flag()?;
    // Before the attach, and before the child crosses its barrier: a bad `-o`
    // path must never cost a released child or a loaded session.
    let out = OutputSink::open(args.kind, args.out.as_deref())?;

    // `start_owned_session` arms the pre-exec loader context before the
    // barrier when exact PT_INTERP binding is safe, and otherwise leaves
    // `initial_set_capture = none` with sticky `PARTIAL`.
    let mut session = engine
        .start_owned_session(policy, &mut child)
        .context("starting attach session")?;

    let mut owned = {
        let marker = marker_never_seen();
        let cancelled = cancelled_by(&stop);
        let mut io = SessionPauseIo::new(&mut engine, &mut session, &child, &marker, &cancelled);
        let mut coordinator =
            PauseCoordinator::preflight(args.pause, &child, &mut io).map_err(pause_failure)?;
        // Arm before the barrier: the owned window has to be protected from
        // the child's first loader event, not from the first tick after it.
        coordinator.arm(&mut io).map_err(pause_failure)?;
        Owned {
            child: Some(child),
            pending_handoff: None,
            coordinator,
            policy: args.pause,
            kill_on_timeout: args.kill_on_timeout,
            pid,
            exit_code: None,
            still_running: false,
        }
    };

    let release = owned
        .child
        .as_mut()
        .expect("owned child is present before release")
        .release()
        .map_err(|failure| anyhow!("run: exec {failure}"));
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
    Ok(OwnedRunOutcome {
        child_exit_code: owned.exit_code,
        child_still_running: owned.still_running,
        child_pid: owned.pid,
        evidence,
    })
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
    let registry = pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry::load(None)
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
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    ev: &p11scope_ebpf_common::Event,
) -> semantics::ProcessKey {
    let pid = (ev.pid_tgid >> 32) as u32;
    let identified = tracker.identify(pid);
    if let Some(retired) = identified.retired {
        state.retire_process(retired);
    }
    identified.key
}

fn retire_exited(tracker: &mut process::Tracker, state: &mut semantics::State) {
    for process in tracker.poll_exited() {
        state.retire_process(process);
    }
}

fn observe_fork(
    tracker: &mut process::Tracker,
    state: &mut semantics::State,
    scope: &Scope,
    pid_descendant_gaps: &mut u64,
    ev: &p11scope_ebpf_common::Event,
) -> bool {
    if !matches!(
        ev.event_type,
        p11scope_ebpf_common::event_type::FORK | p11scope_ebpf_common::event_type::FORK_INTO_CGROUP
    ) {
        return false;
    }
    if !matches!(scope, Scope::Cgroup { .. }) {
        return true;
    }
    let parent_pid = (ev.pid_tgid >> 32) as u32;
    // Static function probes cover cgroup descendants immediately, but Aya's
    // per-process dynamic export links cannot cover a child's C_GetInterface
    // calls before the next membership refresh. Keep semantic inheritance,
    // while making that selection-discovery window explicit.
    *pid_descendant_gaps = pid_descendant_gaps.saturating_add(1);
    if ev.event_type == p11scope_ebpf_common::event_type::FORK_INTO_CGROUP {
        return true;
    }
    if !state.pid_has_process_state(parent_pid) {
        return true;
    }
    let parent = tracker.identify(parent_pid);
    if let Some(retired) = parent.retired {
        state.retire_process(retired);
    }
    if !state.has_process_state(parent.key) {
        tracker.retire(parent.key);
        return true;
    }
    let child = tracker.identify(ev.session as u32);
    if let Some(retired) = child.retired {
        state.retire_process(retired);
    }
    state.fork_process(parent.key, child.key);
    if !state.has_process_state(child.key) {
        state.retire_process(child.key);
        tracker.retire(child.key);
    }
    true
}

fn initial_tracking_evidence(
    scope: &Scope,
    process_creation_tracking_unavailable: bool,
    lifecycle_tracking_unavailable: bool,
) -> (u64, bool) {
    match scope {
        Scope::Pid(_) => (0, lifecycle_tracking_unavailable),
        Scope::Cgroup { .. } => (
            u64::from(process_creation_tracking_unavailable),
            process_creation_tracking_unavailable || lifecycle_tracking_unavailable,
        ),
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
) -> Option<CaptureEnd> {
    if interrupted.interrupted() {
        Some(CaptureEnd::Signal)
    } else if engine.expected_target_exit()
        // An owned child that has already exited ends its run the ordinary
        // way too, without waiting for its exit record: the pidfd is the
        // definitive answer, and the terminal drain below still collects
        // everything the ring holds.
        || owned.is_some_and(|owned| {
            owned
                .child
                .as_ref()
                .is_some_and(|child| !child.still_running())
        })
    {
        Some(CaptureEnd::TargetExit)
    } else if should_stop(interrupted, elapsed, duration) {
        Some(CaptureEnd::DurationExpired)
    } else {
        None
    }
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

#[allow(clippy::too_many_arguments)]
fn capture_profile(
    engine: &mut Engine,
    session: &mut Session,
    scope: &Scope,
    policy: CapturePolicy,
    duration: Option<Duration>,
    output: Option<AtomicFile>,
    interrupted: &SignalState,
    mut owned: Option<&mut Owned>,
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
    let mut state = semantics::State::with_policy(engine.plan(), policy);
    let mut process_tracker = process::Tracker::new();
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
                        tracker: &mut process::Tracker,
                        pid_descendant_gaps: &mut u64|
     -> Result<u64> {
        let quantum = session.live_poll_quantum();
        let mut drain = session.event_drain()?;
        Ok(drain_profile_events(
            &mut drain,
            state,
            tracker,
            scope,
            pid_descendant_gaps,
            quantum,
        ))
    };
    let mut malformed_records: u64 = 0;
    let (mut pid_descendant_gaps, capture_tracking_degraded) = initial_tracking_evidence(
        scope,
        session.process_creation_tracking_unavailable().is_some(),
        session.lifecycle_tracking_unavailable().is_some(),
    );
    let mut stdout_open = true;
    let wall_start = SystemTime::now();
    let clock = Instant::now();
    let mut last_frame = Instant::now() - PROFILE_CADENCE;
    #[rustfmt::skip]
    let loop_result = (|| -> Result<CaptureEnd> {
    loop {
        let elapsed = clock.elapsed();
        // 1. Drain discovery: `Engine` extends `AttachPlan` and applies the
        //    attachment deltas inside this call.
        let (plan_changed, paused) =
            drain_discovery_tick(engine, session, owned.as_deref_mut(), interrupted)?;
        // 2. Synchronize the immediate semantic invalidations, which preserve
        //    unchanged retired decode metadata, before anything reads state.
        if plan_changed {
            state.sync_plan(engine.plan());
        }
        if let Some(end) = capture_end(engine, owned.as_deref(), interrupted, elapsed, duration) {
            break Ok(end);
        }
        // 3. Drain call events — one quantum while the producers are live, so
        //    a hot producer hands control back to step 2's checks every tick.
        if profile {
            malformed_records += drain_events(
                session,
                &mut state,
                &mut process_tracker,
                &mut pid_descendant_gaps,
            )?;
        }
        // 4. Retire exited process state.
        retire_exited(&mut process_tracker, &mut state);
        // 5. Snapshot metrics and counters.
        let mut kernel_evidence = metrics::kernel_evidence(session)?;
        if !profile {
            kernel_evidence.ring_loss = 0;
        }
        let reports = metrics::read(session, engine.plan())?;
        // 6. Check the retained generations and objects.
        engine
            .pinned()
            .check_unchanged()
            .map_err(anyhow::Error::msg)?;

        if last_frame.elapsed() >= PROFILE_CADENCE {
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
                owned.as_deref(),
                pid_descendant_gaps,
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
        tick_sleep(paused, PROFILE_CADENCE);
    }
    })();
    finish_capture_loop(
        loop_result,
        engine,
        session,
        owned.as_deref_mut(),
        interrupted,
    )?;

    let detach = session.detach_producers();
    #[rustfmt::skip]
    let terminal = (|| -> Result<render::Evidence> {
    // A detach error is retained until after this terminal drain. Do not put a
    // fallible provider check between those two operations.
    let plan_changed = if detach.is_ok() {
        engine.drain_discovery_terminal(session)?
    } else {
        engine.drain_discovery_terminal_bounded_from(session)?
    };
    if plan_changed {
        state.sync_plan(engine.plan());
    }
    if profile {
        malformed_records += drain_events(
            session,
            &mut state,
            &mut process_tracker,
            &mut pid_descendant_gaps,
        )?;
    }
    retire_exited(&mut process_tracker, &mut state);
    let reports = metrics::read(session, engine.plan())?;
    let mut kernel_evidence = metrics::kernel_evidence(session)?;
    if !profile {
        kernel_evidence.ring_loss = 0;
    }
    // Last look before the evidence that the final frame and the `-o` report
    // are built from, so an in-place provider change is reflected in both.
    engine
        .pinned()
        .check_unchanged()
        .map_err(anyhow::Error::msg)?;
    // A terminal-drain retry the capture proved is not a loss: judged here,
    // at capture end, before the document that would carry the announcement.
    engine.settle_terminal_drain();
    let mut ev = evidence_for(
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
        owned.as_deref(),
        pid_descendant_gaps,
        capture_tracking_degraded,
    );
    ev.mark_terminal_drain_unproven();
    // The terminal frame and the JSON use the same capture facts.
    let facts = engine.capture_facts();
    let frame = render::live(
        &reports,
        &ev,
        clock.elapsed(),
        &facts.heading(),
        mode,
        policy,
    );
    write_stdout(
        stdout,
        &mut stdout_open,
        format!("\x1b[2J\x1b[H{frame}").as_bytes(),
    )?;
    flush_stdout(stdout, &mut stdout_open)?;

    if let Some(mut out_file) = output {
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
            .to_string();
        let started = fmt_rfc3339(wall_start);
        let ended = fmt_rfc3339(SystemTime::now());
        // `capture.modules[]` comes from the evidence, not from here: one list,
        // rendered twice, so the two sections cannot disagree.
        let capture = render::CaptureMeta {
            started: &started,
            ended: &ended,
            kernel: &kernel,
            policy,
        };
        let j = if profile {
            render::profile_json(&reports, &ev, &state, &capture)
        } else {
            render::json(&reports, &ev, &capture)
        };
        write_json_report(out_file.file(), &j)?;
        out_file.commit().map_err(anyhow::Error::msg)?;
    }

    Ok(ev)
    })();
    combine_detach(terminal, detach)
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
) -> Result<render::Evidence> {
    let trace_limit = resolve_trace_max_events(max_events);
    let mut remaining = Some(trace_limit);
    // A line stream, not a published artifact: opened by the caller before the
    // attach, then appended to as lines arrive.
    let mut out_sink = out;
    let out_file = &mut out_sink;
    let mut stdout_sink = std::io::stdout().lock();
    let stdout: &mut dyn Write = &mut stdout_sink;

    let mut state = semantics::State::with_policy(engine.plan(), policy);
    let mut process_tracker = process::Tracker::new();
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
    let (mut pid_descendant_gaps, capture_tracking_degraded) = initial_tracking_evidence(
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
        // 1. Drain discovery; the Engine extends the plan and applies deltas.
        let (plan_changed, paused) =
            drain_discovery_tick(engine, session, owned.as_deref_mut(), interrupted)?;
        // 2. Synchronize both immediate invalidation consumers at once, so a
        //    trace line can never name a slot semantics has already retired.
        if plan_changed {
            state.sync_plan(engine.plan());
            tracer.sync_plan(engine.plan());
        }
        if let Some(end) = capture_end(engine, owned.as_deref(), interrupted, elapsed, duration) {
            break Ok(end);
        }
        // 3. Drain call events — one quantum while the producers are live, and
        //    the poll itself stops at the last permitted line, so a hot
        //    producer can neither hold off step 2's checks nor the limit below.
        malformed_records += drain_trace_events(
            session,
            &mut remaining,
            &mut state,
            &mut process_tracker,
            scope,
            &mut pid_descendant_gaps,
            &mut tracer,
            stdout,
            &mut stdout_open,
            out_file,
        )?;
        if remaining == Some(0) {
            break Ok(CaptureEnd::LimitReached);
        }
        // 4. Retire exited process state.
        retire_exited(&mut process_tracker, &mut state);
        // 5. Snapshot the loss counter.
        report_trace_loss(
            session,
            &mut last_reported_loss,
            stdout,
            &mut stdout_open,
            out_file,
        )?;
        // 6. Check the retained generations and objects.
        engine
            .pinned()
            .check_unchanged()
            .map_err(anyhow::Error::msg)?;
        flush_stdout(stdout, &mut stdout_open)?;
        if let Some(f) = out_file.as_mut() {
            f.flush().context("flushing trace output file")?;
        }
        if !stdout_open && out_file.is_none() {
            break Ok(CaptureEnd::Error);
        }
        tick_sleep(paused, TRACE_CADENCE);
    }
    })();

    #[rustfmt::skip]
    let end =
    finish_capture_loop(
        loop_result,
        engine,
        session,
        owned.as_deref_mut(),
        interrupted,
    )?;

    let detach = session.detach_producers();
    #[rustfmt::skip]
    let terminal = (|| -> Result<render::Evidence> {
    // Drain everything currently visible after detach, then report the closing
    // loss line. Kernel detach does not wait for callbacks already executing
    // on another CPU, so terminal evidence below remains explicitly PARTIAL.
    let plan_changed = if detach.is_ok() {
        engine.drain_discovery_terminal(session)?
    } else {
        engine.drain_discovery_terminal_bounded_from(session)?
    };
    if plan_changed {
        state.sync_plan(engine.plan());
        tracer.sync_plan(engine.plan());
    }
    malformed_records += drain_trace_events(
        session,
        &mut remaining,
        &mut state,
        &mut process_tracker,
        scope,
        &mut pid_descendant_gaps,
        &mut tracer,
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    retire_exited(&mut process_tracker, &mut state);
    engine
        .pinned()
        .check_unchanged()
        .map_err(anyhow::Error::msg)?;
    report_trace_loss(
        session,
        &mut last_reported_loss,
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    let reports = metrics::read(session, engine.plan())?;
    // Last look before the evidence line the trace ends with, so an in-place
    // provider change is reflected in it.
    engine
        .pinned()
        .check_unchanged()
        .map_err(anyhow::Error::msg)?;
    engine.settle_terminal_drain();
    let trace_truncated = end == CaptureEnd::LimitReached || remaining == Some(0);
    let mut evidence = evidence_for(
        engine,
        engine.capture_facts(),
        session.attached_probes(),
        session.dynamic_per_offset_attached(),
        session.attach_failures(),
        &reports,
        metrics::kernel_evidence(session)?,
        process_tracker.evidence(),
        malformed_records,
        &state,
        engine.pinned().provider_changed(),
        true,
        owned.as_deref(),
        pid_descendant_gaps,
        capture_tracking_degraded,
    );
    evidence.mark_terminal_drain_unproven();
    if trace_truncated {
        emit_trace_line(
            &trace::truncated_line(trace_limit),
            stdout,
            &mut stdout_open,
            out_file,
        )?;
    }
    emit_trace_terminal(
        &reports,
        &tracer,
        &trace::evidence_line(&evidence, policy, trace_truncated),
        stdout,
        &mut stdout_open,
        out_file,
    )?;
    if malformed_records > 0 {
        eprintln!(
            "p11scope: {malformed_records} malformed ring-buffer records discarded this capture"
        );
    }
    if let Some(f) = out_file.as_mut() {
        f.flush().context("flushing trace output file")?;
    }

    Ok(evidence)
    })();
    combine_detach(terminal, detach)
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
fn drain_profile_events<S: crate::events::RecordSource>(
    drain: &mut crate::events::EventDrain<S>,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    scope: &Scope,
    pid_descendant_gaps: &mut u64,
    quantum: Option<usize>,
) -> u64 {
    drain.poll(quantum, |ev| {
        if observe_fork(tracker, state, scope, pid_descendant_gaps, &ev) {
            return ControlFlow::Continue(());
        }
        let process = identify_tracked(tracker, state, &ev);
        state.observe_process(process, &ev);
        if !state.has_process_state(process) {
            state.retire_process(process);
            tracker.retire(process);
        }
        ControlFlow::Continue(())
    });
    drain.malformed()
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
    pid_descendant_gaps: &mut u64,
    tracer: &mut trace::Tracer,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<u64> {
    let quantum = session.live_poll_quantum();
    let mut drain = session.event_drain()?;
    drain_trace_events_from(
        &mut drain,
        remaining,
        state,
        tracker,
        scope,
        pid_descendant_gaps,
        tracer,
        stdout,
        stdout_open,
        out_file,
        quantum,
    )
}

#[allow(clippy::too_many_arguments)]
fn drain_trace_events_from<S: crate::events::RecordSource, W: Write>(
    drain: &mut crate::events::EventDrain<S>,
    remaining: &mut Option<u64>,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    scope: &Scope,
    pid_descendant_gaps: &mut u64,
    tracer: &mut trace::Tracer,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
    quantum: Option<usize>,
) -> Result<u64> {
    let mut write_error = None;
    drain.poll(quantum, |ev| {
        tracer.count_raw_call(&ev);
        if observe_fork(tracker, state, scope, pid_descendant_gaps, &ev) {
            return ControlFlow::Continue(());
        }
        let process = identify_tracked(tracker, state, &ev);
        if write_error.is_some() {
            state.observe_process(process, &ev);
        } else {
            let (emitted, error) = emit_bounded_trace_event(
                remaining,
                || tracer.on_event_process(&ev, process, state),
                stdout,
                stdout_open,
                out_file,
            );
            write_error = error;
            if !emitted {
                state.observe_process(process, &ev);
            }
        }
        if !state.has_process_state(process) {
            state.retire_process(process);
            tracker.retire(process);
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
    if let Some(error) = write_error {
        return Err(error);
    }
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
    owned: Option<&Owned>,
    pid_descendant_gaps: u64,
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
    let pause = owned.map_or_else(Default::default, |owned| owned.coordinator.counters());
    let pause_status = pause.status();
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
        child_still_running: owned.map(|owned| owned.still_running),
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
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use std::time::{Duration, Instant};

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
    fn release_error_defers_settlement_for_owned_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let command = directory.path().join("command");
        std::fs::copy("/bin/true", &command).unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = OwnedChild::spawn(command.clone().into_os_string(), Vec::new()).unwrap();
        std::fs::set_permissions(&command, std::fs::Permissions::from_mode(0o000)).unwrap();

        let failure = child.release().unwrap_err();
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
        let outcome = stage_handoff(child, &mut pending).unwrap();
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
            stage_handoff(child, &mut pending).unwrap(),
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
            settle_owned_child(
                child,
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

        let mut direct = spawn("/bin/sleep", &["1"]);
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

    #[test]
    fn duration_and_forwarded_signals_have_one_owned_cleanup_route() {
        let mut running = spawn("/bin/sleep", &["10"]);
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
            unsafe_requested: false,
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
        let mut gaps = 0;
        let events = (0..=LIVE_POLL_QUANTUM).map(|_| call_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, LIVE_POLL_QUANTUM));

        let malformed = drain_profile_events(
            &mut drain,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut gaps,
            Some(LIVE_POLL_QUANTUM),
        );

        assert_eq!(malformed, 0);
        assert_eq!(drain.source().remaining(), 1);
    }

    #[test]
    fn cgroup_process_creation_inherits_once_and_tags_into_cgroup_no_inherit() {
        use crate::events::{EventDrain, ScriptedRecords};

        let event = p11scope_ebpf_common::Event {
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
        let mut tracker = process::Tracker::new();
        let parent_process = tracker.identify(41).key;
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
        let mut gaps = 0;
        let mut drain = EventDrain::over(ScriptedRecords::events([event], usize::MAX));
        let scope = Scope::Cgroup {
            id: 1,
            path: "/".into(),
            dir: std::sync::Arc::new(std::fs::File::open("/").unwrap()),
        };

        assert_eq!(
            drain_profile_events(
                &mut drain,
                &mut state,
                &mut tracker,
                &scope,
                &mut gaps,
                None,
            ),
            0
        );
        assert_eq!(
            gaps, 1,
            "one fork creates one pre-refresh selection-discovery window"
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
        let mut drain = EventDrain::over(ScriptedRecords::events([into_event], usize::MAX));
        assert_eq!(
            drain_profile_events(
                &mut drain,
                &mut state,
                &mut tracker,
                &scope,
                &mut gaps,
                None,
            ),
            0
        );
        assert_eq!(gaps, 2, "each non-thread process creation adds one gap");
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
        let mut gaps = 0;
        let events = (0..5).map(|_| call_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, 2));

        let malformed = drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut gaps,
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
        let mut gaps = 0;
        let events = (0..=LIVE_POLL_QUANTUM).map(|_| call_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, LIVE_POLL_QUANTUM));

        drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut gaps,
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
        let mut gaps = 0;
        let events = (0..crate::events::LIVE_POLL_QUANTUM + 5).map(|_| call_event());
        let mut drain = EventDrain::over(ScriptedRecords::events(events, usize::MAX));

        drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut gaps,
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
        let mut gaps = 0;
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
        let mut drain = EventDrain::over(ScriptedRecords::events(events, usize::MAX));

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
            &mut gaps,
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
        let mut gaps = 0;
        let mut drain = crate::events::EventDrain::over(crate::events::ScriptedRecords::events(
            [call_event()],
            usize::MAX,
        ));
        drain_trace_events_from(
            &mut drain,
            &mut remaining,
            &mut state,
            &mut tracker,
            &Scope::Pid(std::process::id()),
            &mut gaps,
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
        let run = include_str!("run.rs");
        let run = run.split_once("#[cfg(test)]\nmod tests {").unwrap().0;
        assert_eq!(
            run.matches("let quantum = session.live_poll_quantum();")
                .count(),
            2,
            "one bound decision per drain wrapper, taken before the ring is opened"
        );
        assert_eq!(
            run.matches(".poll(quantum, |ev|").count(),
            2,
            "both event polls carry that bound"
        );
        let attach = include_str!("attach.rs");
        let detach = attach.split_once("pub fn detach_producers(").unwrap().1;
        let detach = detach.split_once("fn has_slot_link").unwrap().0;
        assert!(
            detach.contains("self.producers_detached = detached.is_ok();"),
            "only a fully successful detach makes the ring finite"
        );
    }

    #[test]
    fn terminal_discovery_drains_before_each_event_drain() {
        let source = include_str!("run.rs");
        for (function, event_call, consumers) in [
            (
                "fn capture_profile(",
                "drain_events(",
                ["state.sync_plan(engine.plan());"].as_slice(),
            ),
            (
                "fn capture_trace(",
                "drain_trace_events(",
                [
                    "state.sync_plan(engine.plan());",
                    "tracer.sync_plan(engine.plan());",
                ]
                .as_slice(),
            ),
        ] {
            let body = source.split_once(function).unwrap().1;
            let body = body
                .split_once("fn write_json_report")
                .map_or(body, |(body, _)| body);
            let detached = body
                .find("let detach = session.detach_producers();")
                .expect("terminal detach");
            let terminal = &body[detached..];
            let discovery = terminal
                .find("let plan_changed = if detach.is_ok()")
                .expect("terminal discovery branch");
            let events = terminal.find(event_call).expect("terminal event drain");
            assert!(
                discovery < events,
                "discovery must precede events for {function}"
            );
            let branch = &terminal[discovery..events];
            let (_, after_if) = branch.split_once("if detach.is_ok() {").unwrap();
            let (success, after_else) = after_if.split_once("} else {").unwrap();
            let (failure, _) = after_else.split_once("};").unwrap();
            assert!(success.contains("engine.drain_discovery_terminal(session)?"));
            assert!(!success.contains("engine.drain_discovery(session)?"));
            assert!(failure.contains("engine.drain_discovery_terminal_bounded_from(session)?"));
            assert!(!failure.contains("engine.drain_discovery(session)?"));
            assert!(!failure.contains("engine.drain_discovery_terminal(session)?"));
            for &consumer in consumers {
                let synced = terminal.find(consumer).expect("plan synchronization");
                assert!(
                    synced > discovery && synced < events,
                    "{consumer} ordering for {function}"
                );
            }
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
        let build =
            |engine: &Engine, state: &semantics::State, include_selection, pid_descendant_gaps| {
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
                    None,
                    pid_descendant_gaps,
                    false,
                )
            };

        let clean_metrics = build(&clean, &clean_state, false, 0);
        let truncated_metrics = build(&truncated, &truncated_state, false, 0);
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

        let profile = build(&truncated, &truncated_state, true, 0);
        assert!(profile.interface_selection.selection_truncated);
        assert_eq!(profile.completeness, "PARTIAL");

        assert_eq!(
            clean.interface_selection().providers[0].coverage,
            "absent_covered"
        );
        let gap_profile = build(&clean, &clean_state, true, 1);
        assert_eq!(
            gap_profile.interface_selection.providers[0].coverage,
            "absent_uncovered"
        );
        assert_eq!(gap_profile.pid_descendant_gaps, 1);
        assert_eq!(gap_profile.completeness, "PARTIAL");
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
            None,
            0,
            false,
        );
        let capture = render::CaptureMeta {
            started: "t0",
            ended: "t1",
            kernel: "test",
            policy: CapturePolicy::Allowlisted,
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
            None,
            0,
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
        let (pid_descendant_gaps, capture_tracking_degraded) =
            initial_tracking_evidence(&Scope::Pid(41), true, false);
        assert_eq!((pid_descendant_gaps, capture_tracking_degraded), (0, false));
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
        let j = serde_json::json!({"schema": "pkcs11-scope/observed-profile/v3", "evidence": {}});
        let mut out = AtomicFile::create(&path).unwrap();
        write_json_report(out.file(), &j).expect("shutdown finalization must write the report");
        out.commit().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["schema"], "pkcs11-scope/observed-profile/v3");
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
