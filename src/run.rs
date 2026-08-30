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
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
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
    /// Resolves normal `execvp` PATH spelling, then accepts only a direct
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
        let prepared = PreparedExecutable::resolve(&program).ok().flatten();
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
                    child_exec_failure(exec_writer.as_raw_fd(), io::Error::last_os_error());
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
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::EINTR) {
                        child_exec_failure(exec_writer.as_raw_fd(), error);
                    }
                }
                libc::execvp(program.as_ptr(), argv.as_ptr());
                child_exec_failure(exec_writer.as_raw_fd(), io::Error::last_os_error());
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
        signal_group(self.pid, libc::SIGKILL)?;
        if !self.pin.wait_ready(Some(Duration::from_secs(5)))? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "child reap timeout",
            ));
        }
        self.wait_blocking()
    }

    pub(crate) fn still_running(&self) -> bool {
        !self.reaped && self.pin.still_the_same()
    }

    pub(crate) fn is_reaped(&self) -> bool {
        self.reaped
    }

    /// Task 8 uses this only after pause authorization, links, and stop debt
    /// are closed. Drop then intentionally leaves the running process alone.
    pub(crate) fn hand_off_running(mut self) -> io::Result<u32> {
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

unsafe fn child_exec_failure(fd: i32, error: io::Error) -> ! {
    let errno = error.raw_os_error().unwrap_or(libc::EIO).to_ne_bytes();
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
        ScopeArg::Cgroup(c) => (
            Scope::Cgroup {
                id: scope::cgroup_id(c)?,
                path: c.clone(),
            },
            None,
        ),
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
        kind,
        policy,
        a.duration,
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
    kind: Kind,
    policy: CapturePolicy,
    duration: Option<Duration>,
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
            capture_profile(engine, session, policy, duration, out, interrupted, owned)
        }
        Kind::Trace => {
            let out = match out {
                OutputSink::Trace(file) => Some(file),
                _ => None,
            };
            capture_trace(engine, session, policy, duration, out, interrupted, owned)
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
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        let cleanup = {
            let marker = marker_never_seen();
            let cancelled = cancelled_by(signals);
            let mut io = SessionPauseIo::new(engine, session, &child, &marker, &cancelled);
            self.coordinator.cleanup(&mut io)
        };
        let end = if end == CaptureEnd::DurationExpired && signals.interrupted() {
            CaptureEnd::Signal
        } else {
            end
        };
        // An interrupt ends this run's own work rather than orphaning it; an
        // expired `--duration` is not a reason to end someone's process, so
        // the child is handed back unless `--kill-on-timeout` asked otherwise.
        // An expired `--duration` is the only end that may hand back a live
        // child, and only after coordinator cleanup succeeds.
        let can_hand_off =
            cleanup.is_ok() && end.allows_handoff(self.kill_on_timeout) && signals.claim_handoff();
        let settled: Result<ChildOutcome> = if can_hand_off {
            stage_handoff(child, &mut self.pending_handoff)
        } else if (end == CaptureEnd::Signal || signals.interrupted()) && child.still_running() {
            settle_after_signal(&mut child, signals)
        } else {
            child
                .terminate_and_reap()
                .map(ChildOutcome::Exited)
                .map_err(|error| anyhow!("run: reaping the owned child: {error}"))
        };
        let settled = match settled {
            Ok(ChildOutcome::Exited(code)) => {
                self.exit_code = Some(code);
                self.still_running = false;
                Ok(())
            }
            Ok(ChildOutcome::TimedOutRunning) => {
                self.exit_code = None;
                self.still_running = true;
                Ok(())
            }
            Err(error) => Err(anyhow!("run: reaping the owned child: {error}")),
        };
        // Both outcomes are retained: a cleanup failure must not be lost
        // behind a reap failure, or the other way round (design §10.3).
        combine_finish_errors(cleanup.map_err(pause_failure), settled)
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
    let Some(child) = pending.take() else {
        return Ok(());
    };
    child
        .hand_off_running()
        .map(|_| ())
        .map_err(|error| anyhow!("run: handing back the owned child: {error}"))
}

fn settle_after_signal(child: &mut OwnedChild, signals: &SignalState) -> Result<ChildOutcome> {
    let signal = signals
        .first_signal()
        .ok_or_else(|| anyhow!("run: signal settlement lost the first signal identity"))?;
    child
        .forward_signal(signal)
        .map_err(|error| anyhow!("run: forwarding signal {signal}: {error}"))?;
    let deadline = Instant::now() + TERM_GRACE;
    let mut second_sigint_forwarded = false;
    loop {
        if signal == libc::SIGINT && !second_sigint_forwarded && signals.sigint_deliveries() >= 2 {
            child
                .forward_signal(libc::SIGINT)
                .map_err(|error| anyhow!("run: forwarding second SIGINT: {error}"))?;
            second_sigint_forwarded = true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
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
        .terminate_and_reap()
        .map(ChildOutcome::Exited)
        .map_err(|error| anyhow!("run: settling after signal: {error}"))
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
        args.kind,
        policy,
        args.duration,
        out,
        &stop,
        Some(&mut owned),
    )?;
    commit_handoff(&mut owned.pending_handoff)?;
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
        eprintln!("attach failed (slot {idx}): {msg}");
    }
    if session.attached_probes() == 0 {
        if let Some((_, first)) = session.attach_failures().first() {
            eprintln!(
                "p11scope: {}/{} attach attempts failed, every one the same way — this almost \
                 always means the environment cannot attach BPF uprobes at all: missing \
                 CAP_BPF/CAP_SYS_ADMIN (or root), a kernel lockdown mode, or a restrictive \
                 kernel.perf_event_paranoid sysctl. First underlying error: {first}",
                session.attach_failures().len(),
                session.attached_probes() + session.attach_failures().len()
            );
        }
    }
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
    ev: &p11scope_ebpf_common::Event,
) -> bool {
    if ev.event_type != p11scope_ebpf_common::event_type::FORK {
        return false;
    }
    let parent_pid = (ev.pid_tgid >> 32) as u32;
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
    eprintln!(
        "p11scope: pause: {error}; the capture continues unpaused and reports pause: partial"
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

#[allow(clippy::too_many_arguments)]
fn capture_profile(
    engine: &mut Engine,
    session: &mut Session,
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
                        tracker: &mut process::Tracker|
     -> Result<u64> {
        let mut drain = session.event_drain()?;
        drain.poll(|ev| {
            if observe_fork(tracker, state, &ev) {
                return;
            }
            let process = identify_tracked(tracker, state, &ev);
            state.observe_process(process, &ev);
            if !state.has_process_state(process) {
                state.retire_process(process);
                tracker.retire(process);
            }
        });
        Ok(drain.malformed())
    };
    let mut malformed_records: u64 = 0;
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
        // 3. Drain call events.
        if profile {
            malformed_records += drain_events(session, &mut state, &mut process_tracker)?;
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
                session,
                &reports,
                kernel_evidence,
                process_tracker.evidence(),
                malformed_records,
                &state,
                engine.pinned().provider_changed(),
                owned.as_deref(),
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
    if profile {
        malformed_records += drain_events(session, &mut state, &mut process_tracker)?;
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
        session,
        &reports,
        kernel_evidence,
        process_tracker.evidence(),
        malformed_records,
        &state,
        engine.pinned().provider_changed(),
        owned.as_deref(),
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
    policy: CapturePolicy,
    duration: Option<Duration>,
    out: Option<std::fs::File>,
    interrupted: &SignalState,
    mut owned: Option<&mut Owned>,
) -> Result<render::Evidence> {
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
        // 3. Drain call events.
        malformed_records += drain_trace_events(
            session,
            &mut state,
            &mut process_tracker,
            &mut tracer,
            stdout,
            &mut stdout_open,
            out_file,
        )?;
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
    malformed_records += drain_trace_events(
        session,
        &mut state,
        &mut process_tracker,
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
    let mut evidence = evidence_for(
        engine,
        session,
        &reports,
        metrics::kernel_evidence(session)?,
        process_tracker.evidence(),
        malformed_records,
        &state,
        engine.pinned().provider_changed(),
        owned.as_deref(),
    );
    evidence.mark_terminal_drain_unproven();
    emit_trace_line(
        &trace::evidence_line(&evidence, policy),
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

/// Drains whatever the ring buffer currently holds, rendering and
/// emitting one line per completed call. Returns the malformed-record
/// count from this drain, to accumulate at the call site.
fn drain_trace_events<W: Write>(
    session: &mut Session,
    state: &mut semantics::State,
    tracker: &mut process::Tracker,
    tracer: &mut trace::Tracer,
    stdout: &mut dyn Write,
    stdout_open: &mut bool,
    out_file: &mut Option<W>,
) -> Result<u64> {
    let mut drain = session.event_drain()?;
    let mut write_error = None;
    drain.poll(|ev| {
        if observe_fork(tracker, state, &ev) {
            return;
        }
        let process = identify_tracked(tracker, state, &ev);
        if write_error.is_none() {
            write_error = emit_trace_line(
                &tracer.on_event_process(&ev, process, state),
                stdout,
                stdout_open,
                out_file,
            )
            .err();
        } else {
            state.observe_process(process, &ev);
        }
        if !state.has_process_state(process) {
            state.retire_process(process);
            tracker.retire(process);
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
    session: &Session,
    reports: &[metrics::SlotReport],
    kernel_evidence: metrics::KernelEvidence,
    tracking_evidence: process::TrackingEvidence,
    malformed_records: u64,
    state: &semantics::State,
    provider_changed: bool,
    owned: Option<&Owned>,
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
    let facts = engine.capture_facts();
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
    let mut ev = render::Evidence {
        table_entries: facts.table_entries(),
        slots: facts.slots(),
        attached_probes: session.attached_probes(),
        attach_failures: session
            .attach_failures()
            .iter()
            .map(|(_, msg)| msg.clone())
            .collect(),
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
        process_tracking_failures: tracking_evidence.failures,
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
        loader_discovery: facts.loader_discovery(),
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
    ev.verdict();
    ev
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
    fn exec_errno_exit_status_and_signal_status_are_exact() {
        let mut missing = spawn("/definitely/missing/p11scope-task7", &[]);
        let failure = missing.release().unwrap_err();
        assert_eq!(failure.errno, libc::ENOENT);
        assert_eq!(failure.exit_code, 127);
        assert!(!missing.is_reaped());
        drop(missing);

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
        let mut missing = spawn("/definitely/missing/p11scope-owned-release", &[]);
        let failure = missing.release().unwrap_err();
        assert_eq!(failure.errno, libc::ENOENT);
        assert_eq!(failure.exit_code, 127);
        assert!(
            !missing.is_reaped(),
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
            let child = spawn("/bin/sleep", &["10"]);
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
        assert!(!CaptureEnd::TargetExit.allows_handoff(false));
        assert!(!CaptureEnd::Signal.allows_handoff(false));
        assert!(!CaptureEnd::Error.allows_handoff(false));
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

    #[test]
    fn fork_only_traffic_does_not_consume_process_tracking_budget() {
        let plan = crate::plan::AttachPlan::from_slots(vec![]);
        let mut state = semantics::State::new(&plan);
        let mut tracker = process::Tracker::with_limits(0, 1);
        for parent in 100_000..100_100u32 {
            let event = p11scope_ebpf_common::Event {
                event_type: p11scope_ebpf_common::event_type::FORK,
                pid_tgid: u64::from(parent) << 32,
                session: u64::from(parent + 1),
                ..Default::default()
            };
            assert!(observe_fork(&mut tracker, &mut state, &event));
        }
        assert_eq!(tracker.evidence(), process::TrackingEvidence::default());
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
        let path = dir.path().join("observed.json");
        std::fs::write(&path, b"stale trailing bytes that must disappear").unwrap();
        let j = serde_json::json!({"schema": "pkcs11-scope/observed-profile/v2", "evidence": {}});
        let mut out = AtomicFile::create(&path).unwrap();
        write_json_report(out.file(), &j).expect("shutdown finalization must write the report");
        out.commit().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed["schema"], "pkcs11-scope/observed-profile/v2");
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
