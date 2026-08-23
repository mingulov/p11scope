#![allow(dead_code)] // Task 8 wires this reviewed internal lifecycle into the public run path.

use crate::process::PidPin;
use p11scope_manifest::elf::ElfSnapshot;
use std::ffi::{CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::num::NonZeroU64;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn interpreter(&self) -> &Path {
        &self.interpreter
    }

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
            let _ = self.terminate_and_reap();
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
                let _ = self.terminate_and_reap();
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
        let exit_code = self.wait_blocking().unwrap_or(127);
        Err(ExecFailure { errno, exit_code })
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
        assert!(missing.is_reaped());

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
}
