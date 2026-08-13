//! Manifest trust boundary. Validate the recorded table shape, identify every
//! target through one open file descriptor, and keep those leased descriptors
//! alive through the complete capture while Aya attaches via `/proc/self/fd/*`.

use crate::attach::CapturePolicy;
use p11scope_manifest::identity::{
    IdentityKind, ObjectIdentity, inspect_file, open_object, open_regular,
};
use p11scope_manifest::manifest::*;
use pkcs11_module::{Surface, TableSet, tables_for};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TOTAL_OBJECT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_OBJECTS: usize = p11scope_ebpf_common::MAX_SLOTS as usize;
const MAX_SURFACES: usize = 257; // legacy + the shared acquisition cap
const MAX_FUNCTIONS: usize = 32_768;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DETAIL_BYTES: usize = 4096;
pub const OBJECT_CHANGED_EXIT: i32 = 78;

/// The capture process blocks lease and operator signals before taking any
/// candidate lease. The supervisor consumes this set synchronously through
/// signalfd; a forked worker later unblocks only SIGINT/SIGTERM.
pub struct CaptureSignals {
    fd: OwnedFd,
    previous: libc::sigset_t,
}

impl CaptureSignals {
    pub fn block() -> Result<Self, String> {
        let threads = thread_count()?;
        if threads != 1 {
            return Err(format!(
                "capture signal setup requires a single-threaded process before lease acquisition; found {threads} threads"
            ));
        }
        // SAFETY: both sets are initialized before use; pthread_sigmask writes
        // the previous mask, and signalfd copies the supplied blocked set.
        unsafe {
            let mut blocked = std::mem::zeroed();
            let mut previous = std::mem::zeroed();
            if libc::sigemptyset(&mut blocked) == -1
                || libc::sigaddset(&mut blocked, libc::SIGIO) == -1
                || libc::sigaddset(&mut blocked, libc::SIGINT) == -1
                || libc::sigaddset(&mut blocked, libc::SIGTERM) == -1
            {
                return Err(format!(
                    "preparing capture signal set failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let error = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
            if error != 0 {
                return Err(format!(
                    "blocking capture signals failed: {}",
                    std::io::Error::from_raw_os_error(error)
                ));
            }
            let fd = libc::signalfd(-1, &blocked, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK);
            if fd == -1 {
                libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
                return Err(format!(
                    "creating capture signalfd failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            Ok(Self {
                fd: OwnedFd::from_raw_fd(fd),
                previous,
            })
        }
    }

    fn worker_inherits_mask(self) {
        std::mem::forget(self);
    }
}

impl Drop for CaptureSignals {
    fn drop(&mut self) {
        // SAFETY: previous was filled by pthread_sigmask in block().
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

pub struct SupervisorOutput(OutputMode);

enum OutputMode {
    Trace {
        supervisor_stdout: std::fs::File,
        worker_stdout: std::fs::File,
        supervisor_file: Option<std::fs::File>,
        worker_file: Option<std::fs::File>,
        policy: CapturePolicy,
    },
    Profile {
        worker_stdout: std::fs::File,
        worker_file: Option<std::fs::File>,
        pending: Option<PendingProfile>,
    },
}

impl SupervisorOutput {
    pub fn trace(path: Option<PathBuf>, policy: CapturePolicy) -> Result<Self, String> {
        let supervisor_stdout = duplicate_fd(libc::STDOUT_FILENO)
            .map(std::fs::File::from)
            .map_err(|error| format!("duplicating trace stdout failed: {error}"))?;
        let worker_stdout = supervisor_stdout
            .try_clone()
            .map_err(|error| format!("duplicating worker trace stdout failed: {error}"))?;
        let supervisor_file = path.map(open_trace_output).transpose()?;
        let worker_file = supervisor_file
            .as_ref()
            .map(std::fs::File::try_clone)
            .transpose()
            .map_err(|error| format!("duplicating worker trace output failed: {error}"))?;
        Ok(Self(OutputMode::Trace {
            supervisor_stdout,
            worker_stdout,
            supervisor_file,
            worker_file,
            policy,
        }))
    }

    pub fn profile(path: Option<PathBuf>) -> Result<Self, String> {
        let worker_stdout = duplicate_fd(libc::STDOUT_FILENO)
            .map(std::fs::File::from)
            .map_err(|error| format!("duplicating profile stdout failed: {error}"))?;
        let (worker_file, pending) = match path {
            Some(final_path) => {
                let (file, pending) = PendingProfile::create(final_path)?;
                (Some(file), Some(pending))
            }
            None => (None, None),
        };
        Ok(Self(OutputMode::Profile {
            worker_stdout,
            worker_file,
            pending,
        }))
    }

    fn into_worker(self, objects: VerifiedObjects) -> WorkerContext {
        match self.0 {
            OutputMode::Trace {
                supervisor_stdout,
                worker_stdout,
                supervisor_file,
                worker_file,
                ..
            } => {
                drop(supervisor_stdout);
                drop(supervisor_file);
                WorkerContext {
                    stdout: worker_stdout,
                    output: worker_file,
                    profile: false,
                    objects,
                }
            }
            OutputMode::Profile {
                worker_stdout,
                worker_file,
                pending,
            } => {
                if let Some(pending) = pending {
                    pending.disarm();
                }
                WorkerContext {
                    stdout: worker_stdout,
                    output: worker_file,
                    profile: true,
                    objects,
                }
            }
        }
    }

    fn into_parent(self) -> ParentOutput {
        match self.0 {
            OutputMode::Trace {
                supervisor_stdout,
                worker_stdout,
                supervisor_file,
                worker_file,
                policy,
            } => {
                drop(worker_stdout);
                drop(worker_file);
                ParentOutput::Trace {
                    stdout: supervisor_stdout,
                    file: supervisor_file,
                    policy,
                }
            }
            OutputMode::Profile {
                worker_stdout,
                worker_file,
                pending,
            } => {
                drop(worker_stdout);
                drop(worker_file);
                ParentOutput::Profile { pending }
            }
        }
    }
}

fn open_trace_output(path: PathBuf) -> Result<std::fs::File, String> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| {
            format!(
                "opening regular trace output {} failed: {error}",
                path.display()
            )
        })?;
    if !file
        .metadata()
        .map_err(|error| format!("checking {}: {error}", path.display()))?
        .is_file()
    {
        return Err(format!(
            "trace output {} is not a regular file",
            path.display()
        ));
    }
    Ok(file)
}

struct PendingProfile {
    temp: PathBuf,
    final_path: PathBuf,
    cleanup: bool,
}

impl PendingProfile {
    fn create(final_path: PathBuf) -> Result<(std::fs::File, Self), String> {
        let directory = final_path.parent().unwrap_or_else(|| Path::new("."));
        let name = final_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("profile");
        for sequence in 0..128u32 {
            let temp = directory.join(format!(
                ".{name}.p11scope.{}.{}.tmp",
                std::process::id(),
                sequence
            ));
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)
            {
                Ok(file) => {
                    return Ok((
                        file,
                        Self {
                            temp,
                            final_path,
                            cleanup: true,
                        },
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "creating temporary profile beside {} failed: {error}",
                        final_path.display()
                    ));
                }
            }
        }
        Err(format!(
            "cannot allocate a unique temporary profile beside {}",
            final_path.display()
        ))
    }

    fn disarm(mut self) {
        self.cleanup = false;
    }

    fn publish(mut self) -> Result<(), String> {
        std::fs::rename(&self.temp, &self.final_path).map_err(|error| {
            format!(
                "publishing profile {} failed: {error}",
                self.final_path.display()
            )
        })?;
        self.cleanup = false;
        Ok(())
    }
}

impl Drop for PendingProfile {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = std::fs::remove_file(&self.temp);
        }
    }
}

enum ParentOutput {
    Trace {
        stdout: std::fs::File,
        file: Option<std::fs::File>,
        policy: CapturePolicy,
    },
    Profile {
        pending: Option<PendingProfile>,
    },
}

impl ParentOutput {
    fn abort(&mut self) -> Result<(), String> {
        let Self::Trace {
            stdout,
            file,
            policy,
        } = self
        else {
            return Ok(());
        };
        let record = format!(
            "\n{}\n",
            crate::trace::abort_evidence_line(*policy, "object_lease_break")
        );
        debug_assert!(record.len() < 512);
        if let Some(file) = file {
            file.write_all(record.as_bytes())
                .map_err(|error| format!("writing mandatory trace abort record failed: {error}"))?;
            file.flush().map_err(|error| {
                format!("flushing mandatory trace abort record failed: {error}")
            })?;
            file.sync_data()
                .map_err(|error| format!("syncing mandatory trace abort record failed: {error}"))?;
        }
        bounded_stdout_write(stdout, record.as_bytes());
        Ok(())
    }

    fn finish(self, completed: bool, status: libc::c_int) -> Result<(), String> {
        if let Self::Profile {
            pending: Some(pending),
        } = self
            && completed
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0
        {
            pending.publish()?;
        }
        Ok(())
    }
}

pub struct WorkerContext {
    stdout: std::fs::File,
    output: Option<std::fs::File>,
    profile: bool,
    objects: VerifiedObjects,
}

impl WorkerContext {
    pub fn stdout(&mut self) -> &mut std::fs::File {
        &mut self.stdout
    }

    pub fn output(&mut self) -> Option<&mut std::fs::File> {
        self.output.as_mut()
    }

    pub fn objects(&self) -> &VerifiedObjects {
        &self.objects
    }

    pub fn output_parts(
        &mut self,
    ) -> (
        &mut std::fs::File,
        &mut Option<std::fs::File>,
        &VerifiedObjects,
    ) {
        (&mut self.stdout, &mut self.output, &self.objects)
    }

    /// Call after the capture loop has installed its SIGINT handler. SIGTERM
    /// is restored to its terminating default before either signal is unblocked.
    pub fn unblock_operator_signals(&mut self) -> Result<(), String> {
        // SAFETY: the initialized set is used only to unblock these two
        // operator signals in the single-threaded capture worker.
        unsafe {
            if libc::signal(libc::SIGTERM, libc::SIG_DFL) == libc::SIG_ERR {
                return Err(format!(
                    "resetting worker SIGTERM disposition failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut operators = std::mem::zeroed();
            if libc::sigemptyset(&mut operators) == -1
                || libc::sigaddset(&mut operators, libc::SIGINT) == -1
                || libc::sigaddset(&mut operators, libc::SIGTERM) == -1
            {
                return Err(format!(
                    "preparing worker operator signal set failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let error = libc::pthread_sigmask(libc::SIG_UNBLOCK, &operators, std::ptr::null_mut());
            if error != 0 {
                return Err(format!(
                    "unblocking worker operator signals failed: {}",
                    std::io::Error::from_raw_os_error(error)
                ));
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        self.stdout
            .flush()
            .map_err(|error| format!("flushing worker stdout failed: {error}"))?;
        if let Some(file) = &mut self.output {
            file.flush()
                .map_err(|error| format!("flushing worker output failed: {error}"))?;
            if self.profile {
                file.sync_all()
                    .map_err(|error| format!("syncing temporary profile failed: {error}"))?;
            } else {
                file.sync_data()
                    .map_err(|error| format!("syncing trace output failed: {error}"))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorOutcome {
    Exited(i32),
    Signaled(i32),
    LeaseBroken,
}

pub fn mirror_worker_signal(signal: i32) -> ! {
    // SAFETY: the signal came from WTERMSIG. Restoring its disposition and
    // unblocking it makes the supervisor preserve the worker's signal status
    // even when the invoking shell supplied SIG_IGN or a blocked mask.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        let mut unblocked = std::mem::zeroed();
        libc::sigemptyset(&mut unblocked);
        libc::sigaddset(&mut unblocked, signal);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblocked, std::ptr::null_mut());
        libc::raise(signal);
        libc::_exit(128 + signal)
    }
}

pub fn supervise_capture(
    signals: CaptureSignals,
    objects: VerifiedObjects,
    output: SupervisorOutput,
    worker: impl FnOnce(&mut WorkerContext) -> Result<(), String>,
) -> Result<SupervisorOutcome, String> {
    let threads = thread_count()?;
    if threads != 1 {
        return Err(format!(
            "capture supervisor requires a single-threaded process before fork; found {threads} threads"
        ));
    }

    let (parent_control, child_control) = socket_pair()?;
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: the process is proven single-threaded at this exact point. The
    // child touches only owned descriptors/state and terminates with _exit.
    let child = unsafe { libc::fork() };
    if child == -1 {
        return Err(format!(
            "forking capture worker failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if child == 0 {
        worker_process(
            parent_pid,
            parent_control,
            child_control,
            signals,
            objects,
            output,
            worker,
        );
    }

    drop(child_control);
    drop(worker);
    let mut parent_output = output.into_parent();
    let pidfd = match pidfd_open(child) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            unsafe { libc::kill(child, libc::SIGKILL) };
            let _ = wait_child(child);
            return Err(format!("opening capture worker pidfd failed: {error}"));
        }
    };

    let mut ready = false;
    let mut completed = false;
    let mut worker_failed = false;
    let mut lease_broken = false;
    let mut operator_deadline: Option<Instant> = None;
    let mut malformed_completion = false;
    let mut deadline_expired = false;

    let protocol = (|| -> Result<(), String> {
        while !ready {
            match poll_supervisor(&signals, &parent_control, &pidfd, operator_deadline)? {
                SupervisorEvent::Signal(signal) if signal == libc::SIGIO => {
                    lease_broken = true;
                    return Ok(());
                }
                SupervisorEvent::Signal(signal)
                    if signal == libc::SIGINT || signal == libc::SIGTERM =>
                {
                    pidfd_send_signal(&pidfd, signal)?;
                    operator_deadline.get_or_insert_with(|| Instant::now() + OPERATOR_GRACE);
                }
                SupervisorEvent::Control(READY) => ready = true,
                SupervisorEvent::Control(_) => {
                    malformed_completion = true;
                    return Ok(());
                }
                SupervisorEvent::Exited => return Ok(()),
                SupervisorEvent::Deadline => {
                    deadline_expired = true;
                    return Ok(());
                }
                SupervisorEvent::Signal(_) => {}
            }
        }

        if objects.ensure_stable().is_err()
            || pending_lease_break(&signals, &pidfd, &mut operator_deadline)?
        {
            lease_broken = true;
            return Ok(());
        }
        send_packet(&parent_control, GO)?;

        while !lease_broken && !malformed_completion {
            match poll_supervisor(&signals, &parent_control, &pidfd, operator_deadline)? {
                SupervisorEvent::Signal(signal) if signal == libc::SIGIO => {
                    lease_broken = true;
                    return Ok(());
                }
                SupervisorEvent::Signal(signal)
                    if signal == libc::SIGINT || signal == libc::SIGTERM =>
                {
                    pidfd_send_signal(&pidfd, signal)?;
                    operator_deadline.get_or_insert_with(|| Instant::now() + OPERATOR_GRACE);
                }
                SupervisorEvent::Control(DONE) if !completed => completed = true,
                SupervisorEvent::Control(FAILED) if !completed && !worker_failed => {
                    worker_failed = true;
                    return Ok(());
                }
                SupervisorEvent::Control(_) => {
                    malformed_completion = true;
                    return Ok(());
                }
                SupervisorEvent::Exited => return Ok(()),
                SupervisorEvent::Deadline => {
                    deadline_expired = true;
                    return Ok(());
                }
                SupervisorEvent::Signal(_) => {}
            }
        }
        Ok(())
    })();

    let mut supervisor_error = protocol.err();
    if lease_broken
        || worker_failed
        || malformed_completion
        || deadline_expired
        || supervisor_error.is_some()
    {
        if let Err(error) = pidfd_send_signal(&pidfd, libc::SIGKILL) {
            supervisor_error.get_or_insert(error);
        }
    }
    if let Err(error) = wait_pidfd(&pidfd) {
        supervisor_error.get_or_insert(error);
    }
    let status = wait_child(child);
    if let Err(error) = &status {
        supervisor_error.get_or_insert_with(|| error.clone());
    }
    if objects.ensure_stable().is_err() {
        lease_broken = true;
    }
    match pending_lease_break(&signals, &pidfd, &mut operator_deadline) {
        Ok(broken) => lease_broken |= broken,
        Err(error) => {
            lease_broken = true;
            supervisor_error.get_or_insert(error);
        }
    }
    drop(objects);

    if lease_broken {
        if let Err(error) = parent_output.abort() {
            eprintln!("p11scope: {error}");
        }
        return Ok(SupervisorOutcome::LeaseBroken);
    }
    let status = status?;
    parent_output.finish(
        completed && !worker_failed && !malformed_completion && supervisor_error.is_none(),
        status,
    )?;
    if let Some(error) = supervisor_error {
        return Err(error);
    }
    if libc::WIFEXITED(status) {
        Ok(SupervisorOutcome::Exited(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Ok(SupervisorOutcome::Signaled(libc::WTERMSIG(status)))
    } else {
        Err("capture worker ended with an unknown wait status".into())
    }
}

fn thread_count() -> Result<usize, String> {
    std::fs::read_dir("/proc/self/task")
        .map_err(|error| format!("checking capture thread count failed: {error}"))?
        .try_fold(0usize, |count, entry| entry.map(|_| count + 1))
        .map_err(|error| format!("checking capture thread count failed: {error}"))
}

const READY: u8 = b'R';
const GO: u8 = b'G';
const DONE: u8 = b'D';
const FAILED: u8 = b'F';
const OPERATOR_GRACE: Duration = Duration::from_secs(2);

fn worker_process(
    parent_pid: libc::pid_t,
    parent_control: OwnedFd,
    child_control: OwnedFd,
    signals: CaptureSignals,
    objects: VerifiedObjects,
    output: SupervisorOutput,
    worker: impl FnOnce(&mut WorkerContext) -> Result<(), String>,
) -> ! {
    drop(parent_control);
    signals.worker_inherits_mask();
    // SAFETY: scalar prctl arguments request uncatchable teardown if the
    // supervisor disappears. The getppid recheck closes the setup race.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == -1
        || unsafe { libc::getppid() } != parent_pid
        || send_packet(&child_control, READY).is_err()
        || receive_packet(&child_control) != Ok(Some(GO))
    {
        unsafe { libc::_exit(70) }
    }
    let mut context = output.into_worker(objects);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker(&mut context)));
    let code = match result {
        Ok(Ok(())) => match context.finish() {
            Ok(()) if send_packet(&child_control, DONE).is_ok() => 0,
            Ok(()) => 71,
            Err(error) => {
                eprintln!("p11scope: {error}");
                1
            }
        },
        Ok(Err(error)) => {
            eprintln!("p11scope: {error}");
            1
        }
        Err(_) => 101,
    };
    if code != 0 {
        let _ = send_packet(&child_control, FAILED);
    }
    unsafe { libc::_exit(code) }
}

enum SupervisorEvent {
    Signal(i32),
    Control(u8),
    Exited,
    Deadline,
}

fn poll_supervisor(
    signals: &CaptureSignals,
    control: &OwnedFd,
    pidfd: &OwnedFd,
    deadline: Option<Instant>,
) -> Result<SupervisorEvent, String> {
    let timeout = deadline
        .map(|deadline| deadline.saturating_duration_since(Instant::now()))
        .map(|remaining| remaining.as_millis().min(i32::MAX as u128) as i32)
        .unwrap_or(-1);
    let mut fds = [
        libc::pollfd {
            fd: signals.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        },
        libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    loop {
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if result > 0 {
            break;
        }
        if result == 0 {
            return Ok(SupervisorEvent::Deadline);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("polling capture supervisor failed: {error}"));
        }
    }
    if fds[0].revents & libc::POLLIN != 0 {
        return read_signal(signals).map(SupervisorEvent::Signal);
    }
    if fds[1].revents & libc::POLLIN != 0 {
        return Ok(match receive_packet(control)? {
            Some(packet) => SupervisorEvent::Control(packet),
            None => SupervisorEvent::Exited,
        });
    }
    if fds[2].revents & libc::POLLIN != 0 {
        return Ok(SupervisorEvent::Exited);
    }
    if fds[1].revents & libc::POLLHUP != 0 {
        return Ok(SupervisorEvent::Exited);
    }
    Err("capture supervisor poll returned no recognized event".into())
}

fn read_signal(signals: &CaptureSignals) -> Result<i32, String> {
    let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
    let read = unsafe {
        libc::read(
            signals.fd.as_raw_fd(),
            (&mut info as *mut libc::signalfd_siginfo).cast(),
            std::mem::size_of::<libc::signalfd_siginfo>(),
        )
    };
    if read == std::mem::size_of::<libc::signalfd_siginfo>() as isize {
        Ok(info.ssi_signo as i32)
    } else if read == -1 {
        Err(format!(
            "reading capture signalfd failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Err("capture signalfd returned a short record".into())
    }
}

fn pending_lease_break(
    signals: &CaptureSignals,
    pidfd: &OwnedFd,
    operator_deadline: &mut Option<Instant>,
) -> Result<bool, String> {
    loop {
        let mut pollfd = libc::pollfd {
            fd: signals.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result == 0 {
            return Ok(false);
        }
        if result == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("polling capture signalfd failed: {error}"));
        }
        match read_signal(signals)? {
            libc::SIGIO => return Ok(true),
            signal @ (libc::SIGINT | libc::SIGTERM) => {
                pidfd_send_signal(pidfd, signal)?;
                operator_deadline.get_or_insert_with(|| Instant::now() + OPERATOR_GRACE);
            }
            _ => {}
        }
    }
}

fn socket_pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } == -1
    {
        return Err(format!(
            "creating capture start barrier failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn send_packet(fd: &OwnedFd, packet: u8) -> Result<(), String> {
    let sent = unsafe { libc::send(fd.as_raw_fd(), (&packet as *const u8).cast(), 1, 0) };
    if sent == 1 {
        Ok(())
    } else {
        Err(format!(
            "sending capture supervisor record failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn receive_packet(fd: &OwnedFd) -> Result<Option<u8>, String> {
    let mut packet = 0u8;
    loop {
        let received = unsafe { libc::recv(fd.as_raw_fd(), (&mut packet as *mut u8).cast(), 1, 0) };
        if received == 1 {
            return Ok(Some(packet));
        }
        if received == 0 {
            return Ok(None);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("reading capture supervisor record failed: {error}"));
        }
    }
}

fn pidfd_open(pid: libc::pid_t) -> std::io::Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn pidfd_send_signal(pidfd: &OwnedFd, signal: i32) -> Result<(), String> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(format!(
                "signaling capture worker through pidfd failed: {error}"
            ));
        }
    }
    Ok(())
}

fn wait_pidfd(pidfd: &OwnedFd) -> Result<(), String> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut pollfd, 1, -1) };
        if result > 0 && pollfd.revents & libc::POLLIN != 0 {
            return Ok(());
        }
        if result > 0 {
            return Err(format!(
                "waiting for capture worker pidfd returned events {:#x}",
                pollfd.revents
            ));
        }
        if result == -1 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            return Err(format!(
                "waiting for capture worker pidfd failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
}

fn wait_child(pid: libc::pid_t) -> Result<libc::c_int, String> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        if waited == pid {
            return Ok(status);
        }
        let error = std::io::Error::last_os_error();
        if waited != -1 || error.kind() != std::io::ErrorKind::Interrupted {
            return Err(format!("waiting for capture worker failed: {error}"));
        }
    }
}

fn bounded_stdout_write(stdout: &mut std::fs::File, bytes: &[u8]) {
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return;
    }
    let mut pollfd = libc::pollfd {
        fd: stdout.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    if unsafe { libc::poll(&mut pollfd, 1, 20) } > 0 {
        let _ = stdout.write(bytes);
    }
}

fn duplicate_fd(fd: libc::c_int) -> std::io::Result<OwnedFd> {
    // SAFETY: fcntl duplicates the live descriptor and returns independent fd
    // ownership on success.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: successful F_DUPFD_CLOEXEC returned a new owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

/// Reads one regular, bounded UTF-8 manifest. The descriptor is opened before
/// metadata and content are inspected, so replacing its pathname cannot mix
/// two files in one parse.
pub fn read_manifest(path: &Path) -> Result<String, String> {
    let file = open_regular(path)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest is {} bytes; limit is {MAX_MANIFEST_BYTES}",
            metadata.len()
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read failed: {error}"))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "manifest grew beyond the {MAX_MANIFEST_BYTES}-byte limit"
        ));
    }
    String::from_utf8(bytes).map_err(|error| format!("manifest is not UTF-8: {error}"))
}

#[derive(Debug)]
pub struct VerifiedObjects {
    files: BTreeMap<String, std::fs::File>,
    identities: BTreeMap<String, ObjectIdentity>,
    lease: LeaseMonitor,
}

impl VerifiedObjects {
    /// Path Aya may reopen without re-resolving the untrusted manifest path.
    pub fn attach_path(&self, original: &str) -> Result<PathBuf, String> {
        self.files
            .get(original)
            .map(|file| PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())))
            .ok_or_else(|| format!("object path {original:?} was not verified"))
    }

    /// Fails closed if any writer attempted to change an authorized object.
    /// The leases are held until this value is dropped, so an intact lease
    /// also proves that the bytes hashed at authorization are still current.
    pub fn ensure_stable(&self) -> Result<(), String> {
        self.lease.ensure(self.files.values())
    }

    /// Re-hashes every pinned object after attachment. The held lease is the
    /// continuity guarantee; this second identity check also catches a
    /// filesystem that reported a lease but did not preserve the bytes.
    pub fn verify_stable(&self) -> Result<(), String> {
        self.ensure_stable()?;
        for (path, file) in &self.files {
            let current = inspect_file(file)
                .map_err(|error| format!("rechecking authorized object {path}: {error}"))?
                .identity;
            let expected = &self.identities[path];
            if current.kind != expected.kind
                || current.value != expected.value
                || current.sha256 != expected.sha256
            {
                return Err(format!(
                    "authorized object {path} changed while capture was starting"
                ));
            }
        }
        self.ensure_stable()
    }
}

#[derive(Debug)]
pub(crate) struct LeaseMonitor;

impl LeaseMonitor {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) fn acquire(&self, file: &std::fs::File) -> Result<(), String> {
        // SAFETY: fcntl receives a live descriptor, this single-threaded
        // process's pid as the positive F_SETOWN recipient, and the Linux read
        // lease type. Ownership is set before acquisition so no lease-break
        // notification can race with recipient selection.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETOWN, libc::getpid()) } == -1 {
            return Err(format!(
                "setting object lease signal owner failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } == -1 {
            return Err(format!(
                "cannot acquire required read lease: {}; the observer needs file ownership or CAP_LEASE, and the object must have no writer",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure<'a>(
        &self,
        files: impl IntoIterator<Item = &'a std::fs::File>,
    ) -> Result<(), String> {
        for file in files {
            // SAFETY: F_GETLEASE only queries the lease on this live fd.
            let lease = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLEASE) };
            if lease == -1 {
                return Err(format!(
                    "checking object read lease failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if lease != libc::F_RDLCK {
                return Err("an authorized object changed while capture was active".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct SynchronousLeaseMonitor {
    blocked: libc::sigset_t,
    previous: libc::sigset_t,
}

impl SynchronousLeaseMonitor {
    pub(crate) fn new() -> Result<Self, String> {
        // SAFETY: both sets are initialized before use and pthread_sigmask
        // writes the caller-owned previous mask.
        unsafe {
            let mut blocked = std::mem::zeroed();
            let mut previous = std::mem::zeroed();
            if libc::sigemptyset(&mut blocked) == -1
                || libc::sigaddset(&mut blocked, libc::SIGIO) == -1
            {
                return Err(format!(
                    "preparing provenance lease signal set failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let error = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut previous);
            if error != 0 {
                return Err(format!(
                    "blocking provenance lease signals failed: {}",
                    std::io::Error::from_raw_os_error(error)
                ));
            }
            let monitor = Self { blocked, previous };
            if monitor.consume_signal()? {
                object_changed_exit();
            }
            Ok(monitor)
        }
    }

    pub(crate) fn acquire(&self, file: &std::fs::File) -> Result<(), String> {
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETOWN, libc::getpid()) } == -1 {
            return Err(format!(
                "setting provenance lease signal owner failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } == -1 {
            return Err(format!(
                "cannot acquire required read lease: {}; the observer needs file ownership or CAP_LEASE, and the object must have no writer",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(crate) fn ensure<'a>(
        &self,
        files: impl IntoIterator<Item = &'a std::fs::File>,
    ) -> Result<(), String> {
        if self.consume_signal()? {
            object_changed_exit();
        }
        for file in files {
            let lease = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLEASE) };
            if lease == -1 {
                return Err(format!(
                    "checking provenance read lease failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if lease != libc::F_RDLCK {
                object_changed_exit();
            }
        }
        if self.consume_signal()? {
            object_changed_exit();
        }
        Ok(())
    }

    fn consume_signal(&self) -> Result<bool, String> {
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let mut consumed = false;
        loop {
            // SAFETY: SIGIO is blocked in this thread and both pointers refer
            // to initialized caller-owned values for the duration of the call.
            let signal =
                unsafe { libc::sigtimedwait(&self.blocked, std::ptr::null_mut(), &timeout) };
            if signal == libc::SIGIO {
                consumed = true;
                continue;
            }
            if signal == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EAGAIN) {
                    return Ok(consumed);
                }
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(format!("reading provenance lease signal failed: {error}"));
            }
            return Err(format!(
                "unexpected signal {signal} while reading provenance lease notifications"
            ));
        }
    }
}

fn object_changed_exit() -> ! {
    // Preserve the established CLI contract while consuming the blocked
    // notification synchronously at an authorization checkpoint.
    unsafe { libc::_exit(OBJECT_CHANGED_EXIT) }
}

impl Drop for SynchronousLeaseMonitor {
    fn drop(&mut self) {
        if self.consume_signal() != Ok(false) {
            object_changed_exit();
        }
        // SAFETY: previous was filled by pthread_sigmask in new().
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.previous, std::ptr::null_mut());
        }
    }
}

fn bounded(label: &str, value: &str, limit: usize, problems: &mut Vec<String>) {
    if value.len() > limit {
        problems.push(format!(
            "{label} is {} bytes; limit is {limit}",
            value.len()
        ));
    }
}

fn valid_hex(value: &str) -> bool {
    value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_identity(label: &str, identity: &ObjectIdentity, problems: &mut Vec<String>) {
    match (
        &identity.kind,
        &identity.value,
        &identity.sha256,
        identity.reusable,
    ) {
        (IdentityKind::GnuBuildId, Some(value), Some(sha256), true) => {
            if value.is_empty() || value.len() > 128 || !valid_hex(value) {
                problems.push(format!("{label} has an invalid GNU build-id"));
            }
            if sha256.len() != 64 || !valid_hex(sha256) {
                problems.push(format!("{label} has an invalid content SHA-256"));
            }
        }
        (IdentityKind::Sha256, Some(value), Some(sha256), true) => {
            if value.len() != 64 || !valid_hex(value) || value != sha256 {
                problems.push(format!("{label} has an invalid SHA-256 identity"));
            }
        }
        _ => problems.push(format!(
            "{label} identity is not reusable and has no mandatory whole-file SHA-256"
        )),
    }
    if let Some(note) = &identity.note {
        bounded("identity note", note, MAX_DETAIL_BYTES, problems);
    }
}

fn expected_surface(surface: &SurfaceRecord) -> Result<(Vec<&'static str>, &'static str), String> {
    let version = surface
        .version
        .ok_or_else(|| "walked surface has no version".to_string())?;
    let version = cryptoki_sys::CK_VERSION {
        major: version.major,
        minor: version.minor,
    };
    let source = match surface.source {
        SurfaceSource::LegacyFunctionList => Surface::LegacyFunctionList { version },
        SurfaceSource::Interface { .. } => Surface::StandardInterface { version },
    };
    let (spans, normal_walk) = match tables_for(source) {
        TableSet::Walk(spans) => (spans, "full"),
        TableSet::WalkKnownPrefix(spans) => (spans, "known_prefix"),
        TableSet::Refuse => return Ok((Vec::new(), "refused")),
    };
    let forced_prefix = matches!(
        surface.source,
        SurfaceSource::Interface {
            classification: InterfaceClassification::CorroboratedStandardPrefix,
            ..
        }
    );
    Ok((
        spans
            .iter()
            .flat_map(|span| span.fields().iter().map(|field| field.name))
            .collect(),
        if forced_prefix {
            "known_prefix"
        } else {
            normal_walk
        },
    ))
}

fn walk_name(walk: &WalkOutcome) -> &'static str {
    match walk {
        WalkOutcome::Full => "full",
        WalkOutcome::KnownPrefix => "known_prefix",
        WalkOutcome::Refused => "refused",
        WalkOutcome::NotWalked => "not_walked",
        WalkOutcome::Unreadable { .. } => "unreadable",
    }
}

fn validate_structure(m: &Manifest) -> Vec<String> {
    let mut problems = Vec::new();
    if m.schema != SCHEMA {
        problems.push(format!("manifest schema {:?} is not {SCHEMA:?}", m.schema));
    }
    bounded("module path", &m.module_path, MAX_PATH_BYTES, &mut problems);
    if !Path::new(&m.module_path).is_absolute() {
        problems.push("module path must be absolute".into());
    }
    if m.objects.is_empty() || m.objects.len() > MAX_OBJECTS {
        problems.push(format!(
            "manifest has {} objects; expected 1..={MAX_OBJECTS}",
            m.objects.len()
        ));
    }
    if m.surfaces.len() > MAX_SURFACES {
        problems.push(format!(
            "manifest has {} surfaces; limit is {MAX_SURFACES}",
            m.surfaces.len()
        ));
    }
    if m.vendor_interfaces.len() > 256 {
        problems.push(format!(
            "manifest has {} vendor interfaces; limit is 256",
            m.vendor_interfaces.len()
        ));
    }
    if m.alias_groups.len() > p11scope_ebpf_common::MAX_SLOTS as usize {
        problems.push(format!(
            "manifest has too many alias groups: {}",
            m.alias_groups.len()
        ));
    }

    let mut object_ids = BTreeSet::new();
    let mut object_paths = BTreeSet::new();
    for (position, object) in m.objects.iter().enumerate() {
        bounded("object path", &object.path, MAX_PATH_BYTES, &mut problems);
        if !Path::new(&object.path).is_absolute() {
            problems.push(format!("object {} path must be absolute", object.id));
        }
        if object.id as usize != position {
            problems.push(format!(
                "object ids must be dense: position {position} has id {}",
                object.id
            ));
        }
        if !object_ids.insert(object.id) {
            problems.push(format!("duplicate object id {}", object.id));
        }
        if !object_paths.insert(object.path.as_str()) {
            problems.push(format!("duplicate object path {:?}", object.path));
        }
        validate_identity(
            &format!("object {}", object.id),
            &object.identity,
            &mut problems,
        );
    }
    if m.objects
        .first()
        .is_some_and(|object| object.path != m.module_path)
    {
        problems.push("object id 0 path must equal module_path".into());
    }

    if m.provenance_objects.is_empty() || m.provenance_objects.len() > MAX_OBJECTS {
        problems.push(format!(
            "manifest has {} provenance objects; expected 1..={MAX_OBJECTS}",
            m.provenance_objects.len()
        ));
    }
    let mut provenance_keys = BTreeSet::new();
    let mut provenance_paths = BTreeSet::new();
    let mut provenance_identities = BTreeSet::new();
    for object in &m.provenance_objects {
        bounded(
            "provenance object path",
            &object.path,
            MAX_PATH_BYTES,
            &mut problems,
        );
        if !Path::new(&object.path).is_absolute() {
            problems.push(format!(
                "provenance object path must be absolute: {:?}",
                object.path
            ));
        }
        if object.inode == 0 {
            problems.push(format!(
                "provenance object {:?} has a zero inode",
                object.path
            ));
        }
        if !provenance_keys.insert((object.device_major, object.device_minor, object.inode)) {
            problems.push("duplicate provenance device/inode".into());
        }
        if !provenance_paths.insert(object.path.as_str()) {
            problems.push(format!(
                "duplicate provenance object path {:?}",
                object.path
            ));
        }
        validate_identity(
            &format!("provenance object {:?}", object.path),
            &object.identity,
            &mut problems,
        );
        if let Some(sha256) = &object.identity.sha256 {
            provenance_identities.insert(sha256.as_str());
        }
    }
    for object in &m.objects {
        if object
            .identity
            .sha256
            .as_deref()
            .is_some_and(|sha256| !provenance_identities.contains(sha256))
        {
            problems.push(format!(
                "object {} identity is absent from the executable provenance closure",
                object.id
            ));
        }
    }

    let mut legacy_seen = false;
    let mut interface_indices = BTreeSet::new();
    let mut total_functions = 0usize;
    for (surface_index, surface) in m.surfaces.iter().enumerate() {
        if let Acquisition::Error { detail } = &surface.acquisition {
            bounded(
                "surface acquisition error",
                detail,
                MAX_DETAIL_BYTES,
                &mut problems,
            );
        }
        if let WalkOutcome::Unreadable { detail } = &surface.walk {
            bounded(
                "surface walk error",
                detail,
                MAX_DETAIL_BYTES,
                &mut problems,
            );
        }
        match &surface.source {
            SurfaceSource::LegacyFunctionList => {
                if legacy_seen {
                    problems.push(
                        "manifest contains more than one legacy function-list surface".into(),
                    );
                }
                legacy_seen = true;
                if matches!(surface.acquisition, Acquisition::Empty) {
                    problems.push("legacy acquisition cannot be empty".into());
                }
            }
            SurfaceSource::Interface {
                index,
                raw_name_hex,
                name_lossy,
                name_error,
                classification,
                ..
            } => {
                if *index >= 256 || !interface_indices.insert(*index) {
                    problems.push(format!("invalid or duplicate interface index {index}"));
                }
                if !matches!(surface.acquisition, Acquisition::Ok) {
                    problems.push(format!("interface {index} acquisition must be ok"));
                }
                if let Some(raw) = raw_name_hex {
                    if raw.len() > 512 || !valid_hex(raw) {
                        problems.push(format!("interface {index} has invalid raw_name_hex"));
                    }
                }
                if let Some(name) = name_lossy {
                    bounded("interface name", name, 768, &mut problems);
                }
                if let Some(error) = name_error {
                    bounded(
                        "interface name error",
                        error,
                        MAX_DETAIL_BYTES,
                        &mut problems,
                    );
                }
                let exact_raw = raw_name_hex
                    .as_deref()
                    .is_some_and(|raw| raw.eq_ignore_ascii_case("504b4353203131"));
                match classification {
                    InterfaceClassification::ExactStandard
                        if !exact_raw
                            || name_lossy.as_deref() != Some("PKCS 11")
                            || name_error.is_some() =>
                    {
                        problems.push(format!(
                            "interface {index} exact_standard classification disagrees with its recorded name"
                        ));
                    }
                    InterfaceClassification::CorroboratedStandardPrefix if exact_raw => {
                        problems.push(format!(
                            "interface {index} corroborated classification is invalid for an exact standard name"
                        ));
                    }
                    InterfaceClassification::CorroboratedStandardPrefix
                        if !matches!(surface.walk, WalkOutcome::KnownPrefix) =>
                    {
                        problems.push(format!(
                            "corroborated interface {index} must record a known-prefix walk"
                        ));
                    }
                    _ => {}
                }
            }
        }
        total_functions = total_functions.saturating_add(surface.functions.len());
        if total_functions > MAX_FUNCTIONS {
            problems.push(format!(
                "manifest has more than {MAX_FUNCTIONS} function records"
            ));
            break;
        }
        for function in &surface.functions {
            bounded("function name", &function.name, 128, &mut problems);
            if let Resolution::Resolved { object, .. } = function.resolution
                && !object_ids.contains(&object)
            {
                problems.push(format!(
                    "{} refers to missing object id {object}",
                    function.name
                ));
            }
            if let Resolution::UnusableFile { reason, path_hex } = &function.resolution {
                bounded(
                    "unusable-file reason",
                    reason,
                    MAX_DETAIL_BYTES,
                    &mut problems,
                );
                if path_hex.len() > MAX_PATH_BYTES * 2 || !valid_hex(path_hex) {
                    problems.push(format!("{} has invalid unusable path hex", function.name));
                }
            }
        }

        if !matches!(surface.acquisition, Acquisition::Ok) {
            if !surface.functions.is_empty() || !matches!(surface.walk, WalkOutcome::NotWalked) {
                problems.push(format!(
                    "surface {surface_index} acquired as non-ok must be not_walked and empty"
                ));
            }
            continue;
        }
        if matches!(surface.walk, WalkOutcome::Unreadable { .. }) {
            if !surface.functions.is_empty() {
                problems.push(format!("unreadable surface {surface_index} must be empty"));
            }
            continue;
        }
        if matches!(surface.walk, WalkOutcome::NotWalked) {
            if surface.version.is_some() || !surface.functions.is_empty() {
                problems.push(format!(
                    "not-walked surface {surface_index} must have no version or functions"
                ));
            }
            continue;
        }
        match expected_surface(surface) {
            Ok((expected, expected_walk)) => {
                if walk_name(&surface.walk) != expected_walk {
                    problems.push(format!(
                        "surface {surface_index} walk {:?} disagrees with its source/version; expected {expected_walk}",
                        surface.walk
                    ));
                }
                let actual: Vec<&str> = surface
                    .functions
                    .iter()
                    .map(|function| function.name.as_str())
                    .collect();
                if actual != expected {
                    problems.push(format!(
                        "surface {surface_index} does not match canonical function order (got {}, expected {})",
                        actual.len(),
                        expected.len()
                    ));
                }
            }
            Err(error) => problems.push(format!("surface {surface_index}: {error}")),
        }
    }

    if !legacy_seen {
        problems.push("manifest must contain exactly one legacy acquisition surface".into());
    }

    for vendor in &m.vendor_interfaces {
        if vendor.index >= 256 || !interface_indices.insert(vendor.index) {
            problems.push(format!(
                "invalid or duplicate interface index {}",
                vendor.index
            ));
        }
        if let Some(raw) = &vendor.raw_name_hex
            && (raw.len() > 512 || !valid_hex(raw))
        {
            problems.push(format!(
                "vendor interface {} has invalid raw_name_hex",
                vendor.index
            ));
        }
        for (label, value) in [
            ("vendor interface name", vendor.name_lossy.as_deref()),
            ("vendor interface name error", vendor.name_error.as_deref()),
            (
                "vendor interface version error",
                vendor.version_error.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                bounded(label, value, MAX_DETAIL_BYTES, &mut problems);
            }
        }
    }
    if let Acquisition::Error { detail } = &m.interface_list {
        bounded(
            "interface-list acquisition error",
            detail,
            MAX_DETAIL_BYTES,
            &mut problems,
        );
    }
    let dense_interface_indices = interface_indices
        .iter()
        .copied()
        .eq(0..interface_indices.len());
    match m.interface_list {
        Acquisition::Ok if interface_indices.is_empty() || !dense_interface_indices => problems
            .push("successful interface-list acquisition requires dense interface indices".into()),
        Acquisition::Ok => {}
        _ if !interface_indices.is_empty() => problems.push(
            "non-successful interface-list acquisition cannot contain interface indices".into(),
        ),
        _ => {}
    }
    let alias_entries: usize = m.alias_groups.iter().map(|group| group.entries.len()).sum();
    if alias_entries > MAX_FUNCTIONS {
        problems.push(format!(
            "manifest has too many alias entries: {alias_entries}"
        ));
    }
    for group in &m.alias_groups {
        if !object_ids.contains(&group.object) {
            problems.push(format!(
                "alias group refers to missing object id {}",
                group.object
            ));
        }
        for entry in &group.entries {
            bounded("alias function name", &entry.name, 128, &mut problems);
            if entry.surface >= m.surfaces.len() {
                problems.push(format!(
                    "alias entry refers to missing surface {}",
                    entry.surface
                ));
            }
        }
    }
    problems
}

#[derive(Debug, PartialEq, Eq)]
struct Provenance {
    module: String,
    objects: Vec<String>,
    provenance_objects: Vec<String>,
    interface_list: &'static str,
    surfaces: Vec<ProvenanceSurface>,
    vendor_interfaces: Vec<Vec<String>>,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ProvenanceSurface {
    source: Vec<String>,
    acquisition: &'static str,
    version: Option<(u8, u8)>,
    walk: &'static str,
    functions: Vec<(String, String)>,
}

fn acquisition_name(acquisition: &Acquisition) -> &'static str {
    match acquisition {
        Acquisition::Ok => "ok",
        Acquisition::Absent => "absent",
        Acquisition::Empty => "empty",
        Acquisition::Error { .. } => "error",
    }
}

fn identity_name(object: &ObjectRecord) -> String {
    format!(
        "sha256:{}:{}",
        object.identity.reusable,
        object.identity.sha256.as_deref().unwrap_or("")
    )
}

fn provenance(m: &Manifest) -> Result<Provenance, Vec<String>> {
    let problems = validate_structure(m);
    if !problems.is_empty() {
        return Err(problems);
    }

    let identities: BTreeMap<u32, String> = m
        .objects
        .iter()
        .map(|object| (object.id, identity_name(object)))
        .collect();
    let mut objects: Vec<String> = identities.values().cloned().collect();
    objects.sort();
    let mut provenance_objects: Vec<String> = m
        .provenance_objects
        .iter()
        .map(|object| {
            object
                .identity
                .sha256
                .clone()
                .expect("structure validation requires closure SHA-256")
        })
        .collect();
    provenance_objects.sort();

    let mut surfaces = Vec::with_capacity(m.surfaces.len());
    for surface in &m.surfaces {
        let source = match &surface.source {
            SurfaceSource::LegacyFunctionList => vec!["legacy".into()],
            SurfaceSource::Interface {
                raw_name_hex,
                flags,
                classification,
                ..
            } => vec![
                "interface".into(),
                raw_name_hex.as_deref().unwrap_or("").to_ascii_lowercase(),
                flags.to_string(),
                match classification {
                    InterfaceClassification::ExactStandard => "exact",
                    InterfaceClassification::CorroboratedStandardPrefix => "corroborated",
                }
                .into(),
            ],
        };
        let functions = surface
            .functions
            .iter()
            .map(|function| {
                let resolution = match &function.resolution {
                    Resolution::Resolved {
                        object,
                        file_offset,
                    } => format!(
                        "resolved:{}:{file_offset}",
                        identities
                            .get(object)
                            .expect("structure validation checked object ids")
                    ),
                    Resolution::NullPointer => "null".into(),
                    Resolution::NonFileBacked => "non-file-backed".into(),
                    Resolution::Unmapped => "unmapped".into(),
                    Resolution::UnusableFile { .. } => "unusable-file".into(),
                };
                (function.name.clone(), resolution)
            })
            .collect();
        surfaces.push(ProvenanceSurface {
            source,
            acquisition: acquisition_name(&surface.acquisition),
            version: surface
                .version
                .map(|version| (version.major, version.minor)),
            walk: walk_name(&surface.walk),
            functions,
        });
    }
    surfaces.sort();

    let mut vendor_interfaces: Vec<Vec<String>> = m
        .vendor_interfaces
        .iter()
        .map(|interface| {
            vec![
                interface
                    .raw_name_hex
                    .as_deref()
                    .unwrap_or("")
                    .to_ascii_lowercase(),
                interface
                    .version
                    .map(|version| format!("{}.{}", version.major, version.minor))
                    .unwrap_or_default(),
                interface.flags.to_string(),
                interface.func_list_null.to_string(),
            ]
        })
        .collect();
    vendor_interfaces.sort();

    Ok(Provenance {
        module: identities
            .get(&0)
            .expect("structure validation requires object zero")
            .clone(),
        objects,
        provenance_objects,
        interface_list: acquisition_name(&m.interface_list),
        surfaces,
        vendor_interfaces,
    })
}

/// Proves that a stored manifest's attach semantics were freshly reported by
/// the selected provider. Paths, object ids, and diagnostics are deliberately
/// normalized; object identity, table provenance, and every name-to-offset
/// mapping are not.
pub fn check_provenance(candidate: &Manifest, discovered: &Manifest) -> Result<(), Vec<String>> {
    let candidate = provenance(candidate)?;
    let discovered = provenance(discovered)?;
    if candidate.module != discovered.module {
        return Err(vec![
            "module provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    if candidate.objects != discovered.objects {
        return Err(vec![
            "object provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    if candidate.provenance_objects != discovered.provenance_objects {
        return Err(vec![
            "executable provenance closure differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    if candidate.interface_list != discovered.interface_list {
        return Err(vec![
            "interface-list provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    if candidate.surfaces.len() != discovered.surfaces.len() {
        return Err(vec![
            "surface provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    for (candidate, discovered) in candidate.surfaces.iter().zip(&discovered.surfaces) {
        if candidate.source != discovered.source
            || candidate.acquisition != discovered.acquisition
            || candidate.version != discovered.version
            || candidate.walk != discovered.walk
        {
            return Err(vec![
                "surface provenance differs from fresh discovery; refusing to attach".into(),
            ]);
        }
        if candidate.functions != discovered.functions {
            let name = candidate
                .functions
                .iter()
                .zip(&discovered.functions)
                .find(|(candidate, discovered)| candidate != discovered)
                .map(|(candidate, _)| candidate.0.as_str())
                .unwrap_or("function table");
            return Err(vec![format!(
                "{name} provenance differs from fresh discovery; refusing to attach"
            )]);
        }
    }
    if candidate.vendor_interfaces != discovered.vendor_interfaces {
        return Err(vec![
            "vendor-interface provenance differs from fresh discovery; refusing to attach".into(),
        ]);
    }
    Ok(())
}

/// Opens, identifies, and pins every object. Errors are aggregated so an
/// operator sees every stale or malformed target in one run.
pub fn check_reuse(m: &Manifest) -> Result<VerifiedObjects, Vec<String>> {
    let mut problems = validate_structure(m);
    if !problems.is_empty() {
        return Err(problems);
    }

    let lease = LeaseMonitor::new();
    let mut pinned = Vec::new();
    let mut total_object_bytes = 0u64;
    for object in &m.objects {
        if !object.identity.reusable {
            problems.push(format!(
                "{}: manifest identity is not reusable ({})",
                object.path,
                object
                    .identity
                    .note
                    .as_deref()
                    .unwrap_or("no identity recorded")
            ));
            continue;
        }
        let file = match open_object(Path::new(&object.path)) {
            Ok(file) => file,
            Err(error) => {
                problems.push(format!(
                    "{}: cannot open the file now ({error})",
                    object.path
                ));
                continue;
            }
        };
        if let Err(error) = lease.acquire(&file) {
            problems.push(format!("{}: {error}", object.path));
            continue;
        }
        let len = match file.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) => {
                problems.push(format!("{}: metadata failed ({error})", object.path));
                continue;
            }
        };
        let Some(total) = total_object_bytes.checked_add(len) else {
            problems.push("total object size overflowed u64".into());
            continue;
        };
        if total > MAX_TOTAL_OBJECT_BYTES {
            problems.push(format!(
                "manifest objects total more than the {MAX_TOTAL_OBJECT_BYTES}-byte limit"
            ));
            continue;
        }
        total_object_bytes = total;
        pinned.push((object, file));
    }
    if !problems.is_empty() {
        return Err(problems);
    }

    let mut opened = BTreeMap::new();
    for (object, file) in pinned {
        let inspected = match inspect_file(&file) {
            Ok(inspected) => inspected,
            Err(error) => {
                problems.push(format!(
                    "{}: cannot identify the file now ({error})",
                    object.path
                ));
                continue;
            }
        };
        if inspected.identity.kind != object.identity.kind
            || inspected.identity.value != object.identity.value
            || inspected.identity.sha256 != object.identity.sha256
        {
            problems.push(format!(
                "{}: identity changed since discovery (manifest {:?} {} sha256 {}, current {:?} {} sha256 {}) — re-run `p11scope discover`",
                object.path,
                object.identity.kind,
                object.identity.value.as_deref().unwrap_or("-"),
                object.identity.sha256.as_deref().unwrap_or("-"),
                inspected.identity.kind,
                inspected.identity.value.as_deref().unwrap_or("-"),
                inspected.identity.sha256.as_deref().unwrap_or("-"),
            ));
            continue;
        }
        opened.insert(object.id, (object.path.clone(), file, inspected));
    }

    for surface in &m.surfaces {
        for function in &surface.functions {
            let Resolution::Resolved {
                object,
                file_offset,
            } = function.resolution
            else {
                continue;
            };
            if let Some((path, _, inspected)) = opened.get(&object)
                && !inspected.contains_executable_offset(file_offset)
            {
                problems.push(format!(
                    "{}: {}+{file_offset:#x} is outside every executable ELF segment",
                    function.name, path
                ));
            }
        }
    }

    if !problems.is_empty() {
        return Err(problems);
    }
    if let Err(error) = lease.ensure(opened.values().map(|(_, file, _)| file)) {
        return Err(vec![error]);
    }
    let mut files = BTreeMap::new();
    let mut identities = BTreeMap::new();
    for (path, file, inspected) in opened.into_values() {
        identities.insert(path.clone(), inspected.identity);
        files.insert(path, file);
    }
    Ok(VerifiedObjects {
        files,
        identities,
        lease,
    })
}
