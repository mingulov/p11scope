//! SPDX-License-Identifier: GPL-3.0-or-later
//! A stop signal after the `-o` temp file exists but before attachment
//! must leave no temp file and name the interruption. Inotify alone does
//! not synchronize the sender: startup may finish before it is scheduled.
//! Stop the real observer at syscall boundaries until IN_CREATE arrives,
//! then deliver SIGINT before allowing startup to continue. No BPF privilege
//! or production test hook is needed.

use std::ffi::CString;
use std::io::{Read as _, Seek as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

// libc's ptrace request type differs between the supported host libcs.
#[cfg(target_env = "musl")]
type PtraceRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type PtraceRequest = libc::c_uint;

struct OwnedChild {
    child: Child,
    reaped: bool,
}

impl OwnedChild {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn pid(&self) -> libc::pid_t {
        self.child.id() as libc::pid_t
    }

    fn ptrace(&self, request: PtraceRequest, data: libc::c_int) {
        assert_eq!(
            unsafe {
                libc::ptrace(
                    request,
                    self.pid(),
                    std::ptr::null_mut::<libc::c_void>(),
                    data as usize as *mut libc::c_void,
                )
            },
            0,
            "ptrace {request}: {}",
            std::io::Error::last_os_error()
        );
    }

    fn wait_stop(&mut self, deadline: Instant) -> libc::c_int {
        loop {
            assert!(
                Instant::now() < deadline,
                "observer did not reach the startup barrier"
            );
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid(), &mut status, libc::WNOHANG) };
            if result == self.pid() {
                if libc::WIFSTOPPED(status) {
                    return libc::WSTOPSIG(status);
                }
                // waitpid consumed the exit; never signal this PID afterward.
                self.reaped = true;
                panic!("observer exited before the startup barrier: {status}");
            }
            assert!(
                result >= 0
                    || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted,
                "waitpid: {}",
                std::io::Error::last_os_error()
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn wait_exit(&mut self, deadline: Instant) -> ExitStatus {
        loop {
            if let Some(status) = self.child.try_wait().expect("wait for observer exit") {
                self.reaped = true;
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "observer did not exit after SIGINT"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // Also retires a tracee left stopped by a failed assertion. Keep
        // cleanup bounded, and reap only this direct, still-owned child.
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid(), &mut status, libc::WNOHANG) };
            if result == self.pid() && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
                return;
            }
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        eprintln!("test cleanup could not reap owned child {}", self.pid());
    }
}

fn temp_was_created(inotify: &OwnedFd) -> bool {
    let mut buffer = [0u8; 4096];
    let read = unsafe {
        libc::read(
            inotify.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if read < 0 {
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::WouldBlock
        );
        return false;
    }
    let mut offset = 0usize;
    while offset + std::mem::size_of::<libc::inotify_event>() <= read as usize {
        let event: libc::inotify_event =
            unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset).cast()) };
        let start = offset + std::mem::size_of::<libc::inotify_event>();
        let end = start + event.len as usize;
        assert!(end <= read as usize, "truncated inotify event");
        if event.mask & libc::IN_CREATE != 0 && buffer[start..end].starts_with(b".p11scope.") {
            return true;
        }
        offset = end;
    }
    false
}

#[test]
fn a_stop_signal_during_startup_leaves_no_temp_file_and_names_the_interruption() {
    let target = OwnedChild::new(
        Command::new("sleep")
            .arg("311.27")
            .spawn()
            .expect("spawn sleep target"),
    );
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    assert!(fd >= 0, "{}", std::io::Error::last_os_error());
    let inotify = unsafe { OwnedFd::from_raw_fd(fd) };
    let watched = CString::new(dir.path().as_os_str().as_bytes()).unwrap();
    assert!(unsafe { libc::inotify_add_watch(fd, watched.as_ptr(), libc::IN_CREATE) } >= 0);

    let out = dir.path().join("observed.json");
    // A file avoids a pipe filling while the parent waits for ptrace stops.
    let mut diagnostics = tempfile::tempfile().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_p11scope"));
    command
        .args([
            "profile",
            "--pid",
            &target.pid().to_string(),
            "--duration",
            "1",
            "-o",
        ])
        .arg(&out)
        .stdout(Stdio::null())
        .stderr(diagnostics.try_clone().unwrap());
    // SAFETY: the child only makes an async-signal-safe ptrace syscall before
    // exec; no allocation or synchronization with another parent thread.
    unsafe {
        command.pre_exec(|| {
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut observer = OwnedChild::new(command.spawn().expect("spawn traced p11scope"));
    let deadline = Instant::now() + Duration::from_secs(30);
    assert_eq!(observer.wait_stop(deadline), libc::SIGTRAP, "exec stop");
    observer.ptrace(
        libc::PTRACE_SETOPTIONS,
        libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_EXITKILL,
    );
    loop {
        observer.ptrace(libc::PTRACE_SYSCALL, 0);
        assert_eq!(
            observer.wait_stop(deadline),
            libc::SIGTRAP | 0x80,
            "syscall stop"
        );
        if temp_was_created(&inotify) {
            break;
        }
    }
    // Deliberately delay the sender. The observer stays at the creating
    // syscall's exit instead of racing ahead as it did with inotify alone.
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                observer.pid(),
                observer.pid(),
                libc::SIGINT,
            )
        },
        0
    );
    observer.ptrace(libc::PTRACE_CONT, 0);
    assert_eq!(
        observer.wait_stop(deadline),
        libc::SIGINT,
        "signal-delivery stop"
    );
    // Inject only from the signal-delivery stop: a signal argument at a
    // syscall stop may be silently ignored by ptrace.
    observer.ptrace(libc::PTRACE_DETACH, libc::SIGINT);
    let status = observer.wait_exit(Instant::now() + Duration::from_secs(30));
    diagnostics.rewind().unwrap();
    let mut stderr = String::new();
    diagnostics.read_to_string(&mut stderr).unwrap();

    assert_eq!(
        status.signal(),
        None,
        "killed by a signal instead of stopping cleanly: {stderr}"
    );
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("interrupted by SIGINT"), "{stderr}");
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "startup interruption left {left:?}");
}
