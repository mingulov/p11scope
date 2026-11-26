//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Live isolation probes: fork a child, apply the real isolated fence in
//! it, run the denied syscalls, and check the typed result table. Every
//! verdict is an exact `ISOLATION_*=denied(errno)` / `=allowed` / `=ok`
//! line, never a log-text match.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::os::fd::RawFd;

/// Write one line to the report pipe; only `write` is used, which the
/// fence allows on an already-open descriptor.
fn emit(pipe: RawFd, line: &str) {
    let text = format!("{line}\n");
    let bytes = text.as_bytes();
    let mut done = 0;
    while done < bytes.len() {
        let written = unsafe {
            libc::write(
                pipe,
                bytes[done..].as_ptr() as *const libc::c_void,
                (bytes.len() - done) as libc::size_t,
            )
        };
        if written < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::_exit(3) };
        }
        if written == 0 {
            unsafe { libc::_exit(3) };
        }
        done += written as usize;
    }
}

fn denied_line(name: &str, succeeded: bool) -> String {
    if succeeded {
        format!("ISOLATION_{name}=allowed")
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        format!("ISOLATION_{name}=denied({errno})")
    }
}

/// The fenced child: fence, probe, report, `_exit`. No destructors run
/// here; every arm ends in `_exit`.
fn probe_child(pipe: RawFd) -> ! {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        emit(pipe, "FENCE=error(cannot set no_new_privs)");
        unsafe { libc::_exit(2) };
    }
    if let Err(error) = p11scope_discover::isolation::apply_isolated(None) {
        emit(
            pipe,
            &format!("FENCE=refused({})", error.replace('\n', " ")),
        );
        unsafe { libc::_exit(2) };
    }
    emit(pipe, "FENCE=ok");
    let ppid = unsafe { libc::getppid() };

    // A new user namespace would grant capabilities Landlock cannot see.
    let unshare = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
    emit(pipe, &denied_line("UNSHARE_NEWUSER", unshare == 0));

    // Thread creation must keep working: glibc's pthread_create falls
    // back from clone3 (ENOSYS under the fence) to plain clone.
    let joined = std::thread::spawn(|| {}).join().is_ok();
    emit(
        pipe,
        if joined {
            "ISOLATION_PTHREAD_CREATE=ok"
        } else {
            "ISOLATION_PTHREAD_CREATE=error(join failed)"
        },
    );

    // Another process's memory through /proc: Landlock's ptrace scoping
    // refuses it (the parent lives outside the fenced domain).
    let path = CString::new(format!("/proc/{ppid}/mem")).unwrap();
    let mem = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if mem >= 0 {
        unsafe { libc::close(mem) };
    }
    emit(pipe, &denied_line("PROC_MEM_PP", mem >= 0));

    // The ptrace-equivalent remote-access pair from the earlier round:
    // denied by seccomp before the kernel sees them.
    let mut local = [0u8; 8];
    let local_iov = libc::iovec {
        iov_base: local.as_mut_ptr() as *mut libc::c_void,
        iov_len: local.len(),
    };
    let remote_iov = libc::iovec {
        iov_base: 0x1000 as *mut libc::c_void,
        iov_len: 8,
    };
    let vm_read = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            ppid,
            &local_iov,
            1,
            &remote_iov,
            1,
            0,
        )
    };
    emit(pipe, &denied_line("VM_READV_PP", vm_read >= 0));

    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, ppid, 0, 0) };
    if pidfd < 0 {
        emit(
            pipe,
            &format!(
                "ISOLATION_PIDFD_GETFD_PP=error(pidfd_open {})",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            ),
        );
    } else {
        let stolen = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, 0, 0) };
        emit(pipe, &denied_line("PIDFD_GETFD_PP", stolen >= 0));
        unsafe { libc::close(pidfd as libc::c_int) };
    }

    // IP sockets stay denied; netlink keeps only the route protocol.
    let inet6 = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if inet6 >= 0 {
        unsafe { libc::close(inet6) };
    }
    emit(pipe, &denied_line("SOCKET_INET6", inet6 >= 0));
    let netfilter =
        unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER) };
    if netfilter >= 0 {
        unsafe { libc::close(netfilter) };
    }
    emit(pipe, &denied_line("SOCKET_NETLINK_NF", netfilter >= 0));
    let route = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if route >= 0 {
        unsafe { libc::close(route) };
    }
    if route >= 0 {
        emit(pipe, "ISOLATION_SOCKET_NETLINK_ROUTE=allowed");
    } else {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        emit(
            pipe,
            &format!("ISOLATION_SOCKET_NETLINK_ROUTE=denied({errno})"),
        );
    }

    // Signalling outside the fenced domain: confined by the scoped
    // SIGNAL right on Landlock ABI 6+, open below it.
    let signal = unsafe { libc::kill(ppid, 0) };
    emit(pipe, &denied_line("KILL_PP", signal == 0));

    unsafe { libc::close(pipe) };
    unsafe { libc::_exit(0) };
}

/// The running kernel's Landlock ABI, probed the way the fence does (a
/// null-attr create with the version flag; 444 is
/// `SYS_LANDLOCK_CREATE_RULESET`): the kill expectation depends on it,
/// so it is observed, never assumed.
fn landlock_abi() -> libc::c_long {
    unsafe { libc::syscall(444, std::ptr::null::<u8>(), 0, 1) as libc::c_long }
}

fn read_report(pipe: RawFd) -> String {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = unsafe {
            libc::read(
                pipe,
                chunk.as_mut_ptr() as *mut libc::c_void,
                chunk.len() as libc::size_t,
            )
        };
        if read < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EINTR) {
                continue;
            }
            panic!("reading the probe report failed: errno {errno:?}");
        }
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read as usize]);
    }
    String::from_utf8(bytes).expect("the probe report is UTF-8")
}

#[test]
fn fenced_child_reports_the_denial_table() {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        unsafe { libc::close(fds[0]) };
        probe_child(fds[1]);
    }
    unsafe { libc::close(fds[1]) };
    // A hung child is killed and fails the test instead of hanging the
    // suite; the report is small enough that the child can never block
    // on the pipe before exiting.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            break;
        }
        if waited < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error();
            if errno == Some(libc::EINTR) {
                continue;
            }
            panic!("waitpid failed: errno {errno:?}");
        }
        if std::time::Instant::now() >= deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            let mut reaped = 0;
            unsafe { libc::waitpid(pid, &mut reaped, 0) };
            unsafe { libc::close(fds[0]) };
            panic!("fenced probe child did not exit within 30s; killed");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let report = read_report(fds[0]);
    unsafe { libc::close(fds[0]) };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "probe child failed, status={status}: {report}"
    );
    let mut table = BTreeMap::new();
    for line in report.lines() {
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("malformed probe line: {line:?}"));
        assert!(
            table.insert(key.to_string(), value.to_string()).is_none(),
            "duplicate probe line: {line:?}"
        );
    }
    assert_eq!(
        table.get("FENCE").map(String::as_str),
        Some("ok"),
        "the fence must apply in the probe child: {table:?}"
    );
    let eacces = format!("denied({})", libc::EACCES);
    let eperm = format!("denied({})", libc::EPERM);
    let kill_expected = if landlock_abi() >= 6 {
        eperm.as_str()
    } else {
        "allowed"
    };
    let expected: &[(&str, &str)] = &[
        ("ISOLATION_UNSHARE_NEWUSER", &eacces),
        ("ISOLATION_PTHREAD_CREATE", "ok"),
        ("ISOLATION_PROC_MEM_PP", &eacces),
        ("ISOLATION_VM_READV_PP", &eacces),
        ("ISOLATION_PIDFD_GETFD_PP", &eacces),
        ("ISOLATION_SOCKET_INET6", &eacces),
        ("ISOLATION_SOCKET_NETLINK_NF", &eacces),
        ("ISOLATION_SOCKET_NETLINK_ROUTE", "allowed"),
        ("ISOLATION_KILL_PP", kill_expected),
    ];
    for (key, value) in expected {
        assert_eq!(
            table.get(*key).map(String::as_str),
            Some(*value),
            "probe table mismatch: {table:?}"
        );
    }
    assert_eq!(
        table.len(),
        expected.len() + 1,
        "unexpected probe lines: {table:?}"
    );
}
