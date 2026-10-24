//! SPDX-License-Identifier: GPL-3.0-or-later
//! Z2 retained thread-member custody twins: mint/validate/selector plus every
//! refusal (foreign group, independent Arc, changed birth, exits, permission,
//! missing pidfd, deadline, headroom, FD exhaustion, exec, mid-proof).

use super::{RetainedGroupMember, ValidatedMemberSelector};
use crate::discovery::caller_registry;
use crate::discovery::scan::{CaptureWorkBudget, WORK_CEILING_REASON};
use crate::discovery::sweep_attribution::{FD_RESOURCE_REASON, ReservationOwner, SegmentPolicy};
use crate::process::{PidPin, generation_gone, process_is_zombie};
use std::cell::RefCell;
use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn test_owner() -> ReservationOwner {
    ReservationOwner::new(SegmentPolicy::from_headroom(1024, 4, 16))
}

fn test_budget() -> CaptureWorkBudget {
    CaptureWorkBudget::default()
}

fn test_deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").map_or(usize::MAX, Iterator::count)
}

/// FD counts are process-global, so the two twins that assert them re-run
/// their whole body in a quiescent single-test subprocess (env-gated). The
/// parent only checks the child's exit + its `1 passed` line; the child runs
/// the body. Returns true in the child (run the body), false in the parent.
fn ensure_quiescent_child(selector: &str) -> bool {
    if std::env::var_os("P11SCOPE_R4_FD_CHILD").is_some() {
        return true;
    }
    let exe = std::env::current_exe().expect("test binary path is known");
    let output = std::process::Command::new(exe)
        .arg("--exact")
        .arg(selector)
        .arg("--test-threads=1")
        .env("P11SCOPE_R4_FD_CHILD", "1")
        .output()
        .expect("quiescent child spawns");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "quiescent child failed: status={} stdout={stdout}",
        output.status
    );
    false
}

/// One in-process thread parked until released; always released and joined,
/// even on test failure, so no blocked thread outlives the test.
struct WaitingThread {
    tid: u32,
    release: Option<std::sync::mpsc::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl WaitingThread {
    fn spawn() -> Self {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let tid = unsafe { libc::gettid() };
            let _ = tid_tx.send(tid as u32);
            let _ = release_rx.recv();
        });
        let tid = tid_rx.recv().expect("worker thread reports its tid");
        Self {
            tid,
            release: Some(release_tx),
            handle: Some(handle),
        }
    }

    /// Release the thread and reap it, so its TID is deterministically gone.
    fn kill_and_join(mut self) {
        drop(self.release.take());
        self.handle
            .take()
            .expect("join once")
            .join()
            .expect("worker thread joins");
    }
}

impl Drop for WaitingThread {
    fn drop(&mut self) {
        drop(self.release.take());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A forked single-threaded child parked in `pause()`; SIGKILLed and reaped
/// on drop. The child only calls async-signal-safe `pause()`.
struct PausingChild {
    pid: u32,
}

impl PausingChild {
    fn spawn() -> Self {
        // SAFETY: the child only calls async-signal-safe pause() until killed.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                loop {
                    libc::pause();
                }
            }
        }
        Self { pid: pid as u32 }
    }

    fn kill_and_reap(self) {
        let pid = self.pid as libc::pid_t;
        std::mem::forget(self);
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(pid, &mut status, 0) < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR)
                );
            }
        }
    }
}

impl Drop for PausingChild {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(self.pid as libc::pid_t, &mut status, 0) < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err == Some(libc::ECHILD) {
                    break;
                }
                assert_eq!(err, Some(libc::EINTR));
            }
        }
    }
}

/// The raw-clone survivor: reports its TID over the pipe (whose write end
/// arrives as the argument), then parks in `pause()`. Raw syscalls only;
/// this context shares the dead main's TLS slot, which nobody reads.
extern "C" fn clone_survivor_main(arg: *mut std::ffi::c_void) -> libc::c_int {
    let wfd = arg as usize as libc::c_int;
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let bytes = tid.to_ne_bytes();
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: writing the stack bytes to the pipe.
        let done = unsafe {
            libc::write(
                wfd,
                bytes.as_ptr().add(written).cast(),
                bytes.len() - written,
            )
        };
        if done <= 0 {
            unsafe {
                libc::syscall(libc::SYS_exit, 1);
            }
        }
        written += done as usize;
    }
    loop {
        unsafe {
            libc::pause();
        }
    }
}

/// A thread group whose leader is an unreaped zombie with one live survivor.
/// Built with raw syscalls only (fork-safe): the forked child raw-clones a
/// survivor thread into its group on the COW-inherited stack, then the
/// child's main exits its own thread via raw `exit(2)`. Killed and reaped
/// on drop.
struct ZombieLeaderGroup {
    tgid: u32,
    survivor: u32,
}

impl ZombieLeaderGroup {
    fn spawn() -> Self {
        let mut stack = Box::new([0u8; 65536]);
        // The heap top is 16-aligned (aligned base, multiple-of-16 size).
        let stack_top = stack.as_mut_ptr_range().end as *mut std::ffi::c_void;
        let (mut pipes, mut tid_bytes) = ([0; 2], [0u8; 4]);
        // SAFETY: two valid two-element arrays for pipe2.
        assert_eq!(
            unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: the child only makes raw syscalls (close, clone, exit) on
        // the COW-inherited stack and pipe; no allocator, no pthread, no locks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(pipes[0]);
                const FLAGS: libc::c_int = libc::CLONE_VM
                    | libc::CLONE_FS
                    | libc::CLONE_FILES
                    | libc::CLONE_SIGHAND
                    | libc::CLONE_THREAD
                    | libc::CLONE_SYSVSEM;
                let cloned = libc::clone(
                    clone_survivor_main,
                    stack_top,
                    FLAGS,
                    pipes[1] as isize as *mut std::ffi::c_void,
                );
                if cloned < 0 {
                    libc::_exit(1);
                }
                // The main thread exits alone; the survivor keeps the group.
                libc::syscall(libc::SYS_exit, 0);
                libc::_exit(0);
            }
        }
        // SAFETY: the parent keeps the read end and closes its write copy so
        // a dead child reads as EOF instead of hanging the read below.
        unsafe {
            libc::close(pipes[1]);
        }
        let mut done = 0;
        while done < tid_bytes.len() {
            // SAFETY: reading into a valid stack buffer.
            let got = unsafe {
                libc::read(
                    pipes[0],
                    tid_bytes.as_mut_ptr().add(done).cast(),
                    tid_bytes.len() - done,
                )
            };
            assert!(got > 0, "clone survivor never reported its tid");
            done += got as usize;
        }
        // SAFETY: the read end served its single read.
        unsafe {
            libc::close(pipes[0]);
        }
        Self {
            tgid: pid as u32,
            survivor: u32::from_ne_bytes(tid_bytes),
        }
    }
}

impl Drop for ZombieLeaderGroup {
    fn drop(&mut self) {
        unsafe {
            // SIGKILL to the TGID stops the survivor; the leader is dead.
            libc::kill(self.tgid as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(self.tgid as libc::pid_t, &mut status, 0) < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err == Some(libc::ECHILD) {
                    break;
                }
                assert_eq!(err, Some(libc::EINTR));
            }
        }
    }
}

static WORKDIR_COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_workdir(tag: &str) -> std::path::PathBuf {
    let id = WORKDIR_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("r4-retained-{}-{id}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("test workdir creates");
    dir
}

fn remove_workdir(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

/// Independent /proc stat parse: (start-time ticks, state char).
fn stat_birth_and_state(path: &std::path::Path) -> Option<(u64, char)> {
    let text = std::fs::read_to_string(path).ok()?;
    let end = text.rfind(')')?;
    let mut fields = text[end + 1..].split_whitespace();
    let state = fields.next()?.chars().next()?;
    let birth = fields.nth(18)?.parse().ok()?;
    Some((birth, state))
}

fn write_fake_stat(path: &std::path::Path, pid: u32, birth: u64, state: char) {
    // pid (comm) state + 18 numeric fields + start-time + trailing fields.
    let mut line = format!("{pid} (fake) {state}");
    for _ in 0..18 {
        line.push_str(" 0");
    }
    line.push_str(&format!(
        " {birth} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"
    ));
    line.push('\n');
    std::fs::write(path, line).expect("fake stat writes");
}

fn write_fake_status(path: &std::path::Path, tgid: u32) {
    std::fs::write(path, format!("Name:\tfake\nTgid:\t{tgid}\nPid:\t{tgid}\n"))
        .expect("fake status writes");
}

fn open_dir_fd(path: &std::path::Path) -> Result<OwnedFd, String> {
    std::fs::File::open(path)
        .map(OwnedFd::from)
        .map_err(|error| error.to_string())
}

/// Spawn `python3 -c <script> <workdir>` with no pipes; coordination runs
/// through files under `workdir`. python3 is a documented prerequisite
/// (`docs/development.md`), so a missing interpreter is a fixture failure.
fn spawn_python_child(script: &str, work: &std::path::Path) -> std::process::Child {
    std::process::Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(work)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("python3 spawns (docs/development.md prerequisite)")
}

fn wait_for_file(path: &std::path::Path, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !path.exists() {
        assert!(Instant::now() < deadline, "{what} never appeared");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Wait until `tid` is observably dead in `tgid` (tgkill ESRCH): thread
/// reaping is asynchronous in the kernel, so a joined thread may still
/// answer for a brief window; death is monotonic, so convergence is final.
/// This converges the fixture — the assertions below it still run once.
fn poll_thread_dead(tgid: u32, tid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // SAFETY: signal 0 sends nothing.
        let done = unsafe { libc::tgkill(tgid as libc::pid_t, tid as libc::pid_t, 0) };
        if done != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "joined thread never became observably dead"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn read_tid_file(path: &std::path::Path) -> u32 {
    // The writer creates the file before flushing the TID; wait for content.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Ok(tid) = text.trim().parse()
        {
            return tid;
        }
        assert!(Instant::now() < deadline, "tid file never gained content");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Main thread sleeps 50ms (distinct USER_HZ ticks from its child), spawns one
/// worker, and the worker execs the same python3 binary from the nonleader.
/// The exec'd image writes `execed` first, so the parent observes the exec
/// deterministically instead of polling for it.
const EXEC_SCRIPT: &str = r#"import os
import sys
import threading
import time


def path(name):
    return os.path.join(sys.argv[1], name)


time.sleep(0.05)


def worker():
    with open(path("ready"), "w") as handle:
        handle.write(str(threading.get_native_id()))
    deadline = time.time() + 30
    while not os.path.exists(path("go")):
        if time.time() > deadline:
            os._exit(11)
        time.sleep(0.005)
    resume = (
        "import signal, os; open(" + repr(path("execed")) + ", 'w').write('x'); signal.pause()"
    )
    os.execvp("python3", ["python3", "-c", resume])


thread = threading.Thread(target=worker)
thread.start()
thread.join()
"#;

#[test]
fn retained_group_member_acquire_and_validate_healthy() {
    if !ensure_quiescent_child(
        "discovery::retained_member::tests::retained_group_member_acquire_and_validate_healthy",
    ) {
        return;
    }
    let worker = WaitingThread::spawn();
    let tgid = std::process::id();
    let original = Arc::new(PidPin::open(tgid).expect("self pins"));
    let owner = test_owner();
    let mut work = test_budget();
    let baseline = fd_count();
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("healthy member mints");
    assert_eq!(fd_count(), baseline + 1, "mint holds exactly one FD");
    member
        .validate(test_deadline())
        .expect("healthy member validates");
    let selector: ValidatedMemberSelector<'_> = member.selector().expect("healthy member selects");
    assert_eq!(selector.tgid(), tgid);
    assert_eq!(selector.tid(), worker.tid);
    assert_eq!(
        selector.member_birth(),
        member.test_recorded_births().0,
        "selector carries the minted birth"
    );
    // The relative reads match the canonical identities (like-for-like).
    let member_exe = member.read_exe_identity().expect("member exe reads");
    let canon_exe = caller_registry::read_exe_identity(tgid).expect("canonical exe reads");
    assert_eq!(member_exe, canon_exe);
    let mut maps = member.open_maps().expect("member maps opens");
    let mut maps_text = String::new();
    maps.read_to_string(&mut maps_text).expect("maps reads");
    let (start, end) = maps_text
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let addrs = parts.next()?;
            let perms = parts.next()?;
            if perms.as_bytes().get(2) != Some(&b'x') || !line.contains('/') {
                return None;
            }
            let (start, end) = addrs.split_once('-')?;
            Some((
                u64::from_str_radix(start, 16).ok()?,
                u64::from_str_radix(end, 16).ok()?,
            ))
        })
        .expect("one file-backed executable range exists");
    drop(maps);
    let map_files = member.open_map_files_dir().expect("member map_files opens");
    // Following a map_files entry needs CAP_SYS_ADMIN or
    // CAP_CHECKPOINT_RESTORE (identity.rs:437-440), so unprivileged runs
    // fail closed with EPERM while capable runs prove the identity.
    match member.stat_map_file(start, end) {
        Ok(identity) => {
            assert_ne!(identity.dev, 0, "file-backed range has a device");
            assert_ne!(identity.ino, 0, "file-backed range has an inode");
            assert_eq!(
                map_files.stat(start, end).expect("guard range stats"),
                identity,
                "guard and direct reads agree"
            );
        }
        Err(error) => {
            assert!(
                error.contains("not permitted"),
                "map_files refusal is EPERM, got: {error}"
            );
            assert!(
                map_files.stat(start, end).is_err(),
                "guard fails closed too"
            );
        }
    }
    drop(map_files);
    drop(member);
    assert_eq!(fd_count(), baseline, "drop returns the retained FD");
}

#[test]
fn retained_group_member_rejects_foreign_group() {
    let child_a = PausingChild::spawn();
    let child_b = PausingChild::spawn();
    let original_a = Arc::new(PidPin::open(child_a.pid).expect("child A pins"));
    let owner = test_owner();
    let mut work = test_budget();
    // Each single-threaded child's tid equals its tgid; neither is in the
    // other's group.
    let err =
        RetainedGroupMember::acquire(&original_a, child_b.pid, &owner, &mut work, test_deadline())
            .expect_err("foreign-group tid must not mint");
    assert!(
        err.contains("not a live member"),
        "unexpected refusal: {err}"
    );
    let original_b = Arc::new(PidPin::open(child_b.pid).expect("child B pins"));
    let err =
        RetainedGroupMember::acquire(&original_b, child_a.pid, &owner, &mut work, test_deadline())
            .expect_err("foreign-group tid must not mint");
    assert!(
        err.contains("not a live member"),
        "unexpected refusal: {err}"
    );
}

#[test]
fn retained_group_member_rejects_independent_reopened_arc() {
    let worker = WaitingThread::spawn();
    let tgid = std::process::id();
    let first = Arc::new(PidPin::open(tgid).expect("self pins"));
    let second = Arc::new(PidPin::open(tgid).expect("self re-pins"));
    assert!(
        !Arc::ptr_eq(&first, &second),
        "the reopen is a distinct Arc"
    );
    let owner = test_owner();
    let mut work = test_budget();
    let member =
        RetainedGroupMember::acquire(&first, worker.tid, &owner, &mut work, test_deadline())
            .expect("first minter mints");
    let err = RetainedGroupMember::acquire(&second, worker.tid, &owner, &mut work, test_deadline())
        .expect_err("an independent Arc must not mint over a live member");
    assert!(
        err.contains("different original"),
        "unexpected refusal: {err}"
    );
    drop(member);
}

#[test]
fn retained_group_member_rejects_changed_member_birth() {
    // Phase 1 (validate-time): a recorded birth that no longer matches the
    // live member — exactly the aftermath of a kernel TID reuse.
    let worker = WaitingThread::spawn();
    let tgid = std::process::id();
    let original = Arc::new(PidPin::open(tgid).expect("self pins"));
    let owner = test_owner();
    let mut work = test_budget();
    let mut member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("healthy member mints");
    let (recorded_member, _) = member.test_recorded_births();
    member.test_set_recorded_member_birth(recorded_member.wrapping_add(1));
    let err = member
        .validate(test_deadline())
        .expect_err("changed birth must not validate");
    assert!(err.contains("birth"), "unexpected refusal: {err}");
    drop(member);
    // Phase 2a (mint-time race, birth): the opened member dir reports a
    // different birth than the pre-open check — a reuse between check and open.
    let (real_birth, _) = stat_birth_and_state(std::path::Path::new(&format!(
        "/proc/{tgid}/task/{}/stat",
        worker.tid
    )))
    .expect("real member stat reads");
    let fake = unique_workdir("fake-birth");
    let fake_member = fake.join("member");
    std::fs::create_dir(&fake_member).expect("fake member dir creates");
    write_fake_stat(
        &fake_member.join("stat"),
        worker.tid,
        real_birth.wrapping_add(1),
        'R',
    );
    write_fake_status(&fake_member.join("status"), tgid);
    // The seam only serves the member-dir open now; the absolute pre-checks
    // read the real live worker.
    let open_fake = |_: &std::path::Path| open_dir_fd(&fake_member);
    let err = RetainedGroupMember::acquire_with_proc_opener(
        &original,
        worker.tid,
        &owner,
        &mut work,
        test_deadline(),
        &open_fake,
    )
    .expect_err("birth change at open must not mint");
    assert!(err.contains("birth"), "unexpected refusal: {err}");
    // Phase 2b (mint-time race, group): the opened member reports another group.
    write_fake_stat(&fake_member.join("stat"), worker.tid, real_birth, 'R');
    write_fake_status(&fake_member.join("status"), tgid.wrapping_add(1));
    let err = RetainedGroupMember::acquire_with_proc_opener(
        &original,
        worker.tid,
        &owner,
        &mut work,
        test_deadline(),
        &open_fake,
    )
    .expect_err("group change at open must not mint");
    assert!(err.contains("thread group"), "unexpected refusal: {err}");
    remove_workdir(&fake);
    // Failed mints leave no registry entry: a real mint still works.
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("real mint works after refused races");
    drop(member);
}

#[test]
fn retained_group_member_refuses_original_exit() {
    // Phase 1: mint-then-reap — validate refuses once the group is gone.
    let child = PausingChild::spawn();
    let pid = child.pid;
    let original = Arc::new(PidPin::open(pid).expect("child pins"));
    let owner = test_owner();
    let mut work = test_budget();
    // A single-threaded child: the leader doubles as the only member.
    let member = RetainedGroupMember::acquire(&original, pid, &owner, &mut work, test_deadline())
        .expect("leader-as-member mints while the group lives");
    member
        .validate(test_deadline())
        .expect("live group validates");
    child.kill_and_reap();
    assert!(generation_gone(pid), "reaped child is gone");
    let err = member
        .validate(test_deadline())
        .expect_err("dead group must not validate");
    assert!(err.contains("exit"), "unexpected refusal: {err}");
    drop(member);
    // Phase 2: reap-then-mint — acquire refuses without any live group.
    let child = PausingChild::spawn();
    let pid = child.pid;
    let original = Arc::new(PidPin::open(pid).expect("child pins"));
    child.kill_and_reap();
    assert!(generation_gone(pid), "reaped child is gone");
    let err = RetainedGroupMember::acquire(&original, pid, &owner, &mut work, test_deadline())
        .expect_err("dead group must not mint");
    assert!(err.contains("exit"), "unexpected refusal: {err}");
}

#[test]
fn retained_group_member_refuses_member_death_group_alive() {
    // Phases 1-2: a real zombie-leader group — the leader reads Z at TGID
    // level while the survivor stays provable. (Bare member zombies are not
    // observable: an exited non-leader thread vanishes from the task list
    // immediately, even a joinable never-joined pthread, so member death
    // always reads as absence; only the leader shows Z.)
    let group = ZombieLeaderGroup::spawn();
    let tgid = group.tgid;
    let tid = group.survivor;
    assert_ne!(tid, tgid, "survivor is a nonleader thread");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if process_is_zombie(tgid) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "leader never reached zombie state"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let original = Arc::new(PidPin::open(tgid).expect("zombie group pins"));
    let owner = test_owner();
    let mut budget = test_budget();
    let member = RetainedGroupMember::acquire(&original, tid, &owner, &mut budget, test_deadline())
        .expect("zombie-leader survivor mints");
    member
        .validate(test_deadline())
        .expect("zombie-leader survivor validates");
    // The zombie leader itself is dead as a member: it refuses either as a
    // zombie (listed) or as absent (unlisted) depending on the kernel. The
    // survivor member stays live across this to prove slots are independent.
    let leader_listed = std::fs::read_dir(format!("/proc/{tgid}/task"))
        .expect("task lists")
        .any(|entry| {
            entry
                .expect("entry reads")
                .file_name()
                .to_str()
                .is_some_and(|name| name == tgid.to_string())
        });
    let err = RetainedGroupMember::acquire(&original, tgid, &owner, &mut budget, test_deadline())
        .expect_err("zombie leader must not mint as its own member");
    if leader_listed {
        assert!(err.contains("zombie"), "unexpected refusal: {err}");
    } else {
        assert!(
            err.contains("not a live member"),
            "unexpected refusal: {err}"
        );
    }
    drop(member);
    drop(group);
    // Phases 3-5: a reaped member — gone from the task list, group alive.
    let self_tgid = std::process::id();
    let original_self = Arc::new(PidPin::open(self_tgid).expect("self pins"));
    let worker = WaitingThread::spawn();
    let member = RetainedGroupMember::acquire(
        &original_self,
        worker.tid,
        &owner,
        &mut budget,
        test_deadline(),
    )
    .expect("live member mints");
    let dead_tid = worker.tid;
    let live_guard = member.open_map_files_dir().expect("guard opens while live");
    worker.kill_and_join();
    poll_thread_dead(self_tgid, dead_tid);
    let err = member
        .validate(test_deadline())
        .expect_err("reaped member must not validate");
    assert!(err.contains("no longer"), "unexpected refusal: {err}");
    // The guard stays open (the TGID directory outlives the thread), but
    // the unmapped low range has no identity (covers the lookup failure).
    assert!(
        live_guard.stat(0x1000, 0x2000).is_err(),
        "unmapped range has no identity"
    );
    drop(live_guard);
    // Held reads fail closed once the member is gone.
    assert!(
        member.read_exe_identity().is_none(),
        "dead member has no exe"
    );
    assert!(member.open_maps().is_err(), "dead member has no maps");
    assert!(
        member.open_map_files_dir().is_err(),
        "dead member has no map_files"
    );
    assert!(
        member.stat_map_file(0x1000, 0x2000).is_err(),
        "dead member stats nothing"
    );
    drop(member);
    let err = RetainedGroupMember::acquire(
        &original_self,
        dead_tid,
        &owner,
        &mut budget,
        test_deadline(),
    )
    .expect_err("reaped member must not mint");
    assert!(
        err.contains("not a live member"),
        "unexpected refusal: {err}"
    );
    // Phases 6-8: synthetic death between check and open (fake proc tree).
    let worker = WaitingThread::spawn();
    let (real_birth, _) = stat_birth_and_state(std::path::Path::new(&format!(
        "/proc/{self_tgid}/task/{}/stat",
        worker.tid
    )))
    .expect("real member stat reads");
    let fake = unique_workdir("fake-death");
    let fake_member = fake.join("member");
    std::fs::create_dir(&fake_member).expect("fake member dir creates");
    // The seam only serves the member-dir open now; the absolute pre-checks
    // read the real live worker.
    let open_fake = |_: &std::path::Path| open_dir_fd(&fake_member);
    write_fake_stat(&fake_member.join("stat"), worker.tid, real_birth, 'Z');
    write_fake_status(&fake_member.join("status"), self_tgid);
    let err = RetainedGroupMember::acquire_with_proc_opener(
        &original_self,
        worker.tid,
        &owner,
        &mut budget,
        test_deadline(),
        &open_fake,
    )
    .expect_err("zombie at open must not mint");
    assert!(err.contains("zombie"), "unexpected refusal: {err}");
    std::fs::remove_file(fake_member.join("stat")).expect("fake stat removes");
    let err = RetainedGroupMember::acquire_with_proc_opener(
        &original_self,
        worker.tid,
        &owner,
        &mut budget,
        test_deadline(),
        &open_fake,
    )
    .expect_err("vanished proof at open must not mint");
    assert!(err.contains("unreadable"), "unexpected refusal: {err}");
    write_fake_stat(&fake_member.join("stat"), worker.tid, real_birth, 'R');
    std::fs::remove_file(fake_member.join("status")).expect("fake status removes");
    let err = RetainedGroupMember::acquire_with_proc_opener(
        &original_self,
        worker.tid,
        &owner,
        &mut budget,
        test_deadline(),
        &open_fake,
    )
    .expect_err("vanished status at open must not mint");
    assert!(err.contains("unreadable"), "unexpected refusal: {err}");
    remove_workdir(&fake);
    let member = RetainedGroupMember::acquire(
        &original_self,
        worker.tid,
        &owner,
        &mut budget,
        test_deadline(),
    )
    .expect("real mint works after refused deaths");
    drop(member);
}

#[test]
fn retained_group_member_refuses_permission_failure() {
    let worker = WaitingThread::spawn();
    let original = Arc::new(PidPin::open(std::process::id()).expect("self pins"));
    let owner = test_owner();
    let mut work = test_budget();
    // The member-dir open fails with EACCES: mint refuses fail-closed.
    let err = RetainedGroupMember::acquire_with_proc_opener(
        &original,
        worker.tid,
        &owner,
        &mut work,
        test_deadline(),
        &|_| Err("opening member dir: permission denied (EACCES)".to_string()),
    )
    .expect_err("EACCES must not mint");
    assert!(err.contains("EACCES"), "unexpected refusal: {err}");
    // Nothing stuck: a real mint still works.
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("real mint works after refusals");
    drop(member);
}

#[test]
fn retained_group_member_refuses_missing_original_pidfd() {
    let worker = WaitingThread::spawn();
    let tgid = std::process::id();
    let proc_only = Arc::new(PidPin::test_proc_only(tgid));
    let owner = test_owner();
    let mut work = test_budget();
    let err =
        RetainedGroupMember::acquire(&proc_only, worker.tid, &owner, &mut work, test_deadline())
            .expect_err("a pidfd-less original must not mint");
    assert!(err.contains("pidfd"), "unexpected refusal: {err}");
}

#[test]
fn retained_group_member_refuses_expired_deadline() {
    let worker = WaitingThread::spawn();
    let original = Arc::new(PidPin::open(std::process::id()).expect("self pins"));
    let owner = test_owner();
    let mut work = test_budget();
    let past = Instant::now() - Duration::from_secs(1);
    let err = RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, past)
        .expect_err("expired deadline must not mint");
    assert!(err.contains("deadline"), "unexpected refusal: {err}");
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("live deadline mints");
    let err = member
        .validate(past)
        .expect_err("expired deadline must not validate");
    assert!(err.contains("deadline"), "unexpected refusal: {err}");
    drop(member);
}

#[test]
fn retained_group_member_refuses_zero_headroom() {
    let worker = WaitingThread::spawn();
    let original = Arc::new(PidPin::open(std::process::id()).expect("self pins"));
    // Phase 1: no FD headroom at all.
    let bare = ReservationOwner::new(SegmentPolicy::from_headroom(0, 0, 0));
    let mut work = test_budget();
    let err =
        RetainedGroupMember::acquire(&original, worker.tid, &bare, &mut work, test_deadline())
            .expect_err("zero FD headroom must not mint");
    assert_eq!(err, FD_RESOURCE_REASON);
    // Phase 2: no work headroom at all.
    let owner = test_owner();
    let mut empty = CaptureWorkBudget::with_work_ceiling(0);
    let err =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut empty, test_deadline())
            .expect_err("zero work headroom must not mint");
    assert_eq!(err, WORK_CEILING_REASON);
}

#[test]
fn retained_group_member_refuses_fd_exhaustion_and_cleans_up() {
    if !ensure_quiescent_child(
        "discovery::retained_member::tests::retained_group_member_refuses_fd_exhaustion_and_cleans_up",
    ) {
        return;
    }
    let worker = WaitingThread::spawn();
    let original = Arc::new(PidPin::open(std::process::id()).expect("self pins"));
    // One retained slot and one worker pair: from_headroom(9, 1, 1).
    let tight = ReservationOwner::new(SegmentPolicy::from_headroom(9, 1, 1));
    let mut work = test_budget();
    // Phase 1: the only retained slot is held elsewhere.
    let held_pin = tight.batch().pin().expect("one retained slot exists");
    let before = fd_count();
    let err =
        RetainedGroupMember::acquire(&original, worker.tid, &tight, &mut work, test_deadline())
            .expect_err("exhausted retained class must not mint");
    assert_eq!(err, FD_RESOURCE_REASON);
    assert_eq!(fd_count(), before, "refusal opens nothing");
    drop(held_pin);
    // Phase 2: the worker pair is held elsewhere.
    let held_io = tight.batch().transient().expect("one worker pair exists");
    let before = fd_count();
    let err =
        RetainedGroupMember::acquire(&original, worker.tid, &tight, &mut work, test_deadline())
            .expect_err("exhausted worker class must not mint");
    assert_eq!(err, FD_RESOURCE_REASON);
    assert_eq!(fd_count(), before, "refusal opens nothing");
    drop(held_io);
    // Phase 3: a live member's reads and validation refuse under exhaustion.
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &tight, &mut work, test_deadline())
            .expect("mint works once leases return");
    let held_io = tight.batch().transient().expect("worker pair exists");
    let before = fd_count();
    assert!(
        member.read_exe_identity().is_none(),
        "exhausted reads fail closed"
    );
    let maps_err = member
        .open_maps()
        .expect_err("exhausted maps fail closed")
        .to_string();
    assert_eq!(maps_err, FD_RESOURCE_REASON);
    assert!(
        member.open_map_files_dir().is_err(),
        "exhausted map_files fails closed"
    );
    assert!(
        member.stat_map_file(0x1000, 0x2000).is_err(),
        "exhausted range stats fail closed"
    );
    let err = member
        .validate(test_deadline())
        .expect_err("exhausted validate refuses");
    assert_eq!(err, FD_RESOURCE_REASON);
    assert_eq!(fd_count(), before, "refused reads open nothing");
    drop(held_io);
    assert!(
        member.read_exe_identity().is_some(),
        "reads work once leases return"
    );
    member
        .validate(test_deadline())
        .expect("validate works once leases return");
    drop(member);
}

#[test]
fn retained_group_member_rejects_same_binary_nonleader_exec() {
    let work = unique_workdir("exec");
    let mut child = spawn_python_child(EXEC_SCRIPT, &work);
    let tgid = child.id();
    wait_for_file(&work.join("ready"), "worker ready");
    let tid = read_tid_file(&work.join("ready"));
    assert_ne!(tid, tgid, "worker is a nonleader thread");
    let original = Arc::new(PidPin::open(tgid).expect("python child pins"));
    let (leader0, _) = stat_birth_and_state(std::path::Path::new(&format!("/proc/{tgid}/stat")))
        .expect("leader stat reads");
    let (member0, _) = stat_birth_and_state(std::path::Path::new(&format!(
        "/proc/{tgid}/task/{tid}/stat"
    )))
    .expect("member stat reads");
    assert_ne!(
        leader0, member0,
        "50ms spacing lands on distinct USER_HZ ticks"
    );
    let exe0 = std::fs::metadata(format!("/proc/{tgid}/exe")).expect("pre-exec exe stats");
    let owner = test_owner();
    let mut budget = test_budget();
    let member = RetainedGroupMember::acquire(&original, tid, &owner, &mut budget, test_deadline())
        .expect("pre-exec member mints");
    assert_eq!(member.test_recorded_births(), (member0, leader0));
    member
        .validate(test_deadline())
        .expect("pre-exec member validates");
    std::fs::write(work.join("go"), "go").expect("go writes");
    // The worker execs the same binary from the nonleader; the exec'd image
    // acks with `execed`. The kernel preserves the TGID birth across the
    // exec (process identity stays stable), so the invalidation signal is the
    // TID exchange alone: the old member is gone.
    wait_for_file(&work.join("execed"), "exec landed");
    let (leader1, _) = stat_birth_and_state(std::path::Path::new(&format!("/proc/{tgid}/stat")))
        .expect("post-exec leader stat reads");
    assert_eq!(
        leader1, leader0,
        "kernel preserves TGID birth across nonleader exec"
    );
    let exe1 = std::fs::metadata(format!("/proc/{tgid}/exe")).expect("post-exec exe stats");
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(
        (exe1.dev(), exe1.ino()),
        (exe0.dev(), exe0.ino()),
        "exec kept the same binary"
    );
    let mut tasks: Vec<String> = std::fs::read_dir(format!("/proc/{tgid}/task"))
        .expect("task lists")
        .map(|entry| {
            entry
                .expect("entry reads")
                .file_name()
                .into_string()
                .expect("name decodes")
        })
        .collect();
    tasks.sort();
    assert_eq!(tasks, vec![tgid.to_string()], "only the new leader remains");
    let err = member
        .validate(test_deadline())
        .expect_err("post-exec member must not validate");
    assert!(err.contains("no longer"), "unexpected refusal: {err}");
    drop(member);
    let err = RetainedGroupMember::acquire(&original, tid, &owner, &mut budget, test_deadline())
        .expect_err("exchanged TID must not mint");
    assert!(
        err.contains("not a live member"),
        "unexpected refusal: {err}"
    );
    // Same (tgid, birth): the new leader mints as the same generation, so
    // post-exec custody keeps working (consistent with `PidPin::still_the_same`).
    let member =
        RetainedGroupMember::acquire(&original, tgid, &owner, &mut budget, test_deadline())
            .expect("post-exec leader mints as the same generation");
    member
        .validate(test_deadline())
        .expect("post-exec leader validates");
    drop(member);
    child.kill().expect("post-exec child dies");
    let _ = child.wait();
    remove_workdir(&work);
}

#[test]
fn retained_group_member_rejects_mid_proof_replacement() {
    let worker = WaitingThread::spawn();
    let original = Arc::new(PidPin::open(std::process::id()).expect("self pins"));
    let owner = test_owner();
    let mut work = test_budget();
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("first mint works");
    // A second mint while the proof is live fails — the original Arc stays
    // the only authority for this slot.
    let err =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect_err("re-acquire mid-proof must fail");
    assert!(
        err.contains("already retained"),
        "unexpected refusal: {err}"
    );
    // Without the original Arc the member authorizes nothing.
    drop(original);
    let err = member
        .validate(test_deadline())
        .expect_err("released original authorizes nothing");
    assert!(err.contains("original"), "unexpected refusal: {err}");
    let err = member
        .selector()
        .expect_err("released original selects nothing");
    assert!(err.contains("original"), "unexpected refusal: {err}");
    drop(member);
    // Once the proof drops, the same generation mints again.
    let original = Arc::new(PidPin::open(std::process::id()).expect("self pins"));
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("mint works after the earlier proof dropped");
    member
        .validate(test_deadline())
        .expect("re-minted member validates");
    drop(member);
}

/// An opener that opens the real directory, then kills the worker (a raced
/// death strictly after the open, converged before returning) so the
/// post-open bracket is deterministic.
fn kill_after_open<'a>(
    worker: &'a RefCell<Option<WaitingThread>>,
    tgid: u32,
) -> impl Fn(&std::path::Path) -> Result<OwnedFd, String> + 'a {
    move |path: &std::path::Path| {
        let dir = open_dir_fd(path)?;
        if let Some(victim) = worker.borrow_mut().take() {
            let tid = victim.tid;
            victim.kill_and_join();
            poll_thread_dead(tgid, tid);
        }
        Ok(dir)
    }
}

/// The first file-backed executable range of this process, for range stats
/// that must reach the map_files entry itself.
fn self_executable_file_range() -> (u64, u64) {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("self maps read");
    maps.lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let addrs = parts.next()?;
            let perms = parts.next()?;
            if perms.as_bytes().get(2) != Some(&b'x') || !line.contains('/') {
                return None;
            }
            let (start, end) = addrs.split_once('-')?;
            Some((
                u64::from_str_radix(start, 16).ok()?,
                u64::from_str_radix(end, 16).ok()?,
            ))
        })
        .expect("one file-backed executable range exists")
}

#[test]
fn retained_group_member_reproves_map_files_open_and_stat() {
    if !ensure_quiescent_child(
        "discovery::retained_member::tests::retained_group_member_reproves_map_files_open_and_stat",
    ) {
        return;
    }
    let tgid = std::process::id();
    let original = Arc::new(PidPin::open(tgid).expect("self pins"));
    let owner = test_owner();
    let mut work = test_budget();
    let (start, end) = self_executable_file_range();
    // Phase A: a death raced between the pre-open proof and the open must
    // refuse the directory (never serve a reused TGID's map_files).
    let worker = WaitingThread::spawn();
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("live member mints");
    let victim = RefCell::new(Some(worker));
    let opener = kill_after_open(&victim, tgid);
    let before = fd_count();
    let err = match member.open_map_files_dir_with_opener(&opener) {
        Ok(_) => panic!("raced death must refuse the directory"),
        Err(err) => err,
    };
    assert!(err.contains("no longer"), "unexpected refusal: {err}");
    assert_eq!(
        fd_count(),
        before,
        "refused open closes the raced directory"
    );
    drop(member);
    // Phase B: the same raced death refuses the one-shot range stat.
    let worker = WaitingThread::spawn();
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &owner, &mut work, test_deadline())
            .expect("live member mints");
    let victim = RefCell::new(Some(worker));
    let opener = kill_after_open(&victim, tgid);
    let before = fd_count();
    let err = member
        .stat_map_file_with_opener(start, end, &opener)
        .expect_err("raced death must refuse the range stat");
    assert!(err.contains("no longer"), "unexpected refusal: {err}");
    assert_eq!(
        fd_count(),
        before,
        "refused stat closes the raced directory"
    );
    drop(member);
    // Phase C: a death between the open and the stat refuses even though
    // the guard opened while live (the proof runs even when the stat
    // itself fails, so the custody refusal dominates a stale lookup).
    let worker = WaitingThread::spawn();
    let tid = worker.tid;
    let member = RetainedGroupMember::acquire(&original, tid, &owner, &mut work, test_deadline())
        .expect("live member mints");
    let guard = member.open_map_files_dir().expect("guard opens while live");
    worker.kill_and_join();
    poll_thread_dead(tgid, tid);
    let before = fd_count();
    let err = member
        .test_stat_guarded(&guard, start, end)
        .expect_err("dead member serves no range identity");
    assert!(err.contains("no longer"), "unexpected refusal: {err}");
    assert_eq!(fd_count(), before, "refused stat opens nothing");
    drop(guard);
    drop(member);
}

#[test]
fn retained_group_member_selector_refuses_fd_exhaustion() {
    if !ensure_quiescent_child(
        "discovery::retained_member::tests::retained_group_member_selector_refuses_fd_exhaustion",
    ) {
        return;
    }
    let worker = WaitingThread::spawn();
    let original = Arc::new(PidPin::open(std::process::id()).expect("self pins"));
    let tight = ReservationOwner::new(SegmentPolicy::from_headroom(9, 1, 1));
    let mut work = test_budget();
    let member =
        RetainedGroupMember::acquire(&original, worker.tid, &tight, &mut work, test_deadline())
            .expect("mint works with headroom");
    member.selector().expect("selector works with headroom");
    let held_io = tight.batch().transient().expect("worker pair exists");
    let before = fd_count();
    let err = member
        .selector()
        .expect_err("exhausted selector refuses like its siblings");
    assert_eq!(err, FD_RESOURCE_REASON);
    assert_eq!(fd_count(), before, "refused selector opens nothing");
    drop(held_io);
    member
        .selector()
        .expect("selector works once leases return");
    drop(member);
}

#[test]
fn retained_group_member_tgkill_gate_detects_live_and_reaped_threads() {
    use super::thread_alive_in_group;
    let worker = WaitingThread::spawn();
    let tgid = std::process::id();
    assert!(
        thread_alive_in_group(tgid, worker.tid),
        "live worker reads alive"
    );
    let child_a = PausingChild::spawn();
    let child_b = PausingChild::spawn();
    assert!(
        thread_alive_in_group(child_a.pid, child_a.pid),
        "live child leader reads alive"
    );
    assert!(
        !thread_alive_in_group(child_a.pid, child_b.pid),
        "a tid outside the group reads dead"
    );
    let dead_tid = worker.tid;
    worker.kill_and_join();
    poll_thread_dead(tgid, dead_tid);
    assert!(
        !thread_alive_in_group(tgid, dead_tid),
        "reaped tid reads dead"
    );
}
