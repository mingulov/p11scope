//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pre-arm witness privileged behavior cells (WU-13 P-C phase 2, P2-7):
//! the binding §11 matrix through the live driver on real kernels.
//! Fixture children re-exec this test binary into
//! `witness_fixture_entrypoint` (manifest-helper precedent); the watched
//! target is a private fixture `.so` (nobody else maps it, so Clean and
//! Latched positives are deterministic on busy hosts). Cells serialize
//! on `CELL_LOCK`: system-scope witnesses share global departure state,
//! so the held-teardown cells would otherwise unbalance every concurrently
//! active witness. Every child interaction carries a timeout; nothing
//! here can hang, only fail loudly.

use super::{FileVerdict, FinalizeBackend, KeepReason, Unavailable, WitnessVerdict};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

/// Re-exec entrypoint selector for fixture children.
const ENTRYPOINT: &str = "attach::prearm_witness::prearm_witness_tests::witness_fixture_entrypoint";
/// Fixture protocol environment.
const ENV_CHILD: &str = "P11SCOPE_PW_CHILD";
const ENV_SO: &str = "P11SCOPE_PW_SO";
const ENV_MEMBER_PID: &str = "P11SCOPE_PW_MEMBER_PID";
const ENV_RELEASE: &str = "P11SCOPE_PW_RELEASE";
/// Arms the 1M-VMA assertion in the scale cell (set by the loaded-guest
/// procedure only; the walk-completes positive runs everywhere).
const ENV_SCALE_MM: &str = "P11SCOPE_PW_SCALE_MM";
/// Every child interaction times out; silent children fail, never hang.
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// Serializes the P2-7 cells within this test binary (the outer
/// privileged.lock serializes separate runs).
static CELL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// P2-7 scenarios with live-kernel verdicts.
#[derive(Debug, Clone, Copy)]
enum Cell {
    /// Fixture maps and calls F only after finalize.
    MapAndCallAfterFinalize,
    /// The observer maps F itself during startup (excluded).
    ObserverSelfMap,
    /// F mapped read-only before start.
    RoMappedBeforeStart,
    /// RO → mprotect X → call → RO during the window.
    MprotectDance,
    /// Map and unmap inside the window.
    MapUnmapInsideWindow,
    /// Leader `pthread_exit`s while a thread holds F mapped.
    ZombieLeader,
    /// Member exits while a holder pins its address space.
    HeldTeardown,
    /// Member execs while a holder pins the old address space.
    ExecUnderHolder,
    /// A `--cgroup` member migrates out during the window.
    CgroupMigrateOut,
}

/// Runs one scenario against the live driver and returns the finalized
/// driver verdict.
fn run_cell(cell: Cell) -> WitnessVerdict {
    let _serial = CELL_LOCK.lock().expect("cell lock");
    match cell {
        Cell::MapAndCallAfterFinalize => scenario_map_and_call_after_finalize(),
        Cell::ObserverSelfMap => scenario_observer_self_map(),
        Cell::RoMappedBeforeStart => scenario_ro_mapped_before_start(),
        Cell::MprotectDance => scenario_mprotect_dance(),
        Cell::MapUnmapInsideWindow => scenario_map_unmap_inside_window(),
        Cell::ZombieLeader => scenario_zombie_leader(),
        Cell::HeldTeardown => scenario_held_teardown(),
        Cell::ExecUnderHolder => scenario_exec_under_holder(),
        Cell::CgroupMigrateOut => scenario_cgroup_migrate_out(),
    }
}

/// Starts the witness from inside a nested PID namespace and returns the
/// outcome (the `Pidns` refusal, on a correct kernel).
fn probe_nested_pidns_start() -> Result<WitnessVerdict, Unavailable> {
    let _serial = CELL_LOCK.lock().expect("cell lock");
    scenario_nested_pidns()
}

fn single_verdict(verdict: &WitnessVerdict) -> FileVerdict {
    assert_eq!(verdict.slots.len(), 1, "one watched file per cell");
    verdict.slots[0].verdict
}

fn pidns_initial() -> bool {
    matches!(
        crate::pidns::observer(),
        crate::pidns::ObserverPidNs::Initial
    )
}

/// A fixture child with a line protocol, timeouts, and Drop cleanup
/// (killed and reaped, best effort, never panicking).
struct FixtureChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
}

impl FixtureChild {
    /// Spawns the re-exec entrypoint with `mode` and extra env. `pipes`
    /// selects stdin/stdout pipes (null otherwise).
    fn spawn(mode: &str, envs: &[(&str, &str)], pipes: bool) -> Self {
        let exe = std::env::current_exe().expect("current test binary");
        let mut command = Command::new(exe);
        command.args([ENTRYPOINT, "--exact", "--ignored", "--nocapture"]);
        command.env(ENV_CHILD, mode);
        for (key, value) in envs {
            command.env(key, value);
        }
        if pipes {
            command.stdin(Stdio::piped()).stdout(Stdio::piped());
        } else {
            command.stdin(Stdio::null()).stdout(Stdio::piped());
        }
        // Stderr stays inherited: child diagnostics stay visible.
        let mut child = command.spawn().expect("spawn fixture child");
        let stdin = pipes.then(|| child.stdin.take().expect("child stdin"));
        let stdout = Some(child.stdout.take().expect("child stdout"));
        let mut this = Self {
            child,
            stdin,
            stdout,
        };
        this.set_nonblocking();
        this
    }

    /// Spawns a directly-executed fixture binary (not the re-exec
    /// entrypoint): stdin null, stdout piped for the `READY` line.
    fn spawn_binary(path: &Path, envs: &[(&str, &str)]) -> Self {
        let mut command = Command::new(path);
        for (key, value) in envs {
            command.env(key, value);
        }
        command.stdin(Stdio::null()).stdout(Stdio::piped());
        // Stderr stays inherited: fixture diagnostics stay visible.
        let mut child = command.spawn().expect("spawn fixture binary");
        let stdout = Some(child.stdout.take().expect("child stdout"));
        let mut this = Self {
            child,
            stdin: None,
            stdout,
        };
        this.set_nonblocking();
        this
    }

    fn set_nonblocking(&mut self) {
        use std::os::unix::io::AsRawFd as _;
        let fd = self.stdout.as_ref().expect("stdout").as_raw_fd();
        // SAFETY: fcntl flag juggling on our own pipe end.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0, "getfl child stdout");
        let set = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        assert_eq!(set, 0, "nonblock child stdout");
    }

    /// Sends one protocol line.
    fn send(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().expect("child stdin");
        writeln!(stdin, "{line}").expect("write to fixture child");
        stdin.flush().expect("flush to fixture child");
    }

    /// Reads one protocol line (poll, `CHILD_TIMEOUT`); panics on
    /// timeout, EOF, or hangup instead of hanging. The re-exec'd child
    /// is a libtest binary, so its own framing lines (`running 1 test`,
    /// blank lines, result summaries) are skipped; anything else that is
    /// not a protocol line fails loudly with its content.
    fn recv(&mut self) -> String {
        loop {
            let line = self.recv_raw();
            let trimmed = line.trim_end_matches('\n');
            if trimmed.is_empty()
                || trimmed.starts_with("running ")
                || trimmed.starts_with("test ")
                || trimmed.starts_with("test result")
                || trimmed.starts_with("failures")
                || trimmed.starts_with("error")
                || trimmed.starts_with("note: ")
            {
                continue;
            }
            return line;
        }
    }

    /// Reads one raw stdout line from the child.
    fn recv_raw(&mut self) -> String {
        use std::os::unix::io::AsRawFd as _;
        let fd = self.stdout.as_ref().expect("stdout").as_raw_fd();
        let deadline = Instant::now() + CHILD_TIMEOUT;
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll on our own pipe end.
            let ready = unsafe { libc::poll(&mut pfd, 1, remaining.as_millis() as i32) };
            assert!(
                ready > 0,
                "fixture child silent for {}s",
                CHILD_TIMEOUT.as_secs()
            );
            if pfd.revents & libc::POLLIN != 0 {
                // SAFETY: single-byte read into a stack slot.
                let got = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
                if got == 0 {
                    let status = self.child.try_wait().ok().flatten();
                    panic!(
                        "fixture child EOF waiting for a line (status: {status:?}; \
                         its stderr is inherited above)"
                    );
                }
                if got < 0 {
                    let error = std::io::Error::last_os_error();
                    assert_eq!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock,
                        "child stdout read: {error}"
                    );
                    continue;
                }
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            } else if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
                panic!("fixture child pipe hung up");
            }
        }
        String::from_utf8(line).expect("child speaks UTF-8")
    }

    /// Sends a command and expects an ack line starting with `prefix`;
    /// returns the full ack line.
    fn roundtrip(&mut self, command: &str, prefix: &str) -> String {
        self.send(command);
        let ack = self.recv();
        assert!(
            ack.starts_with(prefix),
            "expected {prefix:?}, child said {ack:?}"
        );
        ack
    }

    /// Waits up to `CHILD_TIMEOUT`, then kills and panics.
    fn wait_expect(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "fixture child would not exit within {}s",
                CHILD_TIMEOUT.as_secs()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for FixtureChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The fixture target source: pure functions, no side effects. Written
/// to the cell dir and compiled at runtime (no committed C file, so no
/// fixture-license row beyond the §12 single-writer slot).
const TARGET_C: &str = r#"
int p11pw_target(void)
{
    return 42;
}

int p11pw_add(int x, int y)
{
    return x + y;
}
"#;

/// The zombie-leader fixture source: maps F, parks a detached holder
/// thread, then the process leader itself `pthread_exit`s (no
/// `exit_group`: `main` never returns). A re-exec'd libtest binary cannot
/// do this — the entrypoint runs on a worker thread, so its `pthread_exit`
/// releases libtest's main into a full process exit that kills the holder
/// (observed: deterministic `Clear` instead of `Found`). Like `TARGET_C`,
/// written to the cell dir and compiled at runtime (no committed C file).
const ZOMBIE_C: &str = r#"
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *holder_thread(void *arg)
{
    (void)arg;
    sleep(300);
    return NULL;
}

int main(void)
{
    const char *so = getenv("P11SCOPE_PW_SO");
    pthread_t thread;
    if (!so)
        return 2;
    if (!dlopen(so, RTLD_NOW | RTLD_LOCAL))
        return 1;
    if (pthread_create(&thread, NULL, holder_thread, NULL))
        return 1;
    pthread_detach(thread);
    printf("READY\n");
    fflush(stdout);
    pthread_exit(NULL);
    return 0;
}
"#;

/// Builds the zombie-leader fixture binary with the system compiler.
fn build_zombie_bin(dir: &Path) -> PathBuf {
    let src = dir.join("p11pw-zombie.c");
    std::fs::write(&src, ZOMBIE_C).expect("write zombie fixture source");
    let out = dir.join("p11pw-zombie");
    let compile = Command::new("gcc")
        .args(["-O2", "-pthread", "-o"])
        .arg(&out)
        .arg(&src)
        .output()
        .expect("execute gcc for the zombie fixture");
    assert!(
        compile.status.success(),
        "zombie fixture compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    out
}

/// Builds the private fixture target `.so` (nobody else maps it) with the
/// system compiler.
fn build_target_so(dir: &Path) -> PathBuf {
    let src = dir.join("p11pw-target.c");
    std::fs::write(&src, TARGET_C).expect("write fixture target source");
    let out = dir.join("p11pw-target.so");
    let compile = Command::new("gcc")
        .args(["-shared", "-fPIC", "-O2", "-o"])
        .arg(&out)
        .arg(&src)
        .output()
        .expect("execute gcc for the fixture target");
    assert!(
        compile.status.success(),
        "fixture target compile failed: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    out
}

/// Polls until `pid` (or the `tid` thread of it) shows state `Z`.
fn poll_zombie(pid: u32, tid: Option<u32>) {
    let path = match tid {
        Some(tid) => format!("/proc/{pid}/task/{tid}/stat"),
        None => format!("/proc/{pid}/stat"),
    };
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if let Ok(stat) = std::fs::read_to_string(&path) {
            let zombie = stat
                .rsplit(')')
                .next()
                .and_then(|after| after.split_whitespace().next())
                == Some("Z");
            if zombie {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "no zombie at {path} within {}s",
            CHILD_TIMEOUT.as_secs()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `poll_zombie` observes a real unreaped child: the state is the first
/// field after `comm` (`process_is_zombie` precedent). Regression test:
/// reading the second field (ppid) instead can never match `Z`, so every
/// zombie cell times out.
#[test]
fn poll_zombie_sees_a_real_zombie() {
    let mut child = Command::new("true").spawn().expect("spawn true");
    let pid = child.id();
    // The child exits at once; left unreaped it is a zombie until the
    // `wait` below. `poll_zombie` must return, not time out.
    poll_zombie(pid, None);
    let status = child.wait().expect("reap the zombie");
    assert!(status.success(), "true exits clean");
}

/// Starts the live witness on one target in the caller-chosen scope.
fn live_start(
    so: &Path,
    scope: &crate::attach::Scope,
) -> super::StartupWitness<super::LiveBackend> {
    super::start(
        &[so.to_path_buf()],
        scope,
        pidns_initial(),
        &mut crate::discovery::scan::CaptureWorkBudget::default(),
    )
    .expect("live witness starts")
}

fn scenario_map_and_call_after_finalize() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let mut child = FixtureChild::spawn("scripted", &[(ENV_SO, so_str)], true);
    // PID scope: the hooks ignore every ambient task, so the verdict is
    // deterministic even when unrelated processes exit mid-window.
    let witnessed = live_start(&so, &crate::attach::Scope::Pid(child.child.id()));
    let verdict = witnessed.finalize(false).expect("verdict");
    // Only now does the fixture map and call: the verdict predates it.
    child.roundtrip("MAP", "OK MAP");
    let ack = child.roundtrip("CALL", "OK CALL 42");
    assert!(ack.contains("42"), "target returns 42: {ack:?}");
    child.roundtrip("QUIT", "OK QUIT");
    let status = child.wait_expect();
    assert!(status.success(), "fixture child exits clean");
    verdict
}

fn scenario_observer_self_map() -> WitnessVerdict {
    use std::os::unix::io::AsRawFd as _;
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let witnessed = live_start(&so, &crate::attach::Scope::System);
    // The observer maps F itself mid-window: excluded, still clean.
    let file = std::fs::File::open(&so).expect("open target");
    let len = file.metadata().expect("fstat").len() as usize;
    // SAFETY: anonymous-length private read-only mapping of our own file.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            file.as_raw_fd(),
            0,
        )
    };
    assert_ne!(addr, libc::MAP_FAILED, "self-map the target");
    let verdict = witnessed.finalize(false).expect("verdict");
    // SAFETY: unmap exactly what the mmap above returned.
    assert_eq!(unsafe { libc::munmap(addr, len) }, 0, "self-unmap");
    verdict
}

fn scenario_ro_mapped_before_start() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let mut child = FixtureChild::spawn("scripted", &[(ENV_SO, so_str)], true);
    child.roundtrip("MAP", "OK MAP");
    // PID scope: ambient-immune (see scenario_map_and_call_after_finalize).
    let witnessed = live_start(&so, &crate::attach::Scope::Pid(child.child.id()));
    let verdict = witnessed.finalize(false).expect("verdict");
    drop(child);
    verdict
}

fn scenario_mprotect_dance() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let mut child = FixtureChild::spawn("scripted", &[(ENV_SO, so_str)], true);
    child.roundtrip("MAP", "OK MAP");
    // PID scope: ambient-immune (see scenario_map_and_call_after_finalize).
    let witnessed = live_start(&so, &crate::attach::Scope::Pid(child.child.id()));
    child.roundtrip("MPROTECT_RO", "OK MPROTECT_RO");
    child.roundtrip("MPROTECT_X", "OK MPROTECT_X");
    let ack = child.roundtrip("CALL", "OK CALL 42");
    assert!(ack.contains("42"), "target returns 42: {ack:?}");
    child.roundtrip("MPROTECT_RO", "OK MPROTECT_RO");
    let verdict = witnessed.finalize(false).expect("verdict");
    drop(child);
    verdict
}

fn scenario_map_unmap_inside_window() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let mut child = FixtureChild::spawn("scripted", &[(ENV_SO, so_str)], true);
    // PID scope: ambient-immune (see scenario_map_and_call_after_finalize).
    let witnessed = live_start(&so, &crate::attach::Scope::Pid(child.child.id()));
    child.roundtrip("MMAP_FILE", "OK MMAP_FILE");
    child.roundtrip("MUNMAP_FILE", "OK MUNMAP_FILE");
    let verdict = witnessed.finalize(false).expect("verdict");
    drop(child);
    verdict
}

fn scenario_zombie_leader() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let zombie = build_zombie_bin(dir.path());
    let mut child = FixtureChild::spawn_binary(&zombie, &[(ENV_SO, so_str)]);
    let ack = child.recv();
    assert!(ack.starts_with("READY"), "zombie maps first: {ack:?}");
    // The leader (tid == pid) must be a stable zombie while a thread
    // holds F; the kernel skips the zombie and visits the thread.
    let pid = child.child.id();
    poll_zombie(pid, Some(pid));
    let witnessed = live_start(&so, &crate::attach::Scope::System);
    let verdict = witnessed.finalize(false).expect("verdict");
    drop(child);
    verdict
}

fn scenario_held_teardown() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let release = dir.path().join("release");
    let release_str = release.to_str().expect("utf8 release path");
    let mut member = FixtureChild::spawn("scripted", &[(ENV_SO, so_str)], true);
    member.roundtrip("MAP", "OK MAP");
    let member_pid = member.child.id().to_string();
    let mut holder = FixtureChild::spawn(
        "holder",
        &[(ENV_MEMBER_PID, &member_pid), (ENV_RELEASE, release_str)],
        false,
    );
    let ack = holder.recv();
    assert!(ack.starts_with("PINNED"), "holder pins first: {ack:?}");
    let witnessed = live_start(&so, &crate::attach::Scope::System);
    // The member exits while the holder pins its address space: the
    // departure is recorded (zombie proves exit_mm ran) but teardown
    // cannot complete until the holder is released.
    member.roundtrip("EXIT", "OK EXIT");
    poll_zombie(member.child.id(), None);
    let verdict = witnessed.finalize(false).expect("verdict");
    std::fs::write(&release, b"go\n").expect("release the holder");
    let ack = holder.recv();
    assert!(ack.starts_with("DONE"), "holder drains: {ack:?}");
    let status = holder.wait_expect();
    assert!(status.success(), "holder exits clean");
    let status = member.wait_expect();
    assert!(status.success(), "member exits clean");
    verdict
}

fn scenario_exec_under_holder() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let release = dir.path().join("release");
    let release_str = release.to_str().expect("utf8 release path");
    let mut member = FixtureChild::spawn("scripted", &[(ENV_SO, so_str)], true);
    member.roundtrip("MAP", "OK MAP");
    let member_pid = member.child.id().to_string();
    let mut holder = FixtureChild::spawn(
        "holder",
        &[(ENV_MEMBER_PID, &member_pid), (ENV_RELEASE, release_str)],
        false,
    );
    let ack = holder.recv();
    assert!(ack.starts_with("PINNED"), "holder pins first: {ack:?}");
    let witnessed = live_start(&so, &crate::attach::Scope::System);
    // The member execs into a just-exit image: the old-mm departure is
    // recorded but its teardown stays pinned; the new mm exits cleanly.
    member.send("EXEC_JUST_EXIT");
    let status = member.wait_expect();
    assert_eq!(status.code(), Some(42), "exec lands in just_exit");
    let verdict = witnessed.finalize(false).expect("verdict");
    std::fs::write(&release, b"go\n").expect("release the holder");
    let ack = holder.recv();
    assert!(ack.starts_with("DONE"), "holder drains: {ack:?}");
    let status = holder.wait_expect();
    assert!(status.success(), "holder exits clean");
    verdict
}

/// A cgroup created for the migration cell; removed on drop.
struct CellCgroup {
    path: PathBuf,
}

impl CellCgroup {
    fn create(name: &str) -> Self {
        let path = PathBuf::from("/sys/fs/cgroup").join(name);
        std::fs::create_dir(&path).expect("create cell cgroup");
        Self { path }
    }

    fn place(&self, pid: u32) {
        std::fs::write(self.path.join("cgroup.procs"), pid.to_string())
            .expect("place member in cgroup");
    }
}

impl Drop for CellCgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn scenario_cgroup_migrate_out() -> WitnessVerdict {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let cgroup = CellCgroup::create(&format!("p11pw-cell-{}", std::process::id()));
    let scope = crate::scope::cgroup(&cgroup.path).expect("cgroup scope");
    // A pure sleeper: migration alone must report `migration`.
    let mut member = FixtureChild::spawn("sleep", &[], false);
    let ack = member.recv();
    assert!(ack.starts_with("READY"), "sleeper ready: {ack:?}");
    let pid = member.child.id();
    cgroup.place(pid);
    let witnessed = live_start(&so, &scope);
    // Migrate out to the root (the write returning means the hook ran).
    std::fs::write("/sys/fs/cgroup/cgroup.procs", pid.to_string()).expect("migrate member out");
    let verdict = witnessed.finalize(false).expect("verdict");
    drop(member);
    drop(cgroup);
    verdict
}

fn scenario_nested_pidns() -> Result<WitnessVerdict, Unavailable> {
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let so_str = so.to_str().expect("utf8 so path");
    let mut probe = FixtureChild::spawn("nested_probe", &[(ENV_SO, so_str)], false);
    let mut saw_marker = false;
    let deadline = Instant::now() + CHILD_TIMEOUT;
    // The probe forwards the inner report, then PROBE-OK.
    loop {
        let line = probe.recv();
        if line.contains("PIDNS-UNAVAILABLE") {
            saw_marker = true;
        }
        if line.starts_with("PROBE-OK") {
            break;
        }
        assert!(Instant::now() < deadline, "nested probe never reported");
    }
    let status = probe.wait_expect();
    assert!(status.success(), "nested probe exits clean");
    assert!(saw_marker, "inner start refused in the nested ns");
    Err(Unavailable::Pidns(
        "nested observer refused (via probe)".into(),
    ))
}

#[test]
#[ignore = "privileged: witness P2-7 map-and-call-after-finalize cell"]
fn privileged_map_and_call_after_finalize_is_clean() {
    let verdict = run_cell(Cell::MapAndCallAfterFinalize);
    assert_eq!(single_verdict(&verdict), FileVerdict::Clear);
}

#[test]
#[ignore = "privileged: witness P2-7 observer-self-map cell"]
fn privileged_observer_self_map_during_startup_is_clean() {
    let verdict = run_cell(Cell::ObserverSelfMap);
    assert_eq!(single_verdict(&verdict), FileVerdict::Clear);
}

#[test]
#[ignore = "privileged: witness P2-7 read-only-mapping cell"]
fn privileged_readonly_mapped_before_start_is_found() {
    let verdict = run_cell(Cell::RoMappedBeforeStart);
    assert_eq!(
        single_verdict(&verdict),
        FileVerdict::Keep(KeepReason::Found)
    );
}

#[test]
#[ignore = "privileged: witness P2-7 mprotect-dance cell"]
fn privileged_mprotect_dance_before_finalize_is_found() {
    let verdict = run_cell(Cell::MprotectDance);
    assert_eq!(
        single_verdict(&verdict),
        FileVerdict::Keep(KeepReason::Found)
    );
}

#[test]
#[ignore = "privileged: witness P2-7 map-unmap cell"]
fn privileged_map_unmap_inside_window_is_latched() {
    let verdict = run_cell(Cell::MapUnmapInsideWindow);
    assert_eq!(
        single_verdict(&verdict),
        FileVerdict::Keep(KeepReason::Latched)
    );
}

#[test]
#[ignore = "privileged: witness P2-7 zombie-leader cell"]
fn privileged_zombie_leader_holding_file_is_found() {
    let verdict = run_cell(Cell::ZombieLeader);
    assert_eq!(
        single_verdict(&verdict),
        FileVerdict::Keep(KeepReason::Found)
    );
}

#[test]
#[ignore = "privileged: witness P2-7 held-teardown cell"]
fn privileged_held_teardown_is_pending() {
    let verdict = run_cell(Cell::HeldTeardown);
    assert_eq!(
        single_verdict(&verdict),
        FileVerdict::Keep(KeepReason::Pending)
    );
}

#[test]
#[ignore = "privileged: witness P2-7 exec-departure cell"]
fn privileged_exec_departure_under_holder_is_pending() {
    let verdict = run_cell(Cell::ExecUnderHolder);
    assert_eq!(
        single_verdict(&verdict),
        FileVerdict::Keep(KeepReason::Pending)
    );
}

#[test]
#[ignore = "privileged: witness P2-7 cgroup-migration cell"]
fn privileged_cgroup_member_migrated_out_is_migration() {
    let verdict = run_cell(Cell::CgroupMigrateOut);
    assert_eq!(
        single_verdict(&verdict),
        FileVerdict::Keep(KeepReason::Migration)
    );
}

#[test]
#[ignore = "privileged: witness P2-7 nested-pidns cell"]
fn privileged_nested_pidns_observer_is_unavailable() {
    match probe_nested_pidns_start() {
        Err(Unavailable::Pidns(_)) => {}
        other => panic!("nested observer must be refused: {other:?}"),
    }
}

/// P2-7 scale: the presence walk completes on the running kernel; the
/// resumption count, wall time and visited VMAs are recorded. The 1M-VMA
/// assertion arms only under `P11SCOPE_PW_SCALE_MM=1M` (the loaded-guest
/// procedure); the walk-completes positive runs everywhere.
#[test]
#[ignore = "privileged: witness P2-7 scale walk cell"]
fn privileged_walk_scale_completes() {
    let _serial = CELL_LOCK.lock().expect("cell lock");
    let dir = tempfile::tempdir().expect("cell dir");
    let so = build_target_so(dir.path());
    let mut witnessed = live_start(&so, &crate::attach::Scope::System);
    let outcome = witnessed.backend.run_walk().expect("walk runs");
    assert!(
        matches!(outcome, super::WalkOutcome::Done),
        "walk completes: {outcome:?}"
    );
    let state = witnessed.backend.read_state().expect("walk state");
    assert_eq!(state.walk_end, 1, "exactly one END");
    let (resumptions, ns) = witnessed.backend.last_walk_measurement();
    eprintln!(
        "witness-scale: vmas={} resumptions={resumptions} ns={ns}",
        state.walk_vmas
    );
    if std::env::var(ENV_SCALE_MM).as_deref() == Ok("1M") {
        assert!(
            state.walk_vmas >= 1_000_000,
            "loaded guest holds 1M VMAs: {}",
            state.walk_vmas
        );
    }
    drop(witnessed);
}

/// Re-exec entrypoint for fixture children (manifest-helper precedent):
/// the mode comes from `P11SCOPE_PW_CHILD`. Not a standalone cell.
#[test]
#[ignore = "private witness fixture helper; invoked by P2-7 cells"]
fn witness_fixture_entrypoint() {
    match std::env::var(ENV_CHILD).expect("fixture mode").as_str() {
        "scripted" => fixture_scripted(),
        "just_exit" => std::process::exit(42),
        "holder" => fixture_holder(),
        "sleep" => fixture_sleep(),
        "nested_probe" => fixture_nested_probe(),
        "nested_inner" => fixture_nested_inner(),
        mode => panic!("unknown fixture mode: {mode}"),
    }
}

/// Print one protocol line, flushed (pipe stdout is block-buffered).
fn say(line: &str) {
    println!("{line}");
    std::io::stdout().flush().expect("flush ack");
}

/// The scripted fixture child: dlopen/mmap/mprotect/call/unmap/exit.
fn fixture_scripted() {
    use std::io::BufRead as _;
    use std::os::unix::io::AsRawFd as _;
    let so = std::env::var(ENV_SO).expect("fixture so path");
    let so_c = std::ffi::CString::new(so).expect("cstr so");
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut func: usize = 0;
    let mut mapped: Option<(*mut std::ffi::c_void, usize)> = None;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    assert!(page > 0, "page size");
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.expect("read command").trim().to_string();
        match line.as_str() {
            "MAP" => {
                assert!(handle.is_null(), "already mapped");
                // SAFETY: dlopen of the fixture target.
                handle = unsafe { libc::dlopen(so_c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
                assert!(!handle.is_null(), "dlopen the target");
                // SAFETY: dlsym of a present symbol.
                let sym = unsafe { libc::dlsym(handle, c"p11pw_target".as_ptr()) };
                assert!(!sym.is_null(), "dlsym p11pw_target");
                func = sym as usize;
                say("OK MAP");
            }
            "CALL" => {
                assert!(func != 0, "call before map");
                // SAFETY: the target is `int p11pw_target(void)`.
                let target: unsafe extern "C" fn() -> i32 = unsafe { std::mem::transmute(func) };
                let ret = unsafe { target() };
                say(&format!("OK CALL {ret}"));
            }
            "MPROTECT_RO" | "MPROTECT_X" => {
                assert!(func != 0, "mprotect before map");
                let prot = if line.ends_with("_X") {
                    libc::PROT_READ | libc::PROT_EXEC
                } else {
                    libc::PROT_READ
                };
                let base = func & !(page - 1);
                // SAFETY: two pages from the aligned base cover the tiny
                // target even across a page boundary.
                let applied = unsafe { libc::mprotect(base as *mut _, 2 * page, prot) };
                assert_eq!(applied, 0, "mprotect the target page");
                say(&format!("OK {line}"));
            }
            "MMAP_FILE" => {
                assert!(mapped.is_none(), "already file-mapped");
                let file = std::fs::File::open(std::env::var(ENV_SO).expect("fixture so path"))
                    .expect("open target");
                let len = file.metadata().expect("fstat").len() as usize;
                // SAFETY: private read-only mapping of our own file.
                let addr = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        len,
                        libc::PROT_READ,
                        libc::MAP_PRIVATE,
                        file.as_raw_fd(),
                        0,
                    )
                };
                assert_ne!(addr, libc::MAP_FAILED, "mmap the target");
                mapped = Some((addr, len));
                say("OK MMAP_FILE");
            }
            "MUNMAP_FILE" => {
                let (addr, len) = mapped.take().expect("mapped first");
                // SAFETY: unmap exactly what MMAP_FILE returned.
                assert_eq!(unsafe { libc::munmap(addr, len) }, 0, "munmap");
                say("OK MUNMAP_FILE");
            }
            "EXIT" => {
                say("OK EXIT");
                std::process::exit(0);
            }
            "EXEC_JUST_EXIT" => {
                use std::os::unix::process::CommandExt as _;
                let exe = std::env::current_exe().expect("current exe");
                let error = Command::new(exe)
                    .args([ENTRYPOINT, "--exact", "--ignored", "--nocapture"])
                    .env(ENV_CHILD, "just_exit")
                    .exec();
                panic!("exec just_exit failed: {error}");
            }
            "QUIT" => {
                say("OK QUIT");
                std::process::exit(0);
            }
            other => panic!("unknown fixture command: {other}"),
        }
    }
}

/// The plain sleeper (cgroup member).
fn fixture_sleep() {
    say("READY");
    std::thread::sleep(Duration::from_secs(300));
}

// userfaultfd ABI (linux/userfaultfd.h): ioctl numbers and structs for
// the held-teardown holder. Verified against the host headers.
// musl `ioctl` takes a c_int request, glibc a c_ulong one; the `as`
// casts keep the identical bit patterns (the numbers set the high bit).
#[cfg(target_env = "musl")]
const UFFDIO_API_NR: libc::c_int = 0xC018_AA3F_u32 as libc::c_int;
#[cfg(target_env = "musl")]
const UFFDIO_REGISTER_NR: libc::c_int = 0xC020_AA00_u32 as libc::c_int;
#[cfg(target_env = "musl")]
const UFFDIO_ZEROPAGE_NR: libc::c_int = 0xC020_AA04_u32 as libc::c_int;
#[cfg(not(target_env = "musl"))]
const UFFDIO_API_NR: libc::c_ulong = 0xC018_AA3F;
#[cfg(not(target_env = "musl"))]
const UFFDIO_REGISTER_NR: libc::c_ulong = 0xC020_AA00;
#[cfg(not(target_env = "musl"))]
const UFFDIO_ZEROPAGE_NR: libc::c_ulong = 0xC020_AA04;
const UFFD_EVENT_PAGEFAULT: u8 = 0x12;

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioZeropage {
    range: UffdioRange,
    mode: u64,
    zeropage: i64,
}

/// The held-teardown holder: pins the member's address space with an
/// open `/proc/<pid>/environ`, then blocks reading it into a
/// userfaultfd page until the parent creates the release file (after
/// finalize). The open fd (not the read) is the deterministic pin:
/// `mem_open` takes the mm reference, so the member's teardown cannot
/// complete while this fd is open.
fn fixture_holder() {
    let member: u32 = std::env::var(ENV_MEMBER_PID)
        .expect("member pid")
        .parse()
        .expect("numeric member pid");
    let release = std::env::var(ENV_RELEASE).expect("release path");
    // SAFETY: userfaultfd creation; checked return.
    let uffd = unsafe { libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC) };
    assert!(uffd >= 0, "userfaultfd (need privileges)");
    let uffd = uffd as i32;
    let mut api = UffdioApi {
        api: 0xAA,
        features: 0,
        ioctls: 0,
    };
    // SAFETY: version handshake on our own uffd fd.
    assert_eq!(
        unsafe { libc::ioctl(uffd, UFFDIO_API_NR, &mut api) },
        0,
        "UFFDIO_API"
    );
    // SAFETY: one anonymous page for the stalled read destination.
    let page = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(page, libc::MAP_FAILED, "stall page");
    let mut register = UffdioRegister {
        range: UffdioRange {
            start: page as u64,
            len: 4096,
        },
        mode: 1, // UFFDIO_REGISTER_MODE_MISSING
        ioctls: 0,
    };
    // SAFETY: register our own page on our own uffd fd.
    assert_eq!(
        unsafe { libc::ioctl(uffd, UFFDIO_REGISTER_NR, &mut register) },
        0,
        "UFFDIO_REGISTER"
    );
    // The resolver thread: waits for the fault, then for the parent's
    // release file, then resolves with a zero page. The page crosses the
    // thread boundary as an integer (raw pointers are not `Send`).
    let page_addr = page as u64;
    let resolver = std::thread::spawn(move || {
        let mut msg = [0u8; 32];
        let mut got = 0;
        while got < msg.len() {
            // SAFETY: blocking read of one uffd message.
            let chunk =
                unsafe { libc::read(uffd, msg[got..].as_mut_ptr().cast(), msg.len() - got) };
            assert!(chunk > 0, "uffd message read");
            got += chunk as usize;
        }
        assert_eq!(msg[0], UFFD_EVENT_PAGEFAULT, "page-fault event");
        let deadline = Instant::now() + Duration::from_secs(60);
        while !Path::new(&release).exists() {
            assert!(Instant::now() < deadline, "release file never appears");
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut zero = UffdioZeropage {
            range: UffdioRange {
                start: page_addr,
                len: 4096,
            },
            mode: 0,
            zeropage: 0,
        };
        // SAFETY: resolve our own fault with a zero page.
        assert_eq!(
            unsafe { libc::ioctl(uffd, UFFDIO_ZEROPAGE_NR, &mut zero) },
            0,
            "UFFDIO_ZEROPAGE"
        );
    });
    use std::os::unix::io::AsRawFd as _;
    let environ = std::fs::File::open(format!("/proc/{member}/environ"))
        .expect("open member environ (pins the mm)");
    say("PINNED");
    // SAFETY: blocking read into our own registered page; the fault
    // stalls until the resolver runs (after the parent's finalize).
    let got = unsafe { libc::read(environ.as_raw_fd(), page, 4096) };
    assert!(got >= 0, "environ read drains after release");
    resolver.join().expect("resolver thread");
    say(&format!("DONE {got}"));
}

/// The nested-pidns probe: unshares a PID namespace, then spawns the
/// inner (no fork: `Command` children of an unshared parent enter the
/// new namespace, and forking this multithreaded test image is unsafe).
/// Forwards the inner report, then PROBE-OK.
fn fixture_nested_probe() {
    // SAFETY: unshare marks future children for a new PID namespace.
    assert_eq!(
        unsafe { libc::unshare(libc::CLONE_NEWPID) },
        0,
        "unshare pidns (need privileges)"
    );
    let exe = std::env::current_exe().expect("current exe");
    let so = std::env::var(ENV_SO).expect("fixture so path");
    let inner = Command::new(exe)
        .args([ENTRYPOINT, "--exact", "--ignored", "--nocapture"])
        .env(ENV_CHILD, "nested_inner")
        .env(ENV_SO, so)
        .output()
        .expect("spawn nested inner");
    let report = String::from_utf8_lossy(&inner.stdout);
    for line in report.lines() {
        say(&format!("INNER {line}"));
    }
    say(&format!(
        "INNER-STATUS {}",
        inner.status.code().unwrap_or(-1)
    ));
    assert!(inner.status.success(), "inner probe exits clean");
    say("PROBE-OK");
}

/// Runs inside the nested namespace: the witness must refuse.
fn fixture_nested_inner() {
    assert!(
        !pidns_initial(),
        "inner really runs nested: {:?}",
        crate::pidns::observer()
    );
    let so = PathBuf::from(std::env::var(ENV_SO).expect("fixture so path"));
    match super::start(
        &[so],
        &crate::attach::Scope::System,
        pidns_initial(),
        &mut crate::discovery::scan::CaptureWorkBudget::default(),
    ) {
        Err(Unavailable::Pidns(_)) => {
            say("PIDNS-UNAVAILABLE");
        }
        Err(other) => panic!("nested start must refuse with Pidns: {other:?}"),
        Ok(_) => panic!("nested start must refuse, not attach"),
    }
}
