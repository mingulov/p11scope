//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Member-stop watchdog: a small process outside the run cgroup that
//! resumes the run's stopped members when the observer dies without its
//! cleanup (`SIGKILL`, `abort`, an OOM kill). The observer holds the
//! write end of a pipe whose read end is the watchdog's stdin. An orderly
//! end writes [`DONE`] before closing it (the observer has resumed every
//! member itself); end of file without it means the observer died, and
//! the watchdog sends `SIGCONT` to every member of the run cgroup tree
//! that is stopped (`T`), several times over [`SWEEP_DELAYS_MS`], so a
//! stop the dying observer's hook placed in flight is resumed too.
//!
//! Every member is pinned by pidfd before it is read, and is signalled
//! through that pidfd only while `/proc` still shows it stopped and in
//! the run cgroup tree, so a recycled PID is never signalled. The owned
//! direct child is never signalled: the hook exempts it, the pause chain
//! holds it, and its own `PR_SET_PDEATHSIG` resumes it after an observer
//! death. A member the user stopped on purpose (job control) also
//! resumes, but only on that abnormal path. The watchdog reads only
//! `cgroup.procs`, each member's `stat` state and its `cgroup` line;
//! nothing is reported. A handle the observer drops without an explicit
//! end (an error return) ends it in order, like [`Watchdog::finish`].

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::RunTree;

/// The hidden first argument that turns `p11scope` into the watchdog.
pub(crate) const WATCHDOG_ARG: &str = "--p11scope-internal-member-stop-watchdog";
/// The line the watchdog prints once it holds its pipe and ignores the
/// terminal signals: the observer activates no stop before it.
const READY: &str = "p11scope-member-stop-watchdog-ready";
/// The orderly-end byte.
pub(crate) const DONE: u8 = b'D';
/// When the abnormal-end sweeps run, from end of file. A dying
/// observer's hook stays attached until its last thread has exited, so a
/// member resumed by an early sweep can stop once more; the later sweeps
/// resume it, and the last one bounds how late a stopped member is still
/// resumed (measured: every member ran again 0.2-0.5 s after a `SIGKILL`
/// under load).
pub(crate) const SWEEP_DELAYS_MS: [u64; 8] = [0, 20, 50, 100, 200, 400, 800, 1600];
/// The capability the watchdog keeps (`linux/capability.h`).
const CAP_KILL: u32 = 5;
/// Kept too when `/proc` hides other users' processes (`hidepid`):
/// `/proc/<pid>` visibility then goes through the ptrace access check.
const CAP_SYS_PTRACE: u32 = 19;
/// The prefix of a line the watchdog prints before its ready line: a
/// setup step that failed (the observer prints it under `-v`).
const NOTE: &str = "p11scope-member-stop-watchdog-note: ";
/// Bounded walk of the run cgroup tree: members may create subgroups.
const MAX_GROUPS: usize = 256;
const MAX_DEPTH: usize = 8;
/// Bounded per-group process list read.
const MAX_PROCS_BYTES: u64 = 4 * 1024 * 1024;
/// How long the observer waits for the ready line.
const READY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an orderly end waits for the watchdog to exit.
const EXIT_WAIT: Duration = Duration::from_secs(1);
/// The test harness entry's environment variable (cgroup root, run
/// cgroup path and exempt tgid, one per line).
#[cfg(test)]
pub(crate) const TEST_ENTRY_ENV: &str = "P11SCOPE_MEMBER_STOP_WATCHDOG_TEST";
#[cfg(test)]
pub(crate) const TEST_ENTRY: &str = "attach::member_stop::watchdog::tests::watchdog_harness_entry";

/// How the observer starts the watchdog: the observer's own executable
/// with [`WATCHDOG_ARG`], or (lib tests) the test executable running the
/// harness entry.
#[derive(Debug, Clone)]
pub(crate) enum WatchdogLauncher {
    SelfExe,
    #[cfg(test)]
    TestHarness,
}

/// The observer's handle on a running watchdog.
pub(crate) struct Watchdog {
    child: std::process::Child,
    alive: Option<std::process::ChildStdin>,
}

impl Drop for Watchdog {
    /// A handle neither finished nor abandoned (an error return while the
    /// hooks start, an unwind) is an orderly end: the observer is alive,
    /// so the watchdog must not sweep, and it is reaped.
    fn drop(&mut self) {
        if let Some(mut alive) = self.alive.take() {
            let _ = alive.write_all(&[DONE]);
            drop(alive);
            self.reap_or_kill();
        }
    }
}

impl Watchdog {
    /// Starts the watchdog in its own session (a process-group kill of
    /// the observer does not reach it) and waits for its ready line.
    /// `exempt_tgid` (the owned direct child) is never swept.
    pub(crate) fn start(
        launcher: &WatchdogLauncher,
        tree: &RunTree,
        exempt_tgid: u32,
    ) -> Result<Self, String> {
        use std::os::unix::process::CommandExt as _;
        let mut command = match launcher {
            WatchdogLauncher::SelfExe => {
                let mut command = std::process::Command::new("/proc/self/exe");
                command
                    .arg(WATCHDOG_ARG)
                    .arg(&tree.cgroup_root)
                    .arg(&tree.run_cgroup)
                    .arg(exempt_tgid.to_string());
                command
            }
            #[cfg(test)]
            WatchdogLauncher::TestHarness => {
                let exe =
                    std::env::current_exe().map_err(|error| format!("test executable: {error}"))?;
                let mut command = std::process::Command::new(exe);
                command
                    .args(["--exact", TEST_ENTRY, "--nocapture", "--test-threads=1"])
                    .env(
                        TEST_ENTRY_ENV,
                        format!(
                            "{}\n{}\n{exempt_tgid}",
                            tree.cgroup_root.display(),
                            tree.run_cgroup.display()
                        ),
                    );
                command
            }
        };
        command
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        // SAFETY: `setsid` is async-signal-safe and touches no memory.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("starting the member-stop watchdog: {error}"))?;
        let alive = child.stdin.take();
        let stdout = child.stdout.take();
        let ready = stdout
            .ok_or_else(|| "watchdog stdout missing".to_string())
            .and_then(wait_ready);
        match ready {
            Ok(notes) => {
                if crate::run::capture_diagnostics_on() {
                    for note in notes {
                        eprintln!("p11scope: member-stop watchdog: {note}");
                    }
                }
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        Ok(Self { child, alive })
    }

    /// The watchdog's process id.
    #[cfg(test)]
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Whether the watchdog has exited (its guard is gone).
    pub(crate) fn lost(&mut self) -> bool {
        !matches!(self.child.try_wait(), Ok(None))
    }

    /// Orderly end: the observer resumed every member itself. Writes
    /// [`DONE`], closes the pipe and reaps the watchdog (bounded).
    pub(crate) fn finish(mut self) {
        if let Some(mut alive) = self.alive.take() {
            let _ = alive.write_all(&[DONE]);
        }
        self.reap_or_kill();
    }

    /// Closes the pipe without [`DONE`]: the watchdog sweeps as it would
    /// after an observer death. The wait is bounded; a watchdog still
    /// sweeping after it is reaped in the background when its sweeps
    /// end, so no zombie waits for the observer's exit.
    pub(crate) fn abandon(mut self) {
        self.alive = None;
        if !self.reap() {
            std::thread::spawn(move || {
                let mut this = self;
                let _ = this.child.wait();
            });
        }
    }

    /// [`Self::abandon`] without waiting for the sweeps to end.
    #[cfg(test)]
    pub(crate) fn abandon_without_wait(mut self) {
        self.alive = None;
        // Reaped in the background so no zombie outlives the test.
        std::thread::spawn(move || {
            let mut this = self;
            let _ = this.child.wait();
        });
    }

    /// Waits (bounded) for the watchdog to exit and reaps it. True when
    /// it was reaped.
    fn reap(&mut self) -> bool {
        let end = std::time::Instant::now() + EXIT_WAIT;
        while std::time::Instant::now() < end {
            if !matches!(self.child.try_wait(), Ok(None)) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    }

    /// After an orderly end: the watchdog has nothing left to do, so one
    /// that does not exit in time is killed, and always reaped (no zombie
    /// outlives the handle).
    fn reap_or_kill(&mut self) {
        if !self.reap() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Reads the child's stdout until the ready line, within [`READY_TIMEOUT`]
/// and a bounded byte count (the test harness prints its own lines first).
fn wait_ready(stdout: std::process::ChildStdout) -> Result<Vec<String>, String> {
    use std::os::fd::AsRawFd as _;
    let deadline = std::time::Instant::now() + READY_TIMEOUT;
    let mut stdout = stdout;
    let mut seen = Vec::new();
    let mut buffer = [0u8; 512];
    while seen.len() < 64 * 1024 {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err("the member-stop watchdog did not get ready in time".into());
        }
        let mut poll = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = i32::try_from(left.as_millis()).unwrap_or(i32::MAX).max(1);
        // SAFETY: one valid pollfd for the duration of the call.
        let polled = unsafe { libc::poll(&mut poll, 1, millis) };
        if polled < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("waiting for the member-stop watchdog: {error}"));
        }
        if polled == 0 {
            continue;
        }
        let read = stdout
            .read(&mut buffer)
            .map_err(|error| format!("reading the member-stop watchdog: {error}"))?;
        if read == 0 {
            return Err("the member-stop watchdog exited before it was ready".into());
        }
        seen.extend_from_slice(&buffer[..read]);
        if seen
            .split(|byte| *byte == b'\n')
            .any(|line| line == READY.as_bytes())
        {
            return Ok(ready_notes(&seen));
        }
    }
    Err("the member-stop watchdog printed no ready line".into())
}

/// Whether a `mountinfo` listing mounts `/proc` with `hidepid` set (any
/// value but `off`), as `ProtectProc=` does.
fn proc_hides_pids(mountinfo: &str) -> bool {
    mountinfo.lines().any(|line| {
        let Some((mount, source)) = line.split_once(" - ") else {
            return false;
        };
        let mut source = source.split(' ');
        let (Some(fstype), Some(_), Some(options)) = (source.next(), source.next(), source.next())
        else {
            return false;
        };
        fstype == "proc"
            && mount.split(' ').nth(4) == Some("/proc")
            && options.split(',').any(|option| {
                option
                    .strip_prefix("hidepid=")
                    .is_some_and(|value| value != "off" && value != "0")
            })
    })
}

/// The capability set the watchdog keeps.
fn watchdog_keep_set(proc_hides_pids: bool) -> u64 {
    let ptrace = if proc_hides_pids {
        1u64 << CAP_SYS_PTRACE
    } else {
        0
    };
    (1u64 << CAP_KILL) | ptrace
}

/// The setup notes printed before the ready line.
fn ready_notes(seen: &[u8]) -> Vec<String> {
    seen.split(|byte| *byte == b'\n')
        .take_while(|line| *line != READY.as_bytes())
        .filter_map(|line| line.strip_prefix(NOTE.as_bytes()))
        .map(|note| String::from_utf8_lossy(note).into_owned())
        .collect()
}

/// The `p11scope` entry: `Some(exit code)` when the first argument is
/// [`WATCHDOG_ARG`], else `None` (an ordinary command).
pub(crate) fn entry(mut args: impl Iterator<Item = std::ffi::OsString>) -> Option<i32> {
    let _program = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new(WATCHDOG_ARG)) {
        return None;
    }
    let (Some(root), Some(run), Some(exempt), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        return Some(2);
    };
    let Some(exempt) = exempt.to_str().and_then(|text| text.parse::<u32>().ok()) else {
        return Some(2);
    };
    Some(watchdog_main(
        RunTree {
            cgroup_root: PathBuf::from(root),
            run_cgroup: PathBuf::from(run),
        },
        exempt,
    ))
}

/// The watchdog process: ignores the terminal and termination signals
/// (it must outlive the observer's own end), prints its ready line, then
/// blocks on the pipe. `exempt_tgid` is never signalled.
pub(crate) fn watchdog_main(tree: RunTree, exempt_tgid: u32) -> i32 {
    // It only reads `/proc` and the cgroup tree and sends SIGCONT: it
    // keeps `CAP_KILL` (a `--user` member runs under another uid), plus
    // `CAP_SYS_PTRACE` only when `/proc` hides other users' processes,
    // and never gains privilege again (a setcap observer re-executed
    // here would otherwise hold its whole file grant for the run). A
    // failed step leaves it working with more privilege: noted.
    let mut notes = Vec::new();
    let hides = std::fs::read_to_string("/proc/self/mountinfo")
        .map(|mountinfo| proc_hides_pids(&mountinfo))
        .unwrap_or_else(|error| {
            notes.push(format!("reading mountinfo: {error}"));
            // Doubt keeps the access a hidden /proc would need.
            true
        });
    if let Err(error) = crate::caps::drop_to_keep(watchdog_keep_set(hides)) {
        notes.push(format!("dropping capabilities: {error}"));
    }
    // SAFETY: `PR_SET_NO_NEW_PRIVS` takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        notes.push(format!(
            "setting no_new_privs: {}",
            std::io::Error::last_os_error()
        ));
    }
    for signal in [
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGQUIT,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGPIPE,
    ] {
        // SAFETY: installs SIG_IGN; no handler code runs.
        unsafe {
            libc::signal(signal, libc::SIG_IGN);
        }
    }
    {
        let mut stdout = std::io::stdout().lock();
        // On lines of their own (the test harness prints a partial line
        // before them).
        let mut lines = String::from("\n");
        for note in &notes {
            lines.push_str(&format!("{NOTE}{note}\n"));
        }
        if writeln!(stdout, "{lines}{READY}")
            .and_then(|()| stdout.flush())
            .is_err()
        {
            return 1;
        }
    }
    // The observer read the ready line; later output has no reader.
    if let Ok(null) = std::fs::OpenOptions::new().write(true).open("/dev/null") {
        use std::os::fd::AsRawFd as _;
        // SAFETY: duplicates a valid descriptor over stdout.
        unsafe {
            libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO);
        }
    }
    if wait_for_end() {
        return 0;
    }
    let start = std::time::Instant::now();
    for delay in SWEEP_DELAYS_MS {
        let at = start + Duration::from_millis(delay);
        let now = std::time::Instant::now();
        if at > now {
            std::thread::sleep(at - now);
        }
        resume_stopped_members(&tree, exempt_tgid);
    }
    0
}

/// Blocks until the pipe ends. True for an orderly end ([`DONE`] seen).
fn wait_for_end() -> bool {
    let mut stdin = std::io::stdin().lock();
    let mut done = false;
    let mut byte = [0u8; 64];
    loop {
        match stdin.read(&mut byte) {
            Ok(0) => return done,
            Ok(read) => done |= byte[..read].contains(&DONE),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return done,
        }
    }
}

/// One sweep: every stopped member of the run cgroup tree resumes,
/// except `exempt_tgid`. Returns how many were signalled.
pub(crate) fn resume_stopped_members(tree: &RunTree, exempt_tgid: u32) -> usize {
    let mut resumed = 0;
    for pid in run_tree_pids(&tree.run_cgroup) {
        if pid == exempt_tgid {
            continue;
        }
        if resume_if_stopped_member(pid, tree) {
            resumed += 1;
        }
    }
    resumed
}

/// The PIDs listed by the run cgroup and its subgroups (bounded walk).
fn run_tree_pids(run_cgroup: &Path) -> Vec<u32> {
    let mut pids = Vec::new();
    let mut groups = vec![(run_cgroup.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((group, depth)) = groups.pop() {
        visited += 1;
        if visited > MAX_GROUPS {
            break;
        }
        if let Ok(file) = std::fs::File::open(group.join("cgroup.procs")) {
            let mut text = String::new();
            if file.take(MAX_PROCS_BYTES).read_to_string(&mut text).is_ok() {
                pids.extend(
                    text.lines()
                        .filter_map(|line| line.trim().parse::<u32>().ok()),
                );
            }
        }
        if depth + 1 >= MAX_DEPTH {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&group) {
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    groups.push((entry.path(), depth + 1));
                }
            }
        }
    }
    pids
}

/// Pins `pid`, then signals it only while `/proc` shows it stopped and in
/// the run cgroup tree. With the pidfd held, a live `pid` cannot name
/// another process; a dead one makes the signal fail harmlessly.
pub(crate) fn resume_if_stopped_member(pid: u32, tree: &RunTree) -> bool {
    let Ok(pin) = crate::process::PidPin::open(pid) else {
        return false;
    };
    if pin.probe_signal_authority().is_err() {
        return false;
    }
    if !process_stopped(pid) || tree.contains_pinned(&pin) != Ok(true) {
        return false;
    }
    pin.send_signal(libc::SIGCONT).is_ok()
}

/// Whether any task of `pid` shows the stopped state `T` in its
/// `/proc/<pid>/task/<tid>/stat`: a thread group whose main thread exited
/// (`pthread_exit`) reads `Z` for its leader while its other threads are
/// stopped.
pub(crate) fn process_stopped(pid: u32) -> bool {
    crate::discovery::pause::read_task_states(pid)
        .is_ok_and(|states| states.values().any(|state| *state == b'T'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture_guard::DieWithParent as _;

    /// Harness entry for [`WatchdogLauncher::TestHarness`]: a no-op
    /// unless the launcher's environment names what to guard, in which
    /// case this test process becomes the watchdog and exits with its
    /// code.
    #[test]
    fn watchdog_harness_entry() {
        let Ok(spec) = std::env::var(TEST_ENTRY_ENV) else {
            return;
        };
        let mut lines = spec.lines();
        let (Some(root), Some(run), Some(exempt)) = (lines.next(), lines.next(), lines.next())
        else {
            panic!("root, run cgroup and exempt tgid: {spec:?}");
        };
        std::process::exit(watchdog_main(
            RunTree {
                cgroup_root: PathBuf::from(root),
                run_cgroup: PathBuf::from(run),
            },
            exempt.parse().expect("exempt tgid"),
        ));
    }

    /// `hidepid` (any value but `off`, as `ProtectProc=` mounts it) on
    /// the `/proc` mount hides other users' processes from a watchdog
    /// without the ptrace capability.
    #[test]
    fn hidepid_proc_mounts_are_detected() {
        let line = |point: &str, options: &str| {
            format!("30 22 0:5 / {point} rw,nosuid shared:5 - proc proc {options}\n")
        };
        assert!(!proc_hides_pids(&line("/proc", "rw")));
        assert!(!proc_hides_pids(&line("/proc", "rw,hidepid=off")));
        assert!(!proc_hides_pids(&line("/proc", "rw,subset=pid")));
        assert!(proc_hides_pids(&line("/proc", "rw,hidepid=invisible")));
        assert!(proc_hides_pids(&line("/proc", "rw,hidepid=noaccess,gid=4")));
        assert!(proc_hides_pids(&line("/proc", "rw,hidepid=ptraceable")));
        assert!(proc_hides_pids(&line("/proc", "rw,hidepid=2")));
        assert!(
            !proc_hides_pids(&line("/run/other", "rw,hidepid=invisible")),
            "only the /proc mount"
        );
    }

    #[test]
    fn the_watchdog_keeps_ptrace_only_under_hidepid() {
        assert_eq!(watchdog_keep_set(false), 1u64 << CAP_KILL);
        assert_eq!(
            watchdog_keep_set(true),
            (1u64 << CAP_KILL) | (1u64 << CAP_SYS_PTRACE)
        );
    }

    #[test]
    fn ready_notes_are_collected_before_the_ready_line() {
        let seen = format!(
            "harness noise\n{NOTE}dropping capabilities: EPERM\n{NOTE}no_new_privs: EINVAL\n\n{READY}\n"
        );
        assert_eq!(
            ready_notes(seen.as_bytes()),
            vec![
                "dropping capabilities: EPERM".to_string(),
                "no_new_privs: EINVAL".to_string()
            ]
        );
        assert!(ready_notes(format!("\n{READY}\n").as_bytes()).is_empty());
    }

    #[test]
    fn the_entry_takes_only_its_hidden_argument() {
        let args = |list: &[&str]| {
            list.iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
                .into_iter()
        };
        assert_eq!(entry(args(&["p11scope", "run", "--", "true"])), None);
        assert_eq!(entry(args(&["p11scope"])), None);
        assert_eq!(entry(args(&["p11scope", WATCHDOG_ARG])), Some(2));
        assert_eq!(
            entry(args(&["p11scope", WATCHDOG_ARG, "/a", "/b", "c"])),
            Some(2)
        );
        assert_eq!(
            entry(args(&["p11scope", WATCHDOG_ARG, "/a", "/b"])),
            Some(2)
        );
        assert_eq!(
            entry(args(&["p11scope", WATCHDOG_ARG, "/a", "/b", "7", "8"])),
            Some(2)
        );
    }

    /// A run tree that lists only `pids`: a scratch directory stands in
    /// for the cgroup root, with this test process's own cgroup path
    /// below it (so `/proc/<pid>/cgroup` of a child places it inside) and
    /// a `cgroup.procs` naming only the given children. The sweep then
    /// sees nothing else of the test executable's cgroup.
    fn listed_tree(pids: &[u32]) -> (tempfile::TempDir, RunTree) {
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let relative = crate::scope::parse_cgroup_v2_relative(&own)
            .expect("a cgroup v2 line for the test process")
            .to_string();
        let root = tempfile::tempdir().unwrap();
        let run = root.path().join(relative);
        std::fs::create_dir_all(&run).unwrap();
        let list: String = pids.iter().map(|pid| format!("{pid}\n")).collect();
        std::fs::write(run.join("cgroup.procs"), list).unwrap();
        let tree = RunTree {
            cgroup_root: root.path().to_path_buf(),
            run_cgroup: run,
        };
        (root, tree)
    }

    fn stopped_sleep() -> std::process::Child {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .die_with_parent()
            .spawn()
            .unwrap();
        // SAFETY: signals our own child.
        unsafe {
            libc::kill(child.id() as i32, libc::SIGSTOP);
        }
        while !process_stopped(child.id()) {
            std::thread::sleep(Duration::from_millis(2));
        }
        child
    }

    fn resumes_within(pid: u32, wait: Duration) -> bool {
        let end = std::time::Instant::now() + wait;
        while std::time::Instant::now() < end {
            if !process_stopped(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    }

    /// A handle dropped without `finish` or `abandon` (an early error
    /// return while the hooks start) is an orderly end, not an observer
    /// death: nothing is swept, and the watchdog is reaped.
    #[test]
    fn a_dropped_watchdog_ends_in_order_and_is_reaped() {
        let mut member = stopped_sleep();
        let (_root, tree) = listed_tree(&[member.id()]);
        let watchdog = Watchdog::start(&WatchdogLauncher::TestHarness, &tree, 0).unwrap();
        let watchdog_pid = watchdog.pid();
        drop(watchdog);
        assert!(
            !resumes_within(member.id(), Duration::from_millis(200)),
            "no sweep resumed the member"
        );
        assert!(
            !Path::new(&format!("/proc/{watchdog_pid}")).exists(),
            "the watchdog exited and was reaped"
        );
        let _ = member.kill();
        let _ = member.wait();
    }

    /// A process whose main thread exited while another thread lives is
    /// still stopped (its leader reads `Z`): the sweep must see it.
    #[test]
    fn a_stopped_process_with_an_exited_leader_reads_stopped() {
        let mut child = std::process::Command::new("python3")
            .args([
                "-c",
                "import threading, time, ctypes\n\
                 threading.Thread(target=time.sleep, args=(30,)).start()\n\
                 ctypes.CDLL(None).pthread_exit(None)\n",
            ])
            .die_with_parent()
            .spawn()
            .expect("python3 for the exited-leader fixture");
        let pid = child.id();
        let leader_gone = (0..500).any(|_| {
            std::thread::sleep(Duration::from_millis(5));
            crate::discovery::pause::read_task_states(pid)
                .is_ok_and(|states| states.get(&pid) == Some(&b'Z') && states.len() >= 2)
        });
        assert!(leader_gone, "the leader exited while a thread lives");
        // SAFETY: signals our own child.
        unsafe {
            libc::kill(pid as i32, libc::SIGSTOP);
        }
        let stopped = (0..500).any(|_| {
            std::thread::sleep(Duration::from_millis(2));
            process_stopped(pid)
        });
        let _ = child.kill();
        let _ = child.wait();
        assert!(stopped, "a stopped thread group reads stopped");
    }

    /// The watchdog needs only `CAP_KILL` (a `--user` member runs under
    /// another uid) and never gains privilege: no new privileges.
    #[test]
    fn the_watchdog_runs_without_new_privileges() {
        let (_root, tree) = listed_tree(&[]);
        let watchdog = Watchdog::start(&WatchdogLauncher::TestHarness, &tree, 0).unwrap();
        // The harness runs `watchdog_main` on a test thread (capabilities
        // and no-new-privileges are per thread); the observer's own
        // watchdog runs it on its only thread. Read the thread that ran it.
        let tasks: Vec<String> = std::fs::read_dir(format!("/proc/{}/task", watchdog.pid()))
            .unwrap()
            .flatten()
            .filter_map(|task| std::fs::read_to_string(task.path().join("status")).ok())
            .collect();
        watchdog.finish();
        let field = |status: &str, name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
                .unwrap_or_default()
                .to_string()
        };
        let guarded: Vec<&String> = tasks
            .iter()
            .filter(|status| field(status, "NoNewPrivs:") == "1")
            .collect();
        assert!(
            !guarded.is_empty(),
            "no task without new privileges: {tasks:?}"
        );
        for status in guarded {
            let effective = u64::from_str_radix(&field(status, "CapEff:"), 16).unwrap();
            assert_eq!(
                effective & !(1u64 << CAP_KILL),
                0,
                "CapEff {effective:x} beyond CAP_KILL"
            );
        }
    }

    /// An abandoned watchdog sweeps past the observer's bounded wait; it
    /// is still reaped when its sweeps end (no zombie until the observer
    /// exits).
    #[test]
    fn an_abandoned_watchdog_is_reaped_after_its_sweeps() {
        let mut member = stopped_sleep();
        let (_root, tree) = listed_tree(&[member.id()]);
        let watchdog = Watchdog::start(&WatchdogLauncher::TestHarness, &tree, 0).unwrap();
        let watchdog_pid = watchdog.pid();
        watchdog.abandon();
        assert!(
            resumes_within(member.id(), Duration::from_secs(2)),
            "the sweep resumes the member"
        );
        let end = std::time::Instant::now() + Duration::from_secs(4);
        while Path::new(&format!("/proc/{watchdog_pid}")).exists()
            && std::time::Instant::now() < end
        {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !Path::new(&format!("/proc/{watchdog_pid}")).exists(),
            "the abandoned watchdog was reaped"
        );
        let _ = member.kill();
        let _ = member.wait();
    }

    /// After an observer death the sweep resumes stopped members but
    /// never the exempt direct child (held by the pause chain, resumed by
    /// its own death signal).
    #[test]
    fn the_sweep_never_signals_the_exempt_direct_child() {
        let mut direct = stopped_sleep();
        let mut member = stopped_sleep();
        let (_root, tree) = listed_tree(&[direct.id(), member.id()]);
        let watchdog = Watchdog::start(&WatchdogLauncher::TestHarness, &tree, direct.id()).unwrap();
        watchdog.abandon();
        assert!(
            resumes_within(member.id(), Duration::from_secs(2)),
            "the member resumes"
        );
        assert!(
            !resumes_within(direct.id(), Duration::from_millis(100)),
            "the direct child stays held"
        );
        for child in [&mut direct, &mut member] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn stopped_state_reads_from_stat() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .die_with_parent()
            .spawn()
            .unwrap();
        let pid = child.id();
        assert!(!process_stopped(pid));
        // SAFETY: signals our own child.
        unsafe {
            libc::kill(pid as i32, libc::SIGSTOP);
        }
        let mut stopped = false;
        for _ in 0..500 {
            if process_stopped(pid) {
                stopped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(stopped);
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A stopped process outside the run tree is never signalled; one
    /// inside it (the test's own cgroup stands in as the run tree)
    /// resumes.
    #[test]
    fn only_a_stopped_member_of_the_run_tree_resumes() {
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let Some(relative) = crate::scope::parse_cgroup_v2_relative(&own) else {
            panic!("no cgroup v2 line for the test process: {own:?}");
        };
        let root = Path::new("/sys/fs/cgroup");
        let ours = RunTree {
            cgroup_root: root.to_path_buf(),
            run_cgroup: root.join(relative),
        };
        let elsewhere = RunTree {
            cgroup_root: root.to_path_buf(),
            run_cgroup: root.join("p11scope-no-such-run-group"),
        };
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .die_with_parent()
            .spawn()
            .unwrap();
        let pid = child.id();
        // SAFETY: signals our own child.
        unsafe {
            libc::kill(pid as i32, libc::SIGSTOP);
        }
        while !process_stopped(pid) {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!resume_if_stopped_member(pid, &elsewhere));
        assert!(process_stopped(pid), "a non-member stays as it was");
        assert!(resume_if_stopped_member(pid, &ours));
        let mut resumed = false;
        for _ in 0..500 {
            if !process_stopped(pid) {
                resumed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(resumed, "the member resumes");
        assert!(
            !resume_if_stopped_member(pid, &ours),
            "a running member is not signalled"
        );
        let _ = child.kill();
        let _ = child.wait();
    }
}
