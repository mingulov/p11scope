//! SPDX-License-Identifier: GPL-3.0-or-later
//! Test-only parent-death guard for fixture processes.
//!
//! A fixture child spawned without a guard outlives a test process that
//! dies abruptly (panic, SIGTERM, SIGKILL, campaign timeout): `Drop` never
//! runs and the child reparents to init. On 2026-11-02, 257 pressure-live
//! drivers were found polling their gates 9.5 hours after their test died,
//! loading a 5-vCPU host to about 4.7. Every long-lived test holder must
//! die with its test, whatever way the test dies.
//!
//! [`die_with_parent`] arms `PR_SET_PDEATHSIG, SIGKILL` in a `pre_exec`
//! hook plus a `getppid` recheck against the forking process, closing the
//! fork race: a parent that died before the `prctl` never fires the
//! signal, and a live subreaper may adopt the child first, so testing for
//! init alone misses live adoption. The recheck exits 127 without exec
//! when the owner is already gone.
//!
//! `PR_SET_PDEATHSIG` fires when the forking *thread* exits. That is fine
//! here because the spawning test thread outlives its children: tests
//! spawn holders on the test thread itself and reap them before the test
//! returns. Never spawn a guarded long-lived child on a short-lived
//! helper thread (its exit would kill the child early); the
//! `rust_owned_stopped_fixture_dies_with_its_spawner_thread` twin in
//! `inventory_coordinator` pins exactly that thread-death semantic on
//! purpose.
//!
//! The setting survives `exec`, so one registration covers C fixtures
//! too. A fixture that forks its own grandchildren must re-arm after each
//! fork; every current C grandchild is finite or EOF-terminated on parent
//! death, so only the spawn seam needs the guard.
//!
//! Integration tests cannot link this `cfg(test)` module; they use the
//! mirror helper in `tests/support/mod.rs`. Keep the two bodies in sync.

use std::process::Command;

/// A `Command` extension arming parent-death SIGKILL on the future child
/// (see the module docs). Chainable: `Command::new(..).die_with_parent()`
/// keeps the one-line spawn shape at every holder site.
pub(crate) trait DieWithParent {
    fn die_with_parent(&mut self) -> &mut Self;
}

impl DieWithParent for Command {
    fn die_with_parent(&mut self) -> &mut Self {
        use std::os::unix::process::CommandExt as _;
        // The orphan check compares against the owner at fork: a live
        // subreaper may adopt the child before the hook runs, so testing
        // for init alone misses live adoption, and the death signal never
        // fires for a death that predates it.
        let owner = std::process::id();
        // SAFETY: the hook runs after fork before exec; its body uses
        // async-signal-safe calls only (prctl, getppid, _exit), allocates
        // nothing and touches no parent memory. The signal fires when the
        // forking *thread* exits; the spawning test thread outlives its
        // children (see the module docs), so thread death is test death
        // here. A parent already gone exits 127 before exec, so no orphan
        // starts; the caller's readiness logic then fails loud.
        unsafe {
            self.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::getppid() != owner as libc::pid_t {
                    libc::_exit(127);
                }
                Ok(())
            });
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::DieWithParent as _;
    use std::collections::BTreeMap;
    use std::io::Write as _;
    use std::process::Command;
    use std::time::{Duration, Instant};

    const GUARD_ENV: &str = "P11SCOPE_FIXTURE_GUARD";
    const VICTIM_ENV: &str = "P11SCOPE_FIXTURE_GUARD_VICTIM";
    const INTERMEDIATE_ENV: &str = "P11SCOPE_FIXTURE_GUARD_INTERMEDIATE";
    const VICTIM_TEST: &str = "fixture_guard::tests::victim_main";
    const INTERMEDIATE_TEST: &str = "fixture_guard::tests::intermediate_main";
    /// The brief's bound: every descendant gone within about 2 s of the
    /// victim's death (delivery is milliseconds; the bound is generous).
    const GONE_DEADLINE: Duration = Duration::from_secs(2);
    const PIDFILE_DEADLINE: Duration = Duration::from_secs(15);

    /// Start time (field 22) of a live pid, distinguishing it from a
    /// reused pid number.
    fn start_time(pid: u32) -> Option<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let tail = stat.rsplit_once(") ")?.1;
        tail.split_whitespace().nth(19).map(str::to_string)
    }

    fn proc_matches(pid: u32, start: &str) -> bool {
        start_time(pid).as_deref() == Some(start)
    }

    fn append_pid_line(pidfile: &std::path::Path, role: &str, pid: u32) {
        let start = start_time(pid).unwrap_or_else(|| panic!("{role} {pid} has no start time"));
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(pidfile)
            .expect("pidfile appends");
        writeln!(file, "{role} {pid} {start}").expect("pidfile line writes");
    }

    fn read_pidfile(pidfile: &std::path::Path) -> BTreeMap<String, (u32, String)> {
        let mut out = BTreeMap::new();
        let text = std::fs::read_to_string(pidfile).unwrap_or_default();
        for line in text.lines() {
            let mut parts = line.split_whitespace();
            if let (Some(role), Some(pid), Some(start)) = (parts.next(), parts.next(), parts.next())
                && let Ok(pid) = pid.parse::<u32>()
            {
                out.insert(role.to_string(), (pid, start.to_string()));
            }
        }
        out
    }

    /// Re-executed victim mode: plays the test process that dies. Spawns
    /// the guarded tree (an intermediate plus a direct sleeper), records
    /// it, then sleeps until the orchestrator SIGKILLs it. Without
    /// [`VICTIM_ENV`] this is an ordinary passing test.
    ///
    /// The children are never reaped: the victim dies by SIGKILL and its
    /// children reparent away, so no `wait` is possible; `/proc` polling
    /// is the assertion.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn victim_main() {
        let Ok(pidfile) = std::env::var(VICTIM_ENV) else {
            return;
        };
        let guarded = std::env::var(GUARD_ENV).as_deref() == Ok("1");
        let pidfile = std::path::PathBuf::from(pidfile);
        let log = pidfile
            .parent()
            .expect("pidfile has a parent")
            .join("intermediate.log");
        let mut intermediate = Command::new(std::env::current_exe().unwrap());
        intermediate
            .args(["--exact", INTERMEDIATE_TEST])
            .env(INTERMEDIATE_ENV, &pidfile)
            .env(GUARD_ENV, if guarded { "1" } else { "0" })
            .stdin(std::process::Stdio::null())
            .stdout(std::fs::File::create(&log).expect("intermediate log creates"))
            .stderr(std::process::Stdio::null());
        if guarded {
            intermediate.die_with_parent();
        }
        let child = intermediate
            .spawn()
            .expect("victim spawns its intermediate");
        append_pid_line(&pidfile, "intermediate", child.id());
        let mut direct = Command::new("sleep");
        direct
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if guarded {
            direct.die_with_parent();
        }
        let direct = direct.spawn().expect("victim spawns its direct sleeper");
        append_pid_line(&pidfile, "direct", direct.id());
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    /// Re-executed intermediate mode: the middle of the tree. Spawns one
    /// forked grandchild (a sleep), records it, then sleeps until killed.
    /// Without [`INTERMEDIATE_ENV`] this is an ordinary passing test.
    ///
    /// The grandchild is never reaped (see `victim_main`): it reparents
    /// away when the tree dies, so no `wait` is possible.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn intermediate_main() {
        let Ok(pidfile) = std::env::var(INTERMEDIATE_ENV) else {
            return;
        };
        let guarded = std::env::var(GUARD_ENV).as_deref() == Ok("1");
        let mut grandchild = Command::new("sleep");
        grandchild
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        if guarded {
            grandchild.die_with_parent();
        }
        let grandchild = grandchild
            .spawn()
            .expect("intermediate spawns its grandchild");
        append_pid_line(
            std::path::Path::new(&pidfile),
            "grandchild",
            grandchild.id(),
        );
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    struct Tree {
        dir: tempfile::TempDir,
        pidfile: std::path::PathBuf,
        victim: std::process::Child,
        members: BTreeMap<String, (u32, String)>,
    }

    impl Tree {
        /// Spawn the victim helper (unguarded: it plays the dying test)
        /// and wait for its three recorded descendants.
        fn spawn(guarded: bool) -> Self {
            let dir = tempfile::tempdir().expect("tree tempdir creates");
            let pidfile = dir.path().join("tree.pids");
            let victim_log = dir.path().join("victim.log");
            let mut victim = Command::new(std::env::current_exe().unwrap());
            victim
                .args(["--exact", VICTIM_TEST])
                .env(VICTIM_ENV, &pidfile)
                .env(GUARD_ENV, if guarded { "1" } else { "0" })
                .stdin(std::process::Stdio::null())
                .stdout(std::fs::File::create(&victim_log).expect("victim log creates"))
                .stderr(std::process::Stdio::null());
            let mut victim = victim.spawn().expect("orchestrator spawns its victim");
            let deadline = Instant::now() + PIDFILE_DEADLINE;
            let members = loop {
                let members = read_pidfile(&pidfile);
                if members.len() == 3 {
                    break members;
                }
                assert!(
                    Instant::now() < deadline,
                    "victim published {} of 3 descendants: {}",
                    members.len(),
                    std::fs::read_to_string(&victim_log).unwrap_or_default()
                );
                assert!(
                    victim.try_wait().expect("try_wait").is_none(),
                    "victim exited before publishing its tree: {}",
                    std::fs::read_to_string(&victim_log).unwrap_or_default()
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            for (role, (pid, start)) in &members {
                assert!(
                    proc_matches(*pid, start),
                    "{role} {pid} is not the recorded live descendant"
                );
            }
            Self {
                dir,
                pidfile,
                victim,
                members,
            }
        }

        /// SIGKILL the victim (the abrupt test death) and reap it.
        fn kill_victim(&mut self) {
            // SAFETY: signals only the owned victim pid.
            assert_eq!(
                unsafe { libc::kill(self.victim.id() as libc::pid_t, libc::SIGKILL) },
                0,
                "SIGKILL to the owned victim: {}",
                std::io::Error::last_os_error()
            );
            let status = self.victim.wait().expect("the victim reaps");
            assert!(!status.success(), "a SIGKILLed victim never exits 0");
        }

        fn survivors(&self) -> Vec<String> {
            self.members
                .iter()
                .filter(|(_, (pid, start))| proc_matches(*pid, start))
                .map(|(role, (pid, _))| format!("{role} {pid}"))
                .collect()
        }

        /// Best-effort cleanup so even a RED run leaks no sleepers.
        fn cleanup(&self) {
            for (pid, start) in self.members.values() {
                if proc_matches(*pid, start) {
                    // SAFETY: signals only the recorded descendant pid
                    // whose start time still matches.
                    unsafe {
                        libc::kill(*pid as libc::pid_t, libc::SIGKILL);
                    }
                }
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            while !self.survivors().is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    #[test]
    fn guarded_tree_dies_with_its_victim() {
        let mut tree = Tree::spawn(true);
        tree.kill_victim();
        let deadline = Instant::now() + GONE_DEADLINE;
        let survivors = loop {
            let survivors = tree.survivors();
            if survivors.is_empty() || Instant::now() >= deadline {
                break survivors;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        tree.cleanup();
        assert!(
            survivors.is_empty(),
            "guarded descendants outlived their victim past {GONE_DEADLINE:?}: {survivors:?}"
        );
        let _ = std::fs::remove_file(&tree.pidfile);
        let _ = &tree.dir;
    }

    /// Spawn `sleep 30` on a helper thread (guarded when asked), prove
    /// it live, exit the thread, and return the recorded (pid, start
    /// time). The child reparents to this process (whose group is
    /// alive): guarded, it dies by the death signal; unguarded, it
    /// survives. The dropped `Child` handle never waits; callers reap
    /// through raw `waitpid`.
    #[allow(clippy::zombie_processes)]
    fn spawn_sleeper_on_exiting_thread(guarded: bool) -> (u32, String) {
        std::thread::spawn(move || {
            let mut sleeper = Command::new("sleep");
            sleeper
                .arg("30")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if guarded {
                sleeper.die_with_parent();
            }
            let mut child = sleeper.spawn().expect("spawner spawns its sleeper");
            let pid = child.id();
            assert!(
                child.try_wait().expect("try_wait").is_none(),
                "sleeper live before the spawner thread exits"
            );
            let start = start_time(pid).expect("sleeper has a start time");
            drop(child);
            (pid, start)
        })
        .join()
        .expect("the spawner thread joins")
    }

    /// The victim helper itself must die with its spawner: it loops
    /// `sleep(3600)` forever, so an unguarded victim orphans its whole
    /// subtree when the orchestrator dies first. A helper thread plays
    /// the orchestrator (spawn returns only after the tree publishes,
    /// so the thread cannot exit before the guard arms); the main
    /// thread then observes the victim's death and the cascade.
    #[test]
    fn victim_dies_with_spawning_thread() {
        let mut tree = std::thread::spawn(|| Tree::spawn(true))
            .join()
            .expect("the spawner thread joins");
        let deadline = Instant::now() + GONE_DEADLINE;
        let survivors = loop {
            // Reap the victim through the retained handle once dead
            // (it reparents to this process, whose group is alive).
            let _ = tree.victim.try_wait();
            let survivors = tree.survivors();
            if survivors.is_empty() || Instant::now() >= deadline {
                break survivors;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let victim_status = tree.victim.try_wait().expect("try_wait on the victim");
        if victim_status.is_none() {
            // SAFETY: signals only the owned victim pid.
            unsafe {
                libc::kill(tree.victim.id() as libc::pid_t, libc::SIGKILL);
            }
            let _ = tree.victim.wait();
        }
        tree.cleanup();
        assert!(
            survivors.is_empty(),
            "victim subtree outlived its spawner past {GONE_DEADLINE:?}: {survivors:?}"
        );
        assert!(
            victim_status.is_some(),
            "the victim itself outlived its spawner"
        );
    }

    /// The orphan poll must reap test-owned zombies, not report them
    /// forever. A guarded sleeper spawned on a helper thread is
    /// SIGKILLed on thread exit and reparents to this process (group
    /// alive) as a zombie; `survivors()` must reap it via `waitpid`
    /// and report empty. Without the reap, the same zombie shape fails
    /// the main cells whenever a process-wide subreaper window overlaps
    /// a kill window.
    #[test]
    fn survivors_reaps_test_owned_zombies() {
        let (pid, start) = spawn_sleeper_on_exiting_thread(true);
        // Shape the assertion input exactly as `Tree::spawn` records
        // it; the victim handle below is already reaped and never polled.
        let mut victim = Command::new("true").spawn().expect("true spawns");
        victim.wait().expect("true reaps");
        let dir = tempfile::tempdir().expect("tree tempdir creates");
        let tree = Tree {
            pidfile: dir.path().join("tree.pids"),
            dir,
            victim,
            members: BTreeMap::from([("sleeper".to_string(), (pid, start))]),
        };
        let deadline = Instant::now() + GONE_DEADLINE;
        let survivors = loop {
            let survivors = tree.survivors();
            if survivors.is_empty() || Instant::now() >= deadline {
                break survivors;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        tree.cleanup();
        assert!(
            survivors.is_empty(),
            "test-owned zombie {pid} still reported past {GONE_DEADLINE:?}"
        );
    }

    /// Thread-death twin for [`DieWithParent`]: a helper thread spawns
    /// a guarded sleeper, proves it live, and exits; the death signal
    /// must fire for the dead spawner thread even though the test
    /// process lives on. The main thread observes the zombie and reaps
    /// it, asserting the death signal (not an exit) killed it.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn guarded_sleeper_dies_with_spawning_thread() {
        let (pid, start) = spawn_sleeper_on_exiting_thread(true);
        let deadline = Instant::now() + GONE_DEADLINE;
        let status = loop {
            let mut status = 0;
            // SAFETY: `waitpid` on the owned sleeper pid; `WNOHANG`
            // never blocks, `EINTR` retries.
            let waited = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if waited == pid as libc::pid_t {
                break status;
            }
            if waited < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR),
                    "waitpid on the owned sleeper {pid} failed"
                );
            } else {
                assert!(
                    Instant::now() < deadline,
                    "guarded sleeper {pid} outlived its spawner thread past {GONE_DEADLINE:?}"
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
            "the sleeper died by signal 9, not an exit: status {status:#x}"
        );
        assert!(
            !proc_matches(pid, &start),
            "the reaped sleeper {pid} is gone from /proc"
        );
    }

    /// Negative control: without the guard the same sleeper survives
    /// the spawner thread's exit, proving the twin above can see
    /// survival. Cleans up what it orphans.
    #[allow(clippy::zombie_processes)]
    #[test]
    fn unguarded_sleeper_survives_spawning_thread() {
        let (pid, start) = spawn_sleeper_on_exiting_thread(false);
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            proc_matches(pid, &start),
            "the unguarded control must stay live to prove the twin sees survival"
        );
        // SAFETY: signals only the owned sleeper pid, then reaps it
        // (it reparented to this process).
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
        let mut status = 0;
        // SAFETY: blocking reap of the SIGKILLed sleeper; `EINTR` retries.
        loop {
            let waited = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
            if waited == pid as libc::pid_t {
                break;
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR),
                "reaping the control sleeper {pid} failed"
            );
        }
        assert!(
            !proc_matches(pid, &start),
            "the control must clean up what it orphaned"
        );
    }

    /// Negative control: without the guard the same tree orphans, proving
    /// the cell can see orphans (a cell that passes either way proves
    /// nothing). Cleans up what it orphans.
    #[test]
    fn unguarded_tree_orphans_without_the_guard() {
        let mut tree = Tree::spawn(false);
        tree.kill_victim();
        std::thread::sleep(Duration::from_millis(500));
        let survivors = tree.survivors();
        tree.cleanup();
        assert_eq!(
            survivors.len(),
            3,
            "the unguarded control must orphan its whole tree, survivors: {survivors:?}"
        );
        assert!(
            tree.survivors().is_empty(),
            "the control must clean up what it orphaned"
        );
    }
}
