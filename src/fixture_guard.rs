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
        // RED: no guard registered yet; the orphan cell below fails until
        // the pre_exec hook lands.
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
            {
                if let Ok(pid) = pid.parse::<u32>() {
                    out.insert(role.to_string(), (pid, start.to_string()));
                }
            }
        }
        out
    }

    /// Re-executed victim mode: plays the test process that dies. Spawns
    /// the guarded tree (an intermediate plus a direct sleeper), records
    /// it, then sleeps until the orchestrator SIGKILLs it. Without
    /// [`VICTIM_ENV`] this is an ordinary passing test.
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
