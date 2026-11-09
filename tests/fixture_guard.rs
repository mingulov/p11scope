//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Mirror cell for the integration-side parent-death guard
//! (`tests/support/mod.rs::DieWithParent`): a victim helper spawns one
//! guarded sleeper, dies by SIGKILL, and the sleeper must be gone within
//! about 2 s. The unguarded twin is the negative control. Single level:
//! two-level chaining is proven by the unit cell in `src/fixture_guard.rs`.

#[allow(dead_code)]
mod support;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use support::DieWithParent as _;

const GUARD_ENV: &str = "P11SCOPE_FIXTURE_GUARD_IT";
const VICTIM_ENV: &str = "P11SCOPE_FIXTURE_GUARD_IT_VICTIM";
const VICTIM_TEST: &str = "victim_main";
const GONE_DEADLINE: Duration = Duration::from_secs(2);
const PIDFILE_DEADLINE: Duration = Duration::from_secs(15);

fn start_time(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.rsplit_once(") ")?.1;
    tail.split_whitespace().nth(19).map(str::to_string)
}

fn proc_matches(pid: u32, start: &str) -> bool {
    start_time(pid).as_deref() == Some(start)
}

/// Re-executed victim mode: plays the test process that dies. Spawns one
/// guarded sleeper through the support helper, records it, then sleeps
/// until the orchestrator SIGKILLs it. Without [`VICTIM_ENV`] this is an
/// ordinary passing test.
///
/// The sleeper is never reaped: the victim dies by SIGKILL and the
/// sleeper reparents away, so no `wait` is possible; `/proc` polling is
/// the assertion.
#[allow(clippy::zombie_processes)]
#[test]
fn victim_main() {
    let Ok(pidfile) = std::env::var(VICTIM_ENV) else {
        return;
    };
    let guarded = std::env::var(GUARD_ENV).as_deref() == Ok("1");
    let mut sleeper = Command::new("sleep");
    sleeper
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if guarded {
        sleeper.die_with_parent();
    }
    let sleeper = sleeper.spawn().expect("victim spawns its sleeper");
    let start = start_time(sleeper.id()).expect("sleeper has a start time");
    std::fs::write(&pidfile, format!("{} {start}\n", sleeper.id())).expect("pidfile writes");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

struct Tree {
    _dir: tempfile::TempDir,
    victim: std::process::Child,
    pid: u32,
    start: String,
}

impl Tree {
    /// Spawn the victim helper (guarded: the guard watches the
    /// orchestrator, so it is inert during the proof, which kills the
    /// victim explicitly) and wait for its recorded sleeper.
    fn spawn(guarded: bool) -> Self {
        let dir = tempfile::tempdir().expect("tree tempdir creates");
        let pidfile = dir.path().join("tree.pid");
        let victim_log =
            std::fs::File::create(dir.path().join("victim.log")).expect("victim log creates");
        let mut victim = Command::new(std::env::current_exe().unwrap());
        victim
            .args(["--exact", VICTIM_TEST])
            .env(VICTIM_ENV, &pidfile)
            .env(GUARD_ENV, if guarded { "1" } else { "0" })
            .stdin(Stdio::null())
            .stdout(victim_log)
            .stderr(Stdio::null());
        victim.die_with_parent();
        let mut victim = victim.spawn().expect("orchestrator spawns its victim");
        let deadline = Instant::now() + PIDFILE_DEADLINE;
        let (pid, start) = loop {
            if let Ok(text) = std::fs::read_to_string(&pidfile) {
                let mut parts = text.split_whitespace();
                if let (Some(pid), Some(start)) = (parts.next(), parts.next())
                    && let Ok(pid) = pid.parse::<u32>()
                {
                    break (pid, start.to_string());
                }
            }
            assert!(
                Instant::now() < deadline,
                "victim never published its sleeper"
            );
            assert!(
                victim.try_wait().expect("try_wait").is_none(),
                "victim exited before publishing its sleeper"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            proc_matches(pid, &start),
            "sleeper {pid} is not the recorded live descendant"
        );
        Self {
            _dir: dir,
            victim,
            pid,
            start,
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

    /// Best-effort cleanup so even a failing run leaks no sleeper.
    fn cleanup(&self) {
        if proc_matches(self.pid, &self.start) {
            // SAFETY: signals only the recorded descendant pid whose
            // start time still matches.
            unsafe {
                libc::kill(self.pid as libc::pid_t, libc::SIGKILL);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while proc_matches(self.pid, &self.start) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[test]
fn guarded_sleeper_dies_with_its_victim() {
    let mut tree = Tree::spawn(true);
    tree.kill_victim();
    let deadline = Instant::now() + GONE_DEADLINE;
    while proc_matches(tree.pid, &tree.start) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let survived = proc_matches(tree.pid, &tree.start);
    tree.cleanup();
    assert!(
        !survived,
        "guarded sleeper {} outlived its victim past {GONE_DEADLINE:?}",
        tree.pid
    );
}

/// The victim helper itself must die with its spawner: it loops
/// `sleep(3600)` forever, so an unguarded victim orphans its sleeper
/// when the orchestrator dies first. A helper thread plays the
/// orchestrator; the main thread then observes the victim's death and
/// the sleeper's.
#[test]
fn victim_dies_with_spawning_thread() {
    let mut tree = std::thread::spawn(|| Tree::spawn(true))
        .join()
        .expect("the spawner thread joins");
    let deadline = Instant::now() + GONE_DEADLINE;
    while proc_matches(tree.pid, &tree.start) && Instant::now() < deadline {
        // Reap the victim through the retained handle once dead (it
        // reparents to this process, whose group is alive).
        let _ = tree.victim.try_wait();
        std::thread::sleep(Duration::from_millis(10));
    }
    let survived = proc_matches(tree.pid, &tree.start);
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
        !survived,
        "victim sleeper {} outlived its spawner past {GONE_DEADLINE:?}",
        tree.pid
    );
    assert!(
        victim_status.is_some(),
        "the victim itself outlived its spawner"
    );
}

/// Negative control: without the guard the same sleeper orphans, proving
/// the cell can see orphans. Cleans up what it orphans.
#[test]
fn unguarded_sleeper_orphans_without_the_guard() {
    let mut tree = Tree::spawn(false);
    tree.kill_victim();
    std::thread::sleep(Duration::from_millis(500));
    let orphaned = proc_matches(tree.pid, &tree.start);
    tree.cleanup();
    assert!(
        orphaned,
        "the unguarded control must orphan its sleeper to prove the cell sees orphans"
    );
    assert!(
        !proc_matches(tree.pid, &tree.start),
        "the control must clean up what it orphaned"
    );
}
