//! SPDX-License-Identifier: GPL-3.0-or-later
//! T8/G18 live256 native pressure suite (System scope).
//!
//! This module drives the genuine live256 construction: 255 retained
//! provider-bearing children plus the eligible late owner plus one genuine
//! fresh EXEC head, all real native processes built from
//! `tests/fixtures/pressure-live/` (compiled on demand by path, the same
//! way `tests/pressure_late_provider.rs` compiles its driver). No
//! fabricated PIDs, no direct request insertion and no scripted native
//! records on the live path: queued keys must trace to actual kernel
//! DISCOVERY records collected from a real attach session.
//!
//! Layering (what each test pins):
//! - `test_live256_requires_every_owned_participant` (G18, unprivileged):
//!   the population accounts every owned participant exactly once, and
//!   removing owned participants removes exactly their contribution.
//! - `test_late_provider_cannot_be_replaced_by_ambient_counts` (G18,
//!   unprivileged): late admission follows the late owner's real mapping
//!   (physical identity), never ambient counts or digest equality.
//! - `pressure_ticket_spend_fits_256_without_ambient` (unprivileged):
//!   ticket mechanics: the real ownership-gated path arms each owned
//!   provider view exactly once, the head arms nothing, the envelope
//!   fills to exactly 256, and the 257th prepare refuses. (Per-view
//!   arming at 255 needs live EXEC upgrades: static discovery attributes
//!   one module per unique file. The privileged control proves the full
//!   255 live.)
//! - `pressure_live_ticket_spend_control_refuses_ambient` (privileged):
//!   the FIRST live control. A quiet window plus an owned probe prove
//!   ticket spend fits and refuse the cell on any ambient arming. This
//!   is the ticket-257 NO-NEED boundary condition: G16 does not gate T8
//!   only while no uncontrolled arming spends tickets in the episode.
//! - `pressure_live256_genuine_episode_admits_late_then_head` (privileged):
//!   the full positive episode (Tasks 1+2): 256 genuine queued keys, a
//!   nonempty late-provider rescan with physical publication and loader
//!   rearm (ticket 256), original-head admission, zero unexplained loss.
//! - `pressure_live256_all_blocked_twin_refuses_once` (privileged): the
//!   separately declared all-blocked/N+1 twin: exactly one head refusal,
//!   sticky loss, FIFO progress, and a batch no strict lossless verdict
//!   can pass. No capacity reset.
//! - `pressure_live256_unparked_head_control_admits` (privileged): the
//!   twin's fullness control. The identical arming with an empty request
//!   map admits the same head with zero loss, proving the refusal pins
//!   the full blocked map rather than the head.
//! - `pressure_all_blocked_fail_control_selects_eligible` (unprivileged,
//!   deterministic): the twin's blockedness fail-control. The twin's exact
//!   map shape minus the live contexts selects an eligible entry instead
//!   of refusing, proving the refusal pins per-entry blockedness: break
//!   the all-blocked precondition and the verdict flips.
//!
//! FIFO/ages/serials preservation *across service opportunities* stays
//! pinned by the deterministic unit mechanism tests in `engine_tests.rs`
//! (`pressure_services_unprotected_request_before_original_head`,
//! `pressure_all_blocked_fifo_refuses_once_then_advances`,
//! `pressure_attempt_rotation_is_finite_and_keeps_serials`); the live
//! episode pins that genuine live inputs drive that mechanism to the
//! correct outcome. The equal-content/different-file control stays pinned
//! by `pressure_late_provider_admission_with_physical_joins` (C7 phase 2),
//! which already admits a byte-identical distinct-inode copy with its own
//! slots; it is not duplicated here.
//!
//! Privileged tests assert root first, run one at a time under the
//! exclusive privileged lane (`/var/tmp/p11scope-ws-tmp/privileged.lock`,
//! held by the runner), never fork during the capture window (log files
//! are polled with plain reads), and reap every owned child. Temporary
//! I/O goes to `TMPDIR` (disk-backed on the dev host, never tmpfs).

use super::session_fixture::ScriptedSession;
use super::*;
use crate::attach::{BackendSelection, CapturePolicy, Scope};
use crate::cli::{CaptureArgs, Kind, ScopeArg};
use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::PinnedObjectId;
use crate::discovery::loader::{LoaderContextSpec, MAX_LOADER_CONTEXTS};
use crate::discovery::scheduler::MAX_PENDING_REFRESH;
use crate::process::ProcessView;
use p11scope_ebpf_common::DISCOVERY_POINTERS;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Retained provider-bearing children in the live256 population.
const RETAINED_CHILDREN: usize = 255;
/// Burst size per publication surface in unprivileged cells: small for
/// speed, still a nonempty honest ledger per child.
const UNPRIVILEGED_REPEAT: usize = 5;
/// Burst size in privileged cells: enough independent calls to prove
/// useful service without stretching the privileged lane.
const LIVE_REPEAT: usize = 25;
/// Post-admission burst size in privileged cells (old/new calls).
const LIVE_REPEAT2: usize = 5;
/// Hang guard for a full 257-child spawn wave plus gate protocol.
const POPULATION_DEADLINE: Duration = Duration::from_secs(180);
/// Hang guard for the live drain/service settle loop.
const SETTLE_DEADLINE: Duration = Duration::from_secs(120);

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn gcc_available() -> bool {
    Command::new("gcc")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Compiled pressure-live fixtures plus their work directory. The
/// providers mirror `check.sh`: the same version-matrix source with all
/// three publication surfaces, as two distinct files.
struct FixtureBuild {
    dir: tempfile::TempDir,
    early: PathBuf,
    late: PathBuf,
    driver: PathBuf,
    head: PathBuf,
}

fn compile(output: &Path, args: &[&str], source: &Path) {
    let status = Command::new("gcc")
        .args(args)
        .arg("-o")
        .arg(output)
        .arg(source)
        .status()
        .unwrap_or_else(|error| panic!("gcc {} failed to spawn: {error}", output.display()));
    assert!(status.success(), "gcc {} exited {status}", output.display());
}

impl FixtureBuild {
    fn compile_all(tag: &str) -> Self {
        assert!(gcc_available(), "gcc must be installed for {tag}");
        let dir = tempfile::Builder::new()
            .prefix(&format!("t8-live256-{tag}-"))
            .tempdir()
            .expect("disk-backed TMPDIR must accept the fixture dir");
        let matrix = manifest_dir().join("crates/discover/tests/fixture/version_matrix.c");
        let early = dir.path().join("early.so");
        compile(
            &early,
            &["-shared", "-fPIC", "-DMATRIX_INTERFACES=1"],
            &matrix,
        );
        let late = dir.path().join("late.so");
        std::fs::copy(&early, &late).expect("late provider is a byte copy, never a hardlink");
        assert_ne!(
            std::fs::metadata(&early).unwrap().ino(),
            std::fs::metadata(&late).unwrap().ino(),
            "early and late providers must be distinct physical files"
        );
        assert_eq!(
            sha256_file(&early),
            sha256_file(&late),
            "early and late providers share bytes so identity must carry the distinction"
        );
        let live = manifest_dir().join("tests/fixtures/pressure-live");
        let driver = dir.path().join("driver");
        // The driver links libdl, so it needs trailing -ldl past the source.
        let status = Command::new("gcc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
            .arg(&driver)
            .arg(live.join("driver.c"))
            .arg("-ldl")
            .status()
            .expect("gcc driver link must spawn");
        assert!(status.success(), "gcc driver link exited {status}");
        let head = dir.path().join("head");
        let head_static = Command::new("gcc")
            .args([
                "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-o",
            ])
            .arg(&head)
            .arg(live.join("static-head.c"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !head_static {
            compile(
                &head,
                &["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"],
                &live.join("static-head.c"),
            );
        }
        println!(
            "t8: fixtures built (head linkage: {})",
            if head_static { "static" } else { "dynamic" }
        );
        Self {
            dir,
            early,
            late,
            driver,
            head,
        }
    }
}

fn sha256_file(path: &Path) -> String {
    Sha256::digest(std::fs::read(path).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// One owned native child. Stdout and stderr go to a per-child log file
/// (never a pipe: 257 pipes would risk a blocked writer, and polling
/// files forks nothing during a live capture).
struct LiveChild {
    role: &'static str,
    child: Child,
    log: PathBuf,
}

impl LiveChild {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn has_prefix(&self, prefix: &str) -> bool {
        self.log_text().lines().any(|line| line.starts_with(prefix))
    }

    /// SIGTERM, then a bounded wait; SIGKILL only as a last resort, and a
    /// kill -9 exit is always a failure (the fixtures owe a clean SIGTERM
    /// shutdown). Returns the exit code.
    fn terminate(&mut self, what: &str) -> i32 {
        let pid = self.pid() as libc::pid_t;
        // SAFETY: kill only signals the owned child pid.
        assert_eq!(
            unsafe { libc::kill(pid, libc::SIGTERM) },
            0,
            "{what}: SIGTERM to owned pid {} failed: {}",
            self.pid(),
            std::io::Error::last_os_error()
        );
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match self.child.try_wait().expect("try_wait on owned child") {
                Some(status) => {
                    return status.code().unwrap_or_else(|| {
                        panic!(
                            "{what}: owned pid {} died by signal, want a clean exit",
                            self.pid()
                        )
                    });
                }
                None => {
                    assert!(
                        Instant::now() < deadline,
                        "{what}: owned pid {} ignored SIGTERM for 30s",
                        self.pid()
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}

fn proc_reaped(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/cmdline")).is_err()
}

/// The live256 population: retained provider children, the eligible late
/// owner and the provider-free head, all behind one gate file.
struct Population {
    fixtures: FixtureBuild,
    gate: PathBuf,
    gate2: Option<PathBuf>,
    children: Vec<LiveChild>,
    late_pid: u32,
    head_pid: u32,
    repeat: usize,
    repeat2: Option<usize>,
}

impl Population {
    /// Spawn `retained` provider children on `early`, one late owner on
    /// `late`, and the static head, all behind the gate; wait for every
    /// READY. Spawning is the only forking phase; everything after this
    /// point polls log files without forking.
    fn spawn(tag: &str, retained: usize, repeat: usize, with_late: bool) -> Self {
        Self::spawn_on(
            FixtureBuild::compile_all(tag),
            retained,
            repeat,
            with_late,
            true,
            None,
        )
    }

    /// Spawn onto prebuilt fixtures (live cells compile before capture so
    /// no fork lands inside the window). When `with_head` is false the
    /// head joins later via `spawn_head` (hook-clock separation). When
    /// `second_burst` is `Some`, provider children arm a second gate for
    /// the post-admission burst (old/new independent calls).
    fn spawn_on(
        fixtures: FixtureBuild,
        retained: usize,
        repeat: usize,
        with_late: bool,
        with_head: bool,
        second_burst: Option<usize>,
    ) -> Self {
        let gate = fixtures.dir.path().join("gate");
        assert!(
            !gate.exists(),
            "the gate must start absent so no child bursts early"
        );
        let gate2 = second_burst.map(|_| fixtures.dir.path().join("gate2"));
        if let Some(gate2) = &gate2 {
            assert!(!gate2.exists(), "the second gate must start absent too");
        }
        let mut children = Vec::with_capacity(retained + 2);
        let spawn_one =
            |role: &'static str, name: &str, args: &[&str], fixtures: &FixtureBuild| -> LiveChild {
                let log = fixtures.dir.path().join(format!("{name}.log"));
                let out = std::fs::File::create(&log).expect("per-child log must create");
                let err = out.try_clone().expect("stderr shares the child log");
                let child = Command::new(&fixtures.driver)
                    .args(args)
                    .env_clear()
                    .stdin(Stdio::null())
                    .stdout(out)
                    .stderr(err)
                    .spawn()
                    .unwrap_or_else(|error| panic!("spawn {role} {name}: {error}"));
                LiveChild { role, child, log }
            };
        let repeat_arg = repeat.to_string();
        let gate_arg = gate.to_str().unwrap().to_string();
        let gate2_arg = gate2
            .as_ref()
            .map(|path| path.to_str().unwrap().to_string());
        let repeat2_arg = second_burst.map(|repeat| repeat.to_string());
        for index in 0..retained {
            let provider = fixtures.early.to_str().unwrap().to_string();
            let mut args: Vec<&str> = vec![&provider, "retain", &repeat_arg, &gate_arg];
            if let (Some(gate), Some(rep)) = (gate2_arg.as_deref(), repeat2_arg.as_deref()) {
                args.push(gate);
                args.push(rep);
            }
            children.push(spawn_one(
                "retain",
                &format!("retain{index:03}"),
                &args,
                &fixtures,
            ));
        }
        let mut late_pid = 0;
        if with_late {
            let provider = fixtures.late.to_str().unwrap().to_string();
            let mut args: Vec<&str> = vec![&provider, "late", &repeat_arg, &gate_arg];
            if let (Some(gate), Some(rep)) = (gate2_arg.as_deref(), repeat2_arg.as_deref()) {
                args.push(gate);
                args.push(rep);
            }
            let late = spawn_one("late", "late", &args, &fixtures);
            late_pid = late.pid();
            children.push(late);
        }
        // The head spawns last so its genuine EXEC is the fresh head after
        // the retained prefix; tests verify the order from hook clocks,
        // never from spawn order alone.
        let mut head_pid = 0;
        if with_head {
            let head_log = fixtures.dir.path().join("head.log");
            let head_out = std::fs::File::create(&head_log).expect("head log must create");
            let head_err = head_out.try_clone().expect("head stderr shares the log");
            let head = Command::new(&fixtures.head)
                .arg(&gate_arg)
                .env_clear()
                .stdin(Stdio::null())
                .stdout(head_out)
                .stderr(head_err)
                .spawn()
                .expect("spawn static head");
            head_pid = head.id();
            children.push(LiveChild {
                role: "head",
                child: head,
                log: head_log,
            });
        }
        let mut population = Self {
            fixtures,
            gate,
            gate2,
            children,
            late_pid,
            head_pid,
            repeat,
            repeat2: second_burst,
        };
        population.wait_for_ready();
        population
    }

    fn wait_for_ready(&mut self) {
        let deadline = Instant::now() + POPULATION_DEADLINE;
        let mut pending: BTreeSet<u32> = self.children.iter().map(LiveChild::pid).collect();
        assert_eq!(
            pending.len(),
            self.children.len(),
            "every owned child must have a distinct pid"
        );
        while !pending.is_empty() {
            assert!(
                Instant::now() < deadline,
                "READY wave timed out with {} of {} children silent",
                pending.len(),
                self.children.len()
            );
            let mut done = Vec::new();
            for child in &mut self.children {
                if !pending.contains(&child.pid()) {
                    continue;
                }
                if child.has_prefix("READY pid=") {
                    let want = format!("READY pid={}", child.pid());
                    assert!(
                        child.log_text().lines().any(|line| line == want),
                        "{} child at {} reported {}, want exactly {want}",
                        child.role,
                        child.log.display(),
                        child
                            .log_text()
                            .lines()
                            .find(|line| line.starts_with("READY"))
                            .unwrap_or("<no READY>")
                    );
                    done.push(child.pid());
                    continue;
                }
                assert!(
                    child.child.try_wait().expect("try_wait").is_none(),
                    "{} child {} exited before READY: {}",
                    child.role,
                    child.pid(),
                    child.log_text()
                );
            }
            for pid in done {
                pending.remove(&pid);
            }
            if !pending.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        println!(
            "t8: READY wave complete: {} children ({} retain, late={}, head={})",
            self.children.len(),
            self.children
                .iter()
                .filter(|child| child.role == "retain")
                .count(),
            self.late_pid,
            self.head_pid
        );
    }

    /// Release the gate (plain file creation: no fork), then wait for
    /// every LEDGER line while the children hold their mappings.
    fn release_and_wait_ledgers(&mut self) {
        std::fs::write(&self.gate, b"release\n").expect("gate release must write");
        let deadline = Instant::now() + POPULATION_DEADLINE;
        let mut pending: BTreeSet<u32> = self.children.iter().map(LiveChild::pid).collect();
        while !pending.is_empty() {
            assert!(
                Instant::now() < deadline,
                "LEDGER wave timed out with {} of {} children silent",
                pending.len(),
                self.children.len()
            );
            let mut done = Vec::new();
            for child in &mut self.children {
                if !pending.contains(&child.pid()) {
                    continue;
                }
                if child.has_prefix("LEDGER ") {
                    done.push(child.pid());
                    continue;
                }
                assert!(
                    child.child.try_wait().expect("try_wait").is_none(),
                    "{} child {} exited before LEDGER: {}",
                    child.role,
                    child.pid(),
                    child.log_text()
                );
            }
            for pid in done {
                pending.remove(&pid);
            }
            if !pending.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        println!("t8: LEDGER wave complete: {} children", self.children.len());
    }

    /// Release the second gate, then wait for every provider child's
    /// second LEDGER (the head holds on its single ledger).
    fn release2_and_wait_ledgers(&mut self, what: &str) {
        let gate2 = self
            .gate2
            .as_ref()
            .unwrap_or_else(|| panic!("{what}: no second gate armed"))
            .clone();
        std::fs::write(&gate2, b"release\n").expect("second gate release must write");
        let deadline = Instant::now() + POPULATION_DEADLINE;
        let mut pending: BTreeSet<u32> = self.provider_pids();
        while !pending.is_empty() {
            assert!(
                Instant::now() < deadline,
                "{what}: LEDGER-2 wave timed out with {} providers silent",
                pending.len()
            );
            let mut done = Vec::new();
            for child in &mut self.children {
                if !pending.contains(&child.pid()) {
                    continue;
                }
                if child
                    .log_text()
                    .lines()
                    .filter(|line| line.starts_with("LEDGER "))
                    .count()
                    >= 2
                {
                    done.push(child.pid());
                    continue;
                }
                assert!(
                    child.child.try_wait().expect("try_wait").is_none(),
                    "{what}: {} child {} exited before LEDGER 2: {}",
                    child.role,
                    child.pid(),
                    child.log_text()
                );
            }
            for pid in done {
                pending.remove(&pid);
            }
            if !pending.is_empty() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        println!(
            "t8: LEDGER-2 wave complete: {} providers",
            self.provider_pids().len()
        );
    }

    fn pids(&self) -> BTreeSet<u32> {
        self.children.iter().map(LiveChild::pid).collect()
    }

    fn provider_pids(&self) -> BTreeSet<u32> {
        self.children
            .iter()
            .filter(|child| child.role != "head")
            .map(LiveChild::pid)
            .collect()
    }

    /// SIGTERM every owned child, verify each exit code, verify each PID
    /// is reaped, and remove the work directory. `expect_code` maps a
    /// child role to its required exit code.
    fn terminate_all(&mut self, what: &str, expect_code: &dyn Fn(&str) -> i32) {
        for child in &mut self.children {
            let code = child.terminate(what);
            assert_eq!(
                code,
                expect_code(child.role),
                "{what}: {} child {} exited {code}",
                child.role,
                child.pid()
            );
        }
        for pid in self.pids() {
            assert!(proc_reaped(pid), "{what}: owned child {pid} must reap");
        }
        let dir = self.fixtures.dir.path().to_path_buf();
        self.children.clear();
        std::fs::remove_dir_all(&dir).expect("the cell removes its fixtures");
        assert!(!dir.exists(), "{what}: the cell removes its fixtures");
    }
}

/// Backstop: a failed assertion must not strand 257 live children. Best
/// effort only (no asserts, no exit-code checks); the explicit
/// `terminate_all` in each test is the real cleanup proof.
impl Drop for Population {
    fn drop(&mut self) {
        for child in &mut self.children {
            // SAFETY: best-effort SIGTERM to the owned child pid.
            unsafe {
                libc::kill(child.pid() as libc::pid_t, libc::SIGTERM);
            }
        }
        for child in &mut self.children {
            let deadline = Instant::now() + Duration::from_secs(10);
            while child.child.try_wait().unwrap_or(None).is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = child.child.kill();
            let _ = child.child.wait();
        }
        // TempDir removes the work directory itself.
    }
}

struct ParsedLedger {
    pid: u32,
    mode: String,
    burst: u64,
    complete: bool,
    functions: Vec<(String, u64, u64)>,
}

fn parse_provider_ledger(text: &str, what: &str) -> ParsedLedger {
    parse_provider_ledgers(text, what)
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("{what}: no LEDGER line"))
}

fn parse_provider_ledgers(text: &str, what: &str) -> Vec<ParsedLedger> {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("LEDGER "))
        .collect();
    assert!(!lines.is_empty(), "{what}: no LEDGER line");
    lines
        .iter()
        .map(|line| parse_one_ledger(line, what))
        .collect()
}

fn parse_one_ledger(line: &str, what: &str) -> ParsedLedger {
    let value: serde_json::Value =
        serde_json::from_str(line.strip_prefix("LEDGER ").unwrap()).expect("LEDGER must be JSON");
    assert_eq!(
        value.get("schema").and_then(serde_json::Value::as_str),
        Some("p11scope/pressure-live-ledger/v1"),
        "{what}: ledger schema"
    );
    let functions = value
        .get("functions")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|function| {
            (
                function
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                function
                    .get("attempts")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(u64::MAX),
                function
                    .get("successful")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(u64::MAX),
            )
        })
        .collect();
    ParsedLedger {
        pid: value
            .get("pid")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as u32,
        mode: value
            .get("mode")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_string(),
        burst: value
            .get("burst")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        complete: value
            .get("complete")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        functions,
    }
}

struct TargetLine {
    name: String,
    major: u32,
    minor: u32,
    ino: u64,
}

fn parse_targets(text: &str) -> Vec<TargetLine> {
    text.lines()
        .filter(|line| line.starts_with("TARGET "))
        .map(|line| {
            let value: serde_json::Value =
                serde_json::from_str(line.strip_prefix("TARGET ").unwrap())
                    .expect("TARGET must be JSON");
            let dev = value
                .get("dev")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            TargetLine {
                name: value
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?")
                    .to_string(),
                major: dev.first().and_then(serde_json::Value::as_u64).unwrap_or(0) as u32,
                minor: dev.get(1).and_then(serde_json::Value::as_u64).unwrap_or(0) as u32,
                ino: value
                    .get("ino")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            }
        })
        .collect()
}

/// The kernel's `(major, minor, ino)` rendering of `pid`'s live mapping
/// of the file named `name`: the independent side of every TARGET join.
/// Maps-vs-maps, never stat: on btrfs stat() and maps report different
/// device numbers for the same file.
fn maps_triple(pid: u32, name: &str, what: &str) -> (u32, u32, u64) {
    let maps = maps_text(pid);
    assert!(!maps.is_empty(), "{what}: owned pid {pid} maps must read");
    for line in maps.lines() {
        let fields: Vec<&str> = line.splitn(6, ' ').collect();
        if fields.len() == 6 && fields[5].ends_with(name) {
            let (major, minor) = fields[3].split_once(':').unwrap();
            return (
                u32::from_str_radix(major, 16).unwrap(),
                u32::from_str_radix(minor, 16).unwrap(),
                fields[4].parse::<u64>().unwrap(),
            );
        }
    }
    panic!("{what}: owned pid {pid} maps no object ending with {name}");
}

fn maps_text(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default()
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0)
}

fn vm_hwm_kb() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")
                .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
        })
        .unwrap_or(0)
}

fn self_cpu_jiffies() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let rest = stat.rsplit_once(") ").map(|(_, rest)| rest).unwrap_or("");
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let utime: u64 = fields
        .get(11)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let stime: u64 = fields
        .get(12)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    utime + stime
}

fn system_args(hints: Vec<PathBuf>) -> CaptureArgs {
    CaptureArgs {
        kind: Kind::Profile,
        modules: hints,
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: ScopeArg::System,
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        max_scan_pids: None,
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: BackendSelection::default(),
    }
}

/// The ambient-refusal oracle: every attached loader context must belong
/// to an owned pid. Any other arming is uncontrolled ambient spend and
/// refuses the cell (loud failure, never a quiet pass).
fn assert_no_ambient_arms(engine: &Engine, owned: &BTreeSet<u32>, what: &str) {
    for (id, context) in engine.loader_registry.attached_contexts() {
        let view = engine
            .views
            .iter()
            .find(|view| view.id() == context.spec.view)
            .unwrap_or_else(|| panic!("{what}: context {} names a missing view", id.get()));
        assert!(
            owned.contains(&view.pid()),
            "{what}: REFUSED: ambient arming: context {} attached to foreign pid {} (owned set has {} pids)",
            id.get(),
            view.pid(),
            owned.len()
        );
    }
}

/// G18 oracle: the live256 construction requires every owned
/// participant. The full native population accounts each owned pid
/// exactly once (READY/LEDGER/TARGET all name the true child pid and
/// join the owned provider files), and removing owned participants
/// before release removes exactly their contribution: no phantom keys,
/// no substitution, nothing lingers.
#[test]
fn test_live256_requires_every_owned_participant() {
    const WHAT: &str = "g18-requires-every-participant";
    let wall_start = Instant::now();
    let fds_start = fd_count();
    let mut population =
        Population::spawn("g18-every", RETAINED_CHILDREN, UNPRIVILEGED_REPEAT, true);
    assert_eq!(population.children.len(), RETAINED_CHILDREN + 2);

    // Mutation: one retained child and the late owner leave before
    // release. Both owe exit 1 (SIGTERM before the gate means the burst
    // never completed) and no LEDGER line.
    let removed_retain = population
        .children
        .iter()
        .find(|child| child.role == "retain")
        .map(LiveChild::pid)
        .unwrap();
    let removed_late = population.late_pid;
    for pid in [removed_retain, removed_late] {
        let index = population
            .children
            .iter()
            .position(|child| child.pid() == pid)
            .unwrap();
        let mut child = population.children.swap_remove(index);
        let code = child.terminate(WHAT);
        assert_eq!(
            code, 1,
            "{WHAT}: pre-release SIGTERM must exit 1, got {code}"
        );
        assert!(proc_reaped(pid), "{WHAT}: removed child {pid} must reap");
        assert!(
            !child.has_prefix("LEDGER "),
            "{WHAT}: removed child {pid} must leave no phantom LEDGER"
        );
    }
    assert_eq!(population.children.len(), RETAINED_CHILDREN);

    population.release_and_wait_ledgers();
    let mut ledger_pids = BTreeSet::new();
    for child in &population.children {
        let text = child.log_text();
        if child.role == "head" {
            assert_eq!(
                parse_targets(&text).len(),
                0,
                "{WHAT}: the head emits no TARGET"
            );
            assert!(
                text.lines().any(|line| line
                    .starts_with("LEDGER {\"schema\":\"p11scope/pressure-live-head/v1\"")),
                "{WHAT}: head LEDGER schema"
            );
            ledger_pids.insert(child.pid());
            continue;
        }
        let ledgers = parse_provider_ledgers(&text, WHAT);
        assert_eq!(
            ledgers.len(),
            1,
            "{WHAT}: single-burst children emit one LEDGER"
        );
        let ledger = &ledgers[0];
        assert_eq!(
            ledger.pid,
            child.pid(),
            "{WHAT}: LEDGER names the true child pid"
        );
        assert_eq!(
            ledger.mode, child.role,
            "{WHAT}: LEDGER mode matches the population role"
        );
        assert_eq!(ledger.burst, 1, "{WHAT}: the single burst numbers 1");
        assert!(
            ledger.complete,
            "{WHAT}: {} ledger must be complete",
            child.pid()
        );
        assert_eq!(
            ledger.functions.len(),
            3,
            "{WHAT}: three publication surfaces"
        );
        for (name, attempts, successful) in &ledger.functions {
            assert_eq!(
                (*attempts, *successful),
                (UNPRIVILEGED_REPEAT as u64, UNPRIVILEGED_REPEAT as u64),
                "{WHAT}: {name} attempts/successful are honest and nonempty"
            );
        }
        let targets = parse_targets(&text);
        assert_eq!(targets.len(), 3, "{WHAT}: one TARGET per surface");
        let want = maps_triple(child.pid(), "early.so", WHAT);
        for target in &targets {
            assert_eq!(
                (target.major, target.minor, target.ino),
                want,
                "{WHAT}: {} TARGET joins the owned early provider",
                target.name
            );
        }
        ledger_pids.insert(child.pid());
    }
    assert_eq!(
        ledger_pids,
        population.pids(),
        "{WHAT}: every surviving owned pid accounts exactly once"
    );
    assert!(
        !ledger_pids.contains(&removed_retain) && !ledger_pids.contains(&removed_late),
        "{WHAT}: removed participants leave no contribution behind"
    );

    // The head maps no provider: provider-freedom from /proc, never from
    // the LEDGER self-report alone.
    let head_maps = maps_text(population.head_pid);
    assert!(
        !head_maps.contains("early.so") && !head_maps.contains("late.so"),
        "{WHAT}: the head must map no provider"
    );
    let head_cmdline =
        std::fs::read(format!("/proc/{}/cmdline", population.head_pid)).unwrap_or_default();
    let head_cmdline = String::from_utf8_lossy(&head_cmdline);
    assert!(
        !head_cmdline.contains("early.so") && !head_cmdline.contains("late.so"),
        "{WHAT}: the head argv names no provider"
    );

    population.terminate_all(WHAT, &|_| 0);
    let fds_end = fd_count();
    assert!(
        fds_end <= fds_start + 4,
        "{WHAT}: no descriptor leak: start={fds_start} end={fds_end}"
    );
    println!(
        "g18: every-participant: 255 ledgers exact, 2 removed cleanly, wall={:?} VmHWM={}KiB fds {fds_start}->{fds_end}",
        wall_start.elapsed(),
        vm_hwm_kb()
    );
}

impl Population {
    /// Add the eligible late owner to a running population (the
    /// late-provider arrival), then wait for its READY.
    fn spawn_late(&mut self, what: &str) -> u32 {
        assert_eq!(
            self.late_pid, 0,
            "{what}: the late owner joins exactly once"
        );
        let log = self.fixtures.dir.path().join("late.log");
        let out = std::fs::File::create(&log).expect("late log must create");
        let err = out.try_clone().expect("late stderr shares the log");
        let mut command = Command::new(&self.fixtures.driver);
        command
            .arg(self.fixtures.late.to_str().unwrap())
            .arg("late")
            .arg(self.repeat.to_string())
            .arg(self.gate.to_str().unwrap());
        if let (Some(gate2), Some(repeat2)) = (self.gate2.as_ref(), self.repeat2) {
            command
                .arg(gate2.to_str().unwrap())
                .arg(repeat2.to_string());
        }
        let mut late = LiveChild {
            role: "late",
            child: command
                .env_clear()
                .stdin(Stdio::null())
                .stdout(out)
                .stderr(err)
                .spawn()
                .expect("spawn late owner"),
            log,
        };
        let pid = late.pid();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if late.has_prefix(&format!("READY pid={pid}")) {
                break;
            }
            assert!(
                late.child.try_wait().expect("try_wait").is_none(),
                "{what}: late child exited before READY: {}",
                late.log_text()
            );
            assert!(
                Instant::now() < deadline,
                "{what}: late child never became READY"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        self.late_pid = pid;
        self.children.push(late);
        pid
    }

    /// Add the provider-free head to a running population after a
    /// hook-clock separation, then wait for its READY.
    fn spawn_head(&mut self, what: &str) -> u32 {
        assert_eq!(self.head_pid, 0, "{what}: the head joins exactly once");
        let log = self.fixtures.dir.path().join("head.log");
        let out = std::fs::File::create(&log).expect("head log must create");
        let err = out.try_clone().expect("head stderr shares the log");
        let mut head = LiveChild {
            role: "head",
            child: Command::new(&self.fixtures.head)
                .arg(self.gate.to_str().unwrap())
                .env_clear()
                .stdin(Stdio::null())
                .stdout(out)
                .stderr(err)
                .spawn()
                .expect("spawn static head"),
            log,
        };
        let pid = head.pid();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if head.has_prefix(&format!("READY pid={pid}")) {
                break;
            }
            assert!(
                head.child.try_wait().expect("try_wait").is_none(),
                "{what}: head exited before READY: {}",
                head.log_text()
            );
            assert!(Instant::now() < deadline, "{what}: head never became READY");
            std::thread::sleep(Duration::from_millis(10));
        }
        self.head_pid = pid;
        self.children.push(head);
        pid
    }
}

/// G18 oracle: the late provider cannot be replaced by ambient counts.
/// A 255-strong provider background plus the head creates zero late
/// presence (no owned mapping, no discovery, no slot); the late owner
/// alone admits it, joined by physical identity even though its bytes
/// are identical to the early provider's.
#[test]
fn test_late_provider_cannot_be_replaced_by_ambient_counts() {
    const WHAT: &str = "g18-late-not-ambient";
    let wall_start = Instant::now();
    let mut population =
        Population::spawn("g18-late", RETAINED_CHILDREN, UNPRIVILEGED_REPEAT, false);
    assert_eq!(population.children.len(), RETAINED_CHILDREN + 1);
    assert_eq!(
        sha256_file(&population.fixtures.early),
        sha256_file(&population.fixtures.late),
        "{WHAT}: the trap is set: identical bytes, distinct files"
    );
    // Inode numbers are stable across stat and maps (only the btrfs
    // device rendering differs); digests prove same-bytes.
    assert_ne!(
        std::fs::metadata(&population.fixtures.early).unwrap().ino(),
        std::fs::metadata(&population.fixtures.late).unwrap().ino(),
        "{WHAT}: distinct physical files"
    );

    // No owned process maps late.so: the background cannot conjure it.
    for child in &population.children {
        assert!(
            !maps_text(child.pid()).contains("late.so"),
            "{WHAT}: {} child {} must not map late.so before the late owner arrives",
            child.role,
            child.pid()
        );
    }

    // Discovery over the 255-strong background, before any call: early
    // identifies physically (cold tables admit no slots yet), late stays
    // absent, and every admitted slot targets owned files only.
    let hints = vec![
        population.fixtures.early.clone(),
        population.fixtures.late.clone(),
    ];
    let engine1 = Engine::discover(&system_args(hints.clone()), &Scope::System, None)
        .expect("system discovery");
    assert_module_identified(
        &engine1,
        population.children[0].pid(),
        &population.fixtures.early,
        WHAT,
    );
    assert_module_absent(&engine1, &population.fixtures.late, WHAT);
    assert_slots_target(&engine1, &["early.so"], WHAT);

    // The late owner arrives: late identifies with its own physical
    // identity while early stays retained; still no calls, still no
    // coverage from counts alone.
    let late_pid = population.spawn_late(WHAT);
    assert!(
        maps_text(late_pid).contains("late.so"),
        "{WHAT}: the late owner really maps late.so"
    );
    let engine2 = Engine::discover(&system_args(hints.clone()), &Scope::System, None)
        .expect("system rediscovery");
    assert_module_identified(&engine2, late_pid, &population.fixtures.late, WHAT);
    assert_module_identified(
        &engine2,
        population.children[0].pid(),
        &population.fixtures.early,
        WHAT,
    );
    assert_slots_target(&engine2, &["early.so", "late.so"], WHAT);
    let late_module = engine2
        .discovery()
        .modules
        .iter()
        .find(|module| module.path.ends_with("late.so"))
        .unwrap();
    let late_maps = maps_triple(late_pid, "late.so", WHAT);
    assert_eq!(
        (late_module.dev, late_module.ino),
        ((late_maps.0 as u64, late_maps.1 as u64), late_maps.2),
        "{WHAT}: late joins its own (dev, ino), not early's"
    );
    assert_ne!(
        late_maps,
        maps_triple(population.children[0].pid(), "early.so", WHAT),
        "{WHAT}: late and early keep distinct maps identities"
    );

    // After release the warm tables publish: both providers join fully
    // with their own slots, all owned.
    population.release_and_wait_ledgers();
    let engine3 =
        Engine::discover(&system_args(hints), &Scope::System, None).expect("post-call discovery");
    assert_module_joined(&engine3, late_pid, &population.fixtures.late, WHAT);
    assert_module_joined(
        &engine3,
        population.children[0].pid(),
        &population.fixtures.early,
        WHAT,
    );
    assert_slots_target(&engine3, &["early.so", "late.so"], WHAT);

    // The late ledger and TARGETs join the late file after release.
    let late_child = population
        .children
        .iter()
        .find(|child| child.pid() == late_pid)
        .unwrap();
    let late_text = late_child.log_text();
    let late_ledgers = parse_provider_ledgers(&late_text, WHAT);
    assert_eq!(
        late_ledgers.len(),
        1,
        "{WHAT}: single-burst late emits one LEDGER"
    );
    let late_ledger = &late_ledgers[0];
    assert_eq!(late_ledger.mode, "late");
    assert_eq!(late_ledger.burst, 1);
    assert!(late_ledger.complete);
    assert!(
        late_ledger
            .functions
            .iter()
            .all(|(_, attempts, successful)| (*attempts, *successful)
                == (UNPRIVILEGED_REPEAT as u64, UNPRIVILEGED_REPEAT as u64))
    );
    let late_maps = maps_triple(late_pid, "late.so", WHAT);
    for target in parse_targets(&late_text) {
        assert_eq!(
            (target.major, target.minor, target.ino),
            late_maps,
            "{WHAT}: late TARGET joins late.so"
        );
    }

    drop(engine1);
    drop(engine2);
    drop(engine3);
    population.terminate_all(WHAT, &|_| 0);
    println!(
        "g18: late-not-ambient: absent under 255 background, admitted by its owner, wall={:?}",
        wall_start.elapsed()
    );
}

/// Module identification without slot coverage: the kernel's identity
/// rendering plus the fixture digest. For cold tables (no call yet),
/// where planning slots would be dishonest.
fn assert_module_identified(engine: &Engine, pid: u32, object: &Path, what: &str) {
    let name = object.file_name().unwrap().to_string_lossy().into_owned();
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("owned maps must read");
    let mut found = None;
    for line in maps.lines() {
        let fields: Vec<&str> = line.splitn(6, ' ').collect();
        if fields.len() == 6 && fields[5].ends_with(&name) {
            let (major, minor) = fields[3].split_once(':').unwrap();
            found = Some((
                (
                    u64::from_str_radix(major, 16).unwrap(),
                    u64::from_str_radix(minor, 16).unwrap(),
                ),
                fields[4].parse::<u64>().unwrap(),
            ));
            break;
        }
    }
    let (dev, ino) = found
        .unwrap_or_else(|| panic!("{what}: owned pid {pid} maps no object ending with {name}"));
    let module = engine
        .discovery()
        .modules
        .iter()
        .find(|module| module.path.ends_with(&name))
        .unwrap_or_else(|| panic!("{what}: {name} must be a discovered module"));
    assert_eq!(
        (module.dev, module.ino),
        (dev, ino),
        "{what}: {name} joins (dev, ino)"
    );
    assert_eq!(
        module.sha256.as_deref(),
        Some(sha256_file(object).as_str()),
        "{what}: {name} joins the fixture digest"
    );
    println!("t8: {what}: {name} identified: ino={ino}");
}

/// A discovered module carries the kernel's identity rendering and the
/// fixture digest, and every planned slot into it resolves inside the
/// object's own bytes. Mirrors the C7 join (the same public shape).
fn assert_module_joined(engine: &Engine, pid: u32, object: &Path, what: &str) {
    let name = object.file_name().unwrap().to_string_lossy().into_owned();
    let (dev, ino) = {
        let maps =
            std::fs::read_to_string(format!("/proc/{pid}/maps")).expect("owned maps must read");
        let mut found = None;
        for line in maps.lines() {
            let fields: Vec<&str> = line.splitn(6, ' ').collect();
            if fields.len() == 6 && fields[5].ends_with(&name) {
                let (major, minor) = fields[3].split_once(':').unwrap();
                found = Some((
                    (
                        u64::from_str_radix(major, 16).unwrap(),
                        u64::from_str_radix(minor, 16).unwrap(),
                    ),
                    fields[4].parse::<u64>().unwrap(),
                ));
                break;
            }
        }
        found.unwrap_or_else(|| panic!("{what}: owned pid {pid} maps no object ending with {name}"))
    };
    let module = engine
        .discovery()
        .modules
        .iter()
        .find(|module| module.path.ends_with(&name))
        .unwrap_or_else(|| panic!("{what}: {name} must be a discovered module"));
    assert_eq!(
        (module.dev, module.ino),
        (dev, ino),
        "{what}: {name} joins (dev, ino)"
    );
    assert_eq!(
        module.sha256.as_deref(),
        Some(sha256_file(object).as_str()),
        "{what}: {name} joins the fixture digest"
    );
    let len = std::fs::metadata(object).unwrap().len();
    let slots: Vec<_> = engine
        .plan()
        .slots
        .iter()
        .filter(|slot| slot.object_path.ends_with(&name))
        .collect();
    assert!(
        !slots.is_empty(),
        "{what}: {name} admits at least one planned slot"
    );
    for slot in &slots {
        assert!(
            slot.file_offset < len,
            "{what}: {name} slot offset resolves inside {len} bytes"
        );
    }
    println!(
        "t8: {what}: {name} admitted: {} slot(s), ino={ino}",
        slots.len()
    );
}

fn assert_module_absent(engine: &Engine, object: &Path, what: &str) {
    let name = object.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        !engine
            .discovery()
            .modules
            .iter()
            .any(|module| module.path.ends_with(&name)),
        "{what}: nothing maps {name} yet"
    );
    assert!(
        !engine
            .plan()
            .slots
            .iter()
            .any(|slot| slot.object_path.ends_with(&name)),
        "{what}: no slot targets unmapped {name}"
    );
}

/// Every admitted slot targets one of the named owned objects: ambient
/// coverage can never substitute for owned admission.
fn assert_slots_target(engine: &Engine, allowed: &[&str], what: &str) {
    for slot in &engine.plan().slots {
        assert!(
            allowed.iter().any(|name| slot.object_path.ends_with(name)),
            "{what}: slot targets ambient object {}",
            slot.object_path
        );
    }
}

/// Every minted loader ticket (any state): with no removals this is the
/// exact allocated set, insensitive to the prepared/attached distinction.
fn minted_ids(engine: &Engine) -> BTreeSet<u16> {
    let mut ids = BTreeSet::new();
    for view in &engine.views {
        ids.extend(
            engine
                .loader_registry
                .ids_for_view(view.id())
                .iter()
                .map(|id| id.get()),
        );
    }
    ids
}

/// Zero episode loss: no queue refusal, no dropped newcomer, and no
/// request-queue or loader-arming loss entry. Discovery-informational
/// skips (scope notes, ambient misses, cold-table notes) are expected
/// on a shared host and are not episode loss.
fn assert_no_episode_loss(engine: &Engine, what: &str) {
    assert_eq!(
        engine.discovery_truncated, 0,
        "{what}: no refusal in the episode"
    );
    assert_eq!(
        engine.newcomer_ages.dropped_unknown, 0,
        "{what}: no dropped newcomer in the episode"
    );
    let loss: Vec<_> = engine
        .counters
        .object_skips
        .iter()
        .filter(|skip| {
            skip.subject == "live discovery refresh" || skip.subject == "live loader arming"
        })
        .collect();
    assert!(loss.is_empty(), "{what}: zero episode loss: {loss:?}");
}

/// Resolve the live view position for an owned pid, fresh on every call
/// (arming may reshape the view list, so positions never persist).
/// One-line live census for the twin/control phase boundaries: total
/// views, owned views, minted loader ids (count plus any missing from
/// 1..=256), ambient views, queued retirements and exploratory evictions.
fn twin_census(engine: &Engine, owned: &BTreeSet<u32>, tag: &str, what: &str) {
    let minted = minted_ids(engine);
    let missing: Vec<u16> = (1..=256).filter(|id| !minted.contains(id)).collect();
    let owned_views = engine
        .views
        .iter()
        .filter(|view| owned.contains(&view.pid()))
        .count();
    let ambient_views = engine.views.len().saturating_sub(owned_views);
    println!(
        "t8: {what}: census {tag}: views={} owned_views={} ambient_views={} minted={} missing={:?} retire_intents={} pending_retire={} explore_evict={} truncated={}",
        engine.views.len(),
        owned_views,
        ambient_views,
        minted.len(),
        missing,
        engine.retirement_intents.len(),
        engine.pending_retirements.len(),
        engine.exploratory_evictions,
        engine.discovery_truncated
    );
}

fn live_position(engine: &Engine, pid: u32, what: &str) -> usize {
    engine
        .views
        .iter()
        .position(|view| view.pid() == pid && view.still_the_same())
        .unwrap_or_else(|| panic!("{what}: owned pid {pid} has no live view"))
}

/// A tiny hand-rolled group for the gate/envelope test: two provider
/// children on distinct files plus the head. Small on purpose: static
/// discovery attributes one module per unique file, so per-view arming
/// at 255 needs live EXEC upgrades (the privileged control proves the
/// full 255 live); this test pins the ownership gate, the head-0 rule
/// and the exact 256 envelope instead.
struct SmallGroup {
    dir: tempfile::TempDir,
    gate: PathBuf,
    children: Vec<LiveChild>,
}

impl SmallGroup {
    fn spawn(fixtures: &FixtureBuild, second: &Path, what: &str) -> Self {
        let tmp = tempfile::Builder::new()
            .prefix("t8-ticket-gate-")
            .tempdir()
            .expect("gate dir must create");
        let gate = tmp.path().join("gate");
        let mut children = Vec::new();
        for (role, name, provider) in [
            ("retain", "one", fixtures.early.to_str().unwrap()),
            ("retain", "two", second.to_str().unwrap()),
        ] {
            let log = tmp.path().join(format!("{name}.log"));
            let out = std::fs::File::create(&log).expect("child log must create");
            let err = out.try_clone().unwrap();
            let child = Command::new(&fixtures.driver)
                .arg(provider)
                .arg(role)
                .arg(UNPRIVILEGED_REPEAT.to_string())
                .arg(gate.to_str().unwrap())
                .env_clear()
                .stdin(Stdio::null())
                .stdout(out)
                .stderr(err)
                .spawn()
                .unwrap_or_else(|error| panic!("{what}: spawn {name}: {error}"));
            children.push(LiveChild { role, child, log });
        }
        let head_log = tmp.path().join("head.log");
        let head_out = std::fs::File::create(&head_log).expect("head log must create");
        let head_err = head_out.try_clone().unwrap();
        let head = Command::new(&fixtures.head)
            .arg(gate.to_str().unwrap())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(head_out)
            .stderr(head_err)
            .spawn()
            .unwrap_or_else(|error| panic!("{what}: spawn head: {error}"));
        children.push(LiveChild {
            role: "head",
            child: head,
            log: head_log,
        });
        let deadline = Instant::now() + Duration::from_secs(60);
        while children.iter().any(|child| !child.has_prefix("READY pid=")) {
            assert!(Instant::now() < deadline, "{what}: READY wave timed out");
            assert!(
                children.iter_mut().all(|child| child
                    .child
                    .try_wait()
                    .expect("try_wait")
                    .is_none()),
                "{what}: a child exited before READY"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        Self {
            dir: tmp,
            gate,
            children,
        }
    }

    fn pids(&self) -> BTreeSet<u32> {
        self.children.iter().map(LiveChild::pid).collect()
    }

    fn release_and_wait_ledgers(&mut self, what: &str) {
        std::fs::write(&self.gate, b"release\n").expect("gate release must write");
        let deadline = Instant::now() + Duration::from_secs(60);
        while self
            .children
            .iter()
            .any(|child| !child.has_prefix("LEDGER "))
        {
            assert!(Instant::now() < deadline, "{what}: LEDGER wave timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate_all(&mut self, what: &str) {
        for child in &mut self.children {
            assert_eq!(child.terminate(what), 0, "{what}: {} exits 0", child.role);
        }
        for pid in self.pids() {
            assert!(proc_reaped(pid), "{what}: owned child {pid} must reap");
        }
        self.children.clear();
        let dir = self.dir.path().to_path_buf();
        std::fs::remove_dir_all(&dir).expect("the cell removes its gate dir");
        assert!(!dir.exists(), "{what}: the cell removes its gate dir");
    }
}

impl Drop for SmallGroup {
    fn drop(&mut self) {
        for child in &mut self.children {
            // SAFETY: best-effort SIGTERM to the owned child pid.
            unsafe {
                libc::kill(child.pid() as libc::pid_t, libc::SIGTERM);
            }
        }
        for child in &mut self.children {
            let deadline = Instant::now() + Duration::from_secs(10);
            while child.child.try_wait().unwrap_or(None).is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            let _ = child.child.kill();
            let _ = child.child.wait();
        }
    }
}

/// Ticket mechanics under the first live control: the real
/// ownership-gated arming path arms each owned provider view exactly
/// once, the provider-free head arms nothing, the envelope fills to
/// exactly 256, and the 257th prepare refuses. Any ambient
/// provider-bearing view refuses the cell. The full live256 spend
/// (255 same-file views via live EXEC upgrades) is proved privileged.
#[test]
fn pressure_ticket_spend_fits_256_without_ambient() {
    const WHAT: &str = "t8-ticket-spend";
    let wall_start = Instant::now();
    let fixtures = FixtureBuild::compile_all("tickets");
    // Two distinct provider files (same bytes): static discovery gives
    // each mapper its own module, so both views arm for real.
    let second = fixtures.dir.path().join("second.so");
    std::fs::copy(&fixtures.early, &second).expect("second provider must copy");
    assert_ne!(
        std::fs::metadata(&fixtures.early).unwrap().ino(),
        std::fs::metadata(&second).unwrap().ino()
    );
    let mut group = SmallGroup::spawn(&fixtures, &second, WHAT);
    let owned = group.pids();
    assert_eq!(owned.len(), 3);

    let hints = vec![fixtures.early.clone(), second.clone()];
    let mut engine =
        Engine::discover(&system_args(hints), &Scope::System, None).expect("system discovery");
    assert_eq!(
        engine.loader_arms, 0,
        "{WHAT}: discovery alone arms nothing"
    );
    assert!(
        minted_ids(&engine).is_empty(),
        "{WHAT}: discovery alone mints nothing"
    );

    // Every provider-owned view must be an owned pid, and both owned
    // provider children must own one: no missing child, no ambient
    // provider-bearing process.
    let provider_pids: BTreeSet<u32> = group
        .children
        .iter()
        .filter(|child| child.role != "head")
        .map(LiveChild::pid)
        .collect();
    let mut provider_views = BTreeSet::new();
    for view in &engine.views {
        let owned_provider = engine
            .modules
            .iter()
            .any(|module| module.scanned.view == view.id());
        if owned_provider {
            assert!(
                owned.contains(&view.pid()),
                "{WHAT}: REFUSED: ambient provider-bearing view for foreign pid {}",
                view.pid()
            );
            provider_views.insert(view.pid());
        }
    }
    assert_eq!(
        provider_views, provider_pids,
        "{WHAT}: exactly the 2 owned provider views, no more, no fewer"
    );

    // Arm both owned provider views through the real ownership-gated
    // path: one ticket each, nothing ambient.
    let mut session = ScriptedSession::default();
    // The scripted session must report the attach like a real one, or
    // every arm mints but reports false (engine_tests precedent).
    session.dynamic_loader_reports_added = true;
    let mut additions_allowed = true;
    let mut pending_views = PendingViewRetirements::new();
    let mut owned_pids: Vec<u32> = provider_pids.iter().copied().collect();
    owned_pids.sort_unstable();
    for pid in &owned_pids {
        let position = live_position(&engine, *pid, WHAT);
        let view_id = engine.views[position].id();
        assert!(
            !engine.loader_arming_gated(view_id),
            "{WHAT}: owned pid {pid} is provider-owned, not gated"
        );
        // The bool is candidate-changed bookkeeping (ORed into batch
        // state by production callers), not the armed signal: a fully
        // successful arm still reports false when its candidate applies
        // no change. The armed signal is the minted context, like the
        // pressure oracle's "really rearmed" check.
        let _candidate_changed: bool = engine
            .arm_loader_or_partial(
                position,
                &mut session,
                &mut additions_allowed,
                &mut pending_views,
            )
            .unwrap_or_else(|error| panic!("{WHAT}: arming owned pid {pid} failed: {error:#}"));
        assert_eq!(
            engine.loader_registry.ids_for_view(view_id).len(),
            1,
            "{WHAT}: owned pid {pid} must arm exactly one context; skips={:?} attach_calls={} minted={:?}",
            engine.counters.object_skips,
            session.dynamic_loader_attach_calls,
            minted_ids(&engine)
        );
    }
    assert_eq!(engine.loader_arms, 2, "{WHAT}: 2 real arm attempts");
    assert_eq!(
        minted_ids(&engine),
        [1, 2].into_iter().collect::<BTreeSet<_>>(),
        "{WHAT}: tickets 1..=2 minted exactly once"
    );
    assert_no_ambient_arms(&engine, &owned, WHAT);

    // Fill the envelope to exactly 256 through direct registry commits
    // (registry mechanics, like the loader's own tests): tickets stay
    // capture-lifetime monotonic and each mints once.
    let first_view = engine.views[live_position(&engine, owned_pids[0], WHAT)].id();
    for _ in 3..=MAX_LOADER_CONTEXTS as u16 {
        let prepared = engine
            .loader_registry
            .preflight(LoaderContextSpec {
                view: first_view,
                loader: PinnedObjectId(9),
                mapping: None,
                hook: p11scope_manifest::elf::SymbolFact {
                    virtual_address: 0x2100,
                    file_offset: 0x2100,
                },
                state_address: None,
            })
            .expect("envelope fill must preflight below capacity");
        engine
            .loader_registry
            .prepare(prepared)
            .expect("envelope fill must prepare");
    }
    assert_eq!(
        minted_ids(&engine),
        (1..=256).collect::<BTreeSet<_>>(),
        "{WHAT}: tickets 1..=256"
    );
    assert_no_ambient_arms(&engine, &owned, WHAT);

    // The provider-free head spends nothing: gated when visible, absent
    // otherwise, and the counters never move either way.
    let head_pid = group
        .children
        .iter()
        .find(|child| child.role == "head")
        .map(LiveChild::pid)
        .unwrap();
    match engine
        .views
        .iter()
        .position(|view| view.pid() == head_pid && view.still_the_same())
    {
        Some(position) => {
            let head_view = engine.views[position].id();
            assert!(
                engine.loader_arming_gated(head_view),
                "{WHAT}: the head view stays gated"
            );
            let head_armed = engine
                .arm_loader_or_partial(
                    position,
                    &mut session,
                    &mut additions_allowed,
                    &mut pending_views,
                )
                .expect("head arming probes nothing invariantly");
            assert!(!head_armed, "{WHAT}: the gated head must not arm");
        }
        None => {
            println!("t8: {WHAT}: the head has no provider view (provider-free processes stay out)")
        }
    }
    assert_eq!(
        engine.loader_arms, 2,
        "{WHAT}: the head adds no arm attempt"
    );
    assert_eq!(
        minted_ids(&engine).len(),
        256,
        "{WHAT}: the head mints no ticket"
    );

    // The envelope edge: a 257th prepare refuses before any validation,
    // so the positive sequence fits exactly and ticket 257 needs G16.
    let probe = engine.loader_registry.preflight(LoaderContextSpec {
        view: first_view,
        loader: PinnedObjectId(9),
        mapping: None,
        hook: p11scope_manifest::elf::SymbolFact {
            virtual_address: 0x2100,
            file_offset: 0x2100,
        },
        state_address: None,
    });
    assert_eq!(
        probe.unwrap_err(),
        "loader context capacity 256 is exhausted",
        "{WHAT}: the 257th ticket refuses"
    );

    group.release_and_wait_ledgers(WHAT);
    for child in &group.children {
        if child.role == "head" {
            continue;
        }
        let ledger = parse_provider_ledger(&child.log_text(), WHAT);
        assert_eq!(ledger.burst, 1);
        assert!(ledger.complete, "{WHAT}: {} ledger complete", child.pid());
    }
    drop(engine);
    group.terminate_all(WHAT);
    println!(
        "t8: ticket-spend: gate 2+0 exact, envelope 256 exact, 257th refused, wall={:?} VmHWM={}KiB",
        wall_start.elapsed(),
        vm_hwm_kb()
    );
}

// ---------------------------------------------------------------------------
// Privileged live cells (root + BPF + the exclusive privileged lane).
// ---------------------------------------------------------------------------

/// Root owns the live lane; anything else is a loud failure, never a skip.
fn assert_privileged_lane(what: &str) {
    // SAFETY: geteuid only reads this process's effective user identity.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "{what}: run as root under the privileged lane"
    );
    assert!(
        Path::new("/sys/kernel/btf/vmlinux").exists(),
        "{what}: the live lane needs host vmlinux BTF"
    );
}

fn record_pid(record: &DiscoveryRecord) -> u32 {
    (record.pid_tgid >> 32) as u32
}

/// EXEC pids in a collected batch that no owned child produced: any of
/// these in the burst batch refuses the cell (uncontrolled ambient).
fn ambient_exec_pids(records: &[DiscoveryRecord], owned: &BTreeSet<u32>) -> Vec<u32> {
    records
        .iter()
        .filter(|record| record.kind == DISCOVERY_KIND_EXEC && !owned.contains(&record_pid(record)))
        .map(record_pid)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn start_live_system_capture(hints: Vec<PathBuf>, what: &str) -> (Engine, crate::attach::Session) {
    let started = Instant::now();
    let mut engine =
        Engine::discover(&system_args(hints), &Scope::System, None).expect("live system discovery");
    let session = engine
        .start_session(
            CapturePolicy::Allowlisted,
            None,
            BackendSelection::default(),
        )
        .unwrap_or_else(|error| panic!("{what}: start_session failed: {error:#}"));
    println!("t8: {what}: capture live after {:?}", started.elapsed());
    assert_eq!(
        engine.loader_arms, 0,
        "{what}: capture startup arms nothing"
    );
    (engine, session)
}

struct SettleReport {
    ticks: u64,
    pending_high_water: usize,
    requested_high_water: usize,
    inter_drain_max: Duration,
    wall: Duration,
}

/// Drive the production cadence (shallow drains, periodic full frames,
/// one service quantum per tick) until every owned pid has settled and
/// no pressure episode remains. Ambient newcomers may come and go; they
/// must never block owned settlement.
fn settle_live_episode(
    engine: &mut Engine,
    session: &mut crate::attach::Session,
    owned: &BTreeSet<u32>,
    what: &str,
) -> SettleReport {
    let start = Instant::now();
    let deadline = start + SETTLE_DEADLINE;
    let mut last_tick = Instant::now();
    let mut report = SettleReport {
        ticks: 0,
        pending_high_water: 0,
        requested_high_water: 0,
        inter_drain_max: Duration::ZERO,
        wall: Duration::ZERO,
    };
    loop {
        let tick_start = Instant::now();
        report.inter_drain_max = report
            .inter_drain_max
            .max(tick_start.duration_since(last_tick));
        last_tick = tick_start;
        let force_full = report.ticks.is_multiple_of(20);
        engine
            .drain_discovery_shallow(session, force_full)
            .unwrap_or_else(|error| panic!("{what}: shallow drain failed: {error:#}"));
        engine
            .service_backlog_quantum(session)
            .unwrap_or_else(|error| panic!("{what}: service quantum failed: {error:#}"));
        report.ticks += 1;
        report.pending_high_water = report
            .pending_high_water
            .max(engine.pending_discovery_records.len());
        report.requested_high_water = report
            .requested_high_water
            .max(engine.refresh_requested.len());
        let owned_pending_request = engine
            .refresh_requested
            .keys()
            .any(|pid| owned.contains(pid));
        let owned_pending_record = engine
            .pending_discovery_records
            .iter()
            .any(|queued| owned.contains(&record_pid(&queued.record)));
        if !owned_pending_request
            && !owned_pending_record
            && engine.pressure_episode.is_none()
            && !engine.pressure_rotation_pending
        {
            report.wall = start.elapsed();
            println!(
                "t8: {what}: settled in {} ticks ({:?}), pending high-water {}, requested high-water {}",
                report.ticks, report.wall, report.pending_high_water, report.requested_high_water
            );
            return report;
        }
        if Instant::now() >= deadline {
            let episode_loss: Vec<_> = engine
                .counters
                .object_skips
                .iter()
                .filter(|skip| {
                    skip.subject == "live discovery refresh"
                        || skip.subject == "live loader arming"
                        || skip.subject == "pressure service"
                        || skip.subject == "live discovery tick"
                })
                .collect();
            let sample_requests: Vec<u32> = engine
                .refresh_requested
                .keys()
                .filter(|pid| owned.contains(pid))
                .copied()
                .take(5)
                .collect();
            let pending_owned_records = engine
                .pending_discovery_records
                .iter()
                .filter(|queued| owned.contains(&record_pid(&queued.record)))
                .count();
            // Minimal stuck-state census: owned views alive now, and how
            // many hold a loader context. Known limit (lane-A runtime):
            // the 256-view capacity is shared with ambient in System
            // scope, so reconcile evicts unadmitted owned views faster
            // than pressure admits them; viewless requests strand and the
            // rotation stalls. See the T8 report before rerunning.
            let owned_views = engine
                .views
                .iter()
                .filter(|view| owned.contains(&view.pid()))
                .count();
            let owned_armed = engine
                .views
                .iter()
                .filter(|view| owned.contains(&view.pid()))
                .filter(|view| !engine.loader_registry.ids_for_view(view.id()).is_empty())
                .count();
            panic!(
                "{what}: unsettled after {:?}: owned-requests={} pending-owned-records={} requested-hw={} views={} owned-views={} owned-armed={} rotation={} truncated={} dropped={} passes={} attempts={} arms={} minted={} scans={} sample={sample_requests:?} episode_loss={episode_loss:?}",
                start.elapsed(),
                engine
                    .refresh_requested
                    .keys()
                    .filter(|pid| owned.contains(pid))
                    .count(),
                pending_owned_records,
                report.requested_high_water,
                engine.views.len(),
                owned_views,
                owned_armed,
                engine.pressure_rotation_pending,
                engine.discovery_truncated,
                engine.newcomer_ages.dropped_unknown,
                engine.pressure_service_passes,
                engine.pressure_attempts,
                engine.loader_arms,
                minted_ids(engine).len(),
                engine.deep_scans,
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// FIRST live control: prove ticket spend fits and refuse on ambient
/// arming. A quiet window with no owned population must arm nothing;
/// then a small owned probe (3 provider children + the head) must spend
/// exactly 3 tickets on owned pids only, with zero loss. Any ambient
/// arming refuses the cell: G16 does not gate T8 only while the episode
/// is free of uncontrolled spend (the ticket-257 NO-NEED boundary).
#[test]
#[ignore = "privileged: live BPF system capture; run as root with --ignored --test-threads=1 under the privileged lane"]
fn pressure_live_ticket_spend_control_refuses_ambient() {
    const WHAT: &str = "t8-live-control";
    assert_privileged_lane(WHAT);
    let wall_start = Instant::now();
    let cpu_start = self_cpu_jiffies();
    let fds_start = fd_count();

    // Fixtures compile before capture: no forks inside the window.
    let fixtures = FixtureBuild::compile_all("live-control");
    let hints = vec![fixtures.early.clone(), fixtures.late.clone()];
    let (mut engine, mut session) = start_live_system_capture(hints, WHAT);

    // Quiet window: no owned population. Ambient EXECs may queue and
    // complete, but nothing may arm (no hinted provider is mapped).
    std::thread::sleep(Duration::from_secs(2));
    engine.drain_discovery(&mut session).expect("quiet drain");
    assert_eq!(
        engine.loader_arms, 0,
        "{WHAT}: REFUSED: ambient arming during the quiet window ({} arms); the host is not controlled",
        engine.loader_arms
    );
    assert!(
        minted_ids(&engine).is_empty(),
        "{WHAT}: REFUSED: ambient minted tickets in the quiet window"
    );

    // Owned probe: 3 provider children plus the head, behind one gate.
    let mut probe = Population::spawn_on(fixtures, 3, 3, false, true, None);
    let owned = probe.pids();
    let head_pid = probe.head_pid;
    assert_eq!(owned.len(), 4);
    probe.release_and_wait_ledgers();

    let settle = settle_live_episode(&mut engine, &mut session, &owned, WHAT);
    for child in &probe.children {
        if child.role == "head" {
            continue;
        }
        let ledgers = parse_provider_ledgers(&child.log_text(), WHAT);
        assert_eq!(
            ledgers.len(),
            1,
            "{WHAT}: single-burst probe emits one LEDGER"
        );
        assert_eq!(ledgers[0].burst, 1);
        assert!(ledgers[0].complete, "{WHAT}: probe ledger complete");
    }
    assert_eq!(
        engine.loader_arms, 3,
        "{WHAT}: exactly the 3 owned probe arms"
    );
    assert_eq!(
        minted_ids(&engine),
        [1, 2, 3].into_iter().collect::<BTreeSet<_>>(),
        "{WHAT}: tickets 1..=3"
    );
    assert_no_ambient_arms(&engine, &owned, WHAT);
    // The head completed with no ticket: it has no loader context.
    if let Some(head_view) = engine.views.iter().find(|view| view.pid() == head_pid) {
        assert!(
            engine
                .loader_registry
                .ids_for_view(head_view.id())
                .is_empty(),
            "{WHAT}: the probe head must hold no loader context"
        );
    }
    assert_no_episode_loss(&engine, WHAT);

    probe.terminate_all(WHAT, &|_| 0);
    drop(session);
    drop(engine);
    let fds_end = fd_count();
    println!(
        "t8: live-control: PASS: quiet 0 arms, probe 3 owned tickets, head 0, zero loss; ticks={} wall={:?} VmHWM={}KiB fds {fds_start}->{fds_end} cpu={} jiffies",
        settle.ticks,
        wall_start.elapsed(),
        vm_hwm_kb(),
        self_cpu_jiffies().saturating_sub(cpu_start)
    );
}

/// The genuine live256 positive episode (Tasks 1+2): 255 retained
/// provider children plus the eligible late owner plus one genuine
/// fresh EXEC head, all real native processes. Burst 1 warms every
/// provider table and ledgers the old calls; the burst is then collected
/// from the kernel ring (every key traces to an actual DISCOVERY record,
/// the head is last by hook clock, and any ambient EXEC in the burst
/// refuses the cell); the episode runs the nonempty late-provider rescan,
/// physical publication and loader rearm (ticket 256), admits the
/// original head, and settles with zero unexplained loss; burst 2
/// ledgers post-admission independent calls.
///
/// Known limit (lane-A runtime, 2026-10-19): does not converge yet. The
/// 256-view capacity is shared with ambient in System scope, so reconcile
/// evicts unadmitted owned views faster than pressure admits them; the
/// viewless requests strand and the rotation stalls. Repro preserved for
/// the runtime fix; see the T8 report.
#[test]
#[ignore = "privileged: live BPF 256-request pressure episode; run as root with --ignored --test-threads=1 under the privileged lane"]
fn pressure_live256_genuine_episode_admits_late_then_head() {
    const WHAT: &str = "t8-live256";
    assert_privileged_lane(WHAT);
    assert_eq!(
        MAX_PENDING_REFRESH, 256,
        "the request map holds exactly 256 keys"
    );
    let wall_start = Instant::now();
    let cpu_start = self_cpu_jiffies();
    let fds_start = fd_count();

    let fixtures = FixtureBuild::compile_all("live256");
    let late_path = fixtures.late.clone();
    let hints = vec![fixtures.early.clone(), fixtures.late.clone()];
    let (mut engine, mut session) = start_live_system_capture(hints, WHAT);

    // Capture first, then the population: 255 retained plus the late
    // owner, READY, then the head after a hook-clock separation.
    let wave_start = Instant::now();
    let mut population = Population::spawn_on(
        fixtures,
        RETAINED_CHILDREN,
        LIVE_REPEAT,
        true,
        false,
        Some(LIVE_REPEAT2),
    );
    assert_eq!(population.children.len(), RETAINED_CHILDREN + 1);
    std::thread::sleep(Duration::from_millis(500));
    let head_pid = population.spawn_head(WHAT);
    let owned = population.pids();
    assert_eq!(owned.len(), RETAINED_CHILDREN + 2);
    let wave_elapsed = wave_start.elapsed();
    // Nothing drained yet: the whole burst is genuinely pending.
    assert_eq!(
        engine.loader_arms, 0,
        "{WHAT}: no arming before the first drain"
    );
    assert!(
        engine.refresh_requested.is_empty(),
        "{WHAT}: no requests before the first drain"
    );
    assert!(
        engine.pending_discovery_records.is_empty(),
        "{WHAT}: no backlog before the first drain"
    );

    // Release 1 first: burst 1 warms every provider table (cold tables
    // publish nothing) and ledgers the old independent calls.
    let release1_start = Instant::now();
    population.release_and_wait_ledgers();
    let release1_elapsed = release1_start.elapsed();

    // Collect the burst without applying: the construction proof comes
    // from genuine kernel records, never from spawn order.
    let serial_before = engine.last_refresh_serial;
    let scans_before = engine.deep_scans;
    let (records, malformed, _) = engine
        .collect_frame_discovery(&mut session)
        .unwrap_or_else(|error| panic!("{WHAT}: burst collect failed: {error:#}"));
    assert_eq!(malformed, 0, "{WHAT}: the burst batch must be clean");
    let owned_execs: BTreeMap<u32, u64> = records
        .iter()
        .filter(|record| record.kind == DISCOVERY_KIND_EXEC && owned.contains(&record_pid(record)))
        .map(|record| (record_pid(record), record.hook_ts_ns))
        .collect();
    assert_eq!(
        owned_execs.len(),
        owned.len(),
        "{WHAT}: every owned pid produced a genuine EXEC (got {} of {})",
        owned_execs.len(),
        owned.len()
    );
    let ambient_execs = ambient_exec_pids(&records, &owned);
    assert!(
        ambient_execs.is_empty(),
        "{WHAT}: REFUSED: ambient EXECs in the burst batch ({ambient_execs:?}); rerun in a quiet window"
    );
    let head_ts = owned_execs[&head_pid];
    let max_ts = *owned_execs.values().max().unwrap();
    assert_eq!(
        head_ts, max_ts,
        "{WHAT}: REFUSED: the head EXEC is not last by hook clock (scheduling race); rerun"
    );
    println!(
        "t8: {WHAT}: burst collected: {} records, 257 owned EXECs, head last by hook clock",
        records.len()
    );

    // Apply the burst and settle the episode; then release gate 2 so
    // burst 2 ledgers post-admission independent calls.
    let apply_start = Instant::now();
    engine
        .apply_discovery_batch(&mut session, records, malformed)
        .unwrap_or_else(|error| panic!("{WHAT}: burst apply failed: {error:#}"));
    let settle = settle_live_episode(&mut engine, &mut session, &owned, WHAT);
    let apply_elapsed = apply_start.elapsed();
    population.release2_and_wait_ledgers(WHAT);
    let post_start = Instant::now();
    engine
        .drain_discovery(&mut session)
        .expect("post-admission drain");
    let _post_settle = settle_live_episode(&mut engine, &mut session, &owned, WHAT);
    let post_elapsed = post_start.elapsed();

    // Task 1: the construction. A service pass only runs when a head
    // parks at a full map, so passes >= 1 with 257 owned EXECs, zero
    // ambient EXECs and zero refusals proves exactly 256 genuine queued
    // keys behind the parked head.
    assert!(
        engine.pressure_service_passes >= 1,
        "{WHAT}: the episode must run at least one service pass"
    );
    assert!(
        engine.last_refresh_serial - serial_before >= owned.len() as u64,
        "{WHAT}: every owned EXEC queued (serial delta {})",
        engine.last_refresh_serial - serial_before
    );
    // Task 2: exact tickets on owned pids only, late rearm on 256, head 0.
    assert_eq!(engine.loader_arms, 256, "{WHAT}: exactly 256 arm attempts");
    assert_eq!(
        minted_ids(&engine),
        (1..=256).collect::<BTreeSet<_>>(),
        "{WHAT}: tickets 1..=256"
    );
    assert_no_ambient_arms(&engine, &owned, WHAT);
    let late_view = engine
        .views
        .iter()
        .find(|view| view.pid() == population.late_pid)
        .map(ProcessView::id)
        .unwrap();
    assert_eq!(
        engine
            .loader_registry
            .ids_for_view(late_view)
            .iter()
            .map(|id| id.get())
            .collect::<Vec<_>>(),
        vec![256],
        "{WHAT}: the late rearm holds ticket 256"
    );
    if let Some(head_view) = engine.views.iter().find(|view| view.pid() == head_pid) {
        assert!(
            engine
                .loader_registry
                .ids_for_view(head_view.id())
                .is_empty(),
            "{WHAT}: the admitted head holds no loader context"
        );
    }
    // Task 2: nonempty late rescan, physical publication, zero loss.
    assert!(
        engine.deep_scans > scans_before,
        "{WHAT}: the late rescan is nonempty"
    );
    assert_module_joined(&engine, population.late_pid, &late_path, WHAT);
    assert_module_joined(
        &engine,
        population.children[0].pid(),
        &population.fixtures.early,
        WHAT,
    );
    assert_slots_target(&engine, &["early.so", "late.so"], WHAT);
    assert_no_episode_loss(&engine, WHAT);
    assert!(
        engine.pressure_episode.is_none(),
        "{WHAT}: the episode settles clean"
    );
    assert!(
        !engine.pressure_rotation_pending,
        "{WHAT}: no rotation outlives the episode"
    );

    // Old/new independent calls: both bursts complete and honest per
    // child, every TARGET joined to its own process's live maps.
    for child in &population.children {
        let text = child.log_text();
        if child.role == "head" {
            assert_eq!(
                parse_targets(&text).len(),
                0,
                "{WHAT}: the head emits no TARGET"
            );
            continue;
        }
        let ledgers = parse_provider_ledgers(&text, WHAT);
        assert_eq!(
            ledgers.len(),
            2,
            "{WHAT}: {} emits both bursts",
            child.pid()
        );
        assert_eq!(
            (ledgers[0].burst, ledgers[1].burst),
            (1, 2),
            "{WHAT}: {} bursts number 1 then 2",
            child.pid()
        );
        for ledger in &ledgers {
            assert_eq!(ledger.pid, child.pid());
            assert!(
                ledger.complete,
                "{WHAT}: {} burst {} ledger complete",
                child.pid(),
                ledger.burst
            );
        }
        assert!(
            ledgers[0]
                .functions
                .iter()
                .all(|(_, attempts, successful)| (*attempts, *successful)
                    == (LIVE_REPEAT as u64, LIVE_REPEAT as u64)),
            "{WHAT}: {} old calls honest",
            child.pid()
        );
        assert!(
            ledgers[1]
                .functions
                .iter()
                .all(|(_, attempts, successful)| (*attempts, *successful)
                    == (LIVE_REPEAT2 as u64, LIVE_REPEAT2 as u64)),
            "{WHAT}: {} new post-admission calls honest",
            child.pid()
        );
        let want = if child.role == "late" {
            maps_triple(child.pid(), "late.so", WHAT)
        } else {
            maps_triple(child.pid(), "early.so", WHAT)
        };
        for target in parse_targets(&text) {
            assert_eq!(
                (target.major, target.minor, target.ino),
                want,
                "{WHAT}: TARGET joins the owner's provider"
            );
        }
    }

    population.terminate_all(WHAT, &|_| 0);
    drop(session);
    drop(engine);
    let fds_end = fd_count();
    println!(
        "t8: live256: PASS: 256 keys + head admitted, tickets 256 owned-only, zero loss; wave={wave_elapsed:?} release1={release1_elapsed:?} apply+settle={apply_elapsed:?} post={post_elapsed:?} ticks={} inter_drain_max={:?} pending_hw={} requested_hw={} wall={:?} VmHWM={}KiB fds {fds_start}->{fds_end} cpu={} jiffies",
        settle.ticks,
        settle.inter_drain_max,
        settle.pending_high_water,
        settle.requested_high_water,
        wall_start.elapsed(),
        vm_hwm_kb(),
        self_cpu_jiffies().saturating_sub(cpu_start)
    );
}

/// The all-blocked fail-control (deterministic, unprivileged): the
/// twin's exact map shape — 256 consumed requests through the same
/// `request_refresh_consumed` seam — minus the live contexts. With
/// blocking broken (no view holds a loader context anywhere), the held
/// head's episode must SELECT an eligible entry instead of ruling the
/// snapshot out: the lowest-pid entry is selected, nothing is ruled out
/// without an attempt, and no refusal is recorded. This proves the
/// twin's refusal pins per-entry blockedness: make every entry eligible
/// and the verdict flips from refuse-once to select. The mirror half
/// (all entries ineligible, no selection, refused once) stays pinned by
/// the deterministic unit twin and the live twin on genuine records.
/// No capture runs here: selection reads only the request map, the view
/// list and the loader registry, so an empty engine plus the seam-fed
/// map is the whole precondition. The head record is synthesized (this
/// is not the live path) and carries only the fields the episode and
/// protection readers consult.
#[test]
fn pressure_all_blocked_fail_control_selects_eligible() {
    const WHAT: &str = "t8-fail-control";
    let mut engine = Engine::empty();
    assert!(
        engine.views.is_empty(),
        "{WHAT}: the fail-control starts viewless"
    );
    assert!(
        minted_ids(&engine).is_empty(),
        "{WHAT}: the fail-control mints nothing"
    );
    for offset in 0..MAX_PENDING_REFRESH {
        let pid = 4_000_000 + offset as u32;
        assert!(
            engine.request_refresh_consumed(pid, Some(1_000 + offset as u64)),
            "{WHAT}: request {offset} consumes"
        );
    }
    assert_eq!(
        engine.refresh_requested.len(),
        MAX_PENDING_REFRESH,
        "{WHAT}: the map is full"
    );
    assert!(
        engine
            .refresh_requested
            .values()
            .all(|request| request.owner.is_none()),
        "{WHAT}: every entry is ownerless (blocking broken)"
    );
    let head_pid = 6_000_000u32;
    let head = QueuedDiscoveryRecord {
        record: DiscoveryRecord {
            hook_ts_ns: u64::MAX,
            pid_tgid: (u64::from(head_pid) << 32) | u64::from(head_pid),
            table_ptr: 0,
            interface_flags: 0,
            pointers: [0; DISCOVERY_POINTERS],
            kind: DISCOVERY_KIND_EXEC,
            case_id: 0,
            interface_index: 0,
            name_class: 0,
            status_flags: 0,
            usable_n: 0,
            pointers_attempted: 0,
            completed_prefix: 0,
            version_major: 0,
            version_minor: 0,
            selection_version_class: 0,
            reserved_zero: [0; 1],
            symbol_id: 0,
            announced_count: 0,
            reserved_tail_zero: [0; 4],
            send_signal_rc: 0,
            return_rv: 0,
            request_flags: 0,
            binding_id: 0,
        },
        terminal_owner: None,
        terminal_exports: Vec::new(),
    };
    engine.pressure_episode_begin(&head);
    let episode = engine
        .pressure_episode
        .as_ref()
        .expect("{WHAT}: the held head opens an episode");
    assert_eq!(
        episode.snapshot.len(),
        MAX_PENDING_REFRESH,
        "{WHAT}: the episode snapshots the full map"
    );
    let protection = engine.pressure_protection_for(std::slice::from_ref(&head), &[]);
    assert!(
        !protection.block_all,
        "{WHAT}: a plain EXEC head narrows its protection"
    );
    let selection = engine
        .pressure_select_next(&protection)
        .expect("{WHAT}: an eligible entry is selected (blocking broken)");
    assert_eq!(
        selection.pid, 4_000_000,
        "{WHAT}: selection takes the lowest eligible pid"
    );
    assert!(
        engine
            .pressure_episode
            .as_ref()
            .is_some_and(|episode| episode.ruled_out.is_empty()),
        "{WHAT}: nothing is ruled out without an attempt"
    );
    assert_eq!(
        engine.discovery_truncated, 0,
        "{WHAT}: no refusal without all-blocked"
    );
    assert_eq!(
        engine.newcomer_ages.dropped_unknown, 0,
        "{WHAT}: no dropped newcomer without all-blocked"
    );
}

/// The separately declared all-blocked/N+1 twin: a TRUE live
/// all-blocked episode in two phases, mirroring the deterministic unit
/// twin `pressure_all_blocked_fifo_refuses_once_then_advances` on genuine
/// records. Phase 1 arms 256 retained obligations via burst 1 plus a full
/// settle (exactly 256 arms, tickets 1..=256, zero loss; the map fills
/// to exactly 256 owned keys with no 257th owned arrival). Phase 2 refills
/// the request map through the same `request_refresh_consumed` seam the
/// unit twin uses — the obligations are genuinely live (real pids, real
/// views, real loader contexts from a real settled capture) — then parks
/// a genuine fresh-EXEC head against the full blocked map. Every queued
/// request is ineligible (its owner holds a live loader context), so the
/// head is refused exactly once with sticky explicit loss, zero safe
/// scans and zero selection attempts. No capacity reset at the refusal:
/// all 256 contexts survive identical, views stay live, no retirements
/// queued. The suffix then advances through ordinary service (FIFO
/// progress): a bounded run of forced full ticks retires the serviced
/// prefix, so minted contexts drain monotonically and scan work grows.
/// Neither map convergence nor rearm is pinned there: at live-256 the
/// post-retirement rescan systematically defers behind the tick quantum
/// (the initial scan phase consumes it scan-until-expiry over the 256
/// refreshed views, and retirement detaches add wall-time, so every
/// refilled request is retained while its contexts retire), and rearm is
/// additionally impossible because phase 1 spent the 256
/// capture-lifetime loader IDs. Only progress and the sticky loss are
/// pinned, so any strict lossless verdict over this batch must fail.
/// Own episode, own capture, fresh ticket budget.
///
/// The pre-twin shape (257 genuine EXECs in one batch, head last) is NOT
/// all-blocked: it converges to admitted-head under any working fix, so
/// its refusal asserts encoded the lane-A stall. That shape is preserved
/// as the `pressure_live256_unparked_head_control_admits` control, which
/// proves the refusal pins the all-blocked precondition: without the full
/// blocked map the same head is admitted with zero loss.
#[test]
#[ignore = "privileged: live BPF all-blocked negative twin; run as root with --ignored --test-threads=1 under the privileged lane"]
fn pressure_live256_all_blocked_twin_refuses_once() {
    const WHAT: &str = "t8-twin";
    assert_privileged_lane(WHAT);
    let wall_start = Instant::now();
    let cpu_start = self_cpu_jiffies();
    let fds_start = fd_count();

    let fixtures = FixtureBuild::compile_all("twin");
    let hints = vec![fixtures.early.clone()];
    let (mut engine, mut session) = start_live_system_capture(hints, WHAT);

    // Phase 1: 256 retained provider children, no head yet. Release 1
    // warms every provider table (cold tables publish nothing) and ledgers
    // the old independent calls.
    let mut population =
        Population::spawn_on(fixtures, 256, LIVE_REPEAT, false, false, Some(LIVE_REPEAT2));
    assert_eq!(population.children.len(), 256);
    assert_eq!(
        engine.loader_arms, 0,
        "{WHAT}: no arming before the first drain"
    );
    population.release_and_wait_ledgers();
    let owned: BTreeSet<u32> = population.pids();
    assert_eq!(owned.len(), 256);

    // Burst 1 must be pure-owned: any ambient EXEC would park against the
    // filling map and spend work the armed checkpoint forbids.
    let serial_before = engine.last_refresh_serial;
    let (records, malformed, _) = engine
        .collect_frame_discovery(&mut session)
        .unwrap_or_else(|error| panic!("{WHAT}: burst 1 collect failed: {error:#}"));
    assert_eq!(malformed, 0, "{WHAT}: the burst 1 batch must be clean");
    let owned_execs: BTreeMap<u32, u64> = records
        .iter()
        .filter(|record| record.kind == DISCOVERY_KIND_EXEC && owned.contains(&record_pid(record)))
        .map(|record| (record_pid(record), record.hook_ts_ns))
        .collect();
    assert_eq!(
        owned_execs.len(),
        owned.len(),
        "{WHAT}: every owned pid produced a genuine EXEC"
    );
    let ambient_execs = ambient_exec_pids(&records, &owned);
    assert!(
        ambient_execs.is_empty(),
        "{WHAT}: REFUSED: ambient EXECs in the burst 1 batch ({ambient_execs:?}); rerun in a quiet window"
    );
    println!(
        "t8: {WHAT}: burst 1 collected: {} records, 256 owned EXECs",
        records.len()
    );

    engine
        .apply_discovery_batch(&mut session, records, malformed)
        .unwrap_or_else(|error| panic!("{WHAT}: burst 1 apply failed: {error:#}"));
    let settle1 = settle_live_episode(&mut engine, &mut session, &owned, WHAT);

    // The armed checkpoint: 256 live obligations, exactly 256 arms, zero
    // loss. Passes and attempts are observations only here: a provider-free
    // ambient EXEC during the full-map window parks and is serviced
    // without arming (the positive tolerates the same), so only the
    // refusal's own deltas pin zero transactions/attempts.
    assert_eq!(engine.loader_arms, 256, "{WHAT}: exactly 256 arm attempts");
    assert_eq!(
        minted_ids(&engine),
        (1..=256).collect::<BTreeSet<_>>(),
        "{WHAT}: tickets 1..=256"
    );
    assert_no_ambient_arms(&engine, &owned, WHAT);
    assert_no_episode_loss(&engine, WHAT);
    println!(
        "t8: {WHAT}: armed checkpoint: passes={} attempts={} arms={} scans={}",
        engine.pressure_service_passes,
        engine.pressure_attempts,
        engine.loader_arms,
        engine.deep_scans
    );
    assert!(
        engine.exec_rearm_views.is_empty(),
        "{WHAT}: no rearm markers before the refusal"
    );
    assert!(
        engine.retirement_intents.is_empty(),
        "{WHAT}: arming queues no retirements"
    );
    let armed_views = engine
        .views
        .iter()
        .filter(|view| owned.contains(&view.pid()))
        .count();
    assert_eq!(armed_views, 256, "{WHAT}: 256 live armed views");
    for view in &engine.views {
        if owned.contains(&view.pid()) {
            assert!(
                view.still_the_same(),
                "{WHAT}: armed pid {} stays live",
                view.pid()
            );
        }
    }
    let contexts_before: BTreeMap<u32, Vec<u16>> = engine
        .views
        .iter()
        .filter(|view| owned.contains(&view.pid()))
        .map(|view| {
            (
                view.pid(),
                engine
                    .loader_registry
                    .ids_for_view(view.id())
                    .iter()
                    .map(|id| id.get())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(contexts_before.len(), 256, "{WHAT}: 256 armed obligations");
    assert!(
        contexts_before.values().all(|ids| ids.len() == 1),
        "{WHAT}: one live obligation per armed pid"
    );
    twin_census(&engine, &owned, "armed", WHAT);

    // One extra drain+service tick for lagging ambient: the refill needs
    // an empty map, and an ambient request dispatched in the settle's last
    // drain may still need one service. A lingering ambient request would
    // either refuse an owned refill (corrupting the exactly-once refusal)
    // or sit in the snapshot as an unblocked candidate (breaking
    // all-blocked for real), so anything more than one tick of lag —
    // residue or fresh loss — refuses the cell. No extended drain loop: on
    // a noisy host extra drains only extend storm exposure.
    engine
        .drain_discovery_shallow(&mut session, false)
        .unwrap_or_else(|error| panic!("{WHAT}: lag drain failed: {error:#}"));
    engine
        .service_backlog_quantum(&mut session)
        .unwrap_or_else(|error| panic!("{WHAT}: lag service failed: {error:#}"));
    assert_eq!(
        engine.discovery_truncated, 0,
        "{WHAT}: REFUSED: fresh loss in the seam window (truncated={}); rerun in a quiet window",
        engine.discovery_truncated
    );
    assert!(
        engine.refresh_requested.is_empty(),
        "{WHAT}: REFUSED: ambient residue in the map ({} keys: {:?}); rerun in a quiet window",
        engine.refresh_requested.len(),
        engine.refresh_requested.keys().take(8).collect::<Vec<_>>()
    );
    twin_census(&engine, &owned, "lagged", WHAT);

    // Phase 2: refill the request map through the same consumed-request
    // seam the unit twin uses. The obligations are genuinely live: real
    // pids, real views, real loader contexts from the settled capture.
    for pid in &owned {
        assert!(
            engine.request_refresh_consumed(*pid, crate::attach::monotonic_ns()),
            "{WHAT}: request for armed pid {pid} consumes"
        );
    }
    assert_eq!(
        engine.refresh_requested.len(),
        256,
        "{WHAT}: the map is full of live obligations"
    );

    // The fresh head parks against the full blocked map. Its batch must
    // hold no other request-creating arrival: at a full blocked map any
    // unknown-pid consumed record would corrupt the exactly-once refusal.
    let head_pid = population.spawn_head(WHAT);
    let owned2 = population.pids();
    assert_eq!(owned2.len(), 257);
    let (head_records, head_malformed, _) = engine
        .collect_frame_discovery(&mut session)
        .unwrap_or_else(|error| panic!("{WHAT}: head collect failed: {error:#}"));
    assert_eq!(head_malformed, 0, "{WHAT}: the head batch must be clean");
    let head_execs: Vec<u64> = head_records
        .iter()
        .filter(|record| record.kind == DISCOVERY_KIND_EXEC && record_pid(record) == head_pid)
        .map(|record| record.hook_ts_ns)
        .collect();
    assert_eq!(
        head_execs.len(),
        1,
        "{WHAT}: the head produced exactly one genuine EXEC"
    );
    let head_ambient = ambient_exec_pids(&head_records, &owned2);
    assert!(
        head_ambient.is_empty(),
        "{WHAT}: REFUSED: ambient EXECs in the head batch ({head_ambient:?}); rerun in a quiet window"
    );
    let foreign: BTreeSet<u32> = head_records
        .iter()
        .map(record_pid)
        .filter(|pid| !owned2.contains(pid))
        .collect();
    assert!(
        foreign.is_empty(),
        "{WHAT}: REFUSED: foreign records in the head batch ({foreign:?}); rerun in a quiet window"
    );
    println!(
        "t8: {WHAT}: head batch collected: {} records, head EXEC present",
        head_records.len()
    );

    // Dispatch the head batch DIRECTLY through the production dispatch,
    // exactly as the unit twin does: the apply wrapper's trailing
    // inventory tick would begin FIFO service (retire churn) before the
    // refusal is observed. No nested ring pull can run here: with
    // every candidate blocked, no service pass runs to invoke the
    // collector, so the batch in hand is the whole input.
    let passes_before_dispatch = engine.pressure_service_passes;
    let attempts_before_dispatch = engine.pressure_attempts;
    let scans_before_dispatch = engine.deep_scans;
    let mut queued: Vec<QueuedDiscoveryRecord> = head_records
        .into_iter()
        .map(|record| QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        })
        .collect();
    let mut collect = Engine::collect_discovery_records;
    engine
        .process_discovery_records(
            &mut session,
            &mut queued,
            &mut PendingViewRetirements::new(),
            &mut true,
            &mut collect,
            &mut PauseClosure::new(true),
        )
        .unwrap_or_else(|error| panic!("{WHAT}: head dispatch failed: {error:#}"));
    assert!(queued.is_empty(), "{WHAT}: the head batch fully dispatches");
    twin_census(&engine, &owned2, "dispatched", WHAT);

    // The twin predicates, mirroring the unit twin on genuine records.
    assert_eq!(
        engine.discovery_truncated, 1,
        "{WHAT}: the all-blocked head is refused exactly once"
    );
    assert!(
        !engine.refresh_requested.contains_key(&head_pid),
        "{WHAT}: a refused head leaves no request behind"
    );
    assert_eq!(
        engine.newcomer_ages.dropped_unknown, 1,
        "{WHAT}: the refused head keeps explicit dropped-age evidence"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.subject == "live discovery refresh"
                && skip.reason.contains("exceeded the bounded pending queue")),
        "{WHAT}: the refusal publishes explicit loss: {:?}",
        engine.counters.object_skips
    );
    assert_eq!(
        engine.deep_scans, scans_before_dispatch,
        "{WHAT}: the all-blocked refusal runs zero safe scans"
    );
    assert_eq!(
        engine.pressure_attempts, attempts_before_dispatch,
        "{WHAT}: no selection was ever attempted"
    );
    assert_eq!(
        engine.pressure_service_passes, passes_before_dispatch,
        "{WHAT}: the refusal runs no service transaction"
    );
    // No capacity reset: every obligation survives identical.
    assert_eq!(
        minted_ids(&engine),
        (1..=256).collect::<BTreeSet<_>>(),
        "{WHAT}: all 256 contexts survive"
    );
    let contexts_after: BTreeMap<u32, Vec<u16>> = engine
        .views
        .iter()
        .filter(|view| owned.contains(&view.pid()))
        .map(|view| {
            (
                view.pid(),
                engine
                    .loader_registry
                    .ids_for_view(view.id())
                    .iter()
                    .map(|id| id.get())
                    .collect(),
            )
        })
        .collect();
    assert_eq!(
        contexts_after, contexts_before,
        "{WHAT}: all 256 live contexts survive the refusal identical"
    );
    assert_no_ambient_arms(&engine, &owned2, WHAT);
    for view in &engine.views {
        if owned.contains(&view.pid()) {
            assert!(
                view.still_the_same(),
                "{WHAT}: retained pid {} stays live",
                view.pid()
            );
        }
    }
    assert!(
        engine.retirement_intents.is_empty(),
        "{WHAT}: the blocked pass queues no retirements"
    );

    // FIFO progress through ordinary service, driven deterministically:
    // a bounded run of forced full ticks. The force flag only runs the
    // production drain+tick when the ring is idle; the tick itself is
    // ordinary service (enumerate, scan, retire, rescan, rearm), the same
    // tick ambient bursts would trigger, minus storm-timing flakiness.
    //
    // Only progress and sticky loss are pinned here. The map is
    // deliberately NOT pinned empty: at live-256 the post-retirement
    // rescan systematically defers (the initial scan phase consumes the
    // tick quantum scan-until-expiry over the 256 refreshed views, and
    // retirement detaches add wall-time, so refilled requests are
    // retained while their contexts retire), and rearm is additionally
    // impossible because phase 1 spent the 256 capture-lifetime loader
    // IDs. The deterministic unit twin drains because its harness never
    // expires the quantum; requiring convergence here pinned an
    // unachievable state (0 of 256 refilled requests completed in 137s
    // of ambient settling while 170 contexts retired). Progress is the
    // serviced prefix advancing: each running tick scans and retires its
    // next quantum-bound prefix, so minted contexts drain monotonically
    // and scan work grows.
    let minted_before_suffix = minted_ids(&engine).len();
    assert_eq!(
        minted_before_suffix, 256,
        "{WHAT}: the suffix starts with all 256 obligations live"
    );
    let scans_before_suffix = engine.deep_scans;
    let mut minted_floor = minted_before_suffix;
    for tick in 0..8u32 {
        engine
            .drain_discovery_shallow(&mut session, true)
            .unwrap_or_else(|error| panic!("{WHAT}: suffix drain {tick} failed: {error:#}"));
        engine
            .service_backlog_quantum(&mut session)
            .unwrap_or_else(|error| panic!("{WHAT}: suffix service {tick} failed: {error:#}"));
        let minted_now = minted_ids(&engine).len();
        assert!(
            minted_now <= minted_floor,
            "{WHAT}: service never un-retires (tick {tick}: {minted_now} > {minted_floor})"
        );
        minted_floor = minted_now;
        println!(
            "t8: {WHAT}: suffix tick {tick}: map={} minted={minted_now} scans={} truncated={} dropped={}",
            engine.refresh_requested.len(),
            engine.deep_scans,
            engine.discovery_truncated,
            engine.newcomer_ages.dropped_unknown
        );
    }
    assert!(
        minted_floor < minted_before_suffix,
        "{WHAT}: the suffix retired obligations through ordinary service (FIFO progress)"
    );
    assert!(
        engine.deep_scans > scans_before_suffix,
        "{WHAT}: the suffix performed scan work"
    );
    // The loss is sticky: later service never erases it, so any strict
    // lossless verdict over this batch must fail. The counts are lower
    // bounds, not exact: ambient newcomers arriving during the suffix at
    // the full blocked map are genuinely refused too, so a stormy host
    // adds refusals past the head's one. The exact-once pin stands above,
    // taken before the suffix ran.
    assert!(
        engine.discovery_truncated >= 1,
        "{WHAT}: the historical loss survives service"
    );
    assert!(
        engine.newcomer_ages.dropped_unknown >= 1,
        "{WHAT}: the refused head keeps explicit dropped-age evidence"
    );
    assert!(
        engine
            .counters
            .object_skips
            .iter()
            .any(|skip| skip.subject == "live discovery refresh"
                && skip.reason.contains("exceeded the bounded pending queue")),
        "{WHAT}: the refusal's explicit loss entry persists: {:?}",
        engine.counters.object_skips
    );
    assert_no_ambient_arms(&engine, &owned2, WHAT);
    for view in &engine.views {
        if owned2.contains(&view.pid()) {
            assert!(
                view.still_the_same(),
                "{WHAT}: serviced pid {} stays live",
                view.pid()
            );
        }
    }

    // Burst 2 ledgers post-admission independent calls; both bursts stay
    // complete and honest per child. No convergence settle follows: the
    // refilled map is not pinned empty (see the suffix above), so the
    // post drain only pulls ring leftovers before the ledger join.
    population.release2_and_wait_ledgers(WHAT);
    engine
        .drain_discovery(&mut session)
        .expect("post-admission drain");
    for child in &population.children {
        if child.role == "head" {
            continue;
        }
        let ledgers = parse_provider_ledgers(&child.log_text(), WHAT);
        assert_eq!(
            ledgers.len(),
            2,
            "{WHAT}: {} emits both bursts",
            child.pid()
        );
        assert!(
            ledgers.iter().all(|ledger| ledger.complete),
            "{WHAT}: {} ledgers complete",
            child.pid()
        );
    }
    let serial_delta = engine.last_refresh_serial.saturating_sub(serial_before);
    let passes_end = engine.pressure_service_passes;
    let attempts_end = engine.pressure_attempts;
    let arms_end = engine.loader_arms;
    population.terminate_all(WHAT, &|_| 0);
    drop(session);
    drop(engine);
    let fds_end = fd_count();
    println!(
        "t8: twin: PASS: 1 refusal, sticky loss, FIFO progress (minted 256->{minted_floor}), 256 contexts survive refusal; serial_delta={serial_delta} arm_ticks={} suffix_ticks=8 passes={passes_end} attempts={attempts_end} arms={arms_end} inter_drain_max={:?} wall={:?} VmHWM={}KiB fds {fds_start}->{fds_end} cpu={} jiffies",
        settle1.ticks,
        settle1.inter_drain_max,
        wall_start.elapsed(),
        vm_hwm_kb(),
        self_cpu_jiffies().saturating_sub(cpu_start)
    );
}

/// The unparked-head control for the all-blocked twin: the identical
/// phase-1 arming (256 obligations, 256 arms, zero loss, never parked),
/// but the fresh head arrives against an EMPTY map (no refilled
/// requests), so it never parks, is never refused, and is admitted with
/// zero loss while consuming no loader ticket (provider-free views stay
/// unarmed). This control proves the twin's refusal pins the all-blocked
/// precondition: break the full blocked map and the same head is
/// admitted, not refused. Release 2, the post drain and the LEDGER checks
/// match the twin (the control's small map additionally settles, which
/// the twin's full map structurally cannot), so the request-map refill
/// is the only variable.
#[test]
#[ignore = "privileged: live BPF unparked-head control; run as root with --ignored --test-threads=1 under the privileged lane"]
fn pressure_live256_unparked_head_control_admits() {
    const WHAT: &str = "t8-unparked";
    assert_privileged_lane(WHAT);
    let wall_start = Instant::now();
    let cpu_start = self_cpu_jiffies();
    let fds_start = fd_count();

    let fixtures = FixtureBuild::compile_all("unparked");
    let hints = vec![fixtures.early.clone()];
    let (mut engine, mut session) = start_live_system_capture(hints, WHAT);

    // Phase 1, identical to the twin: 256 retained provider children, no
    // head yet; release 1 warms every provider table and ledgers burst 1.
    let mut population =
        Population::spawn_on(fixtures, 256, LIVE_REPEAT, false, false, Some(LIVE_REPEAT2));
    assert_eq!(population.children.len(), 256);
    assert_eq!(
        engine.loader_arms, 0,
        "{WHAT}: no arming before the first drain"
    );
    population.release_and_wait_ledgers();
    let owned: BTreeSet<u32> = population.pids();
    assert_eq!(owned.len(), 256);

    let serial_before = engine.last_refresh_serial;
    let (records, malformed, _) = engine
        .collect_frame_discovery(&mut session)
        .unwrap_or_else(|error| panic!("{WHAT}: burst 1 collect failed: {error:#}"));
    assert_eq!(malformed, 0, "{WHAT}: the burst 1 batch must be clean");
    let owned_execs: BTreeMap<u32, u64> = records
        .iter()
        .filter(|record| record.kind == DISCOVERY_KIND_EXEC && owned.contains(&record_pid(record)))
        .map(|record| (record_pid(record), record.hook_ts_ns))
        .collect();
    assert_eq!(
        owned_execs.len(),
        owned.len(),
        "{WHAT}: every owned pid produced a genuine EXEC"
    );
    let ambient_execs = ambient_exec_pids(&records, &owned);
    assert!(
        ambient_execs.is_empty(),
        "{WHAT}: REFUSED: ambient EXECs in the burst 1 batch ({ambient_execs:?}); rerun in a quiet window"
    );
    println!(
        "t8: {WHAT}: burst 1 collected: {} records, 256 owned EXECs",
        records.len()
    );

    engine
        .apply_discovery_batch(&mut session, records, malformed)
        .unwrap_or_else(|error| panic!("{WHAT}: burst 1 apply failed: {error:#}"));
    let settle1 = settle_live_episode(&mut engine, &mut session, &owned, WHAT);

    // The same armed checkpoint as the twin. Passes and attempts are
    // observations only: provider-free ambient parks without arming.
    assert_eq!(engine.loader_arms, 256, "{WHAT}: exactly 256 arm attempts");
    assert_eq!(
        minted_ids(&engine),
        (1..=256).collect::<BTreeSet<_>>(),
        "{WHAT}: tickets 1..=256"
    );
    assert_no_ambient_arms(&engine, &owned, WHAT);
    assert_no_episode_loss(&engine, WHAT);
    println!(
        "t8: {WHAT}: armed checkpoint: passes={} attempts={} arms={} scans={}",
        engine.pressure_service_passes,
        engine.pressure_attempts,
        engine.loader_arms,
        engine.deep_scans
    );

    // The broken precondition: no request-map refill, so the map stays
    // empty and the head cannot park. One lag tick first, exactly as the
    // twin does, so the refill step stays the only variable.
    engine
        .drain_discovery_shallow(&mut session, false)
        .unwrap_or_else(|error| panic!("{WHAT}: lag drain failed: {error:#}"));
    engine
        .service_backlog_quantum(&mut session)
        .unwrap_or_else(|error| panic!("{WHAT}: lag service failed: {error:#}"));
    assert_eq!(
        engine.discovery_truncated, 0,
        "{WHAT}: REFUSED: fresh loss in the seam window (truncated={}); rerun in a quiet window",
        engine.discovery_truncated
    );
    assert!(
        engine.refresh_requested.is_empty(),
        "{WHAT}: REFUSED: ambient residue in the map ({} keys: {:?}); rerun in a quiet window",
        engine.refresh_requested.len(),
        engine.refresh_requested.keys().take(8).collect::<Vec<_>>()
    );

    // The same fresh head against the empty map, under the same batch
    // purity gates as the twin.
    let head_pid = population.spawn_head(WHAT);
    let owned2 = population.pids();
    assert_eq!(owned2.len(), 257);
    let (head_records, head_malformed, _) = engine
        .collect_frame_discovery(&mut session)
        .unwrap_or_else(|error| panic!("{WHAT}: head collect failed: {error:#}"));
    assert_eq!(head_malformed, 0, "{WHAT}: the head batch must be clean");
    let head_execs: Vec<u64> = head_records
        .iter()
        .filter(|record| record.kind == DISCOVERY_KIND_EXEC && record_pid(record) == head_pid)
        .map(|record| record.hook_ts_ns)
        .collect();
    assert_eq!(
        head_execs.len(),
        1,
        "{WHAT}: the head produced exactly one genuine EXEC"
    );
    let head_ambient = ambient_exec_pids(&head_records, &owned2);
    assert!(
        head_ambient.is_empty(),
        "{WHAT}: REFUSED: ambient EXECs in the head batch ({head_ambient:?}); rerun in a quiet window"
    );
    let foreign: BTreeSet<u32> = head_records
        .iter()
        .map(record_pid)
        .filter(|pid| !owned2.contains(pid))
        .collect();
    assert!(
        foreign.is_empty(),
        "{WHAT}: REFUSED: foreign records in the head batch ({foreign:?}); rerun in a quiet window"
    );
    println!(
        "t8: {WHAT}: head batch collected: {} records, head EXEC present",
        head_records.len()
    );

    // Dispatch directly, exactly as the twin does, so the request-map
    // refill stays the only variable: an empty map consumes the head.
    let mut queued: Vec<QueuedDiscoveryRecord> = head_records
        .into_iter()
        .map(|record| QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        })
        .collect();
    let mut collect = Engine::collect_discovery_records;
    engine
        .process_discovery_records(
            &mut session,
            &mut queued,
            &mut PendingViewRetirements::new(),
            &mut true,
            &mut collect,
            &mut PauseClosure::new(true),
        )
        .unwrap_or_else(|error| panic!("{WHAT}: head dispatch failed: {error:#}"));
    assert!(queued.is_empty(), "{WHAT}: the head batch fully dispatches");

    // The control predicates: the unparked head consumes a request and is
    // never refused.
    assert_eq!(
        engine.discovery_truncated, 0,
        "{WHAT}: the unparked head is not refused"
    );
    assert!(
        engine.refresh_requested.contains_key(&head_pid),
        "{WHAT}: the unparked head consumes a request"
    );
    assert_eq!(
        engine.newcomer_ages.dropped_unknown, 0,
        "{WHAT}: the unparked head drops nothing"
    );

    let settle2 = settle_live_episode(&mut engine, &mut session, &owned2, WHAT);
    assert!(
        !engine
            .refresh_requested
            .keys()
            .any(|pid| owned2.contains(pid)),
        "{WHAT}: the head request completes"
    );
    assert_no_episode_loss(&engine, WHAT);
    assert_eq!(
        engine.loader_arms, 256,
        "{WHAT}: the admitted head consumes no loader ticket"
    );
    assert_eq!(
        minted_ids(&engine),
        (1..=256).collect::<BTreeSet<_>>(),
        "{WHAT}: tickets still 1..=256"
    );
    // The admitted head holds no loader context on either genuine
    // completion path: viewless (P3 probationary completion at full
    // capacity, the expected path with 256 owned views resident) or an
    // exploratory view. Either way no ticket was spent (arms still 256).
    match engine.views.iter().find(|view| view.pid() == head_pid) {
        None => println!("t8: {WHAT}: head completed viewlessly (P3 probationary, no ticket)"),
        Some(view) => assert!(
            engine.loader_registry.ids_for_view(view.id()).is_empty(),
            "{WHAT}: the admitted head holds no loader context"
        ),
    }

    population.release2_and_wait_ledgers(WHAT);
    engine
        .drain_discovery(&mut session)
        .expect("post-admission drain");
    let _post_settle = settle_live_episode(&mut engine, &mut session, &owned2, WHAT);
    for child in &population.children {
        if child.role == "head" {
            continue;
        }
        let ledgers = parse_provider_ledgers(&child.log_text(), WHAT);
        assert_eq!(
            ledgers.len(),
            2,
            "{WHAT}: {} emits both bursts",
            child.pid()
        );
        assert!(
            ledgers.iter().all(|ledger| ledger.complete),
            "{WHAT}: {} ledgers complete",
            child.pid()
        );
    }
    let serial_delta = engine.last_refresh_serial.saturating_sub(serial_before);
    let passes_end = engine.pressure_service_passes;
    let attempts_end = engine.pressure_attempts;
    population.terminate_all(WHAT, &|_| 0);
    drop(session);
    drop(engine);
    let fds_end = fd_count();
    println!(
        "t8: unparked: PASS: head admitted with zero loss, 256 tickets intact; serial_delta={serial_delta} arm_ticks={} admit_ticks={} passes={passes_end} attempts={attempts_end} wall={:?} VmHWM={}KiB fds {fds_start}->{fds_end} cpu={} jiffies",
        settle1.ticks,
        settle2.ticks,
        wall_start.elapsed(),
        vm_hwm_kb(),
        self_cpu_jiffies().saturating_sub(cpu_start)
    );
}
