//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Launcher-chain tests: who launched the caller.
//!
//! A named parent (`chain-parent`) launches a short-lived SoftHSM client
//! (`chain-client`, alive for one capture). The scan lane must report the
//! chain in JSON (`callers[].launched_by`, nearest first, with per-caller
//! gaps), in `-v` text (`chain-client <- chain-parent ...`), and in the
//! concise default (`chain-client (from chain-parent)`). Counts and caller
//! identity never change. The test reads the expected (ppid, start_time)
//! pair itself from `/proc`, so a wrong chain fails loudly.

#[allow(dead_code)]
mod support;

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use support::DieWithParent as _;

fn serial_guard() -> MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

fn tmp(name: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn gcc(dir: &Path, out: &str, source: &Path, args: &[&str], libs: &[&str]) -> PathBuf {
    let bin = dir.join(out);
    let mut cmd = Command::new("gcc");
    cmd.args(args).arg("-o").arg(&bin).arg(source).args(libs);
    assert!(
        cmd.status().unwrap().success(),
        "gcc failed for {out}: {cmd:?}"
    );
    bin
}

fn fixture_source(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

/// Probe SoftHSM (Debian then Fedora paths); panic loudly when absent —
/// these cells need the real provider, never a skip.
fn softhsm_path() -> PathBuf {
    for candidate in [
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
    ] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return path;
        }
    }
    panic!("SoftHSM not installed (probed Debian and Fedora paths)");
}

/// Independent `/proc` oracle: (ppid, start_time) from one stat line.
fn stat_pair(pid: u32) -> (u32, u64) {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let end = text.rfind(')').expect("stat comm");
    let mut fields = text[end + 1..].split_whitespace();
    let _state = fields.next().expect("stat state");
    let ppid: u32 = fields.next().expect("stat ppid").parse().expect("ppid");
    let start: u64 = fields
        .nth(17)
        .expect("stat starttime")
        .parse()
        .expect("start");
    (ppid, start)
}

/// A named parent with its short-lived client, both reaped on drop.
struct Chain {
    parent: Option<Child>,
    parent_pid: u32,
    client_pid: u32,
    gate: PathBuf,
}

impl Chain {
    fn spawn(dir: &Path, name: &str) -> Self {
        Self::spawn_with_parent(dir, name, "chain-parent", "public-cli/chain-parent.c")
    }

    fn spawn_with_parent(dir: &Path, name: &str, parent_exe: &str, parent_src: &str) -> Self {
        let parent_bin = gcc(
            dir,
            parent_exe,
            &fixture_source(parent_src),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &[],
        );
        let client_bin = gcc(
            dir,
            "chain-client",
            &fixture_source("parent-chain/chain-client.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let ready = dir.join(format!("{name}.ready"));
        let _ = std::fs::remove_file(&ready);
        let gate = dir.join(format!("{name}.gate"));
        let _ = std::fs::remove_file(&gate);
        let mut parent = Command::new(&parent_bin)
            .arg(&client_bin)
            .arg(softhsm_path())
            .arg(&ready)
            .arg(&gate)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .die_with_parent()
            .spawn()
            .unwrap();
        let parent_pid = parent.id();
        let client_pid = {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Ok(text) = std::fs::read_to_string(&ready)
                    && let Some(pid) = text.split_whitespace().nth(1)
                {
                    break pid.parse::<u32>().unwrap();
                }
                assert!(
                    Instant::now() < deadline,
                    "fixture {name} never became ready"
                );
                assert!(
                    parent.try_wait().unwrap().is_none(),
                    "the named parent exited before its client was ready"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        // The independent oracle: the client really is the parent's child.
        // Under a subreaper the adoption lands only once the intermediate
        // has exited, so poll with a deadline like the orphan helper.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (ppid, _) = stat_pair(client_pid);
            if ppid == parent_pid {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the client must be parented by the named launcher \
                 (ppid {ppid}, parent {parent_pid})"
            );
            assert!(
                parent.try_wait().unwrap().is_none(),
                "the named parent exited before its client was adopted"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        Self {
            parent: Some(parent),
            parent_pid,
            client_pid,
            gate,
        }
    }

    /// Release both fixtures and require a clean exit.
    fn release(mut self) {
        std::fs::write(&self.gate, b"go\n").unwrap();
        let mut parent = self.parent.take().expect("the chain owns its parent");
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = parent.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the chain never exited");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(status.success(), "the chain must exit cleanly: {status}");
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.client_pid as libc::pid_t, libc::SIGKILL);
        }
        if let Some(mut parent) = self.parent.take() {
            let _ = parent.kill();
            let _ = parent.wait();
        }
    }
}

/// A double-forked client reparented to init: no waitable parent, only
/// the gate and the init adoption. Killed on drop like a chain client.
struct Orphan {
    client_pid: u32,
    gate: PathBuf,
}

impl Orphan {
    fn spawn(dir: &Path, name: &str) -> Self {
        let parent_bin = gcc(
            dir,
            "orphan-parent",
            &fixture_source("parent-chain/orphan-parent.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &[],
        );
        let client_bin = gcc(
            dir,
            "chain-client",
            &fixture_source("parent-chain/chain-client.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let ready = dir.join(format!("{name}.ready"));
        let _ = std::fs::remove_file(&ready);
        let gate = dir.join(format!("{name}.gate"));
        let _ = std::fs::remove_file(&gate);
        let mut spawner = Command::new(&parent_bin)
            .arg(&client_bin)
            .arg(softhsm_path())
            .arg(&ready)
            .arg(&gate)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .die_with_parent()
            .spawn()
            .unwrap();
        // The spawner reaps the intermediate child and exits at once;
        // the client outlives it under init.
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = spawner.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the orphan spawner never exited");
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(
            status.success(),
            "the orphan spawner must exit cleanly: {status}"
        );
        let client_pid = {
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Ok(text) = std::fs::read_to_string(&ready)
                    && let Some(pid) = text.split_whitespace().nth(1)
                {
                    break pid.parse::<u32>().unwrap();
                }
                assert!(
                    Instant::now() < deadline,
                    "fixture {name} never became ready"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        // The orphan owns its client from here: on any failure below
        // its `Drop` kills the client at once instead of leaving it to
        // the gate's 30 s ceiling.
        let orphan = Self { client_pid, gate };
        // The independent oracle: the client really is orphaned to init
        // — or, under a desktop shell, to the systemd user manager,
        // which production reports as `init_parent` too. Anything else
        // (another subreaper between here and pid 1) fails loudly:
        // this cell needs the init adoption, never a skip.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (ppid, _) = stat_pair(orphan.client_pid);
            if ppid == 1 || adopted_by_user_manager(ppid) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the orphaned client never reached init (ppid {ppid}): \
                 a subreaper adopted it or the double fork failed"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        orphan
    }

    /// Release the client and require its exit. Not our child, so poll
    /// `/proc` for the exit (reaped, or zombie awaiting init's wait).
    fn release(self) {
        std::fs::write(&self.gate, b"go\n").unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match std::fs::read_to_string(format!("/proc/{}/stat", self.client_pid)) {
                Err(_) => break,
                Ok(text) => {
                    let end = text.rfind(')').expect("stat comm");
                    let state = text[end + 1..].split_whitespace().next();
                    if state == Some("Z") {
                        break;
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "the orphaned client never exited"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Orphan {
    fn drop(&mut self) {
        unsafe {
            libc::kill(self.client_pid as libc::pid_t, libc::SIGKILL);
        }
    }
}

/// Independent `/proc` oracle for the systemd unit: the first valid
/// unit of the `0:` cgroup path (leading slices skipped), or the first
/// valid unit after `user@<uid>.service` when that service is the first
/// non-slice component (systemd's anchored `skip_user_prefix`; a
/// mid-path occurrence is a delegated name). Walked names keep
/// systemd's unit-name charset, length and `@` rules. Derived in the
/// test from the raw file, so production must agree byte for byte.
fn systemd_unit_oracle(cgroup: &str) -> Option<String> {
    const SUFFIXES: &[&str] = &[
        ".service",
        ".scope",
        ".socket",
        ".timer",
        ".target",
        ".path",
        ".mount",
        ".automount",
        ".swap",
        ".device",
    ];
    fn chars_valid(prefix: &str, allow_at: bool) -> bool {
        prefix.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b':' | b'-' | b'_' | b'.' | b'\\')
                || (allow_at && byte == b'@')
        })
    }
    fn is_slice(name: &str) -> bool {
        name.len() < 256
            && name.len() > ".slice".len()
            && name.ends_with(".slice")
            && chars_valid(&name[..name.len() - ".slice".len()], false)
    }
    fn is_unit(name: &str) -> bool {
        if name.len() >= 256 || name.starts_with('@') {
            return false;
        }
        SUFFIXES.iter().any(|suffix| {
            name.len() > suffix.len() && name.ends_with(suffix) && {
                let prefix = &name[..name.len() - suffix.len()];
                chars_valid(prefix, true) && prefix.find('@').is_none_or(|at| prefix.len() > at + 1)
            }
        })
    }
    fn is_user_manager(component: &str) -> bool {
        component
            .strip_prefix("user@")
            .and_then(|rest| rest.strip_suffix(".service"))
            .is_some_and(|uid| !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()))
    }
    let mut path = None;
    for line in cgroup.lines() {
        let Some(rest) = line.strip_prefix("0:") else {
            continue;
        };
        let Some((_, candidate)) = rest.split_once(':') else {
            continue;
        };
        path = Some(candidate.strip_suffix(" (deleted)").unwrap_or(candidate));
        break;
    }
    let path = path?;
    if path.starts_with("/../") {
        return None;
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    let mut rest = parts.as_slice();
    while let [first, tail @ ..] = rest {
        if !is_slice(first.strip_prefix('_').unwrap_or(first)) {
            break;
        }
        rest = tail;
    }
    let start = match rest {
        [manager, ..] if is_user_manager(manager) => parts.len() - rest.len() + 1,
        _ => 0,
    };
    for component in &parts[start..] {
        let name = component.strip_prefix('_').unwrap_or(component);
        if is_slice(name) {
            continue;
        }
        if is_unit(name) {
            return Some(name.to_string());
        }
        return None;
    }
    None
}

/// Whether a `/proc/<pid>/cgroup` text ends in the systemd user
/// manager itself (`user@<uid>.service/init.scope`, numeric uid):
/// desktop test shells run under `systemd --user`, so an orphaned
/// fixture lands there instead of pid 1.
fn cgroup_is_user_manager_init(cgroup: &str) -> bool {
    let mut path = None;
    for line in cgroup.lines() {
        let Some(rest) = line.strip_prefix("0:") else {
            continue;
        };
        let Some((_, candidate)) = rest.split_once(':') else {
            continue;
        };
        path = Some(candidate);
        break;
    }
    let Some(path) = path else {
        return false;
    };
    let mut tail = [None, None];
    for part in path.split('/').filter(|part| !part.is_empty()) {
        tail = [tail[1], Some(part)];
    }
    let [Some(manager), Some(scope)] = tail else {
        return false;
    };
    if scope != "init.scope" {
        return false;
    }
    manager
        .strip_prefix("user@")
        .and_then(|rest| rest.strip_suffix(".service"))
        .is_some_and(|uid| !uid.is_empty() && uid.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `pid` was adopted by the systemd user manager (an
/// unreadable cgroup answers false: adoption needs positive evidence).
fn adopted_by_user_manager(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .is_ok_and(|cgroup| cgroup_is_user_manager_init(&cgroup))
}

#[test]
fn systemd_unit_oracle_matches_systemd_on_anchored_and_invalid_names() {
    // The oracle pins the same systemd rule production implements: an
    // anchored `user@N.service` takes the user unit, a mid-path one is
    // a delegated name, and names systemd rejects yield nothing.
    assert_eq!(
        systemd_unit_oracle("0::/system.slice/docker-abc.scope/user@0.service/sshd.service\n")
            .as_deref(),
        Some("docker-abc.scope")
    );
    assert_eq!(
        systemd_unit_oracle(
            "0::/machine.slice/systemd-nspawn@c1.service/payload/user.slice/user-1000.slice/user@1000.service/app.slice/backup.service\n"
        )
        .as_deref(),
        Some("systemd-nspawn@c1.service")
    );
    assert_eq!(
        systemd_unit_oracle(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/backup.service\n"
        )
        .as_deref(),
        Some("backup.service")
    );
    assert_eq!(
        systemd_unit_oracle("0::/system.slice/foo bar.service\n").as_deref(),
        None
    );
    assert_eq!(
        systemd_unit_oracle("0::/foo@bar.slice/x.service\n").as_deref(),
        None
    );
    assert_eq!(
        systemd_unit_oracle("0::/system.slice/foo@.service\n").as_deref(),
        None
    );
    assert_eq!(
        systemd_unit_oracle("0::/system.slice/getty@tty1.service\n").as_deref(),
        Some("getty@tty1.service")
    );
}

#[test]
fn orphan_user_manager_adoption_tail_matches_init_scope_only() {
    assert!(cgroup_is_user_manager_init(
        "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n"
    ));
    assert!(!cgroup_is_user_manager_init(
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-gated.scope\n"
    ));
    assert!(!cgroup_is_user_manager_init(
        "0::/user.slice/user-1000.slice/user@notauid.service/init.scope\n"
    ));
    assert!(!cgroup_is_user_manager_init(
        "0::/system.slice/session-c2.scope\n"
    ));
    assert!(!cgroup_is_user_manager_init(""));
}

fn observe(pid: u32, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .arg("inventory")
        .arg("--pid")
        .arg(pid.to_string())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn caller_for(doc: &Value, pid: u64) -> Vec<&Value> {
    doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|caller| caller["pid"] == pid)
        .collect()
}

const CHAIN_GAP_SUBJECT: &str = "caller parent chain";
const KNOWN_CHAIN_REASONS: &[&str] = &[
    "launcher exited before read",
    "launcher hidden by /proc hidepid",
    "parent chain truncated after 4 ancestors",
];

#[test]
fn launcher_chain_json_names_the_named_parent_first() {
    let _guard = serial_guard();
    let dir = tmp("launcher-chain-json");
    let chain = Chain::spawn(&dir, "json");
    let (_, client_start) = stat_pair(chain.client_pid);
    let (_, parent_start) = stat_pair(chain.parent_pid);
    let output = observe(chain.client_pid, &["--capture", "scan", "--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "chain observe failed: {stderr}");
    assert!(
        !stderr.contains("panicked"),
        "stderr stays panic-free: {stderr}"
    );
    let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    // Counts and caller identity never change.
    assert_eq!(doc["budgets"]["callers"]["occupied"], 1);
    let callers = caller_for(&doc, u64::from(chain.client_pid));
    assert_eq!(callers.len(), 1, "one incarnation for the client");
    let caller = callers[0];
    assert_eq!(caller["pid"], chain.client_pid);
    assert_eq!(caller["start_time"], client_start);
    // The chain: nearest first, the named parent on top.
    let launched = caller["launched_by"]
        .as_array()
        .unwrap_or_else(|| panic!("callers[].launched_by must be an array: {caller}"));
    assert!(
        (1..=4).contains(&launched.len()),
        "the walk keeps 1..=4 ancestors, got {}",
        launched.len()
    );
    assert_eq!(launched[0]["pid"], chain.parent_pid);
    assert_eq!(launched[0]["exe"], "chain-parent");
    assert_eq!(launched[0]["start_time"], parent_start);
    for ancestor in &launched[1..] {
        assert!(ancestor["pid"].as_u64().is_some_and(|pid| pid > 0));
        assert!(ancestor["start_time"].as_u64().is_some());
        assert!(ancestor["exe"].is_string() || ancestor["exe"].is_null());
    }
    assert!(
        launched.iter().all(|ancestor| ancestor["pid"] != 1),
        "init is never shown as the launcher: {launched:?}"
    );
    assert_eq!(caller["launched_by_origin"], "chain");
    assert!(caller["launched_by_unit"].is_null());
    // A gap is either absent (a root was reached) or named.
    if !caller["launched_by_gap"].is_null() {
        assert_eq!(caller["launched_by_gap"]["subject"], CHAIN_GAP_SUBJECT);
        let reason = caller["launched_by_gap"]["reason"].as_str().unwrap();
        assert!(
            KNOWN_CHAIN_REASONS.contains(&reason),
            "a named gap, never a guess: {reason}"
        );
    }
    chain.release();
}

#[test]
fn launcher_chain_verbose_text_shows_the_chain() {
    let _guard = serial_guard();
    let dir = tmp("launcher-chain-verbose");
    let chain = Chain::spawn(&dir, "verbose");
    let output = observe(chain.client_pid, &["--capture", "scan", "-v"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "chain observe failed: {stderr}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains("chain-client <- chain-parent"),
        "the -v chain per caller, got:\n{text}"
    );
    chain.release();
}

#[test]
fn launcher_chain_concise_text_shows_one_hop() {
    let _guard = serial_guard();
    let dir = tmp("launcher-chain-concise");
    let chain = Chain::spawn(&dir, "concise");
    let output = observe(chain.client_pid, &["--capture", "scan"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "chain observe failed: {stderr}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        text.contains("chain-client (from chain-parent)"),
        "the concise one-hop suffix, got:\n{text}"
    );
    chain.release();
}

/// An orphaned client (double fork, adopted by init) reports
/// `init_parent` with an empty chain, a null gap and the systemd unit
/// the independent `/proc` oracle derives for the live client.
#[test]
fn launcher_chain_orphan_reports_init_parent_with_oracle_unit() {
    let _guard = serial_guard();
    let dir = tmp("launcher-chain-orphan");
    let orphan = Orphan::spawn(&dir, "orphan");
    let raw = std::fs::read_to_string(format!("/proc/{}/cgroup", orphan.client_pid)).unwrap();
    let expected_unit = systemd_unit_oracle(&raw);
    let output = observe(orphan.client_pid, &["--capture", "scan", "--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "orphan observe failed: {stderr}");
    assert!(
        !stderr.contains("panicked"),
        "stderr stays panic-free: {stderr}"
    );
    let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    let callers = caller_for(&doc, u64::from(orphan.client_pid));
    assert_eq!(callers.len(), 1, "one incarnation for the orphan");
    let caller = callers[0];
    assert!(
        caller["launched_by"].as_array().is_some_and(Vec::is_empty),
        "init is never shown as the launcher: {}",
        caller["launched_by"]
    );
    assert_eq!(caller["launched_by_origin"], "init_parent");
    assert!(
        caller["launched_by_gap"].is_null(),
        "init_parent is not a read failure: {}",
        caller["launched_by_gap"]
    );
    assert_eq!(
        caller["launched_by_unit"].as_str(),
        expected_unit.as_deref(),
        "the unit matches the independent /proc oracle (raw {raw:?})"
    );
    orphan.release();
}

/// A client adopted by a same-namespace child subreaper keeps the
/// adopter as a visible link: subreapers expose no `/proc` flag, so
/// this is the documented known limit, pinned against silent renames.
#[test]
fn launcher_chain_subreaper_adoption_shows_the_adopter() {
    let _guard = serial_guard();
    let dir = tmp("launcher-chain-subreaper");
    let chain = Chain::spawn_with_parent(
        &dir,
        "subreaper",
        "subreaper-parent",
        "parent-chain/subreaper-parent.c",
    );
    let output = observe(chain.client_pid, &["--capture", "scan", "--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "subreaper observe failed: {stderr}"
    );
    assert!(
        !stderr.contains("panicked"),
        "stderr stays panic-free: {stderr}"
    );
    let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    let callers = caller_for(&doc, u64::from(chain.client_pid));
    assert_eq!(callers.len(), 1, "one incarnation for the client");
    let caller = callers[0];
    let launched = caller["launched_by"].as_array().unwrap();
    assert!(
        !launched.is_empty(),
        "the adopting subreaper stays a visible link: {caller}"
    );
    assert_eq!(launched[0]["pid"], chain.parent_pid);
    assert_eq!(launched[0]["exe"], "subreaper-parent");
    assert_eq!(caller["launched_by_origin"], "chain");
    assert!(caller["launched_by_unit"].is_null());
    chain.release();
}
