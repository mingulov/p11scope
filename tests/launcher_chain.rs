//! SPDX-License-Identifier: GPL-3.0-or-later
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
        let parent_bin = gcc(
            dir,
            "chain-parent",
            &fixture_source("parent-chain/chain-parent.c"),
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
        let (ppid, _) = stat_pair(client_pid);
        assert_eq!(
            ppid, parent_pid,
            "the client must be parented by the named launcher"
        );
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
    "parent unknown: exited before read",
    "parent unknown: unreadable /proc entry",
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
