//! SPDX-License-Identifier: GPL-3.0-or-later
//! Public-command inventory tests (module/caller inventory behaviors).
//!
//! Every behavior is asserted through the public `p11scope inventory`
//! command over owned fixtures, reading the public JSON with the same
//! independent reader as the contract test: multi-caller/multi-module/
//! multi-user edges, fork/exec incarnations, unload/reload history,
//! SIGKILL evidence freezing, and `-o`/stdout document identity.

use serde_json::Value;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

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

fn matrix_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("crates/discover/tests/fixture/version_matrix.c")
}

/// Kills owned fixture pids on drop, so a failed assert cannot leak
/// sleepers.
struct FixtureGuard {
    pids: Vec<u32>,
}

impl FixtureGuard {
    fn pid_is_gone(pid: u32) -> bool {
        std::fs::metadata(format!("/proc/{pid}")).is_err()
    }
}

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        for &pid in &self.pids {
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        for &pid in &self.pids {
            while !Self::pid_is_gone(pid) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn caller_for(doc: &Value, pid: u64) -> Vec<&Value> {
    doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|caller| caller["pid"] == pid)
        .collect()
}

fn module_for<'a>(doc: &'a Value, so_name: &str) -> &'a Value {
    let found: Vec<&Value> = doc["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|module| {
            module["paths"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path.as_str().unwrap().rsplit('/').next().unwrap() == so_name)
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one module observing {so_name}"
    );
    found[0]
}

fn edges_for<'a>(doc: &'a Value, caller_id: &str, module_id: &str) -> Vec<&'a Value> {
    doc["edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|edge| edge["caller"] == caller_id && edge["module"] == module_id)
        .collect()
}

// ---------------------------------------------------------------------------
// E1: multi-caller, multi-module, multi-provider, multi-user.
// ---------------------------------------------------------------------------

struct E1Dance {
    doc: Value,
    pids: BTreeMap<String, u32>,
    guard: Option<FixtureGuard>,
}

fn e1_dance(dir: &Path) -> E1Dance {
    let ready = dir.join("ready");
    let _ = std::fs::remove_dir_all(&ready);
    std::fs::create_dir_all(&ready).unwrap();
    let driver = gcc(
        dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let matrix = matrix_source();
    let p1 = gcc(
        dir,
        "ic-p1.so",
        &matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let p2 = gcc(
        dir,
        "ic-p2.so",
        &matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=41"],
        &[],
    );
    let out = dir.join("out.json");
    let _ = std::fs::remove_file(&out);
    let output = Command::new("sh")
        .arg(fixture_source("inventory-observe.sh"))
        .arg("--system")
        .args(["--json", "--max-scan-pids", "4096"])
        .env("INV_DRIVER", &driver)
        .env("INV_SET", "e1")
        .env("INV_P1", &p1)
        .env("INV_P2", &p2)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(
        output.status.success(),
        "e1 observe failed: {output:?} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let mut pids = BTreeMap::new();
    for name in ["A", "B", "C"] {
        let text = std::fs::read_to_string(ready.join(format!("{name}.ready"))).unwrap();
        let pid: u32 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        pids.insert(name.to_owned(), pid);
    }
    let guard = FixtureGuard {
        pids: pids.values().copied().collect(),
    };
    let body = std::fs::read_to_string(&out).unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    E1Dance {
        doc,
        pids,
        guard: Some(guard),
    }
}

#[test]
fn e1_multi_caller_multi_module_edges() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-e1");
    let mut dance = e1_dance(&dir);
    let doc = &dance.doc;
    assert_eq!(doc["schema"], "p11scope/inventory/v1");

    // Multi-caller: A and B share P1. Multi-module: C maps P1 and P2.
    // Multi-provider (P1, P2) and multi-user (A, B, C) in one document.
    let p1 = module_for(doc, "ic-p1.so");
    let p2 = module_for(doc, "ic-p2.so");
    assert_ne!(p1["id"], p2["id"]);
    assert_ne!(p1["identity"]["sha256"], p2["identity"]["sha256"]);
    let mut pairs = BTreeMap::new();
    for (name, so_names) in [
        ("A", vec!["ic-p1.so"]),
        ("B", vec!["ic-p1.so"]),
        ("C", vec!["ic-p1.so", "ic-p2.so"]),
    ] {
        let pid = u64::from(*dance.pids.get(name).unwrap());
        let callers = caller_for(doc, pid);
        assert_eq!(callers.len(), 1, "one incarnation for {name}");
        let caller_id = callers[0]["id"].as_str().unwrap();
        for so_name in so_names {
            let module = if so_name == "ic-p1.so" { p1 } else { p2 };
            let module_id = module["id"].as_str().unwrap();
            let found = edges_for(doc, caller_id, module_id);
            assert_eq!(found.len(), 1, "expected edge {name} -> {so_name}");
            assert_eq!(found[0]["mapping"]["state"], "mapped");
            assert_eq!(found[0]["entries"]["count"], 0);
            assert_scan_only_entries(found[0], &format!("{name} -> {so_name}"));
            pairs.insert((name, so_name), (caller_id, module_id));
        }
    }
    // Exactly the four expected edges among our callers — no more.
    let our_callers: Vec<&str> = pairs.values().map(|(caller, _)| *caller).collect();
    let our_edges: Vec<&Value> = doc["edges"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|edge| our_callers.contains(&edge["caller"].as_str().unwrap()))
        .collect();
    assert_eq!(our_edges.len(), 4);
    drop(dance.guard.take());
}

// ---------------------------------------------------------------------------
// --pid dances: exec, unload/reload, SIGKILL, -o identity.
// ---------------------------------------------------------------------------

struct PidDance {
    doc: Value,
    pid: u32,
    guard: Option<FixtureGuard>,
}

/// Run the pid observer: `mode` selects the fixture driver, `observer`
/// holds the observer args after `--pid`, `prov` the provider basename.
fn pid_dance(
    dir: &Path,
    name: &str,
    driver_source: &str,
    driver_out: &str,
    mode: &str,
    prov_name: &str,
    observer: &[&str],
) -> PidDance {
    let ready = dir.join(format!("{name}.ready"));
    let _ = std::fs::remove_file(&ready);
    let driver = gcc(
        dir,
        driver_out,
        &fixture_source(driver_source),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let prov = gcc(
        dir,
        prov_name,
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let out = dir.join(format!("{name}.json"));
    let _ = std::fs::remove_file(&out);
    let mut cmd = Command::new("sh");
    cmd.arg(fixture_source("inventory-observe-pid.sh"))
        .env("INV_DRIVER", &driver)
        .env("INV_MODE", mode)
        .env("INV_PROV", &prov)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for arg in observer {
        cmd.arg(arg);
    }
    let output = cmd.spawn().unwrap().wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{name} observe failed: {output:?} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    let text = std::fs::read_to_string(&ready).unwrap();
    let pid: u32 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let guard = FixtureGuard { pids: vec![pid] };
    let body = std::fs::read_to_string(&out).unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    PidDance {
        doc,
        pid,
        guard: Some(guard),
    }
}

#[test]
fn e2_exec_retires_and_admits_incarnations() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-exec");
    let mut dance = pid_dance(
        &dir,
        "exec",
        "inventory-exec-driver.c",
        "exec-driver",
        "exec",
        "ic-exec.so",
        &["--json", "--duration", "10s"],
    );
    let doc = &dance.doc;
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    assert_eq!(doc["scope"], format!("pid:{}", dance.pid));
    assert!(doc["observation"]["passes"].as_u64().unwrap() >= 2);

    // Two incarnations, one pid: the pre-exec driver and post-exec sleep.
    let callers = caller_for(doc, u64::from(dance.pid));
    assert_eq!(callers.len(), 2, "exec must split incarnations");
    let (old, new) = if callers[0]["incarnation"] == 0 {
        (callers[0], callers[1])
    } else {
        (callers[1], callers[0])
    };
    assert_eq!(old["incarnation"], 0);
    assert_eq!(old["lifecycle"], "exec_retired");
    assert_eq!(old["retired"], true);
    assert!(
        old["image"]["exe"]["path"]
            .as_str()
            .unwrap()
            .ends_with("exec-driver"),
        "old exe: {}",
        old["image"]["exe"]["path"]
    );
    assert_eq!(new["incarnation"], 1);
    assert_eq!(new["lifecycle"], "mapped");
    assert_eq!(new["retired"], false);
    assert!(
        new["image"]["exe"]["path"]
            .as_str()
            .unwrap()
            .contains("sleep"),
        "new exe: {}",
        new["image"]["exe"]["path"]
    );
    assert_ne!(old["id"], new["id"]);

    // The old incarnation's usage evidence is retained: its edge ends
    // but stays in the document, and the module is unknown (no unload
    // was proven — the new image simply never mapped it).
    let module = module_for(doc, "ic-exec.so");
    let old_edges = edges_for(
        doc,
        old["id"].as_str().unwrap(),
        module["id"].as_str().unwrap(),
    );
    assert_eq!(old_edges.len(), 1);
    assert_eq!(old_edges[0]["mapping"]["state"], "ended");
    assert_eq!(old_edges[0]["entries"]["count"], 0);
    assert!(
        edges_for(
            doc,
            new["id"].as_str().unwrap(),
            module["id"].as_str().unwrap()
        )
        .is_empty()
    );
    assert_eq!(module["lifecycle"], "unknown");
    assert_eq!(module["unloaded_observed"], false);
    drop(dance.guard.take());
}

#[test]
fn e2_unload_reload_observed_with_history() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-reload");
    let mut dance = pid_dance(
        &dir,
        "reload",
        "inventory-reload-driver.c",
        "reload-driver",
        "reload",
        "ic-reload.so",
        &["--json", "--duration", "14s"],
    );
    let doc = &dance.doc;
    assert_eq!(doc["schema"], "p11scope/inventory/v1");

    let callers = caller_for(doc, u64::from(dance.pid));
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0]["lifecycle"], "mapped");
    let module = module_for(doc, "ic-reload.so");
    let edge = edges_for(
        doc,
        callers[0]["id"].as_str().unwrap(),
        module["id"].as_str().unwrap(),
    );
    assert_eq!(edge.len(), 1);
    // Reloaded: mapped now, with exactly one observed interruption and
    // the unload retained in history.
    assert_eq!(edge[0]["mapping"]["state"], "mapped");
    assert_eq!(edge[0]["mapping"]["interruptions"], 1);
    assert_eq!(module["lifecycle"], "mapped");
    assert_eq!(module["unloaded_observed"], true);
    drop(dance.guard.take());
}

/// DR-C5-EDGE through the real `run_with_writer` stream: one multi-pass
/// reload run read by three consumers — the `-o` JSON document, the
/// `--event-log` JSONL stream and the stdout text snapshot. The last
/// `edge_observed` per edge equals the document's edge, every edge has
/// one, the derived states equal the text snapshot's, the mid-run
/// unload/reload streamed its own records, and the records are accounted
/// by the pass markers plus `ended`.
#[test]
fn edge_observed_replay_equals_the_snapshot_edges_over_a_reload_run() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-edge-stream");
    let ready = dir.join("edges.ready");
    let driver = gcc(
        &dir,
        "edges-reload-driver",
        &fixture_source("inventory-reload-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let prov = gcc(
        &dir,
        "ic-edges.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let private = private_dir();
    let document_path = private.path().join("edges.json");
    // B1: the stream needs a trusted parent like `-o`, so it lives in
    // the private dir too — `target/tmp` inherits the checkout's
    // ancestors, which may be group-writable.
    let stream_path = private.path().join("edges.jsonl");
    let text_path = dir.join("edges.txt");
    let output = Command::new("sh")
        .arg(fixture_source("inventory-observe-pid.sh"))
        .env("INV_DRIVER", &driver)
        .env("INV_MODE", "reload")
        .env("INV_PROV", &prov)
        .env("INV_READY", &ready)
        .env("INV_OUT", &text_path)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .args(["--duration", "14s", "-o"])
        .arg(&document_path)
        .arg("--event-log")
        .arg(&stream_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let text = std::fs::read_to_string(&ready).unwrap();
    let pid: u32 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let _fixture = FixtureGuard { pids: vec![pid] };
    assert!(
        output.status.success(),
        "observe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&document_path).unwrap()).unwrap();
    let text = std::fs::read_to_string(&text_path).unwrap();
    let lines: Vec<Value> = std::fs::read_to_string(&stream_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.last().unwrap()["kind"], "ended");
    assert!(doc["observation"]["passes"].as_u64().unwrap() >= 5);
    let records: Vec<&Value> = lines
        .iter()
        .filter(|line| line["kind"] == "edge_observed")
        .map(|line| &line["event"])
        .collect();
    let mut last: BTreeMap<(String, String), &Value> = BTreeMap::new();
    let mut per_edge: BTreeMap<(String, String), usize> = BTreeMap::new();
    for record in &records {
        let key = (
            record["caller"].as_str().unwrap().to_string(),
            record["module"].as_str().unwrap().to_string(),
        );
        *per_edge.entry(key.clone()).or_default() += 1;
        last.insert(key, record);
    }
    let edges = doc["edges"].as_array().unwrap();
    assert!(!edges.is_empty());
    assert_eq!(last.len(), edges.len(), "one replayed record per edge");
    for edge in edges {
        let key = (
            edge["caller"].as_str().unwrap().to_string(),
            edge["module"].as_str().unwrap().to_string(),
        );
        let record = last[&key];
        let mut replayed = record.clone();
        for state in ["presence", "capture", "activity"] {
            replayed.as_object_mut().unwrap().remove(state);
        }
        assert_eq!(&replayed, edge, "JSONL replay == JSON for {key:?}");
        let line = text
            .lines()
            .find(|line| line.starts_with(&format!("edge {} -> {} ", key.0, key.1)))
            .unwrap_or_else(|| panic!("no text line for {key:?}: {text}"));
        let states = format!(
            "presence {} capture {} activity {} ",
            record["presence"].as_str().unwrap(),
            record["capture"].as_str().unwrap(),
            record["activity"].as_str().unwrap()
        );
        assert!(line.contains(&states), "text {line:?} vs JSONL {states:?}");
    }
    // The reloaded edge streamed mapped, unloaded and mapped again mid-run.
    let module = module_for(&doc, "ic-edges.so");
    let caller = &caller_for(&doc, u64::from(pid))[0];
    let key = (
        caller["id"].as_str().unwrap().to_string(),
        module["id"].as_str().unwrap().to_string(),
    );
    assert_eq!(last[&key]["mapping"]["interruptions"], 1);
    assert!(
        per_edge[&key] >= 3,
        "records for the reloaded edge: {per_edge:?}"
    );
    let presences: Vec<&str> = records
        .iter()
        .filter(|record| record["caller"] == key.0.as_str() && record["module"] == key.1.as_str())
        .map(|record| record["presence"].as_str().unwrap())
        .collect();
    assert!(presences.contains(&"unloaded"), "{presences:?}");
    // Accounting: pass markers plus the final sweep cover every record.
    let passes: u64 = lines
        .iter()
        .filter(|line| line["kind"] == "pass_committed")
        .map(|line| line["event"]["edge_events"].as_u64().unwrap())
        .sum();
    let swept = lines.last().unwrap()["event"]["edge_events"]
        .as_u64()
        .unwrap();
    assert_eq!(passes + swept, records.len() as u64);
    // ...commit by commit, and nothing was left unretained.
    let mut since = 0u64;
    for line in &lines {
        match line["kind"].as_str().unwrap() {
            "edge_observed" => since += 1,
            "pass_committed" | "ended" => {
                assert_eq!(line["event"]["edge_events"], since, "{line}");
                since = 0;
            }
            _ => {}
        }
    }
    assert_eq!(lines.last().unwrap()["event"]["edges_unretained"], 0);
}

#[test]
fn b3_sigkill_freezes_evidence_with_exit_state() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-suicide");
    // `-o` needs a trusted directory (no group-writable ancestors); the
    // worktree target dir does not qualify, so the report goes to TMPDIR.
    let out_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = out_dir.path().join("suicide.json");
    let mut dance = pid_dance(
        &dir,
        "suicide",
        "inventory-suicide-driver.c",
        "suicide-driver",
        "suicide",
        "ic-suicide.so",
        &["--json", "--duration", "10s", "-o", file.to_str().unwrap()],
    );
    assert_eq!(dance.doc["schema"], "p11scope/inventory/v1");
    // The run survived its target's mid-observation death: exit 0 above
    // plus the empty-pass gap below.
    assert!(
        dance.doc["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["subject"] == "scan pass produced no observation"),
        "death passes must gap: {}",
        dance.doc["gaps"]
    );
    let callers = caller_for(&dance.doc, u64::from(dance.pid));
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0]["lifecycle"], "exited");
    assert_eq!(callers[0]["retired"], true);
    let module = module_for(&dance.doc, "ic-suicide.so");
    let edge = edges_for(
        &dance.doc,
        callers[0]["id"].as_str().unwrap(),
        module["id"].as_str().unwrap(),
    );
    assert_eq!(edge.len(), 1);
    assert_eq!(edge[0]["mapping"]["state"], "ended");
    // Frozen: zero entries, no recency, and the module is unknown (a
    // dead caller's absence proves no unload).
    assert_eq!(edge[0]["entries"]["count"], 0);
    assert!(edge[0]["entries"]["last_seen_ns"].is_null());
    assert_eq!(module["lifecycle"], "unknown");
    assert_eq!(module["unloaded_observed"], false);
    // `-o` holds the same document stdout carried.
    let file_body = std::fs::read_to_string(&file).unwrap();
    let file_doc: Value = serde_json::from_str(&file_body).unwrap();
    assert_eq!(file_doc, dance.doc);
    drop(dance.guard.take());
}

#[test]
fn out_file_matches_stdout_document() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-outfile");
    let out_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = out_dir.path().join("snapshot.json");
    // One snapshot pass, both sinks: byte-identical documents.
    let ready = dir.join("plain.ready");
    let _ = std::fs::remove_file(&ready);
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let prov = gcc(
        &dir,
        "ic-plain.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let out = dir.join("plain.json");
    let _ = std::fs::remove_file(&out);
    let output = Command::new("sh")
        .arg(fixture_source("inventory-observe-pid.sh"))
        .arg("--json")
        .arg("-o")
        .arg(&file)
        .env("INV_DRIVER", &driver)
        .env("INV_MODE", "plain")
        .env("INV_PROV", &prov)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(
        output.status.success(),
        "plain observe failed: {output:?} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&ready).unwrap();
    let pid: u32 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let guard = FixtureGuard { pids: vec![pid] };
    let stdout_body = std::fs::read_to_string(&out).unwrap();
    let file_body = std::fs::read_to_string(&file).unwrap();
    assert_eq!(stdout_body, file_body, "-o and --json must agree");
    let doc: Value = serde_json::from_str(&stdout_body).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    assert_eq!(doc["observation"]["passes"], 1);
    drop(guard);
}

// ---------------------------------------------------------------------------
// M8: inventory admission is judged against the Inventory endpoint budget.
// ---------------------------------------------------------------------------

/// The NSS-softokn-shaped fixture publishes 8 interface-linked tables of 68
/// distinct entry targets each (`catalog-nss/provider.c`): 544 endpoints,
/// past the 512-slot Detailed ceiling `inspect` judges by, inside the
/// 4096-endpoint Inventory budget the inventory command instruments under.
/// Its verdict must be the Inventory one.
#[test]
fn admission_verdict_uses_the_inventory_budget_not_the_detailed_slot_ceiling() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-admission");
    let ready = dir.join("nss.ready");
    let _ = std::fs::remove_file(&ready);
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let prov = gcc(
        &dir,
        "ic-nss.so",
        &fixture_source("catalog-nss/provider.c"),
        &[
            "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
        ],
        &[],
    );
    let out = dir.join("nss.json");
    let _ = std::fs::remove_file(&out);
    let output = Command::new("sh")
        .arg(fixture_source("inventory-observe-pid.sh"))
        .arg("--json")
        .env("INV_DRIVER", &driver)
        .env("INV_MODE", "plain")
        .env("INV_PROV", &prov)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(
        output.status.success(),
        "nss observe failed: {output:?} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(&ready).unwrap();
    let pid: u32 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let guard = FixtureGuard { pids: vec![pid] };
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");

    let module = module_for(&doc, "ic-nss.so");
    assert_eq!(
        module["admission"]["state"], "admitted",
        "admission: {}",
        module["admission"]
    );
    assert_eq!(module["admission"]["endpoints"], 8 * 68);
    assert_eq!(module["admission"]["reasons"], serde_json::json!([]));
    let callers = caller_for(&doc, u64::from(pid));
    assert_eq!(callers.len(), 1);
    let edges = edges_for(
        &doc,
        callers[0]["id"].as_str().unwrap(),
        module["id"].as_str().unwrap(),
    );
    assert_eq!(edges.len(), 1);
    assert_eq!(
        edges[0]["entries"]["observation"],
        "unknown (usage observation unavailable)"
    );
    assert_eq!(edges[0]["entries"]["count"], 0);
    assert_scan_only_entries(edges[0], "driver -> ic-nss.so");
    // The first verdict stood: no admission change history.
    assert_eq!(module["admission"]["history"], serde_json::json!([]));
    // The run's attach set holds the module's 544 endpoints of 4096.
    assert_eq!(
        doc["budgets"]["inventory_endpoints"],
        serde_json::json!({"limit": 4096, "occupied": 8 * 68, "refused": 0}),
        "budgets: {}",
        doc["budgets"]
    );
    assert_eq!(
        doc["budgets"]["inventory_attach_modules"],
        serde_json::json!({"limit": 4096, "occupied": 1, "refused": 0}),
    );
    assert_eq!(doc["observation"]["usage_feed"], false);
    drop(guard);
}

/// The scan lane's entries object: the v1 columns unchanged (count 0,
/// no recency, not in flight, `unknown (usage observation
/// unavailable)`) plus the additive Task 6 C2 coverage — unknown, for
/// the reason `scan_only`, with no instant and no loss flag.
fn assert_scan_only_entries(edge: &Value, name: &str) {
    let entries = &edge["entries"];
    let mut keys: Vec<&str> = entries
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "cap",
            "count",
            "coverage",
            "first_seen_ns",
            "in_flight",
            "last_seen_ns",
            "observation",
            "saturated"
        ],
        "{name}"
    );
    assert_eq!(entries["count"], 0, "{name}");
    assert!(entries["first_seen_ns"].is_null(), "{name}");
    assert!(entries["last_seen_ns"].is_null(), "{name}");
    assert_eq!(entries["in_flight"], false, "{name}");
    assert_eq!(
        entries["observation"], "unknown (usage observation unavailable)",
        "{name}"
    );
    assert_eq!(
        entries["coverage"],
        serde_json::json!({
            "state": "unknown",
            "since_ns": null,
            "until_ns": null,
            "first_ns": null,
            "lossy": null,
            "reason": "scan_only",
            "detail": null,
        }),
        "{name}"
    );
}

// ---------------------------------------------------------------------------
// S1/D4: mechanism/operation context at command level.
//
// D4-positive (an owned multi-mechanism workload through the real
// binary showing OBSERVED mechanism/operation context) is EXPLICITLY
// OPEN: trusted per-call events need the privileged BPF capture lane
// (see `observe_semantic`), which this unprivileged suite cannot run.
// These two tests pin the scan lane's honest contract instead — the
// S1-extended schema renders with withheld unknowns, stderr stays
// honest on degraded runs — so the privileged lane inherits a
// documented baseline, not a silent gap.
// ---------------------------------------------------------------------------

/// An owned provider-mapping fixture process, terminated and reaped
/// on drop (a failed assert cannot leak sleepers or zombies).
struct LiveDriver {
    child: Option<std::process::Child>,
    pid: u32,
}

impl LiveDriver {
    fn spawn(dir: &Path, name: &str, providers: &[&str]) -> Self {
        let driver = gcc(
            dir,
            &format!("{name}-driver"),
            &fixture_source("catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let mut libs = Vec::new();
        for soname in providers {
            libs.push(gcc(
                dir,
                soname,
                &matrix_source(),
                &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
                &[],
            ));
        }
        let ready = dir.join(format!("{name}.ready"));
        let _ = std::fs::remove_file(&ready);
        let child = Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg("--sleep")
            .arg("120")
            .args(&libs)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self::adopt(child, &ready, name, Duration::from_secs(30))
    }

    /// Owns `child` before anything can panic, then waits for its
    /// `READY <pid>` line in `ready`: a fixture that never becomes ready, or
    /// a ready line that does not parse, is killed and reaped by `Drop`
    /// (DR-55).
    fn adopt(child: std::process::Child, ready: &Path, name: &str, timeout: Duration) -> Self {
        let mut driver = Self {
            child: Some(child),
            pid: 0,
        };
        let deadline = Instant::now() + timeout;
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(ready)
                && let Some(pid) = text.split_whitespace().nth(1)
            {
                break pid.parse::<u32>().unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "fixture {name} never became ready"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        let child = driver.child.as_mut().expect("the driver owns its child");
        assert_eq!(pid, child.id(), "ready pid is the spawned driver");
        let _ = child.try_wait().unwrap();
        driver.pid = pid;
        driver
    }
}

impl Drop for LiveDriver {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// DR-55: a fixture that never becomes ready makes the readiness assert
/// panic; the driver must already own the child then, so its `Drop` kills
/// and reaps it instead of leaking a 120 s sleeper.
#[test]
fn a_driver_that_never_becomes_ready_is_reaped_after_the_panic() {
    let dir = tmp("inventory-command-never-ready");
    let child = Command::new("sleep")
        .arg("120")
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    let ready = dir.join("never.ready");
    let adopted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        LiveDriver::adopt(child, &ready, "never", Duration::from_millis(200))
    }));
    assert!(adopted.is_err(), "the readiness assert must fire");
    // Reaped: our child is gone, not running and not a zombie.
    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    let error = std::io::Error::last_os_error();
    if waited == 0 {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        unsafe { libc::waitpid(pid, &mut status, 0) };
        panic!("the never-ready driver {pid} was leaked still running");
    }
    assert_eq!(waited, -1, "the never-ready driver {pid} was left unreaped");
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
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

#[test]
fn s1_command_json_carries_semantic_schema_with_honest_unknowns() {
    // Multi-module workload through the real binary over owned
    // fixtures: production is scan-only (no semantic feed), so the
    // S1-extended schema renders with honest withheld unknowns at
    // command level — the fields exist, nothing is invented.
    let _guard = serial_guard();
    let dir = tmp("inventory-command-s1");
    let driver = LiveDriver::spawn(&dir, "s1", &["s1-p1.so", "s1-p2.so"]);
    let output = observe(driver.pid, &["--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "s1 observe failed: {stderr}");
    assert!(
        !stderr.contains("panicked"),
        "stderr stays panic-free: {stderr}"
    );
    let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    assert_eq!(doc["scope"], format!("pid:{}", driver.pid));
    for soname in ["s1-p1.so", "s1-p2.so"] {
        let module = module_for(&doc, soname);
        let module_id = module["id"].as_str().unwrap();
        let callers = caller_for(&doc, u64::from(driver.pid));
        assert_eq!(callers.len(), 1, "one incarnation for the driver");
        let edges = edges_for(&doc, callers[0]["id"].as_str().unwrap(), module_id);
        assert_eq!(edges.len(), 1, "expected edge -> {soname}");
        assert_eq!(edges[0]["mapping"]["state"], "mapped");
        // The additive S1 keys exist with honest withheld values.
        let mut keys: Vec<&str> = edges[0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "caller",
                "entries",
                "mapping",
                "mechanisms",
                "module",
                "operations",
                "semantics"
            ],
            "{soname}"
        );
        assert_eq!(
            edges[0]["semantics"], "unknown (semantic capture withheld)",
            "{soname}"
        );
        assert!(edges[0]["mechanisms"].is_null(), "{soname}");
        assert!(edges[0]["operations"].is_null(), "{soname}");
    }
    let budget = &doc["budgets"]["semantic_state"];
    assert_eq!(budget["occupied"], 0);
    assert_eq!(budget["status"], "withheld");
    assert_eq!(budget["refused"], 0);
    assert_eq!(
        budget["unknown_edges"],
        doc["edges"].as_array().unwrap().len() as u64
    );
}

#[test]
fn s1_command_degraded_run_keeps_stderr_honest() {
    // A refused run (dashboard forced onto a pipe) degrades with an
    // honest stderr notice; the snapshot it emits instead carries the
    // S1 semantic budget line and withheld columns.
    let _guard = serial_guard();
    let dir = tmp("inventory-command-s1-degrade");
    let driver = LiveDriver::spawn(&dir, "s1d", &["s1d-p1.so"]);
    let output = observe(driver.pid, &["--dashboard"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "degraded run exits 0: {stderr}");
    assert!(
        stderr.contains("degraded to pager snapshots") && !stderr.contains("panicked"),
        "honest degrade notice: {stderr}"
    );
    assert!(
        !output.stdout.contains(&0x1b),
        "no ANSI on the degraded pipe"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("semantic_state withheld held 0/"),
        "snapshot semantic budget: {stdout}"
    );
    assert!(
        stdout.contains("unknown (semantic capture withheld)"),
        "snapshot withheld columns: {stdout}"
    );
}

#[test]
fn max_gaps_knob_defaults_to_1024_and_binds_retention() {
    // End-to-end wiring: the enforced gap bound renders in
    // budgets.retained_history, 1024 when the flag is absent, the
    // override when set; retained/suppressed always agree with the
    // gaps array and its counter.
    let _guard = serial_guard();
    let dir = tmp("inventory-command-max-gaps");
    let driver = LiveDriver::spawn(&dir, "mg", &["mg-p1.so"]);
    for (args, expected_limit) in [
        (vec!["--json"], 1024),
        (vec!["--json", "--max-gaps", "3"], 3),
    ] {
        let output = observe(driver.pid, &args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "observe {args:?} failed: {stderr}");
        let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
        let history = &doc["budgets"]["retained_history"];
        assert_eq!(history["limit"], expected_limit, "args {args:?}");
        let gaps = doc["gaps"].as_array().unwrap();
        assert_eq!(history["retained"], gaps.len() as u64, "args {args:?}");
        assert_eq!(
            history["suppressed"], doc["gaps_suppressed"],
            "args {args:?}"
        );
        assert!(gaps.len() as u64 <= expected_limit, "args {args:?}");
    }
}

// ---------------------------------------------------------------------------
// Task 6 C5.1: the usage lane flag, the classic stop path, and hard sink
// failures. Unprivileged: the native lane itself runs in the privileged
// cells (`inventory_capture`) and the installed qualification.
// ---------------------------------------------------------------------------

fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// The observation keys the scan lane has always carried; the native lane
/// adds `lane`, `settlement` and `retirement`.
const SCAN_OBSERVATION_KEYS: [&str; 5] = [
    "ended_ns",
    "native_witnesses",
    "passes",
    "started_ns",
    "usage_feed",
];

fn observation_keys(doc: &Value) -> Vec<String> {
    let mut keys: Vec<String> = doc["observation"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    keys.sort_unstable();
    keys
}

/// A 0700 directory `-o` trusts (the target dir's ancestors may not be).
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

fn gap_subjects(doc: &Value) -> Vec<String> {
    doc["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|gap| gap["subject"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[test]
fn capture_native_without_privilege_is_an_error_naming_why() {
    if running_as_root() {
        eprintln!("skipped: root can run the native lane");
        return;
    }
    let _guard = serial_guard();
    let dir = tmp("inventory-command-native-refused");
    let driver = LiveDriver::spawn(&dir, "nr", &["nr-p1.so"]);
    let output = observe(driver.pid, &["--capture", "native", "--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("--capture native: the native usage lane cannot run:"),
        "{stderr}"
    );
    assert!(output.stdout.is_empty(), "no document on a refused lane");
}

#[test]
fn capture_auto_without_privilege_falls_back_to_scan_with_a_named_gap() {
    if running_as_root() {
        eprintln!("skipped: root runs the native lane under auto");
        return;
    }
    let _guard = serial_guard();
    let dir = tmp("inventory-command-auto-fallback");
    let driver = LiveDriver::spawn(&dir, "af", &["af-p1.so"]);
    for args in [vec!["--json"], vec!["--capture", "auto", "--json"]] {
        let output = observe(driver.pid, &args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{args:?}: {stderr}");
        assert!(
            stderr.contains("native usage feed unavailable, continuing with the scan lane"),
            "{stderr}"
        );
        let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
        let gap = doc["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|gap| gap["subject"] == "native usage feed unavailable")
            .unwrap_or_else(|| panic!("{args:?}: {}", doc["gaps"]));
        assert!(gap["caller"].is_null() && gap["module"].is_null() && gap["pid"].is_null());
        assert!(!gap["reason"].as_str().unwrap().is_empty());
        assert_eq!(observation_keys(&doc), SCAN_OBSERVATION_KEYS, "{args:?}");
        for edge in doc["edges"].as_array().unwrap() {
            assert_eq!(edge["entries"]["coverage"]["reason"], "scan_only", "{edge}");
        }
    }
}

/// `--capture scan` is today's scan lane: no BPF attempt, no native line on
/// stderr, no native gap, and the observation shape the scan lane always had.
#[test]
fn capture_scan_keeps_the_scan_lane_document() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-scan-lane");
    let driver = LiveDriver::spawn(&dir, "sl", &["sl-p1.so"]);
    let output = observe(driver.pid, &["--capture", "scan", "--json"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        !stderr.contains("native usage") && !stderr.contains("native capture"),
        "{stderr}"
    );
    let doc: Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).unwrap();
    assert_eq!(observation_keys(&doc), SCAN_OBSERVATION_KEYS);
    assert!(
        !gap_subjects(&doc)
            .iter()
            .any(|subject| subject.contains("native")),
        "{}",
        doc["gaps"]
    );
    assert_eq!(doc["observation"]["usage_feed"], false);
    let edges = doc["edges"].as_array().unwrap();
    assert!(!edges.is_empty());
    for edge in edges {
        assert_eq!(edge["entries"]["coverage"]["state"], "unknown");
        assert_eq!(edge["entries"]["coverage"]["reason"], "scan_only");
    }
}

/// The classic loop's stop path: SIGINT mid-window still writes the
/// stream's `ended`, commits `-o`, and exits 0.
#[test]
fn a_classic_run_interrupted_by_sigint_commits_its_report_and_stream() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-sigint");
    let driver = LiveDriver::spawn(&dir, "si", &["si-p1.so"]);
    let private = private_dir();
    let out = private.path().join("report.json");
    // B1: the stream needs a trusted parent like `-o` (see above).
    let stream = private.path().join("events.jsonl");
    let mut observer = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["inventory", "--pid", &driver.pid.to_string()])
        .args(["--capture", "scan", "--duration", "120s", "-o"])
        .arg(&out)
        .arg("--event-log")
        .arg(&stream)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = observer.id();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !std::fs::read_to_string(&stream).is_ok_and(|text| text.contains("\"pass_committed\"")) {
        if Instant::now() >= deadline {
            let _ = observer.kill();
            panic!("the observer never committed a pass");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let sent = Instant::now();
    // SAFETY: `pid` is our live, unreaped child.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGINT) }, 0);
    let status = loop {
        if let Some(status) = observer.try_wait().unwrap() {
            break status;
        }
        if sent.elapsed() > Duration::from_secs(15) {
            let _ = observer.kill();
            panic!("SIGINT did not end the classic loop within 15 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = observer.wait_with_output().unwrap();
    assert_eq!(
        status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(doc["observation"]["passes"].as_u64().unwrap() >= 1);
    let text = std::fs::read_to_string(&stream).unwrap();
    let last: Value = serde_json::from_str(text.lines().last().unwrap()).unwrap();
    assert_eq!(last["kind"], "ended", "{text}");
    assert_eq!(last["event"]["passes"], doc["observation"]["passes"]);
}

/// A reader that went away before the final document is an error (exit 1,
/// one stderr line), never silent; the `-o` report it follows is committed.
#[test]
fn a_closed_stdout_pipe_is_an_error_after_the_report_commits() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-closed-stdout");
    let driver = LiveDriver::spawn(&dir, "cs", &["cs-p1.so"]);
    let private = private_dir();
    let out = private.path().join("report.json");
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["inventory", "--pid", &driver.pid.to_string()])
        .args(["--capture", "scan", "--json", "-o"])
        .arg(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.starts_with("p11scope: ") && stderr.to_lowercase().contains("broken pipe"),
        "{stderr}"
    );
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
}

/// A device as `--event-log` is refused up front, never written through:
/// B1 gives the stream `-o`'s regular-file check, so `/dev/full` (once the
/// full-disk probe, failing at write with ENOSPC) now fails at open with
/// the non-regular refusal. Either way an unusable stream is an error,
/// never silent loss, and no success document is printed.
#[test]
fn a_device_event_log_is_refused_up_front() {
    let _guard = serial_guard();
    let dir = tmp("inventory-command-full-stream");
    let driver = LiveDriver::spawn(&dir, "fs", &["fs-p1.so"]);
    let output = observe(
        driver.pid,
        &["--capture", "scan", "--json", "--event-log", "/dev/full"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("it is a character device"), "{stderr}");
    assert!(output.stdout.is_empty(), "no success document: {stderr}");
}

/// C7 A3/A4: `P11SCOPE_PROOF_STAT_THREADS` and `P11SCOPE_SHARD_THREADS`
/// are read once per run. A multi-pass `inventory --system` collects every
/// pass, yet prints each knob's stderr note exactly once (the proof-stat
/// note once repeated every pass).
#[test]
fn the_proof_stat_thread_note_prints_once_per_multi_pass_run() {
    let _guard = serial_guard();
    let private = private_dir();
    let out = private.path().join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["inventory", "--system", "--capture", "scan"])
        .args(["--max-scan-pids", "1", "--duration", "6s", "--json", "-o"])
        .arg(&out)
        .env("P11SCOPE_PROOF_STAT_THREADS", "2")
        .env("P11SCOPE_SHARD_THREADS", "2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    let passes = doc["observation"]["passes"].as_u64().unwrap();
    assert!(
        passes >= 2,
        "needs a multi-pass run, got {passes}: {stderr}"
    );
    let notes: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("P11SCOPE_PROOF_STAT_THREADS"))
        .collect();
    assert_eq!(
        notes,
        ["p11scope: P11SCOPE_PROOF_STAT_THREADS=2 selects 2 proof-stat threads"],
        "{passes} passes: {stderr}"
    );
    let notes: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("P11SCOPE_SHARD_THREADS"))
        .collect();
    assert_eq!(
        notes,
        ["p11scope: P11SCOPE_SHARD_THREADS=2 selects 2 shard threads"],
        "{passes} passes: {stderr}"
    );
}
