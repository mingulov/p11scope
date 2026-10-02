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
        let mut child = Command::new(&driver)
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
        let deadline = Instant::now() + Duration::from_secs(30);
        let pid = loop {
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
        };
        assert_eq!(pid, child.id(), "ready pid is the spawned driver");
        let _ = child.try_wait().unwrap();
        Self {
            child: Some(child),
            pid,
        }
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
