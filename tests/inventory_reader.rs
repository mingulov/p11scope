//! SPDX-License-Identifier: GPL-3.0-or-later
//! Independent inventory reader (module/caller inventory contract).
//!
//! Reads ONLY the `inventory` output document (via CLI invocation on
//! owned fixture processes — no private-harness shortcuts) and asserts
//! every expected module, caller, edge, and gap is present with the
//! right identity/state/reason, including the refused NSS/closure cases,
//! the same-path dance pair, and the hardlink alias pair. Also pins the
//! negative contracts: no record reports a mapping as an observed call.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;
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

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Owned fixture set. Basenames carry an `ir-` prefix so a concurrently
/// running catalog dance (same basenames without the prefix) can never
/// merge into our assertions.
struct FixtureSet {
    dir: PathBuf,
    driver: PathBuf,
    v1: PathBuf,
    v2: PathBuf,
    prov: PathBuf,
    nss: PathBuf,
    close: PathBuf,
    h1: PathBuf,
    h2: PathBuf,
    ready: PathBuf,
}

fn build_fixtures(dir: &Path) -> FixtureSet {
    let matrix = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let driver = gcc(
        dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let v1 = gcc(
        dir,
        "ir-v1.so",
        &matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let v2 = gcc(
        dir,
        "ir-v2.so",
        &matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=41"],
        &[],
    );
    let hbase = gcc(dir, "ir-hbase.so", &matrix, &["-shared", "-fPIC"], &[]);
    let h1 = dir.join("ir-h1.so");
    let h2 = dir.join("ir-h2.so");
    std::fs::hard_link(&hbase, &h1).unwrap();
    std::fs::hard_link(&hbase, &h2).unwrap();
    assert_eq!(
        std::fs::metadata(&h1).unwrap().ino(),
        std::fs::metadata(&h2).unwrap().ino(),
        "alias pair must share one inode"
    );
    let nss = gcc(
        dir,
        "ir-nss.so",
        &fixture_source("catalog-nss/provider.c"),
        &[
            "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
        ],
        &[],
    );
    let close = gcc(
        dir,
        "ir-close.so",
        &fixture_source("catalog-closure/provider.c"),
        &[
            "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
        ],
        &[],
    );
    let ready = dir.join("ready");
    std::fs::create_dir_all(&ready).unwrap();
    FixtureSet {
        dir: dir.to_path_buf(),
        driver,
        v1,
        v2,
        prov: dir.join("ir-prov.so"),
        nss,
        close,
        h1,
        h2,
        ready,
    }
}

/// Kills owned fixture pids on drop, so a failed assert cannot leak
/// 300-second sleepers.
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

/// Strict-admission asserts hold only when ambient processes stay
/// memory-unreadable: ptrace_scope >= 1 and unprivileged. Any other
/// machine shape relaxes admission *state* only — identity, callers,
/// edges, and the structural NSS/closure refusals stay strict
/// everywhere.
fn strict_admission() -> bool {
    if unsafe { libc::getuid() } == 0 {
        return false;
    }
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .is_ok_and(|text| text.trim() != "0")
}

fn read_ready_pids(ready: &Path) -> BTreeMap<String, u32> {
    let mut pids = BTreeMap::new();
    for name in ["A", "B", "N", "C", "H1", "H2"] {
        let text = std::fs::read_to_string(ready.join(format!("{name}.ready"))).unwrap();
        let pid: u32 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        pids.insert(name.to_owned(), pid);
    }
    pids
}

struct Dance {
    json: Option<Value>,
    text: Option<String>,
    stderr: String,
    script_stdout_empty: bool,
    observer: u32,
    pids: BTreeMap<String, u32>,
    guard: Option<FixtureGuard>,
}

impl Dance {
    fn retire(&mut self) {
        drop(self.guard.take());
    }
}

/// Run the observe script once. `json_out` selects the JSON dance
/// (strict asserts) or the text dance (rendering asserts). `max_gaps`
/// passes an explicit `--max-gaps` bound; None keeps the 1024 default.
fn dance(fixtures: &FixtureSet, json_out: bool, max_gaps: Option<usize>) -> Dance {
    let _ = std::fs::remove_dir_all(&fixtures.ready);
    std::fs::create_dir_all(&fixtures.ready).unwrap();
    let out = fixtures
        .dir
        .join(if json_out { "out.json" } else { "out.txt" });
    let _ = std::fs::remove_file(&out);
    let mut extra = if json_out {
        vec![
            "--json".to_string(),
            "--max-scan-pids".to_string(),
            "4096".to_string(),
        ]
    } else {
        vec!["--max-scan-pids".to_string(), "4096".to_string()]
    };
    if let Some(bound) = max_gaps {
        extra.push("--max-gaps".to_string());
        extra.push(bound.to_string());
    }
    let script = fixture_source("inventory-observe.sh");
    let child = Command::new("sh")
        .arg(&script)
        .arg("--system")
        .args(&extra)
        .env("INV_DRIVER", &fixtures.driver)
        .env("INV_SET", "contract")
        .env("INV_V1", &fixtures.v1)
        .env("INV_V2", &fixtures.v2)
        .env("INV_PROV", &fixtures.prov)
        .env("INV_NSS", &fixtures.nss)
        .env("INV_CLOSE", &fixtures.close)
        .env("INV_H1", &fixtures.h1)
        .env("INV_H2", &fixtures.h2)
        .env("INV_READY", &fixtures.ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The script execs the observer, so the child pid IS the observer pid.
    let observer = child.id();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "observe script failed: {output:?} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let script_stdout_empty = output.stdout.is_empty();
    let pids = read_ready_pids(&fixtures.ready);
    let guard = FixtureGuard {
        pids: pids.values().copied().collect(),
    };
    let body = std::fs::read_to_string(&out).unwrap();
    let (json, text) = if json_out {
        // Strict reader: the document must parse as JSON as-is.
        let value: Value = serde_json::from_str(&body).unwrap();
        (Some(value), None)
    } else {
        (None, Some(body))
    };
    Dance {
        json,
        text,
        stderr,
        script_stdout_empty,
        observer,
        pids,
        guard: Some(guard),
    }
}

fn pid_of(pids: &BTreeMap<String, u32>, name: &str) -> u64 {
    u64::from(*pids.get(name).unwrap())
}

/// The one caller record for an owned pid. Ambient callers never share
/// our pids, so the match is exact.
fn caller_for(doc: &Value, pid: u64) -> &Value {
    let found: Vec<&Value> = doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|caller| caller["pid"] == pid)
        .collect();
    assert_eq!(found.len(), 1, "expected exactly one caller for pid {pid}");
    found[0]
}

/// The one module record observing `so_name` (file name). Ambient
/// objects never share our `ir-` file names, so the match is exact.
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

fn edge_for<'a>(doc: &'a Value, caller_id: &str, module_id: &str) -> &'a Value {
    let found = edges_for(doc, caller_id, module_id);
    assert_eq!(
        found.len(),
        1,
        "expected exactly one edge {caller_id} -> {module_id}"
    );
    found[0]
}

#[test]
fn inventory_contract_modules_callers_edges_gaps() {
    let _guard = serial_guard();
    let dir = tmp("inventory-reader-contract");
    let fixtures = build_fixtures(&dir);
    // Explicit gap bound with full `--system` scope unchanged and the
    // same assertions: measured ambient on a loaded host is ~1464-1477
    // total gaps, so 4096 (~2.8x headroom) keeps owned gaps retained
    // without narrowing what the contract observes.
    let mut dance = dance(&fixtures, true, Some(4096));
    let doc = dance.json.as_ref().unwrap();

    // Document basics: the exact schema id, scope, clock, observation.
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    assert_eq!(doc["scope"], "system");
    assert_eq!(doc["clock"]["basis"], "CLOCK_MONOTONIC");
    assert_eq!(doc["clock"]["unit"], "ns");
    assert!(doc["observation"]["passes"].as_u64().unwrap() >= 1);
    assert_eq!(doc["observation"]["usage_feed"], false);
    assert!(
        doc["observation"]["started_ns"].as_u64().unwrap()
            <= doc["observation"]["ended_ns"].as_u64().unwrap()
    );

    // Every owned caller is present with scan-pinned incarnation facts.
    for name in ["A", "B", "N", "C", "H1", "H2"] {
        let caller = caller_for(doc, pid_of(&dance.pids, name));
        assert_eq!(caller["lifecycle"], "mapped");
        assert_eq!(caller["retired"], false);
        assert_eq!(caller["incarnation"], 0);
        assert_eq!(caller["image"]["authority"], "scan_pinned");
        assert_eq!(caller["image"]["exec_observed"], true);
        assert!(
            caller["image"]["exe"]["path"]
                .as_str()
                .unwrap()
                .ends_with("driver"),
            "caller {name} exe: {}",
            caller["image"]["exe"]["path"]
        );
        assert!(caller["start_time"].is_u64());
        assert!(
            caller["first_seen_ns"].as_u64().unwrap() <= caller["last_seen_ns"].as_u64().unwrap()
        );
    }

    // The same-path pair: exactly one module record for ir-prov.so, with
    // the LIVE (V2) bytes — A's deleted mapping is verified absence,
    // never a second module and never conflated into B's edge.
    let prov = module_for(doc, "ir-prov.so");
    assert_eq!(prov["identity"]["sha256"], sha256_file(&fixtures.v2));
    assert_ne!(prov["identity"]["sha256"], sha256_file(&fixtures.v1));
    let caller_a = caller_for(doc, pid_of(&dance.pids, "A"));
    let caller_b = caller_for(doc, pid_of(&dance.pids, "B"));
    assert!(
        edges_for(
            doc,
            caller_a["id"].as_str().unwrap(),
            prov["id"].as_str().unwrap()
        )
        .is_empty(),
        "A's deleted mapping must not edge to the live module"
    );
    let edge_b = edge_for(
        doc,
        caller_b["id"].as_str().unwrap(),
        prov["id"].as_str().unwrap(),
    );
    assert_eq!(edge_b["mapping"]["state"], "mapped");
    // The deleted mapping is an explicit gap, not silent absence.
    assert!(
        doc["gaps"].as_array().unwrap().iter().any(|gap| {
            gap["pid"] == pid_of(&dance.pids, "A")
                && (gap["reason"].as_str().unwrap().contains("deleted")
                    || gap["subject"].as_str().unwrap().contains("deleted"))
        }),
        "A's deleted mapping must surface as a gap: {}",
        doc["gaps"]
    );

    // The refused pair: present with refusal reasons, zero invented
    // calls. Structural refusals hold on every machine shape.
    for (name, so_name) in [("N", "ir-nss.so"), ("C", "ir-close.so")] {
        let module = module_for(doc, so_name);
        assert_eq!(module["admission"]["state"], "refused");
        assert!(
            !module["admission"]["reasons"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{so_name} must carry refusal reasons"
        );
        let caller = caller_for(doc, pid_of(&dance.pids, name));
        let edge = edge_for(
            doc,
            caller["id"].as_str().unwrap(),
            module["id"].as_str().unwrap(),
        );
        assert_eq!(edge["mapping"]["state"], "mapped");
        assert_eq!(edge["entries"]["count"], 0);
        assert!(edge["entries"]["last_seen_ns"].is_null());
        assert_eq!(edge["entries"]["observation"], "unknown (not admitted)");
    }

    // The alias pair: one module record under two paths, two edges.
    let alias_modules: Vec<&Value> = doc["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|module| {
            let paths: BTreeSet<&str> = module["paths"]
                .as_array()
                .unwrap()
                .iter()
                .map(|path| path.as_str().unwrap())
                .collect();
            paths.contains(fixtures.h1.to_str().unwrap())
                || paths.contains(fixtures.h2.to_str().unwrap())
        })
        .collect();
    assert_eq!(alias_modules.len(), 1, "hardlink pair must merge");
    let alias = alias_modules[0];
    let alias_paths: BTreeSet<&str> = alias["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    assert!(alias_paths.contains(fixtures.h1.to_str().unwrap()));
    assert!(alias_paths.contains(fixtures.h2.to_str().unwrap()));
    for name in ["H1", "H2"] {
        let caller = caller_for(doc, pid_of(&dance.pids, name));
        let edge = edge_for(
            doc,
            caller["id"].as_str().unwrap(),
            alias["id"].as_str().unwrap(),
        );
        assert_eq!(edge["mapping"]["state"], "mapped");
        assert_eq!(edge["entries"]["count"], 0);
    }

    // Admitted-shape modules read unknown-unavailable on a strict
    // machine; anywhere else any non-observed reading is honest, but
    // the entry columns still invent nothing.
    if strict_admission() {
        assert_eq!(prov["admission"]["state"], "admitted");
        assert_eq!(
            edge_b["entries"]["observation"],
            "unknown (usage observation unavailable)"
        );
    } else {
        assert_ne!(edge_b["entries"]["observation"], "observed");
    }

    // The authority gap: the scan lane names its missing exact-image
    // authority explicitly.
    assert!(
        doc["gaps"].as_array().unwrap().iter().any(|gap| {
            gap["subject"] == "exact image authority unavailable"
                && gap["reason"]
                    .as_str()
                    .unwrap()
                    .contains("no BPF image identity")
        }),
        "authority gap missing: {}",
        doc["gaps"]
    );

    // Negative contracts over the WHOLE document, owned and ambient:
    // no edge invents a call, and every reference resolves.
    let caller_ids: BTreeSet<&str> = doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|caller| caller["id"].as_str().unwrap())
        .collect();
    let module_ids: BTreeSet<&str> = doc["modules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|module| module["id"].as_str().unwrap())
        .collect();
    let mut mapped_edges = 0u32;
    for edge in doc["edges"].as_array().unwrap() {
        assert_eq!(edge["entries"]["count"], 0, "invented call: {edge}");
        assert!(edge["entries"]["first_seen_ns"].is_null());
        assert!(edge["entries"]["last_seen_ns"].is_null());
        assert_ne!(edge["entries"]["observation"], "observed");
        assert!(
            caller_ids.contains(edge["caller"].as_str().unwrap()),
            "dangling edge caller: {edge}"
        );
        assert!(
            module_ids.contains(edge["module"].as_str().unwrap()),
            "dangling edge module: {edge}"
        );
        if edge["mapping"]["state"] == "mapped" {
            mapped_edges += 1;
        }
    }
    // Mappings exist while calls do not: the two are never conflated.
    assert!(mapped_edges > 0, "expected mapped edges with zero calls");
    for gap in doc["gaps"].as_array().unwrap() {
        if !gap["caller"].is_null() {
            assert!(caller_ids.contains(gap["caller"].as_str().unwrap()));
        }
        if !gap["module"].is_null() {
            assert!(module_ids.contains(gap["module"].as_str().unwrap()));
        }
    }

    // Plumbing: the script's own stdout stays empty (the document went
    // to the file), and progress went to stderr.
    assert!(dance.script_stdout_empty);
    assert!(dance.stderr.contains("p11scope:"), "{}", dance.stderr);
    assert_ne!(dance.observer, 0);
    dance.retire();
}

#[test]
fn inventory_text_dance_renders() {
    let _guard = serial_guard();
    let dir = tmp("inventory-reader-text");
    let fixtures = build_fixtures(&dir);
    let mut dance = dance(&fixtures, false, None);
    let text = dance.text.as_ref().unwrap();
    assert!(text.starts_with("inventory system ("), "{text}");
    assert!(text.contains("caller c"), "{text}");
    assert!(text.contains("module m"), "{text}");
    assert!(text.contains("edge "), "{text}");
    assert!(text.contains("gap ["), "{text}");
    assert!(dance.script_stdout_empty);
    dance.retire();
}
