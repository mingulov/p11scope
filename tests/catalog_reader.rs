//! SPDX-License-Identifier: GPL-3.0-or-later
//! Independent catalog reader (module/caller inventory Phase 1 gate).
//!
//! Reads ONLY the `inspect --system` output document (via CLI invocation
//! on owned fixture processes — no private-harness shortcuts) and asserts
//! every expected catalog object is present with the right
//! identity/state/reason, including the refused NSS/closure cases, the
//! same-path dance pair, and the hardlink alias pair. Also pins the
//! negative contracts: no record reports a mapping as an observed call,
//! and inspection executes no provider code (E3 marker).

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
    // Link inputs after the source: `--as-needed` drops a `-l` that
    // precedes the object needing it.
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

/// Owned fixture set: every .so the dance maps. Built once per test.
struct FixtureSet {
    dir: PathBuf,
    driver: PathBuf,
    v1: PathBuf,
    v2: PathBuf,
    prov: PathBuf,
    tless: PathBuf,
    mw: PathBuf,
    nss: PathBuf,
    close: PathBuf,
    h1: PathBuf,
    h2: PathBuf,
    ready: PathBuf,
    marker: PathBuf,
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
        "v1.so",
        &matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let v2 = gcc(
        dir,
        "v2.so",
        &matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=41"],
        &[],
    );
    let tless = gcc(dir, "tless.so", &matrix, &["-shared", "-fPIC"], &[]);
    let hbase = gcc(dir, "hbase.so", &matrix, &["-shared", "-fPIC"], &[]);
    let h1 = dir.join("h1.so");
    let h2 = dir.join("h2.so");
    std::fs::hard_link(&hbase, &h1).unwrap();
    std::fs::hard_link(&hbase, &h2).unwrap();
    assert_eq!(
        std::fs::metadata(&h1).unwrap().ino(),
        std::fs::metadata(&h2).unwrap().ino(),
        "alias pair must share one inode"
    );
    let nss = gcc(
        dir,
        "nss.so",
        &fixture_source("catalog-nss/provider.c"),
        &[
            "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
        ],
        &[],
    );
    let close = gcc(
        dir,
        "closure.so",
        &fixture_source("catalog-closure/provider.c"),
        &[
            "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
        ],
        &[],
    );
    let backend = gcc(
        dir,
        "backend.so",
        &fixture_source("multi-wrapper/backend.c"),
        &["-shared", "-fPIC"],
        &[],
    );
    let mw = {
        let bin = dir.join("mw.so");
        let backend_arg = backend.to_str().unwrap().to_owned();
        let ok = Command::new("gcc")
            .args([
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fPIC",
                "-shared",
                "-Wl,-z,defs",
                "-o",
            ])
            .arg(&bin)
            .arg(fixture_source("multi-wrapper/provider.c"))
            .arg(backend_arg)
            .status()
            .unwrap()
            .success();
        assert!(ok, "gcc failed for mw.so");
        bin
    };
    let ready = dir.join("ready");
    std::fs::create_dir_all(&ready).unwrap();
    FixtureSet {
        dir: dir.to_path_buf(),
        driver,
        v1,
        v2,
        prov: dir.join("prov.so"),
        tless,
        mw,
        nss,
        close,
        h1,
        h2,
        ready,
        marker: dir.join("marker"),
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

/// Strict-admission asserts (B/MW admitted) hold only when ambient
/// processes stay memory-unreadable: ptrace_scope >= 1 and unprivileged.
/// Any other machine shape relaxes admission *state* only — identity,
/// tables, classes, and the always-over-capacity N/C refusals stay
/// strict everywhere.
fn strict_admission() -> bool {
    if unsafe { libc::getuid() } == 0 {
        return false;
    }
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .is_ok_and(|text| text.trim() != "0")
}

fn read_ready_pids(ready: &Path) -> BTreeMap<String, u32> {
    let mut pids = BTreeMap::new();
    for name in ["A", "B", "T", "M", "N", "C", "H1", "H2"] {
        let text = std::fs::read_to_string(ready.join(format!("{name}.ready"))).unwrap();
        let pid: u32 = text.split_whitespace().nth(1).unwrap().parse().unwrap();
        pids.insert(name.to_owned(), pid);
    }
    pids
}

struct Dance {
    /// Parsed output document (JSON dance) or raw text (text dance).
    json: Option<Value>,
    text: Option<String>,
    stderr: String,
    script_stdout_empty: bool,
    observer: u32,
    pids: BTreeMap<String, u32>,
    marker: BTreeSet<u32>,
    guard: Option<FixtureGuard>,
}

impl Dance {
    /// Kill this dance's fixtures now (their files are reused by the
    /// next dance: lingering sleepers would merge into its objects).
    fn retire(&mut self) {
        drop(self.guard.take());
    }
}

/// Run the observe script once. `json_out` selects the JSON dance
/// (strict asserts) or the text dance (rendering asserts).
fn dance(fixtures: &FixtureSet, json_out: bool) -> Dance {
    let _ = std::fs::remove_dir_all(&fixtures.ready);
    std::fs::create_dir_all(&fixtures.ready).unwrap();
    let out = fixtures
        .dir
        .join(if json_out { "out.json" } else { "out.txt" });
    let _ = std::fs::remove_file(&out);
    let script = fixture_source("catalog-observe.sh");
    let child = Command::new("sh")
        .arg(&script)
        .arg("--system")
        .args(if json_out {
            vec!["--json", "--max-scan-pids", "4096"]
        } else {
            vec!["--max-scan-pids", "4096"]
        })
        .env("CATALOG_DRIVER", &fixtures.driver)
        .env("CATALOG_V1", &fixtures.v1)
        .env("CATALOG_V2", &fixtures.v2)
        .env("CATALOG_PROV", &fixtures.prov)
        .env("CATALOG_TLESS", &fixtures.tless)
        .env("CATALOG_MW", &fixtures.mw)
        .env("CATALOG_NSS", &fixtures.nss)
        .env("CATALOG_CLOSE", &fixtures.close)
        .env("CATALOG_H1", &fixtures.h1)
        .env("CATALOG_H2", &fixtures.h2)
        .env("CATALOG_READY", &fixtures.ready)
        .env("CATALOG_MARKER", &fixtures.marker)
        .env("CATALOG_OUT", &out)
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
    let marker: BTreeSet<u32> = std::fs::read_to_string(&fixtures.marker)
        .unwrap()
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().parse().unwrap())
        .collect();
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
        marker,
        guard: Some(guard),
    }
}

fn pid_of(pids: &BTreeMap<String, u32>, name: &str) -> u64 {
    u64::from(*pids.get(name).unwrap())
}

/// Everything the document says about the owned fixtures, for a failure
/// message: the scan summary, every object with an observation under the
/// fixture directory, the fixture processes, and every skipped/notes record
/// naming a fixture pid or path. DR-CATALOG-H2-ALIAS-FLAKE lost an
/// intermittent "exactly one object observing h2.so" failure because only the
/// count was printed and the next run overwrote out.json.
fn fixture_extract(doc: &Value, pids: &BTreeMap<String, u32>) -> String {
    let fixture_pids: BTreeSet<u64> = pids.values().map(|pid| u64::from(*pid)).collect();
    let in_fixture_dir = |path: &str| path.contains("/catalog-reader/");
    let objects: Vec<Value> = doc["objects"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|object| {
            object["observations"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|ob| ob["path"].as_str().is_some_and(in_fixture_dir))
        })
        .map(|object| {
            let observations: Vec<Value> = object["observations"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|ob| {
                    serde_json::json!({
                        "pid": ob["pid"], "path": ob["path"], "evidence": ob["evidence"],
                    })
                })
                .collect();
            serde_json::json!({
                "path": object["path"], "inode": object["inode"],
                "admission": object["admission"], "observations": observations,
            })
        })
        .collect();
    let processes: Vec<&Value> = doc["processes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|process| {
            process["pid"]
                .as_u64()
                .is_some_and(|pid| fixture_pids.contains(&pid))
        })
        .collect();
    let gaps = |key: &str| -> Vec<&Value> {
        doc[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|gap| {
                gap["pid"]
                    .as_u64()
                    .is_some_and(|pid| fixture_pids.contains(&pid))
                    || gap["subject"].as_str().is_some_and(in_fixture_dir)
                    || gap["reason"].as_str().is_some_and(in_fixture_dir)
            })
            .collect()
    };
    serde_json::json!({
        "fixture_pids": pids,
        "scan": doc["scan"],
        "objects": objects,
        "processes": processes,
        "skipped": gaps("skipped"),
        "notes": gaps("notes"),
    })
    .to_string()
}

/// The one catalog object whose observations map `so_name` (file name).
/// Ambient objects never share our tmp-dir file names, so the match is
/// exact on the file name and the rest of the machine is ignored.
fn object_for<'a>(doc: &'a Value, pids: &BTreeMap<String, u32>, so_name: &str) -> &'a Value {
    let found: Vec<&Value> = doc["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| {
            o["observations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|ob| ob["path"].as_str().unwrap().rsplit('/').next().unwrap() == so_name)
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one object observing {so_name}; fixture extract: {}",
        fixture_extract(doc, pids)
    );
    found[0]
}

fn tables_of(object: &Value) -> Vec<(String, u64, String, u64)> {
    // Every asserted fixture object has exactly one observation except H.
    let observations = object["observations"].as_array().unwrap();
    assert_eq!(observations.len(), 1);
    observations[0]["tables"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| {
            (
                t["version"].as_str().unwrap().to_owned(),
                t["entries"].as_u64().unwrap(),
                t["walk"].as_str().unwrap().to_owned(),
                t["null_entries"].as_array().unwrap().len() as u64,
            )
        })
        .collect()
}

fn assert_no_call_fields(value: &Value) {
    const FORBIDDEN: &[&str] = &[
        "call",
        "calls",
        "callers",
        "count",
        "counts",
        "observed_calls",
        "n_calls",
    ];
    fn walk(value: &Value, path: &mut String) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    assert!(
                        !FORBIDDEN.contains(&key.as_str()),
                        "catalog record reports a call/count field: {path}/{key}"
                    );
                    let pushed = path.len();
                    path.push('/');
                    path.push_str(key);
                    walk(child, path);
                    path.truncate(pushed);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    let pushed = path.len();
                    path.push_str(&format!("[{index}]"));
                    walk(child, path);
                    path.truncate(pushed);
                }
            }
            _ => {}
        }
    }
    walk(value, &mut String::new());
}

#[test]
fn catalog_reader_finds_every_fixture_object() {
    let _guard = serial_guard();
    let dir = tmp("catalog-reader");
    let fixtures = build_fixtures(&dir);
    let strict = strict_admission();

    // ---- JSON dance: the full strict read. ----
    let mut run = dance(&fixtures, true);
    let doc = run.json.as_ref().unwrap();
    assert_eq!(doc["schema"], "p11scope/inspect-system/v1");
    assert_eq!(doc["scope"], "system");
    assert!(
        run.script_stdout_empty,
        "progress must never pollute stdout"
    );
    for phase in ["enumerating", "deep-scanning", "rendering"] {
        assert!(
            run.stderr.contains(phase),
            "stderr must show startup progress ({phase}): {}",
            run.stderr.lines().take(3).collect::<Vec<_>>().join("\n")
        );
    }

    // B: same-path dance, V2 bytes pinned. Three file-backed tables; the
    // 3.0 table's exported anchors corroborate the object.
    let b = object_for(doc, &run.pids, "prov.so");
    assert_eq!(
        tables_of(b),
        vec![
            ("2.41".to_owned(), 68, "known_prefix".to_owned(), 0),
            ("2.40".to_owned(), 68, "full".to_owned(), 0),
            ("3.0".to_owned(), 92, "full".to_owned(), 0),
        ]
    );
    assert_eq!(b["observations"][0]["pid"], pid_of(&run.pids, "B"));
    assert_eq!(b["inode"], std::fs::metadata(&fixtures.prov).unwrap().ino());
    assert_eq!(b["identity"]["sha256"], sha256_file(&fixtures.prov));
    assert_eq!(sha256_file(&fixtures.prov), sha256_file(&fixtures.v2));
    assert_ne!(sha256_file(&fixtures.prov), sha256_file(&fixtures.v1));
    assert_eq!(b["admission"]["class"], "corroborated");
    if strict {
        assert_eq!(b["admission"]["state"], "admitted");
        assert_eq!(b["admission"]["endpoints"], 92);
    } else if b["admission"]["state"] == "refused" {
        assert!(
            b["admission"]["reason"]
                .as_str()
                .unwrap()
                .contains("attach slots"),
            "relaxed B refusal must still be capacity-shaped"
        );
    }

    // A: same-path dance, V1 bytes. The kernel marks the replaced
    // mapping deleted, so A is a verified-absence note, never a module.
    for object in doc["objects"].as_array().unwrap() {
        for observation in object["observations"].as_array().unwrap() {
            assert_ne!(
                observation["pid"],
                pid_of(&run.pids, "A"),
                "the deleted V1 mapping must contribute no observation"
            );
        }
    }
    let a_note = doc["notes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|note| note["pid"] == pid_of(&run.pids, "A"))
        .expect("A must leave a deleted-mapping note");
    assert!(
        a_note["subject"].as_str().unwrap().contains("(deleted)"),
        "A note must name the deleted path: {a_note}"
    );
    assert_eq!(a_note["reason"], "deleted mapping");

    // N: refused NSS shape. Eight interface-linked tables (publication
    // evidence) whose 544 endpoints exceed the 512-slot ceiling alone.
    let n = object_for(doc, &run.pids, "nss.so");
    let n_tables = tables_of(n);
    assert_eq!(n_tables.len(), 8);
    assert!(
        n_tables.iter().all(|(version, entries, walk, nulls)| {
            version == "2.40" && *entries == 68 && walk == "full" && *nulls == 0
        }),
        "all 8 NSS tables must be full 68-entry 2.40 decodes: {n_tables:?}"
    );
    let n_ifaces = n["observations"][0]["interfaces"].as_array().unwrap();
    assert_eq!(n_ifaces.len(), 8);
    for (index, iface) in n_ifaces.iter().enumerate() {
        assert_eq!(iface["name_class"], "exact_standard");
        assert_eq!(iface["name"], "PKCS 11");
        assert_eq!(iface["flags"], 0);
        assert_eq!(iface["table"], index as u64);
    }
    assert_eq!(n["admission"]["state"], "refused");
    assert_eq!(n["admission"]["class"], "corroborated");
    let n_reason = n["admission"]["reason"].as_str().unwrap();
    assert!(
        n_reason.contains("544") && n_reason.contains("512"),
        "NSS refusal must be the 544-over-512 capacity whole-refusal: {n_reason}"
    );

    // C: refused p11-kit closure shape. 65 bare heuristic tables, no
    // triples, 532 endpoints that cannot fit the remaining slots.
    let c = object_for(doc, &run.pids, "closure.so");
    let c_tables = tables_of(c);
    assert_eq!(c_tables.len(), 65);
    assert!(
        c_tables.iter().all(|(version, entries, walk, nulls)| {
            version == "3.2" && *entries == 104 && walk == "full" && *nulls == 0
        }),
        "all 65 closure tables must be full 104-entry 3.2 decodes"
    );
    assert_eq!(
        c["observations"][0]["interfaces"].as_array().unwrap().len(),
        0
    );
    assert_eq!(c["admission"]["state"], "refused");
    assert_eq!(c["admission"]["class"], "closure_array");
    let c_reason = c["admission"]["reason"].as_str().unwrap();
    assert!(
        c_reason.contains("65") && c_reason.contains("lookalike"),
        "closure refusal must name the 65 lookalike tables: {c_reason}"
    );

    // M: admitted multi-table shape. Four file-backed templates; any
    // interface triple here is spurious data, never standard linkage.
    let m = object_for(doc, &run.pids, "mw.so");
    assert_eq!(
        tables_of(m),
        vec![("3.2".to_owned(), 104, "full".to_owned(), 0); 4]
    );
    for iface in m["observations"][0]["interfaces"].as_array().unwrap() {
        assert_eq!(
            iface["name_class"], "other",
            "MW triples are spurious, never standard: {iface}"
        );
    }
    assert_eq!(m["admission"]["class"], "heuristic");
    if strict {
        assert_eq!(m["admission"]["state"], "admitted");
        assert_eq!(m["admission"]["endpoints"], 27);
    } else if m["admission"]["state"] == "refused" {
        assert!(
            m["admission"]["reason"]
                .as_str()
                .unwrap()
                .contains("attach slots"),
            "relaxed MW refusal must still be capacity-shaped"
        );
    }

    // T: mapped but never called. Zero tables, verified-absence note.
    let t = object_for(doc, &run.pids, "tless.so");
    assert_eq!(t["observations"][0]["tables"].as_array().unwrap().len(), 0);
    assert_eq!(t["admission"]["state"], "admitted");
    assert_eq!(t["admission"]["class"], "heuristic");
    let t_note = doc["notes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|note| note["pid"] == pid_of(&run.pids, "T"))
        .expect("T must leave a no-table note");
    assert!(
        t_note["reason"]
            .as_str()
            .unwrap()
            .contains("no function table"),
        "T note must explain the absence: {t_note}"
    );

    // H1/H2: one hardlinked file under two paths. One object, two
    // observations, an alias relationship — never two objects.
    let h1_path = fixtures.h1.to_str().unwrap().to_owned();
    let h2_path = fixtures.h2.to_str().unwrap().to_owned();
    let h = object_for(doc, &run.pids, "h1.so");
    assert_eq!(object_for(doc, &run.pids, "h2.so"), h);
    let h_observations = h["observations"].as_array().unwrap();
    assert_eq!(h_observations.len(), 2);
    let mut h_paths: Vec<&str> = h_observations
        .iter()
        .map(|ob| ob["path"].as_str().unwrap())
        .collect();
    h_paths.sort_unstable();
    assert_eq!(h_paths, vec![h1_path.as_str(), h2_path.as_str()]);
    assert_eq!(h["observations"][0]["tables"].as_array().unwrap().len(), 0);
    assert_eq!(h["inode"], std::fs::metadata(&fixtures.h1).unwrap().ino());
    assert_eq!(
        std::fs::metadata(&fixtures.h1).unwrap().ino(),
        std::fs::metadata(&fixtures.h2).unwrap().ino()
    );
    let h_index = doc["objects"]
        .as_array()
        .unwrap()
        .iter()
        .position(|o| *o == *h)
        .unwrap() as u64;
    let alias = doc["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rel| rel["kind"] == "alias" && rel["object"] == h_index)
        .expect("the hardlink pair must publish an alias relationship");
    let mut alias_paths: Vec<&str> = alias["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    alias_paths.sort_unstable();
    assert_eq!(alias_paths, h_paths);

    // Processes: all eight fixtures attributed, all scanned (children of
    // the observer are always memory-readable).
    for name in ["A", "B", "T", "M", "N", "C", "H1", "H2"] {
        let process = doc["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["pid"] == pid_of(&run.pids, name))
            .unwrap_or_else(|| panic!("fixture {name} must be attributed"));
        assert_eq!(process["status"], "scanned", "fixture {name} must scan");
    }

    // Catalog/admission separation: every admission is scan-only, every
    // object carries a state and a class, both refusals are counted.
    assert_eq!(doc["admission"]["scan_only"], true);
    assert!(
        doc["admission"]["note"]
            .as_str()
            .unwrap()
            .contains("manifest"),
        "scan-only note must disclaim the manifest"
    );
    // The summary totals count every catalog object, ambient ones
    // included, so they are pinned to the per-object records rather than
    // to a machine-dependent number.
    let objects = doc["objects"].as_array().unwrap();
    let in_state = |state: &str| {
        objects
            .iter()
            .filter(|object| object["admission"]["state"] == state)
            .count() as u64
    };
    assert_eq!(doc["admission"]["admitted"], in_state("admitted"));
    assert_eq!(doc["admission"]["refused"], in_state("refused"));
    assert!(doc["admission"]["refused"].as_u64().unwrap() >= 2);
    // Fixture-owned admissions only: an ambient same-uid process keeps its
    // maps readable under ptrace_scope=1, so a desktop's libp11-kit is
    // cataloged and admitted at 0 endpoints, while a hosted runner maps
    // none. N/C are refused on every machine (their endpoints exceed the
    // whole 512-slot budget alone); T/H are admitted on every machine
    // (zero endpoints always fit). B/M admission is ambient-sensitive,
    // hence the strict gate.
    assert_eq!(h["admission"]["state"], "admitted");
    let fixture_admitted = [b, m, t, h]
        .iter()
        .filter(|object| object["admission"]["state"] == "admitted")
        .count();
    if strict {
        assert_eq!(fixture_admitted, 4, "B, M, T and H must all be admitted");
    } else {
        assert!(fixture_admitted >= 2, "T and H must be admitted");
    }
    for object in objects {
        assert_eq!(object["admission"]["scan_only"], true);
        assert!(object["admission"]["state"].is_string());
        assert!(object["admission"]["class"].is_string());
    }

    // E3: exactly the three constructor-bearing fixtures ran provider
    // code (at dlopen, in their own processes); the observer never did.
    let mut expected_marker = BTreeSet::new();
    for name in ["M", "N", "C"] {
        expected_marker.insert(*run.pids.get(name).unwrap());
    }
    assert_eq!(run.marker, expected_marker);
    assert!(
        !run.marker.contains(&run.observer),
        "the observer must never execute provider code"
    );

    // Mappings are never reported as observed calls.
    assert_no_call_fields(doc);

    // ---- Text dance: same facts, human-readable. ----
    run.retire();
    let text_run = dance(&fixtures, false);
    let text = text_run.text.as_ref().unwrap();
    for fragment in [
        "closure.so",
        "nss.so",
        "prov.so",
        "mw.so",
        "tless.so",
        "h1.so",
        "h2.so",
        "refused (closure_array)",
        "refused (corroborated)",
        "admitted",
        "alias object",
        "(deleted)",
        "scan-only admission",
    ] {
        assert!(
            text.contains(fragment),
            "text rendering must carry {fragment:?}"
        );
    }
    for phase in ["enumerating", "deep-scanning", "rendering"] {
        assert!(
            text_run.stderr.contains(phase),
            "text stderr must show startup progress ({phase})"
        );
    }
}
