//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Independent catalog reader (module/caller inventory Phase 1 gate).
//!
//! Reads ONLY the `inspect --system` output document (via CLI invocation
//! on owned fixture processes — no private-harness shortcuts) and asserts
//! every expected catalog object is present with the right
//! identity/state/reason, including default-profile NSS/closure refusals
//! and wide-profile whole admissions, the same-path dance pair, and the
//! hardlink alias pair. Also pins the negative contracts: no record
//! reports a mapping as an observed call,
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

fn build_fixtures(dir: &Path, corroborated: bool) -> FixtureSet {
    let matrix = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/discover/tests/fixture/version_matrix.c");
    let called_matrix = fixture_source("catalog-version-matrix.c");
    let export_mode = if corroborated {
        "-DCATALOG_PARTIAL_EXPORTS=0"
    } else {
        "-DCATALOG_PARTIAL_EXPORTS=1"
    };
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
        &called_matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40", export_mode],
        &[],
    );
    let v2 = gcc(
        dir,
        "v2.so",
        &called_matrix,
        &["-shared", "-fPIC", "-DLEGACY_MINOR=41", export_mode],
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

/// Strict positive assertions hold only when ambient
/// processes stay memory-unreadable: ptrace_scope >= 1 and unprivileged.
/// Other machines may refuse wide N/C whole for capacity; their admitted
/// endpoint totals, tables, classes and identities remain exact.
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
    let binary = env!("CARGO_BIN_EXE_p11scope");
    // Full detail: the strict asserts below read the complete text and
    // the startup progress on stderr, both verbose-only since CLI-1.
    let inspect_args: &[&str] = if json_out {
        &["--system", "--json", "--max-scan-pids", "4096", "-v"]
    } else {
        &["--system", "--max-scan-pids", "4096", "-v"]
    };
    eprintln!(
        "catalog reader: profile={} binary={binary} inspect {}",
        if cfg!(feature = "wide-detailed-2112") {
            "wide-detailed-2112"
        } else {
            "default-512"
        },
        inspect_args.join(" ")
    );
    let child = Command::new("sh")
        .arg(&script)
        .args(inspect_args)
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
        .env("P11SCOPE_BIN", binary)
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

#[derive(Clone, Copy)]
struct WholeFixture {
    class: &'static str,
    demand: u64,
    lookalikes: Option<u64>,
}

/// JK-22a relaxed corner: ambient occupancy can leave a closure array with
/// room for a reserve-capped prefix but not for whole, so relaxed runs
/// accept the named prefix gap beside the whole outcomes. Strict pins stay
/// exact: N is always refused whole ahead of C in default (its published
/// union exceeds the ceiling), which blocks C's prefix, and wide admits C
/// whole.
fn validate_closure_admission(
    admission: WholeAdmission<'_>,
    fixture: WholeFixture,
    wide: bool,
    strict: bool,
) -> Result<(), String> {
    // The producer files a prefix-admitted closure as partial with
    // its attached count; that shape validates in both modes. The
    // retired refused-plus-prefix shape stays accepted only when
    // relaxed, for reads of older captures.
    let reason = admission.reason.unwrap_or("");
    if admission.state == "partial"
        && admission.class == "closure_array"
        && reason.contains("template tables attached")
        && reason.contains("(closure_prefix)")
    {
        return Ok(());
    }
    // An over-bound closure stays published-only in every mode: its
    // union exceeds the 104-target whole bound, so it attaches only
    // its published tables, and none is published yet. JSON carries
    // the full reason; text renders the terse by-design form that
    // points at --json. The retired capacity-shaped whole refusal
    // below stays accepted for reads of older captures.
    let published_full = reason.contains("attaches only its published tables")
        && fixture.lookalikes.is_some_and(|tables| {
            reason.contains(&format!(
                "none of its {tables} lookalike function tables is published yet"
            ))
        });
    let published_terse = reason.contains("proxy closure array not attached by design")
        && reason.contains("the providers it forwards to attach when they load");
    if admission.state == "refused"
        && admission.class == "closure_array"
        && admission.endpoints.is_none()
        && (published_full || published_terse)
    {
        return Ok(());
    }
    match validate_whole_admission(admission, fixture, wide, strict) {
        Ok(()) => Ok(()),
        Err(error) if !strict => {
            if admission.state == "refused"
                && admission.class == "closure_array"
                && reason.contains("template tables attached")
                && reason.contains("(closure_prefix)")
            {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

const NSS: WholeFixture = WholeFixture {
    class: "corroborated",
    demand: 544,
    lookalikes: None,
};
const CLOSURE: WholeFixture = WholeFixture {
    class: "closure_array",
    demand: 532,
    lookalikes: Some(65),
};

#[derive(Clone, Copy)]
struct WholeAdmission<'a> {
    state: &'a str,
    class: &'a str,
    endpoints: Option<u64>,
    reason: Option<&'a str>,
}

fn json_whole_admission(admission: &Value) -> Result<WholeAdmission<'_>, String> {
    Ok(WholeAdmission {
        state: admission["state"]
            .as_str()
            .ok_or("admission state is missing")?,
        class: admission["class"]
            .as_str()
            .ok_or("admission class is missing")?,
        endpoints: admission["endpoints"].as_u64(),
        reason: admission["reason"].as_str(),
    })
}

fn text_whole_admission(block: &str) -> Result<WholeAdmission<'_>, String> {
    let mut lines = block
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("admission  "));
    let line = lines.next().ok_or("text admission is missing")?;
    if lines.next().is_some() {
        return Err("text object must have exactly one admission".into());
    }
    if let Some(admitted) = line.strip_prefix("admission  profile/run would watch ") {
        // `68 functions (class standard; ...)` or `1 function (class ...; ...)`.
        let (endpoints, rest) = admitted
            .split_once(' ')
            .ok_or("text admitted endpoint count is missing")?;
        let (_, rest) = rest
            .split_once("(class ")
            .ok_or("text admitted class is missing")?;
        let (class, _) = rest
            .split_once([';', ',', ')'])
            .ok_or("text admitted class is unterminated")?;
        Ok(WholeAdmission {
            state: "admitted",
            class,
            endpoints: Some(endpoints.parse().map_err(|_| "invalid text endpoints")?),
            reason: None,
        })
    } else if let Some(refused) = line.strip_prefix("admission  refused (") {
        let (class, reason) = refused
            .split_once("): ")
            .ok_or("text refusal reason is missing")?;
        Ok(WholeAdmission {
            state: "refused",
            class,
            endpoints: None,
            reason: Some(reason),
        })
    } else if let Some(partial) = line.strip_prefix("admission  partial (") {
        let (class, reason) = partial
            .split_once("): ")
            .ok_or("text partial reason is missing")?;
        // Endpoint partials open with attached counts ("A of N ...");
        // template-table partials carry tables instead of endpoints.
        let endpoints = reason
            .contains("endpoints attached")
            .then(|| {
                reason
                    .split_once(" of ")
                    .and_then(|(attached, _)| attached.parse().ok())
            })
            .flatten();
        Ok(WholeAdmission {
            state: "partial",
            class,
            endpoints,
            reason: Some(reason),
        })
    } else {
        Err(format!("unexpected text admission: {line}"))
    }
}

fn validate_whole_admission(
    admission: WholeAdmission<'_>,
    fixture: WholeFixture,
    wide: bool,
    strict: bool,
) -> Result<(), String> {
    if admission.class != fixture.class {
        return Err(format!("expected {} admission class", fixture.class));
    }
    match admission.state {
        "admitted" if wide => {
            if admission.endpoints != Some(fixture.demand) {
                return Err(format!(
                    "expected the whole {}-endpoint admission, got {:?}",
                    fixture.demand, admission.endpoints
                ));
            }
            Ok(())
        }
        "refused" if !wide || !strict => {
            let reason = admission.reason.ok_or("whole refusal reason is missing")?;
            let capacity = if wide { 2112 } else { 512 };
            if admission.endpoints.is_some()
                || !reason.contains(&format!("module needs {} more", fixture.demand))
                || !reason.contains(&format!("only {capacity} attach slots"))
                || !reason.contains("refusing to attach a prefix")
                || fixture.lookalikes.is_some_and(|tables| {
                    !reason.contains(&format!("prefix of its {tables} lookalike"))
                })
            {
                return Err(format!(
                    "expected a capacity-shaped whole refusal: {reason}"
                ));
            }
            Ok(())
        }
        "partial" if !wide => {
            let endpoints = admission
                .endpoints
                .ok_or("partial admission endpoints are missing")?;
            let reason = admission.reason.ok_or("partial gap reason is missing")?;
            if endpoints == 0
                || endpoints >= fixture.demand
                || !reason.contains(&format!(
                    "{endpoints} of {} endpoints attached",
                    fixture.demand
                ))
                || !reason.contains("(provider_partial)")
            {
                return Err(format!(
                    "expected a named function-level partial gap: {reason}"
                ));
            }
            Ok(())
        }
        _ => Err(format!(
            "unexpected {} admission for wide={wide}, strict={strict}",
            admission.state
        )),
    }
}

// Literal public refusal shapes; no planner or provider-demand computation.
const NSS_WIDE_REFUSAL: &str = "module needs 544 more; only 2112 attach slots are available; 1700 are in use (1700 active, 0 retired) - refusing to attach a prefix";
const CLOSURE_WIDE_REFUSAL: &str = "module needs 532 more; only 2112 attach slots are available; 1207 are in use (1207 active, 0 retired); 528 are reserved for providers with a corroborated function table - refusing to attach a prefix of its 65 lookalike function tables";

#[test]
fn catalog_admission_oracle_accepts_relaxed_wide_whole_refusals() {
    for (fixture, class, reason) in [
        (NSS, "corroborated", NSS_WIDE_REFUSAL),
        (CLOSURE, "closure_array", CLOSURE_WIDE_REFUSAL),
    ] {
        let json = serde_json::json!({ "state": "refused", "class": class, "reason": reason });
        let text = format!(
            "  admission  refused ({class}): {reason} [scan-only admission: manifest corroboration was not consulted]"
        );
        validate_whole_admission(json_whole_admission(&json).unwrap(), fixture, true, false)
            .unwrap();
        validate_whole_admission(text_whole_admission(&text).unwrap(), fixture, true, false)
            .unwrap();
        for invalid_reason in [
            "provider metadata unavailable",
            "module needs 68 more; only 2112 attach slots are available - refusing to attach a prefix",
        ] {
            let json = serde_json::json!({
                "state": "refused", "class": class, "reason": invalid_reason,
            });
            let text = format!(
                "  admission  refused ({class}): {invalid_reason} [scan-only admission: manifest corroboration was not consulted]"
            );
            assert!(
                validate_whole_admission(
                    json_whole_admission(&json).unwrap(),
                    fixture,
                    true,
                    false,
                )
                .is_err()
            );
            assert!(
                validate_whole_admission(
                    text_whole_admission(&text).unwrap(),
                    fixture,
                    true,
                    false,
                )
                .is_err()
            );
        }
    }
}

#[test]
fn catalog_admission_oracle_rejects_strict_wide_refusals() {
    for (fixture, class, reason) in [
        (NSS, "corroborated", NSS_WIDE_REFUSAL),
        (CLOSURE, "closure_array", CLOSURE_WIDE_REFUSAL),
    ] {
        let json = serde_json::json!({ "state": "refused", "class": class, "reason": reason });
        let text = format!(
            "  admission  refused ({class}): {reason} [scan-only admission: manifest corroboration was not consulted]"
        );
        assert!(
            validate_whole_admission(json_whole_admission(&json).unwrap(), fixture, true, true)
                .is_err()
        );
        assert!(
            validate_whole_admission(text_whole_admission(&text).unwrap(), fixture, true, true)
                .is_err()
        );
    }
}

#[test]
fn catalog_admission_oracle_rejects_admitted_prefixes() {
    for (fixture, class, endpoints) in [(NSS, "corroborated", 68), (CLOSURE, "closure_array", 20)] {
        let json =
            serde_json::json!({ "state": "admitted", "class": class, "endpoints": endpoints });
        let text = format!(
            "  admission  profile/run would watch {endpoints} functions (class {class}; scan only: names below come from the files themselves)"
        );
        for strict in [false, true] {
            assert!(
                validate_whole_admission(
                    json_whole_admission(&json).unwrap(),
                    fixture,
                    true,
                    strict,
                )
                .is_err()
            );
            assert!(
                validate_whole_admission(
                    text_whole_admission(&text).unwrap(),
                    fixture,
                    true,
                    strict,
                )
                .is_err()
            );
        }
    }
}

#[test]
fn catalog_closure_admission_accepts_prefix_gap_only_when_relaxed() {
    let reason = "33 of 65 template tables attached; calls through the others are not counted (closure_prefix)";
    let json =
        serde_json::json!({ "state": "refused", "class": "closure_array", "reason": reason });
    let text = format!(
        "  admission  refused (closure_array): {reason} [scan-only admission: manifest corroboration was not consulted]"
    );
    for wide in [false, true] {
        validate_closure_admission(json_whole_admission(&json).unwrap(), CLOSURE, wide, false)
            .unwrap();
        validate_closure_admission(text_whole_admission(&text).unwrap(), CLOSURE, wide, false)
            .unwrap();
        assert!(
            validate_closure_admission(json_whole_admission(&json).unwrap(), CLOSURE, wide, true,)
                .is_err()
        );
        assert!(
            validate_closure_admission(text_whole_admission(&text).unwrap(), CLOSURE, wide, true,)
                .is_err()
        );
    }
}

#[test]
fn catalog_partial_admission_accepts_prefix_shapes_with_counts() {
    // The producer files a prefix-admitted object as partial with its
    // attached count; the oracle must read that shape in both
    // renderings, for closure and provider prefixes alike.
    let closure_reason = "33 of 65 template tables attached; calls through the others are not counted (closure_prefix)";
    let closure_json = serde_json::json!({
        "state": "partial", "class": "closure_array",
        "endpoints": 3399, "reason": closure_reason,
    });
    let closure_text =
        format!("  admission  partial (closure_array): {closure_reason} [scan-only admission]");
    for wide in [false, true] {
        for strict in [false, true] {
            validate_closure_admission(
                json_whole_admission(&closure_json).unwrap(),
                CLOSURE,
                wide,
                strict,
            )
            .unwrap();
            validate_closure_admission(
                text_whole_admission(&closure_text).unwrap(),
                CLOSURE,
                wide,
                strict,
            )
            .unwrap();
        }
    }
    // A provider prefix reads the same way: partial state plus the
    // attached count in JSON, partial verb in text. Both renderings
    // must parse (the text verb is new) and keep their counts.
    let provider_reason =
        "300 of 600 endpoints attached; calls through the others are not counted (provider_prefix)";
    let provider_json = serde_json::json!({
        "state": "partial", "class": "heuristic",
        "endpoints": 300, "reason": provider_reason,
    });
    let provider = json_whole_admission(&provider_json).unwrap();
    assert_eq!(provider.state, "partial");
    assert_eq!(provider.endpoints, Some(300));
    let provider_text =
        format!("  admission  partial (heuristic): {provider_reason} [scan-only admission]");
    let parsed = text_whole_admission(&provider_text).unwrap();
    assert_eq!(parsed.state, "partial");
    assert_eq!(parsed.class, "heuristic");
}

#[test]
fn catalog_reader_keeps_partial_export_tables_useful_but_heuristic() {
    let _guard = serial_guard();
    let dir = tmp("catalog-reader-partial-exports");
    let fixtures = build_fixtures(&dir, false);
    let run = dance(&fixtures, true);
    let b = object_for(run.json.as_ref().unwrap(), &run.pids, "prov.so");
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
    assert_eq!(b["admission"]["class"], "heuristic");
    assert_eq!(b["admission"]["scan_only"], true);
    match b["admission"]["state"].as_str() {
        Some("admitted") => assert_eq!(b["admission"]["endpoints"], 92),
        Some("partial") => {
            // A corroborated provider partial may crowd B out even in
            // strict mode; the gap stays named with counts either way.
            assert!(b["admission"]["endpoints"].as_u64().unwrap() > 0);
            let reason = b["admission"]["reason"].as_str().unwrap();
            assert!(
                reason.contains("endpoints attached")
                    && (reason.contains("(provider_prefix)")
                        || reason.contains("(provider_partial)")),
                "B partial must be a named prefix/partial gap with counts: {reason}"
            );
        }
        Some("refused") => {
            assert!(b["admission"]["endpoints"].is_null());
            let reason = b["admission"]["reason"].as_str().unwrap();
            assert!(
                reason.contains("attach slots")
                    || (reason.contains("endpoints attached")
                        && (reason.contains("(provider_prefix)")
                            || reason.contains("(provider_partial)"))),
                "B refusal must be capacity-shaped or a named prefix/partial gap: {reason}"
            );
        }
        state => panic!("unexpected partial-export admission: {state:?}"),
    }
}

#[test]
fn catalog_reader_finds_every_fixture_object() {
    let _guard = serial_guard();
    let dir = tmp("catalog-reader");
    let fixtures = build_fixtures(&dir, true);
    let strict = strict_admission();
    let wide = cfg!(feature = "wide-detailed-2112");

    // ---- JSON dance: the full strict read. ----
    let mut run = dance(&fixtures, true);
    let doc = run.json.as_ref().unwrap();
    assert_eq!(doc["schema"], "p11scope/inspect-system/v1");
    assert_eq!(doc["scope"], "system");
    assert_eq!(doc["admission"]["policy"], "detailed");
    assert_eq!(doc["admission"]["scope"], "shared");
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
    // 3.0 table's 92 matching standard exports corroborate the object.
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
    // Live competition decides B's fate: admitted whole with room, a
    // named partial gap when crowded, or a capacity-shaped refusal when
    // even tier-0 does not fit. Each state keeps its shape pins.
    match b["admission"]["state"].as_str() {
        Some("admitted") => assert_eq!(b["admission"]["endpoints"], 92),
        Some("partial") => {
            let endpoints = b["admission"]["endpoints"].as_u64().unwrap();
            assert!(endpoints > 0 && endpoints < 92);
            let reason = b["admission"]["reason"].as_str().unwrap();
            assert!(
                reason.contains(&format!("{endpoints} of 92 endpoints attached"))
                    && (reason.contains("(provider_prefix)")
                        || reason.contains("(provider_partial)")),
                "B partial must be a named gap with counts: {reason}"
            );
        }
        Some("refused") => {
            assert!(
                b["admission"]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("attach slots"),
                "B refusal must still be capacity-shaped"
            );
        }
        state => panic!("unexpected B admission: {state:?}"),
    }

    // A: same-path dance, V1 bytes. The kernel marks the replaced
    // mapping deleted: A's running copy is uncounted loss (a skipped
    // gap), never a module and never conflated into B's edge.
    for object in doc["objects"].as_array().unwrap() {
        for observation in object["observations"].as_array().unwrap() {
            assert_ne!(
                observation["pid"],
                pid_of(&run.pids, "A"),
                "the deleted V1 mapping must contribute no observation"
            );
        }
    }
    let a_gap = doc["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .find(|gap| gap["pid"] == pid_of(&run.pids, "A"))
        .expect("A must leave a replaced-file gap");
    assert!(
        a_gap["subject"].as_str().unwrap().contains("(deleted)"),
        "A gap must name the deleted path: {a_gap}"
    );
    assert_eq!(
        a_gap["reason"],
        "replaced on disk while running; not examined, calls not counted"
    );

    // N: eight interface-linked tables (publication evidence), with 544
    // distinct physical endpoints. Default attaches the most important
    // endpoints as a named function-level partial gap (or refuses the
    // whole object when even tier-0 does not fit); strict wide must
    // admit the complete union, never a strongest-table prefix; relaxed
    // wide may instead report a whole capacity refusal.
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
    assert_eq!(n["admission"]["class"], "corroborated");
    validate_whole_admission(
        json_whole_admission(&n["admission"]).unwrap(),
        NSS,
        wide,
        strict,
    )
    .unwrap();

    // C: 65 bare heuristic tables, no triples, 532 distinct endpoints.
    // The 532-target union exceeds the 104-target whole bound, so the
    // layer stays published-only with none of its 65 tables published.
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
    assert_eq!(c["admission"]["class"], "closure_array");
    validate_closure_admission(
        json_whole_admission(&c["admission"]).unwrap(),
        CLOSURE,
        wide,
        strict,
    )
    .unwrap();

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
    // Live competition decides MW's fate: a corroborated provider
    // partial may crowd it out entirely. Each state keeps its shape.
    match m["admission"]["state"].as_str() {
        Some("admitted") => assert_eq!(m["admission"]["endpoints"], 27),
        Some("partial") => {
            let endpoints = m["admission"]["endpoints"].as_u64().unwrap();
            assert!(endpoints > 0 && endpoints < 27);
            let reason = m["admission"]["reason"].as_str().unwrap();
            assert!(
                reason.contains(&format!("{endpoints} of 27 endpoints attached"))
                    && (reason.contains("(provider_prefix)")
                        || reason.contains("(provider_partial)")),
                "MW partial must be a named gap with counts: {reason}"
            );
        }
        Some("refused") => {
            assert!(
                m["admission"]["reason"]
                    .as_str()
                    .unwrap()
                    .contains("attach slots"),
                "MW refusal must still be capacity-shaped"
            );
        }
        state => panic!("unexpected MW admission: {state:?}"),
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
    // object carries a state and a class, default refusals are counted.
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
    assert_eq!(doc["admission"]["partial"], in_state("partial"));
    assert_eq!(doc["admission"]["refused"], in_state("refused"));
    if !wide {
        assert!(doc["admission"]["refused"].as_u64().unwrap() >= 2);
    }
    // Fixture-owned admissions only: an ambient same-uid process keeps its
    // maps readable under ptrace_scope=1, so a desktop's libp11-kit is
    // cataloged and admitted at 0 endpoints, while a hosted runner maps
    // none. N is a default partial-or-refusal and a strict wide
    // whole-admission; C is refused; T/H have zero endpoints and always
    // fit. B/M/N/C, like wide N/C, may lose room to live competition or
    // to an earlier corroborated partial, so only T/H are counted here —
    // every other fixture keeps its per-object shape pins above.
    assert_eq!(h["admission"]["state"], "admitted");
    assert_eq!(t["admission"]["state"], "admitted");
    let fixture_admitted = [b, m, t, h, n, c]
        .iter()
        .filter(|object| object["admission"]["state"] == "admitted")
        .count();
    let fixture_covered = [b, m, t, h, n, c]
        .iter()
        .filter(|object| {
            object["admission"]["state"] == "admitted" || object["admission"]["state"] == "partial"
        })
        .count();
    // T/H (zero endpoints) always admitted; B/M/N each admitted, partial,
    // or capacity-shaped refused (pinned per object above) depending on
    // live competition and earlier corroborated partials; C refused. The
    // strict-wide whole-admission pin is unchanged: partial never fires
    // when everything fits.
    if strict && wide {
        assert_eq!(
            fixture_admitted, 5,
            "B, M, T, H and N must be admitted in the wide profile; C stays refused (awaiting publication)"
        );
    } else {
        assert!(fixture_covered >= 2, "at least T/H must be admitted");
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
        "  admission  ",
        "alias object",
        "(deleted)",
        "names below come from the files themselves",
    ] {
        assert!(
            text.contains(fragment),
            "text rendering must carry {fragment:?}"
        );
    }
    // Read each fixture's own object block: ambient objects must never
    // satisfy the NSS/closure text admission checks.
    for (name, fixture) in [("nss.so", NSS), ("closure.so", CLOSURE)] {
        let path = fixtures.dir.join(name);
        let block = text
            .split("object[")
            .find(|block| {
                block
                    .lines()
                    .next()
                    .is_some_and(|header| header.ends_with(path.to_str().unwrap()))
            })
            .unwrap_or_else(|| panic!("text must contain the {name} object block: {text}"));
        let admission = text_whole_admission(block).unwrap();
        if name == "closure.so" {
            validate_closure_admission(admission, fixture, wide, strict)
                .unwrap_or_else(|error| panic!("{name} text admission: {error}: {block}"));
        } else {
            validate_whole_admission(admission, fixture, wide, strict)
                .unwrap_or_else(|error| panic!("{name} text admission: {error}: {block}"));
        }
    }
    for phase in ["enumerating", "deep-scanning", "rendering"] {
        assert!(
            text_run.stderr.contains(phase),
            "text stderr must show startup progress ({phase})"
        );
    }
}
