//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned multi-wrapper fixture provider + workload oracle: self-tests.
//!
//! The C fixture under `tests/fixtures/multi-wrapper/` models the p11-kit
//! fixed-closure shape (64 template tables, heap published wrappers with
//! first-free allocation, direct backend forwarding) and ships a seeded
//! workload that writes the exact oracle for every scenario. These tests
//! pin the fixture to its oracle: log bytes must equal `expected` exactly,
//! structural invariants (holes, indices, forwarding, failure, nesting,
//! legacy silence, stripped layout flag) must hold, and golden totals must
//! match. Tasks 1.4/1.5/1.6 consume the same binaries + oracle schema as
//! ground truth for observed-vs-expected attach/discovery assertions; see
//! `tests/fixtures/multi-wrapper/README.md`.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

// Pinned workload totals (scenario, seed) -> (total, wrapper, backend).
// Regenerate with the workload binary; pinned so any behavior drift in the
// provider, backend, or workload breaks loudly instead of shifting silently.
const GOLDEN_FIVE_0: (usize, usize, usize) = (120, 60, 60);
const GOLDEN_FIVE_1_TOTAL: usize = 106;
const GOLDEN_HOLES_0: usize = 26;
const GOLDEN_REUSE_0: usize = 28;
const GOLDEN_PAIR_A_0: usize = 52;
const GOLDEN_PAIR_B_0: usize = 52;
const GOLDEN_FORWARD_0: (usize, usize, usize) = (20, 7, 13);
const GOLDEN_FAIL_0: (usize, usize, usize) = (23, 13, 10);

const EXERCISED: [&str; 6] = [
    "C_Initialize",
    "C_GetSlotList",
    "C_OpenSession",
    "C_Login",
    "C_Sign",
    "C_SignUpdate",
];

#[derive(Clone)]
struct Build {
    provider: PathBuf,
    stripped: PathBuf,
    workload: PathBuf,
}

fn shared_build() -> Build {
    static LOCK: Mutex<()> = Mutex::new(());
    static DONE: OnceLock<Build> = OnceLock::new();
    let _guard = LOCK.lock().unwrap();
    DONE.get_or_init(|| {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi-wrapper");
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("mw-shared");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let backend = dir.join("backend.so");
        let provider = dir.join("provider.so");
        let stripped = dir.join("provider-stripped.so");
        let workload = dir.join("workload");
        let backend_c = fixture.join("backend.c").into_os_string();
        let provider_c = fixture.join("provider.c").into_os_string();
        let workload_c = fixture.join("workload.c").into_os_string();
        let backend_so = backend.clone().into_os_string();
        let provider_so = provider.clone().into_os_string();
        let stripped_so = stripped.clone().into_os_string();
        let workload_bin = workload.clone().into_os_string();
        let common = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC"];
        let mut args: Vec<&str> = common.to_vec();
        args.extend(["-shared", "-Wl,-z,defs", "-o"]);
        let mut full: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
        full.extend([backend_so.clone(), backend_c]);
        gcc_os(&full);
        let mut full: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
        full.extend([provider_so, provider_c.clone(), backend_so.clone()]);
        gcc_os(&full);
        let mut sargs: Vec<std::ffi::OsString> =
            common.iter().map(std::ffi::OsString::from).collect();
        sargs.push("-DSTRIPPED_VARIANT=1".into());
        sargs.extend(["-shared".into(), "-Wl,-z,defs".into(), "-o".into()]);
        sargs.extend([stripped_so, provider_c, backend_so]);
        gcc_os(&sargs);
        let output = Command::new("strip")
            .arg("--strip-all")
            .arg(&stripped)
            .output()
            .expect("spawn strip");
        assert!(
            output.status.success(),
            "strip failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut wargs: Vec<std::ffi::OsString> =
            common.iter().map(std::ffi::OsString::from).collect();
        wargs.extend(["-o".into(), workload_bin, workload_c, "-ldl".into()]);
        gcc_os(&wargs);
        Build {
            provider,
            stripped,
            workload,
        }
    })
    .clone()
}

fn gcc_os(args: &[std::ffi::OsString]) {
    let rest: Vec<&std::ffi::OsStr> = args.iter().map(AsRef::as_ref).collect();
    let output = Command::new("gcc").args(&rest).output().expect("spawn gcc");
    assert!(
        output.status.success(),
        "gcc failed ({rest:?}): {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn tmp(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Run one workload scenario; returns the parsed oracle JSON.
fn run_case(
    build: &Build,
    provider: &Path,
    scenario: &str,
    seed: u64,
    log: &Path,
    oracle: &Path,
) -> serde_json::Value {
    let output = Command::new(&build.workload)
        .arg(provider)
        .arg(scenario)
        .arg(seed.to_string())
        .arg(log)
        .arg(oracle)
        .output()
        .expect("spawn workload");
    assert!(
        output.status.success(),
        "workload {scenario} seed {seed} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = std::fs::read_to_string(oracle).expect("read oracle");
    serde_json::from_str(&text).expect("parse oracle JSON")
}

fn read_lines(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(text) => text.lines().map(str::to_string).collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => panic!("read {}: {error}", path.display()),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    pid: i64,
    tid: i64,
    layer: String,
    func: String,
    idx: u64,
    via: String,
    rv: u64,
}

impl Record {
    fn parse(line: &str) -> Record {
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(parts.len(), 7, "malformed log line: {line}");
        Record {
            pid: parts[0].parse().unwrap(),
            tid: parts[1].parse().unwrap(),
            layer: parts[2].to_string(),
            func: parts[3].to_string(),
            idx: parts[4].parse().unwrap(),
            via: parts[5].to_string(),
            rv: parts[6].parse().unwrap(),
        }
    }

    fn key(&self) -> String {
        format!(
            "{} {} {} {} {}",
            self.layer, self.func, self.idx, self.via, self.rv
        )
    }
}

/// Core oracle contract: the log lines for this pid equal `expected` byte
/// for byte, the recomputed per-key counts equal `counts`, and `total`
/// matches. Every scenario test starts here.
fn assert_exact_oracle(log: &[String], oracle: &serde_json::Value) -> Vec<Record> {
    let pid = oracle["pid"].as_i64().expect("oracle pid");
    let expected: Vec<String> = oracle["expected"]
        .as_array()
        .expect("oracle expected")
        .iter()
        .map(|value| value.as_str().expect("expected line").to_string())
        .collect();
    let actual: Vec<String> = log
        .iter()
        .filter(|line| Record::parse(line).pid == pid)
        .cloned()
        .collect();
    assert_eq!(actual, expected, "log bytes must equal the oracle exactly");
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut records = Vec::new();
    for line in &actual {
        let record = Record::parse(line);
        *counts.entry(record.key()).or_insert(0) += 1;
        records.push(record);
    }
    let oracle_counts: BTreeMap<String, usize> = oracle["counts"]
        .as_object()
        .expect("oracle counts")
        .iter()
        .map(|(key, value)| (key.clone(), value.as_u64().expect("count") as usize))
        .collect();
    assert_eq!(counts, oracle_counts, "recomputed counts must match oracle");
    assert_eq!(
        actual.len(),
        oracle["total"].as_u64().expect("oracle total") as usize,
        "oracle total must match"
    );
    records
}

fn layer_totals(records: &[Record]) -> (usize, usize, usize, usize) {
    let mut wrapper = 0;
    let mut backend = 0;
    let mut legacy = 0;
    let mut shared = 0;
    for record in records {
        match record.layer.as_str() {
            "wrapper" => wrapper += 1,
            "backend" => backend += 1,
            "legacy" => legacy += 1,
            "shared" => shared += 1,
            other => panic!("unknown layer {other}"),
        }
    }
    (wrapper, backend, legacy, shared)
}

/// Every successful wrapper entry is immediately followed by its nested
/// backend entry (same func/idx/tid); every nested backend is immediately
/// preceded by its wrapper. Single-threaded workload, so adjacency is exact.
fn assert_nested_pairing(records: &[Record]) {
    assert!(!records.is_empty(), "pairing needs records");
    for window in records.windows(2) {
        if window[0].layer == "wrapper" && window[0].rv == 0 {
            assert_eq!(
                window[1].layer, "backend",
                "wrapper must nest backend: {window:?}"
            );
            assert_eq!(window[1].func, window[0].func);
            assert_eq!(window[1].idx, window[0].idx);
            assert_eq!(window[1].tid, window[0].tid);
            assert_eq!(window[1].via, "nested");
            assert_eq!(window[1].rv, 0);
        }
    }
    for window in records.windows(2) {
        if window[1].layer == "backend" && window[1].via == "nested" {
            assert_eq!(
                window[0].layer, "wrapper",
                "nested backend needs wrapper: {window:?}"
            );
            assert_eq!(window[0].func, window[1].func);
            assert_eq!(window[0].idx, window[1].idx);
        }
    }
    for record in records {
        assert_eq!(record.tid, record.pid, "workload is single-threaded");
    }
}

#[test]
fn five_wrappers_activate_index_beyond_3() {
    let build = shared_build();
    let dir = tmp("mw-five");
    let log = dir.join("five.log");
    let oracle_path = dir.join("five.oracle.json");
    let oracle = run_case(&build, &build.provider, "five", 0, &log, &oracle_path);
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    let mut indices: Vec<u64> = records
        .iter()
        .filter(|record| record.layer == "wrapper")
        .map(|record| record.idx)
        .collect();
    indices.sort_unstable();
    indices.dedup();
    assert!(
        indices.len() >= 5,
        "need >=5 published wrappers: {indices:?}"
    );
    assert!(
        *indices.iter().max().unwrap() > 3,
        "active index must exceed 3"
    );
    assert_eq!(indices, vec![0, 1, 2, 3, 4]);
    let (wrapper, backend, legacy, shared) = layer_totals(&records);
    assert_eq!((records.len(), wrapper, backend), GOLDEN_FIVE_0);
    assert_eq!((legacy, shared), (0, 0), "no legacy/shared calls in five");
    assert_nested_pairing(&records);
    assert_eq!(oracle["build_variant"].as_str().unwrap(), "normal");
    assert!(oracle["layout_known"].as_bool().unwrap());
}

#[test]
fn holes_keep_index_17_active_with_0_to_3_free() {
    let build = shared_build();
    let dir = tmp("mw-holes");
    let log = dir.join("holes.log");
    let oracle_path = dir.join("holes.oracle.json");
    let oracle = run_case(&build, &build.provider, "holes", 0, &log, &oracle_path);
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    let mut indices: Vec<u64> = records.iter().map(|record| record.idx).collect();
    indices.sort_unstable();
    indices.dedup();
    assert_eq!(indices, vec![17], "only index 17 is active");
    let free: Vec<i64> = oracle["free_at_call"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_i64().unwrap())
        .collect();
    for free_idx in 0..4 {
        assert!(
            free.contains(&free_idx),
            "index {free_idx} must be free: {free:?}"
        );
    }
    let occupied: Vec<i64> = oracle["occupied_at_call"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_i64().unwrap())
        .collect();
    assert_eq!(occupied, vec![17]);
    assert_eq!(records.len(), GOLDEN_HOLES_0);
    assert_nested_pairing(&records);
}

#[test]
fn freed_index_is_reused_first() {
    let build = shared_build();
    let dir = tmp("mw-reuse");
    let log = dir.join("reuse.log");
    let oracle_path = dir.join("reuse.oracle.json");
    let oracle = run_case(&build, &build.provider, "reuse", 0, &log, &oracle_path);
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    assert_eq!(
        oracle["reused"].as_i64().unwrap(),
        0,
        "first free index wins"
    );
    let mut indices: Vec<u64> = records.iter().map(|record| record.idx).collect();
    indices.sort_unstable();
    indices.dedup();
    assert_eq!(indices, vec![0, 17]);
    assert_eq!(records.len(), GOLDEN_REUSE_0);
    assert_nested_pairing(&records);
}

#[test]
fn two_processes_use_different_indices_of_one_inode() {
    use std::os::unix::fs::MetadataExt as _;
    let build = shared_build();
    let dir = tmp("mw-pair");
    let log = dir.join("pair.log");
    let oracle_a = dir.join("pair-a.oracle.json");
    let oracle_b = dir.join("pair-b.oracle.json");
    // Same provider inode for both processes; the point of the lane.
    let metadata = std::fs::metadata(&build.provider).unwrap();
    let (dev, ino) = (metadata.dev(), metadata.ino());
    let oracle_a = run_case(&build, &build.provider, "pair_a", 0, &log, &oracle_a);
    let after_a = std::fs::metadata(&build.provider).unwrap();
    let oracle_b = run_case(&build, &build.provider, "pair_b", 0, &log, &oracle_b);
    assert_eq!((after_a.dev(), after_a.ino()), (dev, ino), "same inode");
    let lines = read_lines(&log);
    let records_a = assert_exact_oracle(&lines, &oracle_a);
    let records_b = assert_exact_oracle(&lines, &oracle_b);
    assert_ne!(
        oracle_a["pid"].as_i64().unwrap(),
        oracle_b["pid"].as_i64().unwrap(),
        "two distinct processes"
    );
    let mut indices_a: Vec<u64> = records_a.iter().map(|record| record.idx).collect();
    indices_a.sort_unstable();
    indices_a.dedup();
    let mut indices_b: Vec<u64> = records_b.iter().map(|record| record.idx).collect();
    indices_b.sort_unstable();
    indices_b.dedup();
    assert_eq!(indices_a, vec![0, 1]);
    assert_eq!(indices_b, vec![5, 6]);
    assert_eq!(records_a.len(), GOLDEN_PAIR_A_0);
    assert_eq!(records_b.len(), GOLDEN_PAIR_B_0);
    assert_eq!(lines.len(), GOLDEN_PAIR_A_0 + GOLDEN_PAIR_B_0);
}

#[test]
fn direct_backend_forwarding_skips_the_wrapper_layer() {
    let build = shared_build();
    let dir = tmp("mw-forward");
    let log = dir.join("forward.log");
    let oracle_path = dir.join("forward.oracle.json");
    let oracle = run_case(&build, &build.provider, "forward", 0, &log, &oracle_path);
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    let (wrapper, backend, legacy, shared) = layer_totals(&records);
    assert_eq!((records.len(), wrapper, backend), GOLDEN_FORWARD_0);
    assert_eq!((legacy, shared), (0, 0));
    for func in ["C_GetSlotList", "C_Sign"] {
        let direct = records
            .iter()
            .filter(|record| {
                record.layer == "backend" && record.func == func && record.via == "direct"
            })
            .count();
        assert_eq!(direct, 3, "{func} must forward directly, 3 calls");
        assert!(
            !records
                .iter()
                .any(|record| record.layer == "wrapper" && record.func == func),
            "{func} must have no wrapper record"
        );
    }
    for record in &records {
        if record.layer == "backend" && record.via == "nested" {
            assert!(
                !["C_GetSlotList", "C_Sign"].contains(&record.func.as_str()),
                "forwarded funcs never nest: {record:?}"
            );
        }
    }
    // Non-forwarded funcs still pair wrapper -> nested backend.
    let paired: Vec<Record> = records
        .iter()
        .filter(|record| !["C_GetSlotList", "C_Sign"].contains(&record.func.as_str()))
        .cloned()
        .collect();
    assert_nested_pairing(&paired);
}

#[test]
fn wrapper_only_failure_returns_error_without_backend() {
    let build = shared_build();
    let dir = tmp("mw-fail");
    let log = dir.join("fail.log");
    let oracle_path = dir.join("fail.oracle.json");
    let oracle = run_case(&build, &build.provider, "fail", 0, &log, &oracle_path);
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    let (wrapper, backend, legacy, shared) = layer_totals(&records);
    assert_eq!((records.len(), wrapper, backend), GOLDEN_FAIL_0);
    assert_eq!((legacy, shared), (0, 0));
    let failures: Vec<&Record> = records
        .iter()
        .filter(|record| record.layer == "wrapper" && record.func == "C_Sign")
        .collect();
    assert_eq!(failures.len(), 3);
    for failure in &failures {
        assert_eq!(failure.rv, 0x30, "CKR_DEVICE_ERROR");
    }
    assert!(
        !records
            .iter()
            .any(|record| record.layer == "backend" && record.func == "C_Sign"),
        "failed wrapper must not reach the backend"
    );
    let paired: Vec<Record> = records
        .iter()
        .filter(|record| record.func != "C_Sign")
        .cloned()
        .collect();
    assert_nested_pairing(&paired);
}

#[test]
fn nested_wrapper_backend_calls_pair_exactly_on_another_seed() {
    let build = shared_build();
    let dir = tmp("mw-nested");
    let log = dir.join("nested.log");
    let oracle_path = dir.join("nested.oracle.json");
    let oracle = run_case(&build, &build.provider, "five", 1, &log, &oracle_path);
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    assert_eq!(records.len(), GOLDEN_FIVE_1_TOTAL);
    assert_eq!(oracle["seed"].as_u64().unwrap(), 1);
    assert_nested_pairing(&records);
    // Per (func, idx) the wrapper and nested-backend counts agree exactly.
    for func in EXERCISED {
        for idx in 0..5 {
            let wrappers = records
                .iter()
                .filter(|record| {
                    record.layer == "wrapper" && record.func == func && record.idx == idx
                })
                .count();
            let backends = records
                .iter()
                .filter(|record| {
                    record.layer == "backend"
                        && record.func == func
                        && record.idx == idx
                        && record.via == "nested"
                })
                .count();
            assert!(wrappers > 0, "{func} idx {idx} must be called");
            assert_eq!(wrappers, backends, "{func} idx {idx} must pair 1:1");
        }
    }
}

#[test]
fn legacy_static_table_is_published_but_never_called() {
    let build = shared_build();
    let dir = tmp("mw-legacy");
    let log = dir.join("legacy.log");
    let oracle_path = dir.join("legacy.oracle.json");
    let oracle = run_case(&build, &build.provider, "legacy", 0, &log, &oracle_path);
    assert!(oracle["legacy"]["published"].as_bool().unwrap());
    assert_eq!(oracle["legacy"]["major"].as_i64().unwrap(), 2);
    assert_eq!(oracle["legacy"]["minor"].as_i64().unwrap(), 40);
    assert_eq!(oracle["total"].as_u64().unwrap(), 0);
    assert!(oracle["expected"].as_array().unwrap().is_empty());
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    assert!(
        records.is_empty(),
        "legacy workload emits zero call records"
    );
}

#[test]
fn stripped_build_is_unknown_layout_with_identical_counts() {
    let build = shared_build();
    let dynamic = Command::new("nm")
        .args(["-D", build.provider.to_str().unwrap()])
        .output()
        .expect("spawn nm");
    let dynamic = String::from_utf8_lossy(&dynamic.stdout);
    for symbol in ["p11scope_fixed", "C_GetFunctionList", "mw_alloc"] {
        assert!(dynamic.contains(symbol), "normal build exports {symbol}");
    }
    let stripped = Command::new("nm")
        .arg(build.stripped.to_str().unwrap())
        .output()
        .expect("spawn nm");
    let stripped_text = String::from_utf8_lossy(&stripped.stdout);
    assert!(
        !stripped_text.contains("p11scope_fixed"),
        "stripped build hides the pool"
    );
    let dir = tmp("mw-stripped");
    let log = dir.join("stripped.log");
    let oracle_path = dir.join("stripped.oracle.json");
    let oracle = run_case(&build, &build.stripped, "five", 0, &log, &oracle_path);
    assert_eq!(oracle["build_variant"].as_str().unwrap(), "stripped");
    assert!(!oracle["layout_known"].as_bool().unwrap());
    let records = assert_exact_oracle(&read_lines(&log), &oracle);
    assert_eq!(records.len(), GOLDEN_FIVE_0.0);
    // Same workload, same seed: counts are build-invariant.
    let dir = tmp("mw-stripped-normal");
    let normal_log = dir.join("normal.log");
    let normal_oracle = dir.join("normal.oracle.json");
    let normal = run_case(
        &build,
        &build.provider,
        "five",
        0,
        &normal_log,
        &normal_oracle,
    );
    assert_eq!(oracle["counts"], normal["counts"]);
}

#[test]
fn workload_is_deterministic_for_a_fixed_seed() {
    let build = shared_build();
    let dir = tmp("mw-determinism");
    let log_a = dir.join("a.log");
    let log_b = dir.join("b.log");
    let oracle_a = dir.join("a.oracle.json");
    let oracle_b = dir.join("b.oracle.json");
    let parsed_a = run_case(&build, &build.provider, "five", 0, &log_a, &oracle_a);
    let parsed_b = run_case(&build, &build.provider, "five", 0, &log_b, &oracle_b);
    assert_exact_oracle(&read_lines(&log_a), &parsed_a);
    assert_exact_oracle(&read_lines(&log_b), &parsed_b);
    // Pids differ across runs; everything else must be byte-identical.
    let normalize = |lines: Vec<String>| {
        lines
            .iter()
            .map(|line| {
                let record = Record::parse(line);
                format!(
                    "0 0 {} {} {} {} {}",
                    record.layer, record.func, record.idx, record.via, record.rv
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(normalize(read_lines(&log_a)), normalize(read_lines(&log_b)));
    assert_eq!(parsed_a["counts"], parsed_b["counts"]);
    assert_eq!(parsed_a["total"], parsed_b["total"]);
}
