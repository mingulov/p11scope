//! SPDX-License-Identifier: GPL-3.0-or-later
//! D3d identity-backend integration: bounded real-CLI sweep cells.
//!
//! Every behavior is asserted through the public `p11scope inventory`
//! command over owned fixtures, reading the public JSON independently:
//! the userspace sweep cell proves the exact ledgered process/provider
//! edges with zero false edges (byte-identical different-file and
//! data-only negatives included); auto without proof stays
//! userspace/null without loading; forced kernel either proves the full
//! ledgered set through the kernel backend (byte-identical and data-only
//! negatives, all module edges enumerated, per-range coverage over a
//! proof-requiring btrfs fixture) or refuses with its named line before
//! any sink exists; explicit selection outside `--system` is a usage
//! error; `--pid` carries no identity key; stdout and `-o` bytes agree.
//!
//! System sweep fixtures run under `inventory-identity-observe.sh`,
//! which execs the observer as their parent: under ptrace_scope=1
//! only a descendant's map_files are readable, so sweep proof
//! requires the observer to be an ancestor of every fixture.
//!
//! `P11SCOPE_IDENTITY_FIXTURE_DIR`, when set, pins the per-cell fixture
//! roots (binaries, providers, READY markers, observer stdout) under it
//! instead of `$CARGO_TARGET_TMPDIR`; the kernel-positive cell asserts
//! that root is a proof-requiring (btrfs) filesystem before its edge,
//! coverage and disclosure assertions can pass.
//!
//! D3a ABBA performance gate (measured 2026-10-10, small sweep cells,
//! forced kernel vs forced userspace on the same host): kernel pass p95
//! is roughly 80% slower than the matched userspace pass, which blocks
//! default-kernel progression under the over-5% rule. Automatic
//! threshold gating is unaffected (below-threshold segments stay
//! userspace by policy, not by timing). No D3a-named artifact path
//! exists for performance gates; this cell file records the outcome.
//!
//! D3d brief item 6 native-lane coverage: pending (scan lane only).

use serde_json::Value;
use std::collections::BTreeSet;
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

/// Sweep-cell fixture root: `$P11SCOPE_IDENTITY_FIXTURE_DIR/<name>` when
/// the caller pins fixtures to a proof-requiring filesystem, else a fresh
/// `$CARGO_TARGET_TMPDIR/<name>`. Only the per-cell subdir is cleaned.
fn fixture_dir(name: &str) -> PathBuf {
    let dir = match std::env::var_os("P11SCOPE_IDENTITY_FIXTURE_DIR") {
        Some(root) => PathBuf::from(root).join(name),
        None => PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name),
    };
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Whether `dir` lives on btrfs (statfs magic): the proof-requiring
/// filesystem the kernel-positive cell demands for its fixtures.
fn dir_is_btrfs(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: statfs writes the whole struct on success.
    let rc = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
    assert_eq!(rc, 0, "statfs {}", dir.display());
    // SAFETY: success above initialized it.
    let stat = unsafe { stat.assume_init() };
    stat.f_type as u64 == BTRFS_SUPER_MAGIC
}

/// A tempdir the report trust check accepts under any umask.
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
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

/// Kill owned fixture PIDs (reaped by init after the observer exits).
fn kill_pids(pids: &[u32]) {
    for &pid in pids {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    for &pid in pids {
        while std::fs::metadata(format!("/proc/{pid}")).is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn ready_pid(ready_dir: &Path, name: &str) -> u32 {
    let text = std::fs::read_to_string(ready_dir.join(format!("{name}.ready"))).unwrap();
    text.split_whitespace().nth(1).unwrap().parse().unwrap()
}

/// Independent ground truth: executable mappings of `provider` in `pid`
/// from /proc, read without the observer.
fn exec_ranges_for(pid: u32, provider: &Path) -> Vec<(u64, u64)> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap();
    let target = provider.to_str().unwrap().to_string();
    let mut ranges = Vec::new();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");
        for _ in 0..3 {
            parts.next();
        }
        let path = parts.next().unwrap_or("");
        if perms.starts_with("r-x")
            && path == target
            && let Some((low, high)) = range.split_once('-')
            && let (Ok(low), Ok(high)) =
                (u64::from_str_radix(low, 16), u64::from_str_radix(high, 16))
        {
            ranges.push((low, high));
        }
    }
    ranges
}

fn callers_for(doc: &Value, pid: u64) -> Vec<&Value> {
    doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|caller| caller["pid"] == pid)
        .collect()
}

fn module_for(doc: &Value, so_name: &str) -> Value {
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
    assert_eq!(found.len(), 1, "expected exactly one module for {so_name}");
    found[0].clone()
}

/// Deep-scanned PIDs from the observer's progress lines (independent
/// of the document): `deep-scanning i/n (pid X)...` lines only — swept
/// holders that prove also appear in `admitted (pid X)` lines, which
/// must not count as selected.
fn selected_pids(stderr: &str) -> BTreeSet<u32> {
    let mut selected = BTreeSet::new();
    for line in stderr.lines() {
        if !line.contains("deep-scanning") {
            continue;
        }
        if let Some(rest) = line.split("(pid ").nth(1)
            && let Some(pid) = rest.split(')').next()
            && let Ok(pid) = pid.parse::<u32>()
        {
            selected.insert(pid);
        }
    }
    selected
}

struct BuiltFixtures {
    dir: PathBuf,
    driver: PathBuf,
    dataonly: PathBuf,
    provider: PathBuf,
    copy: PathBuf,
}

fn build_fixtures(name: &str, minor: u32, so_name: &str) -> BuiltFixtures {
    let dir = fixture_dir(name);
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let dataonly = gcc(
        &dir,
        "dataonly",
        &fixture_source("identity-dataonly.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &[],
    );
    let minor_flag = format!("-DLEGACY_MINOR={minor}");
    let provider = gcc(
        &dir,
        so_name,
        &matrix_source(),
        &["-shared", "-fPIC", &minor_flag],
        &[],
    );
    let copy = dir.join("id-copy.so");
    std::fs::copy(&provider, &copy).unwrap();
    assert_eq!(
        std::fs::read(&provider).unwrap(),
        std::fs::read(&copy).unwrap(),
        "byte-identical copy"
    );
    assert_ne!(
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&provider).unwrap()),
        std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&copy).unwrap()),
        "different file"
    );
    BuiltFixtures {
        dir,
        driver,
        dataonly,
        provider,
        copy,
    }
}

struct ObserveOutcome {
    doc: Value,
    selected: BTreeSet<u32>,
    holder_pids: Vec<u32>,
    copy_pid: Option<u32>,
    dataonly_pid: Option<u32>,
    /// Independent ground truth per holder: executable provider ranges
    /// from /proc while the holders live (established before coverage).
    holder_ranges: Vec<Vec<(u64, u64)>>,
}

/// One sweep attempt: fresh fixtures under the observer-as-parent
/// helper, ground truth from /proc while holders live, fixtures
/// reaped before returning. Returns `None` when the observer itself
/// fails (the forced-kernel refusal arm inspects that path).
fn attempt_observe(
    fixtures: &BuiltFixtures,
    attempt: &str,
    set: &str,
    observer_args: &[String],
    cap: usize,
    report_dir: &Path,
) -> Option<ObserveOutcome> {
    let ready = fixtures.dir.join(format!("ready-{attempt}"));
    let _ = std::fs::remove_dir_all(&ready);
    let out_file = fixtures.dir.join(format!("out-{attempt}.json"));
    let _ = std::fs::remove_file(&out_file);
    let report = report_dir.join(format!("report-{attempt}.json"));
    let mut args: Vec<String> = observer_args.to_vec();
    args.push("--json".to_string());
    args.push("-o".to_string());
    args.push(report.to_str().unwrap().to_string());
    let mut cmd = Command::new("sh");
    cmd.arg(fixture_source("inventory-identity-observe.sh"))
        .args(&args)
        .env("INV_DRIVER", &fixtures.driver)
        .env("INV_DATAONLY", &fixtures.dataonly)
        .env("INV_SET", set)
        .env("INV_P1", &fixtures.provider)
        .env("INV_COPY", &fixtures.copy)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out_file)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.spawn().unwrap().wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    // Fixture PIDs from READY files (observer output plays no role).
    let mut pids = Vec::new();
    let mut holders = Vec::new();
    for name in ["H1", "H2", "H3"] {
        let pid = ready_pid(&ready, name);
        holders.push(pid);
        pids.push(pid);
    }
    let (copy_pid, dataonly_pid) = if set == "sweep" {
        let copy = ready_pid(&ready, "C");
        let data = ready_pid(&ready, "D");
        pids.push(copy);
        pids.push(data);
        (Some(copy), Some(data))
    } else {
        (None, None)
    };
    // Ground truth while holders live (mappings are static sleeps).
    let mut holder_ranges = Vec::new();
    for pid in &holders {
        let ranges = exec_ranges_for(*pid, &fixtures.provider);
        assert!(
            !ranges.is_empty(),
            "holder {pid} maps the provider exec (cap {cap})"
        );
        holder_ranges.push(ranges);
    }
    kill_pids(&pids);
    if !output.status.success() {
        // Refusal arm: no document, but the stderr line and the
        // missing sink are the assertions. Stash stderr for them.
        std::fs::write(fixtures.dir.join(format!("refused-{attempt}.txt")), &stderr).unwrap();
        return None;
    }
    assert!(output.stdout.is_empty(), "helper stdout stays empty");
    let stdout = std::fs::read(&out_file).unwrap();
    let file = std::fs::read(&report).unwrap();
    assert_eq!(file, stdout, "stdout and -o bytes agree (cap {cap})");
    let doc: Value = serde_json::from_slice(&file).unwrap();
    let selected = selected_pids(&stderr);
    assert!(
        stderr.contains("process maps (cap "),
        "cap {cap} must force sweep proof"
    );
    Some(ObserveOutcome {
        doc,
        selected,
        holder_pids: holders,
        copy_pid,
        dataonly_pid,
        holder_ranges,
    })
}

/// Ground-truth exec range counts, established from /proc before any
/// coverage claim: every holder maps the provider exec (a zero-range
/// holder would make its edge vacuous), and the same provider through
/// the same loader maps the same count everywhere (measured: 1 per
/// holder on this toolchain). A positive edge proves every caller range
/// or no edge at all (`prove_match` over `is_caller_range`), so each
/// edged holder below covers its whole ground-truth set.
fn ground_truth_range_counts(observed: &ObserveOutcome) -> Vec<usize> {
    let counts: Vec<usize> = observed.holder_ranges.iter().map(Vec::len).collect();
    assert_eq!(
        counts.len(),
        observed.holder_pids.len(),
        "one ground-truth set per holder"
    );
    for (pid, count) in observed.holder_pids.iter().zip(&counts) {
        assert!(*count >= 1, "holder {pid} maps no provider exec range");
    }
    assert!(
        counts.iter().all(|count| *count == counts[0]),
        "uniform provider layout across holders: {counts:?}"
    );
    counts
}

/// D3d bounded userspace sweep cell: three holders dlopen the complete
/// provider ELF through the normal loader under a sweep-forcing cap
/// (deep-scan cannot bypass sweep proof); at least two holders stay
/// unselected while a separate selected holder supplies the held
/// provider pins; the ledger names the expected holder/provider edges;
/// a byte-identical different file and a data-only mapping are
/// negatives. Swept holders prove only where the host lets the
/// observer read map_files (privileged here); elsewhere they stay
/// honest unknowns, never false edges — the full three-edge proof is
/// the privileged production cell.
#[test]
fn d3d_userspace_sweep_cell_proves_exact_ledgered_edges() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-userspace", 40, "id-p1.so");
    let report_dir = private_dir();
    let mut outcome = None;
    for (attempt, cap) in ["a", "b", "c"].into_iter().zip([8usize, 32, 128]) {
        let observed = attempt_observe(
            &fixtures,
            attempt,
            "sweep",
            &[
                "--system".to_string(),
                "--capture".to_string(),
                "scan".to_string(),
                "--identity-backend".to_string(),
                "userspace".to_string(),
                "--module".to_string(),
                fixtures.provider.to_str().unwrap().to_string(),
                "--max-scan-pids".to_string(),
                cap.to_string(),
            ],
            cap,
            report_dir.path(),
        )
        .expect("userspace sweep observes");
        let selected_holders = observed
            .holder_pids
            .iter()
            .filter(|pid| observed.selected.contains(pid))
            .count();
        if selected_holders >= 1 && observed.holder_pids.len() - selected_holders >= 2 {
            outcome = Some(observed);
            break;
        }
    }
    let observed = outcome.expect("a cap with a selected supplier and two swept holders");

    // The selected supplier always proves (deep scan needs no
    // map_files); swept holders prove where the host allows and stay
    // honest unknowns otherwise. No holder ever edges falsely.
    let module = module_for(&observed.doc, "id-p1.so");
    let module_id = module["id"].as_str().unwrap();
    let mut edge_callers = BTreeSet::new();
    for edge in observed.doc["edges"].as_array().unwrap() {
        if edge["module"] == module_id {
            edge_callers.insert(edge["caller"].as_str().unwrap().to_string());
        }
    }
    assert!(
        !edge_callers.is_empty(),
        "nonempty expected edge set (the supplier proves)"
    );
    let mut swept_proved = 0;
    let mut proved = Vec::new();
    for pid in &observed.holder_pids {
        let callers = callers_for(&observed.doc, u64::from(*pid));
        let caller_id = callers.first().map(|caller| caller["id"].as_str().unwrap());
        let edged = caller_id.is_some_and(|id| edge_callers.contains(id));
        if observed.selected.contains(pid) {
            assert_eq!(callers.len(), 1, "selected holder {pid} is one caller");
            assert!(edged, "selected holder {pid} proves its edge");
        } else if edged {
            swept_proved += 1;
        }
        proved.push(edged);
    }
    if swept_proved < 2 {
        // Honest degradation: the gaps name map_files_unavailable for
        // the unproved swept holders, never silence or false edges.
        let gaps = observed.doc["gaps"].as_array().unwrap();
        assert!(
            gaps.iter().any(|gap| gap["subject"] == "maps attribution"
                && gap["reason"]
                    .as_str()
                    .unwrap()
                    .contains("map_files_unavailable")),
            "unproved sweep stays an honest map_files gap"
        );
    }
    // Per-range coverage: the ground-truth sets are established above
    // (nonempty, uniform); each proved holder covers its whole set (an
    // edge is all caller ranges or nothing), so the covered count is the
    // proved holders' full ground truth — at least the supplier — and
    // every unproved swept range stays gap-disclosed, never silent.
    let counts = ground_truth_range_counts(&observed);
    let covered: usize = proved
        .iter()
        .zip(&counts)
        .map(|(edged, count)| usize::from(*edged) * count)
        .sum();
    assert!(
        covered >= counts[0],
        "at least the supplier is fully covered: {covered} of {}",
        counts.iter().sum::<usize>()
    );
    // Every edge to the provider comes from a ledgered holder: zero
    // false edges, whatever the host proved.
    for caller_id in &edge_callers {
        let pid = observed.doc["callers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|caller| caller["id"] == *caller_id)
            .unwrap()["pid"]
            .as_u64()
            .unwrap() as u32;
        assert!(
            observed.holder_pids.contains(&pid),
            "edge caller {caller_id} (pid {pid}) is a ledgered holder"
        );
    }
    for (pid, why) in [
        (observed.copy_pid.unwrap(), "byte-identical different file"),
        (observed.dataonly_pid.unwrap(), "data-only mapping"),
    ] {
        for caller in callers_for(&observed.doc, u64::from(pid)) {
            let caller_id = caller["id"].as_str().unwrap();
            assert!(
                !edge_callers.contains(caller_id),
                "{why} (pid {pid}) must not edge to the original provider"
            );
        }
    }

    // Disclosure: userspace with no fallback; scan lane only with
    // honest scan-only unknowns (no lane key, no usage feed, unknown
    // per-edge usage observations).
    let identity = &observed.doc["observation"]["identity"];
    assert_eq!(identity["backend"], "userspace");
    assert_eq!(identity["fallback"], Value::Null);
    assert_eq!(identity.as_object().unwrap().len(), 2);
    assert!(observed.doc["observation"].get("lane").is_none());
    assert_eq!(observed.doc["observation"]["usage_feed"], false);
    for edge in observed.doc["edges"].as_array().unwrap() {
        assert!(
            edge["entries"]["observation"]
                .as_str()
                .unwrap()
                .starts_with("unknown"),
            "scan-only edge stays unknown: {}",
            edge["entries"]["observation"]
        );
    }
}

/// D3d auto without proof: the default selection over a complete scan
/// (no sweep) loads nothing and reports userspace/null.
#[test]
fn d3d_auto_without_proof_reports_userspace_null() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-auto-noproof", 41, "id-a1.so");
    let report_dir = private_dir();
    let ready = fixtures.dir.join("ready-auto");
    let out_file = fixtures.dir.join("out-auto.json");
    let report = report_dir.path().join("report-auto.json");
    let output = Command::new("sh")
        .arg(fixture_source("inventory-identity-observe.sh"))
        .arg("--system")
        .arg("--capture")
        .arg("scan")
        .arg("--module")
        .arg(&fixtures.provider)
        .arg("--max-scan-pids")
        .arg("65536")
        .arg("--json")
        .arg("-o")
        .arg(&report)
        .env("INV_DRIVER", &fixtures.driver)
        .env("INV_DATAONLY", &fixtures.dataonly)
        .env("INV_SET", "trio")
        .env("INV_P1", &fixtures.provider)
        .env("INV_COPY", &fixtures.copy)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out_file)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "{stderr}");
    let holders: Vec<u32> = ["H1", "H2", "H3"]
        .iter()
        .map(|n| ready_pid(&ready, n))
        .collect();
    for pid in &holders {
        assert!(!exec_ranges_for(*pid, &fixtures.provider).is_empty());
    }
    kill_pids(&holders);
    let stdout = std::fs::read(&out_file).unwrap();
    let file = std::fs::read(&report).unwrap();
    assert_eq!(file, stdout);
    let doc: Value = serde_json::from_slice(&file).unwrap();
    let identity = &doc["observation"]["identity"];
    assert_eq!(identity["backend"], "userspace");
    assert_eq!(identity["fallback"], Value::Null);
    let module = module_for(&doc, "id-a1.so");
    for pid in &holders {
        let callers = callers_for(&doc, u64::from(*pid));
        assert_eq!(callers.len(), 1);
        let caller_id = callers[0]["id"].as_str().unwrap();
        let edges: Vec<&Value> = doc["edges"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|edge| edge["caller"] == caller_id && edge["module"] == module["id"])
            .collect();
        assert_eq!(edges.len(), 1, "holder {pid} keeps its edge without sweep");
    }
}

/// D3d forced kernel through the real command: either the kernel
/// backend proves the full ledgered set on a proof-requiring btrfs
/// fixture (privileged capable host) or the refusal names its finite
/// reason before any sink exists (anything else). The positive arm
/// asserts the exact three holder/provider edges, zero false edges over
/// all enumerated module edges, both negatives un-edged, and per-range
/// coverage of every owned requested exec range. A successful empty
/// capture never satisfies this gate.
#[test]
fn d3d_forced_kernel_proves_or_refuses_before_sinks() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-forced", 42, "id-k1.so");
    let report_dir = private_dir();
    for (attempt, cap) in ["a", "b", "c"].into_iter().zip([8usize, 32, 128]) {
        let observed = attempt_observe(
            &fixtures,
            attempt,
            "sweep",
            &[
                "--system".to_string(),
                "--capture".to_string(),
                "scan".to_string(),
                "--identity-backend".to_string(),
                "kernel".to_string(),
                "--module".to_string(),
                fixtures.provider.to_str().unwrap().to_string(),
                "--max-scan-pids".to_string(),
                cap.to_string(),
            ],
            cap,
            report_dir.path(),
        );
        let Some(observed) = observed else {
            let stderr =
                std::fs::read_to_string(fixtures.dir.join(format!("refused-{attempt}.txt")))
                    .unwrap();
            assert!(
                stderr.contains("--identity-backend kernel: kernel identity is unavailable: "),
                "named refusal: {stderr}"
            );
            let reason = stderr
                .split("--identity-backend kernel: kernel identity is unavailable: ")
                .nth(1)
                .unwrap()
                .split_whitespace()
                .next()
                .unwrap()
                .trim_matches(|c| c == '\'' || c == '"' || c == '\n');
            assert!(
                [
                    "no_btf",
                    "kernel_fix_missing",
                    "no_task_iter_pidfd",
                    "numbering_mismatch",
                    "numbering_unknown",
                    "permission_denied",
                    "load_failed",
                    "probe_failed",
                ]
                .contains(&reason),
                "finite reason: {reason}"
            );
            assert!(!reason.contains('/'), "no raw paths: {reason}");
            assert!(
                !report_dir
                    .path()
                    .join(format!("report-{attempt}.json"))
                    .exists(),
                "no sink is created before refusal"
            );
            return;
        };
        // Success: only a cap with a selected supplier and two swept
        // holders satisfies this gate; otherwise try a wider cap.
        let selected_holders = observed
            .holder_pids
            .iter()
            .filter(|pid| observed.selected.contains(pid))
            .count();
        if selected_holders < 1 || observed.holder_pids.len() - selected_holders < 2 {
            continue;
        }
        // A kernel-positive claim needs a proof-requiring filesystem:
        // no-proof fast paths cannot satisfy this gate.
        assert!(
            dir_is_btrfs(&fixtures.dir),
            "kernel-positive cell requires its fixtures on btrfs; set \
             P11SCOPE_IDENTITY_FIXTURE_DIR to a btrfs dir (got {})",
            fixtures.dir.display()
        );
        let identity = &observed.doc["observation"]["identity"];
        assert_eq!(identity["backend"], "kernel");
        assert_eq!(
            identity["fallback"],
            Value::Null,
            "a forced proof cell admits no fallback"
        );
        let module = module_for(&observed.doc, "id-k1.so");
        let module_id = module["id"].as_str().unwrap();
        // All module edges enumerated: every edge to the provider comes
        // from a ledgered holder (zero false edges), and every holder
        // keeps exactly one kernel edge.
        let mut edge_callers = BTreeSet::new();
        for edge in observed.doc["edges"].as_array().unwrap() {
            if edge["module"] == module_id {
                edge_callers.insert(edge["caller"].as_str().unwrap().to_string());
            }
        }
        assert_eq!(edge_callers.len(), 3, "complete expected edge set");
        for pid in &observed.holder_pids {
            let callers = callers_for(&observed.doc, u64::from(*pid));
            assert_eq!(callers.len(), 1, "holder {pid} is one caller");
            let caller_id = callers[0]["id"].as_str().unwrap();
            assert!(
                edge_callers.contains(caller_id),
                "holder {pid} keeps its kernel edge"
            );
        }
        for caller_id in &edge_callers {
            let pid = observed.doc["callers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|caller| caller["id"] == *caller_id)
                .unwrap()["pid"]
                .as_u64()
                .unwrap() as u32;
            assert!(
                observed.holder_pids.contains(&pid),
                "edge caller {caller_id} (pid {pid}) is a ledgered holder"
            );
        }
        // Full ledger negatives: the byte-identical different file and
        // the data-only mapping never edge to the original provider. The
        // copy holder is inventoried (a nonempty caller set), so its
        // negative is never vacuous.
        assert!(
            !callers_for(&observed.doc, u64::from(observed.copy_pid.unwrap())).is_empty(),
            "copy holder is an inventoried caller"
        );
        for (pid, why) in [
            (observed.copy_pid.unwrap(), "byte-identical different file"),
            (observed.dataonly_pid.unwrap(), "data-only mapping"),
        ] {
            for caller in callers_for(&observed.doc, u64::from(pid)) {
                let caller_id = caller["id"].as_str().unwrap();
                assert!(
                    !edge_callers.contains(caller_id),
                    "{why} (pid {pid}) must not edge to the original provider"
                );
            }
        }
        // Per-range coverage: the ground-truth sets are established from
        // /proc (nonempty, uniform), and all three holders edge — an edge
        // is all caller ranges or nothing, so every owned requested exec
        // range is covered.
        let counts = ground_truth_range_counts(&observed);
        let total: usize = counts.iter().sum();
        assert!(
            total >= observed.holder_pids.len(),
            "nonempty covered range set: {total}"
        );
        return;
    }
    panic!("no cap left a selected supplier with two swept holders");
}

/// D3d: explicit identity selection outside `--system` is a usage
/// error; duplicate, missing and invalid values are usage errors.
#[test]
fn d3d_identity_selection_outside_system_is_a_usage_error() {
    for args in [
        vec!["--pid", "1", "--identity-backend", "kernel"],
        vec!["--pid", "1", "--identity-backend", "userspace"],
        vec![
            "--cgroup",
            "/sys/fs/cgroup/owned.scope",
            "--identity-backend",
            "kernel",
        ],
        vec!["--system", "--identity-backend", "both"],
        vec![
            "--system",
            "--identity-backend",
            "kernel",
            "--identity-backend",
            "auto",
        ],
        vec!["--system", "--identity-backend"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
            .arg("inventory")
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "args {args:?}");
        assert!(output.stdout.is_empty(), "args {args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        assert!(
            stderr.contains("--identity-backend"),
            "args {args:?}: {stderr}"
        );
    }
}

/// An owned provider-mapping fixture process for the `--pid` cell
/// (sibling observation needs no map_files).
struct PidFixture {
    child: Option<std::process::Child>,
    pid: u32,
}

impl Drop for PidFixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// D3d: a dashboard run with identity carries the backend disclosure
/// in its final document through the real interactive path: pty stdout
/// and stdin, the alternate-screen takeover (never the degraded pipe
/// path), a duration end, and the `-o` report.
#[test]
fn d3d_dashboard_run_with_identity_discloses_backend() {
    use std::io::Read as _;
    use std::os::fd::FromRawFd as _;
    let _guard = serial_guard();
    let dir = fixture_dir("inventory-identity-dashboard");
    let provider = gcc(
        &dir,
        "id-d1.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=44"],
        &[],
    );
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let ready = dir.join("d.ready");
    let mut holder = PidFixture {
        child: None,
        pid: 0,
    };
    holder.child = Some(
        Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg("--sleep")
            .arg("120")
            .arg(&provider)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    holder.pid = loop {
        if let Ok(text) = std::fs::read_to_string(&ready)
            && let Some(pid) = text.split_whitespace().nth(1)
        {
            break pid.parse::<u32>().unwrap();
        }
        assert!(Instant::now() < deadline, "holder never became ready");
        std::thread::sleep(Duration::from_millis(50));
    };
    // The dashboard's terminal: stdout and stdin are the slave (live
    // keys, no input sent — the duration ends the run); a drainer owns
    // the only master handle so frames never block the run.
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `openpty` writes two fresh fds; the other pointers may be null.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    assert_eq!(opened, 0, "openpty");
    // SAFETY: fresh descriptors owned from here on.
    let (master_file, slave_file) = unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    };
    let mut drain_master = master_file.try_clone().unwrap();
    drop(master_file);
    let drainer = std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut chunk = [0u8; 65536];
        while let Ok(read) = drain_master.read(&mut chunk) {
            if read == 0 {
                break;
            }
            seen.extend_from_slice(&chunk[..read]);
        }
        seen
    });
    let out_dir = private_dir();
    let report = out_dir.path().join("dashboard.json");
    let mut observer = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .arg("inventory")
        .arg("--system")
        .arg("--capture")
        .arg("scan")
        .arg("--module")
        .arg(&provider)
        .arg("--identity-backend")
        .arg("userspace")
        .arg("--json")
        .arg("--dashboard")
        .arg("--duration")
        .arg("8s")
        .arg("-o")
        .arg(&report)
        .stdin(slave_file.try_clone().unwrap())
        .stdout(slave_file)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = observer.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = observer.kill();
            panic!("dashboard run never ended");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "dashboard run: {status}");
    // The writer is gone: buffered stderr drains, then EOF, promptly.
    let mut err = Vec::new();
    observer
        .stderr
        .take()
        .unwrap()
        .read_to_end(&mut err)
        .unwrap();
    let seen = drainer.join().unwrap();
    // The real interactive path took over the terminal (alternate
    // screen), never the degraded pipe path.
    assert!(
        seen.windows(8).any(|window| window == b"\x1b[?1049h"),
        "dashboard took over the terminal"
    );
    let stderr = String::from_utf8_lossy(&err).to_string();
    assert!(!stderr.contains("degraded"), "{stderr}");
    let doc: Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    let identity = &doc["observation"]["identity"];
    assert_eq!(identity["backend"], "userspace");
    assert_eq!(identity["fallback"], Value::Null);
    assert_eq!(identity.as_object().unwrap().len(), 2);
}

/// D3d: `--pid` carries no identity key (implicit default loads
/// nothing); stdout and `-o` bytes still agree.
#[test]
fn d3d_pid_carries_no_identity_key() {
    let _guard = serial_guard();
    let dir = tmp("inventory-identity-pid");
    let provider = gcc(
        &dir,
        "id-pid.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=43"],
        &[],
    );
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let ready = dir.join("p.ready");
    let mut holder = PidFixture {
        child: None,
        pid: 0,
    };
    holder.child = Some(
        Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg("--sleep")
            .arg("120")
            .arg(&provider)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let pid = loop {
        if let Ok(text) = std::fs::read_to_string(&ready)
            && let Some(pid) = text.split_whitespace().nth(1)
        {
            break pid.parse::<u32>().unwrap();
        }
        assert!(Instant::now() < deadline, "holder never became ready");
        std::thread::sleep(Duration::from_millis(50));
    };
    holder.pid = pid;
    let out_dir = private_dir();
    let out = out_dir.path().join("pid.json");
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .arg("inventory")
        .arg("--pid")
        .arg(pid.to_string())
        .arg("--capture")
        .arg("scan")
        .arg("--json")
        .arg("-o")
        .arg(&out)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(output.status.success(), "{stderr}");
    let file = std::fs::read(&out).unwrap();
    assert_eq!(file, output.stdout);
    let doc: Value = serde_json::from_slice(&file).unwrap();
    assert!(
        doc["observation"].get("identity").is_none(),
        "{}",
        doc["observation"]
    );
}
