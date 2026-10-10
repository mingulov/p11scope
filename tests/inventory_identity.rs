//! SPDX-License-Identifier: GPL-3.0-or-later
//! D3d identity-backend integration: bounded real-CLI sweep cells.
//!
//! Every behavior is asserted through the public `p11scope inventory`
//! command over owned fixtures, reading the public JSON independently:
//! the userspace sweep cell proves the exact ledgered process/provider
//! edges with zero false edges (byte-identical different-file and
//! data-only negatives included); auto without proof stays
//! userspace/null without loading; forced kernel either proves through
//! the kernel backend or refuses with its named line before any sink
//! exists; explicit selection outside `--system` is a usage error;
//! `--pid` carries no identity key; stdout and `-o` bytes agree.
//!
//! System sweep fixtures run under `inventory-identity-observe.sh`,
//! which execs the observer as their parent: under ptrace_scope=1
//! only a descendant's map_files are readable, so sweep proof
//! requires the observer to be an ancestor of every fixture.

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
/// of the document): `deep-scanning i/n (pid X)...`.
fn selected_pids(stderr: &str) -> BTreeSet<u32> {
    let mut selected = BTreeSet::new();
    for line in stderr.lines() {
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
    let dir = tmp(name);
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
    for pid in &holders {
        assert!(
            !exec_ranges_for(*pid, &fixtures.provider).is_empty(),
            "holder {pid} maps the provider exec (cap {cap})"
        );
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
    })
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
/// backend proves the ledgered edges (privileged capable host) or the
/// refusal names its finite reason before any sink exists (anything
/// else). A successful empty capture never satisfies this gate.
#[test]
fn d3d_forced_kernel_proves_or_refuses_before_sinks() {
    let _guard = serial_guard();
    let fixtures = build_fixtures("inventory-identity-forced", 42, "id-k1.so");
    let report_dir = private_dir();
    for (attempt, cap) in ["a", "b", "c"].into_iter().zip([8usize, 32, 128]) {
        let observed = attempt_observe(
            &fixtures,
            attempt,
            "trio",
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
        let identity = &observed.doc["observation"]["identity"];
        assert_eq!(identity["backend"], "kernel");
        assert_eq!(
            identity["fallback"],
            Value::Null,
            "a forced proof cell admits no fallback"
        );
        let module = module_for(&observed.doc, "id-k1.so");
        let module_id = module["id"].as_str().unwrap();
        let mut count = 0;
        for pid in &observed.holder_pids {
            let callers = callers_for(&observed.doc, u64::from(*pid));
            assert_eq!(callers.len(), 1, "holder {pid} is one caller");
            let caller_id = callers[0]["id"].as_str().unwrap();
            let edges: Vec<&Value> = observed.doc["edges"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|edge| edge["caller"] == caller_id && edge["module"] == module_id)
                .collect();
            assert_eq!(edges.len(), 1, "holder {pid} keeps its kernel edge");
            count += edges.len();
        }
        assert_eq!(count, 3, "nonempty complete expected edge set");
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
