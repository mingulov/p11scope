//! SPDX-License-Identifier: GPL-3.0-or-later
//! Public-command breadth matrix: scale and churn workloads through the
//! real `p11scope inventory` binary over owned fixtures, asserting
//! ledger agreement at command level with the harness's public API,
//! plus slow-output backpressure, unwritable-`-o` honesty, and
//! SIGKILL-mid-run atomicity.

use p11scope::discovery::inventory_workload::{FdScope, assert_settled, assert_subset_ledger};
use serde_json::Value;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

/// Stated peak-RSS bound for every observer run below. Real runs peak
/// near ~40 MiB; the bound leaves headroom for machine variance while
/// still catching runaway growth.
const OBSERVER_RSS_BOUND_BYTES: u64 = 256 << 20;

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

fn ready_pid(ready_file: &Path) -> u32 {
    std::fs::read_to_string(ready_file)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

/// Spawn a helper (which execs the observer, preserving its pid) while
/// sampling the observer's peak RSS from `/proc/<pid>/status`. `VmHWM`
/// is kernel-tracked peak, so the max over 5ms samples is the run's
/// peak; the helper shell before the exec is smaller and never wins.
///
/// Observer stderr goes to a FILE, never a pipe: a multi-pass
/// `--system` run emits hundreds of kilobytes of progress, which
/// deadlocks a 64 KiB pipe nobody drains mid-run.
fn spawn_with_peak(cmd: &mut Command, stderr_log: &Path) -> (std::process::Output, u64) {
    cmd.stderr(std::fs::File::create(stderr_log).unwrap());
    let mut child = cmd.spawn().unwrap();
    let pid = child.id();
    let mut peak = 0u64;
    loop {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:")
                    && let Some(kb) = rest
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                {
                    peak = peak.max(kb * 1024);
                }
            }
        }
        match child.try_wait().unwrap() {
            Some(_) => break,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let output = child.wait_with_output().unwrap();
    (output, peak)
}

/// Terminal settlement at command level: the full structural check
/// plus suppression consistency. The exact suppressed COUNT depends on
/// live machine state (unreadable pids per pass × passes), so the
/// in-crate retention test pins exactness (476) while command level
/// pins structure, budget-row agreement, and cap engagement.
fn assert_settled_consistent(doc: &Value) {
    let suppressed = doc["gaps_suppressed"].as_u64().unwrap();
    assert_settled(doc, suppressed);
    assert_eq!(
        doc["budgets"]["retained_history"]["suppressed"]
            .as_u64()
            .unwrap(),
        suppressed,
        "budget row agrees with the top-level counter"
    );
    if suppressed > 0 {
        assert_eq!(
            doc["gaps"].as_array().unwrap().len(),
            1024,
            "suppression means the 1024 retention cap engaged"
        );
    }
}

/// Stderr progress stays honest: pass lines are present, and no success
/// is ever claimed — refused and partial runs read as what they are.
fn assert_stderr_honest(stderr: &str) {
    assert!(
        stderr.contains("pass 0:"),
        "progress names its passes: {stderr:?}"
    );
    assert!(
        !stderr.to_lowercase().contains("success"),
        "no success claims on stderr: {stderr:?}"
    );
}

/// The per-pass gap/refusal/suppressed line (`report_progress`) is the
/// actual honesty mechanism on refused and partial runs: it must name
/// exactly the gap, budget-refusal, and suppressed counts the document
/// carries. Parses `p11scope: pass N: G gap(s) (R budget refusal(s), S
/// suppressed)` and pins all three against the caller's exact values.
fn assert_pass_gap_line(stderr: &str, pass: u64, gaps: usize, refusals: usize, suppressed: u64) {
    let prefix = format!("p11scope: pass {pass}: ");
    let line = stderr
        .lines()
        .find(|line| line.starts_with(&prefix) && line.contains("budget refusal"))
        .unwrap_or_else(|| panic!("pass {pass} gap/refusal/suppressed line present: {stderr:?}"));
    let rest = line.strip_prefix(&prefix).unwrap();
    let (seen_gaps, rest) = rest.split_once(' ').unwrap();
    let seen_gaps: usize = seen_gaps.parse().unwrap();
    let inner = rest.split('(').nth(1).unwrap().strip_suffix(')').unwrap();
    let mut parts = inner.split(", ");
    let seen_refusals: usize = parts
        .next()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let seen_suppressed: u64 = parts
        .next()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        (seen_gaps, seen_refusals, seen_suppressed),
        (gaps, refusals, suppressed),
        "stderr gap line agrees with the document: {line:?}"
    );
}

// ---------------------------------------------------------------------------
// E2: scale through the real binary.
// ---------------------------------------------------------------------------

#[test]
fn scale_48_drivers_4_providers_through_real_binary() {
    let _guard = serial_guard();
    let dir = tmp("inventory-scale-e2");
    let ready = dir.join("ready");
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let matrix = matrix_source();
    let mut provs = Vec::new();
    for (index, minor) in [40, 41, 42, 43].iter().enumerate() {
        provs.push(gcc(
            &dir,
            &format!("is-p{index}.so"),
            &matrix,
            &["-shared", "-fPIC", &format!("-DLEGACY_MINOR={minor}")],
            &[],
        ));
    }
    let prov_list = provs
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let out = dir.join("out.json");
    let stderr_log = dir.join("stderr.log");
    let mut cmd = Command::new("sh");
    cmd.arg(fixture_source("inventory-scale-observe.sh"))
        .arg("--system")
        .args(["--json", "--max-scan-pids", "4096"])
        .env("INV_DRIVER", &driver)
        .env("INV_COUNT", "48")
        .env("INV_PROVIDERS", &prov_list)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let (output, peak) = spawn_with_peak(&mut cmd, &stderr_log);
    let mut pids = Vec::new();
    for entry in std::fs::read_dir(&ready).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("ready") {
            pids.push(ready_pid(&path));
        }
    }
    assert_eq!(pids.len(), 48, "every driver reported ready");
    let guard = FixtureGuard { pids: pids.clone() };
    let stderr = std::fs::read_to_string(&stderr_log).unwrap();
    assert!(
        output.status.success(),
        "scale observe failed: {:?} {stderr}",
        output.status,
    );
    assert!(output.stdout.is_empty());
    assert_stderr_honest(&stderr);
    assert!(
        peak < OBSERVER_RSS_BOUND_BYTES,
        "observer peak RSS {peak} stays within {OBSERVER_RSS_BOUND_BYTES}"
    );
    let body = std::fs::read_to_string(&out).unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    assert_eq!(doc["scope"], "system");
    // Ledger agreement at command level: 48 owned callers, 4 owned
    // modules, exactly the 192 owned edges — every one mapped.
    assert_subset_ledger(
        &doc,
        &pids,
        &["is-p0.so", "is-p1.so", "is-p2.so", "is-p3.so"],
        192,
    );
    assert_settled_consistent(&doc);
    drop(guard);
}

// ---------------------------------------------------------------------------
// E2: churn through the real binary.
// ---------------------------------------------------------------------------

#[test]
fn churn_anchor_and_churners_settle_through_real_binary() {
    let _guard = serial_guard();
    let dir = tmp("inventory-churn-e2");
    let ready = dir.join("ready");
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let prov = gcc(
        &dir,
        "is-churn.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let out = dir.join("out.json");
    let stderr_log = dir.join("stderr.log");
    let mut cmd = Command::new("sh");
    cmd.arg(fixture_source("inventory-churn-observe.sh"))
        .arg("--system")
        .args(["--json", "--duration", "14s", "--max-scan-pids", "4096"])
        .env("INV_DRIVER", &driver)
        .env("INV_PROV", &prov)
        .env("INV_CHURNERS", "8")
        .env("INV_ANCHOR_KILL_SECS", "11")
        .env("INV_READY", &ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let (output, peak) = spawn_with_peak(&mut cmd, &stderr_log);
    let anchor_pid = ready_pid(&ready.join("anchor.ready"));
    let mut churn_pids = Vec::new();
    for entry in std::fs::read_dir(&ready).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("churn-") && name.ends_with(".ready") {
            churn_pids.push(ready_pid(&path));
        }
    }
    let mut all_pids = churn_pids.clone();
    all_pids.push(anchor_pid);
    let guard = FixtureGuard {
        pids: all_pids.clone(),
    };
    let stderr = std::fs::read_to_string(&stderr_log).unwrap();
    assert!(
        output.status.success(),
        "churn observe failed: {:?} {stderr}",
        output.status,
    );
    assert!(output.stdout.is_empty());
    assert_stderr_honest(&stderr);
    assert!(
        peak < OBSERVER_RSS_BOUND_BYTES,
        "observer peak RSS {peak} stays within {OBSERVER_RSS_BOUND_BYTES}"
    );
    let body = std::fs::read_to_string(&out).unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    // The anchor was observed from the first pass and killed at 11s of
    // 14: exactly one incarnation, deterministically exited.
    let anchors: Vec<&Value> = doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|caller| caller["pid"] == u64::from(anchor_pid))
        .collect();
    assert_eq!(anchors.len(), 1, "one anchor incarnation");
    assert_eq!(anchors[0]["lifecycle"], "exited");
    assert_eq!(anchors[0]["retired"], true);
    // At least one short-lived churner was observed mid-churn (8
    // churners × 4s lives over 14 one-second passes).
    let observed_churners = churn_pids
        .iter()
        .filter(|pid| {
            doc["callers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|caller| caller["pid"] == u64::from(**pid))
        })
        .count();
    assert!(
        observed_churners >= 1,
        "at least one churner observed (spawned {})",
        churn_pids.len(),
    );
    // Terminal settlement over our pids: every observed caller is live
    // or retired-with-reason, every owned edge resolves.
    let our_pids: std::collections::HashSet<u64> =
        all_pids.iter().map(|pid| u64::from(*pid)).collect();
    for caller in doc["callers"].as_array().unwrap() {
        if !our_pids.contains(&caller["pid"].as_u64().unwrap()) {
            continue;
        }
        let lifecycle = caller["lifecycle"].as_str().unwrap();
        if lifecycle == "mapped" {
            assert_eq!(caller["retired"], false);
        } else {
            assert_eq!(caller["retired"], true);
            assert!(caller["lifecycle_reason"].is_string());
        }
    }
    assert_settled_consistent(&doc);
    drop(guard);
}

// ---------------------------------------------------------------------------
// C1: slow output — backpressure delays, never loses.
// ---------------------------------------------------------------------------

#[test]
fn slow_stdout_reader_gets_exact_bytes() {
    let _guard = serial_guard();
    let fd_scope = FdScope::open("slow-output command run");
    let dir = tmp("inventory-slow-e2");
    let ready = dir.join("ready");
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let matrix = matrix_source();
    let mut provs = Vec::new();
    for (index, minor) in [40, 41, 42, 43].iter().enumerate() {
        provs.push(gcc(
            &dir,
            &format!("is-s{index}.so"),
            &matrix,
            &["-shared", "-fPIC", &format!("-DLEGACY_MINOR={minor}")],
            &[],
        ));
    }
    let prov_list = provs
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    // The observer's stdout is a 4 KiB FIFO: a ~400 KiB document cannot
    // fit, so a stalled reader genuinely backpressures the writer.
    let fifo = dir.join("out.fifo");
    let fifo_c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(
        unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) },
        0,
        "mkfifo succeeds"
    );
    let stderr_log = dir.join("stderr.log");
    let mut child = {
        let mut cmd = Command::new("sh");
        cmd.arg(fixture_source("inventory-scale-observe.sh"))
            .arg("--system")
            .args(["--json", "--max-scan-pids", "4096"])
            .env("INV_DRIVER", &driver)
            .env("INV_COUNT", "48")
            .env("INV_PROVIDERS", &prov_list)
            .env("INV_READY", &ready)
            .env("INV_OUT", &fifo)
            .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&stderr_log).unwrap());
        // `cmd` drops here: the parent's copy of the child's stderr
        // file must not outlive the spawn (the FD scope below counts
        // it otherwise).
        cmd.spawn().unwrap()
    };
    let pid = child.id();
    // Opening the read end unblocks the observer's already-waiting
    // write end; shrinking the pipe to one page arms backpressure.
    use std::os::fd::AsRawFd as _;
    let fifo_file = std::fs::File::open(&fifo).unwrap();
    assert_eq!(
        unsafe { libc::fcntl(fifo_file.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
        4096,
        "the FIFO shrinks to one page"
    );
    let mut peak = 0u64;
    let sample_peak = |peak: &mut u64| {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:")
                    && let Some(kb) = rest
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse::<u64>().ok())
                {
                    *peak = (*peak).max(kb * 1024);
                }
            }
        }
    };
    // The first bytes prove the scan finished and the writer entered
    // its write phase; then the reader stalls 3s. A writer that is
    // still alive afterwards was blocked on the full pipe — engagement
    // proven, with no flake direction (an unblocked writer would exit).
    use std::io::Read as _;
    let mut reader = std::io::BufReader::new(fifo_file);
    let mut first = [0u8; 16];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(&first[..2], b"{\n", "the document starts streaming");
    sample_peak(&mut peak);
    // Child-side FD oracle for the stalled writer: its FD set stays
    // stable across the stall — no leak while blocked on
    // backpressure. The helper exec'd the observer, so `pid` IS the
    // writer.
    let child_fds = || {
        std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .count()
    };
    let fds_before = child_fds();
    std::thread::sleep(Duration::from_secs(3));
    sample_peak(&mut peak);
    let fds_after = child_fds();
    assert!(
        child.try_wait().unwrap().is_none(),
        "the writer stalls on the unread pipe (backpressure engaged)"
    );
    assert_eq!(
        fds_after, fds_before,
        "the stalled writer's FD set stays stable across the stall"
    );
    let mut body = first.to_vec();
    reader.read_to_end(&mut body).unwrap();
    sample_peak(&mut peak);
    let output = child.wait_with_output().unwrap();
    let stderr = std::fs::read_to_string(&stderr_log).unwrap();
    assert!(
        output.status.success(),
        "slow run exits 0: {:?} {stderr}",
        output.status,
    );
    assert_stderr_honest(&stderr);
    assert!(
        peak < OBSERVER_RSS_BOUND_BYTES,
        "observer peak RSS {peak} stays within {OBSERVER_RSS_BOUND_BYTES}"
    );
    let mut pids = Vec::new();
    for entry in std::fs::read_dir(&ready).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("ready") {
            pids.push(ready_pid(&path));
        }
    }
    let guard = FixtureGuard { pids };
    // Eventual exactness: the stalled-then-drained bytes are the whole
    // valid document, ledger and all.
    let text = String::from_utf8(body).unwrap();
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    let owned_pids: Vec<u32> = doc["callers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|caller| {
            guard
                .pids
                .contains(&(caller["pid"].as_u64().unwrap() as u32))
        })
        .map(|caller| caller["pid"].as_u64().unwrap() as u32)
        .collect();
    assert_eq!(owned_pids.len(), 48);
    assert_subset_ledger(
        &doc,
        &owned_pids,
        &["is-s0.so", "is-s1.so", "is-s2.so", "is-s3.so"],
        192,
    );
    assert_settled_consistent(&doc);
    drop(reader);
    fd_scope.assert_delta(0);
    drop(guard);
}

// ---------------------------------------------------------------------------
// C1: unwritable `-o` is a hard error, never empty success.
// ---------------------------------------------------------------------------

#[test]
fn unwritable_out_is_a_hard_error_not_success() {
    let _guard = serial_guard();
    // Fail-fast before any scan: no fixtures needed, any pid scans
    // nothing because `-o` creation fails first.
    let me = std::process::id();
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["inventory", "--pid"])
        .arg(me.to_string())
        .args(["--json", "-o", "/dev/full"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(
        !output.status.success(),
        "unwritable -o must fail, got {:?}",
        output.status,
    );
    assert!(
        output.stdout.is_empty(),
        "no document on stdout for a failed run"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("opening inventory report") || stderr.contains("/dev/full"),
        "stderr names the failed sink: {stderr:?}"
    );
}

// ---------------------------------------------------------------------------
// C1: SIGKILL mid-run leaves no partial report.
// ---------------------------------------------------------------------------

#[test]
fn sigkill_mid_run_leaves_no_partial_report() {
    let _guard = serial_guard();
    // The test parent must not leak across the kill: the scope opens
    // before the spawn and asserts a zero delta after the reap.
    //
    // No observer-RSS bound exists for this cell, by construction: the
    // observed process is dead, so there is no peak to sample — and no
    // document to settle. Atomicity-by-absence (no report file at the
    // destination) is the oracle, alongside the parent-side FD delta.
    let fd_scope = FdScope::open("sigkill command run");
    let dir = tmp("inventory-sigkill-e2");
    // `-o` needs a trusted directory; the target dir does not qualify.
    let out_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = out_dir.path().join("killed.json");
    let ready = dir.join("kill.ready");
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let prov = gcc(
        &dir,
        "is-kill.so",
        &matrix_source(),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let stderr_log = dir.join("stderr.log");
    let mut child = Command::new("sh")
        .arg(fixture_source("inventory-observe-pid.sh"))
        .args(["--json", "--duration", "25s", "-o"])
        .arg(&file)
        .env("INV_DRIVER", &driver)
        .env("INV_MODE", "plain")
        .env("INV_PROV", &prov)
        .env("INV_READY", &ready)
        .env("INV_OUT", dir.join("kill.json"))
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_log).unwrap())
        .spawn()
        .unwrap();
    // Passes tick every second; at 4s the run is mid-observation with
    // progress on stderr and nothing committed to `-o` yet.
    std::thread::sleep(Duration::from_secs(4));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the 25s run is still observing at 4s"
    );
    unsafe {
        libc::kill(child.id() as i32, libc::SIGKILL);
    }
    let output = child.wait_with_output().unwrap();
    use std::os::unix::process::ExitStatusExt as _;
    assert_eq!(
        output.status.signal(),
        Some(libc::SIGKILL),
        "the run died by our SIGKILL"
    );
    let stderr = std::fs::read_to_string(&stderr_log).unwrap();
    assert!(
        stderr.contains("pass 0:"),
        "progress before death stays: {stderr:?}"
    );
    // Atomic `-o`: the destination holds no partial report.
    assert!(
        std::fs::metadata(&file).is_err(),
        "SIGKILL leaves no report at the destination"
    );
    let pid: u32 = ready_pid(&ready);
    let _guard = FixtureGuard { pids: vec![pid] };
    drop(_guard);
    fd_scope.assert_delta(0);
}

// ---------------------------------------------------------------------------
// E2: a partial run names its gaps on stderr, exactly.
// ---------------------------------------------------------------------------

#[test]
fn scan_cap_overflow_reports_exact_gap_line_on_stderr() {
    let _guard = serial_guard();
    let fd_scope = FdScope::open("scan-cap command run");
    let dir = tmp("inventory-gapline-e2");
    // `-o` needs a trusted directory; the target dir does not qualify.
    let out_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = out_dir.path().join("partial.json");
    let stderr_log = dir.join("stderr.log");
    // One small budget, overflowed on purpose: the machine always holds
    // more than one process (the test, its shell, the observer), so a
    // scan cap of 1 always truncates and the run is always partial.
    // `cmd` drops with the block: the parent's copy of the child's
    // stderr file must not outlive the spawn (the FD scope below
    // counts it otherwise).
    let (output, peak) = {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_p11scope"));
        cmd.args([
            "inventory",
            "--system",
            "--json",
            "--max-scan-pids",
            "1",
            "-o",
        ])
        .arg(&file)
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
        spawn_with_peak(&mut cmd, &stderr_log)
    };
    let stderr = std::fs::read_to_string(&stderr_log).unwrap();
    assert!(
        output.status.success(),
        "capped observe exits 0: {:?} {stderr}",
        output.status,
    );
    // Both sinks carry the same bytes: the `-o` file and stdout agree.
    assert_eq!(
        output.stdout,
        std::fs::read(&file).unwrap(),
        "stdout and the -o report agree byte for byte"
    );
    assert_stderr_honest(&stderr);
    assert!(
        peak < OBSERVER_RSS_BOUND_BYTES,
        "observer peak RSS {peak} stays within {OBSERVER_RSS_BOUND_BYTES}"
    );
    let body = std::fs::read_to_string(&file).unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    // The run is genuinely partial: the discovery-capped record made the
    // document (one deep scan cannot examine every process's objects).
    let gaps = doc["gaps"].as_array().unwrap();
    assert!(
        gaps.iter().any(|gap| gap["subject"] == "discovery capped"
            && gap["reason"]
                .as_str()
                .unwrap()
                .contains("deep-scanned by provider rarity (limit 1)")),
        "the truncation gap names the overflowed budget: {}",
        doc["gaps"]
    );
    // The stderr gap line names exactly what the document carries —
    // the honesty mechanism on a partial run.
    let refusals = gaps.iter().filter(|gap| !gap["budget"].is_null()).count();
    let suppressed = doc["gaps_suppressed"].as_u64().unwrap();
    assert_pass_gap_line(&stderr, 0, gaps.len(), refusals, suppressed);
    assert_settled_consistent(&doc);
    fd_scope.assert_delta(0);
}
