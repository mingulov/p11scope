//! SPDX-License-Identifier: GPL-3.0-or-later
//! Phase 4 breadth tests: scale, budgets, failure injection, churn,
//! shutdown, and honest history — every workload through the ONE harness
//! (`super`), every expectation an exact ledger over the real JSON path.

use super::*;
use crate::attach::Scope;
use crate::capacity::{AttachCost, InventoryBudget};
use crate::discovery::caller_registry::{
    AdmissionState, CallerEvent, CallerId, DEFAULT_MAX_CALLERS, DEFAULT_MAX_EDGES,
    DEFAULT_MAX_MODULES, ImageAuthority, ModuleInfo, ModuleKey, OsProcessSource, RegistryLimits,
};
use crate::discovery::engine::inventory::{ImageCheck, ImageGuard, UnavailableImageGuard};
use crate::discovery::engine::inventory_coordinator::{InventoryCoordinator, InventoryScope};
use crate::discovery::hooks::HookRegistry;
use p11scope_ebpf_common::ImageIdentity;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn harness() -> Harness {
    Harness::new(RegistryLimits::default_limits()).unwrap()
}

struct WorkloadWorker {
    child: std::process::Child,
    reaped: bool,
}

impl Drop for WorkloadWorker {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: Command::process_group(0) created this worker's own
            // group. Its unreaped leader reserves the identity until wait.
            unsafe { libc::kill(-(self.child.id() as i32), libc::SIGKILL) };
            let _ = self.child.wait();
        }
    }
}

struct WorkloadWorkerResult {
    pid: u32,
    result: Result<String, String>,
}

fn run_workload_worker(mode: &str, timeout: std::time::Duration) -> WorkloadWorkerResult {
    use std::os::unix::process::CommandExt as _;
    use std::process::{Command, Stdio};

    let dir = tempfile::tempdir().unwrap();
    let stdout_path = dir.path().join("stdout");
    let stderr_path = dir.path().join("stderr");
    let nonce = dir.path().file_name().unwrap().to_str().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "discovery::inventory_workload::tests::workload_fd_worker",
            "--exact",
            "--nocapture",
        ])
        .env("P11SCOPE_WORKLOAD_FD_WORKER", mode)
        .env("P11SCOPE_WORKLOAD_FD_NONCE", nonce)
        .env("P11SCOPE_WORKLOAD_RSS_WORKER", "1")
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&stdout_path).unwrap())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .process_group(0)
        .spawn()
        .unwrap();
    let pid = child.id();
    let mut owned = WorkloadWorker {
        child,
        reaped: false,
    };
    let result = (|| {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: valid output for the retained child; do not reap before
            // checking completion, so failed workers retain group custody.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(format!("worker wait failed: {error}"));
                }
            } else {
                // SAFETY: zero-initialized output, filled by successful waitid.
                let info = unsafe { info.assume_init() };
                if unsafe { info.si_pid() } == pid as i32 {
                    let stdout = std::fs::read_to_string(&stdout_path).unwrap();
                    let stderr = std::fs::read_to_string(&stderr_path).unwrap();
                    if info.si_code != libc::CLD_EXITED || unsafe { info.si_status() } != 0 {
                        return Err(format!("worker failed:\n{stdout}\n{stderr}"));
                    }
                    let marker = format!("WORKLOAD_FD_DONE {mode} {nonce} {pid}");
                    if stdout.lines().filter(|line| *line == marker).count() != 1 {
                        return Err(format!(
                            "worker completion marker missing:\n{stdout}\n{stderr}"
                        ));
                    }
                    let status = owned.child.wait().map_err(|error| error.to_string())?;
                    owned.reaped = true;
                    assert!(status.success());
                    return Ok(stdout);
                }
            }
            if std::time::Instant::now() >= deadline {
                let stdout = std::fs::read_to_string(&stdout_path).unwrap();
                return Err(format!("worker deadline expired:\n{stdout}"));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    })();
    drop(owned);
    WorkloadWorkerResult { pid, result }
}

fn assert_workload_worker_reaped(pid: u32) {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY: non-consuming, non-signaling check after our child guard settled.
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn isolated_workload(mode: &str) {
    let outcome = run_workload_worker(mode, std::time::Duration::from_secs(60));
    assert_workload_worker_reaped(outcome.pid);
    assert!(outcome.result.is_ok(), "{}", outcome.result.unwrap_err());
}

#[test]
fn workload_fd_worker() {
    use std::io::Write as _;
    use std::os::fd::AsRawFd as _;

    let Ok(mode) = std::env::var("P11SCOPE_WORKLOAD_FD_WORKER") else {
        return;
    };
    let nonce = std::env::var("P11SCOPE_WORKLOAD_FD_NONCE").unwrap();
    println!("WORKLOAD_FD_START {mode} {nonce} {}", std::process::id());
    std::io::stdout().flush().unwrap();
    match mode.as_str() {
        "admission" => inject_admission_failures(),
        "mutation" => inject_provider_mutation(),
        "discovery-loss" => inject_discovery_loss(),
        "churn" => run_churn_storm(),
        "shutdown" => interrupt_shutdown(),
        "rss" => workload_rss_worker(),
        // Owned-pidfd accounting runs here, in a private process: the
        // census observes /proc/self/fd, which a concurrent lib test
        // can pollute with its own pidfds for our sleepers (a census
        // read 2 with zero held here; a unit read 36 after one owner).
        // A pidfd for one of our pids in this worker is ours by
        // construction, so the exact counts keep their meaning.
        "owner-growth-257" => grow_native_owners_to_257(),
        "owner-growth-failure" => inject_native_owner_growth_failure(),
        "pidfd-census" => owned_pidfd_census_classifier(),
        "system-sweep-release" => system_sweep_releases_its_pins(),
        "oracle-clean" => {
            let owned_directory = std::fs::File::open("/proc/self/fd").unwrap();
            let scope = FdScope::open("isolated clean baseline");
            assert!(scope.before.contains_key(&owned_directory.as_raw_fd()));
            for fd in scope.before.keys() {
                // SAFETY: query a borrowed descriptor without changing ownership.
                assert!(unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
            }
            scope.assert_delta(0);
            let accounted = std::fs::File::open("/dev/zero").unwrap();
            scope.assert_delta(1);
            drop(accounted);
            scope.assert_delta(0);
        }
        "oracle-retained" => {
            let scope = FdScope::open("isolated retained File");
            let retained = std::fs::File::open("/dev/zero").unwrap();
            scope.assert_delta(0);
            std::hint::black_box(&retained);
        }
        "oracle-duplicate" => {
            let baseline = std::fs::File::open("/dev/null").unwrap();
            let scope = FdScope::open("isolated retained duplicate");
            let retained = baseline.try_clone().unwrap();
            scope.assert_delta(0);
            std::hint::black_box(&retained);
        }
        "oracle-compensated" => {
            let foreign = std::fs::File::open("/dev/null").unwrap();
            let scope = FdScope::open("isolated compensated retention");
            let retained = std::fs::File::open("/dev/zero").unwrap();
            drop(foreign);
            scope.assert_delta(0);
            std::hint::black_box(&retained);
        }
        "oracle-replaced" => {
            let original = std::fs::File::open("/dev/null").unwrap();
            let original_fd = original.as_raw_fd();
            let scope = FdScope::open("isolated distinct resource replacement");
            drop(original);
            let replacement = std::fs::File::open("/dev/zero").unwrap();
            assert_eq!(replacement.as_raw_fd(), original_fd);
            scope.assert_delta(0);
            std::hint::black_box(&replacement);
        }
        "missing-marker" => return,
        "deadline" => std::thread::sleep(std::time::Duration::from_secs(60)),
        _ => panic!("unknown workload worker mode: {mode}"),
    }
    println!("WORKLOAD_FD_DONE {mode} {nonce} {}", std::process::id());
}

#[test]
fn workload_fd_oracle_rejects_compensating_foreign_close() {
    let outcome = run_workload_worker("oracle-compensated", std::time::Duration::from_secs(10));
    assert_workload_worker_reaped(outcome.pid);
    let error = outcome
        .result
        .expect_err("retention must not cancel baseline loss");
    assert!(error.contains("baseline FD"), "{error}");
}

#[test]
fn workload_fd_oracle_detects_retention_and_distinct_resource_replacement() {
    isolated_workload("oracle-clean");
    for (mode, reason) in [
        ("oracle-retained", "FD delta"),
        ("oracle-duplicate", "FD delta"),
        ("oracle-replaced", "baseline FD"),
    ] {
        let outcome = run_workload_worker(mode, std::time::Duration::from_secs(10));
        assert_workload_worker_reaped(outcome.pid);
        let error = outcome
            .result
            .expect_err("unaccounted resource must refuse");
        assert!(error.contains(reason), "{mode}: {error}");
    }
}

#[test]
fn workload_fd_worker_requires_execution_and_reaps_failures() {
    for (mode, reason) in [
        ("unknown", "unknown workload worker mode"),
        ("missing-marker", "worker completion marker missing"),
        ("deadline", "worker deadline expired"),
    ] {
        let outcome = run_workload_worker(mode, std::time::Duration::from_secs(2));
        assert_workload_worker_reaped(outcome.pid);
        let error = outcome.result.expect_err("invalid execution must refuse");
        assert!(error.contains(reason), "{mode}: {error}");
        assert!(
            error.contains("WORKLOAD_FD_START"),
            "worker must execute: {error}"
        );
    }
}

#[test]
fn workload_fd_deadline_guard_terminates_an_acknowledged_descendant() {
    use crate::process::PidPin;
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};

    struct Descendant(PidPin);
    impl Drop for Descendant {
        fn drop(&mut self) {
            // The retained original pidfd provides independent cleanup even
            // when a negative control breaks the worker's group termination.
            let _ = self.0.send_signal(libc::SIGKILL);
            let exited = self.0.wait_ready(Some(Duration::from_secs(5)));
            eprintln!(
                "WORKLOAD_DESCENDANT_CLEANUP pid={} exited={exited:?}",
                self.0.pid()
            );
        }
    }

    let child = std::process::Command::new("sh")
        .args([
            "-c",
            "sleep 60 & descendant=$!; printf '%s\\n' \"$descendant\"; wait \"$descendant\"",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut worker = WorkloadWorker {
        child,
        reaped: false,
    };
    let worker_pid = worker.child.id();
    let acquired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut output = worker.child.stdout.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut acknowledgement = Vec::new();
        while !acknowledgement.ends_with(b"\n") {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero() && acknowledgement.len() < 32);
            assert!(
                crate::discovery::test_subject::poll_fd(output.as_raw_fd(), remaining).unwrap()
            );
            let mut byte = [0];
            output.read_exact(&mut byte).unwrap();
            acknowledgement.push(byte[0]);
        }
        let pid: u32 = std::str::from_utf8(&acknowledgement)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let pin = PidPin::open(pid).unwrap();
        pin.pidfd().expect("the control retains an original pidfd");
        pin.probe_signal_authority().unwrap();
        // SAFETY: observe the acknowledged child while its owning worker and
        // group leader are still retained, without sending any numeric signal.
        assert_eq!(unsafe { libc::getpgid(pid as i32) }, worker_pid as i32);
        eprintln!("WORKLOAD_DESCENDANT_READY leader={worker_pid} descendant={pid}");
        Descendant(pin)
    }));
    let descendant = match acquired {
        Ok(descendant) => descendant,
        Err(panic) => {
            // SAFETY: setup failed before independent pin custody; the exact
            // newly created group leader is still owned and unreaped here.
            unsafe { libc::kill(-(worker_pid as i32), libc::SIGKILL) };
            std::panic::resume_unwind(panic);
        }
    };
    assert!(
        !descendant
            .0
            .wait_ready(Some(Duration::from_millis(20)))
            .unwrap(),
        "a live descendant must survive to the bounded deadline"
    );
    // Exercise the same guard used when run_workload_worker reaches its
    // deadline; its separate launcher control covers that error branch.
    drop(worker);
    assert_workload_worker_reaped(worker_pid);
    assert!(
        descendant
            .0
            .wait_ready(Some(Duration::from_secs(2)))
            .unwrap(),
        "worker cleanup left its acknowledged descendant alive"
    );
}

#[test]
fn workload_fd_workers_preserve_mutation_under_parent_churn_and_concurrent_rss() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct Churn {
        stop: std::sync::Arc<AtomicBool>,
        worker: Option<std::thread::JoinHandle<std::io::Result<()>>>,
    }
    impl Drop for Churn {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let cycles = std::sync::Arc::new(AtomicU64::new(0));
    let worker_stop = stop.clone();
    let worker_cycles = cycles.clone();
    let mut churn = Churn {
        stop,
        worker: Some(std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                let file = std::fs::File::open("/dev/null")?;
                let sockets = std::os::unix::net::UnixStream::pair()?;
                std::hint::black_box((&file, &sockets));
                worker_cycles.fetch_add(1, Ordering::AcqRel);
                std::thread::yield_now();
            }
            Ok(())
        })),
    };
    let before = cycles.load(Ordering::Acquire);
    let (mutation, rss) = std::thread::scope(|scope| {
        let mutation =
            scope.spawn(|| run_workload_worker("mutation", std::time::Duration::from_secs(60)));
        let rss = scope.spawn(|| run_workload_worker("rss", std::time::Duration::from_secs(60)));
        (mutation.join().unwrap(), rss.join().unwrap())
    });
    churn.stop.store(true, Ordering::Release);
    churn.worker.take().unwrap().join().unwrap().unwrap();
    let after = cycles.load(Ordering::Acquire);
    assert!(
        after > before,
        "parent FD churn must execute during worker lifetime"
    );
    assert_workload_worker_reaped(mutation.pid);
    assert_workload_worker_reaped(rss.pid);
    let mutation = mutation.result.unwrap();
    let rss = rss.result.unwrap();
    let directory = |output: &str| {
        output
            .lines()
            .find_map(|line| line.strip_prefix("WORKLOAD_MUTATION_DIR "))
            .unwrap()
            .to_string()
    };
    let mutation_dir = directory(&mutation);
    let rss_dir = directory(&rss);
    assert_ne!(
        mutation_dir, rss_dir,
        "concurrent invocations own distinct fixtures"
    );
    assert!(!Path::new(&mutation_dir).exists());
    assert!(!Path::new(&rss_dir).exists());
    assert!(rss.contains("WORKLOAD_RSS_HWM_BYTES "));
    eprintln!(
        "WORKLOAD_FD_CONTROL parent_churn_cycles={} mutation_dir={} rss_dir={}",
        after - before,
        mutation_dir,
        rss_dir
    );
}

fn limited(
    callers: usize,
    modules: usize,
    edges: usize,
    gaps: usize,
    endpoints: usize,
    semantic: usize,
) -> Harness {
    Harness::new(RegistryLimits::new(callers, modules, edges, gaps, endpoints, semantic).unwrap())
        .unwrap()
}

/// E-test-style fixture build: compile one C source with gcc into the
/// test tmp dir.
fn gcc(dir: &Path, out: &str, source: &Path, args: &[&str], libs: &[&str]) -> PathBuf {
    let bin = dir.join(out);
    let mut cmd = std::process::Command::new("gcc");
    cmd.args(args).arg("-o").arg(&bin).arg(source).args(libs);
    assert!(
        cmd.status().unwrap().success(),
        "gcc failed for {out}: {cmd:?}"
    );
    bin
}

fn wait_for(path: &Path, what: &str) {
    for _ in 0..300 {
        if std::fs::metadata(path).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("fixture {what} never arrived: {}", path.display());
}

/// Kills the owned fixture child on drop, so a failed assert cannot
/// leak a sleeper.
struct ChildReaper(std::process::Child);

impl Drop for ChildReaper {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Scripted guard over owned fixtures: every presented identity checks
/// exact (the pids are owned sleepers, never the host's tasks).
struct AcceptAllImages;

impl ImageGuard for AcceptAllImages {
    fn check(&mut self, _: &crate::process::ProcessView, _: ImageIdentity) -> ImageCheck {
        ImageCheck::Exact
    }
}

fn owner_image(pid: u32) -> ImageIdentity {
    ImageIdentity {
        task_cookie: u64::from(pid) + 1,
        exec_id: 7,
    }
}

// ---------------------------------------------------------------------------
// A1: fill to capacity per resource, plus one combined workload.
// ---------------------------------------------------------------------------

#[test]
fn scale_fill_callers_to_capacity_with_exact_ledger() {
    let spec = ScaleSpec {
        name: "fill-callers",
        callers: DEFAULT_MAX_CALLERS,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 1000,
    };
    let mut harness = harness();
    let events = harness.stage_scale(&spec);
    assert_eq!(events.len(), DEFAULT_MAX_CALLERS);
    assert!(
        events
            .iter()
            .all(|event| matches!(event, CallerEvent::Admitted { .. })),
        "every scripted pid admits below the cap"
    );
    let receipt = harness.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    // One past the cap: the adapter refuses with a named gap while the
    // 4096 retained incarnations stay intact.
    let now = harness.now_ns();
    harness
        .source()
        .spawn(1000 + DEFAULT_MAX_CALLERS as u32, 9999);
    let observed: BTreeSet<u32> = (0..=DEFAULT_MAX_CALLERS)
        .map(|index| 1000 + index as u32)
        .collect();
    let overflow = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(overflow.len(), 1);
    match &overflow[0] {
        CallerEvent::AdmitFailed { pid, budget, .. } => {
            assert_eq!(*pid, 1000 + DEFAULT_MAX_CALLERS as u32);
            let refusal = budget.expect("caller overflow names its budget");
            assert_eq!(
                (refusal.resource, refusal.limit, refusal.requested),
                ("callers", DEFAULT_MAX_CALLERS, DEFAULT_MAX_CALLERS + 1)
            );
        }
        other => panic!("expected a budget refusal, got {other:?}"),
    }
    harness
        .coordinator_mut()
        .apply_reconcile_events(&overflow, now);
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: DEFAULT_MAX_CALLERS as u64,
            modules: 1,
            edges: DEFAULT_MAX_CALLERS as u64,
            endpoints: 4,
            callers_refused: 1,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    // Adapter and registry agree on the caller census.
    assert_eq!(
        harness.coordinator().registry().caller_count(),
        DEFAULT_MAX_CALLERS
    );
    // The refusal gap names resource, limit, and requested.
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "caller admission failed");
    assert_eq!(gap["budget"]["resource"], "callers");
    assert_eq!(gap["budget"]["limit"], DEFAULT_MAX_CALLERS);
    assert_eq!(gap["budget"]["requested"], DEFAULT_MAX_CALLERS + 1);
    // Old evidence intact: the first incarnation still maps its module.
    assert_eq!(document["callers"][0]["id"], "c0");
    assert_eq!(document["callers"][0]["lifecycle"], "mapped");
    assert_eq!(document["edges"][0]["mapping"]["state"], "mapped");
}

#[test]
fn scale_fill_modules_to_capacity_with_exact_ledger() {
    let spec = ScaleSpec {
        name: "fill-modules",
        callers: 1,
        modules: DEFAULT_MAX_MODULES,
        edges_per_caller: DEFAULT_MAX_MODULES,
        endpoints_per_module: 4,
        first_pid: 2000,
    };
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    // One module past the cap: the mapping drops with a named gap while
    // the retained catalog stays intact.
    let now = harness.now_ns();
    let caller = harness.coordinator().adapter().live_id(2000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        2000,
        scale_module_info(DEFAULT_MAX_MODULES, 4),
        now,
    );
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: DEFAULT_MAX_MODULES as u64,
            edges: DEFAULT_MAX_MODULES as u64,
            endpoints: (DEFAULT_MAX_MODULES * 4) as u64,
            callers_refused: 0,
            modules_refused: 1,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "module capacity exhausted");
    assert_eq!(gap["budget"]["resource"], "modules");
    assert_eq!(gap["budget"]["limit"], DEFAULT_MAX_MODULES);
    assert_eq!(gap["budget"]["requested"], DEFAULT_MAX_MODULES + 1);
    assert_eq!(document["modules"].as_array().unwrap().len(), 4096);
    assert_eq!(document["modules"][0]["id"], "m0");
}

#[test]
fn scale_fill_edges_to_capacity_with_exact_ledger() {
    let spec = ScaleSpec {
        name: "fill-edges",
        callers: 128,
        modules: 256,
        edges_per_caller: 256,
        endpoints_per_module: 4,
        first_pid: 3000,
    };
    assert_eq!(spec.layout().len(), DEFAULT_MAX_EDGES);
    let mut harness = harness();
    harness.stage_scale(&spec);
    let receipt = harness.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    // One edge past the cap: a new caller mapping a new module is
    // refused on edges (both other budgets have headroom) with the old
    // 32768 intact.
    let now = harness.now_ns();
    harness.source().spawn(4000, 4242);
    let observed: BTreeSet<u32> = [4000].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 1);
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    let caller = harness.coordinator().adapter().live_id(4000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        4000,
        scale_module_info(256, 4),
        now,
    );
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 129,
            modules: 257,
            edges: DEFAULT_MAX_EDGES as u64,
            endpoints: (257 * 4) as u64,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 1,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "edge capacity exhausted");
    assert_eq!(gap["budget"]["resource"], "edges");
    assert_eq!(gap["budget"]["limit"], DEFAULT_MAX_EDGES);
    assert_eq!(gap["budget"]["requested"], DEFAULT_MAX_EDGES + 1);
}

#[test]
fn scale_combined_caps_all_resources_with_exact_ledger() {
    // 4096 callers × 8 striped modules: every resource at its cap in one
    // workload (32768 edges, 4096 distinct modules, 16384 endpoints).
    let spec = ScaleSpec {
        name: "combined-caps",
        callers: DEFAULT_MAX_CALLERS,
        modules: DEFAULT_MAX_MODULES,
        edges_per_caller: 8,
        endpoints_per_module: 4,
        first_pid: 5000,
    };
    let layout = spec.layout();
    assert_eq!(layout.len(), DEFAULT_MAX_EDGES);
    let touched: BTreeSet<usize> = layout.iter().map(|(_, module)| *module).collect();
    assert_eq!(touched.len(), DEFAULT_MAX_MODULES);
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    // One past every cap: caller, module, and edge refusals each name
    // their resource while the retained snapshot stays whole.
    let now = harness.now_ns();
    harness
        .source()
        .spawn(5000 + DEFAULT_MAX_CALLERS as u32, 7777);
    let observed: BTreeSet<u32> = [5000 + DEFAULT_MAX_CALLERS as u32].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 1);
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    let caller = harness.coordinator().adapter().live_id(5000).unwrap();
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        5000,
        scale_module_info(DEFAULT_MAX_MODULES, 4),
        now,
    );
    // Caller c0 maps modules m0..m7; m8 is retained but unmapped by c0,
    // so this mapping refuses on edges, not modules.
    harness.coordinator_mut().registry_mut().note_mapping(
        caller,
        5000,
        scale_module_info(8, 4),
        now,
    );
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: DEFAULT_MAX_CALLERS as u64,
            modules: DEFAULT_MAX_MODULES as u64,
            edges: DEFAULT_MAX_EDGES as u64,
            endpoints: (DEFAULT_MAX_MODULES * 4) as u64,
            callers_refused: 1,
            modules_refused: 1,
            edges_refused: 1,
            endpoints_refused: 0,
            gaps: Some(3),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let subjects: Vec<&str> = document["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|gap| gap["subject"].as_str().unwrap())
        .collect();
    assert_eq!(
        subjects,
        [
            "caller admission failed",
            "module capacity exhausted",
            "edge capacity exhausted"
        ]
    );
}

// ---------------------------------------------------------------------------
// A2: the t7 cardinalities as inventory projections, plus 257 native owners.
// ---------------------------------------------------------------------------

/// One t7-cardinality projection: the attach-level family covers these
/// endpoint counts; the inventory side renders the exact caller, module,
/// and edge counts from scripted staging at the same cardinalities.
fn t7_projection(name: &'static str, callers: usize, modules: usize, first_pid: u32) {
    let spec = ScaleSpec {
        name,
        callers,
        modules,
        edges_per_caller: modules,
        endpoints_per_module: 4,
        first_pid,
    };
    let mut harness = harness();
    harness.stage_scale(&spec);
    let receipt = harness.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    let document = harness.render();
    let ledger = spec.expected_ledger();
    assert!(
        ledger.endpoints > 512,
        "the projection carries >512 endpoints"
    );
    assert_ledger(&document, &ledger);
    assert_settled(&document, 0);
}

#[test]
fn inventory_projection_at_t7_cardinality_4097() {
    // 17 × 241: the attach-level n4097 as 4097 inventory edges.
    t7_projection("t7-4097", 17, 241, 20_000);
}

#[test]
fn inventory_projection_at_t7_cardinality_6530() {
    // 10 × 653: the attach-level 6530 union as 6530 inventory edges.
    t7_projection("t7-6530", 10, 653, 21_000);
}

#[test]
fn inventory_projection_at_t7_cardinality_8192() {
    // 32 × 256: the attach-level n8192 as 8192 inventory edges.
    t7_projection("t7-8192", 32, 256, 22_000);
}

#[test]
fn native_owner_growth_to_257_over_owned_sleepers() {
    // The owned-pidfd census observes /proc/self/fd: it runs in a
    // private worker, never beside concurrent lib tests.
    isolated_workload("owner-growth-257");
}

/// 257 native owners through the real growth path, run in the
/// `owner-growth-257` worker with its owned-pidfd accounting.
fn grow_native_owners_to_257() {
    // 257 owned sleepers: the pids behind 257 native owners through the
    // real `open_inventory_owner` growth path.
    let mut children = Vec::new();
    for _ in 0..257 {
        children.push(
            std::process::Command::new("sleep")
                .arg("120")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    struct Reaper(Vec<std::process::Child>);
    impl Drop for Reaper {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let _reaper = Reaper(children);
    let pids: Vec<u32> = _reaper.0.iter().map(|child| child.id()).collect();
    let owned: BTreeSet<u32> = pids.iter().copied().collect();
    let mut harness = harness();
    let mut guard = AcceptAllImages;
    // Owned-FD accounting, measured never assumed: this private
    // worker owns its fd table, and the census counts only pidfds for
    // these 257 sleepers, so foreign pipes/sockets/eventfds — and
    // pidfds for other pids — cannot move the needle. The first owner
    // establishes the unit cost (one pin fd where the kernel offers
    // pidfds, zero where it falls back), and the remaining 256 must
    // cost exactly 256× that unit — retained by design, never leaked
    // beyond it.
    let now = harness.now_ns();
    let before = count_owned_pidfds_floor(&owned);
    harness.source().spawn(pids[0], 5000);
    let first = harness
        .coordinator_mut()
        .test_open_native_owner(pids[0], owner_image(pids[0]), &mut guard, now)
        .unwrap();
    let unit = count_owned_pidfds_floor(&owned).saturating_sub(before);
    assert!(unit <= 1, "one owner retains at most one fd, got {unit}");
    for (index, pid) in pids.iter().enumerate().skip(1) {
        harness.source().spawn(*pid, 5000 + index as u64);
        harness
            .coordinator_mut()
            .test_open_native_owner(*pid, owner_image(*pid), &mut guard, now)
            .unwrap();
    }
    assert_eq!(
        count_owned_pidfds_floor(&owned),
        before + 257 * unit,
        "257 owners retain exactly the accounted pins"
    );
    assert!(harness.coordinator().owner_of(first).is_some());
    harness.advance(10);
    // One shared module for all 257 callers: 257 native edges.
    let now = harness.now_ns();
    for pid in &pids {
        let caller = harness.coordinator().adapter().live_id(*pid).unwrap();
        harness.coordinator_mut().registry_mut().note_mapping(
            caller,
            *pid,
            scale_module_info(0, 4),
            now,
        );
    }
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 257,
            modules: 1,
            edges: 257,
            endpoints: 4,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(0),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    for caller in document["callers"].as_array().unwrap() {
        assert_eq!(
            caller["image"]["authority"], "native_exact",
            "every grown caller carries native authority",
        );
    }
}

/// Direct pidfd_open for the census classifier below, mirroring
/// `crate::process`'s private opener. `None` where the kernel lacks
/// pidfds (the fallback shape).
fn pidfd_open_test(pid: u32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd as _;
    // SAFETY: Linux pidfd_open takes scalar pid/flags, returns a new fd or -1.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return None;
    }
    // SAFETY: the syscall returned a live fd this test owns.
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[test]
fn system_sweep_releases_its_pidfd_pins_on_drop() {
    // The owned-pidfd census runs in private workers because concurrent
    // system sweeps transiently pin every live process, ours included.
    // This is the release side of that premise: a real system-scope
    // discovery pins the fresh sleepers while its engine lives, and
    // dropping the engine returns the census to zero. Private worker: no
    // other sweep can pin these sleepers here.
    isolated_workload("system-sweep-release");
}

/// The system-sweep release workload, run in the `system-sweep-release`
/// worker.
fn system_sweep_releases_its_pins() {
    let mut reapers = Vec::new();
    for _ in 0..2 {
        reapers.push(ChildReaper(
            std::process::Command::new("sleep")
                .arg("30")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        ));
    }
    let owned: BTreeSet<u32> = reapers.iter().map(|reaper| reaper.0.id()).collect();
    assert_eq!(
        count_owned_pidfds_floor(&owned),
        0,
        "nothing pins the fresh sleepers yet"
    );
    let live = std::fs::read_dir("/proc")
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.bytes().all(|byte| byte.is_ascii_digit()))
        })
        .count();
    let args = crate::cli::CaptureArgs {
        kind: crate::cli::Kind::Profile,
        modules: vec![],
        manifests: vec![],
        hooks: HookRegistry::builtin(),
        scope: crate::cli::ScopeArg::System,
        metrics: false,
        duration: None,
        out: None,
        max_events: None,
        // Under-cap: the sweep admits every live process, both sleepers
        // included, with headroom for processes born meanwhile.
        max_scan_pids: Some(live + 256),
        ring_bytes: None,
        drain_interval: None,
        unsafe_requested: false,
        allow_confined_uretprobe: false,
        attach_backend: crate::attach::BackendSelection::default(),
    };
    let engine =
        crate::discovery::engine::Engine::discover(&args, &crate::attach::Scope::System, None)
            .expect("system-scope discovery");
    let held = count_owned_pidfds_floor(&owned);
    assert!(
        held >= owned.len(),
        "the live system engine pins every fresh sleeper (non-vacuous premise), held {held}"
    );
    drop(engine);
    assert_eq!(
        count_owned_pidfds_floor(&owned),
        0,
        "a dropped system engine releases every pin it took"
    );
}

#[test]
fn owned_pidfd_census_counts_only_owned_pidfds() {
    // The owned-pidfd census observes /proc/self/fd: it runs in a
    // private worker, never beside concurrent lib tests.
    isolated_workload("pidfd-census");
}

/// The owned-pidfd classifier, run in the `pidfd-census` worker.
/// Two owned sleepers behind the census; nothing else in this private
/// process pins them, so the owned count is exactly what this workload
/// opens itself.
fn owned_pidfd_census_classifier() {
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let mut reapers = Vec::new();
    for _ in 0..2 {
        reapers.push(ChildReaper(
            std::process::Command::new("sleep")
                .arg("30")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        ));
    }
    let owned: BTreeSet<u32> = reapers.iter().map(|reaper| reaper.0.id()).collect();
    assert_eq!(owned.len(), 2);
    assert_eq!(
        count_owned_pidfds(&owned),
        0,
        "nothing pins the fresh sleepers yet"
    );
    // Foreign FD shapes never move the owned needle: a pipe, a
    // socketpair, and an eventfd stay open for the rest of the test.
    let mut pipe_fds = [0; 2];
    assert_eq!(
        unsafe { libc::pipe(pipe_fds.as_mut_ptr()) },
        0,
        "pipe opens"
    );
    // SAFETY: `pipe` returned two live fds this test owns.
    let (_pipe_read, _pipe_write) = unsafe {
        (
            OwnedFd::from_raw_fd(pipe_fds[0]),
            OwnedFd::from_raw_fd(pipe_fds[1]),
        )
    };
    let mut sock_fds = [0; 2];
    assert_eq!(
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sock_fds.as_mut_ptr()) },
        0,
        "socketpair opens"
    );
    // SAFETY: `socketpair` returned two live fds this test owns.
    let (_sock_a, _sock_b) = unsafe {
        (
            OwnedFd::from_raw_fd(sock_fds[0]),
            OwnedFd::from_raw_fd(sock_fds[1]),
        )
    };
    let eventfd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    assert!(eventfd >= 0, "eventfd opens");
    // SAFETY: `eventfd` returned a live fd this test owns.
    let _event = unsafe { OwnedFd::from_raw_fd(eventfd) };
    assert_eq!(
        count_owned_pidfds(&owned),
        0,
        "foreign pipes/sockets/eventfds are not owned pidfds"
    );
    match pidfd_open_test(std::process::id()) {
        None => {
            // No pidfd_open on this kernel: the fallback shape pins the
            // census at zero — nothing can count as an owned pidfd.
            assert_eq!(count_owned_pidfds(&owned), 0);
        }
        Some(foreign) => {
            assert_eq!(
                count_owned_pidfds(&owned),
                0,
                "a pidfd for a foreign pid is not owned"
            );
            let first = pidfd_open_test(*owned.iter().next().unwrap())
                .expect("an owned pid opens where self did");
            assert_eq!(
                count_owned_pidfds(&owned),
                1,
                "a pidfd for an owned pid counts exactly once"
            );
            drop(first);
            assert_eq!(
                count_owned_pidfds(&owned),
                0,
                "closing the pin releases the count"
            );
            drop(foreign);
        }
    }
    assert_eq!(count_owned_pidfds(&owned), 0);
}

/// The attach path at t7 scale is privileged-only: these cells run the
/// real attach preparation at N endpoints (the BPF load fails loudly
/// with EPERM outside the privileged lane) and then prove the inventory
/// projection renders the exact caller/module/edge counts at the same
/// cardinality. Controller lanes run them; implementer lanes record
/// them unrun.
fn attach_projection(n: u64, callers: usize, modules: usize, first_pid: u32) {
    let cost = AttachCost::for_endpoints(n);
    assert_eq!(cost.links, n);
    assert_eq!(cost.program_loads, 2);
    let budget = InventoryBudget::new(n, 8 * n).expect("8N inventory payload");
    assert_eq!(budget.payload_bytes(), 8 * n);
    let prepared = crate::attach::PreparedInventory::prepare(
        Scope::System,
        budget,
        crate::attach::AttachBackend::Multi,
    )
    .expect("the privileged lane prepares inventory attach at scale");
    assert_eq!(
        prepared.endpoint_capacity().get(),
        n as u32,
        "attach prepared exactly N endpoints"
    );
    drop(prepared);
    let spec = ScaleSpec {
        name: "attach-projection",
        callers,
        modules,
        edges_per_caller: modules,
        endpoints_per_module: 4,
        first_pid,
    };
    assert_eq!(spec.layout().len() as u64, n);
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    let document = harness.render();
    assert_ledger(&document, &spec.expected_ledger());
    assert_settled(&document, 0);
}

#[test]
#[ignore = "controller lane: privileged BPF load plus attach-scale projection at 4097 endpoints"]
fn privileged_inventory_attach_projection_n4097() {
    attach_projection(4097, 17, 241, 30_000);
}

#[test]
#[ignore = "controller lane: privileged BPF load plus attach-scale projection at 6530 endpoints"]
fn privileged_inventory_attach_projection_n6530() {
    attach_projection(6530, 10, 653, 31_000);
}

#[test]
#[ignore = "controller lane: privileged BPF load plus attach-scale projection at 8192 endpoints"]
fn privileged_inventory_attach_projection_n8192() {
    attach_projection(8192, 32, 256, 32_000);
}

// ---------------------------------------------------------------------------
// A3: one combined workload beyond 6530 edges.
// ---------------------------------------------------------------------------

#[test]
fn combined_workload_beyond_6530_edges_with_exact_ledger() {
    // 200 × 40 = 8000 (caller, module) edges: the inventory-level
    // counterpart of the attach-level 6530 union — same number family,
    // both sides proven, no unit conflation.
    let spec = ScaleSpec {
        name: "beyond-6530",
        callers: 200,
        modules: 40,
        edges_per_caller: 40,
        endpoints_per_module: 16,
        first_pid: 40_000,
    };
    assert_eq!(spec.layout().len(), 8000);
    let mut harness = harness();
    harness.stage_scale(&spec);
    harness.commit();
    let document = harness.render();
    let ledger = spec.expected_ledger();
    assert_eq!(
        (
            ledger.callers,
            ledger.modules,
            ledger.edges,
            ledger.endpoints
        ),
        (200, 40, 8000, 640)
    );
    assert_ledger(&document, &ledger);
    assert_settled(&document, 0);
}

// ---------------------------------------------------------------------------
// B: separate budgets, named refusal, evidence intact.
// ---------------------------------------------------------------------------

/// One scripted module with full admission control, for budget tests.
fn module_info(index: usize, admission: AdmissionState, endpoints: Option<usize>) -> ModuleInfo {
    let path = format!("/budget/b{index}.so");
    ModuleInfo {
        path: path.clone(),
        key: ModuleKey::physical(
            8,
            2,
            200_000 + index as u64,
            Some(format!("bsha{index:06}")),
            &path,
        ),
        double_loaded: false,
        build_id: None,
        identity_source: Some("workload".into()),
        admission,
        admission_class: Some("exact".into()),
        admission_endpoints: endpoints,
        admission_reasons: Vec::new(),
    }
}

#[test]
fn separate_budgets_refuse_by_name_without_erasing_evidence() {
    // Caller budget: 4 retained, the 5th refused at admission.
    let mut callers = limited(4, 64, 64, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "budget-callers",
        callers: 4,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 60_000,
    };
    callers.stage_scale(&spec);
    callers.commit();
    let now = callers.now_ns();
    callers.source().spawn(60_004, 1111);
    let observed: BTreeSet<u32> = [60_004].into_iter().collect();
    let events = callers.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    callers
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    callers.commit();
    let document = callers.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 4,
            modules: 1,
            edges: 4,
            endpoints: 4,
            callers_refused: 1,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["budgets"]["callers"]["limit"], 4);
    let gap = &document["gaps"][0];
    assert_eq!(gap["budget"]["resource"], "callers");
    assert_eq!(gap["budget"]["limit"], 4);
    assert_eq!(gap["budget"]["requested"], 5);
    // The text summary carries the refusal too.
    let text = crate::inventory::render_text(callers.coordinator(), "workload", 0, now, 2);
    assert!(
        text.contains("(budget callers: limit 4, requested 5)"),
        "text refusal names resource, limit, requested:\n{text}"
    );

    // Module budget: 2 retained, the 3rd refused.
    let mut modules = limited(64, 2, 64, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "budget-modules",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 61_000,
    };
    modules.stage_scale(&spec);
    modules.commit();
    let now = modules.now_ns();
    let caller = modules.coordinator().adapter().live_id(61_000).unwrap();
    modules.coordinator_mut().registry_mut().note_mapping(
        caller,
        61_000,
        module_info(2, AdmissionState::Admitted, Some(4)),
        now,
    );
    modules.commit();
    let document = modules.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: 2,
            edges: 2,
            endpoints: 8,
            callers_refused: 0,
            modules_refused: 1,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["gaps"][0]["budget"]["resource"], "modules");

    // Edge budget: 2 retained, the 3rd refused (module budget has room).
    let mut edges = limited(64, 64, 2, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "budget-edges",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 62_000,
    };
    edges.stage_scale(&spec);
    edges.commit();
    let now = edges.now_ns();
    let caller = edges.coordinator().adapter().live_id(62_000).unwrap();
    edges.coordinator_mut().registry_mut().note_mapping(
        caller,
        62_000,
        module_info(7, AdmissionState::Admitted, Some(4)),
        now,
    );
    edges.commit();
    let document = edges.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: 3,
            edges: 2,
            endpoints: 12,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 1,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["gaps"][0]["budget"]["resource"], "edges");
    assert_eq!(document["gaps"][0]["budget"]["requested"], 3);

    // Endpoint budget: 10 retained, a module costing past it refused
    // while the retained catalog and its edges stay.
    let mut endpoints = limited(64, 64, 64, 64, 10, 64);
    let spec = ScaleSpec {
        name: "budget-endpoints",
        callers: 1,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 63_000,
    };
    endpoints.stage_scale(&spec);
    endpoints.commit();
    let now = endpoints.now_ns();
    let caller = endpoints.coordinator().adapter().live_id(63_000).unwrap();
    endpoints.coordinator_mut().registry_mut().note_mapping(
        caller,
        63_000,
        module_info(9, AdmissionState::Admitted, Some(4)),
        now,
    );
    endpoints.commit();
    let document = endpoints.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: 2,
            edges: 2,
            endpoints: 8,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 1,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "endpoint budget exhausted");
    assert_eq!(gap["budget"]["resource"], "endpoints");
    assert_eq!(gap["budget"]["limit"], 10);
    assert_eq!(gap["budget"]["requested"], 12);
    assert_eq!(document["budgets"]["endpoints"]["occupied"], 8);

    // Every budget row carries its own limit, occupancy, and loss
    // counter — including the withheld semantic budget and the
    // retained-history row.
    assert_eq!(document["budgets"]["semantic_state"]["limit"], 64);
    assert_eq!(document["budgets"]["semantic_state"]["occupied"], 0);
    assert_eq!(document["budgets"]["semantic_state"]["status"], "withheld");
    assert_eq!(document["budgets"]["semantic_state"]["unknown_edges"], 2);
    assert_eq!(
        document["budgets"]["counters"]["cap"],
        18446744073709551615u64
    );
    assert_eq!(document["budgets"]["counters"]["observed_edges"], 0);
    assert_eq!(document["budgets"]["counters"]["saturated_edges"], 0);
    assert_eq!(document["budgets"]["retained_history"]["limit"], 64);
    assert_eq!(document["budgets"]["retained_history"]["retained"], 1);
    assert_eq!(document["budgets"]["retained_history"]["suppressed"], 0);
}

#[test]
fn endpoint_census_charges_only_admitted_modules() {
    let mut harness = limited(64, 64, 64, 64, 100, 64);
    let now = harness.now_ns();
    let registry = harness.coordinator_mut().registry_mut();
    // Refused, unresolved, and count-less admitted modules cost nothing.
    registry.note_mapping(
        CallerId(0),
        50,
        module_info(0, AdmissionState::Refused, Some(50)),
        now,
    );
    registry.note_mapping(
        CallerId(1),
        51,
        module_info(1, AdmissionState::Unresolved, Some(60)),
        now,
    );
    registry.note_mapping(
        CallerId(2),
        52,
        module_info(2, AdmissionState::Admitted, None),
        now,
    );
    registry.note_mapping(
        CallerId(3),
        53,
        module_info(3, AdmissionState::Admitted, Some(30)),
        now,
    );
    registry.note_mapping(
        CallerId(4),
        54,
        module_info(4, AdmissionState::Admitted, Some(40)),
        now,
    );
    harness.commit();
    assert_eq!(harness.coordinator().registry().endpoints_total(), 70);
    // 70 + 40 exceeds the 100 census: the new module refuses with a
    // named gap and the retained five stay.
    let now = harness.now_ns();
    harness.coordinator_mut().registry_mut().note_mapping(
        CallerId(5),
        55,
        module_info(5, AdmissionState::Admitted, Some(40)),
        now,
    );
    harness.commit();
    let registry = harness.coordinator().registry();
    assert_eq!(registry.endpoints_total(), 70);
    assert_eq!(registry.module_count(), 5);
    assert_eq!(registry.endpoints_refused(), 1);
    // No render here: these CallerIds were never adapter-admitted (the
    // census rule is registry-level), and the renderer asserts every
    // edge endpoint resolves. The budgets row itself renders in the
    // budget test above.
    assert_eq!(registry.gaps().len(), 1);
    let gap = &registry.gaps()[0];
    assert_eq!(gap.subject, "endpoint budget exhausted");
    let refusal = gap.budget.expect("the refusal names its budget");
    assert_eq!(
        (refusal.resource, refusal.limit, refusal.requested),
        ("endpoints", 100, 110)
    );
}

#[test]
fn counter_saturation_renders_nonzero_in_budgets_census() {
    let mut harness = limited(64, 64, 64, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "counter-saturation",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 63_500,
    };
    harness.stage_scale(&spec);
    harness.commit();
    // One observed batch at the cap: the counter saturates through the
    // normal budgets path, and the census renders it nonzero.
    let now = harness.now_ns();
    let caller = harness.coordinator().adapter().live_id(63_500).unwrap();
    let key = harness
        .coordinator()
        .registry()
        .modules()
        .next()
        .unwrap()
        .key
        .clone();
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &key, u64::MAX, now);
    harness.commit();
    let document = harness.render();
    assert_ledger(&document, &spec.expected_ledger());
    assert_settled(&document, 0);
    assert_eq!(document["budgets"]["counters"]["observed_edges"], 1);
    assert_eq!(document["budgets"]["counters"]["saturated_edges"], 1);
    assert_eq!(document["edges"][0]["entries"]["count"], u64::MAX);
    assert_eq!(document["edges"][0]["entries"]["saturated"], true);
}

#[test]
fn refusal_preserves_previously_observed_entry_counts() {
    // One caller, one module, one edge with observed use — then a
    // second caller overflows the caller budget. The refusal names its
    // budget while the frozen entry count stays intact.
    let mut harness = limited(1, 64, 64, 64, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "use-preservation",
        callers: 1,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 63_600,
    };
    harness.stage_scale(&spec);
    harness.commit();
    let now = harness.now_ns();
    let caller = harness.coordinator().adapter().live_id(63_600).unwrap();
    let key = harness
        .coordinator()
        .registry()
        .modules()
        .next()
        .unwrap()
        .key
        .clone();
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &key, 5, now);
    harness.commit();
    // Overflow the caller budget: the second pid refuses at admission
    // while the first stays live (both observed, so no exit).
    let now = harness.now_ns();
    harness.source().spawn(63_601, 2222);
    let observed: BTreeSet<u32> = [63_600, 63_601].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 1);
    match &events[0] {
        CallerEvent::AdmitFailed { pid, budget, .. } => {
            assert_eq!(*pid, 63_601);
            let refusal = budget.expect("caller overflow names its budget");
            assert_eq!(
                (refusal.resource, refusal.limit, refusal.requested),
                ("callers", 1, 2)
            );
        }
        other => panic!("expected a budget refusal, got {other:?}"),
    }
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1,
            modules: 1,
            edges: 1,
            endpoints: 4,
            callers_refused: 1,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    // Use-preservation: the staged entry count survived the refusal.
    assert_eq!(document["edges"][0]["entries"]["count"], 5);
    assert_eq!(document["gaps"][0]["budget"]["resource"], "callers");
}

// ---------------------------------------------------------------------------
// C: failure injection with exact loss accounting and terminal settlement.
// ---------------------------------------------------------------------------

#[test]
fn admission_failures_gap_exactly_with_zero_fd_delta() {
    isolated_workload("admission");
}

/// Admission/growth failure injection, callable from the test above
/// and from the RSS worker.
fn inject_admission_failures() {
    let scope = FdScope::open("admission failure injection");
    let mut harness = harness();
    let now = harness.now_ns();
    for pid in 7000..7008 {
        harness.source().spawn(pid, 1000 + pid as u64);
    }
    for pid in [7001, 7003, 7005] {
        harness.source().set_fail_open(pid, true);
    }
    let observed: BTreeSet<u32> = (7000..7008).collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 8);
    let failed: Vec<&CallerEvent> = events
        .iter()
        .filter(|event| matches!(event, CallerEvent::AdmitFailed { .. }))
        .collect();
    assert_eq!(failed.len(), 3);
    for event in &failed {
        match event {
            CallerEvent::AdmitFailed { reason, budget, .. } => {
                assert!(reason.contains("injected admission failure"), "{reason}");
                assert_eq!(*budget, None, "pin failures carry no budget");
            }
            other => panic!("expected AdmitFailed, got {other:?}"),
        }
    }
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    // The injection clears: the failed three admit on the next pass.
    for pid in [7001, 7003, 7005] {
        harness.source().set_fail_open(pid, false);
    }
    let now = harness.now_ns();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    assert_eq!(events.len(), 3);
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    harness.commit();
    scope.assert_delta(0);
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 8,
            modules: 0,
            edges: 0,
            endpoints: 0,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            // The three failures of one pass aggregate into one counted
            // gap (C1b ruling 4), naming the first.
            gaps: Some(1),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    let gap = &document["gaps"][0];
    assert_eq!(gap["subject"], "caller admission failed");
    assert_eq!(gap["pid"], serde_json::Value::Null);
    assert!(
        gap["reason"]
            .as_str()
            .unwrap()
            .starts_with("3 pids could not be admitted this pass; first: pid 7001: "),
        "{gap}"
    );
    assert_eq!(gap["budget"], serde_json::Value::Null);
}

#[test]
fn native_owner_growth_failure_accounts_loss_exactly() {
    // The owned-pidfd census observes /proc/self/fd: it runs in a
    // private worker, never beside concurrent lib tests.
    isolated_workload("owner-growth-failure");
}

/// Native-owner growth-path failure injection, run in the
/// `owner-growth-failure` worker with its owned-pidfd accounting.
fn inject_native_owner_growth_failure() {
    fn some_image(pid: u32) -> Option<ImageIdentity> {
        Some(owner_image(pid))
    }
    // One owned sleeper behind a real scan pass: BPF-style image
    // identity exists for it, but the guard refuses exact authority,
    // so `open_inventory_owner` fails through the production path.
    let child = std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let _reaper = ChildReaper(child);
    let owned: BTreeSet<u32> = [pid].into_iter().collect();
    // Pin shape, measured never assumed: on pidfd kernels the admitted
    // caller retains one pidfd; on fallback kernels it retains none.
    // The failed growth must retain nothing either way, so the owned
    // census after the scan is exactly the caller's pin.
    let probe = crate::process::PidPin::open(pid).expect("the owned sleeper pins");
    let pin_holds_fd = probe.pidfd().is_ok();
    drop(probe);
    let before = count_owned_pidfds_floor(&owned);
    let mut coordinator = InventoryCoordinator::new(
        Scope::Pid(pid),
        HookRegistry::builtin(),
        Vec::new(),
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
    .unwrap();
    let t0 = crate::discovery::caller_registry::now_ns();
    let report = coordinator
        .scan_pass(
            &InventoryScope::Pid(pid),
            None,
            &mut UnavailableImageGuard,
            &mut crate::discovery::native_binding::OwnerImages(some_image),
            u64::MAX,
            t0,
        )
        .unwrap();
    assert_eq!(report.scanned, 1);
    assert_eq!(report.native_callers, 0, "growth failed: no native caller");
    assert_eq!(report.scan_callers, 1, "the scan lane still admits the pid");
    coordinator.commit_batch(false).unwrap();
    assert_eq!(
        count_owned_pidfds_floor(&owned),
        before + usize::from(pin_holds_fd),
        "the scan retains exactly the admitted caller's pin; the failed growth retains nothing"
    );
    let document = crate::inventory::render_json(&coordinator, "workload", t0, t0, 1);
    // Exact loss accounting: one gap names the failed growth with the
    // pid and the open error; the scan-lane incarnation carries on
    // with scan-pinned authority and no retained owner.
    let growth_gaps: Vec<&serde_json::Value> = document["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|gap| gap["subject"] == "native inventory owner unavailable")
        .collect();
    assert_eq!(
        growth_gaps.len(),
        1,
        "one growth-failure gap: {}",
        document["gaps"]
    );
    assert_eq!(growth_gaps[0]["pid"], pid);
    assert!(
        growth_gaps[0]["reason"]
            .as_str()
            .unwrap()
            .contains("inventory exact-image authority unavailable or changed"),
        "the gap carries the open error: {}",
        growth_gaps[0]["reason"]
    );
    assert!(growth_gaps[0]["budget"].is_null());
    assert_eq!(document["callers"].as_array().unwrap().len(), 1);
    assert_eq!(document["callers"][0]["lifecycle"], "mapped");
    assert_eq!(
        document["callers"][0]["image"]["authority"], "scan_pinned",
        "growth failure falls back to scan-lane authority"
    );
    let caller = coordinator.adapter().live_id(pid).unwrap();
    assert!(
        coordinator.owner_of(caller).is_none(),
        "the failed growth retains no owner"
    );
    assert_eq!(document["gaps_suppressed"], 0);
    assert_settled(&document, 0);
    // The bad-image shape, direct: a zero task cookie never reaches the
    // open — the growth path refuses it with no state change.
    let mut harness = harness();
    let now = harness.now_ns();
    let mut guard = AcceptAllImages;
    let error = harness
        .coordinator_mut()
        .test_open_native_owner(
            pid,
            ImageIdentity {
                task_cookie: 0,
                exec_id: 7,
            },
            &mut guard,
            now,
        )
        .expect_err("a zero task cookie refuses the growth path");
    assert!(
        format!("{error:#}").contains("lacks image identity"),
        "the error names the missing identity: {error:#}"
    );
}

#[test]
fn provider_mutation_mid_run_splits_module_instances() {
    isolated_workload("mutation");
}

/// Provider-mutation injection (dlclose/dlopen of a changed `.so`),
/// callable from the test above and from the RSS worker.
fn inject_provider_mutation() {
    let base = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let owned_dir = tempfile::Builder::new()
        .prefix("workload-mutate-")
        .tempdir_in(base)
        .unwrap();
    let dir = owned_dir.path();
    println!("WORKLOAD_MUTATION_DIR {}", dir.display());
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let v1 = gcc(
        dir,
        "mut-v1.so",
        &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
        &[],
    );
    let v2 = gcc(
        dir,
        "mut-v2.so",
        &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
        &["-shared", "-fPIC", "-DLEGACY_MINOR=41"],
        &[],
    );
    let driver = gcc(
        dir,
        "mutate-driver",
        &manifest.join("tests/fixtures/inventory-mutate-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    // The provider path the driver maps; v1 bytes first.
    let prov = dir.join("mut-prov.so");
    std::fs::copy(&v1, &prov).unwrap();
    let ready = dir.join("mut.ready");
    let go = dir.join("mut.go");
    let done = dir.join("mut.done");
    let child = std::process::Command::new(&driver)
        .arg("--ready")
        .arg(&ready)
        .arg("--go")
        .arg(&go)
        .arg("--done")
        .arg(&done)
        .arg(&prov)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let driver_pid = child.id();
    let reaper = ChildReaper(child);
    wait_for(&ready, "mutate ready");
    let coordinator_scope = FdScope::open("provider mutation coordinator lifetime");
    let mut coordinator = InventoryCoordinator::new(
        Scope::Pid(driver_pid),
        HookRegistry::builtin(),
        vec![prov.clone()],
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
    .unwrap();
    let t0 = crate::discovery::caller_registry::now_ns();
    coordinator
        .scan_pass(
            &InventoryScope::Pid(driver_pid),
            None,
            &mut UnavailableImageGuard,
            &mut crate::discovery::native_binding::ScanOnlyIdentity,
            u64::MAX,
            t0,
        )
        .unwrap();
    coordinator.commit_batch(false).unwrap();
    // Atomic replace plus the driver's dlclose/dlopen: the same path
    // resolves to a new physical instance. The FD scope covers the
    // whole second pass — scans open files transiently and retain
    // nothing new.
    let scope = FdScope::open("provider mutation second pass");
    std::fs::copy(&v2, dir.join("mut-prov.staging")).unwrap();
    std::fs::rename(dir.join("mut-prov.staging"), &prov).unwrap();
    std::fs::write(&go, "go\n").unwrap();
    wait_for(&done, "mutate done");
    let t1 = crate::discovery::caller_registry::now_ns();
    coordinator
        .scan_pass(
            &InventoryScope::Pid(driver_pid),
            None,
            &mut UnavailableImageGuard,
            &mut crate::discovery::native_binding::ScanOnlyIdentity,
            u64::MAX,
            t1,
        )
        .unwrap();
    coordinator.commit_batch(false).unwrap();
    scope.assert_delta(0);
    let document = crate::inventory::render_json(&coordinator, "workload", t0, t1, 2);
    assert_settled(&document, 0);
    // One pid, one incarnation, still mapped: dlclose/dlopen is not exec.
    assert_eq!(document["callers"].as_array().unwrap().len(), 1);
    assert_eq!(
        document["callers"][0]["pid"].as_u64().unwrap(),
        u64::from(driver_pid)
    );
    assert_eq!(document["callers"][0]["lifecycle"], "mapped");
    let caller_id = document["callers"][0]["id"].as_str().unwrap().to_string();
    // Two physical instances under one path: the mutation split them.
    let prov_str = prov.to_string_lossy().into_owned();
    let ours: Vec<&serde_json::Value> = document["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|module| {
            module["paths"]
                .as_array()
                .unwrap()
                .iter()
                .any(|path| path.as_str().unwrap() == prov_str)
        })
        .collect();
    assert_eq!(ours.len(), 2, "one path, two instances");
    assert_ne!(ours[0]["id"], ours[1]["id"]);
    assert_ne!(
        ours[0]["identity"]["sha256"], ours[1]["identity"]["sha256"],
        "v1 and v2 bytes differ"
    );
    let (old, new) = if ours[0]["lifecycle"] == "unloaded" {
        (ours[0], ours[1])
    } else {
        (ours[1], ours[0])
    };
    // The complete rescan proved v1 gone (sticky unload) while v2 maps.
    assert_eq!(old["lifecycle"], "unloaded");
    assert_eq!(old["unloaded_observed"], true);
    assert_eq!(new["lifecycle"], "mapped");
    let edge_for = |module: &str| {
        document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|edge| edge["caller"] == caller_id && edge["module"] == module)
            .unwrap()
            .clone()
    };
    let old_edge = edge_for(old["id"].as_str().unwrap());
    let new_edge = edge_for(new["id"].as_str().unwrap());
    assert_eq!(old_edge["mapping"]["state"], "ended");
    assert_eq!(old_edge["mapping"]["interruptions"], 1);
    assert!(old_edge["mapping"]["reason"].is_string());
    assert_eq!(new_edge["mapping"]["state"], "mapped");
    assert_eq!(new_edge["entries"]["count"], 0);
    drop(coordinator);
    coordinator_scope.assert_delta(0);
    drop(reaper);
    assert_workload_worker_reaped(driver_pid);
}

#[test]
fn discovery_loss_marks_uncertain_with_exact_gaps() {
    isolated_workload("discovery-loss");
}

/// Event/discovery-loss injection, callable from the test above and
/// from the RSS worker.
fn inject_discovery_loss() {
    let scope = FdScope::open("discovery loss injection");
    let mut harness = harness();
    let spec = ScaleSpec {
        name: "loss",
        callers: 4,
        modules: 2,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 70_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    // Event loss before the discovery loss: a usage batch for an edge
    // that was never mapped drops with its own gap.
    let now = harness.now_ns();
    let caller = harness.coordinator().adapter().live_id(70_000).unwrap();
    let ghost = ModuleKey::physical(8, 9, 999, Some("ghost".into()), "/loss/ghost.so");
    harness
        .coordinator_mut()
        .registry_mut()
        .observe_entries(caller, &ghost, 5, now);
    harness.commit();
    // Discovery loss: a pass with no observation behind it. Live
    // callers stay live; their edges turn uncertain — neither
    // confirmed nor refuted.
    let report = harness.observe_loss("injected discovery loss");
    assert_eq!(report.scanned, 0);
    scope.assert_delta(0);
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 4,
            modules: 2,
            edges: 8,
            endpoints: 8,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(2),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    assert_eq!(document["observation"]["passes"], 3);
    for edge in document["edges"].as_array().unwrap() {
        assert_eq!(edge["mapping"]["state"], "uncertain");
    }
    let subjects: Vec<&str> = document["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|gap| gap["subject"].as_str().unwrap())
        .collect();
    assert_eq!(
        subjects,
        [
            "entry without mapping evidence",
            "scan pass produced no observation"
        ]
    );
}

#[test]
fn caller_churn_storm_settles_with_exact_ledger() {
    isolated_workload("churn");
}

/// Caller churn (spawn/exit storm), callable from the test above and
/// from the RSS worker. RSS itself is bounded by the worker's isolated
/// peak, never by an in-process delta (RSS is process-global and the
/// suite runs parallel).
fn run_churn_storm() {
    let scope = FdScope::open("caller churn storm");
    let mut harness = harness();
    // 128 pids × 8 generations: a spawn/exit storm with PID reuse.
    let spec = ChurnSpec {
        pids: 128,
        generations: 8,
        modules: 16,
        first_pid: 80_000,
    };
    let (admitted, events) = harness.run_churn(&spec);
    assert_eq!(admitted, 1024, "every generation admits every pid");
    let exits = events
        .iter()
        .filter(|event| matches!(event, CallerEvent::Exited { .. }))
        .count();
    assert_eq!(exits, 1024, "every incarnation retires exactly once");
    scope.assert_delta(0);
    let document = harness.render();
    assert_ledger(
        &document,
        &Ledger {
            callers: 1024,
            modules: 16,
            edges: 1024,
            endpoints: 64,
            callers_refused: 0,
            modules_refused: 0,
            edges_refused: 0,
            endpoints_refused: 0,
            gaps: Some(0),
            gaps_suppressed: 0,
        },
    );
    assert_settled(&document, 0);
    // Terminal settlement, every record: all 1024 retired with reasons,
    // all 1024 edges ended with reasons, modules unknown (a dead
    // caller's absence proves no unload).
    for caller in document["callers"].as_array().unwrap() {
        assert_eq!(caller["lifecycle"], "exited");
        assert_eq!(caller["retired"], true);
    }
    for edge in document["edges"].as_array().unwrap() {
        assert_eq!(edge["mapping"]["state"], "ended");
    }
    for module in document["modules"].as_array().unwrap() {
        assert_eq!(module["lifecycle"], "unknown");
    }
}

#[test]
fn interrupted_shutdown_drops_the_batch_whole_never_partial() {
    isolated_workload("shutdown");
}

/// Interrupted-shutdown injection (coordinator dropped mid-batch),
/// callable from the test above and from the RSS worker.
fn interrupt_shutdown() {
    let scope = FdScope::open("interrupted shutdown");
    // Stage a batch and render before the commit: adapter admissions are
    // live, but every staged registry fact is invisible.
    let spec = ScaleSpec {
        name: "interrupted",
        callers: 8,
        modules: 4,
        edges_per_caller: 2,
        endpoints_per_module: 4,
        first_pid: 90_000,
    };
    let mut doomed = harness();
    doomed.stage_scale(&spec);
    let pre = doomed.render();
    assert_eq!(pre["callers"].as_array().unwrap().len(), 8);
    assert_eq!(pre["modules"].as_array().unwrap().len(), 0);
    assert_eq!(pre["edges"].as_array().unwrap().len(), 0);
    // The coordinator drops mid-batch: 16 staged mappings, zero
    // published. Recovery is a deterministic re-run, and the replay's
    // applied count is the exact loss accounting of the dropped batch.
    drop(doomed);
    let mut replay = harness();
    replay.stage_scale(&spec);
    let receipt = replay.commit();
    assert_eq!(receipt.registry_facts, receipt.registry_published);
    assert_eq!(receipt.registry_applied, 16, "the dropped batch staged 16");
    scope.assert_delta(0);
    let document = replay.render();
    assert_ledger(&document, &spec.expected_ledger());
    assert_settled(&document, 0);
}

// ---------------------------------------------------------------------------
// D: honest history — retention caps, eviction markers, never silent.
// ---------------------------------------------------------------------------

#[test]
fn retention_overflow_marks_eviction_never_silent_completeness() {
    use crate::discovery::caller_registry::RegistryGap;
    let mut harness = limited(64, 64, 64, 1024, 1 << 20, 64);
    let spec = ScaleSpec {
        name: "retention",
        callers: 3,
        modules: 1,
        edges_per_caller: 1,
        endpoints_per_module: 4,
        first_pid: 95_000,
    };
    harness.stage_scale(&spec);
    harness.commit();
    // Three edges, three mapping truths: ended (complete evidence),
    // uncertain (truncated observation), mapped (live evidence).
    let now = harness.now_ns();
    harness.source().kill(95_000);
    let observed: BTreeSet<u32> = [95_001, 95_002].into_iter().collect();
    let events = harness.coordinator_mut().adapter_mut().reconcile(
        &observed,
        &mut |_| ImageAuthority::ScanPinned,
        now,
    );
    harness
        .coordinator_mut()
        .apply_reconcile_events(&events, now);
    let middle = harness.coordinator().adapter().live_id(95_001).unwrap();
    harness
        .coordinator_mut()
        .registry_mut()
        .note_member_unscanned(middle);
    // Overflow gap retention: 1500 staged into a 1024 bound.
    for index in 0..1500 {
        harness
            .coordinator_mut()
            .registry_mut()
            .record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: format!("retention probe {index}"),
                reason: "the retention test overflows the gap bound on purpose".into(),
                budget: None,
            });
    }
    harness.commit();
    let document = harness.render();
    let gaps = document["gaps"].as_array().unwrap();
    assert_eq!(gaps.len(), 1024, "retention caps at the bound");
    assert_eq!(document["gaps_suppressed"], 476, "476 evicted, exactly");
    assert_eq!(document["budgets"]["retained_history"]["retained"], 1024,);
    assert_eq!(document["budgets"]["retained_history"]["suppressed"], 476,);
    assert_settled(&document, 476);
    let text = crate::inventory::render_text(harness.coordinator(), "workload", 0, now, 2);
    assert!(
        text.contains("gaps suppressed: 476"),
        "the text summary marks the eviction:\n{text}"
    );
    // No silent completeness claim: no key anywhere names completeness.
    fn assert_no_completeness(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    assert!(
                        key != "complete" && key != "completeness",
                        "no completeness claim key"
                    );
                    assert_no_completeness(child);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    assert_no_completeness(item);
                }
            }
            _ => {}
        }
    }
    assert_no_completeness(&document);
    // Observed-complete vs truncated vs unknown, in one document.
    let states: BTreeSet<&str> = document["edges"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge| edge["mapping"]["state"].as_str().unwrap())
        .collect();
    assert_eq!(
        states,
        ["ended", "mapped", "uncertain"].into_iter().collect()
    );
    for edge in document["edges"].as_array().unwrap() {
        assert_eq!(
            edge["entries"]["observation"],
            "unknown (usage observation unavailable)"
        );
        assert_eq!(edge["semantics"], "unknown (semantic capture withheld)");
    }
}

// ---------------------------------------------------------------------------
// C: one isolated RSS bound for every in-crate injection.
// ---------------------------------------------------------------------------

/// Stated peak-RSS bound for the whole injection battery (admission
/// failures, discovery loss, interrupted shutdown, provider mutation,
/// and the 1024-incarnation churn storm) in one isolated process.
/// Measured at ~38 MiB (test binary baseline plus the battery); the
/// 256 MiB bound leaves headroom for allocator and platform variance
/// while still catching runaway growth.
const INJECTION_RSS_BOUND_BYTES: u64 = 256 << 20;

/// RSS worker: re-runs every in-crate injection body in one isolated
/// process and prints its peak RSS. A no-op in normal suite runs (the
/// env gate is set only by the parent test's re-exec); the bodies'
/// own assertions re-verify the ledgers in isolation as a bonus.
#[test]
fn workload_rss_worker() {
    if std::env::var_os("P11SCOPE_WORKLOAD_RSS_WORKER").is_none() {
        return;
    }
    inject_admission_failures();
    inject_discovery_loss();
    interrupt_shutdown();
    inject_provider_mutation();
    run_churn_storm();
    println!("WORKLOAD_RSS_HWM_BYTES {}", peak_rss_bytes());
}

#[test]
fn injected_workloads_stay_within_rss_bound() {
    let output = run_workload_worker("rss", std::time::Duration::from_secs(60));
    assert_workload_worker_reaped(output.pid);
    let stdout = output
        .result
        .expect("the RSS worker runs every injection green");
    let hwm: u64 = stdout
        .lines()
        .find_map(|line| line.strip_prefix("WORKLOAD_RSS_HWM_BYTES ")?.parse().ok())
        .expect("the worker prints its peak RSS");
    assert!(
        hwm < INJECTION_RSS_BOUND_BYTES,
        "injection battery peak RSS {hwm} bytes stays within {INJECTION_RSS_BOUND_BYTES}"
    );
}

// ---------------------------------------------------------------------------
// C1b: callers past the deep-scan cap, through the coordinator.
// ---------------------------------------------------------------------------

mod c1b {
    use super::*;
    use crate::inspect_system::{
        AdmissionRecord, AdmissionSummary, Catalog, CatalogObject, MemberGeneration, MemberStatus,
        Observation, ObservationEvidence, ProcessRecord,
    };
    use crate::process::ProcessViewId;
    use p11scope_manifest::maps::{Device, ObjectKey};

    const REP: u32 = 10_000;
    const CALLERS: u32 = 300;
    const IDLE: u32 = 148;

    fn start(pid: u32) -> u64 {
        1_000 + u64::from(pid)
    }

    fn driver() -> ExeIdentity {
        ExeIdentity {
            dev: 1,
            ino: 100,
            mtime_secs: 10,
            mtime_nanos: 0,
            path: Some("/bin/driver".into()),
        }
    }

    fn generation(pid: u32) -> Option<MemberGeneration> {
        Some(MemberGeneration {
            start_time: Some(start(pid)),
            exe: Some(driver()),
        })
    }

    fn observation(pid: u32, evidence: ObservationEvidence) -> Observation {
        Observation {
            pid,
            path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
            double_loaded: false,
            evidence,
        }
    }

    /// The catalog `inspect_system::collect` assembles for 448 processes
    /// over a 256 cap: one deep-scanned SoftHSM2 caller, 299 identical
    /// callers attributed by maps identity, 148 idle processes. `drop`
    /// lists callers whose catalog no longer shows the provider.
    fn catalog(drop: &[u32], generations: &[(u32, Option<MemberGeneration>)]) -> Catalog {
        let callers: Vec<u32> = (REP..REP + CALLERS)
            .filter(|pid| !drop.contains(pid))
            .collect();
        let object = CatalogObject {
            path: "/usr/lib/softhsm/libsofthsm2.so".into(),
            key: ObjectKey {
                device: Device { major: 8, minor: 1 },
                inode: 4_242,
            },
            sha256: Some("sha-softhsm2".into()),
            build_id: None,
            identity_source: Some("mountinfo"),
            note: None,
            mappings: callers
                .iter()
                .map(|pid| (*pid, (*pid == REP).then_some(ProcessViewId(0))))
                .collect(),
            observations: callers
                .iter()
                .map(|pid| {
                    observation(
                        *pid,
                        if *pid == REP {
                            ObservationEvidence::DeepScan
                        } else {
                            ObservationEvidence::MapsMatch
                        },
                    )
                })
                .collect(),
            admission: AdmissionRecord::Admitted {
                class: "heuristic",
                endpoints: 68,
            },
        };
        let mut processes: Vec<ProcessRecord> = (REP..REP + CALLERS)
            .map(|pid| ProcessRecord {
                application: crate::inspect_identity::InspectApplicationResult::Unknown(
                    crate::inspect_identity::InspectIdentityUnknown::NotExamined,
                ),
                complete_scan: None,
                pid,
                status: if pid == REP {
                    MemberStatus::Scanned
                } else {
                    MemberStatus::MapsMatched
                },
                objects: if drop.contains(&pid) {
                    Vec::new()
                } else {
                    vec![0]
                },
                generation: generations
                    .iter()
                    .find(|(known, _)| *known == pid)
                    .map_or_else(|| generation(pid), |(_, scripted)| scripted.clone()),
            })
            .collect();
        processes.extend((20_000..20_000 + IDLE).map(|pid| ProcessRecord {
            application: crate::inspect_identity::InspectApplicationResult::Unknown(
                crate::inspect_identity::InspectIdentityUnknown::NotExamined,
            ),
            complete_scan: None,
            pid,
            status: MemberStatus::NotSelected { loss: None },
            objects: Vec::new(),
            generation: None,
        }));
        Catalog {
            scan_status: "complete",
            lowering: None,
            enumerated: (CALLERS + IDLE) as usize,
            selected: 2,
            scanned: 2,
            maps_matched: (CALLERS - 1) as usize,
            unexamined: 0,
            unexamined_objects: 0,
            snapshots_unavailable: 0,
            attribution_losses: BTreeMap::new(),
            cap: 256,
            scan_ms: 0,
            processes,
            objects: vec![object],
            relationships: Vec::new(),
            admission: AdmissionSummary {
                uncorroborated_candidates: 0,
                module_ambiguous: 0,
                admitted: 1,
                refused: 0,
                unresolved: 0,
            },
            skipped: Vec::new(),
            notes: Vec::new(),
            explanation: None,
            stage_timings: crate::timing::StageTimings::new(),
        }
    }

    fn spawned() -> Harness {
        let mut harness = harness();
        for pid in (REP..REP + CALLERS).chain(20_000..20_000 + IDLE) {
            harness.source().spawn(pid, start(pid));
        }
        harness.advance(1);
        harness
    }

    fn edge_of(document: &serde_json::Value, pid: u32) -> Option<serde_json::Value> {
        let caller = document["callers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|caller| caller["pid"] == pid && caller["retired"] == false)?["id"]
            .clone();
        document["edges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|edge| edge["caller"] == caller)
            .cloned()
    }

    #[test]
    fn every_identical_caller_past_the_cap_registers_with_an_edge() {
        let mut harness = spawned();
        let report = harness.apply_catalog(catalog(&[], &[]));
        assert_eq!(report.scanned, CALLERS as usize);
        assert_eq!(report.maps_matched, (CALLERS - 1) as usize);
        let document = harness.render();
        assert_eq!(
            document["callers"].as_array().unwrap().len(),
            CALLERS as usize
        );
        assert_eq!(document["modules"].as_array().unwrap().len(), 1);
        let edges = document["edges"].as_array().unwrap();
        assert_eq!(edges.len(), CALLERS as usize);
        assert!(
            edges
                .iter()
                .all(|edge| edge["mapping"]["state"] == "mapped")
        );
        let evidence = |label: &str| {
            edges
                .iter()
                .filter(|edge| edge["mapping"]["evidence"] == label)
                .count()
        };
        assert_eq!(evidence("deep_scan"), 1);
        assert_eq!(evidence("maps_match"), (CALLERS - 1) as usize);
        // The usage coverage shape stays the seven keys.
        let coverage = edges[0]["entries"]["coverage"].as_object().unwrap();
        assert_eq!(coverage.len(), 7);
    }

    #[test]
    fn a_maps_match_absence_is_uncertain_while_a_deep_scan_absence_ends() {
        let mut harness = spawned();
        harness.apply_catalog(catalog(&[], &[]));
        harness.advance(1);
        harness.apply_catalog(catalog(&[REP, REP + 5], &[]));
        let document = harness.render();
        assert_eq!(
            edge_of(&document, REP).unwrap()["mapping"]["state"],
            "ended",
            "a complete deep scan proves the absence"
        );
        assert_eq!(
            edge_of(&document, REP + 5).unwrap()["mapping"]["state"],
            "uncertain",
            "a maps match decoded nothing: its absence is never authoritative"
        );
        assert_eq!(
            edge_of(&document, REP + 6).unwrap()["mapping"]["state"],
            "mapped"
        );
    }

    #[test]
    fn a_generation_or_image_the_caller_is_not_never_projects() {
        let mut harness = spawned();
        let mut exec = driver();
        exec.ino = 101;
        let reused = Some(MemberGeneration {
            start_time: Some(start(REP + 1) + 1),
            exe: Some(driver()),
        });
        let execed = Some(MemberGeneration {
            start_time: Some(start(REP + 2)),
            exe: Some(exec),
        });
        let blind = Some(MemberGeneration {
            start_time: Some(start(REP + 3)),
            exe: None,
        });
        let deep_reused = Some(MemberGeneration {
            start_time: Some(start(REP) + 7),
            exe: None,
        });
        harness.apply_catalog(catalog(
            &[],
            &[
                (REP + 1, reused),
                (REP + 2, execed),
                (REP + 3, blind),
                (REP, deep_reused),
            ],
        ));
        let document = harness.render();
        for pid in [REP, REP + 1, REP + 2, REP + 3] {
            assert!(
                edge_of(&document, pid).is_none(),
                "pid {pid} must not project"
            );
        }
        assert_eq!(
            document["edges"].as_array().unwrap().len(),
            (CALLERS - 4) as usize
        );
        let gap = document["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|gap| gap["subject"] == "caller generation join refused")
            .expect("the refused joins are one counted gap");
        let reason = gap["reason"].as_str().unwrap();
        assert!(reason.contains("2 generation_changed"), "{reason}");
        assert!(reason.contains("1 exec_changed"), "{reason}");
        assert!(reason.contains("1 confirm_unreadable"), "{reason}");
    }

    fn join_refusal_reason(document: &serde_json::Value) -> String {
        document["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|gap| gap["subject"] == "caller generation join refused")
            .expect("the refused join is one counted gap")["reason"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The deep-scan lane refuses an image other than the admitted one
    /// when both were read, exactly as the maps lane does.
    #[test]
    fn the_deep_scan_lane_refuses_an_exec_both_sides_read() {
        let mut harness = spawned();
        let mut exec = driver();
        exec.ino = 101;
        harness.apply_catalog(catalog(
            &[],
            &[(
                REP,
                Some(MemberGeneration {
                    start_time: Some(start(REP)),
                    exe: Some(exec),
                }),
            )],
        ));
        let document = harness.render();
        assert!(
            edge_of(&document, REP).is_none(),
            "the deep scan must not project"
        );
        assert!(edge_of(&document, REP + 1).is_some());
        let reason = join_refusal_reason(&document);
        assert!(reason.contains("1 exec_changed"), "{reason}");
    }

    /// A start time neither the collection nor the admission could read
    /// joins nothing, in the deep-scan lane too: `None == None` is no
    /// proof of one generation.
    #[test]
    fn the_deep_scan_lane_refuses_a_start_time_neither_side_read() {
        let mut harness = spawned();
        harness.source().blind(REP);
        harness.apply_catalog(catalog(
            &[],
            &[(
                REP,
                Some(MemberGeneration {
                    start_time: None,
                    exe: None,
                }),
            )],
        ));
        let document = harness.render();
        assert!(
            edge_of(&document, REP).is_none(),
            "the deep scan must not project"
        );
        assert!(edge_of(&document, REP + 1).is_some());
        let reason = join_refusal_reason(&document);
        assert!(reason.contains("1 generation_changed"), "{reason}");
    }

    #[test]
    fn identical_budget_refusal_aggregates_across_passes_into_one_repeated_gap() {
        let limits = RegistryLimits::new(100, 4096, 32768, 1024, 1_048_576, 32768).unwrap();
        let mut harness = Harness::new(limits).unwrap();
        for pid in (REP..REP + CALLERS).chain(20_000..20_000 + IDLE) {
            harness.source().spawn(pid, start(pid));
        }
        harness.apply_catalog(catalog(&[], &[]));
        harness.advance(1);
        harness.apply_catalog(catalog(&[], &[]));
        let document = harness.render();
        assert_eq!(document["callers"].as_array().unwrap().len(), 100);
        let refusals: Vec<&serde_json::Value> = document["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|gap| gap["subject"] == "caller admission failed")
            .collect();
        // Two passes publish the identical aggregate: one gap, repeated.
        assert_eq!(
            refusals.len(),
            1,
            "one per distinct aggregate, not per pid or pass: {refusals:?}"
        );
        assert_eq!(refusals[0]["repeats"], 2, "{refusals:?}");
        for gap in refusals {
            assert!(
                gap["reason"]
                    .as_str()
                    .unwrap()
                    .starts_with("200 admissions refused this pass"),
                "{gap}"
            );
            assert_eq!(gap["budget"]["resource"], "callers");
            assert_eq!(gap["budget"]["limit"], 100);
        }
    }
}

#[test]
fn fd_census_quiescence_retries_until_two_attempts_agree() {
    fn resource(tag: u64) -> FdResource {
        FdResource {
            link: std::path::PathBuf::from(format!("/dev/null#{tag}")),
            dev: 1,
            ino: tag,
            mode: 0o20000,
            rdev: 0,
            pidfd_target: None,
        }
    }
    fn census(entries: &[(i32, u64)]) -> std::collections::BTreeMap<i32, FdResource> {
        entries
            .iter()
            .map(|(fd, tag)| (*fd, resource(*tag)))
            .collect()
    }
    // Churn then settle: disagreeing attempts retry, agreement returns.
    let mut calls = 0;
    let map = quiesce_census(|| -> std::io::Result<_> {
        calls += 1;
        Ok(match calls {
            1 => census(&[(3, 1), (4, 1)]),
            _ => census(&[(3, 1)]),
        })
    })
    .expect("agreeing attempts return");
    assert_eq!(calls, 3, "one churned attempt plus the agreeing pair");
    assert_eq!(map, census(&[(3, 1)]));
    // A hard error resets the streak instead of poisoning it.
    let mut calls = 0;
    let map = quiesce_census(|| -> std::io::Result<_> {
        calls += 1;
        if calls == 1 {
            return Err(std::io::Error::other("boom"));
        }
        Ok(census(&[(3, 1)]))
    })
    .expect("error then agreement returns");
    assert_eq!(calls, 3, "error plus the agreeing pair");
    assert_eq!(map.len(), 1);
    // Sustained disagreement exhausts the bound and reports honestly.
    let mut calls = 0;
    let error = quiesce_census(|| -> std::io::Result<_> {
        calls += 1;
        Ok(census(&[(3, calls as u64)]))
    })
    .expect_err("eternal churn must not return a torn census");
    assert_eq!(calls, FD_CENSUS_QUIESCE_ATTEMPTS as usize);
    assert_eq!(error.to_string(), "FD census never quiesced");
}
