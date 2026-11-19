//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Public-command breadth matrix: scale and churn workloads through the
//! real `p11scope inventory` binary over owned fixtures, asserting
//! ledger agreement at command level with the harness's public API,
//! plus slow-output backpressure, unwritable-`-o` honesty, and
//! SIGKILL-mid-run atomicity.

use p11scope::discovery::inventory_workload::{FdScope, assert_settled, assert_subset_ledger};
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use support::DieWithParent as _;

#[allow(dead_code)]
mod support;

#[path = "support/multi_host.rs"]
mod multi_host;

/// Breadth/churn always check their mapping ledgers. Eligible hosts retain
/// the live Auto path; other hosts first prove the exact early refusal, then
/// run the explicit offline path rather than treating refusal as a snapshot.
fn system_capture_args() -> Vec<&'static str> {
    if let Some(reason) = multi_host::refusal() {
        let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
            .args(["inventory", "--system", "--capture", "native", "--json"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        assert_eq!(
            String::from_utf8(output.stderr).unwrap(),
            format!("p11scope: inventory --system: {reason}\n")
        );
        vec!["--capture", "scan", "--identity-backend", "userspace"]
    } else {
        vec!["--capture", "auto"]
    }
}

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

/// One real legacy68 table with exact own-export evidence for every retained
/// target. Sparse tails contain observedNULLs, not aliases or guessed fields.
fn capacity_provider(dir: &Path, name: &str, unique: usize) -> PathBuf {
    assert!((1..=68).contains(&unique));
    let mut source = String::from(
        "typedef unsigned long CK_RV;\n\
         typedef struct { unsigned char version[2]; void *functions[68]; } Table;\n\
         CK_RV C_GetFunctionList(void **out);\n",
    );
    let mut slots = vec!["0".to_string(); 68];
    slots[3] = "(void *)C_GetFunctionList".into();
    for ordinal in (0..68).filter(|ordinal| *ordinal != 3).take(unique - 1) {
        let function = pkcs11_module::function_name(ordinal).unwrap();
        source.push_str(&format!("CK_RV {function}(void) {{ return 0; }}\n"));
        slots[ordinal] = format!("(void *){function}");
    }
    source.push_str(&format!(
        "static Table table = {{{{2,40}}, {{{}}}}};\n\
         CK_RV C_GetFunctionList(void **out) {{ if (!out) return 7; *out = &table; return 0; }}\n",
        slots.join(","),
    ));
    let path = dir.join(format!("{name}.c"));
    std::fs::write(&path, source).unwrap();
    gcc(
        dir,
        &format!("{name}.so"),
        &path,
        &["-shared", "-fPIC"],
        &[],
    )
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
    spawn_with_peak_pumping(cmd, stderr_log, &mut || false)
}

/// Default for `P11SCOPE_TEST_TIME_SCALE`, matching the contract suite.
const DEFAULT_TEST_TIME_SCALE: f64 = 5.0;

/// A SLACK hang-guard bound in whole seconds: `base` scaled by
/// `P11SCOPE_TEST_TIME_SCALE`. Use only where expiry can mean nothing but
/// failure: the churn run stops on progress, so a healthy run never waits
/// this out and only a stalled host approaches it.
fn slack_secs(base: u64) -> u64 {
    let scale = match std::env::var("P11SCOPE_TEST_TIME_SCALE") {
        Ok(raw) if !raw.trim().is_empty() => raw.trim().parse::<f64>().unwrap_or(f64::NAN),
        _ => DEFAULT_TEST_TIME_SCALE,
    };
    assert!(
        scale.is_finite() && scale >= 1.0,
        "P11SCOPE_TEST_TIME_SCALE must be a finite number >= 1"
    );
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let scaled = (base as f64 * scale).ceil() as u64;
    scaled
}

/// `spawn_with_peak` with a hook the churn test uses to tail the
/// observer's event log while it runs. The hook must be infallible and
/// cheap: it runs every 5 ms until the child exits. It returns true once
/// the run has reached the progress the test needs; the child then gets
/// exactly one SIGTERM (its graceful stop path still writes every sink)
/// and the loop keeps pumping and draining until it exits.
fn spawn_with_peak_pumping(
    cmd: &mut Command,
    stderr_log: &Path,
    pump: &mut dyn FnMut() -> bool,
) -> (std::process::Output, u64) {
    cmd.stderr(std::fs::File::create(stderr_log).unwrap());
    cmd.die_with_parent();
    let mut child = cmd.spawn().unwrap();
    let pid = child.id();
    // Drain stdout while the child runs: the final report can exceed the
    // 64 KiB pipe (an unaimed --system run names every unselected process),
    // and the observer's writer watchdog fails the run when nobody reads.
    let stdout = child
        .stdout
        .take()
        .expect("spawn_with_peak callers pipe stdout");
    let drain = std::thread::spawn(move || {
        use std::io::Read as _;
        let mut stdout = stdout;
        let mut bytes = Vec::new();
        stdout
            .read_to_end(&mut bytes)
            .expect("drain observer stdout");
        bytes
    });
    let mut peak = 0u64;
    // Latched: the observer ends its run on the first signal and exits at
    // once on a second one, so progress may request the stop any number of
    // times but the signal goes out exactly once. The pid cannot be reused
    // here: the child is our live unreaped descendant until the wait below.
    let mut stop_signalled = false;
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
        if pump() && !stop_signalled {
            stop_signalled = true;
            // SAFETY: signalling our live child, whose pid stays ours until
            // reaped; SIGTERM runs its graceful stop path, which still
            // writes the report and event sinks.
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        match child.try_wait().unwrap() {
            Some(_) => break,
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    let mut output = child.wait_with_output().unwrap();
    output.stdout = drain.join().expect("stdout drain thread");
    (output, peak)
}

/// Terminal settlement at command level: the full structural check
/// plus suppression consistency. The exact suppressed COUNT depends on
/// live machine state (unreadable pids per pass × passes), so the
/// in-crate retention test pins exactness (476) while command level
/// pins structure, budget-row agreement, and cap engagement. The in-run
/// cap is 8192 (`DEFAULT_MAX_GAPS`); stop-time disclosures may add up to
/// 64 headroom rows (`TERMINAL_GAP_RESERVE`), so an engaged cap reads
/// 8192..=8256.
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
        let len = doc["gaps"].as_array().unwrap().len();
        assert!(
            (8192..=8256).contains(&len),
            "suppression means the 8192 in-run retention cap engaged; stop-time headroom allows up to 8256 rows, got {len}"
        );
    }
}

#[test]
fn invalid_inventory_endpoint_budget_precedes_every_sink() {
    let _guard = serial_guard();
    let dir = tmp("inventory-invalid-endpoint-budget");
    let report = dir.join("report.json");
    let events = dir.join("events.jsonl");
    let diagnostics = dir.join("diagnostics");
    let output = Command::new(env!("CARGO_BIN_EXE_p11scope"))
        .args(["inventory", "--system", "--max-endpoints", "131073"])
        .arg("-o")
        .arg(&report)
        .arg("--event-log")
        .arg(&events)
        .arg("--diagnostics")
        .arg(&diagnostics)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("--max-endpoints") && stderr.contains("1-131072"),
        "a policy error names the selected endpoint range: {stderr}"
    );
    assert!(output.stdout.is_empty());
    assert!(
        !report.exists(),
        "invalid selection must not create a report"
    );
    assert!(
        !events.exists(),
        "invalid selection must not create an event log"
    );
    assert!(
        !diagnostics.exists(),
        "invalid selection must not create diagnostic output"
    );
}

/// Independently enumerate the owned fixture's published canonical table. The
/// observer never executes this code: this is the test application calling
/// its own provider, then translating its function addresses through its
/// own executable mappings. No attach plan or observer result supplies the
/// population count.
fn fixture_endpoint_offsets(provider: &Path) -> BTreeSet<u64> {
    #[repr(C)]
    struct Table {
        version: [u8; 2],
        functions: [*mut libc::c_void; 68],
    }
    struct Library(*mut libc::c_void);
    impl Drop for Library {
        fn drop(&mut self) {
            assert_eq!(unsafe { libc::dlclose(self.0) }, 0);
        }
    }

    let path = std::ffi::CString::new(provider.as_os_str().as_encoded_bytes()).unwrap();
    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(
        !handle.is_null(),
        "load owned fixture {}",
        provider.display()
    );
    let library = Library(handle);
    let symbol = unsafe { libc::dlsym(library.0, c"C_GetFunctionList".as_ptr()) };
    assert!(!symbol.is_null());
    let get_list: unsafe extern "C" fn(*mut *mut Table) -> libc::c_ulong =
        unsafe { std::mem::transmute(symbol) };
    let mut table = std::ptr::null_mut();
    assert_eq!(unsafe { get_list(&mut table) }, 0);
    let table = unsafe { table.as_ref() }.unwrap();
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    table
        .functions
        .iter()
        .filter(|function| !function.is_null())
        .map(|function| {
            let address = *function as u64;
            maps.lines()
                .find_map(|line| {
                    let fields: Vec<_> = line.split_whitespace().collect();
                    let (start, end) = fields[0].split_once('-').unwrap();
                    let start = u64::from_str_radix(start, 16).unwrap();
                    let end = u64::from_str_radix(end, 16).unwrap();
                    (start <= address && address < end).then(|| {
                        assert!(fields[1].contains('x'), "fixture target must be executable");
                        assert_eq!(fields[5], provider.to_str().unwrap());
                        u64::from_str_radix(fields[2], 16).unwrap() + address - start
                    })
                })
                .expect("each published fixture endpoint has a file-backed executable mapping")
        })
        .collect()
}

/// Pin the fixture through the same held-FD mapping helper as the public
/// qualification runners. Btrfs's fstat device is a different identity domain.
fn fixture_mapped_key(provider: &Path) -> (u64, u64, u64) {
    let output = Command::new("python3")
        .arg("-I")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/mapped-provider-pin.py"))
        .arg(provider)
        .output()
        .unwrap();
    assert!(output.status.success(), "held provider pin: {:?}", output);
    let pin: Value = serde_json::from_slice(&output.stdout).unwrap();
    (
        pin["dev"][0].as_u64().unwrap(),
        pin["dev"][1].as_u64().unwrap(),
        pin["ino"].as_u64().unwrap(),
    )
}

#[test]
fn inventory_capacity_public_exact_discoverable_boundaries() {
    let _guard = serial_guard();
    let dir = tmp("inventory-exact-capacity-boundaries");
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    let full = capacity_provider(&dir, "full", 68);
    let full_offsets = fixture_endpoint_offsets(&full);
    assert_eq!(
        full_offsets.len(),
        68,
        "one canonical table; unused interface exports are absent"
    );
    for demand in [4097, 6531, 8192] {
        let population = dir.join(demand.to_string());
        std::fs::create_dir(&population).unwrap();
        let count = demand / full_offsets.len();
        let remainder = demand % full_offsets.len();
        let tail = capacity_provider(&population, "tail", remainder);
        let tail_offsets = fixture_endpoint_offsets(&tail);
        assert_eq!(tail_offsets.len(), remainder, "independent physical tail");
        let mut providers = Vec::new();
        let mut union = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for index in 0..=count {
            let provider = population.join(format!("provider-{index:03}.so"));
            let (template, offsets) = if index == count {
                (&tail, &tail_offsets)
            } else {
                (&full, &full_offsets)
            };
            std::fs::copy(template, &provider).unwrap();
            let identity = fixture_mapped_key(&provider);
            assert!(
                identities.insert(identity),
                "each copy has a distinct mapped inode"
            );
            for offset in offsets {
                union.insert((identity, *offset));
            }
            providers.push(provider);
        }
        assert_eq!(
            union.len(),
            demand,
            "deduplicated mapped object/offset union before observer execution"
        );
        let alias = population.join("hardlink-alias.so");
        std::fs::hard_link(&providers[0], &alias).unwrap();
        assert_eq!(
            fixture_mapped_key(&alias),
            fixture_mapped_key(&providers[0])
        );
        let mut loaded = providers.clone();
        loaded.push(alias);
        let ready = population.join("ready");
        let output_path = population.join("inventory.json");
        let stderr = population.join("inventory.stderr");
        let mut command = Command::new("sh");
        command
            .arg(fixture_source("inventory-scale-observe.sh"))
            .args([
                "--system",
                "--json",
                "--capture",
                "scan",
                "--identity-backend",
                "userspace",
                "--max-scan-pids",
                "64",
                "--max-endpoints",
                "8192",
            ]);
        for provider in &loaded {
            command.arg("--module").arg(provider);
        }
        command
            .env("INV_DRIVER", &driver)
            .env("INV_COUNT", "1")
            .env(
                "INV_PROVIDERS",
                loaded
                    .iter()
                    .map(|path| path.to_str().unwrap())
                    .collect::<Vec<_>>()
                    .join(" "),
            )
            .env("INV_READY", &ready)
            .env("INV_OUT", &output_path)
            .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        let (output, peak) = spawn_with_peak(&mut command, &stderr);
        let _fixture = FixtureGuard {
            pids: vec![ready_pid(&ready.join("S001.ready"))],
        };
        assert!(
            output.status.success(),
            "boundary{demand}: {}",
            std::fs::read_to_string(&stderr).unwrap()
        );
        assert!(
            peak < OBSERVER_RSS_BOUND_BYTES,
            "boundary{demand}: peak RSS{peak}"
        );
        let document: Value =
            serde_json::from_slice(&std::fs::read(&output_path).unwrap()).unwrap();
        assert_eq!(document["budgets"]["inventory_endpoints"]["limit"], 8192);
        assert_eq!(
            document["budgets"]["inventory_endpoints"]["occupied"],
            demand
        );
        assert_eq!(document["budgets"]["inventory_endpoints"]["refused"], 0);
        assert_eq!(
            document["modules"].as_array().unwrap().len(),
            providers.len(),
            "hardlink alias does not add a physical module"
        );
        for provider in &providers {
            let identity = fixture_mapped_key(provider);
            let module = document["modules"]
                .as_array()
                .unwrap()
                .iter()
                .find(|module| {
                    module["identity"]["device"]["major"].as_u64() == Some(identity.0)
                        && module["identity"]["device"]["minor"].as_u64() == Some(identity.1)
                        && module["identity"]["inode"].as_u64() == Some(identity.2)
                })
                .expect("each independently pinned provider is retained");
            assert!(
                module["paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|path| path.as_str() == provider.to_str())
            );
            assert_eq!(module["admission"]["state"], "admitted");
            assert_eq!(
                module["admission"]["endpoints"],
                if provider == providers.last().unwrap() {
                    remainder
                } else {
                    full_offsets.len()
                }
            );
        }
    }
}

#[test]
fn inventory_capacity_default_admits_and_override_admits() {
    let _guard = serial_guard();
    let dir = tmp("inventory-selected-endpoint-capacity");
    let driver = gcc(
        &dir,
        "driver",
        &fixture_source("catalog-driver.c"),
        &["-O2", "-Wall", "-Wextra", "-Werror"],
        &["-ldl"],
    );
    // Keep the exact4140 demand using getter-proven legacy storage, with
    // independently corroborated targets instead of a label-sized legacy read.
    let template = capacity_provider(&dir, "template", 68);
    let tail = capacity_provider(&dir, "tail", 60);
    let offsets = fixture_endpoint_offsets(&template);
    let tail_offsets = fixture_endpoint_offsets(&tail);
    assert_eq!(
        offsets.len(),
        68,
        "distinct published physical function offsets"
    );
    assert_eq!(tail_offsets.len(), 60);
    let mut providers = Vec::new();
    let mut physical_union = BTreeSet::new();
    for index in 0..=60 {
        let provider = dir.join(format!("capacity-{index:02}.so"));
        let (source, own_offsets) = if index == 60 {
            (&tail, &tail_offsets)
        } else {
            (&template, &offsets)
        };
        std::fs::copy(source, &provider).unwrap();
        let metadata = std::fs::metadata(&provider).unwrap();
        for offset in own_offsets {
            physical_union.insert((metadata.dev(), metadata.ino(), *offset));
        }
        providers.push(provider);
    }
    assert_eq!(
        physical_union.len(),
        4140,
        "same bytes at distinct inodes stay distinct"
    );
    assert!(physical_union.len() > 4096);
    let provider_list = providers
        .iter()
        .map(|path| path.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    for (label, selected, dashboard) in [
        ("default", None, false),
        ("selected", Some(8192), false),
        ("dashboard", Some(8192), true),
    ] {
        let ready = dir.join(format!("ready-{label}"));
        let out = dir.join(format!("{label}.json"));
        let stderr_log = dir.join(format!("{label}.stderr"));
        let mut command = Command::new("sh");
        command
            .arg(fixture_source("inventory-scale-observe.sh"))
            .args([
                "--system",
                "--json",
                "--capture",
                "scan",
                "--identity-backend",
                "userspace",
                "--max-scan-pids",
                "64",
            ]);
        for provider in &providers {
            command.arg("--module").arg(provider);
        }
        if let Some(selected) = selected {
            command.arg("--max-endpoints").arg(selected.to_string());
        }
        if dashboard {
            command.arg("--dashboard");
        }
        command
            .env("INV_DRIVER", &driver)
            .env("INV_COUNT", "1")
            .env("INV_PROVIDERS", &provider_list)
            .env("INV_READY", &ready)
            .env("INV_OUT", &out)
            .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped());
        let (output, peak) = spawn_with_peak(&mut command, &stderr_log);
        let fixture = FixtureGuard {
            pids: vec![ready_pid(&ready.join("S001.ready"))],
        };
        let stderr = std::fs::read_to_string(&stderr_log).unwrap();
        assert!(
            output.status.success(),
            "{label}: {:?}: {stderr}",
            output.status
        );
        assert!(
            peak < OBSERVER_RSS_BOUND_BYTES,
            "{label}: observer peak RSS {peak}"
        );
        let document: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        let budget = &document["budgets"]["inventory_endpoints"];
        assert_eq!(budget["limit"], selected.unwrap_or(32768));
        assert_eq!(document["budgets"]["endpoints"]["limit"], 1_048_576);
        {
            assert_eq!(budget["occupied"], physical_union.len());
            assert_eq!(budget["refused"], 0);
            assert_eq!(
                document["modules"].as_array().unwrap().len(),
                providers.len()
            );
            for provider in &providers {
                let matching: Vec<_> = document["modules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|module| {
                        module["paths"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|path| path.as_str() == provider.to_str())
                    })
                    .collect();
                assert_eq!(
                    matching.len(),
                    1,
                    "one physical module for {}",
                    provider.display()
                );
                let module = matching[0];
                assert_eq!(
                    module["identity"]["inode"],
                    std::fs::metadata(provider).unwrap().ino()
                );
                assert_eq!(module["admission"]["state"], "admitted");
                assert_eq!(
                    module["admission"]["endpoints"],
                    if provider == providers.last().unwrap() {
                        60
                    } else {
                        68
                    }
                );
            }
        }
        drop(fixture);
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

/// The terminal gap/refusal/suppressed line is the actual honesty
/// mechanism on refused and partial runs: computed from the same snapshot
/// as the JSON document, after the terminal disclosures commit, it must name
/// exactly the gap, budget-refusal, and suppressed counts the document
/// carries. Per-pass lines are progress — cumulative when their pass
/// published — so churn after the last pass can leave them below the final
/// counts. Parses `p11scope: final: G gap(s) (R budget refusal(s), S
/// suppressed)` and pins all three against the caller's exact values.
fn assert_final_gap_line(stderr: &str, gaps: usize, refusals: usize, suppressed: u64) {
    let prefix = "p11scope: final: ";
    let line = stderr
        .lines()
        .find(|line| line.starts_with(prefix) && line.contains("budget refusal"))
        .unwrap_or_else(|| panic!("final gap/refusal/suppressed line present: {stderr:?}"));
    let rest = line.strip_prefix(prefix).unwrap();
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
        .args(system_capture_args())
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

/// A ready file still being written parses to nothing; the churn pump
/// retries on its next tick instead of panicking on a torn read.
fn try_ready_pid(ready_file: &Path) -> Option<u32> {
    std::fs::read_to_string(ready_file)
        .ok()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// True while `pid` still names our fixture driver (never signal a
/// stranger on a reused pid).
fn pid_is_driver(pid: u32, driver_exe: &str) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .is_ok_and(|exe| exe.to_string_lossy() == *driver_exe)
}

/// Scratch dir outside the worktree for product-opened outputs: the
/// product's output trust policy refuses group-writable ancestors (like
/// this repo's checkout parent), which the target-tmp dir inherits.
/// `TMPDIR` on lanes and CI runners, sticky `/tmp` elsewhere.
fn trusted_scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// True when a pending-coverage gap reason names `pid` in its bounded
/// `(pids N, M, ...)` list. Exact token match, never substring: pid 12
/// must not match 123, and a truncated `and N more` tail names nobody.
fn gap_reason_names_pid(reason: &str, pid: u32) -> bool {
    let want = pid.to_string();
    let Some(list) = reason.split("(pids ").nth(1) else {
        return false;
    };
    let list = list.split(')').next().unwrap_or("");
    list.split(", ").any(|token| {
        let token = token.strip_prefix("and ").unwrap_or(token);
        !token.contains(' ') && token == want
    })
}

/// Per-request signal outcomes for twins: the `fail_pid` request, when
/// set, returns the kernel's `-1/ESRCH` for the already-reaped
/// `dead_probe_pid`; every other request is a non-delivering
/// `kill(pid, 0)` probe returning 0 while the fixture lives. Twins run
/// the live branch (`signal_outcome: None`) over owned fixtures passing
/// the real executable checks, so both shimmed requests execute and
/// combine exactly like live `SIGTERM` requests. No signal is delivered.
#[derive(Clone, Copy)]
struct SignalShim {
    fail_pid: Option<u32>,
    dead_probe_pid: u32,
}

/// Condition driver for the churn test: tails the observer's `--event-log`
/// while it runs, births churn-C when the first pass publishes, and kills
/// the anchor plus churn-A once churn-A's admission publishes. No fixed
/// sleeps: the birth and the kill land right after the publishing pass,
/// whatever the host's pass cadence (under overrun the next pass is due
/// at once, and the deaths are observed either as absent-from-enumeration
/// or dead-at-scan-time). Infallible by construction: a missed signal
/// surfaces as a loud document assertion below, never as a pump panic.
struct ChurnCondition {
    ready: PathBuf,
    events: PathBuf,
    birth_fifo: PathBuf,
    driver_exe: String,
    offset: u64,
    pending: String,
    anchor: Option<u32>,
    churn_a: Option<u32>,
    churn_b: Option<u32>,
    spawner: Option<u32>,
    churn_c: Option<u32>,
    admitted: BTreeSet<u32>,
    exited: BTreeSet<u32>,
    killed: bool,
    kill_signalled: bool,
    kill_baseline_exited: BTreeSet<u32>,
    signal_outcome: Option<bool>,
    signal_shim: Option<SignalShim>,
    signal_requests: Vec<(u32, libc::c_int)>,
    birth_fired: bool,
    last_pass: Option<u64>,
    kill_admitting_pass: Option<u64>,
    exit_observing_pass: Option<u64>,
    file_id: Option<(u64, u64)>,
    stop_requested: bool,
    rotated: bool,
}

impl ChurnCondition {
    fn pump(&mut self) {
        if self.anchor.is_none() {
            // Ready files exist before the observer execs (the helper
            // ready-gates every fixture), so all three are pass-0
            // baseline; a torn early read retries next tick.
            let anchor = try_ready_pid(&self.ready.join("anchor.ready"));
            let churn_a = try_ready_pid(&self.ready.join("churn-a.ready"));
            let churn_b = try_ready_pid(&self.ready.join("churn-b.ready"));
            if anchor.is_none() || churn_a.is_none() || churn_b.is_none() {
                return;
            }
            self.anchor = anchor;
            self.churn_a = churn_a;
            self.churn_b = churn_b;
        }
        // The spawner pid file is pre-exec too, but it gates nothing:
        // churn-C's own pid covers the guard once born, and a missing
        // file fails loudly below instead of stalling the baseline.
        if self.spawner.is_none() {
            self.spawner = try_ready_pid(&self.ready.join("spawner.pid"));
        }
        // Churn-C is born mid-run, after the first published pass, so
        // its ready file appears on a later tick; a torn read retries.
        if self.churn_c.is_none() {
            self.churn_c = try_ready_pid(&self.ready.join("churn-c.ready"));
        }
        let mut file = match std::fs::File::open(&self.events) {
            Ok(file) => file,
            Err(_) => return,
        };
        // Rotation tripwire: the run disables rotation (wide threshold), so
        // a replaced file (device/inode change) or a shrink below the
        // consumed offset means the tail lost markers and must fail loudly
        // below instead of evaluating guards on a partial stream. Nothing
        // else replaces or truncates this file. The length check alone
        // misses a rename whose regrown file already reaches the offset.
        let meta = match file.metadata() {
            Ok(meta) => meta,
            Err(_) => return,
        };
        let id = (meta.dev(), meta.ino());
        match self.file_id {
            Some(known) if known != id => {
                self.rotated = true;
                return;
            }
            Some(_) => {}
            None => self.file_id = Some(id),
        }
        if meta.len() < self.offset {
            self.rotated = true;
            return;
        }
        if file.seek(std::io::SeekFrom::Start(self.offset)).is_err() {
            return;
        }
        let mut fresh = String::new();
        if file.read_to_string(&mut fresh).is_err() {
            return;
        }
        self.offset += fresh.len() as u64;
        self.pending.push_str(&fresh);
        // Snapshot before draining: a commit batch can land whole in one
        // tick, so the admitting pass's own marker may be processed below
        // before the kill check runs. The admitting pass is always one
        // past the last marker seen on an earlier tick: admitted events
        // precede their marker in one sequential byte stream, and
        // complete-lines-only processing keeps that order.
        let pass_before_tick = self.last_pass;
        // Complete lines only: the observer may be mid-write, and files
        // flush per line, so a newline-terminated line parses whole.
        while let Some(end) = self.pending.find('\n') {
            let line: String = self.pending.drain(..=end).collect();
            self.handle_event_line(&line);
        }
        if !self.killed && self.churn_a.is_some_and(|a| self.admitted.contains(&a)) {
            // Latched once the condition fires, even when a pid check
            // refuses the kill below: a reused pid must never be
            // signalled on a later tick, and the document assertions
            // below stay loud about the missed kill.
            self.killed = true;
            if self.kill_admitting_pass.is_none() {
                // Fallback when the admission bypassed event lines (a
                // twin pre-seeding `admitted` directly): one past the
                // last marker seen before this tick. The row-time
                // resolution in the admitted handler already covered
                // every streamed admission.
                self.kill_admitting_pass = Some(
                    pass_before_tick
                        .map(|pass| pass.saturating_add(1))
                        .unwrap_or(0),
                );
            }
            // Eligibility for the progress stop needs successful
            // requests for BOTH fixtures, not just the attempt above.
            // The scripted path injects the outcome so twins stay
            // deterministic over dead pids; the live path checks the
            // fixture identity it already holds and issues both
            // requests through the per-request seam (twins inject
            // per-request outcomes through that same seam).
            let signalled = match self.signal_outcome {
                Some(outcome) => outcome,
                None => {
                    if let (Some(churn_a), Some(anchor)) = (self.churn_a, self.anchor)
                        && pid_is_driver(churn_a, &self.driver_exe)
                        && pid_is_driver(anchor, &self.driver_exe)
                    {
                        self.request_signal(churn_a);
                        self.request_signal(anchor);
                        true
                    } else {
                        false
                    }
                }
            };
            if signalled {
                self.kill_signalled = true;
                // Refuse every death already consumed before these
                // requests: only post-request observations committed by
                // a later ordinary marker can satisfy the stop.
                self.kill_baseline_exited = self.exited.clone();
            }
        }
    }

    /// Progress stop: the kill was attempted AND successfully requested
    /// for both fixtures, a nonterminal pass past the admitting pass
    /// committed both post-request exit observations, and churn-C's
    /// birth is visible. A later pass alone proves nothing: a
    /// descheduled pump can consume pre-kill markers in one tick, a pass
    /// published after the kill request may have scanned before the
    /// signals landed, and fixtures can exit independently while a batch
    /// is buffered. The run then ends on progress instead of the wall
    /// clock; the `--duration` backstop only bounds a stalled observer.
    /// Waiting for churn-C's ready file too keeps an early stop from
    /// racing its birth: the birth trigger fired at the first pass, so by
    /// a later pass the spawner has had a full pass to fork it, and any
    /// residual lag just runs one more pass.
    fn settled_for_stop(&self) -> bool {
        self.killed
            && self.kill_signalled
            && self.churn_c.is_some()
            && matches!(
                (self.kill_admitting_pass, self.exit_observing_pass),
                (Some(admitting), Some(observing)) if observing > admitting
            )
    }

    /// One signal request, returning the raw `kill(2)` status (`0` on
    /// success). Every request is logged in order, including failures:
    /// a failing first request must not skip the second fixture.
    fn request_signal(&mut self, pid: u32) -> libc::c_int {
        let rc = match self.signal_shim {
            Some(shim) if Some(pid) == shim.fail_pid => unsafe {
                // The kernel's own result for a reaped pid: -1/ESRCH.
                libc::kill(shim.dead_probe_pid as i32, libc::SIGTERM)
            },
            Some(_) => unsafe {
                // Non-delivering existence probe: 0 while the fixture lives.
                libc::kill(pid as i32, 0)
            },
            None => unsafe { libc::kill(pid as i32, libc::SIGTERM) },
        };
        self.signal_requests.push((pid, rc));
        rc
    }

    fn handle_pass_marker(&mut self, payload: &Value) {
        // The mid-run birth trigger: the first published pass, whatever
        // its number, wakes the FIFO-blocked spawner exactly once. The
        // FIFO opens O_RDWR so it never blocks; a failed write still
        // latches, and the churn-C asserts below stay loud about it.
        if !self.birth_fired {
            self.birth_fired = true;
            let _ = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.birth_fifo)
                .and_then(|mut fifo| {
                    use std::io::Write as _;
                    fifo.write_all(b"x\n")
                });
        }
        // Only real passes count for the kill-cadence guard: the stop
        // commit's marker reuses the last pass number and scans nothing.
        let terminal = payload.get("final").and_then(Value::as_bool) == Some(true);
        if !terminal && let Some(pass) = payload.get("pass").and_then(Value::as_u64) {
            self.last_pass = Some(self.last_pass.map_or(pass, |last| last.max(pass)));
            // Caller events precede their pass marker in the commit batch,
            // so both conditioned exits being present at marker time means
            // this pass carried them — but only once the kill was
            // successfully requested for both fixtures, and only for
            // deaths observed after those requests. A death already
            // consumed before the requests is refused, so the first
            // qualifying pass gates the stop.
            if self.kill_signalled
                && self.exit_observing_pass.is_none()
                && let (Some(anchor), Some(churn_a)) = (self.anchor, self.churn_a)
                && self.exited.contains(&anchor)
                && self.exited.contains(&churn_a)
                && !self.kill_baseline_exited.contains(&anchor)
                && !self.kill_baseline_exited.contains(&churn_a)
            {
                self.exit_observing_pass = Some(pass);
            }
        }
    }

    fn handle_event_line(&mut self, line: &str) {
        let event: Value = match serde_json::from_str(line) {
            Ok(event) => event,
            Err(_) => return,
        };
        if event["kind"] == "pass_committed" {
            self.handle_pass_marker(&event["event"]);
            return;
        }
        if event["kind"] != "caller_event" {
            return;
        }
        let payload = &event["event"];
        let pid = payload["identity_context"]["caller"]["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok());
        // Attribute by pid plus the fixture executable: a reused pid
        // naming another program must not satisfy our conditions.
        let ours = payload["identity_context"]["caller"]["executable"]["path"]
            .as_str()
            .is_some_and(|path| path == self.driver_exe);
        if !ours {
            return;
        }
        match (payload["event"].as_str(), pid) {
            (Some("admitted"), Some(pid)) => {
                // Resolve the admitting pass at the churn-A admission
                // row, from the most recent preceding ordinary marker
                // (pass 0 when none seen yet). Admitted events precede
                // their pass marker in one sequential byte stream, so
                // this stays accurate when the first admitting row
                // follows other completed passes within one pump read.
                let first_churn_a = self.churn_a.is_some_and(|a| a == pid)
                    && !self.admitted.contains(&pid)
                    && self.kill_admitting_pass.is_none();
                self.admitted.insert(pid);
                if first_churn_a {
                    self.kill_admitting_pass = Some(
                        self.last_pass
                            .map(|pass| pass.saturating_add(1))
                            .unwrap_or(0),
                    );
                }
            }
            (Some("exited") | Some("retired"), Some(pid)) => {
                self.exited.insert(pid);
            }
            _ => {}
        }
    }
}

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
    let scratch = trusted_scratch("inventory-churn-e2-events");
    let events = scratch.join("events.jsonl");
    let stderr_log = dir.join("stderr.log");
    // The run ends on progress (the conditioned kill plus a later pass
    // published past it), so the duration is a SLACK hang guard a healthy
    // run never waits out, not the bound the settlement needs.
    let hang = slack_secs(30);
    let duration = format!("{hang}s");
    let mut cmd = Command::new("sh");
    cmd.arg(fixture_source("inventory-churn-observe.sh"))
        .arg("--system")
        .args(["--json", "--duration"])
        .arg(duration)
        .args(["--max-scan-pids", "4096"])
        .args(system_capture_args())
        .arg("--event-log")
        .arg(&events)
        // No rotation (wide threshold): the condition pump tails this file
        // by byte offset while the run is live, and a rotation blinds it to
        // every later marker; past the retained files the evidence is even
        // deleted, which no pump could recover. Mid-run birth/kill triggers
        // need the complete stream; rotation itself is covered by its
        // dedicated cells.
        .args(["--event-rotate-bytes", "1024M"])
        .env("INV_DRIVER", &driver)
        .env("INV_PROV", &prov)
        .env("INV_READY", &ready)
        .env("INV_OUT", &out)
        .env("P11SCOPE_BIN", env!("CARGO_BIN_EXE_p11scope"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped());
    let mut condition = ChurnCondition {
        ready: ready.clone(),
        events: events.clone(),
        birth_fifo: ready.join("birth.fifo"),
        driver_exe: driver.to_string_lossy().into_owned(),
        offset: 0,
        pending: String::new(),
        anchor: None,
        churn_a: None,
        churn_b: None,
        spawner: None,
        churn_c: None,
        admitted: BTreeSet::new(),
        exited: BTreeSet::new(),
        killed: false,
        kill_signalled: false,
        kill_baseline_exited: BTreeSet::new(),
        signal_outcome: None,
        signal_shim: None,
        signal_requests: Vec::new(),
        birth_fired: false,
        last_pass: None,
        kill_admitting_pass: None,
        exit_observing_pass: None,
        file_id: None,
        stop_requested: false,
        rotated: false,
    };
    let (output, peak) = spawn_with_peak_pumping(&mut cmd, &stderr_log, &mut || {
        condition.pump();
        let stop = condition.settled_for_stop();
        if stop {
            condition.stop_requested = true;
        }
        stop
    });
    // Final tail: the last pass may have published between the final
    // pump tick and the child's exit.
    condition.pump();
    let guard = FixtureGuard {
        pids: [
            condition.anchor,
            condition.churn_a,
            condition.churn_b,
            condition.churn_c,
            condition.spawner,
        ]
        .into_iter()
        .flatten()
        .collect(),
    };
    let stderr = std::fs::read_to_string(&stderr_log).unwrap();
    assert!(
        output.status.success(),
        "churn observe failed: {:?} {stderr}",
        output.status,
    );
    assert!(output.stdout.is_empty());
    assert_stderr_honest(&stderr);
    // The run disables rotation; a shrink means the tail lost markers and
    // every guard below would evaluate a partial stream. This fires before
    // the pid expects so rotation is diagnosed as rotation, not as a
    // missing birth or a stuck guard.
    assert!(
        !condition.rotated,
        "event log rotated mid-run; the offset tail cannot see rotated markers"
    );
    let anchor_pid = condition.anchor.expect("helper readied the anchor");
    let churn_a_pid = condition.churn_a.expect("helper readied churn-A");
    let churn_b_pid = condition.churn_b.expect("helper readied churn-B");
    let churn_c_pid = condition
        .churn_c
        .expect("helper birthed churn-C after the first pass");
    let _spawner_pid = condition
        .spawner
        .expect("helper recorded the mid-run spawner");
    assert!(
        peak < OBSERVER_RSS_BOUND_BYTES,
        "observer peak RSS {peak} stays within {OBSERVER_RSS_BOUND_BYTES}"
    );
    let body = std::fs::read_to_string(&out).unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
    // The conditioned kill lands after the admitting pass publishes, so
    // settlement needs that pass plus a later one observing the deaths.
    let passes = doc["observation"]["passes"].as_u64().unwrap();
    assert!(
        passes >= 2,
        "churn settlement needs an admitting pass plus a later pass observing the mid-run deaths; got {passes} published passes (hang guard {hang}s, progress stop requested: {})",
        condition.stop_requested
    );
    // Kill-cadence guard: the conditioned kill needs a pass AFTER the
    // admitting pass observing the deaths. `passes >= 2` alone does
    // not prove that when the kill fires on the final pass's publish.
    if let Some(admitting) = condition.kill_admitting_pass {
        let last = condition
            .last_pass
            .expect("pass markers published for completed passes");
        assert!(
            last > admitting,
            "conditioned kill landed on pass {admitting}'s publish but no later pass published (last pass {last}, progress stop requested: {}, exit-observing pass: {:?}); the mid-run deaths need a pass after the admitting pass",
            condition.stop_requested,
            condition.exit_observing_pass
        );
    }
    // The conditions fired mid-run: every baseline fixture admitted,
    // the two conditioned kills observed dead, the survivor never
    // exited. Churn-C (the mid-run birth) is asserted separately below.
    for (pid, name) in [
        (anchor_pid, "anchor"),
        (churn_a_pid, "churn-A"),
        (churn_b_pid, "churn-B"),
    ] {
        assert!(
            condition.admitted.contains(&pid),
            "{name} (pid {pid}) admitted mid-run"
        );
    }
    for (pid, name) in [(anchor_pid, "anchor"), (churn_a_pid, "churn-A")] {
        assert!(
            condition.exited.contains(&pid),
            "{name} (pid {pid}) exited after its conditioned kill (progress stop requested: {}, exit-observing pass: {:?})",
            condition.stop_requested,
            condition.exit_observing_pass
        );
    }
    assert!(
        !condition.exited.contains(&churn_b_pid),
        "churn-B (pid {churn_b_pid}) stays alive to run end"
    );
    // Terminal settlement over our pids: the survivor stays mapped
    // with one live incarnation; the killed two retire and fold into
    // departed_use with their exit state preserved.
    let incarnations = |pid: u32| {
        doc["callers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|caller| caller["pid"] == u64::from(pid))
            .collect::<Vec<_>>()
    };
    let folded = |pid: u32| {
        doc["modules"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|module| module["departed_use"]["identities"].as_array())
            .flat_map(|identities| identities.iter())
            .filter(|ident| ident["pid"] == u64::from(pid))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        incarnations(churn_b_pid).len(),
        1,
        "one churn-B incarnation"
    );
    for (pid, name) in [(anchor_pid, "anchor"), (churn_a_pid, "churn-A")] {
        assert!(
            incarnations(pid).is_empty(),
            "{name} (pid {pid}) retired and folded"
        );
        assert_eq!(folded(pid).len(), 1, "one folded {name} incarnation");
    }
    let anchor = folded(anchor_pid)[0];
    assert_eq!(anchor["lifecycle"], "exited");
    let churn_a = folded(churn_a_pid)[0];
    assert_eq!(churn_a["lifecycle"], "exited");
    let churn_b = incarnations(churn_b_pid)[0];
    assert_eq!(churn_b["lifecycle"], "mapped");
    assert_eq!(churn_b["retired"], false);
    // The mid-run birth: churn-C is forked after the first published
    // pass. When a later pass enumerates it, it is admitted mid-run and
    // settled mapped; when no pass ever enumerates it (the next pass
    // enumerates within milliseconds of the trigger under overrun), it
    // is alive at stop and the stop disclosure names its pid. Death
    // legs below cover a fixture that died first. Every leg is exact;
    // no leg passes vacuously. (A SIGKILLed harness orphans the spawner
    // the same way it orphans sleepers; every other exit path kills it
    // through the guard above, including assert panics.)
    let churn_c_incarnations = incarnations(churn_c_pid);
    let churn_c_alive = pid_is_driver(churn_c_pid, &condition.driver_exe);
    let churn_c_admitted = condition.admitted.contains(&churn_c_pid);
    if churn_c_alive && churn_c_admitted {
        assert!(
            !condition.exited.contains(&churn_c_pid),
            "churn-C (pid {churn_c_pid}) stays alive to run end"
        );
        assert_eq!(churn_c_incarnations.len(), 1, "one churn-C incarnation");
        let churn_c = churn_c_incarnations[0];
        assert_eq!(churn_c["lifecycle"], "mapped");
        assert_eq!(churn_c["retired"], false);
    } else if churn_c_alive {
        // Alive but never admitted: born after the last enumeration
        // that could see it, so the stop disclosure names it — the
        // never-scanned diff on scan capture, the pending-coverage gap
        // where exec hooks tracked it. Never a caller row, never
        // silent. (The pid lists bound at ten shown; churn-C's pid is
        // the smallest among missed births absent pid wrap or reuse —
        // pids allocate sequentially and missed births postdate the
        // last enumeration — so truncation cannot hide it behind
        // later starters.)
        assert!(
            churn_c_incarnations.is_empty(),
            "churn-C (pid {churn_c_pid}) never admitted and must leave no caller row"
        );
        let gaps = doc["gaps"].as_array().unwrap();
        let named = gaps.iter().any(|gap| {
            (gap["subject"] == "processes missed by every scan"
                || gap["subject"] == "discovery coverage ended before stop")
                && gap["reason"]
                    .as_str()
                    .is_some_and(|reason| gap_reason_names_pid(reason, churn_c_pid))
        });
        assert!(
            named,
            "churn-C (pid {churn_c_pid}) born mid-run but never enumerated must be named by the stop disclosure"
        );
    } else if churn_c_admitted {
        // Died after admission: retired and folded, never silently
        // dropped.
        assert!(
            churn_c_incarnations.is_empty(),
            "churn-C (pid {churn_c_pid}) retired and folded"
        );
        let churn_c_folded = folded(churn_c_pid);
        assert_eq!(churn_c_folded.len(), 1, "one churn-C incarnation");
        let churn_c = churn_c_folded[0];
        assert_eq!(churn_c["lifecycle"], "exited");
        assert!(churn_c["lifecycle_reason"].is_string());
    } else {
        // Died before admission: never a caller row, counted in its
        // named gap — the short-lived aggregate once two passes miss
        // it, else the pending-coverage gap naming its pid. The
        // aggregate is count-only by product design and names no pid,
        // so that disjunct is attribution by elimination (dead plus
        // unadmitted plus the aggregate present), confounded by any
        // ambient short-lived program on the host. (Scan-only capture
        // has no exec hooks, so an unadmitted death there fails loudly
        // here instead of passing silently.)
        assert!(
            churn_c_incarnations.is_empty(),
            "churn-C (pid {churn_c_pid}) died unadmitted and must leave no caller row"
        );
        let gaps = doc["gaps"].as_array().unwrap();
        let counted = gaps.iter().any(|gap| {
            gap["subject"] == "short-lived processes never scanned"
                || (gap["subject"] == "discovery coverage ended before stop"
                    && gap["reason"]
                        .as_str()
                        .is_some_and(|reason| gap_reason_names_pid(reason, churn_c_pid)))
        });
        assert!(
            counted,
            "churn-C (pid {churn_c_pid}) died before admission and must be counted in its named gap"
        );
    }
    // Every observed caller is live or retired-with-reason, every owned
    // edge resolves.
    let our_pids: std::collections::HashSet<u64> =
        [anchor_pid, churn_a_pid, churn_b_pid, churn_c_pid]
            .into_iter()
            .map(u64::from)
            .collect();
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
    // The event stream served its conditions; failures above keep it.
    let _ = std::fs::remove_dir_all(&scratch);
}

// ---------------------------------------------------------------------------
// E2 twins: the kill-cadence guard's admitting-pass bookkeeping, scripted.
// ---------------------------------------------------------------------------
//
// The pump records the admitting pass as one past the last published
// marker, because caller events precede their pass marker in the commit
// batch. These twins pin that bookkeeping for both tick interleavings
// without running the observer: the whole batch landing in one tick (the
// marker is already processed when the kill check runs), and events and
// marker split across two ticks.

// Above PID_MAX_LIMIT (2^22): these pids can never be live, and the
// driver path exists nowhere, so `pid_is_driver` is doubly false and the
// scripted kill latch below can never signal anything.
const GUARD_ANCHOR: u32 = 4_190_305;
const GUARD_CHURN_A: u32 = 4_190_306;
const GUARD_CHURN_B: u32 = 4_190_307;
const GUARD_CHURN_C: u32 = 4_190_308;
const GUARD_DRIVER: &str = "/nonexistent/churn-guard-driver";

/// Scripted `ChurnCondition` over dead pids and a fake driver path: the
/// kill latch fires on the admitted event with a successful signal
/// outcome injected, but no signal is ever sent. Twins covering a
/// refused kill override `signal_outcome` with `Some(false)`.
fn scripted_churn_condition(dir: &Path) -> ChurnCondition {
    let ready = dir.join("ready");
    std::fs::create_dir_all(&ready).unwrap();
    for (name, pid) in [
        ("anchor.ready", GUARD_ANCHOR),
        ("churn-a.ready", GUARD_CHURN_A),
        ("churn-b.ready", GUARD_CHURN_B),
    ] {
        std::fs::write(ready.join(name), format!("READY {pid}\n")).unwrap();
    }
    ChurnCondition {
        ready,
        events: dir.join("events.jsonl"),
        birth_fifo: dir.join("birth.fifo"),
        driver_exe: GUARD_DRIVER.to_owned(),
        offset: 0,
        pending: String::new(),
        anchor: None,
        churn_a: None,
        churn_b: None,
        spawner: None,
        churn_c: None,
        admitted: BTreeSet::new(),
        exited: BTreeSet::new(),
        killed: false,
        kill_signalled: false,
        kill_baseline_exited: BTreeSet::new(),
        signal_outcome: Some(true),
        signal_shim: None,
        signal_requests: Vec::new(),
        birth_fired: false,
        last_pass: None,
        kill_admitting_pass: None,
        exit_observing_pass: None,
        file_id: None,
        stop_requested: false,
        rotated: false,
    }
}

fn guard_admitted_line(pid: u32) -> String {
    format!(
        "{{\"kind\":\"caller_event\",\"event\":{{\"event\":\"admitted\",\"identity_context\":{{\"caller\":{{\"pid\":{pid},\"executable\":{{\"path\":\"{GUARD_DRIVER}\"}}}}}}}}}}\n"
    )
}

fn guard_pass_marker_line(pass: u64) -> String {
    format!("{{\"kind\":\"pass_committed\",\"event\":{{\"pass\":{pass}}}}}\n")
}

fn guard_exit_line(pid: u32) -> String {
    format!(
        "{{\"kind\":\"caller_event\",\"event\":{{\"event\":\"exited\",\"identity_context\":{{\"caller\":{{\"pid\":{pid},\"executable\":{{\"path\":\"{GUARD_DRIVER}\"}}}}}}}}}}\n"
    )
}

fn guard_terminal_marker_line(pass: u64) -> String {
    // The native stop's commit, as emitted by the product: it commits
    // after the last pass, scans nothing, and reuses the last ordinary
    // pass number with `final` set.
    format!("{{\"kind\":\"pass_committed\",\"event\":{{\"pass\":{pass},\"final\":true}}}}\n")
}

#[test]
fn churn_kill_guard_records_admitting_pass_on_same_tick_batch() {
    // The whole commit batch lands in one pump tick: the admitted line
    // and its pass-0 marker are processed together, and the kill check
    // runs after. The admitting pass is 0, not one past the marker the
    // same tick already processed.
    let dir = tmp("inventory-churn-guard-same-tick");
    let mut condition = scripted_churn_condition(&dir);
    std::fs::write(
        &condition.events,
        format!(
            "{}{}",
            guard_admitted_line(GUARD_CHURN_A),
            guard_pass_marker_line(0)
        ),
    )
    .unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert_eq!(condition.last_pass, Some(0));
    assert_eq!(
        condition.kill_admitting_pass,
        Some(0),
        "same-tick batch: churn-A admitted by pass 0, not one past its marker"
    );
}

#[test]
fn churn_kill_guard_records_admitting_pass_on_split_ticks() {
    // Twin: the admitted line lands one tick before its marker. The
    // admitting pass is still 0, and the marker tick must not move it.
    let dir = tmp("inventory-churn-guard-split-tick");
    let mut condition = scripted_churn_condition(&dir);
    std::fs::write(&condition.events, guard_admitted_line(GUARD_CHURN_A)).unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert_eq!(condition.last_pass, None);
    assert_eq!(condition.kill_admitting_pass, Some(0));
    let mut later = std::fs::read_to_string(&condition.events).unwrap();
    later.push_str(&guard_pass_marker_line(0));
    std::fs::write(&condition.events, later).unwrap();
    condition.pump();
    assert_eq!(condition.last_pass, Some(0));
    assert_eq!(
        condition.kill_admitting_pass,
        Some(0),
        "marker tick keeps the admitting pass"
    );
}

#[test]
fn churn_pump_trips_rotation_tripwire_on_shrink() {
    // Twin: the live run disables rotation, so a file that shrinks below
    // the consumed offset (rename replaced it with a shorter one) must
    // latch `rotated` instead of silently evaluating a partial stream.
    // Truncation stands in for the rename: the tripwire keys on the
    // shrink, not the mechanism.
    let dir = tmp("inventory-churn-guard-rotation");
    let mut condition = scripted_churn_condition(&dir);
    std::fs::write(
        &condition.events,
        format!(
            "{}{}",
            guard_admitted_line(GUARD_CHURN_A),
            guard_pass_marker_line(0)
        ),
    )
    .unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert!(!condition.rotated, "a growing stream trips nothing");
    std::fs::write(&condition.events, guard_pass_marker_line(1)).unwrap();
    condition.pump();
    assert!(
        condition.rotated,
        "a shrink below the consumed offset latches rotated"
    );
    assert_eq!(
        condition.last_pass,
        Some(0),
        "the post-shrink tick consumes nothing further"
    );
}

#[test]
fn churn_settled_for_stop_needs_kill_and_later_pass_and_birth() {
    // Twin: the progress stop fires only when the kill was attempted and
    // successfully requested for both fixtures, a later pass carrying
    // both post-request exit observations published past the admitting
    // pass, and churn-C's birth is visible. Each missing leg vetoes the
    // stop on its own. A later pass without the exits never stops, even
    // with the kill and the birth.
    let dir = tmp("inventory-churn-guard-stop");
    let mut condition = scripted_churn_condition(&dir);
    condition.anchor = Some(GUARD_ANCHOR);
    condition.churn_a = Some(GUARD_CHURN_A);
    condition.exited.insert(GUARD_ANCHOR);
    condition.exited.insert(GUARD_CHURN_A);
    condition.kill_admitting_pass = Some(0);
    condition.last_pass = Some(1);
    condition.exit_observing_pass = Some(1);
    condition.churn_c = Some(GUARD_CHURN_C);
    assert!(
        !condition.settled_for_stop(),
        "exit pass plus birth without the kill never stop"
    );
    condition.killed = true;
    assert!(
        !condition.settled_for_stop(),
        "a kill attempt without successful requests for both fixtures never stops"
    );
    condition.kill_signalled = true;
    condition.exit_observing_pass = None;
    assert!(
        !condition.settled_for_stop(),
        "the kill without an exit-observing pass never stops"
    );
    condition.exit_observing_pass = Some(0);
    assert!(
        !condition.settled_for_stop(),
        "an exit-observing pass that is not past the admitting pass never stops"
    );
    condition.exit_observing_pass = Some(1);
    condition.churn_c = None;
    assert!(
        !condition.settled_for_stop(),
        "the kill plus an exit-observing pass without churn-C's birth never stops"
    );
    condition.churn_c = Some(GUARD_CHURN_C);
    assert!(
        condition.settled_for_stop(),
        "kill plus exit-observing pass plus birth stop the run"
    );
    condition.kill_admitting_pass = None;
    assert!(
        !condition.settled_for_stop(),
        "a kill without its admitting pass never stops"
    );
}

#[test]
fn churn_stop_waits_for_exits_after_backlog() {
    // Twin: a descheduled pump can consume pass 0 and pass 1 in one tick
    // before the kill signals land. The pre-kill pass 1 must not satisfy
    // the stop: only a later pass carrying both exit observations does.
    let dir = tmp("inventory-churn-guard-stop-backlog");
    let mut condition = scripted_churn_condition(&dir);
    std::fs::write(
        &condition.events,
        format!(
            "{}{}{}",
            guard_admitted_line(GUARD_CHURN_A),
            guard_pass_marker_line(0),
            guard_pass_marker_line(1)
        ),
    )
    .unwrap();
    std::fs::write(
        condition.ready.join("churn-c.ready"),
        format!("READY {}\n", GUARD_CHURN_C),
    )
    .unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert_eq!(condition.kill_admitting_pass, Some(0));
    assert_eq!(condition.last_pass, Some(1));
    assert!(condition.churn_c.is_some(), "churn-C birth is visible");
    assert!(condition.exited.is_empty(), "no exit observed yet");
    assert!(
        !condition.settled_for_stop(),
        "a later pass without either exit observation must not stop"
    );
    let mut later = std::fs::read_to_string(&condition.events).unwrap();
    later.push_str(&guard_exit_line(GUARD_ANCHOR));
    later.push_str(&guard_exit_line(GUARD_CHURN_A));
    later.push_str(&guard_pass_marker_line(2));
    std::fs::write(&condition.events, later).unwrap();
    condition.pump();
    assert!(
        condition.settled_for_stop(),
        "both exits carried by a later pass stop the run"
    );
}

#[test]
fn churn_stop_needs_both_exits_not_one() {
    // Twin: a pass published after the kill request may have scanned
    // before the signals took effect. Zero exits, then one exit, must
    // each veto the stop on their own; only both exits stop it.
    let dir = tmp("inventory-churn-guard-stop-exits");
    let mut condition = scripted_churn_condition(&dir);
    std::fs::write(
        &condition.events,
        format!(
            "{}{}",
            guard_admitted_line(GUARD_CHURN_A),
            guard_pass_marker_line(0)
        ),
    )
    .unwrap();
    std::fs::write(
        condition.ready.join("churn-c.ready"),
        format!("READY {}\n", GUARD_CHURN_C),
    )
    .unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert_eq!(condition.kill_admitting_pass, Some(0));
    let mut stream = std::fs::read_to_string(&condition.events).unwrap();
    stream.push_str(&guard_pass_marker_line(1));
    std::fs::write(&condition.events, &stream).unwrap();
    condition.pump();
    assert_eq!(condition.last_pass, Some(1));
    assert!(
        !condition.settled_for_stop(),
        "a post-request pass without exits must not stop"
    );
    stream.push_str(&guard_exit_line(GUARD_ANCHOR));
    stream.push_str(&guard_pass_marker_line(2));
    std::fs::write(&condition.events, &stream).unwrap();
    condition.pump();
    assert!(
        !condition.settled_for_stop(),
        "one exit observation must not stop without the other"
    );
    // Commit barrier: both exit rows alone are not a commit. The writer
    // flushes per line, so the rows and their marker land as separate
    // appends; the pump can read the rows and pause before the marker.
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&condition.events)
            .unwrap();
        file.write_all(guard_exit_line(GUARD_CHURN_A).as_bytes())
            .unwrap();
    }
    condition.pump();
    assert!(
        condition.exited.contains(&GUARD_ANCHOR) && condition.exited.contains(&GUARD_CHURN_A),
        "both exit rows are consumed before their marker"
    );
    assert_eq!(
        condition.exit_observing_pass, None,
        "both exit rows alone are not a commit"
    );
    assert!(
        !condition.settled_for_stop(),
        "both exit rows without their marker must not stop"
    );
    assert_eq!(
        condition.last_pass,
        Some(2),
        "no new pass commits before its marker"
    );
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&condition.events)
            .unwrap();
        file.write_all(guard_pass_marker_line(3).as_bytes())
            .unwrap();
    }
    condition.pump();
    assert_eq!(
        condition.exit_observing_pass,
        Some(3),
        "the ordinary marker commits the staged exits at pass 3"
    );
    assert!(
        condition.settled_for_stop(),
        "both exit observations stop the run"
    );
}

#[test]
fn churn_stop_refuses_exits_buffered_before_kill_request() {
    // Twin: both exits land buffered in the same tick as the admitting
    // row, before any kill request. The attempt latch fires, but the
    // pre-request deaths must not satisfy the stop, and a later marker
    // with no new observations must not commit them either — whether
    // the fixture identity check refuses the signals or (scripted)
    // reports success. The refused leg pins eligibility; the success
    // leg pins the pre-request baseline refusal.
    for signal_outcome in [false, true] {
        let dir = tmp(&format!(
            "inventory-churn-guard-stop-buffered-{signal_outcome}"
        ));
        let mut condition = scripted_churn_condition(&dir);
        condition.signal_outcome = Some(signal_outcome);
        std::fs::write(
            &condition.events,
            format!(
                "{}{}",
                guard_admitted_line(GUARD_ANCHOR),
                guard_pass_marker_line(0)
            ),
        )
        .unwrap();
        condition.pump();
        assert!(
            !condition.killed,
            "anchor admission alone leaves the kill latch clear (signals {signal_outcome})"
        );
        assert_eq!(condition.last_pass, Some(0));
        std::fs::write(
            condition.ready.join("churn-c.ready"),
            format!("READY {}\n", GUARD_CHURN_C),
        )
        .unwrap();
        let mut buffered = std::fs::read_to_string(&condition.events).unwrap();
        buffered.push_str(&guard_admitted_line(GUARD_CHURN_A));
        buffered.push_str(&guard_pass_marker_line(1));
        buffered.push_str(&guard_exit_line(GUARD_ANCHOR));
        buffered.push_str(&guard_exit_line(GUARD_CHURN_A));
        buffered.push_str(&guard_pass_marker_line(2));
        std::fs::write(&condition.events, &buffered).unwrap();
        condition.pump();
        assert!(
            condition.killed,
            "kill latch fires on churn-A admission (signals {signal_outcome})"
        );
        assert_eq!(condition.kill_admitting_pass, Some(1));
        assert_eq!(
            condition.kill_signalled, signal_outcome,
            "eligibility tracks the injected signal outcome"
        );
        assert!(condition.churn_c.is_some(), "churn-C birth is visible");
        assert!(
            condition.exited.contains(&GUARD_ANCHOR) && condition.exited.contains(&GUARD_CHURN_A),
            "both buffered exits are consumed in the request tick"
        );
        assert_eq!(
            condition.exit_observing_pass, None,
            "no pass observes post-request exits yet (signals {signal_outcome})"
        );
        assert!(
            !condition.settled_for_stop(),
            "exits committed before the kill request must not stop (signals {signal_outcome})"
        );
        buffered.push_str(&guard_pass_marker_line(3));
        std::fs::write(&condition.events, &buffered).unwrap();
        condition.pump();
        assert!(
            !condition.settled_for_stop(),
            "a later marker with no new observations must not commit pre-request deaths (signals {signal_outcome})"
        );
    }
}

#[test]
fn churn_stop_ignores_terminal_marker() {
    // Twin: a native stop batch can carry exits under a final marker
    // that scans nothing and reuses the last ordinary pass number. The
    // terminal commit must not satisfy the scan gate: no last-pass
    // move, no exit-observing latch, no stop.
    let dir = tmp("inventory-churn-guard-stop-terminal");
    let mut condition = scripted_churn_condition(&dir);
    std::fs::write(
        &condition.events,
        format!(
            "{}{}{}",
            guard_admitted_line(GUARD_CHURN_A),
            guard_pass_marker_line(0),
            guard_pass_marker_line(1)
        ),
    )
    .unwrap();
    std::fs::write(
        condition.ready.join("churn-c.ready"),
        format!("READY {}\n", GUARD_CHURN_C),
    )
    .unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert_eq!(condition.kill_admitting_pass, Some(0));
    assert_eq!(condition.last_pass, Some(1));
    let mut terminal = std::fs::read_to_string(&condition.events).unwrap();
    terminal.push_str(&guard_exit_line(GUARD_ANCHOR));
    terminal.push_str(&guard_exit_line(GUARD_CHURN_A));
    terminal.push_str(&guard_terminal_marker_line(1));
    std::fs::write(&condition.events, &terminal).unwrap();
    condition.pump();
    assert!(
        condition.exited.contains(&GUARD_ANCHOR) && condition.exited.contains(&GUARD_CHURN_A),
        "both exits are consumed under the terminal marker"
    );
    assert_eq!(
        condition.last_pass,
        Some(1),
        "a terminal marker never advances the last pass"
    );
    assert_eq!(
        condition.exit_observing_pass, None,
        "a terminal marker cannot satisfy the scan gate"
    );
    assert!(
        !condition.settled_for_stop(),
        "exits under a terminal marker must not stop"
    );
}

#[test]
fn churn_pump_trips_rotation_tripwire_on_rename_regrow() {
    // Twin: rotation renames the file and a new file regrows. When the
    // regrown file is already at least as long as the consumed offset,
    // the length check alone misses the replacement; the device/inode
    // change must still latch `rotated`.
    let dir = tmp("inventory-churn-guard-rotation-rename");
    let mut condition = scripted_churn_condition(&dir);
    let initial = format!(
        "{}{}",
        guard_admitted_line(GUARD_CHURN_A),
        guard_pass_marker_line(0)
    );
    std::fs::write(&condition.events, &initial).unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert!(!condition.rotated, "a growing stream trips nothing");
    let consumed = condition.offset;
    std::fs::rename(&condition.events, dir.join("events.jsonl.1")).unwrap();
    let mut regrow = format!(
        "{}{}{}",
        guard_admitted_line(GUARD_CHURN_B),
        guard_pass_marker_line(1),
        guard_pass_marker_line(2)
    );
    while (regrow.len() as u64) < consumed {
        regrow.push_str(&guard_pass_marker_line(2));
    }
    std::fs::write(&condition.events, &regrow).unwrap();
    condition.pump();
    assert!(
        condition.rotated,
        "a rename with regrow to the consumed offset latches rotated"
    );
}

// ---------------------------------------------------------------------------
// E2 review twins: failed signal requests, same-tick admitting markers,
// and mixed pre/post-request exits.
// ---------------------------------------------------------------------------

fn live_admitted_line(pid: u32, exe: &str) -> String {
    format!(
        "{{\"kind\":\"caller_event\",\"event\":{{\"event\":\"admitted\",\"identity_context\":{{\"caller\":{{\"pid\":{pid},\"executable\":{{\"path\":\"{exe}\"}}}}}}}}}}\n"
    )
}

fn live_exit_line(pid: u32, exe: &str) -> String {
    format!(
        "{{\"kind\":\"caller_event\",\"event\":{{\"event\":\"exited\",\"identity_context\":{{\"caller\":{{\"pid\":{pid},\"executable\":{{\"path\":\"{exe}\"}}}}}}}}}}\n"
    )
}

/// An owned `sleep` fixture that dies with the test process and is
/// reaped on drop, so a failing twin leaks neither processes nor zombies.
fn spawn_owned_sleep() -> support::ChildGuard {
    let mut cmd = Command::new("sleep");
    cmd.arg("300")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.die_with_parent();
    support::ChildGuard::new(cmd.spawn().expect("sleep fixture spawns"))
}

/// A fully reaped pid whose `SIGTERM` request returns the kernel's
/// `-1/ESRCH`. Nothing spawns between the reap and the pump, so the pid
/// cannot be recycled underneath the probe.
fn reaped_probe_pid() -> u32 {
    let mut probe = Command::new("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("probe spawns");
    let pid = probe.id();
    let status = probe.wait().expect("probe reaps");
    assert!(status.success());
    let premise = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    assert_eq!(premise, -1, "a reaped pid refuses signals");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "a reaped pid fails with ESRCH"
    );
    pid
}

/// Drive one live-branch signal-request case over owned `sleep`
/// fixtures: the request tick admits churn-A under pass 0, both exit
/// rows arrive under pass 1, and `fail` selects the request returning
/// the kernel's `-1/ESRCH` (`Some(true)` fails churn-A's first request,
/// `Some(false)` fails the anchor's second request, `None` succeeds
/// both as the positive control).
fn signal_request_case(case: &str, fail: Option<bool>) {
    let dir = tmp(&format!("inventory-churn-review-{case}"));
    let anchor = spawn_owned_sleep();
    let churn_a = spawn_owned_sleep();
    let churn_b = spawn_owned_sleep();
    let churn_c = spawn_owned_sleep();
    let anchor_pid = anchor.child.id();
    let churn_a_pid = churn_a.child.id();
    let churn_b_pid = churn_b.child.id();
    let churn_c_pid = churn_c.child.id();
    let sleep_exe = std::fs::read_link(format!("/proc/{anchor_pid}/exe"))
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(
        pid_is_driver(anchor_pid, &sleep_exe) && pid_is_driver(churn_a_pid, &sleep_exe),
        "{case}: both signalled fixtures pass the real executable checks"
    );
    let fail_pid = match fail {
        Some(true) => Some(churn_a_pid),
        Some(false) => Some(anchor_pid),
        None => None,
    };
    let mut condition = scripted_churn_condition(&dir);
    for (name, pid) in [
        ("anchor.ready", anchor_pid),
        ("churn-a.ready", churn_a_pid),
        ("churn-b.ready", churn_b_pid),
        ("churn-c.ready", churn_c_pid),
    ] {
        std::fs::write(condition.ready.join(name), format!("READY {pid}\n")).unwrap();
    }
    condition.driver_exe = sleep_exe.clone();
    condition.signal_outcome = None;
    condition.signal_shim = Some(SignalShim {
        fail_pid,
        dead_probe_pid: reaped_probe_pid(),
    });
    std::fs::write(
        &condition.events,
        format!(
            "{}{}",
            live_admitted_line(churn_a_pid, &sleep_exe),
            guard_pass_marker_line(0)
        ),
    )
    .unwrap();
    condition.pump();
    assert!(
        condition.killed,
        "{case}: kill latch fires on churn-A admission"
    );
    assert_eq!(condition.kill_admitting_pass, Some(0));
    assert!(
        condition.churn_c.is_some(),
        "{case}: churn-C birth is visible"
    );
    let expected_requests = match fail {
        Some(true) => vec![(churn_a_pid, -1), (anchor_pid, 0)],
        Some(false) => vec![(churn_a_pid, 0), (anchor_pid, -1)],
        None => vec![(churn_a_pid, 0), (anchor_pid, 0)],
    };
    assert_eq!(
        condition.signal_requests, expected_requests,
        "{case}: both requests run in order with their own outcomes"
    );
    let mut later = std::fs::read_to_string(&condition.events).unwrap();
    later.push_str(&live_exit_line(anchor_pid, &sleep_exe));
    later.push_str(&live_exit_line(churn_a_pid, &sleep_exe));
    later.push_str(&guard_pass_marker_line(1));
    std::fs::write(&condition.events, &later).unwrap();
    condition.pump();
    assert!(
        condition.exited.contains(&anchor_pid) && condition.exited.contains(&churn_a_pid),
        "{case}: both exit rows are consumed under the later marker"
    );
    assert_eq!(
        condition.last_pass,
        Some(1),
        "{case}: the later marker commits"
    );
    if fail.is_some() {
        assert!(
            !condition.kill_signalled,
            "{case}: a failed request vetoes stop eligibility"
        );
        assert_eq!(
            condition.exit_observing_pass, None,
            "{case}: no exit-observing pass latches without eligibility"
        );
        assert!(
            !condition.settled_for_stop(),
            "{case}: a failed request must not stop"
        );
    } else {
        assert!(
            condition.kill_signalled,
            "{case}: two successful requests grant stop eligibility"
        );
        assert_eq!(
            condition.exit_observing_pass,
            Some(1),
            "{case}: the later marker commits both post-request exits"
        );
        assert!(
            condition.settled_for_stop(),
            "{case}: two successful requests plus the committed exits stop the run"
        );
    }
}

#[test]
fn review_churn_a_request_failed() {
    // Twin: churn-A's (first) signal request fails with the kernel's
    // -1/ESRCH — the fixture exits between the identity check and its
    // syscall — while the anchor's (second) request succeeds. Both
    // requests still run in order, and the failure vetoes stop
    // eligibility: no exit-pass latch and no progress stop once both
    // exit rows arrive under the later ordinary marker.
    signal_request_case("churn-a-request-failed", Some(true));
}

#[test]
fn review_anchor_request_failed() {
    // Twin: the anchor's (second) signal request fails with the
    // kernel's -1/ESRCH while churn-A's (first) request succeeds. The
    // failure vetoes stop eligibility exactly like a failed first
    // request: no exit-pass latch and no progress stop.
    signal_request_case("anchor-request-failed", Some(false));
}

#[test]
fn review_both_requests_succeed() {
    // Positive control: both live-branch requests succeed, so stop
    // eligibility latches and the later ordinary marker commits both
    // post-request exits into a progress stop.
    signal_request_case("both-requests-succeed", None);
}

#[test]
fn review_preceding_marker_in_admission_tick() {
    // Twin: the admission tick's own read already holds an earlier
    // ordinary marker (pass 0 admitted the anchor) before churn-A's
    // admission row. The admitting pass resolves at the admission row
    // from the most recent preceding marker — pass 1 — not from the
    // pre-tick snapshot (pass 0) the fallback would derive.
    let dir = tmp("inventory-churn-review-preceding-marker");
    let mut condition = scripted_churn_condition(&dir);
    std::fs::write(
        &condition.events,
        format!(
            "{}{}{}{}",
            guard_admitted_line(GUARD_ANCHOR),
            guard_pass_marker_line(0),
            guard_admitted_line(GUARD_CHURN_A),
            guard_pass_marker_line(1)
        ),
    )
    .unwrap();
    condition.pump();
    assert!(condition.killed, "kill latch fires on churn-A admission");
    assert_eq!(condition.last_pass, Some(1));
    assert_eq!(
        condition.kill_admitting_pass,
        Some(1),
        "same-tick preceding marker admits churn-A at pass 1, not the pre-tick snapshot"
    );
}

#[test]
fn review_mixed_pre_and_post_request_exits() {
    // Twin: one fixture's exit is already consumed when the kill
    // request fires while the other's arrives under a later ordinary
    // marker, in both orientations. Scripted success keeps eligibility
    // true, so only the per-fixture baseline refusal vetoes the latch:
    // each orientation pins one predicate, and removing either single
    // predicate latches the other fixture's post-request exit.
    for (pre, post, slug, label) in [
        (
            GUARD_ANCHOR,
            GUARD_CHURN_A,
            "anchor-pre",
            "anchor pre-request, churn-A post-request",
        ),
        (
            GUARD_CHURN_A,
            GUARD_ANCHOR,
            "churn-a-pre",
            "churn-A pre-request, anchor post-request",
        ),
    ] {
        let dir = tmp(&format!("inventory-churn-review-mixed-{slug}"));
        let mut condition = scripted_churn_condition(&dir);
        std::fs::write(
            &condition.events,
            format!(
                "{}{}{}",
                guard_admitted_line(GUARD_ANCHOR),
                guard_pass_marker_line(0),
                guard_exit_line(pre)
            ),
        )
        .unwrap();
        condition.pump();
        assert!(
            !condition.killed,
            "({label}) admission without churn-A leaves the kill latch clear"
        );
        std::fs::write(
            condition.ready.join("churn-c.ready"),
            format!("READY {}\n", GUARD_CHURN_C),
        )
        .unwrap();
        let mut tick = std::fs::read_to_string(&condition.events).unwrap();
        tick.push_str(&guard_admitted_line(GUARD_CHURN_A));
        tick.push_str(&guard_pass_marker_line(1));
        std::fs::write(&condition.events, &tick).unwrap();
        condition.pump();
        assert!(
            condition.killed,
            "({label}) kill latch fires on churn-A admission"
        );
        assert_eq!(condition.kill_admitting_pass, Some(1));
        assert!(
            condition.kill_signalled,
            "({label}) scripted success keeps stop eligibility"
        );
        assert!(
            condition.churn_c.is_some(),
            "({label}) churn-C birth is visible"
        );
        tick.push_str(&guard_exit_line(post));
        tick.push_str(&guard_pass_marker_line(2));
        std::fs::write(&condition.events, &tick).unwrap();
        condition.pump();
        assert!(
            condition.exited.contains(&pre) && condition.exited.contains(&post),
            "({label}) both exits are consumed under the later marker"
        );
        assert_eq!(
            condition.last_pass,
            Some(2),
            "({label}) the later marker commits"
        );
        assert_eq!(
            condition.exit_observing_pass, None,
            "({label}) the pre-request exit vetoes the latch"
        );
        assert!(
            !condition.settled_for_stop(),
            "({label}) a pre-request exit must not stop"
        );
        tick.push_str(&guard_pass_marker_line(3));
        std::fs::write(&condition.events, &tick).unwrap();
        condition.pump();
        assert!(
            !condition.settled_for_stop(),
            "({label}) a bare later marker must not commit the pre-request exit"
        );
    }
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
            .args([
                "--json",
                "--capture",
                "scan",
                "--identity-backend",
                "userspace",
                "--max-scan-pids",
                "4096",
            ])
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
        cmd.die_with_parent();
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
        .args(["--json", "--capture", "scan", "-o", "/dev/full"])
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
        .args(["--json", "--capture", "scan", "--duration", "25s", "-o"])
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
        .die_with_parent()
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
        // The per-pass gap line is verbose-only since CLI-1 (the concise
        // head carries the PARTIAL coverage); full detail for the pin.
        cmd.args([
            "inventory",
            "--system",
            "--json",
            "--capture",
            "scan",
            "--identity-backend",
            "userspace",
            "--max-scan-pids",
            "1",
            "-v",
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
    // Piped: `spawn_with_peak` drains stdout mid-run, so the 64 KiB
    // pipe never deadlocks; a file stdout would panic its contract.
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
    // The stderr honesty line names exactly what the document carries.
    // The per-pass line is progress (it predates the terminal disclosures),
    // so only its presence is pinned; the final line carries the exact pin.
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("p11scope: pass 0: ") && line.contains("budget refusal")),
        "pass 0 progress gap line present: {stderr:?}"
    );
    let refusals = gaps.iter().filter(|gap| !gap["budget"].is_null()).count();
    let suppressed = doc["gaps_suppressed"].as_u64().unwrap();
    assert_final_gap_line(&stderr, gaps.len(), refusals, suppressed);
    assert_settled_consistent(&doc);
    fd_scope.assert_delta(0);
}

/// The dashboard twin of [`assert_final_gap_line`]: the typescript holds
/// dashboard frames (ANSI) plus the post-restore closing lines, so the
/// search tolerates a line prefix and parses from the `p11scope: final: `
/// marker. Pins the same three counts against the caller's exact values.
fn assert_dashboard_final_gap_line(output: &str, gaps: usize, refusals: usize, suppressed: u64) {
    let marker = "p11scope: final: ";
    let line = output
        .lines()
        .find(|line| line.contains(marker) && line.contains("budget refusal"))
        .unwrap_or_else(|| panic!("final gap/refusal/suppressed line present: {output:?}"));
    let rest = line.split_once(marker).unwrap().1;
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
        "dashboard gap line agrees with the document: {line:?}"
    );
}

/// Dashboard honesty at default verbosity: the interactive tail shows
/// per-pass gap progress always, so its terminal correction must also
/// appear there — from the same snapshot as the JSON document — or the
/// user sees only the stale number. Runs the real dashboard on a pty
/// (`script`) with an overflowed scan cap, no `-v`, the JSON in `-o`.
#[test]
fn dashboard_final_gap_line_at_default_verbosity_agrees_with_document() {
    let _guard = serial_guard();
    let dir = tmp("inventory-dashboard-gapline-e2");
    // `-o` needs a trusted directory; the target dir does not qualify.
    let out_dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(out_dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let report = out_dir.path().join("dashboard-partial.json");
    let typescript = dir.join("typescript");
    // One small budget, overflowed on purpose (as in the scan-cap cell):
    // a scan cap of 1 always truncates, so the run is always partial.
    // No `-v`, no `--json`: default-verbosity dashboard frames on the pty,
    // the JSON document in `-o`, closing lines replayed after the restore.
    let command = format!(
        "{} inventory --system --capture scan --identity-backend userspace --max-scan-pids 1 --dashboard --duration 4s -o {}",
        env!("CARGO_BIN_EXE_p11scope"),
        report.display(),
    );
    let status = Command::new("timeout")
        .args(["60", "script", "-qec", &command])
        .arg(&typescript)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("timeout runs the script dashboard session");
    assert!(
        status.success(),
        "the script dashboard session exits 0: {status}"
    );
    let output = std::fs::read(&typescript).expect("script wrote the typescript");
    // The interactive path ran, not the degraded classic fallback.
    assert!(
        output
            .windows(b"\x1b[?1049h".len())
            .any(|bytes| bytes == b"\x1b[?1049h"),
        "the dashboard took the alternate screen"
    );
    let text = String::from_utf8_lossy(&output);
    assert!(
        !text.contains("degraded to"),
        "dashboard did not degrade to the classic path"
    );
    let body = std::fs::read_to_string(&report).unwrap();
    let doc: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["schema"], "p11scope/inventory/v1");
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
    // Default verbosity still shows the per-pass gap progress (stale
    // number): the replay after the restore carries it.
    assert!(
        text.lines()
            .any(|line| line.contains("p11scope: pass") && line.contains("budget refusal")),
        "per-pass gap line visible at default verbosity"
    );
    // ... so the terminal correction must also appear there, agreeing
    // with the document it was rendered from.
    let refusals = gaps.iter().filter(|gap| !gap["budget"].is_null()).count();
    let suppressed = doc["gaps_suppressed"].as_u64().unwrap();
    assert_dashboard_final_gap_line(&text, gaps.len(), refusals, suppressed);
}
