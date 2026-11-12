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
    spawn_with_peak_pumping(cmd, stderr_log, &mut || {})
}

/// `spawn_with_peak` with a hook the churn test uses to tail the
/// observer's event log while it runs. The hook must be infallible and
/// cheap: it runs every 5 ms until the child exits.
fn spawn_with_peak_pumping(
    cmd: &mut Command,
    stderr_log: &Path,
    pump: &mut dyn FnMut(),
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
        pump();
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
    birth_fired: bool,
    last_pass: Option<u64>,
    kill_admitting_pass: Option<u64>,
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
            // Admitted events precede their pass marker in the commit
            // batch, so the admitting pass is one past the last marker
            // seen before this tick (pass 0 when none seen yet); the
            // kill-cadence assert below needs a later pass observing the
            // deaths.
            self.kill_admitting_pass = Some(
                pass_before_tick
                    .map(|pass| pass.saturating_add(1))
                    .unwrap_or(0),
            );
            if let (Some(churn_a), Some(anchor)) = (self.churn_a, self.anchor)
                && pid_is_driver(churn_a, &self.driver_exe)
                && pid_is_driver(anchor, &self.driver_exe)
            {
                unsafe {
                    libc::kill(churn_a as i32, libc::SIGTERM);
                    libc::kill(anchor as i32, libc::SIGTERM);
                }
            }
        }
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
                self.admitted.insert(pid);
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
    let mut cmd = Command::new("sh");
    cmd.arg(fixture_source("inventory-churn-observe.sh"))
        .arg("--system")
        .args(["--json", "--duration", "14s", "--max-scan-pids", "4096"])
        .args(system_capture_args())
        .arg("--event-log")
        .arg(&events)
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
        birth_fired: false,
        last_pass: None,
        kill_admitting_pass: None,
    };
    let (output, peak) = spawn_with_peak_pumping(&mut cmd, &stderr_log, &mut || condition.pump());
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
        "churn settlement needs an admitting pass plus a later pass observing the mid-run deaths; got {passes} published passes in 14s"
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
            "conditioned kill landed on pass {admitting}'s publish but no later pass published (last pass {last}); the mid-run deaths need a pass after the admitting pass"
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
            "{name} (pid {pid}) exited after its conditioned kill"
        );
    }
    assert!(
        !condition.exited.contains(&churn_b_pid),
        "churn-B (pid {churn_b_pid}) stays alive to run end"
    );
    // Terminal settlement over our pids: exactly one incarnation each,
    // the killed two exited and retired, the survivor mapped.
    let incarnations = |pid: u32| {
        doc["callers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|caller| caller["pid"] == u64::from(pid))
            .collect::<Vec<_>>()
    };
    for (pid, name) in [
        (anchor_pid, "anchor"),
        (churn_a_pid, "churn-A"),
        (churn_b_pid, "churn-B"),
    ] {
        assert_eq!(incarnations(pid).len(), 1, "one {name} incarnation");
    }
    let anchor = incarnations(anchor_pid)[0];
    assert_eq!(anchor["lifecycle"], "exited");
    assert_eq!(anchor["retired"], true);
    let churn_a = incarnations(churn_a_pid)[0];
    assert_eq!(churn_a["lifecycle"], "exited");
    assert_eq!(churn_a["retired"], true);
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
        // Died after admission: settled dead, never silently dropped.
        assert_eq!(churn_c_incarnations.len(), 1, "one churn-C incarnation");
        let churn_c = churn_c_incarnations[0];
        assert_eq!(churn_c["lifecycle"], "exited");
        assert_eq!(churn_c["retired"], true);
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
const GUARD_DRIVER: &str = "/nonexistent/churn-guard-driver";

/// Scripted `ChurnCondition` over dead pids and a fake driver path: the
/// kill latch fires on the admitted event, but no signal is ever sent.
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
        birth_fired: false,
        last_pass: None,
        kill_admitting_pass: None,
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
