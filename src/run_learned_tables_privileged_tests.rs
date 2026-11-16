//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Live cell for default-`run` table learning on getter-only
//! providers: `tests/fixtures/run-learned-tables/provider.c` builds a
//! kryoptic-shaped shared object (only C_GetFunctionList,
//! C_GetInterface, C_GetInterfaceList exported; every table function
//! hidden), and `worker.c` is a short-lived pkcs11-check-shaped child
//! (dlopen, C_GetInterfaceList + C_GetInterface, table calls, exit).
//!
//! A default `run` (no manifest) over sequential short-lived workers
//! must attach the provider's table functions from a transient
//! scan's decoded tables and count the workers' table calls — not
//! just the three getters. Prints TABLE_CELL lines. Root BPF lane,
//! run serially through `scripts/run-privileged-lib-tests.sh`; spawns
//! the real observer (`P11SCOPE_E2E_OBSERVER`, else the `p11scope`
//! sibling of the test binary).
//!
//! Oracle (16:20 exact accounting, never a floor): each sequential
//! worker calls its own table function, so every ground-truth call
//! is observed or pinned inside the disclosed pre-first-attach
//! window; any mid-capture (post-attach) miss fails the cell. The
//! pure `check_exact_accounting` below is the oracle; its negative
//! controls are unprivileged unit tests in this file.

use crate::fixture_guard::DieWithParent as _;
use anyhow::{Context as _, Result, bail, ensure};
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_secs(60);

/// One sequential worker's table slot: 12 distinct non-getter
/// ordinals of the 3.0 table ((3, 68, 69) are the getters), each
/// with its standard-layout name. Worker `i` calls only
/// `ORDINALS[i]` so its calls are distinguishable in the profile.
const ORDINALS: [(u32, &str); 12] = [
    (0, "C_Initialize"),
    (1, "C_Finalize"),
    (2, "C_GetInfo"),
    (4, "C_GetSlotList"),
    (5, "C_GetSlotInfo"),
    (6, "C_GetTokenInfo"),
    (7, "C_GetMechanismList"),
    (8, "C_GetMechanismInfo"),
    (9, "C_InitToken"),
    (10, "C_InitPIN"),
    (11, "C_SetPIN"),
    (12, "C_OpenSession"),
];

/// One sequential worker's ground truth from its DONE ledger line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WorkerGroundTruth {
    /// Script order (arrival order over the sequential stdout pipe).
    index: usize,
    ordinal: u32,
    name: &'static str,
    /// Expected table calls (one per round).
    calls: u64,
    /// CLOCK_MONOTONIC nanoseconds around the call burst, same clock
    /// the observer stamps its attach instants with.
    burst_start_ns: u64,
    burst_end_ns: u64,
}

/// Exact accounting per the 16:20 ruling, pure over the parsed
/// report plus the workers' ledgers: observed + disclosed-missed ==
/// ground truth, misses only inside the disclosed pre-first-attach
/// window. Any mid-capture (post-attach) loss fails:
///
/// * every worker's function resolves to at most one row of the
///   provider's own module (no alias fan-out, no wrong-module
///   count, no overcount above the ledger);
/// * at least one worker is fully observed (the positive: learning
///   attached something);
/// * misses form a run prefix with at most one boundary partial
///   (any hole or late partial is a post-attach loss);
/// * every missed call sits inside the module's disclosed
///   `mapped_unattached` table window (fully-missed bursts end
///   before it closes; the boundary partial starts before it
///   closes);
/// * no BPF event loss is on the record (counts would be lower
///   bounds, not exact);
/// * no mechanism is decoded from the learned tables and
///   attribution stays withheld (20:50: standard-layout names, not
///   proven).
fn check_exact_accounting(
    report: &serde_json::Value,
    provider_path: &str,
    workers: &[WorkerGroundTruth],
) -> Result<()> {
    ensure!(
        !workers.is_empty(),
        "no worker ledgers: the ground truth is empty"
    );
    let functions = report
        .get("functions")
        .and_then(serde_json::Value::as_array)
        .context("observed profile has no functions array")?;
    let evidence = report
        .get("evidence")
        .context("observed profile has no evidence object")?;
    let event_loss = evidence
        .get("event_loss")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    ensure!(
        event_loss == 0,
        "event_loss={event_loss}: counts are lower bounds, exact accounting cannot pass"
    );
    let modules = evidence
        .get("discovery")
        .and_then(serde_json::Value::as_array)
        .context("observed profile has no evidence.discovery array")?;
    let module = modules
        .iter()
        .find(|module| {
            module
                .get("path")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|path| path == provider_path)
        })
        .with_context(|| format!("no discovery record for the fixture provider {provider_path}"))?;
    let module_id = module.get("module").or(Some(module));
    let matches_provider = |row: &serde_json::Value| -> bool {
        let row_module = match row.get("module") {
            Some(row_module) => row_module,
            None => return false,
        };
        let Some(want) = module_id else {
            return false;
        };
        want.get("sha256") == row_module.get("sha256")
            && want.get("ino") == row_module.get("ino")
            && want.get("dev") == row_module.get("dev")
    };
    // Per-worker observed counts, each from exactly the provider's
    // own row (absent = the slot never attached = zero observed).
    let mut observed: Vec<u64> = Vec::with_capacity(workers.len());
    for worker in workers {
        let rows: Vec<&serde_json::Value> = functions
            .iter()
            .filter(|function| {
                matches_provider(function)
                    && function
                        .get("names")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|names| {
                            names
                                .iter()
                                .any(|name| name.as_str().is_some_and(|name| name == worker.name))
                        })
            })
            .collect();
        ensure!(
            rows.len() <= 1,
            "worker {} ({}): {} provider rows name it, ambiguous attribution (alias fan-out?)",
            worker.index,
            worker.name,
            rows.len(),
        );
        let calls = match rows.first() {
            None => 0,
            Some(row) => {
                ensure!(
                    !row.get("aliased")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false),
                    "worker {} ({}): its row is aliased, the count is not exact",
                    worker.index,
                    worker.name,
                );
                row.get("calls")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
            }
        };
        ensure!(
            calls <= worker.calls,
            "worker {} ({}): observed {calls} above the {} ledger calls (overcount)",
            worker.index,
            worker.name,
            worker.calls,
        );
        observed.push(calls);
    }
    let full = workers.iter().filter(|worker| {
        observed
            .get(worker.index)
            .is_some_and(|calls| *calls == worker.calls)
    });
    ensure!(
        full.count() > 0,
        "no worker fully observed: learning attached nothing (base shape)"
    );
    // Miss shape: zeros form a run prefix, at most one partial sits
    // immediately after them, the rest is fully observed. Anything
    // else is a mid-capture (post-attach) loss.
    let mut partials = 0usize;
    let mut first_full: Option<usize> = None;
    let mut seen_partial_after_full = false;
    for (index, worker) in workers.iter().enumerate() {
        let calls = observed[index];
        if calls == worker.calls {
            first_full.get_or_insert(index);
        } else if calls == 0 {
            ensure!(
                first_full.is_none(),
                "worker {index} ({}) missed after worker {} was fully observed: \
                 a mid-capture loss, never a pre-first-attach window",
                worker.name,
                first_full.unwrap_or(0),
            );
        } else {
            partials += 1;
            ensure!(
                partials <= 1,
                "workers partially observed twice: a mid-capture loss, never one attach boundary"
            );
            if first_full.is_some() {
                seen_partial_after_full = true;
            }
        }
    }
    ensure!(
        !seen_partial_after_full,
        "a partial worker follows a fully observed one: a mid-capture loss, never the attach boundary"
    );
    // Every miss sits inside the disclosed table window: the
    // module's `mapped_unattached` window covers its undeclared
    // (table) endpoints up to their max attach instant.
    let windows = module
        .get("unobserved_windows")
        .and_then(serde_json::Value::as_array)
        .context("the provider record discloses no unobserved windows")?;
    let window_end = windows
        .iter()
        .filter(|window| {
            window
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|reason| reason == "mapped_unattached")
        })
        .filter_map(|window| window.get("end_ns").and_then(serde_json::Value::as_u64))
        .max()
        .context("the provider record discloses no mapped_unattached table window")?;
    for (index, worker) in workers.iter().enumerate() {
        let calls = observed[index];
        if calls == 0 {
            ensure!(
                worker.burst_end_ns < window_end,
                "worker {index} ({}) missed with its burst ending at {}ns, after the disclosed \
                 table window closed at {window_end}ns: an undisclosed mid-capture loss",
                worker.name,
                worker.burst_end_ns,
            );
        } else if calls < worker.calls {
            ensure!(
                worker.burst_start_ns < window_end,
                "worker {index} ({}) partially observed with its burst starting at {}ns, after the \
                 disclosed table window closed at {window_end}ns: an undisclosed mid-capture loss",
                worker.name,
                worker.burst_start_ns,
            );
        }
    }
    let ground: u64 = workers.iter().map(|worker| worker.calls).sum();
    let seen: u64 = observed.iter().sum();
    let missed = ground.saturating_sub(seen);
    ensure!(
        seen + missed == ground,
        "observed ({seen}) + disclosed-missed ({missed}) != ground truth ({ground})"
    );
    println!("TABLE_CELL exact accounting: observed={seen} missed={missed} ground={ground}");
    // 20:50 names ruling for the learned getter-only tables:
    // standard-layout names may be shown, always marked unproven,
    // never decoded (no mechanisms, no arguments).
    let mechanisms = report
        .get("mechanisms")
        .and_then(serde_json::Value::as_array)
        .context("observed profile has no mechanisms array")?;
    ensure!(
        mechanisms.is_empty(),
        "mechanisms decoded from learned getter-only tables: {mechanisms:?}"
    );
    let attribution = evidence
        .pointer("/gap_classes/attribution/status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    ensure!(
        attribution == "withheld",
        "attribution status is {attribution:?}, learned getter-only names must stay unproven (withheld)"
    );
    Ok(())
}

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn observer_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("P11SCOPE_E2E_OBSERVER") {
        let path = PathBuf::from(path);
        ensure!(
            path.exists(),
            "P11SCOPE_E2E_OBSERVER={} is missing",
            path.display()
        );
        return Ok(path);
    }
    std::env::current_exe()?
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join("p11scope"))
        .filter(|path| path.exists())
        .context("no observer binary: set P11SCOPE_E2E_OBSERVER or build p11scope beside this test binary")
}

/// Builds the getter-only provider and its short-lived worker. Fails
/// by name when the shape is wrong (anything but exactly the three
/// getters exported), never skips.
fn build_fixtures(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let library = dir.join("libtableprov.so");
    let status = Command::new("cc")
        .args([
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-shared",
            "-fPIC",
            "-fvisibility=hidden",
            "-o",
        ])
        .arg(&library)
        .arg(repo("tests/fixtures/run-learned-tables/provider.c"))
        .status()
        .context("running cc (a C compiler is required to build the fixture)")?;
    ensure!(status.success(), "provider fixture build failed");
    let worker = dir.join("worker");
    let status = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&worker)
        .arg(repo("tests/fixtures/run-learned-tables/worker.c"))
        .status()
        .context("running cc")?;
    ensure!(status.success(), "worker fixture build failed");
    let output = Command::new("readelf")
        .arg("--dyn-syms")
        .arg(&library)
        .output()
        .context("running readelf")?;
    ensure!(output.status.success(), "readelf --dyn-syms failed");
    let mut exported: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().nth(7).map(str::to_string))
        .filter(|name| name.starts_with("C_"))
        .collect();
    exported.sort();
    ensure!(
        exported
            == [
                "C_GetFunctionList".to_string(),
                "C_GetInterface".to_string(),
                "C_GetInterfaceList".to_string(),
            ],
        "the provider must export exactly the three getters, exported: {exported:?}"
    );
    Ok((library, worker))
}

fn head(log: &Path) -> String {
    std::fs::read_to_string(log)
        .map(|text| text.chars().take(1500).collect::<String>())
        .unwrap_or_default()
}

fn tail(log: &Path) -> String {
    std::fs::read_to_string(log)
        .map(|text| {
            let start = text.len().saturating_sub(2000);
            text[start..].to_string()
        })
        .unwrap_or_default()
}

/// Parses one worker DONE ledger line into ground truth. `index` is
/// the script order (arrival order over the sequential pipe).
fn parse_ledger_line(index: usize, line: &str) -> Result<WorkerGroundTruth> {
    let rest = line
        .strip_prefix("DONE worker=")
        .with_context(|| format!("ledger line without DONE worker=: {line}"))?;
    let mut calls: Option<u64> = None;
    let mut burst_start_ns: Option<u64> = None;
    let mut burst_end_ns: Option<u64> = None;
    let mut ordinal: Option<u32> = None;
    for field in rest.split_whitespace() {
        if let Some(value) = field.strip_prefix("table_calls=") {
            calls = Some(
                value
                    .parse()
                    .with_context(|| format!("ledger calls: {line}"))?,
            );
        } else if let Some(value) = field.strip_prefix("burst_start_ns=") {
            burst_start_ns = Some(
                value
                    .parse()
                    .with_context(|| format!("ledger burst_start_ns: {line}"))?,
            );
        } else if let Some(value) = field.strip_prefix("burst_end_ns=") {
            burst_end_ns = Some(
                value
                    .parse()
                    .with_context(|| format!("ledger burst_end_ns: {line}"))?,
            );
        } else if let Some(value) = field.strip_prefix("ordinal=") {
            ordinal = Some(
                value
                    .parse()
                    .with_context(|| format!("ledger ordinal: {line}"))?,
            );
        }
    }
    let (expected_ordinal, name) = ORDINALS[index];
    let ordinal = ordinal.with_context(|| format!("ledger line without ordinal: {line}"))?;
    ensure!(
        ordinal == expected_ordinal,
        "worker {index} called ordinal {ordinal}, script order says {expected_ordinal} ({name}): {line}"
    );
    let calls = calls.with_context(|| format!("ledger line without calls: {line}"))?;
    let burst_start_ns =
        burst_start_ns.with_context(|| format!("ledger line without burst_start_ns: {line}"))?;
    let burst_end_ns =
        burst_end_ns.with_context(|| format!("ledger line without burst_end_ns: {line}"))?;
    ensure!(
        burst_start_ns <= burst_end_ns,
        "worker {index} burst ends before it starts: {line}"
    );
    Ok(WorkerGroundTruth {
        index,
        ordinal,
        name,
        calls,
        burst_start_ns,
        burst_end_ns,
    })
}

#[test]
#[ignore = "privileged: default run over short-lived workers learns a getter-only provider's tables and counts their table calls"]
fn privileged_run_default_learns_tables_for_a_getter_only_provider() -> Result<()> {
    let tag = "run-learned-tables";
    let observer = observer_binary()?;
    // Fixtures live directly under /tmp (not the runner's 0700
    // TMPDIR): the observer's child is fully deprivileged (zero
    // capabilities even as root), so it cannot traverse
    // root-only directories to reach them.
    let dir = tempfile::TempDir::new_in("/tmp")?;
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )?;
    let (library, worker) = build_fixtures(dir.path())?;
    for path in [&library, &worker] {
        std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    }
    // Sequential short-lived workers, pkcs11-check-shaped: each
    // dlopens, negotiates the 3.0 interface, calls its own table
    // function 10 times and lingers about a second with the
    // provider mapped (the matrix unit workers' lifetime), so the
    // owned-tree watch can scan them. Enough of them that slow
    // hosts still run most workers after the late attach lands.
    const ROUNDS_EACH: usize = 10;
    const LINGER_MS: usize = 1000;
    assert_eq!(ORDINALS.len(), 12);
    let mut script = String::from("set -e; ");
    for (index, (ordinal, _)) in ORDINALS.iter().enumerate() {
        use std::fmt::Write as _;
        write!(
            script,
            "'{}' '{}' {ROUNDS_EACH} {LINGER_MS} {ordinal} || {{ echo \"WORKER_FAIL i={index} rc=$?\"; exit 1; }}; ",
            worker.display(),
            library.display(),
        )
        .expect("script fits");
    }
    let report = dir.path().join("run.json");
    let log = dir.path().join("observer.log");
    let log_file = std::fs::File::create(&log)?;
    // `--user root`: the fixtures live in a root-only tempdir, and
    // `run` otherwise drops the child to the sudo invoker (covered
    // by its own cells), which could not execute them.
    let mut child = Command::new(&observer)
        .arg("run")
        .arg("--user")
        .arg("root")
        .arg("-o")
        .arg(&report)
        .arg("--")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .stdout(Stdio::piped())
        .stderr(log_file)
        .die_with_parent()
        .spawn()
        .context("spawning the observer")?;
    let stdout = child.stdout.take().context("observer stdout")?;
    let mut workers: Vec<WorkerGroundTruth> = Vec::new();
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if line.starts_with("WORKER_FAIL") {
            println!("TABLE_CELL {tag} {line}");
        }
        if line.starts_with("DONE worker=") {
            let index = workers.len();
            workers.push(parse_ledger_line(index, &line)?);
        }
    }
    let deadline = Instant::now() + STEP * 2;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(
            Instant::now() < deadline,
            "the observer never stopped: {}",
            tail(&log)
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let ledger_calls: u64 = workers.iter().map(|worker| worker.calls).sum();
    println!("TABLE_CELL {tag} observer {status}");
    println!(
        "TABLE_CELL {tag} ledger workers={}/{} table_calls={ledger_calls}",
        workers.len(),
        ORDINALS.len(),
    );
    ensure!(
        status.success(),
        "run exited {status}; log head: {}; log tail: {}",
        head(&log),
        tail(&log)
    );
    ensure!(
        workers.len() == ORDINALS.len(),
        "only {}/{} workers reported; observer log: {}",
        workers.len(),
        ORDINALS.len(),
        tail(&log)
    );
    for worker in &workers {
        ensure!(
            worker.calls == ROUNDS_EACH as u64,
            "worker {} ledger {} != expected {ROUNDS_EACH}",
            worker.index,
            worker.calls,
        );
    }
    let expected = (ORDINALS.len() * ROUNDS_EACH) as u64;
    ensure!(
        ledger_calls == expected,
        "ledger {ledger_calls} != expected {expected}"
    );
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&report)?)?;
    check_exact_accounting(&report, &library.to_string_lossy(), &workers)
        .map_err(|error| anyhow::anyhow!("{error:#}; observer log tail: {}", tail(&log)))?;
    let table_observed: u64 = report
        .get("functions")
        .and_then(serde_json::Value::as_array)
        .map(|functions| {
            functions
                .iter()
                .filter(|function| {
                    function
                        .get("names")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|names| {
                            names.iter().any(|name| {
                                name.as_str().is_some_and(|name| {
                                    ORDINALS.iter().any(|(_, want)| *want == name)
                                })
                            })
                        })
                })
                .filter_map(|function| function.get("calls").and_then(serde_json::Value::as_u64))
                .sum()
        })
        .unwrap_or(0);
    if table_observed < ledger_calls {
        println!("TABLE_CELL {tag} PARTIAL table_observed={table_observed} ledger={ledger_calls}");
    }
    Ok(())
}

/// The worker alone (no observer) prints a sane ledger: the negative
/// control that a cell failure is the observer's, not the fixture's.
#[test]
fn run_learned_tables_worker_reports_its_ledger() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (library, worker) = build_fixtures(dir.path())?;
    let output = Command::new(&worker)
        .arg(&library)
        .arg("4")
        .output()
        .context("running the worker")?;
    if !output.status.success() {
        bail!(
            "worker exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let line = String::from_utf8_lossy(&output.stdout);
    ensure!(
        line.starts_with("DONE worker=") && line.contains("table_calls=12"),
        "unexpected worker ledger: {line:?}"
    );
    ensure!(
        line.contains("burst_start_ns=") && line.contains("burst_end_ns="),
        "the ledger must carry the burst window: {line:?}"
    );
    // Ordinal mode: one slot per round, still exact.
    let output = Command::new(&worker)
        .arg(&library)
        .arg("5")
        .arg("0")
        .arg("4")
        .output()
        .context("running the ordinal worker")?;
    ensure!(
        output.status.success(),
        "ordinal worker exited {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let line = String::from_utf8_lossy(&output.stdout);
    ensure!(
        line.starts_with("DONE worker=")
            && line.contains("table_calls=5")
            && line.contains("ordinal=4"),
        "unexpected ordinal ledger: {line:?}"
    );
    Ok(())
}

#[cfg(test)]
mod exact_accounting_tests {
    use super::{ORDINALS, WorkerGroundTruth, check_exact_accounting};

    const PROVIDER: &str = "/tmp/tableprov/libtableprov.so";
    const DEV: (u64, u64) = (0, 41);
    const INO: u64 = 137905;
    const SHA: &str = "1bcecfc265afb465e2955b23c6d869dbf4a9fa2c34687062bca0859553a35074";
    /// The disclosed table window closes here in every synthetic
    /// report below.
    const WINDOW_END: u64 = 1000;

    fn worker(index: usize, start_ns: u64, end_ns: u64) -> WorkerGroundTruth {
        let (ordinal, name) = ORDINALS[index];
        WorkerGroundTruth {
            index,
            ordinal,
            name,
            calls: 10,
            burst_start_ns: start_ns,
            burst_end_ns: end_ns,
        }
    }

    fn function_row(name: &str, calls: u64) -> serde_json::Value {
        serde_json::json!({
            "calls": calls,
            "module": {"dev": [DEV.0, DEV.1], "ino": INO, "sha256": SHA},
            "names": [name],
        })
    }

    /// Three workers, per-worker observed counts (`None` = no row,
    /// the base-run shape for an unattached slot).
    fn report(observed: [Option<u64>; 3]) -> serde_json::Value {
        let functions: Vec<serde_json::Value> = observed
            .iter()
            .enumerate()
            .filter_map(|(index, calls)| calls.map(|calls| function_row(ORDINALS[index].1, calls)))
            .collect();
        serde_json::json!({
            "functions": functions,
            "mechanisms": [],
            "evidence": {
                "event_loss": 0,
                "gap_classes": {"attribution": {"status": "withheld"}},
                "discovery": [{
                    "path": PROVIDER,
                    "dev": [DEV.0, DEV.1],
                    "ino": INO,
                    "sha256": SHA,
                    "unobserved_windows": [
                        {"start_ns": 100, "end_ns": 500, "reason": "late_discovery"},
                        {"start_ns": 100, "end_ns": WINDOW_END, "reason": "mapped_unattached"},
                    ],
                }],
            },
        })
    }

    fn ledgers() -> Vec<WorkerGroundTruth> {
        vec![
            worker(0, 100, 200),
            worker(1, 300, 400),
            worker(2, 1100, 1200),
        ]
    }

    #[test]
    fn exact_accounting_accepts_a_clean_prefix_run() {
        // Worker 0 missed inside the disclosed window, workers 1-2
        // fully observed: the honest tip shape.
        let report = report([Some(0), Some(10), Some(10)]);
        check_exact_accounting(&report, PROVIDER, &ledgers()).expect("a clean prefix run passes");
    }

    #[test]
    fn exact_accounting_accepts_absent_rows_for_pre_attach_workers() {
        // No row at all for the pre-attach worker (its slot never
        // attached): still a disclosed pre-attach miss.
        let report = report([None, Some(10), Some(10)]);
        check_exact_accounting(&report, PROVIDER, &ledgers())
            .expect("an absent pre-attach row passes");
    }

    #[test]
    fn exact_accounting_accepts_a_boundary_partial() {
        // Worker 1 partially observed with its burst starting
        // before the disclosed window closed: the attach landed in
        // its burst, the only honest partial position.
        let report = report([Some(0), Some(4), Some(10)]);
        check_exact_accounting(&report, PROVIDER, &ledgers()).expect("a boundary partial passes");
    }

    #[test]
    fn exact_accounting_rejects_a_mid_capture_hole() {
        // Worker 1 missed while workers 0 and 2 are observed: a
        // post-attach loss, never a pre-first-attach window.
        let report = report([Some(10), Some(0), Some(10)]);
        let error = check_exact_accounting(&report, PROVIDER, &ledgers())
            .expect_err("a mid-capture hole must fail");
        assert!(
            format!("{error:#}").contains("mid-capture"),
            "the failure names the mid-capture loss: {error:#}"
        );
    }

    #[test]
    fn exact_accounting_rejects_a_zero_after_a_partial() {
        // Worker 0 partially observed, worker 1 missed, worker 2
        // full: the zero sits after an attach boundary, a
        // post-attach loss, never a run prefix.
        let report = report([Some(4), Some(0), Some(10)]);
        let error = check_exact_accounting(&report, PROVIDER, &ledgers())
            .expect_err("a zero after a partial must fail");
        assert!(
            format!("{error:#}").contains("mid-capture"),
            "the failure names the mid-capture loss: {error:#}"
        );
    }

    #[test]
    fn exact_accounting_rejects_a_hole_between_two_windows() {
        // Two disclosed table windows with a gap between them; the
        // missed burst sits in the gap (before the latest end): the
        // miss is inside no single disclosed window.
        let mut report = report([Some(0), Some(10), Some(10)]);
        report["evidence"]["discovery"][0]["unobserved_windows"] = serde_json::json!([
            {"start_ns": 100, "end_ns": 200, "reason": "mapped_unattached"},
            {"start_ns": 500, "end_ns": 1000, "reason": "mapped_unattached"},
        ]);
        let workers = vec![
            worker(0, 300, 400),
            worker(1, 1100, 1200),
            worker(2, 1300, 1400),
        ];
        let error = check_exact_accounting(&report, PROVIDER, &workers)
            .expect_err("a miss between two windows must fail");
        assert!(
            format!("{error:#}").contains("window"),
            "the failure names the window: {error:#}"
        );
    }

    #[test]
    fn exact_accounting_accepts_a_miss_before_its_own_endpoint_attach() {
        // The missed burst sits past every disclosed window but ends
        // before its own endpoint's first attach began: the attach
        // point discloses the miss.
        let mut report = report([Some(0), Some(10), Some(10)]);
        report["evidence"]["discovery"][0]["unobserved_windows"] = serde_json::json!([
            {"start_ns": 100, "end_ns": 150, "reason": "mapped_unattached"},
        ]);
        report["evidence"]["discovery"][0]["first_attach_points"] = serde_json::json!([
            {"file_offset": 0x1000, "began_ns": 500, "attached_ns": 520},
        ]);
        report["functions"][0]["target"] = serde_json::json!({
            "object": {"dev": [DEV.0, DEV.1], "ino": INO, "sha256": SHA},
            "file_offset": 0x1000,
        });
        let workers = vec![
            worker(0, 300, 400),
            worker(1, 1100, 1200),
            worker(2, 1300, 1400),
        ];
        check_exact_accounting(&report, PROVIDER, &workers)
            .expect("a miss before its own endpoint attach passes");
    }

    #[test]
    fn exact_accounting_accepts_a_partial_straddling_its_own_endpoint_attach() {
        // The partial's burst starts past every disclosed window but
        // its own endpoint's first attach began mid-burst: the attach
        // landed inside the burst.
        let mut report = report([Some(0), Some(4), Some(10)]);
        report["evidence"]["discovery"][0]["unobserved_windows"] = serde_json::json!([
            {"start_ns": 100, "end_ns": 150, "reason": "mapped_unattached"},
        ]);
        report["evidence"]["discovery"][0]["first_attach_points"] = serde_json::json!([
            {"file_offset": 0x1010, "began_ns": 420, "attached_ns": 430},
        ]);
        report["functions"][1]["target"] = serde_json::json!({
            "object": {"dev": [DEV.0, DEV.1], "ino": INO, "sha256": SHA},
            "file_offset": 0x1010,
        });
        let workers = vec![
            worker(0, 100, 120),
            worker(1, 400, 450),
            worker(2, 1300, 1400),
        ];
        check_exact_accounting(&report, PROVIDER, &workers)
            .expect("a partial straddling its own endpoint attach passes");
    }

    #[test]
    fn exact_accounting_accepts_a_leading_partial() {
        // No zero prefix at all: the first worker straddles the
        // attach boundary and everything after is fully observed.
        let report = report([Some(4), Some(10), Some(10)]);
        check_exact_accounting(&report, PROVIDER, &ledgers()).expect("a leading partial passes");
    }

    #[test]
    fn exact_accounting_rejects_a_late_partial() {
        // Worker 2 partially observed although its burst ran fully
        // after the disclosed window closed: post-attach loss.
        let report = report([Some(0), Some(10), Some(4)]);
        let error = check_exact_accounting(&report, PROVIDER, &ledgers())
            .expect_err("a late partial must fail");
        assert!(
            format!("{error:#}").contains("mid-capture"),
            "the failure names the mid-capture loss: {error:#}"
        );
    }

    #[test]
    fn exact_accounting_rejects_an_unobserved_run() {
        // Nothing observed at all (the base shape): the positive
        // control — learning must have attached something.
        let report = report([None, None, None]);
        let error = check_exact_accounting(&report, PROVIDER, &ledgers())
            .expect_err("an unobserved run must fail");
        assert!(
            format!("{error:#}").contains("no worker"),
            "the failure names the missing positive: {error:#}"
        );
    }

    #[test]
    fn exact_accounting_rejects_overcount() {
        // More observed than the ground truth (alias fan-out or
        // double count): exact means bounded above too.
        let report = report([Some(0), Some(10), Some(11)]);
        check_exact_accounting(&report, PROVIDER, &ledgers()).expect_err("overcount must fail");
    }

    #[test]
    fn exact_accounting_rejects_alias_fanout_rows() {
        // One function spread over two rows: the checker must not
        // silently sum (or pick) an ambiguous attribution.
        let mut report = report([Some(0), Some(10), Some(10)]);
        report["functions"]
            .as_array_mut()
            .expect("functions array")
            .push(function_row(ORDINALS[2].1, 0));
        check_exact_accounting(&report, PROVIDER, &ledgers()).expect_err("alias fan-out must fail");
    }

    #[test]
    fn exact_accounting_rejects_misses_outside_the_window() {
        // Worker 0 missed although its burst ended after the
        // disclosed window closed: the miss is undisclosed.
        let report = report([Some(0), Some(10), Some(10)]);
        let workers = vec![
            worker(0, 1100, 1200),
            worker(1, 1300, 1400),
            worker(2, 1500, 1600),
        ];
        let error = check_exact_accounting(&report, PROVIDER, &workers)
            .expect_err("an undisclosed miss must fail");
        assert!(
            format!("{error:#}").contains("window"),
            "the failure names the window: {error:#}"
        );
    }

    #[test]
    fn exact_accounting_rejects_a_missing_table_window() {
        // No mapped_unattached window disclosed: misses cannot be
        // pinned to a window, so any miss fails.
        let mut report = report([Some(0), Some(10), Some(10)]);
        report["evidence"]["discovery"][0]
            .as_object_mut()
            .expect("module record")
            .remove("unobserved_windows");
        check_exact_accounting(&report, PROVIDER, &ledgers())
            .expect_err("a missing window must fail");
    }

    #[test]
    fn exact_accounting_rejects_event_loss() {
        // BPF event loss makes every count a lower bound: exact
        // accounting cannot pass with loss on the record.
        let mut report = report([Some(0), Some(10), Some(10)]);
        report["evidence"]["event_loss"] = serde_json::json!(3);
        check_exact_accounting(&report, PROVIDER, &ledgers()).expect_err("event loss must fail");
    }

    #[test]
    fn exact_accounting_ignores_wrong_module_rows() {
        // A same-named row from another module (another cgroup) must
        // not count toward this provider's workers.
        let mut report = report([None, Some(10), Some(10)]);
        report["functions"]
            .as_array_mut()
            .expect("functions array")
            .push(serde_json::json!({
                "calls": 10,
                "module": {"dev": [0, 42], "ino": 999, "sha256": "other"},
                "names": [ORDINALS[0].1],
            }));
        check_exact_accounting(&report, PROVIDER, &ledgers())
            .expect("a wrong-module row must not disturb the accounting");
    }
}
