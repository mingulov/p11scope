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

use crate::fixture_guard::DieWithParent as _;
use anyhow::{Context as _, Result, bail, ensure};
use std::io::{BufRead as _, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const STEP: Duration = Duration::from_secs(60);

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

fn tail(log: &Path) -> String {
    std::fs::read_to_string(log)
        .map(|text| {
            let start = text.len().saturating_sub(2000);
            text[start..].to_string()
        })
        .unwrap_or_default()
}

#[test]
#[ignore = "privileged: default run over short-lived workers learns a getter-only provider's tables and counts their table calls"]
fn privileged_run_default_learns_tables_for_a_getter_only_provider() -> Result<()> {
    let tag = "run-learned-tables";
    let observer = observer_binary()?;
    let dir = tempfile::tempdir()?;
    let (library, worker) = build_fixtures(dir.path())?;
    // Sequential short-lived workers, pkcs11-check-shaped: each
    // dlopens, negotiates the 3.0 interface and makes 30 table
    // calls within milliseconds. Enough of them that slow hosts
    // still run most workers after the late attach lands.
    const WORKERS: usize = 120;
    const ROUNDS_EACH: usize = 10;
    const CALLS_PER_ROUND: usize = 3;
    let script = format!(
        "for i in $(seq 1 {WORKERS}); do '{}' '{}' {ROUNDS_EACH} || {{ echo \"WORKER_FAIL i=$i rc=$?\"; exit 1; }}; done",
        worker.display(),
        library.display()
    );
    let report = dir.path().join("run.json");
    let log = dir.path().join("observer.log");
    let log_file = std::fs::File::create(&log)?;
    let mut child = Command::new(&observer)
        .arg("run")
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
    let mut ledger_calls: u64 = 0;
    let mut ledger_workers: usize = 0;
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Some(rest) = line.strip_prefix("DONE worker=") {
            let mut calls: Option<u64> = None;
            for field in rest.split_whitespace() {
                if let Some(value) = field.strip_prefix("table_calls=") {
                    calls = Some(
                        value
                            .parse()
                            .with_context(|| format!("ledger calls: {line}"))?,
                    );
                }
            }
            ledger_calls += calls.with_context(|| format!("ledger line without calls: {line}"))?;
            ledger_workers += 1;
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
    println!("TABLE_CELL {tag} observer {status}");
    println!(
        "TABLE_CELL {tag} ledger workers={ledger_workers}/{WORKERS} table_calls={ledger_calls}"
    );
    ensure!(status.success(), "run exited {status}: {}", tail(&log));
    ensure!(
        ledger_workers == WORKERS,
        "only {ledger_workers}/{WORKERS} workers reported; observer log: {}",
        tail(&log)
    );
    let expected = (WORKERS * ROUNDS_EACH * CALLS_PER_ROUND) as u64;
    ensure!(
        ledger_calls == expected,
        "ledger {ledger_calls} != expected {expected}"
    );
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&report)?)?;
    let functions = report
        .get("functions")
        .and_then(serde_json::Value::as_array)
        .context("observed profile has no functions array")?;
    let mut by_name = std::collections::BTreeMap::new();
    for function in functions {
        let calls = function
            .get("calls")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        for name in function
            .get("names")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(name) = name.as_str() {
                *by_name.entry(name.to_string()).or_insert(0) += calls;
            }
        }
    }
    println!("TABLE_CELL {tag} ledger table_calls={ledger_calls} observed={by_name:?}");
    for name in ["C_Initialize", "C_GetSlotList"] {
        let calls = by_name.get(name).copied().unwrap_or(0);
        ensure!(
            calls > 0,
            "no {name} calls observed (getter-only blindness): {by_name:?}; observer log: {}",
            tail(&log)
        );
    }
    let table_observed: u64 = by_name
        .iter()
        .filter(|(name, _)| {
            !["C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"].contains(&name.as_str())
        })
        .map(|(_, calls)| *calls)
        .sum();
    // Generous floor: even a very late attach must leave most of
    // the sequential workers covered; the base observes zero.
    ensure!(
        table_observed * 10 >= ledger_calls,
        "only {table_observed}/{ledger_calls} table calls observed; observer log: {}",
        tail(&log)
    );
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
    Ok(())
}
