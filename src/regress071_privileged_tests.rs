//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! End-to-end regression cells for the v0.7.0 -> v0.7.1 admission/counting
//! regression: `profile --system` undercounts short-lived callers by
//! ~25-30% with zero loss counters, newcomer admission stalls and slots
//! retire (`active_slots` 0 vs 68), and `inventory --system` entry counting
//! stops ~1 min into a 1/s short-lived stream.
//!
//! Each cell drives a deterministic workload with a known exact call count
//! under the real observer binary ([`observer_binary`]: `P11SCOPE_E2E_OBSERVER`
//! when set, else the `p11scope` sibling of this test binary) and asserts:
//! counted calls == driver calls exactly for every exercised endpoint, zero
//! errors, the view never stops (trailing-cohort calls are counted, which an
//! exact total proves), and no unnamed loss: on a mismatch the cell prints
//! every schema loss counter and fails, because no counter today counts
//! never-observed calls. A future fix that names its misses in a
//! calls-denominated counter extends [`NAMED_CALL_LOSS_COUNTERS`]; queue/pid
//! counters never qualify.
//!
//! RED contract: every cell FAILS on the buggy build (2234b514f) with an
//! exact-count mismatch / retired view for the right reason, and PASSES on
//! v0.7.0. The cells run in the curated privileged campaign (default lane,
//! exact selectors, nonzero selection) and take <= 5 min each.
//!
//! - (a) `..._bigchild_kills_exact_lp64`: N 1 GiB children in 2-way
//!   bursts with K call rounds each, plus an exact C_GetSlotList poll
//!   control and fork noise. R071A lines.
//! - (b) `..._newcomer_flood_exact_lp64`: 2-way sync bursts of 1 GiB
//!   children with K call rounds plus loader churn. R071B lines.
//! - (c) `..._shortlived_stream_exact_lp64`: `inventory --system` with a
//!   1/s short-lived stream. R071C lines.
//! - (d) `..._bind_mount_two_view_exact_lp64`: flood children alternating
//!   two views of one provider file on a private ext4 loop mount,
//!   bind-mounted into the workload dir. R071D lines.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};

use crate::fixture_guard::DieWithParent as _;

/// SoftHSM2 provider layouts across hosts (Debian multiarch first, then
/// the /usr/lib layout the vng guests carry, then Fedora /usr/lib64).
const SOFTHSM_CANDIDATES: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
];

/// Counters that count MISSED CALLS in a calls-denominated unit and may
/// therefore account for a driver-vs-observed miss. Empty today: queue and
/// pid counters (`newcomer dropped`, `pid_descendant_gaps`) count pids/marks,
/// not calls, and `cgroups[].unadmitted` is a subset of already-counted
/// calls. Extend only with a counter whose unit is proven calls.
const NAMED_CALL_LOSS_COUNTERS: &[&str] = &[];

fn softhsm_path() -> Result<String> {
    for candidate in SOFTHSM_CANDIDATES {
        if Path::new(candidate).exists() {
            return Ok(candidate.to_string());
        }
    }
    anyhow::bail!(
        "SoftHSM2 provider is missing (tried {})",
        SOFTHSM_CANDIDATES.join(", ")
    )
}

/// The observer under test: an explicit `P11SCOPE_E2E_OBSERVER` binary
/// (the positive/negative controls point it at the release under test),
/// else a `p11scope` staged beside this test binary (the CI artifact
/// layout, which is also what the vng guest sees), else the `p11scope`
/// sibling of this test binary's directory (a local `cargo build`
/// layout).
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
    let current = std::env::current_exe()?;
    if let Some(staged) = current
        .parent()
        .map(|dir| dir.join("p11scope"))
        .filter(|path| path.exists())
    {
        return Ok(staged);
    }
    let sibling = current
        .parent()
        .and_then(Path::parent)
        .map(|dir| dir.join("p11scope"));
    if let Some(sibling) = sibling.filter(|path| path.exists()) {
        return Ok(sibling);
    }
    anyhow::bail!(
        "no observer binary: set P11SCOPE_E2E_OBSERVER or build the p11scope binary beside this test binary"
    )
}

fn fixture_source(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/regress071")
        .join(name)
}

fn cc_build(source: &Path, out: &Path) -> Result<()> {
    ensure!(source.exists(), "fixture {} is missing", source.display());
    let status = Command::new("cc")
        .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(source)
        .arg("-o")
        .arg(out)
        .args(["-ldl", "-lpthread"])
        .status()
        .context("running cc")?;
    ensure!(
        status.success(),
        "fixture build failed for {}",
        source.display()
    );
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(path)?;
    Ok(p11scope_manifest::identity::hex(&Sha256::digest(&bytes)))
}

/// Owned workload directory: compiled fixture binaries, one private
/// provider copy (bytes-identical to the system provider, distinguished
/// by its inode), and a private token store.
struct R071Workload {
    dir: tempfile::TempDir,
    bins: BTreeMap<String, PathBuf>,
    conf: PathBuf,
    provider_copy: PathBuf,
    provider_sha256: String,
    provider_ino: u64,
}

impl R071Workload {
    fn build(bin_names: &[&str], token_label: &str) -> Result<Self> {
        let module = softhsm_path()?;
        let dir = tempfile::tempdir()?;
        let mut bins = BTreeMap::new();
        for name in bin_names {
            let out = dir.path().join(name);
            cc_build(&fixture_source(&format!("{name}.c")), &out)?;
            bins.insert(name.to_string(), out);
        }
        let provider_copy = dir.path().join("libsofthsm2-copy.so");
        std::fs::copy(&module, &provider_copy)?;
        ensure!(
            sha256_file(Path::new(&module))? == sha256_file(&provider_copy)?,
            "provider copy hash mismatch"
        );
        let provider_sha256 = sha256_file(&provider_copy)?;
        let provider_ino = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(&provider_copy)?.ino()
        };
        let tokens = dir.path().join("tokens");
        std::fs::create_dir(&tokens)?;
        let conf = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\nslots.mechanisms = ALL\nlibrary.reset_on_fork = false\n",
                tokens.display()
            ),
        )?;
        let status = Command::new("softhsm2-util")
            .args(["--init-token", "--free", "--label", token_label])
            .args(["--so-pin", "5678", "--pin", "1234"])
            .env("SOFTHSM2_CONF", &conf)
            .stdout(Stdio::null())
            .status()
            .context("running softhsm2-util")?;
        ensure!(status.success(), "softhsm2-util --init-token failed");
        Ok(Self {
            dir,
            bins,
            conf,
            provider_copy,
            provider_sha256,
            provider_ino,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn bin(&self, name: &str) -> Result<&Path> {
        self.bins
            .get(name)
            .map(PathBuf::as_path)
            .with_context(|| format!("workload has no bin {name}"))
    }
}

/// Keep the workload directory on failure so the printed report path
/// stays readable; on success the directory drops as before.
fn keep_on_failure(workload: R071Workload, outcome: Result<()>, tag: &str) -> Result<()> {
    if outcome.is_err() {
        eprintln!("{tag} evidence kept at {}", workload.dir.path().display());
        let _ = workload.dir.keep();
    }
    outcome
}

/// A fixture child with file logs, reaped on drop. Drivers poll the
/// stdout file for READY/COUNTS lines (no pipe buffering races) and
/// SIGKILL on schedule; an unexpected exit is fixture evidence, never
/// a product verdict.
struct LoggedChild {
    child: Child,
    out: PathBuf,
    stderr: PathBuf,
    tag: String,
}

impl LoggedChild {
    fn spawn(
        tag: &str,
        bin: &Path,
        args: &[&str],
        envs: &[(&str, &str)],
        out: &Path,
        conf: &Path,
    ) -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let private_log = |path: &Path| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        };
        let stderr = out.with_extension("stderr");
        let mut command = Command::new(bin);
        command.args(args);
        command.env("SOFTHSM2_CONF", conf);
        for (key, value) in envs {
            command.env(key, value);
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(private_log(out)?)
            .stderr(private_log(&stderr)?)
            .die_with_parent()
            .spawn()
            .with_context(|| format!("{tag}: spawning {}", bin.display()))?;
        Ok(Self {
            child,
            out: out.to_path_buf(),
            stderr,
            tag: tag.to_string(),
        })
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn has_prefix(&self, prefix: &str) -> bool {
        std::fs::read_to_string(&self.out)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with(prefix)))
    }

    fn line_with_prefix(&self, prefix: &str) -> Option<String> {
        std::fs::read_to_string(&self.out)
            .ok()?
            .lines()
            .find(|line| line.starts_with(prefix))
            .map(str::to_string)
    }

    fn diagnostics(&self) -> String {
        fn tail(path: &Path) -> String {
            let text =
                std::fs::read_to_string(path).unwrap_or_else(|e| format!("<unreadable: {e}>"));
            let lines: Vec<&str> = text.lines().collect();
            let skip = lines.len().saturating_sub(8);
            lines[skip..].join("\\n")
        }
        format!(
            "{}: pid={} out tail=[{}] stderr tail=[{}]",
            self.tag,
            self.pid(),
            tail(&self.out),
            tail(&self.stderr)
        )
    }

    fn ensure_alive(&mut self, point: &str) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::bail!(
                "{} exited {point} with {status}: {}",
                self.tag,
                self.diagnostics()
            );
        }
        Ok(())
    }

    fn wait_for_prefix(&mut self, prefix: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        while !self.has_prefix(prefix) {
            if let Err(error) = self.ensure_alive(&format!("before {prefix:?}")) {
                if self.has_prefix(prefix) {
                    break;
                }
                return Err(error);
            }
            ensure!(
                Instant::now() < deadline,
                "{} never printed {prefix:?}: {}",
                self.tag,
                self.diagnostics()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    /// SIGKILL and reap; returns the exit status.
    fn kill_and_wait(&mut self) -> Result<std::process::ExitStatus> {
        if self.child.try_wait()?.is_none() {
            let _ = self.child.kill();
        }
        self.child
            .wait()
            .with_context(|| format!("{}: reaping", self.tag))
    }
}

impl Drop for LoggedChild {
    fn drop(&mut self) {
        let _ = self.kill_and_wait();
    }
}

/// Parse a `COUNTS k=v ...` fixture line into its counters.
fn parse_counts_line(line: &str) -> BTreeMap<String, u64> {
    line.split_whitespace()
        .filter_map(|field| field.split_once('='))
        .filter_map(|(key, value)| value.parse::<u64>().ok().map(|n| (key.to_string(), n)))
        .collect()
}

/// The observer under test: spawned once per cell with `--duration`,
/// reaped on drop. Readiness is the product's own stderr signal
/// (`capturing:` for profile, `p11scope: pass 0:` for inventory), so
/// counted calls are strictly post-attach on every revision.
struct Observer {
    child: Child,
    log: PathBuf,
    report: PathBuf,
}

impl Observer {
    fn spawn(
        workload: &R071Workload,
        observer: &Path,
        command: &str,
        modules: &[&Path],
        duration_s: u64,
        report_name: &str,
        tag: &str,
    ) -> Result<Self> {
        let report = workload.path(report_name);
        let log = workload.path(&format!("{tag}-observer.log"));
        let file = std::fs::File::create(&log)?;
        let mut args: Vec<String> = vec![command.to_string(), "--system".to_string()];
        for module in modules {
            args.push("--module".to_string());
            args.push(module.display().to_string());
        }
        args.push("--duration".to_string());
        args.push(format!("{duration_s}s"));
        args.push("-o".to_string());
        args.push(report.display().to_string());
        let child = Command::new(observer)
            .args(&args)
            .env("SOFTHSM2_CONF", &workload.conf)
            .stdin(Stdio::null())
            .stdout(file.try_clone()?)
            .stderr(file)
            .die_with_parent()
            .spawn()
            .context("spawning observer")?;
        println!("{tag} observer spawned pid={} args={args:?}", child.id());
        Ok(Self { child, log, report })
    }

    fn wait_for(&mut self, needle: &str, budget: Duration, tag: &str) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            if std::fs::read_to_string(&self.log)
                .is_ok_and(|text| text.lines().any(|line| line.contains(needle)))
            {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait()? {
                anyhow::bail!(
                    "{tag}: the observer exited before {needle:?}: {}",
                    self.evidence(&format!("exited {status}"))
                );
            }
            ensure!(
                Instant::now() < deadline,
                "{tag}: {needle:?} never appeared: {}",
                self.evidence("still running")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn wait_exit(&mut self, budget: Duration, tag: &str) -> Result<i32> {
        let deadline = Instant::now() + budget;
        loop {
            if let Some(status) = self.child.try_wait()? {
                let rc = status.code().unwrap_or(-1);
                println!("{tag} observer rc={rc}");
                ensure!(
                    rc == 0,
                    "{tag}: the observer must exit 0, got {rc}: {}",
                    self.evidence(&format!("exited {status}"))
                );
                return Ok(rc);
            }
            ensure!(
                Instant::now() < deadline,
                "{tag}: the observer never stopped: {}",
                self.evidence("still running")
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn evidence(&self, status: &str) -> String {
        let text =
            std::fs::read_to_string(&self.log).unwrap_or_else(|e| format!("<unreadable: {e}>"));
        let lines: Vec<&str> = text.lines().collect();
        let skip = lines.len().saturating_sub(40);
        format!(
            "observer {status}; report={}; log tail=[{}]",
            self.report.display(),
            lines[skip..].join("\\n")
        )
    }

    fn report(&self) -> Result<serde_json::Value> {
        let bytes = std::fs::read(&self.report)?;
        serde_json::from_slice(&bytes).context("parsing the observer report")
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        if self.child.try_wait().is_ok_and(|status| status.is_none()) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

/// Per-endpoint observed totals for one module file: name -> (calls,
/// errors). Only rows whose `module.sha256` AND `module.ino` match count:
/// a concurrent lane's bytes-identical provider (same sha256, different
/// file) can share the capture, and its session must never join the owned
/// totals. Forwarding-layer rows are not headline calls and stay out, like
/// the flood compare. Inode numbers agree across device domains; only the
/// device rendering differs.
fn profile_fn_totals_scoped(
    doc: &serde_json::Value,
    sha256: &str,
    ino: u64,
) -> BTreeMap<String, (u64, u64)> {
    let mut totals = BTreeMap::new();
    let rows = doc
        .get("functions")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for row in rows {
        if row
            .get("forwarding_layer")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            continue;
        }
        let module = row
            .get("module")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let sha_ok = module
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            == sha256;
        let ino_ok = module
            .get("ino")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            == ino;
        if !(sha_ok && ino_ok) {
            continue;
        }
        let calls = row
            .get("calls")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let errors = row
            .get("errors")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let names: Vec<String> = match row.get("names") {
            Some(serde_json::Value::Array(names)) => names
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect(),
            Some(serde_json::Value::String(name)) => vec![name.clone()],
            _ => vec![],
        };
        for name in names {
            let entry = totals.entry(name).or_insert((0, 0));
            entry.0 += calls;
            entry.1 += errors;
        }
    }
    totals
}

fn evidence_u64(doc: &serde_json::Value, key: &str) -> Option<u64> {
    doc.get("evidence")?.get(key)?.as_u64()
}

/// One compact pressure line (printed on pass and fail): admission and
/// view health that contextualize the verdict.
fn profile_pressure_line(doc: &serde_json::Value) -> String {
    let ev = doc
        .get("evidence")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let sched = ev
        .get("scheduling")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let newcomer = sched
        .get("newcomer_queue")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    format!(
        "slots={} active={} admitted={} pending={} mean_age_ms={} deferrals={}",
        ev.get("slots").unwrap_or(&serde_json::Value::Null),
        ev.get("active_slots").unwrap_or(&serde_json::Value::Null),
        newcomer.get("admitted").unwrap_or(&serde_json::Value::Null),
        newcomer.get("pending").unwrap_or(&serde_json::Value::Null),
        newcomer
            .get("mean_admitted_age_ms")
            .unwrap_or(&serde_json::Value::Null),
        sched
            .get("discovery_deferrals")
            .unwrap_or(&serde_json::Value::Null),
    )
}

/// Every schema loss counter that could name a miss, for the failure
/// message. A miss with all of these at zero is unnamed loss.
fn profile_loss_inventory(doc: &serde_json::Value) -> String {
    let ev = doc
        .get("evidence")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let mut parts = Vec::new();
    for key in [
        "event_loss",
        "learned_event_loss",
        "learned_cap_skipped",
        "in_flight_at_end",
        "pending_at_end",
        "unmatched_returns",
        "unmatched_closes",
        "async_orphans",
        "async_duplicates",
        "async_evictions",
        "orphan_ops",
        "start_insert_failures",
        "rv_update_failures",
        "state_reconciliations",
        "semantic_capture_failures",
        "discovery_ring_loss",
        "discovery_truncated",
    ] {
        parts.push(format!(
            "{key}={}",
            ev.get(key).unwrap_or(&serde_json::Value::Null)
        ));
    }
    let sched = ev
        .get("scheduling")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    for key in [
        "capture_event_loss",
        "capture_discovery_loss",
        "detach_event_loss",
        "detach_discovery_loss",
        "drain_budget_exhaustions",
        "discovery_deferrals",
        "newcomer_queue",
    ] {
        parts.push(format!(
            "scheduling.{key}={}",
            sched.get(key).unwrap_or(&serde_json::Value::Null)
        ));
    }
    let rings = ev
        .get("ring_accounting")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    parts.push(format!("ring_accounting={rings}"));
    let unadmitted: u64 = doc
        .get("cgroups")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    row.get("unadmitted")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                })
                .sum()
        })
        .unwrap_or(0);
    parts.push(format!(
        "cgroups_unadmitted_sum={unadmitted} (a subset of counted calls, never a miss)"
    ));
    let skipped: Vec<String> = ev
        .get("skipped")
        .and_then(serde_json::Value::as_array)
        .map(|rows| {
            rows.iter()
                .map(|gap| {
                    format!(
                        "{} | {}",
                        gap.get("name")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?"),
                        gap.get("reason")
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("?")
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    parts.push(format!("skipped={skipped:?}"));
    parts.push(format!(
        "completeness={}",
        ev.get("completeness").unwrap_or(&serde_json::Value::Null)
    ));
    parts.push(format!(
        "gap_classes={}",
        ev.get("gap_classes").unwrap_or(&serde_json::Value::Null)
    ));
    parts.join("; ")
}

/// The profile verdict shared by cells (a), (b) and (d): every `driver`
/// endpoint observed exactly with zero errors, and no unnamed loss.
/// Totals scope to the owned file (`sha256` + `ino`); `slots` and
/// `active_slots` are capture-global (concurrent lanes' providers join
/// discovery), so the owned-exact counts are the verdict and a fully
/// stopped view (0 active) is only a guard: exact totals already prove
/// the view counted through the last child.
fn assert_profile_exact(
    tag: &str,
    doc: &serde_json::Value,
    driver: &BTreeMap<String, u64>,
    sha256: &str,
    ino: u64,
) -> Result<()> {
    let observed = profile_fn_totals_scoped(doc, sha256, ino);
    let mut mismatches = Vec::new();
    for (name, want) in driver {
        let (got, errors) = observed.get(name).copied().unwrap_or((0, 0));
        let flag = if got == *want && errors == 0 {
            "OK"
        } else {
            "MISMATCH"
        };
        println!("{tag} {name}: driver={want} observed={got} errors={errors} {flag}");
        if flag != "OK" {
            mismatches.push(format!(
                "{name}: driver={want} observed={got} errors={errors}"
            ));
        }
    }
    // Zero-count rows are schema noise (the observer lists every table
    // endpoint); a nonzero unexpected endpoint on the owned file is a
    // fixture or product anomaly and fails the verdict. Other files'
    // rows never reach this map (inode scope above).
    let extra: BTreeMap<_, _> = observed
        .iter()
        .filter(|(name, (calls, errors))| {
            !driver.contains_key(name.as_str()) && (*calls > 0 || *errors > 0)
        })
        .map(|(name, (calls, errors))| (name.clone(), (*calls, *errors)))
        .collect();
    println!("{tag} nonzero unexpected endpoints: {extra:?}");
    if !extra.is_empty() {
        mismatches.push(format!("unexpected owned endpoints: {extra:?}"));
    }
    let slots = evidence_u64(doc, "slots").unwrap_or(0);
    let active = evidence_u64(doc, "active_slots").unwrap_or(0);
    println!("{tag} slots={slots} active_slots={active}");
    println!("{tag} pressure: {}", profile_pressure_line(doc));
    ensure!(
        active > 0,
        "{tag}: the whole view stopped (0 active slots): {}",
        profile_loss_inventory(doc)
    );
    if mismatches.is_empty() {
        println!("{tag} RESULT verdict=PASS");
        return Ok(());
    }
    // A miss is unnamed loss unless a calls-denominated counter from
    // NAMED_CALL_LOSS_COUNTERS accounts for every missing call.
    let named: u64 = 0;
    let _ = NAMED_CALL_LOSS_COUNTERS.len();
    anyhow::bail!(
        "{tag}: UNNAMED LOSS: {} (named call-loss counters account for {named}); {}",
        mismatches.join(", "),
        profile_loss_inventory(doc)
    )
}

// ---------------------------------------------------------------------------
// Cell (a): sequential 1 GiB kill loop + exact poll control.
// ---------------------------------------------------------------------------

/// Cell (a) shape: 2-way bursts of short-lived 1 GiB children with K
/// counted call rounds each (K = 10 + elapsed minute, SIGKILLed after
/// COUNTS) under `profile --system --module <private copy>`, plus a
/// long-lived holder running an exact number of C_GetSlotList polls, an
/// anchor mapping the copy from capture start (attach settles before
/// counted kills), and loader churn. The verdict scopes to the private
/// copy's inode: a concurrent lane's bytes-identical provider can share
/// the capture. Tuned on fedora against 2234b514f (RED) and v0.7.0
/// (GREEN); see the lane report for the numbers.
const A_DURATION_S: u64 = 270;
const A_QUIET_S: u64 = 15;
const A_NWAY: usize = 2;
const A_K0: u64 = 10;
const A_MIB: u64 = 1024;
const A_HOLDER_POLLS: u32 = 22;
const A_HOLDER_POLL_MS: u64 = 10_000;
const A_CHURN_US: u64 = 100;

/// Cell (a): `profile --system` over N short-lived 1 GiB children in
/// 2-way bursts with K counted call rounds each, plus a long-lived holder
/// running an exact number of C_GetSlotList polls and loader churn. The
/// v0.7.1 regression undercounts the kills and drops polls of the admitted
/// holder with zero loss counters. Prints R071A lines. Root BPF lane,
/// serial.
#[test]
#[ignore = "privileged: profile --system counts every 1 GiB kill-loop C_Initialize and every holder poll exactly"]
fn privileged_profile_system_bigchild_kills_exact_lp64() -> Result<()> {
    let observer = observer_binary()?;
    let workload = R071Workload::build(
        &[
            "r071_flood_child",
            "r071_holder",
            "r071_anchor",
            "r071_churn",
        ],
        "r071a",
    )?;
    let outcome = cell_a_inner(&workload, &observer);
    keep_on_failure(workload, outcome, "R071A")
}

fn cell_a_inner(workload: &R071Workload, observer: &Path) -> Result<()> {
    const TAG: &str = "R071A";
    // The holder starts pre-capture: its C_Initialize/C_GetSlotList
    // setup calls are outside the window; only its gated polls count.
    let holder_out = workload.path("holder.out");
    let holder_gate = workload.path("holder.gate");
    let mut holder = LoggedChild::spawn(
        "holder",
        workload.bin("r071_holder")?,
        &[
            workload.provider_copy.to_str().context("provider path")?,
            holder_gate.to_str().context("gate path")?,
            &A_HOLDER_POLLS.to_string(),
            &A_HOLDER_POLL_MS.to_string(),
        ],
        &[],
        &holder_out,
        &workload.conf,
    )?;
    holder.wait_for_prefix("READY ", Duration::from_secs(60))?;
    println!("{TAG} holder ready pid={}", holder.pid());
    let provider = workload.provider_copy.to_str().context("provider path")?;
    // --module scope (like cell (b)): the default lane stays exact on
    // fedora at this pressure; the narrowed scope reproduces the stall.
    let modules = [workload.provider_copy.as_path()];
    let anchor_out = workload.path("anchor.out");
    let mut anchor = LoggedChild::spawn(
        "anchor",
        workload.bin("r071_anchor")?,
        &[provider],
        &[],
        &anchor_out,
        &workload.conf,
    )?;
    anchor.wait_for_prefix("ANCHOR ", Duration::from_secs(30))?;
    println!("{TAG} anchor pid={}", anchor.pid());
    let obs_start = Instant::now();
    let mut obs = Observer::spawn(
        workload,
        observer,
        "profile",
        &modules,
        A_DURATION_S,
        "r071a-profile.json",
        TAG,
    )?;
    obs.wait_for("capturing:", Duration::from_secs(120), TAG)?;
    println!("{TAG} observer capturing, quiet {A_QUIET_S}s");
    std::thread::sleep(Duration::from_secs(A_QUIET_S));
    let churn_out = workload.path("churn.out");
    let mut churn = LoggedChild::spawn(
        "churn",
        workload.bin("r071_churn")?,
        &[provider, &A_CHURN_US.to_string()],
        &[],
        &churn_out,
        &workload.conf,
    )?;
    churn.wait_for_prefix("CHURN ", Duration::from_secs(30))?;
    println!("{TAG} churn pid={}", churn.pid());
    std::fs::write(&holder_gate, b"open\n")?;
    println!("{TAG} holder gate opened");
    let loop_start = Instant::now();
    // No new bursts in the last 8 s (observer-relative, like cell (b)).
    let loop_end = obs_start + Duration::from_secs(A_DURATION_S.saturating_sub(8));
    let mut iters = 0u64;
    let mut reap_sum_ms = 0u64;
    let driver_log = workload.path("r071a-driver.log");
    let mut driver = std::fs::File::create(&driver_log)?;
    use std::io::Write as _;
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for name in [
        "C_Initialize",
        "C_GetFunctionList",
        "C_GetSlotList",
        "C_GetInfo",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
    ] {
        totals.insert(name.to_string(), 0);
    }
    while Instant::now() < loop_end {
        if obs.child.try_wait()?.is_some() {
            anyhow::bail!(
                "{TAG}: the observer exited mid-loop: {}",
                obs.evidence("exited")
            );
        }
        // One burst: spawn all, gather every READY + COUNTS, then
        // SIGKILL all back-to-back so teardown windows overlap. K grows
        // per minute (cell (b)'s prefix-attribution signature).
        let mins = loop_start.elapsed().as_secs() / 60;
        let k = A_K0 + mins.min(20);
        let mut burst = Vec::with_capacity(A_NWAY);
        for _slot in 0..A_NWAY {
            iters += 1;
            let out = workload.path(&format!("kill-{iters}.out"));
            let child = LoggedChild::spawn(
                &format!("kill-{iters}"),
                workload.bin("r071_flood_child")?,
                &[
                    workload.provider_copy.to_str().context("provider path")?,
                    &k.to_string(),
                    &A_MIB.to_string(),
                ],
                &[],
                &out,
                &workload.conf,
            )?;
            burst.push((iters, child));
        }
        let mut batch_counts = Vec::with_capacity(A_NWAY);
        for (n, child) in burst.iter_mut() {
            child.wait_for_prefix("READY ", Duration::from_secs(180))?;
            child.wait_for_prefix("COUNTS ", Duration::from_secs(120))?;
            let counts = parse_counts_line(&child.line_with_prefix("COUNTS ").unwrap_or_default());
            ensure!(
                counts.get("failed").copied().unwrap_or(1) == 0
                    && counts.get("init").copied().unwrap_or(0) == 1
                    && counts.get("slotlist").copied().unwrap_or(0) == 1 + k
                    && counts.get("getinfo").copied().unwrap_or(0) == k
                    && counts.get("getslotinfo").copied().unwrap_or(0) == k
                    && counts.get("gettokeninfo").copied().unwrap_or(0) == k,
                "{TAG}: FIXTURE: kill-{n} unhealthy for K={k}: {counts:?}: {}",
                child.diagnostics()
            );
            batch_counts.push(counts);
        }
        for ((n, child), counts) in burst.iter_mut().zip(batch_counts.iter()) {
            let pid = child.pid();
            let t0 = Instant::now();
            let status = child.kill_and_wait()?;
            let reap_ms = t0.elapsed().as_millis() as u64;
            reap_sum_ms += reap_ms;
            ensure!(
                !status.success(),
                "{TAG}: FIXTURE: kill-{n} exited {status} instead of dying by signal: {}",
                child.diagnostics()
            );
            *totals.get_mut("C_Initialize").unwrap() += 1;
            *totals.get_mut("C_GetFunctionList").unwrap() += 1;
            *totals.get_mut("C_GetSlotList").unwrap() += counts["slotlist"];
            *totals.get_mut("C_GetInfo").unwrap() += counts["getinfo"];
            *totals.get_mut("C_GetSlotInfo").unwrap() += counts["getslotinfo"];
            *totals.get_mut("C_GetTokenInfo").unwrap() += counts["gettokeninfo"];
            writeln!(
                driver,
                "CHILD n={n} pid={pid} reap_ms={reap_ms} slotlist={} getinfo={}",
                counts["slotlist"], counts["getinfo"]
            )?;
        }
    }
    drop(driver);
    println!("{TAG} loop done iters={iters} reap_sum_ms={reap_sum_ms}");
    ensure!(
        iters > 0,
        "{TAG}: FIXTURE: the kill loop ran zero iterations"
    );
    obs.wait_exit(Duration::from_secs(A_DURATION_S + 120), TAG)?;
    churn.kill_and_wait()?;
    anchor.kill_and_wait()?;
    holder.kill_and_wait()?;
    let holder_text = std::fs::read_to_string(&holder_out)?;
    let polls = holder_text
        .lines()
        .filter(|line| line.starts_with("POLL "))
        .count() as u64;
    ensure!(
        holder_text.lines().any(|line| line.starts_with("DONE ")),
        "{TAG}: FIXTURE: the holder never finished its polls: {}",
        holder.diagnostics()
    );
    ensure!(
        polls == u64::from(A_HOLDER_POLLS),
        "{TAG}: FIXTURE: holder ran {polls} polls, want {}",
        A_HOLDER_POLLS
    );
    // The holder's pre-capture setup (one init, one slotlist) is outside
    // the window; its gated polls join the flood's slotlists.
    *totals.get_mut("C_GetSlotList").unwrap() += polls;
    println!("{TAG} driver: kills={iters} holder_polls={polls}");
    let doc = obs.report()?;
    assert_profile_exact(
        TAG,
        &doc,
        &totals,
        &workload.provider_sha256,
        workload.provider_ino,
    )
}

// ---------------------------------------------------------------------------
// Cell (b): 2-way newcomer flood with loader churn.
// ---------------------------------------------------------------------------

/// Cell (b) shape: sync bursts of short-lived 1 GiB children with K
/// call rounds (K = 10 + elapsed minute, the prefix-attribution
/// signature) under loader churn. Tuned on fedora against 2234b514f
/// (RED) and v0.7.0 (GREEN); see the lane report for the numbers.
const B_DURATION_S: u64 = 270;
const B_K0: u64 = 10;
const B_HOLD_MS: u64 = 50;
const B_NWAY: usize = 2;
const B_MIB: u64 = 1024;
const B_CHURN_US: u64 = 100;

/// Cell (b): `profile --system --module <private copy>` under a fast
/// newcomer flood: 2-way sync bursts of short-lived 1 GiB children with
/// K counted call rounds each, SIGKILLed back-to-back, plus loader
/// churn. The v0.7.1 regression stops counting mid-run (slots retire,
/// `active_slots` 0) with the miss in no counter. Prints R071B lines.
/// Root BPF lane, serial.
#[test]
#[ignore = "privileged: profile --system counts a newcomer flood of short-lived callers exactly"]
fn privileged_profile_system_newcomer_flood_exact_lp64() -> Result<()> {
    let observer = observer_binary()?;
    let workload =
        R071Workload::build(&["r071_flood_child", "r071_anchor", "r071_churn"], "r071b")?;
    let outcome = cell_b_inner(&workload, &observer);
    keep_on_failure(workload, outcome, "R071B")
}

fn cell_b_inner(workload: &R071Workload, observer: &Path) -> Result<()> {
    const TAG: &str = "R071B";
    let provider = workload.provider_copy.to_str().context("provider path")?;
    // Apparatus: one child must print READY + COUNTS with zero failures.
    {
        let out = workload.path("apparatus.out");
        let mut probe = LoggedChild::spawn(
            "apparatus",
            workload.bin("r071_flood_child")?,
            &[provider, "2", &B_MIB.to_string()],
            &[],
            &out,
            &workload.conf,
        )?;
        probe.wait_for_prefix("READY ", Duration::from_secs(120))?;
        probe.wait_for_prefix("COUNTS ", Duration::from_secs(120))?;
        let counts = parse_counts_line(&probe.line_with_prefix("COUNTS ").unwrap_or_default());
        probe.kill_and_wait()?;
        ensure!(
            counts.get("failed").copied().unwrap_or(1) == 0
                && counts.get("init").copied().unwrap_or(0) == 1,
            "{TAG}: FIXTURE: apparatus child unhealthy: {counts:?}"
        );
        println!("{TAG} apparatus ok");
    }
    let anchor_out = workload.path("anchor.out");
    let mut anchor = LoggedChild::spawn(
        "anchor",
        workload.bin("r071_anchor")?,
        &[provider],
        &[],
        &anchor_out,
        &workload.conf,
    )?;
    anchor.wait_for_prefix("ANCHOR ", Duration::from_secs(30))?;
    println!("{TAG} anchor pid={}", anchor.pid());
    let obs_start = Instant::now();
    let mut obs = Observer::spawn(
        workload,
        observer,
        "profile",
        &[workload.provider_copy.as_path()],
        B_DURATION_S,
        "r071b-profile.json",
        TAG,
    )?;
    obs.wait_for("capturing:", Duration::from_secs(120), TAG)?;
    println!("{TAG} observer capturing, settle 5s");
    std::thread::sleep(Duration::from_secs(5));
    let churn_out = workload.path("churn.out");
    let mut churn = LoggedChild::spawn(
        "churn",
        workload.bin("r071_churn")?,
        &[provider, &B_CHURN_US.to_string()],
        &[],
        &churn_out,
        &workload.conf,
    )?;
    churn.wait_for_prefix("CHURN ", Duration::from_secs(30))?;
    println!("{TAG} churn pid={}", churn.pid());
    let loop_start = Instant::now();
    // No new bursts in the last 8 s (observer-relative, like orun.sh);
    // past the end the driver idles until the observer stops.
    let loop_end = obs_start + Duration::from_secs(B_DURATION_S.saturating_sub(8));
    let driver_log = workload.path("r071b-driver.log");
    let mut driver_file = std::fs::File::create(&driver_log)?;
    use std::io::Write as _;
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for name in [
        "C_Initialize",
        "C_GetFunctionList",
        "C_GetSlotList",
        "C_GetInfo",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
    ] {
        totals.insert(name.to_string(), 0);
    }
    let mut per_child_k: Vec<u64> = Vec::new();
    let mut n = 0u64;
    let mut burst = 0u64;
    while Instant::now() < loop_end {
        if obs.child.try_wait()?.is_some() {
            anyhow::bail!(
                "{TAG}: the observer exited mid-loop: {}",
                obs.evidence("exited")
            );
        }
        burst += 1;
        let mins = loop_start.elapsed().as_secs() / 60;
        let k = B_K0 + mins.min(20);
        let mut batch = Vec::with_capacity(B_NWAY);
        for slot in 0..B_NWAY {
            let out = workload.path(&format!("b{burst}s{slot}.out"));
            let child = LoggedChild::spawn(
                &format!("b{burst}s{slot}"),
                workload.bin("r071_flood_child")?,
                &[provider, &k.to_string(), &B_MIB.to_string()],
                &[],
                &out,
                &workload.conf,
            )?;
            batch.push(child);
        }
        let mut batch_counts = Vec::with_capacity(B_NWAY);
        for child in batch.iter_mut() {
            child.wait_for_prefix("READY ", Duration::from_secs(180))?;
            child.wait_for_prefix("COUNTS ", Duration::from_secs(120))?;
            let counts = parse_counts_line(&child.line_with_prefix("COUNTS ").unwrap_or_default());
            ensure!(
                counts.get("failed").copied().unwrap_or(1) == 0,
                "{TAG}: FIXTURE: {} failed calls: {}",
                child.tag,
                child.diagnostics()
            );
            ensure!(
                counts.get("init").copied().unwrap_or(0) == 1
                    && counts.get("slotlist").copied().unwrap_or(0) == 1 + k
                    && counts.get("getinfo").copied().unwrap_or(0) == k
                    && counts.get("getslotinfo").copied().unwrap_or(0) == k
                    && counts.get("gettokeninfo").copied().unwrap_or(0) == k,
                "{TAG}: FIXTURE: {} counts deviate from K={k}: {counts:?}: {}",
                child.tag,
                child.diagnostics()
            );
            batch_counts.push(counts);
        }
        if B_HOLD_MS > 0 {
            std::thread::sleep(Duration::from_millis(B_HOLD_MS));
        }
        for child in batch.iter_mut() {
            child.kill_and_wait()?;
        }
        for counts in &batch_counts {
            n += 1;
            per_child_k.push(k);
            *totals.get_mut("C_Initialize").unwrap() += 1;
            // Each child calls C_GetFunctionList once via dlsym; the
            // observer counts it (flood legs prove 1:1 with children).
            *totals.get_mut("C_GetFunctionList").unwrap() += 1;
            *totals.get_mut("C_GetSlotList").unwrap() += counts["slotlist"];
            *totals.get_mut("C_GetInfo").unwrap() += counts["getinfo"];
            *totals.get_mut("C_GetSlotInfo").unwrap() += counts["getslotinfo"];
            *totals.get_mut("C_GetTokenInfo").unwrap() += counts["gettokeninfo"];
            writeln!(
                driver_file,
                "CHILD n={n} burst={burst} k={k} t_wall_ms={} init=1 gfl=1 slotlist={} getinfo={} getslotinfo={} gettokeninfo={}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                counts["slotlist"],
                counts["getinfo"],
                counts["getslotinfo"],
                counts["gettokeninfo"]
            )?;
        }
    }
    drop(driver_file);
    println!("{TAG} bursts={burst} children={n}");
    ensure!(n > 0, "{TAG}: FIXTURE: the flood ran zero children");
    obs.wait_exit(Duration::from_secs(B_DURATION_S + 120), TAG)?;
    churn.kill_and_wait()?;
    anchor.kill_and_wait()?;
    let doc = obs.report()?;
    if let Err(error) = assert_profile_exact(
        TAG,
        &doc,
        &totals,
        &workload.provider_sha256,
        workload.provider_ino,
    ) {
        // Prefix attribution: with the K signature, the observed GetInfo
        // total equals the prefix sum of the first P children when the
        // view stopped after child P. Print P for the failure record.
        let observed =
            profile_fn_totals_scoped(&doc, &workload.provider_sha256, workload.provider_ino);
        let got = observed
            .get("C_GetInfo")
            .map(|(calls, _)| *calls)
            .unwrap_or(0);
        let mut prefix = 0u64;
        let mut at = 0usize;
        for (index, k) in per_child_k.iter().enumerate() {
            prefix += k;
            if prefix == got {
                at = index + 1;
                break;
            }
            if prefix > got {
                break;
            }
        }
        println!(
            "{TAG} prefix attribution: observed getinfo={got} matches the first {at} of {n} children"
        );
        return Err(error);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inventory helpers + cell (c).
// ---------------------------------------------------------------------------

/// The owned module row (matched by sha256 AND inode: a concurrent
/// lane's bytes-identical provider shares the sha but never the file)
/// plus its id label.
fn inventory_owned_module<'a>(
    doc: &'a serde_json::Value,
    sha256: &str,
    ino: u64,
) -> Result<(&'a serde_json::Value, String)> {
    let modules = doc
        .get("modules")
        .and_then(serde_json::Value::as_array)
        .context("modules array")?;
    for module in modules {
        let identity = module
            .get("identity")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let sha_ok = identity
            .get("sha256")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            == sha256;
        let ino_ok = identity
            .get("inode")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            == ino;
        if sha_ok && ino_ok {
            let id = module
                .get("id")
                .and_then(serde_json::Value::as_str)
                .context("module id")?
                .to_string();
            return Ok((module, id));
        }
    }
    anyhow::bail!("the owned provider module (sha {sha256} ino {ino}) is absent from the report")
}

/// Sum of `entries.count` over live edges of one module, plus the
/// coverage state/reason histogram that names every uncounted edge.
fn inventory_live_edge_sum(
    doc: &serde_json::Value,
    module_id: &str,
) -> (u64, BTreeMap<String, u64>) {
    let mut sum = 0u64;
    let mut states = BTreeMap::new();
    let edges = doc
        .get("edges")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    for edge in edges {
        if edge.get("module").and_then(serde_json::Value::as_str) != Some(module_id) {
            continue;
        }
        let entries = edge
            .get("entries")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        sum += entries
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let coverage = entries
            .get("coverage")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let state = coverage
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?");
        let reason = coverage
            .get("reason")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        *states.entry(format!("{state}/{reason}")).or_insert(0) += 1;
    }
    (sum, states)
}

/// True when a reaped inventory child ran exactly its K-round shape.
fn inv_counts_healthy(counts: &BTreeMap<String, u64>, k: u64) -> bool {
    counts.get("failed").copied().unwrap_or(1) == 0
        && counts.get("init").copied().unwrap_or(0) == 1
        && counts.get("slotlist").copied().unwrap_or(0) == 1 + k
        && counts.get("getinfo").copied().unwrap_or(0) == k
        && counts.get("getslotinfo").copied().unwrap_or(0) == k
        && counts.get("gettokeninfo").copied().unwrap_or(0) == k
        && counts.get("finalize").copied().unwrap_or(0) == 1
}

fn inventory_gaps_summary(doc: &serde_json::Value) -> String {
    let gaps = doc
        .get("gaps")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut subjects: BTreeMap<String, u64> = BTreeMap::new();
    for gap in &gaps {
        let subject = gap
            .get("subject")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_string();
        let repeats = gap
            .get("repeats")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(1);
        *subjects.entry(subject).or_insert(0) += repeats;
    }
    format!("gaps={} subjects={subjects:?}", gaps.len())
}

/// Cell (c) shape: a 1/s stream of short-lived callers (map, wait for
/// admission, K call rounds, exit) under `inventory --system`. Tuned on
/// fedora against 2234b514f (RED) and v0.7.0 (GREEN); see the lane
/// report for the numbers.
const C_DURATION_S: u64 = 210;
const C_RATE_PER_S: f64 = 1.0;
const C_WAIT_S: u64 = 20;
const C_LINGER_S: u64 = 2;
const C_K0: u64 = 10;
const C_POOL: usize = 64;
const C_END_MARGIN_S: u64 = 35;

/// Cell (c): `inventory --system` over a 1/s stream of short-lived
/// callers (each: map, 20 s admission wait, 3+4K entries, exit). The
/// v0.7.1 regression stops counting entries ~1 min in. The verdict sums
/// the owned module's departed entries (when the fold exists) plus its
/// live edge entries (where exited callers stay as rows, as on v0.7.0)
/// and requires the driver total exactly. Prints R071C lines. Root BPF
/// lane, serial.
#[test]
#[ignore = "privileged: inventory --system counts a 1/s short-lived stream exactly"]
fn privileged_inventory_system_shortlived_stream_exact_lp64() -> Result<()> {
    let observer = observer_binary()?;
    let workload = R071Workload::build(&["r071_inv_child"], "r071c")?;
    let outcome = cell_c_inner(&workload, &observer);
    keep_on_failure(workload, outcome, "R071C")
}

fn cell_c_inner(workload: &R071Workload, observer: &Path) -> Result<()> {
    const TAG: &str = "R071C";
    let provider = workload.provider_copy.to_str().context("provider path")?;
    // Distinct exe copies (distinct inodes) so every caller folds as
    // its own identity, like the hostfill-66 pool.
    let pool = workload.path("pool");
    std::fs::create_dir(&pool)?;
    for index in 0..C_POOL {
        std::fs::copy(
            workload.bin("r071_inv_child")?,
            pool.join(format!("short_{index:03}")),
        )?;
    }
    println!("{TAG} pool ready: {C_POOL} copies");
    // Apparatus: one full-life child must exit 0 with zero failures.
    {
        let out = workload.path("apparatus.out");
        let mut probe = LoggedChild::spawn(
            "apparatus",
            &pool.join("short_000"),
            &[
                provider,
                "2",
                &C_WAIT_S.to_string(),
                &C_LINGER_S.to_string(),
            ],
            &[],
            &out,
            &workload.conf,
        )?;
        probe.wait_for_prefix("COUNTS ", Duration::from_secs(C_WAIT_S + 120))?;
        let counts = parse_counts_line(&probe.line_with_prefix("COUNTS ").unwrap_or_default());
        // The apparatus child exits itself after its linger; wait for a
        // clean exit rather than killing it.
        let deadline = Instant::now() + Duration::from_secs(60);
        let status = loop {
            if let Some(status) = probe.child.try_wait()? {
                break status;
            }
            ensure!(
                Instant::now() < deadline,
                "{TAG}: FIXTURE: apparatus child never exited: {}",
                probe.diagnostics()
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        ensure!(
            status.success() && counts.get("failed").copied().unwrap_or(1) == 0,
            "{TAG}: FIXTURE: apparatus child unhealthy: {status} {counts:?}"
        );
        println!("{TAG} apparatus ok");
    }
    let obs_start = Instant::now();
    let mut obs = Observer::spawn(
        workload,
        observer,
        "inventory",
        &[],
        C_DURATION_S,
        "r071c-report.json",
        TAG,
    )?;
    obs.wait_for("p11scope: pass 0:", Duration::from_secs(180), TAG)?;
    println!("{TAG} observer pass 0 published, settle 10s");
    std::thread::sleep(Duration::from_secs(10));
    let stream_start = Instant::now();
    let stream_end = obs_start + Duration::from_secs(C_DURATION_S.saturating_sub(C_END_MARGIN_S));
    let driver_log = workload.path("r071c-driver.log");
    let mut driver_file = std::fs::File::create(&driver_log)?;
    use std::io::Write as _;
    struct Inflight {
        child: LoggedChild,
        k: u64,
        expected: u64,
        index: u64,
    }
    let mut inflight: Vec<Inflight> = Vec::new();
    let mut children = 0u64;
    let mut expected_total = 0u64;
    let mut next_spawn = Instant::now();
    let mut pool_index = 0usize;
    while Instant::now() < stream_end {
        if obs.child.try_wait()?.is_some() {
            anyhow::bail!(
                "{TAG}: the observer exited mid-stream: {}",
                obs.evidence("exited")
            );
        }
        // Reap completed children first, every pass.
        let mut still = Vec::with_capacity(inflight.len());
        for mut item in inflight.drain(..) {
            match item.child.child.try_wait()? {
                None => still.push(item),
                Some(status) => {
                    let counts = parse_counts_line(
                        &item.child.line_with_prefix("COUNTS ").unwrap_or_default(),
                    );
                    ensure!(
                        status.success() && inv_counts_healthy(&counts, item.k),
                        "{TAG}: FIXTURE: child {} unhealthy for K={}: {status} {counts:?}: {}",
                        item.index,
                        item.k,
                        item.child.diagnostics()
                    );
                    children += 1;
                    expected_total += item.expected;
                    writeln!(
                        driver_file,
                        "CHILD n={children} k={} expected={} init={} slotlist={} getinfo={} getslotinfo={} gettokeninfo={} finalize={}",
                        item.k,
                        item.expected,
                        counts["init"],
                        counts["slotlist"],
                        counts["getinfo"],
                        counts["getslotinfo"],
                        counts["gettokeninfo"],
                        counts["finalize"]
                    )?;
                }
            }
        }
        inflight = still;
        if Instant::now() >= next_spawn {
            next_spawn = Instant::now() + Duration::from_secs_f64(1.0 / C_RATE_PER_S);
            let mins = stream_start.elapsed().as_secs() / 60;
            let k = C_K0 + mins.min(120);
            let expected = 3 + 4 * k;
            let exe = pool.join(format!("short_{:03}", pool_index % C_POOL));
            pool_index += 1;
            let index = children + inflight.len() as u64 + 1;
            let out = workload.path(&format!("c{index}.out"));
            let child = LoggedChild::spawn(
                &format!("c{index}"),
                &exe,
                &[
                    provider,
                    &k.to_string(),
                    &C_WAIT_S.to_string(),
                    &C_LINGER_S.to_string(),
                ],
                &[],
                &out,
                &workload.conf,
            )?;
            inflight.push(Inflight {
                child,
                k,
                expected,
                index,
            });
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // The end margin (35 s) exceeds the child life (20 + 2 s): every
    // spawned child must exit before the observer stops.
    let drain_end = Instant::now() + Duration::from_secs(60);
    while !inflight.is_empty() && Instant::now() < drain_end {
        let mut still = Vec::with_capacity(inflight.len());
        for mut item in inflight.drain(..) {
            match item.child.child.try_wait()? {
                None => still.push(item),
                Some(status) => {
                    let counts = parse_counts_line(
                        &item.child.line_with_prefix("COUNTS ").unwrap_or_default(),
                    );
                    ensure!(
                        status.success() && inv_counts_healthy(&counts, item.k),
                        "{TAG}: FIXTURE: child {} unhealthy at drain: {status} {counts:?}",
                        item.index
                    );
                    children += 1;
                    expected_total += item.expected;
                    writeln!(
                        driver_file,
                        "CHILD n={children} k={} expected={}",
                        item.k, item.expected
                    )?;
                }
            }
        }
        inflight = still;
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(driver_file);
    ensure!(
        inflight.is_empty(),
        "{TAG}: FIXTURE: {} children still pending at observer stop",
        inflight.len()
    );
    println!("{TAG} stream done children={children} expected_entries={expected_total}");
    ensure!(children > 0, "{TAG}: FIXTURE: the stream ran zero children");
    obs.wait_exit(Duration::from_secs(C_DURATION_S + 120), TAG)?;
    let doc = obs.report()?;
    let (owned, module_id) =
        inventory_owned_module(&doc, &workload.provider_sha256, workload.provider_ino)?;
    let departed = owned
        .get("departed_use")
        .and_then(|use_| use_.get("entries"))
        .and_then(|entries| entries.get("count"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let departed_callers = owned
        .get("departed_use")
        .and_then(|use_| use_.get("callers"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let (live_sum, live_states) = inventory_live_edge_sum(&doc, &module_id);
    let counted = departed + live_sum;
    println!(
        "{TAG} owned {module_id}: departed_entries={departed} departed_callers={departed_callers} live_sum={live_sum} live_states={live_states:?}"
    );
    println!("{TAG} {}", inventory_gaps_summary(&doc));
    println!("{TAG} driver_expected={expected_total} counted={counted}");
    ensure!(
        counted == expected_total,
        "{TAG}: UNNAMED LOSS: driver {expected_total} entries, counted {counted} (departed {departed} + live {live_sum}); {}",
        inventory_gaps_summary(&doc)
    );
    println!("{TAG} RESULT verdict=PASS");
    Ok(())
}

// ---------------------------------------------------------------------------
// Cell (d): two bind-mounted views of one provider file.
// ---------------------------------------------------------------------------

/// A host-namespace bind mount of an owned directory, released on drop
/// and verified gone after the explicit release. The cell runs as root;
/// a failed mount/umount fails the cell naming the stage (never a
/// silent skip), and a leaked mount fails loudly with its path.
struct BindMount {
    target: PathBuf,
}

impl BindMount {
    fn bind(source: &Path, target: &Path, tag: &str) -> Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        ensure!(
            source.is_dir(),
            "{tag}: FIXTURE: bind source {} is not a dir",
            source.display()
        );
        ensure!(
            target.is_dir(),
            "{tag}: FIXTURE: bind target {} is not a dir",
            target.display()
        );
        let source_c = CString::new(source.as_os_str().as_bytes())?;
        let target_c = CString::new(target.as_os_str().as_bytes())?;
        // SAFETY: mount(2) with NUL-terminated owned paths; MS_BIND only.
        let rc = unsafe {
            libc::mount(
                source_c.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        ensure!(
            rc == 0,
            "{tag}: FIXTURE: bind mount {} -> {} failed: {}",
            source.display(),
            target.display(),
            std::io::Error::last_os_error()
        );
        Ok(Self {
            target: target.to_path_buf(),
        })
    }

    fn is_mounted(&self) -> bool {
        let target = self.target.display().to_string();
        std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|table| {
            table.lines().any(|line| {
                let fields: Vec<&str> = line.split_ascii_whitespace().collect();
                fields.get(4) == Some(&target.as_str())
            })
        })
    }

    fn unmount(&self, tag: &str) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;

        let target_c = CString::new(self.target.as_os_str().as_bytes())?;
        // SAFETY: umount2(2) on the owned bind target.
        let rc = unsafe { libc::umount2(target_c.as_ptr(), 0) };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            // Already gone (a Drop beat us to it) is fine.
            if error.raw_os_error() != Some(libc::EINVAL) {
                anyhow::bail!(
                    "{tag}: FIXTURE: umount {} failed: {error}",
                    self.target.display()
                );
            }
        }
        Ok(())
    }
}

impl Drop for BindMount {
    fn drop(&mut self) {
        let _ = self.unmount("R071D-drop");
    }
}

/// A private ext4 filesystem on a loop device (mounted with `mount -o
/// loop`, released on drop with a lazy fallback), following the
/// established `Ext4Loop` pattern. The provider copy lives here so the
/// cross-filesystem bind below reproduces the ext4 domain split. Root
/// only; every stage fails the cell naming itself (never a skip).
struct Ext4Loop {
    mount: PathBuf,
}

impl Ext4Loop {
    fn create(dir: &Path, tag: &str) -> Result<Self> {
        let image = dir.join("r071d-ext4.img");
        std::fs::File::create(&image)?.set_len(64 << 20)?;
        let mount = dir.join("r071d-ext4");
        std::fs::create_dir(&mount)?;
        let run = |program: &str, args: &[&std::ffi::OsStr]| -> Result<()> {
            let status = Command::new(program)
                .args(args)
                .status()
                .with_context(|| format!("{tag}: FIXTURE: {program} is required"))?;
            ensure!(
                status.success(),
                "{tag}: FIXTURE: {program} {args:?} failed with {status}"
            );
            Ok(())
        };
        run(
            "mkfs.ext4",
            &["-q".as_ref(), "-F".as_ref(), image.as_os_str()],
        )?;
        run(
            "mount",
            &[
                "-o".as_ref(),
                "loop".as_ref(),
                image.as_os_str(),
                mount.as_os_str(),
            ],
        )?;
        println!(
            "{tag} ext4 loop mounted: {} on {}",
            image.display(),
            mount.display()
        );
        Ok(Self { mount })
    }

    fn is_mounted(&self) -> bool {
        let target = self.mount.display().to_string();
        std::fs::read_to_string("/proc/self/mountinfo").is_ok_and(|table| {
            table.lines().any(|line| {
                let fields: Vec<&str> = line.split_ascii_whitespace().collect();
                fields.get(4) == Some(&target.as_str())
            })
        })
    }

    fn unmount(&self, tag: &str) -> Result<()> {
        let status = Command::new("umount")
            .arg(&self.mount)
            .status()
            .with_context(|| format!("{tag}: FIXTURE: umount is required"))?;
        if !status.success() {
            let _ = Command::new("umount").arg("-l").arg(&self.mount).status();
            anyhow::bail!(
                "{tag}: FIXTURE: umount {} failed with {status}",
                self.mount.display()
            );
        }
        Ok(())
    }
}

impl Drop for Ext4Loop {
    fn drop(&mut self) {
        let unmounted = Command::new("umount")
            .arg(&self.mount)
            .status()
            .is_ok_and(|status| status.success());
        if !unmounted {
            let _ = Command::new("umount").arg("-l").arg(&self.mount).status();
        }
    }
}

/// Cell (d) shape: flood children alternating two views of one provider
/// file that lives on a private ext4 loop mount and is bind-mounted into
/// the workload dir (the cross-filesystem bind reproduces the ext4 domain
/// split; same-filesystem binds merge and stay exact), under a
/// default-lane `profile --system` with the verdict scoped to the file's
/// inode, plus loader churn. Tuned on fedora against 2234b514f (RED) and
/// v0.7.0 (GREEN); see the lane report for the numbers.
const D_DURATION_S: u64 = 270;
const D_K0: u64 = 10;
const D_HOLD_MS: u64 = 50;
/// 3-way bursts (≈3 GiB concurrent, fine on CI runners and fedora; this
/// cell stays out of the 4 GiB vng guests): 2-way breaks too close to
/// the run's end for a reliable margin.
const D_NWAY: usize = 3;
const D_MIB: u64 = 1024;
const D_CHURN_US: u64 = 100;

/// Cell (d): `profile --system` (default lane) over flood children that
/// alternately map one provider file on a private ext4 loop mount through
/// two bind-mounted views, with loader churn. The v0.7.1 identity path
/// rejects the whole key group on the domain split and retires the view;
/// the good build counts every view exactly. Prints R071D lines. Root BPF
/// lane, serial. Needs loop mounts and mkfs.ext4 (like the ext4 cells).
#[test]
#[ignore = "privileged: profile --system counts two bind-mounted views of one provider exactly"]
fn privileged_profile_system_bind_mount_two_view_exact_lp64() -> Result<()> {
    let observer = observer_binary()?;
    let workload =
        R071Workload::build(&["r071_flood_child", "r071_anchor", "r071_churn"], "r071d")?;
    let outcome = cell_d_inner(&workload, &observer);
    keep_on_failure(workload, outcome, "R071D")
}

fn cell_d_inner(workload: &R071Workload, observer: &Path) -> Result<()> {
    const TAG: &str = "R071D";
    use std::os::unix::fs::MetadataExt as _;

    // One file, two views across filesystems: the provider copy lives
    // on a private ext4 loop mount (orig/) and is bind-mounted into the
    // workload dir (bind/). Both paths name the same kernel file (proven
    // by fstat); the cross-filesystem bind reproduces the ext4 domain
    // split. Declared ext4-before-bind so Drops release bind-first.
    let ext4 = Ext4Loop::create(workload.dir.path(), TAG)?;
    ensure!(
        ext4.is_mounted(),
        "{TAG}: FIXTURE: the ext4 loop mount did not appear"
    );
    let orig = ext4.mount.join("orig");
    std::fs::create_dir(&orig)?;
    let bind = workload.path("d-bind");
    std::fs::create_dir(&bind)?;
    let orig_provider = orig.join("libsofthsm2-copy.so");
    std::fs::copy(&workload.provider_copy, &orig_provider)?;
    ensure!(
        sha256_file(&orig_provider)? == workload.provider_sha256,
        "{TAG}: FIXTURE: orig copy hash mismatch"
    );
    // Both views share this inode (proven by fstat below); the verdict
    // scopes to it, never to the workload copy's inode.
    let orig_ino = {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(&orig_provider)?.ino()
    };
    let mount = BindMount::bind(&orig, &bind, TAG)?;
    ensure!(
        mount.is_mounted(),
        "{TAG}: FIXTURE: the bind mount did not appear"
    );
    let bind_provider = bind.join("libsofthsm2-copy.so");
    let orig_meta = std::fs::metadata(&orig_provider)?;
    let bind_meta = std::fs::metadata(&bind_provider)?;
    ensure!(
        orig_meta.dev() == bind_meta.dev() && orig_meta.ino() == bind_meta.ino(),
        "{TAG}: FIXTURE: the two views are not one file: {orig_meta:?} vs {bind_meta:?}"
    );
    println!(
        "{TAG} two views of one file: {} <-> {}",
        orig_provider.display(),
        bind_provider.display()
    );
    let views = [orig_provider, bind_provider];
    let view_strs: Vec<String> = views
        .iter()
        .map(|path| path.display().to_string())
        .collect();

    let anchor_out = workload.path("anchor.out");
    let mut anchor = LoggedChild::spawn(
        "anchor",
        workload.bin("r071_anchor")?,
        &[view_strs[0].as_str()],
        &[],
        &anchor_out,
        &workload.conf,
    )?;
    anchor.wait_for_prefix("ANCHOR ", Duration::from_secs(30))?;
    let obs_start = Instant::now();
    let mut obs = Observer::spawn(
        workload,
        observer,
        "profile",
        &[],
        D_DURATION_S,
        "r071d-profile.json",
        TAG,
    )?;
    obs.wait_for("capturing:", Duration::from_secs(120), TAG)?;
    println!("{TAG} observer capturing, settle 5s");
    std::thread::sleep(Duration::from_secs(5));
    let churn_out = workload.path("churn.out");
    let mut churn = LoggedChild::spawn(
        "churn",
        workload.bin("r071_churn")?,
        &[view_strs[0].as_str(), &D_CHURN_US.to_string()],
        &[],
        &churn_out,
        &workload.conf,
    )?;
    churn.wait_for_prefix("CHURN ", Duration::from_secs(30))?;
    println!("{TAG} churn pid={}", churn.pid());
    let loop_start = Instant::now();
    let loop_end = obs_start + Duration::from_secs(D_DURATION_S.saturating_sub(8));
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    for name in [
        "C_Initialize",
        "C_GetFunctionList",
        "C_GetSlotList",
        "C_GetInfo",
        "C_GetSlotInfo",
        "C_GetTokenInfo",
    ] {
        totals.insert(name.to_string(), 0);
    }
    let mut n = 0u64;
    let mut burst = 0u64;
    while Instant::now() < loop_end {
        if obs.child.try_wait()?.is_some() {
            anyhow::bail!(
                "{TAG}: the observer exited mid-loop: {}",
                obs.evidence("exited")
            );
        }
        burst += 1;
        let mins = loop_start.elapsed().as_secs() / 60;
        let k = D_K0 + mins.min(20);
        let mut batch = Vec::with_capacity(D_NWAY);
        for slot in 0..D_NWAY {
            // Alternate views per slot, rotating each burst so both views
            // see every timing position.
            let view = &view_strs[(slot + burst as usize) % view_strs.len()];
            let out = workload.path(&format!("d{burst}s{slot}.out"));
            let child = LoggedChild::spawn(
                &format!("d{burst}s{slot}"),
                workload.bin("r071_flood_child")?,
                &[view.as_str(), &k.to_string(), &D_MIB.to_string()],
                &[],
                &out,
                &workload.conf,
            )?;
            batch.push(child);
        }
        let mut batch_counts = Vec::with_capacity(D_NWAY);
        for child in batch.iter_mut() {
            child.wait_for_prefix("READY ", Duration::from_secs(180))?;
            child.wait_for_prefix("COUNTS ", Duration::from_secs(120))?;
            let counts = parse_counts_line(&child.line_with_prefix("COUNTS ").unwrap_or_default());
            ensure!(
                counts.get("failed").copied().unwrap_or(1) == 0
                    && counts.get("init").copied().unwrap_or(0) == 1
                    && counts.get("slotlist").copied().unwrap_or(0) == 1 + k
                    && counts.get("getinfo").copied().unwrap_or(0) == k
                    && counts.get("getslotinfo").copied().unwrap_or(0) == k
                    && counts.get("gettokeninfo").copied().unwrap_or(0) == k,
                "{TAG}: FIXTURE: {} unhealthy for K={k}: {counts:?}: {}",
                child.tag,
                child.diagnostics()
            );
            batch_counts.push(counts);
        }
        if D_HOLD_MS > 0 {
            std::thread::sleep(Duration::from_millis(D_HOLD_MS));
        }
        for child in batch.iter_mut() {
            child.kill_and_wait()?;
        }
        for counts in &batch_counts {
            n += 1;
            *totals.get_mut("C_Initialize").unwrap() += 1;
            *totals.get_mut("C_GetFunctionList").unwrap() += 1;
            *totals.get_mut("C_GetSlotList").unwrap() += counts["slotlist"];
            *totals.get_mut("C_GetInfo").unwrap() += counts["getinfo"];
            *totals.get_mut("C_GetSlotInfo").unwrap() += counts["getslotinfo"];
            *totals.get_mut("C_GetTokenInfo").unwrap() += counts["gettokeninfo"];
        }
    }
    println!("{TAG} bursts={burst} children={n}");
    ensure!(n > 0, "{TAG}: FIXTURE: the flood ran zero children");
    obs.wait_exit(Duration::from_secs(D_DURATION_S + 120), TAG)?;
    churn.kill_and_wait()?;
    anchor.kill_and_wait()?;
    mount.unmount(TAG)?;
    ensure!(
        !mount.is_mounted(),
        "{TAG}: FIXTURE: the bind mount at {} leaked; umount it by hand",
        mount.target.display()
    );
    ext4.unmount(TAG)?;
    ensure!(
        !ext4.is_mounted(),
        "{TAG}: FIXTURE: the ext4 loop mount at {} leaked; umount it by hand",
        ext4.mount.display()
    );
    println!("{TAG} bind and ext4 loop mounts released");
    let doc = obs.report()?;
    assert_profile_exact(TAG, &doc, &totals, &workload.provider_sha256, orig_ino)
}

// ---------------------------------------------------------------------------
// Unprivileged unit tests for the cell parsers and budgets.
// ---------------------------------------------------------------------------

#[test]
fn counts_line_parses_counters_and_ignores_junk() {
    let counts = parse_counts_line("COUNTS init=1 slotlist=11 getinfo=10 failed=0");
    assert_eq!(counts.get("init"), Some(&1));
    assert_eq!(counts.get("slotlist"), Some(&11));
    assert_eq!(counts.get("getinfo"), Some(&10));
    assert_eq!(counts.get("failed"), Some(&0));
    assert!(!counts.contains_key("COUNTS"));
    let empty = parse_counts_line("READY hello");
    assert!(empty.is_empty());
}

#[test]
fn profile_totals_scope_to_one_file_and_skip_forwarding() {
    let doc = serde_json::json!({
        "functions": [
            {"names": ["C_Initialize"], "calls": 5, "errors": 0,
             "forwarding_layer": false, "module": {"sha256": "owned", "ino": 11}},
            {"names": ["C_GetSlotList"], "calls": 50, "errors": 0,
             "forwarding_layer": false, "module": {"sha256": "owned", "ino": 11}},
            {"names": ["C_Initialize"], "calls": 100, "errors": 1,
             "forwarding_layer": false, "module": {"sha256": "ambient", "ino": 22}},
            {"names": ["C_Initialize"], "calls": 1000, "errors": 0,
             "forwarding_layer": false, "module": {"sha256": "owned", "ino": 33}},
            {"names": ["C_Initialize"], "calls": 7, "errors": 0,
             "forwarding_layer": true, "module": {"sha256": "owned", "ino": 11}},
        ]
    });
    // Same-sha sister files stay out: only the owned inode counts.
    let scoped = profile_fn_totals_scoped(&doc, "owned", 11);
    assert_eq!(scoped.get("C_Initialize"), Some(&(5, 0)));
    assert_eq!(scoped.get("C_GetSlotList"), Some(&(50, 0)));
}

fn verdict_doc(rows: serde_json::Value, slots: u64, active: u64) -> serde_json::Value {
    serde_json::json!({
        "functions": rows,
        "evidence": {"slots": slots, "active_slots": active, "completeness": "PARTIAL",
                      "skipped": [], "scheduling": {}},
    })
}

#[test]
fn verdict_passes_exact_with_zero_count_noise() {
    let doc = verdict_doc(
        serde_json::json!([
            {"names": ["C_Initialize"], "calls": 5, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 11}},
            {"names": ["C_GetSlotList"], "calls": 0, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 11}},
            {"names": ["C_Initialize"], "calls": 99, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 33}},
        ]),
        139,
        68,
    );
    let mut driver = BTreeMap::new();
    driver.insert("C_Initialize".to_string(), 5);
    assert_profile_exact("R071T", &doc, &driver, "owned", 11).unwrap();
}

#[test]
fn verdict_fails_on_mismatch_and_on_nonzero_extras() {
    let mut driver = BTreeMap::new();
    driver.insert("C_Initialize".to_string(), 5);
    let miss = verdict_doc(
        serde_json::json!([
            {"names": ["C_Initialize"], "calls": 4, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 11}},
        ]),
        68,
        68,
    );
    let error = assert_profile_exact("R071T", &miss, &driver, "owned", 11).unwrap_err();
    assert!(error.to_string().contains("UNNAMED LOSS"), "{error}");
    let extra = verdict_doc(
        serde_json::json!([
            {"names": ["C_Initialize"], "calls": 5, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 11}},
            {"names": ["C_GetInfo"], "calls": 3, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 11}},
        ]),
        68,
        68,
    );
    let error = assert_profile_exact("R071T", &extra, &driver, "owned", 11).unwrap_err();
    assert!(
        error.to_string().contains("unexpected owned endpoints"),
        "{error}"
    );
    // Sister-file rows (same bytes, other inode) never join the verdict.
    let scoped = verdict_doc(
        serde_json::json!([
            {"names": ["C_Initialize"], "calls": 5, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 11}},
            {"names": ["C_GetInfo"], "calls": 3, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 33}},
        ]),
        139,
        68,
    );
    assert_profile_exact("R071T", &scoped, &driver, "owned", 11).unwrap();
}

#[test]
fn verdict_fails_when_the_whole_view_stopped() {
    let mut driver = BTreeMap::new();
    driver.insert("C_Initialize".to_string(), 5);
    let doc = verdict_doc(
        serde_json::json!([
            {"names": ["C_Initialize"], "calls": 5, "errors": 0, "forwarding_layer": false,
             "module": {"sha256": "owned", "ino": 11}},
        ]),
        68,
        0,
    );
    let error = assert_profile_exact("R071T", &doc, &driver, "owned", 11).unwrap_err();
    assert!(error.to_string().contains("0 active slots"), "{error}");
}

#[test]
fn inventory_child_shape_accepts_exact_k_rounds() {
    let good = parse_counts_line(
        "COUNTS init=1 slotlist=11 getinfo=10 getslotinfo=10 gettokeninfo=10 finalize=1 failed=0",
    );
    assert!(inv_counts_healthy(&good, 10));
    assert!(!inv_counts_healthy(&good, 11));
    let failed = parse_counts_line(
        "COUNTS init=1 slotlist=11 getinfo=10 getslotinfo=10 gettokeninfo=10 finalize=1 failed=1",
    );
    assert!(!inv_counts_healthy(&failed, 10));
}

#[test]
fn cell_durations_fit_the_five_minute_budget() {
    for (name, duration_s) in [
        ("a", A_DURATION_S),
        ("b", B_DURATION_S),
        ("c", C_DURATION_S),
        ("d", D_DURATION_S),
    ] {
        assert!(
            duration_s <= 285,
            "cell {name} observer duration {duration_s}s exceeds the 5-minute cell budget with setup"
        );
    }
    assert!(
        u64::from(A_HOLDER_POLLS) * A_HOLDER_POLL_MS / 1000 + A_QUIET_S + 15 < A_DURATION_S,
        "the cell (a) holder must finish its polls inside the capture"
    );
    const {
        assert!(
            C_WAIT_S + C_LINGER_S + 5 < C_END_MARGIN_S,
            "the cell (c) end margin must exceed the child life"
        );
    }
}
