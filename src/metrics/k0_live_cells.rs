// SPDX-License-Identifier: GPL-3.0-or-later
//! K0 live cells: `--select-endpoint` detail from the broad counter on
//! a real SoftHSM workload (Fedora, root). Both cells run the real
//! observer binary (`P11SCOPE_E2E_OBSERVER` or the `p11scope` sibling
//! of this test binary) as `profile --pid --mode metrics
//! --counter-mode counts --select-endpoint C_Sign` against a
//! gate-synchronized ledger workload, then compare the `-o` report
//! with the workload's own exact ledger. The positive pins a known
//! call count; the negative execs mid-window through the ledger's
//! exec-chain mode and pins the caller-changed void.
//!
//! Gate discipline (no sleeps on the critical path): every phase the
//! test drives waits on a workload line (`READY`, `WATCH_READY`,
//! `DONE`) or an observer line (a `C_Sign` row proves attach plus
//! discovery plus the pre-loop selection read), each under an outer
//! deadline that fails loudly. `--hold` keeps the watched pid mapped
//! through close so no leader exit voids the window.

use anyhow::{Context as _, Result, ensure};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// SoftHSM2 provider layouts across guest images (Debian multiarch
/// first, then the /usr/lib layout the vng guests carry, then the
/// Fedora /usr/lib64 layout the controller's live cells use).
const SOFTHSM_CANDIDATES: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib64/pkcs11/libsofthsm2.so",
];

fn ledger_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-cli/inventory-ledger.c")
}

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
/// (the guest driver stages one) or the `p11scope` sibling of this
/// test binary's directory (a local `cargo build` layout).
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
    let sibling = std::env::current_exe()?
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

/// CLOCK_MONOTONIC in nanoseconds: the absolute basis the ledger's
/// C8 deadline uses (same host, same time namespace).
fn monotonic_ns() -> u64 {
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut stamp) },
        0
    );
    stamp.tv_sec as u64 * 1_000_000_000 + stamp.tv_nsec as u64
}

struct K0Workload {
    dir: tempfile::TempDir,
    ledger: PathBuf,
    conf: PathBuf,
}

impl K0Workload {
    fn build(module: &str) -> Result<Self> {
        ensure!(
            Path::new(module).exists(),
            "SoftHSM2 provider {module} is missing"
        );
        ensure!(ledger_source().exists(), "ledger fixture is missing");
        let dir = tempfile::tempdir()?;
        let ledger = dir.path().join("ledger");
        let status = Command::new("cc")
            .args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"])
            .arg(ledger_source())
            .arg("-o")
            .arg(&ledger)
            .args(["-ldl", "-lpthread"])
            .status()
            .context("running cc")?;
        ensure!(status.success(), "ledger build failed");
        let tokens = dir.path().join("tokens");
        std::fs::create_dir(&tokens)?;
        let conf = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        )?;
        let status = Command::new("softhsm2-util")
            .args(["--init-token", "--free", "--label", "k0cell"])
            .args(["--so-pin", "5678", "--pin", "1234"])
            .env("SOFTHSM2_CONF", &conf)
            .stdout(Stdio::null())
            .status()
            .context("running softhsm2-util")?;
        ensure!(status.success(), "softhsm2-util --init-token failed");
        Ok(Self { dir, ledger, conf })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn private_log(path: &Path) -> Result<std::fs::File> {
        use std::os::unix::fs::OpenOptionsExt as _;

        Ok(std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?)
    }

    /// A gated `mech` image: maps eagerly (discoverable at attach),
    /// prints READY after setup, then waits on `gate` before its
    /// main-phase iterations and holds the pid after DONE.
    fn spawn_mech(&self, out: &Path, module: &str, gate: &Path, iters: u32) -> Result<K0Process> {
        ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
        let stderr = out.with_extension("stderr");
        let child = Command::new(&self.ledger)
            .args([
                "mech",
                "--cell",
                "K0P",
                "--module",
                module,
                "--iters",
                &iters.to_string(),
                "--gate",
                gate.to_str().context("gate path")?,
                "--hold",
            ])
            .env("SOFTHSM2_CONF", &self.conf)
            .stdin(Stdio::null())
            .stdout(Self::private_log(out)?)
            .stderr(Self::private_log(&stderr)?)
            .spawn()
            .context("spawning ledger")?;
        Ok(K0Process {
            child,
            out: out.to_path_buf(),
            stderr,
        })
    }

    /// A two-image exec-chain: generation 0 runs `iters` iterations,
    /// execs the same ledger binary (leader exec, same provider), and
    /// generation 1 runs `2 * iters`. Every phase waits on a C8 gate
    /// the test drives; the last image holds the pid after DONE.
    fn spawn_chain(
        &self,
        out: &Path,
        module: &str,
        gate: &Path,
        gates: &Path,
        iters: u32,
    ) -> Result<K0Process> {
        ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
        let stderr = out.with_extension("stderr");
        let deadline = monotonic_ns() + 300_000_000_000;
        let child = Command::new(&self.ledger)
            .args([
                "exec-chain",
                "--cell",
                "K0X",
                "--module",
                module,
                "--iters",
                &iters.to_string(),
                "--gate",
                gate.to_str().context("gate path")?,
                "--chain",
                &format!("leader:{}", self.ledger.display()),
                "--c8-gate-prefix",
                gates.to_str().context("gates path")?,
                "--c8-gated-images",
                "2",
                "--c8-deadline",
                &deadline.to_string(),
                "--delay-ms",
                "500",
                "--hold",
            ])
            .env("SOFTHSM2_CONF", &self.conf)
            .stdin(Stdio::null())
            .stdout(Self::private_log(out)?)
            .stderr(Self::private_log(&stderr)?)
            .spawn()
            .context("spawning ledger")?;
        Ok(K0Process {
            child,
            out: out.to_path_buf(),
            stderr,
        })
    }
}

struct K0Process {
    child: Child,
    out: PathBuf,
    stderr: PathBuf,
}

impl K0Process {
    fn has(&self, prefix: &str) -> bool {
        std::fs::read_to_string(&self.out)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with(prefix)))
    }

    fn has_line(&self, parts: &[&str]) -> bool {
        std::fs::read_to_string(&self.out).is_ok_and(|text| {
            text.lines()
                .any(|line| parts.iter().all(|part| line.contains(part)))
        })
    }

    fn diagnostics(&self) -> String {
        use std::io::{Read as _, Seek as _, SeekFrom};

        fn tail(path: &Path) -> std::io::Result<Vec<String>> {
            let mut file = std::fs::File::open(path)?;
            let start = file.metadata()?.len().saturating_sub(4096);
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            file.take(4096).read_to_end(&mut bytes)?;
            let text = String::from_utf8_lossy(&bytes);
            let mut lines: Vec<_> = text.lines().rev().take(12).map(String::from).collect();
            lines.reverse();
            Ok(lines)
        }
        format!(
            "ledger tail={:?}; stderr tail={:?}",
            tail(&self.out),
            tail(&self.stderr)
        )
    }

    fn ensure_alive(&mut self, point: &str) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            anyhow::bail!(
                "ledger exited {point} with {status}: {}",
                self.diagnostics()
            );
        }
        Ok(())
    }

    fn wait_for(&mut self, prefix: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        while !self.has(prefix) {
            if let Err(error) = self.ensure_alive(&format!("before {prefix:?}")) {
                // A finite control can publish its last line between the
                // first read and exit observation. Re-read after reaping.
                if self.has(prefix) {
                    break;
                }
                return Err(error);
            }
            ensure!(
                Instant::now() < deadline,
                "ledger {} never printed {prefix:?}: {}",
                self.out.display(),
                self.diagnostics()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn wait_for_line(&mut self, parts: &[&str], label: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        while !self.has_line(parts) {
            if let Err(error) = self.ensure_alive(&format!("before {label:?}")) {
                if self.has_line(parts) {
                    break;
                }
                return Err(error);
            }
            ensure!(
                Instant::now() < deadline,
                "ledger {} never printed {label:?}: {}",
                self.out.display(),
                self.diagnostics()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }

    fn kill(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for K0Process {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Sum one function's main-phase ledger counts: `(entered, bad)`.
/// The ledger is the workload's own exact record — what THIS process
/// did — so it is the independent oracle for the observed detail.
fn ledger_main_counts(out: &Path, func: &str) -> Result<(u64, u64)> {
    let text = std::fs::read_to_string(out)?;
    let mut entered = 0;
    let mut bad = 0;
    let mut lines = 0;
    for line in text.lines().filter(|line| line.starts_with("LEDGER ")) {
        let get = |key: &str| {
            line.split_whitespace()
                .find_map(|token| token.strip_prefix(key)?.parse::<String>().ok())
        };
        if get("fn=").as_deref() != Some(func) {
            continue;
        }
        if get("phase=").as_deref() != Some("main") {
            continue;
        }
        entered += get("n=")
            .context("ledger n")?
            .parse::<u64>()
            .context("ledger n parses")?;
        bad += get("bad=")
            .context("ledger bad")?
            .parse::<u64>()
            .context("ledger bad parses")?;
        lines += 1;
    }
    ensure!(lines > 0, "no main-phase ledger lines for {func}");
    Ok((entered, bad))
}

/// Wait for the observer's first row naming `needle`: attach plus
/// discovery plus the pre-loop selection read all precede the first
/// frame, so opening the workload gate here keeps every main-phase
/// call strictly inside the K0 window.
fn wait_for_observer_row(
    observer_out: &Path,
    needle: &str,
    child: &mut Child,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let seen = std::fs::read_to_string(observer_out)
            .is_ok_and(|text| text.lines().any(|line| line.contains(needle)));
        if seen {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "observer never showed {needle:?} (pid={})",
            child.id()
        );
        ensure!(
            child.try_wait()?.is_none(),
            "the observer exited before showing {needle:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One C8 gate file the ledger waits on: `<prefix>.<generation>.<phase>`.
fn c8_gate(prefix: &Path, generation: u32, phase: &str) -> PathBuf {
    PathBuf::from(format!("{}.{generation}.{phase}", prefix.display()))
}

fn wait_for_observer_stop(child: &mut Child, budget: Duration) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        ensure!(
            Instant::now() < deadline,
            "the observer never stopped (pid={})",
            child.id()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_observer(
    observer: &Path,
    pid: u32,
    duration_secs: u64,
    out: &Path,
    log: &Path,
) -> Result<Child> {
    let log_file = std::fs::File::create(log)?;
    Command::new(observer)
        .args([
            "profile",
            "--pid",
            &pid.to_string(),
            "--mode",
            "metrics",
            "--counter-mode",
            "counts",
            "--select-endpoint",
            "C_Sign",
            "--duration",
            &duration_secs.to_string(),
            "-o",
            out.to_str().context("out path")?,
        ])
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()
        .context("spawning observer")
}

#[test]
#[ignore = "privileged K0 cell (Fedora, root): profile --select-endpoint counts on a real SoftHSM workload with an exact ledger-known C_Sign count"]
fn k0_live_detail_matches_ledger_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build(&module)?;
    let out = workload.path("k0p.json");
    let log = workload.path("k0p.observer.log");
    let gate = workload.path("k0p.gate");
    let ledger_out = workload.path("k0p.ledger.out");
    // Four main-phase iterations, one clean C_Sign each; setup and
    // teardown never call C_Sign, so the window count is exactly 4.
    let mut target = workload.spawn_mech(&ledger_out, &module, &gate, 4)?;
    target.wait_for("READY ", Duration::from_secs(60))?;
    let pid = target.child.id();
    let mut child = spawn_observer(&observer, pid, 60, &out, &log)?;
    wait_for_observer_row(&log, "C_Sign", &mut child, Duration::from_secs(120))?;
    std::fs::write(&gate, b"open\n")?;
    target.wait_for("DONE ", Duration::from_secs(60))?;
    // The held pid stays mapped while the observer closes on its own
    // duration: no leader exit can void the window.
    let status = wait_for_observer_stop(&mut child, Duration::from_secs(180))?;
    target.ensure_alive("at observer stop")?;
    target.kill();
    ensure!(status.success(), "observer exited {status}");
    let (entered, bad) = ledger_main_counts(&ledger_out, "C_Sign")?;
    ensure!(entered == 4 && bad == 0, "workload did 4 clean signs");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).context("reading -o JSON")?)?;
    let selected = &document["evidence"]["selected_detail"];
    let record = &selected["selection"];
    ensure!(
        record["endpoint"] == serde_json::json!("C_Sign"),
        "selection names C_Sign: {record}"
    );
    let slot = record["slot"].as_u64().context("selection slot")?;
    ensure!(
        record.get("refusal").is_none(),
        "the clean window succeeds: {record}"
    );
    let detail = selected.get("detail").context("detail renders")?;
    let rows = detail["rows"].as_array().context("detail rows")?;
    ensure!(rows.len() == 1, "Detail carries only the selected slot");
    ensure!(rows[0]["slot"] == serde_json::json!(slot), "detail slot");
    ensure!(rows[0]["entered"] == serde_json::json!(4), "detail entered");
    ensure!(
        rows[0]["returned"] == serde_json::json!(4),
        "detail returned"
    );
    ensure!(rows[0]["errors"] == serde_json::json!(0), "detail errors");
    let aggregate = selected.get("aggregate").context("aggregate renders")?;
    let aggregate_rows = aggregate["rows"].as_array().context("aggregate rows")?;
    let sibling = aggregate_rows
        .iter()
        .find(|row| row["slot"] == serde_json::json!(slot))
        .context("aggregate carries the selected slot")?;
    ensure!(
        rows[0] == *sibling,
        "live detail equals the aggregate cells for the slot"
    );
    Ok(())
}

#[test]
#[ignore = "privileged K0 cell (Fedora, root): profile --select-endpoint counts voids as caller-changed when the SoftHSM workload execs mid-window"]
fn k0_live_exec_voids_detail_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build(&module)?;
    let out = workload.path("k0x.json");
    let log = workload.path("k0x.observer.log");
    let gate = workload.path("k0x.gate");
    let gates = workload.path("k0x.gates");
    let ledger_out = workload.path("k0x.ledger.out");
    // Generation 0 runs 2 iterations, execs the same ledger binary,
    // and generation 1 runs 4: every image's count is distinct, and
    // the same provider maps on both sides of the exec.
    let mut target = workload.spawn_chain(&ledger_out, &module, &gate, &gates, 2)?;
    target.wait_for_line(
        &["WATCH_READY", "gen=0", "phase=go"],
        "gen0 go",
        Duration::from_secs(60),
    )?;
    std::fs::write(c8_gate(&gates, 0, "go"), b"open\n")?;
    target.wait_for("READY ", Duration::from_secs(60))?;
    let pid = target.child.id();
    let mut child = spawn_observer(&observer, pid, 150, &out, &log)?;
    wait_for_observer_row(&log, "C_Sign", &mut child, Duration::from_secs(120))?;
    std::fs::write(&gate, b"open\n")?;
    target.wait_for_line(&["DONE", "gen=0"], "gen0 done", Duration::from_secs(60))?;
    std::fs::write(c8_gate(&gates, 0, "next"), b"open\n")?;
    target.wait_for_line(
        &["WATCH_READY", "gen=1", "phase=go"],
        "gen1 go",
        Duration::from_secs(60),
    )?;
    std::fs::write(c8_gate(&gates, 1, "go"), b"open\n")?;
    target.wait_for_line(&["DONE", "gen=1"], "gen1 done", Duration::from_secs(60))?;
    std::fs::write(c8_gate(&gates, 1, "next"), b"open\n")?;
    // The exec lands strictly inside the window: after the
    // selection-time read (first frame precedes the gate) and before
    // the close read (DONE gen=1 precedes observer stop).
    let status = wait_for_observer_stop(&mut child, Duration::from_secs(240))?;
    target.ensure_alive("at observer stop")?;
    target.kill();
    ensure!(status.success(), "observer exited {status}");
    let text = std::fs::read_to_string(&ledger_out)?;
    ensure!(
        text.lines()
            .any(|line| line.starts_with("EXEC ") && line.contains("gen=0")),
        "gen0 execed mid-window"
    );
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).context("reading -o JSON")?)?;
    let selected = &document["evidence"]["selected_detail"];
    let record = &selected["selection"];
    ensure!(
        record["endpoint"] == serde_json::json!("C_Sign"),
        "selection names C_Sign: {record}"
    );
    ensure!(
        record["refusal"] == serde_json::json!("promotion_caller_changed"),
        "the exec voids the detail: {record}"
    );
    ensure!(selected.get("detail").is_none(), "no detail on a void");
    ensure!(
        selected.get("aggregate").is_none(),
        "no window aggregate on a void"
    );
    ensure!(selected.get("lineage").is_none(), "no lineage on a void");
    // The void is attribution, not loss: the pre-exec calls stay in
    // the main report's aggregate (post-exec calls may add more once
    // the links re-fire).
    let functions = document["functions"]
        .as_array()
        .context("functions array")?;
    let row = functions
        .iter()
        .find(|function| {
            function["names"]
                .as_array()
                .is_some_and(|names| names.iter().any(|name| name == "C_Sign"))
        })
        .context("main report carries C_Sign")?;
    ensure!(
        row["calls"].as_u64().unwrap_or(0) >= 2,
        "pre-exec calls stay aggregated: {row}"
    );
    Ok(())
}
