//! SPDX-License-Identifier: GPL-3.0-or-later
//! K0 live cells: `--select-endpoint` detail from the broad counter on
//! a real SoftHSM workload (root). Every cell runs the real observer
//! binary (`P11SCOPE_E2E_OBSERVER` or the `p11scope` sibling of this
//! test binary) with `--mode metrics --counter-mode counts
//! --select-endpoint C_Sign` against a gate-synchronized ledger
//! workload, then compares the `-o` report with the workload's own
//! exact ledger. `profile --pid` and owned `run` positives pin a known
//! call count with the target held alive through close; the exec
//! negative execs mid-window through the ledger's exec-chain mode and
//! pins the caller-changed void; the two exit cells let the watched
//! process exit inside the window (owned `run` without `--hold`, and a
//! `--pid` target that ends before the duration) and pin what an exit
//! does to the detail; the gate-less cell runs a short owned child
//! with no test synchronization and pins that every render sees
//! every call the main report saw, while a fail-closed
//! `broad_stopping` void with same-report truncation is also accepted
//! (same constraint as the exec cell).
//!
//! Gate discipline (no sleeps on the critical path): every phase the
//! test drives waits on a workload line (`READY`, `WATCH_READY`,
//! `DONE`) or the observer's `capturing` readiness line (it proves
//! attach plus discovery plus the pre-loop selection read; live
//! frames are TTY-only, so a function row never lands in the log),
//! each under an outer deadline that fails loudly. In the positives
//! `--hold` keeps the watched pid alive through close, so the window
//! closes on the observer's duration rather than on an exit.

use anyhow::{Context as _, Result, bail, ensure};
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
    /// Owned-`run` cells under `sudo`: a test-owned 0711 base the
    /// dropped child can traverse (declared after `dir`, so it drops
    /// last). `None` keeps the workload under `$TMPDIR`.
    base: Option<tempfile::TempDir>,
    ledger: PathBuf,
    conf: PathBuf,
}

impl K0Workload {
    fn build(module: &str) -> Result<Self> {
        Self::build_with_base(module, None)
    }

    /// The owned-`run` workload. Under `sudo` the observer drops the
    /// owned child to the invoking user, who must traverse to its
    /// ledger, config, token and gate. The runner's `$TMPDIR` is a
    /// root-only 0700 directory, so the workload goes under a
    /// test-owned 0711 base in the sticky `/var/tmp` instead and the
    /// runner's directory is never re-moded. Without `sudo` (root CI)
    /// the child stays root and `$TMPDIR` serves as is.
    fn build_owned(module: &str) -> Result<Self> {
        if std::env::var_os("SUDO_UID").is_none() {
            return Self::build_with_base(module, None);
        }
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::Builder::new()
            .prefix("p11scope-k0run-")
            .tempdir_in("/var/tmp")
            .context("test-owned base under /var/tmp")?;
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o711))
            .context("open the test-owned base for traversal")?;
        Self::build_with_base(module, Some(base))
    }

    fn build_with_base(module: &str, base: Option<tempfile::TempDir>) -> Result<Self> {
        ensure!(
            Path::new(module).exists(),
            "SoftHSM2 provider {module} is missing"
        );
        ensure!(ledger_source().exists(), "ledger fixture is missing");
        let dir = match &base {
            Some(base) => tempfile::tempdir_in(base.path())?,
            None => tempfile::tempdir()?,
        };
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
        Ok(Self {
            dir,
            base,
            ledger,
            conf,
        })
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
    /// main-phase iterations; after DONE it holds the pid (`hold`) or
    /// exits.
    fn spawn_mech(
        &self,
        out: &Path,
        module: &str,
        gate: &Path,
        iters: u32,
        hold: bool,
    ) -> Result<K0Process> {
        ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
        let stderr = out.with_extension("stderr");
        let iters = iters.to_string();
        let mut args = vec![
            "mech",
            "--cell",
            "K0P",
            "--module",
            module,
            "--iters",
            &iters,
            "--gate",
            gate.to_str().context("gate path")?,
        ];
        if hold {
            args.push("--hold");
        }
        let child = Command::new(&self.ledger)
            .args(&args)
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
                "--ledger-singletons",
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

/// Bounded observer-log tail for failure evidence: the last 40 lines
/// within 8 KiB, so a failure carries the observer's own words.
fn observer_log_tail(log: &Path) -> Vec<String> {
    const MAX_LINES: usize = 40;
    const MAX_BYTES: usize = 8192;
    let text = match std::fs::read_to_string(log) {
        Ok(text) => text,
        Err(error) => return vec![format!("<log unreadable: {error}>")],
    };
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.len() > MAX_LINES {
        lines.drain(..lines.len() - MAX_LINES);
    }
    let mut bytes = 0;
    let mut kept = Vec::new();
    for line in lines.into_iter().rev() {
        if bytes + line.len() + 1 > MAX_BYTES {
            break;
        }
        bytes += line.len() + 1;
        kept.push(line.to_string());
    }
    kept.reverse();
    kept
}

/// One failure line carrying the observer's exit status, the report
/// path and the bounded log tail.
fn observer_evidence(log: &Path, report: &Path, status: &str) -> String {
    format!(
        "observer {status}; report={}; log tail={:?}",
        report.display(),
        observer_log_tail(log)
    )
}

/// The observer readiness line the cells gate on: attach plus
/// discovery plus the pre-loop selection read all precede it, so
/// opening the workload gate here keeps every main-phase call
/// strictly inside the K0 window.
const CAPTURE_READY_NEEDLE: &str = "p11scope: capturing: ";

/// Wait for the observer line containing `needle`.
fn wait_for_observer_row(
    observer_out: &Path,
    needle: &str,
    child: &mut Child,
    report: &Path,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let seen = std::fs::read_to_string(observer_out)
            .is_ok_and(|text| text.lines().any(|line| line.contains(needle)));
        if seen {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!(
                "the observer exited before showing {needle:?}: {}",
                observer_evidence(observer_out, report, &format!("exited {status}"))
            );
        }
        ensure!(
            Instant::now() < deadline,
            "observer never showed {needle:?} (pid={}): {}",
            child.id(),
            observer_evidence(observer_out, report, "still running")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// One C8 gate file the ledger waits on: `<prefix>.<generation>.<phase>`.
fn c8_gate(prefix: &Path, generation: u32, phase: &str) -> PathBuf {
    PathBuf::from(format!("{}.{generation}.{phase}", prefix.display()))
}

fn wait_for_observer_stop(
    child: &mut Child,
    log: &Path,
    report: &Path,
    budget: Duration,
) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        ensure!(
            Instant::now() < deadline,
            "the observer never stopped (pid={}): {}",
            child.id(),
            observer_evidence(log, report, "still running")
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Require a nonzero probe count on the capture line: a zero-probe
/// capture observes nothing, so passing it on would fail downstream
/// instead of at the cause.
fn require_attached_probes(log: &Path, report: &Path) -> Result<()> {
    let text = std::fs::read_to_string(log).unwrap_or_default();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix(CAPTURE_READY_NEEDLE) else {
            continue;
        };
        let count = rest
            .split_whitespace()
            .next()
            .and_then(|first| first.parse::<usize>().ok());
        match count {
            Some(probes) => {
                ensure!(
                    probes > 0,
                    "the observer attached no probes: {}",
                    observer_evidence(log, report, "capture line shows 0 probes")
                );
                return Ok(());
            }
            None => break,
        }
    }
    anyhow::bail!(
        "the observer showed no readable capture line: {}",
        observer_evidence(log, report, "capture line missing")
    )
}

/// Keep the workload directory on failure so the printed report path
/// stays readable; on success the directory drops as before.
fn keep_workload_on_failure(workload: K0Workload, outcome: Result<()>, tag: &str) -> Result<()> {
    if outcome.is_err() {
        eprintln!("{tag} evidence kept at {}", workload.dir.path().display());
        let _ = workload.dir.keep();
        if let Some(base) = workload.base {
            let _ = base.keep();
        }
    }
    outcome
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
#[ignore = "privileged K0 cell (root with gcc, softhsm2-util, SoftHSM2 and an observer binary): profile --select-endpoint counts on a real SoftHSM workload with an exact ledger-known C_Sign count"]
fn k0_live_detail_matches_ledger_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build(&module)?;
    let outcome = k0_detail_inner(&workload, &module, &observer);
    keep_workload_on_failure(workload, outcome, "K0P")
}

fn k0_detail_inner(workload: &K0Workload, module: &str, observer: &Path) -> Result<()> {
    let out = workload.path("k0p.json");
    let log = workload.path("k0p.observer.log");
    let gate = workload.path("k0p.gate");
    let ledger_out = workload.path("k0p.ledger.out");
    // Four main-phase iterations, one clean C_Sign each; setup and
    // teardown never call C_Sign, so the window count is exactly 4.
    let mut target = workload.spawn_mech(&ledger_out, module, &gate, 4, true)?;
    target.wait_for("READY ", Duration::from_secs(60))?;
    let pid = target.child.id();
    let mut child = spawn_observer(observer, pid, 60, &out, &log)?;
    wait_for_observer_row(
        &log,
        CAPTURE_READY_NEEDLE,
        &mut child,
        &out,
        Duration::from_secs(120),
    )?;
    require_attached_probes(&log, &out)?;
    std::fs::write(&gate, b"open\n")?;
    target.wait_for("DONE ", Duration::from_secs(60))?;
    // The held pid stays alive while the observer closes on its own
    // duration, so this positive pins a window without an exit (the
    // exit cells pin the exit).
    let status = wait_for_observer_stop(&mut child, &log, &out, Duration::from_secs(180))?;
    target.ensure_alive("at observer stop")?;
    target.kill();
    ensure!(
        status.success(),
        "observer exited {status}: {}",
        observer_evidence(&log, &out, &format!("exited {status}"))
    );
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
#[ignore = "privileged K0 cell (root with gcc, softhsm2-util, SoftHSM2 and an observer binary): profile --select-endpoint counts voids as caller-changed when the SoftHSM workload execs mid-window"]
fn k0_live_exec_voids_detail_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build(&module)?;
    let outcome = k0_exec_inner(&workload, &module, &observer);
    keep_workload_on_failure(workload, outcome, "K0X")
}

#[allow(clippy::too_many_arguments)] // One owned-run spawn over all retained inputs; the cell drives it directly.
fn spawn_run_observer(
    observer: &Path,
    module: &str,
    duration_secs: u64,
    out: &Path,
    log: &Path,
    ledger: &Path,
    conf: &Path,
    gate: &Path,
    pause: Option<&str>,
    child_tail: &[&str],
) -> Result<Child> {
    let log_file = std::fs::File::create(log)?;
    let mut command = Command::new(observer);
    command.args([
        "run",
        "--mode",
        "metrics",
        "--counter-mode",
        "counts",
        "--select-endpoint",
        "C_Sign",
        "--module",
        module,
        "--prearm-module",
        module,
        "--duration",
        &duration_secs.to_string(),
        "-o",
        out.to_str().context("out path")?,
    ]);
    // The gate-less probe overrides the pause policy through the
    // environment; every other shape runs explicit `never` (the
    // pre-0.7.0 default the cells were qualified under).
    command.args(["--pause", pause.unwrap_or("never")]);
    command.args([
        "--",
        ledger.to_str().context("ledger path")?,
        "mech",
        "--cell",
        "K0R",
        "--module",
        module,
        "--iters",
        "4",
        "--gate",
        gate.to_str().context("gate path")?,
    ]);
    command
        .args(child_tail)
        .env("SOFTHSM2_CONF", conf)
        // T-2: the K0 debug line carries comparable/exit-only counts.
        .env("P11SCOPE_K0_DEBUG", "1")
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .spawn()
        .context("spawning observer")
}

#[test]
#[ignore = "privileged K0 cell (root with gcc, softhsm2-util, SoftHSM2 and an observer binary): run --select-endpoint counts on a real SoftHSM workload with an exact ledger-known C_Sign count"]
fn k0_live_run_detail_matches_ledger_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build_owned(&module)?;
    let outcome = k0_run_inner(&workload, &module, &observer);
    keep_workload_on_failure(workload, outcome, "K0R")
}

fn k0_run_inner(workload: &K0Workload, module: &str, observer: &Path) -> Result<()> {
    let document = k0_owned_run(workload, module, observer, "k0r", OwnedChild::Held, None)?;
    require_four_sign_detail(&document)
}

/// How the owned `mech` child ends.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnedChild {
    /// `--hold`: alive past the observer's duration, reaped by its
    /// handoff PID; the window closes on the duration.
    Held,
    /// No `--hold`: the child exits after DONE, inside the window, and
    /// the capture ends on that exit. `--delay-ms` keeps it alive
    /// after the gate for that long before its calls, so the
    /// observer's discovery frames process the child's provider-load
    /// records while the child still runs. Without the delay the
    /// exit still voids intermittently: unbound late loader records
    /// reject as real truncation (only exit-explained counts
    /// render), so the immediate shape cannot pin a render.
    ExitsAfter { delay_ms: u32 },
    /// No gate at all (`--gate -`): the short-program shape. The child
    /// runs at release, signs four times and exits on its own,
    /// possibly before the K0 window opens; the capture ends on that
    /// exit. Whether the detail still sees every call the aggregate
    /// saw is what the gate-less cell pins.
    Gateless,
}

/// Drive one owned `run --select-endpoint C_Sign` over a `mech` child
/// doing four clean C_Sign calls, and return the `-o` report. The
/// child is gated unless the shape is `Gateless`; `pause` overrides
/// the observer's `--pause` policy for the gate-less probe only.
fn k0_owned_run(
    workload: &K0Workload,
    module: &str,
    observer: &Path,
    tag: &str,
    shape: OwnedChild,
    pause: Option<&str>,
) -> Result<serde_json::Value> {
    let out = workload.path(&format!("{tag}.json"));
    let log = workload.path(&format!("{tag}.observer.log"));
    let gate = workload.path(&format!("{tag}.gate"));
    if shape != OwnedChild::Gateless {
        ensure!(!gate.exists(), "gate {} pre-exists", gate.display());
    }
    // Four main-phase iterations, one clean C_Sign each; setup and
    // teardown never call C_Sign, so the window count is exactly 4.
    // The owned child maps its provider after the observer attaches,
    // so the observer pre-arms the file with --prearm-module (and
    // narrows with --module); the child's own startup exec precedes
    // the window and must not void it.
    // The owned child drops to the invoking user when the observer
    // runs as root via sudo; hand the workload tree to that user so
    // the child can read its ledger, config, token and gate (the
    // workload sits under a test-owned 0711 base, `build_owned`).
    if let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
        ensure!(
            workload.base.is_some(),
            "owned-run workload under sudo needs its test-owned base"
        );
        let status = std::process::Command::new("chown")
            .args([
                "-R",
                &format!("{uid}:{gid}"),
                workload.dir.path().to_str().context("workload path")?,
            ])
            .status()
            .context("chown workload to invoking user")?;
        ensure!(status.success(), "chown workload to {uid}:{gid}");
    }
    let delay;
    let child_tail: Vec<&str> = match shape {
        OwnedChild::Held => vec!["--hold"],
        OwnedChild::ExitsAfter { delay_ms } => {
            delay = delay_ms.to_string();
            vec!["--delay-ms", &delay]
        }
        OwnedChild::Gateless => vec![],
    };
    // The ledger takes `--gate -` for no gate; the gate-less child
    // runs at release without any test synchronization.
    let spawn_gate: &Path = if shape == OwnedChild::Gateless {
        Path::new("-")
    } else {
        &gate
    };
    let mut child = spawn_run_observer(
        observer,
        module,
        60,
        &out,
        &log,
        &workload.ledger,
        &workload.conf,
        spawn_gate,
        pause,
        &child_tail,
    )?;
    wait_for_observer_row(
        &log,
        CAPTURE_READY_NEEDLE,
        &mut child,
        &out,
        Duration::from_secs(120),
    )?;
    require_attached_probes(&log, &out)?;
    if shape != OwnedChild::Gateless {
        std::fs::write(&gate, b"open\n")?;
    }
    wait_for_observer_row(&log, "DONE ", &mut child, &out, Duration::from_secs(60))?;
    let status = wait_for_observer_stop(&mut child, &log, &out, Duration::from_secs(180))?;
    // A held child stays alive past the observer's duration handoff;
    // reap it by the handoff PID the observer names. A child that
    // exited on its own ended the capture and names no handoff.
    let handoff = std::fs::read_to_string(&log).ok().and_then(|text| {
        text.lines().find_map(|line| {
            line.strip_prefix(
                "p11scope: duration expired without --kill-on-timeout; handed back live child pid ",
            )?
            .split_whitespace()
            .next()?
            .parse::<i32>()
            .ok()
        })
    });
    if let Some(pid) = handoff {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let mut status = 0;
        unsafe {
            libc::waitpid(pid, &mut status, 0);
        }
    }
    ensure!(
        status.success(),
        "observer exited {status}: {}",
        observer_evidence(&log, &out, &format!("exited {status}"))
    );
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).context("reading -o JSON")?)?;
    if shape != OwnedChild::Held {
        // The exit lands inside the window: the capture ended on the
        // child's own exit, before the duration, with no handoff.
        // Owned runs never print the non-owned `capture ended: target
        // exited` stderr marker (they name the child's status instead),
        // so the report is the channel: `loop_end_reason` pins the
        // target-exit end, `child_still_running: false` with no
        // `handoff_child_pid` pins the reaped child.
        let reason = document["evidence"]["scheduling"]["phase_mono_ns"]["loop_end_reason"]
            .as_str()
            .unwrap_or("?");
        let still_running = document["evidence"]["child_still_running"].as_bool();
        let handoff_pid = document["evidence"]["handoff_child_pid"].as_u64();
        ensure!(
            handoff.is_none()
                && reason == crate::render::LOOP_END_TARGET_EXIT
                && still_running == Some(false)
                && handoff_pid.is_none(),
            "the unheld child must exit inside the window and end the capture \
             (loop_end_reason={reason:?}, child_still_running={still_running:?}, \
             handoff_child_pid={handoff_pid:?}): {}",
            observer_evidence(&log, &out, "no target-exit end")
        );
    }
    let (entered, bad) = ledger_main_counts(&log, "C_Sign")?;
    ensure!(entered == 4 && bad == 0, "workload did 4 clean signs");
    Ok(document)
}

/// The rendered positive: the selection names C_Sign without a refusal,
/// the detail carries exactly the selected slot with the ledger's four
/// clean calls, and equals the window aggregate's row for that slot.
fn require_four_sign_detail(document: &serde_json::Value) -> Result<()> {
    let selected = &document["evidence"]["selected_detail"];
    let record = &selected["selection"];
    ensure!(
        record["endpoint"] == serde_json::json!("C_Sign"),
        "selection names C_Sign: {record}"
    );
    let slot = record["slot"].as_u64().context("selection slot")?;
    ensure!(
        record.get("refusal").is_none(),
        "the window succeeds: {record}"
    );
    let detail = selected.get("detail").context("detail renders")?;
    let rows = detail["rows"].as_array().context("detail rows")?;
    ensure!(rows.len() == 1, "Detail carries only the selected slot");
    ensure!(rows[0]["slot"] == serde_json::json!(slot), "detail slot");
    ensure!(rows[0]["entered"] == serde_json::json!(4), "detail entered");
    ensure!(
        rows[0]["returned"] == serde_json::json!(4),
        "Detail returned"
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

/// What an exit of the watched process inside the window does to the
/// detail: the documented outcome every exit cell pins. The counter
/// bank's probes are bound to the original task, so the exit ends the
/// window cleanly and the detail renders the four calls made before it
/// (K0-4).
fn require_exit_outcome(document: &serde_json::Value) -> Result<()> {
    require_four_sign_detail(document)
}

#[test]
#[ignore = "privileged K0 cell (root with gcc, softhsm2-util, SoftHSM2 and an observer binary): run --select-endpoint counts whose owned child does four C_Sign calls and exits inside the window"]
fn k0_live_run_exit_in_window_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build_owned(&module)?;
    // The delayed-exit shape: the child waits three seconds after the
    // gate so the observer's ~1 s discovery frames process its
    // provider-load records while it still runs; then it signs four
    // times and exits inside the window. An immediate exit would
    // race loader-hit processing against view retirement and void
    // intermittently (see the `ExitsAfter` docs), so the delay pins
    // the exit-cleanly contract deterministically.
    let outcome = k0_owned_run(
        &workload,
        &module,
        &observer,
        "k0re",
        OwnedChild::ExitsAfter { delay_ms: 3000 },
        None,
    )
    .and_then(|document| require_exit_outcome(&document));
    keep_workload_on_failure(workload, outcome, "K0RE")
}

#[test]
#[ignore = "privileged K0 cell (root with gcc, softhsm2-util, SoftHSM2 and an observer binary): run --select-endpoint counts on a gate-less short owned child that signs four times and exits at once"]
fn k0_live_run_gateless_exit_matches_main_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build_owned(&module)?;
    // P11SCOPE_K0_PAUSE=always probes the pause hypothesis (the child
    // pauses at its load until the observer processes it); the
    // default campaign leaves it unset, which runs explicit `--pause never`.
    let pause = std::env::var("P11SCOPE_K0_PAUSE").ok();
    let outcome = k0_owned_run(
        &workload,
        &module,
        &observer,
        "k0g",
        OwnedChild::Gateless,
        pause.as_deref(),
    )
    .and_then(|document| {
        let log = std::fs::read_to_string(workload.path("k0g.observer.log"))
            .context("reading the gateless observer log")?;
        require_detail_matches_main_counts(&document, &log)
    });
    keep_workload_on_failure(workload, outcome, "K0G")
}

/// One parsed `k0-debug` line (T-2): selection-time comparable losses
/// plus close-time truncation, exit-only total and per-route exit-only
/// counts, and comparable losses.
struct K0DebugCounts {
    before_comparable: [u64; 4],
    after_truncated: u64,
    after_exit: u64,
    after_exit_routes: [u64; 3],
    after_comparable: [u64; 4],
}

/// Parses the observer's `k0-debug` line from its log. Required: the
/// cell fails closed when the line is missing or malformed.
fn parse_k0_debug_counts(log: &str) -> Result<K0DebugCounts> {
    let line = log
        .lines()
        .find(|line| line.starts_with("k0-debug:"))
        .context("the observer logged its k0-debug line")?;
    let rest = line.strip_prefix("k0-debug:").unwrap().trim();
    let mut before_comparable = None;
    let mut after_truncated = None;
    let mut after_exit = None;
    let mut after_exit_routes = None;
    let mut after_comparable = None;
    for part in rest.split_whitespace() {
        let (key, value) = part.split_once('=').context("k0-debug part")?;
        match key {
            "before_comparable" => before_comparable = Some(parse_loss_array(value)?),
            "after_truncated" => after_truncated = Some(value.parse::<u64>()?),
            "after_exit" => after_exit = Some(value.parse::<u64>()?),
            "after_exit_routes" => after_exit_routes = Some(parse_route_array(value)?),
            "after_comparable" => after_comparable = Some(parse_loss_array(value)?),
            _ => bail!("unknown k0-debug key {key:?}"),
        }
    }
    Ok(K0DebugCounts {
        before_comparable: before_comparable.context("k0-debug before_comparable")?,
        after_truncated: after_truncated.context("k0-debug after_truncated")?,
        after_exit: after_exit.context("k0-debug after_exit")?,
        after_exit_routes: after_exit_routes.context("k0-debug after_exit_routes")?,
        after_comparable: after_comparable.context("k0-debug after_comparable")?,
    })
}

fn parse_loss_array(text: &str) -> Result<[u64; 4]> {
    let inner = text
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
        .context("loss array brackets")?;
    let mut parts = inner.split(',');
    let mut out = [0u64; 4];
    for slot in &mut out {
        *slot = parts
            .next()
            .context("loss array arity")?
            .trim()
            .parse::<u64>()?;
    }
    ensure!(parts.next().is_none(), "loss array arity");
    Ok(out)
}

fn parse_route_array(text: &str) -> Result<[u64; 3]> {
    let inner = text
        .strip_prefix('[')
        .and_then(|text| text.strip_suffix(']'))
        .context("route array brackets")?;
    let mut parts = inner.split(',');
    let mut out = [0u64; 3];
    for slot in &mut out {
        *slot = parts
            .next()
            .context("route array arity")?
            .trim()
            .parse::<u64>()?;
    }
    ensure!(parts.next().is_none(), "route array arity");
    Ok(out)
}

/// The gate-less short-run shape: the selection names C_Sign, and the
/// run either renders exactly — the detail's entered/returned counts
/// equal the main report's C_Sign calls, so no call the aggregate saw
/// fell outside the window — or fails closed as `broad_stopping` with
/// the truncation in the same report (loader records that arrive after
/// the view retires reject as real truncation; same constraint as the
/// exec cell). The ledger count (four clean signs, already ensured by
/// the driver) and the aggregate count (also four: the uprobes attach
/// before the child is released) keep the render comparison
/// non-vacuous. T-2 prints truncation plus comparable/exit-only
/// counts on both paths and gates renders on comparable losses
/// standing still, so a regression of the exit-only split fails.
fn require_detail_matches_main_counts(document: &serde_json::Value, log: &str) -> Result<()> {
    let selected = &document["evidence"]["selected_detail"];
    let record = &selected["selection"];
    ensure!(
        record["endpoint"] == serde_json::json!("C_Sign"),
        "selection names C_Sign: {record}"
    );
    let debug = parse_k0_debug_counts(log)?;
    if record.get("refusal").is_some() {
        let reason = record["refusal"].as_str().context("void reason")?;
        let truncated = document["evidence"]["discovery_truncated"]
            .as_u64()
            .context("the report carries its truncation count")?;
        ensure!(
            debug.after_truncated == truncated,
            "debug and report truncation agree: {} vs {truncated}",
            debug.after_truncated,
        );
        eprintln!(
            "k0-live-gateless-cell: void reason = {reason} (discovery_truncated={truncated} exit={} routes={:?} comparable={:?}->{:?})",
            debug.after_exit,
            debug.after_exit_routes,
            debug.before_comparable,
            debug.after_comparable,
        );
        ensure!(
            reason == "broad_stopping" && truncated >= 1,
            "the short run fails closed with evidence: {record}"
        );
        ensure!(selected.get("detail").is_none(), "no detail on a void");
        ensure!(
            selected.get("aggregate").is_none(),
            "no aggregate on a void"
        );
        ensure!(selected.get("lineage").is_none(), "no lineage on a void");
        return Ok(());
    }
    let slot = record["slot"].as_u64().context("selection slot")?;
    let detail = selected.get("detail").context("detail renders")?;
    let rows = detail["rows"].as_array().context("detail rows")?;
    ensure!(rows.len() == 1, "Detail carries only the selected slot");
    ensure!(rows[0]["slot"] == serde_json::json!(slot), "detail slot");
    let entered = rows[0]["entered"].as_u64().context("detail entered")?;
    let returned = rows[0]["returned"].as_u64().context("detail returned")?;
    let errors = rows[0]["errors"].as_u64().context("detail errors")?;
    // Torn-read check: every counted return adds exactly one
    // return-value count, so a rendered row's `rv_counts` sum equals
    // its `returned` delta; anything else fails the cell instead of
    // passing a disagreeing row.
    let rv_counts = rows[0]["rv_counts"]
        .as_object()
        .context("detail rv_counts")?;
    let mut rv_sum = 0u128;
    for (rv, count) in rv_counts {
        rv_sum += u128::from(count.as_u64().with_context(|| format!("rv_counts[{rv}]"))?);
    }
    ensure!(
        rv_sum == u128::from(returned),
        "detail rv_counts sum equals returned: {rv_sum} vs {returned}"
    );
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
    let main_calls = row["calls"].as_u64().context("main C_Sign calls")?;
    let main_errors = row["errors"].as_u64().context("main C_Sign errors")?;
    let truncated = document["evidence"]["discovery_truncated"]
        .as_u64()
        .context("the report carries its truncation count")?;
    ensure!(
        debug.after_truncated == truncated,
        "debug and report truncation agree: {} vs {truncated}",
        debug.after_truncated,
    );
    eprintln!(
        "k0-live-gateless-cell: main={main_calls}/{main_errors} detail={entered}/{returned}/{errors} (discovery_truncated={truncated} exit={} routes={:?} comparable={:?}->{:?})",
        debug.after_exit, debug.after_exit_routes, debug.before_comparable, debug.after_comparable,
    );
    ensure!(
        main_calls == 4 && main_errors == 0,
        "the aggregate saw all four ledger calls: {row}"
    );
    ensure!(
        entered == main_calls && returned == main_calls && errors == 0,
        "detail equals the main report: detail={entered}/{returned}/{errors} main={main_calls}"
    );
    ensure!(
        debug.after_comparable == debug.before_comparable,
        "a render grows no comparable loss: {:?} -> {:?}",
        debug.before_comparable,
        debug.after_comparable,
    );
    Ok(())
}

#[test]
#[ignore = "privileged K0 cell (root with gcc, softhsm2-util, SoftHSM2 and an observer binary): profile --pid --select-endpoint counts whose target does four C_Sign calls and exits before the duration ends"]
fn k0_live_pid_exit_in_window_counts_lp64() -> Result<()> {
    let module = softhsm_path()?;
    let observer = observer_binary()?;
    let workload = K0Workload::build(&module)?;
    let outcome = k0_pid_exit_inner(&workload, &module, &observer);
    keep_workload_on_failure(workload, outcome, "K0PE")
}

fn k0_pid_exit_inner(workload: &K0Workload, module: &str, observer: &Path) -> Result<()> {
    let out = workload.path("k0pe.json");
    let log = workload.path("k0pe.observer.log");
    let gate = workload.path("k0pe.gate");
    let ledger_out = workload.path("k0pe.ledger.out");
    // Four main-phase iterations, one clean C_Sign each, then the
    // target exits (no --hold) while the observer's duration still
    // runs: the exit lands strictly inside the window.
    let mut target = workload.spawn_mech(&ledger_out, module, &gate, 4, false)?;
    target.wait_for("READY ", Duration::from_secs(60))?;
    let pid = target.child.id();
    let mut child = spawn_observer(observer, pid, 60, &out, &log)?;
    wait_for_observer_row(
        &log,
        CAPTURE_READY_NEEDLE,
        &mut child,
        &out,
        Duration::from_secs(120),
    )?;
    require_attached_probes(&log, &out)?;
    std::fs::write(&gate, b"open\n")?;
    target.wait_for("DONE ", Duration::from_secs(60))?;
    let exited = target.child.wait().context("reaping the target")?;
    ensure!(exited.success(), "the target exited {exited}");
    let status = wait_for_observer_stop(&mut child, &log, &out, Duration::from_secs(180))?;
    ensure!(
        status.success(),
        "observer exited {status}: {}",
        observer_evidence(&log, &out, &format!("exited {status}"))
    );
    let (entered, bad) = ledger_main_counts(&ledger_out, "C_Sign")?;
    ensure!(entered == 4 && bad == 0, "workload did 4 clean signs");
    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out).context("reading -o JSON")?)?;
    require_exit_outcome(&document)
}

fn k0_exec_inner(workload: &K0Workload, module: &str, observer: &Path) -> Result<()> {
    let out = workload.path("k0x.json");
    let log = workload.path("k0x.observer.log");
    let gate = workload.path("k0x.gate");
    let gates = workload.path("k0x.gates");
    let ledger_out = workload.path("k0x.ledger.out");
    // Generation 0 runs 2 iterations, execs the same ledger binary,
    // and generation 1 runs 4: every image's count is distinct, and
    // the same provider maps on both sides of the exec.
    let mut target = workload.spawn_chain(&ledger_out, module, &gate, &gates, 2)?;
    target.wait_for_line(
        &["WATCH_READY", "gen=0", "phase=go"],
        "gen0 go",
        Duration::from_secs(60),
    )?;
    std::fs::write(c8_gate(&gates, 0, "go"), b"open\n")?;
    target.wait_for("READY ", Duration::from_secs(60))?;
    let pid = target.child.id();
    let mut child = spawn_observer(observer, pid, 150, &out, &log)?;
    wait_for_observer_row(
        &log,
        CAPTURE_READY_NEEDLE,
        &mut child,
        &out,
        Duration::from_secs(120),
    )?;
    require_attached_probes(&log, &out)?;
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
    let status = wait_for_observer_stop(&mut child, &log, &out, Duration::from_secs(240))?;
    target.ensure_alive("at observer stop")?;
    target.kill();
    ensure!(
        status.success(),
        "observer exited {status}: {}",
        observer_evidence(&log, &out, &format!("exited {status}"))
    );
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
    // The exec voids the detail, but the refusal word depends on load:
    // the contract checks truncation growth (step 1) before the exec
    // witness (step 3), and the post-exec loader rescan under load
    // leaves exec-caused truncation behind, which voids as
    // `broad_stopping`. That arm is only accepted with the truncation
    // in the same report, so a lost exec witness cannot hide behind
    // it: quiet runs still take the caller-changed path.
    let reason = record["refusal"]
        .as_str()
        .context("the exec voids the detail")?;
    let truncated = document["evidence"]["discovery_truncated"]
        .as_u64()
        .context("the report carries its truncation count")?;
    eprintln!("k0-live-exec-cell: void reason = {reason} (discovery_truncated={truncated})");
    ensure!(
        reason == "promotion_caller_changed" || (reason == "broad_stopping" && truncated >= 1),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The `k0-debug` parser accepts the per-route exit-only
    /// breakdown (`after_exit_routes=[scan_end,reject,zero_state]`)
    /// and still fails closed on unknown keys.
    #[test]
    fn k0_debug_parser_accepts_the_per_route_breakdown() {
        let log = "noise\nk0-debug: before_comparable=[0,0,0,0] after_truncated=1 after_exit=1 after_exit_routes=[0,1,0] after_comparable=[0,0,0,0]\n";
        let counts = parse_k0_debug_counts(log).expect("the line parses");
        assert_eq!(counts.after_exit_routes, [0, 1, 0]);
        assert_eq!(counts.after_exit, 1);
        assert_eq!(counts.after_truncated, 1);
    }
}
