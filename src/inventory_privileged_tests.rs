//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, ignored live gates for the native inventory lane (Task 6 C5.1).
//! Root BPF lane, run serially through `scripts/run-privileged-lib-tests.sh`.
//! Every caller is an owned `inventory-ledger` process (the C8 acceptance
//! workload) against SoftHSM2 or the ledger's held provider, with its own
//! independent stdout ledger; the observer is the production classic path.

use super::*;
use crate::attach::capture::{
    CaptureTargets, CleanupSummary, CookieQuery, DiscoveryBatch, ExtendReceipt, ExtendWindow,
    NativeDomainId, ReadWindow, ScopeIncarnation, WitnessBatch,
};
use crate::discovery::caller_registry::UseCoverage;
use crate::discovery::inventory_attach_set::TargetDelta;
use crate::inventory_capture::{CaptureLane, Retirement, Stopped};
use anyhow::{bail, ensure};
use p11scope_ebpf_common::ImageIdentity;
use std::cell::{Cell, RefCell};
use std::process::{Child, Command, Stdio};

const SOFTHSM: &str = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so";

fn ledger_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-cli/inventory-ledger.c")
}

/// The ledger workload, its held provider, and one initialized SoftHSM2
/// token, in a private directory.
struct Workload {
    dir: tempfile::TempDir,
    ledger: PathBuf,
    held: PathBuf,
    conf: PathBuf,
}

impl Workload {
    fn build() -> Result<Self> {
        ensure!(
            Path::new(SOFTHSM).exists(),
            "SoftHSM2 provider {SOFTHSM} is missing"
        );
        let dir = tempfile::tempdir()?;
        let ledger = dir.path().join("ledger");
        let held = dir.path().join("held.so");
        let gcc = |args: &[&str], out: &Path| -> Result<()> {
            let status = Command::new("gcc")
                .args(args)
                .arg("-o")
                .arg(out)
                .arg(ledger_source())
                .args(["-ldl", "-lpthread"])
                .status()
                .context("running gcc")?;
            ensure!(status.success(), "gcc {args:?} failed");
            Ok(())
        };
        gcc(&["-O1", "-Wall", "-Wextra", "-Werror"], &ledger)?;
        gcc(
            &[
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                "-DINVENTORY_LEDGER_HELD_PROVIDER",
            ],
            &held,
        )?;
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
            .args(["--init-token", "--free", "--label", "c51"])
            .args(["--so-pin", "5678", "--pin", "1234"])
            .env("SOFTHSM2_CONF", &conf)
            .stdout(Stdio::null())
            .status()
            .context("running softhsm2-util")?;
        ensure!(status.success(), "softhsm2-util --init-token failed");
        Ok(Self {
            dir,
            ledger,
            held,
            conf,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// One ledger process; its stdout is the ledger file `<cell>.out`.
    fn spawn(&self, cell: &str, args: &[&str]) -> Result<LedgerProcess> {
        let out = self.path(&format!("{cell}.out"));
        let child = Command::new(&self.ledger)
            .args(args)
            .env("SOFTHSM2_CONF", &self.conf)
            .env("INVENTORY_LEDGER_RELEASE", self.path("release"))
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out)?)
            .stderr(std::fs::File::create(self.path(&format!("{cell}.err")))?)
            .spawn()
            .context("spawning the ledger")?;
        let process = LedgerProcess { child, out };
        process.wait_for("READY ", Duration::from_secs(30))?;
        Ok(process)
    }
}

struct LedgerProcess {
    child: Child,
    out: PathBuf,
}

impl LedgerProcess {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn has(&self, prefix: &str) -> bool {
        std::fs::read_to_string(&self.out)
            .is_ok_and(|text| text.lines().any(|line| line.starts_with(prefix)))
    }

    /// The ledger's output, for a failure message.
    fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.out)
            .map(|text| text.lines().take(24).map(String::from).collect())
            .unwrap_or_default()
    }

    fn wait_for(&self, prefix: &str, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        while !self.has(prefix) {
            ensure!(
                Instant::now() < deadline,
                "ledger {} never printed {prefix:?}",
                self.out.display()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}

impl Drop for LedgerProcess {
    fn drop(&mut self) {
        // SIGTERM lets a --hold ledger tear its session down; then reap.
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// One witness read as the probe saw it.
#[derive(Debug, Clone)]
struct ReadStamp {
    before_ns: u64,
    after_ns: u64,
    health_read_ns: u64,
    rows_read_ns: u64,
    max_recorded_ns: Option<u64>,
}

/// The production capture behind a recording seam: the activation instant,
/// the exec-coverage stamp, every read's stamps and every row's tgid. It can
/// raise SIGINT inside the activating extend.
struct Probe<L> {
    inner: L,
    raise_sigint_on_activation: bool,
    activation_began_ns: Option<u64>,
    exec_coverage_ns: Option<u64>,
    reads: Vec<ReadStamp>,
    row_tgids: Vec<u32>,
    stop_began: Option<Instant>,
    /// Begin-stop to retired: the measured kernel detach time.
    retired_after: Option<Duration>,
}

impl<L> Probe<L> {
    fn new(inner: L) -> Self {
        Self {
            inner,
            raise_sigint_on_activation: false,
            activation_began_ns: None,
            exec_coverage_ns: None,
            reads: Vec::new(),
            row_tgids: Vec::new(),
            stop_began: None,
            retired_after: None,
        }
    }
}

impl<L: CaptureLane<PidPin>> NativeIdentity<PidPin> for Probe<L> {
    fn owner_image(&mut self, pid: u32) -> Option<ImageIdentity> {
        self.inner.owner_image(pid)
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        self.inner.query_cookie(domain, pin)
    }
}

impl<L: CaptureLane<PidPin>> CaptureLane<PidPin> for Probe<L> {
    fn domain(&self) -> NativeDomainId {
        self.inner.domain()
    }

    fn incarnation(&self) -> Option<ScopeIncarnation> {
        self.inner.incarnation()
    }

    fn extend(
        &mut self,
        delta: TargetDelta,
        targets: &dyn CaptureTargets,
        window: ExtendWindow,
    ) -> ExtendReceipt {
        if self.activation_began_ns.is_none() {
            self.activation_began_ns = Some(now_ns());
            if self.raise_sigint_on_activation {
                // SAFETY: raising a signal whose handler is installed.
                unsafe {
                    libc::raise(libc::SIGINT);
                }
            }
        }
        let receipt = self.inner.extend(delta, targets, window);
        if let Some(coverage) = receipt.exec_coverage {
            self.exec_coverage_ns = Some(coverage.start_ns());
        }
        receipt
    }

    fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        self.inner.service_discovery(window)
    }

    fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        let before_ns = now_ns();
        let batch = self.inner.read_witnesses(window);
        let after_ns = now_ns();
        self.row_tgids
            .extend(batch.rows.iter().map(|row| row.host_tgid));
        self.reads.push(ReadStamp {
            before_ns,
            after_ns,
            health_read_ns: batch.health_read_ns,
            rows_read_ns: batch.rows_read_ns,
            max_recorded_ns: batch.rows.iter().map(|row| row.recorded_at_ns).max(),
        });
        batch
    }

    fn begin_stop(&mut self) {
        self.stop_began = Some(Instant::now());
        self.inner.begin_stop();
    }

    fn poll_retirement(&mut self, deadline: Instant) -> Result<bool> {
        let retired = self.inner.poll_retirement(deadline);
        if matches!(retired, Ok(true)) && self.retired_after.is_none() {
            self.retired_after = self.stop_began.map(|began| began.elapsed());
        }
        retired
    }

    fn cleanup(&self) -> Option<CleanupSummary> {
        self.inner.cleanup()
    }
}

fn pid_coordinator(pid: u32, module: &Path) -> Result<InventoryCoordinator<OsProcessSource>> {
    InventoryCoordinator::new(
        Scope::Pid(pid),
        HookRegistry::builtin(),
        vec![module.to_path_buf()],
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
}

fn pid_probe(
    pid: u32,
    coordinator: &InventoryCoordinator<OsProcessSource>,
) -> Result<Probe<FacadeLane>> {
    let pin = PidPin::open(pid).map_err(anyhow::Error::msg)?;
    Ok(Probe::new(FacadeLane::prepare(
        crate::attach::capture::CaptureScope::Pid(pin),
        coordinator.attach_set().budget(),
    )?))
}

/// The caller incarnation of `pid` and its edge coverage (one edge).
fn edge_coverage(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    pid: u32,
) -> Result<Vec<UseCoverage>> {
    let callers: Vec<_> = coordinator
        .adapter()
        .records()
        .filter(|record| record.pid == pid)
        .map(|record| record.id)
        .collect();
    ensure!(!callers.is_empty(), "pid {pid} was never admitted");
    let registry = coordinator.registry();
    Ok(registry
        .edges()
        .filter(|edge| callers.contains(&edge.caller))
        .map(|edge| registry.coverage(edge))
        .collect())
}

/// Drives the production classic loop (`ClassicDriver` + `run_classic`) over
/// `lane`: `on_pass(pass)` runs after every committed pass and says whether
/// to stop.
fn drive<L: CaptureLane<PidPin>>(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    scope: InspectScope,
    lane: NativeLane<L>,
    on_pass: &mut dyn FnMut(u64) -> Result<bool>,
) -> Result<Stopped<L>> {
    let inventory_scope = match scope {
        InspectScope::Pid(pid) => InventoryScope::Pid(pid),
        InspectScope::System => InventoryScope::System,
    };
    let deadline = Some(Instant::now() + Duration::from_secs(120));
    let mut driver = ClassicDriver {
        coordinator,
        inventory_scope: &inventory_scope,
        scope,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline,
    };
    let stop = Cell::new(false);
    let stop_now = || stop.get();
    let clock = LoopClock {
        deadline,
        stop: &stop_now,
        interval: Duration::from_millis(300),
        tick: SERVICE_TICK,
    };
    let stopped = run_classic(
        &mut driver,
        Some(lane),
        &clock,
        &mut |driver: &mut ClassicDriver<'_>, point| {
            if let Publish::Pass { .. } = point {
                stop.set(on_pass(driver.coordinator.passes())?);
            }
            Ok(())
        },
    )?;
    stopped.context("a native run stops its lane")
}

/// C5.1 cell 1: PID scope through the production loop. The two facade stamp
/// sites no unit test reaches hold (exec coverage stamped after activation
/// began; every read's `rows_read_ns` after its sweep), the ledgered caller's
/// edge is witnessed, and a foreign caller of the same provider never
/// appears.
#[test]
#[ignore = "root-owned live BPF lane; native lane --pid: stamps, witnessed edge, no foreign caller"]
fn privileged_native_lane_pid_lp64() -> Result<()> {
    let workload = Workload::build()?;
    let gate = workload.path("gate");
    let gate_arg = gate.to_str().context("gate path")?.to_string();
    let target = workload.spawn(
        "target",
        &[
            "mech", "--cell", "T", "--module", SOFTHSM, "--iters", "2", "--gate", &gate_arg,
            "--hold",
        ],
    )?;
    let foreign = workload.spawn(
        "foreign",
        &[
            "mech", "--cell", "F", "--module", SOFTHSM, "--iters", "2", "--gate", &gate_arg,
            "--hold",
        ],
    )?;
    let mut coordinator = pid_coordinator(target.pid(), Path::new(SOFTHSM))?;
    let probe = pid_probe(target.pid(), &coordinator)?;
    let lane = NativeLane::start(probe, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| anyhow::anyhow!("{reason}"))?;
    let done_at = Cell::new(None::<u64>);
    let stopped = drive(
        &mut coordinator,
        InspectScope::Pid(target.pid()),
        lane,
        &mut |passes| {
            // The first pass absorbs and attaches; open the gate after it.
            if passes >= 2 && !gate.exists() {
                std::fs::write(&gate, b"")?;
            }
            if done_at.get().is_none() && target.has("DONE ") && foreign.has("DONE ") {
                done_at.set(Some(passes));
            }
            Ok(done_at.get().is_some_and(|at| passes >= at + 2) || passes >= 60)
        },
    )?;
    ensure!(done_at.get().is_some(), "the ledgers never finished");
    let probe = &stopped.capture;
    let began = probe.activation_began_ns.context("no activation")?;
    let coverage_ns = probe.exec_coverage_ns.context("no exec coverage stamp")?;
    ensure!(
        coverage_ns > began,
        "exec coverage {coverage_ns} not after activation began {began}"
    );
    ensure!(probe.reads.len() >= 4, "{:?}", probe.reads);
    for read in &probe.reads {
        ensure!(
            read.before_ns < read.rows_read_ns
                && read.rows_read_ns <= read.after_ns
                && read.health_read_ns < read.rows_read_ns
                && read
                    .max_recorded_ns
                    .is_none_or(|recorded| recorded < read.rows_read_ns),
            "rows_read_ns is not stamped after the sweep: {read:?}"
        );
    }
    ensure!(!probe.row_tgids.is_empty(), "no witness row at all");
    ensure!(
        probe.row_tgids.iter().all(|tgid| *tgid == target.pid()),
        "a foreign tgid reached the PID-scoped lane: {:?} (target {})",
        probe.row_tgids,
        target.pid()
    );
    let coverage = edge_coverage(&coordinator, target.pid())?;
    ensure!(
        coverage.len() == 1 && coverage[0].is_witnessed(),
        "{coverage:?}"
    );
    ensure!(
        coordinator
            .adapter()
            .records()
            .all(|record| record.pid != foreign.pid()),
        "the foreign caller was admitted"
    );
    let census = coordinator.registry().witness_census().clone();
    ensure!(
        census.bound >= 1 && census.pending == 0,
        "census: {census:?}"
    );
    ensure!(
        matches!(stopped.summary.retirement, Retirement::Closed(ref cleanup) if cleanup.failures.is_empty()),
        "{:?}",
        stopped.summary
    );
    eprintln!(
        "C51_PID target={} foreign={} passes={} reads={} rows={} bound={} unbound={} \
         coverage_after_activation_ns={} attached={} retired_ms={:?}",
        target.pid(),
        foreign.pid(),
        stopped.summary.passes,
        probe.reads.len(),
        probe.row_tgids.len(),
        census.bound,
        census.unbound_total(),
        coverage_ns - began,
        stopped.summary.attached,
        probe.retired_after.map(|after| after.as_millis()),
    );
    Ok(())
}

/// One production run through `run_with_writer` with `--json` and an event
/// log; `stop` is polled every service tick.
fn run_product(
    scope: InspectScope,
    module: &Path,
    events: &Path,
    stop: &dyn Fn() -> bool,
) -> Result<(serde_json::Value, String)> {
    let mut stdout = Vec::new();
    let reported = std::cell::Cell::new(None::<Instant>);
    let code = run_with_writer(
        scope,
        &[module.to_path_buf()],
        &HookRegistry::builtin(),
        true,
        None,
        None,
        Some(Duration::from_secs(120)),
        None,
        false,
        Some(events),
        Some(1 << 30),
        None,
        CaptureMode::Native,
        stop,
        &|| reported.set(Some(Instant::now())),
        false,
        &mut stdout,
    )?;
    // Evidence for DR-C51-DETACH: the blocking detach after the report.
    if let Some(at) = reported.get() {
        eprintln!(
            "p11scope-cell: blocking detach after the report took {} ms",
            at.elapsed().as_millis()
        );
    }
    ensure!(code == 0, "exit code {code}");
    let document: serde_json::Value = serde_json::from_slice(&stdout)?;
    Ok((document, std::fs::read_to_string(events)?))
}

/// The edges of every caller of `pid`, with their coverage objects.
fn doc_edges(document: &serde_json::Value, pid: u32) -> Vec<&serde_json::Value> {
    let ids: Vec<&str> = document["callers"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|caller| caller["pid"] == pid)
        .filter_map(|caller| caller["id"].as_str())
        .collect();
    document["edges"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|edge| edge["caller"].as_str().is_some_and(|id| ids.contains(&id)))
        .collect()
}

fn stream_ended(stream: &str) -> bool {
    stream
        .lines()
        .last()
        .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .is_some_and(|line| line["kind"] == "ended")
}

/// C5.1 cell 2: `--system`, production path. A process that dlopens the
/// provider only after the capture started (late, past several passes) is
/// admitted, its provider absorbed and attached by a later extend, and its
/// calls witnessed against its own incarnation.
#[test]
#[ignore = "root-owned live BPF lane; native lane --system witnesses a late dlopen"]
fn privileged_native_lane_system_late_dlopen_lp64() -> Result<()> {
    let workload = Workload::build()?;
    let gate = workload.path("gate");
    let gate_arg = gate.to_str().context("gate path")?.to_string();
    let late = workload.spawn(
        "late",
        &[
            "mech",
            "--late",
            "--cell",
            "P7",
            "--module",
            SOFTHSM,
            "--iters",
            "2",
            "--gate",
            &gate_arg,
            "--delay-ms",
            "2500",
            "--hold",
        ],
    )?;
    ensure!(!late.has("MAPPED "), "the late cell mapped before its gate");
    let started = Instant::now();
    let done_at = RefCell::new(None::<Instant>);
    let stop = || {
        if started.elapsed() > Duration::from_secs(3) && !gate.exists() {
            let _ = std::fs::write(&gate, b"");
        }
        if done_at.borrow().is_none() && late.has("DONE ") {
            *done_at.borrow_mut() = Some(Instant::now());
        }
        done_at
            .borrow()
            .is_some_and(|at| at.elapsed() > Duration::from_secs(3))
            || started.elapsed() > Duration::from_secs(90)
    };
    let events = workload.path("system.jsonl");
    let (document, stream) = run_product(InspectScope::System, Path::new(SOFTHSM), &events, &stop)?;
    ensure!(done_at.borrow().is_some(), "the late ledger never finished");
    ensure!(
        document["observation"]["lane"] == "native",
        "{}",
        document["observation"]
    );
    ensure!(document["observation"]["settlement"] == "unsettled");
    // R-C51-4 bounds the pre-report detach wait to 10 s; a system scope's
    // detach (136 endpoints here) can outlast it on a loaded host. Then
    // the report must say so: retirement unsettled with its gap.
    let retirement = &document["observation"]["retirement"];
    ensure!(
        retirement == "closed"
            || (retirement == "unsettled"
                && document["gaps"].as_array().is_some_and(|gaps| {
                    gaps.iter()
                        .any(|gap| gap["subject"] == "native capture retirement unsettled")
                })),
        "{}",
        document["observation"]
    );
    let edges = doc_edges(&document, late.pid());
    let witnesses = &document["observation"]["native_witnesses"];
    ensure!(edges.len() == 1, "late dlopen edges: {edges:?}");
    let state = &edges[0]["entries"]["coverage"]["state"];
    // Host exec churn can overflow the DISCOVERY ring while a system pass
    // scans (no servicing then): the late caller's row is then honestly
    // `lifecycle_loss`, and its watch must not claim absence (the C5.2
    // demotion, gap `native capture lifecycle evidence lost`).
    let lifecycle_lost = witnesses["unbound_reasons"].get("lifecycle_loss").is_some()
        || document["gaps"].as_array().is_some_and(|gaps| {
            gaps.iter()
                .any(|gap| gap["subject"] == "native capture lifecycle evidence lost")
        });
    if lifecycle_lost {
        // R-C51-3: witnessed, or unknown with reason `loss` — never a
        // watch, never another unknown reason (review F6).
        let reason = &edges[0]["entries"]["coverage"]["reason"];
        ensure!(
            *state == "witnessed" || (*state == "unknown" && *reason == "loss"),
            "under lost lifecycle evidence the edge must read witnessed or unknown/loss: \
             {edges:?}; witnesses {witnesses}"
        );
        eprintln!("C51_LATE_LIFECYCLE_LOSS state={state} witnesses={witnesses}");
    } else {
        ensure!(
            *state == "witnessed",
            "late dlopen edge: {edges:?}; witnesses {witnesses}; ledger {:?}",
            late.lines()
        );
    }
    ensure!(
        witnesses["unbound_reasons"]
            .get("exec_coverage_gap")
            .is_none(),
        "{witnesses}"
    );
    ensure!(stream_ended(&stream), "the stream did not end");
    eprintln!(
        "C51_LATE pid={} passes={} witnesses={witnesses}",
        late.pid(),
        document["observation"]["passes"]
    );
    Ok(())
}

/// C5.1 cell 3: a call held in the provider across the stop. Retirement still
/// closes within its budget (detach does not wait for the call), the run
/// reads `settlement: unsettled`, the held call's entry is witnessed, and
/// the call returns only after the harness releases it.
#[test]
#[ignore = "root-owned live BPF lane; native lane stop with a held call reads unsettled"]
fn privileged_native_lane_stop_held_call_unsettled_lp64() -> Result<()> {
    let workload = Workload::build()?;
    let release = workload.path("release");
    let fifo = std::ffi::CString::new(release.to_str().context("release path")?)?;
    // SAFETY: a valid NUL-terminated path.
    ensure!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0, "mkfifo");
    let gate = workload.path("gate6");
    let gate_arg = gate.to_str().context("gate path")?.to_string();
    let held_arg = workload.held.to_str().context("held path")?.to_string();
    let held = workload.spawn(
        "held",
        &[
            "held", "--cell", "P6", "--module", &held_arg, "--gate", &gate_arg,
        ],
    )?;
    let started = Instant::now();
    let held_at = RefCell::new(None::<Instant>);
    let stop = || {
        if started.elapsed() > Duration::from_secs(3) && !gate.exists() {
            let _ = std::fs::write(&gate, b"");
        }
        if held_at.borrow().is_none() && held.has("HELD ") {
            *held_at.borrow_mut() = Some(Instant::now());
        }
        held_at
            .borrow()
            .is_some_and(|at| at.elapsed() > Duration::from_secs(3))
            || started.elapsed() > Duration::from_secs(60)
    };
    let events = workload.path("stop.jsonl");
    let stop_began = Cell::new(None::<Instant>);
    let observed = || {
        let stopping = stop();
        if stopping && stop_began.get().is_none() {
            stop_began.set(Some(Instant::now()));
        }
        stopping
    };
    let (document, stream) = run_product(
        InspectScope::Pid(held.pid()),
        &workload.held,
        &events,
        &observed,
    )?;
    let stop_latency = stop_began.get().map(|at| at.elapsed());
    ensure!(held_at.borrow().is_some(), "the call was never held");
    ensure!(
        !held.has("RETURNED "),
        "the held call returned before release"
    );
    ensure!(document["observation"]["settlement"] == "unsettled");
    ensure!(
        document["observation"]["retirement"] == "closed",
        "{}",
        document["observation"]
    );
    let edges = doc_edges(&document, held.pid());
    ensure!(
        edges.len() == 1 && edges[0]["entries"]["coverage"]["state"] == "witnessed",
        "held-call edge: {edges:?}"
    );
    ensure!(stream_ended(&stream), "the stream did not end");
    // Only now may the held call return.
    let file = std::fs::OpenOptions::new().write(true).open(&release)?;
    drop(file);
    held.wait_for("RETURNED ", Duration::from_secs(10))?;
    eprintln!(
        "C51_HELD pid={} stop_to_exit={stop_latency:?} witnesses={}",
        held.pid(),
        document["observation"]["native_witnesses"]
    );
    Ok(())
}

/// C5.1 cell 4: SIGINT arrives during the activating extend (the real signal
/// through the production stop flag). The run still makes one full pass
/// after activation, stops through the bounded stop, and retires cleanly.
#[test]
#[ignore = "root-owned live BPF lane; SIGINT during activation still gets one full pass"]
fn privileged_native_lane_sigint_during_extend_lp64() -> Result<()> {
    let workload = Workload::build()?;
    let target = workload.spawn(
        "target",
        &[
            "mech", "--cell", "S", "--module", SOFTHSM, "--iters", "2", "--hold",
        ],
    )?;
    target.wait_for("DONE ", Duration::from_secs(30))?;
    let mut coordinator = pid_coordinator(target.pid(), Path::new(SOFTHSM))?;
    let mut probe = pid_probe(target.pid(), &coordinator)?;
    probe.raise_sigint_on_activation = true;
    let flag = StopFlag::install();
    let lane = NativeLane::start(probe, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| anyhow::anyhow!("{reason}"))?;
    ensure!(
        flag.stopped(),
        "SIGINT during activation did not reach the stop flag"
    );
    let inventory_scope = InventoryScope::Pid(target.pid());
    let deadline = Some(Instant::now() + Duration::from_secs(120));
    let mut driver = ClassicDriver {
        coordinator: &mut coordinator,
        inventory_scope: &inventory_scope,
        scope: InspectScope::Pid(target.pid()),
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline,
    };
    let stop = || flag.stopped();
    let clock = LoopClock {
        deadline,
        stop: &stop,
        interval: POLL_INTERVAL,
        tick: SERVICE_TICK,
    };
    let began = Instant::now();
    let stopped = run_classic(&mut driver, Some(lane), &clock, &mut |_, _| Ok(()))?
        .context("a native run stops its lane")?;
    let elapsed = began.elapsed();
    ensure!(stopped.summary.passes == 1, "{:?}", stopped.summary);
    ensure!(coordinator.passes() == 1);
    ensure!(
        matches!(stopped.summary.retirement, Retirement::Closed(_)),
        "{:?}",
        stopped.summary
    );
    let probe = &stopped.capture;
    // Pass read, terminal read, last read.
    ensure!(probe.reads.len() == 3, "{:?}", probe.reads);
    let coverage = edge_coverage(&coordinator, target.pid())?;
    if coverage.is_empty() {
        bail!("the one pass mapped no edge");
    }
    eprintln!(
        "C51_SIGINT pid={} loop_ms={} coverage={coverage:?}",
        target.pid(),
        elapsed.as_millis()
    );
    Ok(())
}
