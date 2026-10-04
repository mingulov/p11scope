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
use crate::inventory_capture::{CaptureLane, Retirement, RetirementLoad, Stopped};
use anyhow::{bail, ensure};
use p11scope_ebpf_common::ImageIdentity;
use std::cell::{Cell, RefCell};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;

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
    /// Endpoints attached so far, shared with the pass callback.
    attached: Rc<Cell<usize>>,
    /// Summed attach wall time over every extend.
    attach_ns: u64,
    /// The longest single attach (one link: an entry or a group).
    attach_ns_max: u64,
    /// The longest one extend spent attaching.
    extend_attach_ns_max: u64,
    /// The kernel links the capture held when the stop began.
    links_at_stop: Option<usize>,
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
            attached: Rc::default(),
            attach_ns: 0,
            attach_ns_max: 0,
            extend_attach_ns_max: 0,
            links_at_stop: None,
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

    fn backend(&self) -> crate::inventory_capture::LaneBackend {
        self.inner.backend()
    }

    fn live_links(&self) -> Option<usize> {
        self.inner.live_links()
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
        self.attached
            .set(self.attached.get() + receipt.attached.len());
        self.attach_ns += receipt.attach_ns_total;
        self.attach_ns_max = self.attach_ns_max.max(receipt.attach_ns_max);
        self.extend_attach_ns_max = self.extend_attach_ns_max.max(receipt.attach_ns_total);
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
        self.links_at_stop = self.inner.live_links();
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
        crate::attach::BackendSelection::Auto,
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
        display: None,
    };
    let stop = Cell::new(false);
    let stop_now = || stop.get();
    let clock = LoopClock {
        deadline,
        stop: &stop_now,
        interval: Duration::from_millis(300),
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
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
    // C5.11: `auto` takes uprobe-multi under PID scope exactly where the
    // pid-filter probe proves the kernel filter, and discloses the filter.
    let backend = &stopped.summary.backend;
    let expected = if crate::attach::kernel_multi_pid_filter().is_ok() {
        (
            crate::attach::AttachBackend::Multi,
            crate::inventory_capture::ScopeFilter::KernelPidAndBpf,
        )
    } else {
        (
            crate::attach::AttachBackend::Singles,
            crate::inventory_capture::ScopeFilter::PerfTaskAndBpf,
        )
    };
    ensure!(
        (backend.backend, backend.scope_filter) == expected,
        "{backend:?}"
    );
    eprintln!(
        "C51_PID mechanism={} scope_filter={:?} fallback={:?}",
        backend.mechanism(),
        backend.scope_filter.label(),
        backend.fallback
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

/// A pty pair for the slow-terminal cell: the master is the terminal the
/// cell never reads during the stall.
fn open_pty(cols: u16, rows: u16) -> Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::FromRawFd as _;
    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `openpty` writes two fresh fds; the other pointers may be null.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    ensure!(opened == 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: fresh descriptors owned from here on.
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    })
}

/// C5.3 cell: the native lane under the interactive dashboard on a
/// terminal that is never read for 20 s. The ledger calls the provider
/// during the stall. The capture must not notice the terminal: the longest
/// gap between service ticks stays under 100 ms, passes keep their 1 s
/// cadence, the calls are witnessed, no lifecycle record is lost (idle
/// host), and the frames the terminal did not take are shed and counted.
/// After the stop the terminal reads again: the screen is restored and the
/// report is written before any detach (R-C51-4).
#[test]
#[ignore = "root-owned live BPF lane; native lane under the dashboard on a stalled pty"]
fn privileged_native_lane_dashboard_slow_pty_lp64() -> Result<()> {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;
    let workload = Workload::build()?;
    let gate = workload.path("gate");
    let gate_arg = gate.to_str().context("gate path")?.to_string();
    let target = workload.spawn(
        "target",
        &[
            "mech", "--cell", "D", "--module", SOFTHSM, "--iters", "4", "--gate", &gate_arg,
            "--hold",
        ],
    )?;
    let (master, slave) = open_pty(200, 60)?;
    let stall = Duration::from_secs(20);
    let started = Instant::now();
    let stop_at = RefCell::new(None::<Instant>);
    let drainer = RefCell::new(None::<std::thread::JoinHandle<Vec<u8>>>);
    let master = RefCell::new(Some(master));
    let events = workload.path("dashboard.jsonl");
    // The window is anchored at the lane's first committed pass (review
    // point 6), not at the test start: scan, prepare and activation (about
    // 7.5 s in a vng guest) are not the lane's cadence. The terminal is
    // never read until the stop either way.
    let anchor = Cell::new(None::<Instant>);
    let stop = || {
        if anchor.get().is_none() {
            if std::fs::read_to_string(&events)
                .is_ok_and(|text| text.contains("\"kind\":\"pass_committed\""))
            {
                anchor.set(Some(Instant::now()));
            } else if started.elapsed() < Duration::from_secs(90) {
                return false;
            }
        }
        let active = anchor.get().map_or(stall, |at| at.elapsed());
        // The ledger calls in the middle of the stall.
        if active > Duration::from_secs(8) && !gate.exists() {
            let _ = std::fs::write(&gate, b"");
        }
        if active < stall {
            return false;
        }
        if stop_at.borrow().is_none() {
            *stop_at.borrow_mut() = Some(Instant::now());
            // The terminal reads again from the stop on.
            if let Some(mut master) = master.borrow_mut().take() {
                *drainer.borrow_mut() = Some(std::thread::spawn(move || {
                    let mut seen = Vec::new();
                    let mut chunk = [0u8; 65536];
                    while let Ok(read) = master.read(&mut chunk) {
                        if read == 0 {
                            break;
                        }
                        seen.extend_from_slice(&chunk[..read]);
                    }
                    seen
                }));
            }
        }
        true
    };
    let account = std::rc::Rc::new(Cell::new(None::<DisplayAccount>));
    let terminal = DashboardIo {
        output: slave.as_raw_fd(),
        input: None,
        account: Some(std::rc::Rc::clone(&account)),
        stderr_fd: 2,
        stderr: StderrRoute::Capture,
    };
    let reported = Cell::new(None::<Instant>);
    let mut stdout = Vec::new();
    let code = run_with_terminal(
        InspectScope::Pid(target.pid()),
        &[PathBuf::from(SOFTHSM)],
        &HookRegistry::builtin(),
        true,
        None,
        None,
        Some(Duration::from_secs(120)),
        None,
        true,
        Some(&events),
        Some(1 << 30),
        None,
        CaptureMode::Native,
        crate::attach::BackendSelection::Auto,
        &stop,
        &|| reported.set(Some(Instant::now())),
        true,
        &mut stdout,
        &terminal,
    )?;
    drop(slave);
    let seen = drainer
        .borrow_mut()
        .take()
        .context("the stop never started the drainer")?
        .join()
        .map_err(|_| anyhow::anyhow!("the drainer panicked"))?;
    ensure!(code == 0, "exit code {code}");
    let stop_at = stop_at.borrow().context("never stopped")?;
    let to_report = reported.get().context("no report")? - stop_at;
    let account = account.get().context("no display account")?;
    let document: serde_json::Value = serde_json::from_slice(&stdout)?;
    let stream = std::fs::read_to_string(&events)?;
    ensure!(target.has("DONE "), "the ledger never finished");
    ensure!(
        account.terminal.frames_shed > 0,
        "the stall never bit: {account:?}"
    );
    // A loaded host declares its slowness through P11SCOPE_TEST_TIME_SCALE
    // (default 1: the literal bounds); it scales the tick-gap bound and
    // the pass floor below, nothing else.
    let scale = test_time_scale()?;
    let tick_bound = Duration::from_millis(100).mul_f64(scale);
    ensure!(
        account.longest_gap < tick_bound,
        "a service tick waited on the terminal (bound {tick_bound:?}, time scale {scale}): \
         {account:?}"
    );
    // Across a pass the gap also carries the pass's own work (the first
    // pass attaches every endpoint, within its 250 ms extend window).
    ensure!(
        account.longest_pass_gap < Duration::from_secs(1),
        "a pass lost its cadence: {account:?}"
    );
    ensure!(
        account.terminal.restored,
        "screen not restored: {account:?}"
    );
    let restore = b"\x1b[?25h\x1b[?1049l";
    ensure!(
        seen.windows(restore.len()).any(|window| window == restore),
        "the restore never reached the terminal"
    );
    // The cadence proper is the pass-gap (< 1 s) and tick-gap (< 100 ms)
    // checks above; the count only catches a stalled loop: three quarters
    // of the active seconds, at least 12 (15 for the nominal 20 s).
    let anchor = anchor.get().context("the lane never committed a pass")?;
    let active_secs = stop_at.saturating_duration_since(anchor).as_secs_f64();
    let required = ((12.0 / scale).floor() as u64).max((0.75 * active_secs / scale).floor() as u64);
    let passes = document["observation"]["passes"].as_u64().unwrap_or(0);
    ensure!(
        passes >= required,
        "passes kept no cadence: {passes} in {active_secs:.1} s active (need {required})"
    );
    ensure!(document["observation"]["lane"] == "native");
    ensure!(
        document["observation"]["retirement"] == "closed",
        "{}",
        document["observation"]
    );
    // R-C51-4: the report within the 10 s pre-output bound of the stop.
    ensure!(
        to_report < Duration::from_secs(12),
        "stop to report took {to_report:?}"
    );
    let edges = doc_edges(&document, target.pid());
    ensure!(
        edges.len() == 1 && edges[0]["entries"]["coverage"]["state"] == "witnessed",
        "the calls during the stall were not witnessed: {edges:?}"
    );
    let witnesses = &document["observation"]["native_witnesses"];
    ensure!(
        witnesses["unbound_reasons"].get("lifecycle_loss").is_none()
            && !document["gaps"].as_array().is_some_and(|gaps| {
                gaps.iter()
                    .any(|gap| gap["subject"] == "native capture lifecycle evidence lost")
            }),
        "lifecycle evidence lost on an idle host: {witnesses}"
    );
    ensure!(stream_ended(&stream), "the stream did not end");
    eprintln!(
        "C53_SLOW_PTY pid={} passes={passes} required={required} active_s={active_secs:.1} \
         time_scale={scale} \
         startup_ms={} ticks={} longest_gap_ms={} written={} shed={} \
         cut={} shed_bytes={} stall_ms={} restored={} stop_to_report_ms={} \
         longest_pass_gap_ms={} witnesses={witnesses}",
        target.pid(),
        anchor.saturating_duration_since(started).as_millis(),
        account.ticks,
        account.longest_gap.as_millis(),
        account.terminal.frames_written,
        account.terminal.frames_shed,
        account.terminal.frames_cut,
        account.terminal.bytes_shed,
        account.terminal.stall_ms,
        account.terminal.restored,
        to_report.as_millis(),
        account.longest_pass_gap.as_millis(),
    );
    Ok(())
}

/// `P11SCOPE_TEST_TIME_SCALE` (default 1, at least 1): how much slower than
/// nominal a loaded host declares itself, the same variable the Python
/// harnesses and `tests/artifact_contracts.rs` read. Cells that scale a
/// bound by it say which; with the default every bound is literal.
fn test_time_scale() -> Result<f64> {
    let scale = match std::env::var("P11SCOPE_TEST_TIME_SCALE") {
        Ok(raw) if !raw.trim().is_empty() => raw.trim().parse::<f64>().unwrap_or(f64::NAN),
        _ => 1.0,
    };
    ensure!(
        scale.is_finite() && scale >= 1.0,
        "P11SCOPE_TEST_TIME_SCALE must be a finite number >= 1"
    );
    Ok(scale)
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
        crate::attach::BackendSelection::Auto,
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
    // Host exec churn can still overflow the DISCOVERY ring in a window the
    // lane does not service (C5.7 services it while a pass collects, not
    // while the scan applies or the extend attaches): the late caller's row
    // is then honestly
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
        display: None,
    };
    let stop = || flag.stopped();
    let clock = LoopClock {
        deadline,
        stop: &stop,
        interval: POLL_INTERVAL,
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
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

/// One `exec_churn` run's SUMMARY fields.
fn churn_summary(ledger: &Path) -> Result<BTreeMap<String, f64>> {
    let text = std::fs::read_to_string(ledger)?;
    let line = text
        .lines()
        .find(|line| line.starts_with("SUMMARY "))
        .context("exec_churn wrote no SUMMARY")?;
    Ok(line
        .split_whitespace()
        .skip(1)
        .filter_map(|field| field.split_once('='))
        .filter_map(|(key, value)| Some((key.to_string(), value.parse().ok()?)))
        .collect())
}

/// One churn phase: a production `--system` native run while `exec_churn`
/// forks `rate` /bin/true execs per second (unrelated to any provider) for
/// `seconds`, beside an idle process that maps SoftHSM2 and never calls it
/// (a watch to demote). Returns the document and the churn's SUMMARY.
fn churn_phase(
    workload: &Workload,
    churn: &Path,
    rate: u32,
    seconds: u32,
) -> Result<(serde_json::Value, BTreeMap<String, f64>, u32)> {
    let mut mapper = Command::new("sleep")
        .arg("600")
        .env("LD_PRELOAD", SOFTHSM)
        .env("SOFTHSM2_CONF", &workload.conf)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
        .context("spawning the idle mapper")?;
    let mapper_pid = mapper.id();
    let ledger = workload.path(&format!("churn-{rate}.ledger"));
    let child = RefCell::new(None::<Child>);
    let ended = Cell::new(None::<Instant>);
    let started = Instant::now();
    let stop = || {
        // Churn from the first service tick on (the capture is active).
        if child.borrow().is_none() && ended.get().is_none() {
            match Command::new(churn)
                .args([rate.to_string(), seconds.to_string(), "0".into()])
                .arg(&ledger)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .spawn()
            {
                Ok(spawned) => *child.borrow_mut() = Some(spawned),
                Err(_) => ended.set(Some(Instant::now())),
            }
        }
        if ended.get().is_none()
            && let Some(running) = child.borrow_mut().as_mut()
            && !matches!(running.try_wait(), Ok(None))
        {
            ended.set(Some(Instant::now()));
        }
        // Two more seconds of passes after the churn, then stop.
        ended
            .get()
            .is_some_and(|at| at.elapsed() > Duration::from_secs(2))
            || started.elapsed() > Duration::from_secs(u64::from(seconds) + 60)
    };
    let events = workload.path(&format!("churn-{rate}.jsonl"));
    let result = run_product(InspectScope::System, Path::new(SOFTHSM), &events, &stop);
    if let Some(mut running) = child.borrow_mut().take() {
        let _ = running.kill();
        let _ = running.wait();
    }
    let _ = mapper.kill();
    let _ = mapper.wait();
    let (document, stream) = result?;
    ensure!(stream_ended(&stream), "the stream did not end");
    Ok((document, churn_summary(&ledger)?, mapper_pid))
}

/// The host's 1-minute load average.
fn load1() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse().ok())
        .unwrap_or(f64::INFINITY)
}

/// What one churn phase showed: its loss (ring loss, malformed records and
/// failed quanta together), whether the loss gap was recorded, and the
/// idle mapper's edges as `state/reason`.
struct ChurnOutcome {
    achieved: f64,
    loss: u64,
    records: u64,
    lost_gap: bool,
    mapper: Vec<(String, String)>,
    load1: f64,
    line: String,
}

fn churn_outcome(
    workload: &Workload,
    churn: &Path,
    rate: u32,
    seconds: u32,
) -> Result<ChurnOutcome> {
    let load1 = load1();
    let began = Instant::now();
    let (document, summary, mapper_pid) = churn_phase(workload, churn, rate, seconds)?;
    let minutes = began.elapsed().as_secs_f64() / 60.0;
    let observation = &document["observation"];
    ensure!(observation["lane"] == "native", "{observation}");
    let lifecycle = &observation["lifecycle"];
    let count = |key: &str| lifecycle[key].as_u64().context(format!("lifecycle {key}"));
    let ring_loss = count("ring_loss")?;
    let loss = ring_loss + count("malformed")? + count("failed_quanta")?;
    let records = count("records")?;
    let execs = summary.get("execs").copied().unwrap_or(0.0);
    let achieved = summary.get("achieved_rate").copied().unwrap_or(0.0);
    // Every churn exec is an exec record plus a leader-exit record.
    ensure!(
        loss > 0 || records as f64 >= 2.0 * execs * 0.95,
        "{records} lifecycle records for {execs} execs and no loss: {lifecycle}"
    );
    let lost_gap = document["gaps"].as_array().is_some_and(|gaps| {
        gaps.iter()
            .any(|gap| gap["subject"] == "native capture lifecycle evidence lost")
    });
    let mapper: Vec<(String, String)> = doc_edges(&document, mapper_pid)
        .iter()
        .map(|edge| {
            let coverage = &edge["entries"]["coverage"];
            (
                coverage["state"].as_str().unwrap_or("?").to_string(),
                coverage["reason"].as_str().unwrap_or("-").to_string(),
            )
        })
        .collect();
    // The positive control: the idle mapper was admitted and its provider
    // edge exists in every phase, or nothing below proves anything.
    ensure!(
        !mapper.is_empty(),
        "the idle mapper (pid {mapper_pid}) has no edge: the cell would pass vacuously"
    );
    let line = format!(
        "rate={rate} achieved={achieved} execs={execs} load1={load1:.2} passes={} \
         records={records} ring_loss={ring_loss} loss={loss} loss_per_min={:.0} \
         recovery_rescans={} lost_gap={lost_gap} mapper_edges={mapper:?}",
        observation["passes"],
        loss as f64 / minutes,
        lifecycle["recovery_rescans"],
    );
    Ok(ChurnOutcome {
        achieved,
        loss,
        records,
        lost_gap,
        mapper,
        load1,
        line,
    })
}

/// No loss: no loss gap, and the idle mapper's every edge is a real watch.
fn ensure_lossless(outcome: &ChurnOutcome) -> Result<()> {
    ensure!(
        !outcome.lost_gap,
        "a lifecycle-loss gap without a counted loss: {}",
        outcome.line
    );
    ensure!(
        outcome
            .mapper
            .iter()
            .all(|(state, _)| state == "watched_no_use"),
        "with no loss the idle mapper must read watched_no_use: {}",
        outcome.line
    );
    Ok(())
}

/// A loss: its gap is recorded and the idle mapper's every edge is demoted
/// to unknown/loss, never a watch over the loss.
fn ensure_honest_loss(outcome: &ChurnOutcome) -> Result<()> {
    ensure!(outcome.lost_gap, "a loss without its gap: {}", outcome.line);
    ensure!(
        outcome
            .mapper
            .iter()
            .all(|(state, reason)| state == "unknown" && reason == "loss"),
        "under a lifecycle loss the idle mapper must read unknown/loss: {}",
        outcome.line
    );
    Ok(())
}

/// C5.7 (DR-C3-1, M4): exec-only host churn against the native `--system`
/// lane, beside an idle SoftHSM2 mapper whose edge must exist in every
/// phase (review L-3).
///
/// - 100 execs/s: no loss, no loss gap, and the mapper reads
///   `watched_no_use`. Servicing the ring only between passes loses about
///   half the records here. An attempt whose churn reached under 90
///   execs/s proves nothing and counts as a failed attempt (re-check R-1).
///   Unrelated host churn can still overflow the ring in the windows the
///   lane does not service, so a lossy or starved attempt is retried once
///   (review L-4); if both lose, each started at load1 above 4 and the
///   loss stays within 1% of the records, the zero-loss check is skipped
///   with its reason (the honesty checks still apply). Anything else
///   fails, a starved attempt included.
/// - 1,000 execs/s: either a loss with its gap and the mapper demoted to
///   unknown/loss, or no loss with the 100/s checks. The branch taken is
///   printed (`C57_CHURN_BRANCH`).
#[test]
#[ignore = "root-owned live BPF lane; native --system under 100 and 1,000 execs/s exec churn"]
fn privileged_native_lane_system_exec_churn_lp64() -> Result<()> {
    let workload = Workload::build()?;
    let churn = workload.path("exec_churn");
    let status = Command::new("gcc")
        .args(["-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&churn)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/fixtures/exec_churn.c"))
        .status()
        .context("running gcc")?;
    ensure!(status.success(), "gcc exec_churn failed");
    let seconds = 20;
    let mut lossy = Vec::new();
    let mut starved = Vec::new();
    let mut passed = false;
    for attempt in 1..=2 {
        let outcome = churn_outcome(&workload, &churn, 100, seconds)?;
        eprintln!("C57_CHURN attempt={attempt} {}", outcome.line);
        if outcome.loss > 0 {
            ensure_honest_loss(&outcome)?;
        }
        if outcome.achieved < 90.0 {
            // The churn never reached the rate: nothing is proven.
            eprintln!(
                "C57_CHURN_BRANCH rate=100 branch=starved attempt={attempt} achieved={}",
                outcome.achieved
            );
            starved.push(outcome.line);
            continue;
        }
        if outcome.loss == 0 {
            ensure_lossless(&outcome)?;
            eprintln!("C57_CHURN_BRANCH rate=100 branch=lossless attempt={attempt}");
            passed = true;
            break;
        }
        lossy.push(outcome);
    }
    if !passed {
        ensure!(
            starved.is_empty(),
            "the 100 execs/s churn was starved (under 90 execs/s) and no attempt passed: {}",
            starved.join(" | ")
        );
        let loaded = lossy.iter().all(|outcome| outcome.load1 > 4.0);
        let small = lossy
            .iter()
            .all(|outcome| outcome.loss * 100 <= outcome.records + outcome.loss);
        ensure!(
            loaded && small,
            "100 execs/s lost lifecycle records twice: {}",
            lossy
                .iter()
                .map(|outcome| outcome.line.as_str())
                .collect::<Vec<_>>()
                .join(" | ")
        );
        eprintln!(
            "C57_CHURN_BRANCH rate=100 branch=skipped reason=\"both attempts lost at most 1% \
             at load1 above 4; zero-loss not judged (indicative)\""
        );
    }
    let outcome = churn_outcome(&workload, &churn, 1000, seconds)?;
    eprintln!("C57_CHURN {}", outcome.line);
    if outcome.loss > 0 {
        ensure_honest_loss(&outcome)?;
        eprintln!("C57_CHURN_BRANCH rate=1000 branch=loss");
    } else {
        ensure_lossless(&outcome)?;
        eprintln!("C57_CHURN_BRANCH rate=1000 branch=lossless");
    }
    Ok(())
}

/// C5.11: a `--system` run over at least 400 endpoints retires inside its
/// budget and reads `retirement: closed` under uprobe-multi (per-offset
/// links may read unsettled: one close per endpoint). Copies of SoftHSM2 (each its own
/// inode, so its own object of 68 endpoints) are mapped by `map` ledgers;
/// the lane absorbs them over several passes.
/// Under `auto` on a kernel whose functional probe links uprobe-multi the
/// run must take it. Prints `C511_SCALE` with begin-stop to retired, for
/// the retirement-time-against-endpoints measurement.
///
/// Knobs (measurement only): `P11SCOPE_CELL_COPIES` (default 8 copies,
/// 544 endpoints), `P11SCOPE_CELL_BACKEND` (auto|multi|singles, default
/// auto) and `P11SCOPE_CELL_MAPPERS` (mapper processes per copy, default 1:
/// the registration walk grows with them, review M1).
#[test]
#[ignore = "root-owned live BPF lane; native --system over 400+ endpoints retires closed"]
fn privileged_native_lane_system_many_endpoints_lp64() -> Result<()> {
    let copies: usize = std::env::var("P11SCOPE_CELL_COPIES")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(8);
    let selection = crate::attach::BackendSelection::from_cli(
        &std::env::var("P11SCOPE_CELL_BACKEND").unwrap_or_else(|_| "auto".into()),
    )?;
    let rounds: usize = std::env::var("P11SCOPE_CELL_MAPPERS")
        .ok()
        .map(|value| value.parse())
        .transpose()?
        .unwrap_or(1);
    let workload = Workload::build()?;
    let mut providers = Vec::with_capacity(copies);
    for copy in 0..copies {
        let out = workload.path(&format!("softhsm-{copy}.so"));
        std::fs::copy(SOFTHSM, &out)?;
        providers.push(out);
    }
    let gate = workload.path("gate");
    let gate_arg = gate.to_str().context("gate path")?.to_string();
    let mut mappers = Vec::new();
    for round in 0..rounds {
        for (index, chunk) in providers.chunks(4).enumerate() {
            let mut args = vec!["map".to_string(), "--cell".into(), format!("S{index}")];
            for provider in chunk {
                args.push("--module".into());
                args.push(provider.to_str().context("provider path")?.into());
            }
            args.extend(["--gate".into(), gate_arg.clone(), "--hold".into()]);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            mappers.push(workload.spawn(&format!("map{index}-{round}"), &args)?);
        }
    }
    let mut coordinator = InventoryCoordinator::new(
        Scope::System,
        HookRegistry::builtin(),
        providers.clone(),
        OsProcessSource,
        RegistryLimits::default_limits(),
    )?;
    let probe = Probe::new(FacadeLane::prepare(
        crate::attach::capture::CaptureScope::System,
        coordinator.attach_set().budget(),
        selection,
    )?);
    let attached = Rc::clone(&probe.attached);
    let lane = NativeLane::start(probe, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| anyhow::anyhow!("{reason}"))?;
    let expected = copies * 68;
    let attached_at = Cell::new(None::<u64>);
    let stopped = drive(
        &mut coordinator,
        InspectScope::System,
        lane,
        &mut |passes| {
            if attached_at.get().is_none() && attached.get() >= expected {
                attached_at.set(Some(passes));
            }
            Ok(attached_at.get().is_some_and(|at| passes >= at + 2) || passes >= 40)
        },
    )?;
    let _ = std::fs::write(&gate, b"");
    let summary = &stopped.summary;
    let backend = &summary.backend;
    let load = RetirementLoad {
        backend: backend.backend,
        links: stopped.capture.links_at_stop.unwrap_or(summary.attached),
        endpoints: summary.attached,
    };
    let budget = LaneWindows::PROVISIONAL.retirement_budget(load);
    let cleanup = stopped.capture.cleanup();
    eprintln!(
        "C511_SCALE selection={} mechanism={} fallback={:?} copies={copies} expected={expected} \
         mappers={} attached={} failed={} passes={} links={} attach_ms={} \
         attach_link_max_ms={:.1} extend_attach_max_ms={:.1} budget_ms={} retired_ms={:?} \
         retirement={} cleanup={cleanup:?}",
        backend.selection_label(),
        backend.mechanism(),
        backend.fallback,
        mappers.len(),
        summary.attached,
        summary.failed,
        summary.passes,
        load.links,
        stopped.capture.attach_ns / 1_000_000,
        stopped.capture.attach_ns_max as f64 / 1e6,
        stopped.capture.extend_attach_ns_max as f64 / 1e6,
        budget.as_millis(),
        stopped.capture.retired_after.map(|after| after.as_millis()),
        summary.retirement.label(),
    );
    let summary = summary.clone();
    let backend = summary.backend.clone();
    // An unsettled retirement finishes in the drop (after the report in
    // production): its time completes the measurement.
    let dropping = Instant::now();
    drop(stopped);
    eprintln!(
        "C511_SCALE_DROP retirement={} drop_ms={}",
        summary.retirement.label(),
        dropping.elapsed().as_millis()
    );
    ensure!(
        summary.attached >= 400 && summary.attached >= expected && summary.failed == 0,
        "{summary:?}"
    );
    // uprobe-multi closes hundreds of endpoints in a few links well inside
    // the budget: it must read closed. Per-offset links on a kernel without
    // it (5.15) close one link per endpoint and may honestly outlast the
    // 10 s pre-report wait (R-C51-4): closed or unsettled, never a failure.
    let closed = matches!(summary.retirement, Retirement::Closed(ref cleanup) if cleanup.failures.is_empty());
    ensure!(
        closed
            || (backend.backend == crate::attach::AttachBackend::Singles
                && matches!(summary.retirement, Retirement::Unsettled(_))),
        "{summary:?}"
    );
    if selection == crate::attach::BackendSelection::Auto
        && crate::inventory_capture::multi_functional_probe().is_ok()
    {
        ensure!(
            backend.mechanism() == "uprobe-multi" && backend.fallback.is_none(),
            "auto did not take uprobe-multi on a capable kernel: {backend:?}"
        );
    }
    drop(mappers);
    Ok(())
}
