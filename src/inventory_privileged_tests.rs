//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, ignored live gates for the native inventory lane (Task 6 C5.1).
//! Root BPF lane, run serially through `scripts/run-privileged-lib-tests.sh`.
//! Every caller is an owned `inventory-ledger` process (the C8 acceptance
//! workload) against SoftHSM2 or the ledger's held provider, with its own
//! independent stdout ledger; the observer is the production classic path.

use super::*;
use crate::attach::capture::{
    CaptureScopeCoverage, CaptureTargets, CleanupSummary, CookieQuery, DiscoveryBatch,
    ExtendReceipt, ExtendWindow, NativeDomainId, ReadWindow, WitnessBatch,
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
        if let Ok(Some(_)) = self.child.try_wait() {
            return;
        }
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

    fn scope_coverage(&self) -> CaptureScopeCoverage {
        self.inner.scope_coverage()
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
        inventory_scope: Some(inventory_scope),
        scope: scope.into(),
        cgroup: None,
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
        coverage.len() == 1 && matches!(coverage[0], UseCoverage::Counted { .. }),
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
        &mut crate::inventory_output::WriterStdout(&mut stdout),
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
        edges.len() == 1
            && edges[0]["entries"]["coverage"]["state"] == "counted"
            && edges[0]["entries"]["count"]
                .as_u64()
                .is_some_and(|count| count >= 1),
        "the calls during the stall were not counted: {edges:?}"
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

/// `P11SCOPE_TEST_TIME_SCALE` (default 1, from 1 to 4 here): how much
/// slower than nominal a loaded host declares itself, the same variable
/// the Python harnesses and `tests/artifact_contracts.rs` read. Cells that
/// scale a bound by it say which; with the default every bound is literal.
fn test_time_scale() -> Result<f64> {
    parse_time_scale(std::env::var("P11SCOPE_TEST_TIME_SCALE").ok().as_deref())
}

fn parse_time_scale(raw: Option<&str>) -> Result<f64> {
    let scale = match raw.map(str::trim) {
        Some(raw) if !raw.is_empty() => raw.parse::<f64>().unwrap_or(f64::NAN),
        _ => 1.0,
    };
    // A cap keeps the knob a load allowance, never a way to pass a
    // regressed dashboard (4 x 100 ms ticks, a quarter of the passes).
    ensure!(
        scale.is_finite() && (1.0..=4.0).contains(&scale),
        "P11SCOPE_TEST_TIME_SCALE must be a number from 1 to 4"
    );
    Ok(scale)
}

/// Review (runner opt-ins): the time scale defaults to 1 and is refused
/// outside 1..=4 rather than clamped.
#[test]
fn the_test_time_scale_is_refused_outside_one_to_four() {
    assert_eq!(parse_time_scale(None).unwrap(), 1.0);
    assert_eq!(parse_time_scale(Some(" ")).unwrap(), 1.0);
    assert_eq!(parse_time_scale(Some("2.5")).unwrap(), 2.5);
    assert_eq!(parse_time_scale(Some("4")).unwrap(), 4.0);
    for refused in ["4.01", "0.5", "abc", "inf", "NaN"] {
        assert!(parse_time_scale(Some(refused)).is_err(), "{refused}");
    }
}

/// One production run through `run_with_writer` with `--json` and an event
/// log; `stop` is polled every service tick.
fn run_product(
    scope: InspectScope,
    module: &Path,
    events: &Path,
    stop: &dyn Fn() -> bool,
) -> Result<(serde_json::Value, String)> {
    run_product_modules(scope, &[module.to_path_buf()], events, stop)
}

/// `run_product` over several provider hints (the A-then-B cell attaches
/// two provider instances).
fn run_product_modules(
    scope: InspectScope,
    modules: &[PathBuf],
    events: &Path,
    stop: &dyn Fn() -> bool,
) -> Result<(serde_json::Value, String)> {
    let mut stdout = Vec::new();
    let reported = std::cell::Cell::new(None::<Instant>);
    let code = run_with_writer(
        scope,
        modules,
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
        &mut crate::inventory_output::WriterStdout(&mut stdout),
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

/// Builds the existing owned retirement fixture: two distinct provider tables
/// point at one physical Initialize body. Its ledger counts actual calls only.
struct DemotionWorkload {
    process: LedgerProcess,
    control: std::fs::File,
    dir: tempfile::TempDir,
}

impl DemotionWorkload {
    fn spawn() -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = tempfile::tempdir()?;
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/public-cli/demotion-ledger.c");
        for (name, mode) in [
            ("libdemotion-common.so", Some("DEMOTION_COMMON")),
            ("provider-A.so", Some("DEMOTION_PROVIDER_A")),
            ("provider-B.so", Some("DEMOTION_PROVIDER_B")),
            ("workload", None),
        ] {
            let mut command = Command::new("cc");
            command.args(["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]);
            if let Some(mode) = mode {
                command.args(["-shared", "-fPIC"]).arg(format!("-D{mode}"));
            } else {
                command.arg("-DDEMOTION_PHASED_LEDGER");
            }
            command.arg(&source).arg("-o").arg(dir.path().join(name));
            if mode.is_some_and(|mode| mode != "DEMOTION_COMMON") {
                command.arg("-L").arg(dir.path()).args([
                    "-ldemotion-common",
                    "-Wl,-rpath,$ORIGIN",
                    "-Wl,-z,defs",
                ]);
            } else if mode.is_none() {
                command.arg("-ldl");
            }
            ensure!(command.status()?.success(), "building {name} failed");
        }
        let fifo = dir.path().join("control");
        ensure!(
            Command::new("mkfifo")
                .arg("-m")
                .arg("600")
                .arg(&fifo)
                .status()?
                .success(),
            "creating the owned control FIFO failed"
        );
        let out = dir.path().join("workload.out");
        let child = Command::new(dir.path().join("workload"))
            .args([
                dir.path().join("provider-A.so"),
                dir.path().join("provider-B.so"),
                dir.path().join("libdemotion-common.so"),
                fifo.clone(),
                dir.path().join("calls.jsonl"),
            ])
            .args(["0123456789abcdef0123456789abcdef", "110000"])
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out)?)
            .stderr(std::fs::File::create(dir.path().join("workload.err"))?)
            .spawn()?;
        let process = LedgerProcess { child, out };
        process.wait_for("{\"event\":\"prepared\"", Duration::from_secs(5))?;
        let control = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(fifo)?;
        Ok(Self {
            dir,
            process,
            control,
        })
    }

    fn command(&self, command: &str, acknowledgement: &str) -> Result<()> {
        writeln!(&self.control, "{command}")?;
        self.process.wait_for(
            &format!("{{\"event\":\"{acknowledgement}\""),
            Duration::from_secs(5),
        )
    }

    fn calls(&self) -> Result<Vec<serde_json::Value>> {
        jsonl_records(&self.dir.path().join("calls.jsonl"))
    }

    /// Compare held and loaded files through their vm_file identities, never
    /// through fstat's device versus the device printed by /proc/maps.
    fn check_mapping(&self, name: &str) -> Result<()> {
        use crate::discovery::identity::{map_files_identity, self_mapped_identity};
        use std::os::unix::ffi::OsStrExt;
        let path = self.dir.path().join(name);
        let file = std::fs::File::open(&path)?;
        let held = self_mapped_identity(&file).map_err(anyhow::Error::msg)?;
        let maps = p11scope_manifest::maps::parse_maps(&std::fs::read(format!(
            "/proc/{}/maps",
            self.process.pid()
        ))?)
        .map_err(anyhow::Error::msg)?;
        let loaded = maps
            .iter()
            .find(|entry| {
                entry.permissions[2] == b'x'
                    && entry.raw_path.as_deref() == Some(path.as_os_str().as_bytes())
            })
            .context(format!("{name} has no owned executable mapping"))?;
        let target = map_files_identity(self.process.pid(), loaded.start, loaded.end)?;
        ensure!(
            held == target,
            "held and loaded fixture file differ: {name}"
        );
        Ok(())
    }
}

fn jsonl_records(path: &Path) -> Result<Vec<serde_json::Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| serde_json::from_str(line).map_err(anyhow::Error::from))
        .collect()
}

fn phase_calls(ledger: &[serde_json::Value], phase: &str) -> u64 {
    ledger
        .iter()
        .filter(|row| row["kind"] == "call" && row["phase"] == phase)
        .count() as u64
}

fn check_demotion_ledger(ledger: &[serde_json::Value]) -> Result<()> {
    let calls: Vec<_> = ledger.iter().filter(|row| row["kind"] == "call").collect();
    for (index, call) in calls.iter().enumerate() {
        ensure!(
            call["sequence"] == index as u64 + 1,
            "call sequence: {call}"
        );
        ensure!(
            call["entered"] == true
                && call["completed"] == true
                && matches!((call["before_call_ns"].as_u64(), call["after_return_ns"].as_u64()),
                    (Some(before), Some(after)) if after > before),
            "incomplete call: {call}"
        );
        ensure!(
            matches!(call["return_status"].as_u64(), Some(0 | 7)),
            "return: {call}"
        );
    }
    for (phase, expected) in [("a", 5), ("shared", 2), ("fence", 1), ("proof", 2)] {
        ensure!(
            phase_calls(ledger, phase) == expected,
            "workload phase {phase} missing"
        );
    }
    ensure!(calls.len() == 10, "workload call total: {}", calls.len());
    let terminal = ledger.last().context("empty workload ledger")?;
    ensure!(
        terminal["kind"] == "complete"
            && terminal["complete"] == true
            && terminal["calls"] == calls.len() as u64,
        "workload terminal: {terminal}"
    );
    Ok(())
}

#[test]
fn demotion_fixture_records_phased_calls() -> Result<()> {
    let mut workload = DemotionWorkload::spawn()?;
    for (command, ack) in [
        ("ready", "a-done"),
        ("load-b", "b-ready"),
        ("shared", "shared-done"),
        ("unload-a", "a-unmapped"),
        ("fence", "fence-done"),
        ("proof", "final-calls"),
        ("stop", "done"),
    ] {
        workload.command(command, ack)?;
    }
    ensure!(
        workload.process.child.wait()?.success(),
        "workload exit failed"
    );
    let ledger = workload.calls()?;
    check_demotion_ledger(&ledger)?;
    let mut incomplete = ledger.clone();
    incomplete.last_mut().context("terminal row")?["complete"] = false.into();
    ensure!(
        check_demotion_ledger(&incomplete).is_err(),
        "accepted an incomplete workload"
    );
    let mut missing_phase = ledger;
    let call = missing_phase
        .iter_mut()
        .find(|row| row["phase"] == "shared")
        .context("shared call")?;
    call["phase"] = serde_json::Value::Null;
    ensure!(
        check_demotion_ledger(&missing_phase).is_err(),
        "accepted a missing shared call phase"
    );
    Ok(())
}

fn demotion_edge<'a>(
    stream: &'a [serde_json::Value],
    pid: u32,
    suffix: &str,
) -> Option<&'a serde_json::Value> {
    stream.iter().rev().find_map(|row| {
        let event = &row["event"];
        (row["kind"] == "edge_observed"
            && event["identity_context"]["caller"]["pid"] == pid
            && event["identity_context"]["module"]["path"]
                .as_str()
                .is_some_and(|path| path.ends_with(suffix)))
        .then_some(event)
    })
}

/// The real PID capture must preserve A's published history, withhold shared
/// calls and the first post-retirement read, then allocate only later B calls.
/// FIFO milestones use public capture state; the C call ledger is the oracle.
#[test]
#[ignore = "root-owned live BPF lane; real provider retirement recovers B and exports diagnostics"]
fn privileged_native_lane_pid_provider_retirement_diagnostics_lp64() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut workload = DemotionWorkload::spawn()?;
    let pid = workload.process.pid();
    workload.check_mapping("provider-A.so")?;
    workload.check_mapping("libdemotion-common.so")?;
    let root = workload.dir.path();
    let events = root.join("events.jsonl");
    let diagnostics = root.join("diagnostics.jsonl");
    let started = Instant::now();
    let stage = Cell::new(0u8);
    let failure = RefCell::new(None::<anyhow::Error>);
    let stop = || {
        let advance = || -> Result<bool> {
            ensure!(
                started.elapsed() < Duration::from_secs(95),
                "retirement workload did not reach capture milestone {}",
                stage.get()
            );
            if stage.get() == 7 {
                return Ok(true);
            }
            let stream = if events.exists() {
                jsonl_records(&events)?
            } else {
                Vec::new()
            };
            // A partial event publication is not a committed observer milestone.
            if !stream
                .last()
                .is_some_and(|row| row["kind"] == "pass_committed")
            {
                return Ok(false);
            }
            let a = demotion_edge(&stream, pid, "provider-A.so");
            let b = demotion_edge(&stream, pid, "provider-B.so");
            let ledger = workload.calls()?;
            let a_calls = phase_calls(&ledger, "a");
            let shared = phase_calls(&ledger, "shared");
            let has_gap = |text: &str| {
                stream.iter().any(|row| {
                    row["kind"] == "gap_recorded"
                        && row["event"]["subject"] == "rejected demoted count"
                        && row["event"]["reason"]
                            .as_str()
                            .is_some_and(|reason| reason.contains(text))
                })
            };
            match stage.get() {
                0 if a.is_some_and(|edge| {
                    edge["presence"] == "mapped" && edge["capture"] == "armed"
                }) =>
                {
                    workload.command("ready", "a-done")?;
                    stage.set(1);
                }
                1 if a_calls > 0 && a.is_some_and(|edge| edge["entries"]["count"] == a_calls) => {
                    // This stop callback quiesces the observer between passes;
                    // B's unselected acquisition call precedes its attachment.
                    workload.command("load-b", "b-ready")?;
                    workload.check_mapping("provider-B.so")?;
                    stage.set(2);
                }
                2 if b.is_some_and(|edge| {
                    edge["presence"] == "mapped" && edge["capture"] == "armed"
                }) =>
                {
                    workload.command("shared", "shared-done")?;
                    stage.set(3);
                }
                3 if shared > 0
                    && (has_gap(&format!(
                        "{shared} unattributed calls after sharing appeared"
                    )) || has_gap(&format!(
                        "absolute count range ({a_calls}, {}]",
                        a_calls + shared
                    ))) =>
                {
                    ensure!(
                        a.is_some_and(|edge| edge["entries"]["count"] == a_calls)
                            && b.is_some_and(|edge| edge["entries"]["count"] == 0),
                        "shared calls escaped withholding: A={a:?}, B={b:?}"
                    );
                    workload.command("unload-a", "a-unmapped")?;
                    stage.set(4);
                }
                4 if a.is_some_and(|edge| edge["presence"] == "unloaded") => {
                    workload.command("fence", "fence-done")?;
                    stage.set(5);
                }
                5 if has_gap(&format!(
                    "absolute count range ({}, {}]",
                    a_calls + shared,
                    a_calls + shared + phase_calls(&ledger, "fence")
                )) =>
                {
                    ensure!(
                        b.is_some_and(|edge| edge["entries"]["count"] == 0),
                        "the fence was attributed: B={b:?}"
                    );
                    workload.command("proof", "final-calls")?;
                    stage.set(6);
                }
                6 if phase_calls(&ledger, "proof") > 0
                    && b.is_some_and(|edge| {
                        edge["entries"]["count"] == phase_calls(&ledger, "proof")
                    }) =>
                {
                    stage.set(7);
                    return Ok(true);
                }
                _ => {}
            }
            Ok(false)
        };
        match advance() {
            Ok(done) => done,
            Err(error) => {
                *failure.borrow_mut() = Some(error);
                true
            }
        }
    };
    let mut stdout = Vec::new();
    let code = run_with_terminal_diagnostics(
        InspectScope::Pid(pid),
        // Ownership retirement needs a complete inventory of this owned
        // caller. Explicit module hints deliberately cannot prove absence.
        &[],
        &HookRegistry::builtin(),
        true,
        None,
        None,
        Some(Duration::from_secs(100)),
        None,
        false,
        Some(&events),
        None,
        None,
        CaptureMode::Native,
        crate::attach::BackendSelection::Auto,
        &stop,
        &|| {},
        false,
        &mut WriterStdout(&mut stdout),
        &DashboardIo::stdio(),
        DiagnosticRequest {
            path: Some(&diagnostics),
            pid_filter: Some(pid),
            second_signal: &|| false,
        },
        None,
    )?;
    if let Some(error) = failure.into_inner() {
        eprintln!("RETIREMENT_FAILURE workload={:?}", workload.process.lines());
        let records = jsonl_records(&diagnostics).unwrap_or_default();
        for row in records.iter().rev().take(32).rev() {
            eprintln!("RETIREMENT_DIAGNOSTIC {row}");
        }
        return Err(error);
    }
    ensure!(
        code == 0 && stage.get() == 7,
        "exit={code}, capture milestone={}",
        stage.get()
    );
    workload.command("stop", "done")?;
    ensure!(
        workload.process.child.wait()?.success(),
        "workload exit failed"
    );
    let ledger = workload.calls()?;
    check_demotion_ledger(&ledger)?;
    let document: serde_json::Value = serde_json::from_slice(&stdout)?;
    let stream = std::fs::read_to_string(&events)?;
    ensure!(stream_ended(&stream), "event stream did not end");
    ensure!(
        document["observation"]["lane"] == "native"
            && document["observation"]["settlement"] == "unsettled",
        "{}",
        document["observation"]
    );
    ensure!(
        !ab_lifecycle_loss_detected(&document),
        "lifecycle loss invalidated retirement recovery"
    );
    let edges = doc_edges(&document, pid);
    ensure!(edges.len() == 2, "owned caller edges: {edges:?}");
    let doc_modules = document["modules"].as_array().context("modules")?;
    let edge_for = |suffix: &str| -> Result<&serde_json::Value> {
        edges
            .iter()
            .copied()
            .find(|edge| {
                doc_modules.iter().any(|module| {
                    module["id"] == edge["module"]
                        && module["paths"].as_array().is_some_and(|paths| {
                            paths.iter().any(|path| {
                                path.as_str().is_some_and(|path| path.ends_with(suffix))
                            })
                        })
                })
            })
            .context(format!("missing owned edge {suffix}"))
    };
    let a = edge_for("provider-A.so")?;
    let b = edge_for("provider-B.so")?;
    let a_calls = phase_calls(&ledger, "a");
    let shared = phase_calls(&ledger, "shared");
    let fence = phase_calls(&ledger, "fence");
    let proof = phase_calls(&ledger, "proof");
    ensure!(a["entries"]["count"] == a_calls, "A history changed: {a}");
    ensure!(
        b["entries"]["count"] == proof && b["entries"]["coverage"]["state"] == "counted",
        "B did not recover the independent proof calls: {b}"
    );
    let records = jsonl_records(&diagnostics)?;
    ensure!(
        std::fs::metadata(&diagnostics)?.permissions().mode() & 0o777 == 0o600,
        "diagnostic destination is not private"
    );
    ensure!(
        records.first().is_some_and(|row| row["kind"] == "header")
            && records.last().is_some_and(|row| row["kind"] == "footer"
                && row["capture_settlement"] == "unsettled"
                && row["diagnostics_complete"] == true),
        "diagnostic envelope incomplete"
    );
    let header = &records[0];
    let footer = records.last().expect("checked diagnostic footer");
    ensure!(
        header["pid_filter"] == pid && header["scope"] == "pid" && header["mode"] == "native",
        "focused diagnostic request changed: {header}"
    );
    ensure!(
        footer["records_written"] == records.len() as u64 - 2
            && footer["bytes_written"] == std::fs::metadata(&diagnostics)?.len()
            && footer["kinds"].as_array().is_some_and(|kinds| kinds
                .iter()
                .all(|kind| kind["evicted"] == 0 && kind["omitted"] == 0)),
        "diagnostic records missing: {footer}"
    );
    let recovered = records
        .iter()
        .find(|row| {
            row["decision"] == "placed"
                && row["module_id"] == b["module"]
                && row["edge_total"] == proof
                && row["staged"] == proof
        })
        .context("actual recovered-B placement missing")?;
    let pair = &recovered["pair"];
    ensure!(!pair.is_null(), "recovered placement has no pair");
    ensure!(
        records
            .iter()
            .any(|row| row["pair"] == *pair && row["new_eligibility"] == "shared_owner")
            && records.iter().any(|row| row["pair"] == *pair
                && row["new_eligibility"] == "sole_owner"
                && row["module_id"] == b["module"]),
        "actual shared-to-B ownership transition missing"
    );
    let fence_decision = records
        .iter()
        .find(|row| {
            row["pair"] == *pair
                && row["decision"] == "withheld"
                && row["reason"] == "awaiting_fence"
                && row["after"] == a_calls + shared
                && row["through"] == a_calls + shared + fence
        })
        .context("the fence prefix was not withheld")?;
    ensure!(
        fence_decision["observation_ref"]["status"] == "retained",
        "the selected fence read is not retained: {fence_decision}"
    );
    let observation_seq = fence_decision["observation_ref"]["seq"]
        .as_u64()
        .context("selected fence observation reference missing")?;
    let fence_read = records
        .iter()
        .find(|row| {
            row["seq"] == observation_seq
                && row["kind"] == "count_observation"
                && row["pair"] == *pair
                && row["absolute"] == a_calls + shared + fence
        })
        .context("actual selected fence observation missing")?;
    ensure!(
        (fence_read["origin"] == "initial" || fence_read["origin"] == "refresh")
            && fence_read["pre"]
                .as_u64()
                .is_some_and(|pre| fence_read["post"]
                    .as_u64()
                    .is_some_and(|post| pre > 0 && post > pre)),
        "the selected fence read lacks its actual origin/bracket: {fence_read}"
    );
    ensure!(
        recovered["base"] == a_calls + shared + fence
            && recovered["absolute"] == a_calls + shared + fence + proof
            && recovered["baseline_pre"] == fence_read["pre"]
            && recovered["baseline_post"] == fence_read["post"],
        "recovery lost actual fence context: {recovered}"
    );
    eprintln!(
        "RETIREMENT_LIVE pid={pid} passes={} a={a_calls} shared_withheld={shared} fence_withheld={fence} b={proof} diagnostics={} elapsed_ms={}",
        document["observation"]["passes"],
        records.len(),
        started.elapsed().as_millis()
    );
    Ok(())
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
        // R-C51-3: counted, or unknown with reason `loss` — never a
        // watch, never another unknown reason (review F6).
        let reason = &edges[0]["entries"]["coverage"]["reason"];
        ensure!(
            *state == "counted" || (*state == "unknown" && *reason == "loss"),
            "under lost lifecycle evidence the edge must read counted or unknown/loss: \
             {edges:?}; witnesses {witnesses}"
        );
        eprintln!("C51_LATE_LIFECYCLE_LOSS state={state} witnesses={witnesses}");
    } else {
        ensure!(
            *state == "counted",
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

/// CLOCK_MONOTONIC in nanoseconds: the capture clock basis the stream's
/// `at_ns` stamps use (same host, same time namespace).
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

/// One parsed `LEDGER` line: module path, function, phase, and counts.
struct LedgerEntry {
    module: String,
    func: String,
    phase: String,
    n: u64,
    bad: u64,
}

fn parse_ledger(text: &str) -> Vec<LedgerEntry> {
    text.lines()
        .filter(|line| line.starts_with("LEDGER "))
        .filter_map(|line| {
            let (mut module, mut func, mut phase) = (None, None, None);
            let (mut n, mut bad) = (None, None);
            for token in line.split_whitespace() {
                let Some((key, value)) = token.split_once('=') else {
                    continue;
                };
                match key {
                    "module" => module = Some(value.to_string()),
                    "fn" => func = Some(value.to_string()),
                    "phase" => phase = Some(value.to_string()),
                    "n" => n = value.parse().ok(),
                    "bad" => bad = value.parse().ok(),
                    _ => {}
                }
            }
            Some(LedgerEntry {
                module: module?,
                func: func?,
                phase: phase?,
                n: n?,
                bad: bad?,
            })
        })
        .collect()
}

/// One `edge_observed` record for a single edge, in stream order.
struct EdgeRecord {
    at_ns: u64,
    count: u64,
    state: String,
}

fn edge_series(
    lines: &[serde_json::Value],
    caller_id: &str,
    module_id: &str,
) -> (Vec<EdgeRecord>, usize) {
    let mut series = Vec::new();
    let mut malformed = 0;
    for line in lines.iter().filter(|line| {
        line["kind"] == "edge_observed"
            && line["event"]["caller"] == caller_id
            && line["event"]["module"] == module_id
    }) {
        match (
            line["at_ns"].as_u64(),
            line["event"]["entries"]
                .get("count")
                .and_then(serde_json::Value::as_u64),
            line["event"]["entries"]["coverage"]["state"].as_str(),
        ) {
            (Some(at_ns), Some(count), Some(state)) => series.push(EdgeRecord {
                at_ns,
                count,
                state: state.to_string(),
            }),
            _ => malformed += 1,
        }
    }
    (series, malformed)
}

/// The A-then-B parsers over canned lines (no lane needed).
#[test]
fn ab_helpers_parse_a_canned_ledger_and_stream() {
    let ledger = parse_ledger(
        "IDENT cell=AB pid=7 start=1 gen=0 exe=/bin/ledger\n\
         MAPPED cell=AB pid=7 start=1 gen=0 exe=/bin/ledger module=/p/a.so ino=1\n\
         LEDGER cell=AB pid=7 start=1 gen=0 exe=/bin/ledger module=/p/a.so fn=C_Init mech=- n=2 bad=0 phase=setup t0=1 t1=2\n\
         LEDGER cell=AB pid=7 start=1 gen=0 exe=/bin/ledger module=/p/b.so fn=C_Init mech=- n=1 bad=0 phase=setup t0=3 t1=3\n",
    );
    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger[0].module, "/p/a.so");
    assert_eq!(ledger[0].n, 2);
    assert_eq!(ledger[1].func, "C_Init");
    assert!(ledger.iter().all(|entry| entry.bad == 0));
    let lines: Vec<serde_json::Value> = [
        serde_json::json!({"kind": "edge_observed", "at_ns": 10, "event": {
            "caller": "c0", "module": "m1",
            "entries": {"count": 0, "coverage": {"state": "quiet"}}}}),
        serde_json::json!({"kind": "edge_observed", "at_ns": 20, "event": {
            "caller": "c0", "module": "m1",
            "entries": {"count": 1, "coverage": {"state": "counted"}}}}),
        serde_json::json!({"kind": "edge_observed", "at_ns": 30, "event": {
            "caller": "c0", "module": "m1", "entries": {"coverage": {}}}}),
    ]
    .into_iter()
    .collect();
    let (series, malformed) = edge_series(&lines, "c0", "m1");
    assert_eq!(malformed, 1);
    assert_eq!(series.len(), 2);
    assert_eq!(series[0].count, 0);
    assert_eq!(series[0].state, "quiet");
    assert_eq!(series[1].count, 1);
}

/// Whether the edge's final state survives lifecycle loss honestly
/// (round 2, F6): counted, or unknown with reason `loss` — never a
/// watch, never another unknown reason.
fn ab_edge_survives_lifecycle_loss(edge: &serde_json::Value) -> bool {
    let state = edge["entries"]["coverage"]["state"].as_str();
    let reason = edge["entries"]["coverage"]["reason"].as_str();
    state == Some("counted") || (state == Some("unknown") && reason == Some("loss"))
}

/// Whether the AB run lost lifecycle evidence (round 3, F3-05): the
/// unbound `lifecycle_loss` reason, the `native capture lifecycle
/// evidence lost` gap, or a nonzero `observation.lifecycle.ring_loss`
/// (a DISCOVERY-ring window the lane never serviced overflows exactly
/// the lifecycle records the other two signals name).
fn ab_lifecycle_loss_detected(document: &serde_json::Value) -> bool {
    let witnesses = &document["observation"]["native_witnesses"];
    witnesses["unbound_reasons"].get("lifecycle_loss").is_some()
        || document["gaps"].as_array().is_some_and(|gaps| {
            gaps.iter()
                .any(|gap| gap["subject"] == "native capture lifecycle evidence lost")
        })
        || document["observation"]["lifecycle"]["ring_loss"]
            .as_u64()
            .is_some_and(|loss| loss > 0)
}

/// The AB cell's lifecycle-loss verdict (round 3, F3-05): `Ok` when no
/// loss was detected and the cell may proceed; `Err` (the cell FAILS,
/// never passes-or-skips) when loss voids the qualification — after
/// proving the honest-loss shape on both edges first.
fn ab_lifecycle_loss_verdict(
    detected: bool,
    edge_a: &serde_json::Value,
    edge_b: &serde_json::Value,
    witnesses: &serde_json::Value,
) -> Result<()> {
    if !detected {
        return Ok(());
    }
    // R-C51-3: counted, or unknown with reason `loss` — never a
    // watch, never another unknown reason (review F6).
    for edge in [edge_a, edge_b] {
        ensure!(
            ab_edge_survives_lifecycle_loss(edge),
            "under lost lifecycle evidence the edge must read counted or unknown/loss: \
             {edge}; witnesses {witnesses}"
        );
    }
    // Round 2 (F6/S6): honest loss is checked above, but it voids
    // this qualification cell — returning success here would record
    // PASS without checking first-count, growth, finals, or stream
    // end. Pinned by `ab_lifecycle_loss_branch_fails_the_cell`.
    bail!("lifecycle loss voids the AB first-count qualification: {witnesses}");
}

/// Whether B's first count demonstrably held still across the idle
/// window (round 2, F5/S7): the first counted record published
/// strictly before gate2, plus a later counted record with the same
/// unchanged count — also before gate2 — with a pass commit between
/// the two in stream order (so a distinct idle pass carried the
/// unchanged count). A lone pre-gate2 record, or two records from the
/// same commit, proves no idle hold.
fn ab_idle_hold_across_commits(
    lines: &[serde_json::Value],
    caller_id: &str,
    module_id: &str,
    first: &EdgeRecord,
    gate2_ns: u64,
) -> bool {
    if first.at_ns >= gate2_ns {
        return false;
    }
    let mut hits = Vec::new();
    let mut commits = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        match line["kind"].as_str() {
            Some("pass_committed") => commits.push(index),
            Some("edge_observed") => {
                if line["event"]["caller"] != caller_id || line["event"]["module"] != module_id {
                    continue;
                }
                let at = line["at_ns"].as_u64();
                let count = line["event"]["entries"]
                    .get("count")
                    .and_then(|count| count.as_u64());
                let state = line["event"]["entries"]["coverage"]["state"].as_str();
                if let (Some(at), Some(count), Some(state)) = (at, count, state)
                    && at < gate2_ns
                    && state == "counted"
                    && count == first.count
                {
                    hits.push(index);
                }
            }
            _ => {}
        }
    }
    if hits.len() < 2 {
        return false;
    }
    let (lo, hi) = (hits[0], hits[hits.len() - 1]);
    commits.iter().any(|commit| *commit > lo && *commit < hi)
}

#[test]
fn ab_lifecycle_loss_predicate_accepts_only_honest_states() {
    let edge = |state: &str, reason: Option<&str>| serde_json::json!({"entries": {"coverage": {"state": state, "reason": reason}}});
    assert!(ab_edge_survives_lifecycle_loss(&edge("counted", None)));
    assert!(ab_edge_survives_lifecycle_loss(&edge(
        "unknown",
        Some("loss")
    )));
    assert!(!ab_edge_survives_lifecycle_loss(&edge(
        "watched_no_use",
        None
    )));
    assert!(!ab_edge_survives_lifecycle_loss(&edge(
        "unknown",
        Some("scan_only")
    )));
    assert!(!ab_edge_survives_lifecycle_loss(&edge("unknown", None)));
}

// F3-05 branch-forcing pin: detected loss voids the AB cell — the
// verdict is Err (the runner records FAIL: rc != 0, no
// `test result: ok. 1 passed` line), never Ok (PASS-or-skip) — even
// when both edges degrade honestly. Reverting the tail to `Ok(())`
// turns this pin red.
#[test]
fn ab_lifecycle_loss_branch_fails_the_cell() {
    let edge = |state: &str, reason: Option<&str>| serde_json::json!({"entries": {"coverage": {"state": state, "reason": reason}}});
    let honest = edge("counted", None);
    let witnesses = serde_json::json!({"unbound_reasons": {"lifecycle_loss": 1}});
    assert!(
        ab_lifecycle_loss_verdict(true, &honest, &honest, &witnesses).is_err(),
        "honest loss still voids the qualification"
    );
    assert!(
        ab_lifecycle_loss_verdict(false, &honest, &honest, &witnesses).is_ok(),
        "a clean run proceeds past the loss branch"
    );
    let watched = edge("watched_no_use", None);
    assert!(
        ab_lifecycle_loss_verdict(true, &honest, &watched, &witnesses).is_err(),
        "dishonest degradation under loss fails the shape check"
    );
}

// F3-05 (astra S4): detection covers the unbound reason, the gap, and
// a nonzero `observation.lifecycle.ring_loss` — each alone detects,
// and a clean document (or one with no lifecycle block) does not.
#[test]
fn ab_lifecycle_loss_detection_covers_ring_loss() {
    let doc = |witnesses: serde_json::Value,
               gaps: serde_json::Value,
               lifecycle: serde_json::Value| {
        serde_json::json!({"observation": {"native_witnesses": witnesses, "lifecycle": lifecycle}, "gaps": gaps})
    };
    let clean_witnesses = serde_json::json!({"unbound_reasons": {}});
    let no_gaps = serde_json::json!([]);
    let no_loss = serde_json::json!({"ring_loss": 0});
    assert!(!ab_lifecycle_loss_detected(&doc(
        clean_witnesses.clone(),
        no_gaps.clone(),
        no_loss.clone()
    )));
    assert!(ab_lifecycle_loss_detected(&doc(
        serde_json::json!({"unbound_reasons": {"lifecycle_loss": 1}}),
        no_gaps.clone(),
        no_loss.clone()
    )));
    assert!(ab_lifecycle_loss_detected(&doc(
        clean_witnesses.clone(),
        serde_json::json!([{"subject": "native capture lifecycle evidence lost"}]),
        no_loss.clone()
    )));
    assert!(ab_lifecycle_loss_detected(&doc(
        clean_witnesses.clone(),
        no_gaps.clone(),
        serde_json::json!({"ring_loss": 1})
    )));
    assert!(!ab_lifecycle_loss_detected(&serde_json::json!(
        {"observation": {"native_witnesses": clean_witnesses}, "gaps": []}
    )));
}

#[test]
fn ab_idle_hold_requires_two_unchanged_records_across_a_commit() {
    let record = |at_ns: u64, count: u64, state: &str| {
        serde_json::json!({"kind": "edge_observed", "at_ns": at_ns, "event": {
            "caller": "c0", "module": "m1",
            "entries": {"count": count, "coverage": {"state": state}}}})
    };
    let commit = serde_json::json!({"kind": "pass_committed", "event": {}});
    let first = EdgeRecord {
        at_ns: 10,
        count: 1,
        state: "counted".to_string(),
    };
    // Vacuous: a lone pre-gate2 record proves no hold.
    assert!(!ab_idle_hold_across_commits(
        &[record(10, 1, "counted")],
        "c0",
        "m1",
        &first,
        100
    ));
    // Same-commit pair: no idle pass between them.
    assert!(!ab_idle_hold_across_commits(
        &[record(10, 1, "counted"), record(20, 1, "counted")],
        "c0",
        "m1",
        &first,
        100
    ));
    // Cross-commit pair: a distinct idle pass carried the count.
    assert!(ab_idle_hold_across_commits(
        &[
            record(10, 1, "counted"),
            commit.clone(),
            record(20, 1, "counted")
        ],
        "c0",
        "m1",
        &first,
        100
    ));
    // First counted at/after gate2: not an idle hold.
    let late = EdgeRecord {
        at_ns: 100,
        count: 1,
        state: "counted".to_string(),
    };
    assert!(!ab_idle_hold_across_commits(
        &[
            record(10, 1, "counted"),
            commit.clone(),
            record(20, 1, "counted")
        ],
        "c0",
        "m1",
        &late,
        100
    ));
    // Changed count: not unchanged.
    assert!(!ab_idle_hold_across_commits(
        &[record(10, 1, "counted"), commit, record(20, 2, "counted")],
        "c0",
        "m1",
        &first,
        100
    ));
}

/// C5.1 cell 4: `--system`, production path. A-then-B: the caller maps and
/// uses provider A from the start (admitted), performs one A call after
/// capture starts (the post-gate1 eager call, caching the caller), then
/// maps provider B — a second provider instance — strictly after capture
/// starts. B sits mapped-but-idle through a quarantine, publishes exactly
/// one counted call (`C_Initialize`), waits several passes idle, then runs
/// the rest. The stream must show B discovered after its gate with A
/// already counted (P3's cached-caller sequence), B's first counted record
/// (published before gate2) at exactly that one call, an unchanged counted
/// observation across a distinct idle commit, growth after release, and
/// ledger-exact final counts for both edges. Lifecycle loss voids the
/// cell (it fails) instead of passing vacuously.
#[test]
#[ignore = "root-owned live BPF lane; native lane --system counts a late second module's first call exactly"]
fn privileged_native_lane_system_ab_first_count_lp64() -> Result<()> {
    let workload = Workload::build()?;
    // B is a second copy of the provider: a distinct (path, ino) module.
    let b_path = workload.path("b-provider.so");
    std::fs::copy(SOFTHSM, &b_path)?;
    let gate = workload.path("gate");
    let gate2 = workload.path("gate2");
    let gate_arg = gate.to_str().context("gate path")?.to_string();
    let gate2_arg = gate2.to_str().context("gate2 path")?.to_string();
    let b_arg = b_path.to_str().context("B path")?.to_string();
    let ab = workload.spawn(
        "AB",
        &[
            "mech",
            "--cell",
            "AB",
            "--module",
            SOFTHSM,
            "--module",
            &b_arg,
            "--iters",
            "2",
            "--late-from",
            "1",
            "--gate",
            &gate_arg,
            "--delay-ms",
            "5000",
            "--single-call",
            "1",
            "--gate2",
            &gate2_arg,
            "--hold",
        ],
    )?;
    let ab_out = workload.path("AB.out");
    let ab_text = || std::fs::read_to_string(&ab_out).unwrap_or_default();
    ensure!(
        !ab_text()
            .lines()
            .any(|line| line.starts_with("MAPPED ") && line.contains("b-provider.so")),
        "B mapped before its gate"
    );
    let started = Instant::now();
    let gate1_ns = Cell::new(0u64);
    let gate2_ns = Cell::new(0u64);
    let init_seen_at = RefCell::new(None::<Instant>);
    let done_at = RefCell::new(None::<Instant>);
    let events = workload.path("system.jsonl");
    let stop = || {
        if gate1_ns.get() == 0 && started.elapsed() > Duration::from_secs(3) {
            let _ = std::fs::write(&gate, b"");
            gate1_ns.set(monotonic_ns());
        }
        if gate1_ns.get() != 0
            && init_seen_at.borrow().is_none()
            && ab_text().lines().any(|line| {
                line.starts_with("LEDGER ")
                    && line.contains("b-provider.so")
                    && line.contains("fn=C_Initialize")
            })
        {
            *init_seen_at.borrow_mut() = Some(Instant::now());
        }
        // B's single call is done; hold it idle across several passes so
        // the first count must sit still before any later increment.
        if gate2_ns.get() == 0
            && init_seen_at
                .borrow()
                .is_some_and(|at| at.elapsed() > Duration::from_secs(6))
        {
            let _ = std::fs::write(&gate2, b"");
            gate2_ns.set(monotonic_ns());
        }
        if done_at.borrow().is_none() && ab.has("DONE ") {
            *done_at.borrow_mut() = Some(Instant::now());
        }
        done_at
            .borrow()
            .is_some_and(|at| at.elapsed() > Duration::from_secs(3))
            || started.elapsed() > Duration::from_secs(120)
    };
    let modules = vec![PathBuf::from(SOFTHSM), b_path.clone()];
    let (document, stream) = run_product_modules(InspectScope::System, &modules, &events, &stop)?;
    ensure!(gate1_ns.get() != 0, "gate1 never opened");
    ensure!(gate2_ns.get() != 0, "gate2 never opened");
    ensure!(done_at.borrow().is_some(), "the AB ledger never finished");
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

    // The workload's ground truth: every call rv==0, B's Initialize alone.
    let ledger = parse_ledger(&ab_text());
    ensure!(
        ledger.iter().all(|entry| entry.bad == 0),
        "workload calls failed"
    );
    let sum = |module: &str, want: &dyn Fn(&LedgerEntry) -> bool| -> u64 {
        ledger
            .iter()
            .filter(|entry| entry.module.ends_with(module) && want(entry))
            .map(|entry| entry.n)
            .sum()
    };
    let always = |_: &LedgerEntry| true;
    let a_total = sum("libsofthsm2.so", &always);
    let a_setup = sum("libsofthsm2.so", &|entry| entry.phase == "setup");
    let b_total = sum("b-provider.so", &always);
    let b_gfl = sum("b-provider.so", &|entry| entry.func == "C_GetFunctionList");
    let b_init = sum("b-provider.so", &|entry| {
        entry.func == "C_Initialize" && entry.phase == "setup"
    });
    ensure!(a_total > a_setup, "A ledger has no main-phase calls");
    ensure!(b_init == 1, "B ledger Initialize count: {b_init}");
    ensure!(b_total > b_gfl + b_init, "B ledger has no post-gate2 calls");
    ensure!(
        ab_text()
            .lines()
            .filter(|line| line.starts_with("MAPPED "))
            .count()
            == 2,
        "expected A and B mappings"
    );

    // Two distinct module instances, one caller, two edges. Same-file
    // instances are distinct (another host process may map the provider
    // too), so our modules resolve through our caller's edges — never by
    // a bare path match — with the instance inode cross-checked.
    let callers = document["callers"].as_array().context("callers")?;
    let caller_id = callers
        .iter()
        .find(|caller| caller["pid"] == ab.pid())
        .and_then(|caller| caller["id"].as_str())
        .context("AB caller missing")?;
    let doc_modules = document["modules"].as_array().context("modules")?;
    let edges = doc_edges(&document, ab.pid());
    ensure!(edges.len() == 2, "AB edges: {edges:?}");
    let (mut edge_a, mut edge_b) = (None, None);
    for edge in &edges {
        let module = doc_modules
            .iter()
            .find(|module| module["id"] == edge["module"])
            .context(format!("edge module missing: {edge}"))?;
        let paths = module["paths"].as_array().context("module paths")?;
        let is = |suffix: &str| {
            paths
                .iter()
                .any(|path| path.as_str().is_some_and(|p| p.ends_with(suffix)))
        };
        if is("b-provider.so") {
            edge_b = Some((*edge, module));
        } else if is("libsofthsm2.so") {
            edge_a = Some((*edge, module));
        }
    }
    let (edge_a, module_a) = edge_a.context(format!("A edge missing in {edges:?}"))?;
    let (edge_b, module_b) = edge_b.context(format!("B edge missing in {edges:?}"))?;
    ensure!(module_a["id"] != module_b["id"], "A and B share one module");
    use std::os::unix::fs::MetadataExt;
    ensure!(
        module_a["identity"]["inode"] == std::fs::metadata(SOFTHSM)?.ino(),
        "A module inode: {}",
        module_a["identity"]
    );
    ensure!(
        module_b["identity"]["inode"] == std::fs::metadata(&b_path)?.ino(),
        "B module inode: {}",
        module_b["identity"]
    );
    let mod_a = edge_a["module"].as_str().context("A edge module id")?;
    let mod_b = edge_b["module"].as_str().context("B edge module id")?;

    let lines: Vec<serde_json::Value> = stream
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let admitted_ns = lines
        .iter()
        .find(|line| {
            line["kind"] == "caller_event"
                && line["event"]["event"] == "admitted"
                && line["event"]["caller"] == caller_id
        })
        .and_then(|line| line["at_ns"].as_u64())
        .context("AB caller never admitted")?;
    let (series_a, malformed_a) = edge_series(&lines, caller_id, mod_a);
    let (series_b, malformed_b) = edge_series(&lines, caller_id, mod_b);
    ensure!(
        malformed_a == 0 && malformed_b == 0,
        "malformed edge records"
    );
    ensure!(!series_b.is_empty(), "B never observed");

    // Host exec churn can still overflow the DISCOVERY ring in a window
    // the lane does not service: then the edge is honestly counted, or
    // unknown with reason `loss` — never a watch (the C5.2 demotion).
    let witnesses = &document["observation"]["native_witnesses"];
    ab_lifecycle_loss_verdict(
        ab_lifecycle_loss_detected(&document),
        edge_a,
        edge_b,
        witnesses,
    )?;

    // P3's sequence: the caller was admitted before B was ever observed,
    // and B was observed strictly after its gate opened.
    ensure!(
        admitted_ns < series_b[0].at_ns,
        "caller admitted at {admitted_ns}, B first observed at {}",
        series_b[0].at_ns
    );
    ensure!(
        series_b[0].at_ns > gate1_ns.get(),
        "B first observed at {}, gate1 opened at {}",
        series_b[0].at_ns,
        gate1_ns.get()
    );
    // B mapped-but-idle through the quarantine, then exactly one call:
    // every record before the first counted one carries no calls (the
    // lane's idle vocabulary — unknown, watched_no_use, quiet — is its
    // own business), and nothing is ever dropped in this run.
    let render = |series: &[EdgeRecord]| {
        series
            .iter()
            .map(|record| {
                format!(
                    "+{}ms:{}:{}",
                    record.at_ns.saturating_sub(gate1_ns.get()) / 1_000_000,
                    record.state,
                    record.count
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let first_counted = series_b
        .iter()
        .find(|record| record.state == "counted")
        .context(format!("B never counted in {}", render(&series_b)))?;
    // Round 2 (F5/S7): the first count must publish before the idle
    // window ends — otherwise the idle hold below is vacuous.
    ensure!(
        first_counted.at_ns < gate2_ns.get(),
        "B first counted at {}, gate2 opened at {}: the first count must publish before the idle window ends",
        first_counted.at_ns,
        gate2_ns.get()
    );
    ensure!(
        series_b
            .iter()
            .take_while(|record| record.state != "counted")
            .all(|record| record.count == 0 && record.state != "dropped"),
        "B claimed calls before its first use in {}",
        render(&series_b)
    );
    ensure!(
        series_a
            .iter()
            .chain(series_b.iter())
            .all(|record| record.state != "dropped"),
        "a count was dropped"
    );
    ensure!(
        first_counted.count == b_init,
        "B first count {} != ledger Initialize {b_init}",
        first_counted.count
    );
    // No increment across the idle passes: nothing above the first count
    // before gate2 opened — plus a nonvacuous hold (round 2, F5/S7):
    // an unchanged counted observation across a distinct idle commit
    // before the release — then growth after the release.
    ensure!(
        series_b
            .iter()
            .filter(|record| record.at_ns < gate2_ns.get())
            .all(|record| record.count <= first_counted.count),
        "B incremented before gate2"
    );
    ensure!(
        ab_idle_hold_across_commits(&lines, caller_id, mod_b, first_counted, gate2_ns.get()),
        "B's first count never held still across an idle commit before gate2 in {}",
        render(&series_b)
    );
    ensure!(
        series_b
            .iter()
            .any(|record| record.at_ns > gate2_ns.get() && record.count > first_counted.count),
        "B never grew after gate2"
    );
    ensure!(
        series_b
            .windows(2)
            .all(|pair| pair[0].count <= pair[1].count),
        "B counts went backwards"
    );
    // P3's cached-caller premise (round 2, F5): the workload performs
    // an A call after capture starts (the post-gate1 eager call,
    // before B maps), so A counts strictly before B's first counted
    // record — the caller is cached before B is ever observed. (A's
    // main phase runs after the release too.)
    let a_first_counted = series_a
        .iter()
        .find(|record| record.state == "counted")
        .context("A never counted")?;
    ensure!(
        a_first_counted.at_ns > gate1_ns.get(),
        "A first counted at {}, gate1 opened at {}: the premise call must run after capture starts",
        a_first_counted.at_ns,
        gate1_ns.get()
    );
    ensure!(
        a_first_counted.at_ns < first_counted.at_ns,
        "A first counted at {}, B first counted at {}: the cached-caller premise needs A first",
        a_first_counted.at_ns,
        first_counted.at_ns
    );
    // Ledger-exact finals: B missed nothing (its only pre-attach call is
    // the uncounted dlsym acquisition); A missed exactly its pre-capture
    // setup.
    ensure!(
        edge_b["entries"]["coverage"]["state"] == "counted",
        "B final edge: {edge_b}"
    );
    ensure!(
        edge_b["entries"]["count"] == b_total - b_gfl,
        "B final count {} != ledger {}",
        edge_b["entries"]["count"],
        b_total - b_gfl
    );
    ensure!(
        edge_a["entries"]["coverage"]["state"] == "counted",
        "A final edge: {edge_a}"
    );
    ensure!(
        edge_a["entries"]["count"] == a_total - a_setup,
        "A final count {} != ledger {}",
        edge_a["entries"]["count"],
        a_total - a_setup
    );
    ensure!(
        witnesses["unbound_reasons"]
            .get("exec_coverage_gap")
            .is_none(),
        "{witnesses}"
    );
    ensure!(stream_ended(&stream), "the stream did not end");
    eprintln!(
        "C51_AB pid={} passes={} a_final={} b_first={} b_final={} witnesses={witnesses}",
        ab.pid(),
        document["observation"]["passes"],
        edge_a["entries"]["count"],
        first_counted.count,
        edge_b["entries"]["count"],
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
        edges.len() == 1
            && edges[0]["entries"]["coverage"]["state"] == "counted"
            && edges[0]["entries"]["count"]
                .as_u64()
                .is_some_and(|count| count >= 1),
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
        inventory_scope: Some(inventory_scope),
        scope: InspectScope::Pid(target.pid()).into(),
        cgroup: None,
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
    // Review R4: `P11SCOPE_CELL_SCOPE=pid` captures the first mapper only
    // (its providers, each still mapped by every round), as `--pid` would.
    let pid_scope = match std::env::var("P11SCOPE_CELL_SCOPE").as_deref() {
        Ok("pid") => Some(mappers[0].pid()),
        Ok("system") | Err(_) => None,
        Ok(other) => bail!("P11SCOPE_CELL_SCOPE={other}: expected system or pid"),
    };
    let (engine_scope, capture_scope, inspect_scope, expected) = match pid_scope {
        Some(pid) => (
            Scope::Pid(pid),
            crate::attach::capture::CaptureScope::Pid(
                PidPin::open(pid).map_err(anyhow::Error::msg)?,
            ),
            InspectScope::Pid(pid),
            copies.min(4) * 68,
        ),
        None => (
            Scope::System,
            crate::attach::capture::CaptureScope::System,
            InspectScope::System,
            copies * 68,
        ),
    };
    let mut coordinator = InventoryCoordinator::new(
        engine_scope,
        HookRegistry::builtin(),
        providers.clone(),
        OsProcessSource,
        RegistryLimits::default_limits(),
    )?;
    let probe = Probe::new(FacadeLane::prepare(
        capture_scope,
        coordinator.attach_set().budget(),
        selection,
    )?);
    let attached = Rc::clone(&probe.attached);
    let lane = NativeLane::start(probe, &mut coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| anyhow::anyhow!("{reason}"))?;
    let attached_at = Cell::new(None::<u64>);
    let stopped = drive(&mut coordinator, inspect_scope, lane, &mut |passes| {
        if attached_at.get().is_none() && attached.get() >= expected {
            attached_at.set(Some(passes));
        }
        Ok(attached_at.get().is_some_and(|at| passes >= at + 2) || passes >= 40)
    })?;
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
        "C511_SCALE scope={} selection={} mechanism={} fallback={:?} copies={copies} expected={expected} \
         mappers={} attached={} failed={} passes={} links={} attach_ms={} \
         attach_link_max_ms={:.1} extend_attach_max_ms={:.1} budget_ms={} retired_ms={:?} \
         retirement={} cleanup={cleanup:?}",
        if pid_scope.is_some() { "pid" } else { "system" },
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
        (pid_scope.is_some() || summary.attached >= 400)
            && summary.attached >= expected
            && summary.failed == 0,
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
        && (pid_scope.is_none() || crate::attach::kernel_multi_pid_filter().is_ok())
    {
        ensure!(
            backend.mechanism() == "uprobe-multi" && backend.fallback.is_none(),
            "auto did not take uprobe-multi on a capable kernel: {backend:?}"
        );
    }
    drop(mappers);
    Ok(())
}
