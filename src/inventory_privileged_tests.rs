//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned, ignored live gates for the native inventory lane (Task 6 C5.1),
//! plus the D3d forced-kernel sweep cells (production identity proof over
//! owned btrfs fixtures through the production classic path).
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
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: None,
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        identity: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    let stop = Cell::new(false);
    let stop_now = || stop.get();
    let clock = LoopClock {
        deadline,
        stop: &stop_now,
        now: &Instant::now,
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
    )
    .map_err(|outcome| {
        assert!(
            outcome.retained.is_none(),
            "this semantic:None test driver is synchronous: {outcome:?}"
        );
        outcome
            .error
            .expect("a synchronous loop failure has its error")
    })?;
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

#[cfg(test)]
#[path = "inventory_privileged_tests/operator_diagnostics_wrap.rs"]
mod operator_diagnostics_wrap;

const DEMOTION_PREBUILT_FILES: [&str; 4] = [
    "libdemotion-common.so",
    "provider-A.so",
    "provider-B.so",
    "workload",
];

/// Explicit test-only opt-in. A bad payload refuses; it never falls back to a
/// local build on a host whose selected test route requires prebuilt inputs.
fn copy_demotion_prebuilt(source: &Path, destination: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        source.is_absolute(),
        "prebuilt demotion directory must be absolute"
    );
    let mut inputs = Vec::new();
    for name in DEMOTION_PREBUILT_FILES {
        let path = source.join(name);
        let metadata = std::fs::symlink_metadata(&path)
            .with_context(|| format!("reading prebuilt demotion input {}", path.display()))?;
        ensure!(
            metadata.file_type().is_file(),
            "prebuilt demotion input must be a regular nonsymlink file: {}",
            path.display()
        );
        ensure!(
            name != "workload" || metadata.permissions().mode() & 0o111 != 0,
            "prebuilt demotion workload must be executable"
        );
        inputs.push((path, name, metadata.permissions()));
    }
    // Validate all four before making the test's private execution copies.
    for (path, name, permissions) in inputs {
        let target = destination.join(name);
        std::fs::copy(&path, &target)
            .with_context(|| format!("copying prebuilt demotion input {}", path.display()))?;
        std::fs::set_permissions(target, permissions)?;
    }
    Ok(())
}

#[test]
fn demotion_prebuilt_copies_exact_inputs_and_executable_permissions() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    for name in DEMOTION_PREBUILT_FILES {
        let path = source.path().join(name);
        std::fs::write(&path, name.as_bytes())?;
        let mode = if name == "workload" { 0o750 } else { 0o640 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    }
    copy_demotion_prebuilt(source.path(), destination.path())?;
    for name in DEMOTION_PREBUILT_FILES {
        let path = destination.path().join(name);
        ensure!(std::fs::read(&path)? == name.as_bytes());
        let mode = if name == "workload" { 0o750 } else { 0o640 };
        ensure!(std::fs::metadata(path)?.permissions().mode() & 0o777 == mode);
    }
    Ok(())
}

#[test]
fn demotion_prebuilt_refuses_relative_missing_symlink_and_nonregular_inputs() -> Result<()> {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let source = tempfile::tempdir()?;
    let destination = tempfile::tempdir()?;
    ensure!(copy_demotion_prebuilt(Path::new("relative"), destination.path()).is_err());
    ensure!(copy_demotion_prebuilt(source.path(), destination.path()).is_err());
    for name in DEMOTION_PREBUILT_FILES {
        std::fs::write(source.path().join(name), name)?;
    }
    ensure!(copy_demotion_prebuilt(source.path(), destination.path()).is_err());
    let workload = source.path().join("workload");
    std::fs::set_permissions(&workload, std::fs::Permissions::from_mode(0o750))?;
    let provider = source.path().join("provider-A.so");
    std::fs::remove_file(&provider)?;
    symlink(source.path().join("provider-B.so"), &provider)?;
    ensure!(copy_demotion_prebuilt(source.path(), destination.path()).is_err());
    std::fs::remove_file(&provider)?;
    std::fs::create_dir(&provider)?;
    ensure!(copy_demotion_prebuilt(source.path(), destination.path()).is_err());
    ensure!(std::fs::read_dir(destination.path())?.next().is_none());
    Ok(())
}

impl DemotionWorkload {
    fn spawn() -> Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = tempfile::tempdir()?;
        if let Some(prebuilt) = std::env::var_os("P11SCOPE_DEMOTION_PREBUILT_DIR") {
            copy_demotion_prebuilt(Path::new(&prebuilt), dir.path())?;
        } else {
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
        None,
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
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: None,
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        identity: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    let stop = || flag.stopped();
    let clock = LoopClock {
        deadline,
        stop: &stop,
        now: &Instant::now,
        interval: POLL_INTERVAL,
        tick: SERVICE_TICK,
        collection_tick: SERVICE_TICK,
    };
    let began = Instant::now();
    let stopped = run_classic(&mut driver, Some(lane), &clock, &mut |_, _| Ok(()))
        .map_err(|outcome| {
            assert!(
                outcome.retained.is_none(),
                "this semantic:None test driver is synchronous: {outcome:?}"
            );
            outcome
                .error
                .expect("a synchronous loop failure has its error")
        })?
        .context("a native run stops its lane")?;
    // The run is over: end the driver's coordinator borrow before the
    // direct coordinator reads below (its Drop would extend it).
    drop(driver);
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

// ---------------------------------------------------------------------------
// D3d privileged gates: forced-kernel production proof cells.
// ---------------------------------------------------------------------------

use std::collections::BTreeSet;

/// D3d forced-kernel sweep fixtures: three holders dlopen the complete
/// provider ELF through the normal loader, a fourth maps a byte-identical
/// different file, a fifth maps the provider data-only. All are direct
/// children of the test process (the observer), on a proof-requiring
/// btrfs fixture root, with independent /proc ground truth. Killed and
/// reaped on drop.
struct IdentitySweep {
    provider: PathBuf,
    holders: Vec<u32>,
    holder_ranges: Vec<Vec<(u64, u64)>>,
    copy_pid: u32,
    dataonly_pid: u32,
    children: Vec<Child>,
    _dir: tempfile::TempDir,
}

impl Drop for IdentitySweep {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
        }
        for child in &mut self.children {
            let _ = child.wait();
        }
    }
}

impl IdentitySweep {
    fn manifest(rel: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    fn gcc(dir: &Path, out: &str, source: &Path, args: &[&str], libs: &[&str]) -> Result<PathBuf> {
        let bin = dir.join(out);
        let status = Command::new("gcc")
            .args(args)
            .arg("-o")
            .arg(&bin)
            .arg(source)
            .args(libs)
            .status()
            .context("running gcc")?;
        ensure!(status.success(), "gcc failed for {out}");
        Ok(bin)
    }

    /// Whether `dir` lives on btrfs (statfs magic): the proof-requiring
    /// filesystem these cells demand for their fixtures.
    fn dir_is_btrfs(dir: &Path) -> Result<bool> {
        use std::os::unix::ffi::OsStrExt as _;
        const BTRFS_SUPER_MAGIC: u64 = 0x9123_683e;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        // SAFETY: statfs writes the whole struct on success.
        let rc = unsafe { libc::statfs(path.as_ptr(), stat.as_mut_ptr()) };
        ensure!(
            rc == 0,
            "statfs {}: {}",
            dir.display(),
            std::io::Error::last_os_error()
        );
        // SAFETY: success above initialized it.
        let stat = unsafe { stat.assume_init() };
        // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
        #[allow(clippy::unnecessary_cast)]
        Ok(stat.f_type as u64 == BTRFS_SUPER_MAGIC)
    }

    /// Independent ground truth: executable mappings of `provider` in `pid`
    /// from /proc, read without the observer.
    fn exec_ranges_for(pid: u32, provider: &Path) -> Result<Vec<(u64, u64)>> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))?;
        let target = provider.to_str().context("provider path")?.to_string();
        let mut ranges = Vec::new();
        for line in maps.lines() {
            let mut parts = line.split_whitespace();
            let range = parts.next().unwrap_or("");
            let perms = parts.next().unwrap_or("");
            for _ in 0..3 {
                parts.next();
            }
            let path = parts.next().unwrap_or("");
            if perms.starts_with("r-x")
                && path == target
                && let Some((low, high)) = range.split_once('-')
                && let (Ok(low), Ok(high)) =
                    (u64::from_str_radix(low, 16), u64::from_str_radix(high, 16))
            {
                ranges.push((low, high));
            }
        }
        Ok(ranges)
    }

    fn sha256_file(path: &Path) -> Result<String> {
        use sha2::Digest as _;
        let mut digest = sha2::Sha256::new();
        digest.update(std::fs::read(path)?);
        Ok(digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    fn build(so_name: &str, minor: u32) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        ensure!(
            Self::dir_is_btrfs(dir.path())?,
            "D3d kernel cell needs TMPDIR on btrfs (proof-requiring fixtures); run by hand \
             as root: TMPDIR=<btrfs dir> <libtest> --exact <path> --ignored --test-threads=1 \
             --nocapture"
        );
        let driver = Self::gcc(
            dir.path(),
            "driver",
            &Self::manifest("tests/fixtures/catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        )?;
        let dataonly = Self::gcc(
            dir.path(),
            "dataonly",
            &Self::manifest("tests/fixtures/identity-dataonly.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &[],
        )?;
        let minor_flag = format!("-DLEGACY_MINOR={minor}");
        let provider = Self::gcc(
            dir.path(),
            so_name,
            &Self::manifest("crates/discover/tests/fixture/version_matrix.c"),
            &["-shared", "-fPIC", &minor_flag],
            &[],
        )?;
        let copy = dir.path().join("gate-copy.so");
        std::fs::copy(&provider, &copy)?;
        ensure!(
            std::fs::read(&provider)? == std::fs::read(&copy)?,
            "byte-identical copy"
        );
        let mut children = Vec::new();
        let mut spawn = |name: &str, binary: &Path, lib: &Path| -> Result<u32> {
            let ready = dir.path().join(format!("{name}.ready"));
            let log = std::fs::File::create(dir.path().join(format!("{name}.log")))?;
            children.push(
                Command::new(binary)
                    .arg("--ready")
                    .arg(&ready)
                    .arg("--sleep")
                    .arg("300")
                    .arg(lib)
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(log.try_clone()?))
                    .stderr(Stdio::from(log))
                    .spawn()?,
            );
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if let Ok(text) = std::fs::read_to_string(&ready)
                    && let Some(pid) = text.split_whitespace().nth(1)
                {
                    return pid.parse().context("ready pid");
                }
                ensure!(Instant::now() < deadline, "{name} never became ready");
                std::thread::sleep(Duration::from_millis(50));
            }
        };
        let mut holders = Vec::new();
        for name in ["H1", "H2", "H3"] {
            holders.push(spawn(name, &driver, &provider)?);
        }
        let copy_pid = spawn("C", &driver, &copy)?;
        let dataonly_pid = spawn("D", &dataonly, &provider)?;
        // Ground truth while holders live (mappings are static sleeps).
        let mut holder_ranges = Vec::new();
        for pid in &holders {
            let ranges = Self::exec_ranges_for(*pid, &provider)?;
            ensure!(!ranges.is_empty(), "holder {pid} maps the provider exec");
            holder_ranges.push(ranges);
        }
        Ok(Self {
            provider,
            holders,
            holder_ranges,
            copy_pid,
            dataonly_pid,
            children,
            _dir: dir,
        })
    }

    /// One production run with forced kernel over this sweep.
    fn run_forced_kernel(
        &self,
        cap: usize,
        duration: Option<Duration>,
        stop: &dyn Fn() -> bool,
    ) -> Result<serde_json::Value> {
        let mut stdout = Vec::new();
        let code = run_with_terminal_diagnostics(
            InspectScope::System,
            std::slice::from_ref(&self.provider),
            &HookRegistry::builtin(),
            true,
            Some(cap),
            None,
            duration,
            None,
            false,
            None,
            None,
            None,
            CaptureMode::Scan,
            crate::attach::BackendSelection::Auto,
            Some(crate::cli::IdentityBackendSelection::Kernel),
            stop,
            &|| {},
            false,
            &mut crate::inventory_output::WriterStdout(&mut stdout),
            &DashboardIo::stdio(),
            DiagnosticRequest::disabled(),
            None,
        )?;
        ensure!(code == 0, "exit code {code}");
        Ok(serde_json::from_slice(&stdout)?)
    }

    fn callers_for(doc: &serde_json::Value, pid: u64) -> Vec<&serde_json::Value> {
        doc["callers"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|caller| caller["pid"] == pid)
            .collect()
    }

    /// The full positive gate: kernel backend with no fallback, the exact
    /// three holder/provider edges, zero false edges over all enumerated
    /// module edges, both negatives un-edged, and per-range coverage of
    /// every owned requested exec range.
    fn assert_kernel_positive(&self, doc: &serde_json::Value, so_name: &str) -> Result<()> {
        ensure!(
            doc["observation"]["identity"]["backend"] == "kernel",
            "identity: {}",
            doc["observation"]["identity"]
        );
        ensure!(
            doc["observation"]["identity"]["fallback"].is_null(),
            "identity: {}",
            doc["observation"]["identity"]
        );
        let modules: Vec<&serde_json::Value> = doc["modules"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|module| {
                module["paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|path| path.as_str().unwrap().rsplit('/').next().unwrap() == so_name)
            })
            .collect();
        ensure!(modules.len() == 1, "exactly one module for {so_name}");
        let module_id = modules[0]["id"].as_str().unwrap();
        let mut edge_callers = BTreeSet::new();
        for edge in doc["edges"].as_array().unwrap() {
            if edge["module"] == module_id {
                edge_callers.insert(edge["caller"].as_str().unwrap().to_string());
            }
        }
        ensure!(edge_callers.len() == 3, "complete expected edge set");
        for pid in &self.holders {
            let callers = Self::callers_for(doc, u64::from(*pid));
            ensure!(callers.len() == 1, "holder {pid} is one caller");
            ensure!(
                edge_callers.contains(callers[0]["id"].as_str().unwrap()),
                "holder {pid} keeps its kernel edge"
            );
        }
        for caller_id in &edge_callers {
            let pid = doc["callers"]
                .as_array()
                .unwrap()
                .iter()
                .find(|caller| caller["id"] == *caller_id)
                .unwrap()["pid"]
                .as_u64()
                .unwrap() as u32;
            ensure!(
                self.holders.contains(&pid),
                "edge caller {caller_id} (pid {pid}) is a ledgered holder"
            );
        }
        ensure!(
            !Self::callers_for(doc, u64::from(self.copy_pid)).is_empty(),
            "copy holder is an inventoried caller"
        );
        for (pid, why) in [
            (self.copy_pid, "byte-identical different file"),
            (self.dataonly_pid, "data-only mapping"),
        ] {
            for caller in Self::callers_for(doc, u64::from(pid)) {
                ensure!(
                    !edge_callers.contains(caller["id"].as_str().unwrap()),
                    "{why} (pid {pid}) must not edge to the original provider"
                );
            }
        }
        // Per-range coverage: every ground-truth set is nonempty and the
        // same provider maps uniformly, and all three holders edge — an
        // edge is all caller ranges or nothing.
        let counts: Vec<usize> = self.holder_ranges.iter().map(Vec::len).collect();
        ensure!(counts.iter().all(|count| *count >= 1), "{counts:?}");
        ensure!(
            counts.iter().all(|count| *count == counts[0]),
            "uniform provider layout: {counts:?}"
        );
        Ok(())
    }
}

/// Live processes on this host (numeric /proc entries): a sweep cap is
/// only attempted past it, so every attempt forces sweep proof.
fn live_process_count() -> u64 {
    std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.bytes().all(|b| b.is_ascii_digit()))
                })
                .count() as u64
        })
        .unwrap_or(0)
}

/// D3d privileged gate: forced kernel proves the full ledgered sweep set
/// through the production classic path on a proof-requiring btrfs
/// fixture — exact three holder/provider edges, zero false edges, both
/// negatives, per-range coverage, `backend == kernel`, `fallback ==
/// null`. A refused host fails here (no environment skip): the gate
/// names a kernel-identity-capable host.
#[test]
#[ignore = "root-owned live BPF lane; D3d forced-kernel sweep cell over a btrfs fixture"]
fn privileged_identity_kernel_sweep_cell_lp64() -> Result<()> {
    let sweep = IdentitySweep::build("gate-k1.so", 242)?;
    let procs = live_process_count();
    let mut last = String::new();
    for cap in [8usize, 32, 128] {
        if procs <= cap as u64 {
            last = format!("cap {cap}: skipped (only {procs} live processes)");
            continue;
        }
        let doc = sweep.run_forced_kernel(cap, None, &|| false)?;
        let identity = &doc["observation"]["identity"];
        if identity["backend"] == "kernel" && identity["fallback"].is_null() {
            sweep.assert_kernel_positive(&doc, "gate-k1.so")?;
            eprintln!(
                "D3D_KERNEL_CELL mode=single cap={cap} edges=3/3 ranges={:?} \
                 provider_sha256={} backend=kernel fallback=null",
                sweep.holder_ranges.iter().map(Vec::len).collect::<Vec<_>>(),
                IdentitySweep::sha256_file(&sweep.provider)?,
            );
            return Ok(());
        }
        last = format!(
            "cap {cap}: backend={} fallback={}",
            identity["backend"], identity["fallback"]
        );
    }
    bail!("no cap proved the forced-kernel cell (live procs {procs}): {last}");
}

/// D3d privileged gate: forced kernel sustains the full positive cell
/// across repeated passes on its one capture-owned session (per-pass
/// fresh installs under fresh generations, sticky status and counters
/// shared): at least two passes, then the exact edges, zero false
/// edges, both negatives, per-range coverage, `backend == kernel`,
/// `fallback == null` in the final document.
#[test]
#[ignore = "root-owned live BPF lane; D3d forced-kernel multi-pass session reuse over a btrfs fixture"]
fn privileged_identity_kernel_multipass_reuse_lp64() -> Result<()> {
    let sweep = IdentitySweep::build("gate-k2.so", 243)?;
    let procs = live_process_count();
    // Find a cap with a selected supplier first (single snapshots, as in
    // the single-pass gate); the multipass run then reuses that cap.
    let mut cap = None;
    for candidate in [8usize, 32, 128] {
        if procs <= candidate as u64 {
            continue;
        }
        let doc = sweep.run_forced_kernel(candidate, None, &|| false)?;
        if doc["observation"]["identity"]["backend"] == "kernel"
            && doc["observation"]["identity"]["fallback"].is_null()
        {
            sweep.assert_kernel_positive(&doc, "gate-k2.so")?;
            cap = Some(candidate);
            break;
        }
    }
    let cap = cap.context("no cap proved the forced-kernel cell")?;
    let started = Instant::now();
    let doc = sweep.run_forced_kernel(cap, Some(Duration::from_secs(30)), &|| {
        started.elapsed() > Duration::from_secs(12)
    })?;
    let passes = doc["observation"]["passes"].as_u64().unwrap_or(0);
    ensure!(
        passes >= 2,
        "expected repeated installs, got {passes} pass(es)"
    );
    sweep.assert_kernel_positive(&doc, "gate-k2.so")?;
    eprintln!(
        "D3D_KERNEL_CELL mode=multi cap={cap} passes={passes} edges=3/3 ranges={:?} \
         provider_sha256={} backend=kernel fallback=null",
        sweep.holder_ranges.iter().map(Vec::len).collect::<Vec<_>>(),
        IdentitySweep::sha256_file(&sweep.provider)?,
    );
    Ok(())
}

/// A SoftHSM2 manifest for the live joint-finish cell: the recipe is
/// the fixture manifest's (attach privileged tests), with the entry
/// offsets discovered from the installed provider's ELF.
fn softhsm_joint_manifest(workload: &Workload) -> Result<std::path::PathBuf> {
    use anyhow::Context as _;
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;
    let path = std::path::Path::new(SOFTHSM);
    ensure!(path.exists(), "SoftHSM2 provider {SOFTHSM} is missing");
    let file = open_object(path).map_err(anyhow::Error::msg)?;
    let inspected = inspect_file(&file).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = std::fs::File::open(path)?;
    let snapshot = p11scope_manifest::elf::ElfSnapshot::read(&elf).map_err(anyhow::Error::msg)?;
    let mut offsets = Vec::new();
    for name in ["C_SignInit", "C_Sign"] {
        let fact = snapshot
            .defined_symbol(name)
            .map_err(anyhow::Error::msg)?
            .with_context(|| format!("SoftHSM2 exports no {name}"))?;
        offsets.push(fact.file_offset);
    }
    let functions = match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
        version: cryptoki_sys::CK_VERSION {
            major: 2,
            minor: 40,
        },
    }) {
        pkcs11_module::TableSet::Walk(spans) => spans
            .iter()
            .flat_map(|span| span.fields())
            .map(|field| {
                let resolution = match field.name {
                    "C_SignInit" => Resolution::Resolved {
                        object: 0,
                        file_offset: offsets[0],
                    },
                    "C_Sign" => Resolution::Resolved {
                        object: 0,
                        file_offset: offsets[1],
                    },
                    _ => Resolution::NullPointer,
                };
                FunctionRecord {
                    name: field.name.into(),
                    resolution,
                }
            })
            .collect(),
        _ => anyhow::bail!("2.40 is a full standard table"),
    };
    let path = path.to_str().context("SoftHSM2 path")?.to_string();
    let manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: path.clone(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.clone(),
            identity: inspected.identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path,
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity: inspected.identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version {
                major: 2,
                minor: 40,
            }),
            walk: WalkOutcome::Full,
            functions,
        }],
        vendor_interfaces: Vec::new(),
        alias_groups: Vec::new(),
        selection_evidence: Default::default(),
    };
    ensure!(
        crate::manifest_input::validate_structure(&manifest).is_empty(),
        "the SoftHSM2 manifest is well-formed"
    );
    let manifest_path = workload.path("joint-live.dr37.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    Ok(manifest_path)
}

/// R1.4 live-machine joint-finish cell: a real semantic lane over a
/// SoftHSM2 ledger target drives the T14 finish driver from begin
/// to Published to WoundDown. The begin returning Ok (M1) and the
/// poll reaching Published (M3) are the only arms unit tests cannot
/// build a live machine for; both are asserted here, then the lane
/// finishes H0, winds down and hands its session over. Prints
/// JOINT_LIVE lines. Root BPF lane, serial.
#[test]
#[ignore = "privileged: live joint machine begin to Published to WoundDown through the T14 driver"]
fn privileged_joint_driver_live_finish_begin_poll_wound_down_lp64() -> Result<()> {
    use anyhow::Context as _;
    use std::time::{Duration, Instant};

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
    let manifest = softhsm_joint_manifest(&workload)?;
    let mut coordinator = pid_coordinator(target.pid(), Path::new(SOFTHSM))?;
    coordinator.set_semantic_manifests(vec![manifest]);
    let scope = Scope::Pid(target.pid());
    let attach_subset = coordinator
        .prepare_semantic_subset()
        .subset
        .context("the SoftHSM2 subset prepares")?;
    let convert_subset = coordinator
        .prepare_semantic_subset()
        .subset
        .context("the conversion subset prepares")?;
    let mut lane = crate::inventory_semantics::AttestedSemanticLane::start_live(
        attach_subset,
        convert_subset,
        &scope,
        crate::attach::BackendSelection::Auto,
    )
    .map_err(|refusal| anyhow::anyhow!("live lane attaches: {refusal}"))?;
    ensure!(lane.is_live(), "the lane owns its live session");
    ensure!(
        !lane.has_joint_machine(),
        "no machine before initialization"
    );
    lane.initialize_joint(&coordinator)
        .map_err(|refusal| anyhow::anyhow!("the joint machine initializes: {refusal}"))?;
    ensure!(lane.has_joint_machine(), "the machine initializes live");
    eprintln!("JOINT_LIVE attach=ok machine=ok");

    // Let the ledgered calls flow, then drive the T14 finish driver.
    if !gate.exists() {
        std::fs::write(&gate, b"")?;
    }
    let started = Instant::now();
    while !target.has("DONE ") {
        ensure!(
            started.elapsed() < Duration::from_secs(120),
            "the ledger never finished: {:?}",
            target.lines()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
    let mut driver = ClassicDriver {
        coordinator: &mut coordinator,
        inventory_scope: Some(InventoryScope::Pid(target.pid())),
        scope: InventoryRunScope::Pid(target.pid()),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: Some(lane),
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        identity: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    };
    driver.begin_final_joint_finish();
    ensure!(
        driver.joint_finish == JointFinishDriver::Polling,
        "M1: the live begin returns Ok and polls, got {:?}",
        driver.joint_finish
    );
    ensure!(
        !driver
            .semantic
            .as_ref()
            .expect("lane")
            .joint_finish_disposition_required(),
        "M1: the Ok begin latches nothing"
    );
    eprintln!("JOINT_LIVE begin=ok polling");

    let mut polls = 0;
    loop {
        let outcome = {
            let (coordinator, semantic, finish, first_error) = (
                &mut *driver.coordinator,
                &mut driver.semantic,
                &mut driver.joint_finish,
                &mut driver.joint_first_error,
            );
            ClassicDriver::step_begun_joint_finish(semantic, finish, coordinator, first_error)
        };
        polls += 1;
        // The publish lands in the driver state; the step outcome
        // only reports staying, wound-down or abandoned.
        if driver.joint_finish == JointFinishDriver::Published {
            break;
        }
        ensure!(
            !matches!(outcome, JointStepOutcome::Abandoned),
            "M3: the live poll never abandons"
        );
        ensure!(
            polls < 200,
            "M3: the live poll reaches Published within 200 polls"
        );
    }
    ensure!(
        driver.joint_finish == JointFinishDriver::Published,
        "M3: the live poll publishes, got {:?} after {polls} polls",
        driver.joint_finish
    );
    eprintln!("JOINT_LIVE published_after={polls}");

    // H0 stops through the production finish path, then the detach
    // joins and the session hands over.
    {
        let (coordinator, semantic) = (&mut *driver.coordinator, &mut driver.semantic);
        let lane = semantic.as_mut().expect("lane");
        if let Some(finish) = lane.finish_semantic_stop() {
            coordinator.stage_semantic_batch(finish);
            lane.note_semantic_staged();
            commit_semantic_finish(coordinator, lane)?;
            lane.note_semantic_published();
        }
        ensure!(lane.is_finished(), "H0 stops");
    }
    let mut wound_polls = 0;
    loop {
        let (coordinator, semantic) = (&mut *driver.coordinator, &mut driver.semantic);
        let lane = semantic.as_mut().expect("lane");
        match lane.poll_wound_down(coordinator, &mut std::io::sink()) {
            Ok(true) => break,
            Ok(false) => {}
            Err(refusal) => anyhow::bail!("the live wound-down never refuses: {refusal}"),
        }
        wound_polls += 1;
        ensure!(wound_polls < 600, "the live detach joins within 600 polls");
        std::thread::sleep(Duration::from_millis(10));
    }
    let lane = driver.semantic.as_mut().expect("lane");
    let session = lane
        .take_joined_session()
        .map_err(|refusal| anyhow::anyhow!("the wound-down lane hands its session: {refusal}"))?;
    ensure!(session.is_some(), "the live take hands the session");
    eprintln!("JOINT_LIVE wound_down_after={wound_polls} take=some");
    Ok(())
}

// ---------------------------------------------------------------------------
// R1.6 live Joint root cells: the production classic Session with Joint on,
// over the owned live-joint provider workload. System scope with private
// provider copies (a SoftHSM copy plus the fixture's held provider), so
// exactly the owned processes are observed and every population is exact.
// Each cell drives native discovery passes first (adapter records and
// mapped edges, the machine's binding input), then starts the semantic
// lane, initializes the Joint machine, and drives service/commit/finish
// through the real lane APIs directly; the production on-tick wiring that
// will call the same APIs is a separate pending task. Diagnostics print
// as JOINT_R16 lines.
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn live_joint_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/object-journal/live-joint.c")
}

/// The R1.6 workload: the standard token setup plus the live-joint fixture
/// workload, its held provider and a private SoftHSM copy. Nothing else on
/// the host maps the copies, so System scope observes exactly these owners.
struct JointWorkload {
    workload: Workload,
    joint: PathBuf,
    held: PathBuf,
    soft_copy: PathBuf,
}

impl JointWorkload {
    fn build() -> Result<Self> {
        let workload = Workload::build()?;
        let joint = workload.path("live-joint");
        let held = workload.path("live-joint-held.so");
        let gcc = |args: &[&str], out: &Path| -> Result<()> {
            let status = Command::new("gcc")
                .args(args)
                .arg("-o")
                .arg(out)
                .arg(live_joint_source())
                .arg("-ldl")
                .status()
                .context("running gcc")?;
            ensure!(status.success(), "gcc {args:?} failed");
            Ok(())
        };
        gcc(&["-O1", "-Wall", "-Wextra", "-Werror"], &joint)?;
        gcc(
            &[
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-shared",
                "-fPIC",
                "-DLIVE_JOINT_HELD_PROVIDER",
            ],
            &held,
        )?;
        let soft_copy = workload.path("soft-copy.so");
        std::fs::copy(SOFTHSM, &soft_copy).context("copying SoftHSM2")?;
        Ok(Self {
            workload,
            joint,
            held,
            soft_copy,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.workload.path(name)
    }

    /// One live-joint process; its stdout is the ledger file `<cell>.out`.
    /// Reuses the owned-child/deadline helper shape (`LedgerProcess`).
    fn spawn(
        &self,
        cell: &str,
        args: &[&str],
        extra_env: &[(&str, &Path)],
    ) -> Result<LedgerProcess> {
        let out = self.path(&format!("{cell}.out"));
        let mut command = Command::new(&self.joint);
        command
            .args(args)
            .env("SOFTHSM2_CONF", &self.workload.conf)
            .stdin(Stdio::null())
            .stdout(std::fs::File::create(&out)?)
            .stderr(std::fs::File::create(self.path(&format!("{cell}.err")))?);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let child = command.spawn().context("spawning live-joint")?;
        let process = LedgerProcess { child, out };
        process.wait_for("READY ", Duration::from_secs(30))?;
        Ok(process)
    }
}

/// The fixed SoftHSM call script's functions (every call the b/exec
/// modes make is observed; the CALLS ledger carries the adaptive counts).
const JOINT_SOFT_FUNCTIONS: &[&str] = &[
    "C_Initialize",
    "C_Finalize",
    "C_GetSlotList",
    "C_GetTokenInfo",
    "C_OpenSession",
    "C_CloseSession",
    "C_Login",
    "C_Logout",
    "C_DigestInit",
    "C_Digest",
    "C_SignInit",
    "C_Sign",
    "C_GenerateKey",
];

/// A Joint manifest for any owned provider: the live joint-finish cell's
/// recipe (file identity + mapping key + ELF offsets for the named
/// functions), parameterized by provider. That cell's helper is untouched.
fn provider_joint_manifest(
    dir: &Path,
    provider: &Path,
    functions: &[&str],
    file_name: &str,
) -> Result<PathBuf> {
    use p11scope_manifest::identity::{inspect_file, mapping_file_key, open_object};
    use p11scope_manifest::manifest::*;
    ensure!(
        provider.exists(),
        "provider {} is missing",
        provider.display()
    );
    let file = open_object(provider).map_err(anyhow::Error::msg)?;
    let inspected = inspect_file(&file).map_err(anyhow::Error::msg)?;
    let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let elf = std::fs::File::open(provider)?;
    let snapshot = p11scope_manifest::elf::ElfSnapshot::read(&elf).map_err(anyhow::Error::msg)?;
    let mut offsets = Vec::new();
    for name in functions {
        let fact = snapshot
            .defined_symbol(name)
            .map_err(anyhow::Error::msg)?
            .with_context(|| format!("{} exports no {name}", provider.display()))?;
        offsets.push(fact.file_offset);
    }
    let functions = match pkcs11_module::tables_for(pkcs11_module::Surface::LegacyFunctionList {
        version: cryptoki_sys::CK_VERSION {
            major: 2,
            minor: 40,
        },
    }) {
        pkcs11_module::TableSet::Walk(spans) => spans
            .iter()
            .flat_map(|span| span.fields())
            .map(|field| {
                let resolution = functions
                    .iter()
                    .position(|name| *name == field.name)
                    .map_or(Resolution::NullPointer, |at| Resolution::Resolved {
                        object: 0,
                        file_offset: offsets[at],
                    });
                FunctionRecord {
                    name: field.name.into(),
                    resolution,
                }
            })
            .collect(),
        _ => anyhow::bail!("2.40 is a full standard table"),
    };
    let path = provider.to_str().context("provider path")?.to_string();
    let manifest = Manifest {
        schema: SCHEMA.into(),
        module_path: path.clone(),
        objects: vec![ObjectRecord {
            id: 0,
            path: path.clone(),
            identity: inspected.identity.clone(),
        }],
        provenance_objects: vec![ProvenanceObject {
            path,
            device_major: mapping.device_major,
            device_minor: mapping.device_minor,
            inode: mapping.inode,
            identity: inspected.identity,
        }],
        interface_list: Acquisition::Absent,
        surfaces: vec![SurfaceRecord {
            source: SurfaceSource::LegacyFunctionList,
            acquisition: Acquisition::Ok,
            version: Some(Version {
                major: 2,
                minor: 40,
            }),
            walk: WalkOutcome::Full,
            functions,
        }],
        vendor_interfaces: Vec::new(),
        alias_groups: Vec::new(),
        selection_evidence: Default::default(),
    };
    ensure!(
        crate::manifest_input::validate_structure(&manifest).is_empty(),
        "the {} manifest is well-formed",
        provider.display()
    );
    let manifest_path = dir.join(file_name);
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
    Ok(manifest_path)
}

fn system_joint_coordinator(modules: &[PathBuf]) -> Result<InventoryCoordinator<OsProcessSource>> {
    InventoryCoordinator::new(
        Scope::System,
        HookRegistry::builtin(),
        modules.to_vec(),
        OsProcessSource,
        RegistryLimits::default_limits(),
    )
}

/// Native discovery passes until `done` says stop (adapter records and
/// mapped edges for the owned processes, the Joint machine's binding
/// input). The native lane stops afterwards; its records persist in the
/// coordinator.
fn drive_native_passes_until(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    done: &mut dyn FnMut(u64) -> Result<bool>,
) -> Result<()> {
    let probe = Probe::new(FacadeLane::prepare(
        crate::attach::capture::CaptureScope::System,
        coordinator.attach_set().budget(),
        crate::attach::BackendSelection::Auto,
    )?);
    let lane = NativeLane::start(probe, coordinator, LaneWindows::PROVISIONAL, None)
        .map_err(|(_, reason)| anyhow::anyhow!("{reason}"))?;
    drive(coordinator, InspectScope::System, lane, done)?;
    Ok(())
}

/// Native discovery until every listed pid has a mapped edge (bounded:
/// at most ten short drives; each drive stops its own lane while the
/// coordinator's records accumulate).
fn drive_until_mapped(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    pids: &[u32],
) -> Result<()> {
    for round in 0..10 {
        if pids.iter().all(|pid| has_mapped_edge(coordinator, *pid)) {
            return Ok(());
        }
        drive_native_passes_until(coordinator, &mut |passes| Ok(passes >= 4))?;
        let mapped = pids
            .iter()
            .filter(|pid| has_mapped_edge(coordinator, **pid))
            .count();
        eprintln!(
            "JOINT_R16 r16-map round={round} mapped={}/{}",
            mapped,
            pids.len()
        );
    }
    ensure!(
        pids.iter().all(|pid| has_mapped_edge(coordinator, *pid)),
        "every owner maps before attach"
    );
    Ok(())
}

fn caller_of(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    pid: u32,
) -> Result<crate::discovery::caller_registry::CallerId> {
    coordinator
        .adapter()
        .live_id(pid)
        .with_context(|| format!("pid {pid} was never admitted"))
}

fn module_of(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    substr: &str,
) -> Result<crate::discovery::caller_registry::ModuleId> {
    coordinator
        .registry()
        .modules()
        .find(|module| module.paths.iter().any(|path| path.contains(substr)))
        .map(|module| module.id)
        .with_context(|| format!("no module matching {substr:?}"))
}

fn has_mapped_edge(coordinator: &InventoryCoordinator<OsProcessSource>, pid: u32) -> bool {
    let Some(id) = coordinator.adapter().live_id(pid) else {
        return false;
    };
    coordinator
        .registry()
        .edges_of(id)
        .any(|edge| edge.mapping == crate::discovery::caller_registry::MappingState::Mapped)
}

/// Start the production semantic lane over the manifests and initialize
/// its Joint machine, before any lane tick (initialization refuses once
/// ticks or stashed refresh exist).
fn start_joint_lane(
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    manifests: Vec<PathBuf>,
) -> Result<crate::inventory_semantics::AttestedSemanticLane> {
    coordinator.set_semantic_manifests(manifests);
    let attach_subset = coordinator
        .prepare_semantic_subset()
        .subset
        .context("the attach subset prepares")?;
    let convert_subset = coordinator
        .prepare_semantic_subset()
        .subset
        .context("the conversion subset prepares")?;
    let scope = Scope::System;
    let mut lane = crate::inventory_semantics::AttestedSemanticLane::start_live(
        attach_subset,
        convert_subset,
        &scope,
        crate::attach::BackendSelection::Auto,
    )
    .map_err(|refusal| anyhow::anyhow!("live lane attaches: {refusal}"))?;
    ensure!(lane.is_live(), "the lane owns its live session");
    lane.initialize_joint(coordinator)
        .map_err(|refusal| anyhow::anyhow!("the joint machine initializes: {refusal}"))?;
    ensure!(lane.has_joint_machine(), "the machine initializes live");
    joint_drive_line(&lane, coordinator, "r16-lane", "started");
    Ok(lane)
}

/// One JOINT_R16 drive-state line: the lane gates plus the machine's
/// retained phase/demand, before every driven step (and after a
/// refusal, where the retained phase names the exact failing step).
fn joint_drive_line(
    lane: &crate::inventory_semantics::AttestedSemanticLane,
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
    step: &str,
) {
    let (live, gated, finished, ticks, phase, demand, work, base, staging) =
        lane.joint_drive_state_for_test();
    let work = work.map_or_else(
        || "-".to_string(),
        |(attempted, pending)| format!("{attempted}/{pending}"),
    );
    let staging = staging.map_or_else(|| "-".to_string(), |detail| detail.to_string());
    let stuck = lane.joint_stuck_diagnostic_for_test();
    let stuck = stuck.as_deref().unwrap_or("-");
    let trip = lane.joint_guard_trip_for_test().unwrap_or("-");
    eprintln!(
        "JOINT_R16 {tag} step={step} live={} gated={} finished={} ticks={ticks} \
         phase={phase} demand={demand} work={work} base={base} staging={staging} \
         revision={} feeds={} stuck={stuck} trip={trip}",
        u8::from(live),
        u8::from(gated),
        u8::from(finished),
        coordinator.registry().published_revision(),
        coordinator.registry().joint_feeds(),
    );
}

/// Drive one Running transaction to publication through the real lane
/// APIs (the future on-tick path, called directly): one begin, bounded
/// service/poll slices, exactly one published revision.
fn service_to_published(
    lane: &mut crate::inventory_semantics::AttestedSemanticLane,
    coordinator: &mut InventoryCoordinator<OsProcessSource>,
    engine_changed: bool,
    tag: &str,
) -> Result<u64> {
    use crate::inventory_semantics::{JointServiceMode, JointWorkBudget};
    joint_drive_line(lane, coordinator, tag, "begin");
    lane.begin_joint_commit(engine_changed).map_err(|refusal| {
        let reason = match refusal {
            crate::inventory_semantics::JointCommitRefusal::NotInitialized => "not initialized",
            crate::inventory_semantics::JointCommitRefusal::OutstandingRequest => {
                "outstanding request"
            }
            crate::inventory_semantics::JointCommitRefusal::DispositionRequired => {
                "disposition required"
            }
        };
        anyhow::anyhow!("{tag}: begin refused: {reason}")
    })?;
    let revision_before = coordinator.registry().published_revision();
    let started = Instant::now();
    let mut polls = 0u64;
    loop {
        let mut budget = JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        joint_drive_line(lane, coordinator, tag, &format!("service{polls}"));
        lane.service_joint(&mut *coordinator, JointServiceMode::Running, &mut budget)
            .map_err(|reason| {
                joint_drive_line(lane, coordinator, tag, "service-FAILED");
                anyhow::anyhow!(
                    "{tag}: service refused: {reason} waiters={:?}",
                    lane.joint_stuck_diagnostic_for_test(),
                )
            })?;
        let mut budget = JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        joint_drive_line(lane, coordinator, tag, &format!("poll{polls}"));
        let commit = lane
            .poll_joint_commit(&mut *coordinator, &mut budget)
            .map_err(|reason| {
                joint_drive_line(lane, coordinator, tag, "poll-FAILED");
                anyhow::anyhow!(
                    "{tag}: commit poll refused: {reason} waiters={:?}",
                    lane.joint_stuck_diagnostic_for_test(),
                )
            })?;
        polls += 1;
        if matches!(
            commit,
            crate::discovery::engine::inventory_coordinator::JointCommitProgress::Published(_)
        ) {
            let revision_after = coordinator.registry().published_revision();
            ensure!(
                revision_after == revision_before + 1,
                "{tag}: one published revision per transaction: \
                 {revision_before} -> {revision_after}"
            );
            return Ok(polls);
        }
        let scan_bound =
            crate::semantic_capture::TickLimits::default().pending_for + Duration::from_secs(3);
        ensure!(
            started.elapsed() < scan_bound,
            "{tag}: unpublished after {} polls ({} ms, bound {} ms); \
             stuck audit={:?} h3={:?} waiters={:?}",
            polls,
            started.elapsed().as_millis(),
            scan_bound.as_millis(),
            lane.joint_audit_diagnostic_for_test(),
            coordinator.reference_h3_audit_state(),
            lane.joint_stuck_diagnostic_for_test(),
        );
        ensure!(
            started.elapsed() < Duration::from_secs(120),
            "{tag}: unpublished after 120 s; stuck audit={:?} h3={:?} waiters={:?}",
            lane.joint_audit_diagnostic_for_test(),
            coordinator.reference_h3_audit_state(),
            lane.joint_stuck_diagnostic_for_test(),
        );
    }
}

/// The fixture's CALLS ledger: per-function entered counts, total entered,
/// total failed. The observer's exact populations are checked against
/// these, never against hardcoded counts.
fn ledger_calls(out: &Path) -> Result<(BTreeMap<String, u64>, u64, u64)> {
    let text = std::fs::read_to_string(out)?;
    let mut per_function = BTreeMap::new();
    let mut total = 0u64;
    let mut bad = 0u64;
    for line in text.lines().filter(|line| line.starts_with("CALLS ")) {
        let mut function = None;
        let mut entered = None;
        let mut failed = None;
        for token in line.split_whitespace() {
            if let Some(name) = token.strip_prefix("fn=") {
                function = Some(name.to_string());
            } else if let Some(count) = token.strip_prefix("n=") {
                entered = Some(count.parse::<u64>()?);
            } else if let Some(count) = token.strip_prefix("bad=") {
                failed = Some(count.parse::<u64>()?);
            }
        }
        let (Some(function), Some(entered), Some(failed)) = (function, entered, failed) else {
            anyhow::bail!("unparsable CALLS line: {line:?}")
        };
        *per_function.entry(function).or_insert(0) += entered;
        total += entered;
        bad += failed;
    }
    Ok((per_function, total, bad))
}

/// The first `t=` stamp on a ledger line with the given prefix.
fn ledger_stamp(out: &Path, prefix: &str) -> Result<u64> {
    let text = std::fs::read_to_string(out)?;
    for line in text.lines().filter(|line| line.starts_with(prefix)) {
        for token in line.split_whitespace() {
            if let Some(stamp) = token.strip_prefix("t=") {
                return Ok(stamp.parse::<u64>()?);
            }
        }
    }
    anyhow::bail!("no {prefix:?} stamp in {}", out.display())
}

/// One semantic edge's observable populations.
struct JointEdgeSnapshot {
    api_returns: Option<u64>,
    reduced: u64,
    joint: bool,
    started: Option<u64>,
    completed: Option<u64>,
    /// S1 mechanism rows as (mechanism, attributed calls, errors), by id.
    mechanisms: Vec<(u64, u64, u64)>,
}

fn joint_edge_snapshot(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    pid: u32,
    module_substr: &str,
) -> Result<JointEdgeSnapshot> {
    let caller = caller_of(coordinator, pid)?;
    let module = module_of(coordinator, module_substr)?;
    let record = coordinator
        .registry()
        .instance_semantic_edges()
        .find(|record| record.caller == caller && record.module == module)
        .with_context(|| format!("no semantic edge for pid {pid} on {module_substr:?}"))?;
    let mut mechanisms: Vec<(u64, u64, u64)> = record
        .semantics
        .as_ref()
        .map(|edge| {
            edge.mechanisms()
                .iter()
                .map(|(id, row)| (*id, row.calls, row.errors))
                .collect()
        })
        .unwrap_or_default();
    mechanisms.sort();
    Ok(JointEdgeSnapshot {
        api_returns: record.api_returns,
        reduced: record.feed.reduced(),
        joint: record.feed.mode() == crate::semantics_key_use::FeedMode::Joint,
        started: record.semantics.as_ref().map(|edge| edge.started()),
        completed: record.semantics.as_ref().map(|edge| edge.completed()),
        mechanisms,
    })
}

/// Split a CALLS ledger's entered calls into the semantically admitted
/// population (`api_returns`/`reduced`) and the count-only population.
/// Conversion refuses COUNT_ONLY slots, so the observer's exact semantic
/// populations are the semantic side, never the raw ledger total. Unknown
/// names count as count-only: without a descriptor they have no slot and
/// are never observed.
fn ledger_semantic_split(per_function: &BTreeMap<String, u64>) -> (u64, u64) {
    let mut semantic = 0u64;
    let mut count_only = 0u64;
    for (function, entered) in per_function {
        let admitted = crate::kinds::descriptor(function).is_some_and(|descriptor| {
            descriptor != p11scope_ebpf_common::SlotSemantics::COUNT_ONLY
        });
        if admitted {
            semantic = semantic.saturating_add(*entered);
        } else {
            count_only = count_only.saturating_add(*entered);
        }
    }
    (semantic, count_only)
}

/// Count registry gaps with an exact subject/reason/caller triple,
/// summing repeat counts: the registry publishes one gap row per run
/// and bumps repeats, so identical refusals share a row. This is the
/// disclosed side of an expected refusal (count-only slot, no-receipt
/// admission).
fn count_disclosed_gaps(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    subject: &str,
    reason: &str,
    caller: Option<crate::discovery::caller_registry::CallerId>,
) -> u64 {
    let registry = coordinator.registry();
    registry
        .gaps()
        .iter()
        .zip(registry.gap_repeats().iter())
        .filter(|(gap, _)| gap.subject == subject && gap.reason == reason && gap.caller == caller)
        .map(|(_, repeats)| *repeats)
        .fold(0u64, |total, repeats| total.saturating_add(repeats))
}

/// Sorted fingerprint of every semantic edge's observable populations.
/// The idle loop proves ambient lifecycle publishes move none of them.
fn joint_edges_fingerprint(coordinator: &InventoryCoordinator<OsProcessSource>) -> Vec<String> {
    let mut rows: Vec<String> = coordinator
        .registry()
        .instance_semantic_edges()
        .map(|record| {
            format!(
                "{:?}/{:?} api={:?} red={} joint={} st={:?} co={:?} lossy={} reasons={:?}",
                record.caller,
                record.module,
                record.api_returns,
                record.feed.reduced(),
                record.feed.mode() == crate::semantics_key_use::FeedMode::Joint,
                record.semantics.as_ref().map(|edge| edge.started()),
                record.semantics.as_ref().map(|edge| edge.completed()),
                record.lossy,
                record.reasons,
            )
        })
        .collect();
    rows.sort();
    rows
}

/// Sorted fingerprint of every published gap row with its repeat count.
fn joint_gaps_fingerprint(coordinator: &InventoryCoordinator<OsProcessSource>) -> Vec<String> {
    let registry = coordinator.registry();
    let mut rows: Vec<String> = registry
        .gaps()
        .iter()
        .zip(registry.gap_repeats().iter())
        .map(|(gap, repeats)| format!("{gap:?} x{repeats}"))
        .collect();
    rows.sort();
    rows.push(format!("suppressed={}", registry.gaps_suppressed()));
    rows
}

/// The single disclosed reason for a caller-less scope-gap subject:
/// exactly one published row must carry the subject, else the
/// disclosure is missing or ambiguous and no exemption can pin it.
fn disclosed_scope_reason(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    subject: &str,
) -> Result<String> {
    let mut reasons = coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == subject)
        .map(|gap| gap.reason.clone())
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    ensure!(
        reasons.len() == 1,
        "{subject}: expected one disclosed reason, found {reasons:?}"
    );
    Ok(reasons.pop().expect("one reason checked"))
}

/// One disclosed gap population exempted from the quiet check: an exact
/// subject/reason/caller triple with a minimum and an optional maximum.
/// The exemption asserts the population first (never vacuous), then the
/// quiet check skips exactly those gaps.
struct QuietExemption<'a> {
    subject: &'a str,
    reason: &'a str,
    caller: Option<crate::discovery::caller_registry::CallerId>,
    min: u64,
    max: Option<u64>,
}

/// The quiet-path loss twins with disclosed exemptions. Anything else
/// loss-ish still fails.
fn assert_quiet_twins_except(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
    exempt: &[QuietExemption<'_>],
) -> Result<()> {
    for exemption in exempt {
        let count = count_disclosed_gaps(
            coordinator,
            exemption.subject,
            exemption.reason,
            exemption.caller,
        );
        let within_max = exemption.max.is_none_or(|max| count <= max);
        ensure!(
            count >= exemption.min && within_max,
            "{tag}: disclosed {:?}/{:?} gaps for {:?}: {count} (expected >={} {})",
            exemption.subject,
            exemption.reason,
            exemption.caller,
            exemption.min,
            exemption
                .max
                .map_or("".to_string(), |max| format!("and <={max}")),
        );
    }
    for gap in coordinator.registry().gaps() {
        let excused = exempt.iter().any(|exemption| {
            gap.subject == exemption.subject
                && gap.reason == exemption.reason
                && gap.caller == exemption.caller
        });
        if excused {
            continue;
        }
        let subject = gap.subject.to_lowercase();
        let reason = gap.reason.to_lowercase();
        ensure!(
            !subject.contains("loss")
                && !subject.contains("lost")
                && !subject.contains("refused")
                && !subject.contains("shed")
                && !subject.contains("unsettled")
                && !reason.contains("loss"),
            "{tag}: unexpected gap {}: {}",
            gap.subject,
            gap.reason
        );
    }
    for record in coordinator.registry().instance_semantic_edges() {
        ensure!(
            !record.lossy,
            "{tag}: edge {:?}/{:?} is lossy",
            record.caller,
            record.module
        );
        for reason in &record.reasons {
            let text = format!("{reason:?}");
            ensure!(
                ![
                    "SemanticLoss",
                    "OutOfOrderReturn",
                    "AuthorityExhausted",
                    "InstanceCapacity",
                    "SemanticStateCapacity",
                    "NegativeStateCapacity",
                    "SemanticResourceCapacity",
                    "BeforeSemanticBoundary",
                    "CountOnly",
                    "Unauthorized",
                    "AmbiguousDescriptor",
                    "CallerUnbound",
                    "InstanceUnproven",
                    "ProviderInstanceUnproven",
                ]
                .contains(&text.as_str()),
                "{tag}: edge {:?}/{:?} carries {text}",
                record.caller,
                record.module
            );
        }
    }
    let (takes, pending) = coordinator.reference_h3_audit_state();
    ensure!(!pending, "{tag}: H3 pending after publication");
    eprintln!("JOINT_R16 {tag} h3_takes={takes}");
    Ok(())
}

/// Failure-path diagnosis for an exactness mismatch: the caller's full
/// edge record (or its absence), the binding/mapping state, every
/// registry gap, the per-function ledger with each function's
/// semantic/count-only verdict, and the lane counters. The cell prints
/// these lines before bailing so the root log shows where missing
/// calls went.
fn exactness_diagnosis(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    pid: u32,
    module_substr: &str,
    per_function: &BTreeMap<String, u64>,
) -> Vec<String> {
    let mut lines = Vec::new();
    let caller = coordinator.adapter().live_id(pid);
    lines.push(format!(
        "pid={pid} caller={caller:?} module~{module_substr:?}"
    ));
    match caller {
        Some(id) => {
            lines.push(format!(
                "bound={} mapped={}",
                coordinator.semantic_bindings().get(id).is_some(),
                u8::from(has_mapped_edge(coordinator, pid)),
            ));
            let mut found = false;
            for record in coordinator.registry().instance_semantic_edges() {
                if record.caller != id {
                    continue;
                }
                let path = coordinator
                    .registry()
                    .module(record.module)
                    .map(|module| module.paths.iter().next().cloned().unwrap_or_default())
                    .unwrap_or_default();
                if !path.contains(module_substr) {
                    continue;
                }
                found = true;
                let reasons: Vec<&str> =
                    record.reasons.iter().map(|reason| reason.label()).collect();
                lines.push(format!(
                    "edge api_returns={:?} historical_only={} saturated={} lossy={} \
                     reasons={reasons:?} started={:?} completed={:?} orphans={:?} \
                     joint={} reduced={}",
                    record.api_returns,
                    record.historical_only_returns,
                    record.saturated,
                    record.lossy,
                    record.semantics.as_ref().map(|edge| edge.started()),
                    record.semantics.as_ref().map(|edge| edge.completed()),
                    record.semantics.as_ref().map(|edge| edge.orphans()),
                    record.feed.mode() == crate::semantics_key_use::FeedMode::Joint,
                    record.feed.reduced(),
                ));
            }
            if !found {
                lines.push("no semantic edge for this caller/module".to_string());
            }
        }
        None => lines.push("caller never admitted".to_string()),
    }
    let registry = coordinator.registry();
    for (gap, repeats) in registry.gaps().iter().zip(registry.gap_repeats().iter()) {
        lines.push(format!(
            "gap subject={:?} reason={:?} caller={:?} module={:?} repeats={repeats}",
            gap.subject, gap.reason, gap.caller, gap.module
        ));
    }
    let mut ledger: Vec<(&String, &u64)> = per_function.iter().collect();
    ledger.sort();
    for (function, entered) in ledger {
        let verdict = match crate::kinds::descriptor(function) {
            Some(descriptor) if descriptor != p11scope_ebpf_common::SlotSemantics::COUNT_ONLY => {
                "semantic"
            }
            Some(_) => "count-only",
            None => "unknown",
        };
        lines.push(format!("ledger fn={function} entered={entered} {verdict}"));
    }
    let (takes, pending) = coordinator.reference_h3_audit_state();
    lines.push(format!(
        "h3 takes={takes} pending={pending} feeds={} receipts={}",
        coordinator.registry().joint_feeds(),
        coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .len(),
    ));
    lines
}

/// A ClassicDriver seating the Joint lane, for the production finish
/// path (mirrors the live joint-finish cell's driver over System scope).
fn joint_finish_driver<'a>(
    coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
    lane: crate::inventory_semantics::AttestedSemanticLane,
) -> ClassicDriver<'a> {
    ClassicDriver {
        coordinator,
        inventory_scope: Some(InventoryScope::System),
        scope: InspectScope::System.into(),
        cgroup: None,
        max_scan_pids: None,
        guard: UnavailableImageGuard,
        deadline: None,
        attach_backend: crate::attach::BackendSelection::Auto,
        display: None,
        semantic: Some(lane),
        semantic_staged: false,
        seated_summary: None,
        second_signal: None,
        lifecycle: crate::inventory_promotion::lifecycle::SelectedLifecycleService::new(),
        completion_source: None,
        pending_install: None,
        installed_promotion: None,
        retiring: None,
        identity: None,
        joint_finish: JointFinishDriver::NotBegun,
        stop_requested: false,
        joint_first_error: None,
        suspended: false,
        joint_commit_pending: false,
        joint_tick_refusal: None,
        joint_commit_retries: 0,
        #[cfg(test)]
        terminal_seq_calls: 0,
        #[cfg(test)]
        reclaim_calls: Vec::new(),
        #[cfg(test)]
        joint_begin_calls: 0,
        #[cfg(test)]
        joint_step_calls: 0,
        #[cfg(test)]
        joint_commit_polls: 0,
        #[cfg(test)]
        take_promotion_work_calls: 0,
        #[cfg(test)]
        drive_pending_install_calls: 0,
        #[cfg(test)]
        service_caller_metadata_calls: 0,
        #[cfg(test)]
        commit_calls: 0,
    }
}

/// Stop the seated Joint lane through the production finish driver and
/// hand its session over with joined same-owner cleanup: begin to
/// Published, H0 stop, wound-down, take, and a genuine mint from the
/// production completion minter. Every loop is bounded (finite stop).
fn finish_stop_take_mint(
    driver: &mut ClassicDriver<'_>,
    tag: &str,
) -> Result<crate::inventory_promotion::lifecycle::SessionNativeCompletion> {
    use crate::inventory_promotion::lifecycle::NativeCompletionSource as _;
    joint_drive_line(
        driver.semantic.as_ref().expect("lane"),
        &*driver.coordinator,
        tag,
        "finish-begin",
    );
    driver.begin_final_joint_finish();
    ensure!(
        driver.joint_finish == JointFinishDriver::Polling,
        "{tag}: the live begin returns Ok and polls, got {:?}",
        driver.joint_finish
    );
    ensure!(
        !driver
            .semantic
            .as_ref()
            .expect("lane")
            .joint_finish_disposition_required(),
        "{tag}: the Ok begin latches nothing"
    );
    let mut polls = 0u64;
    loop {
        let outcome = {
            let (coordinator, semantic, finish, first_error) = (
                &mut *driver.coordinator,
                &mut driver.semantic,
                &mut driver.joint_finish,
                &mut driver.joint_first_error,
            );
            ClassicDriver::step_begun_joint_finish(semantic, finish, coordinator, first_error)
        };
        polls += 1;
        if driver.joint_finish == JointFinishDriver::Published {
            break;
        }
        ensure!(
            !matches!(outcome, JointStepOutcome::Abandoned),
            "{tag}: the live poll never abandons"
        );
        ensure!(
            polls < 200,
            "{tag}: the live poll reaches Published within 200 polls"
        );
    }
    eprintln!("JOINT_R16 {tag} published_after={polls}");
    let domain = driver.semantic.as_ref().expect("lane").domain();
    {
        let (coordinator, semantic) = (&mut *driver.coordinator, &mut driver.semantic);
        let lane = semantic.as_mut().expect("lane");
        if let Some(finish) = lane.finish_semantic_stop() {
            coordinator.stage_semantic_batch(finish);
            lane.note_semantic_staged();
            commit_semantic_finish(coordinator, lane)?;
            lane.note_semantic_published();
        }
        ensure!(lane.is_finished(), "{tag}: H0 stops");
    }
    let mut wound_polls = 0u64;
    loop {
        let (coordinator, semantic) = (&mut *driver.coordinator, &mut driver.semantic);
        let lane = semantic.as_mut().expect("lane");
        match lane.poll_wound_down(coordinator, &mut std::io::sink()) {
            Ok(true) => break,
            Ok(false) => {}
            Err(refusal) => anyhow::bail!("{tag}: the live wound-down never refuses: {refusal}"),
        }
        wound_polls += 1;
        ensure!(
            wound_polls < 600,
            "{tag}: the live detach joins within 600 polls"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let session = driver
        .semantic
        .as_mut()
        .expect("lane")
        .take_joined_session()
        .map_err(|refusal| {
            anyhow::anyhow!("{tag}: the wound-down lane hands its session: {refusal}")
        })?
        .with_context(|| format!("{tag}: the live take hands the session"))?;
    eprintln!("JOINT_R16 {tag} wound_down_after={wound_polls} take=some");
    let mut minter = crate::attach::NativeCompletionMinter::new();
    minter.note_wound_down(domain, session);
    let started = Instant::now();
    loop {
        if let Some(completion) = minter.poll_completion(domain) {
            ensure!(
                completion.domain() == domain,
                "{tag}: the genuine mint names the wound-down domain"
            );
            ensure!(
                minter.take_first_failure().is_none(),
                "{tag}: the genuine mint never fails"
            );
            eprintln!(
                "JOINT_R16 {tag} minted after {} ms",
                started.elapsed().as_millis()
            );
            return Ok(completion);
        }
        ensure!(
            started.elapsed() < Duration::from_secs(30),
            "{tag}: the genuine mint completes within 30 s"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The fixture's held-sign mechanism: mode `a` (A/H/S) signs with
/// CKM_SHA256_HMAC (tests/fixtures/object-journal/live-joint.c defines
/// `CKM_SHA256_HMAC` and mode `a` sets it on its sign mechanism).
const A_SIGN_MECHANISM: u64 = 0x251;

/// The od33-1 lane disclosure, counted by its frozen reason code: the
/// subject text may evolve, the reason is the contract. Caller-less by
/// construction (once per lane).
fn count_joint_journal_unavailable(coordinator: &InventoryCoordinator<OsProcessSource>) -> u64 {
    let registry = coordinator.registry();
    registry
        .gaps()
        .iter()
        .zip(registry.gap_repeats().iter())
        .filter(|(gap, _)| gap.caller.is_none() && gap.reason == "joint_journal_unavailable")
        .map(|(_, repeats)| *repeats)
        .fold(0u64, |total, repeats| total.saturating_add(repeats))
}

/// Named route-loss gaps covering `caller`: its non-conversion gaps
/// plus every caller-less semantic/Joint/instance gap. Conversion
/// refusals ("semantic input refused") cover count-only calls only and
/// never explain a missing semantic edge, so they do not count; the
/// `joint_journal_unavailable` lane disclosure is caller-less but
/// carries a `key operations ...` subject outside this set, so it never
/// masks a silent drop either.
fn count_named_route_gaps(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    caller: crate::discovery::caller_registry::CallerId,
) -> u64 {
    let registry = coordinator.registry();
    registry
        .gaps()
        .iter()
        .zip(registry.gap_repeats().iter())
        .filter(|(gap, _)| {
            (gap.caller == Some(caller) && gap.subject != "semantic input refused")
                || (gap.caller.is_none()
                    && (gap.subject.starts_with("semantic")
                        || gap.subject.starts_with("Joint")
                        || gap.subject.starts_with("instance")))
        })
        .map(|(_, repeats)| *repeats)
        .fold(0u64, |total, repeats| total.saturating_add(repeats))
}

/// The v0.5.0 S1 pins shared by the three converted cells (R-51): no
/// Joint feed anywhere, exactly one `joint_journal_unavailable` lane
/// disclosure, and `object_observations` unavailable with the frozen
/// `journal_unavailable` reason.
fn assert_s1_joint_absence(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
    observations: &crate::key_operation_projection::ObjectObservations,
) -> Result<()> {
    ensure!(
        coordinator.registry().joint_feeds() == 0,
        "{tag}: no Joint feed without a journal producer: {}",
        coordinator.registry().joint_feeds()
    );
    ensure!(
        count_joint_journal_unavailable(coordinator) == 1,
        "{tag}: exactly one joint_journal_unavailable disclosure: {}",
        count_joint_journal_unavailable(coordinator)
    );
    ensure!(
        observations.status == crate::key_operation_projection::ObsStatus::Unavailable
            && observations.reason == "journal_unavailable",
        "{tag}: object observations are unavailable without a journal producer: {:?} ({})",
        observations.status,
        observations.reason
    );
    eprintln!(
        "JOINT_R16 {tag}-s1 feeds=0 disclosure=1 status={:?} reason={}",
        observations.status, observations.reason
    );
    Ok(())
}

/// Per-owner S1 feed state after a publish, plus the silent-drop rule.
/// For each owner: its caller id and binding; each of its semantic
/// edges (module, API returns, feed mode, receipt selection, staged and
/// reduced counts); its non-path gaps; then the caller-less semantic,
/// Joint and instance gaps. Ids, counts and reason codes only, no paths.
///
/// `completed` marks owners whose ledger is DONE: a completed owner that
/// is bound but shows no semantic edge and no named route-loss gap fails
/// loudly (silent drop = release blocker). A named route-loss gap passes
/// and is printed above. Held owners (`completed == false`) print only:
/// their returns may legitimately route in a later quantum.
fn s1_feed_check(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
    owners: &[(&str, u32, bool)],
) -> Result<()> {
    let registry = coordinator.registry();
    for (name, pid, _) in owners {
        let caller = coordinator.adapter().live_id(*pid);
        let bound = caller.is_some_and(|id| coordinator.semantic_bindings().get(id).is_some());
        eprintln!("JOINT_R16 {tag}-feed {name} caller={caller:?} bound={bound}");
        let Some(id) = caller else {
            continue;
        };
        for record in registry
            .instance_semantic_edges()
            .filter(|record| record.caller == id)
        {
            eprintln!(
                "JOINT_R16 {tag}-feed {name} edge module={:?} api={:?} mode={:?} selected={} staged={} reduced={}",
                record.module,
                record.api_returns,
                record.feed.mode(),
                record.feed.selected_receipt().is_some(),
                record.feed.staged_len(),
                record.feed.reduced(),
            );
        }
        for (gap, repeats) in registry.gaps().iter().zip(registry.gap_repeats().iter()) {
            if gap.caller == Some(id) && !gap.subject.contains('/') {
                eprintln!(
                    "JOINT_R16 {tag}-feed {name} gap subject={:?} reason={:?} repeats={repeats}",
                    gap.subject, gap.reason
                );
            }
        }
    }
    for (gap, repeats) in registry.gaps().iter().zip(registry.gap_repeats().iter()) {
        if gap.caller.is_none()
            && (gap.subject.starts_with("semantic")
                || gap.subject.starts_with("Joint")
                || gap.subject.starts_with("instance"))
        {
            eprintln!(
                "JOINT_R16 {tag}-feed gap subject={:?} reason={:?} repeats={repeats}",
                gap.subject, gap.reason
            );
        }
    }
    eprintln!(
        "JOINT_R16 {tag}-feed suppressed={}",
        registry.gaps_suppressed()
    );
    for (name, pid, completed) in owners {
        if !completed {
            continue;
        }
        let caller = coordinator.adapter().live_id(*pid);
        let bound = caller.is_some_and(|id| coordinator.semantic_bindings().get(id).is_some());
        let Some(id) = caller else {
            continue;
        };
        if !bound {
            continue;
        }
        let edges = registry
            .instance_semantic_edges()
            .filter(|record| record.caller == id)
            .count();
        if edges == 0 && count_named_route_gaps(coordinator, id) == 0 {
            anyhow::bail!(
                "{tag}: SILENT ROUTE LOSS for {name} (pid {pid} caller {id:?}): bound with \
                 completed calls but no semantic edge and no named gap (release blocker)"
            );
        }
    }
    Ok(())
}

/// Per-owner mapping state after a native drive: process liveness, the
/// live caller id, every adapter record for the pid (id, incarnation,
/// lifecycle, retired), and every registry edge of those callers
/// (module, mapping state). Ids, counts and states only, no paths.
fn mapping_diagnosis(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
    owners: &[(&str, u32)],
) {
    for (name, pid) in owners {
        let alive = std::path::Path::new(&format!("/proc/{pid}")).exists();
        let live = coordinator.adapter().live_id(*pid);
        eprintln!(
            "JOINT_R16 {tag}-map {name} pid={pid} alive={} live={live:?}",
            u8::from(alive)
        );
        for record in coordinator
            .adapter()
            .records()
            .filter(|record| record.pid == *pid)
        {
            eprintln!(
                "JOINT_R16 {tag}-map {name} record id={:?} incarnation={} lifecycle={:?} retired={}",
                record.id, record.incarnation, record.lifecycle, record.retired,
            );
            for edge in coordinator.registry().edges_of(record.id) {
                eprintln!(
                    "JOINT_R16 {tag}-map {name} edge module={:?} mapping={:?}",
                    edge.module, edge.mapping,
                );
            }
        }
    }
}

/// R1.6 cell 1: the first birth through a held q1 to q2 and stop. Process
/// A runs C_SignInit (returns at once) and enters a held C_Sign (its
/// return is genuinely absent until the harness releases the FIFO); the
/// held call is semantic on purpose, since a COUNT_ONLY slot can never
/// birth Joint. Process B completes its whole SoftHSM script meanwhile.
/// q1 publishes with A retained (no replay through the missing END, no
/// fabricated return); the release lands A's return in q2; q2 publishes
/// everything semantic exactly once (B's two count-only calls are
/// counted but refused from conversion by design, each refusal
/// disclosed); the lane stops finite with joined same-owner cleanup.
/// v0.5.0 runs the S1 branch below (`journal_linked() == false`, pinned
/// by `production_seal_is_not_journal_linked`); the Joint asserts stay
/// behind the flag for 0.5.1.
#[test]
#[ignore = "privileged: live Joint first birth through a held q1 to q2 and stop"]
fn privileged_joint_first_birth_q2_and_stop_lp64() -> Result<()> {
    let cell_started = Instant::now();
    let workload = JointWorkload::build()?;
    let release = workload.path("release");
    let fifo = std::ffi::CString::new(release.to_str().context("release path")?)?;
    // SAFETY: a valid NUL-terminated path.
    ensure!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0, "mkfifo");
    let go = workload.path("go");
    let go_arg = go.to_str().context("go path")?.to_string();
    let held_arg = workload.held.to_str().context("held path")?.to_string();
    let soft_arg = workload
        .soft_copy
        .to_str()
        .context("soft-copy path")?
        .to_string();
    // The lane attaches before A/B spawn: a Joint birth needs a
    // post-attach watched-mapping change, and pre-attach processes can
    // only ever be S1-only.
    let mut coordinator =
        system_joint_coordinator(&[workload.soft_copy.clone(), workload.held.clone()])?;
    let manifest_soft = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.soft_copy,
        JOINT_SOFT_FUNCTIONS,
        "joint-r16-soft.dr37.json",
    )?;
    let manifest_held = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.held,
        &["C_SignInit", "C_Sign"],
        "joint-r16-held.dr37.json",
    )?;
    let mut lane = start_joint_lane(&mut coordinator, vec![manifest_soft, manifest_held])?;
    let process_a = workload.spawn(
        "a",
        &[
            "a",
            "--cell",
            "A",
            "--module",
            &held_arg,
            "--go",
            &go_arg,
            "--release",
            release.to_str().context("release path")?,
            "--hold",
        ],
        &[],
    )?;
    let process_b = workload.spawn(
        "b",
        &[
            "b", "--cell", "B", "--module", &soft_arg, "--go", &go_arg, "--iters", "2", "--hold",
        ],
        &[],
    )?;
    drive_until_mapped(&mut coordinator, &[process_a.pid(), process_b.pid()])?;
    let revision_before = coordinator.registry().published_revision();
    std::fs::write(&go, b"")?;
    process_a.wait_for("HELD ", Duration::from_secs(30))?;
    process_b.wait_for("DONE ", Duration::from_secs(60))?;
    ensure!(
        !process_a.has("RETURNED "),
        "A's held call returned before release"
    );
    let (b_by_fn, b_total, b_bad) = ledger_calls(&process_b.out)?;
    ensure!(
        b_bad == 0,
        "B's script never fails: {:?}",
        process_b.lines()
    );
    ensure!(b_total > 0, "B completed its script");

    // q1: B completed, A's return genuinely absent. The publication keeps
    // A retained without replaying anything through the missing END.
    let q1_polls = service_to_published(&mut lane, &mut coordinator, true, "r16-q1")?;
    s1_feed_check(
        &coordinator,
        "r16-q1",
        &[("A", process_a.pid(), false), ("B", process_b.pid(), true)],
    )?;
    let q1_end_ns = monotonic_ns();
    let edge_a_q1 = joint_edge_snapshot(&coordinator, process_a.pid(), "live-joint-held.so");
    let edge_b_q1 = joint_edge_snapshot(&coordinator, process_b.pid(), "soft-copy.so");
    let reduced_q1: u64 = coordinator
        .registry()
        .instance_semantic_edges()
        .map(|record| record.feed.reduced())
        .sum();
    ensure!(
        reduced_q1 == 0,
        "r16-q1: no replay through the missing END(A): reduced {reduced_q1}"
    );
    if let Ok(edge) = &edge_a_q1 {
        // A's SignInit return may route at q1, but the held Sign return
        // is genuinely absent: anything below 2 proves no fabrication.
        ensure!(
            edge.api_returns.is_none_or(|count| count <= 1),
            "r16-q1: A's held return is genuinely absent while held: {:?}",
            edge.api_returns
        );
    }
    // Without A's END, further service adds no CALL facts: no replay, no
    // edge movement, no new gaps, no H3 pending. The ring is system-wide,
    // so ambient non-call (FORK/task-newtask) lifecycle records may land
    // mid-window; a demandless service legally collects and publishes
    // them, one H3 take per publish. The revision may advance on ambient
    // lifecycle only; call content must not move.
    let revision_q1 = coordinator.registry().published_revision();
    let h3_q1 = coordinator.reference_h3_audit_state();
    let edges_q1 = joint_edges_fingerprint(&coordinator);
    let gaps_q1 = joint_gaps_fingerprint(&coordinator);
    let feeds_q1 = coordinator.registry().joint_feeds();
    let receipts_q1 = coordinator
        .registry()
        .pending_joint_receipts_for_test()
        .len();
    let mut idle_publishes = 0u64;
    for idle in 0..3 {
        let mut budget = crate::inventory_semantics::JointWorkBudget {
            remaining_actions: 1024,
            deadline: Instant::now() + Duration::from_millis(10),
        };
        joint_drive_line(&lane, &coordinator, "r16-q1", &format!("idle{idle}"));
        let progress = lane
            .service_joint(
                &mut coordinator,
                crate::inventory_semantics::JointServiceMode::Running,
                &mut budget,
            )
            .map_err(|reason| {
                joint_drive_line(&lane, &coordinator, "r16-q1", "idle-FAILED");
                anyhow::anyhow!("r16-q1: idle service refused: {reason}")
            })?;
        if progress == crate::inventory_semantics::JointServiceProgress::Published {
            idle_publishes += 1;
        }
    }
    let revision_idle = coordinator.registry().published_revision();
    let h3_idle = coordinator.reference_h3_audit_state();
    let rev_advance = revision_idle.saturating_sub(revision_q1);
    ensure!(
        rev_advance == idle_publishes,
        "r16-q1: each idle revision comes from exactly one idle publish: \
         {revision_q1}->{revision_idle} with {idle_publishes} publishes"
    );
    ensure!(
        h3_idle.0.saturating_sub(h3_q1.0) == idle_publishes as usize,
        "r16-q1: one H3 take per idle publish: takes {}->{} with {idle_publishes} publishes",
        h3_q1.0,
        h3_idle.0,
    );
    ensure!(
        h3_idle.1 == h3_q1.1,
        "r16-q1: idle service opens no H3 pending"
    );
    ensure!(
        joint_edges_fingerprint(&coordinator) == edges_q1,
        "r16-q1: idle service moves no edge call facts: {:?} vs {:?}",
        joint_edges_fingerprint(&coordinator),
        edges_q1,
    );
    ensure!(
        joint_gaps_fingerprint(&coordinator) == gaps_q1,
        "r16-q1: idle service records no gaps: {:?} vs {:?}",
        joint_gaps_fingerprint(&coordinator),
        gaps_q1,
    );
    ensure!(
        coordinator.registry().joint_feeds() == feeds_q1
            && coordinator
                .registry()
                .pending_joint_receipts_for_test()
                .len()
                == receipts_q1,
        "r16-q1: idle service mints no feeds or receipts"
    );
    let reduced_idle: u64 = coordinator
        .registry()
        .instance_semantic_edges()
        .map(|record| record.feed.reduced())
        .sum();
    ensure!(reduced_idle == 0, "r16-q1: idle service replays nothing");
    eprintln!(
        "JOINT_R16 r16-q1-idle revisions={revision_q1}->{revision_idle} \
         takes={}->{} publishes={idle_publishes} edges={} gaps={}",
        h3_q1.0,
        h3_idle.0,
        edges_q1.len(),
        gaps_q1.len(),
    );
    eprintln!(
        "JOINT_R16 r16-q1 polls={q1_polls} revision={revision_before}->{revision_q1} \
         reduced={reduced_q1} b_edge={} a_edge={}",
        edge_b_q1.is_ok(),
        edge_a_q1.is_ok(),
    );
    eprintln!(
        "JOINT_R16 r16-q1-bcount b_api={:?} slot_refusals={}",
        edge_b_q1.as_ref().ok().and_then(|edge| edge.api_returns),
        caller_of(&coordinator, process_b.pid())
            .ok()
            .map_or(0, |caller| count_disclosed_gaps(
                &coordinator,
                "semantic input refused",
                "slot",
                Some(caller),
            )),
    );
    ensure_joint_birth_marker_wired(&coordinator, "r16-q1")?;

    // Release A's return into q2.
    std::fs::OpenOptions::new().write(true).open(&release)?;
    process_a.wait_for("RETURNED ", Duration::from_secs(30))?;
    let t_enter = ledger_stamp(&process_a.out, "HELD ")?;
    let t_exit = ledger_stamp(&process_a.out, "RETURNED ")?;
    ensure!(
        t_enter < q1_end_ns && q1_end_ns < t_exit,
        "the hold genuinely spans q1: enter {t_enter} q1-end {q1_end_ns} exit {t_exit}"
    );
    let (a_by_fn, a_total, a_bad) = ledger_calls(&process_a.out)?;
    ensure!(
        a_bad == 0 && a_total == 2,
        "A made exactly SignInit plus its held Sign"
    );

    // q2: A's genuine END lands; everything semantic completes exactly
    // once. The ledgers' count-only calls (C_Initialize, C_GetSlotList)
    // are counted but refused from semantic conversion by design, each
    // refusal disclosed; `api_returns`/`reduced` cover the semantic
    // side only, never the raw entered total.
    let q2_polls = service_to_published(&mut lane, &mut coordinator, false, "r16-q2")?;
    s1_feed_check(
        &coordinator,
        "r16-q2",
        &[("A", process_a.pid(), true), ("B", process_b.pid(), true)],
    )?;
    let (a_semantic, a_count_only) = ledger_semantic_split(&a_by_fn);
    let (b_semantic, b_count_only) = ledger_semantic_split(&b_by_fn);
    let edge_a = joint_edge_snapshot(&coordinator, process_a.pid(), "live-joint-held.so")?;
    let edge_b = joint_edge_snapshot(&coordinator, process_b.pid(), "soft-copy.so")?;
    let diagnose = |ok: bool, pid: u32, module: &str, by_fn: &BTreeMap<String, u64>| {
        if !ok {
            for line in exactness_diagnosis(&coordinator, pid, module, by_fn) {
                eprintln!("JOINT_R16 r16-q2-diag {line}");
            }
        }
    };
    diagnose(
        edge_a.api_returns == Some(a_semantic),
        process_a.pid(),
        "live-joint-held.so",
        &a_by_fn,
    );
    ensure!(
        edge_a.api_returns == Some(a_semantic),
        "A's API returns are exact: {:?} vs semantic ledger {a_semantic} \
         (entered {a_total}, count-only {a_count_only})",
        edge_a.api_returns
    );
    diagnose(
        edge_b.api_returns == Some(b_semantic),
        process_b.pid(),
        "soft-copy.so",
        &b_by_fn,
    );
    ensure!(
        edge_b.api_returns == Some(b_semantic),
        "B's API returns are exact: {:?} vs semantic ledger {b_semantic} \
         (entered {b_total}, count-only {b_count_only})",
        edge_b.api_returns
    );
    let caller_a = caller_of(&coordinator, process_a.pid())?;
    let caller_b = caller_of(&coordinator, process_b.pid())?;
    ensure!(
        count_disclosed_gaps(
            &coordinator,
            "semantic input refused",
            "slot",
            Some(caller_a)
        ) == a_count_only,
        "A's count-only calls are disclosed as slot refusals: {a_count_only}"
    );
    ensure!(
        count_disclosed_gaps(
            &coordinator,
            "semantic input refused",
            "slot",
            Some(caller_b)
        ) == b_count_only,
        "B's count-only calls are disclosed as slot refusals: {b_count_only}"
    );
    // B's script starts 2 digests + 1 sign + 1 direct keygen (unit-pinned
    // 1/1 each); session/query calls start nothing.
    ensure!(
        edge_b.started == Some(4) && edge_b.completed == Some(4),
        "B's completions are exact: {:?}/{:?}",
        edge_b.started,
        edge_b.completed
    );
    ensure!(
        edge_a.started == Some(1) && edge_a.completed == Some(1),
        "A's sign operation completes exactly: {:?}/{:?}",
        edge_a.started,
        edge_a.completed
    );
    let receipts = coordinator.registry().pending_joint_receipts_for_test();
    let aggregates = coordinator.registry().keyuse_for_test().aggregates();
    let revision = coordinator.registry().published_revision();
    let observations = coordinator.registry().joint_observations(revision);
    // v0.5.0 seals every production attachment without a journal
    // producer (OD33/R-50): the S1 branch below runs, and the Joint
    // asserts stay for the 0.5.1 linked world.
    let linked = coordinator.registry().journal_linked();
    if linked {
        diagnose(
            edge_a.reduced == a_semantic,
            process_a.pid(),
            "live-joint-held.so",
            &a_by_fn,
        );
        ensure!(
            edge_a.reduced == a_semantic,
            "A reduces exactly once: {} vs {a_semantic}",
            edge_a.reduced
        );
        diagnose(
            edge_b.reduced == b_semantic,
            process_b.pid(),
            "soft-copy.so",
            &b_by_fn,
        );
        ensure!(
            edge_b.reduced == b_semantic,
            "B reduces exactly once: {} vs {b_semantic}",
            edge_b.reduced
        );
        ensure!(edge_a.joint && edge_b.joint, "both feeds are Joint");
        ensure!(
            receipts.len() >= 2,
            "nonzero observed Joint receipts: {}",
            receipts.len()
        );
        ensure!(
            coordinator.registry().joint_feeds() >= 2,
            "both owners hold Joint feeds"
        );
        ensure!(!aggregates.is_empty(), "nonzero observed key receipts");
        ensure!(
            observations.status == crate::key_operation_projection::ObsStatus::Populated,
            "the guarded H9 section populates: {:?} ({})",
            observations.status,
            observations.reason
        );
        ensure!(
            !observations.key_operations.is_empty(),
            "the populated section carries key-operation rows"
        );
        ensure!(
            observations.revision == revision,
            "the section tags the published revision"
        );
    } else {
        ensure!(
            !edge_a.joint && !edge_b.joint,
            "both feeds stay S1-only without a journal producer"
        );
        ensure!(
            edge_a.mechanisms == vec![(A_SIGN_MECHANISM, a_semantic, 0)],
            "A's S1 edge carries its mechanism: {:?} vs [(0x251, {a_semantic}, 0)]",
            edge_a.mechanisms
        );
        assert_s1_joint_absence(&coordinator, "r16-q2", &observations)?;
    }
    assert_quiet_twins_except(
        &coordinator,
        "r16-q2",
        &[QuietExemption {
            subject: "semantic input refused",
            reason: "slot",
            caller: Some(caller_b),
            min: b_count_only,
            max: Some(b_count_only),
        }],
    )?;
    eprintln!(
        "JOINT_R16 r16-q2 polls={q2_polls} revision={revision} feeds={} receipts={} key_aggs={} \
         key_rows={} a_api={:?} b_api={:?}",
        coordinator.registry().joint_feeds(),
        receipts.len(),
        aggregates.len(),
        observations.key_operations.len(),
        edge_a.api_returns,
        edge_b.api_returns,
    );

    // Finite stop with joined same-owner cleanup (the stop helper
    // checks the genuine mint names the wound-down domain).
    let mut driver = joint_finish_driver(&mut coordinator, lane);
    let _completion = finish_stop_take_mint(&mut driver, "r16-stop")?;
    drop(driver);
    drop(process_a);
    drop(process_b);
    eprintln!(
        "JOINT_R16 r16-stop elapsed_s={} q1_polls={q1_polls} q2_polls={q2_polls}",
        cell_started.elapsed().as_secs(),
    );
    ensure!(
        cell_started.elapsed() < Duration::from_secs(300),
        "the cell stops finite"
    );
    Ok(())
}

/// R1.6 cell 3: Joint promotion from A to B. A publishes its useful
/// calls, then winds down through the production §8.6 driver: while A
/// winds, B's queued promotion request is held (no preparation, no
/// admission); A's finish publishes, its detach joins, the genuine
/// minter mints, and the seal-drained gate retires A's namespace; only
/// then is B's request taken, B seated on the same coordinator, and B's
/// useful calls published. A retires before B is admitted.
/// v0.5.0 runs the S1 branches below (`journal_linked() == false`,
/// pinned by `production_seal_is_not_journal_linked`); the Joint asserts
/// stay behind the flag for 0.5.1.
#[test]
#[ignore = "privileged: live Joint promotion retires A before B is admitted"]
fn privileged_joint_promotion_a_to_b_lp64() -> Result<()> {
    let cell_started = Instant::now();
    let workload = JointWorkload::build()?;
    let go_a = workload.path("go-a");
    let go_a_arg = go_a.to_str().context("go-a path")?.to_string();
    let go_b = workload.path("go-b");
    let go_b_arg = go_b.to_str().context("go-b path")?.to_string();
    let soft_arg = workload
        .soft_copy
        .to_str()
        .context("soft-copy path")?
        .to_string();
    // The lane attaches before PA/PB spawn: a Joint birth needs a
    // post-attach watched-mapping change, and pre-attach processes can
    // only ever be S1-only.
    let mut coordinator = system_joint_coordinator(std::slice::from_ref(&workload.soft_copy))?;
    let manifest_soft = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.soft_copy,
        JOINT_SOFT_FUNCTIONS,
        "joint-r16-soft.dr37.json",
    )?;
    let mut lane_a = start_joint_lane(&mut coordinator, vec![manifest_soft.clone()])?;
    let process_a = workload.spawn(
        "pa",
        &[
            "b", "--cell", "PA", "--module", &soft_arg, "--go", &go_a_arg, "--iters", "1", "--hold",
        ],
        &[],
    )?;
    let process_b = workload.spawn(
        "pb",
        &[
            "b", "--cell", "PB", "--module", &soft_arg, "--go", &go_b_arg, "--iters", "1", "--hold",
        ],
        &[],
    )?;
    drive_until_mapped(&mut coordinator, &[process_a.pid(), process_b.pid()])?;
    let domain_a = lane_a.domain();
    std::fs::write(&go_a, b"")?;
    process_a.wait_for("DONE ", Duration::from_secs(60))?;
    let (a_by_fn, a_total, a_bad) = ledger_calls(&process_a.out)?;
    ensure!(a_bad == 0 && a_total > 0, "A ran its script");
    // qa: A publishes its useful calls. The ledger's count-only calls
    // (C_Initialize, C_GetSlotList) are counted but refused from
    // semantic conversion by design, each refusal disclosed;
    // `api_returns`/`reduced` cover the semantic side only, never the
    // raw entered total.
    let qa_polls = service_to_published(&mut lane_a, &mut coordinator, true, "r16c-qa")?;
    s1_feed_check(
        &coordinator,
        "r16c-qa",
        &[("A", process_a.pid(), true), ("B", process_b.pid(), false)],
    )?;
    ensure_joint_birth_marker_wired(&coordinator, "r16c-qa")?;
    let (a_semantic, a_count_only) = ledger_semantic_split(&a_by_fn);
    let edge_a = joint_edge_snapshot(&coordinator, process_a.pid(), "soft-copy.so")?;
    let diagnose = |ok: bool, pid: u32, module: &str, by_fn: &BTreeMap<String, u64>| {
        if !ok {
            for line in exactness_diagnosis(&coordinator, pid, module, by_fn) {
                eprintln!("JOINT_R16 r16c-qa-diag {line}");
            }
        }
    };
    diagnose(
        edge_a.api_returns == Some(a_semantic),
        process_a.pid(),
        "soft-copy.so",
        &a_by_fn,
    );
    ensure!(
        edge_a.api_returns == Some(a_semantic),
        "A is exact: {:?} vs semantic {a_semantic} (entered {a_total}, count-only {a_count_only})",
        edge_a.api_returns
    );
    let caller_a = caller_of(&coordinator, process_a.pid())?;
    ensure!(
        count_disclosed_gaps(
            &coordinator,
            "semantic input refused",
            "slot",
            Some(caller_a)
        ) == a_count_only,
        "A's count-only calls are disclosed as slot refusals: {a_count_only}"
    );
    ensure!(
        edge_a.started == Some(3) && edge_a.completed == Some(3),
        "A completions are exact: {:?}/{:?}",
        edge_a.started,
        edge_a.completed
    );
    // v0.5.0 seals every production attachment without a journal
    // producer (OD33/R-50): the S1 branch below runs, and the Joint
    // asserts stay for the 0.5.1 linked world.
    let linked = coordinator.registry().journal_linked();
    if linked {
        diagnose(
            edge_a.reduced == a_semantic,
            process_a.pid(),
            "soft-copy.so",
            &a_by_fn,
        );
        ensure!(
            edge_a.reduced == a_semantic,
            "A reduces exactly: {} vs {a_semantic}",
            edge_a.reduced
        );
        ensure!(edge_a.joint, "A is Joint");
    } else {
        ensure!(!edge_a.joint, "A stays S1-only without a journal producer");
        ensure!(
            coordinator.registry().joint_feeds() == 0,
            "r16c-qa: no Joint feed without a journal producer: {}",
            coordinator.registry().joint_feeds()
        );
        ensure!(
            count_joint_journal_unavailable(&coordinator) == 1,
            "r16c-qa: exactly one joint_journal_unavailable disclosure: {}",
            count_joint_journal_unavailable(&coordinator)
        );
    }
    eprintln!(
        "JOINT_R16 r16c-qa polls={qa_polls} a_api={:?}",
        edge_a.api_returns
    );

    // Seat A's lane in the production promotion driver with a posed
    // install record (A's real caller/module ids): the selected-install
    // chain that would have produced it is interactive-only and covered
    // by unit scenes; everything from the wind-down entry on is live.
    // B's promotion request queues with B's real ids; its viewed frame
    // is scripted, which the assertions never depend on: the §8.6 hold
    // fires before any view read, and the post-retire take is proven by
    // queue consumption plus the refusal record, never by preparation.
    let held_display = super::promotion_driver_tests::headless_display();
    let mut driver =
        super::promotion_driver_tests::driver_with_display(&mut coordinator, held_display.display);
    driver.semantic = Some(lane_a);
    driver.completion_source = Some(Box::new(crate::attach::NativeCompletionMinter::new()));
    let module_a = module_of(driver.coordinator, "soft-copy.so")?;
    driver.installed_promotion = Some(InstalledPromotion {
        capture: CaptureId::new(41),
        request: RequestId::new(7),
        pair: PromotionPair::new(caller_a.0, module_a.0),
    });
    let display = driver.display.as_mut().expect("headless display");
    ensure!(
        display.promotion_enable(CaptureId::new(41)),
        "the promotion control enables"
    );
    let caller_b = caller_of(driver.coordinator, process_b.pid())?;
    let module_b = module_of(driver.coordinator, "soft-copy.so")?;
    display
        .queue_promotion_request_for_test(
            crate::inventory_promotion::lifecycle::scripted_promotion_view_for_test(),
            caller_b,
            module_b,
        )
        .map_err(|_| anyhow::anyhow!("B's promotion request queues"))?;
    eprintln!("JOINT_R16 r16c-queued b_request=ok");

    // The wind-down entry retires nothing yet: A's whole lane winds in
    // its domain with the promotion flag armed.
    driver.wind_down_installed_promotion(PromotionEnd::LaneClosed);
    ensure!(
        driver.installed_promotion.is_none(),
        "the wind-down consumes the install"
    );
    ensure!(
        driver
            .retiring
            .as_ref()
            .is_some_and(|retiring| retiring.winding.is_some()),
        "A's whole lane winds in its retiring domain"
    );
    ensure!(
        driver.coordinator.promotion_finish(),
        "A's promotion finish arms"
    );
    ensure!(
        has_gap(driver.coordinator, "selected promotion ended"),
        "the wind-down discloses its end"
    );
    ensure!(
        driver
            .retiring
            .as_ref()
            .and_then(|retiring| retiring.winding.as_ref())
            .is_some_and(|winding| winding.finish == JointFinishDriver::Polling),
        "A's promotion finish begins polling"
    );

    // While A winds, B is held: the take runs (its call counts) but
    // takes nothing — no worker, no install, no refusal record.
    driver.take_promotion_work();
    ensure!(
        driver.take_promotion_work_calls == 1,
        "the held take runs once"
    );
    ensure!(driver.lifecycle.is_idle(), "no preparation starts for B");
    ensure!(driver.pending_install.is_none(), "no install pends for B");
    ensure!(
        driver
            .retiring
            .as_ref()
            .is_some_and(|retiring| retiring.winding.is_some()),
        "A still winds"
    );
    ensure!(
        !has_gap(driver.coordinator, "selected promotion refused"),
        "a held B is not refused either"
    );
    ensure!(
        driver
            .coordinator
            .registry()
            .instance_semantic_edges()
            .all(|record| record.caller != caller_b),
        "B is admitted nowhere while A winds"
    );
    eprintln!("JOINT_R16 r16c-hold b_held=ok");

    // Retire A through the production winding poll: finish, joined
    // detach, genuine mint, seal-drained retire.
    let retire_started = Instant::now();
    let mut retire_polls = 0u64;
    while !driver.poll_joint_winding() {
        retire_polls += 1;
        ensure!(retire_polls < 1200, "A retires within 1200 winding polls");
        ensure!(
            retire_started.elapsed() < Duration::from_secs(120),
            "A retires within 120 s"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    ensure!(driver.retiring.is_none(), "A's domain retires");
    ensure!(
        !driver.coordinator.promotion_finish(),
        "the promotion flag clears on retire"
    );
    eprintln!("JOINT_R16 r16c-retire polls={retire_polls}");
    // Twin: A's namespace is gone — the same domain retires no more.
    let twin = driver.coordinator.retire_joint_domain(
        crate::inventory_promotion::lifecycle::SessionNativeCompletion::scripted(domain_a),
    );
    let Err((_, refusal)) = twin else {
        anyhow::bail!("A's retired namespace refuses a second retire as foreign")
    };
    ensure!(
        matches!(
            refusal,
            crate::discovery::engine::inventory_coordinator::semantics::JointRetireRefusal::NotLiveDomain
        ),
        "the second retire refuses as foreign"
    );

    // The hold releases: B's request is taken (the queue drains and the
    // scripted view refuses through the bounded refusal path — the §8.6
    // content is take-vs-hold, not preparation, which unit scenes own).
    // A worker starting from a scripted view would be a finding, not a
    // pass: fail loudly so it is investigated, never silently absorbed.
    driver.take_promotion_work();
    ensure!(
        driver.take_promotion_work_calls == 2,
        "the released take runs"
    );
    ensure!(
        driver
            .display
            .as_mut()
            .expect("headless display")
            .take_promotion_request()
            .is_none(),
        "the released take consumes B's request"
    );
    ensure!(
        has_gap(driver.coordinator, "selected promotion refused"),
        "the scripted view refuses through the bounded path"
    );
    ensure!(
        driver.lifecycle.is_idle(),
        "no worker starts from a scripted view"
    );
    eprintln!("JOINT_R16 r16c-take b_taken=ok");

    // B seats on the same coordinator that outlived A, and B's useful
    // calls publish exactly. B had no edge before this seat: A retired
    // before B was admitted.
    ensure!(
        driver
            .coordinator
            .registry()
            .instance_semantic_edges()
            .all(|record| record.caller != caller_b),
        "B still has no edge before its seat"
    );
    let manifest_soft_b = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.soft_copy,
        JOINT_SOFT_FUNCTIONS,
        "joint-r16-soft-b.dr37.json",
    )?;
    // The promotion driver drops here; the coordinator outlives it for B.
    let coordinator = &mut *driver.coordinator;
    let mut lane_b = start_joint_lane(&mut *coordinator, vec![manifest_soft_b])?;
    std::fs::write(&go_b, b"")?;
    process_b.wait_for("DONE ", Duration::from_secs(60))?;
    let (b_by_fn, b_total, b_bad) = ledger_calls(&process_b.out)?;
    ensure!(b_bad == 0 && b_total > 0, "B ran its script");
    let qb_polls = service_to_published(&mut lane_b, &mut *coordinator, false, "r16c-qb")?;
    s1_feed_check(
        coordinator,
        "r16c-qb",
        &[("A", process_a.pid(), false), ("B", process_b.pid(), true)],
    )?;
    let (b_semantic, b_count_only) = ledger_semantic_split(&b_by_fn);
    let edge_b = joint_edge_snapshot(coordinator, process_b.pid(), "soft-copy.so")?;
    let diagnose = |ok: bool, pid: u32, module: &str, by_fn: &BTreeMap<String, u64>| {
        if !ok {
            for line in exactness_diagnosis(coordinator, pid, module, by_fn) {
                eprintln!("JOINT_R16 r16c-qb-diag {line}");
            }
        }
    };
    diagnose(
        edge_b.api_returns == Some(b_semantic),
        process_b.pid(),
        "soft-copy.so",
        &b_by_fn,
    );
    ensure!(
        edge_b.api_returns == Some(b_semantic),
        "B is exact: {:?} vs semantic {b_semantic} (entered {b_total}, count-only {b_count_only})",
        edge_b.api_returns
    );
    ensure!(
        count_disclosed_gaps(
            coordinator,
            "semantic input refused",
            "slot",
            Some(caller_b)
        ) == b_count_only,
        "B's count-only calls are disclosed as slot refusals: {b_count_only}"
    );
    ensure!(
        edge_b.started == Some(3) && edge_b.completed == Some(3),
        "B completions are exact: {:?}/{:?}",
        edge_b.started,
        edge_b.completed
    );
    let revision = coordinator.registry().published_revision();
    let observations = coordinator.registry().joint_observations(revision);
    // v0.5.0 seals every production attachment without a journal
    // producer (OD33/R-50): the S1 branch below runs, and the Joint
    // asserts stay for the 0.5.1 linked world.
    let linked = coordinator.registry().journal_linked();
    if linked {
        diagnose(
            edge_b.reduced == b_semantic,
            process_b.pid(),
            "soft-copy.so",
            &b_by_fn,
        );
        ensure!(
            edge_b.reduced == b_semantic,
            "B reduces exactly: {} vs {b_semantic}",
            edge_b.reduced
        );
        ensure!(edge_b.joint, "B is Joint");
        ensure!(
            !coordinator
                .registry()
                .pending_joint_receipts_for_test()
                .is_empty(),
            "nonzero observed Joint receipts"
        );
        ensure!(
            !coordinator
                .registry()
                .keyuse_for_test()
                .aggregates()
                .is_empty(),
            "nonzero observed key receipts"
        );
        ensure!(
            observations.status == crate::key_operation_projection::ObsStatus::Populated,
            "the guarded H9 section populates after promotion: {:?} ({})",
            observations.status,
            observations.reason
        );
    } else {
        ensure!(!edge_b.joint, "B stays S1-only without a journal producer");
        assert_s1_joint_absence(coordinator, "r16c-qb", &observations)?;
    }
    // The quiet twins excuse exactly the disclosed populations: both
    // callers' count-only slot refusals (A's rows survive its retire;
    // gaps are audit rows, not domain state) and the single expected
    // scripted-view promotion refusal.
    let promotion_reason = disclosed_scope_reason(coordinator, "selected promotion refused")?;
    let expected_reasons = [
        crate::inventory_promotion::PromotionRefusal::StaleView.label(),
        crate::inventory_promotion::PromotionRefusal::ManifestUnavailable.label(),
    ];
    ensure!(
        expected_reasons.contains(&promotion_reason.as_str()),
        "r16c-qb: unexpected promotion refusal reason {promotion_reason:?}, expected one of {expected_reasons:?}"
    );
    assert_quiet_twins_except(
        coordinator,
        "r16c-qb",
        &[
            QuietExemption {
                subject: "semantic input refused",
                reason: "slot",
                caller: Some(caller_a),
                min: a_count_only,
                max: Some(a_count_only),
            },
            QuietExemption {
                subject: "semantic input refused",
                reason: "slot",
                caller: Some(caller_b),
                min: b_count_only,
                max: Some(b_count_only),
            },
            QuietExemption {
                subject: "selected promotion refused",
                reason: &promotion_reason,
                caller: None,
                min: 1,
                max: Some(1),
            },
        ],
    )?;
    eprintln!(
        "JOINT_R16 r16c-qb polls={qb_polls} revision={revision} b_api={:?} \
         promotion_refusal={promotion_reason:?}",
        edge_b.api_returns
    );

    // Finite stop with joined same-owner cleanup for B's lane.
    let mut stop_driver = joint_finish_driver(&mut *coordinator, lane_b);
    let _completion = finish_stop_take_mint(&mut stop_driver, "r16c-stop")?;
    drop(stop_driver);
    drop(driver);
    drop(process_a);
    drop(process_b);
    eprintln!(
        "JOINT_R16 r16c-stop elapsed_s={}",
        cell_started.elapsed().as_secs()
    );
    ensure!(
        cell_started.elapsed() < Duration::from_secs(300),
        "the cell stops finite"
    );
    Ok(())
}

#[cfg(test)]
mod joint_ledger_parse_tests {
    //! Unit tests for the R1.6 ledger parsers (pure, no root): the exact
    //! population assertions rest on these, so their parsing is pinned
    //! here rather than trusted implicitly.
    use super::{
        JOINT_SOFT_FUNCTIONS, QuietExemption, assert_quiet_twins_except, count_disclosed_gaps,
        disclosed_scope_reason, exactness_diagnosis, joint_edges_fingerprint,
        joint_gaps_fingerprint, ledger_calls, ledger_semantic_split, ledger_stamp,
        system_joint_coordinator,
    };
    use std::collections::BTreeMap;

    #[test]
    fn calls_ledger_sums_per_function_and_totals() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("b.out");
        std::fs::write(
            &out,
            "MAPPED cell=B pid=11 module=/tmp/soft-copy.so ino=7\n\
             READY cell=B pid=11 exe=/tmp/live-joint\n\
             CALLS cell=B pid=11 fn=C_Initialize n=1 bad=0\n\
             CALLS cell=B pid=11 fn=C_GetTokenInfo n=2 bad=0\n\
             CALLS cell=B pid=11 fn=C_Digest n=2 bad=1\n\
             DONE cell=B pid=11 gen=0 exe=/tmp/live-joint status=fail\n",
        )?;
        let (per_function, total, bad) = ledger_calls(&out)?;
        assert_eq!(per_function.get("C_Initialize"), Some(&1));
        assert_eq!(per_function.get("C_GetTokenInfo"), Some(&2));
        assert_eq!(per_function.get("C_Digest"), Some(&2));
        assert_eq!(total, 5);
        assert_eq!(bad, 1);
        Ok(())
    }

    #[test]
    fn calls_ledger_rejects_garbled_lines() {
        let dir = tempfile::tempdir().expect("scratch");
        let out = dir.path().join("g.out");
        std::fs::write(&out, "CALLS cell=B pid=11 fn=C_Digest n=many bad=0\n").expect("write");
        assert!(ledger_calls(&out).is_err());
    }

    #[test]
    fn stamps_read_the_first_prefix_match() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("a.out");
        std::fs::write(
            &out,
            "READY cell=A pid=12 exe=/tmp/live-joint\n\
             HELD cell=A pid=12 fn=C_WaitForSlotEvent t=100\n\
             RETURNED cell=A pid=12 fn=C_WaitForSlotEvent t=200 rv=0\n",
        )?;
        assert_eq!(ledger_stamp(&out, "HELD ")?, 100);
        assert_eq!(ledger_stamp(&out, "RETURNED ")?, 200);
        assert!(ledger_stamp(&out, "MISSING ").is_err());
        Ok(())
    }

    /// Exactly the script's probed SoftHSM functions stay semantic except
    /// C_Initialize and C_GetSlotList, which the capture catalog pins
    /// count-only. If this catalog moves, every semantic-only population
    /// below (and the cells' exactness asserts) must be revisited.
    #[test]
    fn joint_soft_functions_pin_two_count_only() {
        let mut count_only = Vec::new();
        for name in JOINT_SOFT_FUNCTIONS {
            let descriptor = crate::kinds::descriptor(name)
                .unwrap_or_else(|| panic!("{name} leaves the capture catalog"));
            if descriptor == p11scope_ebpf_common::SlotSemantics::COUNT_ONLY {
                count_only.push(*name);
            }
        }
        assert_eq!(count_only, ["C_Initialize", "C_GetSlotList"]);
    }

    fn script_ledger(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
        entries
            .iter()
            .map(|(function, entered)| ((*function).to_string(), *entered))
            .collect()
    }

    /// The cells' exact semantic populations per script shape: the raw
    /// ledger total minus the count-only entered calls. Unknown names
    /// count as count-only (no descriptor, no slot, never observed).
    #[test]
    fn script_ledgers_split_semantic_from_count_only() {
        // Cell 1 B: the fixed script at --iters 2 over two token slots.
        let digest2 = script_ledger(&[
            ("C_Initialize", 1),
            ("C_GetSlotList", 1),
            ("C_GetTokenInfo", 2),
            ("C_OpenSession", 1),
            ("C_Login", 1),
            ("C_GenerateKey", 1),
            ("C_SignInit", 1),
            ("C_Sign", 1),
            ("C_DigestInit", 2),
            ("C_Digest", 2),
            ("C_Logout", 1),
            ("C_CloseSession", 1),
            ("C_Finalize", 1),
        ]);
        assert_eq!(digest2.values().sum::<u64>(), 16);
        assert_eq!(ledger_semantic_split(&digest2), (14, 2));
        // Cell 3 A / cell 2 E script: --iters 1 over two token slots.
        let digest1 = script_ledger(&[
            ("C_Initialize", 1),
            ("C_GetSlotList", 1),
            ("C_GetTokenInfo", 2),
            ("C_OpenSession", 1),
            ("C_Login", 1),
            ("C_GenerateKey", 1),
            ("C_SignInit", 1),
            ("C_Sign", 1),
            ("C_DigestInit", 1),
            ("C_Digest", 1),
            ("C_Logout", 1),
            ("C_CloseSession", 1),
            ("C_Finalize", 1),
        ]);
        assert_eq!(digest1.values().sum::<u64>(), 14);
        assert_eq!(ledger_semantic_split(&digest1), (12, 2));
        // Cell 2 E: the tallied gen-1 probe plus the --iters 1 script.
        let mut probe = digest1.clone();
        for function in ["C_Initialize", "C_GetSlotList", "C_Finalize"] {
            *probe.get_mut(function).expect("scripted call") += 1;
        }
        assert_eq!(probe.values().sum::<u64>(), 17);
        assert_eq!(ledger_semantic_split(&probe), (13, 4));
        // Cell 2 C: the absence subject's three calls.
        let absent = script_ledger(&[("C_Initialize", 1), ("C_GetSlotList", 1), ("C_Finalize", 1)]);
        assert_eq!(ledger_semantic_split(&absent), (1, 2));
        // The held pair (cells 1 A, 2 H/S): fully semantic.
        let held = script_ledger(&[("C_SignInit", 1), ("C_Sign", 1)]);
        assert_eq!(ledger_semantic_split(&held), (2, 0));
        // Unknown names are never observed.
        let strange = script_ledger(&[("C_Initialize", 1), ("C_Bogus", 3)]);
        assert_eq!(ledger_semantic_split(&strange), (0, 4));
    }

    /// The disclosed-gap counter matches the exact subject/reason/caller
    /// triple and nothing else.
    #[test]
    fn disclosed_gap_counter_matches_exact_triples() -> anyhow::Result<()> {
        use crate::discovery::caller_registry::{CallerId, RegistryGap};
        let mut coordinator = system_joint_coordinator(&[])?;
        let caller = CallerId(7);
        for _ in 0..2 {
            coordinator.registry_mut().record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: None,
                subject: "semantic input refused".into(),
                reason: "slot".into(),
                budget: None,
            });
        }
        coordinator.registry_mut().record_gap(RegistryGap {
            caller: Some(CallerId(9)),
            module: None,
            pid: None,
            subject: "semantic input refused".into(),
            reason: "slot".into(),
            budget: None,
        });
        // Gaps stage until publication; the two identical rows share
        // one published row with two repeats.
        coordinator.registry_mut().publish();
        assert_eq!(coordinator.registry().gaps().len(), 2);
        assert_eq!(
            count_disclosed_gaps(&coordinator, "semantic input refused", "slot", Some(caller)),
            2
        );
        assert_eq!(
            count_disclosed_gaps(
                &coordinator,
                "semantic input refused",
                "slot",
                Some(CallerId(9))
            ),
            1
        );
        assert_eq!(
            count_disclosed_gaps(&coordinator, "semantic input refused", "slot", None),
            0
        );
        assert_eq!(
            count_disclosed_gaps(
                &coordinator,
                "semantic input refused",
                "custody",
                Some(caller)
            ),
            0
        );
        Ok(())
    }

    /// The idle fingerprints distinguish gap content and repeats, and
    /// cover edges: identical states fingerprint identically, any new
    /// gap row changes the fingerprint, and an edge-less coordinator
    /// fingerprints empty.
    #[test]
    fn idle_fingerprints_distinguish_gaps_and_cover_edges() -> anyhow::Result<()> {
        use crate::discovery::caller_registry::{CallerId, RegistryGap};
        let mut coordinator = system_joint_coordinator(&[])?;
        assert!(joint_edges_fingerprint(&coordinator).is_empty());
        let bare = joint_gaps_fingerprint(&coordinator);
        assert_eq!(bare, vec!["suppressed=0".to_string()]);
        let caller = CallerId(7);
        for _ in 0..2 {
            coordinator.registry_mut().record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: None,
                subject: "semantic input refused".into(),
                reason: "slot".into(),
                budget: None,
            });
        }
        coordinator.registry_mut().publish();
        let gapped = joint_gaps_fingerprint(&coordinator);
        assert_ne!(gapped, bare);
        // One published row with two repeats, plus the suppressed line.
        assert_eq!(gapped.len(), 2);
        assert!(gapped.iter().any(|row| row.contains("x2")));
        // An unchanged state fingerprints identically.
        assert_eq!(joint_gaps_fingerprint(&coordinator), gapped);
        assert!(joint_edges_fingerprint(&coordinator).is_empty());
        Ok(())
    }

    /// The exemption asserts its population first: a missing disclosed
    /// population fails, and a present one is skipped by the quiet check
    /// while anything else loss-ish still fails.
    #[test]
    fn quiet_exemption_demands_its_gaps() -> anyhow::Result<()> {
        use crate::discovery::caller_registry::{CallerId, RegistryGap};
        let mut coordinator = system_joint_coordinator(&[])?;
        let caller = CallerId(7);
        let exemption = QuietExemption {
            subject: "semantic input refused",
            reason: "slot",
            caller: Some(caller),
            min: 2,
            max: Some(2),
        };
        assert!(assert_quiet_twins_except(&coordinator, "t", &[exemption]).is_err());
        for _ in 0..2 {
            coordinator.registry_mut().record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: None,
                subject: "semantic input refused".into(),
                reason: "slot".into(),
                budget: None,
            });
        }
        coordinator.registry_mut().publish();
        let exemption = QuietExemption {
            subject: "semantic input refused",
            reason: "slot",
            caller: Some(caller),
            min: 2,
            max: Some(2),
        };
        assert!(assert_quiet_twins_except(&coordinator, "t", &[exemption]).is_ok());
        coordinator.registry_mut().record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "semantic calls unrouted".into(),
            reason: "1 calls shed without a route (pending=1)".into(),
            budget: None,
        });
        coordinator.registry_mut().publish();
        let exemption = QuietExemption {
            subject: "semantic input refused",
            reason: "slot",
            caller: Some(caller),
            min: 2,
            max: Some(2),
        };
        assert!(assert_quiet_twins_except(&coordinator, "t", &[exemption]).is_ok());
        coordinator.registry_mut().record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "semantic calls lost".into(),
            reason: "loss".into(),
            budget: None,
        });
        coordinator.registry_mut().publish();
        let exemption = QuietExemption {
            subject: "semantic input refused",
            reason: "slot",
            caller: Some(caller),
            min: 2,
            max: Some(2),
        };
        assert!(assert_quiet_twins_except(&coordinator, "t", &[exemption]).is_err());
        Ok(())
    }

    /// The failure diagnosis names the missing edge, every gap, and each
    /// ledger function's verdict without root or a live lane.
    #[test]
    fn exactness_diagnosis_names_edge_gaps_and_verdicts() -> anyhow::Result<()> {
        use crate::discovery::caller_registry::{CallerId, RegistryGap};
        let mut coordinator = system_joint_coordinator(&[])?;
        coordinator.registry_mut().record_gap(RegistryGap {
            caller: Some(CallerId(7)),
            module: None,
            pid: None,
            subject: "semantic input refused".into(),
            reason: "slot".into(),
            budget: None,
        });
        coordinator.registry_mut().publish();
        let ledger = script_ledger(&[("C_Initialize", 1), ("C_Sign", 2)]);
        let lines = exactness_diagnosis(&coordinator, 999, "soft-copy.so", &ledger).join("\n");
        assert!(lines.contains("caller never admitted"), "{lines}");
        assert!(lines.contains("semantic input refused"), "{lines}");
        assert!(
            lines.contains("fn=C_Initialize entered=1 count-only"),
            "{lines}"
        );
        assert!(lines.contains("fn=C_Sign entered=2 semantic"), "{lines}");
        assert!(lines.contains("h3 takes="), "{lines}");
        Ok(())
    }

    /// The scope-reason reader demands exactly one published row for
    /// the subject: a missing or ambiguous disclosure fails instead
    /// of silently picking a reason.
    #[test]
    fn scope_reason_demands_one_disclosed_row() -> anyhow::Result<()> {
        use crate::discovery::caller_registry::{CallerId, RegistryGap};
        let mut coordinator = system_joint_coordinator(&[])?;
        assert!(disclosed_scope_reason(&coordinator, "selected promotion refused").is_err());
        coordinator.registry_mut().record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "selected promotion refused".into(),
            reason: "view expired".into(),
            budget: None,
        });
        coordinator.registry_mut().publish();
        assert_eq!(
            disclosed_scope_reason(&coordinator, "selected promotion refused")?,
            "view expired"
        );
        coordinator.registry_mut().record_gap(RegistryGap {
            caller: Some(CallerId(3)),
            module: None,
            pid: None,
            subject: "selected promotion refused".into(),
            reason: "manifest unavailable".into(),
            budget: None,
        });
        coordinator.registry_mut().publish();
        assert!(disclosed_scope_reason(&coordinator, "selected promotion refused").is_err());
        Ok(())
    }

    /// A caller-less scope gap (the promotion refusal) is exempted by
    /// its exact triple like any disclosed population: missing fails,
    /// present skips.
    #[test]
    fn quiet_exemption_excuses_callerless_scope_gap() -> anyhow::Result<()> {
        use crate::discovery::caller_registry::RegistryGap;
        let mut coordinator = system_joint_coordinator(&[])?;
        let exemption = QuietExemption {
            subject: "selected promotion refused",
            reason: "view expired",
            caller: None,
            min: 1,
            max: Some(1),
        };
        assert!(assert_quiet_twins_except(&coordinator, "t", &[exemption]).is_err());
        coordinator.registry_mut().record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "selected promotion refused".into(),
            reason: "view expired".into(),
            budget: None,
        });
        coordinator.registry_mut().publish();
        let exemption = QuietExemption {
            subject: "selected promotion refused",
            reason: "view expired",
            caller: None,
            min: 1,
            max: Some(1),
        };
        assert!(assert_quiet_twins_except(&coordinator, "t", &[exemption]).is_ok());
        Ok(())
    }
}

use crate::inventory_promotion::{CaptureId, PromotionEnd, PromotionPair, RequestId};

fn has_gap(coordinator: &InventoryCoordinator<OsProcessSource>, subject: &str) -> bool {
    coordinator
        .registry()
        .gaps()
        .iter()
        .any(|gap| gap.subject == subject)
}

/// Reasons of the retained-S1 birth disclosures. With the object-journal
/// marker wired, an observed-call birth installs a Joint feed instead of
/// disclosing its native refusal here.
fn joint_birth_gap_reasons(coordinator: &InventoryCoordinator<OsProcessSource>) -> Vec<String> {
    coordinator
        .registry()
        .gaps()
        .iter()
        .filter(|gap| gap.subject == "Joint birth unavailable; retained S1")
        .map(|gap| gap.reason.clone())
        .collect()
}

/// Pin the wired marker after a publish: no observed-call birth may
/// disclose RowUnreadable (the unwired-marker refusal), so the cells'
/// Joint assertions below run against installed feeds.
fn ensure_joint_birth_marker_wired(
    coordinator: &InventoryCoordinator<OsProcessSource>,
    tag: &str,
) -> Result<()> {
    let gaps = joint_birth_gap_reasons(coordinator);
    eprintln!("JOINT_R16 {tag}-births gaps={gaps:?}");
    ensure!(
        !gaps
            .iter()
            .any(|reason| reason == "joint_birth_native_RowUnreadable"),
        "{tag}: an observed-call birth disclosed the unwired marker: {gaps:?}"
    );
    Ok(())
}

/// The semantic-edge census: (pid, module path) pairs. Owner pids resolve
/// through the adapter records (live and retired); unknown callers print
/// numerically.
fn joint_edge_census(coordinator: &InventoryCoordinator<OsProcessSource>) -> Vec<(u32, String)> {
    let mut census = Vec::new();
    for record in coordinator.registry().instance_semantic_edges() {
        let pid = coordinator
            .adapter()
            .records()
            .find(|caller| caller.id == record.caller)
            .map(|caller| caller.pid)
            .unwrap_or(u32::MAX);
        let path = coordinator
            .registry()
            .module(record.module)
            .map(|module| module.paths.iter().next().cloned().unwrap_or_default())
            .unwrap_or_default();
        census.push((pid, path));
    }
    census.sort();
    census
}

/// R1.6 cell 2: absence and S1Only siblings beside an exec. E execs
/// under native coverage and its successor incarnation is admitted (with
/// its mapped edge) before the semantic lane attaches; then E-post births
/// Joint; C maps only the SoftHSM copy (its unmapped held provider is
/// absence-proven, never a false positive); H holds a semantic call on
/// the held provider so that module genuinely exists in the run; S enters
/// its held call before attach (entries genuinely shed) and returns it
/// late, but the entry-less return is dropped in-kernel before any event,
/// so S stays mapped-but-silent with its admission refusal disclosed:
/// never bound, never an edge, never Joint. Three transactions, one
/// revision each, then a finite stop with joined same-owner cleanup.
/// v0.5.0 runs the S1 branches below (`journal_linked() == false`,
/// pinned by `production_seal_is_not_journal_linked`); the Joint asserts
/// stay behind the flag for 0.5.1.
#[test]
#[ignore = "privileged: live Joint absence and S1Only siblings beside an exec"]
fn privileged_joint_absence_and_s1only_siblings_lp64() -> Result<()> {
    let cell_started = Instant::now();
    let workload = JointWorkload::build()?;
    let release_h = workload.path("release-h");
    let release_s = workload.path("release-s");
    for release in [&release_h, &release_s] {
        let fifo = std::ffi::CString::new(release.to_str().context("release path")?)?;
        // SAFETY: a valid NUL-terminated path.
        ensure!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) } == 0, "mkfifo");
    }
    // S spawns before attach (its entries are genuinely pre-attach)
    // and stays S1-only. E's gen 0 spawns before attach too, but E-post
    // is born after attach by the covered exec, and C/H spawn after the
    // lane attaches, so all three are Joint-birth eligible. E's own
    // go/trig gates open under the native exec drive; C's, H's and
    // E-post's gates open after.
    let go = workload.path("go");
    let go_arg = go.to_str().context("go path")?.to_string();
    let go_e = workload.path("go-e");
    let go_e_arg = go_e.to_str().context("go-e path")?.to_string();
    let trig_e = workload.path("trig-e");
    let trig_e_arg = trig_e.to_str().context("trig-e path")?.to_string();
    let exec_e = workload.path("exec-e");
    let exec_e_arg = exec_e.to_str().context("exec-e path")?.to_string();
    let go_s = workload.path("go-s");
    let go_s_arg = go_s.to_str().context("go-s path")?.to_string();
    let late_e = workload.path("late-e");
    let late_e_arg = late_e.to_str().context("late-e path")?.to_string();
    let held_arg = workload.held.to_str().context("held path")?.to_string();
    let soft_arg = workload
        .soft_copy
        .to_str()
        .context("soft-copy path")?
        .to_string();
    let process_e = workload.spawn(
        "e",
        &[
            "exec",
            "--cell",
            "E",
            "--module",
            &soft_arg,
            "--go",
            &go_e_arg,
            "--trig",
            &trig_e_arg,
            "--execgate",
            &exec_e_arg,
            "--late",
            &late_e_arg,
            "--iters",
            "1",
            "--hold",
        ],
        &[],
    )?;
    let process_s = workload.spawn(
        "s",
        &[
            "a",
            "--cell",
            "S",
            "--module",
            &held_arg,
            "--go",
            &go_s_arg,
            "--release",
            release_s.to_str().context("release-s path")?,
            "--hold",
        ],
        &[],
    )?;
    // S enters its held call before attach; the HELD line plus the
    // post-hoc stamp check prove both entries predate the lane.
    std::fs::write(&go_s, b"")?;
    process_s.wait_for("HELD ", Duration::from_secs(30))?;
    let mut coordinator =
        system_joint_coordinator(&[workload.soft_copy.clone(), workload.held.clone()])?;
    let manifest_soft = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.soft_copy,
        JOINT_SOFT_FUNCTIONS,
        "joint-r16-soft.dr37.json",
    )?;
    let manifest_held = provider_joint_manifest(
        workload.workload.dir.path(),
        &workload.held,
        &["C_SignInit", "C_Sign"],
        "joint-r16-held.dr37.json",
    )?;
    let mut lane = start_joint_lane(&mut coordinator, vec![manifest_soft, manifest_held])?;
    let attach_ns = monotonic_ns();
    // C and H spawn after the lane attaches, so their mappings and
    // calls are Joint-birth eligible. E-post is born after attach by
    // the covered exec below.
    let process_c = workload.spawn(
        "c",
        &[
            "absent", "--cell", "C", "--module", &soft_arg, "--go", &go_arg, "--hold",
        ],
        &[],
    )?;
    let process_h = workload.spawn(
        "h",
        &[
            "a",
            "--cell",
            "H",
            "--module",
            &held_arg,
            "--go",
            &go_arg,
            "--release",
            release_h.to_str().context("release-h path")?,
            "--hold",
        ],
        &[],
    )?;
    // Release C/H (`go`) and E-post's late gate (`late_e`) before the
    // spanning drive: the fixture's gate wait times out after 30 s
    // (live-joint.c `wait_for_file`: 3000 x 10 ms, then it exits), and
    // the 16-pass drive runs past that on a loaded host (47 s with 459
    // processes on the dev host, where C/H died waiting and C was
    // unmapped at the check). Neither gate depends on the drive's
    // phase: the lane is already attached, so C/H/E-post still run
    // under it, and q1 is the first semantic service either way. E's
    // exec gates (go_e/exec/trig) stay pass-gated: the mint needs gen
    // 0's bound image, the EXEC record and gen 1's row in that order.
    std::fs::write(&go, b"")?;
    std::fs::write(&late_e, b"")?;
    // One native drive spans mapping and the exec: run_classic gates the
    // coordinator when the drive ends, so a second drive's passes would
    // refuse while its counter never advances. The binder mints the
    // successor only when a single domain sees gen 0's bound image, the
    // EXEC record and gen 1's later-image row, in that order: rows first
    // read after the EXEC record drains refuse against the pre-exec
    // incarnation, so gen 0's probe must be read and settled before the
    // exec. go_e opens once pass 1 has admitted E; the exec gate opens
    // at pass 8, several passes after gen 0's rows bind; trig_e opens
    // once gen 1 readies (its probe proves the later image). Passes take
    // seconds next to the fixture's milliseconds, so the schedule has
    // wide margins; the post-drive ensures check the mapping, the mint
    // and the successor's mapped edge.
    let e_out = process_e.out.clone();
    let mut go_written = false;
    let mut exec_written = false;
    let mut trig_written = false;
    drive_native_passes_until(&mut coordinator, &mut |passes| {
        if !go_written && passes >= 2 {
            std::fs::write(&go_e, b"")?;
            go_written = true;
        }
        if !exec_written && passes >= 8 {
            std::fs::write(&exec_e, b"")?;
            exec_written = true;
        }
        let text = std::fs::read_to_string(&e_out).unwrap_or_default();
        let readys = text
            .lines()
            .filter(|line| line.starts_with("READY "))
            .count();
        if !trig_written && readys >= 2 {
            std::fs::write(&trig_e, b"")?;
            trig_written = true;
        }
        let exec = text.lines().any(|line| line.starts_with("EXEC "));
        let gen0 = text.lines().any(|line| line.starts_with("GEN0DONE "));
        let trig_done = text.lines().any(|line| line.starts_with("TRIGDONE "));
        eprintln!(
            "JOINT_R16 r16b-exec pass={passes} readys={readys} exec={} gen0={} trig={} trigdone={} xgate={}",
            u8::from(exec),
            u8::from(gen0),
            u8::from(trig_written),
            u8::from(trig_done),
            u8::from(exec_written),
        );
        Ok(passes >= 16)
    })?;
    mapping_diagnosis(
        &coordinator,
        "r16b-drive",
        &[
            ("E", process_e.pid()),
            ("C", process_c.pid()),
            ("S", process_s.pid()),
            ("H", process_h.pid()),
        ],
    );
    for (name, pid) in [
        ("E", process_e.pid()),
        ("C", process_c.pid()),
        ("S", process_s.pid()),
        ("H", process_h.pid()),
    ] {
        ensure!(
            has_mapped_edge(&coordinator, pid),
            "the {name} sibling maps in the spanning drive"
        );
    }
    let caller_s = caller_of(&coordinator, process_s.pid())?;
    let exec_records: Vec<_> = coordinator
        .adapter()
        .records()
        .filter(|record| record.pid == process_e.pid())
        .collect();
    eprintln!(
        "JOINT_R16 r16b-exec admitted records={} live={:?} mapped={}",
        exec_records.len(),
        coordinator
            .adapter()
            .live_id(process_e.pid())
            .map(|id| id.0),
        u8::from(has_mapped_edge(&coordinator, process_e.pid())),
    );
    for record in &exec_records {
        eprintln!(
            "JOINT_R16 r16b-exec record id={:?} incarnation={} lifecycle={:?} retired={}",
            record.id, record.incarnation, record.lifecycle, record.retired
        );
    }
    ensure!(
        exec_records.len() >= 2,
        "the exec minted a new incarnation: {} records",
        exec_records.len()
    );
    ensure!(
        has_mapped_edge(&coordinator, process_e.pid()),
        "the exec successor maps in the spanning drive"
    );

    // E-post, C and H run under the attached lane (`go` and `late_e`
    // opened before the drive, so the fixture's 30 s gate wait cannot
    // expire mid-drive). Both probes ran after attach too: gen 0's
    // sheds (its image is retired at conversion) while gen 1's stages,
    // so the ledger counts the b script plus the gen 1 probe.
    process_e.wait_for("DONE ", Duration::from_secs(60))?;
    process_c.wait_for("DONE ", Duration::from_secs(60))?;
    process_h.wait_for("HELD ", Duration::from_secs(30))?;
    ensure!(
        !process_h.has("RETURNED "),
        "H's held call returned before release"
    );
    let (e_by_fn, e_total, e_bad) = ledger_calls(&process_e.out)?;
    let (c_by_fn, c_total, c_bad) = ledger_calls(&process_c.out)?;
    ensure!(e_bad == 0 && c_bad == 0, "E and C never fail");
    ensure!(e_total > 0 && c_total == 3, "E and C ran their scripts");

    // q1: E-post and C completed, H held, S held pre-attach (its
    // entries shed, contributing nothing). Nothing replays through the
    // missing END(H), not even H's own completed SignInit: the frame
    // gates replay as a whole. S is neither bound nor registered: its
    // entries predate attach and it fired no post-attach probe event,
    // so the kernel minted no task cookie for it; the H0 scan refuses
    // and the refresh mints no receipt. Fail-closed absence, disclosed
    // below — not an upgrade to come.
    let q1_polls = service_to_published(&mut lane, &mut coordinator, true, "r16b-q1")?;
    // Print-only at q1: the frame gates replay as a whole while H is
    // held, so edge presence for E/C at q1 is unpinned.
    s1_feed_check(
        &coordinator,
        "r16b-q1",
        &[
            ("E", process_e.pid(), false),
            ("C", process_c.pid(), false),
            ("H", process_h.pid(), false),
            ("S", process_s.pid(), false),
        ],
    )?;
    let q1_end_ns = monotonic_ns();
    let reduced_q1: u64 = coordinator
        .registry()
        .instance_semantic_edges()
        .map(|record| record.feed.reduced())
        .sum();
    ensure!(reduced_q1 == 0, "r16b-q1: nothing replays while H is held");
    ensure!(
        coordinator
            .registry()
            .instance_semantic_edges()
            .all(|record| record.caller != caller_s),
        "r16b-q1: the pre-attach sibling registers nothing without observed calls"
    );
    ensure!(
        coordinator.semantic_bindings().get(caller_s).is_none(),
        "r16b-q1: the pre-attach sibling stays unbound without a kernel cookie"
    );
    ensure!(
        count_disclosed_gaps(
            &coordinator,
            "semantic admission refused",
            "semantic_unavailable:no_receipt",
            Some(caller_s),
        ) >= 1,
        "r16b-q1: the pre-attach sibling's admission refusal is disclosed"
    );
    let feeds_q1 = coordinator.registry().joint_feeds();
    let receipts_q1 = coordinator
        .registry()
        .pending_joint_receipts_for_test()
        .len();
    eprintln!(
        "JOINT_R16 r16b-q1 polls={q1_polls} feeds={feeds_q1} receipts={receipts_q1} \
         s_bound={} s_refusals={} census={:?}",
        u8::from(coordinator.semantic_bindings().get(caller_s).is_some()),
        count_disclosed_gaps(
            &coordinator,
            "semantic admission refused",
            "semantic_unavailable:no_receipt",
            Some(caller_s),
        ),
        joint_edge_census(&coordinator),
    );
    ensure_joint_birth_marker_wired(&coordinator, "r16b-q1")?;

    // Release H into q2; S stays held on its own FIFO.
    std::fs::OpenOptions::new().write(true).open(&release_h)?;
    process_h.wait_for("RETURNED ", Duration::from_secs(30))?;
    // DONE lands after the CALLS flush, so the ledger read below sees
    // H's whole pair.
    process_h.wait_for("DONE ", Duration::from_secs(30))?;
    let h_enter = ledger_stamp(&process_h.out, "HELD ")?;
    let h_exit = ledger_stamp(&process_h.out, "RETURNED ")?;
    ensure!(
        h_enter < q1_end_ns && q1_end_ns < h_exit,
        "H's hold genuinely spans q1"
    );
    let (h_by_fn, h_total, h_bad) = ledger_calls(&process_h.out)?;
    ensure!(
        h_bad == 0 && h_total == 2,
        "H made exactly SignInit plus its held Sign"
    );
    let q2_polls = service_to_published(&mut lane, &mut coordinator, false, "r16b-q2")?;
    s1_feed_check(
        &coordinator,
        "r16b-q2",
        &[
            ("E", process_e.pid(), true),
            ("C", process_c.pid(), true),
            ("H", process_h.pid(), true),
            ("S", process_s.pid(), false),
        ],
    )?;
    let (e_semantic, e_count_only) = ledger_semantic_split(&e_by_fn);
    let (c_semantic, c_count_only) = ledger_semantic_split(&c_by_fn);
    let (h_semantic, h_count_only) = ledger_semantic_split(&h_by_fn);
    let edge_e = joint_edge_snapshot(&coordinator, process_e.pid(), "soft-copy.so")?;
    let edge_c = joint_edge_snapshot(&coordinator, process_c.pid(), "soft-copy.so")?;
    let edge_h = joint_edge_snapshot(&coordinator, process_h.pid(), "live-joint-held.so")?;
    let caller_e = caller_of(&coordinator, process_e.pid())?;
    let caller_c = caller_of(&coordinator, process_c.pid())?;
    // v0.5.0 seals every production attachment without a journal
    // producer (OD33/R-50): the S1 branches below run, and the Joint
    // asserts stay for the 0.5.1 linked world.
    let linked = coordinator.registry().journal_linked();
    if linked {
        ensure!(
            edge_e.joint && edge_c.joint && edge_h.joint,
            "E, C and H are Joint"
        );
    } else {
        ensure!(
            !edge_e.joint && !edge_c.joint && !edge_h.joint,
            "E, C and H stay S1-only without a journal producer"
        );
    }
    let diagnose = |ok: bool, pid: u32, module: &str, by_fn: &BTreeMap<String, u64>| {
        if !ok {
            for line in exactness_diagnosis(&coordinator, pid, module, by_fn) {
                eprintln!("JOINT_R16 r16b-q2-diag {line}");
            }
        }
    };
    diagnose(
        edge_e.api_returns == Some(e_semantic),
        process_e.pid(),
        "soft-copy.so",
        &e_by_fn,
    );
    // E-post (exec-ordering race): attributed, or its miss is disclosed
    // as a named gap — never dropped silently. The strict Joint shape
    // stays for the 0.5.1 linked world.
    let e_attributed = edge_e.api_returns == Some(e_semantic);
    if linked {
        diagnose(
            edge_e.reduced == e_semantic,
            process_e.pid(),
            "soft-copy.so",
            &e_by_fn,
        );
        ensure!(
            e_attributed && edge_e.reduced == e_semantic,
            "E-post is exact: {:?}/{} vs semantic {e_semantic} \
             (entered {e_total}, count-only {e_count_only})",
            edge_e.api_returns,
            edge_e.reduced
        );
    } else if !e_attributed {
        let named = count_named_route_gaps(&coordinator, caller_e);
        eprintln!(
            "JOINT_R16 r16b-q2 e_miss api={:?} expected={e_semantic} named_gaps={named}",
            edge_e.api_returns
        );
        ensure!(
            named > 0,
            "E-post calls missed with no named gap (silent drop): {:?} vs semantic {e_semantic}",
            edge_e.api_returns
        );
    }
    diagnose(
        edge_c.api_returns == Some(c_semantic),
        process_c.pid(),
        "soft-copy.so",
        &c_by_fn,
    );
    ensure!(
        edge_c.api_returns == Some(c_semantic),
        "C is exact: {:?} vs semantic {c_semantic} \
         (entered {c_total}, count-only {c_count_only})",
        edge_c.api_returns,
    );
    diagnose(
        edge_h.api_returns == Some(h_semantic),
        process_h.pid(),
        "live-joint-held.so",
        &h_by_fn,
    );
    ensure!(
        edge_h.api_returns == Some(h_semantic),
        "H is exact: {:?} vs semantic {h_semantic} \
         (entered {h_total}, count-only {h_count_only})",
        edge_h.api_returns,
    );
    if linked {
        diagnose(
            edge_c.reduced == c_semantic,
            process_c.pid(),
            "soft-copy.so",
            &c_by_fn,
        );
        ensure!(
            edge_c.reduced == c_semantic,
            "C reduces exactly: {} vs {c_semantic}",
            edge_c.reduced
        );
        diagnose(
            edge_h.reduced == h_semantic,
            process_h.pid(),
            "live-joint-held.so",
            &h_by_fn,
        );
        ensure!(
            edge_h.reduced == h_semantic,
            "H reduces exactly: {} vs {h_semantic}",
            edge_h.reduced
        );
    }
    // The count-only calls never admit: each refusal is disclosed.
    for (pid, count_only, who) in [
        (process_e.pid(), e_count_only, "E-post"),
        (process_c.pid(), c_count_only, "C"),
        (process_h.pid(), h_count_only, "H"),
    ] {
        let caller = caller_of(&coordinator, pid)?;
        ensure!(
            count_disclosed_gaps(&coordinator, "semantic input refused", "slot", Some(caller))
                == count_only,
            "{who}'s count-only calls are disclosed as slot refusals: {count_only}"
        );
    }
    // E-post completions are exact when its calls attributed (or on the
    // strict linked branch); a disclosed S1 miss skips them.
    if linked || e_attributed {
        ensure!(
            edge_e.started == Some(3) && edge_e.completed == Some(3),
            "E-post completions are exact: {:?}/{:?}",
            edge_e.started,
            edge_e.completed
        );
    }
    ensure!(
        edge_c.started == Some(0) && edge_c.completed == Some(0),
        "C starts no operation: {:?}/{:?}",
        edge_c.started,
        edge_c.completed
    );
    ensure!(
        edge_h.started == Some(1) && edge_h.completed == Some(1),
        "H's sign operation completes exactly: {:?}/{:?}",
        edge_h.started,
        edge_h.completed
    );
    ensure!(
        coordinator
            .registry()
            .instance_semantic_edges()
            .all(|record| record.caller != caller_s),
        "r16b-q2: the still-held sibling registers nothing"
    );
    // No unmapped object ever gains a positive: every edge pairs its
    // owner with a provider it genuinely mapped.
    let census = joint_edge_census(&coordinator);
    for (pid, path) in &census {
        let held = path.contains("live-joint-held.so");
        let soft = path.contains("soft-copy.so");
        ensure!(
            (*pid == process_h.pid() && held)
                || (*pid != process_h.pid() && *pid != u32::MAX && soft),
            "r16b-q2: no false unmapped positive: {census:?}"
        );
    }
    for (pid, want) in [
        (process_e.pid(), "soft-copy.so"),
        (process_c.pid(), "soft-copy.so"),
        (process_h.pid(), "live-joint-held.so"),
    ] {
        ensure!(
            census
                .iter()
                .any(|(edge_pid, path)| *edge_pid == pid && path.contains(want)),
            "r16b-q2: owner {pid} pairs with {want}: {census:?}"
        );
    }
    eprintln!("JOINT_R16 r16b-q2 polls={q2_polls} census={census:?}");
    let feeds_q2 = coordinator.registry().joint_feeds();
    let receipts_q2 = coordinator
        .registry()
        .pending_joint_receipts_for_test()
        .len();

    // q3: S's late return is kernel-silent. Its entries predate
    // attach, so no START row exists for the held call and the return
    // probe drops it before emitting any event: no kernel record, no
    // task cookie, still no binding, still no edge. S stays
    // mapped-but-silent with its admission refusal disclosed per
    // transaction; it never holds a feed, Joint or otherwise.
    let unknown_before = coordinator
        .registry()
        .keyuse_for_test()
        .evidence()
        .unknown_key_rows;
    std::fs::OpenOptions::new().write(true).open(&release_s)?;
    process_s.wait_for("RETURNED ", Duration::from_secs(30))?;
    // DONE lands after the CALLS flush, so the ledger read below sees
    // S's whole pair.
    process_s.wait_for("DONE ", Duration::from_secs(30))?;
    let s_enter = ledger_stamp(&process_s.out, "HELD ")?;
    let s_exit = ledger_stamp(&process_s.out, "RETURNED ")?;
    ensure!(
        s_enter < attach_ns && attach_ns < s_exit,
        "S's entries predate attach and its return postdates it: {s_enter} {attach_ns} {s_exit}"
    );
    let (_, s_total, s_bad) = ledger_calls(&process_s.out)?;
    ensure!(
        s_bad == 0 && s_total == 2,
        "S entered exactly its held pair"
    );
    let q3_polls = service_to_published(&mut lane, &mut coordinator, false, "r16b-q3")?;
    ensure!(
        coordinator.semantic_bindings().get(caller_s).is_none(),
        "r16b-q3: the pre-attach sibling stays unbound after its silent return"
    );
    ensure!(
        joint_edge_snapshot(&coordinator, process_s.pid(), "live-joint-held.so").is_err(),
        "r16b-q3: the pre-attach sibling registers nothing without observed calls"
    );
    ensure!(
        has_mapped_edge(&coordinator, process_s.pid()),
        "r16b-q3: the pre-attach sibling stays mapped"
    );
    ensure!(
        coordinator.semantic_bindings().get(caller_s).is_none()
            && coordinator
                .registry()
                .instance_semantic_edges()
                .all(|record| record.caller != caller_s),
        "S never holds a feed, Joint or otherwise: no binding, no edge"
    );
    // Each transaction Binding sweeps at most 4 consecutive (caller,
    // object) pairs past the persistent refresh cursor
    // (src/discovery/inventory_coordinator/semantics.rs:1301 `for _ in 0..4`),
    // and q1, q2 and q3 sweep once each, so S's refusal floor follows from
    // this cell's actual pair count: full coverage while the universe fits
    // the limit, rotation coverage beyond it. The probe below runs the real
    // sweep (same function, same always-true charge as the Binding path) to
    // measure the universe instead of assuming it; a new fixture pair then
    // lowers the floor instead of failing opaquely. Probing advances the
    // persistent cursor, which is nil while the universe fits the limit
    // (every sweep covers all pairs) and harmless beyond it (no later
    // assert depends on sweep order). The universe is stable across q1-q3:
    // no process exits or spawns between them.
    let mut pairs = BTreeSet::new();
    for probe in 0..8usize {
        let attempts = coordinator.semantic_refresh_attempts(&lane, None, |_| true);
        let mut fresh = false;
        for attempt in &attempts {
            let objects: Vec<_> = lane
                .subset()
                .required()
                .iter()
                .filter(|(object, slots)| {
                    slots.first().copied() == Some(attempt.slot)
                        && attempt.module.as_ref().is_none_or(|module| {
                            lane.subset().proves_provider_module(**object, module)
                        })
                })
                .map(|(object, _)| *object)
                .collect();
            ensure!(
                objects.len() == 1,
                "r16b-q3: the swept refresh pair inverts to one object: {:?}",
                attempt.caller
            );
            fresh |= pairs.insert((attempt.caller, objects[0]));
        }
        if !fresh {
            break;
        }
        ensure!(
            probe + 1 < 8,
            "r16b-q3: the refresh pair universe keeps growing past the probe cap: {pairs:?}"
        );
    }
    let pair_count = pairs.len();
    ensure!(
        pairs.iter().any(|(caller, _)| *caller == caller_s),
        "r16b-q3: S's own pair is swept: {pairs:?}"
    );
    let bindings = 3u64;
    let s_floor: u64 = if pair_count <= 4 {
        bindings
    } else {
        (4 * bindings) / pair_count as u64
    };
    let s_refusals = count_disclosed_gaps(
        &coordinator,
        "semantic admission refused",
        "semantic_unavailable:no_receipt",
        Some(caller_s),
    );
    ensure!(
        s_refusals >= s_floor,
        "r16b-q3: the pre-attach sibling's admission refusals stay disclosed: \
         {s_refusals} over {pair_count} pairs (floor {s_floor}): {pairs:?}"
    );
    ensure!(
        coordinator.registry().joint_feeds() == feeds_q2,
        "S adds no Joint feed: {} vs {feeds_q2}",
        coordinator.registry().joint_feeds()
    );
    ensure!(
        coordinator
            .registry()
            .pending_joint_receipts_for_test()
            .len()
            == receipts_q2,
        "S installs no Joint receipt"
    );
    let census_q3 = joint_edge_census(&coordinator);
    ensure!(
        census_q3
            .iter()
            .all(|(edge_pid, _)| *edge_pid != process_s.pid()),
        "r16b-q3: S pairs with nothing while kernel-silent: {census_q3:?}"
    );
    let unknown_after = coordinator
        .registry()
        .keyuse_for_test()
        .evidence()
        .unknown_key_rows;
    ensure!(
        unknown_after == unknown_before,
        "S contributes no key facts while kernel-silent: {unknown_before} -> {unknown_after}"
    );
    let receipts = coordinator.registry().pending_joint_receipts_for_test();
    let revision = coordinator.registry().published_revision();
    let observations = coordinator.registry().joint_observations(revision);
    let linked = coordinator.registry().journal_linked();
    if linked {
        ensure!(!receipts.is_empty(), "nonzero observed Joint receipts");
        let aggregates = coordinator.registry().keyuse_for_test().aggregates();
        ensure!(!aggregates.is_empty(), "nonzero observed key receipts");
        ensure!(
            observations.status == crate::key_operation_projection::ObsStatus::Populated,
            "the guarded H9 section populates: {:?} ({})",
            observations.status,
            observations.reason
        );
        ensure!(
            !observations.key_operations.is_empty(),
            "the populated section carries key-operation rows"
        );
    } else {
        assert_s1_joint_absence(&coordinator, "r16b-q3", &observations)?;
    }
    // E-post missed its calls (exec-ordering race): its slot floor drops
    // to zero (unobserved calls convert nothing) while the ledger max
    // still holds, and its named miss gaps, printed at q2, are exempt
    // here so the miss path passes disclosed. Attributed E-post keeps
    // the exact floor and gains no dynamic exemption.
    let e_slot_min = if e_attributed { e_count_only } else { 0 };
    let mut exemptions = vec![
        QuietExemption {
            subject: "semantic input refused",
            reason: "slot",
            caller: Some(caller_e),
            min: e_slot_min,
            max: Some(e_count_only),
        },
        QuietExemption {
            subject: "semantic input refused",
            reason: "slot",
            caller: Some(caller_c),
            min: c_count_only,
            max: Some(c_count_only),
        },
        QuietExemption {
            subject: "semantic admission refused",
            reason: "semantic_unavailable:no_receipt",
            caller: Some(caller_s),
            min: s_floor,
            max: None,
        },
    ];
    let mut e_miss_gaps: Vec<(String, String)> = Vec::new();
    if !e_attributed {
        for gap in coordinator.registry().gaps() {
            if gap.caller != Some(caller_e) || gap.subject == "semantic input refused" {
                continue;
            }
            let key = (gap.subject.clone(), gap.reason.clone());
            if !e_miss_gaps.contains(&key) {
                e_miss_gaps.push(key);
            }
        }
    }
    for (subject, reason) in &e_miss_gaps {
        exemptions.push(QuietExemption {
            subject: subject.as_str(),
            reason: reason.as_str(),
            caller: Some(caller_e),
            min: 1,
            max: None,
        });
    }
    assert_quiet_twins_except(&coordinator, "r16b-q3", &exemptions)?;
    eprintln!(
        "JOINT_R16 r16b-q3 polls={q3_polls} revision={revision} feeds={} receipts={} \
         unknown_key={unknown_before}->{unknown_after} s_refusals={s_refusals} \
         pairs={pair_count} floor={s_floor}",
        coordinator.registry().joint_feeds(),
        receipts.len(),
    );

    // Finite stop with joined same-owner cleanup.
    let mut driver = joint_finish_driver(&mut coordinator, lane);
    let _completion = finish_stop_take_mint(&mut driver, "r16b-stop")?;
    drop(driver);
    drop(process_e);
    drop(process_c);
    drop(process_s);
    drop(process_h);
    eprintln!(
        "JOINT_R16 r16b-stop elapsed_s={}",
        cell_started.elapsed().as_secs()
    );
    ensure!(
        cell_started.elapsed() < Duration::from_secs(300),
        "the cell stops finite"
    );
    Ok(())
}
