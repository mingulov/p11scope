//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native lane over a scripted facade and a real coordinator (scripted
//! process source, scripted catalogs): the exact call order of startup,
//! passes and stop, and what each ordering rule buys end to end.

use super::*;
use crate::attach::capture::{
    AttachedEndpoint, CallerCountUpdate, CaptureHealth, CapturePhase, DomainCookie, ExecCoverage,
    WitnessRow,
};
use crate::discovery::caller_registry::tests::ScriptedSource;
use crate::discovery::caller_registry::{CallerId, ExeIdentity, RegistryLimits, UseCoverage};
use crate::discovery::engine::inventory::UnavailableImageGuard;
use crate::discovery::hooks::HookRegistry;
use crate::discovery::inventory_attach_set::AttachEndpoint;
use crate::discovery::inventory_attach_set::tests as fx;
use crate::discovery::inventory_workload::{Harness, ScaleSpec};
use crate::discovery::native_binding::UnboundReason;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;

type Pin = (u32, u64);
type Log = Rc<RefCell<Vec<String>>>;

const PID: u32 = 7;
const START: u64 = 500;
const TICKET: u64 = 41;
/// A failure bound only: a gated collection that is never serviced fails
/// after this instead of hanging.
const GATE_TIMEOUT: Duration = Duration::from_secs(5);
/// No collection tick fires in the exact-order tests: their collections
/// return at once.
const NO_COLLECTION_TICK: Duration = Duration::from_secs(3600);

#[derive(Clone, Copy)]
enum ExitRelease {
    Reclaimed,
    RetainedForExit,
}

/// RED-only forwarding seam for the approved owned release hook. It calls
/// the current production finalizer, which drops the full capture after output.
/// The release hook is deliberately not a production API until GREEN.
fn exit_finalizer_under_test<L, T>(
    stopped: Option<Stopped<L>>,
    write: impl FnOnce(Option<&LaneSummary>) -> T,
    outputs_attempted: &dyn Fn(),
    progress: &mut dyn FnMut(String),
    _release: impl FnOnce(Stopped<L>) -> ExitRelease,
) -> T {
    finish_native(stopped, write, outputs_attempted, progress)
}

struct HostExitPacket {
    capture: RetiringCapture,
    reader: crate::events::DiscoveryDrain<crate::events::ScriptedRecords>,
    _reader_fd: std::fs::File,
    drop_started: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for HostExitPacket {
    fn drop(&mut self) {
        // Observe actual owning destruction; no close/settlement is credited.
        self.drop_started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn exit_finalizer_control(completed: bool) {
    use std::os::fd::AsRawFd as _;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let log = Arc::new(Mutex::new(Vec::new()));
    let actor_log = Arc::clone(&log);
    let drop_started = Arc::new(AtomicUsize::new(0));
    let actor_drop = Arc::clone(&drop_started);
    let (made, owner_receiver) = mpsc::sync_channel(1);
    let (returned, result_receiver) = mpsc::sync_channel(1);
    let caller = std::thread::Builder::new()
        .spawn(move || {
            // The full facade envelope is created on its owning caller thread;
            // its native types are not required to be Send by the exit API.
            let case = RetiringCapture::host_exit_case("pending");
            let reader_fd = std::fs::File::open("/dev/null").unwrap();
            let raw_reader = reader_fd.as_raw_fd();
            let observation = case.observation();
            let release = case.release_on_unwind();
            let packet = HostExitPacket {
                capture: case.capture,
                reader: crate::events::DiscoveryDrain::over(
                    crate::events::ScriptedRecords::records([vec![0], vec![1]], 2),
                ),
                _reader_fd: reader_fd,
                drop_started: actor_drop,
            };
            // Declared after packet, so unwind releases its gate before the
            // packet's real owning destructor can join the pending job.
            let _release = release;
            // Actual queued decoder data; never a fabricated kernel row.
            let queued = packet.reader.source().remaining() == 2;
            let _domain = packet.capture.domain();
            made.send((observation, raw_reader)).unwrap();
            let saw_complete = if completed {
                case.gate
                    .wait_for(Duration::from_secs(1), |state| state.completed.contains(&0))
            } else {
                true
            };
            let summary = LaneSummary {
                retirement: if completed {
                    Retirement::Closed(CleanupSummary {
                        attempted: 1,
                        closed: 1,
                        failures: Vec::new(),
                        retained_links: 0,
                    })
                } else {
                    Retirement::Unsettled("actual host retirement close is still gated".into())
                },
                backend: LaneBackend::singles(),
                passes: 0,
                attached: 1,
                failed: 0,
                lifecycle: LifecycleTally::default(),
                lifecycle_high_water_bytes: None,
            };
            let write_log = Arc::clone(&actor_log);
            let arm_log = Arc::clone(&actor_log);
            let progress_log = Arc::clone(&actor_log);
            let release_log = Arc::clone(&actor_log);
            let result = exit_finalizer_under_test(
                Some(Stopped {
                    events: Vec::new(),
                    summary,
                    capture: packet,
                }),
                move |summary| {
                    write_log
                        .lock()
                        .unwrap()
                        .push(format!("output:{}", summary.unwrap().retirement.label()));
                    7
                },
                &move || arm_log.lock().unwrap().push("armed".into()),
                &mut move |line| progress_log.lock().unwrap().push(line),
                move |stopped| {
                    if completed {
                        drop(stopped);
                        release_log.lock().unwrap().push("reclaimed".into());
                        ExitRelease::Reclaimed
                    } else {
                        // The generic hook must pass the complete owner. This
                        // host packet includes actual job, root, File lease,
                        // reader fd and queued decoder data, not native maps.
                        std::mem::forget(stopped);
                        release_log.lock().unwrap().push("retained".into());
                        ExitRelease::RetainedForExit
                    }
                },
            );
            // SAFETY: inspect the control's original reader descriptor only;
            // no descriptor opens occur after the owning finalizer returned.
            let reader_open = unsafe { libc::fcntl(raw_reader, libc::F_GETFD) } >= 0;
            returned
                .send((result, reader_open, queued && saw_complete))
                .unwrap();
        })
        .unwrap();
    let (owner, _raw_reader) = owner_receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    let entered = owner
        .gate
        .wait_for(Duration::from_secs(1), |state| state.started.contains(&0));
    if completed {
        owner.gate.release_all();
    }
    let early = result_receiver
        .recv_timeout(Duration::from_millis(100))
        .ok();
    let root_held = owner.root.upgrade().is_some();
    let pin_held = owner.pin.upgrade().is_some();
    owner.gate.release_all();
    caller.join().unwrap();
    let after = early.unwrap_or_else(|| {
        result_receiver
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
    });
    let finished = owner
        .gate
        .wait_for(Duration::from_secs(1), |state| state.completed.contains(&0));
    let log = log.lock().unwrap().clone();
    assert!(
        entered && finished,
        "actual worker did not settle after release"
    );
    assert!(owner.gate.snapshot().failures.is_empty());
    assert_eq!(after.0, 7, "output result changed during ownership handoff");
    assert!(
        after.2,
        "queued decoder or completed close observation changed"
    );
    assert!(
        log[0].starts_with("output:") && log[1] == "armed",
        "{log:?}"
    );
    if completed {
        assert!(!after.1);
        assert_eq!(drop_started.load(Ordering::SeqCst), 1);
        assert!(owner.root.upgrade().is_none() && owner.pin.upgrade().is_none());
        assert!(
            !log.iter().any(|entry| entry.contains("detaching")),
            "{log:?}"
        );
    } else {
        assert!(
            early.is_some(),
            "post-output finalizer joined the pending actual job"
        );
        assert!(root_held && pin_held && after.1);
        assert_eq!(drop_started.load(Ordering::SeqCst), 0);
        assert!(log.iter().any(|entry| entry == "retained"), "{log:?}");
        assert!(
            !log.iter()
                .any(|entry| entry.contains("native probes detached")),
            "{log:?}"
        );
    }
}

#[test]
fn inventory_exit_retention_finalizer_keeps_full_owner_after_output_attempts() {
    RetiringCapture::run_host_exit_child(
        "inventory_capture::tests::inventory_exit_retention_finalizer_keeps_full_owner_after_output_attempts",
        || exit_finalizer_control(false),
    );
}

#[test]
fn inventory_exit_retention_completed_finalizer_still_reclaims_normally() {
    RetiringCapture::run_host_exit_child(
        "inventory_capture::tests::inventory_exit_retention_completed_finalizer_still_reclaims_normally",
        || exit_finalizer_control(true),
    );
}

/// The existing scripted capture through the real PID-pin runtime seam.
/// It supplies no kernel identity or privileged capture evidence.
pub(crate) fn cgroup_runtime_lane() -> (
    impl CaptureLane<crate::process::PidPin>,
    Rc<RefCell<Vec<String>>>,
) {
    cgroup_runtime_lane_with_exec(None)
}

pub(crate) fn cgroup_runtime_exec_lane(
    pid: u32,
) -> (
    impl CaptureLane<crate::process::PidPin>,
    Rc<RefCell<Vec<String>>>,
) {
    cgroup_runtime_lane_with_exec(Some(pid))
}

fn cgroup_runtime_lane_with_exec(
    pid: Option<u32>,
) -> (
    impl CaptureLane<crate::process::PidPin>,
    Rc<RefCell<Vec<String>>>,
) {
    struct OsLane(ScriptedLane, Option<u32>, u64);
    impl NativeIdentity<crate::process::PidPin> for OsLane {
        fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
            None
        }
        fn query_cookie(
            &mut self,
            domain: NativeDomainId,
            pin: &crate::process::PidPin,
        ) -> CookieQuery {
            if domain == self.0.domain && self.1 == Some(pin.pid()) {
                CookieQuery::Cookie(DomainCookie::scripted(domain, TICKET))
            } else {
                CookieQuery::NoCookie
            }
        }
    }
    impl CaptureLane<crate::process::PidPin> for OsLane {
        fn domain(&self) -> NativeDomainId {
            self.0.domain()
        }
        fn scope_coverage(&self) -> CaptureScopeCoverage {
            self.0.scope_coverage()
        }
        fn extend(
            &mut self,
            delta: TargetDelta,
            targets: &dyn CaptureTargets,
            window: ExtendWindow,
        ) -> ExtendReceipt {
            self.0.extend(delta, targets, window)
        }
        fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
            self.0.service_discovery(window)
        }
        fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
            let mut batch = self.0.read_witnesses(window);
            if let Some(pid) = self.1
                && let Some(endpoint) = self.0.attached.first()
            {
                self.2 = self.2.saturating_add(1);
                // Each new image row needs a later empty read's health
                // horizon, alongside a later lifecycle drain, before binding.
                let exec = match self.2 {
                    1 => Some(1),
                    3 => Some(2),
                    _ => None,
                };
                if let Some(exec) = exec {
                    batch.rows.push(WitnessRow::scripted(
                        self.0.domain,
                        TICKET,
                        exec,
                        endpoint.object,
                        endpoint.id,
                        pid,
                        batch.rows_read_ns,
                    ));
                }
            }
            batch
        }
        fn begin_stop(&mut self) {
            self.0.begin_stop();
        }
        fn poll_retirement(&mut self, deadline: Instant) -> Result<bool> {
            self.0.poll_retirement(deadline)
        }
        fn cleanup(&self) -> Option<CleanupSummary> {
            self.0.cleanup()
        }
    }
    let log = Log::default();
    let mut lane = ScriptedLane::new(&log);
    lane.scope_coverage = CaptureScopeCoverage::Cgroup;
    (OsLane(lane, pid, 0), log)
}

/// Strictly increasing CLOCK_MONOTONIC stamps: each facade batch follows
/// the one before it, and every stamp follows the real clock.
#[derive(Default)]
struct Stamps(u64);

impl Stamps {
    fn next(&mut self) -> u64 {
        self.0 = now_ns().max(self.0 + 1);
        self.0
    }
}

/// One row the scripted capture reports: the attached endpoint's index (in
/// attach order), the caller tgid, and its ticket.
#[derive(Clone, Copy)]
struct RowSpec {
    endpoint: usize,
    tgid: u32,
    ticket: u64,
}

/// One refreshed count the scripted capture reports: the attached endpoint's
/// index (for its object), the caller image, and the re-read count.
#[derive(Clone, Copy)]
struct CountSpec {
    endpoint: usize,
    ticket: u64,
    exec: u64,
    count: u64,
}

/// A scripted facade: records every call, activates on the first extend,
/// attaches what it is given (minus a scripted deferral), reports scripted
/// rows per read, answers scripted cookies, and retires after a scripted
/// number of polls (never, when `None`).
struct ScriptedLane {
    log: Log,
    scope_coverage: CaptureScopeCoverage,
    domain: NativeDomainId,
    stamps: Stamps,
    activated: bool,
    refuse_activation: bool,
    /// Endpoints the next non-activating extend defers (from the end).
    defer_next: usize,
    attached: Vec<AttachEndpoint>,
    reads: VecDeque<Vec<RowSpec>>,
    /// Refreshed counts per read, popped in read order like `reads`.
    refreshes: VecDeque<Vec<CountSpec>>,
    /// Health instants of every read, in order.
    read_stamps: Vec<u64>,
    cookies: HashMap<Pin, u64>,
    stopping: bool,
    polls: u32,
    retire_after: Option<u32>,
    retirement_error: bool,
    retired: bool,
    /// The first this many reads cannot prove health.
    unproven_reads: usize,
    /// Reads (1-based) that stop mid-sweep.
    partial_reads: HashSet<usize>,
    /// Reads (1-based) whose count-refresh sweep does not complete.
    partial_refresh_reads: HashSet<usize>,
    /// Reads (1-based) whose count-refresh sweep completes with gaps.
    gappy_refresh_reads: HashSet<usize>,
    /// How long each read takes.
    read_delay: Duration,
    /// After this many reads, the next `.1` discovery quanta stop at their
    /// record bound (the ring still holds records).
    undrained_after_reads: Option<(usize, usize)>,
    /// The start of the last complete lifecycle drain (the facade's
    /// `lifecycle_proven_ns`).
    drained_ns: u64,
    /// Signalled on every discovery service (the collection gate's tap).
    serviced: Option<mpsc::Sender<()>>,
    /// Every serviced quantum's start stamp, in drain order.
    service_stamps: Rc<RefCell<Vec<u64>>>,
    /// Records each discovery quantum returns (non-exec, binder-neutral).
    records_per_service: usize,
    /// The DISCOVERY ring-loss counter each read reports, in read order
    /// (the last one repeats; empty: 0).
    ring_loss: VecDeque<u64>,
    /// The malformed-record count each read reports, as `ring_loss`.
    malformed: VecDeque<u64>,
    /// Discovery services (1-based) whose quantum fails on an undecodable
    /// record.
    failed_services: HashSet<usize>,
    /// The drain high-water each discovery quantum reports, by service
    /// (1-based: the first entry is the first service); `None` past it.
    drain_high_water_bytes: Vec<Option<u64>>,
    services: usize,
    /// The actual deadlines passed through the native I/O boundary.
    io_deadlines: Rc<RefCell<Vec<(&'static str, Instant)>>>,
}

impl Drop for ScriptedLane {
    fn drop(&mut self) {
        self.note("drop");
    }
}

impl ScriptedLane {
    fn new(log: &Log) -> Self {
        let mut cookies = HashMap::new();
        cookies.insert((PID, START), TICKET);
        Self {
            log: Rc::clone(log),
            scope_coverage: CaptureScopeCoverage::System,
            domain: NativeDomainId::mint(),
            stamps: Stamps::default(),
            activated: false,
            refuse_activation: false,
            defer_next: 0,
            attached: Vec::new(),
            reads: VecDeque::new(),
            refreshes: VecDeque::new(),
            read_stamps: Vec::new(),
            cookies,
            stopping: false,
            polls: 0,
            retire_after: Some(1),
            retirement_error: false,
            retired: false,
            unproven_reads: 0,
            partial_reads: HashSet::new(),
            partial_refresh_reads: HashSet::new(),
            gappy_refresh_reads: HashSet::new(),
            read_delay: Duration::ZERO,
            undrained_after_reads: None,
            drained_ns: 0,
            serviced: None,
            service_stamps: Rc::default(),
            records_per_service: 0,
            ring_loss: VecDeque::new(),
            malformed: VecDeque::new(),
            failed_services: HashSet::new(),
            drain_high_water_bytes: Vec::new(),
            services: 0,
            io_deadlines: Rc::default(),
        }
    }

    fn note(&self, entry: impl Into<String>) {
        self.log.borrow_mut().push(entry.into());
    }

    fn custody(&self) -> ScopeCustody {
        match self.scope_coverage {
            CaptureScopeCoverage::System => ScopeCustody::System,
            CaptureScopeCoverage::Pid(_) => ScopeCustody::PidHeld,
            CaptureScopeCoverage::Cgroup => ScopeCustody::CgroupHeld,
        }
    }
}

impl NativeIdentity<Pin> for ScriptedLane {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &Pin) -> CookieQuery {
        if domain != self.domain {
            return CookieQuery::Unavailable("another domain".into());
        }
        match self.cookies.get(pin) {
            Some(ticket) => CookieQuery::Cookie(DomainCookie::scripted(domain, *ticket)),
            None => CookieQuery::NoCookie,
        }
    }
}

impl CaptureLane<Pin> for ScriptedLane {
    fn domain(&self) -> NativeDomainId {
        self.domain
    }

    fn scope_coverage(&self) -> CaptureScopeCoverage {
        self.scope_coverage
    }

    fn extend(
        &mut self,
        mut delta: TargetDelta,
        _: &dyn CaptureTargets,
        _: ExtendWindow,
    ) -> ExtendReceipt {
        let ids: Vec<String> = delta
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id.0.to_string())
            .collect();
        self.note(format!("extend[{}]", ids.join(",")));
        let mut receipt = ExtendReceipt {
            custody: Some(self.custody()),
            ..ExtendReceipt::default()
        };
        if !self.activated {
            if self.refuse_activation {
                receipt.refused = Some("scripted activation refusal".into());
                receipt.deferred = delta;
                return receipt;
            }
            self.activated = true;
            receipt.activated_roots = true;
            receipt.exec_coverage = Some(ExecCoverage::scripted(self.domain, self.stamps.next()));
        }
        let keep = delta.endpoints.len().saturating_sub(self.defer_next);
        if self.defer_next > 0 && !delta.endpoints.is_empty() {
            receipt.deferred.endpoints = delta.endpoints.split_off(keep);
            self.defer_next = 0;
        }
        for endpoint in delta.endpoints {
            receipt.attached.push(AttachedEndpoint {
                id: endpoint.id,
                object: endpoint.object,
                at_ns: self.stamps.next(),
            });
            self.attached.push(endpoint);
        }
        receipt
    }

    fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        self.io_deadlines
            .borrow_mut()
            .push(("discovery", window.deadline()));
        self.note("service");
        self.services += 1;
        // SAFETY: `DiscoveryRecord` is a plain `repr(C)` integer record; all
        // zeroes is a valid value (kind 0: no exec, the binder ignores it).
        let records = (0..self.records_per_service.min(window.max_rows()))
            .map(|_| unsafe { std::mem::zeroed::<p11scope_ebpf_common::DiscoveryRecord>() })
            .collect();
        let mut batch = DiscoveryBatch::scripted(self.domain, records, self.stamps.next());
        batch.drain_high_water_bytes = self
            .drain_high_water_bytes
            .get(self.services - 1)
            .copied()
            .flatten();
        // A quantum that fills its window stops at its record bound.
        batch.record_bound_reached = self.records_per_service >= window.max_rows();
        if self.failed_services.contains(&self.services) {
            batch.failure = Some("scripted undecodable record".into());
        }
        self.service_stamps.borrow_mut().push(batch.started_ns);
        if let Some(serviced) = &self.serviced {
            let _ = serviced.send(());
        }
        if let Some((after, left)) = self.undrained_after_reads.as_mut()
            && self.read_stamps.len() >= *after
            && *left > 0
        {
            *left -= 1;
            batch.record_bound_reached = true;
        }
        if batch.drained() {
            self.drained_ns = batch.started_ns;
        }
        batch
    }

    fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        self.io_deadlines.borrow_mut().push((
            if self.stopping {
                "post-read"
            } else {
                "pre-read"
            },
            window.deadline(),
        ));
        self.note("read");
        std::thread::sleep(self.read_delay);
        let health_read_ns = self.stamps.next();
        self.read_stamps.push(health_read_ns);
        let rows = self
            .reads
            .pop_front()
            .unwrap_or_default()
            .into_iter()
            .map(|spec| {
                let endpoint = self.attached[spec.endpoint];
                WitnessRow::scripted(
                    self.domain,
                    spec.ticket,
                    1,
                    endpoint.object,
                    endpoint.id,
                    spec.tgid,
                    health_read_ns,
                )
            })
            .collect();
        let counts = self
            .refreshes
            .pop_front()
            .unwrap_or_default()
            .into_iter()
            .map(|spec| {
                let endpoint = self.attached[spec.endpoint];
                CallerCountUpdate {
                    image: ImageIdentity {
                        task_cookie: spec.ticket,
                        exec_id: spec.exec,
                    },
                    object: endpoint.object,
                    count: spec.count,
                }
            })
            .collect();
        let rows_read_ns = self.stamps.next();
        let health_unproven = (self.read_stamps.len() <= self.unproven_reads)
            .then(|| "scripted unreadable health".to_string());
        let scripted = |counts: &mut VecDeque<u64>| match counts.len() {
            0 => 0,
            1 => counts[0],
            _ => counts.pop_front().unwrap(),
        };
        let ring_loss = scripted(&mut self.ring_loss);
        let malformed = scripted(&mut self.malformed);
        WitnessBatch {
            domain: self.domain,
            phase: if self.stopping {
                CapturePhase::Retiring
            } else {
                CapturePhase::Active
            },
            rows,
            integrity: Vec::new(),
            integrity_total: 0,
            visited: 0,
            sweep_completed: !self.partial_reads.contains(&self.read_stamps.len()),
            sweeps_completed: 1,
            row_bound_reached: false,
            deadline_reached: false,
            read_failures: Vec::new(),
            unrecorded_rows: 0,
            sweep_gaps: false,
            counts,
            refresh_sweep_completed: !self.partial_refresh_reads.contains(&self.read_stamps.len()),
            refresh_sweep_gaps: self.gappy_refresh_reads.contains(&self.read_stamps.len()),
            refresh_deadline_reached: false,
            refresh_sweeps_completed: 1,
            seen_rows: 0,
            pair_limit: 64,
            lifecycle_loss: None,
            lifecycle_proven_ns: self.drained_ns,
            health: CaptureHealth {
                discovery_counters: Some([ring_loss, 0, 0, 0, 0]),
                malformed_discovery: malformed,
                ..CaptureHealth::default()
            },
            health_regression: None,
            health_unproven,
            health_baseline_ns: 0,
            health_read_ns,
            rows_anchor_ns: rows_read_ns,
            rows_read_ns,
            counts_read_ns: rows_read_ns,
            changed_objects: Vec::new(),
            custody: self.custody(),
            custody_proven_ns: None,
            unsettled: self.stopping,
        }
    }

    fn begin_stop(&mut self) {
        self.note("begin_stop");
        self.stopping = true;
    }

    fn poll_retirement(&mut self, deadline: Instant) -> Result<bool> {
        self.io_deadlines
            .borrow_mut()
            .push(("retirement", deadline));
        self.note("poll");
        self.polls += 1;
        if self.retirement_error {
            return Err(anyhow!("controlled retirement poll failure"));
        }
        if self.retire_after.is_some_and(|after| self.polls >= after) {
            self.retired = true;
        }
        Ok(self.retired)
    }

    fn cleanup(&self) -> Option<CleanupSummary> {
        self.retired.then(|| CleanupSummary {
            attempted: self.attached.len() + 2,
            closed: self.attached.len() + 2,
            failures: Vec::new(),
            retained_links: 0,
        })
    }
}

/// A real coordinator over a scripted process source (pid 7, start 500,
/// mapping one two-endpoint provider) that records every call the lane and
/// the loop make on it.
struct Scene {
    _dir: tempfile::TempDir,
    path: PathBuf,
    source: ScriptedSource,
    coordinator: InventoryCoordinator<ScriptedSource>,
    log: Log,
    /// The loop's per-tick hook notes `display` (C5.3: the dashboard).
    display_ticks: bool,
    /// Exercise the serialized optional-job hook without native proof.
    native_service_ticks: bool,
    /// A second caller (pid, start) that maps the provider from this scan
    /// (1-based) on.
    joiner: Option<(u32, u64, usize)>,
    scans: usize,
    /// The first collection waits for this many discovery services (C5.7
    /// threading boundary): it cannot finish unless the loop services the
    /// ring while it runs.
    collect_gate: Option<(mpsc::Receiver<()>, usize)>,
    /// Every staged lifecycle quantum's start stamp, in staging order.
    staged_lifecycle: Vec<u64>,
    /// Every staged witness batch's refreshed-count size, in staging order.
    staged_counts: Vec<usize>,
}

impl Scene {
    fn new(log: &Log) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = fx::provider(&dir, "a.so", "provider-a");
        let source = ScriptedSource::default();
        source.spawn(PID, START);
        let coordinator = InventoryCoordinator::new(
            crate::attach::Scope::System,
            HookRegistry::builtin(),
            Vec::new(),
            source.clone(),
            RegistryLimits::default_limits(),
        )
        .unwrap();
        Self {
            _dir: dir,
            path,
            source,
            coordinator,
            log: Rc::clone(log),
            display_ticks: false,
            native_service_ticks: false,
            joiner: None,
            scans: 0,
            collect_gate: None,
            staged_lifecycle: Vec::new(),
            staged_counts: Vec::new(),
        }
    }

    fn note(&self, entry: impl Into<String>) {
        self.log.borrow_mut().push(entry.into());
    }

    /// The pass's catalog: pid 7 maps the provider, plus the Inventory
    /// lowering the attach set absorbs.
    fn catalog(&self) -> crate::inspect_system::Catalog {
        let pins = fx::pass_pins(&[(&self.path, "sha-a")]);
        let module = fx::module(&pins, &self.path, &fx::offsets(2));
        let policy =
            crate::plan::AdmissionPolicy::Inventory(self.coordinator.attach_set().budget());
        let plan = fx::lower_named(std::slice::from_ref(&module), &pins, policy);
        let path = self.path.to_str().unwrap().to_string();
        let mut members = vec![(PID, START)];
        if let Some((pid, start, from)) = self.joiner
            && self.scans >= from
        {
            members.push((pid, start));
        }
        let (key, sha256) = {
            let summary = pins.pinned().find(|summary| summary.path == path).unwrap();
            (summary.key, summary.sha256.to_string())
        };
        let object = crate::inspect_system::CatalogObject {
            path: path.clone(),
            key,
            sha256: Some(sha256),
            build_id: None,
            identity_source: Some("mountinfo"),
            note: None,
            mappings: Vec::new(),
            observations: members
                .iter()
                .map(|(pid, _)| crate::inspect_system::Observation {
                    pid: *pid,
                    path: path.clone(),
                    exports: Vec::new(),
                    tables: Vec::new(),
                    interfaces: Vec::new(),
                    double_loaded: false,
                    evidence: crate::inspect_system::ObservationEvidence::DeepScan,
                })
                .collect(),
            admission: crate::inspect_system::AdmissionRecord::Admitted {
                class: "exact",
                endpoints: 2,
            },
        };
        crate::inspect_system::Catalog {
            scan_status: "complete",
            lowering: Some(crate::inspect_system::CatalogLowering { plan, pins }),
            enumerated: 1,
            selected: 1,
            scanned: 1,
            maps_matched: 0,
            unexamined: 0,
            unexamined_objects: 0,
            snapshots_unavailable: 0,
            attribution_losses: std::collections::BTreeMap::new(),
            cap: 1,
            scan_ms: 0,
            processes: members
                .iter()
                .map(|(pid, start)| crate::inspect_system::ProcessRecord {
                    application: crate::inspect_identity::InspectApplicationResult::Unknown(
                        crate::inspect_identity::InspectIdentityUnknown::NotExamined,
                    ),
                    complete_scan: None,
                    pid: *pid,
                    status: crate::inspect_system::MemberStatus::Scanned,
                    objects: vec![0],
                    generation: Some(crate::inspect_system::MemberGeneration {
                        start_time: Some(*start),
                        exe: Some(ExeIdentity {
                            dev: 1,
                            ino: 100,
                            mtime_secs: 10,
                            mtime_nanos: 0,
                            path: Some("/bin/driver".into()),
                        }),
                    }),
                })
                .collect(),
            objects: vec![object],
            relationships: Vec::new(),
            admission: crate::inspect_system::AdmissionSummary {
                uncorroborated_candidates: 0,
                module_ambiguous: 0,
                admitted: 1,
                refused: 0,
                unresolved: 0,
            },
            skipped: Vec::new(),
            notes: Vec::new(),
            explanation: None,
            stage_timings: crate::timing::StageTimings::new(),
        }
    }

    fn caller(&self, pid: u32) -> CallerId {
        self.coordinator
            .adapter()
            .records()
            .find(|record| record.pid == pid)
            .map(|record| record.id)
            .expect("the pid was admitted")
    }

    fn coverage(&self) -> UseCoverage {
        self.coverage_of(PID)
    }

    fn coverage_of(&self, pid: u32) -> UseCoverage {
        let caller = self.caller(pid);
        let registry = self.coordinator.registry();
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("pid 7 has its edge");
        registry.coverage(edge)
    }

    fn gap_subjects(&self) -> Vec<String> {
        self.coordinator
            .registry()
            .gaps()
            .iter()
            .map(|gap| gap.subject.clone())
            .collect()
    }
}

impl LaneHost<Pin> for Scene {
    fn begin_capture_coverage(&mut self, scope: CaptureScopeCoverage) {
        self.note("begin_capture_coverage");
        self.coordinator.begin_capture_coverage(scope);
    }

    fn abandon_capture_coverage(&mut self) {
        self.note("abandon_capture_coverage");
        self.coordinator.abandon_capture_coverage();
    }

    fn note_extend_receipt(&mut self, receipt: &ExtendReceipt) {
        self.note(if receipt.exec_coverage.is_some() {
            "note_extend_receipt(activating)"
        } else {
            "note_extend_receipt"
        });
        self.coordinator.note_extend_receipt(receipt);
    }

    fn note_capture_custody(&mut self, custody: &ScopeCustody) {
        self.note("note_capture_custody");
        self.coordinator.note_capture_custody(custody);
    }

    fn take_target_delta(&mut self) -> TargetDelta {
        self.note("take_target_delta");
        self.coordinator.take_target_delta()
    }

    fn capture_targets(&self) -> &dyn CaptureTargets {
        self.coordinator.attach_set()
    }

    fn stage_native(
        &mut self,
        batch: NativeBatch,
        identity: &mut dyn NativeIdentity<Pin>,
        now_ns: u64,
    ) -> NativeReceipt {
        self.note(match &batch {
            NativeBatch::Witness(_) => "stage:witness",
            NativeBatch::Lifecycle(_) => "stage:lifecycle",
            NativeBatch::Finish { .. } => "stage:finish",
            NativeBatch::Semantic(_) => "stage:semantic",
        });
        if let NativeBatch::Lifecycle(lifecycle) = &batch {
            self.staged_lifecycle.push(lifecycle.started_ns);
        }
        if let NativeBatch::Witness(witness) = &batch {
            self.staged_counts.push(witness.counts.len());
        }
        self.coordinator.stage_native(batch, identity, now_ns)
    }

    fn end_capture_coverage(&mut self, at_ns: u64) {
        self.note("end_capture_coverage");
        self.coordinator.end_capture_coverage(at_ns);
    }

    fn note_native_lane(&mut self) {
        self.note("note_native_lane");
        LaneHost::<Pin>::note_native_lane(&mut self.coordinator);
    }

    fn note_scope_gap(&mut self, subject: String, reason: String) {
        self.note(format!("gap:{subject}"));
        self.coordinator.note_scope_gap(subject, reason);
    }

    fn note_refresh_loss(&mut self, reason: String) {
        self.note(format!("refresh-loss:{reason}"));
        self.coordinator.note_refresh_loss(reason);
    }
}

impl PassDriver<Pin> for Scene {
    type Host = Self;

    fn host(&mut self) -> &mut Self {
        self
    }

    fn collector(&mut self) -> CollectJob {
        self.note("collect");
        self.scans += 1;
        let catalog = self.catalog();
        let gate = self.collect_gate.take();
        CollectJob::Legacy(Box::new(move || {
            if let Some((serviced, wanted)) = gate {
                for _ in 0..wanted {
                    serviced
                        .recv_timeout(GATE_TIMEOUT)
                        .map_err(|_| anyhow!("the ring was not serviced during the collection"))?;
                }
            }
            Ok(catalog)
        }))
    }

    fn apply(
        &mut self,
        collected: CollectedPass,
        identity: &mut dyn NativeIdentity<Pin>,
        now_ns: u64,
    ) -> Result<PassReport> {
        self.note("scan");
        Ok(self.coordinator.apply_catalog(
            collected.legacy()?,
            &mut UnavailableImageGuard,
            identity,
            u64::MAX,
            now_ns,
        ))
    }

    fn commit(&mut self, engine_changed: bool) -> Result<()> {
        self.note("commit");
        self.coordinator.commit_batch(engine_changed).map(|_| ())
    }

    fn on_tick(&mut self) {
        if self.display_ticks {
            self.note("display");
        }
    }

    fn on_native_service(&mut self, capture: Option<&mut dyn CaptureLane<Pin>>) {
        if self.native_service_ticks {
            self.note(if capture.is_some() {
                "native-service"
            } else {
                "native-unavailable"
            });
        }
    }
}

fn windows() -> LaneWindows {
    LaneWindows {
        retirement_base: Duration::from_millis(200),
        retirement_per_link: Duration::from_millis(50),
        ..LaneWindows::PROVISIONAL
    }
}

/// Runs `passes` passes (no pause between them), then the stop.
fn run(
    scene: &mut Scene,
    lane: ScriptedLane,
    passes: usize,
) -> (Stopped<ScriptedLane>, Vec<CallerEvent>) {
    run_ticking(scene, lane, passes, NO_COLLECTION_TICK)
}

/// `run` with a collection tick.
fn run_ticking(
    scene: &mut Scene,
    lane: ScriptedLane,
    passes: usize,
    collection_tick: Duration,
) -> (Stopped<ScriptedLane>, Vec<CallerEvent>) {
    let log = Rc::clone(&scene.log);
    let started = NativeLane::start(lane, scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    // Completed passes stop after publication (F9): counting scans
    // would fire during the Nth apply, before its native half, and the
    // restored post-apply split would skip its extension.
    let publishes = move || {
        log.borrow()
            .iter()
            .filter(|entry| *entry == "publish:pass")
            .count()
    };
    let stop = move || publishes() >= passes;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick,
    };
    let mut published = Vec::new();
    let stopped = run_classic(
        scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            match point {
                Publish::Pass { report, .. } => {
                    scene.note("publish:pass");
                    published.extend(report.events.iter().cloned());
                }
                Publish::Retiring {
                    attached, budget, ..
                } => {
                    scene.note(format!(
                        "publish:retiring {attached} {}",
                        budget.as_millis()
                    ));
                }
                Publish::Stop { events, .. } => {
                    scene.note("publish:stop");
                    published.extend(events.iter().cloned());
                }
            }
            Ok(())
        },
    )
    .unwrap()
    .expect("a native run stops its lane");
    (stopped, published)
}

fn entries(log: &Log) -> Vec<String> {
    log.borrow().clone()
}

const STARTUP: [&str; 4] = [
    "begin_capture_coverage",
    "extend[]",
    "note_extend_receipt(activating)",
    "note_native_lane",
];

fn pass(extend: &str) -> Vec<String> {
    [
        "collect",
        "scan",
        "take_target_delta",
        extend,
        "note_extend_receipt",
        "service",
        "stage:lifecycle",
        "read",
        "stage:witness",
        "commit",
        "publish:pass",
    ]
    .map(String::from)
    .to_vec()
}

const STOP: [&str; 15] = [
    // Two endpoints: the 200 ms base and 50 ms for each.
    "publish:retiring 2 300",
    // A complete lifecycle drain right before the terminal read.
    "service",
    "stage:lifecycle",
    "read",
    "stage:witness",
    "end_capture_coverage",
    "begin_stop",
    "poll",
    "service",
    "stage:lifecycle",
    "read",
    "stage:witness",
    "stage:finish",
    "commit",
    "publish:stop",
];

/// Invariants 1, 2 and 4 as one exact call sequence: activation before the
/// first scan with its receipt forwarded at once, then per pass scan →
/// delta → extend → receipt → lifecycle → witness → commit → publish, then
/// the terminal read before the coverage ends, retirement under service, one
/// more read, Finish, commit.
#[test]
fn the_lane_follows_the_contract_order_from_startup_through_stop() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let (stopped, _) = run(&mut scene, lane, 2);
    let mut expected: Vec<String> = STARTUP.map(String::from).to_vec();
    expected.extend(pass("extend[0,1]"));
    expected.extend(pass("extend[]"));
    expected.extend(STOP.map(String::from));
    assert_eq!(entries(&log), expected);
    assert_eq!(stopped.summary.passes, 2);
    assert_eq!(stopped.summary.attached, 2);
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

/// F9 mid-apply cancellation: a stop landing during apply latches
/// before the pass's native half — no new target extension or
/// successor admission starts — while the applied pass still commits,
/// publishes, and owned-drains. The joiner would admit on a second
/// scan, proving no second pass runs.
#[test]
fn mid_apply_cancellation_skips_extension_and_successor_mint_but_preserves_applied_data() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.source.spawn(8, 800);
    scene.joiner = Some((8, 800, 2));
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    // The stop fires as soon as the first apply logs "scan": during
    // the apply, before its native half.
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 1;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let mut pass_publications = 0;
    let stopped = run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            match point {
                Publish::Pass { .. } => {
                    scene.note("publish:pass");
                    pass_publications += 1;
                }
                Publish::Retiring {
                    attached, budget, ..
                } => scene.note(format!(
                    "publish:retiring {attached} {}",
                    budget.as_millis()
                )),
                Publish::Stop { .. } => scene.note("publish:stop"),
            }
            Ok(())
        },
    )
    .unwrap()
    .expect("the owned stop still drains");
    assert_eq!(stopped.summary.passes, 1, "the in-flight pass still runs");
    assert_eq!(pass_publications, 1, "the applied pass is published");
    let captured = entries(&log);
    assert_eq!(
        captured.iter().filter(|entry| *entry == "scan").count(),
        1,
        "no second pass starts after the stop: {captured:?}"
    );
    assert_eq!(
        captured
            .iter()
            .filter(|entry| entry.starts_with("extend["))
            .count(),
        1,
        "only the startup extend runs: {captured:?}"
    );
    assert!(
        !captured.iter().any(|entry| entry == "take_target_delta"),
        "no target delta is taken after the stop: {captured:?}"
    );
    assert_eq!(
        captured.iter().filter(|entry| *entry == "commit").count(),
        2,
        "the applied pass commits, then the stop's terminal commit runs: {captured:?}"
    );
    assert!(
        captured.iter().any(|entry| entry == "publish:stop"),
        "the stop still publishes: {captured:?}"
    );
    assert!(
        captured.iter().any(|entry| entry == "begin_stop"),
        "retirement still begins: {captured:?}"
    );
    // The applied incarnation stands; the joiner never admits.
    let _ = scene.caller(PID);
    assert_eq!(
        scene.coordinator.adapter().len(),
        1,
        "no successor or joiner mints after the stop"
    );
    assert_eq!(
        scene.coordinator.adapter().live_id(8),
        None,
        "the second-scan joiner never admits"
    );
}

#[test]
fn cgroup_lane_startup_and_terminal_reads_preserve_explicit_coverage() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.scope_coverage = CaptureScopeCoverage::Cgroup;
    let (stopped, _) = run(&mut scene, lane, 2);
    assert_eq!(
        scene.coverage(),
        UseCoverage::Unknown(UnknownReason::ScopeMembershipUnproven)
    );
    assert_eq!(
        stopped.capture.scope_coverage(),
        CaptureScopeCoverage::Cgroup
    );
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

/// The stop summary carries the run's drain high-water (the terminal
/// sweep folds in with every pass drain); a lane that sampled nothing
/// reports none.
#[test]
fn the_stop_summary_carries_the_drain_high_water() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // The largest fill comes first and a smaller one after it, so only a
    // maximum (not the last report) reads 777.
    lane.drain_high_water_bytes = vec![Some(777), None, Some(50)];
    let (stopped, _) = run(&mut scene, lane, 1);
    let services = log
        .borrow()
        .iter()
        .filter(|entry| *entry == "service")
        .count();
    assert!(services >= 3, "the script must be consumed: {services}");
    assert_eq!(stopped.summary.lifecycle_high_water_bytes, Some(777));

    let log = Log::default();
    let mut scene = Scene::new(&log);
    let (stopped, _) = run(&mut scene, ScriptedLane::new(&log), 1);
    assert_eq!(stopped.summary.lifecycle_high_water_bytes, None);
}

/// Invariant 1 end to end: the roots activate before the first scan and
/// the activating receipt is forwarded, so the caller the first pass admits
/// is inside exec coverage and its first-pass row binds at stop. Activating
/// after the scan, or dropping the activating receipt, leaves the row an
/// `exec_coverage_gap` instead.
#[test]
fn a_row_of_the_first_pass_binds_because_activation_precedes_the_scan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.reads.push_back(vec![RowSpec {
        endpoint: 0,
        tgid: PID,
        ticket: TICKET,
    }]);
    let (_, _) = run(&mut scene, lane, 1);
    let census = scene.coordinator.registry().witness_census().clone();
    assert_eq!(
        (census.rows, census.bound, census.pending),
        (1, 1, 0),
        "{census:?}"
    );
    assert_eq!(census.unbound.get(&UnboundReason::ExecCoverageGap), None);
    // C7 C4: the scripted row carries a first-sight count, so the
    // bound edge reads `counted`.
    assert!(
        matches!(scene.coverage(), UseCoverage::Counted { .. }),
        "{:?}",
        scene.coverage()
    );
}

/// P1-2: live publication is stamped after refresh+commit: a count that
/// rose during the pass reads RecentlyObserved at its own pass's
/// publication, never Quiet from a presentation clock older than the
/// read. Driven through the actual loop with the production publish
/// timestamp (no artificial presentation time); the read delay separates
/// scan-start from rows-read by milliseconds, deterministically.
#[test]
fn a_rising_count_reads_recently_observed_at_its_own_pass_publication() {
    use crate::inventory_present::{Activity, Presentation};
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Pass 1 witnesses the row (first-sight count 1); pass 2's refresh
    // raises it to 6.
    lane.reads.push_back(vec![RowSpec {
        endpoint: 0,
        tgid: PID,
        ticket: TICKET,
    }]);
    lane.reads.push_back(Vec::new());
    lane.refreshes.push_back(Vec::new());
    lane.refreshes.push_back(vec![CountSpec {
        endpoint: 0,
        ticket: TICKET,
        exec: 1,
        count: 6,
    }]);
    lane.read_delay = Duration::from_millis(2);
    let started_ns = now_ns();
    let pass_log = Rc::clone(&scene.log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = move || {
        pass_log
            .borrow()
            .iter()
            .filter(|entry| *entry == "scan")
            .count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let mut observed: Vec<(u64, Option<u64>, Activity)> = Vec::new();
    run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            if let Publish::Pass { now_ns, .. } = point {
                let presentation = Presentation::capture(
                    &scene.coordinator,
                    "s",
                    started_ns,
                    now_ns,
                    scene.coordinator.passes(),
                );
                let caller = scene.caller(PID);
                let edge = presentation
                    .edges
                    .iter()
                    .find(|edge| edge.caller == caller)
                    .expect("pid 7 has its edge");
                observed.push((now_ns, edge.entry_last_seen_ns, edge.activity));
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(observed.len(), 2, "{observed:?}");
    // Pass 1's row is still horizon-pending at its publication (both
    // horizons must strictly cover the read): no entry last-seen yet.
    assert_eq!(observed[0].1, None, "{:?}", observed[0]);
    // Pass 2 decides the row and stages the rise to 6: production
    // ordering (publication at or after the read) and a rise that reads
    // recently observed at its own publication.
    let (publish_ns, last_seen, activity) = &observed[1];
    let last_seen = last_seen.expect("the decided rise has an entry last-seen");
    assert!(
        *publish_ns >= last_seen,
        "publication {publish_ns} precedes its read {last_seen}"
    );
    assert_eq!(
        *activity,
        Activity::RecentlyObserved,
        "a rise during the pass reads recently observed at its publication"
    );
}

/// Invariant 4.2: the terminal read is staged before the coverage ends, so a
/// watch runs until that read's clean instant (capped at the terminal
/// drain's start), not the pass before.
#[test]
fn a_watch_ends_at_the_terminal_read_staged_before_coverage_ends() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let (stopped, _) = run(&mut scene, lane, 2);
    // Reads: pass 1, pass 2, terminal, last.
    let stamps = stopped.capture.read_stamps.clone();
    assert_eq!(stamps.len(), 4, "{stamps:?}");
    let UseCoverage::WatchedNoUse { since_ns, until_ns } = scene.coverage() else {
        panic!("{:?}", scene.coverage());
    };
    assert!(since_ns < stamps[1], "watched from the attaches on");
    // The terminal read's clean instant, capped at the start of the full
    // lifecycle drain right before it (`lifecycle_proven_ns`): past the
    // pass-2 read, never past the terminal read.
    let until = until_ns.expect("frozen");
    assert!(
        stamps[1] < until && until <= stamps[2],
        "{until} {stamps:?}"
    );
}

/// Invariant 4.6: Finish decides what the last read left waiting (no later
/// lifecycle drain covers it): nothing stays pending, and the row reads
/// `evidence_incomplete`, never bound.
#[test]
fn finish_decides_the_rows_the_last_read_reported() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Pass 1 and the terminal read report nothing; the last read one row.
    lane.reads.extend([
        Vec::new(),
        Vec::new(),
        vec![RowSpec {
            endpoint: 1,
            tgid: PID,
            ticket: TICKET,
        }],
    ]);
    run(&mut scene, lane, 1);
    let census = scene.coordinator.registry().witness_census().clone();
    assert_eq!((census.rows, census.pending), (1, 0), "{census:?}");
    assert_eq!(
        census.unbound.get(&UnboundReason::EvidenceIncomplete),
        Some(&1),
        "{census:?}"
    );
}

/// Invariant 2.3: what an extend deferred is resubmitted ahead of the next
/// delta, so the module is attached on the next pass and then watched.
#[test]
fn deferred_endpoints_are_resubmitted_on_the_next_pass() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.defer_next = 1;
    let (stopped, _) = run(&mut scene, lane, 3);
    let extends: Vec<String> = entries(&log)
        .into_iter()
        .filter(|entry| entry.starts_with("extend["))
        .collect();
    assert_eq!(
        extends,
        ["extend[]", "extend[0,1]", "extend[1]", "extend[]"]
    );
    assert_eq!(stopped.summary.attached, 2);
    assert!(
        matches!(scene.coverage(), UseCoverage::WatchedNoUse { .. }),
        "{:?}",
        scene.coverage()
    );
}

/// Invariant 4.1 (F9): a stop requested before the first pass (a signal
/// during activation) runs zero passes: the host gate latches before any
/// scan, and the owned stop drain still runs.
#[test]
fn a_stop_requested_during_startup_runs_zero_passes() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &|| true,
        now: &Instant::now,
        interval: Duration::from_secs(600),
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let stopped = run_classic(&mut scene, Some(started), &clock, &mut |_, _| Ok(()))
        .unwrap()
        .unwrap();
    assert_eq!(stopped.summary.passes, 0);
    let log = entries(&log);
    assert!(
        !log.iter()
            .any(|entry| entry == "scan" || entry == "collect"),
        "{log:?}"
    );
    assert!(
        log.iter().any(|entry| entry == "end_capture_coverage"),
        "{log:?}"
    );
    assert!(log.iter().any(|entry| entry == "begin_stop"), "{log:?}");
    assert_eq!(scene.coordinator.passes(), 0);
}

/// Invariant 5: retirement past its budget reads unsettled with a gap; the
/// read, Finish and commit still run, and the capture is handed back for a
/// drop after the output.
#[test]
fn a_missed_retirement_budget_reads_unsettled_with_a_gap() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let (stopped, _) = run(&mut scene, lane, 1);
    let Retirement::Unsettled(reason) = &stopped.summary.retirement else {
        panic!("{:?}", stopped.summary.retirement);
    };
    // Two endpoints attached: the 200 ms base and 50 ms for each.
    assert_eq!(stopped.summary.attached, 2);
    assert!(reason.contains("did not detach within 300 ms"), "{reason}");
    assert_eq!(stopped.summary.retirement.label(), "unsettled");
    assert!(
        scene
            .gap_subjects()
            .contains(&"native capture retirement unsettled".to_string()),
        "{:?}",
        scene.gap_subjects()
    );
    let log = entries(&log);
    let tail: Vec<&str> = log.iter().rev().take(5).rev().map(String::as_str).collect();
    assert_eq!(
        tail,
        [
            "stage:witness",
            "stage:finish",
            "gap:native capture retirement unsettled",
            "commit",
            "publish:stop"
        ]
    );
    assert!(!stopped.capture.retired);
}

/// The entries between the retiring notice and the end of coverage: the
/// terminal reads.
fn terminal_reads(log: &[String]) -> Vec<&str> {
    let from = log
        .iter()
        .position(|e| e.starts_with("publish:retiring"))
        .unwrap();
    let to = log
        .iter()
        .position(|e| e == "end_capture_coverage")
        .unwrap();
    log[from + 1..to]
        .iter()
        .map(String::as_str)
        .filter(|e| *e != "service" && *e != "stage:lifecycle")
        .collect()
}

/// C5.2 closure I-1: stop drains the lifecycle ring completely right
/// before the terminal read and forwards each quantum before the coverage
/// ends, so a loss still in the ring is seen before the watch freezes.
#[test]
fn a_stop_drains_the_lifecycle_ring_before_the_terminal_read() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // The pass reads once; then two quanta stop at their record bound.
    lane.undrained_after_reads = Some((1, 2));
    run(&mut scene, lane, 1);
    let log = entries(&log);
    let from = log
        .iter()
        .position(|e| e.starts_with("publish:retiring"))
        .unwrap();
    let to = log
        .iter()
        .position(|e| e == "end_capture_coverage")
        .unwrap();
    assert_eq!(
        log[from + 1..to]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        [
            "service",
            "stage:lifecycle",
            "service",
            "stage:lifecycle",
            "service",
            "stage:lifecycle",
            "read",
            "stage:witness"
        ]
    );
}

/// C5.1 carry (C5.2 review): a bounded terminal read that stops mid-sweep
/// proves no clean instant, so stop keeps reading (each read staged before
/// the coverage ends) until a CALLER_USE sweep completes.
#[test]
fn a_stop_keeps_reading_until_the_terminal_sweep_completes() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Read 1 is the pass's; reads 2 and 3 stop mid-sweep, read 4 completes.
    lane.partial_reads.extend([2, 3]);
    let (stopped, _) = run(&mut scene, lane, 1);
    assert_eq!(
        terminal_reads(&entries(&log)),
        [
            "read",
            "stage:witness",
            "read",
            "stage:witness",
            "read",
            "stage:witness"
        ]
    );
    assert_eq!(stopped.capture.read_stamps.len(), 5);
}

/// 2-C3: the terminal count refresh happens after `begin_stop`: stop keeps
/// reading (each read staged) until a refresh sweep completes without gaps,
/// so every witnessed row's count gets its last word.
#[test]
fn a_stop_refreshes_counts_after_begin_stop_until_exact() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // Read 1 is the pass's; read 2 is the pre-stop terminal sweep; reads 3
    // and 4 (after begin_stop) leave the refresh incomplete and gappy, and
    // read 5 exacts it.
    lane.partial_refresh_reads.extend([3]);
    lane.gappy_refresh_reads.extend([4]);
    let count = |count| CountSpec {
        endpoint: 0,
        ticket: TICKET,
        exec: 1,
        count,
    };
    lane.refreshes
        .extend([vec![], vec![], vec![count(9)], vec![count(12)], vec![]]);
    let (stopped, _) = run(&mut scene, lane, 1);
    assert_eq!(stopped.capture.read_stamps.len(), 5);
    let log = entries(&log);
    let stopped_at = log.iter().position(|entry| entry == "begin_stop").unwrap();
    let after: Vec<&str> = log[stopped_at..]
        .iter()
        .map(String::as_str)
        .filter(|entry| *entry == "read" || *entry == "stage:witness")
        .collect();
    assert_eq!(
        after,
        [
            "read",
            "stage:witness",
            "read",
            "stage:witness",
            "read",
            "stage:witness"
        ]
    );
    assert_eq!(scene.staged_counts, [0, 0, 1, 1, 0]);
}

/// 2-C3: the terminal refresh is bounded: a refresh that never completes
/// stops reading at the budget and the stop goes on.
#[test]
fn a_terminal_refresh_that_never_completes_is_bounded() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // 10 ms reads, partial up to read 300: the 500 ms budget allows ~50.
    lane.partial_refresh_reads.extend(3..=300);
    lane.read_delay = Duration::from_millis(10);
    let (stopped, _) = run(&mut scene, lane, 1);
    let log = entries(&log);
    let stopped_at = log.iter().position(|entry| entry == "begin_stop").unwrap();
    let reads = log[stopped_at..]
        .iter()
        .filter(|entry| *entry == "read")
        .count();
    assert!((1..150).contains(&reads), "{reads}");
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

/// P1-4: when the terminal refresh budget expires without a gap-free
/// sweep, the stop reports the incomplete refresh: witnessed counts
/// keep their last read as a lower bound, never a fresh terminal word.
/// P1-5 terminal-first: the retained count demotes to lossy, so the
/// terminal observation withholds quiet (a scope gap alone would leave
/// the edge loss-free).
#[test]
fn a_terminal_refresh_that_never_completes_is_reported() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.reads.push_back(vec![RowSpec {
        endpoint: 0,
        tgid: PID,
        ticket: TICKET,
    }]);
    lane.partial_refresh_reads.extend(3..=300);
    lane.read_delay = Duration::from_millis(10);
    let _ = run(&mut scene, lane, 1);
    let log = entries(&log);
    assert!(
        log.iter()
            .any(|entry| entry.contains("terminal count refresh incomplete")),
        "the stop reports its incomplete terminal refresh: {log:?}"
    );
    assert!(
        matches!(scene.coverage(), UseCoverage::Counted { lossy: true, .. }),
        "the incomplete terminal refresh demotes the retained count: {:?}",
        scene.coverage()
    );
}

/// The terminal sweep is bounded: a sweep that never completes stops
/// reading at the budget and the stop goes on (its reads are not clean).
#[test]
fn a_terminal_sweep_that_never_completes_is_bounded() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    // 10 ms reads, partial up to read 300: the 500 ms budget allows ~50.
    lane.partial_reads.extend(2..=300);
    lane.read_delay = Duration::from_millis(10);
    let (stopped, _) = run(&mut scene, lane, 1);
    let reads = terminal_reads(&entries(&log)).len() / 2;
    assert!((1..150).contains(&reads), "{reads}");
    assert!(matches!(stopped.summary.retirement, Retirement::Closed(_)));
}

/// Each Singles link pays its own kernel detach (about 73 ms on host 7.0,
/// 68 links in 4.9 s), so the budget grows with the attached endpoints —
/// but the report never waits more than `PRE_OUTPUT_RETIREMENT_WAIT`
/// (R-C51-4); the rest of the detach runs after the report.
#[test]
fn the_retirement_budget_grows_with_the_attached_endpoints_up_to_its_cap() {
    let windows = LaneWindows::PROVISIONAL;
    let singles = |links| RetirementLoad {
        backend: AttachBackend::Singles,
        links,
        endpoints: links,
    };
    assert_eq!(PRE_OUTPUT_RETIREMENT_WAIT, Duration::from_secs(10));
    assert_eq!(
        windows.retirement_budget(singles(0)),
        Duration::from_secs(5)
    );
    assert_eq!(
        windows.retirement_budget(singles(8)),
        Duration::from_millis(6_200)
    );
    assert_eq!(
        windows.retirement_budget(singles(68)),
        PRE_OUTPUT_RETIREMENT_WAIT
    );
    assert_eq!(
        windows.retirement_budget(singles(usize::MAX)),
        PRE_OUTPUT_RETIREMENT_WAIT
    );
}

/// C5.11: Multi's share is per group link plus each member's walk, so a
/// system scope of hundreds of endpoints in a few groups budgets seconds,
/// not the cap; the same endpoints as Singles links reach the cap.
#[test]
fn the_multi_retirement_budget_counts_group_links_and_member_walks() {
    let windows = LaneWindows::PROVISIONAL;
    let multi = RetirementLoad {
        backend: AttachBackend::Multi,
        links: 12,
        endpoints: 400,
    };
    // 5 s + 12 x 100 ms + 400 x 10 ms = 10.2 s, capped.
    assert_eq!(windows.retirement_budget(multi), PRE_OUTPUT_RETIREMENT_WAIT);
    let small = RetirementLoad {
        backend: AttachBackend::Multi,
        links: 3,
        endpoints: 68,
    };
    assert_eq!(
        windows.retirement_budget(small),
        Duration::from_millis(5_000 + 300 + 680)
    );
    let as_singles = RetirementLoad {
        backend: AttachBackend::Singles,
        links: 70,
        endpoints: 68,
    };
    assert_eq!(
        windows.retirement_budget(as_singles),
        PRE_OUTPUT_RETIREMENT_WAIT
    );
}

/// R-C51-4: the report is written first, the immediate exit on a second
/// signal is armed next, and only then does an unsettled retirement's
/// blocking detach run, between two progress lines.
#[test]
fn the_report_is_written_before_the_blocking_detach() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let (stopped, _) = run(&mut scene, lane, 1);
    assert_eq!(stopped.summary.retirement.label(), "unsettled");
    log.borrow_mut().clear();
    let note = |entry: &str| log.borrow_mut().push(entry.to_string());
    let code = finish_native(
        Some(stopped),
        |summary| {
            assert_eq!(summary.unwrap().retirement.label(), "unsettled");
            note("report");
            7
        },
        &|| note("armed"),
        &mut |line| {
            note(if line.contains("detached") {
                "progress:done"
            } else {
                "progress:start"
            })
        },
    );
    assert_eq!(code, 7);
    assert_eq!(
        entries(&log),
        ["report", "armed", "progress:start", "drop", "progress:done"]
    );
}

/// A pass callback failure still gets one bounded native stop and terminal
/// read. Later stop-publication failures cannot replace the first error or
/// drop the unsettled capture before the caller's final sinks.
#[test]
fn failed_pass_publication_retains_native_stop_for_final_sinks() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let mut publications = Vec::new();
    let outcome =
        run_classic_finalizing(&mut scene, Some(started), &clock, None, &mut |_, point| {
            let stage = match point {
                Publish::Pass { .. } => "pass",
                Publish::Retiring { .. } => "retiring",
                Publish::Stop { .. } => "stop",
            };
            publications.push(stage);
            Err(anyhow!("{stage} publication failed"))
        });
    assert_eq!(
        outcome.error.unwrap().to_string(),
        "pass publication failed"
    );
    assert_eq!(publications, ["pass", "retiring", "stop"]);
    let captured = entries(&log);
    assert_eq!(captured.iter().filter(|entry| *entry == "scan").count(), 1);
    assert_eq!(
        captured
            .iter()
            .filter(|entry| *entry == "begin_stop")
            .count(),
        1
    );
    assert!(captured.iter().any(|entry| entry == "stage:finish"));
    assert!(!captured.iter().any(|entry| entry == "drop"));
    let stopped = outcome
        .stopped
        .expect("native ownership survives the error");
    log.borrow_mut().clear();
    finish_native(
        Some(stopped),
        |_| {
            log.borrow_mut().push("report".into());
            log.borrow_mut().push("diagnostics".into());
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    assert_eq!(entries(&log), ["report", "diagnostics", "armed", "drop"]);
}

#[test]
fn failed_pass_application_still_reads_terminal_state_and_keeps_first_error() {
    struct FailedDriver<'a>(&'a mut Scene);
    impl PassDriver<Pin> for FailedDriver<'_> {
        type Host = Scene;
        fn host(&mut self) -> &mut Scene {
            self.0
        }
        fn collector(&mut self) -> CollectJob {
            self.0.collector()
        }
        fn apply(
            &mut self,
            _: CollectedPass,
            _: &mut dyn NativeIdentity<Pin>,
            _: u64,
        ) -> Result<PassReport> {
            self.0.note("apply:failed");
            Err(anyhow!("first application error"))
        }
        fn commit(&mut self, _: bool) -> Result<()> {
            self.0.note("commit:failed");
            Err(anyhow!("later terminal commit error"))
        }
        fn on_tick(&mut self) {}
    }
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let outcome = run_classic_finalizing(
        &mut FailedDriver(&mut scene),
        Some(started),
        &clock,
        None,
        &mut |_, _| Ok(()),
    );
    assert_eq!(
        outcome.error.unwrap().to_string(),
        "first application error"
    );
    assert!(outcome.stopped.is_some());
    let captured = entries(&log);
    assert_eq!(
        captured
            .iter()
            .filter(|entry| *entry == "apply:failed")
            .count(),
        1
    );
    assert_eq!(
        captured
            .iter()
            .filter(|entry| *entry == "commit:failed")
            .count(),
        1
    );
    assert!(captured.iter().any(|entry| entry == "stage:finish"));
    assert!(!captured.iter().any(|entry| entry == "drop"));
}

#[test]
#[should_panic(expected = "stop before any pass after activation")]
fn zero_pass_successful_stop_keeps_the_full_pass_guard() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let started = NativeLane::start(ScriptedLane::new(&log), &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    started.stop(&mut scene);
}

#[test]
fn zero_pass_prologue_failure_still_finishes_terminal_reads() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let started = NativeLane::start(ScriptedLane::new(&log), &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let mut publications = Vec::new();
    let outcome = run_classic_finalizing(
        &mut scene,
        Some(started),
        &clock,
        Some(anyhow!("started append failure")),
        &mut |_, point| {
            publications.push(match point {
                Publish::Retiring { .. } => "retiring",
                Publish::Stop { .. } => "stop",
                Publish::Pass { .. } => "pass",
            });
            Ok(())
        },
    );
    assert_eq!(outcome.error.unwrap().to_string(), "started append failure");
    assert_eq!(publications, ["retiring", "stop"]);
    let stopped = outcome.stopped.unwrap();
    assert_eq!(stopped.summary.passes, 0);
    let captured = entries(&log);
    assert!(
        !captured
            .iter()
            .any(|entry| entry == "collect" || entry == "scan")
    );
    assert!(captured.iter().any(|entry| entry == "stage:finish"));
    assert!(!captured.iter().any(|entry| entry == "drop"));
    log.borrow_mut().clear();
    finish_native(
        Some(stopped),
        |_| log.borrow_mut().push("outputs".into()),
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    assert_eq!(entries(&log), ["outputs", "armed", "drop"]);
}

#[test]
fn failed_output_attempt_arms_escape_before_detach() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let (stopped, _) = run(&mut scene, lane, 1);
    log.borrow_mut().clear();
    let result = finish_native(
        Some(stopped),
        |_| {
            log.borrow_mut().push("output:failed".into());
            Err::<(), _>("sink failed")
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |line| log.borrow_mut().push(line),
    );
    assert_eq!(result, Err("sink failed"));
    let entries = entries(&log);
    assert_eq!(&entries[..2], ["output:failed", "armed"]);
    assert!(
        !entries
            .iter()
            .any(|line| line.contains("report written") || line.contains("report saved")),
        "{entries:?}"
    );
    assert!(entries[2].contains("detaching"));
    assert_eq!(entries[3], "drop");
    assert!(entries[4].contains("detached"));
}

/// Exercise the real native stop publication, then the shared output
/// finalizer: a final-pass append failure retires only its event writer.
#[test]
fn stop_event_failure_keeps_native_cleanup_report_and_stdout() {
    use crate::inventory::{EventLogState, StreamState, emit_stop_events, finish_output};
    use crate::inventory_events::{EventFault, EventWriter, started_payload};
    use crate::inventory_present::Presentation;
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        dir.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let events = dir.path().join("events.jsonl");
    let report = dir.path().join("report.json");
    let mut writer = EventWriter::create(&events, 1 << 20, 2).unwrap();
    let attempts = Rc::new(RefCell::new(Vec::new()));
    writer.fault = Some(EventFault {
        kind: "pass_committed",
        final_pass_only: true,
        after_ended: false,
        attempts: attempts.clone(),
    });
    let now = now_ns();
    let initial = Presentation::capture(&scene.coordinator, "system", now, now, 0);
    writer
        .append("started", started_payload("system", now, &initial), now)
        .unwrap();
    let mut stream = EventLogState::new(Some(writer));
    let mut state = StreamState::new();
    let scans = log.clone();
    let stop = || scans.borrow().iter().any(|entry| entry == "scan");
    let clock = LoopClock {
        deadline: None,
        stop: &stop,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let stopped = run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            if let Publish::Stop { events, now_ns } = point {
                scene.note("publish:stop");
                let view = Presentation::capture(
                    &scene.coordinator,
                    "system",
                    now,
                    now_ns,
                    scene.coordinator.passes(),
                );
                let error = stream.attempt("stop publication", |writer| {
                    emit_stop_events(
                        writer,
                        &mut state,
                        events,
                        scene.coordinator.passes(),
                        &view,
                        now_ns,
                    )
                });
                assert!(error.unwrap().contains("event log stop publication"));
            }
            Ok(())
        },
    )
    .unwrap();
    assert!(stream.first_error().is_some());
    assert!(
        stream
            .attempt("must stay retired", |_| panic!(
                "retired event writer reused"
            ))
            .is_none()
    );
    let view = Presentation::capture(
        &scene.coordinator,
        "system",
        now,
        now_ns(),
        scene.coordinator.passes(),
    );
    let mut stdout = Vec::new();
    let outcome = finish_native(
        stopped,
        |summary| {
            finish_output(
                Some(crate::output::AtomicFile::create(&report).unwrap()),
                &mut stream,
                &mut state,
                &view,
                true,
                false,
                &mut crate::inventory_output::WriterStdout(&mut stdout),
                summary,
                None,
            )
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    assert_eq!(outcome.exit_code(), 1);
    assert_eq!(std::fs::read(report).unwrap(), stdout);
    assert!(log.borrow().iter().any(|entry| entry == "publish:stop"));
    let entries = entries(&log);
    assert!(
        entries.iter().position(|entry| entry == "armed").unwrap()
            < entries.iter().position(|entry| entry == "drop").unwrap()
    );
    assert_eq!(
        attempts
            .borrow()
            .iter()
            .filter(|kind| *kind == "pass_committed")
            .count(),
        1
    );
    assert!(!attempts.borrow().iter().any(|kind| kind == "ended"));
}

/// A closed retirement has nothing left to detach: no progress lines.
#[test]
fn a_closed_retirement_reports_without_a_detach_phase() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let (stopped, _) = run(&mut scene, lane, 1);
    log.borrow_mut().clear();
    let note = |entry: &str| log.borrow_mut().push(entry.to_string());
    finish_native(
        Some(stopped),
        |_| note("report"),
        &|| note("armed"),
        &mut |_| note("progress"),
    );
    assert_eq!(entries(&log), ["report", "armed", "drop"]);
}

/// The child half of the second-signal test: inert unless its parent sets
/// the environment.
#[test]
fn stop_flag_child_exits_on_the_armed_signal() {
    if std::env::var_os("P11SCOPE_STOPFLAG_CHILD").is_none() {
        return;
    }
    let flag = crate::inventory_dashboard::StopFlag::install();
    // SAFETY: raising a signal whose handler is installed.
    unsafe { libc::raise(libc::SIGINT) };
    // Positive control: before arming, a signal only requests the stop.
    assert!(flag.stopped());
    println!("FIRST_SIGNAL_STOPPED");
    flag.exit_on_next_signal();
    // SAFETY: as above.
    unsafe { libc::raise(libc::SIGTERM) };
    println!("SURVIVED_SECOND_SIGNAL");
    std::process::exit(0);
}

/// R-C51-4: once the report is written, a second SIGINT/SIGTERM ends the
/// process at once (128 + signal), whatever the drop is still doing.
#[test]
fn after_the_report_a_second_signal_exits_at_once() {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "inventory_capture::tests::stop_flag_child_exits_on_the_armed_signal",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("P11SCOPE_STOPFLAG_CHILD", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("FIRST_SIGNAL_STOPPED"), "{stdout}");
    assert!(!stdout.contains("SURVIVED_SECOND_SIGNAL"), "{stdout}");
    assert_eq!(
        output.status.code(),
        Some(128 + libc::SIGTERM),
        "{output:?}"
    );
}

/// The actual generic loop and finalizer consume the same Retiring action as
/// the production classic/dashboard callbacks. A delivery inside that action
/// must not be absorbed by a boundary captured after native stop returns.
fn native_output_boundary_control(
    dashboard: bool,
    key_stop: bool,
    before: usize,
    during: bool,
    with_sinks: bool,
) {
    use crate::inventory::{
        EventLogState, StreamState, begin_scan_stdout, finish_output, retiring_stdout,
    };
    use crate::inventory_output::{FdStdout, FinalStdout, StdoutResult};
    use std::cell::Cell;
    use std::os::fd::AsRawFd;
    struct Recorded<'a> {
        inner: FdStdout<'a>,
        log: Log,
        sinks: Option<(std::path::PathBuf, std::path::PathBuf)>,
    }
    impl FinalStdout for Recorded<'_> {
        fn begin_finalization(&mut self) {
            self.log.borrow_mut().push("stdout:begin".into());
            self.inner.begin_finalization();
        }
        fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
            self.log.borrow_mut().push("stdout:attempt".into());
            if let Some((report, events)) = &self.sinks {
                assert_eq!(
                    std::fs::read(report).unwrap(),
                    bytes,
                    "requested report was not committed before stdout cancellation/acquisition"
                );
                assert!(
                    std::fs::read_to_string(events)
                        .unwrap()
                        .lines()
                        .any(
                            |line| serde_json::from_str::<serde_json::Value>(line).unwrap()["kind"]
                                == "ended"
                        ),
                    "requested event completion was not attempted before stdout"
                );
            }
            self.inner.write_document(bytes)
        }
    }
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.retire_after = None;
    let lane = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let delivered = Cell::new(0);
    let key = Cell::new(false);
    let stop = || delivered.get() > 0 || key.get();
    let clock = LoopClock {
        deadline: (!key_stop && before == 0).then(Instant::now),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let file = tempfile::NamedTempFile::new().unwrap();
    let count = || delivered.get();
    let sinks = tempfile::tempdir().unwrap();
    std::fs::set_permissions(
        sinks.path(),
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let report = sinks.path().join("report.json");
    let events = sinks.path().join("events.jsonl");
    let mut stdout = Recorded {
        inner: FdStdout::new(file.as_raw_fd(), &count),
        log: log.clone(),
        sinks: with_sinks.then(|| (report.clone(), events.clone())),
    };
    let stopped = run_classic(
        &mut scene,
        Some(lane),
        &clock,
        &mut |scene: &mut Scene, point| {
            match point {
                Publish::Pass { .. } => {
                    delivered.set(before);
                    key.set(key_stop);
                    scene.note("publish:pass");
                }
                Publish::Retiring { .. } => {
                    scene.note("publish:retiring");
                    retiring_stdout(&mut stdout, || {
                        scene.note(if dashboard {
                            "restore"
                        } else {
                            "classic-notice"
                        });
                        if during {
                            delivered.set(1);
                            scene.note("delivery:acknowledged-1");
                        }
                    });
                }
                Publish::Stop { .. } => {
                    scene.note("publish:stop");
                    assert_eq!(delivered.get(), if during { 1 } else { before });
                }
            }
            Ok(())
        },
    )
    .unwrap();
    begin_scan_stdout(&mut stdout, stopped.is_some());
    let now = now_ns();
    let view =
        crate::inventory_present::Presentation::capture(&scene.coordinator, "system", now, now, 1);
    let sink = with_sinks.then(|| crate::output::AtomicFile::create(&report).unwrap());
    let writer = with_sinks
        .then(|| crate::inventory_events::EventWriter::create(&events, 1 << 20, 2).unwrap());
    let outcome = finish_native(
        stopped,
        |summary| {
            let outcome = finish_output(
                sink,
                &mut EventLogState::new(writer),
                &mut StreamState::new(),
                &view,
                true,
                false,
                &mut stdout,
                summary,
                None,
            );
            log.borrow_mut().push("output:result".into());
            outcome
        },
        &|| log.borrow_mut().push("armed".into()),
        &mut |_| {},
    );
    let cancelled = during || before == 2;
    assert_eq!(
        outcome.exit_code(),
        i32::from(cancelled),
        "{outcome:?}; {:?}",
        entries(&log)
    );
    assert_eq!(outcome.stdout_cancelled(), cancelled, "{outcome:?}");
    let bytes = std::fs::read(file.path()).unwrap();
    if cancelled {
        assert!(
            bytes.is_empty(),
            "cancelled output accepted a late document"
        );
    } else {
        let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(document["observation"]["lane"], "native");
    }
    let entries = entries(&log);
    let at = |name| entries.iter().position(|entry| entry == name).unwrap();
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.as_str() == "stdout:begin")
            .count(),
        1
    );
    assert!(
        at("stdout:begin")
            < at(if dashboard {
                "restore"
            } else {
                "classic-notice"
            })
    );
    assert!(at("stdout:begin") < at("begin_stop"));
    assert!(at("begin_stop") < at("publish:stop"));
    assert!(at("publish:stop") < at("stdout:attempt"));
    assert!(at("output:result") < at("armed") && at("armed") < at("drop"));
}

#[test]
fn native_signal_during_retiring_cancels_stdout() {
    for dashboard in [false, true] {
        for key in [false, true] {
            native_output_boundary_control(dashboard, key, 0, true, false);
        }
    }
}

#[test]
fn native_first_capture_stop_signal_preserves_stdout() {
    for dashboard in [false, true] {
        native_output_boundary_control(dashboard, false, 1, false, false);
    }
}

#[test]
fn native_second_delivery_before_retiring_cancels_stdout() {
    for dashboard in [false, true] {
        native_output_boundary_control(dashboard, false, 2, false, false);
    }
}

#[test]
fn native_retiring_signal_preserves_requested_event_and_report() {
    for dashboard in [false, true] {
        for key in [false, true] {
            native_output_boundary_control(dashboard, key, 0, true, true);
        }
        native_output_boundary_control(dashboard, false, 1, false, true);
    }
}

#[test]
fn stop_flag_counts_distinct_deliveries_child() {
    if std::env::var_os("P11SCOPE_COUNT_CHILD").is_none() {
        return;
    }
    let flag = crate::inventory_dashboard::StopFlag::install();
    assert_eq!(flag.signal_count(), 0);
    for (signal, expected) in [(libc::SIGINT, 1), (libc::SIGTERM, 2), (libc::SIGHUP, 2)] {
        unsafe {
            libc::raise(signal);
        }
        assert_eq!(
            flag.signal_count(),
            expected,
            "delivered-handler count lost a distinct signal"
        );
        assert!(flag.stopped());
    }
}

#[test]
fn distinct_stop_deliveries_saturate_without_arming_force_exit() {
    struct Owned(std::process::Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut child = Owned(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inventory_capture::tests::stop_flag_counts_distinct_deliveries_child",
                "--nocapture",
            ])
            .env("P11SCOPE_COUNT_CHILD", "1")
            .spawn()
            .unwrap(),
    );
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            panic!("owned signal-count child watchdog");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success(), "delivered-count child failed: {status}");
}

/// The auto fallback seam: a refused activation hands the capture back and
/// the coordinator forgets the coverage, so the run is the scan lane again.
#[test]
fn a_refused_activation_hands_back_the_capture_and_forgets_coverage() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.refuse_activation = true;
    let Err((mut lane, reason)) = NativeLane::start(lane, &mut scene, windows(), None) else {
        panic!("a refused activation must not start the lane");
    };
    assert!(reason.contains("scripted activation refusal"), "{reason}");
    assert_eq!(
        entries(&log),
        [
            "begin_capture_coverage",
            "extend[]",
            "abandon_capture_coverage"
        ]
    );
    retire_refused(&mut lane, Duration::from_millis(50));
    assert!(lane.retired);
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    run_classic(&mut scene, none, &clock, &mut |_, _| Ok(())).unwrap();
    assert_eq!(
        scene.coverage(),
        UseCoverage::Unknown(UnknownReason::ScanOnly)
    );
}

/// The scan lane runs the same loop with no native call at all.
#[test]
fn the_scan_lane_makes_no_native_call() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let clock = LoopClock {
        deadline: None,
        stop: &|| false,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    let stopped = run_classic(&mut scene, none, &clock, &mut |scene: &mut Scene, _| {
        scene.note("publish");
        Ok(())
    })
    .unwrap();
    assert!(stopped.is_none());
    assert_eq!(entries(&log), ["collect", "scan", "commit", "publish"]);
}

/// Invariant 3: between passes each tick drains one discovery quantum and
/// stages it at once.
#[test]
fn ticks_between_passes_stage_each_discovery_quantum() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::from_millis(40),
        tick: Duration::from_millis(5),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, _| {
            scene.note("publish:pass");
            Ok(())
        },
    )
    .unwrap();
    let log = entries(&log);
    let first = log
        .iter()
        .position(|entry| entry == "publish:pass")
        .unwrap();
    let second = log.iter().rposition(|entry| entry == "collect").unwrap();
    let between = &log[first + 1..second];
    assert!(between.len() >= 4, "{between:?}");
    for pair in between.chunks(2) {
        assert_eq!(pair, ["service", "stage:lifecycle"], "{between:?}");
    }
}

/// C5.3: the dashboard draws on the loop's own service ticks, each after
/// the lane's quantum is staged, so the native lane runs under the
/// dashboard exactly as on the classic path: the passes and the stop keep
/// the contract order, and every tick still services the ring first.
#[test]
fn the_display_ticks_after_each_lane_service_without_reordering_it() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    // Completed passes stop after publication (F9): counting scans
    // would fire during the second apply and skip its extension.
    let publishes = {
        let log = Rc::clone(&log);
        move || {
            log.borrow()
                .iter()
                .filter(|entry| *entry == "publish:pass")
                .count()
        }
    };
    let stop = move || publishes() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::from_millis(40),
        tick: Duration::from_millis(5),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(
        &mut scene,
        Some(started),
        &clock,
        &mut |scene: &mut Scene, point| {
            match point {
                Publish::Pass { .. } => scene.note("publish:pass"),
                Publish::Retiring {
                    attached, budget, ..
                } => scene.note(format!(
                    "publish:retiring {attached} {}",
                    budget.as_millis()
                )),
                Publish::Stop { .. } => scene.note("publish:stop"),
            }
            Ok(())
        },
    )
    .unwrap();
    let log = entries(&log);
    let first = log
        .iter()
        .position(|entry| entry == "publish:pass")
        .unwrap();
    let second = log.iter().rposition(|entry| entry == "scan").unwrap();
    // A pass's collection entry (C5.7) belongs to the pass, not the ticks.
    let between: Vec<&str> = log[first + 1..second]
        .iter()
        .map(String::as_str)
        .filter(|entry| *entry != "collect")
        .collect();
    assert!(between.len() >= 6, "{between:?}");
    for tick in between.chunks(3) {
        assert_eq!(
            tick,
            ["service", "stage:lifecycle", "display"],
            "{between:?}"
        );
    }
    // Without the display's entries the run is the classic contract order.
    let classic: Vec<String> = log
        .iter()
        .filter(|entry| !matches!(entry.as_str(), "display" | "service" | "stage:lifecycle"))
        .cloned()
        .collect();
    let mut expected: Vec<String> = STARTUP.map(String::from).to_vec();
    for extend in ["extend[0,1]", "extend[]"] {
        expected.extend(pass(extend));
    }
    expected.extend(STOP.map(String::from));
    expected.push("drop".into());
    expected.retain(|entry| !matches!(entry.as_str(), "service" | "stage:lifecycle"));
    assert_eq!(classic, expected);
    // The stop never draws: the display is given back before it.
    let retiring = log
        .iter()
        .position(|entry| entry.starts_with("publish:retiring"))
        .unwrap();
    assert!(!log[retiring..].iter().any(|entry| entry == "display"));
}

/// The scan lane's dashboard still draws on every tick.
#[test]
fn the_display_ticks_in_the_scan_lane_too() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::from_millis(30),
        tick: Duration::from_millis(5),
        collection_tick: NO_COLLECTION_TICK,
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    run_classic(&mut scene, none, &clock, &mut |scene: &mut Scene, _| {
        scene.note("publish");
        Ok(())
    })
    .unwrap();
    let log = entries(&log);
    let first = log.iter().position(|entry| entry == "publish").unwrap();
    let second = log.iter().rposition(|entry| entry == "scan").unwrap();
    // A pass's collection entry (C5.7) belongs to the pass, not the ticks.
    let between: Vec<&str> = log[first + 1..second]
        .iter()
        .map(String::as_str)
        .filter(|entry| *entry != "collect")
        .collect();
    assert!(between.len() >= 2, "{log:?}");
    assert!(between.iter().all(|entry| *entry == "display"), "{log:?}");
}

/// C5.3 with C5.7: while a pass collects, each collection tick services the
/// lifecycle ring first and only then lets the dashboard draw.
#[test]
fn the_ring_is_serviced_before_the_display_while_a_pass_collects() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    let mut lane = ScriptedLane::new(&log);
    let (serviced, gate) = mpsc::channel();
    lane.serviced = Some(serviced);
    scene.collect_gate = Some((gate, 3));
    run_ticking(&mut scene, lane, 1, Duration::from_millis(1));
    let log = entries(&log);
    let collect = log.iter().position(|entry| entry == "collect").unwrap();
    let scan = log.iter().position(|entry| entry == "scan").unwrap();
    let during = &log[collect + 1..scan];
    assert!(during.len() >= 6, "{log:?}");
    for tick in during.chunks(2) {
        assert_eq!(tick, ["service", "display"], "{log:?}");
    }
}

#[test]
fn native_jobs_share_the_retained_owner_between_ring_and_display() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    scene.native_service_ticks = true;
    let mut lane = ScriptedLane::new(&log);
    let (serviced, gate) = mpsc::channel();
    lane.serviced = Some(serviced);
    scene.collect_gate = Some((gate, 3));
    run_ticking(&mut scene, lane, 1, Duration::from_millis(1));
    let log = entries(&log);
    let collect = log.iter().position(|entry| entry == "collect").unwrap();
    let scan = log.iter().position(|entry| entry == "scan").unwrap();
    let during = &log[collect + 1..scan];
    assert!(
        during.len() >= 9,
        "the gated real collection must service three times: {log:?}"
    );
    for tick in during.chunks(3) {
        assert_eq!(tick, ["service", "native-service", "display"], "{log:?}");
    }
    let retiring = log
        .iter()
        .position(|entry| entry.starts_with("publish:retiring"))
        .unwrap();
    assert!(
        !log[retiring..]
            .iter()
            .any(|entry| entry == "native-service")
    );
}

#[test]
fn native_jobs_receive_explicit_unavailability_in_scan_ticks() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.display_ticks = true;
    scene.native_service_ticks = true;
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::from_millis(30),
        tick: Duration::from_millis(5),
        collection_tick: NO_COLLECTION_TICK,
    };
    let none: Option<NativeLane<ScriptedLane>> = None;
    run_classic(&mut scene, none, &clock, &mut |scene: &mut Scene, _| {
        scene.note("publish");
        Ok(())
    })
    .unwrap();
    let log = entries(&log);
    let first = log.iter().position(|entry| entry == "publish").unwrap();
    let second = log.iter().rposition(|entry| entry == "scan").unwrap();
    let between: Vec<&str> = log[first + 1..second]
        .iter()
        .map(String::as_str)
        .filter(|entry| *entry != "collect")
        .collect();
    assert!(between.len() >= 4, "{log:?}");
    for tick in between.chunks(2) {
        assert_eq!(tick, ["native-unavailable", "display"], "{log:?}");
    }
    assert!(!log.iter().any(|entry| entry == "native-service"));
}

/// C5.3: the tick schedule is fixed-rate: a tick's own work (the draw after
/// the ring's service) does not move the next tick later, and a tick that
/// overran a whole period makes the next one due at once.
#[test]
fn a_tick_schedule_keeps_its_rate_through_the_work_of_a_tick() {
    let start = Instant::now();
    let period = Duration::from_millis(10);
    let mut schedule = TickSchedule::starting(start, period);
    assert_eq!(schedule.wait(start), period);
    // The tick due at 10 ms ran until 13 ms: the next is due at 20 ms.
    schedule.advance(start + Duration::from_millis(13));
    assert_eq!(
        schedule.wait(start + Duration::from_millis(13)),
        Duration::from_millis(7)
    );
    // The tick due at 20 ms ran until 45 ms: the next is due at once.
    schedule.advance(start + Duration::from_millis(45));
    assert_eq!(
        schedule.wait(start + Duration::from_millis(45)),
        Duration::ZERO
    );
    // And the one after keeps the period from there.
    schedule.advance(start + Duration::from_millis(46));
    assert_eq!(
        schedule.wait(start + Duration::from_millis(46)),
        Duration::from_millis(9)
    );
}

/// C5.3: a slow draw inside each collection tick (15 ms of a 20 ms tick)
/// does not slow the ring's service cadence: over a 400 ms collection the
/// ring is serviced about every 20 ms (about 19 times), not every 35 ms
/// (about 11 times) as a schedule restarted after each tick's work would.
#[test]
fn a_slow_draw_never_delays_the_ring_service_while_a_pass_collects() {
    let mut starts = Vec::new();
    collect_off_thread(
        || std::thread::sleep(Duration::from_millis(400)),
        Duration::from_millis(20),
        &mut || {
            starts.push(Instant::now());
            // The draw that follows the ring's service.
            std::thread::sleep(Duration::from_millis(15));
        },
    );
    // Judge the typical spacing between services, not the count: a loaded
    // host can oversleep any single tick, but only a schedule restarted
    // after each tick's work spaces services by the period plus the draw
    // (about 35 ms) as a rule. The fixed-rate schedule keeps about 20 ms.
    assert!(
        starts.len() >= 5,
        "the ring was serviced {} times",
        starts.len()
    );
    let mut gaps: Vec<Duration> = starts.windows(2).map(|w| w[1] - w[0]).collect();
    gaps.sort();
    let median = gaps[gaps.len() / 2];
    assert!(
        median < Duration::from_millis(30),
        "median service spacing {median:?} over {} services",
        starts.len()
    );
}

/// Ruling D1: a run whose watches cannot be proven (a foreign PID
/// namespace) marks coverage unproven from activation on: witnesses still
/// bind, but no edge ever reads watched.
#[test]
fn a_lossy_start_never_claims_a_watch() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let started = NativeLane::start(
        lane,
        &mut scene,
        windows(),
        Some("scripted foreign pid namespace".into()),
    )
    .map_err(|(_, reason)| reason)
    .unwrap();
    let scans = {
        let log = Rc::clone(&log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= 2;
    let clock = LoopClock {
        deadline: Some(Instant::now() + Duration::from_secs(600)),
        stop: &stop,
        now: &Instant::now,
        interval: Duration::ZERO,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(&mut scene, Some(started), &clock, &mut |_, _| Ok(())).unwrap();
    assert!(
        matches!(
            scene.coverage(),
            UseCoverage::Unknown(UnknownReason::Loss(ref reason))
                if reason.contains("scripted foreign pid namespace")
        ),
        "{:?}",
        scene.coverage()
    );
    assert!(entries(&log).contains(&"note_capture_custody".to_string()));
}

/// The native lane's uncovered reason: an edge no coverage note reached (its
/// first projection fell in a pass whose health was unproven) reads
/// `not_attached`, never `scan_only`.
#[test]
fn an_edge_no_coverage_note_reached_reads_not_attached_in_the_native_lane() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    scene.source.spawn(8, 800);
    scene.joiner = Some((8, 800, 2));
    let mut lane = ScriptedLane::new(&log);
    lane.unproven_reads = 1;
    run(&mut scene, lane, 2);
    assert_eq!(
        scene.coverage_of(8),
        UseCoverage::Unknown(UnknownReason::NotAttached)
    );
}

/// C5.7 (ruling D8), the threading boundary: the pass's collection runs on
/// a worker while the loop services the lifecycle ring. The gated
/// collection cannot finish until the ring was serviced three times while
/// it ran (servicing only between passes fails it). Nothing is staged
/// while it runs; the held quanta stage after the scan applied and the
/// extend receipt, ahead of the pass's own quantum, and every quantum ever
/// drained stages exactly once, in drain order.
#[test]
fn the_ring_is_serviced_while_a_pass_collects_and_staged_after_its_scan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    let (serviced, gate) = mpsc::channel();
    lane.serviced = Some(serviced);
    scene.collect_gate = Some((gate, 3));
    let drained = Rc::clone(&lane.service_stamps);
    run_ticking(&mut scene, lane, 1, Duration::from_millis(1));
    let log = entries(&log);
    let collect = log.iter().position(|entry| entry == "collect").unwrap();
    let scan = log.iter().position(|entry| entry == "scan").unwrap();
    let during = &log[collect + 1..scan];
    assert!(during.len() >= 3, "{log:?}");
    assert!(during.iter().all(|entry| entry == "service"), "{log:?}");
    let after_scan = &log[scan..];
    let mut expected: Vec<String> = [
        "scan",
        "take_target_delta",
        "extend[0,1]",
        "note_extend_receipt",
    ]
    .map(String::from)
    .to_vec();
    expected.extend(std::iter::repeat_n(
        "stage:lifecycle".to_string(),
        during.len(),
    ));
    expected.extend(["service", "stage:lifecycle", "read"].map(String::from));
    assert_eq!(
        &after_scan[..expected.len()],
        expected.as_slice(),
        "{log:?}"
    );
    assert_eq!(scene.staged_lifecycle, *drained.borrow());
}

/// C5.7: collection ticks hold at most `held_records` drained records, a
/// strict bound: each quantum is capped at the room left, and past the
/// bound they drain nothing (the ring keeps the rest, and the kernel counts
/// what it cannot hold). The held quanta stage with the pass, which frees
/// the bound.
#[test]
fn collection_ticks_hold_at_most_the_record_bound() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.records_per_service = 2;
    let windows = LaneWindows {
        held_records: 3,
        ..windows()
    };
    let mut started = NativeLane::start(lane, &mut scene, windows, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    for _ in 0..5 {
        started.collecting_tick();
        assert!(started.held_records <= 3, "{}", started.held_records);
    }
    let services = |log: &Log| {
        log.borrow()
            .iter()
            .filter(|entry| *entry == "service")
            .count()
    };
    // Two records, then the one record of room left, then nothing.
    assert_eq!(services(&log), 2);
    assert_eq!(started.held_records, 3);
    assert!(!entries(&log).contains(&"stage:lifecycle".to_string()));
    started.after_pass(&mut scene);
    assert_eq!(scene.staged_lifecycle.len(), 3, "two held, one serviced");
    // Staging frees the bound.
    started.collecting_tick();
    assert_eq!(services(&log), 4);
}

/// C5.7 (Sol F4): a quiet capture's slow collection cannot grow the held
/// batches without bound. Empty quanta charge zero records but each batch
/// shell costs memory, so past the batch bound the ticks drain nothing
/// (the ring keeps the rest) — otherwise every 10 ms tick would add one
/// more batch shell for the whole collection.
#[test]
fn quiet_collection_holds_at_most_the_batch_bound() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    // `records_per_service` stays 0: a quiet capture drains empty quanta.
    let lane = ScriptedLane::new(&log);
    let mut started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let bound = windows().held_batches;
    for _ in 0..20_000 {
        started.collecting_tick();
        assert!(
            started.held.len() <= bound,
            "quiet collection holds {} batches",
            started.held.len()
        );
    }
    assert_eq!(
        LaneWindows::PROVISIONAL.held_batches,
        16_384,
        "the shell budget pins the default"
    );
}

/// C5.7 (Sol F4): the batch bound engages like the record bound — past
/// it the ticks drain nothing (the ring keeps the rest, and the kernel
/// counts what it cannot hold) — and staging with the pass frees it.
#[test]
fn collection_ticks_hold_at_most_the_batch_bound() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let lane = ScriptedLane::new(&log);
    let windows = LaneWindows {
        held_batches: 3,
        ..windows()
    };
    let mut started = NativeLane::start(lane, &mut scene, windows, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    for _ in 0..5 {
        started.collecting_tick();
        assert!(started.held.len() <= 3, "{}", started.held.len());
    }
    let services = |log: &Log| {
        log.borrow()
            .iter()
            .filter(|entry| *entry == "service")
            .count()
    };
    // Three empty quanta, then nothing: the ring keeps the rest.
    assert_eq!(services(&log), 3);
    assert_eq!(started.held.len(), 3);
    assert_eq!(started.held_records, 0, "empty quanta charge zero records");
    assert!(!entries(&log).contains(&"stage:lifecycle".to_string()));
    started.after_pass(&mut scene);
    assert_eq!(scene.staged_lifecycle.len(), 4, "three held, one serviced");
    // Staging frees the bound.
    started.collecting_tick();
    assert_eq!(services(&log), 5);
}

/// C5.7: one collection tick drains quantum after quantum while each stops
/// at its record bound (the ring still holds more), until the held bound
/// stops it; the last quantum takes only the room left.
#[test]
fn a_collection_tick_drains_full_quanta_until_the_held_bound() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.records_per_service = 1000;
    let windows = LaneWindows {
        held_records: 600,
        ..windows()
    };
    let mut started = NativeLane::start(lane, &mut scene, windows, None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    started.collecting_tick();
    // 256 + 256 + the 88 records of room left.
    let services = entries(&log)
        .iter()
        .filter(|entry| *entry == "service")
        .count();
    assert_eq!(services, 3);
    assert_eq!((started.held_records, started.tally.records), (600, 600));
}

/// C5.7 (review M-1): collection-time drains are counted like any other:
/// their records, a failed quantum (which also grants a recovery rescan),
/// and they stage with the pass. `observation.lifecycle` is public, so
/// each field is pinned.
#[test]
fn collection_time_drains_are_counted_and_a_failed_one_grants_a_rescan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.records_per_service = 3;
    lane.failed_services = HashSet::from([2]);
    let mut started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    // Service 1 drains 3 records; service 2 fails (its 3 records still
    // count as dequeued) and ends the tick; service 3 drains 3 more.
    started.collecting_tick();
    started.collecting_tick();
    started.collecting_tick();
    assert_eq!(
        started.tally,
        LifecycleTally {
            records: 9,
            failed_quanta: 1,
            ..LifecycleTally::default()
        }
    );
    assert!(started.take_recovery_rescan(), "a failed quantum is a loss");
    started.after_pass(&mut scene);
    assert_eq!(scene.staged_lifecycle.len(), 4, "three held, one serviced");
}

/// FB-R5 (review M-1): a malformed-record rise is a loss: counted, and it
/// grants a recovery rescan; an unchanged count grants nothing.
#[test]
fn a_malformed_record_rise_is_counted_and_grants_a_rescan() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.malformed = VecDeque::from([0, 2, 2]);
    let mut started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    started.after_pass(&mut scene);
    assert!(!started.take_recovery_rescan());
    started.after_pass(&mut scene);
    assert_eq!(started.tally.malformed, 2);
    assert!(started.take_recovery_rescan());
    started.after_pass(&mut scene);
    assert!(
        !started.take_recovery_rescan(),
        "no rescan follows a rescan"
    );
    started.after_pass(&mut scene);
    assert!(!started.take_recovery_rescan(), "no new loss, no new grant");
    assert_eq!(started.tally.malformed, 2);
}

/// Runs the scripted lane under `clock`; the stop is `stop_after` scans.
fn run_clocked(
    scene: &mut Scene,
    lane: ScriptedLane,
    stop_after: usize,
    interval: Duration,
    deadline: Duration,
) -> Stopped<ScriptedLane> {
    let started = NativeLane::start(lane, scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let scans = {
        let log = Rc::clone(&scene.log);
        move || log.borrow().iter().filter(|entry| *entry == "scan").count()
    };
    let stop = move || scans() >= stop_after;
    let clock = LoopClock {
        deadline: Some(Instant::now() + deadline),
        stop: &stop,
        now: &Instant::now,
        interval,
        tick: Duration::from_millis(1),
        collection_tick: NO_COLLECTION_TICK,
    };
    run_classic(scene, Some(started), &clock, &mut |_, _| Ok(()))
        .unwrap()
        .unwrap()
}

/// FB-R5: a lifecycle loss starts the next pass at once (a recovery
/// rescan) instead of waiting out the interval; the tally counts the loss
/// and the rescan. Without the rescan the hour-long interval holds the
/// second pass past the deadline.
#[test]
fn a_lifecycle_loss_starts_the_next_pass_at_once() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([4]);
    let stopped = run_clocked(
        &mut scene,
        lane,
        2,
        Duration::from_secs(3600),
        Duration::from_secs(3),
    );
    assert_eq!(stopped.summary.passes, 2);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (4, 1),
        "{tally:?}"
    );
    // Every quantum the lane drained is counted (none carried records).
    assert_eq!(tally.records, 0);
}

/// FB-R5 (review M-1 N1): one loss grants one rescan for the whole run; a
/// steady loss count never re-arms it, so later passes keep the interval.
#[test]
fn one_loss_grants_one_recovery_rescan_for_the_run() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([4]);
    let stopped = run_clocked(
        &mut scene,
        lane,
        5,
        Duration::ZERO,
        Duration::from_secs(600),
    );
    assert_eq!(stopped.summary.passes, 5);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (4, 1),
        "{tally:?}"
    );
}

/// Review L-2: `recovery_rescans` counts passes that started; a rescan
/// granted just before the stop never ran and is not counted.
#[test]
fn a_rescan_granted_before_the_stop_is_not_counted() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([4]);
    let stopped = run_clocked(
        &mut scene,
        lane,
        1,
        Duration::from_secs(3600),
        Duration::from_secs(600),
    );
    assert_eq!(stopped.summary.passes, 1);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (4, 0),
        "{tally:?}"
    );
}

/// FB-R5, the bound: a recovery rescan is never followed by another, so a
/// host that loses records on every pass rescans early at most every
/// second pass; a later loss after a normal pass is granted again.
#[test]
fn recovery_rescans_never_follow_each_other() {
    let log = Log::default();
    let mut scene = Scene::new(&log);
    let mut lane = ScriptedLane::new(&log);
    lane.ring_loss = VecDeque::from([1, 2, 3, 4, 5]);
    lane.records_per_service = 2;
    let mut started = NativeLane::start(lane, &mut scene, windows(), None)
        .map_err(|(_, reason)| reason)
        .unwrap();
    let mut granted = Vec::new();
    for _ in 0..5 {
        started.after_pass(&mut scene);
        let grant = started.take_recovery_rescan();
        if grant {
            started.begin_recovery_rescan();
        }
        granted.push(grant);
    }
    assert_eq!(granted, [true, false, true, false, true]);
    let stopped = started.stop(&mut scene);
    let tally = stopped.summary.lifecycle;
    assert_eq!(
        (tally.ring_loss, tally.recovery_rescans),
        (5, 3),
        "{tally:?}"
    );
    let services = entries(&log)
        .iter()
        .filter(|entry| *entry == "service")
        .count() as u64;
    assert_eq!(tally.records, 2 * services);
    assert_eq!((tally.malformed, tally.failed_quanta), (0, 0));
}

/// C5.7: a worker that panics resumes its panic on the loop's thread
/// (never a silent empty pass), and its value otherwise crosses back.
#[test]
fn the_collection_worker_hands_back_its_value_or_its_panic() {
    let mut ticks = 0;
    assert_eq!(
        collect_off_thread(|| 7, Duration::from_millis(1), &mut || ticks += 1),
        7
    );
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        collect_off_thread(
            || -> u32 { panic!("scripted collection panic") },
            Duration::from_millis(1),
            &mut || {},
        )
    }))
    .unwrap_err();
    assert_eq!(
        panic.downcast_ref::<&str>().copied(),
        Some("scripted collection panic")
    );
}

// ---- C5.11: backend selection and disclosure --------------------------------

mod cgroup_backend_selection {
    use super::*;
    use crate::inventory_capture::{MultiScopeProbe, prepare_scoped_on_backend};
    use std::sync::Arc;

    #[test]
    fn cgroup_multi_retry_uses_general_probe_and_the_same_retained_root() {
        let tree = tempfile::tempdir().unwrap();
        let selected = tree.path().join("selected");
        std::fs::create_dir(&selected).unwrap();
        let saved = crate::scope::cgroup(&selected).unwrap();
        let crate::attach::Scope::Cgroup { dir: original, .. } = &saved else {
            unreachable!()
        };
        let original = Arc::clone(original);
        let scope = CaptureScope::cgroup(saved).unwrap();
        let tried = RefCell::new(Vec::new());
        let probes = RefCell::new(Vec::new());
        let (prepared, chosen) = prepare_scoped_on_backend(
            BackendSelection::Auto,
            &scope,
            |probe| {
                probes.borrow_mut().push(probe);
                assert_eq!(probe, MultiScopeProbe::General);
                Ok(())
            },
            |attempt, backend| {
                let CaptureScope::Cgroup(cgroup) = attempt else {
                    panic!("scope changed")
                };
                assert!(Arc::ptr_eq(&original, cgroup.root()));
                tried.borrow_mut().push(backend);
                if backend == AttachBackend::Multi {
                    std::fs::rename(&selected, tree.path().join("held-original")).unwrap();
                    std::fs::create_dir(&selected).unwrap();
                    return Err(anyhow!("scripted Multi refusal"));
                }
                Ok(cgroup)
            },
        )
        .unwrap();
        assert_eq!(probes.into_inner(), [MultiScopeProbe::General]);
        assert_eq!(
            tried.into_inner(),
            [AttachBackend::Multi, AttachBackend::Singles]
        );
        assert!(Arc::ptr_eq(&original, prepared.root()));
        assert_eq!(chosen.scope_filter.label(), Some("bpf-cgroup"));
        assert_eq!(chosen.backend, AttachBackend::Singles);
    }

    #[test]
    fn cgroup_singles_does_not_probe_and_keeps_cgroup_filter() {
        let tree = tempfile::tempdir().unwrap();
        let scope = CaptureScope::cgroup(crate::scope::cgroup(tree.path()).unwrap()).unwrap();
        let (_, chosen) = prepare_scoped_on_backend(
            BackendSelection::Singles,
            &scope,
            |_| panic!("Singles must not probe"),
            |attempt, backend| {
                assert_eq!(backend, AttachBackend::Singles);
                assert_eq!(attempt.scope_coverage(), CaptureScopeCoverage::Cgroup);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(chosen.scope_filter, ScopeFilter::BpfCgroup);
    }

    #[test]
    fn cgroup_forced_multi_never_tries_singles_after_refusal() {
        let tree = tempfile::tempdir().unwrap();
        let scope = CaptureScope::cgroup(crate::scope::cgroup(tree.path()).unwrap()).unwrap();
        let tried = RefCell::new(Vec::new());
        let outcome = prepare_scoped_on_backend(
            BackendSelection::Multi,
            &scope,
            |probe| {
                assert_eq!(probe, MultiScopeProbe::General);
                Ok(())
            },
            |attempt, backend| {
                assert_eq!(attempt.scope_coverage(), CaptureScopeCoverage::Cgroup);
                tried.borrow_mut().push(backend);
                Err::<(), _>(anyhow!("scripted forced refusal"))
            },
        );
        assert!(outcome.is_err());
        assert_eq!(tried.into_inner(), [AttachBackend::Multi]);
    }
}

mod backend_selection {
    use crate::attach::{AttachBackend, BackendSelection};
    use crate::inventory_capture::{LaneBackend, prepare_on_backend};
    use anyhow::anyhow;
    use std::cell::RefCell;

    /// Runs the resolution with a scripted probe and preparation, and
    /// returns the outcome plus every backend a preparation was tried on.
    fn resolve(
        selection: BackendSelection,
        probe: Result<(), &str>,
        multi_prepares: bool,
    ) -> (anyhow::Result<LaneBackend>, Vec<AttachBackend>, bool) {
        let tried = RefCell::new(Vec::new());
        let probed = RefCell::new(false);
        let outcome = prepare_on_backend(
            selection,
            || {
                *probed.borrow_mut() = true;
                probe.map_err(String::from)
            },
            |backend| {
                tried.borrow_mut().push(backend);
                if backend == AttachBackend::Multi && !multi_prepares {
                    return Err(anyhow!("multi load refused"));
                }
                Ok(backend)
            },
        )
        .map(|(prepared, chosen)| {
            assert_eq!(
                prepared, chosen.backend,
                "the prepared backend is disclosed"
            );
            chosen
        });
        (outcome, tried.into_inner(), probed.into_inner())
    }

    #[test]
    fn auto_on_a_multi_kernel_attaches_multi_after_a_linking_probe() {
        let (chosen, tried, probed) = resolve(BackendSelection::Auto, Ok(()), true);
        let chosen = chosen.unwrap();
        assert_eq!(chosen.backend, AttachBackend::Multi);
        assert_eq!(chosen.mechanism(), "uprobe-multi");
        assert_eq!(chosen.selection_label(), "auto");
        assert_eq!(chosen.fallback, None);
        assert!(probed);
        assert_eq!(
            tried,
            [AttachBackend::Multi],
            "no Singles object was loaded"
        );
    }

    #[test]
    fn auto_falls_back_to_singles_for_the_whole_capture_when_the_probe_fails() {
        let (chosen, tried, _) = resolve(BackendSelection::Auto, Err("EOPNOTSUPP"), true);
        let chosen = chosen.unwrap();
        assert_eq!(chosen.backend, AttachBackend::Singles);
        assert_eq!(chosen.mechanism(), "per-offset");
        assert!(
            chosen
                .fallback
                .as_deref()
                .is_some_and(|reason| reason.contains("functional probe failed: EOPNOTSUPP")),
            "{chosen:?}"
        );
        assert_eq!(tried, [AttachBackend::Singles], "Multi was never loaded");
    }

    #[test]
    fn auto_retries_a_failed_multi_preparation_once_on_singles() {
        let (chosen, tried, _) = resolve(BackendSelection::Auto, Ok(()), false);
        let chosen = chosen.unwrap();
        assert_eq!(chosen.backend, AttachBackend::Singles);
        assert!(
            chosen
                .fallback
                .as_deref()
                .is_some_and(|reason| reason.contains("multi load refused"))
        );
        assert_eq!(tried, [AttachBackend::Multi, AttachBackend::Singles]);
    }

    /// The owner directive: a capability probe, never the kernel version,
    /// decides; `auto` always asks the probe.
    #[test]
    fn auto_always_asks_the_probe_whatever_the_kernel_version() {
        let (_, _, probed) = resolve(BackendSelection::Auto, Ok(()), true);
        assert!(probed);
        let (chosen, tried, probed) = resolve(BackendSelection::Auto, Err("EINVAL"), true);
        assert!(probed);
        assert_eq!(chosen.unwrap().backend, AttachBackend::Singles);
        assert_eq!(tried, [AttachBackend::Singles]);
    }

    #[test]
    fn forced_multi_surfaces_the_refusal_and_never_falls_back() {
        let (chosen, tried, _) = resolve(BackendSelection::Multi, Err("ENOSYS"), true);
        let error = chosen.unwrap_err();
        assert!(
            format!("{error:#}").contains("--attach-backend multi") && tried.is_empty(),
            "{error:#} {tried:?}"
        );
        let (chosen, tried, _) = resolve(BackendSelection::Multi, Ok(()), false);
        assert!(chosen.is_err());
        assert_eq!(
            tried,
            [AttachBackend::Multi],
            "forced Multi never tries Singles"
        );
        let (chosen, _, _) = resolve(BackendSelection::Multi, Ok(()), true);
        assert_eq!(chosen.unwrap().backend, AttachBackend::Multi);
    }

    #[test]
    fn forced_singles_never_probes() {
        let (chosen, tried, probed) = resolve(BackendSelection::Singles, Ok(()), true);
        assert_eq!(chosen.unwrap().backend, AttachBackend::Singles);
        assert!(!probed);
        assert_eq!(tried, [AttachBackend::Singles]);
    }

    /// The security review's rule at the facade: a PID-scoped Multi
    /// capture needs the proven kernel pid filter. Unprivileged, the probe
    /// cannot run, so the refusal names the filter before anything loads.
    #[test]
    fn a_pid_scoped_multi_capture_needs_the_proven_kernel_pid_filter() {
        use crate::attach::capture::{CaptureScope, InventoryCapture, caller_budget};
        if crate::attach::kernel_multi_pid_filter().is_ok() {
            return; // privileged on a fixed kernel: the privileged cells cover it
        }
        let budget = crate::capacity::InventoryBudget::new(4, 32).unwrap();
        let pin = crate::process::PidPin::open(std::process::id()).unwrap();
        let error = InventoryCapture::prepare(
            CaptureScope::Pid(pin),
            budget,
            caller_budget(budget, 2).unwrap(),
            AttachBackend::Multi,
        )
        .err()
        .expect("a PID-scoped Multi capture was prepared without the pid filter");
        assert!(
            format!("{error:#}").contains("kernel pid filter"),
            "{error:#}"
        );
    }
}

/// Sol P2 residual: a scan-only zero-pass stop streams its diagnostic
/// gap under a terminal `final` marker, so the consumer's
/// AGREE-GAP-ACCOUNTING check (`sum(pass_committed.new_gaps)` equals the
/// streamed `gap_recorded` count) passes through the real finalizer: the
/// real loop, a real coordinator, the real per-commit emitters and the
/// real `finish_output` — not a unit seam.
mod scan_terminal_accounting_tests {
    use super::*;
    use crate::inventory::{
        EventLogState, StreamState, emit_pass_events, emit_stop_events, finish_output,
        start_event_log,
    };
    use crate::inventory_events::EventWriter;
    use crate::inventory_output::{FinalStdout, StdoutResult};
    use crate::inventory_present::Presentation;

    const SCOPE: &str = "s";

    struct DiscardStdout;
    impl FinalStdout for DiscardStdout {
        fn begin_finalization(&mut self) {}
        fn write_document(&mut self, bytes: &[u8]) -> StdoutResult {
            Ok(bytes.len())
        }
    }

    /// The production classic stream wiring (minus stderr progress
    /// lines): the real prologue, the real per-commit emitters on
    /// publication, the real `finish_output`.
    struct StreamRun {
        _dir: tempfile::TempDir,
        path: PathBuf,
        stream: EventLogState,
        state: StreamState,
        started_ns: u64,
    }

    impl StreamRun {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("events.jsonl");
            let writer = EventWriter::create(&path, 1 << 20, 5).unwrap();
            Self {
                _dir: dir,
                path,
                stream: EventLogState::new(Some(writer)),
                state: StreamState::new(),
                started_ns: now_ns(),
            }
        }

        fn publish(&mut self, scene: &mut Scene, point: Publish<'_>) {
            let started_ns = self.started_ns;
            let error = match point {
                Publish::Pass { report, now_ns } => {
                    self.stream.attempt("pass publication", |writer| {
                        let presentation = Presentation::capture(
                            &scene.coordinator,
                            SCOPE,
                            started_ns,
                            now_ns,
                            scene.coordinator.passes(),
                        );
                        emit_pass_events(writer, &mut self.state, report, &presentation, now_ns)
                    })
                }
                Publish::Retiring { .. } => None,
                Publish::Stop { events, now_ns } => {
                    self.stream.attempt("stop publication", |writer| {
                        let presentation = Presentation::capture(
                            &scene.coordinator,
                            SCOPE,
                            started_ns,
                            now_ns,
                            scene.coordinator.passes(),
                        );
                        emit_stop_events(
                            writer,
                            &mut self.state,
                            events,
                            scene.coordinator.passes(),
                            &presentation,
                            now_ns,
                        )
                    })
                }
            };
            assert!(error.is_none(), "publication streams: {error:?}");
        }

        fn finish(mut self, scene: &mut Scene) -> Vec<serde_json::Value> {
            let ended_ns = now_ns();
            let presentation = Presentation::capture(
                &scene.coordinator,
                SCOPE,
                self.started_ns,
                ended_ns,
                scene.coordinator.passes(),
            );
            let outcome = finish_output(
                None,
                &mut self.stream,
                &mut self.state,
                &presentation,
                false,
                true,
                &mut DiscardStdout,
                None,
                None,
            );
            assert!(
                outcome.failures().is_empty(),
                "final sinks confirm: {:?}",
                outcome.failures()
            );
            assert_eq!(outcome.event_log_confirmed(), Some(true));
            std::fs::read_to_string(&self.path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect()
        }
    }

    fn kinds(lines: &[serde_json::Value]) -> Vec<&str> {
        lines
            .iter()
            .map(|line| line["kind"].as_str().unwrap())
            .collect()
    }

    /// The consumer's AGREE-GAP-ACCOUNTING check verbatim: the markers'
    /// `new_gaps` sums to the streamed `gap_recorded` count.
    fn assert_gap_accounting(lines: &[serde_json::Value]) {
        let streamed = lines
            .iter()
            .filter(|line| line["kind"] == "gap_recorded")
            .count() as u64;
        let accounted: u64 = lines
            .iter()
            .filter(|line| line["kind"] == "pass_committed")
            .map(|line| line["event"]["new_gaps"].as_u64().unwrap())
            .sum();
        assert_eq!(
            accounted, streamed,
            "new_gaps sums to the streamed gaps: {lines:?}"
        );
    }

    fn scan_clock(stop: &dyn Fn() -> bool) -> LoopClock<'_> {
        LoopClock {
            deadline: None,
            stop,
            now: &Instant::now,
            interval: Duration::ZERO,
            tick: Duration::from_millis(1),
            collection_tick: NO_COLLECTION_TICK,
        }
    }

    #[test]
    fn scan_only_zero_pass_stop_streams_its_gap_under_a_terminal_marker() {
        let log = Log::default();
        let mut scene = Scene::new(&log);
        let mut run = StreamRun::new();
        let initial_error =
            start_event_log(&mut run.stream, &scene.coordinator, SCOPE, run.started_ns);
        assert!(initial_error.is_none());
        // A pre-requested stop: the zero-pass shape with no timing.
        let stop = || true;
        let clock = scan_clock(&stop);
        let outcome = run_classic_finalizing(
            &mut scene,
            None::<NativeLane<ScriptedLane>>,
            &clock,
            initial_error,
            &mut |scene, point| {
                run.publish(scene, point);
                Ok(())
            },
        );
        assert!(outcome.error.is_none(), "exit 0 is preserved");
        assert!(outcome.stopped.is_none());
        assert!(outcome.zero_pass.is_some(), "a zero-pass stop is reported");
        let lines = run.finish(&mut scene);
        let kinds = kinds(&lines);
        assert_eq!(kinds.first(), Some(&"started"));
        assert_eq!(kinds.last(), Some(&"ended"));
        let gaps: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|line| line["kind"] == "gap_recorded")
            .collect();
        assert_eq!(gaps.len(), 1, "{lines:?}");
        assert_eq!(gaps[0]["event"]["subject"], ZERO_PASS_GAP_SUBJECT);
        let markers: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|line| line["kind"] == "pass_committed")
            .collect();
        assert_eq!(markers.len(), 1, "{lines:?}");
        let marker = &markers[0]["event"];
        assert_eq!(marker["final"], true, "terminal, not a scan pass");
        assert_eq!(marker["pass"], 0);
        assert_eq!(marker["scanned"], 0, "no completed pass is claimed");
        assert_eq!(marker["new_gaps"], 1);
        assert_eq!(
            marker["totals"],
            serde_json::json!({"callers": 0, "modules": 0, "edges": 0}),
            "nothing was admitted: {marker}"
        );
        assert_gap_accounting(&lines);
    }

    #[test]
    fn scan_snapshot_streams_its_pass_without_a_terminal_marker() {
        // The healthy twin: an in-budget scan pass streams under its own
        // pass marker, with no diagnostic gap and no terminal marker.
        let log = Log::default();
        let mut scene = Scene::new(&log);
        let mut run = StreamRun::new();
        let initial_error =
            start_event_log(&mut run.stream, &scene.coordinator, SCOPE, run.started_ns);
        assert!(initial_error.is_none());
        let stop = || false;
        let clock = scan_clock(&stop);
        let outcome = run_classic_finalizing(
            &mut scene,
            None::<NativeLane<ScriptedLane>>,
            &clock,
            initial_error,
            &mut |scene, point| {
                run.publish(scene, point);
                Ok(())
            },
        );
        assert!(outcome.error.is_none());
        assert!(outcome.zero_pass.is_none(), "no zero-pass stop happened");
        let lines = run.finish(&mut scene);
        let markers: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|line| line["kind"] == "pass_committed")
            .collect();
        assert_eq!(markers.len(), 1, "{lines:?}");
        assert!(
            markers[0]["event"].get("final").is_none(),
            "a scan pass carries no terminal flag: {}",
            markers[0]["event"]
        );
        assert!(
            !lines.iter().any(|line| line["kind"] == "gap_recorded"
                && line["event"]["subject"] == ZERO_PASS_GAP_SUBJECT),
            "no diagnostic gap fires in budget: {lines:?}"
        );
        assert_gap_accounting(&lines);
    }

    #[test]
    fn native_zero_pass_stop_streams_its_gap_under_a_terminal_marker() {
        // The native control: the pre-existing terminal path already
        // accounts the diagnostic gap; the same harness proves it.
        let log = Log::default();
        let mut scene = Scene::new(&log);
        let lane = ScriptedLane::new(&log);
        let started = NativeLane::start(lane, &mut scene, windows(), None)
            .map_err(|(_, reason)| reason)
            .unwrap();
        let mut run = StreamRun::new();
        let initial_error =
            start_event_log(&mut run.stream, &scene.coordinator, SCOPE, run.started_ns);
        assert!(initial_error.is_none());
        let stop = || true;
        let clock = scan_clock(&stop);
        let outcome = run_classic_finalizing(
            &mut scene,
            Some(started),
            &clock,
            initial_error,
            &mut |scene, point| {
                run.publish(scene, point);
                Ok(())
            },
        );
        assert!(outcome.error.is_none(), "exit 0 is preserved");
        assert!(outcome.stopped.is_some(), "the owned stop still drains");
        assert!(outcome.zero_pass.is_some(), "a zero-pass stop is reported");
        let lines = run.finish(&mut scene);
        let gaps: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|line| line["kind"] == "gap_recorded")
            .collect();
        assert!(
            gaps.iter()
                .any(|gap| gap["event"]["subject"] == ZERO_PASS_GAP_SUBJECT),
            "the diagnostic gap streams: {lines:?}"
        );
        let markers: Vec<&serde_json::Value> = lines
            .iter()
            .filter(|line| line["kind"] == "pass_committed")
            .collect();
        assert_eq!(markers.len(), 1, "{lines:?}");
        assert_eq!(markers[0]["event"]["final"], true);
        assert_gap_accounting(&lines);
    }
}

mod promotion_baseline_lane_tests {
    //! DR37 baseline acquisition through the lane trait: lanes without
    //! the inventory baseline program refuse honestly through the
    //! default, and the facade refuses outside Active. Both through
    //! `&mut dyn`, exactly as the scheduler calls them.
    use super::*;

    fn presented_frame() -> std::sync::Arc<crate::inventory_present::Presentation> {
        let mut harness = Harness::new(RegistryLimits::default_limits()).unwrap();
        harness.stage_scale(&ScaleSpec {
            name: "baseline-lane",
            callers: 1,
            modules: 1,
            edges_per_caller: 1,
            endpoints_per_module: 1,
            first_pid: 90_000,
        });
        harness.commit();
        std::sync::Arc::new(crate::inventory_present::Presentation::capture(
            harness.coordinator(),
            "pid",
            1,
            2,
            1,
        ))
    }

    fn window() -> ReadWindow {
        ReadWindow::new(1, Instant::now() + Duration::from_secs(1)).unwrap()
    }

    #[test]
    fn scripted_lane_refuses_promotion_baselines_through_dyn() {
        let (mut lane, _) = cgroup_runtime_lane();
        let lane: &mut dyn CaptureLane<crate::process::PidPin> = &mut lane;
        let error = lane
            .query_promotion_baselines(
                crate::inventory_promotion::CaptureId::new(7),
                presented_frame(),
                &[],
                window(),
                &mut |_| unreachable!("a refusing lane reserves nothing"),
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("unavailable"),
            "honest refusal: {error:#}"
        );
    }

    #[test]
    fn facade_lane_outside_active_refuses_promotion_baselines() {
        let mut facade = FacadeLane {
            domain: NativeDomainId::mint(),
            scope_coverage: CaptureScopeCoverage::System,
            backend: LaneBackend::singles(),
            state: FacadeState::Moving,
        };
        let lane: &mut dyn CaptureLane<crate::process::PidPin> = &mut facade;
        let error = lane
            .query_promotion_baselines(
                crate::inventory_promotion::CaptureId::new(7),
                presented_frame(),
                &[],
                window(),
                &mut |_| unreachable!("a refusing lane reserves nothing"),
            )
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("unavailable"),
            "honest refusal: {error:#}"
        );
    }
}

/// Exercise the production loop, real native-lane staging and coordinator;
/// only publication readiness and the scoped completion callback are scripted.
/// These controls supply no actual Joint or installed cgroup qualification.
mod publication_progress_tests {
    use super::*;
    use std::cell::Cell;

    fn live_native(run: &RetainedClassicRun<ScriptedLane>) -> &NativeLane<ScriptedLane> {
        match run.native.as_ref().expect("the original native owner") {
            RetainedNative::Live(lane) => lane,
            RetainedNative::Stopping(_) | RetainedNative::Stopped(_) => {
                panic!("the running loop cannot start terminal I/O")
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Poll {
        Pending,
        Published,
        Fail,
    }

    struct Driver {
        scene: Scene,
        control: Option<CollectionControl>,
        pending: bool,
        pending_on_collect: bool,
        pending_on_tick: Option<usize>,
        polls: VecDeque<Poll>,
        changes: Vec<bool>,
        stop: Rc<Cell<bool>>,
        stop_after_poll: Option<usize>,
        stop_after_tick: Option<usize>,
        stop_in_apply: bool,
        fail_finish: bool,
        stop_on_emission: bool,
        interval: Duration,
        collected_ptr: usize,
        report_ptr: usize,
        report_changed: bool,
        applies: usize,
        finishes: usize,
        emissions: usize,
        ticks: usize,
        native_domains: Vec<NativeDomainId>,
        host_stops: usize,
        suspended: usize,
        legacy_commits: usize,
        legacy_stops: usize,
        lane_stops: usize,
    }

    impl Driver {
        fn new(log: &Log, scoped: bool, polls: &[Poll]) -> Self {
            Self {
                scene: Scene::new(log),
                control: scoped.then(|| CollectionControl::new(None)),
                pending: false,
                pending_on_collect: false,
                pending_on_tick: None,
                polls: polls.iter().copied().collect(),
                changes: Vec::new(),
                stop: Rc::default(),
                stop_after_poll: None,
                stop_after_tick: None,
                stop_in_apply: false,
                fail_finish: false,
                stop_on_emission: true,
                interval: Duration::ZERO,
                collected_ptr: 0,
                report_ptr: 0,
                report_changed: false,
                applies: 0,
                finishes: 0,
                emissions: 0,
                ticks: 0,
                native_domains: Vec::new(),
                host_stops: 0,
                suspended: 0,
                legacy_commits: 0,
                legacy_stops: 0,
                lane_stops: 0,
            }
        }

        fn assert_retained(&self, outcome: &ClassicOutcome<ScriptedLane>) {
            assert!(outcome.stopped.is_none());
            assert!(outcome.zero_pass.is_none());
            let retained = outcome.retained.as_ref().expect("the same run is retained");
            assert_eq!(retained.discarded_collections, 0);
            assert!(retained.host_stopped);
            assert_eq!(self.host_stops, 1, "the F9 gate remains once-only");
            assert_eq!(self.suspended, 1);
            assert_eq!(self.legacy_stops, 0, "no fresh semantic terminal sequence");
            assert_eq!(self.legacy_commits, 0, "no legacy terminal publication");
            let completed = retained.completed_passes as usize;
            assert_eq!(self.emissions, completed);
            let lane = live_native(retained);
            assert!(!lane.capture.stopping, "no new terminal drain");
            assert!(!entries(&self.scene.log).iter().any(|line| line == "drop"));
            match &retained.pass {
                RetainedPass::BeforeCollection => {
                    assert_eq!(self.scene.scans, completed, "no next collector launched");
                    assert_eq!(self.applies, completed, "no next report was created");
                }
                RetainedPass::Collected {
                    collected,
                    scan_now_ns,
                } => {
                    assert!(*scan_now_ns > 0);
                    let CollectedPass::Legacy(Ok(catalog)) = collected else {
                        panic!("the original catalog must remain owned");
                    };
                    assert_eq!(catalog.processes.as_ptr() as usize, self.collected_ptr);
                    assert_eq!(self.scene.scans, completed + 1);
                    assert_eq!(self.applies, completed);
                }
                RetainedPass::Applied { report, .. } => {
                    assert_eq!(report.pending_refresh.as_ptr() as usize, self.report_ptr);
                    assert_eq!(self.scene.scans, completed + 1);
                    assert_eq!(self.applies, completed + 1);
                }
                RetainedPass::Terminal { .. } => {
                    panic!("the running loop must retain the original pass")
                }
            }
        }
    }

    impl LaneHost<Pin> for Driver {
        fn begin_capture_coverage(&mut self, scope: CaptureScopeCoverage) {
            self.scene.begin_capture_coverage(scope);
        }
        fn abandon_capture_coverage(&mut self) {
            self.scene.abandon_capture_coverage();
        }
        fn note_extend_receipt(&mut self, receipt: &ExtendReceipt) {
            self.scene.note_extend_receipt(receipt);
        }
        fn note_capture_custody(&mut self, custody: &ScopeCustody) {
            self.scene.note_capture_custody(custody);
        }
        fn take_target_delta(&mut self) -> TargetDelta {
            self.scene.take_target_delta()
        }
        fn capture_targets(&self) -> &dyn CaptureTargets {
            self.scene.capture_targets()
        }
        fn stage_native(
            &mut self,
            batch: NativeBatch,
            identity: &mut dyn NativeIdentity<Pin>,
            now_ns: u64,
        ) -> NativeReceipt {
            self.scene.stage_native(batch, identity, now_ns)
        }
        fn end_capture_coverage(&mut self, at_ns: u64) {
            self.scene.end_capture_coverage(at_ns);
        }
        fn note_native_lane(&mut self) {
            self.scene.note_native_lane();
        }
        fn note_scope_gap(&mut self, subject: String, reason: String) {
            self.scene.note_scope_gap(subject, reason);
        }
        fn note_refresh_loss(&mut self, reason: String) {
            self.scene.note_refresh_loss(reason);
        }
        fn stop_coordinator(&mut self) {
            self.host_stops += 1;
            self.scene.coordinator.stop();
        }
    }

    impl PassDriver<Pin> for Driver {
        type Host = Self;
        fn host(&mut self) -> &mut Self {
            self
        }
        fn collector(&mut self) -> CollectJob {
            self.scene.scans += 1;
            self.scene.note("collect");
            if self.pending_on_collect {
                self.pending = true;
            }
            let catalog = self.scene.catalog();
            self.collected_ptr = catalog.processes.as_ptr() as usize;
            CollectJob::Legacy(Box::new(move || Ok(catalog)))
        }
        fn collection_control(&self) -> Option<CollectionControl> {
            self.control.clone()
        }
        fn apply(
            &mut self,
            collected: CollectedPass,
            identity: &mut dyn NativeIdentity<Pin>,
            now_ns: u64,
        ) -> Result<PassReport> {
            let CollectedPass::Legacy(Ok(catalog)) = &collected else {
                panic!("the loop must apply its original successful collection");
            };
            assert_eq!(catalog.processes.as_ptr() as usize, self.collected_ptr);
            self.applies += 1;
            let mut report = self.scene.apply(collected, identity, now_ns)?;
            report.pending_refresh = vec![self.scene.caller(PID)];
            self.report_ptr = report.pending_refresh.as_ptr() as usize;
            self.report_changed = report.engine_changed;
            if self.stop_in_apply {
                self.stop.set(true);
            }
            Ok(report)
        }
        fn commit(&mut self, changed: bool) -> Result<()> {
            self.legacy_commits += 1;
            self.scene.commit(changed)
        }
        fn poll_commit(&mut self, changed: bool) -> Result<PassCommitProgress> {
            self.changes.push(changed);
            if self.stop_after_poll == Some(self.changes.len()) {
                self.stop.set(true);
            }
            match self.polls.pop_front().unwrap_or(Poll::Published) {
                Poll::Pending => {
                    self.scene.note("poll:pending");
                    self.pending = true;
                    Ok(PassCommitProgress::Pending)
                }
                Poll::Published => {
                    self.scene.note("poll:published");
                    self.pending = false;
                    self.scene.commit(changed)?;
                    Ok(PassCommitProgress::Published)
                }
                Poll::Fail => {
                    // A failure flag is no ownership or completion oracle.
                    self.pending = false;
                    Err(anyhow!("original publication failure"))
                }
            }
        }
        fn publication_pending(&self) -> bool {
            self.pending
        }
        fn finish_pass(&mut self, report: &mut PassReport) -> Result<()> {
            self.scene.note("finish");
            self.finishes += 1;
            assert_eq!(report.pending_refresh.as_ptr() as usize, self.report_ptr);
            report.scan_callers = 73;
            report.events.push(CallerEvent::Exited {
                id: self.scene.caller(PID),
                reason: "controlled scoped completion".into(),
            });
            if self.fail_finish {
                anyhow::bail!("completion failed after mutating the original report");
            }
            Ok(())
        }
        fn on_native_service(&mut self, capture: Option<&mut dyn CaptureLane<Pin>>) {
            self.scene.note("native-service");
            if let Some(capture) = capture {
                self.native_domains.push(capture.domain());
            }
        }
        fn on_tick(&mut self) {
            self.scene.note("tick");
            self.ticks += 1;
            if self.pending_on_tick == Some(self.ticks) {
                self.pending = true;
            }
            if self.stop_after_tick == Some(self.ticks) {
                self.stop.set(true);
            }
        }
        fn on_publication_suspended(&mut self) {
            self.suspended += 1;
        }
        fn on_stop_requested(&mut self) {
            self.legacy_stops += 1;
        }
        fn on_lane_stopped(&mut self) {
            self.lane_stops += 1;
        }
    }

    fn drive(
        driver: &mut Driver,
        lane: ScriptedLane,
        windows: LaneWindows,
    ) -> ClassicOutcome<ScriptedLane> {
        drive_initial(driver, lane, windows, None)
    }

    fn drive_initial(
        driver: &mut Driver,
        lane: ScriptedLane,
        windows: LaneWindows,
        initial_error: Option<anyhow::Error>,
    ) -> ClassicOutcome<ScriptedLane> {
        let started = NativeLane::start(lane, driver, windows, None)
            .map_err(|(_, reason)| reason)
            .unwrap();
        let stop = Rc::clone(&driver.stop);
        let stop = || stop.get();
        let clock = LoopClock {
            deadline: Some(Instant::now() + GATE_TIMEOUT),
            stop: &stop,
            now: &Instant::now,
            interval: driver.interval,
            tick: Duration::from_millis(1),
            collection_tick: NO_COLLECTION_TICK,
        };
        run_classic_finalizing(
            driver,
            Some(started),
            &clock,
            initial_error,
            &mut |driver, point| {
                if let Publish::Pass { report, .. } = point {
                    assert_eq!(report.pending_refresh.as_ptr() as usize, driver.report_ptr);
                    if driver.control.is_some() {
                        assert_eq!(
                            report.scan_callers, 73,
                            "emit the completed original report"
                        );
                        assert_eq!(
                        report.events.iter().filter(|event| matches!(event,
                            CallerEvent::Exited { reason, .. } if reason == "controlled scoped completion"
                        )).count(),
                        1,
                        "emit the scoped completion event once"
                    );
                    }
                    driver.scene.note("emit");
                    driver.emissions += 1;
                    if driver.stop_on_emission {
                        driver.stop.set(true);
                    }
                }
                Ok(())
            },
        )
    }

    #[test]
    fn pending_before_apply_preserves_the_original_collection() {
        let log = Log::default();
        let mut driver = Driver::new(
            &log,
            false,
            &[Poll::Pending, Poll::Published, Poll::Published],
        );
        driver.pending_on_collect = true;
        let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
        assert!(outcome.error.is_none(), "{outcome:?}");
        assert!(outcome.retained.is_none());
        assert_eq!(
            (driver.scene.scans, driver.applies, driver.emissions),
            (1, 1, 1)
        );
        let ClassicCompletion::Finalized {
            stopped,
            error,
            zero_pass,
        } = outcome.into_completion().unwrap()
        else {
            panic!("the completed original run must finalize");
        };
        assert!(stopped.is_some() && error.is_none() && zero_pass.is_none());
        assert_eq!(driver.changes, [false, false, driver.report_changed]);
        assert_eq!(driver.ticks, 1);
        let log = entries(&log);
        assert!(
            log.iter()
                .position(|line| line == "poll:published")
                .unwrap()
                < log.iter().position(|line| line == "scan").unwrap()
        );
    }

    #[test]
    fn both_scoped_commit_polls_finish_and_emit_once() {
        let log = Log::default();
        let mut driver = Driver::new(
            &log,
            true,
            &[
                Poll::Pending,
                Poll::Published,
                Poll::Pending,
                Poll::Published,
            ],
        );
        let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
        assert!(outcome.error.is_none(), "{outcome:?}");
        assert!(outcome.retained.is_none());
        assert_eq!(
            (
                driver.scene.scans,
                driver.applies,
                driver.finishes,
                driver.emissions
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(driver.changes, [driver.report_changed, false, false, false]);
        assert_eq!(outcome.stopped.unwrap().summary.passes, 1);
        let log = entries(&log);
        let published: Vec<usize> = log
            .iter()
            .enumerate()
            .filter_map(|(i, line)| (line == "poll:published").then_some(i))
            .collect();
        let finish = log.iter().position(|line| line == "finish").unwrap();
        let extend = log.iter().position(|line| line == "extend[0,1]").unwrap();
        let emit = log.iter().position(|line| line == "emit").unwrap();
        assert_eq!(
            log.iter()
                .filter(|line| line.starts_with("extend["))
                .count(),
            2
        );
        assert!(
            published[0] < finish
                && finish < extend
                && extend < published[1]
                && published[1] < emit,
            "{log:?}"
        );
    }

    #[test]
    fn pending_service_keeps_the_same_native_owner_and_hold_bounds() {
        let log = Log::default();
        let mut driver = Driver::new(&log, false, &[Poll::Pending; 4]);
        driver.stop_after_tick = Some(3);
        let mut lane = ScriptedLane::new(&log);
        let domain = lane.domain;
        lane.records_per_service = 1;
        let windows = LaneWindows {
            discovery_records: 1,
            pass_quanta: 1,
            held_records: 3,
            held_batches: 2,
            ..windows()
        };
        let outcome = drive(&mut driver, lane, windows);
        driver.assert_retained(&outcome);
        assert_eq!(driver.ticks, 3);
        assert_eq!(driver.native_domains, [domain; 3]);
        let held = live_native(outcome.retained.as_ref().unwrap());
        assert_eq!((held.held.len(), held.held_records), (2, 2));
        assert_eq!(
            held.capture.services, 3,
            "one pass quantum and two held quanta"
        );
        let log = entries(&log);
        assert_eq!(
            log.iter().filter(|line| *line == "stage:lifecycle").count(),
            1,
            "pending service holds new inputs: {log:?}"
        );
        for (i, line) in log
            .iter()
            .enumerate()
            .filter(|(_, line)| *line == "native-service")
        {
            assert_eq!(
                log[i + 1],
                "tick",
                "service precedes each display tick: {line}"
            );
        }
    }

    #[test]
    fn pending_cancellation_returns_original_collection_or_report() {
        for (before_apply, scoped, stop_in_apply, polls, phase) in [
            (true, true, false, vec![Poll::Pending], None),
            (
                false,
                false,
                false,
                vec![Poll::Pending],
                Some(AppliedPassPhase::FirstCommit),
            ),
            (
                false,
                false,
                true,
                vec![Poll::Pending],
                Some(AppliedPassPhase::FirstCommit),
            ),
            (
                false,
                true,
                false,
                vec![Poll::Published, Poll::Pending],
                Some(AppliedPassPhase::ScopedReceipts),
            ),
        ] {
            let log = Log::default();
            let mut driver = Driver::new(&log, scoped, &polls);
            driver.pending_on_collect = before_apply;
            driver.stop_in_apply = stop_in_apply;
            driver.stop_after_poll = Some(polls.len());
            let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
            driver.assert_retained(&outcome);
            assert!(outcome.error.is_none(), "{outcome:?}");
            let retained = outcome.retained.as_ref().unwrap();
            assert_eq!(retained.stop_cause, Some(ZeroPassCause::OperatorStop));
            assert!(retained.elapsed < GATE_TIMEOUT);
            if scoped {
                assert!(retained.control.as_ref().unwrap().check().is_err());
            }
            match (&retained.pass, phase) {
                (RetainedPass::Collected { .. }, None) => {}
                (RetainedPass::Applied { phase: actual, .. }, Some(want)) => {
                    assert_eq!(*actual, want)
                }
                _ => panic!("cancellation changed the original owned phase"),
            }
        }
    }

    #[test]
    fn pending_poll_failure_returns_original_collection_or_report() {
        for (before_apply, scoped, polls, phase) in [
            (true, false, vec![Poll::Fail], None),
            (
                false,
                false,
                vec![Poll::Fail],
                Some(AppliedPassPhase::FirstCommitAttempted),
            ),
            (
                false,
                false,
                vec![Poll::Pending, Poll::Fail],
                Some(AppliedPassPhase::FirstCommitAttempted),
            ),
            (
                false,
                true,
                vec![Poll::Published, Poll::Pending, Poll::Fail],
                Some(AppliedPassPhase::ScopedReceiptsAttempted),
            ),
        ] {
            let log = Log::default();
            let mut driver = Driver::new(&log, scoped, &polls);
            driver.pending_on_collect = before_apply;
            let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
            driver.assert_retained(&outcome);
            assert_eq!(
                outcome.error.as_ref().unwrap().to_string(),
                "original publication failure"
            );
            assert!(
                !driver.pending,
                "ownership does not depend on a cleared readiness flag"
            );
            match (&outcome.retained.as_ref().unwrap().pass, phase) {
                (RetainedPass::Collected { .. }, None) => {}
                (RetainedPass::Applied { phase: actual, .. }, Some(want)) => {
                    assert_eq!(*actual, want)
                }
                _ => panic!("publication failure changed the original owned phase"),
            }
        }
    }

    #[test]
    fn sync_defaults_preserve_commit_order() {
        let log = Log::default();
        let mut scene = Scene::new(&log);
        let (stopped, _) = run(&mut scene, ScriptedLane::new(&log), 1);
        assert_eq!(stopped.summary.passes, 1);
        assert_eq!(scene.scans, 1);
        let mut expected: Vec<String> = STARTUP.map(String::from).to_vec();
        expected.extend(pass("extend[0,1]"));
        expected.extend(STOP.map(String::from));
        assert_eq!(entries(&log), expected);
    }

    #[test]
    fn compat_adapter_preserves_retained_failure_ownership() {
        let log = Log::default();
        let mut driver = Driver::new(&log, false, &[Poll::Pending, Poll::Fail]);
        let lane = NativeLane::start(ScriptedLane::new(&log), &mut driver, windows(), None)
            .map_err(|(_, reason)| reason)
            .unwrap();
        let stop = || false;
        let clock = LoopClock {
            deadline: Some(Instant::now() + GATE_TIMEOUT),
            stop: &stop,
            now: &Instant::now,
            interval: Duration::ZERO,
            tick: Duration::from_millis(1),
            collection_tick: NO_COLLECTION_TICK,
        };
        let mut outcome = match run_classic(&mut driver, Some(lane), &clock, &mut |_, _| Ok(())) {
            Err(outcome) => outcome,
            Ok(_) => panic!("compatibility adapter flattened the retained failure"),
        };
        driver.assert_retained(&outcome);
        // Even a malformed mixed outcome must return both owners intact.
        let other_log = Log::default();
        let mut other_scene = Scene::new(&other_log);
        let (stopped, _) = run(&mut other_scene, ScriptedLane::new(&other_log), 1);
        outcome.stopped = Some(stopped);
        let mut outcome = match outcome.into_completion() {
            Err(outcome) => outcome,
            Ok(_) => panic!("a stopped+retained outcome was accepted"),
        };
        assert!(outcome.stopped.is_some() && outcome.retained.is_some());
        assert!(!entries(&log).iter().any(|line| line == "drop"));
        assert!(!entries(&other_log).iter().any(|line| line == "drop"));
        let stopped = outcome.stopped.take().unwrap();
        let ClassicCompletion::Retained { run, error } = outcome.into_completion().unwrap() else {
            panic!("the complete original run must survive conversion");
        };
        assert!(run.native.is_some());
        assert_eq!(error.unwrap().to_string(), "original publication failure");
        drop(stopped);
    }

    #[test]
    fn failed_scoped_completion_preserves_the_mutated_report_and_lane() {
        let log = Log::default();
        let mut driver = Driver::new(&log, true, &[Poll::Published]);
        driver.fail_finish = true;
        let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
        driver.assert_retained(&outcome);
        assert!(
            !driver.publication_pending(),
            "first publication already completed"
        );
        assert_eq!(
            (driver.changes.len(), driver.finishes, driver.emissions),
            (1, 1, 0)
        );
        let RetainedPass::Applied { report, phase } = &outcome.retained.as_ref().unwrap().pass
        else {
            panic!("the mutated original report must remain owned");
        };
        assert_eq!(*phase, AppliedPassPhase::ScopedCompletionFailed);
        assert_eq!(report.scan_callers, 73);
        assert_eq!(
            report
                .events
                .iter()
                .filter(|event| matches!(event,
                    CallerEvent::Exited { reason, .. } if reason == "controlled scoped completion"
                ))
                .count(),
            1
        );
        assert_eq!(
            outcome.error.as_ref().unwrap().to_string(),
            "completion failed after mutating the original report"
        );
        assert_eq!(
            entries(&log)
                .iter()
                .filter(|line| line.starts_with("extend["))
                .count(),
            1,
            "only startup extends; no after-cgroup hook"
        );
    }

    #[test]
    fn before_collection_publication_resolves_before_any_new_work() {
        for (between_passes, scoped, polls) in [
            (
                false,
                false,
                vec![Poll::Pending, Poll::Published, Poll::Published],
            ),
            (
                false,
                true,
                vec![
                    Poll::Pending,
                    Poll::Published,
                    Poll::Published,
                    Poll::Published,
                ],
            ),
            (
                true,
                false,
                vec![Poll::Published, Poll::Pending, Poll::Published],
            ),
            (
                true,
                true,
                vec![
                    Poll::Published,
                    Poll::Published,
                    Poll::Pending,
                    Poll::Published,
                ],
            ),
        ] {
            let log = Log::default();
            let mut driver = Driver::new(&log, scoped, &polls);
            driver.pending = !between_passes;
            if between_passes {
                driver.pending_on_tick = Some(1);
                driver.stop_on_emission = false;
                driver.interval = Duration::from_secs(60);
                // Complete the original between-pass publication, then stop
                // before a second physical pass can start.
                driver.stop_after_poll = Some(polls.len());
            }
            let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
            assert!(outcome.error.is_none(), "{outcome:?}");
            assert!(outcome.retained.is_none());
            assert_eq!(
                (driver.scene.scans, driver.applies, driver.emissions),
                (1, 1, 1)
            );
            assert_eq!(driver.changes.len(), polls.len());
            assert_eq!(driver.finishes, usize::from(scoped));
            assert_eq!(outcome.stopped.unwrap().summary.passes, 1);
            let log = entries(&log);
            let published: Vec<usize> = log
                .iter()
                .enumerate()
                .filter_map(|(i, line)| (line == "poll:published").then_some(i))
                .collect();
            if between_passes {
                let tick = log.iter().position(|line| line == "tick").unwrap();
                let last = *published.last().unwrap();
                assert!(tick < last);
                assert!(
                    !log[tick + 1..last]
                        .iter()
                        .any(|line| line.starts_with("stage:")),
                    "pending service must hold fresh native inputs: {log:?}"
                );
            } else {
                let collect = log.iter().position(|line| line == "collect").unwrap();
                assert!(
                    published[0] < collect,
                    "resolve the existing publication before collection: {log:?}"
                );
                assert_eq!(driver.changes[0..2], [false, false]);
            }
        }
    }

    #[test]
    fn before_collection_stop_preserves_original_owners_and_accounting() {
        for scoped in [false, true] {
            for stop_before_poll in [false, true] {
                let log = Log::default();
                let mut driver = Driver::new(&log, scoped, &[Poll::Pending]);
                driver.pending = true;
                driver.stop.set(stop_before_poll);
                driver.stop_after_poll = Some(1);
                let lane = ScriptedLane::new(&log);
                let domain = lane.domain;
                let control = driver.control.clone();
                let outcome = drive(&mut driver, lane, windows());
                driver.assert_retained(&outcome);
                let run = outcome.retained.as_ref().unwrap();
                assert!(matches!(run.pass, RetainedPass::BeforeCollection));
                assert_eq!(run.completed_passes, 0);
                assert_eq!(run.stop_cause, Some(ZeroPassCause::OperatorStop));
                assert!(run.elapsed < GATE_TIMEOUT);
                assert_eq!(live_native(run).capture.domain, domain);
                assert_eq!((driver.collected_ptr, driver.report_ptr), (0, 0));
                assert_eq!(driver.changes.len(), usize::from(!stop_before_poll));
                assert!(driver.scene.staged_lifecycle.is_empty());
                if let Some(control) = control {
                    assert!(control.check().is_err(), "same original cancellation latch");
                    assert!(run.control.as_ref().unwrap().check().is_err());
                }
            }

            let log = Log::default();
            let polls = if scoped {
                vec![Poll::Published, Poll::Published, Poll::Pending]
            } else {
                vec![Poll::Published, Poll::Pending]
            };
            let mut driver = Driver::new(&log, scoped, &polls);
            driver.pending_on_tick = Some(1);
            driver.stop_after_tick = Some(2);
            driver.stop_on_emission = false;
            driver.interval = Duration::from_secs(60);
            let lane = ScriptedLane::new(&log);
            let domain = lane.domain;
            let outcome = drive(&mut driver, lane, windows());
            driver.assert_retained(&outcome);
            let run = outcome.retained.as_ref().unwrap();
            assert!(matches!(run.pass, RetainedPass::BeforeCollection));
            assert_eq!(
                run.completed_passes, 1,
                "the previous pass remains counted once"
            );
            assert_eq!(run.stop_cause, Some(ZeroPassCause::OperatorStop));
            assert_eq!(live_native(run).capture.domain, domain);
            assert_eq!(driver.ticks, 2);
            assert_eq!(driver.native_domains, [domain; 2]);
            assert_eq!(
                driver.scene.staged_lifecycle.len(),
                if scoped { 3 } else { 2 },
                "no new native staging after the first tick made publication pending"
            );
            assert_eq!(
                live_native(run).held.len(),
                1,
                "pending native service retains the next quantum instead"
            );
        }
    }

    #[test]
    fn before_collection_error_preserves_original_owners_and_first_error() {
        for scoped in [false, true] {
            let log = Log::default();
            let mut driver = Driver::new(&log, scoped, &[Poll::Fail]);
            driver.pending = true;
            let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
            driver.assert_retained(&outcome);
            assert!(matches!(
                outcome.retained.as_ref().unwrap().pass,
                RetainedPass::BeforeCollection
            ));
            assert_eq!(
                outcome.error.as_ref().unwrap().to_string(),
                "original publication failure"
            );
            assert_eq!(driver.changes, [false]);
            assert_eq!((driver.collected_ptr, driver.report_ptr), (0, 0));

            for stopped in [false, true] {
                let log = Log::default();
                let mut driver = Driver::new(&log, scoped, &[Poll::Fail]);
                driver.pending = true;
                driver.stop.set(stopped);
                let outcome = drive_initial(
                    &mut driver,
                    ScriptedLane::new(&log),
                    windows(),
                    Some(anyhow!("original prologue failure")),
                );
                driver.assert_retained(&outcome);
                let run = outcome.retained.as_ref().unwrap();
                assert!(matches!(run.pass, RetainedPass::BeforeCollection));
                assert_eq!(
                    outcome.error.as_ref().unwrap().to_string(),
                    "original prologue failure"
                );
                assert!(
                    driver.changes.is_empty(),
                    "an initial error cannot start another poll"
                );
                assert_eq!(
                    run.stop_cause,
                    stopped.then_some(ZeroPassCause::OperatorStop)
                );
                assert!(
                    !entries(&log)
                        .iter()
                        .any(|line| line == "gap:inventory capture failed"),
                    "do not mutate the unfinished publication with a fresh failure gap"
                );
            }

            let log = Log::default();
            let polls = if scoped {
                vec![Poll::Published, Poll::Published, Poll::Fail]
            } else {
                vec![Poll::Published, Poll::Fail]
            };
            let mut driver = Driver::new(&log, scoped, &polls);
            driver.pending_on_tick = Some(1);
            driver.stop_on_emission = false;
            driver.interval = Duration::from_secs(60);
            let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
            driver.assert_retained(&outcome);
            let run = outcome.retained.as_ref().unwrap();
            assert!(matches!(run.pass, RetainedPass::BeforeCollection));
            assert_eq!(run.completed_passes, 1);
            assert_eq!(
                outcome.error.as_ref().unwrap().to_string(),
                "original publication failure"
            );
            assert_eq!(driver.changes.len(), polls.len());
            assert_eq!(driver.ticks, 1);
        }
    }

    mod retained_completion_tests {
        use super::*;

        fn retained(
            outcome: ClassicOutcome<ScriptedLane>,
        ) -> (RetainedClassicRun<ScriptedLane>, Option<anyhow::Error>) {
            match outcome.into_completion().unwrap() {
                ClassicCompletion::Retained { run, error } => (run, error),
                ClassicCompletion::Finalized { .. } => panic!("expected the original retained run"),
            }
        }

        fn before_collection(
            driver: &mut Driver,
            lane: Option<ScriptedLane>,
            initial_error: Option<anyhow::Error>,
        ) -> ClassicOutcome<ScriptedLane> {
            driver.pending = true;
            driver.stop.set(true);
            let lane = lane.map(|lane| {
                NativeLane::start(lane, driver, windows(), None)
                    .map_err(|(_, reason)| reason)
                    .unwrap()
            });
            let stop = Rc::clone(&driver.stop);
            let clock = LoopClock {
                deadline: None,
                stop: &|| stop.get(),
                now: &Instant::now,
                interval: Duration::ZERO,
                tick: Duration::from_millis(1),
                collection_tick: NO_COLLECTION_TICK,
            };
            run_classic_finalizing(driver, lane, &clock, initial_error, &mut |_, _| {
                panic!("pending startup cannot emit")
            })
        }

        fn publish(driver: &mut Driver, point: Publish<'_>) -> Result<()> {
            match point {
                Publish::Pass { report, .. } => {
                    assert_eq!(report.pending_refresh.as_ptr() as usize, driver.report_ptr);
                    driver.emissions += 1;
                    driver.scene.note("complete:pass");
                }
                Publish::Retiring { .. } => driver.scene.note("complete:retiring"),
                Publish::Stop { .. } => driver.scene.note("complete:stop"),
            }
            Ok(())
        }

        fn slice_with(
            driver: &mut Driver,
            outcome: ClassicOutcome<ScriptedLane>,
            now: Instant,
            actions: usize,
            emit: &mut dyn FnMut(&mut Driver, Publish<'_>) -> Result<()>,
        ) -> ClassicOutcome<ScriptedLane> {
            let (run, error) = retained(outcome);
            let stop = Rc::clone(&driver.stop);
            let clock = LoopClock {
                deadline: None,
                stop: &|| stop.get(),
                now: &|| now,
                interval: Duration::ZERO,
                tick: Duration::from_millis(1),
                collection_tick: NO_COLLECTION_TICK,
            };
            let mut budget = RetainedWorkBudget {
                remaining_actions: actions,
                deadline: now + Duration::from_millis(1),
            };
            poll_retained_classic(driver, run, error, &clock, &mut budget, emit)
        }

        fn slice(
            driver: &mut Driver,
            outcome: ClassicOutcome<ScriptedLane>,
            now: Instant,
            actions: usize,
        ) -> ClassicOutcome<ScriptedLane> {
            slice_with(driver, outcome, now, actions, &mut publish)
        }

        fn complete(
            driver: &mut Driver,
            mut outcome: ClassicOutcome<ScriptedLane>,
            now: Instant,
        ) -> ClassicOutcome<ScriptedLane> {
            for _ in 0..256 {
                if outcome.retained.is_none() {
                    return outcome;
                }
                assert!(
                    outcome.retained.as_ref().unwrap().block.is_none(),
                    "healthy owned work cannot require an invented disposition"
                );
                outcome = slice(driver, outcome, now, 1);
            }
            panic!("bounded scripted terminal work did not finish");
        }

        // A zero allowance must not even sample the injected controls. A slice
        // deadline must fence work, not become an operator/collection stop.
        #[test]
        fn zero_budget_and_expired_slice_run_no_work() {
            for allowance in [0, 1] {
                let log = Log::default();
                let mut driver = Driver::new(&log, false, &[Poll::Published]);
                let outcome = before_collection(&mut driver, Some(ScriptedLane::new(&log)), None);
                let (run, error) = retained(outcome);
                let before = entries(&log);
                let now = Instant::now();
                let calls = Cell::new(0);
                let clock = LoopClock {
                    deadline: None,
                    stop: &|| {
                        calls.set(calls.get() + 1);
                        false
                    },
                    now: &|| {
                        calls.set(calls.get() + 1);
                        now
                    },
                    interval: Duration::ZERO,
                    tick: Duration::from_millis(1),
                    collection_tick: NO_COLLECTION_TICK,
                };
                let mut budget = RetainedWorkBudget {
                    remaining_actions: allowance,
                    deadline: now,
                };
                let outcome = poll_retained_classic(
                    &mut driver,
                    run,
                    error,
                    &clock,
                    &mut budget,
                    &mut |_, _| panic!("no publication allowance"),
                );
                let (run, _) = retained(outcome);
                assert!(matches!(run.pass, RetainedPass::BeforeCollection));
                assert_eq!(entries(&log), before);
                assert!(driver.changes.is_empty());
                assert_eq!(driver.host_stops, 1);
                assert_eq!(run.stop_cause, Some(ZeroPassCause::OperatorStop));
                if allowance == 0 {
                    assert_eq!(calls.get(), 0);
                }
            }
        }

        // A budget of one must eventually reach native service and the tick;
        // repeatedly restarting at poll_commit would starve both forever.
        #[test]
        fn budget_one_services_the_same_pending_owner() {
            let log = Log::default();
            let mut driver = Driver::new(&log, false, &[Poll::Pending]);
            driver.stop_after_poll = Some(1);
            let mut lane = ScriptedLane::new(&log);
            let domain = lane.domain;
            lane.records_per_service = 1;
            let limits = LaneWindows {
                discovery_records: 1,
                pass_quanta: 1,
                held_records: 2,
                held_batches: 2,
                ..windows()
            };
            let mut outcome = drive(&mut driver, lane, limits);
            driver.stop_after_poll = None;
            driver.polls.extend([Poll::Pending; 4]);
            let now = Instant::now();
            for _ in 0..12 {
                outcome = slice(&mut driver, outcome, now, 1);
            }
            let (run, _) = retained(outcome);
            let Some(RetainedNative::Live(lane)) = run.native.as_ref() else {
                panic!("keep the original live lane");
            };
            assert_eq!(driver.native_domains, [domain; 3]);
            assert_eq!(driver.ticks, 3);
            assert_eq!((lane.held.len(), lane.held_records), (2, 2));
            assert_eq!(driver.changes.len(), 4);
            assert_eq!(
                (driver.scene.scans, driver.applies, driver.emissions),
                (1, 1, 0)
            );
            assert!(!entries(&log).iter().any(|line| line == "begin_stop"));
        }

        // Every one-action yield around first publication, finish, the
        // recorded extension skip and second publication keeps one report.
        #[test]
        fn pass_boundaries_finish_count_and_emit_once() {
            let log = Log::default();
            let mut driver = Driver::new(&log, true, &[Poll::Pending]);
            driver.stop_after_poll = Some(1);
            let outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
            driver.stop_after_poll = None;
            driver
                .polls
                .extend([Poll::Published, Poll::Published, Poll::Published]);
            let outcome = complete(&mut driver, outcome, Instant::now());
            assert!(outcome.error.is_none(), "{outcome:?}");
            assert_eq!(
                (
                    driver.scene.scans,
                    driver.applies,
                    driver.finishes,
                    driver.emissions
                ),
                (1, 1, 1, 1)
            );
            assert_eq!(driver.changes, [driver.report_changed, false, false, false]);
            assert_eq!(driver.host_stops, 1);
            assert_eq!(driver.legacy_stops, 0);
            assert_eq!(driver.legacy_commits, 0);
            assert_eq!(driver.lane_stops, 1);
            assert_eq!(outcome.stopped.as_ref().unwrap().summary.passes, 1);
            assert_eq!(
                entries(&log)
                    .iter()
                    .filter(|line| line.starts_with("extend["))
                    .count(),
                1,
                "a gated completion cannot start the after-cgroup extension"
            );
        }

        #[test]
        fn collected_and_failed_callbacks_require_owned_disposition() {
            for case in 0..3 {
                let log = Log::default();
                let mut driver = Driver::new(
                    &log,
                    case == 1,
                    &[if case == 2 { Poll::Fail } else { Poll::Pending }],
                );
                driver.pending_on_collect = case == 0;
                driver.stop_after_poll = Some(1);
                driver.fail_finish = case == 1;
                let mut outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
                if case == 1 {
                    driver.stop_after_poll = None;
                    driver.polls.push_back(Poll::Published);
                    for _ in 0..8 {
                        if outcome.retained.as_ref().unwrap().block.is_some() {
                            break;
                        }
                        outcome = slice(&mut driver, outcome, Instant::now(), 1);
                    }
                }
                let want = match case {
                    0 => RetainedBlock::Collected,
                    1 => RetainedBlock::ScopedCompletion,
                    _ => RetainedBlock::Publication,
                };
                assert_eq!(outcome.retained.as_ref().unwrap().block, Some(want));
                let run = outcome.retained.as_ref().unwrap();
                if case == 0 {
                    let RetainedPass::Collected {
                        collected: CollectedPass::Legacy(Ok(catalog)),
                        ..
                    } = &run.pass
                    else {
                        panic!("retain the exact unapplied collection");
                    };
                    assert_eq!(catalog.processes.as_ptr() as usize, driver.collected_ptr);
                    assert_eq!(driver.applies, 0);
                } else {
                    let RetainedPass::Applied { report, phase } = &run.pass else {
                        panic!("retain the exact applied report");
                    };
                    assert_eq!(report.pending_refresh.as_ptr() as usize, driver.report_ptr);
                    if case == 1 {
                        assert_eq!(*phase, AppliedPassPhase::ScopedCompletionFailed);
                        assert_eq!(report.scan_callers, 73);
                        assert_eq!(report.events.iter().filter(|event| matches!(event,
                            CallerEvent::Exited { reason, .. } if reason == "controlled scoped completion"
                        )).count(), 1);
                        assert_eq!((driver.finishes, driver.changes.len()), (1, 2));
                        assert_eq!(
                            entries(&log)
                                .iter()
                                .filter(|line| line.starts_with("extend["))
                                .count(),
                            1
                        );
                    } else {
                        assert_eq!(*phase, AppliedPassPhase::FirstCommitAttempted);
                        assert_eq!(
                            outcome.error.as_ref().unwrap().to_string(),
                            "original publication failure"
                        );
                    }
                }
                let calls = driver.changes.len();
                let before = entries(&log);
                let outcome = slice(&mut driver, outcome, Instant::now(), 100);
                assert_eq!(outcome.retained.as_ref().unwrap().block, Some(want));
                assert_eq!(driver.changes.len(), calls);
                assert_eq!(entries(&log), before);
                assert_eq!(driver.emissions, 0);
            }
        }

        #[test]
        fn callback_failure_retains_the_advanced_attempt_and_original_report() {
            let log = Log::default();
            let mut driver = Driver::new(&log, false, &[Poll::Pending]);
            driver.stop_after_poll = Some(1);
            let mut outcome = drive(&mut driver, ScriptedLane::new(&log), windows());
            driver.polls.push_back(Poll::Published);
            for _ in 0..8 {
                let ready = matches!(
                    outcome.retained.as_ref().unwrap().pass,
                    RetainedPass::Applied {
                        phase: AppliedPassPhase::ReadyToEmit,
                        ..
                    }
                );
                if ready {
                    break;
                }
                outcome = slice(&mut driver, outcome, Instant::now(), 1);
            }
            let outcome = slice_with(
                &mut driver,
                outcome,
                Instant::now(),
                1,
                &mut |driver, point| {
                    assert!(matches!(point, Publish::Pass { .. }));
                    driver.emissions += 1;
                    Err(anyhow!("partial pass output failed"))
                },
            );
            let run = outcome.retained.as_ref().unwrap();
            let RetainedPass::Applied { report, phase } = &run.pass else {
                panic!("retain the same report on output failure");
            };
            assert_eq!(*phase, AppliedPassPhase::EmissionAttempted);
            assert_eq!(report.pending_refresh.as_ptr() as usize, driver.report_ptr);
            assert_eq!(run.completed_passes, 1);
            assert_eq!(run.block, Some(RetainedBlock::Publication));
            assert_eq!(
                outcome.error.as_ref().unwrap().to_string(),
                "partial pass output failed"
            );
            let outcome = slice(&mut driver, outcome, Instant::now(), 20);
            assert_eq!(driver.emissions, 1);
            assert!(outcome.stopped.is_none());
        }

        #[test]
        fn native_stop_yields_in_order_with_one_original_capture() {
            for failed_retirement in [false, true] {
                let log = Log::default();
                let mut driver = Driver::new(&log, false, &[Poll::Published, Poll::Published]);
                let mut lane = ScriptedLane::new(&log);
                lane.retirement_error = failed_retirement;
                lane.partial_reads.insert(1);
                lane.partial_refresh_reads.insert(3);
                let domain = lane.domain;
                let deadlines = Rc::clone(&lane.io_deadlines);
                let outcome = before_collection(&mut driver, Some(lane), None);
                let now = Instant::now();
                let outcome = complete(&mut driver, outcome, now);
                assert!(outcome.error.is_none(), "{outcome:?}");
                let stopped = outcome.stopped.unwrap();
                assert_eq!(stopped.capture.domain, domain);
                assert_eq!(stopped.summary.passes, 0);
                assert_eq!(
                    matches!(stopped.summary.retirement, Retirement::Unsettled(_)),
                    failed_retirement
                );
                if failed_retirement {
                    let Retirement::Unsettled(reason) = &stopped.summary.retirement else {
                        unreachable!()
                    };
                    assert!(reason.contains("controlled retirement poll failure"));
                }
                assert!(
                    deadlines
                        .borrow()
                        .iter()
                        .all(|(_, end)| *end <= now + Duration::from_millis(1))
                );
                let events = entries(&log);
                let work: Vec<&str> = events
                    .iter()
                    .map(String::as_str)
                    .filter(|s| {
                        matches!(
                            *s,
                            "read"
                                | "stage:witness"
                                | "end_capture_coverage"
                                | "begin_stop"
                                | "poll"
                                | "stage:finish"
                                | "complete:stop"
                        )
                    })
                    .collect();
                assert_eq!(
                    work,
                    [
                        "read",
                        "stage:witness",
                        "read",
                        "stage:witness",
                        "end_capture_coverage",
                        "begin_stop",
                        "poll",
                        "read",
                        "stage:witness",
                        "read",
                        "stage:witness",
                        "stage:finish",
                        "complete:stop"
                    ]
                );
                assert!(!events.iter().any(|line| line == "drop"));
                drop(stopped);
                assert_eq!(
                    entries(&log).iter().filter(|line| *line == "drop").count(),
                    1
                );
            }
        }

        #[test]
        fn native_deadlines_do_not_restart_between_slices() {
            let log = Log::default();
            let mut driver = Driver::new(&log, false, &[Poll::Published, Poll::Published]);
            let mut lane = ScriptedLane::new(&log);
            lane.partial_refresh_reads.extend(1..=1000);
            let deadlines = Rc::clone(&lane.io_deadlines);
            let mut outcome = before_collection(&mut driver, Some(lane), None);
            let now = Instant::now();
            for _ in 0..100 {
                if deadlines
                    .borrow()
                    .iter()
                    .any(|(kind, _)| *kind == "post-read")
                {
                    break;
                }
                outcome = slice(&mut driver, outcome, now, 1);
            }
            let reads = deadlines
                .borrow()
                .iter()
                .filter(|(kind, _)| *kind == "post-read")
                .count();
            assert_eq!(reads, 1);
            let outcome = complete(&mut driver, outcome, now + Duration::from_secs(1));
            assert!(outcome.retained.is_none());
            assert_eq!(
                deadlines
                    .borrow()
                    .iter()
                    .filter(|(kind, _)| *kind == "post-read")
                    .count(),
                reads,
                "expiry cannot restart the native refresh window"
            );
            assert_eq!(
                entries(&log)
                    .iter()
                    .filter(|line| line.starts_with("refresh-loss:"))
                    .count(),
                1
            );
        }

        #[test]
        fn stopped_native_owner_survives_final_publication_pending_and_error() {
            for fail in [false, true] {
                let log = Log::default();
                let mut driver = Driver::new(&log, false, &[Poll::Published, Poll::Pending]);
                let mut outcome =
                    before_collection(&mut driver, Some(ScriptedLane::new(&log)), None);
                let now = Instant::now();
                for _ in 0..100 {
                    if driver.changes.len() == 2 {
                        break;
                    }
                    outcome = slice(&mut driver, outcome, now, 1);
                }
                assert_eq!(driver.changes, [false, false]);
                assert!(matches!(
                    outcome.retained.as_ref().unwrap().native,
                    Some(RetainedNative::Stopped(_))
                ));
                assert!(outcome.stopped.is_none());
                assert!(!entries(&log).iter().any(|line| line == "drop"));
                driver
                    .polls
                    .push_back(if fail { Poll::Fail } else { Poll::Published });
                if fail {
                    for _ in 0..8 {
                        if outcome.retained.as_ref().unwrap().block.is_some() {
                            break;
                        }
                        outcome = slice(&mut driver, outcome, now, 1);
                    }
                    let run = outcome.retained.as_ref().unwrap();
                    assert_eq!(run.block, Some(RetainedBlock::Publication));
                    assert!(matches!(run.native, Some(RetainedNative::Stopped(_))));
                    assert_eq!(
                        outcome.error.as_ref().unwrap().to_string(),
                        "original publication failure"
                    );
                    assert!(
                        !entries(&log)
                            .iter()
                            .any(|line| line == "complete:stop" || line == "drop")
                    );
                } else {
                    let mut outcome = complete(&mut driver, outcome, now);
                    finish_native(
                        outcome.stopped.take(),
                        |_| driver.scene.note("final-sink"),
                        &|| {},
                        &mut |_| {},
                    );
                    let log = entries(&log);
                    assert!(
                        log.iter().position(|s| s == "final-sink").unwrap()
                            < log.iter().position(|s| s == "drop").unwrap()
                    );
                }
            }
        }

        #[test]
        fn zero_pass_completion_preserves_cause_accounting_and_first_error() {
            for (scoped, failed) in [(false, false), (true, false), (false, true), (true, true)] {
                let log = Log::default();
                let mut driver = Driver::new(&log, scoped, &[Poll::Published, Poll::Published]);
                let mut lane = ScriptedLane::new(&log);
                if scoped {
                    lane.scope_coverage = CaptureScopeCoverage::Cgroup;
                }
                let outcome = if failed {
                    driver.pending = true;
                    let outcome = drive_initial(
                        &mut driver,
                        lane,
                        windows(),
                        Some(anyhow!("first run failure")),
                    );
                    assert!(outcome.retained.as_ref().unwrap().stop_cause.is_none());
                    // This cancellation arrives during finite completion,
                    // after the original error/gate, through the same control.
                    driver.stop.set(true);
                    outcome
                } else {
                    before_collection(&mut driver, Some(lane), None)
                };
                let outcome = complete(&mut driver, outcome, Instant::now());
                assert_eq!(
                    (driver.scene.scans, driver.applies, driver.emissions),
                    (0, 0, 0)
                );
                assert_eq!(driver.host_stops, 1);
                assert_eq!(outcome.stopped.as_ref().unwrap().summary.passes, 0);
                assert_eq!(
                    entries(&log)
                        .iter()
                        .filter(|line| *line == "gap:cgroup collection cancelled before launch")
                        .count(),
                    usize::from(scoped && !failed),
                    "preserve the actual scoped startup diagnostic before the generic zero-pass marker"
                );
                assert_eq!(driver.changes.len(), if scoped && !failed { 3 } else { 2 });
                if failed {
                    assert_eq!(
                        outcome.error.as_ref().unwrap().to_string(),
                        "first run failure"
                    );
                    assert!(outcome.zero_pass.is_none());
                    if let Some(control) = &driver.control {
                        assert!(
                            control.check().is_err(),
                            "finite cancellation latches the original shared control"
                        );
                    }
                } else {
                    let zero = outcome.zero_pass.unwrap();
                    assert_eq!(zero.cause, ZeroPassCause::OperatorStop);
                    assert_eq!(zero.discarded, 0);
                    assert!(zero.elapsed < GATE_TIMEOUT);
                    assert!(outcome.error.is_none());
                }
            }
        }

        #[test]
        fn scan_zero_pass_failure_retains_its_best_effort_status_channel() {
            for failure_at in 0..3 {
                let log = Log::default();
                let mut driver = Driver::new(
                    &log,
                    false,
                    &[
                        Poll::Published,
                        if failure_at == 1 {
                            Poll::Fail
                        } else {
                            Poll::Published
                        },
                    ],
                );
                let mut outcome = before_collection(&mut driver, None, None);
                let now = Instant::now();
                if failure_at != 0 {
                    for _ in 0..30 {
                        if outcome.retained.as_ref().unwrap().block.is_some() {
                            break;
                        }
                        outcome = slice_with(&mut driver, outcome, now, 1, &mut |driver, point| {
                            if failure_at == 2 && matches!(&point, Publish::Stop { .. }) {
                                driver.scene.note("diagnostic-output-attempt");
                                Err(anyhow!("partial diagnostic output failed"))
                            } else {
                                publish(driver, point)
                            }
                        });
                    }
                    let run = outcome.retained.as_ref().unwrap();
                    assert!(
                        outcome.error.is_none(),
                        "best-effort diagnostic failure cannot change F9 status"
                    );
                    assert_eq!(run.block, Some(RetainedBlock::Publication));
                    assert_eq!(
                        run.terminal_callback_error.as_ref().unwrap().to_string(),
                        if failure_at == 1 {
                            "original publication failure"
                        } else {
                            "partial diagnostic output failed"
                        }
                    );
                    assert!(run.native.is_none());
                    let phase = if failure_at == 1 {
                        RetainedTerminalPhase::FinalCommitAttempted
                    } else {
                        RetainedTerminalPhase::EmitStopAttempted
                    };
                    assert!(
                        matches!(run.pass, RetainedPass::Terminal { phase: actual } if actual == phase)
                    );
                    assert!(
                        outcome.zero_pass.is_none(),
                        "an unfinished diagnostic is not finalized"
                    );
                    let outcome = slice_with(&mut driver, outcome, now, 100, &mut |_, _| {
                        panic!("a failed diagnostic callback cannot replay")
                    });
                    assert!(outcome.retained.is_some() && outcome.error.is_none());
                } else {
                    let outcome = complete(&mut driver, outcome, now);
                    assert!(outcome.error.is_none());
                    assert!(outcome.zero_pass.is_some());
                    assert!(outcome.stopped.is_none());
                    assert_eq!(
                        entries(&log)
                            .iter()
                            .filter(|s| *s == "complete:stop")
                            .count(),
                        1
                    );
                }
            }
        }
    }
}
