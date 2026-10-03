//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native usage lane of `p11scope inventory` (Task 6 C5.1): the loop
//! adapter that owns the Inventory capture facade, services it between
//! scan passes, stages every native batch through the coordinator, and
//! drives the bounded stop.
//!
//! The order is the C3/C4 contract (`task6-c5-plan.md` §1 C5.1):
//!
//! 1. Startup: `begin_capture_coverage(incarnation)`, then an empty-delta
//!    `extend` that activates the lifecycle roots before the first scan,
//!    then `note_extend_receipt`. The activating receipt carries
//!    `exec_coverage`, so it is forwarded before any native batch of its
//!    domain is staged.
//! 2. Each pass: `now` read before collection, `scan_pass` with the capture
//!    as the native identity, `take_target_delta` behind the previous
//!    receipt's deferred backlog, a bounded `extend`, `note_extend_receipt`,
//!    `service_discovery` → `stage_native(Lifecycle)` in drain order (never
//!    rebuilt), `read_witnesses` → `stage_native(Witness)`, then the caller
//!    commits and emits the pass and native events.
//! 3. Between passes: a service tick drains one discovery quantum and stages
//!    it at once.
//! 4. Stop: at least one full pass after activation; the terminal read is
//!    staged before `end_capture_coverage`; `begin_stop`; discovery serviced
//!    until a complete drain while retirement is polled; one more read;
//!    `Finish{domain}`; the caller commits and writes the final sinks.
//! 5. A retirement that misses its budget reads `retirement: unsettled` with
//!    a gap; the capture is dropped after the output (the documented
//!    blocking reclamation path).
//!
//! Settlement (ruling D3): Inventory has no stop gate, so a native run's
//! settlement is always `unsettled` — a call in flight at stop may leave no
//! row. Witnesses are positive facts and survive stop.

use crate::attach::AttachBackend;
use crate::attach::capture::{
    CaptureScope, CaptureTargets, CleanupSummary, CookieQuery, DiscoveryBatch, ExtendReceipt,
    ExtendWindow, InventoryCapture, NativeDomainId, ReadWindow, RetiredCapture, RetiringCapture,
    ScopeCustody, ScopeIncarnation, WitnessBatch, default_caller_budget,
};
use crate::discovery::caller_registry::{CallerEvent, ProcessSource, UnknownReason, now_ns};
use crate::discovery::engine::inventory_coordinator::{
    InventoryCoordinator, NativeBatch, NativeReceipt, PassReport,
};
use crate::discovery::inventory_attach_set::TargetDelta;
use crate::discovery::native_binding::{NativeIdentity, ScanOnlyIdentity};
use crate::process::PidPin;
use anyhow::{Result, anyhow};
use p11scope_ebpf_common::ImageIdentity;
use std::time::{Duration, Instant};

/// The per-pass and per-tick windows (ruling D9: provisional until the M1
/// and M5 measurements re-ratify them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LaneWindows {
    /// Attach attempts per pass, and the pass's attach budget.
    pub extend_entries: usize,
    pub extend_budget: Duration,
    /// CALLER_USE rows per witness read, and its budget.
    pub witness_rows: usize,
    pub witness_budget: Duration,
    /// Lifecycle records per discovery quantum, and its budget.
    pub discovery_records: usize,
    pub discovery_budget: Duration,
    /// Discovery quanta one pass may stage before it moves on (the ticks
    /// between passes take the rest).
    pub pass_quanta: usize,
    /// How long stop waits for the probes to detach before it reads
    /// `retirement: unsettled`: the base, plus a share for each attached
    /// endpoint (every Singles link pays its own kernel detach), up to the
    /// cap.
    pub retirement_base: Duration,
    pub retirement_per_endpoint: Duration,
    pub retirement_cap: Duration,
}

impl LaneWindows {
    pub(crate) const PROVISIONAL: Self = Self {
        extend_entries: 512,
        extend_budget: Duration::from_millis(250),
        witness_rows: 8192,
        witness_budget: Duration::from_millis(100),
        discovery_records: 256,
        discovery_budget: Duration::from_millis(10),
        pass_quanta: 64,
        // Host 7.0 detached 68 links in 4.9 s (about 73 ms each).
        retirement_base: Duration::from_secs(5),
        retirement_per_endpoint: Duration::from_millis(250),
        retirement_cap: Duration::from_secs(120),
    };

    /// The stop's retirement budget for `attached` endpoints.
    pub(crate) fn retirement_budget(&self, attached: usize) -> Duration {
        let share = u32::try_from(attached)
            .ok()
            .and_then(|count| self.retirement_per_endpoint.checked_mul(count))
            .unwrap_or(self.retirement_cap);
        self.retirement_base
            .saturating_add(share)
            .min(self.retirement_cap)
    }

    fn extend(&self) -> ExtendWindow {
        ExtendWindow::new(self.extend_entries, Instant::now() + self.extend_budget)
            .expect("the provisional extend window is positive")
    }

    fn witness(&self) -> ReadWindow {
        ReadWindow::new(self.witness_rows, Instant::now() + self.witness_budget)
            .expect("the provisional witness window is positive")
    }

    fn discovery(&self) -> ReadWindow {
        ReadWindow::new(
            self.discovery_records,
            Instant::now() + self.discovery_budget,
        )
        .expect("the provisional discovery window is positive")
    }
}

/// The service tick between passes (plan §1 C5.1 invariant 3).
pub(crate) const SERVICE_TICK: Duration = Duration::from_millis(20);

/// The facade operations the lane drives: the real capture in production,
/// a scripted lane in the call-order tests. Every method is the facade's
/// own; `begin_stop` and `poll_retirement` hide the typestate moves.
pub(crate) trait CaptureLane<Pin>: NativeIdentity<Pin> {
    fn domain(&self) -> NativeDomainId;
    fn incarnation(&self) -> Option<ScopeIncarnation>;
    fn extend(
        &mut self,
        delta: TargetDelta,
        targets: &dyn CaptureTargets,
        window: ExtendWindow,
    ) -> ExtendReceipt;
    fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch;
    fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch;
    /// Starts owned retirement; a second call does nothing.
    fn begin_stop(&mut self);
    /// True once every link had its close attempt (the retired capture is
    /// then held); false while it is still running at `deadline`.
    fn poll_retirement(&mut self, deadline: Instant) -> Result<bool>;
    /// What retirement closed, once it completed.
    fn cleanup(&self) -> Option<CleanupSummary>;
}

/// The coordinator calls the lane makes (the C3/C4 staging API). A test
/// host records them around a real coordinator.
pub(crate) trait LaneHost<Pin> {
    fn begin_capture_coverage(&mut self, scope: Option<ScopeIncarnation>);
    /// Forget a capture coverage that never activated (the auto fallback).
    fn abandon_capture_coverage(&mut self);
    fn note_extend_receipt(&mut self, receipt: &ExtendReceipt);
    fn note_capture_custody(&mut self, custody: &ScopeCustody);
    fn take_target_delta(&mut self) -> TargetDelta;
    fn capture_targets(&self) -> &dyn CaptureTargets;
    fn stage_native(
        &mut self,
        batch: NativeBatch,
        identity: &mut dyn NativeIdentity<Pin>,
        now_ns: u64,
    ) -> NativeReceipt;
    fn end_capture_coverage(&mut self, at_ns: u64);
    /// The native lane runs: an edge no coverage note reached reads
    /// `not_attached`, never `scan_only`.
    fn note_native_lane(&mut self);
    fn note_scope_gap(&mut self, subject: String, reason: String);
}

impl<S: ProcessSource> LaneHost<S::Pin> for InventoryCoordinator<S> {
    fn begin_capture_coverage(&mut self, scope: Option<ScopeIncarnation>) {
        InventoryCoordinator::begin_capture_coverage(self, scope);
    }

    fn abandon_capture_coverage(&mut self) {
        InventoryCoordinator::abandon_capture_coverage(self);
    }

    fn note_extend_receipt(&mut self, receipt: &ExtendReceipt) {
        InventoryCoordinator::note_extend_receipt(self, receipt);
    }

    fn note_capture_custody(&mut self, custody: &ScopeCustody) {
        InventoryCoordinator::note_capture_custody(self, custody);
    }

    fn take_target_delta(&mut self) -> TargetDelta {
        InventoryCoordinator::take_target_delta(self)
    }

    fn capture_targets(&self) -> &dyn CaptureTargets {
        self.attach_set()
    }

    fn stage_native(
        &mut self,
        batch: NativeBatch,
        identity: &mut dyn NativeIdentity<S::Pin>,
        now_ns: u64,
    ) -> NativeReceipt {
        InventoryCoordinator::stage_native(self, batch, identity, now_ns)
    }

    fn end_capture_coverage(&mut self, at_ns: u64) {
        InventoryCoordinator::end_capture_coverage(self, at_ns);
    }

    fn note_native_lane(&mut self) {
        self.set_uncovered_reason(UnknownReason::NotAttached);
    }

    fn note_scope_gap(&mut self, subject: String, reason: String) {
        InventoryCoordinator::note_scope_gap(self, subject, reason);
    }
}

/// How the native capture's retirement ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Retirement {
    /// Every link had its close attempt within the budget.
    Closed(CleanupSummary),
    /// The budget passed first (or polling failed): the probes may still
    /// be attached when the document is written.
    Unsettled(String),
}

impl Retirement {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Retirement::Closed(_) => "closed",
            Retirement::Unsettled(_) => "unsettled",
        }
    }
}

/// Ruling D3: Inventory has no quiescence protocol, so a native run never
/// reads settled.
pub(crate) const SETTLEMENT: &str = "unsettled";

/// What one native run reports beside the inventory document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaneSummary {
    pub retirement: Retirement,
    pub passes: u64,
    pub attached: usize,
    pub failed: usize,
}

/// A stopped lane: the events and summary its stop staged, and the capture
/// itself, which the caller drops only after the final sinks are written
/// (an unsettled retirement's drop blocks).
pub(crate) struct Stopped<L> {
    pub events: Vec<CallerEvent>,
    pub summary: LaneSummary,
    /// Held only so the caller drops it after the output.
    #[cfg_attr(not(test), allow(dead_code))]
    pub capture: L,
}

/// The lane: the capture plus the state the loop keeps between passes.
pub(crate) struct NativeLane<L> {
    capture: L,
    windows: LaneWindows,
    /// The last receipt's `deferred`, resubmitted ahead of the next delta.
    backlog: TargetDelta,
    /// Events staged by ticks, emitted with the next pass.
    pending_events: Vec<CallerEvent>,
    passes: u64,
    attached: usize,
    failed: usize,
    refusal_reported: bool,
}

impl<L> NativeLane<L> {
    /// Startup (invariant 1). A capture whose activation is refused comes
    /// back with the reason, and the host forgets the coverage it began.
    /// `lossy` marks a run whose watches can never be proven (a foreign PID
    /// namespace, ruling D1): coverage is unproven from the start.
    pub(crate) fn start<Pin, H>(
        mut capture: L,
        host: &mut H,
        windows: LaneWindows,
        lossy: Option<String>,
    ) -> std::result::Result<Self, (L, String)>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        host.begin_capture_coverage(capture.incarnation());
        let receipt = capture.extend(
            TargetDelta::default(),
            host.capture_targets(),
            windows.extend(),
        );
        if let Some(reason) = receipt.refused.clone() {
            host.abandon_capture_coverage();
            return Err((capture, reason));
        }
        if !receipt.activated_roots || receipt.exec_coverage.is_none() {
            host.abandon_capture_coverage();
            return Err((
                capture,
                "the first extend did not activate the capture".into(),
            ));
        }
        host.note_extend_receipt(&receipt);
        host.note_native_lane();
        if let Some(reason) = lossy {
            let at_ns = receipt
                .exec_coverage
                .map_or(0, |coverage| coverage.start_ns());
            host.note_capture_custody(&ScopeCustody::PidUnproven { at_ns, reason });
        }
        Ok(Self {
            capture,
            windows,
            backlog: receipt.deferred,
            pending_events: Vec::new(),
            passes: 0,
            attached: receipt.attached.len(),
            failed: receipt.failed.len(),
            refusal_reported: false,
        })
    }

    /// The capture as the scan pass's native identity.
    pub(crate) fn identity<Pin>(&mut self) -> &mut dyn NativeIdentity<Pin>
    where
        L: CaptureLane<Pin>,
    {
        &mut self.capture
    }

    /// The pass's native half (invariant 2.3–2.5), after its scan and
    /// before its commit. Returns every native event since the last pass.
    pub(crate) fn after_pass<Pin, H>(&mut self, host: &mut H) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        self.passes += 1;
        let mut delta = std::mem::take(&mut self.backlog);
        delta.append(host.take_target_delta());
        let receipt = self
            .capture
            .extend(delta, host.capture_targets(), self.windows.extend());
        host.note_extend_receipt(&receipt);
        self.attached += receipt.attached.len();
        self.failed += receipt.failed.len();
        if let Some(reason) = &receipt.refused
            && !self.refusal_reported
        {
            self.refusal_reported = true;
            host.note_scope_gap(
                "native capture refused an extend".into(),
                format!(
                    "{reason}; providers admitted from now on are not attached and their usage \
                     is not covered"
                ),
            );
        }
        self.backlog = receipt.deferred;
        let mut events = std::mem::take(&mut self.pending_events);
        events.extend(self.service(host, self.windows.pass_quanta));
        let batch = self.capture.read_witnesses(self.windows.witness());
        events.extend(
            host.stage_native(
                NativeBatch::Witness(Box::new(batch)),
                &mut self.capture,
                now_ns(),
            )
            .events,
        );
        events
    }

    /// One service tick between passes (invariant 3).
    pub(crate) fn tick<Pin, H>(&mut self, host: &mut H)
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        let events = self.service(host, 1);
        self.pending_events.extend(events);
    }

    /// Up to `quanta` discovery quanta, each staged as drained, in order.
    fn service<Pin, H>(&mut self, host: &mut H, quanta: usize) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        let mut events = Vec::new();
        for _ in 0..quanta {
            let batch = self.capture.service_discovery(self.windows.discovery());
            let more = batch.record_bound_reached || batch.deadline_reached;
            events.extend(
                host.stage_native(NativeBatch::Lifecycle(batch), &mut self.capture, now_ns())
                    .events,
            );
            if !more {
                break;
            }
        }
        events
    }

    /// The bounded stop (invariant 4). Needs one full pass after
    /// activation: the loop guarantees it before calling.
    pub(crate) fn stop<Pin, H>(mut self, host: &mut H) -> Stopped<L>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        debug_assert!(self.passes > 0, "stop before any pass after activation");
        let mut events = std::mem::take(&mut self.pending_events);
        // The terminal read's coverage half counts only before the end.
        let terminal = self.capture.read_witnesses(self.windows.witness());
        events.extend(
            host.stage_native(
                NativeBatch::Witness(Box::new(terminal)),
                &mut self.capture,
                now_ns(),
            )
            .events,
        );
        host.end_capture_coverage(now_ns());
        self.capture.begin_stop();
        let budget = self.windows.retirement_budget(self.attached);
        let deadline = Instant::now() + budget;
        let mut retired = false;
        let mut poll_error: Option<String> = None;
        loop {
            if !retired && poll_error.is_none() {
                match self.capture.poll_retirement(deadline) {
                    Ok(done) => retired = done,
                    Err(error) => poll_error = Some(format!("{error:#}")),
                }
            }
            let batch = self.capture.service_discovery(self.windows.discovery());
            let drained = batch.drained();
            events.extend(
                host.stage_native(NativeBatch::Lifecycle(batch), &mut self.capture, now_ns())
                    .events,
            );
            let settled_poll = retired || poll_error.is_some();
            if (settled_poll && drained) || Instant::now() >= deadline {
                break;
            }
            if drained {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        // The health horizon for rows the terminal read reported.
        let last = self.capture.read_witnesses(self.windows.witness());
        events.extend(
            host.stage_native(
                NativeBatch::Witness(Box::new(last)),
                &mut self.capture,
                now_ns(),
            )
            .events,
        );
        let domain = self.capture.domain();
        events.extend(
            host.stage_native(NativeBatch::Finish { domain }, &mut self.capture, now_ns())
                .events,
        );
        let retirement = match (retired, poll_error, self.capture.cleanup()) {
            (true, _, Some(cleanup)) => Retirement::Closed(cleanup),
            (true, _, None) => Retirement::Closed(CleanupSummary::default()),
            (false, Some(error), _) => Retirement::Unsettled(error),
            (false, None, _) => Retirement::Unsettled(format!(
                "the probes did not detach within {} ms",
                budget.as_millis()
            )),
        };
        if let Retirement::Unsettled(reason) = &retirement {
            host.note_scope_gap(
                "native capture retirement unsettled".into(),
                format!(
                    "{reason}; the document was written while the Inventory probes may still \
                     be attached, and they are reclaimed (blocking) after it"
                ),
            );
        }
        Stopped {
            events,
            summary: LaneSummary {
                retirement,
                passes: self.passes,
                attached: self.attached,
                failed: self.failed,
            },
            capture: self.capture,
        }
    }
}

/// Bounded retirement of a capture whose start was refused (the auto
/// fallback): close what activation left, then hand it back for drop.
pub(crate) fn retire_refused<Pin, L: CaptureLane<Pin>>(capture: &mut L, budget: Duration) {
    capture.begin_stop();
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let discovery = ReadWindow::new(256, Instant::now() + Duration::from_millis(10))
            .expect("a positive discovery window");
        let _ = capture.service_discovery(discovery);
        match capture.poll_retirement(deadline) {
            Ok(false) => std::thread::sleep(Duration::from_millis(1)),
            Ok(true) | Err(_) => break,
        }
    }
}

/// When the classic loop ends: stop requested, deadline passed, or — with
/// no deadline — after the single snapshot pass.
pub(crate) struct LoopClock<'a> {
    pub deadline: Option<Instant>,
    pub stop: &'a dyn Fn() -> bool,
    /// From one pass's end to the next pass's start.
    pub interval: Duration,
    pub tick: Duration,
}

impl LoopClock<'_> {
    fn ending(&self) -> bool {
        (self.stop)() || self.deadline.is_none_or(|end| Instant::now() >= end)
    }
}

/// The classic loop's pass side: one scan at `now` and the batch commit.
pub(crate) trait PassDriver<Pin> {
    type Host: LaneHost<Pin> + ?Sized;
    fn host(&mut self) -> &mut Self::Host;
    fn scan(&mut self, identity: &mut dyn NativeIdentity<Pin>, now_ns: u64) -> Result<PassReport>;
    fn commit(&mut self, engine_changed: bool) -> Result<()>;
}

/// What the loop hands its publisher after each commit.
pub(crate) enum Publish<'a> {
    /// A committed pass; its events include the native events.
    Pass { report: &'a PassReport, now_ns: u64 },
    /// The native stop begins: `attached` endpoints get up to `budget` to
    /// detach before the document reads unsettled.
    Retiring { attached: usize, budget: Duration },
    /// The native stop's commit: the events it staged.
    Stop {
        events: &'a [CallerEvent],
        now_ns: u64,
    },
}

/// The classic loop, scan or native: passes until the clock ends it (never
/// before one full pass after activation), service ticks between them, and
/// — for the native lane — the bounded stop and its commit. The final
/// sinks are the caller's.
pub(crate) fn run_classic<Pin, D, L>(
    driver: &mut D,
    mut lane: Option<NativeLane<L>>,
    clock: &LoopClock<'_>,
    publish: &mut dyn FnMut(&mut D, Publish<'_>) -> Result<()>,
) -> Result<Option<Stopped<L>>>
where
    D: PassDriver<Pin>,
    L: CaptureLane<Pin>,
{
    let mut passes: u64 = 0;
    loop {
        // At least one full pass after activation: a stop that arrived
        // during startup (activation included) still gets one.
        if passes > 0 && clock.ending() {
            break;
        }
        let now = now_ns();
        let mut report = match lane.as_mut() {
            Some(lane) => driver.scan(lane.identity(), now)?,
            None => driver.scan(&mut ScanOnlyIdentity, now)?,
        };
        if let Some(lane) = lane.as_mut() {
            report.events.extend(lane.after_pass(driver.host()));
        }
        driver.commit(report.engine_changed)?;
        passes += 1;
        publish(
            driver,
            Publish::Pass {
                report: &report,
                now_ns: now,
            },
        )?;
        let next = Instant::now() + clock.interval;
        loop {
            let now = Instant::now();
            if clock.ending() || now >= next {
                break;
            }
            std::thread::sleep(clock.tick.min(next - now));
            if let Some(lane) = lane.as_mut() {
                lane.tick(driver.host());
            }
        }
    }
    let Some(lane) = lane else {
        return Ok(None);
    };
    publish(
        driver,
        Publish::Retiring {
            attached: lane.attached,
            budget: lane.windows.retirement_budget(lane.attached),
        },
    )?;
    let stopped = lane.stop(driver.host());
    driver.commit(false)?;
    publish(
        driver,
        Publish::Stop {
            events: &stopped.events,
            now_ns: now_ns(),
        },
    )?;
    Ok(Some(stopped))
}

/// The production lane: the owned facade across its typestates.
pub(crate) struct FacadeLane {
    domain: NativeDomainId,
    incarnation: Option<ScopeIncarnation>,
    state: FacadeState,
}

enum FacadeState {
    Active(Box<InventoryCapture>),
    Retiring(Box<RetiringCapture>),
    Retired(Box<RetiredCapture>),
    /// Only while a transition is in progress.
    Moving,
}

impl FacadeLane {
    /// Loads and prepares the Inventory object for `scope` with the attach
    /// set's endpoint budget and the default caller-pair limit.
    pub(crate) fn prepare(
        scope: CaptureScope,
        endpoints: crate::capacity::InventoryBudget,
    ) -> Result<Self> {
        let callers = default_caller_budget(endpoints)?;
        let capture = InventoryCapture::prepare(scope, endpoints, callers, AttachBackend::Singles)?;
        Ok(Self {
            domain: capture.domain(),
            incarnation: capture.incarnation(),
            state: FacadeState::Active(Box::new(capture)),
        })
    }
}

impl NativeIdentity<PidPin> for FacadeLane {
    fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
        None
    }

    fn query_cookie(&mut self, domain: NativeDomainId, pin: &PidPin) -> CookieQuery {
        match &mut self.state {
            FacadeState::Active(capture) => {
                NativeIdentity::query_cookie(capture.as_mut(), domain, pin)
            }
            FacadeState::Retiring(capture) => {
                NativeIdentity::query_cookie(capture.as_mut(), domain, pin)
            }
            FacadeState::Retired(capture) => {
                NativeIdentity::query_cookie(capture.as_mut(), domain, pin)
            }
            FacadeState::Moving => CookieQuery::Unavailable("capture in transition".into()),
        }
    }
}

impl CaptureLane<PidPin> for FacadeLane {
    fn domain(&self) -> NativeDomainId {
        self.domain
    }

    fn incarnation(&self) -> Option<ScopeIncarnation> {
        self.incarnation
    }

    fn extend(
        &mut self,
        delta: TargetDelta,
        targets: &dyn CaptureTargets,
        window: ExtendWindow,
    ) -> ExtendReceipt {
        match &mut self.state {
            FacadeState::Active(capture) => capture.extend(delta, targets, window),
            _ => ExtendReceipt {
                refused: Some("the capture is stopping".into()),
                deferred: delta,
                ..ExtendReceipt::default()
            },
        }
    }

    fn service_discovery(&mut self, window: ReadWindow) -> DiscoveryBatch {
        match &mut self.state {
            FacadeState::Active(capture) => capture.service_discovery(window),
            FacadeState::Retiring(capture) => capture.service_discovery(window),
            FacadeState::Retired(capture) => capture.service_discovery(window),
            FacadeState::Moving => unreachable!("no read while the capture moves"),
        }
    }

    fn read_witnesses(&mut self, window: ReadWindow) -> WitnessBatch {
        match &mut self.state {
            FacadeState::Active(capture) => capture.read_witnesses(window),
            FacadeState::Retiring(capture) => capture.read_witnesses(window),
            FacadeState::Retired(capture) => capture.read_witnesses(window),
            FacadeState::Moving => unreachable!("no read while the capture moves"),
        }
    }

    fn begin_stop(&mut self) {
        if let FacadeState::Active(_) = self.state {
            let FacadeState::Active(capture) =
                std::mem::replace(&mut self.state, FacadeState::Moving)
            else {
                unreachable!()
            };
            self.state = FacadeState::Retiring(Box::new(capture.begin_stop()));
        }
    }

    fn poll_retirement(&mut self, deadline: Instant) -> Result<bool> {
        match &mut self.state {
            FacadeState::Retired(_) => return Ok(true),
            FacadeState::Active(_) => return Err(anyhow!("retirement polled before stop")),
            FacadeState::Moving => return Err(anyhow!("capture in transition")),
            FacadeState::Retiring(capture) => {
                if !capture.poll_completion(deadline)? {
                    return Ok(false);
                }
            }
        }
        let FacadeState::Retiring(capture) =
            std::mem::replace(&mut self.state, FacadeState::Moving)
        else {
            unreachable!()
        };
        match capture.try_finish() {
            Ok(retired) => {
                self.state = FacadeState::Retired(Box::new(retired));
                Ok(true)
            }
            Err(back) => {
                self.state = FacadeState::Retiring(back);
                Ok(false)
            }
        }
    }

    fn cleanup(&self) -> Option<CleanupSummary> {
        match &self.state {
            FacadeState::Retired(capture) => Some(capture.cleanup().clone()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "inventory_capture_tests.rs"]
mod tests;
