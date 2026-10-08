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
//!    until a complete drain while retirement is polled; reads until a
//!    count-refresh sweep completes without gaps (the terminal refresh:
//!    every witnessed row's final count, still unsettled); `Finish{domain}`;
//!    the caller commits and writes the final sinks.
//! 5. A retirement that misses its budget reads `retirement: unsettled` with
//!    a gap; the capture is dropped after the output (the documented
//!    blocking reclamation path).
//!
//! Settlement (ruling D3): Inventory has no stop gate, so a native run's
//! settlement is always `unsettled` — a call in flight at stop may leave no
//! row. Witnesses are positive facts and survive stop.
//!
//! Backend (C5.11, owner directive "kernel tiers"): `--attach-backend
//! auto` attaches the usage entries as uprobe-multi groups wherever a
//! functional probe proves the kernel links one — a capability probe, never
//! the kernel version, so distribution backports take the fast path; under
//! `--pid` the probe must also prove the kernel pid filter covers every
//! thread (the groups name the target, plus the in-BPF guard). Otherwise
//! (5.15, or a kernel whose pid filter is thread-exact), or when the
//! Multi preparation fails, the whole capture runs Singles. The choice is
//! made before anything loads, so no observation precedes it and no fresh
//! object is ever presented as a fallback. `multi` and `singles` force
//! one (forced Multi surfaces the refusal). Every native document
//! discloses the mechanism and any fallback reason.

use crate::attach::capture::{
    CaptureScope, CaptureTargets, CleanupSummary, CookieQuery, DiscoveryBatch, ExtendReceipt,
    ExtendWindow, InventoryCapture, NativeDomainId, ReadWindow, RetiredCapture, RetiringCapture,
    ScopeCustody, ScopeIncarnation, WitnessBatch, default_caller_budget,
};
use crate::attach::{AttachBackend, BackendSelection};
use crate::discovery::caller_registry::{CallerEvent, ProcessSource, UnknownReason, now_ns};
use crate::discovery::engine::inventory_coordinator::{
    InventoryCoordinator, NativeBatch, NativeReceipt, PassReport,
};
use crate::discovery::inventory_attach_set::TargetDelta;
use crate::discovery::native_binding::{NativeIdentity, ScanOnlyIdentity};
use crate::inspect_system::Catalog;
use crate::process::PidPin;
use anyhow::{Context as _, Result, anyhow};
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
    /// `retirement: unsettled`: the base, plus the backend's share for
    /// every kernel link it must close ([`RetirementLoad`]), up to the cap.
    /// The shares are upper bounds of a measured close, keyed by the
    /// backend the capability probe chose (never by kernel version): a
    /// close that finishes early ends the wait at once, so only an
    /// under-estimate costs (a false `unsettled`).
    /// The pre-output wait is at most `retirement_cap` (R-C51-4: about
    /// 10 s, so a supervisor's grace — k8s 30 s, systemd 90 s — always
    /// sees the report); the rest of the detach runs after it.
    pub retirement_base: Duration,
    /// How long stop keeps draining the lifecycle ring before its terminal
    /// read, and then keeps reading for a terminal CALLER_USE sweep to
    /// complete (a read that stops mid-sweep proves no clean instant).
    pub terminal_sweep_budget: Duration,
    /// Singles: one close per link, each waiting on its own kernel grace
    /// periods (C5.11 measurements: 18 ms on 5.15, 32-35 ms idle on 6.12
    /// and 7.x, 50-95 ms on a loaded 7.0 host).
    pub retirement_per_link: Duration,
    /// Multi: one close per group link, one grace period each (5-57 ms
    /// measured for a 64-offset group) ...
    pub retirement_per_group_link: Duration,
    /// ... plus each member's per-mm unregister walk (0.5-6 ms measured
    /// per offset with up to 500 processes mapping the provider).
    pub retirement_per_group_endpoint: Duration,
    pub retirement_cap: Duration,
    /// Lifecycle records the lane may hold, drained but not yet staged,
    /// while a pass's collection runs (C5.7). A strict bound: each quantum
    /// is capped at the room left, and at the bound the collection ticks
    /// stop draining; the ring keeps the rest, and what it cannot hold is
    /// counted lost by the kernel, never dropped here.
    pub held_records: usize,
}

/// The longest stop waits for the probes to detach before it writes the
/// report (R-C51-4). Past it the report reads `retirement: unsettled` and
/// the detach finishes after the report, interruptible by a second signal.
pub(crate) const PRE_OUTPUT_RETIREMENT_WAIT: Duration = Duration::from_secs(10);

impl LaneWindows {
    pub(crate) const PROVISIONAL: Self = Self {
        extend_entries: 512,
        extend_budget: Duration::from_millis(250),
        witness_rows: 8192,
        witness_budget: Duration::from_millis(100),
        discovery_records: 256,
        discovery_budget: Duration::from_millis(10),
        pass_quanta: 64,
        retirement_base: Duration::from_secs(5),
        terminal_sweep_budget: Duration::from_millis(500),
        retirement_per_link: Duration::from_millis(150),
        retirement_per_group_link: Duration::from_millis(100),
        retirement_per_group_endpoint: Duration::from_millis(10),
        retirement_cap: PRE_OUTPUT_RETIREMENT_WAIT,
        // 8,192 records of 920 B: at most about 7.2 MiB of user memory
        // (strict), over 4 s of a 1,000 execs/s host (two records per
        // short-lived exec) behind one collection. This userspace bound
        // is separate from the 2 MiB kernel lifecycle ring (~2,259
        // records): the ring keeps what this bound cannot hold, and what
        // it cannot hold is counted lost by the kernel.
        held_records: 8192,
    };

    /// The stop's retirement budget for `load`.
    pub(crate) fn retirement_budget(&self, load: RetirementLoad) -> Duration {
        let times = |share: Duration, count: usize| {
            u32::try_from(count)
                .ok()
                .and_then(|count| share.checked_mul(count))
                .unwrap_or(self.retirement_cap)
        };
        let share = match load.backend {
            AttachBackend::Singles => times(self.retirement_per_link, load.links),
            AttachBackend::Multi => times(self.retirement_per_group_link, load.links)
                .saturating_add(times(self.retirement_per_group_endpoint, load.endpoints)),
        };
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
        self.discovery_at_most(self.discovery_records)
    }

    /// A discovery window of at most `records` (at least one) records.
    fn discovery_at_most(&self, records: usize) -> ReadWindow {
        ReadWindow::new(
            self.discovery_records.min(records).max(1),
            Instant::now() + self.discovery_budget,
        )
        .expect("the provisional discovery window is positive")
    }
}

/// What a stop must close: every kernel link the capture holds (lifecycle
/// roots included) on its backend, and the endpoints in them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetirementLoad {
    pub backend: AttachBackend,
    pub links: usize,
    pub endpoints: usize,
}

/// The service tick between passes (plan §1 C5.1 invariant 3) and while
/// a pass's collection runs on its worker thread (C5.7, ruling D8).
pub(crate) const SERVICE_TICK: Duration = Duration::from_millis(10);

/// The native lane's attach backend and how it was chosen (disclosed in
/// every native document, like the classic `evidence.attach_mechanisms`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LaneBackend {
    pub selection: BackendSelection,
    pub backend: AttachBackend,
    /// Why `auto` runs Singles: the functional probe (or, under PID
    /// scope, the pid-filter probe) or the Multi preparation failed.
    pub fallback: Option<String>,
    /// How the kernel keeps other processes out of a PID-scoped capture.
    pub scope_filter: ScopeFilter,
}

/// What restricts the entry probes to the scope, besides `scope_auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeFilter {
    /// System scope: every process is in scope.
    None,
    /// PID scope, Singles: each perf event is bound to the target's task
    /// (`OneProcess`), plus the in-BPF PID_FILTER guard.
    PerfTaskAndBpf,
    /// PID scope, Multi: each group names the target (the proven kernel
    /// uprobe-multi pid filter), plus the in-BPF PID_FILTER guard.
    KernelPidAndBpf,
}

impl ScopeFilter {
    pub(crate) fn label(self) -> Option<&'static str> {
        match self {
            ScopeFilter::None => None,
            ScopeFilter::PerfTaskAndBpf => Some("perf-task+bpf"),
            ScopeFilter::KernelPidAndBpf => Some("kernel-pid+bpf"),
        }
    }
}

impl LaneBackend {
    /// The mechanism label, as the classic `attach_mechanisms` spells it.
    pub(crate) fn mechanism(&self) -> &'static str {
        match self.backend {
            AttachBackend::Multi => "uprobe-multi",
            AttachBackend::Singles => "per-offset",
        }
    }

    pub(crate) fn selection_label(&self) -> &'static str {
        match self.selection {
            BackendSelection::Auto => "auto",
            BackendSelection::Multi => "multi",
            BackendSelection::Singles => "singles",
        }
    }

    /// A forced Singles capture (the scripted lanes' default).
    pub(crate) fn singles() -> Self {
        Self {
            selection: BackendSelection::Singles,
            backend: AttachBackend::Singles,
            fallback: None,
            scope_filter: ScopeFilter::None,
        }
    }
}

/// Picks the capture's backend and prepares it, before anything loads
/// (session granularity, the classic rule). `probe` links a uprobe-multi
/// probe once (the capability check: no kernel-version policy); `prepare`
/// builds the capture on one backend.
///
/// - `singles`: Singles, never probed.
/// - `multi`: Multi, or the probe's refusal as an error (never a fallback).
/// - `auto`: Multi when the probe links, else Singles with the probe's
///   reason; a failed Multi preparation is retried once on Singles with
///   its reason.
pub(crate) fn prepare_on_backend<T>(
    selection: BackendSelection,
    probe: impl FnOnce() -> std::result::Result<(), String>,
    mut prepare: impl FnMut(AttachBackend) -> Result<T>,
) -> Result<(T, LaneBackend)> {
    let chosen = |backend, fallback| LaneBackend {
        selection,
        backend,
        fallback,
        scope_filter: ScopeFilter::None,
    };
    match selection {
        BackendSelection::Singles => Ok((
            prepare(AttachBackend::Singles)?,
            chosen(AttachBackend::Singles, None),
        )),
        BackendSelection::Multi => {
            probe().map_err(|reason| {
                anyhow!("--attach-backend multi: uprobe-multi is unavailable: {reason}")
            })?;
            Ok((
                prepare(AttachBackend::Multi)?,
                chosen(AttachBackend::Multi, None),
            ))
        }
        BackendSelection::Auto => {
            let reason = match probe() {
                Err(reason) => format!("the uprobe-multi functional probe failed: {reason}"),
                Ok(()) => match prepare(AttachBackend::Multi) {
                    Ok(capture) => return Ok((capture, chosen(AttachBackend::Multi, None))),
                    Err(error) => format!("the uprobe-multi preparation failed: {error:#}"),
                },
            };
            let capture = prepare(AttachBackend::Singles)
                .map_err(|error| error.context(format!("after Multi fallback ({reason})")))?;
            Ok((capture, chosen(AttachBackend::Singles, Some(reason))))
        }
    }
}

/// The production functional probe ([`crate::attach::multi_functional_probe`],
/// shared with the classic session's backend selection).
pub(crate) use crate::attach::multi_functional_probe;

/// The facade operations the lane drives: the real capture in production,
/// a scripted lane in the call-order tests. Every method is the facade's
/// own; `begin_stop` and `poll_retirement` hide the typestate moves.
pub(crate) trait CaptureLane<Pin>: NativeIdentity<Pin> {
    fn domain(&self) -> NativeDomainId;
    /// The attach backend and how it was chosen.
    fn backend(&self) -> LaneBackend {
        LaneBackend::singles()
    }
    /// The kernel links the capture holds now (roots included), when the
    /// lane can count them; else the stop budgets one per endpoint.
    fn live_links(&self) -> Option<usize> {
        None
    }
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
    /// The lane's terminal count refresh never completed: demote the
    /// retained counts to lower bounds (P1-5 terminal-first).
    fn note_refresh_loss(&mut self, reason: String);
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

    fn note_refresh_loss(&mut self, reason: String) {
        InventoryCoordinator::note_refresh_loss(self, reason);
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
    pub backend: LaneBackend,
    pub passes: u64,
    pub attached: usize,
    pub failed: usize,
    pub lifecycle: LifecycleTally,
    /// The run's lifecycle-ring high-water: the maximum fill any drain
    /// reported, including the terminal sweep. Timings telemetry only
    /// (the stop line), never schema.
    pub lifecycle_high_water_bytes: Option<u64>,
}

/// The lifecycle feed's own account (C5.7): what the lane drained, what the
/// kernel counted lost, and the recovery rescans losses scheduled.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LifecycleTally {
    /// Lifecycle records drained from the ring.
    pub records: u64,
    /// The DISCOVERY ring-loss counter (`COUNTERS[0]`, records the kernel
    /// could not reserve) at the last readable health read.
    pub ring_loss: u64,
    /// Malformed lifecycle records at the last health read.
    pub malformed: u64,
    /// Discovery quanta that failed on an undecodable record.
    pub failed_quanta: u64,
    /// Passes started early because a loss was found.
    pub recovery_rescans: u64,
}

impl LifecycleTally {
    /// Absorbs one drained quantum; true when it shows a loss.
    fn note_quantum(&mut self, batch: &DiscoveryBatch) -> bool {
        self.records += batch.records.len() as u64;
        if batch.failure.is_some() {
            self.failed_quanta += 1;
            return true;
        }
        false
    }

    /// Absorbs one witness read's health; true when a loss counter rose.
    fn note_health(&mut self, batch: &WitnessBatch) -> bool {
        let mut rose = false;
        if let Some(ring_loss) =
            crate::attach::capture::ring_loss_rose(self.ring_loss, batch.health.discovery_counters)
        {
            self.ring_loss = ring_loss;
            rose = true;
        }
        if batch.health.malformed_discovery > self.malformed {
            self.malformed = batch.health.malformed_discovery;
            rose = true;
        }
        rose
    }
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
    /// Quanta drained while the pass's collection ran, in drain order, not
    /// yet staged (C5.7); and the records they hold.
    held: Vec<DiscoveryBatch>,
    held_records: usize,
    tally: LifecycleTally,
    /// The run's lifecycle-ring high-water so far (every drained batch,
    /// including the terminal sweep, folds in).
    lifecycle_high_water_bytes: Option<u64>,
    /// A loss was found since the last recovery rescan was granted.
    loss_seen: bool,
    /// The pass that just ran was itself a recovery rescan.
    rescanning: bool,
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
            held: Vec::new(),
            held_records: 0,
            tally: LifecycleTally::default(),
            lifecycle_high_water_bytes: None,
            loss_seen: false,
            rescanning: false,
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
        // What the collection ticks drained stages here, where the ring's
        // own records of that window always staged: after the scan applied
        // and the extend receipt, before any later quantum and the read.
        events.extend(self.stage_held(host));
        events.extend(self.service(host, self.windows.pass_quanta));
        let batch = self.read();
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

    /// One service tick while the pass's collection runs on its worker
    /// (C5.7): drain up to `pass_quanta` quanta and hold them, in drain
    /// order, for `after_pass`. Nothing reaches the host while the catalog
    /// is collected, so the coordinator sees every call in the order it
    /// saw when the ring was serviced only between passes; only the ring
    /// empties sooner. At `held_records` the tick drains nothing more.
    pub(crate) fn collecting_tick<Pin>(&mut self)
    where
        L: CaptureLane<Pin>,
    {
        for _ in 0..self.windows.pass_quanta {
            let room = self.windows.held_records.saturating_sub(self.held_records);
            if room == 0 {
                return;
            }
            let batch = self.drain_within(self.windows.discovery_at_most(room));
            let more = batch.record_bound_reached || batch.deadline_reached;
            self.held_records += batch.records.len();
            self.held.push(batch);
            if !more {
                return;
            }
        }
    }

    /// Stages the held quanta in drain order, never rebuilt.
    fn stage_held<Pin, H>(&mut self, host: &mut H) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        let mut events = Vec::new();
        self.held_records = 0;
        for batch in std::mem::take(&mut self.held) {
            events.extend(
                host.stage_native(NativeBatch::Lifecycle(batch), &mut self.capture, now_ns())
                    .events,
            );
        }
        events
    }

    /// One discovery quantum, counted.
    fn drain_one<Pin>(&mut self) -> DiscoveryBatch
    where
        L: CaptureLane<Pin>,
    {
        self.drain_within(self.windows.discovery())
    }

    /// One discovery quantum within `window`, counted.
    fn drain_within<Pin>(&mut self, window: ReadWindow) -> DiscoveryBatch
    where
        L: CaptureLane<Pin>,
    {
        let batch = self.capture.service_discovery(window);
        self.loss_seen |= self.tally.note_quantum(&batch);
        self.lifecycle_high_water_bytes = self
            .lifecycle_high_water_bytes
            .max(batch.drain_high_water_bytes);
        batch
    }

    /// One witness read, its loss counters counted.
    fn read<Pin>(&mut self) -> WitnessBatch
    where
        L: CaptureLane<Pin>,
    {
        let batch = self.capture.read_witnesses(self.windows.witness());
        self.loss_seen |= self.tally.note_health(&batch);
        batch
    }

    /// Whether the next pass starts at once (FB-R5): a lifecycle loss was
    /// found, so a catalog re-walk admits what the lost records would have
    /// announced without waiting out the interval. Bounded: a recovery
    /// rescan is never followed by another, so at most every second pass is
    /// early. The loss itself stays sticky (ruling D4). The rescan is
    /// counted only when its pass starts (`begin_recovery_rescan`).
    pub(crate) fn take_recovery_rescan(&mut self) -> bool {
        if std::mem::take(&mut self.rescanning) || !self.loss_seen {
            return false;
        }
        self.loss_seen = false;
        self.rescanning = true;
        true
    }

    /// A granted recovery rescan's pass starts now.
    pub(crate) fn begin_recovery_rescan(&mut self) {
        self.tally.recovery_rescans += 1;
    }

    /// Up to `quanta` discovery quanta, each staged as drained, in order.
    fn service<Pin, H>(&mut self, host: &mut H, quanta: usize) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        let mut events = Vec::new();
        for _ in 0..quanta {
            let batch = self.drain_one();
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

    /// What the stop will close (before `begin_stop`).
    pub(crate) fn retirement_load<Pin>(&self) -> RetirementLoad
    where
        L: CaptureLane<Pin>,
    {
        RetirementLoad {
            backend: self.capture.backend().backend,
            links: self.capture.live_links().unwrap_or(self.attached),
            endpoints: self.attached,
        }
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
        // Nothing is held after a pass; staged first all the same.
        events.extend(self.stage_held(host));
        // Drain the lifecycle ring completely (bounded) right before the
        // terminal read, each quantum staged before the coverage ends: a
        // loss still in the ring then reaches the watch before it freezes
        // (C5.2 closure I-1). A failed quantum is a loss the coordinator
        // dates; retrying it would not drain more.
        let drain_deadline = Instant::now() + self.windows.terminal_sweep_budget;
        loop {
            let batch = self.drain_one();
            let done = batch.drained() || batch.failure.is_some();
            let head_pending = batch.head_pending;
            events.extend(
                host.stage_native(NativeBatch::Lifecycle(batch), &mut self.capture, now_ns())
                    .events,
            );
            if done || Instant::now() >= drain_deadline {
                break;
            }
            if head_pending {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        // The terminal read's coverage half counts only before the end, and
        // only a completed sweep proves it clean: read on (bounded) until
        // one completes.
        let sweep_deadline = Instant::now() + self.windows.terminal_sweep_budget;
        loop {
            let terminal = self.read();
            let swept = terminal.sweep_completed;
            events.extend(
                host.stage_native(
                    NativeBatch::Witness(Box::new(terminal)),
                    &mut self.capture,
                    now_ns(),
                )
                .events,
            );
            if swept || Instant::now() >= sweep_deadline {
                break;
            }
        }
        host.end_capture_coverage(now_ns());
        self.capture.begin_stop();
        let budget = self.windows.retirement_budget(self.retirement_load());
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
            let batch = self.drain_one();
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
        // The terminal count refresh: after stop began, keep reading
        // (bounded) until a refresh sweep completes without gaps, so every
        // witnessed row's count gets its last word. Still unsettled per
        // D3: the reads happen after stop began, and retirement may not
        // have closed every link. The last read is the health horizon for
        // rows the terminal read reported. The traversal restarted at
        // `begin_stop`, so a completed sweep is a generation begun after
        // the retirement boundary; when the budget expires first, the
        // incomplete refresh demotes the retained counts to lower bounds
        // (lossy, never a fresh terminal word) and is reported.
        let refresh_budget = self.windows.terminal_sweep_budget;
        let refresh_deadline = Instant::now() + refresh_budget;
        let exact = loop {
            let terminal = self.read();
            let exact = terminal.refresh_sweep_completed && !terminal.refresh_sweep_gaps;
            events.extend(
                host.stage_native(
                    NativeBatch::Witness(Box::new(terminal)),
                    &mut self.capture,
                    now_ns(),
                )
                .events,
            );
            if exact || Instant::now() >= refresh_deadline {
                break exact;
            }
        };
        if !exact {
            // P1-5 terminal-first: the incomplete refresh is a loss
            // boundary, not a scope gap alone — the retained counts
            // demote to lower bounds (lossy), so the terminal
            // observation withholds quiet over them.
            host.note_refresh_loss(format!(
                "terminal count refresh incomplete: no gap-free count-refresh sweep completed \
                 within {} ms after stop began; witnessed counts keep their last read as a \
                 lower bound",
                refresh_budget.as_millis()
            ));
        }
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
                backend: self.capture.backend(),
                passes: self.passes,
                attached: self.attached,
                failed: self.failed,
                lifecycle: self.tally,
                lifecycle_high_water_bytes: self.lifecycle_high_water_bytes,
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
    /// The service tick while a pass's collection runs on its worker.
    pub collection_tick: Duration,
}

impl LoopClock<'_> {
    fn ending(&self) -> bool {
        (self.stop)() || self.deadline.is_none_or(|end| Instant::now() >= end)
    }
}

/// One pass's collection, owned (C5.7): it reads the scope through its own
/// inputs and hands back its catalog. It runs on a worker thread, so it
/// shares nothing with the host or the capture; the catalog is the only
/// thing that crosses back.
pub(crate) type CollectJob = Box<dyn FnOnce() -> Result<Catalog> + Send>;

/// The classic loop's pass side: one pass's collection, its application at
/// `now`, and the batch commit.
pub(crate) trait PassDriver<Pin> {
    type Host: LaneHost<Pin> + ?Sized;
    fn host(&mut self) -> &mut Self::Host;
    /// The pass's collection job, built on the loop's thread.
    fn collector(&mut self) -> CollectJob;
    /// Applies what the collection returned (an error goes through the
    /// pass failure policy), with `identity` as the native identity.
    fn apply(
        &mut self,
        collected: Result<Catalog>,
        identity: &mut dyn NativeIdentity<Pin>,
        now_ns: u64,
    ) -> Result<PassReport>;
    fn commit(&mut self, engine_changed: bool) -> Result<()>;
    /// Once per service tick, after the lane's own service (C5.3: the
    /// interactive dashboard draws here). It must return within a small
    /// bound: it shares the tick.
    fn on_tick(&mut self) {}
}

/// Runs `job` on a scoped worker thread and calls `service` every `tick`
/// until its result arrives (C5.7, ruling D8): the lifecycle ring is
/// serviced while the scope is collected, not only between passes. The
/// result crosses back over a channel; the worker owns everything it reads.
/// A worker that cannot be spawned runs `job` here instead (the ring then
/// waits for the pass, as before); a worker panic resumes here.
pub(crate) fn collect_off_thread<T: Send>(
    job: impl FnOnce() -> T + Send,
    tick: Duration,
    service: &mut dyn FnMut(),
) -> T {
    use std::sync::mpsc::{self, RecvTimeoutError};
    let slot = std::sync::Mutex::new(Some(job));
    let take = |slot: &std::sync::Mutex<Option<_>>| {
        slot.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    };
    std::thread::scope(|scope| {
        let (sender, results) = mpsc::sync_channel(1);
        let slot = &slot;
        let spawned = std::thread::Builder::new()
            .name("p11scope-collect".into())
            .spawn_scoped(scope, move || {
                if let Some(job) = take(slot) {
                    let _ = sender.send(job());
                }
            });
        let worker = match spawned {
            Ok(worker) => worker,
            Err(error) => {
                eprintln!(
                    "p11scope: collecting this pass on the main thread (no worker thread: \
                     {error}); the lifecycle ring waits for it"
                );
                let job = take(slot).expect("an unspawned worker never took the job");
                return job();
            }
        };
        let mut schedule = TickSchedule::starting(Instant::now(), tick);
        loop {
            match results.recv_timeout(schedule.wait(Instant::now())) {
                Ok(value) => return value,
                Err(RecvTimeoutError::Timeout) => {
                    service();
                    schedule.advance(Instant::now());
                }
                Err(RecvTimeoutError::Disconnected) => match worker.join() {
                    Err(panic) => std::panic::resume_unwind(panic),
                    Ok(()) => unreachable!("the worker sends its result before it ends"),
                },
            }
        }
    })
}

/// A fixed-rate tick schedule (C5.3): each tick falls due one period after
/// the previous one fell due, not one period after its work ended. Work a
/// tick does after the lifecycle ring's service (the dashboard's draw)
/// therefore never pushes the next ring service later; a tick whose work
/// overran a whole period makes the next one due at once (never a burst).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TickSchedule {
    due: Instant,
    period: Duration,
}

impl TickSchedule {
    pub(crate) fn starting(now: Instant, period: Duration) -> Self {
        Self {
            due: now + period,
            period,
        }
    }

    /// How long until the next tick is due (zero once it is).
    pub(crate) fn wait(&self, now: Instant) -> Duration {
        self.due.saturating_duration_since(now)
    }

    /// The tick that was due has run (its work ended at `now`).
    pub(crate) fn advance(&mut self, now: Instant) {
        self.due += self.period;
        if self.due < now {
            self.due = now;
        }
    }
}

/// What the loop hands its publisher after each commit.
pub(crate) enum Publish<'a> {
    /// A committed pass; its events include the native events.
    Pass { report: &'a PassReport, now_ns: u64 },
    /// The native stop begins: `attached` endpoints in `links` kernel
    /// links get up to `budget` to detach before the document reads
    /// unsettled.
    Retiring {
        attached: usize,
        links: usize,
        budget: Duration,
    },
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
    let mut rescan = false;
    loop {
        // At least one full pass after activation: a stop that arrived
        // during startup (activation included) still gets one.
        if passes > 0 && clock.ending() {
            break;
        }
        // A granted recovery rescan counts once its pass really starts.
        if std::mem::take(&mut rescan)
            && let Some(lane) = lane.as_mut()
        {
            lane.begin_recovery_rescan();
        }
        let now = now_ns();
        let job = driver.collector();
        // The ring first, then the display (C5.3): on a fixed-rate schedule,
        // so the draw never delays the next ring service.
        let collected = collect_off_thread(job, clock.collection_tick, &mut || {
            if let Some(lane) = lane.as_mut() {
                lane.collecting_tick();
            }
            driver.on_tick();
        });
        let mut report = match lane.as_mut() {
            Some(lane) => driver.apply(collected, lane.identity(), now)?,
            None => driver.apply(collected, &mut ScanOnlyIdentity, now)?,
        };
        if let Some(lane) = lane.as_mut() {
            report.events.extend(lane.after_pass(driver.host()));
        }
        driver.commit(report.engine_changed)?;
        passes += 1;
        // Publication time is sampled AFTER collection, refresh, and
        // commit: rows this pass stamped (rows_read_ns) must not read as
        // the future to the presentation clock, or a rising count reads
        // Quiet live. Scan semantics keep the pass-start `now`.
        let published_ns = now_ns();
        publish(
            driver,
            Publish::Pass {
                report: &report,
                now_ns: published_ns,
            },
        )?;
        rescan = lane.as_mut().is_some_and(NativeLane::take_recovery_rescan);
        let next = if rescan {
            Instant::now()
        } else {
            Instant::now() + clock.interval
        };
        let mut schedule = TickSchedule::starting(Instant::now(), clock.tick);
        loop {
            let now = Instant::now();
            if clock.ending() || now >= next {
                break;
            }
            std::thread::sleep(schedule.wait(now).min(next - now));
            // The ring first, then the display; the schedule is fixed-rate,
            // so the draw never delays the next ring service.
            if let Some(lane) = lane.as_mut() {
                lane.tick(driver.host());
            }
            driver.on_tick();
            schedule.advance(Instant::now());
        }
    }
    let Some(lane) = lane else {
        return Ok(None);
    };
    publish(
        driver,
        Publish::Retiring {
            attached: lane.attached,
            links: lane.retirement_load().links,
            budget: lane.windows.retirement_budget(lane.retirement_load()),
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
    backend: LaneBackend,
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
    /// set's endpoint budget and the default caller-pair limit, on the
    /// backend `selection` resolves to ([`prepare_on_backend`]).
    pub(crate) fn prepare(
        scope: CaptureScope,
        endpoints: crate::capacity::InventoryBudget,
        selection: BackendSelection,
    ) -> Result<Self> {
        let callers = default_caller_budget(endpoints)?;
        // A PID scope's custody is one pidfd: a retried preparation needs
        // its own clone of the same pin, never a reopened PID.
        let mut scope = Some(scope);
        // PID scope's probe is the pid-filter probe: it links a counting
        // uprobe-multi probe named by PID, so it proves both that the
        // kernel links one and that its filter covers every thread.
        let system = matches!(scope, Some(CaptureScope::System));
        let (capture, mut backend) = prepare_on_backend(
            selection,
            || {
                if system {
                    multi_functional_probe()
                } else {
                    crate::attach::kernel_multi_pid_filter()
                }
            },
            |backend| {
                let attempt = match scope.as_ref().context("the capture scope was consumed")? {
                    CaptureScope::System => CaptureScope::System,
                    CaptureScope::Pid(pin) => CaptureScope::Pid(
                        pin.try_clone()
                            .map_err(anyhow::Error::msg)
                            .context("cloning the PID custody for a preparation")?,
                    ),
                };
                InventoryCapture::prepare(attempt, endpoints, callers, backend)
            },
        )?;
        scope.take();
        backend.scope_filter = match (system, backend.backend) {
            (true, _) => ScopeFilter::None,
            (false, AttachBackend::Multi) => ScopeFilter::KernelPidAndBpf,
            (false, AttachBackend::Singles) => ScopeFilter::PerfTaskAndBpf,
        };
        Ok(Self {
            domain: capture.domain(),
            incarnation: capture.incarnation(),
            backend,
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

    fn backend(&self) -> LaneBackend {
        self.backend.clone()
    }

    fn live_links(&self) -> Option<usize> {
        match &self.state {
            FacadeState::Active(capture) => Some(capture.live_links()),
            _ => None,
        }
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

/// The run's end after the stop (R-C51-4): `write` writes the report
/// (stream end, `-o`, stdout) first; then `report_written` arms the
/// immediate exit on a second signal; only then does an unsettled
/// retirement finish its blocking detach, between two progress lines.
pub(crate) fn finish_native<L, T>(
    stopped: Option<Stopped<L>>,
    write: impl FnOnce(Option<&LaneSummary>) -> T,
    report_written: &dyn Fn(),
    progress: &mut dyn FnMut(String),
) -> T {
    let result = write(stopped.as_ref().map(|stopped| &stopped.summary));
    report_written();
    if let Some(stopped) = stopped
        && let Retirement::Unsettled(_) = stopped.summary.retirement
    {
        progress(format!(
            "p11scope: report written; detaching the remaining native probes of {} \
             endpoints (a second SIGINT/SIGTERM exits at once)",
            stopped.summary.attached
        ));
        drop(stopped);
        progress("p11scope: native probes detached".into());
    }
    result
}

#[cfg(test)]
#[path = "inventory_capture_tests.rs"]
mod tests;
