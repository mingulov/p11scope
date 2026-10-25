//! SPDX-License-Identifier: GPL-3.0-or-later
//! The native usage lane of `p11scope inventory` (Task 6 C5.1): the loop
//! adapter that owns the Inventory capture facade, services it between
//! scan passes, stages every native batch through the coordinator, and
//! drives the bounded stop.
//!
//! The order is the C3/C4 contract (`task6-c5-plan.md` §1 C5.1):
//!
//! 1. Startup: `begin_capture_coverage(scope)`, then an empty-delta
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
    CaptureScope, CaptureScopeCoverage, CaptureTargets, CleanupSummary, CookieQuery,
    DiscoveryBatch, ExtendReceipt, ExtendWindow, InventoryCapture, NativeDomainId, ReadWindow,
    RetiredCapture, RetiringCapture, ScopeCustody, WitnessBatch, default_caller_budget,
};
use crate::attach::{AttachBackend, BackendSelection};
use crate::discovery::caller_registry::{CallerEvent, ProcessSource, UnknownReason, now_ns};
use crate::discovery::engine::inventory_coordinator::{
    InventoryCoordinator, NativeBatch, NativeReceipt, PassReport,
};
use crate::discovery::inventory_attach_set::TargetDelta;
use crate::discovery::native_binding::{NativeIdentity, ScanOnlyIdentity};
use crate::inspect_system::Catalog;
use crate::inspect_system::inventory_cgroup::CgroupCollection;
use crate::process::PidPin;
use crate::scope::inventory_cgroup::CollectionControl;
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
    /// Discovery quanta (batch shells) the lane may hold alongside those
    /// records. An empty quantum charges zero records but its shell still
    /// costs memory, so without this bound a quiet capture's slow
    /// collection would hold one more batch per tick without end (Sol
    /// F4). Twice the record bound: record-carrying quanta number at most
    /// `held_records` — each holds at least one record — so a record flow
    /// still fills the record bound first; only zero-record-dominated
    /// ticks stop here, under the same posture (the ring keeps the rest,
    /// and what it cannot hold is counted lost by the kernel, never
    /// dropped here). Staging with the pass frees both bounds.
    pub held_batches: usize,
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
        // 16,384 batch shells (each about a hundred bytes: two stamps,
        // flags, and an empty record vector): at most about 1.7 MiB
        // beside the record bound, however long the collection runs.
        held_batches: 16_384,
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
    /// Cgroup scope: all-process links plus the frozen retained-root filter.
    BpfCgroup,
}

impl ScopeFilter {
    pub(crate) fn label(self) -> Option<&'static str> {
        match self {
            ScopeFilter::None => None,
            ScopeFilter::PerfTaskAndBpf => Some("perf-task+bpf"),
            ScopeFilter::KernelPidAndBpf => Some("kernel-pid+bpf"),
            ScopeFilter::BpfCgroup => Some("bpf-cgroup"),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MultiScopeProbe {
    General,
    PidFilter,
}

/// The facade's backend selection with its retained scope carried through
/// every attempt. Cgroup uses the general probe and never becomes System on
/// retry; only PID links need the functional kernel PID-filter probe.
fn prepare_scoped_on_backend<T>(
    selection: BackendSelection,
    scope: &CaptureScope,
    mut probe: impl FnMut(MultiScopeProbe) -> std::result::Result<(), String>,
    mut prepare: impl FnMut(CaptureScope, AttachBackend) -> Result<T>,
) -> Result<(T, LaneBackend)> {
    let coverage = scope.scope_coverage();
    let probe_kind = match coverage {
        CaptureScopeCoverage::Pid(_) => MultiScopeProbe::PidFilter,
        CaptureScopeCoverage::System | CaptureScopeCoverage::Cgroup => MultiScopeProbe::General,
    };
    let (capture, mut backend) = prepare_on_backend(
        selection,
        || probe(probe_kind),
        |backend| prepare(scope.clone_for_prepare()?, backend),
    )?;
    backend.scope_filter = match (coverage, backend.backend) {
        (CaptureScopeCoverage::System, _) => ScopeFilter::None,
        (CaptureScopeCoverage::Cgroup, _) => ScopeFilter::BpfCgroup,
        (CaptureScopeCoverage::Pid(_), AttachBackend::Multi) => ScopeFilter::KernelPidAndBpf,
        (CaptureScopeCoverage::Pid(_), AttachBackend::Singles) => ScopeFilter::PerfTaskAndBpf,
    };
    Ok((capture, backend))
}

/// The production functional probe ([`crate::attach::multi_functional_probe`],
/// shared with the classic session's backend selection).
pub(crate) use crate::attach::multi_functional_probe;

/// The facade operations the lane drives: the real capture in production,
/// a scripted lane in the call-order tests. Every method is the facade's
/// own; `begin_stop` and `poll_retirement` hide the typestate moves.
pub(crate) trait CaptureLane<Pin>: NativeIdentity<Pin> {
    fn domain(&self) -> NativeDomainId;
    /// One serialized identity-only metadata observation through the retained
    /// capture owner. This grants no Detailed or semantic admission authority.
    fn observe_caller_image(
        &mut self,
        _original: &std::sync::Arc<PidPin>,
        _window: ReadWindow,
    ) -> Result<crate::attach::capture::CallerImageObservation> {
        Err(anyhow!("caller image observation unavailable"))
    }
    /// One pre-view baseline acquisition through the retained capture
    /// owner, for the DR37 promotion scheduler. The default refuses:
    /// lanes without the inventory baseline program cannot qualify
    /// views. Object-safe: the reserve callback crosses as `&mut dyn`.
    fn query_promotion_baselines(
        &mut self,
        _capture: crate::inventory_promotion::CaptureId,
        _presentation: std::sync::Arc<crate::inventory_present::Presentation>,
        _targets: &[crate::attach::selected_detailed::baseline::BaselineTarget],
        _window: ReadWindow,
        _reserve: &mut dyn FnMut(
            usize,
        ) -> std::result::Result<
            crate::semantics_edge::resources::ResourceLease,
            crate::semantics_edge::resources::SemanticResourceRefusal,
        >,
    ) -> Result<crate::attach::selected_detailed::baseline::PromotionBaselineBatch> {
        Err(anyhow!("promotion baselines unavailable"))
    }
    /// The attach backend and how it was chosen.
    fn backend(&self) -> LaneBackend {
        LaneBackend::singles()
    }
    /// The kernel links the capture holds now (roots included), when the
    /// lane can count them; else the stop budgets one per endpoint.
    fn live_links(&self) -> Option<usize> {
        None
    }
    fn scope_coverage(&self) -> CaptureScopeCoverage;
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
    fn begin_capture_coverage(&mut self, scope: CaptureScopeCoverage);
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
    /// The pass loop ended: gate the host before the (possibly slow)
    /// retirement runs. The gate refuses every NEW scan, attach,
    /// successor/name admission and retry; it never blocks the drain —
    /// the stop's terminal `stage_native` quanta (witness counts,
    /// lifecycle evidence including leader-exit link loss, and staged
    /// semantic batches) still absorb and publish through the final
    /// commit. The classic loop calls this exactly once per run: in-loop
    /// when a PID/System stop latches before new apply/commit work,
    /// otherwise right after the driver's own prompt gate.
    fn stop_coordinator(&mut self) {}
}

impl<S: ProcessSource> LaneHost<S::Pin> for InventoryCoordinator<S> {
    fn begin_capture_coverage(&mut self, scope: CaptureScopeCoverage) {
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

    fn stop_coordinator(&mut self) {
        InventoryCoordinator::stop(self);
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
        host.begin_capture_coverage(capture.scope_coverage());
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
        self.extend_targets(host);
        self.stage_pass_evidence(host)
    }

    /// The pass's native half when a stop landed during its apply (F9):
    /// the already-applied owned drain still stages, but no NEW target
    /// extension starts after the stop. The host is already latched, so
    /// the staged evidence drains while successor mint refuses.
    pub(crate) fn after_pass_stopped<Pin, H>(&mut self, host: &mut H) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        self.passes += 1;
        self.stage_pass_evidence(host)
    }

    /// Scoped admission needs the held lifecycle and witness transitions
    /// before its final sample; this phase takes no new target delta.
    pub(crate) fn before_cgroup_commit<Pin, H>(&mut self, host: &mut H) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        self.passes += 1;
        self.stage_pass_evidence(host)
    }

    /// Only a published scoped transaction can supply this pass's delta.
    /// The caller publishes this receipt/evidence in a second normal commit.
    pub(crate) fn after_cgroup_commit<Pin, H>(&mut self, host: &mut H) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        self.extend_targets(host);
        self.stage_pass_evidence(host)
    }

    fn extend_targets<Pin, H>(&mut self, host: &mut H)
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
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
    }

    fn stage_pass_evidence<Pin, H>(&mut self, host: &mut H) -> Vec<CallerEvent>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
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
    /// empties sooner. At `held_records` records or `held_batches`
    /// batches the tick drains nothing more (the batch bound covers
    /// empty quanta, which charge zero records but still cost a shell).
    pub(crate) fn collecting_tick<Pin>(&mut self)
    where
        L: CaptureLane<Pin>,
    {
        for _ in 0..self.windows.pass_quanta {
            let room = self.windows.held_records.saturating_sub(self.held_records);
            if room == 0 || self.held.len() >= self.windows.held_batches {
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

    /// Admit the same real stop paths as the blocking adapter while keeping
    /// zero-pass rejection owned. No assertion or fabricated pass substitutes
    /// for scoped cancellation, the F9 latch or an original run failure.
    #[allow(clippy::result_large_err)] // A rejected transition returns the original native owner.
    fn into_finite_stop<Pin>(
        self,
        disposition: NativeStopDisposition,
        control: Option<&CollectionControl>,
    ) -> std::result::Result<NativeStop<L>, Self>
    where
        L: CaptureLane<Pin>,
    {
        let valid = match disposition {
            NativeStopDisposition::Error => true,
            NativeStopDisposition::Completed => self.passes > 0,
            NativeStopDisposition::CancelledScoped => {
                self.passes == 0
                    && matches!(self.capture.scope_coverage(), CaptureScopeCoverage::Cgroup)
                    && control.is_some_and(|control| control.check().is_err())
            }
            NativeStopDisposition::CancelledUnscoped => {
                self.passes == 0
                    && !matches!(self.capture.scope_coverage(), CaptureScopeCoverage::Cgroup)
            }
        };
        if valid {
            Ok(NativeStop::new(self))
        } else {
            Err(self)
        }
    }

    /// The bounded stop (invariant 4). Needs one full pass after
    /// activation: the loop guarantees it before calling (a stop latched
    /// before the first pass completed takes
    /// `stop_cancelled_unscoped_startup` instead).
    pub(crate) fn stop<Pin, H>(self, host: &mut H) -> Stopped<L>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        debug_assert!(self.passes > 0, "stop before any pass after activation");
        self.stop_after_error(host)
    }

    /// A scoped startup stop retires the activated capture without
    /// collecting or inventing a pass. A latched PID/System startup stop
    /// takes the sibling unscoped path; errors use the separate failure
    /// path below.
    fn stop_cancelled_scoped_startup<Pin, H>(
        self,
        host: &mut H,
        control: &CollectionControl,
    ) -> Stopped<L>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        debug_assert_eq!(self.passes, 0);
        debug_assert!(matches!(
            self.capture.scope_coverage(),
            CaptureScopeCoverage::Cgroup
        ));
        debug_assert!(control.check().is_err(), "scoped startup must be cancelled");
        self.stop_after_error(host)
    }

    /// A latched PID/System startup stop (F9) retires the activated
    /// capture without collecting or inventing a pass: like the scoped
    /// variant, a successful zero-pass stop, not a failure.
    fn stop_cancelled_unscoped_startup<Pin, H>(self, host: &mut H) -> Stopped<L>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        debug_assert_eq!(self.passes, 0);
        debug_assert!(!matches!(
            self.capture.scope_coverage(),
            CaptureScopeCoverage::Cgroup
        ));
        self.stop_after_error(host)
    }

    /// An ordinary failure can precede the first completed pass. Retire
    /// through the same bounded terminal reads without repeating that pass.
    fn stop_after_error<Pin, H>(mut self, host: &mut H) -> Stopped<L>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
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

#[derive(Clone, Copy)]
enum NativeStopDisposition {
    Completed,
    CancelledScoped,
    CancelledUnscoped,
    Error,
}

// Each state owns the actual locals of the existing terminal stop. A yield
// retains the original batch between read and staging, never another queue.
#[derive(Clone, Copy)]
enum NativeStopPhase {
    Held,
    Stage,
    PreDrain,
    PreWitness,
    EndCoverage,
    BeginRetirement,
    RetirementPoll,
    RetirementDrain,
    PostWitness,
    RefreshLoss,
    Finish,
    RetirementGap,
    Summarize,
}

#[derive(Clone, Copy)]
enum NativeAfterStage {
    Held,
    PreDrain { done: bool, head_pending: bool },
    PreWitness { complete: bool },
    RetirementDrain { drained: bool },
    PostWitness { exact: bool },
    Finish,
}

pub(crate) struct NativeStop<L> {
    lane: NativeLane<L>,
    events: Vec<CallerEvent>,
    held: std::vec::IntoIter<DiscoveryBatch>,
    phase: NativeStopPhase,
    pending: Option<NativeBatch>,
    after_stage: NativeAfterStage,
    pre_drain_deadline: Option<Instant>,
    pre_witness_deadline: Option<Instant>,
    retirement_deadline: Option<Instant>,
    refresh_deadline: Option<Instant>,
    drain_attempted: bool,
    witness_attempted: bool,
    refresh_attempted: bool,
    not_before: Option<Instant>,
    retired: bool,
    poll_error: Option<String>,
    retirement_budget: Duration,
    retirement: Option<Retirement>,
}

// Both variants move the same native owner; returning Pending must remain
// allocation-free even after the capture has actually started retirement.
#[allow(clippy::large_enum_variant)]
enum NativeStopProgress<L> {
    Pending(NativeStop<L>),
    Stopped(Stopped<L>),
}

impl<L> NativeStop<L> {
    fn new(mut lane: NativeLane<L>) -> Self {
        let events = std::mem::take(&mut lane.pending_events);
        let held = std::mem::take(&mut lane.held).into_iter();
        lane.held_records = 0;
        Self {
            lane,
            events,
            held,
            phase: NativeStopPhase::Held,
            pending: None,
            after_stage: NativeAfterStage::Held,
            pre_drain_deadline: None,
            pre_witness_deadline: None,
            retirement_deadline: None,
            refresh_deadline: None,
            drain_attempted: false,
            witness_attempted: false,
            refresh_attempted: false,
            not_before: None,
            retired: false,
            poll_error: None,
            retirement_budget: Duration::ZERO,
            retirement: None,
        }
    }

    fn enter(&mut self, phase: NativeStopPhase, now: Instant) {
        let sweep_end = now + self.lane.windows.terminal_sweep_budget;
        match phase {
            NativeStopPhase::PreDrain => {
                self.pre_drain_deadline.get_or_insert(sweep_end);
            }
            NativeStopPhase::PreWitness => {
                self.pre_witness_deadline.get_or_insert(sweep_end);
            }
            NativeStopPhase::PostWitness => {
                self.refresh_deadline.get_or_insert(sweep_end);
            }
            _ => {}
        }
        self.phase = phase;
    }

    fn discovery_window(&self, now: Instant, slice_end: Instant, phase_end: Instant) -> ReadWindow {
        ReadWindow::new(
            self.lane.windows.discovery_records.max(1),
            slice_end
                .min(phase_end)
                .min(now + self.lane.windows.discovery_budget),
        )
        .expect("the retained discovery row allowance is positive")
    }

    fn witness_window(&self, now: Instant, slice_end: Instant, phase_end: Instant) -> ReadWindow {
        ReadWindow::new(
            self.lane.windows.witness_rows,
            slice_end
                .min(phase_end)
                .min(now + self.lane.windows.witness_budget),
        )
        .expect("the retained witness row allowance is positive")
    }

    /// One cooperative action. The caller checks its allowance before this
    /// call; native windows are additionally clamped to the slice deadline.
    fn step<Pin, H>(
        mut self,
        host: &mut H,
        now: Instant,
        slice_end: Instant,
        clock: &LoopClock<'_>,
    ) -> NativeStopProgress<L>
    where
        L: CaptureLane<Pin>,
        H: LaneHost<Pin> + ?Sized,
    {
        if self.not_before.is_some_and(|at| now < at) {
            return NativeStopProgress::Pending(self);
        }
        self.not_before = None;
        match self.phase {
            NativeStopPhase::Held => match self.held.next() {
                Some(batch) => {
                    self.pending = Some(NativeBatch::Lifecycle(batch));
                    self.after_stage = NativeAfterStage::Held;
                    self.phase = NativeStopPhase::Stage;
                }
                None => self.enter(NativeStopPhase::PreDrain, now),
            },
            NativeStopPhase::Stage => {
                let batch = self
                    .pending
                    .take()
                    .expect("one original read awaits staging");
                self.events.extend(
                    host.stage_native(batch, &mut self.lane.capture, now_ns())
                        .events,
                );
                // The next phase's original window starts after this
                // staging action, exactly once, even if it used the slice.
                let now = clock.now();
                match self.after_stage {
                    NativeAfterStage::Held => self.enter(NativeStopPhase::Held, now),
                    NativeAfterStage::PreDrain { done, head_pending } => {
                        if done || now >= self.pre_drain_deadline.unwrap() {
                            self.enter(NativeStopPhase::PreWitness, now);
                        } else {
                            self.phase = NativeStopPhase::PreDrain;
                            if head_pending {
                                self.not_before = Some(now + Duration::from_millis(1));
                            }
                        }
                    }
                    NativeAfterStage::PreWitness { complete } => {
                        self.enter(
                            if complete || now >= self.pre_witness_deadline.unwrap() {
                                NativeStopPhase::EndCoverage
                            } else {
                                NativeStopPhase::PreWitness
                            },
                            now,
                        );
                    }
                    NativeAfterStage::RetirementDrain { drained } => {
                        if ((self.retired || self.poll_error.is_some()) && drained)
                            || now >= self.retirement_deadline.unwrap()
                        {
                            self.enter(NativeStopPhase::PostWitness, now);
                        } else {
                            self.phase = NativeStopPhase::RetirementPoll;
                            if drained {
                                self.not_before = Some(now + Duration::from_millis(1));
                            }
                        }
                    }
                    NativeAfterStage::PostWitness { exact } => {
                        self.phase = if exact {
                            NativeStopPhase::Finish
                        } else if now >= self.refresh_deadline.unwrap() {
                            NativeStopPhase::RefreshLoss
                        } else {
                            NativeStopPhase::PostWitness
                        };
                    }
                    NativeAfterStage::Finish => self.phase = NativeStopPhase::RetirementGap,
                }
            }
            NativeStopPhase::PreDrain => {
                let end = self.pre_drain_deadline.unwrap();
                if self.drain_attempted && now >= end {
                    self.enter(NativeStopPhase::PreWitness, now);
                } else {
                    let batch = self
                        .lane
                        .drain_within(self.discovery_window(now, slice_end, end));
                    self.drain_attempted = true;
                    self.after_stage = NativeAfterStage::PreDrain {
                        done: batch.drained() || batch.failure.is_some(),
                        head_pending: batch.head_pending,
                    };
                    self.pending = Some(NativeBatch::Lifecycle(batch));
                    self.phase = NativeStopPhase::Stage;
                }
            }
            NativeStopPhase::PreWitness => {
                let end = self.pre_witness_deadline.unwrap();
                if self.witness_attempted && now >= end {
                    self.phase = NativeStopPhase::EndCoverage;
                } else {
                    let batch = self
                        .lane
                        .capture
                        .read_witnesses(self.witness_window(now, slice_end, end));
                    self.lane.loss_seen |= self.lane.tally.note_health(&batch);
                    self.witness_attempted = true;
                    self.after_stage = NativeAfterStage::PreWitness {
                        complete: batch.sweep_completed,
                    };
                    self.pending = Some(NativeBatch::Witness(Box::new(batch)));
                    self.phase = NativeStopPhase::Stage;
                }
            }
            NativeStopPhase::EndCoverage => {
                self.phase = NativeStopPhase::BeginRetirement;
                host.end_capture_coverage(now_ns());
            }
            NativeStopPhase::BeginRetirement => {
                self.phase = NativeStopPhase::RetirementPoll;
                self.lane.capture.begin_stop();
                self.retirement_budget = self
                    .lane
                    .windows
                    .retirement_budget(self.lane.retirement_load());
                self.retirement_deadline = Some(clock.now() + self.retirement_budget);
            }
            NativeStopPhase::RetirementPoll => {
                self.phase = NativeStopPhase::RetirementDrain;
                if !self.retired
                    && self.poll_error.is_none()
                    && now < self.retirement_deadline.unwrap()
                {
                    match self
                        .lane
                        .capture
                        .poll_retirement(slice_end.min(self.retirement_deadline.unwrap()))
                    {
                        Ok(done) => self.retired = done,
                        Err(error) => self.poll_error = Some(format!("{error:#}")),
                    }
                }
            }
            NativeStopPhase::RetirementDrain => {
                let batch = self.lane.drain_within(self.discovery_window(
                    now,
                    slice_end,
                    self.retirement_deadline.unwrap(),
                ));
                self.after_stage = NativeAfterStage::RetirementDrain {
                    drained: batch.drained(),
                };
                self.pending = Some(NativeBatch::Lifecycle(batch));
                self.phase = NativeStopPhase::Stage;
            }
            NativeStopPhase::PostWitness => {
                let end = self.refresh_deadline.unwrap();
                if self.refresh_attempted && now >= end {
                    self.phase = NativeStopPhase::RefreshLoss;
                } else {
                    let batch = self
                        .lane
                        .capture
                        .read_witnesses(self.witness_window(now, slice_end, end));
                    self.lane.loss_seen |= self.lane.tally.note_health(&batch);
                    self.refresh_attempted = true;
                    self.after_stage = NativeAfterStage::PostWitness {
                        exact: batch.refresh_sweep_completed && !batch.refresh_sweep_gaps,
                    };
                    self.pending = Some(NativeBatch::Witness(Box::new(batch)));
                    self.phase = NativeStopPhase::Stage;
                }
            }
            NativeStopPhase::RefreshLoss => {
                self.phase = NativeStopPhase::Finish;
                host.note_refresh_loss(format!(
                    "terminal count refresh incomplete: no gap-free count-refresh sweep completed \
                     within {} ms after stop began; witnessed counts keep their last read as a \
                     lower bound",
                    self.lane.windows.terminal_sweep_budget.as_millis()
                ));
            }
            NativeStopPhase::Finish => {
                self.pending = Some(NativeBatch::Finish {
                    domain: self.lane.capture.domain(),
                });
                self.after_stage = NativeAfterStage::Finish;
                self.phase = NativeStopPhase::Stage;
            }
            NativeStopPhase::RetirementGap => {
                self.phase = NativeStopPhase::Summarize;
                let retirement = match (
                    self.retired,
                    self.poll_error.take(),
                    self.lane.capture.cleanup(),
                ) {
                    (true, _, Some(cleanup)) => Retirement::Closed(cleanup),
                    (true, _, None) => Retirement::Closed(CleanupSummary::default()),
                    (false, Some(error), _) => Retirement::Unsettled(error),
                    (false, None, _) => Retirement::Unsettled(format!(
                        "the probes did not detach within {} ms",
                        self.retirement_budget.as_millis()
                    )),
                };
                if let Retirement::Unsettled(reason) = &retirement {
                    host.note_scope_gap("native capture retirement unsettled".into(), format!(
                        "{reason}; the document was written while the Inventory probes may still \
                         be attached, and they are reclaimed (blocking) after it"));
                }
                self.retirement = Some(retirement);
            }
            NativeStopPhase::Summarize => {
                return NativeStopProgress::Stopped(Stopped {
                    events: self.events,
                    summary: LaneSummary {
                        retirement: self
                            .retirement
                            .take()
                            .expect("retirement was summarized once"),
                        backend: self.lane.capture.backend(),
                        passes: self.lane.passes,
                        attached: self.lane.attached,
                        failed: self.lane.failed,
                        lifecycle: self.lane.tally,
                        lifecycle_high_water_bytes: self.lane.lifecycle_high_water_bytes,
                    },
                    capture: self.lane.capture,
                });
            }
        }
        NativeStopProgress::Pending(self)
    }
}

/// When the classic loop ends: stop requested, deadline passed, or — with
/// no deadline — after the single snapshot pass.
pub(crate) struct LoopClock<'a> {
    pub deadline: Option<Instant>,
    pub stop: &'a dyn Fn() -> bool,
    /// The clock deadline reads use: `Instant::now` in production;
    /// tests inject a controlled clock so expiry-during-collection is
    /// established by the fixture, never raced on the wall clock.
    pub now: &'a dyn Fn() -> Instant,
    /// From one pass's end to the next pass's start.
    pub interval: Duration,
    pub tick: Duration,
    /// The service tick while a pass's collection runs on its worker.
    pub collection_tick: Duration,
}

impl LoopClock<'_> {
    fn now(&self) -> Instant {
        (self.now)()
    }
    fn ending(&self) -> bool {
        (self.stop)() || self.deadline.is_none_or(|end| self.now() >= end)
    }
    /// A stop the loop must honor before new work: an operator stop or a
    /// passed deadline. Unlike `ending`, no deadline reads as "run the
    /// single snapshot pass", not as "already ended" (F9).
    fn stop_requested(&self) -> bool {
        self.stop_cause().is_some()
    }
    /// The honor-before-new-work stop with its cause, for the latches
    /// whose outcome the zero-pass diagnostic reports. Same query count
    /// as `stop_requested` (one stop read, then the deadline only when
    /// no stop is pending): the stop callback may be stateful.
    fn stop_cause(&self) -> Option<ZeroPassCause> {
        if (self.stop)() {
            Some(ZeroPassCause::OperatorStop)
        } else if self.deadline.is_some_and(|end| self.now() >= end) {
            Some(ZeroPassCause::Deadline)
        } else {
            None
        }
    }
}

/// Why a zero-pass run stopped: the latched F9 cause, recorded at the
/// latch and never re-queried post-loop (the stop callback may be
/// stateful; the collection control's sticky latch is re-readable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZeroPassCause {
    OperatorStop,
    Deadline,
}

/// The subject of the scope gap a run that ends with zero completed
/// passes stages: the F9-success case reads as what it is instead of
/// staying silent (exit 0 and schemas unchanged).
pub(crate) const ZERO_PASS_GAP_SUBJECT: &str = "no complete collection pass";

/// A run that ended with zero completed passes by stop/deadline (not
/// error): the latched cause, how many completed collections were
/// discarded past the stop, and the loop's elapsed time. Both the
/// document gap and the stderr line render from this one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ZeroPassStop {
    pub(crate) cause: ZeroPassCause,
    pub(crate) discarded: u64,
    pub(crate) elapsed: Duration,
}

impl ZeroPassStop {
    fn event(&self) -> &'static str {
        match (self.cause, self.discarded > 0) {
            (ZeroPassCause::Deadline, true) => "deadline exceeded during pass-0 collection",
            (ZeroPassCause::OperatorStop, true) => "operator stop during pass-0 collection",
            (ZeroPassCause::Deadline, false) => "deadline already passed before pass 0 started",
            (ZeroPassCause::OperatorStop, false) => "operator stop requested before pass 0 started",
        }
    }
    fn outcome(&self) -> String {
        if self.discarded == 0 {
            "no collection ran".to_string()
        } else if self.discarded == 1 {
            "1 completed collection discarded".to_string()
        } else {
            format!("{} completed collections discarded", self.discarded)
        }
    }
    /// The gap reason: cause plus numbers (elapsed, discards).
    pub(crate) fn gap_reason(&self) -> String {
        if self.discarded > 0 {
            format!(
                "{} ({} elapsed); {}",
                self.event(),
                elapsed_secs_2dp(self.elapsed),
                self.outcome()
            )
        } else {
            format!("{}; {}", self.event(), self.outcome())
        }
    }
    /// The stderr line: grep-able, informational, never a success claim
    /// and never an error word (a zero-pass stop is F9-success).
    pub(crate) fn stderr_line(&self) -> String {
        format!(
            "p11scope: stopped with 0 completed passes ({}; {})",
            self.event(),
            self.outcome()
        )
    }
}

/// Elapsed time as `7.16s`: seconds with two decimals, for the
/// zero-pass gap reason.
fn elapsed_secs_2dp(elapsed: Duration) -> String {
    format!("{}.{:02}s", elapsed.as_secs(), elapsed.subsec_millis() / 10)
}

/// One pass's collection, owned (C5.7): it reads the scope through its own
/// inputs and hands back its catalog. It runs on a worker thread, so it
/// shares nothing with the host or the capture; the catalog is the only
/// thing that crosses back.
pub(crate) type LegacyCollectJob = Box<dyn FnOnce() -> Result<Catalog> + Send>;
pub(crate) type CgroupCollectJob = Box<dyn FnOnce() -> CgroupCollection + Send>;

pub(crate) enum CollectJob {
    Legacy(LegacyCollectJob),
    Cgroup {
        control: CollectionControl,
        task: Result<CgroupCollectJob, CgroupJobFailure>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CgroupJobFailure {
    Preparation,
    Spawn,
    Panic,
}

impl CgroupJobFailure {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Preparation => "cgroup collection preparation failed",
            Self::Spawn => "cgroup collection worker could not be spawned",
            Self::Panic => "cgroup collection worker panicked",
        }
    }
}

pub(crate) enum CollectedPass {
    Legacy(Result<Box<Catalog>>),
    Cgroup(Result<Box<CgroupCollection>, CgroupJobFailure>),
}

#[cfg(test)]
impl CollectedPass {
    pub(crate) fn legacy(self) -> Result<Catalog> {
        match self {
            Self::Legacy(catalog) => catalog.map(|catalog| *catalog),
            Self::Cgroup(_) => {
                anyhow::bail!("a scoped result cannot be applied as a legacy catalog")
            }
        }
    }
}

fn collect_job_off_thread(
    job: CollectJob,
    tick: Duration,
    service: &mut dyn FnMut(),
) -> CollectedPass {
    match job {
        CollectJob::Legacy(job) => {
            CollectedPass::Legacy(collect_off_thread(job, tick, service).map(Box::new))
        }
        CollectJob::Cgroup { control, task } => match task {
            Ok(job) => {
                let _ = control.check();
                CollectedPass::Cgroup(collect_cgroup_off_thread(job, tick, service).map(Box::new))
            }
            Err(failure) => CollectedPass::Cgroup(Err(failure)),
        },
    }
}

/// Scoped jobs never run inline. Join the owned worker on every outcome;
/// a returning filesystem operation still determines the next checkpoint.
pub(crate) fn collect_cgroup_off_thread(
    job: CgroupCollectJob,
    tick: Duration,
    service: &mut dyn FnMut(),
) -> Result<CgroupCollection, CgroupJobFailure> {
    use std::sync::mpsc::{self, RecvTimeoutError};
    std::thread::scope(|scope| {
        let (sender, results) = mpsc::sync_channel(1);
        let worker = if worker_spawn_test_failure() {
            Err(std::io::Error::other("injected collection spawn failure"))
        } else {
            std::thread::Builder::new()
                .name("p11scope-cgroup-collect".into())
                .spawn_scoped(scope, move || {
                    let _ = sender.send(job());
                })
        }
        .map_err(|_| CgroupJobFailure::Spawn)?;
        let mut schedule = TickSchedule::starting(Instant::now(), tick);
        loop {
            match results.recv_timeout(schedule.wait(Instant::now())) {
                Ok(value) => {
                    value.observe_worker_returned();
                    worker.join().map_err(|_| CgroupJobFailure::Panic)?;
                    value.observe_worker_joined();
                    return Ok(value);
                }
                Err(RecvTimeoutError::Timeout) => {
                    service();
                    schedule.advance(Instant::now());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = worker.join();
                    return Err(CgroupJobFailure::Panic);
                }
            }
        }
    })
}

/// Whether the same owned publication reached its actual boundary.
#[cfg_attr(not(test), allow(dead_code))] // Pending is enabled by B1's explicit driver port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassCommitProgress {
    Pending,
    Published,
}

/// The classic loop's pass side: one pass's collection, its application at
/// `now`, and the batch commit.
pub(crate) trait PassDriver<Pin> {
    type Host: LaneHost<Pin> + ?Sized;
    fn host(&mut self) -> &mut Self::Host;
    /// The pass's collection job, built on the loop's thread.
    fn collector(&mut self) -> CollectJob;
    fn collection_control(&self) -> Option<CollectionControl> {
        None
    }
    /// Applies what the collection returned (an error goes through the
    /// pass failure policy), with `identity` as the native identity.
    fn apply(
        &mut self,
        collected: CollectedPass,
        identity: &mut dyn NativeIdentity<Pin>,
        now_ns: u64,
    ) -> Result<PassReport>;
    fn commit(&mut self, engine_changed: bool) -> Result<()>;
    /// Poll the same publication. Only its first call carries the applied
    /// engine change; every retry passes false and resumes original ownership.
    /// If a service hook completed it, acknowledge that same publication;
    /// do not prepare or publish another phase in its place.
    fn poll_commit(&mut self, engine_changed: bool) -> Result<PassCommitProgress> {
        self.commit(engine_changed)?;
        Ok(PassCommitProgress::Published)
    }
    /// An earlier owned publication fences the next collected pass's apply.
    fn publication_pending(&self) -> bool {
        false
    }
    /// Consume a scoped completion after its real registry publication.
    fn finish_pass(&mut self, _report: &mut PassReport) -> Result<()> {
        Ok(())
    }
    /// Service optional jobs with the sole retained native capture. The loop
    /// calls this after ring service and before the display tick. Absent native
    /// capture stays explicit; callers cannot create a second query owner.
    fn on_native_service(&mut self, _capture: Option<&mut dyn CaptureLane<Pin>>) {}
    /// Once per service tick, after the lane's own service (C5.3: the
    /// interactive dashboard draws here). It must return within a small
    /// bound: it shares the tick.
    fn on_tick(&mut self) {}
    /// Gate new work promptly when an owned publication leaves the loop.
    /// This hook must only latch the stop: no terminal I/O, new drain,
    /// publication, owner extraction or blocking disposal. The caller keeps
    /// this driver/coordinator beside the returned retained run. The loop
    /// owns the separate once-only host stop gate, including an F9 latch.
    fn on_publication_suspended(&mut self) {}
    /// The pass loop ended (stop, deadline, cancellation or error) and
    /// the lane is about to retire: gate promptly anything the stop
    /// must fence before the (possibly slow) retirement runs. Called
    /// exactly once per run, before `Publish::Retiring`.
    fn on_stop_requested(&mut self) {}
    /// The lane retired and staged its stop; the final commit runs
    /// next. A driver with its own terminal evidence finalizes it
    /// here, before that commit publishes.
    fn on_lane_stopped(&mut self) {}
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
        let spawned = if worker_spawn_test_failure() {
            Err(std::io::Error::other("injected collection spawn failure"))
        } else {
            std::thread::Builder::new()
                .name("p11scope-collect".into())
                .spawn_scoped(scope, move || {
                    if let Some(job) = take(slot) {
                        let _ = sender.send(job());
                    }
                })
        };
        let worker = match spawned {
            Ok(worker) => worker,
            Err(error) => {
                let _ = crate::sink::try_stderr_line(&format!(
                    "p11scope: collecting this pass on the main thread (no worker thread: \
                     {error}); the lifecycle ring waits for it"
                ));
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

fn worker_spawn_test_failure() -> bool {
    #[cfg(test)]
    {
        worker_spawn_test::take_failure()
    }
    #[cfg(not(test))]
    {
        false
    }
}

#[cfg(test)]
pub(crate) mod worker_spawn_test {
    use std::cell::Cell;
    thread_local! {
        static FAIL: Cell<bool> = const { Cell::new(false) };
    }
    pub(super) fn take_failure() -> bool {
        FAIL.with(|flag| flag.replace(false))
    }
    pub(crate) fn fail_next<R>(run: impl FnOnce() -> R) -> R {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                FAIL.with(|flag| flag.set(self.0));
            }
        }
        let _restore = Restore(FAIL.with(|flag| flag.replace(true)));
        run()
    }
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
    /// The terminal commit: the native stop's commit with the events it
    /// staged, or a scan-only zero-pass stop's diagnostic commit with no
    /// events. Both stream under a `final` pass marker with zero scan
    /// counts, so gap accounting still sums without claiming a pass.
    Stop {
        events: &'a [CallerEvent],
        now_ns: u64,
    },
}

/// The classic loop, scan or native: passes until the clock ends it (an
/// operator stop or passed deadline ends it before the first pass too:
/// without a collection control the loop gates the host and runs zero
/// passes, like a cancelled scoped startup), service ticks between them,
/// and — for the native lane — the bounded stop and its commit. The final
/// sinks are the caller's.
/// A finalized outcome keeps stopped native ownership through final sinks.
/// An unfinished completion instead returns its original phase and owners;
/// callers must match completion before extracting or dropping the driver.
#[must_use = "match the completion while retaining the original driver and coordinator"]
pub(crate) struct ClassicOutcome<L> {
    pub(crate) stopped: Option<Stopped<L>>,
    pub(crate) error: Option<anyhow::Error>,
    /// `Some` exactly when the run ended with zero completed passes by
    /// stop/deadline (not error): the finalizer emits one stderr line
    /// from it beside the staged scope gap.
    pub(crate) zero_pass: Option<ZeroPassStop>,
    /// Completion still owns work. The native owner may already be stopped;
    /// keep the original driver/coordinator through its final publication.
    pub(crate) retained: Option<RetainedClassicRun<L>>,
}

/// These states record once-only work, never inferred from a readiness flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AppliedPassPhase {
    FirstCommit,
    FirstCommitAttempted,
    FirstPublished,
    ScopedCompletionAttempted,
    /// The first commit published and finish_pass was called exactly once.
    /// It mutated this report before failing; do not invoke it again.
    ScopedCompletionFailed,
    ScopedFinished,
    /// Scoped completion and the after-cgroup hook (or its stop skip) have
    /// already run once. Only the original second publication may resume.
    ScopedReceipts,
    ScopedReceiptsAttempted,
    ReadyToEmit,
    EmissionAttempted,
    Emitted,
}

/// One call's cooperative work allowance, separate from the run's stop clock.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct RetainedWorkBudget {
    pub(crate) remaining_actions: usize,
    pub(crate) deadline: Instant,
}

/// Only the actual owning driver can reconcile these states. No readiness
/// flag, retry or generic error conversion supplies that disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetainedBlock {
    /// The original unapplied collection still needs its owned disposition.
    Collected,
    /// Scoped completion was attempted; preserve the same mutated report.
    ScopedCompletion,
    /// A commit or publisher callback failed; its attempt cannot be replayed.
    Publication,
    /// Native stop admission was refused; keep the original native phase.
    Native,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetainedServiceCursor {
    Poll,
    HoldNative,
    ServiceNative,
    Tick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetainedTerminalPhase {
    ScopedStartupGap,
    ScopedStartupCommit,
    ScopedStartupCommitAttempted,
    FailureGap,
    ZeroPassGap,
    Retiring,
    RetiringAttempted,
    NativeStop,
    LaneStopped,
    FinalCommit,
    FinalCommitAttempted,
    EmitStop,
    EmitStopAttempted,
    Complete,
}

// The original capture moves once through these phases. Keep that bounded
// ownership inline rather than allocate while returning a failed operation.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RetainedNative<L> {
    Live(NativeLane<L>),
    Stopping(NativeStop<L>),
    Stopped(Stopped<L>),
}

#[cfg_attr(not(test), allow(dead_code))]
// B1 consumes the owned outcome before activation.
// Move the bounded original owners inline; boxing would add a fallible
// allocation and resource charge precisely on this failure handoff.
#[allow(clippy::large_enum_variant)]
pub(crate) enum RetainedPass {
    /// Publication began before any new pass. Never fabricate a collection
    /// or report just to return the existing driver/native ownership.
    BeforeCollection,
    Collected {
        collected: CollectedPass,
        scan_now_ns: u64,
    },
    Applied {
        report: PassReport,
        phase: AppliedPassPhase,
    },
    /// The original pass was disposed or emitted successfully. Terminal
    /// progress owns its native state and diagnostic accounting separately.
    Terminal { phase: RetainedTerminalPhase },
}

/// An unfinished completion, any existing pass and the same native owner,
/// with the loop's original stop accounting. This is not a second work
/// queue or a terminal receipt.
#[cfg_attr(not(test), allow(dead_code))] // Default synchronous drivers never retain a run.
pub(crate) struct RetainedClassicRun<L> {
    pub(crate) pass: RetainedPass,
    pub(crate) native: Option<RetainedNative<L>>,
    pub(crate) control: Option<CollectionControl>,
    pub(crate) completed_passes: u64,
    pub(crate) discarded_collections: u64,
    pub(crate) elapsed: Duration,
    pub(crate) stop_cause: Option<ZeroPassCause>,
    pub(crate) host_stopped: bool,
    pub(crate) block: Option<RetainedBlock>,
    /// Best-effort scan diagnostic failures retain their error without
    /// changing the ordinary run-status channel (F9).
    pub(crate) terminal_callback_error: Option<anyhow::Error>,
    loop_started_at: Instant,
    service: RetainedServiceCursor,
    terminal_zero_pass: Option<ZeroPassStop>,
}

#[cfg_attr(not(test), allow(dead_code))]
// Actual callers must adopt this before enabling Pending.
// Move the bounded original owners inline; boxing would add a fallible
// allocation and resource charge precisely on this failure handoff.
#[allow(clippy::large_enum_variant)]
pub(crate) enum ClassicCompletion<L> {
    Finalized {
        stopped: Option<Stopped<L>>,
        error: Option<anyhow::Error>,
        zero_pass: Option<ZeroPassStop>,
    },
    Retained {
        run: RetainedClassicRun<L>,
        error: Option<anyhow::Error>,
    },
}

impl<L> ClassicOutcome<L> {
    /// A retained result must stay beside its original driver/coordinator.
    /// Reject malformed mixed outcomes without dropping either owner.
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::result_large_err)] // Returning the original owners is the failure contract.
    pub(crate) fn into_completion(self) -> std::result::Result<ClassicCompletion<L>, Self> {
        if self.retained.is_some() && (self.stopped.is_some() || self.zero_pass.is_some()) {
            return Err(self);
        }
        Ok(match self.retained {
            Some(run) => ClassicCompletion::Retained {
                run,
                error: self.error,
            },
            None => ClassicCompletion::Finalized {
                stopped: self.stopped,
                error: self.error,
                zero_pass: self.zero_pass,
            },
        })
    }
}

impl<L> std::fmt::Debug for ClassicOutcome<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClassicOutcome")
            .field("stopped", &self.stopped.is_some())
            .field("retained", &self.retained.is_some())
            .field("error", &self.error)
            .field("zero_pass", &self.zero_pass)
            .field(
                "terminal_callback_error",
                &self
                    .retained
                    .as_ref()
                    .and_then(|run| run.terminal_callback_error.as_ref()),
            )
            .finish()
    }
}

/// Service an already gated, retained run for one finite cooperative slice.
/// The same driver/coordinator must remain beside every returned owner. This
/// never launches another collector or invents a disposition for a failed
/// callback. A deadline limits which actions start; callbacks are not preempted.
/// The phase-aware driver must restrict its service/terminal hooks to the
/// original owned work after suspension; this grants no fresh admission.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn poll_retained_classic<Pin, D, L>(
    driver: &mut D,
    mut run: RetainedClassicRun<L>,
    mut error: Option<anyhow::Error>,
    clock: &LoopClock<'_>,
    budget: &mut RetainedWorkBudget,
    publish: &mut dyn FnMut(&mut D, Publish<'_>) -> Result<()>,
) -> ClassicOutcome<L>
where
    D: PassDriver<Pin>,
    L: CaptureLane<Pin>,
{
    // In particular, do not sample stateful stop/clock callbacks with zero
    // allowance, or touch a blocked owner without its actual disposition.
    let mut finalized = false;
    while budget.remaining_actions > 0 && run.block.is_none() {
        let now = clock.now();
        if now >= budget.deadline {
            break;
        }
        budget.remaining_actions -= 1;
        if run.stop_cause.is_none() {
            run.stop_cause = publication_stop_cause(run.control.as_ref(), clock);
        }
        run.elapsed = run
            .elapsed
            .max(now.saturating_duration_since(run.loop_started_at));

        // A one-action caller resumes the saved service cursor; it cannot
        // restart at poll_commit forever and starve the retained native owner.
        match run.service {
            RetainedServiceCursor::HoldNative => {
                if let Some(RetainedNative::Live(lane)) = run.native.as_mut() {
                    let room = lane.windows.held_records.saturating_sub(lane.held_records);
                    if room > 0 && lane.held.len() < lane.windows.held_batches {
                        let window = ReadWindow::new(
                            lane.windows.discovery_records.min(room).max(1),
                            budget.deadline.min(now + lane.windows.discovery_budget),
                        )
                        .expect("positive room in the original held-record bound");
                        let batch = lane.drain_within(window);
                        lane.held_records += batch.records.len();
                        lane.held.push(batch);
                    }
                }
                run.service = RetainedServiceCursor::ServiceNative;
                continue;
            }
            RetainedServiceCursor::ServiceNative => {
                run.service = RetainedServiceCursor::Tick;
                let capture: Option<&mut dyn CaptureLane<Pin>> = match run.native.as_mut() {
                    Some(RetainedNative::Live(lane)) => Some(&mut lane.capture),
                    Some(RetainedNative::Stopping(stop)) => Some(&mut stop.lane.capture),
                    Some(RetainedNative::Stopped(stopped)) => Some(&mut stopped.capture),
                    None => None,
                };
                driver.on_native_service(capture);
                continue;
            }
            RetainedServiceCursor::Tick => {
                run.service = RetainedServiceCursor::Poll;
                driver.on_tick();
                continue;
            }
            RetainedServiceCursor::Poll => {}
        }

        let mut failure: Option<(RetainedBlock, anyhow::Error, bool)> = None;
        match &mut run.pass {
            RetainedPass::BeforeCollection => match driver.poll_commit(false) {
                Ok(PassCommitProgress::Pending) => run.service = RetainedServiceCursor::HoldNative,
                Ok(PassCommitProgress::Published) => {
                    run.pass = RetainedPass::Terminal {
                        phase: if error.is_none()
                            && run.completed_passes == 0
                            && run
                                .control
                                .as_ref()
                                .is_some_and(|control| control.check().is_err())
                        {
                            RetainedTerminalPhase::ScopedStartupGap
                        } else {
                            RetainedTerminalPhase::FailureGap
                        },
                    }
                }
                Err(next) => failure = Some((RetainedBlock::Publication, next, false)),
            },
            RetainedPass::Collected { .. } => {
                // Stop fenced apply. The real driver must dispose/reconcile
                // this exact collection and its original cgroup context.
                run.block = Some(RetainedBlock::Collected);
            }
            RetainedPass::Applied { report, phase } => match *phase {
                AppliedPassPhase::FirstCommit => {
                    *phase = AppliedPassPhase::FirstCommitAttempted;
                    match driver.poll_commit(false) {
                        Ok(PassCommitProgress::Pending) => {
                            *phase = AppliedPassPhase::FirstCommit;
                            run.service = RetainedServiceCursor::HoldNative;
                        }
                        Ok(PassCommitProgress::Published) => {
                            *phase = AppliedPassPhase::FirstPublished
                        }
                        Err(next) => failure = Some((RetainedBlock::Publication, next, false)),
                    }
                }
                AppliedPassPhase::FirstPublished => {
                    if run.control.is_some() {
                        *phase = AppliedPassPhase::ScopedCompletionAttempted;
                        match driver.finish_pass(report) {
                            Ok(()) => *phase = AppliedPassPhase::ScopedFinished,
                            Err(next) => {
                                *phase = AppliedPassPhase::ScopedCompletionFailed;
                                failure = Some((RetainedBlock::ScopedCompletion, next, false));
                            }
                        }
                    } else {
                        *phase = AppliedPassPhase::ReadyToEmit;
                    }
                }
                AppliedPassPhase::ScopedFinished => {
                    // Every suspended run was already host-gated. Record the
                    // after-cgroup extension SKIP once; only the completion's
                    // already-owned receipt/events may publish from here.
                    *phase = AppliedPassPhase::ScopedReceipts;
                }
                AppliedPassPhase::ScopedReceipts => {
                    *phase = AppliedPassPhase::ScopedReceiptsAttempted;
                    match driver.poll_commit(false) {
                        Ok(PassCommitProgress::Pending) => {
                            *phase = AppliedPassPhase::ScopedReceipts;
                            run.service = RetainedServiceCursor::HoldNative;
                        }
                        Ok(PassCommitProgress::Published) => *phase = AppliedPassPhase::ReadyToEmit,
                        Err(next) => failure = Some((RetainedBlock::Publication, next, false)),
                    }
                }
                AppliedPassPhase::ReadyToEmit => {
                    *phase = AppliedPassPhase::EmissionAttempted;
                    // Match the existing loop's count-before-output rule. An
                    // output callback can have partially emitted before Err.
                    run.completed_passes += 1;
                    match publish(
                        driver,
                        Publish::Pass {
                            report,
                            now_ns: now_ns(),
                        },
                    ) {
                        Ok(()) => *phase = AppliedPassPhase::Emitted,
                        Err(next) => failure = Some((RetainedBlock::Publication, next, false)),
                    }
                }
                AppliedPassPhase::Emitted => {
                    run.pass = RetainedPass::Terminal {
                        phase: RetainedTerminalPhase::FailureGap,
                    };
                }
                AppliedPassPhase::ScopedCompletionAttempted
                | AppliedPassPhase::ScopedCompletionFailed => {
                    run.block = Some(RetainedBlock::ScopedCompletion);
                }
                AppliedPassPhase::FirstCommitAttempted
                | AppliedPassPhase::ScopedReceiptsAttempted
                | AppliedPassPhase::EmissionAttempted => {
                    run.block = Some(RetainedBlock::Publication);
                }
            },
            RetainedPass::Terminal { phase } => match *phase {
                RetainedTerminalPhase::ScopedStartupGap => {
                    let reason = match run
                        .control
                        .as_ref()
                        .and_then(|control| control.check().err())
                    {
                        Some(crate::scope::inventory_cgroup::CollectionStop::OperatorStop) => {
                            "operator stop"
                        }
                        Some(crate::scope::inventory_cgroup::CollectionStop::Deadline) => {
                            "collection deadline"
                        }
                        None => {
                            run.block = Some(RetainedBlock::Publication);
                            continue;
                        }
                    };
                    *phase = RetainedTerminalPhase::ScopedStartupCommit;
                    driver.host().note_scope_gap(
                        "cgroup collection cancelled before launch".into(),
                        reason.into(),
                    );
                }
                RetainedTerminalPhase::ScopedStartupCommit => {
                    *phase = RetainedTerminalPhase::ScopedStartupCommitAttempted;
                    match driver.poll_commit(false) {
                        Ok(PassCommitProgress::Pending) => {
                            *phase = RetainedTerminalPhase::ScopedStartupCommit;
                            run.service = RetainedServiceCursor::HoldNative;
                        }
                        Ok(PassCommitProgress::Published) => {
                            *phase = RetainedTerminalPhase::FailureGap
                        }
                        Err(next) => failure = Some((RetainedBlock::Publication, next, false)),
                    }
                }
                RetainedTerminalPhase::FailureGap => {
                    *phase = RetainedTerminalPhase::ZeroPassGap;
                    if let Some(error) = &error {
                        driver.host().note_scope_gap(
                            "inventory capture failed".into(),
                            format!("{error:#}"),
                        );
                    }
                }
                RetainedTerminalPhase::ZeroPassGap => {
                    *phase = RetainedTerminalPhase::Retiring;
                    if error.is_none() && run.completed_passes == 0 {
                        run.terminal_zero_pass = run.stop_cause.map(|cause| ZeroPassStop {
                            cause,
                            discarded: run.discarded_collections,
                            elapsed: run.elapsed,
                        });
                        if let Some(zero) = &run.terminal_zero_pass {
                            driver
                                .host()
                                .note_scope_gap(ZERO_PASS_GAP_SUBJECT.into(), zero.gap_reason());
                        }
                    }
                }
                RetainedTerminalPhase::Retiring => {
                    if let Some(RetainedNative::Live(lane)) = run.native.as_ref() {
                        let load = lane.retirement_load();
                        let point = Publish::Retiring {
                            attached: lane.attached,
                            links: load.links,
                            budget: lane.windows.retirement_budget(load),
                        };
                        *phase = RetainedTerminalPhase::RetiringAttempted;
                        match publish(driver, point) {
                            Ok(()) => *phase = RetainedTerminalPhase::NativeStop,
                            Err(next) => failure = Some((RetainedBlock::Publication, next, false)),
                        }
                    } else if run.native.is_some() {
                        *phase = RetainedTerminalPhase::NativeStop;
                    } else if error.is_some() || run.terminal_zero_pass.is_some() {
                        *phase = RetainedTerminalPhase::FinalCommit;
                    } else {
                        *phase = RetainedTerminalPhase::Complete;
                    }
                }
                RetainedTerminalPhase::NativeStop => match run.native.take() {
                    Some(RetainedNative::Live(lane)) => {
                        let disposition = if error.is_some() {
                            NativeStopDisposition::Error
                        } else if lane.passes > 0 {
                            NativeStopDisposition::Completed
                        } else if matches!(
                            lane.capture.scope_coverage(),
                            CaptureScopeCoverage::Cgroup
                        ) {
                            NativeStopDisposition::CancelledScoped
                        } else if run.stop_cause.is_some() && run.host_stopped {
                            NativeStopDisposition::CancelledUnscoped
                        } else {
                            run.native = Some(RetainedNative::Live(lane));
                            run.block = Some(RetainedBlock::Native);
                            continue;
                        };
                        match lane.into_finite_stop::<Pin>(disposition, run.control.as_ref()) {
                            Ok(stop) => run.native = Some(RetainedNative::Stopping(stop)),
                            Err(lane) => {
                                run.native = Some(RetainedNative::Live(lane));
                                run.block = Some(RetainedBlock::Native);
                            }
                        }
                    }
                    Some(RetainedNative::Stopping(stop)) => {
                        match stop.step::<Pin, _>(driver.host(), now, budget.deadline, clock) {
                            NativeStopProgress::Pending(stop) => {
                                run.native = Some(RetainedNative::Stopping(stop))
                            }
                            NativeStopProgress::Stopped(stopped) => {
                                run.native = Some(RetainedNative::Stopped(stopped));
                                *phase = RetainedTerminalPhase::LaneStopped;
                            }
                        }
                    }
                    Some(RetainedNative::Stopped(stopped)) => {
                        run.native = Some(RetainedNative::Stopped(stopped));
                        *phase = RetainedTerminalPhase::LaneStopped;
                    }
                    None => *phase = RetainedTerminalPhase::FinalCommit,
                },
                RetainedTerminalPhase::LaneStopped => {
                    *phase = RetainedTerminalPhase::FinalCommit;
                    driver.on_lane_stopped();
                }
                RetainedTerminalPhase::FinalCommit => {
                    *phase = RetainedTerminalPhase::FinalCommitAttempted;
                    let best_effort = run.native.is_none() && run.terminal_zero_pass.is_some();
                    match driver.poll_commit(false) {
                        Ok(PassCommitProgress::Pending) => {
                            *phase = RetainedTerminalPhase::FinalCommit;
                            run.service = RetainedServiceCursor::HoldNative;
                        }
                        Ok(PassCommitProgress::Published) => {
                            *phase = if run.native.is_some() || run.terminal_zero_pass.is_some() {
                                RetainedTerminalPhase::EmitStop
                            } else {
                                RetainedTerminalPhase::Complete
                            };
                        }
                        Err(next) => {
                            failure = Some((RetainedBlock::Publication, next, best_effort))
                        }
                    }
                }
                RetainedTerminalPhase::EmitStop => {
                    *phase = RetainedTerminalPhase::EmitStopAttempted;
                    let events = match run.native.as_ref() {
                        Some(RetainedNative::Stopped(stopped)) => stopped.events.as_slice(),
                        _ => &[],
                    };
                    let best_effort = run.native.is_none() && run.terminal_zero_pass.is_some();
                    match publish(
                        driver,
                        Publish::Stop {
                            events,
                            now_ns: now_ns(),
                        },
                    ) {
                        Ok(()) => *phase = RetainedTerminalPhase::Complete,
                        Err(next) => {
                            failure = Some((RetainedBlock::Publication, next, best_effort))
                        }
                    }
                }
                RetainedTerminalPhase::ScopedStartupCommitAttempted
                | RetainedTerminalPhase::RetiringAttempted
                | RetainedTerminalPhase::FinalCommitAttempted
                | RetainedTerminalPhase::EmitStopAttempted => {
                    run.block = Some(RetainedBlock::Publication);
                }
                RetainedTerminalPhase::Complete => {
                    // A malformed terminal phase still cannot drop an active
                    // capture. Return its ownership for actual reconciliation.
                    if run
                        .native
                        .as_ref()
                        .is_some_and(|native| !matches!(native, RetainedNative::Stopped(_)))
                    {
                        run.block = Some(RetainedBlock::Native);
                    } else {
                        finalized = true;
                    }
                }
            },
        }
        if let Some((block, next, best_effort)) = failure {
            run.block = Some(block);
            if best_effort {
                run.terminal_callback_error.get_or_insert(next);
            } else {
                error.get_or_insert(next);
            }
        }
        if finalized {
            break;
        }
    }
    if finalized {
        let stopped = match run.native {
            Some(RetainedNative::Stopped(stopped)) => Some(stopped),
            None => None,
            // The guarded completion above retains these owners instead.
            Some(RetainedNative::Live(_)) | Some(RetainedNative::Stopping(_)) => unreachable!(),
        };
        ClassicOutcome {
            stopped,
            error,
            zero_pass: run.terminal_zero_pass,
            retained: None,
        }
    } else {
        ClassicOutcome {
            stopped: None,
            error,
            zero_pass: None,
            retained: Some(run),
        }
    }
}

/// Compatibility adapter for existing scripted successful-loop controls.
#[cfg(test)]
#[allow(clippy::result_large_err)] // A failed adapter must return the complete original owners.
pub(crate) fn run_classic<Pin, D, L>(
    driver: &mut D,
    lane: Option<NativeLane<L>>,
    clock: &LoopClock<'_>,
    publish: &mut dyn FnMut(&mut D, Publish<'_>) -> Result<()>,
) -> std::result::Result<Option<Stopped<L>>, ClassicOutcome<L>>
where
    D: PassDriver<Pin>,
    L: CaptureLane<Pin>,
{
    let outcome = run_classic_finalizing(driver, lane, clock, None, publish);
    if outcome.error.is_some() || outcome.retained.is_some() {
        Err(outcome)
    } else {
        Ok(outcome.stopped)
    }
}

enum PublicationWait {
    Published,
    Stopped(ZeroPassCause),
}

fn publication_stop_cause(
    control: Option<&CollectionControl>,
    clock: &LoopClock<'_>,
) -> Option<ZeroPassCause> {
    if let Some(cause) = clock.stop_cause() {
        if cause == ZeroPassCause::OperatorStop
            && let Some(control) = control
        {
            control.cancel();
        }
        return Some(cause);
    }
    control.and_then(|control| match control.check() {
        Err(crate::scope::inventory_cgroup::CollectionStop::OperatorStop) => {
            Some(ZeroPassCause::OperatorStop)
        }
        Err(crate::scope::inventory_cgroup::CollectionStop::Deadline) => {
            Some(ZeroPassCause::Deadline)
        }
        Ok(()) => None,
    })
}

/// Pending work services the same owner but holds new native quanta under
/// the collection bounds. It cannot stage fresh inputs into an unfinished
/// revision. The next ordinary hook or terminal owner stages them once.
fn wait_for_publication<Pin, D, L>(
    driver: &mut D,
    lane: &mut Option<NativeLane<L>>,
    clock: &LoopClock<'_>,
    control: Option<&CollectionControl>,
    mut engine_changed: bool,
    check_before_first_poll: bool,
) -> Result<PublicationWait>
where
    D: PassDriver<Pin>,
    L: CaptureLane<Pin>,
{
    if check_before_first_poll && let Some(cause) = publication_stop_cause(control, clock) {
        return Ok(PublicationWait::Stopped(cause));
    }
    let mut schedule = TickSchedule::starting(Instant::now(), clock.tick);
    loop {
        match driver.poll_commit(engine_changed)? {
            PassCommitProgress::Published => return Ok(PublicationWait::Published),
            PassCommitProgress::Pending => engine_changed = false,
        }
        if let Some(cause) = publication_stop_cause(control, clock) {
            return Ok(PublicationWait::Stopped(cause));
        }
        std::thread::sleep(schedule.wait(Instant::now()));
        if let Some(cause) = publication_stop_cause(control, clock) {
            return Ok(PublicationWait::Stopped(cause));
        }
        if let Some(lane) = lane.as_mut() {
            lane.collecting_tick();
        }
        if let Some(cause) = publication_stop_cause(control, clock) {
            return Ok(PublicationWait::Stopped(cause));
        }
        driver.on_native_service(
            lane.as_mut()
                .map(|lane| &mut lane.capture as &mut dyn CaptureLane<Pin>),
        );
        if let Some(cause) = publication_stop_cause(control, clock) {
            return Ok(PublicationWait::Stopped(cause));
        }
        driver.on_tick();
        if let Some(cause) = publication_stop_cause(control, clock) {
            return Ok(PublicationWait::Stopped(cause));
        }
        schedule.advance(Instant::now());
    }
}

pub(crate) fn run_classic_finalizing<Pin, D, L>(
    driver: &mut D,
    mut lane: Option<NativeLane<L>>,
    clock: &LoopClock<'_>,
    initial_error: Option<anyhow::Error>,
    publish: &mut dyn FnMut(&mut D, Publish<'_>) -> Result<()>,
) -> ClassicOutcome<L>
where
    D: PassDriver<Pin>,
    L: CaptureLane<Pin>,
{
    // A PID/System stop latched in-loop (F9): the post-loop host gate is
    // then skipped, so the host still stops exactly once per run.
    let mut stop_latched = false;
    // The zero-pass diagnostic's inputs, hoisted out of the loop body:
    // completed passes, the first latch's cause, completed collections
    // discarded past the stop, and the loop's start time.
    let mut passes: u64 = 0;
    let mut stop_cause: Option<ZeroPassCause> = None;
    let mut discarded_collections: u64 = 0;
    let loop_start = Instant::now();
    let mut retained_pass: Option<(RetainedPass, Option<CollectionControl>)> = None;
    let mut retained_block = None;
    let running = match initial_error {
        Some(error) => {
            if driver.publication_pending() {
                let control = driver.collection_control();
                stop_cause = publication_stop_cause(control.as_ref(), clock);
                retained_pass = Some((RetainedPass::BeforeCollection, control));
            }
            Err(error)
        }
        None => (|| -> Result<()> {
            let mut rescan = false;
            loop {
                let control = driver.collection_control();
                // A previous service hook can leave an owned publication
                // pending before a new pass exists. Resolve or return that
                // owner before cancellation's diagnostic commit, recovery
                // accounting, collector creation or any fresh native work.
                if driver.publication_pending() {
                    match wait_for_publication(
                        driver,
                        &mut lane,
                        clock,
                        control.as_ref(),
                        false,
                        true,
                    ) {
                        Ok(PublicationWait::Published) => {}
                        Ok(PublicationWait::Stopped(cause)) => {
                            stop_cause.get_or_insert(cause);
                            retained_pass = Some((RetainedPass::BeforeCollection, control));
                            return Ok(());
                        }
                        Err(error) => {
                            retained_block = Some(RetainedBlock::Publication);
                            retained_pass = Some((RetainedPass::BeforeCollection, control));
                            return Err(error);
                        }
                    }
                }
                if let Some(control) = &control
                    && latch_collection_stop(control, clock)
                {
                    if passes == 0 {
                        let reason = match control.check() {
                            Err(crate::scope::inventory_cgroup::CollectionStop::OperatorStop) => {
                                "operator stop"
                            }
                            Err(crate::scope::inventory_cgroup::CollectionStop::Deadline) => {
                                "collection deadline"
                            }
                            Ok(()) => unreachable!("collection cancellation is sticky"),
                        };
                        driver.host().note_scope_gap(
                            "cgroup collection cancelled before launch".into(),
                            reason.into(),
                        );
                        driver.commit(false)?;
                    }
                    break;
                }
                // A requested stop wins before a pass starts. Scoped
                // startup honors it above; PID/System have no collection
                // control to latch, so the loop gates the host itself
                // (F9) and runs zero passes — the old legacy behavior
                // always ran pass 0.
                if control.is_none()
                    && let Some(cause) = clock.stop_cause()
                {
                    stop_cause.get_or_insert(cause);
                    driver.host().stop_coordinator();
                    stop_latched = true;
                    break;
                }
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
                let collected = collect_job_off_thread(job, clock.collection_tick, &mut || {
                    if let Some(lane) = lane.as_mut() {
                        lane.collecting_tick();
                    }
                    driver.on_native_service(
                        lane.as_mut()
                            .map(|lane| &mut lane.capture as &mut dyn CaptureLane<Pin>),
                    );
                    driver.on_tick();
                    if let Some(control) = &control {
                        latch_collection_stop(control, clock);
                    }
                });
                if let Some(control) = &control {
                    latch_collection_stop(control, clock);
                }
                // A tick may have started a publication during collection.
                // Keep this exact returned value before apply/native hooks;
                // cancellation cannot turn its original pins into a discard.
                if driver.publication_pending() {
                    match wait_for_publication(
                        driver,
                        &mut lane,
                        clock,
                        control.as_ref(),
                        false,
                        true,
                    ) {
                        Ok(PublicationWait::Published) => {}
                        Ok(PublicationWait::Stopped(cause)) => {
                            stop_cause.get_or_insert(cause);
                            retained_pass = Some((
                                RetainedPass::Collected {
                                    collected,
                                    scan_now_ns: now,
                                },
                                control,
                            ));
                            return Ok(());
                        }
                        Err(error) => {
                            retained_block = Some(RetainedBlock::Publication);
                            retained_pass = Some((
                                RetainedPass::Collected {
                                    collected,
                                    scan_now_ns: now,
                                },
                                control,
                            ));
                            return Err(error);
                        }
                    }
                }
                if control.is_none()
                    && let Some(cause) = clock.stop_cause()
                {
                    // The stop landed mid-pass: gate the host before
                    // apply/commit, so nothing collected after the stop is
                    // applied, attached, or minted a successor (F9). The
                    // owned stop drain still runs after the loop. The
                    // completed collection is discarded; the diagnostic
                    // counts it when no pass completed.
                    stop_cause.get_or_insert(cause);
                    discarded_collections += 1;
                    driver.host().stop_coordinator();
                    stop_latched = true;
                    break;
                }
                let mut report = match lane.as_mut() {
                    Some(lane) => driver.apply(collected, lane.identity(), now)?,
                    None => driver.apply(collected, &mut ScanOnlyIdentity, now)?,
                };
                // A stop that landed during apply latches before the
                // pass's native half: the already-applied owned drain
                // still stages and commits below, but no NEW target
                // extension or successor admission starts after it (F9).
                let stopped_in_apply = control.is_none() && clock.stop_requested();
                if stopped_in_apply {
                    driver.host().stop_coordinator();
                    stop_latched = true;
                }
                if let Some(lane) = lane.as_mut() {
                    report.events.extend(if control.is_some() {
                        lane.before_cgroup_commit(driver.host())
                    } else if stopped_in_apply {
                        lane.after_pass_stopped(driver.host())
                    } else {
                        lane.after_pass(driver.host())
                    });
                }
                if let Some(control) = &control {
                    latch_collection_stop(control, clock);
                }
                match wait_for_publication(
                    driver,
                    &mut lane,
                    clock,
                    control.as_ref(),
                    report.engine_changed,
                    false,
                ) {
                    Ok(PublicationWait::Published) => {}
                    Ok(PublicationWait::Stopped(cause)) => {
                        stop_cause.get_or_insert(cause);
                        retained_pass = Some((
                            RetainedPass::Applied {
                                report,
                                phase: AppliedPassPhase::FirstCommit,
                            },
                            control,
                        ));
                        return Ok(());
                    }
                    Err(error) => {
                        retained_block = Some(RetainedBlock::Publication);
                        retained_pass = Some((
                            RetainedPass::Applied {
                                report,
                                phase: AppliedPassPhase::FirstCommitAttempted,
                            },
                            control,
                        ));
                        return Err(error);
                    }
                }
                if let Some(scoped_control) = &control {
                    // First publication is complete, independent of any
                    // readiness flag. A failing completion may already have
                    // moved cgroup ownership and mutated the original report.
                    // Record that once-only boundary explicitly and return
                    // the same owner; never retry it or enter legacy stop.
                    if let Err(error) = driver.finish_pass(&mut report) {
                        retained_block = Some(RetainedBlock::ScopedCompletion);
                        retained_pass = Some((
                            RetainedPass::Applied {
                                report,
                                phase: AppliedPassPhase::ScopedCompletionFailed,
                            },
                            control,
                        ));
                        return Err(error);
                    }
                    if !latch_collection_stop(scoped_control, clock)
                        && let Some(lane) = lane.as_mut()
                    {
                        report
                            .events
                            .extend(lane.after_cgroup_commit(driver.host()));
                    }
                    // No pending scoped transaction remains here. This commits
                    // delayed receipt/native facts without rerunning collection.
                    match wait_for_publication(
                        driver,
                        &mut lane,
                        clock,
                        control.as_ref(),
                        false,
                        false,
                    ) {
                        Ok(PublicationWait::Published) => {}
                        Ok(PublicationWait::Stopped(cause)) => {
                            stop_cause.get_or_insert(cause);
                            retained_pass = Some((
                                RetainedPass::Applied {
                                    report,
                                    phase: AppliedPassPhase::ScopedReceipts,
                                },
                                control,
                            ));
                            return Ok(());
                        }
                        Err(error) => {
                            retained_block = Some(RetainedBlock::Publication);
                            retained_pass = Some((
                                RetainedPass::Applied {
                                    report,
                                    phase: AppliedPassPhase::ScopedReceiptsAttempted,
                                },
                                control,
                            ));
                            return Err(error);
                        }
                    }
                }
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
                if stopped_in_apply {
                    // The applied pass published; the latched stop ends
                    // the run before any new sleep, tick, or pass work.
                    // The owned stop drain still runs after the loop.
                    break;
                }
                rescan = lane.as_mut().is_some_and(NativeLane::take_recovery_rescan);
                let next = if rescan {
                    Instant::now()
                } else {
                    Instant::now() + clock.interval
                };
                let mut schedule = TickSchedule::starting(Instant::now(), clock.tick);
                let mut cancelled_in_sleep = false;
                loop {
                    // A pending publication also wins over deadline/stop
                    // escapes. There is no new report to own at this point.
                    if driver.publication_pending() {
                        match wait_for_publication(
                            driver,
                            &mut lane,
                            clock,
                            control.as_ref(),
                            false,
                            true,
                        ) {
                            Ok(PublicationWait::Published) => {}
                            Ok(PublicationWait::Stopped(cause)) => {
                                stop_cause.get_or_insert(cause);
                                retained_pass = Some((RetainedPass::BeforeCollection, control));
                                return Ok(());
                            }
                            Err(error) => {
                                retained_block = Some(RetainedBlock::Publication);
                                retained_pass = Some((RetainedPass::BeforeCollection, control));
                                return Err(error);
                            }
                        }
                    }
                    let now = Instant::now();
                    if clock.ending()
                        || now >= next
                        || control
                            .as_ref()
                            .is_some_and(|control| control.check().is_err())
                    {
                        break;
                    }
                    std::thread::sleep(schedule.wait(now).min(next - now));
                    // A stop that landed during the sleep latches before
                    // the tick: no tick work stages on an unstopped host
                    // after cancellation (F9). The owned stop drain still
                    // runs after the loop.
                    if control.is_none() && clock.stop_requested() {
                        driver.host().stop_coordinator();
                        stop_latched = true;
                        cancelled_in_sleep = true;
                        break;
                    }
                    // The ring first, then the display; the schedule is fixed-rate,
                    // so the draw never delays the next ring service.
                    if let Some(lane) = lane.as_mut() {
                        lane.tick(driver.host());
                    }
                    driver.on_native_service(
                        lane.as_mut()
                            .map(|lane| &mut lane.capture as &mut dyn CaptureLane<Pin>),
                    );
                    driver.on_tick();
                    // This is the actual between-pass producer of Pending.
                    // Do not run another native staging tick or leave through
                    // a clock/control stop before returning its same owner.
                    if driver.publication_pending() {
                        match wait_for_publication(
                            driver,
                            &mut lane,
                            clock,
                            control.as_ref(),
                            false,
                            true,
                        ) {
                            Ok(PublicationWait::Published) => {}
                            Ok(PublicationWait::Stopped(cause)) => {
                                stop_cause.get_or_insert(cause);
                                retained_pass = Some((RetainedPass::BeforeCollection, control));
                                return Ok(());
                            }
                            Err(error) => {
                                retained_block = Some(RetainedBlock::Publication);
                                retained_pass = Some((RetainedPass::BeforeCollection, control));
                                return Err(error);
                            }
                        }
                    }
                    if let Some(control) = &control {
                        latch_collection_stop(control, clock);
                    }
                    schedule.advance(Instant::now());
                }
                if cancelled_in_sleep {
                    break;
                }
            }
            Ok(())
        })(),
    };
    let mut error = running.err();
    if let Some((pass, control)) = retained_pass {
        // Gate only. The old on_stop_requested callback starts terminal I/O,
        // and stop_after_error performs a fresh drain/commit. Neither can
        // consume this unfinished pass. The caller must keep its SAME
        // driver/coordinator with every original owner returned here.
        driver.on_publication_suspended();
        if !stop_latched {
            driver.host().stop_coordinator();
        }
        return ClassicOutcome {
            stopped: None,
            error,
            zero_pass: None,
            retained: Some(RetainedClassicRun {
                block: retained_block.or(match &pass {
                    RetainedPass::Collected { .. } => Some(RetainedBlock::Collected),
                    RetainedPass::Applied {
                        phase: AppliedPassPhase::ScopedCompletionFailed,
                        ..
                    } => Some(RetainedBlock::ScopedCompletion),
                    _ => None,
                }),
                pass,
                native: lane.map(RetainedNative::Live),
                control,
                completed_passes: passes,
                discarded_collections,
                elapsed: loop_start.elapsed(),
                stop_cause,
                host_stopped: true,
                terminal_callback_error: None,
                loop_started_at: loop_start,
                service: RetainedServiceCursor::Poll,
                terminal_zero_pass: None,
            }),
        };
    }
    if let Some(error) = &error {
        driver
            .host()
            .note_scope_gap("inventory capture failed".into(), format!("{error:#}"));
    }
    // The loop ended: gate promptly, before any (possibly slow)
    // retirement. A scan run gates too: a refused native lane never
    // implies a refused semantic lane elsewhere.
    driver.on_stop_requested();
    // The host gate runs with the driver's: terminal EXEC records retire
    // without minting successors, while terminal staging still drains.
    // A PID/System stop already latched in-loop stays single: the loop
    // stops its host exactly once per run.
    if !stop_latched {
        driver.host().stop_coordinator();
    }
    // A silent F9 zero-pass stop now reads as what it is: one scope gap
    // here plus one stderr line from the outcome at the finalizer — both
    // informational, exit 0 and schemas unchanged. Error runs keep only
    // their failure gap, and a trailing discard after published passes
    // stays silent. Covers the scan-only return below and both
    // cancelled-startup branches (scoped reads the control's sticky
    // latch; the stop callback itself is never re-queried).
    let zero_pass = if error.is_none() && passes == 0 {
        let elapsed = loop_start.elapsed();
        if stop_latched {
            stop_cause.map(|cause| ZeroPassStop {
                cause,
                discarded: discarded_collections,
                elapsed,
            })
        } else if let Some(control) = driver.collection_control()
            && let Err(stop) = control.check()
        {
            Some(ZeroPassStop {
                cause: match stop {
                    crate::scope::inventory_cgroup::CollectionStop::OperatorStop => {
                        ZeroPassCause::OperatorStop
                    }
                    crate::scope::inventory_cgroup::CollectionStop::Deadline => {
                        ZeroPassCause::Deadline
                    }
                },
                discarded: discarded_collections,
                elapsed,
            })
        } else {
            None
        }
    } else {
        None
    };
    if let Some(zero) = &zero_pass {
        driver
            .host()
            .note_scope_gap(ZERO_PASS_GAP_SUBJECT.into(), zero.gap_reason());
    }
    let Some(lane) = lane else {
        // Publish the failure gap (or the zero-pass diagnostic gap)
        // without repeating the failed scan/pass. A failed publication
        // commit must not turn the informational diagnostic into a run
        // failure: exit 0 is preserved.
        if error.is_some() || zero_pass.is_some() {
            let _ = driver.commit(false);
        }
        if zero_pass.is_some() {
            // Terminal accounting for the diagnostic gap: it streams
            // under this final marker (zero scan counts, `final: true`),
            // so `new_gaps` still sums to every streamed gap without
            // claiming a completed pass. Best-effort like the commit
            // above: a failed terminal publication must not flip
            // F9-success exit 0. Error runs keep their markerless shape.
            let _ = publish(
                driver,
                Publish::Stop {
                    events: &[],
                    now_ns: now_ns(),
                },
            );
        }
        return ClassicOutcome {
            stopped: None,
            error,
            zero_pass,
            retained: None,
        };
    };
    if let Err(next) = publish(
        driver,
        Publish::Retiring {
            attached: lane.attached,
            links: lane.retirement_load().links,
            budget: lane.windows.retirement_budget(lane.retirement_load()),
        },
    ) {
        if error.is_none() {
            driver
                .host()
                .note_scope_gap("inventory capture failed".into(), format!("{next:#}"));
        }
        error.get_or_insert(next);
    }
    let stopped = if error.is_some() {
        lane.stop_after_error(driver.host())
    } else if lane.passes == 0
        && let Some(control) = driver.collection_control()
        && control.check().is_err()
    {
        lane.stop_cancelled_scoped_startup(driver.host(), &control)
    } else if lane.passes == 0 && stop_latched {
        lane.stop_cancelled_unscoped_startup(driver.host())
    } else {
        lane.stop(driver.host())
    };
    // The driver's own terminal evidence finalizes before the commit
    // below publishes it beside the lane's stop.
    driver.on_lane_stopped();
    if let Err(next) = driver.commit(false) {
        error.get_or_insert(next);
    }
    if let Err(next) = publish(
        driver,
        Publish::Stop {
            events: &stopped.events,
            now_ns: now_ns(),
        },
    ) {
        error.get_or_insert(next);
    }
    ClassicOutcome {
        stopped: Some(stopped),
        error,
        zero_pass,
        retained: None,
    }
}

fn latch_collection_stop(control: &CollectionControl, clock: &LoopClock<'_>) -> bool {
    if (clock.stop)() {
        control.cancel();
    }
    control.check().is_err()
}

/// The production lane: the owned facade across its typestates.
pub(crate) struct FacadeLane {
    domain: NativeDomainId,
    scope_coverage: CaptureScopeCoverage,
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
        let (capture, backend) = prepare_scoped_on_backend(
            selection,
            &scope,
            |probe| match probe {
                MultiScopeProbe::General => multi_functional_probe(),
                MultiScopeProbe::PidFilter => crate::attach::kernel_multi_pid_filter(),
            },
            |attempt, backend| InventoryCapture::prepare(attempt, endpoints, callers, backend),
        )?;
        Ok(Self {
            domain: capture.domain(),
            scope_coverage: capture.scope_coverage(),
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

    fn observe_caller_image(
        &mut self,
        original: &std::sync::Arc<PidPin>,
        window: ReadWindow,
    ) -> Result<crate::attach::capture::CallerImageObservation> {
        match &mut self.state {
            FacadeState::Active(capture) => capture.observe_caller_image(original, window),
            _ => Err(anyhow!("caller image observation unavailable")),
        }
    }

    fn query_promotion_baselines(
        &mut self,
        capture_id: crate::inventory_promotion::CaptureId,
        presentation: std::sync::Arc<crate::inventory_present::Presentation>,
        targets: &[crate::attach::selected_detailed::baseline::BaselineTarget],
        window: ReadWindow,
        reserve: &mut dyn FnMut(
            usize,
        ) -> std::result::Result<
            crate::semantics_edge::resources::ResourceLease,
            crate::semantics_edge::resources::SemanticResourceRefusal,
        >,
    ) -> Result<crate::attach::selected_detailed::baseline::PromotionBaselineBatch> {
        match &mut self.state {
            FacadeState::Active(capture) => capture.query_promotion_baselines(
                capture_id,
                presentation,
                targets,
                window,
                reserve,
            ),
            _ => Err(anyhow!("promotion baselines unavailable")),
        }
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

    fn scope_coverage(&self) -> CaptureScopeCoverage {
        self.scope_coverage
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

/// Process-lifetime retention for the typed process-exit path: the owner
/// is leaked, so no destructor runs and no close or join is attempted.
pub(crate) struct ExitRetention;

impl ExitRetention {
    pub(crate) fn hold<T>(owner: T) {
        std::mem::forget(owner)
    }
}

/// How the run's end released the stopped native owner.
#[derive(Clone, Copy)]
pub(crate) enum ExitRelease {
    #[cfg_attr(not(test), allow(dead_code))] // Production reclaims once disposal proves a close.
    Reclaimed,
    RetainedForExit,
}

/// The run's end after the stop (R-C51-4): `write` attempts final outputs
/// (stream end, `-o`, stdout) first; then `outputs_attempted` arms the
/// immediate exit on a second signal; only then does an unsettled
/// retirement reach `release`, between two progress lines. A reclaimed
/// owner keeps the blocking detach; a retained one stays alive without
/// the closing progress line.
pub(crate) fn finish_native<L, T>(
    stopped: Option<Stopped<L>>,
    write: impl FnOnce(Option<&LaneSummary>) -> T,
    outputs_attempted: &dyn Fn(),
    progress: &mut dyn FnMut(String),
    release: impl FnOnce(Stopped<L>) -> ExitRelease,
) -> T {
    let result = write(stopped.as_ref().map(|stopped| &stopped.summary));
    outputs_attempted();
    if let Some(stopped) = stopped
        && let Retirement::Unsettled(_) = stopped.summary.retirement
    {
        progress(format!(
            "p11scope: output attempts finished; detaching the remaining native probes of {} \
             endpoints (a second SIGINT/SIGTERM exits at once)",
            stopped.summary.attached
        ));
        if matches!(release(stopped), ExitRelease::Reclaimed) {
            progress("p11scope: native probes detached".into());
        }
    }
    result
}

#[cfg(test)]
#[path = "inventory_capture_tests.rs"]
pub(crate) mod tests;

/// Finding 9: a PID/System stop (no collection control) latches the host
/// gate before any new apply/commit work — zero passes when pre-requested,
/// no apply/commit when it lands mid-pass — while the owned stop drain
/// still runs and the host still stops exactly once.
#[cfg(test)]
mod stop_latch_tests {
    use super::*;
    use crate::attach::capture::{CaptureHealth, CapturePhase, ExecCoverage};
    use crate::discovery::identity::RetainedInventoryTarget;
    use crate::discovery::inventory_attach_set::AttachObjectId;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct F9Pin;
    struct F9Targets;
    impl CaptureTargets for F9Targets {
        fn target(&self, _object: AttachObjectId) -> Option<&RetainedInventoryTarget> {
            None
        }
    }

    struct F9Host {
        stops: usize,
        stages: usize,
        targets: F9Targets,
        stop_calls: Option<Rc<Cell<u64>>>,
        stage_marks: Vec<(u64, usize)>,
        gaps: Vec<(String, String)>,
    }
    impl F9Host {
        fn new() -> Self {
            Self {
                stops: 0,
                stages: 0,
                targets: F9Targets,
                stop_calls: None,
                stage_marks: Vec::new(),
                gaps: Vec::new(),
            }
        }
    }
    impl LaneHost<F9Pin> for F9Host {
        fn begin_capture_coverage(&mut self, _scope: CaptureScopeCoverage) {}
        fn abandon_capture_coverage(&mut self) {}
        fn note_extend_receipt(&mut self, _receipt: &ExtendReceipt) {}
        fn note_capture_custody(&mut self, _custody: &ScopeCustody) {}
        fn take_target_delta(&mut self) -> TargetDelta {
            TargetDelta::default()
        }
        fn capture_targets(&self) -> &dyn CaptureTargets {
            &self.targets
        }
        fn stage_native(
            &mut self,
            _batch: NativeBatch,
            _identity: &mut dyn NativeIdentity<F9Pin>,
            _now_ns: u64,
        ) -> NativeReceipt {
            self.stages += 1;
            let calls = self.stop_calls.as_ref().map_or(0, |calls| calls.get());
            self.stage_marks.push((calls, self.stops));
            NativeReceipt::default()
        }
        fn end_capture_coverage(&mut self, _at_ns: u64) {}
        fn note_native_lane(&mut self) {}
        fn note_scope_gap(&mut self, subject: String, reason: String) {
            self.gaps.push((subject, reason));
        }
        fn note_refresh_loss(&mut self, _reason: String) {}
        fn stop_coordinator(&mut self) {
            self.stops += 1;
        }
    }

    struct F9Driver {
        host: F9Host,
        collects: usize,
        applies: usize,
        commits: usize,
        applied: Rc<Cell<usize>>,
        arm_stop_on_collect: Option<Rc<Cell<bool>>>,
        /// Runs first inside the worker collection (which joins before
        /// the loop's post-collection gate), so a test can advance its
        /// controlled clock deterministically mid-collection.
        on_collect: Option<Arc<dyn Fn() + Send + Sync>>,
        /// Mirrors `collects` for stop closures that arm on a later pass.
        collect_count: Option<Rc<Cell<usize>>>,
    }
    impl F9Driver {
        fn new() -> Self {
            Self {
                host: F9Host::new(),
                collects: 0,
                applies: 0,
                commits: 0,
                applied: Rc::new(Cell::new(0)),
                arm_stop_on_collect: None,
                on_collect: None,
                collect_count: None,
            }
        }
        fn report(&self) -> PassReport {
            PassReport {
                pass: self.applies as u64,
                scanned: 0,
                maps_matched: 0,
                native_callers: 0,
                scan_callers: 0,
                engine_changed: false,
                pending_refresh: Vec::new(),
                events: Vec::new(),
                timings: crate::timing::StageTimings::new(),
            }
        }
    }
    impl PassDriver<F9Pin> for F9Driver {
        type Host = F9Host;
        fn host(&mut self) -> &mut F9Host {
            &mut self.host
        }
        fn collector(&mut self) -> CollectJob {
            self.collects += 1;
            if let Some(count) = &self.collect_count {
                count.set(self.collects);
            }
            if let Some(arm) = &self.arm_stop_on_collect {
                arm.set(true);
            }
            let on_collect = self.on_collect.clone();
            CollectJob::Legacy(Box::new(move || {
                if let Some(hook) = &on_collect {
                    hook();
                }
                Err(anyhow!("no collection in the stop-latch probe"))
            }))
        }
        fn apply(
            &mut self,
            _collected: CollectedPass,
            _identity: &mut dyn NativeIdentity<F9Pin>,
            _now_ns: u64,
        ) -> Result<PassReport> {
            self.applies += 1;
            self.applied.set(self.applies);
            Ok(self.report())
        }
        fn commit(&mut self, _engine_changed: bool) -> Result<()> {
            self.commits += 1;
            Ok(())
        }
    }

    struct F9Lane {
        domain: NativeDomainId,
        activated: bool,
        begin_stops: usize,
        extends: usize,
    }
    impl F9Lane {
        fn new() -> Self {
            Self {
                domain: NativeDomainId::mint(),
                activated: false,
                begin_stops: 0,
                extends: 0,
            }
        }
    }
    impl NativeIdentity<F9Pin> for F9Lane {
        fn owner_image(&mut self, _pid: u32) -> Option<ImageIdentity> {
            None
        }
        fn query_cookie(&mut self, _domain: NativeDomainId, _pin: &F9Pin) -> CookieQuery {
            CookieQuery::NoCookie
        }
    }
    impl CaptureLane<F9Pin> for F9Lane {
        fn domain(&self) -> NativeDomainId {
            self.domain
        }
        fn scope_coverage(&self) -> CaptureScopeCoverage {
            CaptureScopeCoverage::System
        }
        fn extend(
            &mut self,
            _delta: TargetDelta,
            _targets: &dyn CaptureTargets,
            _window: ExtendWindow,
        ) -> ExtendReceipt {
            self.extends += 1;
            let mut receipt = ExtendReceipt {
                custody: Some(ScopeCustody::System),
                ..ExtendReceipt::default()
            };
            if !self.activated {
                self.activated = true;
                receipt.activated_roots = true;
                receipt.exec_coverage = Some(ExecCoverage::scripted(self.domain, now_ns()));
            }
            receipt
        }
        fn service_discovery(&mut self, _window: ReadWindow) -> DiscoveryBatch {
            DiscoveryBatch::scripted(self.domain, Vec::new(), now_ns())
        }
        fn read_witnesses(&mut self, _window: ReadWindow) -> WitnessBatch {
            let stamp = now_ns();
            WitnessBatch {
                domain: self.domain,
                phase: CapturePhase::Active,
                rows: Vec::new(),
                integrity: Vec::new(),
                integrity_total: 0,
                visited: 0,
                sweep_completed: true,
                sweeps_completed: 1,
                row_bound_reached: false,
                deadline_reached: false,
                read_failures: Vec::new(),
                unrecorded_rows: 0,
                sweep_gaps: false,
                counts: Vec::new(),
                refresh_sweep_completed: true,
                refresh_sweep_gaps: false,
                refresh_deadline_reached: false,
                refresh_sweeps_completed: 1,
                seen_rows: 0,
                pair_limit: 64,
                lifecycle_loss: None,
                lifecycle_proven_ns: 0,
                health: CaptureHealth::default(),
                health_regression: None,
                health_unproven: None,
                health_baseline_ns: 0,
                health_read_ns: stamp,
                rows_anchor_ns: stamp,
                rows_read_ns: stamp,
                counts_read_ns: stamp,
                changed_objects: Vec::new(),
                custody: ScopeCustody::System,
                custody_proven_ns: None,
                unsettled: false,
            }
        }
        fn begin_stop(&mut self) {
            self.begin_stops += 1;
        }
        fn poll_retirement(&mut self, _deadline: Instant) -> Result<bool> {
            Ok(true)
        }
        fn cleanup(&self) -> Option<CleanupSummary> {
            None
        }
    }

    fn probe_clock(stop: &dyn Fn() -> bool) -> LoopClock<'_> {
        LoopClock {
            deadline: None,
            stop,
            now: &Instant::now,
            interval: Duration::from_secs(60),
            tick: Duration::from_millis(10),
            collection_tick: Duration::from_millis(10),
        }
    }

    #[test]
    fn pre_requested_stop_reports_zero_passes_under_a_terminal_marker() {
        let mut driver = F9Driver::new();
        let stop = || true;
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none());
        assert!(outcome.stopped.is_none());
        assert_eq!(driver.collects, 0, "no new scan after a pre-requested stop");
        assert_eq!(
            driver.applies, 0,
            "no apply, so no attach or successor work"
        );
        assert_eq!(
            driver.commits, 1,
            "only the zero-pass diagnostic gap publishes"
        );
        assert_eq!(pass_publications, 0, "no pass was published");
        assert_eq!(
            stop_publications, 1,
            "the diagnostic gap streams under one terminal marker"
        );
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
    }

    #[test]
    fn mid_pass_stop_discards_the_collection_under_a_terminal_marker() {
        let mut driver = F9Driver::new();
        let stop_flag = Rc::new(Cell::new(false));
        driver.arm_stop_on_collect = Some(Rc::clone(&stop_flag));
        let stop = || stop_flag.get();
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none());
        assert!(outcome.stopped.is_none());
        assert_eq!(driver.collects, 1, "the in-flight collection already ran");
        assert_eq!(
            driver.applies, 0,
            "no apply after the stop, so no successor is minted"
        );
        assert_eq!(
            driver.commits, 1,
            "only the zero-pass diagnostic gap publishes"
        );
        assert_eq!(pass_publications, 0, "no pass was published");
        assert_eq!(
            stop_publications, 1,
            "the diagnostic gap streams under one terminal marker"
        );
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
    }

    #[test]
    fn stop_after_a_completed_pass_still_stops_the_host_exactly_once() {
        let mut driver = F9Driver::new();
        let applied = Rc::clone(&driver.applied);
        let stop = move || applied.get() >= 1;
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none());
        assert!(outcome.stopped.is_none());
        assert_eq!(driver.applies, 1, "the completed pass still applies");
        assert_eq!(driver.commits, 1, "the completed pass still commits");
        assert_eq!(pass_publications, 1, "the completed pass is published");
        assert_eq!(
            stop_publications, 0,
            "a completed scan pass needs no terminal marker"
        );
        assert_eq!(driver.host.stops, 1, "the host stops exactly once");
    }

    #[test]
    fn pre_requested_stop_with_a_lane_drains_without_a_pass() {
        let mut driver = F9Driver::new();
        let started =
            NativeLane::start(F9Lane::new(), driver.host(), LaneWindows::PROVISIONAL, None)
                .map_err(|(_, reason)| reason)
                .unwrap();
        let stop = || true;
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome =
            run_classic_finalizing(&mut driver, Some(started), &clock, None, &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            });
        assert!(outcome.error.is_none());
        let stopped = outcome.stopped.expect("the owned stop still drains");
        assert_eq!(stopped.summary.passes, 0);
        assert_eq!(driver.collects, 0, "no new scan after a pre-requested stop");
        assert_eq!(
            driver.applies, 0,
            "no apply, so no attach or successor work"
        );
        assert_eq!(driver.commits, 1, "only the stop's terminal commit runs");
        assert_eq!(pass_publications, 0, "no pass was published");
        assert_eq!(stop_publications, 1, "the stop still publishes");
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
        assert!(driver.host.stages > 0, "the terminal sweep still stages");
        assert_eq!(stopped.capture.begin_stops, 1, "retirement still begins");
    }

    #[test]
    fn mid_first_pass_stop_with_a_lane_drains_without_apply() {
        let mut driver = F9Driver::new();
        let started =
            NativeLane::start(F9Lane::new(), driver.host(), LaneWindows::PROVISIONAL, None)
                .map_err(|(_, reason)| reason)
                .unwrap();
        let stop_flag = Rc::new(Cell::new(false));
        driver.arm_stop_on_collect = Some(Rc::clone(&stop_flag));
        let stop = || stop_flag.get();
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let outcome =
            run_classic_finalizing(&mut driver, Some(started), &clock, None, &mut |_, point| {
                if matches!(point, Publish::Pass { .. }) {
                    pass_publications += 1;
                }
                Ok(())
            });
        assert!(outcome.error.is_none());
        let stopped = outcome.stopped.expect("the owned stop still drains");
        assert_eq!(stopped.summary.passes, 0);
        assert_eq!(driver.collects, 1, "the in-flight collection already ran");
        assert_eq!(
            driver.applies, 0,
            "no apply after the stop, so no successor is minted"
        );
        assert_eq!(driver.commits, 1, "only the stop's terminal commit runs");
        assert_eq!(pass_publications, 0, "no pass was published");
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
        assert!(driver.host.stages > 0, "the terminal sweep still stages");
        assert_eq!(stopped.capture.begin_stops, 1, "retirement still begins");
    }

    #[test]
    fn passed_deadline_reports_zero_passes_under_a_terminal_marker() {
        let mut driver = F9Driver::new();
        let stop = || false;
        let clock = LoopClock {
            deadline: Some(Instant::now() - Duration::from_secs(1)),
            stop: &stop,
            now: &Instant::now,
            interval: Duration::from_secs(60),
            tick: Duration::from_millis(10),
            collection_tick: Duration::from_millis(10),
        };
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none());
        assert!(outcome.stopped.is_none());
        assert_eq!(driver.collects, 0, "no new scan after a passed deadline");
        assert_eq!(
            driver.applies, 0,
            "no apply, so no attach or successor work"
        );
        assert_eq!(
            driver.commits, 1,
            "only the zero-pass diagnostic gap publishes"
        );
        assert_eq!(pass_publications, 0, "no pass was published");
        assert_eq!(
            stop_publications, 1,
            "the diagnostic gap streams under one terminal marker"
        );
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
    }

    #[test]
    fn stop_during_apply_skips_target_extension_but_commits_applied_data() {
        let mut driver = F9Driver::new();
        let started =
            NativeLane::start(F9Lane::new(), driver.host(), LaneWindows::PROVISIONAL, None)
                .map_err(|(_, reason)| reason)
                .unwrap();
        let applied = Rc::clone(&driver.applied);
        let stop = move || applied.get() >= 1;
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let outcome =
            run_classic_finalizing(&mut driver, Some(started), &clock, None, &mut |_, point| {
                if matches!(point, Publish::Pass { .. }) {
                    pass_publications += 1;
                }
                Ok(())
            });
        assert!(outcome.error.is_none());
        let stopped = outcome.stopped.expect("the owned stop still drains");
        assert_eq!(driver.applies, 1, "the in-flight apply already ran");
        assert_eq!(
            driver.commits, 2,
            "the applied pass commits, then the stop's terminal commit runs"
        );
        assert_eq!(pass_publications, 1, "the completed pass is published");
        assert_eq!(
            stopped.capture.extends, 1,
            "only the startup extend runs: no new target extension starts after the stop"
        );
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
        assert!(driver.host.stages > 0, "the terminal sweep still stages");
        assert_eq!(stopped.capture.begin_stops, 1, "retirement still begins");
    }

    #[test]
    fn sleep_cancellation_latches_before_tick_work() {
        // The stop flips deterministically mid-sleep: the first pass
        // makes four stop() calls before its first sleep can end
        // (pass-top gate, post-collection gate, post-apply gate, first
        // sleep-top check), so a stop that reads true from the fifth
        // call lands during a sleep on every run. A tick that stages
        // while the stop is pending mints successors on an unstopped
        // host.
        const FLIP_AFTER: u64 = 4;
        let mut driver = F9Driver::new();
        let calls = Rc::new(Cell::new(0u64));
        driver.host.stop_calls = Some(Rc::clone(&calls));
        let started =
            NativeLane::start(F9Lane::new(), driver.host(), LaneWindows::PROVISIONAL, None)
                .map_err(|(_, reason)| reason)
                .unwrap();
        let stop_calls = Rc::clone(&calls);
        let stop = move || {
            let next = stop_calls.get() + 1;
            stop_calls.set(next);
            next > FLIP_AFTER
        };
        let clock = LoopClock {
            deadline: Some(Instant::now() + Duration::from_secs(60)),
            stop: &stop,
            now: &Instant::now,
            interval: Duration::from_secs(60),
            tick: Duration::from_millis(1),
            collection_tick: Duration::from_millis(10),
        };
        let mut pass_publications = 0;
        let outcome =
            run_classic_finalizing(&mut driver, Some(started), &clock, None, &mut |_, point| {
                if matches!(point, Publish::Pass { .. }) {
                    pass_publications += 1;
                }
                Ok(())
            });
        assert!(outcome.error.is_none());
        let stopped = outcome.stopped.expect("the owned stop still drains");
        assert!(
            calls.get() > FLIP_AFTER,
            "the stop flipped during the run ({} calls)",
            calls.get()
        );
        assert_eq!(driver.applies, 1, "the completed pass still applies");
        assert_eq!(
            driver.commits, 2,
            "the applied pass commits, then the stop's terminal commit runs"
        );
        assert_eq!(pass_publications, 1, "the completed pass is published");
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
        assert!(
            !driver
                .host
                .stage_marks
                .iter()
                .any(|(at, stops)| *at >= FLIP_AFTER && *stops == 0),
            "no tick work stages while a stop is pending: {:?}",
            driver.host.stage_marks
        );
        assert!(
            driver.host.stage_marks.iter().any(|(_, stops)| *stops == 1),
            "the owned drain still stages after the latch: {:?}",
            driver.host.stage_marks
        );
        assert_eq!(stopped.capture.begin_stops, 1, "retirement still begins");
    }

    #[test]
    fn deadline_during_pass0_collection_reports_zero_pass_gap_and_line() {
        // The G30 shape: pass-0 collection outlasts the deadline, so the
        // completed collection is discarded with no apply — but the run
        // now says so (gap + line), still exiting 0. The loop clock is
        // controlled: it reads before the deadline until the collection
        // itself advances it past, so expiry-during-collection is
        // established by construction. The pre-pass gate runs before the
        // collector starts (program order, one thread) and the worker is
        // the clock's only writer, so the gate cannot observe expiry; the
        // worker joins before the post-collection gate, so that gate
        // always does — on every schedule, with no sleeps.
        let mut driver = F9Driver::new();
        let base = Instant::now();
        let since_base_ms = Arc::new(AtomicU64::new(0));
        driver.on_collect = Some({
            let since_base_ms = Arc::clone(&since_base_ms);
            Arc::new(move || since_base_ms.store(200, Ordering::SeqCst))
        });
        let now_ms = Arc::clone(&since_base_ms);
        let now = move || base + Duration::from_millis(now_ms.load(Ordering::SeqCst));
        let stop = || false;
        let clock = LoopClock {
            deadline: Some(base + Duration::from_millis(150)),
            stop: &stop,
            now: &now,
            interval: Duration::from_secs(60),
            tick: Duration::from_millis(10),
            collection_tick: Duration::from_millis(10),
        };
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none(), "exit 0 is preserved");
        assert!(outcome.stopped.is_none());
        assert_eq!(driver.collects, 1, "the pass-0 collection already ran");
        assert_eq!(driver.applies, 0, "no apply after the deadline");
        assert_eq!(
            driver.commits, 1,
            "only the zero-pass diagnostic gap publishes"
        );
        assert_eq!(pass_publications, 0, "no pass was published");
        assert_eq!(
            stop_publications, 1,
            "the diagnostic gap streams under one terminal marker"
        );
        assert_eq!(
            driver.host.stops, 1,
            "the latch stops the host exactly once"
        );
        let zero = outcome.zero_pass.expect("a zero-pass stop is reported");
        assert_eq!(zero.cause, ZeroPassCause::Deadline);
        assert_eq!(zero.discarded, 1);
        assert_eq!(driver.host.gaps.len(), 1, "{:?}", driver.host.gaps);
        let (subject, reason) = &driver.host.gaps[0];
        assert_eq!(subject, ZERO_PASS_GAP_SUBJECT);
        assert!(
            reason.contains("deadline exceeded during pass-0 collection"),
            "{reason:?}"
        );
        assert!(
            reason.contains("1 completed collection discarded"),
            "{reason:?}"
        );
        assert!(reason.contains("elapsed"), "{reason:?}");
        let line = zero.stderr_line();
        assert_eq!(
            line,
            "p11scope: stopped with 0 completed passes (deadline exceeded during \
             pass-0 collection; 1 completed collection discarded)"
        );
        assert!(
            !line.to_lowercase().contains("success"),
            "no success claims on stderr: {line:?}"
        );
    }

    #[test]
    fn in_budget_run_stages_no_zero_pass_gap() {
        // Snapshot shape: no deadline, no stop — the single pass completes
        // and no diagnostic fires.
        let mut driver = F9Driver::new();
        let stop = || false;
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none());
        assert_eq!(pass_publications, 1, "the snapshot pass is published");
        assert_eq!(
            stop_publications, 0,
            "a completed snapshot needs no terminal marker"
        );
        assert_eq!(driver.applies, 1);
        assert!(outcome.zero_pass.is_none(), "no zero-pass stop happened");
        assert!(driver.host.gaps.is_empty(), "{:?}", driver.host.gaps);
    }

    #[test]
    fn pre_requested_stop_reports_zero_pass_gap_with_stop_cause() {
        let mut driver = F9Driver::new();
        let stop = || true;
        let clock = probe_clock(&stop);
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none(), "exit 0 is preserved");
        assert_eq!(driver.collects, 0, "no new scan after a pre-requested stop");
        assert_eq!(driver.applies, 0);
        assert_eq!(
            driver.commits, 1,
            "only the zero-pass diagnostic gap publishes"
        );
        assert_eq!(pass_publications, 0, "no pass was published");
        assert_eq!(
            stop_publications, 1,
            "the diagnostic gap streams under one terminal marker"
        );
        let zero = outcome.zero_pass.expect("a zero-pass stop is reported");
        assert_eq!(zero.cause, ZeroPassCause::OperatorStop);
        assert_eq!(zero.discarded, 0);
        assert_eq!(
            driver.host.gaps,
            vec![(
                ZERO_PASS_GAP_SUBJECT.to_string(),
                "operator stop requested before pass 0 started; no collection ran".to_string()
            )],
        );
        assert_eq!(
            zero.stderr_line(),
            "p11scope: stopped with 0 completed passes (operator stop requested before \
             pass 0 started; no collection ran)"
        );
    }

    #[test]
    fn initial_error_keeps_only_the_failure_gap() {
        let mut driver = F9Driver::new();
        let stop = || false;
        let clock = probe_clock(&stop);
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            Some(anyhow!("started append failure")),
            &mut |_, point| {
                if matches!(point, Publish::Stop { .. }) {
                    stop_publications += 1;
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_some());
        assert_eq!(
            stop_publications, 0,
            "error runs keep their markerless shape"
        );
        assert!(outcome.zero_pass.is_none(), "errors keep no zero-pass note");
        assert_eq!(driver.host.gaps.len(), 1, "{:?}", driver.host.gaps);
        assert_eq!(driver.host.gaps[0].0, "inventory capture failed");
    }

    #[test]
    fn mid_pass_discard_after_a_published_pass_stays_silent() {
        // The ordinary trailing discard: pass 0 publishes, then the stop
        // lands during pass-1 collection. Results exist, so no gap and no
        // line — only true zero-pass runs report.
        let mut driver = F9Driver::new();
        let count = Rc::new(Cell::new(0usize));
        driver.collect_count = Some(Rc::clone(&count));
        let stop_count = Rc::clone(&count);
        let stop = move || stop_count.get() >= 2;
        let clock = LoopClock {
            deadline: Some(Instant::now() + Duration::from_secs(600)),
            stop: &stop,
            now: &Instant::now,
            interval: Duration::from_millis(1),
            tick: Duration::from_millis(1),
            collection_tick: Duration::from_millis(10),
        };
        let mut pass_publications = 0;
        let mut stop_publications = 0;
        let outcome = run_classic_finalizing(
            &mut driver,
            None::<NativeLane<F9Lane>>,
            &clock,
            None,
            &mut |_, point| {
                match point {
                    Publish::Pass { .. } => pass_publications += 1,
                    Publish::Stop { .. } => stop_publications += 1,
                    Publish::Retiring { .. } => {}
                }
                Ok(())
            },
        );
        assert!(outcome.error.is_none());
        assert_eq!(driver.collects, 2, "pass-1 collection ran, then discarded");
        assert_eq!(driver.applies, 1, "only the completed pass applies");
        assert_eq!(pass_publications, 1, "the completed pass is published");
        assert_eq!(stop_publications, 0, "a trailing discard stays silent");
        assert!(
            outcome.zero_pass.is_none(),
            "a trailing discard stays silent"
        );
        assert!(driver.host.gaps.is_empty(), "{:?}", driver.host.gaps);
        assert_eq!(driver.host.stops, 1, "the host stops exactly once");
    }
}
