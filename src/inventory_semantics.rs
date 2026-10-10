//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private authority carried from retained Inventory inputs to a Detailed lane.

use crate::attach::capture::NativeDomainId;
use crate::attach::{AttachedSemanticSet, BackendSelection, Scope, Session};
use crate::discovery::caller_registry::now_ns;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::process::PidPin;
use crate::run::{STOP_QUIESCE_BUDGET, StopState, TerminalQuiescence};
use crate::semantic_capture::{
    CurrentPartitionReceipt, CurrentReceiptRefusal, Endpoint, InvalidationScope,
    PhysicalSemanticGap, SemanticCapture, TickLimits, TickOutcome, TickReport,
};
use p11scope_ebpf_common::ImageIdentity;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Finite refusal; no private manifest or native record is rendered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticRefusal {
    ManifestInput,
    Unattested,
    IncompleteProvider,
    Attachment,
    Descriptor,
    ProviderInstanceUnproven,
    /// The lane cannot serve this operation yet: Task 5 owns Session
    /// startup and H0 driving; the Task 3 shell refuses honestly.
    Unavailable,
}

impl std::fmt::Display for SemanticRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ManifestInput => "manifest_input_refused",
            Self::Unattested => "unattested",
            Self::IncompleteProvider => "incomplete_provider",
            Self::Attachment => "semantic_attachment_refused",
            Self::Descriptor => "semantic_descriptor_refused",
            Self::ProviderInstanceUnproven => "provider_instance_unproven",
            Self::Unavailable => "semantic_unavailable",
        })
    }
}

pub(crate) use crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset;

/// Lane-staged negative facts: the accompanying negatives one owned H0
/// outcome batch carries. The cut barrier ordinal is H0-timeline evidence
/// (allocated by H0's checked counter after all issued positions), never
/// caller-selected; tests script it exactly as H2 scripts positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task5 lane stages negatives.
pub(crate) enum LaneNegative {
    /// One coalesced physical cut applied before every unpublished call.
    CutBarrier { ordinal: u64 },
    /// A refused collection, recorded through the audited path.
    CollectionRefused { reason: LaneCollectionRefusal },
}

/// Finite lane-collection refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task5 lane stages negatives.
pub(crate) enum LaneCollectionRefusal {
    Backpressure,
    CollectionFailed,
}

impl LaneCollectionRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Backpressure => "backpressure",
            Self::CollectionFailed => "collection_failed",
        }
    }
}

/// One owned H0 outcome batch plus its current-partition receipts and
/// lane-staged negative facts. Move-only: private fields, no
/// Clone/Default/from_parts, redacted Debug. The lane alone constructs
/// it; the coordinator finalizer alone consumes it.
pub(crate) struct SemanticBatch {
    domain: NativeDomainId,
    outcomes: Vec<TickOutcome>,
    current: Vec<CurrentPartitionReceipt>,
    negatives: Vec<LaneNegative>,
    observed_ns: u64,
}

/// Lane negatives per batch: one cut barrier plus bounded collection
/// refusals for the quantum. H0 outcomes and receipts keep H0's own
/// capacity; the lane re-checks them defensively below.
pub(crate) const MAX_LANE_NEGATIVES: usize = 64;

impl std::fmt::Debug for SemanticBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticBatch")
            .field("outcomes", &self.outcomes.len())
            .field("current", &self.current.len())
            .field("negatives", &self.negatives.len())
            .finish_non_exhaustive()
    }
}

impl SemanticBatch {
    /// The lane's batch constructor: bounds-checked before ownership.
    pub(crate) fn from_tick_report(
        domain: NativeDomainId,
        report: TickReport,
        negatives: Vec<LaneNegative>,
        observed_ns: u64,
    ) -> Result<Self, SemanticRefusal> {
        let (outcomes, current) = report.into_parts();
        if outcomes.len() > crate::discovery::instances::MAX_INSTANCES
            || current.len() > crate::discovery::instances::MAX_INSTANCES
            || negatives.len() > MAX_LANE_NEGATIVES
        {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(Self {
            domain,
            outcomes,
            current,
            negatives,
            observed_ns,
        })
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        negatives: Vec<LaneNegative>,
        observed_ns: u64,
    ) -> Self {
        Self::from_tick_report(domain, TickReport::default(), negatives, observed_ns)
            .expect("scripted batch respects lane bounds")
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn observed_ns(&self) -> u64 {
        self.observed_ns
    }

    /// The batch's own cut fence, if any: the maximum cut-barrier
    /// ordinal the lane staged. The finalizer carries the cut's
    /// barrier into the queued ordinary quantum; tokens admitted by
    /// the finalization itself never feed it.
    pub(crate) fn cut_barrier(&self) -> Option<u64> {
        self.negatives
            .iter()
            .filter_map(|negative| match negative {
                LaneNegative::CutBarrier { ordinal } => Some(*ordinal),
                LaneNegative::CollectionRefused { .. } => None,
            })
            .max()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<TickOutcome>,
        Vec<CurrentPartitionReceipt>,
        Vec<LaneNegative>,
    ) {
        (self.outcomes, self.current, self.negatives)
    }
}

/// Validated current-partition coverage, decomposed from a receipt the
/// lane owner validated against current retained binding/router state.
/// The coverage is the conversion's registration and standing proof.
pub(crate) struct LaneCoverage {
    domain: NativeDomainId,
    image: ImageIdentity,
    endpoint: Endpoint,
    ids: Vec<crate::discovery::instances::InstanceId>,
}

impl std::fmt::Debug for LaneCoverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaneCoverage(<private>)")
    }
}

impl LaneCoverage {
    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        image: ImageIdentity,
        endpoint: Endpoint,
        ids: Vec<crate::discovery::instances::InstanceId>,
    ) -> Self {
        Self {
            domain,
            image,
            endpoint,
            ids,
        }
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }

    pub(crate) fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub(crate) fn instances(&self) -> &[crate::discovery::instances::InstanceId] {
        &self.ids
    }
}

/// One optional Detailed lane: the Session owner, H0 `SemanticCapture`
/// driver and proof-bearing batch supplier. Without a live Session (no
/// manifests, or a refused startup) every H0-driving method refuses
/// honestly and broad Inventory is preserved; only a live lane drives
/// H0 collect→audit→route, and no other `SemanticCall` producer exists.
pub(crate) struct AttestedSemanticLane {
    subset: AttestedSubset,
    domain: NativeDomainId,
    live: Option<Box<LiveLane>>,
    startup_failed: bool,
    #[cfg(test)]
    recorded_gaps: Vec<PhysicalSemanticGap>,
    #[cfg(test)]
    scripted_barrier: Option<u64>,
    #[cfg(test)]
    fail_next_cut: bool,
    /// The conversion barrier the finalizer last carried into queued
    /// calls (the cut floor plus this batch's own negatives): tests
    /// assert the fence queued calls met without forging H0 outcomes.
    #[cfg(test)]
    last_conversion_barrier: Option<u64>,
}

/// The live lane: the owned Detailed `Session` (the sole retained EVENTS
/// cursor, maps and links), its H0 `SemanticCapture` driver, the sealed
/// attachment receipt, and the terminal ownership state. Counts only;
/// no record contents ever leave the H0 path.
pub(crate) struct LiveLane {
    session: Session,
    capture: SemanticCapture,
    attached: AttachedSemanticSet,
    gated: bool,
    finished: bool,
    stop_state: StopState,
    final_drain: bool,
    ticks: u64,
    scan_refusals: u64,
    continuity_cuts: u64,
    unrouted_returns: u64,
    drained_batches: u64,
    semantic_loss: bool,
}

impl std::fmt::Debug for LiveLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveLane")
            .field("attached", &self.attached)
            .field("gated", &self.gated)
            .field("finished", &self.finished)
            .field("ticks", &self.ticks)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AttestedSemanticLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttestedSemanticLane(<retained>)")
    }
}

impl AttestedSemanticLane {
    pub(crate) fn start(
        subset: AttestedSubset,
        _scope: &Scope,
        _backend: BackendSelection,
    ) -> Result<Self, SemanticRefusal> {
        // The shell: no Detailed Session, maps, links or cursor. Live
        // startup is `start_live`; the shell refuses H0-driving work.
        if subset.plan().slots.is_empty() {
            return Err(SemanticRefusal::Unattested);
        }
        let domain = NativeDomainId::try_mint().map_err(|_| SemanticRefusal::Unavailable)?;
        Ok(Self {
            subset,
            domain,
            live: None,
            startup_failed: false,
            #[cfg(test)]
            recorded_gaps: Vec::new(),
            #[cfg(test)]
            scripted_barrier: None,
            #[cfg(test)]
            fail_next_cut: false,
            #[cfg(test)]
            last_conversion_barrier: None,
        })
    }

    /// Live startup over two subset mints from the same retained accepted
    /// sources: `attach_subset` seals the Session attachment (it is
    /// consumed by the seal), `convert_subset` stays the lane's
    /// conversion envelope. A second mint fails only when the retained
    /// inputs moved under the startup, which refuses honestly. The
    /// minted shell domain is replaced with the Session's native domain.
    pub(crate) fn start_live(
        attach_subset: AttestedSubset,
        convert_subset: AttestedSubset,
        scope: &Scope,
        backend: BackendSelection,
    ) -> Result<Self, SemanticRefusal> {
        if convert_subset.plan().slots.is_empty() {
            return Err(SemanticRefusal::Unattested);
        }
        let (session, attached) = Session::start_attested(attach_subset, scope, backend)
            .map_err(|_| SemanticRefusal::Attachment)?;
        session
            .validate_semantic_set(&attached)
            .map_err(|_| SemanticRefusal::Attachment)?;
        let domain = session
            .native_domain()
            .ok_or(SemanticRefusal::Unavailable)?;
        let capture = SemanticCapture::new(&session, TickLimits::default())
            .map_err(|_| SemanticRefusal::Unavailable)?;
        Ok(Self {
            subset: convert_subset,
            domain,
            live: Some(Box::new(LiveLane {
                session,
                capture,
                attached,
                gated: false,
                finished: false,
                stop_state: StopState::Running,
                final_drain: false,
                ticks: 0,
                scan_refusals: 0,
                continuity_cuts: 0,
                unrouted_returns: 0,
                drained_batches: 0,
                semantic_loss: false,
            })),
            startup_failed: false,
            #[cfg(test)]
            recorded_gaps: Vec::new(),
            #[cfg(test)]
            scripted_barrier: None,
            #[cfg(test)]
            fail_next_cut: false,
            #[cfg(test)]
            last_conversion_barrier: None,
        })
    }

    /// Whether live startup was attempted and refused. The shell stays
    /// for summary; it drives no H0 work.
    pub(crate) fn mark_startup_failed(&mut self) {
        self.live = None;
        self.startup_failed = true;
    }

    pub(crate) fn subset(&self) -> &AttestedSubset {
        &self.subset
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    /// Whether the lane owns a live Session and H0 driver.
    pub(crate) fn is_live(&self) -> bool {
        self.live.is_some()
    }

    /// Whether the terminal sequence finished (H0 stopped).
    pub(crate) fn is_finished(&self) -> bool {
        self.live.as_ref().is_some_and(|live| live.finished)
    }

    /// One H0 collect→audit→route quantum over the bound callers' stable
    /// custody Arcs. The only producer of lane call batches; a gated,
    /// finished or shell lane refuses instead of inventing calls.
    pub(crate) fn tick(
        &mut self,
        bindings: &[SemanticCallerBinding],
    ) -> Result<SemanticBatch, SemanticRefusal> {
        let domain = self.domain;
        let Some(live) = self.live.as_mut() else {
            return Err(SemanticRefusal::Unavailable);
        };
        if live.gated || live.finished {
            return Err(SemanticRefusal::Unavailable);
        }
        let pins: Vec<Arc<PidPin>> = bindings.iter().map(SemanticCallerBinding::pin).collect();
        let report = live
            .capture
            .tick(&mut live.session, &pins)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        live.ticks += 1;
        live.scan_refusals = live
            .scan_refusals
            .saturating_add(report.scan_refusals.len() as u64);
        live.continuity_cuts = live.capture.continuity_cuts();
        SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns())
    }

    /// One bounded no-call refresh for an unbound candidate pin through
    /// the same owned Session: the accepted scan's images come back as
    /// binding hints, still to be re-proven by the coordinator proof.
    /// The images are claims only; custody and attachment re-verify.
    pub(crate) fn refresh_candidate(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> Result<Vec<ImageIdentity>, SemanticRefusal> {
        let Some(live) = self.live.as_mut() else {
            return Err(SemanticRefusal::Unavailable);
        };
        if live.gated || live.finished {
            return Err(SemanticRefusal::Unavailable);
        }
        let report = live
            .capture
            .refresh(&mut live.session, pin, slot)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        live.scan_refusals = live
            .scan_refusals
            .saturating_add(report.scan_refusals.len() as u64);
        Ok(report
            .current()
            .iter()
            .map(|receipt| receipt.image())
            .collect())
    }

    pub(crate) fn apply_physical_gaps(
        &mut self,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        if let Some(live) = self.live.as_mut() {
            let domain = self.domain;
            if live.finished {
                return Err(SemanticRefusal::Unavailable);
            }
            let report = live
                .capture
                .apply_physical_gaps(&mut live.session, gaps)
                .map_err(|_| SemanticRefusal::Unavailable)?;
            live.continuity_cuts = live.capture.continuity_cuts();
            // The cut's barrier is H0-timeline evidence: the maximum
            // fault-era position this publication allocated, after all
            // issued records. The finalizer carries it into the queued
            // ordinary quantum.
            let barrier = report
                .outcomes()
                .iter()
                .filter_map(|outcome| match outcome {
                    TickOutcome::Invalidation(invalidation)
                        if matches!(invalidation.scope(), InvalidationScope::FaultEra) =>
                    {
                        invalidation.position()
                    }
                    _ => None,
                })
                .max();
            let negatives = barrier
                .map(|ordinal| vec![LaneNegative::CutBarrier { ordinal }])
                .unwrap_or_default();
            return SemanticBatch::from_tick_report(domain, report, negatives, now_ns());
        }
        self.apply_physical_gaps_shell(gaps)
    }

    /// The shell cut: records adjudication for tests without a Session.
    /// Production without a live lane refuses, and the finalizer treats
    /// the refusal as a cut failure, preserving broad Inventory.
    fn apply_physical_gaps_shell(
        &mut self,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        #[cfg(not(test))]
        {
            let _ = gaps;
            Err(SemanticRefusal::Unavailable)
        }
        #[cfg(test)]
        {
            if self.fail_next_cut {
                self.fail_next_cut = false;
                self.recorded_gaps.extend(gaps);
                return Err(SemanticRefusal::Unavailable);
            }
            self.recorded_gaps.extend(gaps);
            let mut negatives = Vec::new();
            if let Some(ordinal) = self.scripted_barrier.take() {
                negatives.push(LaneNegative::CutBarrier { ordinal });
            }
            Ok(SemanticBatch::scripted(self.domain, negatives, 0))
        }
    }

    /// The actual-owner receipt validator: the live lane re-proves
    /// custody, attachment, epoch and partition against the Session's
    /// retained binding/router state through H0. The shell has no
    /// Session to re-prove through and refuses.
    pub(crate) fn validate_current(
        &mut self,
        receipt: &CurrentPartitionReceipt,
    ) -> Result<LaneCoverage, CurrentReceiptRefusal> {
        let Some(live) = self.live.as_mut() else {
            return Err(CurrentReceiptRefusal::Custody);
        };
        let mut report = TickReport::default();
        live.capture
            .validate_current(&mut live.session, receipt, &mut report)?;
        Ok(LaneCoverage {
            domain: receipt.domain(),
            image: receipt.image(),
            endpoint: receipt.endpoint(),
            ids: receipt.instances().to_vec(),
        })
    }

    /// Gaps the shell consumed, in order. Tests assert adjudication
    /// reached the lane; the gaps stay opaque.
    #[cfg(test)]
    pub(crate) fn recorded_gaps(&self) -> &[PhysicalSemanticGap] {
        &self.recorded_gaps
    }

    /// Script the next cut's barrier ordinal (test H0-timeline evidence).
    #[cfg(test)]
    pub(crate) fn script_cut_barrier(&mut self, ordinal: u64) {
        self.scripted_barrier = Some(ordinal);
    }

    /// Fail the next cut (test cut-failure handling).
    #[cfg(test)]
    pub(crate) fn fail_cut_once(&mut self) {
        self.fail_next_cut = true;
    }

    /// Drain recorded gaps (test isolation between publications).
    #[cfg(test)]
    pub(crate) fn take_recorded_gaps(&mut self) -> Vec<PhysicalSemanticGap> {
        std::mem::take(&mut self.recorded_gaps)
    }

    /// Record the conversion barrier the finalizer carried into this
    /// batch's queued calls (finalizer side only).
    #[cfg(test)]
    pub(crate) fn note_conversion_barrier(&mut self, barrier: Option<u64>) {
        self.last_conversion_barrier = barrier;
    }

    /// Drain the last conversion barrier (test isolation).
    #[cfg(test)]
    pub(crate) fn take_last_conversion_barrier(&mut self) -> Option<u64> {
        self.last_conversion_barrier.take()
    }
}

/// Bounded terminal drain quanta per owned cursor (H0's fair terminal
/// poll bound) and records per quantum (one H0 collection quantum).
pub(crate) const TERMINAL_DRAIN_QUANTA: usize = 16;
pub(crate) const TERMINAL_DRAIN_QUANTUM: usize = 1024;

/// Bound on terminal batches staged ahead of commit: one
/// [`TERMINAL_DRAIN_QUANTA`] window each for the quiesce wait and the
/// post-Q drain, plus the terminal Finish batch (always delivered last
/// by [`run_semantic_stop`]).
pub(crate) const TERMINAL_STAGED_BATCH_CAP: usize = 2 * TERMINAL_DRAIN_QUANTA + 1;

/// Bounded terminal staging for the stop sequence. The quiesce wait is
/// time-budgeted, not batch-budgeted, so a noisy producer can deliver
/// an unbounded number of batches before Q; staging them all would
/// hold an unbounded queue ahead of commit. `on_batch` feeds every
/// drained batch here instead: beyond [`TERMINAL_STAGED_BATCH_CAP`]
/// the oldest staged batch is shed (counted) so staging stays bounded
/// while the terminal Finish batch — always delivered last — survives
/// in delivery order. The caller discloses [`shed`](Self::shed)
/// through the audited gap path.
#[derive(Debug, Default)]
pub(crate) struct TerminalBatchStage {
    staged: std::collections::VecDeque<SemanticBatch>,
    shed: usize,
}

impl TerminalBatchStage {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, batch: SemanticBatch) {
        if self.staged.len() >= TERMINAL_STAGED_BATCH_CAP {
            self.staged.pop_front();
            self.shed += 1;
        }
        self.staged.push_back(batch);
    }

    /// Batches currently staged, at most [`TERMINAL_STAGED_BATCH_CAP`].
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.staged.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// Oldest batches shed beyond the cap: the caller discloses this
    /// count through the audited gap path.
    pub(crate) fn shed(&self) -> usize {
        self.shed
    }

    pub(crate) fn into_batches(self) -> impl Iterator<Item = SemanticBatch> {
        self.staged.into_iter()
    }
}

/// One bounded cursor drain's outcome: records consumed (routed calls
/// come back as batches through `on_batch`; the remainder counts as
/// unrouted), whether the producer moved past Q, whether work remains,
/// and whether the read itself failed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LaneDrainOutcome {
    pub records: u64,
    pub post_q: bool,
    pub backlog: bool,
    pub failed: bool,
}

/// The userspace terminal surface the stop orchestration drives, so
/// ordinary tests run the same code against a scripted fake. The live
/// implementation owns the lane's Session and H0 driver; every method
/// below touches only that lane's own cursors, never Inventory-domain
/// authority and never another consumer.
pub(crate) trait SemanticStopIo {
    /// Gate the producer immediately (idempotent).
    fn request_stop(&self);
    fn quiescent(&self) -> bool;
    /// One bounded audited H0 quantum plus servicing of the lane's own
    /// DISCOVERY cursor (serviced, never staged anywhere). `None` is a
    /// quiet tick; `Err` counts a quiesce refusal and the wait continues.
    fn service_quantum(&mut self) -> Result<Option<SemanticBatch>, SemanticRefusal>;
    /// Current (consumer, producer) for the owned EVENTS and DISCOVERY
    /// cursors, in that order. `None` is an unreadable ring.
    fn positions(&mut self) -> Option<[(usize, usize); 2]>;
    /// Bounded EVENTS remainder drain to `stop`: records H0 never
    /// routed count as unrouted; post-Q movement is reported, never
    /// silently consumed.
    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
    /// Bounded DISCOVERY drain to `stop`: cursor servicing only, the
    /// records feed no authority.
    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
    /// H0 `stop()` exactly once: terminal negatives and the semantic
    /// Finish batch. Called only after every drained batch was consumed
    /// and published, so no eligible call sits behind Stopped.
    fn finish_h0(&mut self) -> SemanticBatch;
    /// Actual successful continuity-cut advances (count only).
    fn continuity_cuts(&self) -> u64;
}

/// The terminal sequence's outcome. `q` holds the proven producer
/// positions; `final_drain` is true only when quiescence was proven,
/// both owned cursors drained exactly to Q, no post-Q writer appeared
/// and no semantic loss was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SemanticStopSummary {
    pub quiesced: bool,
    pub waited: Duration,
    pub q: Option<TerminalQuiescence>,
    pub drain_batches: usize,
    pub quiesce_refusals: u64,
    pub post_q_events: bool,
    pub post_q_discovery: bool,
    pub unrouted_returns: u64,
    pub continuity_cuts: u64,
    pub semantic_loss: bool,
    pub final_drain: bool,
}

/// Independent terminal ownership over any [`SemanticStopIo`]: gate
/// immediately, run bounded audited H0 work while waiting up to
/// `budget` for Q, capture both producer positions at proven Q, drain
/// the same owned cursors to those positions in bounded quanta, then
/// stop H0 once and finalize its terminal batch separately. Every
/// drained batch reaches `on_batch` (the caller finalizes and consumes
/// it) before the Finish batch is produced: a stop request is not
/// Finish, and a legitimately drained last return still completes its
/// operation under ordinary adjudication. On unproven Q or a read
/// failure, positive history is preserved, semantic loss is declared,
/// and only one explicitly bounded poll drains each cursor.
pub(crate) fn run_semantic_stop(
    io: &mut impl SemanticStopIo,
    budget: Duration,
    quanta: usize,
    quantum: usize,
    mut now: impl FnMut() -> Instant,
    mut on_batch: impl FnMut(SemanticBatch),
) -> SemanticStopSummary {
    io.request_stop();
    let start = now();
    let mut summary = SemanticStopSummary {
        quiesced: false,
        waited: Duration::ZERO,
        q: None,
        drain_batches: 0,
        quiesce_refusals: 0,
        post_q_events: false,
        post_q_discovery: false,
        unrouted_returns: 0,
        continuity_cuts: io.continuity_cuts(),
        semantic_loss: false,
        final_drain: false,
    };
    summary.quiesced = loop {
        if io.quiescent() {
            break true;
        }
        if now().saturating_duration_since(start) >= budget {
            break false;
        }
        match io.service_quantum() {
            Ok(Some(batch)) => {
                summary.drain_batches += 1;
                on_batch(batch);
            }
            Ok(None) => {}
            Err(_) => summary.quiesce_refusals += 1,
        }
    };
    summary.waited = now().saturating_duration_since(start);
    // At proven Q, capture both producer positions and drain the same
    // owned cursors to those positions in bounded quanta. H0 ticks
    // route what they can (each batch finalizes before Finish); the
    // remainder drain counts what H0 never routed and detects post-Q
    // writers. Never another consumer, never past Q.
    if summary.quiesced {
        match io.positions() {
            Some(current) => {
                let q = TerminalQuiescence {
                    events_q: current[0].1,
                    discovery_q: current[1].1,
                };
                summary.q = Some(q);
                let mut reached = current[0].0 >= q.events_q && current[1].0 >= q.discovery_q;
                for _ in 0..quanta {
                    if reached {
                        break;
                    }
                    match io.service_quantum() {
                        Ok(Some(batch)) => {
                            summary.drain_batches += 1;
                            on_batch(batch);
                        }
                        Ok(None) => {}
                        Err(_) => summary.quiesce_refusals += 1,
                    }
                    match io.positions() {
                        Some(current) => {
                            reached = current[0].0 >= q.events_q && current[1].0 >= q.discovery_q;
                        }
                        None => {
                            summary.semantic_loss = true;
                            break;
                        }
                    }
                }
                if !summary.semantic_loss {
                    let events = io.drain_events_to(q.events_q, quantum);
                    let discovery = io.drain_discovery_to(q.discovery_q, quantum);
                    summary.post_q_events = events.post_q;
                    summary.post_q_discovery = discovery.post_q;
                    summary.unrouted_returns =
                        summary.unrouted_returns.saturating_add(events.records);
                    if events.failed || discovery.failed {
                        summary.semantic_loss = true;
                    } else if reached
                        && !events.backlog
                        && !discovery.backlog
                        && !events.post_q
                        && !discovery.post_q
                    {
                        summary.final_drain = true;
                    }
                }
            }
            None => summary.semantic_loss = true,
        }
    }
    if !summary.quiesced || summary.semantic_loss {
        // Unproven Q or a read failure: preserve positive history,
        // declare semantic loss, and drain only one explicitly bounded
        // poll per cursor under the existing terminal bound.
        summary.semantic_loss = true;
        if let Some(current) = io.positions() {
            let events = io.drain_events_to(current[0].1, quantum);
            let _ = io.drain_discovery_to(current[1].1, quantum);
            summary.unrouted_returns = summary.unrouted_returns.saturating_add(events.records);
        }
    }
    // After all drained batches are consumed and published, H0 stops
    // once: unresolved joins expire and the terminal negatives plus
    // semantic Finish finalize separately, never ahead of drained calls.
    on_batch(io.finish_h0());
    summary.continuity_cuts = io.continuity_cuts();
    summary
}

/// The live [`SemanticStopIo`]: the lane's own Session and H0 driver.
/// DISCOVERY servicing and remainder drains touch only this lane's
/// cursors; nothing here stages Inventory-domain authority.
struct LiveStopIo<'a> {
    session: &'a mut Session,
    capture: &'a mut SemanticCapture,
    pins: Vec<Arc<PidPin>>,
    domain: NativeDomainId,
}

impl SemanticStopIo for LiveStopIo<'_> {
    fn request_stop(&self) {
        self.session.stop_gate().request_stop();
    }

    fn quiescent(&self) -> bool {
        self.session.stop_gate().quiescent()
    }

    fn service_quantum(&mut self) -> Result<Option<SemanticBatch>, SemanticRefusal> {
        // The lane's own DISCOVERY cursor is serviced and discarded:
        // quiescence needs a flowing ring, not Inventory authority.
        for _ in 0..TERMINAL_DRAIN_QUANTA {
            match self.session.discovery_dequeue() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let report = self
            .capture
            .tick(&mut *self.session, &self.pins)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        if report.outcomes().is_empty() && report.current().is_empty() {
            return Ok(None);
        }
        SemanticBatch::from_tick_report(self.domain, report, Vec::new(), now_ns()).map(Some)
    }

    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        let events = self.session.event_drain_positions().ok()?;
        let discovery = self.session.discovery_positions().ok()?;
        Some([
            (events.consumer, events.producer),
            (discovery.consumer, discovery.producer),
        ])
    }

    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        let mut records = 0;
        let drained = (|| -> anyhow::Result<(bool, bool)> {
            let drain = self.session.event_drain()?;
            crate::events::poll_records_to_position(drain, stop, Some(quantum), |_| {
                records += 1;
                std::ops::ControlFlow::Continue(())
            })
        })();
        match drained {
            Ok((post_q, backlog)) => LaneDrainOutcome {
                records,
                post_q,
                backlog,
                failed: false,
            },
            Err(_) => LaneDrainOutcome {
                records,
                post_q: false,
                backlog: true,
                failed: true,
            },
        }
    }

    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        match self.session.collect_discovery_to_position(stop, quantum) {
            Ok((records, _, post_q, backlog)) => LaneDrainOutcome {
                records: records.len() as u64,
                post_q,
                backlog,
                failed: false,
            },
            Err(_) => LaneDrainOutcome {
                records: 0,
                post_q: false,
                backlog: true,
                failed: true,
            },
        }
    }

    fn finish_h0(&mut self) -> SemanticBatch {
        let report = self.capture.stop();
        SemanticBatch::from_tick_report(self.domain, report, Vec::new(), now_ns())
            .expect("H0 stop batches respect lane bounds")
    }

    fn continuity_cuts(&self) -> u64 {
        self.capture.continuity_cuts()
    }
}

impl AttestedSemanticLane {
    /// Gate the Detailed producer immediately on stop request. New
    /// regular ticks refuse from here; only the terminal sequence runs
    /// bounded audited H0 work. One producer's stop never certifies the
    /// other: Inventory's own terminal path is independent.
    pub(crate) fn request_semantic_stop(&mut self) {
        let Some(live) = self.live.as_mut() else {
            return;
        };
        live.session.stop_gate().request_stop();
        live.gated = true;
        live.stop_state = StopState::StopRequested;
    }

    /// The full independent terminal sequence over the live lane: gate
    /// (if not already), wait up to [`STOP_QUIESCE_BUDGET`] with bounded
    /// audited H0 work, drain owned cursors to Q, then stop H0 once.
    /// Every drained batch reaches `on_batch` before the Finish batch;
    /// the caller finalizes, consumes and publishes each in order. A
    /// shell lane (failed startup) finishes nothing and reports no
    /// drain: positive history elsewhere is untouched.
    pub(crate) fn run_semantic_stop(
        &mut self,
        pins: &[Arc<PidPin>],
        now: impl FnMut() -> Instant,
        on_batch: impl FnMut(SemanticBatch),
    ) -> SemanticStopSummary {
        let Some(live) = self.live.as_mut() else {
            return SemanticStopSummary {
                quiesced: false,
                waited: Duration::ZERO,
                q: None,
                drain_batches: 0,
                quiesce_refusals: 0,
                post_q_events: false,
                post_q_discovery: false,
                unrouted_returns: 0,
                continuity_cuts: 0,
                semantic_loss: false,
                final_drain: false,
            };
        };
        live.session.stop_gate().request_stop();
        live.gated = true;
        let domain = self.domain;
        let live = &mut **live;
        let mut io = LiveStopIo {
            session: &mut live.session,
            capture: &mut live.capture,
            pins: pins.to_vec(),
            domain,
        };
        let summary = run_semantic_stop(
            &mut io,
            STOP_QUIESCE_BUDGET,
            TERMINAL_DRAIN_QUANTA,
            TERMINAL_DRAIN_QUANTUM,
            now,
            on_batch,
        );
        live.stop_state = if summary.quiesced {
            StopState::Quiesced { at: Instant::now() }
        } else {
            StopState::QuiescenceUnproven {
                waited: summary.waited,
            }
        };
        live.final_drain = summary.final_drain;
        live.unrouted_returns = live
            .unrouted_returns
            .saturating_add(summary.unrouted_returns);
        live.drained_batches = live
            .drained_batches
            .saturating_add(summary.drain_batches as u64);
        live.semantic_loss = summary.semantic_loss;
        live.continuity_cuts = summary.continuity_cuts;
        live.finished = true;
        if summary.post_q_events {
            eprintln!(
                "p11scope: terminal semantic EVENTS drain: post-quiescence record past the Q \
                 positions (ungated writer)"
            );
        }
        if summary.post_q_discovery {
            eprintln!(
                "p11scope: terminal semantic DISCOVERY drain: post-quiescence record past the Q \
                 positions (ungated writer)"
            );
        }
        summary
    }

    /// The sanitized lane summary: counts only, never instance
    /// API-entry totals. The summary grants no semantic permission.
    pub(crate) fn semantic_summary(&self) -> SemanticCaptureSummary {
        let admitted_endpoints: u64 = self
            .subset
            .required()
            .values()
            .map(|slots| slots.len() as u64)
            .sum();
        let Some(live) = self.live.as_ref() else {
            return SemanticCaptureSummary {
                status: if self.startup_failed {
                    SemanticCaptureStatus::Unavailable
                } else {
                    SemanticCaptureStatus::Disabled
                },
                admitted_endpoints: 0,
                refused_endpoints: 0,
                continuity_cuts: 0,
                unrouted_returns: 0,
                stop_quiescence: SemanticStopQuiescence::NotRequested,
                final_drain: None,
            };
        };
        SemanticCaptureSummary {
            status: if live.finished {
                SemanticCaptureStatus::Stopped
            } else if live.scan_refusals > 0 || live.semantic_loss {
                SemanticCaptureStatus::Partial
            } else {
                SemanticCaptureStatus::Active
            },
            admitted_endpoints,
            refused_endpoints: live.scan_refusals,
            continuity_cuts: live.continuity_cuts,
            unrouted_returns: live.unrouted_returns,
            stop_quiescence: match live.stop_state {
                StopState::Quiesced { .. } => SemanticStopQuiescence::Quiesced,
                StopState::QuiescenceUnproven { .. } => SemanticStopQuiescence::Unproven,
                StopState::Running | StopState::StopRequested => {
                    SemanticStopQuiescence::NotRequested
                }
            },
            final_drain: live.finished.then_some(live.final_drain),
        }
    }
}

/// `observation.semantic_capture.status`: the lane's sanitized state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SemanticCaptureStatus {
    #[default]
    Disabled,
    Active,
    Partial,
    Unavailable,
    Stopped,
}

impl SemanticCaptureStatus {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Active => "active",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
            Self::Stopped => "stopped",
        }
    }
}

/// `observation.semantic_capture.stop_quiescence`: the stop-gate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SemanticStopQuiescence {
    #[default]
    NotRequested,
    Quiesced,
    Unproven,
}

impl SemanticStopQuiescence {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Quiesced => "quiesced",
            Self::Unproven => "unproven",
        }
    }
}

/// The sanitized `observation.semantic_capture` summary: counts only,
/// never instance API-entry totals. Per-provider/edge gaps stay
/// authoritative for availability; this summary grants no permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SemanticCaptureSummary {
    pub status: SemanticCaptureStatus,
    pub admitted_endpoints: u64,
    pub refused_endpoints: u64,
    pub continuity_cuts: u64,
    pub unrouted_returns: u64,
    pub stop_quiescence: SemanticStopQuiescence,
    pub final_drain: Option<bool>,
}

impl SemanticCaptureSummary {
    /// The exact `observation.semantic_capture` shape: `{status,
    /// admitted_endpoints, refused_endpoints, continuity_cuts,
    /// unrouted_returns, stop_quiescence, final_drain}`. `final_drain`
    /// is null before stop, then a boolean.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status.label(),
            "admitted_endpoints": self.admitted_endpoints,
            "refused_endpoints": self.refused_endpoints,
            "continuity_cuts": self.continuity_cuts,
            "unrouted_returns": self.unrouted_returns,
            "stop_quiescence": self.stop_quiescence.label(),
            "final_drain": self.final_drain,
        })
    }
}
