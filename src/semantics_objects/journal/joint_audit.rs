//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! One original ingested collection, immutable audit and bounded all-domain delivery.
#![cfg_attr(not(test), allow(dead_code))] // Ordinary Joint activation remains gated.

use super::joint_driver::{
    IngestedRaw, JointCaptureOwner, RawDisposeReason, RawDisposition, RawProvenance,
    RawQuantumIdentity, RawQuantumRefusal,
};
use super::seal_replay::{ReplayBounds, ReplayPreparation, SealBatchDelivery, SealReplayCursor};
use super::{
    BirthEvidenceSource, BootstrapReceipt, H3DispositionEvidence, H3FinalizerPort,
    H3VoidAcknowledgement, JournalGap, SealSuccess, SealWait, SealedCall, SessionBirthEvidence,
    StagingLedger,
};
use super::{
    ConsumptionOrdinal, FaultEpoch, JournalAdapter, JournalAuditReceipt, SealFailure,
    SealFailureScope, SessionClosureGrant,
};
use crate::attach::{AttachedSemanticSet, SessionDrainProducers};
use crate::discovery::caller_registry::instance_input::JointFeedTarget;
use crate::discovery::engine::inventory_coordinator::semantics::{
    JointPublicationPorts, SemanticCallerBinding, SessionAuditInput, SessionDisposedAuditInput,
};
use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, ResourceLease};
use crate::semantics_key_use::{
    FailureApplyOutcome, FailureBatchProgress, FeedMode, SealBatchProgress, SealFailureDisposition,
    disposition_of,
};
use crate::semantics_objects::{
    CallKey, MAX_FIND_HANDLES, MAX_INPUT_HANDLES, MAX_RESULT_HANDLES, MAX_TEMPLATE_ATTRIBUTES,
};
use crate::semantics_objects::{ObjectDomain, ObjectEffect, ObjectSemantics};
use std::mem::size_of;

/// No Clone or scalar constructor. The original provenance is moved intact;
/// collection-wide loss stays here for all actual consumers. Domain delivery
/// and acknowledgement borrow the canonical owner; ordinary Joint remains inactive.
pub(crate) struct IngestedJointQuantum {
    provenance: RawProvenance,
    ingress: FrameIngress,
    frontier: ConsumptionOrdinal,
    audit: JournalAuditReceipt,
    // Original bulk S1Only refusal and original audit result remain distinct.
    // Both buffers are precharged before the first taint/model mutation.
    raw_failure: Option<SealFailure>,
    // A carried ingest-break void's own original failure (its fenced
    // pre-break ends: uncertain session outcomes, retired objects,
    // voided bootstraps), in a slot of its own so any next frame,
    // ingested or disposed, takes it whatever the other two slots hold.
    void_failure: Option<SealFailure>,
    failure: Option<SealFailure>,
    // Diagnostic-only per-void dedup (scope round): the (fence, gap) of
    // each void failure already counted as ending a Joint feed, so one
    // void fanning out to many feeds counts once. Fixed-size and
    // inline: at most one entry per original slot plus the selected
    // failure, so four slots always suffice and no heap allocation
    // escapes the frame's prepaid storage. Instrumentation only.
    void_feed_ends_counted: [Option<(Option<u64>, JournalGap)>; 4],
    consumers: Vec<FrameConsumer>,
    bound: bool,
    cursor: usize,
    pending: usize,
    future: usize,
    active: Option<ActiveSeal>,
    /// Sliced park cursors (watchdog): resume index and parked total
    /// across ticks. Reset whenever frame progress moves consumers
    /// (advance or H3 requeue) and when a park run completes, so a
    /// stale cursor never skips a newly stuck consumer.
    park_cursor: usize,
    parked_total: usize,
    // Nested buffers always drop before their own reservation.
    failure_storage: Option<ResourceLease>,
    targets_storage: Option<ResourceLease>,
    // Every owned failure buffer drops before its retained storage is refunded.
    _storage: ResourceLease,
    // The carried ingest-break void's own prepaid lease (its raw failure).
    _void_storage: Option<ResourceLease>,
    // Deferred adapter rejections this frame's originals wait on: the
    // audit failure's and the carried raw refusal's per-row work (their
    // O(1) refusals already published). The frame drives them through
    // its service budget and fills each into its failure before any
    // seal or delivery reads it.
    audit_fill: Option<u64>,
    raw_fill: Option<u64>,
    // Bound while an original was still filling: some consumers carry a
    // provisional all-key classification that the exact scope must
    // reconcile before any seal or delivery reads a consumer.
    provisional: bool,
    // A seal outcome whose failure waits on its own deferred rejection
    // (a seal-time audit void or key doom), with its prepaid storage.
    parked: Option<ParkedSeal>,
}

/// One selected seal's outcome held until its deferred rejection fills.
struct ParkedSeal {
    consumer: usize,
    /// The rejection still filling, or `None` once filled.
    ticket: Option<u64>,
    outcome: Result<SealSuccess, SealFailure>,
    storage: ResourceLease,
    bytes: usize,
}

pub(crate) type AuditAcquisition = Result<IngestedJointQuantum, (IngestedRaw, RawQuantumRefusal)>;
pub(crate) type DisposedAuditAcquisition =
    Result<IngestedJointQuantum, (RawDisposition, RawQuantumRefusal)>;

#[derive(Clone, Copy)]
enum FrameIngress {
    Ingested,
    Disposed(RawDisposeReason),
}

fn allocation_bytes<T>(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(size_of::<T>())?
        .checked_add(if capacity == 0 {
            0
        } else {
            OWNED_ALLOCATION_PADDING
        })
}

fn one_failure_bound(adapter: &JournalAdapter, model: &ObjectSemantics) -> Option<usize> {
    let keys = adapter.keys.len();
    let (objects, sessions) = model.audit_loss_record_counts();
    // Collection failure only retires each live view/session once. The
    // abandonment pass and void pass can each add one unheld-domain gap per
    // key. Vec growth requests at most twice the required population (minimum
    // four for ObjectEffect); reserve that capacity before any audit mutation.
    let effects = objects
        .checked_add(sessions)?
        .checked_add(keys.checked_mul(2)?)?;
    let effect_capacity = if effects == 0 {
        0
    } else {
        effects.checked_mul(2)?.max(4)
    };
    allocation_bytes::<ObjectDomain>(keys)?
        .checked_add(allocation_bytes::<ObjectEffect>(effect_capacity)?)
}

fn storage_bound(adapter: &JournalAdapter, model: &ObjectSemantics) -> Option<usize> {
    let one = one_failure_bound(adapter, model)?;
    size_of::<IngestedJointQuantum>()
        .checked_add(one.checked_mul(if adapter.has_s1only_subjects() { 2 } else { 1 })?)
}

pub(super) fn raw_disposition_storage_bound(
    adapter: &JournalAdapter,
    model: &ObjectSemantics,
) -> Option<usize> {
    // The first negative mutation pays for its eventual same-owner frame
    // and BOTH original failures. The lease moves with that owner; quiet
    // disposal cannot strand progress behind a second full reservation.
    size_of::<super::joint_driver::RawDisposition>()
        .checked_add(size_of::<IngestedJointQuantum>())?
        .checked_add(one_failure_bound(adapter, model)?.checked_mul(2)?)
}

/// Only the selected frame supplies this exact typed target and original
/// coordinator binding. The source selects no ordinal and owns no extra queue.
pub(crate) trait JointBirthEvidenceSource {
    fn take_for(
        &mut self,
        target: &JointFeedTarget,
        binding: &SemanticCallerBinding,
    ) -> Result<SessionBirthEvidence, crate::attach::BirthObservationRefusal>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuantumSealProgress {
    LocalPending,
    AwaitFutureInput,
    DeliveryReady,
    Complete,
}

/// Diagnostic-only deliver-side telemetry: active-seal delivery
/// outcomes with progress sums plus entry snapshots that separate
/// budget starvation (zero at entry) from a stale seal (effects
/// already exhausted at entry), with the failure-path record
/// (visits, cleared/progress/retried/stuck, last delivered gap)
/// and the early/other-arm count. Counts and one frozen label
/// only; disclosed beside the stop line while stage timings are
/// requested, never a contract.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeliverDiagnosis {
    pub(crate) complete: u64,
    pub(crate) yielded: u64,
    pub(crate) held: u64,
    pub(crate) replayed: u64,
    pub(crate) disposed: u64,
    pub(crate) entry_zero: u64,
    pub(crate) entry_exhausted: u64,
    pub(crate) f_visits: u64,
    pub(crate) f_cleared: u64,
    pub(crate) f_progress: u64,
    pub(crate) f_retried: u64,
    pub(crate) f_stuck: u64,
    pub(crate) f_last_gap: &'static str,
    pub(crate) d_other: u64,
}

impl Default for DeliverDiagnosis {
    fn default() -> Self {
        Self {
            complete: 0,
            yielded: 0,
            held: 0,
            replayed: 0,
            disposed: 0,
            entry_zero: 0,
            entry_exhausted: 0,
            f_visits: 0,
            f_cleared: 0,
            f_progress: 0,
            f_retried: 0,
            f_stuck: 0,
            f_last_gap: "none",
            d_other: 0,
        }
    }
}

impl DeliverDiagnosis {
    /// One failure-path visit delivering this gap.
    pub(crate) fn note_failure_visit(&mut self, gap: JournalGap) {
        self.f_visits = self.f_visits.saturating_add(1);
        self.f_last_gap = gap.label();
    }

    /// The visit cleared the active (negative delivered, degraded,
    /// or fell back).
    pub(crate) fn note_failure_cleared(&mut self) {
        self.f_cleared = self.f_cleared.saturating_add(1);
    }

    /// The visit advanced a pending visit without clearing the active.
    pub(crate) fn note_failure_progress(&mut self) {
        self.f_progress = self.f_progress.saturating_add(1);
    }

    /// The visit refunded its spend for a same-span retry.
    pub(crate) fn note_failure_retried(&mut self) {
        self.f_retried = self.f_retried.saturating_add(1);
    }

    /// The visit kept the active with no advance (held, yielded, or
    /// a completeness hold that did not qualify).
    pub(crate) fn note_failure_stuck(&mut self) {
        self.f_stuck = self.f_stuck.saturating_add(1);
    }

    /// A deliver visit that reached neither the positive arm nor the
    /// failure path (early returns, disposed-negative service, or a
    /// pending-H3 visit charge).
    pub(crate) fn note_other(&mut self) {
        self.d_other = self.d_other.saturating_add(1);
    }

    pub(crate) fn record(
        &mut self,
        outcome: &crate::semantics_key_use::SealBatchProgress,
        entry_zero: bool,
        entry_exhausted: bool,
    ) {
        use crate::semantics_key_use::SealBatchProgress;
        if entry_zero {
            self.entry_zero = self.entry_zero.saturating_add(1);
        }
        if entry_exhausted {
            self.entry_exhausted = self.entry_exhausted.saturating_add(1);
        }
        match outcome {
            SealBatchProgress::Complete { replayed, disposed } => {
                self.complete = self.complete.saturating_add(1);
                self.replayed = self.replayed.saturating_add(*replayed as u64);
                self.disposed = self.disposed.saturating_add(*disposed as u64);
            }
            SealBatchProgress::Yielded { replayed, disposed } => {
                self.yielded = self.yielded.saturating_add(1);
                self.replayed = self.replayed.saturating_add(*replayed as u64);
                self.disposed = self.disposed.saturating_add(*disposed as u64);
            }
            SealBatchProgress::Held => {
                self.held = self.held.saturating_add(1);
            }
        }
    }

    /// Fold one service-slice-local record into the run total.
    pub(crate) fn absorb(&mut self, other: &Self) {
        self.complete = self.complete.saturating_add(other.complete);
        self.yielded = self.yielded.saturating_add(other.yielded);
        self.held = self.held.saturating_add(other.held);
        self.replayed = self.replayed.saturating_add(other.replayed);
        self.disposed = self.disposed.saturating_add(other.disposed);
        self.entry_zero = self.entry_zero.saturating_add(other.entry_zero);
        self.entry_exhausted = self.entry_exhausted.saturating_add(other.entry_exhausted);
        self.f_visits = self.f_visits.saturating_add(other.f_visits);
        self.f_cleared = self.f_cleared.saturating_add(other.f_cleared);
        self.f_progress = self.f_progress.saturating_add(other.f_progress);
        self.f_retried = self.f_retried.saturating_add(other.f_retried);
        self.f_stuck = self.f_stuck.saturating_add(other.f_stuck);
        if other.f_visits != 0 {
            self.f_last_gap = other.f_last_gap;
        }
        self.d_other = self.d_other.saturating_add(other.d_other);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConsumerState {
    Pending,
    // Retained selected history may receive negatives, never a positive seal.
    NegativeOnly,
    Future,
    Delivered,
    LossDelivered,
}
/// Gap subject for a parked stuck consumer's forced-fallback
/// degrade: the watchdog parked the consumer past its retry stall
/// with counted loss instead of tripping the lane.
pub(crate) const PARKED_CONSUMER_SUBJECT: &str = "joint stuck consumer parked";

/// Outcome of one bounded park scan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ParkProgress {
    /// The scan completed: total newly parked.
    Done(usize),
    /// Budget exhausted mid-scan: call again to resume.
    Yielded,
}

struct FrameConsumer {
    target: JointFeedTarget,
    state: ConsumerState,
    failure: FailureReplayCursor,
    /// Consecutive delivery visits that made no progress (retried or
    /// held): reset on any advance or charged visit. The watchdog
    /// parks consumers still streaked when the frame bound fires.
    stuck_streak: u32,
    /// Parked by the watchdog: the next delivery degrades this
    /// consumer with a forced fallback instead of retrying, so the
    /// cursor advances past it. Cleared on advance.
    parked: bool,
    /// The last failure gap that streaked this consumer, for the
    /// park gap's named cause.
    last_stuck_gap: Option<super::JournalGap>,
    /// This target's feed mode, for reconciling a provisional state.
    mode: FeedMode,
    /// Classified Pending only by a still-filling original's all-key
    /// bound (no exact failure named it yet): reconciled once the
    /// fills finish, with its binding checked if it stays positive.
    provisional: bool,
}
struct ActiveSeal {
    consumer: usize,
    outcome: Result<SealSuccess, SealFailure>,
    replay: SealReplayCursor,
    _storage: ResourceLease,
}

/// Scalar completion metadata, not a receipt or replay/seal authority.
pub(crate) struct DisposedJointQuantum {
    identity: RawQuantumIdentity,
    frontier: ConsumptionOrdinal,
}
impl DisposedJointQuantum {
    pub(crate) fn identity(&self) -> RawQuantumIdentity {
        self.identity
    }
    pub(crate) fn frontier(&self) -> ConsumptionOrdinal {
        self.frontier
    }
}

/// The adapter's per-domain input has no independent constructor. It borrows
/// the original frame audit, frontier and the actual selected receipt.
pub(super) struct AuditedDomainInput<'q> {
    audit: &'q JournalAuditReceipt,
    receipt: &'q BootstrapReceipt,
    frontier: ConsumptionOrdinal,
}
impl<'q> AuditedDomainInput<'q> {
    pub(super) fn into_parts(
        self,
    ) -> (
        &'q JournalAuditReceipt,
        &'q BootstrapReceipt,
        ConsumptionOrdinal,
    ) {
        (self.audit, self.receipt, self.frontier)
    }
}

/// Borrowed negative authority minted only for immediate canonical delivery.
/// No Clone/Copy, supplied failure/H3 pair or production escape constructor.
pub(crate) struct AuditedFailure<'q> {
    failure: &'q SealFailure,
    originals: [Option<&'q SealFailure>; 3],
    audit: &'q JournalAuditReceipt,
    provenance: &'q RawProvenance,
    frontier: ConsumptionOrdinal,
    domain: ObjectDomain,
}
impl AuditedFailure<'_> {
    pub(crate) fn failure(&self) -> &SealFailure {
        self.failure
    }
    /// The largest void fence among the failures that apply to this
    /// domain. The selected failure wins by rank, which need not
    /// carry the largest fence (a fenceless failure can outrank a
    /// fenced void), so feeds record this maximum instead: every
    /// void's fence joins the running maximum.
    pub(crate) fn fence(&self) -> Option<u64> {
        self.originals
            .iter()
            .flatten()
            .filter_map(|failure| failure.fence)
            .max()
    }
    /// The gap of the failure carrying the largest applicable fence
    /// (first in slot order on ties): pairs with [`Self::fence`] so
    /// one void fanning out counts once however selection ranked it.
    pub(crate) fn fenced_gap(&self) -> Option<super::JournalGap> {
        let fence = self.fence()?;
        self.originals
            .iter()
            .flatten()
            .find(|failure| failure.fence == Some(fence))
            .map(|failure| failure.gap)
    }
    pub(crate) fn h3(&self) -> &H3DispositionEvidence {
        &self.audit.h3
    }
    pub(crate) fn domain(&self) -> ObjectDomain {
        self.domain
    }
    pub(crate) fn matches_ledger(&self, ledger: &StagingLedger) -> bool {
        self.provenance.matches_ledger(ledger)
    }

    pub(crate) fn disposition(&self) -> SealFailureDisposition {
        if self
            .originals
            .iter()
            .flatten()
            .any(|failure| disposition_of(failure.gap) == SealFailureDisposition::HistoryLoss)
            // This original audit failure has already fenced and disposed
            // H8 custody in reject_audit. Its retained H9 rows must receive
            // loss rather than exact-completed fallback. A seal-time
            // ResourceUnavailable with retained custody keeps its ordinary
            // Fallback disposition; the flag alone creates no failure.
            || (self.audit.resource_refused
                && self
                    .originals
                    .iter()
                    .flatten()
                    .any(|failure| failure.gap == JournalGap::ResourceUnavailable))
            || matches!(
                self.audit.h3,
                H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted
            )
        {
            SealFailureDisposition::HistoryLoss
        } else {
            // Real loss above wins over a transient take: loss is
            // evidence, a failed take is its absence.
            self.failure.delivery_disposition()
        }
    }

    pub(super) fn validate_input(
        &self,
        adapter: &JournalAdapter,
        input: &AuditedDomainInput<'_>,
    ) -> Result<(), RawQuantumRefusal> {
        let producers = adapter
            .resource_producers
            .as_ref()
            .ok_or(RawQuantumRefusal::ForeignCapture)?;
        self.provenance.validate_owner(adapter, producers)?;
        if adapter.consumed_frontier() != self.frontier || input.frontier != self.frontier {
            return Err(RawQuantumRefusal::StaleFrontier);
        }
        if !std::ptr::eq(self.audit, input.audit)
            || self.domain != input.receipt.domain()
            || !self.failure.affects_domain(self.domain)
        {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn identity(&self) -> RawQuantumIdentity {
        self.provenance.identity()
    }
    #[cfg(test)]
    pub(crate) fn frontier(&self) -> ConsumptionOrdinal {
        self.frontier
    }
}

fn failure_rank(failure: &SealFailure) -> u8 {
    // Contention-failed takes rank as retry, below real endings: a
    // transient take failure never masks a fallback or loss the
    // frame must deliver.
    match failure.delivery_disposition() {
        SealFailureDisposition::Retry => 0,
        SealFailureDisposition::Fallback => 1,
        SealFailureDisposition::HistoryLoss => 2,
    }
}

impl<'q> AuditedFailure<'q> {
    fn new(
        originals: [Option<&'q SealFailure>; 3],
        audit: &'q JournalAuditReceipt,
        provenance: &'q RawProvenance,
        frontier: ConsumptionOrdinal,
        domain: ObjectDomain,
    ) -> Option<Self> {
        let originals =
            originals.map(|failure| failure.filter(|failure| failure.affects_domain(domain)));
        let failure = originals
            .iter()
            .flatten()
            .copied()
            .max_by_key(|failure| failure_rank(failure))?;
        Some(Self {
            failure,
            originals,
            audit,
            provenance,
            frontier,
            domain,
        })
    }
}

/// Inline indices over the original owners. They grant no disposition without
/// the frame's borrowed failure, exact target, original H3 and ledger.
#[derive(Default)]
pub(super) struct FailureReplayCursor {
    pub(super) after: Option<super::JournalNativeKey>,
    pub(super) verified: usize,
    pub(super) suffix: Option<usize>,
    pub(super) consumed: usize,
    slot: usize,
    effect: usize,
    invalidated: bool,
    resource_failed: bool,
    /// Heads this delivery replayed (fallback rows) or disposed
    /// (history loss) across all its slices: the per-consumer totals
    /// the parked-consumer gap counts, since each slice alone sees
    /// only its own head.
    replayed: usize,
    disposed: usize,
}

/// The real frame's two original negatives and bounded per-consumer cursor.
/// No public constructor, merged failure, cloned effects or reusable token.
pub(crate) struct FailureBatchDelivery<'q> {
    audited: AuditedFailure<'q>,
    pub(super) cursor: &'q mut FailureReplayCursor,
    /// Watchdog park override: a parked consumer's retry-mapped
    /// failure delivers as a forced fallback (degrade with counted
    /// loss) instead of retrying, so the cursor advances past it.
    /// `None` delivers the failure's own disposition.
    forced_disposition: Option<SealFailureDisposition>,
}

/// Completion metadata minted from the SAME borrowed originals and cursor.
/// It cannot authorize a seal, replay, H3 acknowledgement or another history.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NegativeDelivered {
    domain: ObjectDomain,
    disposition: SealFailureDisposition,
}
impl NegativeDelivered {
    fn matches(&self, batch: &FailureBatchDelivery<'_>) -> bool {
        batch.negative_delivered().as_ref() == Some(self)
    }
}

impl<'q> FailureBatchDelivery<'q> {
    pub(crate) fn audited(&self) -> &AuditedFailure<'q> {
        &self.audited
    }

    /// The watchdog park override, if this delivery degrades a parked
    /// consumer instead of its failure's own disposition.
    pub(crate) fn forced_disposition(&self) -> Option<SealFailureDisposition> {
        self.forced_disposition
    }
    pub(crate) fn effects_complete(&self) -> bool {
        self.audited.originals[self.cursor.slot..]
            .iter()
            .all(Option::is_none)
    }
    pub(crate) fn negative_delivered(&self) -> Option<NegativeDelivered> {
        let disposition = self.audited.disposition();
        (self.effects_complete()
            && (disposition != SealFailureDisposition::HistoryLoss || self.cursor.invalidated))
            .then_some(NegativeDelivered {
                domain: self.audited.domain(),
                disposition,
            })
    }
    pub(crate) fn advance_effect(&mut self) -> Option<Option<&'q ObjectEffect>> {
        while self.cursor.slot < self.audited.originals.len() {
            let Some(failure) = self.audited.originals[self.cursor.slot] else {
                self.cursor.slot += 1;
                continue;
            };
            let effects = &failure.effects.effects;
            let effect = if self.cursor.effect < effects.len() {
                let effect = &effects[self.cursor.effect];
                self.cursor.effect += 1;
                Some(effect)
            } else if self.cursor.effect == 0 {
                None
            } else {
                return None;
            };
            if self.cursor.effect == effects.len() {
                self.cursor.slot += 1;
                self.cursor.effect = 0;
            }
            return Some(effect);
        }
        None
    }
    pub(crate) fn needs_loss_invalidation(&self) -> bool {
        !self.cursor.invalidated
    }
    pub(crate) fn loss_started(&mut self) {
        self.cursor.invalidated = true;
    }
    pub(crate) fn resource_failed(&self) -> bool {
        self.cursor.resource_failed
    }
    pub(crate) fn note_resource_failure(&mut self) {
        self.cursor.resource_failed = true;
    }
    /// Count one head this delivery replayed as a fallback row.
    pub(crate) fn note_head_replayed(&mut self) {
        self.cursor.replayed = self.cursor.replayed.saturating_add(1);
    }
    /// Count one head this delivery disposed as history loss.
    pub(crate) fn note_head_disposed(&mut self) {
        self.cursor.disposed = self.cursor.disposed.saturating_add(1);
    }
    /// Heads replayed across all this delivery's slices.
    pub(crate) fn delivered_replayed(&self) -> usize {
        self.cursor.replayed
    }
    /// Heads disposed across all this delivery's slices.
    pub(crate) fn delivered_disposed(&self) -> usize {
        self.cursor.disposed
    }
}

struct SelectedBirth<'a, B> {
    source: &'a mut B,
    target: &'a JointFeedTarget,
    binding: &'a SemanticCallerBinding,
}
impl<B: JointBirthEvidenceSource> BirthEvidenceSource for SelectedBirth<'_, B> {
    fn take_birth_evidence(
        &mut self,
    ) -> Result<SessionBirthEvidence, crate::attach::BirthObservationRefusal> {
        self.source.take_for(self.target, self.binding)
    }
}

fn vector_capacity(required: usize) -> Option<usize> {
    if required == 0 {
        Some(0)
    } else {
        required.checked_mul(2).map(|capacity| capacity.max(4))
    }
}

/// Per-category effect counts one seal can emit, from the populations
/// at seal start. Every category is a hard upper bound on the matching
/// effects of any seal outcome, so the sum is the retained effect bound.
///
/// One seal applies its calls once, in place, to one model. Broad
/// actions (contradiction, void, session end, alias retirement,
/// uncertain mutation) emit at most once per object or session over the
/// whole seal, not once per call:
/// - `Retired`/`AccessEnded`/`Destroyed`: only a `Live` view ends, and an
///   ended view never becomes `Live` again (`end_view`, `destroy_view`).
/// - `Downgraded`: only a `Valid` view downgrades, and only allocation
///   makes a view `Valid` (`contradict`).
/// - `SessionEnded`: only a `Live` session ends (`end_session`).
/// - `MetadataInvalidated`: only a view holding an established or
///   conflicting field emits, and each invalidation needs an arming:
///   a pre-seal object arrives armed, `establish` re-arms at most one
///   view per input handle, and R2 promotion arms each view a
///   creation mints, at most one per result handle. So each object
///   present at seal start emits once for its state then, plus once
///   per input-handle establishment and once per result-handle
///   promotion.
///
/// Only staged begins (`adapter.open`) apply an action and mint records:
/// a refused begin applies none (`note_refused` only voids, a broad
/// action). Each applied call touches at most its input, result and find
/// handles, so it mints at most that many views; it mints at most one
/// session per session word, and the per-call slack below covers a
/// second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SealEffectBound {
    /// `Retired`, `AccessEnded` and `Destroyed`: once per object.
    pub(super) lifetime_ends: usize,
    /// `Downgraded`: once per object.
    pub(super) downgrades: usize,
    /// `SessionEnded`: once per session.
    pub(super) session_ends: usize,
    /// `MetadataInvalidated`: once per object plus once per
    /// input-handle re-establishment and once per result-handle
    /// promotion.
    pub(super) invalidations: usize,
    /// Every other effect of an applied seal: the per-call direct effects
    /// plus the seal-level settlement gaps.
    pub(super) direct: usize,
    /// A refused or voided seal that applies no call: one end per object
    /// and session plus two gaps per key. Never combined with the
    /// applied categories above.
    pub(super) loss: usize,
}

/// Seal-level gap effects that belong to no call: settlement emits at
/// most one refusal gap (unheld, ended, stale or prefix contradiction)
/// and one bootstrap refusal.
const SEAL_LEVEL_GAPS: usize = 2;

impl SealEffectBound {
    pub(super) fn sample(adapter: &JournalAdapter, model: &ObjectSemantics) -> Option<Self> {
        let calls = adapter.open.len();
        let (objects, sessions) = model.audit_loss_record_counts();
        let handles = MAX_INPUT_HANDLES
            .checked_add(MAX_RESULT_HANDLES)?
            .checked_add(MAX_FIND_HANDLES)?;
        let prospective_objects = objects.checked_add(calls.checked_mul(handles)?)?;
        let prospective_sessions = sessions.checked_add(calls)?;
        // state::apply_action selects one finite action. Per touched
        // handle, establishment may emit one conflict for each bounded
        // observation and one established summary; creation/first
        // observation, reference, destruction/retirement and
        // unresolved/gap each add at most one.
        let per_handle = MAX_TEMPLATE_ATTRIBUTES.checked_add(1)?.checked_add(4)?;
        // Direct per-call effects: the touched handles plus the session
        // first/open and call gap/unresolved summaries.
        let per_call = handles.checked_mul(per_handle)?.checked_add(4)?;
        Some(Self {
            lifetime_ends: prospective_objects,
            downgrades: prospective_objects,
            session_ends: prospective_sessions,
            // Each invalidation needs an arming: a pre-seal object
            // arrives armed (one per object), `establish` re-arms at
            // most one view per input handle, and R2 promotion arms
            // each view a creation mints, at most one per result
            // handle — a view created during the seal invalidates
            // without any `establish` once a later write in the same
            // seal reaches it.
            invalidations: objects
                .checked_add(calls.checked_mul(MAX_INPUT_HANDLES)?)?
                .checked_add(calls.checked_mul(MAX_RESULT_HANDLES)?)?,
            direct: calls.checked_mul(per_call)?.checked_add(SEAL_LEVEL_GAPS)?,
            loss: objects
                .checked_add(sessions)?
                .checked_add(adapter.keys.len().checked_mul(2)?)?,
        })
    }

    /// The retained effect count: an applied seal's categories, or a
    /// loss outcome, whichever is larger (a seal emits one or the other).
    pub(super) fn total(self) -> Option<usize> {
        let applied = self
            .lifetime_ends
            .checked_add(self.downgrades)?
            .checked_add(self.session_ends)?
            .checked_add(self.invalidations)?
            .checked_add(self.direct)?;
        Some(applied.max(self.loss))
    }
}

/// Retained result only; transition temporaries remain covered by the existing
/// serialized scratch reservation. Recompute from current populations before
/// EVERY seal: a previous domain may have grown the model since acquisition.
/// Linear in retained calls (see [`SealEffectBound`]). The settlement
/// appends straight into the retained effect vector, so no second
/// settlement-sized vector exists at any point.
pub(super) fn result_storage_bound(
    adapter: &JournalAdapter,
    model: &ObjectSemantics,
) -> Option<usize> {
    let effects = SealEffectBound::sample(adapter, model)?.total()?;
    allocation_bytes::<ObjectDomain>(adapter.keys.len())?
        .checked_add(allocation_bytes::<ObjectEffect>(vector_capacity(effects)?)?)?
        .checked_add(allocation_bytes::<SealedCall>(vector_capacity(
            adapter.open.len(),
        )?)?)?
        .checked_add(allocation_bytes::<CallKey>(vector_capacity(
            adapter.open.len(),
        )?)?)
}

pub(super) fn outcome_storage(outcome: &Result<SealSuccess, SealFailure>) -> Option<usize> {
    match outcome {
        Ok(seal) => allocation_bytes::<ObjectEffect>(seal.effects.effects.capacity())?
            .checked_add(allocation_bytes::<SealedCall>(
                seal.prefix.settled.capacity(),
            )?)?
            .checked_add(allocation_bytes::<super::SealReplayStep>(
                seal.prefix.replay_steps.capacity(),
            )?)?
            .checked_add(allocation_bytes::<CallKey>(seal.prefix.open.capacity())?),
        Err(failure) => failure_storage(failure),
    }
}

/// The original locator keeps its separately precharged lease. Counting it
/// here must not pretend it was also paid by the result-buffer reservation.
fn lookup_storage(outcome: &Result<SealSuccess, SealFailure>) -> Option<usize> {
    match outcome {
        Ok(seal) => seal
            .prefix
            .replay_index
            .as_ref()
            .map_or(Some(0), |index| index.retained_bytes()),
        Err(_) => Some(0),
    }
}
/// The current-binding check a fresh positive seal needs: the target's
/// caller still binds this exact key (caller, image and domain tag).
fn check_positive_binding(
    bindings: &crate::discovery::engine::inventory_coordinator::semantics::SemanticBindingSet,
    target: &JointFeedTarget,
) -> Result<(), RawQuantumRefusal> {
    let binding = bindings
        .get(target.caller())
        .ok_or(RawQuantumRefusal::Admission)?;
    let key = target.bootstrap().proof().key;
    let image = binding.image();
    if key.caller != binding.caller().0
        || key.cookie != image.task_cookie
        || key.exec != image.exec_id
        || key.domain_tag != binding.domain().journal_tag()
    {
        return Err(RawQuantumRefusal::Admission);
    }
    Ok(())
}

/// Take the owner's pending ingest-break void: its failure, its prepaid
/// lease and the bytes that lease paid.
fn take_void(owner: &mut JointCaptureOwner) -> (Option<SealFailure>, Option<ResourceLease>, usize) {
    match owner.take_pending_void() {
        Some(void) => (Some(void.failure), Some(void.lease), void.bytes),
        None => (None, None, 0),
    }
}

fn failure_storage(failure: &SealFailure) -> Option<usize> {
    let domains = match &failure.scope {
        SealFailureScope::AffectedDomains(domains) => domains.capacity(),
        _ => 0,
    };
    allocation_bytes::<ObjectDomain>(domains)?.checked_add(allocation_bytes::<ObjectEffect>(
        failure.effects.effects.capacity(),
    )?)
}

impl IngestedJointQuantum {
    /// Bounded diagnostics from this frame's immutable audit. These scalar
    /// watermarks cannot advance H3 or authorize delivery or publication.
    pub(crate) fn no_progress_watermarks(&self) -> (u64, Option<u64>, Option<u64>) {
        let (staged_max, floor) = match self.audit.h3 {
            H3DispositionEvidence::Clean {
                staged_max,
                pending_floor,
            } => (Some(staged_max), pending_floor),
            H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted => {
                (None, None)
            }
        };
        (self.audit.h0_below, staged_max, floor)
    }

    fn original_failures(&self) -> impl Iterator<Item = &SealFailure> {
        self.void_failure
            .iter()
            .chain(self.raw_failure.iter())
            .chain(self.failure.iter())
            .chain(
                self.active
                    .as_ref()
                    .and_then(|active| active.outcome.as_ref().err()),
            )
    }

    /// The only constructor requires both actual ingestion and the retained
    /// Session finalizer. Every refusal preserves the original proof and H3
    /// slot. The reservation comes from the canonical ledger's own pool.
    #[allow(clippy::result_large_err)] // Nonallocating refusal returns the original move-only provenance.
    pub(crate) fn audit(
        authorized: SessionAuditInput<'_>,
        attachment: &AttachedSemanticSet,
        fault: &impl FaultEpoch,
    ) -> AuditAcquisition {
        let (ingested, owner, mut finalizer, producers) = authorized.into_parts();
        let preflight = (|| {
            ingested.validate_owner(owner.adapter(), producers)?;
            if !owner
                .adapter()
                .s1only_subjects_are_owned(ingested.frontier())
            {
                return Err(RawQuantumRefusal::DispositionMismatch);
            }
            if attachment.domain() != producers.native_domain() {
                return Err(RawQuantumRefusal::ForeignCapture);
            }
            if !finalizer.ready_for_audit(producers) {
                return Err(RawQuantumRefusal::H3Undisposed);
            }
            if attachment.generation() < owner.adapter().closure_generation {
                return Err(RawQuantumRefusal::ClosureStale);
            }
            let bytes =
                storage_bound(owner.adapter(), owner.model()).ok_or(RawQuantumRefusal::Capacity)?;
            let storage = owner
                .ledger()
                .resource_reserver()
                .ok_or(RawQuantumRefusal::ForeignLedger)?
                .reserve(bytes)
                .map_err(RawQuantumRefusal::Resource)?;
            Ok((bytes, storage))
        })();
        let (bytes, storage) = match preflight {
            Ok(reserved) => reserved,
            Err(reason) => return Err((ingested, reason)),
        };
        let observed = attachment.generation();
        assert!(
            owner
                .adapter_mut()
                .install_closure_grant(&SessionClosureGrant::observe(attachment))
        );
        let (provenance, frontier) = ingested.into_provenance();
        let audit = JournalAuditReceipt::collect(provenance.collection(), &mut finalizer, observed);
        let (adapter, model) = owner.parts();
        // Finished rejections from a frame that no longer exists have no
        // holder: they drop here, before this frame issues its own.
        adapter.drop_unclaimed_rejections(None);
        // The S1-only negative settles inline when one credit covers it;
        // otherwise the frame holds its ticket and fills it under the
        // service budget before delivery.
        let (raw_failure, raw_fill) = match adapter.refuse_s1only_subjects(model) {
            Some((failure, pending)) => (Some(failure), pending),
            None => (None, None),
        };
        let mark = adapter.rejection_mark();
        let failure = adapter.audit_collected(model, &audit, fault).err();
        let audit_fill = failure
            .as_ref()
            .and_then(|_| adapter.rejection_issued_since(mark));
        // An ingest-break void's abandonment rides the next frame in its
        // own slot, so every pre-break consumer receives it.
        let (void_failure, void_storage, void_bytes) = take_void(owner);
        let frame = Self {
            provenance,
            ingress: FrameIngress::Ingested,
            frontier,
            audit,
            raw_failure,
            void_failure,
            failure,
            void_feed_ends_counted: [None; 4],
            consumers: Vec::new(),
            bound: false,
            cursor: 0,
            pending: 0,
            future: 0,
            active: None,
            park_cursor: 0,
            parked_total: 0,
            failure_storage: None,
            targets_storage: None,
            _storage: storage,
            _void_storage: void_storage,
            audit_fill,
            raw_fill,
            provisional: false,
            parked: None,
        };
        assert!(
            frame.retained_storage_bytes().is_some_and(|owned| bytes
                .checked_add(void_bytes)
                .is_some_and(|paid| owned <= paid)),
            "audit loss storage exceeds its checked preflight bound"
        );
        Ok(frame)
    }

    /// Take the original negative handoff without creating a clean/admitted
    /// route. Recheck current capacities before the sole H3 take: later model
    /// growth cannot reuse an older raw reservation as a smaller audit bound.
    #[allow(clippy::result_large_err)] // Refusal returns the original paid negative owner.
    pub(crate) fn audit_disposed(
        authorized: SessionDisposedAuditInput<'_>,
        attachment: &AttachedSemanticSet,
        fault: &impl FaultEpoch,
    ) -> DisposedAuditAcquisition {
        let (disposed, owner, mut finalizer, producers) = authorized.into_parts();
        let preflight = (|| {
            disposed.validate_owner(owner.adapter(), producers)?;
            if !owner
                .adapter()
                .disposed_has_only_future_input(disposed.frontier())
            {
                return Err(RawQuantumRefusal::H3Undisposed);
            }
            if attachment.domain() != producers.native_domain() {
                return Err(RawQuantumRefusal::ForeignCapture);
            }
            if !finalizer.ready_for_negative_audit(producers) {
                return Err(RawQuantumRefusal::H3Undisposed);
            }
            if attachment.generation() < owner.adapter().closure_generation {
                return Err(RawQuantumRefusal::ClosureStale);
            }
            // A raw refusal whose per-row work is still deferred fills
            // later: charge it at its full one-failure bound now.
            let raw_bytes = if owner.adapter().raw_rejection.is_some() {
                one_failure_bound(owner.adapter(), owner.model())
            } else {
                disposed.failure().map_or(Some(0), failure_storage)
            }
            .ok_or(RawQuantumRefusal::Capacity)?;
            let bytes = size_of::<Self>()
                .checked_add(raw_bytes)
                .and_then(|bytes| {
                    bytes.checked_add(one_failure_bound(owner.adapter(), owner.model())?)
                })
                .ok_or(RawQuantumRefusal::Capacity)?;
            // Reuse the original full allowance when it still covers the
            // actual buffers and current model. Later growth must acquire a
            // full replacement while the original remains paid and untaken.
            let replacement = if bytes > disposed.prepaid_bytes() {
                Some(
                    owner
                        .ledger()
                        .resource_reserver()
                        .ok_or(RawQuantumRefusal::ForeignLedger)?
                        .reserve(bytes)
                        .map_err(RawQuantumRefusal::Resource)?,
                )
            } else {
                None
            };
            Ok((bytes.max(disposed.prepaid_bytes()), replacement))
        })();
        let (bytes, replacement) = match preflight {
            Ok(paid) => paid,
            Err(reason) => return Err((disposed, reason)),
        };
        let observed = attachment.generation();
        assert!(
            owner
                .adapter_mut()
                .install_closure_grant(&SessionClosureGrant::observe(attachment))
        );
        let (provenance, frontier, reason, raw_failure, raw_storage) = disposed.into_parts();
        let storage = match replacement {
            Some(storage) => {
                // The replacement already covers the original buffers.
                drop(raw_storage);
                storage
            }
            None => raw_storage,
        };
        let audit = JournalAuditReceipt::collect(provenance.collection(), &mut finalizer, observed);
        let (adapter, model) = owner.parts();
        let raw_fill = raw_failure
            .as_ref()
            .and_then(|_| adapter.take_raw_rejection());
        adapter.drop_unclaimed_rejections(raw_fill);
        let mark = adapter.rejection_mark();
        let failure = adapter.audit_collected(model, &audit, fault).err();
        let audit_fill = failure
            .as_ref()
            .and_then(|_| adapter.rejection_issued_since(mark));
        let (void_failure, void_storage, void_bytes) = take_void(owner);
        let frame = Self {
            provenance,
            ingress: FrameIngress::Disposed(reason),
            frontier,
            audit,
            raw_failure,
            void_failure,
            failure,
            void_feed_ends_counted: [None; 4],
            consumers: Vec::new(),
            bound: false,
            cursor: 0,
            pending: 0,
            future: 0,
            active: None,
            park_cursor: 0,
            parked_total: 0,
            failure_storage: None,
            targets_storage: None,
            _storage: storage,
            _void_storage: void_storage,
            audit_fill,
            raw_fill,
            provisional: false,
            parked: None,
        };
        assert!(
            frame.retained_storage_bytes().is_some_and(|actual| bytes
                .checked_add(void_bytes)
                .is_some_and(|paid| actual <= paid)),
            "negative audit exceeded its fresh precharge"
        );
        Ok(frame)
    }

    pub(crate) fn identity(&self) -> RawQuantumIdentity {
        self.provenance.identity()
    }

    pub(crate) fn frontier(&self) -> ConsumptionOrdinal {
        self.frontier
    }

    pub(crate) fn validate_owner(
        &self,
        owner: &JointCaptureOwner,
        producers: &SessionDrainProducers,
    ) -> Result<(), RawQuantumRefusal> {
        self.provenance.validate_owner(owner.adapter(), producers)?;
        if owner.adapter().consumed_frontier() != self.frontier {
            return Err(RawQuantumRefusal::StaleFrontier);
        }
        Ok(())
    }

    fn retained_storage_bytes(&self) -> Option<usize> {
        size_of::<Self>()
            .checked_add(self.raw_failure.as_ref().map_or(Some(0), failure_storage)?)?
            .checked_add(
                self.void_failure
                    .as_ref()
                    .map_or(Some(0), failure_storage)?,
            )?
            .checked_add(self.failure.as_ref().map_or(Some(0), failure_storage)?)?
            .checked_add(allocation_bytes::<FrameConsumer>(
                self.consumers.capacity(),
            )?)?
            .checked_add(self.active.as_ref().map_or(Some(0), |active| {
                outcome_storage(&active.outcome)?.checked_add(lookup_storage(&active.outcome)?)
            })?)?
            .checked_add(self.parked.as_ref().map_or(Some(0), |parked| {
                outcome_storage(&parked.outcome)?.checked_add(lookup_storage(&parked.outcome)?)
            })?)
    }

    /// Whether an original this frame holds still waits on its deferred
    /// rejection's per-row work.
    fn awaits_rejection(&self) -> bool {
        self.audit_fill.is_some() || self.raw_fill.is_some() || self.parked.is_some()
    }

    /// Drive this frame's deferred rejections through the shared service
    /// budget (one leaf unit per row, debited before the read) and fill
    /// each finished one into its original, raw before audit before the
    /// parked seal (their decision order). Returns true when nothing this
    /// frame holds still waits.
    fn complete_rejections(
        &mut self,
        adapter: &mut super::JournalAdapter,
        model: &mut ObjectSemantics,
        remaining: &mut usize,
    ) -> bool {
        loop {
            let ticket = self
                .raw_fill
                .or(self.audit_fill)
                .or(self.parked.as_ref().and_then(|parked| parked.ticket));
            let Some(ticket) = ticket else {
                return true;
            };
            if let Some(done) = adapter.take_rejection(ticket) {
                if self.raw_fill == Some(ticket) {
                    self.raw_fill = None;
                    if let Some(raw) = self.raw_failure.as_mut() {
                        raw.fill_rejection(done);
                    }
                } else if self.audit_fill == Some(ticket) {
                    self.audit_fill = None;
                    if let Some(failure) = self.failure.as_mut() {
                        failure.fill_rejection(done);
                    }
                } else if let Some(parked) = self.parked.as_mut() {
                    parked.ticket = None;
                    if let Err(failure) = parked.outcome.as_mut() {
                        failure.fill_rejection(done);
                    }
                }
                continue;
            }
            if *remaining == 0 {
                return false;
            }
            adapter.drive_rejections(model, remaining);
        }
    }

    /// Whether one target's domain lies in an original failure's scope,
    /// including an all-key scope a deferred audit or raw rejection is
    /// still accumulating: those cover every adapter key at its current
    /// era (the scope the cursor will fill, since nothing rebinds a key
    /// while the frame holds it).
    fn failure_affects(&self, adapter: &super::JournalAdapter, target: &JointFeedTarget) -> bool {
        let domain = target.bootstrap().domain();
        if self
            .original_failures()
            .any(|failure| failure.affects_domain(domain))
        {
            return true;
        }
        if self.audit_fill.is_none() && self.raw_fill.is_none() {
            return false;
        }
        let proof = target.bootstrap().proof();
        adapter.keys.get(&proof.key).is_some_and(|state| {
            super::JournalDomainProof {
                key: proof.key,
                era: state.era,
            }
            .domain()
                == domain
        })
    }

    #[cfg(test)]
    pub(crate) fn audited_failure_for_test(
        &self,
        domain: ObjectDomain,
    ) -> Option<AuditedFailure<'_>> {
        self.failure_for(domain)
    }

    #[cfg(test)]
    pub(crate) fn failure_for_test(&self) -> Option<&SealFailure> {
        self.original_failures()
            .max_by_key(|failure| failure_rank(failure))
    }

    /// Pose a seal failure as this frame's recorded failure (the
    /// stuck-consumer twin's stand-in): the next delivery serves it
    /// instead of sealing. Test-only; the posed failure carries no
    /// buffers, so no storage lease is retained for it.
    #[cfg(test)]
    pub(crate) fn set_posed_failure_for_test(&mut self, failure: SealFailure) {
        self.active = None;
        self.failure = Some(failure);
    }

    #[cfg(test)]
    pub(crate) fn original_failures_for_test(&self) -> impl Iterator<Item = &SealFailure> {
        self.original_failures()
    }

    /// Borrow the actual consumer cursor and original spans. This observer
    /// cannot advance work, construct evidence or qualify continuation.
    #[cfg(test)]
    pub(crate) fn negative_effects_complete_for_test(&self, domain: ObjectDomain) -> Option<bool> {
        let consumer = self
            .consumers
            .iter()
            .find(|consumer| consumer.target.bootstrap().domain() == domain)?;
        let originals = self.failure_for(domain)?.originals;
        Some(
            originals[consumer.failure.slot..]
                .iter()
                .all(Option::is_none),
        )
    }

    #[cfg(test)]
    pub(crate) fn audit_for_test(&self) -> &JournalAuditReceipt {
        &self.audit
    }

    #[cfg(test)]
    pub(crate) fn awaits_fill_for_test(&self) -> bool {
        self.audit_fill.is_some() || self.raw_fill.is_some()
    }

    #[cfg(test)]
    pub(crate) fn consumer_progress_for_test(&self) -> (usize, usize, usize) {
        (self.pending, self.future, self.cursor)
    }

    /// Consumer states for provenance tests: (feed id, state label,
    /// streak, parked) in cursor order.
    #[cfg(test)]
    pub(crate) fn consumer_states_for_test(
        &self,
    ) -> Vec<(
        crate::discovery::caller_registry::instance_input::RegistryInstanceId,
        &'static str,
        u32,
        bool,
    )> {
        self.consumers
            .iter()
            .map(|consumer| {
                let state = match consumer.state {
                    ConsumerState::Pending => "Pending",
                    ConsumerState::NegativeOnly => "NegativeOnly",
                    ConsumerState::Future => "Future",
                    ConsumerState::Delivered => "Delivered",
                    ConsumerState::LossDelivered => "LossDelivered",
                };
                (
                    consumer.target.id(),
                    state,
                    consumer.stuck_streak,
                    consumer.parked,
                )
            })
            .collect()
    }

    /// Feed ids the frame proves stuck: unfinished consumers (Pending
    /// or Future) with a stuck-delivery streak, parked for forced
    /// fallback, or named by the frame's failure. The watchdog re-arm
    /// discards exactly these (when non-empty) instead of every
    /// touched feed, so healthy sessions that staged in the abandoned
    /// quantum keep their work for retry. Empty when the frame proves
    /// nothing stuck (an ambiguous transient before any delivery), in
    /// which case the re-arm keeps the existing touched-set scope.
    /// Delivered consumers are done (their queues are empty), so they
    /// never narrow the set.
    pub(crate) fn provenance_stuck_feed_ids(
        &self,
    ) -> Vec<crate::discovery::caller_registry::instance_input::RegistryInstanceId> {
        self.consumers
            .iter()
            .filter(|consumer| {
                matches!(
                    consumer.state,
                    ConsumerState::Pending | ConsumerState::Future
                ) && (consumer.stuck_streak > 0
                    || consumer.parked
                    // An all-key original still filling covers every
                    // consumer it will name (fail closed).
                    || self.audit_fill.is_some()
                    || self.raw_fill.is_some()
                    || self
                        .failure_for(consumer.target.bootstrap().domain())
                        .is_some())
            })
            .map(|consumer| consumer.target.id())
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn active_seal_for_test(&self) -> Option<&SealSuccess> {
        self.active.as_ref()?.outcome.as_ref().ok()
    }

    /// Read-only budget discriminator for the genuine frame's refusal test.
    #[cfg(test)]
    pub(crate) fn replay_reservation_for_test(
        &self,
        ports: &JointPublicationPorts<'_>,
    ) -> Option<(usize, usize, usize)> {
        self.preflight(ports).ok()?;
        let (_, owner, _, _) = ports.read();
        let bounds = ReplayBounds::sample(owner.adapter(), owner.model())?;
        Some((
            result_storage_bound(owner.adapter(), owner.model())?,
            bounds.retained_bytes()?,
            bounds.temporary_bytes()?,
        ))
    }

    #[cfg(test)]
    pub(crate) fn retained_storage_bytes_for_test(&self) -> usize {
        self.retained_storage_bytes()
            .expect("retained bounded storage")
    }

    /// Classification controls borrow this real frame's original affected
    /// ResourceUnavailable. Restore the audit before any actual delivery.
    #[cfg(test)]
    pub(crate) fn assert_resource_disposition_provenance_for_test(&mut self, domain: ObjectDomain) {
        assert!(self.audit.resource_refused);
        assert_eq!(
            self.failure_for(domain).unwrap().disposition(),
            SealFailureDisposition::HistoryLoss
        );
        assert_eq!(
            disposition_of(JournalGap::ResourceUnavailable),
            SealFailureDisposition::Fallback,
            "seal-time resource refusal with retained custody still falls back"
        );
        self.audit.resource_refused = false;
        assert_eq!(
            self.failure_for(domain).unwrap().disposition(),
            SealFailureDisposition::Fallback,
            "ResourceUnavailable alone does not prove original audit disposal"
        );
        self.audit.resource_refused = true;
        assert_eq!(
            self.failure_for(domain).unwrap().disposition(),
            SealFailureDisposition::HistoryLoss
        );
    }

    /// Exercise rejection interlocks using the real mixed frame's three
    /// retained proofs. Every adversarial state/scope change is restored
    /// before the original frame continues through actual bounded delivery.
    #[cfg(test)]
    pub(crate) fn assert_pending_refusal_provenance_for_test(
        &mut self,
        adapter: &mut JournalAdapter,
        exact: super::JournalDomainProof,
        image: super::JournalDomainProof,
        healthy: super::JournalDomainProof,
    ) {
        assert_eq!(size_of::<super::JournalDomainState>(), 72);
        assert_eq!(std::mem::align_of::<super::JournalDomainState>(), 8);
        assert_ne!(exact.key, image.key);
        assert_ne!(exact.key, healthy.key);
        assert_ne!(image.key, healthy.key);
        assert!(!adapter.is_tainted((exact.key.cookie, exact.key.exec)));
        assert!(adapter.is_tainted((image.key.cookie, image.key.exec)));
        assert!(!adapter.is_tainted((healthy.key.cookie, healthy.key.exec)));
        assert!(adapter.keys[&exact.key].s1only_original_refused);
        assert!(!adapter.keys[&image.key].s1only_original_refused);
        assert!(!adapter.keys[&healthy.key].s1only_original_refused);
        assert_eq!(self.pending_refused_proof(adapter, exact.key), Some(exact));
        assert_eq!(self.pending_refused_proof(adapter, image.key), Some(image));
        assert_eq!(self.pending_refused_proof(adapter, healthy.key), None);

        // An actual unrelated key cannot borrow the exact subject's flag,
        // even if a purported union names it and it also appears refused.
        let mut purported = vec![exact.domain(), healthy.domain()];
        purported.sort_unstable();
        let original_scope = std::mem::replace(
            &mut self.raw_failure.as_mut().unwrap().scope,
            SealFailureScope::AffectedDomains(purported),
        );
        let healthy_refused = adapter.keys[&healthy.key].refused;
        adapter.keys.get_mut(&healthy.key).unwrap().refused = true;
        assert_eq!(self.pending_refused_proof(adapter, healthy.key), None);
        adapter.keys.get_mut(&healthy.key).unwrap().refused = healthy_refused;
        self.raw_failure.as_mut().unwrap().scope =
            SealFailureScope::AffectedDomains(vec![image.domain()]);
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        self.raw_failure.as_mut().unwrap().scope = original_scope;

        // The DomainTainted class alone is never exact-original provenance.
        // The same genuine original's flag, retained era and refusal must
        // all still qualify against the original immutable union.
        adapter
            .keys
            .get_mut(&exact.key)
            .unwrap()
            .s1only_original_refused = false;
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        let original_gap = self.raw_failure.as_ref().unwrap().gap;
        self.raw_failure.as_mut().unwrap().gap = JournalGap::DomainTainted;
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        self.raw_failure.as_mut().unwrap().gap = original_gap;
        adapter
            .keys
            .get_mut(&exact.key)
            .unwrap()
            .s1only_original_refused = true;

        adapter.keys.get_mut(&exact.key).unwrap().era = exact.era.checked_add(1).unwrap();
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        adapter.keys.get_mut(&exact.key).unwrap().era = exact.era;
        adapter.keys.get_mut(&exact.key).unwrap().era_ended = true;
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        adapter.keys.get_mut(&exact.key).unwrap().era_ended = false;
        adapter.keys.get_mut(&exact.key).unwrap().refused = false;
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        adapter.keys.get_mut(&exact.key).unwrap().refused = true;

        assert!(self.raw_failure.as_ref().unwrap().h3_voided.is_none());
        self.raw_failure.as_mut().unwrap().h3_voided = Some(self.audit.h0_below);
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        self.raw_failure.as_mut().unwrap().h3_voided = None;
        self.raw_failure.as_mut().unwrap().gap = JournalGap::H3Pending;
        assert_eq!(self.pending_refused_proof(adapter, exact.key), None);
        self.raw_failure.as_mut().unwrap().gap = original_gap;
        assert_eq!(self.pending_refused_proof(adapter, exact.key), Some(exact));
        assert_eq!(self.pending_refused_proof(adapter, image.key), Some(image));
    }
}

impl IngestedJointQuantum {
    fn preflight(&self, ports: &JointPublicationPorts<'_>) -> Result<(), RawQuantumRefusal> {
        let (_, owner, _, producers) = ports.read();
        self.validate_owner(owner, producers)
    }

    fn pending_raw_scope_contains(&self, domain: ObjectDomain) -> bool {
        let Some(raw) = &self.raw_failure else {
            return false;
        };
        let SealFailureScope::AffectedDomains(domains) = &raw.scope else {
            return false;
        };
        domains.binary_search(&domain).is_ok()
    }

    /// This exception belongs only to the exact pending continuation below.
    /// It neither makes a key live nor permits a new seal/fallback. The
    /// original bulk negative captured this typed key-era before refusal.
    fn pending_refused_proof(
        &self,
        adapter: &JournalAdapter,
        key: super::JournalDomainKey,
    ) -> Option<super::JournalDomainProof> {
        let raw = self.raw_failure.as_ref()?;
        if !matches!(
            raw.gap,
            JournalGap::ImageTainted | JournalGap::DomainTainted
        ) || raw.h3_voided.is_some()
        {
            return None;
        }
        let state = adapter.keys.get(&key)?;
        let proof = super::JournalDomainProof {
            key,
            era: state.era,
        };
        (state.refused
            && !state.era_ended
            && (adapter.is_tainted((key.cookie, key.exec)) || state.s1only_original_refused)
            && self.pending_raw_scope_contains(proof.domain()))
        .then_some(proof)
    }

    fn pending_negative_delivered(
        &self,
        consumer: &FrameConsumer,
        adapter: &JournalAdapter,
    ) -> bool {
        let proof = consumer.target.bootstrap().proof();
        if self.pending_refused_proof(adapter, proof.key) != Some(proof)
            || !matches!(
                consumer.state,
                ConsumerState::Pending | ConsumerState::Future | ConsumerState::LossDelivered
            )
            || consumer.failure.consumed != 0
            || consumer.failure.suffix.is_some()
            || consumer.failure.invalidated
            || consumer.failure.resource_failed
        {
            return false;
        }
        let Some(audited) = self.failure_for(consumer.target.bootstrap().domain()) else {
            return false;
        };
        // Same immutable owners as bounded delivery; empty originals still
        // need their actual transition consumed, never a readiness bit alone.
        audited.originals[consumer.failure.slot..]
            .iter()
            .all(Option::is_none)
    }

    /// A truthful H3-pending audit is not a clean audit and cannot seal or
    /// replay. Only the live producer's original pending custody permits its
    /// immutable frame metadata to retire so the next H0 batch can arrive.
    fn pending_h3_is_owned(
        &self,
        ports: &JointPublicationPorts<'_>,
        view: &crate::inventory_semantics::JointContinuationView<'_>,
    ) -> bool {
        let (registry, owner, _, producers) = ports.read();
        let adapter = owner.adapter();
        let Some(failure) = &self.failure else {
            return false;
        };
        let H3DispositionEvidence::Clean {
            staged_max,
            pending_floor: Some(floor),
        } = &self.audit.h3
        else {
            return false;
        };
        if failure.gap != JournalGap::H3Pending
            || !matches!(failure.scope, SealFailureScope::Unqualified)
            || failure.h3_voided.is_some()
            || !failure.effects.effects.is_empty()
            || *floor >= self.audit.h0_below
            || self.audit.resource_refused
            || self.audit.closure_generation != adapter.closure_generation
            || adapter
                .last_fault
                .is_some_and(|previous| previous != self.audit.fault_after)
            || !adapter.refused.is_empty()
            || adapter.stopped
            || adapter.invalidated
            || self.active.is_some()
            || self.original_failures().any(|failure| {
                failure.h3_voided.is_some()
                    || disposition_of(failure.gap) == SealFailureDisposition::HistoryLoss
            })
            // A frame carrying a void (fenced, Fallback since the
            // ingest-break replay) enters the pending continuation
            // only after every consumer the void affects is
            // LossDelivered: the void is taken once, so retiring
            // early would drop its fence and its invalidations with
            // it, leaving pre-void associations closable across the
            // hole. The void slot is the only fenced original that
            // can ride a continuation-eligible frame (audit voids
            // fail the gap check above; raw taints are fenceless).
            || self.void_failure.as_ref().is_some_and(|void| {
                self.consumers.iter().any(|consumer| {
                    void.affects_domain(consumer.target.bootstrap().domain())
                        && consumer.state != ConsumerState::LossDelivered
                })
            })
            || self.raw_failure.as_ref().is_some_and(|raw| {
                !matches!(
                    raw.gap,
                    JournalGap::ImageTainted | JournalGap::DomainTainted
                )
            })
        {
            return false;
        }
        view.inspect(|pending| {
            if !pending.matches(
                producers,
                self.audit.h0_below,
                *floor,
                self.audit.fault_after,
            ) {
                return false;
            }
            let mut verified_negative = 0usize;
            for consumer in &self.consumers {
                if !self.pending_raw_scope_contains(consumer.target.bootstrap().domain()) {
                    continue;
                }
                if !self.pending_negative_delivered(consumer, adapter) {
                    return false;
                }
                let Some(count) = registry.joint_staged_count(&consumer.target) else {
                    return false;
                };
                match registry.joint_history_mode(&consumer.target) {
                    Some(FeedMode::S1Only)
                        if count == 0 && consumer.state == ConsumerState::LossDelivered =>
                    {
                        continue;
                    }
                    Some(FeedMode::Joint) => {}
                    _ => return false,
                }
                // Visit the existing FIFO once; no target-vector lookup for
                // each H8 claim and no copied admission/native index.
                for index in 0..count {
                    let Some((admission, native)) =
                        registry.joint_staged_original_at(&consumer.target, index)
                    else {
                        return false;
                    };
                    let Some(entry) = adapter.open.get(&native) else {
                        return false;
                    };
                    if adapter
                        .completed_fallback_original(
                            entry,
                            &self.audit,
                            consumer.target.bootstrap().proof().key,
                            self.frontier,
                            *staged_max,
                            &consumer.target,
                            registry,
                        )
                        .ok()
                        != Some(Some(admission))
                    {
                        return false;
                    }
                    verified_negative += 1;
                }
            }
            let mut unclaimed = 0usize;
            let mut claimed = 0usize;
            let mut refused_claimed = 0usize;
            for entry in adapter.open.values() {
                let shape = super::shape_of_entry(entry);
                let claimants = adapter.claims.get(&shape.identity);
                let has_claim = adapter.identity_claimed(&shape.identity);
                let Some(end) = entry.end else {
                    // A genuine unclaimed START remains in H8 unchanged.
                    if has_claim || entry.abandon.is_some() || entry.corroborated_return.is_some() {
                        return false;
                    }
                    continue;
                };
                let (Some(origin), Some(resource)) = (entry.collected_origin, entry.raw_resource)
                else {
                    return false;
                };
                if entry.begin_ordinal > self.frontier.0
                    || end.ordinal > self.frontier.0
                    || origin.position() >= self.audit.h0_below
                    || entry.converted_ticket.is_some()
                    || entry.converted_for.is_some()
                    || entry.call_key.is_some()
                    || entry.end_converted
                    || entry.abandon.is_some()
                    || entry.corroborated_return.is_some()
                    || !super::end_agrees_with_begin(&entry.begin, &end.end)
                {
                    return false;
                }
                if has_claim {
                    let mut originals = claimants
                        .into_iter()
                        .flat_map(|claimants| claimants.iter())
                        .flat_map(|(key, claims)| claims.iter().map(move |claim| (key, claim)));
                    let Some((key, claim)) = originals.next() else {
                        return false;
                    };
                    let live = adapter.key_is_live(*key);
                    if originals.next().is_some()
                        || !super::claim_names_shape(&shape, claim)
                        || (!live && self.pending_refused_proof(adapter, *key).is_none())
                        || key.domain_tag != producers.native_domain().journal_tag()
                        || (key.cookie, key.exec) != entry.image
                        || claim.admission != origin.position()
                        || claim.admission > *staged_max
                        || claim.return_ns != end.end.payload_base().event.ts_ns
                        || !adapter.ledger.matches_unconverted_original(
                            entry.begin_ordinal,
                            &resource,
                            Some((key.domain_tag, claim.admission)),
                        )
                    {
                        return false;
                    }
                    refused_claimed += usize::from(!live);
                    claimed += 1;
                } else {
                    if !adapter.ledger.matches_unconverted_original(
                        entry.begin_ordinal,
                        &resource,
                        None,
                    ) {
                        return false;
                    }
                    unclaimed += 1;
                }
            }
            // A shared physical fingerprint cannot count one admission for
            // two opens. Refused/unrepresented or unmatched claims also stay
            // local; a numeric pending floor cannot forgive them.
            if claimed != adapter.claim_counts || refused_claimed != verified_negative {
                return false;
            }
            let mut covered = 0usize;
            let mut floor_seen = false;
            for (position, origin, record, resource) in pending.originals() {
                let (Some(position), Some(origin), Some(resource)) = (position, origin, resource)
                else {
                    return false;
                };
                let Some(entry) = adapter.open.get(&resource.invocation()) else {
                    return false;
                };
                let Some(end) = entry.end else {
                    return false;
                };
                let shape = super::shape_of_entry(entry);
                if position != origin.position()
                    || position < *floor
                    || position >= self.audit.h0_below
                    || entry.collected_origin != Some(origin)
                    || !resource.matches_producers(producers)
                    || !super::event_names_shape(&shape, &record.event)
                    || record.event.ts_ns != end.end.payload_base().event.ts_ns
                    || adapter.identity_claimed(&shape.identity)
                    || !adapter.ledger.matches_unconverted_original(
                        entry.begin_ordinal,
                        resource.reservation(),
                        None,
                    )
                {
                    return false;
                }
                covered += 1;
                floor_seen |= position == *floor;
            }
            floor_seen && covered == unclaimed
        })
    }

    pub(crate) fn defer_pending_h3(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        lane: &crate::inventory_semantics::AttestedSemanticLane,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        self.preflight(ports)?;
        if !self.bound || self.active.is_some() {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        lane.with_joint_continuation(|view| self.defer_pending_h3_with_view(ports, view))
            .unwrap_or(Ok(QuantumSealProgress::LocalPending))
    }

    pub(crate) fn defer_pending_h3_with_view(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        view: &crate::inventory_semantics::JointContinuationView<'_>,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        self.preflight(ports)?;
        if !self.bound || self.active.is_some() {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        if self.awaits_rejection() || !self.pending_h3_is_owned(ports, view) {
            return Ok(QuantumSealProgress::LocalPending);
        }
        // H3 remains pending. Preserve only the already-checked native fault
        // prefix so a first pending frame cannot forget a later epoch move.
        let (_, owner, _, _, _) = ports.split();
        owner.adapter_mut().last_fault = Some(self.audit.fault_after);
        for consumer in &mut self.consumers {
            if consumer.state == ConsumerState::Pending {
                consumer.state = ConsumerState::Future;
                self.pending -= 1;
                self.future += 1;
            }
        }
        self.cursor = self.consumers.len();
        self.reset_park();
        Ok(self.progress())
    }

    pub(crate) fn bind_targets(
        &mut self,
        ports: &JointPublicationPorts<'_>,
    ) -> Result<(), RawQuantumRefusal> {
        self.preflight(ports)?;
        if self.bound {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        let (registry, owner, bindings, _) = ports.read();
        let count = registry.joint_history_targets().count();
        for (target, mode) in registry.joint_history_targets() {
            // Negative fanout still reaches history whose caller binding has
            // ended. Only a fresh positive seal needs the current binding.
            if matches!(self.ingress, FrameIngress::Disposed(_))
                || mode == FeedMode::S1Only
                || self.failure_affects(owner.adapter(), &target)
            {
                continue;
            }
            check_positive_binding(bindings, &target)?;
        }
        let bytes = allocation_bytes::<FrameConsumer>(count).ok_or(RawQuantumRefusal::Capacity)?;
        let storage = owner
            .ledger()
            .resource_reserver()
            .ok_or(RawQuantumRefusal::ForeignLedger)?
            .reserve(bytes)
            .map_err(RawQuantumRefusal::Resource)?;
        let mut consumers = Vec::new();
        consumers
            .try_reserve_exact(count)
            .map_err(|_| RawQuantumRefusal::Allocation)?;
        if allocation_bytes::<FrameConsumer>(consumers.capacity())
            .is_none_or(|actual| actual > bytes)
        {
            return Err(RawQuantumRefusal::Capacity);
        }
        let mut provisional = false;
        consumers.extend(registry.joint_history_targets().map(|(target, mode)| {
            let affects = self.failure_affects(owner.adapter(), &target);
            // Pending only under a still-filling original's all-key
            // bound: the exact scope reconciles it after the fill.
            let tentative = affects && !self.exactly_affects(&target);
            provisional |= tentative;
            FrameConsumer {
                target,
                state: if mode == FeedMode::Joint || affects {
                    ConsumerState::Pending
                } else {
                    ConsumerState::NegativeOnly
                },
                failure: FailureReplayCursor::default(),
                stuck_streak: 0,
                parked: false,
                last_stuck_gap: None,
                mode,
                provisional: tentative,
            }
        }));
        // One charged snapshot, no duplicate-domain hash table or queue.
        consumers.sort_unstable_by_key(|consumer| consumer.target.bootstrap().domain());
        if consumers
            .windows(2)
            .any(|pair| pair[0].target.bootstrap().domain() == pair[1].target.bootstrap().domain())
        {
            return Err(RawQuantumRefusal::Admission);
        }
        consumers.sort_unstable_by_key(|consumer| consumer.target.id());
        self.pending = consumers
            .iter()
            .filter(|consumer| consumer.state == ConsumerState::Pending)
            .count();
        self.cursor = consumers
            .iter()
            .position(|consumer| consumer.state == ConsumerState::Pending)
            .unwrap_or(consumers.len());
        self.consumers = consumers;
        self.targets_storage = Some(storage);
        self.provisional = provisional;
        self.bound = true;
        Ok(())
    }

    /// Whether an original failure's exact (filled) scope names this
    /// target, without a still-filling original's all-key bound.
    fn exactly_affects(&self, target: &JointFeedTarget) -> bool {
        let domain = target.bootstrap().domain();
        self.original_failures()
            .any(|failure| failure.affects_domain(domain))
    }

    /// Once every original has filled, settle each provisional consumer
    /// against the exact scope exactly as binding would have: one the
    /// filled failures name stays Pending for its negative; a disjoint
    /// S1-only history becomes negative-only; a disjoint Joint history
    /// stays positive and must hold its current binding (the check the
    /// provisional bound waived). Nothing read or delivered a consumer
    /// while the fills ran.
    fn reconcile_provisional(
        &mut self,
        ports: &JointPublicationPorts<'_>,
    ) -> Result<(), RawQuantumRefusal> {
        if !self.provisional || self.audit_fill.is_some() || self.raw_fill.is_some() {
            return Ok(());
        }
        let (_, _, bindings, _) = ports.read();
        for index in 0..self.consumers.len() {
            let consumer = &self.consumers[index];
            if !consumer.provisional || self.exactly_affects(&consumer.target) {
                continue;
            }
            if consumer.mode == FeedMode::Joint {
                check_positive_binding(bindings, &consumer.target)?;
            }
        }
        for index in 0..self.consumers.len() {
            if !self.consumers[index].provisional {
                continue;
            }
            self.consumers[index].provisional = false;
            let target = self.consumers[index].target;
            if self.consumers[index].mode != FeedMode::Joint
                && !self.exactly_affects(&target)
                && self.consumers[index].state == ConsumerState::Pending
            {
                self.consumers[index].state = ConsumerState::NegativeOnly;
                self.pending -= 1;
            }
        }
        self.provisional = false;
        self.cursor = self
            .consumers
            .iter()
            .position(|consumer| consumer.state == ConsumerState::Pending)
            .unwrap_or(self.consumers.len());
        Ok(())
    }

    fn advance_consumer(&mut self, state: ConsumerState) {
        debug_assert!(self.consumers[self.cursor].state == ConsumerState::Pending);
        self.consumers[self.cursor].state = state;
        // Advancing is progress: the stuck streak, park flag and last
        // gap reset with the state move.
        self.consumers[self.cursor].stuck_streak = 0;
        self.consumers[self.cursor].parked = false;
        self.consumers[self.cursor].last_stuck_gap = None;
        self.pending -= 1;
        self.future += usize::from(state == ConsumerState::Future);
        self.skip_completed_consumers();
        self.reset_park();
    }

    fn skip_completed_consumers(&mut self) {
        while self.cursor < self.consumers.len()
            && self.consumers[self.cursor].state != ConsumerState::Pending
        {
            self.cursor += 1;
        }
    }

    /// Reset sliced park cursors: frame progress moved consumers, so
    /// any parked run in progress restarts fresh next watchdog fire
    /// instead of resuming past newly stuck consumers.
    fn reset_park(&mut self) {
        self.park_cursor = 0;
        self.parked_total = 0;
    }

    fn advance_pending_visit(&mut self) {
        // A charged visit is progress: reset the passed consumer's
        // stuck streak (its state stays Pending for its spans).
        if self.cursor < self.consumers.len() {
            self.consumers[self.cursor].stuck_streak = 0;
            self.consumers[self.cursor].last_stuck_gap = None;
        }
        self.cursor += 1;
        self.skip_completed_consumers();
        self.reset_park();
    }

    /// Park delivery-stuck consumers (watchdog): every Pending
    /// consumer with a stuck-delivery streak that is not already
    /// parked degrades on its next delivery (forced fallback with
    /// counted loss) instead of retrying, so the frame cursor
    /// advances past it. Future consumers keep waiting (their input
    /// may still arrive); terminal consumers are done. Scans from
    /// the stalled (seal) cursor in stride slices through the budget
    /// with a resumable park cursor; yields when the budget
    /// exhausts. On completion returns the newly parked total; zero
    /// means no consumer can progress by parking (all Future,
    /// terminal, or already parked).
    pub(crate) fn park_stuck_consumers_bounded(&mut self, budget: &mut usize) -> ParkProgress {
        if self.park_cursor == 0 && self.parked_total == 0 {
            self.park_cursor = self.cursor;
        }
        loop {
            if *budget == 0 {
                return ParkProgress::Yielded;
            }
            let allowance = super::SCOPED_RECOVERY_SLICE.min(*budget);
            let mut examined = 0usize;
            while self.park_cursor < self.consumers.len() && examined < allowance {
                let consumer = &mut self.consumers[self.park_cursor];
                self.park_cursor += 1;
                examined += 1;
                if consumer.state == ConsumerState::Pending
                    && consumer.stuck_streak > 0
                    && !consumer.parked
                {
                    consumer.parked = true;
                    self.parked_total += 1;
                }
            }
            *budget = budget.saturating_sub(examined);
            if self.park_cursor >= self.consumers.len() {
                let total = self.parked_total;
                self.reset_park();
                return ParkProgress::Done(total);
            }
        }
    }

    fn progress(&self) -> QuantumSealProgress {
        if self.active.is_some() {
            return QuantumSealProgress::DeliveryReady;
        }
        if self.pending != 0 {
            return QuantumSealProgress::LocalPending;
        }
        if self.future != 0 {
            QuantumSealProgress::AwaitFutureInput
        } else {
            QuantumSealProgress::Complete
        }
    }

    fn failure_for(&self, domain: ObjectDomain) -> Option<AuditedFailure<'_>> {
        AuditedFailure::new(
            [
                self.void_failure.as_ref(),
                self.raw_failure.as_ref(),
                self.failure
                    .as_ref()
                    .or_else(|| self.active.as_ref()?.outcome.as_ref().err()),
            ],
            &self.audit,
            &self.provenance,
            self.frontier,
            domain,
        )
    }

    pub(crate) fn seal_next_bounded(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        births: &mut impl JointBirthEvidenceSource,
        fault: &impl FaultEpoch,
        remaining: &mut usize,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        self.preflight(ports)?;
        if !self.bound {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        if *remaining == 0 {
            return Ok(self.progress());
        }
        // Deferred rejection work first: no original is read, sealed past
        // or delivered until its per-row work has filled it.
        if self.awaits_rejection() {
            let (_, owner, _, _, _) = ports.split();
            let (adapter, model) = owner.parts();
            if !self.complete_rejections(adapter, model, remaining) {
                return Ok(QuantumSealProgress::DeliveryReady);
            }
            self.reconcile_provisional(ports)?;
            if let Some(parked) = self.parked.take() {
                return Ok(self.settle_outcome(
                    ports,
                    parked.consumer,
                    parked.outcome,
                    parked.storage,
                    parked.bytes,
                    remaining,
                ));
            }
        }
        if self.active.is_some() {
            return Ok(QuantumSealProgress::DeliveryReady);
        }
        if self.pending == 0 {
            return Ok(self.progress());
        }
        // Pending-H3 negative service may have visited every consumer while
        // leaving original producer-owned history Pending. Only the exact
        // continuation can turn it Future; no finished-cursor indexing.
        if self.cursor == self.consumers.len() {
            return Ok(QuantumSealProgress::LocalPending);
        }
        let index = self.cursor;
        if self
            .failure_for(self.consumers[index].target.bootstrap().domain())
            .is_some()
        {
            return Ok(QuantumSealProgress::DeliveryReady);
        }
        if self.failure.is_some() {
            return Ok(QuantumSealProgress::LocalPending);
        }
        if let FrameIngress::Disposed(reason) = self.ingress {
            let _ = reason; // Retain the original reason, never positive authority.
            return Ok(QuantumSealProgress::DeliveryReady);
        }
        // Only a Joint history seals positively: an S1-only consumer is
        // Pending solely for a failure that names it (served above).
        if self.consumers[index].mode != FeedMode::Joint || self.consumers[index].provisional {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        // An unrelated raw-only image negative does not replace the actual
        // clean collection audit for this disjoint selected Joint target.
        let target = self.consumers[index].target;
        let (_, owner, bindings, _, _) = ports.split();
        let binding = bindings
            .get(target.caller())
            .ok_or(RawQuantumRefusal::Admission)?;
        let bounds = ReplayBounds::sample(owner.adapter(), owner.model())
            .ok_or(RawQuantumRefusal::Capacity)?;
        let bytes = result_storage_bound(owner.adapter(), owner.model())
            .and_then(|base| base.checked_add(bounds.retained_bytes()?))
            .ok_or(RawQuantumRefusal::Capacity)?;
        let temporary = bounds
            .temporary_bytes()
            .ok_or(RawQuantumRefusal::Capacity)?;
        let reserver = owner
            .ledger()
            .resource_reserver()
            .ok_or(RawQuantumRefusal::ForeignLedger)?;
        let storage = reserver
            .reserve(bytes)
            .map_err(RawQuantumRefusal::Resource)?;
        let locator_storage = reserver
            .reserve(temporary)
            .map_err(RawQuantumRefusal::Resource)?;
        let replay = ReplayPreparation::allocate(bounds, locator_storage)
            .ok_or(RawQuantumRefusal::Capacity)?;
        let (adapter, model) = owner.parts();
        let input = AuditedDomainInput {
            audit: &self.audit,
            receipt: target.bootstrap(),
            frontier: self.frontier,
        };
        let mut selected = SelectedBirth {
            source: births,
            target: &target,
            binding,
        };
        let mark = adapter.rejection_mark();
        // A refusal decided by this seal runs its inline rejection work
        // from this same service budget, never past it.
        adapter.bound_inline_credit(*remaining);
        let outcome = adapter.seal_in_audit(model, input, &mut selected, fault, replay);
        let spent = adapter.take_inline_spent();
        *remaining = remaining.saturating_sub(spent);
        assert!(
            outcome_storage(&outcome).is_some_and(|actual| actual <= bytes),
            "retained seal result exceeds its checked preflight bound"
        );
        assert!(
            lookup_storage(&outcome).is_some_and(|actual| actual <= temporary),
            "retained original lookup exceeds its original preflight lease"
        );
        if outcome.is_err()
            && let Some(ticket) = adapter.rejection_issued_since(mark)
        {
            // The refusal published; its per-row work (an audit void's
            // preserve/fence/wipe, a doomed key's model rows) runs under
            // this shared budget, resuming next service when it
            // exhausts. The outcome settles only once filled.
            self.parked = Some(ParkedSeal {
                consumer: index,
                ticket: Some(ticket),
                outcome,
                storage,
                bytes,
            });
            if !self.complete_rejections(adapter, model, remaining) {
                return Ok(QuantumSealProgress::DeliveryReady);
            }
            let parked = self.parked.take().expect("filled parked seal");
            return Ok(self.settle_outcome(
                ports,
                parked.consumer,
                parked.outcome,
                parked.storage,
                parked.bytes,
                remaining,
            ));
        }
        Ok(self.settle_outcome(ports, index, outcome, storage, bytes, remaining))
    }

    /// Settle one selected seal outcome (filled): a broad failure
    /// requeues every consumer it affects; a fresh birth with no history
    /// of its own waits as future input; anything else becomes the
    /// active delivery.
    fn settle_outcome(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        index: usize,
        outcome: Result<SealSuccess, SealFailure>,
        storage: ResourceLease,
        bytes: usize,
        remaining: &mut usize,
    ) -> QuantumSealProgress {
        assert!(
            outcome_storage(&outcome).is_some_and(|actual| actual <= bytes),
            "retained seal result exceeds its checked preflight bound"
        );
        let target = self.consumers[index].target;
        let (_, owner, _, _, _) = ports.split();
        let adapter = owner.adapter();
        if let Err(failure) = &outcome {
            if matches!(failure.scope, SealFailureScope::AffectedDomains(_)) {
                let failure = outcome.expect_err("checked original broad failure");
                for consumer in &mut self.consumers {
                    if failure.affects_domain(consumer.target.bootstrap().domain()) {
                        self.pending += usize::from(consumer.state != ConsumerState::Pending);
                        self.future -= usize::from(consumer.state == ConsumerState::Future);
                        consumer.state = ConsumerState::Pending;
                        consumer.failure = FailureReplayCursor::default();
                    }
                }
                // One broad failure may revisit earlier positives. Rewind
                // once, rather than rescan the whole target list per delivery.
                self.cursor = self
                    .consumers
                    .iter()
                    .position(|consumer| consumer.state == ConsumerState::Pending)
                    .unwrap_or(self.consumers.len());
                self.failure = Some(failure);
                self.failure_storage = Some(storage);
                self.reset_park();
                return QuantumSealProgress::DeliveryReady;
            }
            // A fresh birth with no staged call of its own inside this
            // frontier (late attach, an idle caller) can only be grounded
            // by the caller's future calls: this immutable frame never
            // seals it, so it waits as future input exactly like an
            // awaited terminal, instead of retrying until the lane-wide
            // no-progress bound stops every caller.
            if failure.gap == JournalGap::BoundNotReady
                && (adapter.last_seal_wait() == SealWait::FreshBirthNoHistory
                    || adapter.awaits_future_terminal(target.bootstrap(), self.frontier))
            {
                // This original target advanced without a delivery. Charge
                // the same shared slice so later targets and the machine's
                // no-progress guard observe the actual committed work.
                *remaining -= 1;
                self.advance_consumer(ConsumerState::Future);
                return QuantumSealProgress::AwaitFutureInput;
            }
        }
        self.active = Some(ActiveSeal {
            consumer: index,
            outcome,
            replay: SealReplayCursor::default(),
            _storage: storage,
        });
        QuantumSealProgress::DeliveryReady
    }

    #[cfg(test)]
    pub(crate) fn seal_next(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        births: &mut impl JointBirthEvidenceSource,
        fault: &impl FaultEpoch,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        let mut remaining = usize::MAX;
        self.seal_next_bounded(ports, births, fault, &mut remaining)
    }

    /// One shared service budget covers original effects, empty phases,
    /// completed-fallback preflight and exact head disposition. Yielding
    /// retains the same result, both negative originals and all held roles.
    pub(crate) fn deliver_next_bounded(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        remaining: &mut usize,
        diagnosis: &mut DeliverDiagnosis,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        self.preflight(ports)?;
        if !self.bound {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        if self.awaits_rejection() {
            // An original still filling is never delivered partially:
            // its deferred work runs first, from this same budget.
            let (_, owner, _, _, _) = ports.split();
            let (adapter, model) = owner.parts();
            if !self.complete_rejections(adapter, model, remaining) {
                diagnosis.note_other();
                return Ok(QuantumSealProgress::DeliveryReady);
            }
            self.reconcile_provisional(ports)?;
            if let Some(parked) = self.parked.take() {
                diagnosis.note_other();
                return Ok(self.settle_outcome(
                    ports,
                    parked.consumer,
                    parked.outcome,
                    parked.storage,
                    parked.bytes,
                    remaining,
                ));
            }
        }
        if self.pending == 0 {
            diagnosis.note_other();
            return Ok(self.progress());
        }
        if self.cursor == self.consumers.len() {
            diagnosis.note_other();
            return Ok(QuantumSealProgress::LocalPending);
        }
        let index = self
            .active
            .as_ref()
            .map_or(self.cursor, |active| active.consumer);
        let target = self.consumers[index].target;
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.outcome.is_ok())
        {
            let active = self.active.as_mut().expect("selected actual result");
            let seal = active.outcome.as_ref().expect("positive original result");
            let mut batch = SealBatchDelivery::new(seal, &mut active.replay);
            let entry_zero = *remaining == 0;
            let entry_exhausted = batch.effects_complete();
            let (registry, owner, _, _, _) = ports.split();
            let (adapter, model) = owner.parts();
            let outcome = registry.deliver_joint_seal(
                target.id(),
                &mut batch,
                model,
                adapter.ledger_mut(),
                remaining,
            );
            diagnosis.record(&outcome, entry_zero, entry_exhausted);
            return match outcome {
                SealBatchProgress::Complete { .. } => {
                    self.active = None;
                    self.advance_consumer(ConsumerState::Delivered);
                    Ok(self.progress())
                }
                SealBatchProgress::Yielded { .. } => Ok(QuantumSealProgress::DeliveryReady),
                SealBatchProgress::Held => Ok(QuantumSealProgress::LocalPending),
            };
        }
        let Some(audited) = AuditedFailure::new(
            [
                self.void_failure.as_ref(),
                self.raw_failure.as_ref(),
                self.failure
                    .as_ref()
                    .or_else(|| self.active.as_ref()?.outcome.as_ref().err()),
            ],
            &self.audit,
            &self.provenance,
            self.frontier,
            target.bootstrap().domain(),
        ) else {
            if matches!(self.ingress, FrameIngress::Disposed(_)) && self.failure.is_none() {
                if *remaining == 0 {
                    diagnosis.note_other();
                    return Ok(QuantumSealProgress::DeliveryReady);
                }
                let (registry, owner, _, _) = ports.read();
                if registry.joint_staged_count(&target) != Some(0) {
                    diagnosis.note_other();
                    return Ok(QuantumSealProgress::LocalPending);
                }
                let state = if owner
                    .adapter()
                    .awaits_future_terminal(target.bootstrap(), self.frontier)
                {
                    ConsumerState::Future
                } else {
                    // Acquisition verified every retained physical owner once.
                    // This negative-only frame cannot create a terminal, and
                    // preflight forbids a changed collection frontier. No H9
                    // head is being consumed and no positive result is minted.
                    ConsumerState::Delivered
                };
                *remaining -= 1;
                self.advance_consumer(state);
                diagnosis.note_other();
                return Ok(self.progress());
            }
            // A truthful pending audit has no positive work to perform at an
            // unaffected target. Charge this visit without changing its
            // Pending history, so a later original negative is not stranded.
            // defer_pending_h3 alone may qualify all held originals Future.
            if self.active.is_none()
                && self
                    .failure
                    .as_ref()
                    .is_some_and(|failure| failure.gap == JournalGap::H3Pending)
                && *remaining != 0
            {
                *remaining -= 1;
                self.advance_pending_visit();
                diagnosis.note_other();
                return Ok(QuantumSealProgress::DeliveryReady);
            }
            diagnosis.note_other();
            return Ok(QuantumSealProgress::LocalPending);
        };
        diagnosis.note_failure_visit(audited.failure().gap);
        // Diagnostic-only (scope round): whether this delivery can end a
        // Joint feed with a void (read before delivery changes the mode).
        // Only a fenced failure is a void; only a Joint feed can end.
        // The fence is the maximum over the failures that apply: the
        // selected failure's rank need not carry it.
        let void_ending = audited.fence().is_some()
            && ports.read().0.joint_history_mode(&target) == Some(FeedMode::Joint);
        let (h3_clean, h3_clean_floor) = match audited.h3() {
            H3DispositionEvidence::Clean { pending_floor, .. } => (true, pending_floor.is_none()),
            H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted => {
                (false, false)
            }
        };
        // A fenced void replays through the H8-aware fallback even
        // while H3 pends: admission failures are per process, and
        // the rows carry no key identity, so staged calls above the
        // floor may reduce before the pending call; consuming each
        // replayed head's H8 keeps the pending continuation's
        // census exact so the frame still retires after its void
        // delivers. Unfenced fallbacks still wait for clean H3.
        let fallback = audited.disposition() == SealFailureDisposition::Fallback
            && ports.read().0.joint_history_mode(&target) == Some(FeedMode::Joint)
            && h3_clean
            && (h3_clean_floor || audited.fence().is_some());
        // A retry replays this visit from the start next time, so what it
        // spends here is refunded below: it delivers nothing.
        let before = *remaining;
        // A parked consumer degrades instead of retrying: force the
        // fallback its feed would take under a fenced void. The flag
        // only alters retry deliveries: a genuine fallback or
        // history loss the seal observed after the park keeps its
        // original route (and its loss invalidation). The streak is
        // copied out here (the batch borrows the consumer below).
        let forced_disposition = (self.consumers[index].parked
            && audited.disposition() == SealFailureDisposition::Retry)
            .then_some(SealFailureDisposition::Fallback);
        let park_streak = self.consumers[index].stuck_streak;
        let mut batch = FailureBatchDelivery {
            audited,
            cursor: &mut self.consumers[index].failure,
            forced_disposition,
        };
        let (registry, owner, _, _, _) = ports.split();
        let (adapter, model) = owner.parts();
        let outcome = if fallback {
            adapter.deliver_completed_fallback(
                AuditedDomainInput {
                    audit: &self.audit,
                    receipt: target.bootstrap(),
                    frontier: self.frontier,
                },
                &mut batch,
                &target,
                registry,
                model,
                remaining,
            )?
        } else {
            registry.deliver_joint_failure(
                target.id(),
                &mut batch,
                model,
                adapter.ledger_mut(),
                remaining,
            )
        };
        // The delivered failure's gap, copied out before the outcome
        // match (the batch borrows frame state the arms mutate).
        let stuck_gap = batch.audited().failure().gap;
        let forced = batch.forced_disposition();
        match outcome {
            FailureBatchProgress::NegativeDelivered(completed) => {
                if !completed.matches(&batch) {
                    return Err(RawQuantumRefusal::DispositionMismatch);
                }
                self.active = None;
                self.advance_consumer(ConsumerState::LossDelivered);
                diagnosis.note_failure_cleared();
                Ok(self.progress())
            }
            FailureBatchProgress::Complete(
                FailureApplyOutcome::Degraded { .. } | FailureApplyOutcome::FellBack { .. },
            ) => {
                if batch.negative_delivered().is_none() {
                    return Err(RawQuantumRefusal::DispositionMismatch);
                }
                // A parked consumer's forced fallback lands its named
                // park gap here, with exact loss counts: the watchdog
                // parked it past its retry stall instead of tripping.
                // Every head degraded across all delivery slices counts,
                // replayed or disposed — not just the terminal slice's.
                if forced.is_some() {
                    let units = batch
                        .delivered_replayed()
                        .saturating_add(batch.delivered_disposed());
                    registry.record_gap(crate::discovery::caller_registry::RegistryGap {
                        caller: Some(target.caller()),
                        module: None,
                        pid: None,
                        subject: PARKED_CONSUMER_SUBJECT.to_string(),
                        reason: format!(
                            "consumer parked after {} stuck delivery visits ({}); degraded with counted loss ({} calls)",
                            park_streak,
                            stuck_gap.label(),
                            units,
                        ),
                        budget: None,
                    });
                }
                // Diagnostic-only (scope round): the void above ended a
                // Joint feed. One void fanning out to many feeds counts
                // once (deduped by fence and gap).
                if void_ending {
                    // Dedup by the void's own (fence, gap): the
                    // selected failure's rank need not carry the
                    // fence, so keying on the selection would count
                    // one void twice across feeds.
                    let audited = batch.audited();
                    let key = (
                        audited.fence(),
                        audited.fenced_gap().expect("a void ending carries a fence"),
                    );
                    if !self.void_feed_ends_counted.contains(&Some(key)) {
                        // Four slots always suffice (see the field);
                        // a full set still counts the ending rather
                        // than dropping a void that ended a feed.
                        if let Some(free) = self
                            .void_feed_ends_counted
                            .iter_mut()
                            .find(|slot| slot.is_none())
                        {
                            *free = Some(key);
                        }
                        adapter.note_void_ended_joint_feed();
                    }
                }
                self.active = None;
                self.advance_consumer(ConsumerState::LossDelivered);
                diagnosis.note_failure_cleared();
                Ok(self.progress())
            }
            FailureBatchProgress::Complete(FailureApplyOutcome::Retried) => {
                self.active = None;
                self.consumers[index].failure = FailureReplayCursor::default();
                // Nothing was delivered and the next visit replays the
                // same spans: no progress, so the running Audited bound
                // can end a seal that only ever retries. Record the
                // streak for the watchdog park.
                self.consumers[index].stuck_streak =
                    self.consumers[index].stuck_streak.saturating_add(1);
                self.consumers[index].last_stuck_gap = Some(stuck_gap);
                *remaining = before;
                diagnosis.note_failure_retried();
                Ok(QuantumSealProgress::LocalPending)
            }
            FailureBatchProgress::Complete(FailureApplyOutcome::HeldForCompleteness) => {
                if self.active.is_none()
                    && self
                        .failure
                        .as_ref()
                        .is_some_and(|failure| failure.gap == JournalGap::H3Pending)
                    && batch.effects_complete()
                    && *remaining != 0
                {
                    // This target's negative spans are done, but its H8/H9
                    // history stays Pending. Charge the visit, then allow
                    // later affected consumers their original spans too.
                    *remaining -= 1;
                    self.advance_pending_visit();
                    diagnosis.note_failure_progress();
                    Ok(QuantumSealProgress::DeliveryReady)
                } else {
                    self.consumers[index].stuck_streak =
                        self.consumers[index].stuck_streak.saturating_add(1);
                    self.consumers[index].last_stuck_gap = Some(stuck_gap);
                    diagnosis.note_failure_stuck();
                    Ok(QuantumSealProgress::LocalPending)
                }
            }
            FailureBatchProgress::Held => {
                self.consumers[index].stuck_streak =
                    self.consumers[index].stuck_streak.saturating_add(1);
                self.consumers[index].last_stuck_gap = Some(stuck_gap);
                diagnosis.note_failure_stuck();
                Ok(QuantumSealProgress::LocalPending)
            }
            #[cfg(test)]
            FailureBatchProgress::Complete(FailureApplyOutcome::Ignored) => {
                self.consumers[index].stuck_streak =
                    self.consumers[index].stuck_streak.saturating_add(1);
                self.consumers[index].last_stuck_gap = Some(stuck_gap);
                diagnosis.note_failure_stuck();
                Ok(QuantumSealProgress::LocalPending)
            }
            FailureBatchProgress::Yielded => {
                diagnosis.note_failure_stuck();
                Ok(QuantumSealProgress::DeliveryReady)
            }
        }
    }

    /// Existing real-frame test controls use one finite service slice per
    /// selected consumer. Production supplies its budget explicitly above.
    #[cfg(test)]
    pub(crate) fn deliver_next(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        let mut remaining = super::MAX_UNSETTLED_STAGED;
        let selected = self.cursor;
        // Diagnostic-only; existing controls assert progress, not telemetry.
        let mut diagnosis = DeliverDiagnosis::default();
        loop {
            let before = remaining;
            let progress = self.deliver_next_bounded(ports, &mut remaining, &mut diagnosis)?;
            if progress != QuantumSealProgress::DeliveryReady
                || remaining == 0
                || before == remaining
                || self.cursor != selected
            {
                return Ok(progress);
            }
        }
    }

    #[allow(clippy::result_large_err)] // Refusal returns the same move-only frame and retained buffers.
    pub(crate) fn finish_frame(
        self,
        ports: &mut JointPublicationPorts<'_>,
    ) -> Result<DisposedJointQuantum, (Self, RawQuantumRefusal)> {
        if self
            .original_failures()
            .any(|failure| failure.gap == JournalGap::H3Pending)
        {
            return Err((self, RawQuantumRefusal::H3Undisposed));
        }
        if self.awaits_rejection() {
            // An unfilled original keeps the frame: its per-row work and
            // its delivery are still owed.
            return Err((self, RawQuantumRefusal::DispositionMismatch));
        }
        self.finish_frame_inner(ports)
    }

    #[allow(clippy::result_large_err)] // Refusal preserves the same frame and original custody.
    pub(crate) fn finish_pending_h3(
        self,
        ports: &mut JointPublicationPorts<'_>,
        lane: &crate::inventory_semantics::AttestedSemanticLane,
    ) -> Result<DisposedJointQuantum, (Self, RawQuantumRefusal)> {
        if let Err(reason) = self.preflight(ports) {
            return Err((self, reason));
        }
        let mut held = Some(self);
        lane.with_joint_continuation(|view| {
            held.take()
                .expect("the original frame moves into one pending check")
                .finish_pending_h3_with_view(ports, view)
        })
        .unwrap_or_else(|| {
            Err((
                held.expect("an unavailable view preserves the original frame"),
                RawQuantumRefusal::H3Undisposed,
            ))
        })
    }

    #[allow(clippy::result_large_err)] // Refusal preserves the same frame and original custody.
    pub(crate) fn finish_pending_h3_with_view(
        self,
        ports: &mut JointPublicationPorts<'_>,
        view: &crate::inventory_semantics::JointContinuationView<'_>,
    ) -> Result<DisposedJointQuantum, (Self, RawQuantumRefusal)> {
        if let Err(reason) = self.preflight(ports) {
            return Err((self, reason));
        }
        if !self.pending_h3_is_owned(ports, view) {
            return Err((self, RawQuantumRefusal::H3Undisposed));
        }
        if !self.bound || self.active.is_some() || self.pending != 0 || self.awaits_rejection() {
            return Err((self, RawQuantumRefusal::DispositionMismatch));
        }
        // The exact continuation above qualified all negative consumers and
        // original H8/H9 owners. They may remain Future only here; no generic
        // finish or H3 void acknowledgement is manufactured for history
        // still held by the live producer. Negative-only histories may have
        // completed their original spans, without any positive replay.
        if self.consumers.iter().any(|consumer| {
            !matches!(
                consumer.state,
                ConsumerState::Future | ConsumerState::NegativeOnly | ConsumerState::LossDelivered
            )
        }) {
            return Err((self, RawQuantumRefusal::DispositionMismatch));
        }
        let fault_after = self.audit.fault_after;
        let disposed = DisposedJointQuantum {
            identity: self.identity(),
            frontier: self.frontier,
        };
        drop(self); // Only frame buffers drop; physical originals retain their owners.
        // Zero eligible heads still require the same exact continuation and
        // native prefix. A refused finish must leave the baseline unchanged.
        let (_, owner, _, _, _) = ports.split();
        owner.adapter_mut().last_fault = Some(fault_after);
        Ok(disposed)
    }

    #[allow(clippy::result_large_err)] // Original frame returned on refusal.
    fn finish_frame_inner(
        self,
        ports: &mut JointPublicationPorts<'_>,
    ) -> Result<DisposedJointQuantum, (Self, RawQuantumRefusal)> {
        if let Err(reason) = self.preflight(ports) {
            return Err((self, reason));
        }
        if !self.bound || self.active.is_some() || self.pending != 0 {
            return Err((self, RawQuantumRefusal::DispositionMismatch));
        }
        if self.original_failures().any(|failure| {
            self.consumers.iter().any(|consumer| {
                failure.affects_domain(consumer.target.bootstrap().domain())
                    && consumer.state != ConsumerState::LossDelivered
            })
        }) {
            return Err((self, RawQuantumRefusal::DispositionMismatch));
        }
        // Check the complete union first. No first original may acknowledge
        // H3 while a later original still has an undisposed consumer.
        for failure in self.original_failures() {
            if let Some(voided_below) = failure.h3_voided {
                let (_, _, _, finalizer, producers) = ports.split();
                finalizer.acknowledge_h3_void(H3VoidAcknowledgement {
                    producers: producers.clone(),
                    voided_below,
                });
            }
        }
        Ok(DisposedJointQuantum {
            identity: self.identity(),
            frontier: self.frontier,
        })
    }

    /// Abandon disposal for the exit hold: mint the frame's completion
    /// metadata without seal proof. The caller holds the semantic lane
    /// for exit, so the frame can never resume; its unfinished audit
    /// state drops with its buffers (physical originals retain their
    /// owners) and the abandon gap discloses the loss. No H3 void is
    /// acknowledged: the seal never consumed this frame's evidence.
    pub(crate) fn abandon_unfinished(self) -> DisposedJointQuantum {
        let disposed = DisposedJointQuantum {
            identity: self.identity(),
            frontier: self.frontier,
        };
        drop(self); // Only frame buffers drop; physical originals retain their owners.
        disposed
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::{JournalGap, ObjectEffects, SealFailure, SealFailureScope};
    use super::failure_rank;

    /// Failure selection ranks a transient unknown take below real
    /// endings: a transient take failure never masks a fallback or
    /// loss the frame must deliver. A permanent take fact ranks with
    /// the fallback it keeps.
    #[test]
    fn failure_rank_orders_unknown_take_below_endings() {
        use crate::attach::BirthObservationRefusal as Refusal;
        fn failure(
            gap: JournalGap,
            take_failed: Option<crate::attach::BirthObservationRefusal>,
        ) -> SealFailure {
            SealFailure {
                scope: SealFailureScope::Unqualified,
                gap,
                effects: ObjectEffects::default(),
                h3_voided: None,
                fence: None,
                take_failed,
            }
        }
        let unknown = failure_rank(&failure(
            JournalGap::BootstrapMismatch,
            Some(Refusal::CurrentPartition),
        ));
        let permanent = failure_rank(&failure(
            JournalGap::BootstrapMismatch,
            Some(Refusal::MarkerNotReady),
        ));
        let fallback = failure_rank(&failure(JournalGap::BootstrapMismatch, None));
        let loss = failure_rank(&failure(JournalGap::H3Loss, None));
        let retry = failure_rank(&failure(JournalGap::H3Pending, None));
        assert_eq!(unknown, retry, "a transient take ranks as retry");
        assert!(
            unknown < fallback,
            "a transient take never masks a fallback"
        );
        assert!(unknown < loss, "a transient take never masks loss");
        assert_eq!(
            permanent, fallback,
            "a permanent take fact ranks with fallback"
        );
    }

    /// Failure selection ranks a stale-witness take with the
    /// fallback it keeps: the mismatch is a real ending, never a
    /// transient unknown, so it must not lose to (or mask) one.
    #[test]
    fn failure_rank_orders_stale_witness_with_fallback() {
        use crate::attach::BirthObservationRefusal as Refusal;
        fn failure(
            gap: JournalGap,
            take_failed: Option<crate::attach::BirthObservationRefusal>,
        ) -> SealFailure {
            SealFailure {
                scope: SealFailureScope::Unqualified,
                gap,
                effects: ObjectEffects::default(),
                h3_voided: None,
                fence: None,
                take_failed,
            }
        }
        let stale = failure_rank(&failure(
            JournalGap::BootstrapMismatch,
            Some(Refusal::RetainedWitnessMismatch),
        ));
        let unknown = failure_rank(&failure(
            JournalGap::BootstrapMismatch,
            Some(Refusal::CurrentPartition),
        ));
        let fallback = failure_rank(&failure(JournalGap::BootstrapMismatch, None));
        assert_eq!(stale, fallback, "a stale-witness take ranks with fallback");
        assert!(
            unknown < stale,
            "a transient take still ranks below the stale-witness ending"
        );
    }

    /// Failure selection ranks the take sub-causes with their
    /// dispositions: races retry below real endings, while a
    /// witness whose truth broke ranks with the fallback it keeps.
    #[test]
    fn failure_rank_orders_take_subcauses_with_dispositions() {
        use crate::attach::BirthObservationRefusal as Refusal;
        fn failure(
            gap: JournalGap,
            take_failed: Option<crate::attach::BirthObservationRefusal>,
        ) -> SealFailure {
            SealFailure {
                scope: SealFailureScope::Unqualified,
                gap,
                effects: ObjectEffects::default(),
                h3_voided: None,
                fence: None,
                take_failed,
            }
        }
        let retry = failure_rank(&failure(JournalGap::H3Pending, None));
        let fallback = failure_rank(&failure(JournalGap::BootstrapMismatch, None));
        for refusal in [
            Refusal::EpochDrift,
            Refusal::TakeDeadline,
            Refusal::SessionBorrowed,
        ] {
            assert_eq!(
                failure_rank(&failure(JournalGap::BootstrapMismatch, Some(refusal))),
                retry,
                "{refusal:?} ranks as retry"
            );
        }
        for refusal in [Refusal::CaptureDrift, Refusal::WitnessStale] {
            assert_eq!(
                failure_rank(&failure(JournalGap::BootstrapMismatch, Some(refusal))),
                fallback,
                "{refusal:?} ranks with fallback"
            );
        }
    }
}
