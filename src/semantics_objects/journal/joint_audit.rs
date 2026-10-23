//! SPDX-License-Identifier: GPL-3.0-or-later
//! One original ingested collection, immutable audit and bounded all-domain delivery.
#![cfg_attr(not(test), allow(dead_code))] // Ordinary Joint activation remains gated.

use super::joint_driver::{
    IngestedRaw, JointCaptureOwner, RawProvenance, RawQuantumIdentity, RawQuantumRefusal,
};
use super::seal_replay::{ReplayBounds, ReplayPreparation, SealBatchDelivery, SealReplayCursor};
use super::{
    BirthEvidenceSource, BootstrapReceipt, H3DispositionEvidence, H3FinalizerPort,
    H3VoidAcknowledgement, JournalGap, SealSuccess, SealedCall, SessionBirthEvidence,
    StagingLedger,
};
use super::{
    ConsumptionOrdinal, FaultEpoch, JournalAdapter, JournalAuditReceipt, SealFailure,
    SealFailureScope, SessionClosureGrant,
};
use crate::attach::{AttachedSemanticSet, SessionDrainProducers};
use crate::discovery::caller_registry::instance_input::JointFeedTarget;
use crate::discovery::engine::inventory_coordinator::semantics::{
    JointPublicationPorts, SemanticCallerBinding, SessionAuditInput,
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
    frontier: ConsumptionOrdinal,
    audit: JournalAuditReceipt,
    // Original bulk S1Only refusal and original audit result remain distinct.
    // Both buffers are precharged before the first taint/model mutation.
    raw_failure: Option<SealFailure>,
    failure: Option<SealFailure>,
    consumers: Vec<FrameConsumer>,
    bound: bool,
    cursor: usize,
    pending: usize,
    future: usize,
    active: Option<ActiveSeal>,
    // Nested buffers always drop before their own reservation.
    failure_storage: Option<ResourceLease>,
    targets_storage: Option<ResourceLease>,
    // Every owned failure buffer drops before its retained storage is refunded.
    _storage: ResourceLease,
}

pub(crate) type AuditAcquisition = Result<IngestedJointQuantum, (IngestedRaw, RawQuantumRefusal)>;

fn allocation_bytes<T>(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(size_of::<T>())?
        .checked_add(if capacity == 0 {
            0
        } else {
            OWNED_ALLOCATION_PADDING
        })
}

fn storage_bound(adapter: &JournalAdapter, model: &ObjectSemantics) -> Option<usize> {
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
    let one = allocation_bytes::<ObjectDomain>(keys)?
        .checked_add(allocation_bytes::<ObjectEffect>(effect_capacity)?)?;
    size_of::<IngestedJointQuantum>()
        .checked_add(one.checked_mul(if adapter.has_s1only_subjects() { 2 } else { 1 })?)
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConsumerState {
    Pending,
    // Retained selected history may receive negatives, never a positive seal.
    NegativeOnly,
    Future,
    Delivered,
    LossDelivered,
}
struct FrameConsumer {
    target: JointFeedTarget,
    state: ConsumerState,
    failure: FailureReplayCursor,
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
    originals: [Option<&'q SealFailure>; 2],
    audit: &'q JournalAuditReceipt,
    provenance: &'q RawProvenance,
    frontier: ConsumptionOrdinal,
    domain: ObjectDomain,
}
impl AuditedFailure<'_> {
    pub(crate) fn failure(&self) -> &SealFailure {
        self.failure
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
            || matches!(
                self.audit.h3,
                H3DispositionEvidence::StagedLoss { .. } | H3DispositionEvidence::Exhausted
            )
        {
            SealFailureDisposition::HistoryLoss
        } else {
            disposition_of(self.failure.gap)
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
    match disposition_of(failure.gap) {
        SealFailureDisposition::Retry => 0,
        SealFailureDisposition::Fallback => 1,
        SealFailureDisposition::HistoryLoss => 2,
    }
}

impl<'q> AuditedFailure<'q> {
    fn new(
        originals: [Option<&'q SealFailure>; 2],
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
}

/// The real frame's two original negatives and bounded per-consumer cursor.
/// No public constructor, merged failure, cloned effects or reusable token.
pub(crate) struct FailureBatchDelivery<'q> {
    audited: AuditedFailure<'q>,
    pub(super) cursor: &'q mut FailureReplayCursor,
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
        while self.cursor.slot < 2 {
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

/// Retained result only; transition temporaries remain covered by the existing
/// serialized scratch reservation. Recompute from current populations before
/// EVERY seal: a previous domain may have grown the model since acquisition.
fn result_storage_bound(adapter: &JournalAdapter, model: &ObjectSemantics) -> Option<usize> {
    let calls = adapter.open.len().checked_add(adapter.refused.len())?;
    let (objects, sessions) = model.audit_loss_record_counts();
    let handles = MAX_INPUT_HANDLES
        .checked_add(MAX_RESULT_HANDLES)?
        .checked_add(MAX_FIND_HANDLES)?;
    let prospective_objects =
        objects.checked_add(calls.checked_mul(MAX_RESULT_HANDLES.max(MAX_FIND_HANDLES))?)?;
    let prospective_sessions = sessions.checked_add(calls)?;
    // state::apply_action selects one finite action. Per touched handle,
    // establishment may emit one conflict for each bounded observation and
    // one established summary; creation/first-observation, reference,
    // destruction/retirement and unresolved/gap each add at most one.
    let per_handle = MAX_TEMPLATE_ATTRIBUTES.checked_add(1)?.checked_add(4)?;
    // A broad action can downgrade, invalidate metadata and retire a live
    // view, and end a session. Include the direct session first/open and
    // call gap/unresolved summaries separately. Repeated broad actions are
    // conservatively counted per actual retained call, not assumed away.
    let per_call = handles
        .checked_mul(per_handle)?
        .checked_add(4)?
        .checked_add(prospective_objects.checked_mul(3)?)?
        .checked_add(prospective_sessions)?;
    let loss = objects
        .checked_add(sessions)?
        .checked_add(adapter.keys.len().checked_mul(2)?)?;
    let effects = calls.checked_mul(per_call)?.checked_add(loss)?;
    allocation_bytes::<ObjectDomain>(adapter.keys.len())?
        .checked_add(allocation_bytes::<ObjectEffect>(vector_capacity(effects)?)?)?
        .checked_add(allocation_bytes::<SealedCall>(vector_capacity(
            adapter.open.len(),
        )?)?)?
        .checked_add(allocation_bytes::<CallKey>(vector_capacity(
            adapter.open.len(),
        )?)?)
}

fn outcome_storage(outcome: &Result<SealSuccess, SealFailure>) -> Option<usize> {
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
    fn original_failures(&self) -> impl Iterator<Item = &SealFailure> {
        self.raw_failure.iter().chain(self.failure.iter()).chain(
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
        let raw_failure = adapter.refuse_s1only_subjects(model);
        let failure = adapter.audit_collected(model, &audit, fault).err();
        let frame = Self {
            provenance,
            frontier,
            audit,
            raw_failure,
            failure,
            consumers: Vec::new(),
            bound: false,
            cursor: 0,
            pending: 0,
            future: 0,
            active: None,
            failure_storage: None,
            targets_storage: None,
            _storage: storage,
        };
        assert!(
            frame
                .retained_storage_bytes()
                .is_some_and(|owned| owned <= bytes),
            "audit loss storage exceeds its checked preflight bound"
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
            .checked_add(self.failure.as_ref().map_or(Some(0), failure_storage)?)?
            .checked_add(allocation_bytes::<FrameConsumer>(
                self.consumers.capacity(),
            )?)?
            .checked_add(self.active.as_ref().map_or(Some(0), |active| {
                outcome_storage(&active.outcome)?.checked_add(lookup_storage(&active.outcome)?)
            })?)
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
        if raw.gap != JournalGap::ImageTainted || raw.h3_voided.is_some() {
            return None;
        }
        let state = adapter.keys.get(&key)?;
        let proof = super::JournalDomainProof {
            key,
            era: state.era,
        };
        (state.refused
            && !state.era_ended
            && adapter.is_tainted((key.cookie, key.exec))
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
            || self
                .raw_failure
                .as_ref()
                .is_some_and(|raw| raw.gap != JournalGap::ImageTainted)
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
                let fingerprint = super::fingerprint_of_begin(&entry.begin);
                let claimants = adapter.claims.get(&fingerprint);
                let has_claim = claimants
                    .is_some_and(|claimants| claimants.values().any(|claims| !claims.is_empty()));
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
                let fingerprint = super::fingerprint_of_begin(&entry.begin);
                if position != origin.position()
                    || position < *floor
                    || position >= self.audit.h0_below
                    || entry.collected_origin != Some(origin)
                    || !resource.matches_producers(producers)
                    || !super::fingerprint_matches_event(&fingerprint, &record.event)
                    || record.event.ts_ns != end.end.payload_base().event.ts_ns
                    || adapter.claims.get(&fingerprint).is_some_and(|claimants| {
                        claimants.values().any(|claims| !claims.is_empty())
                    })
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
        if !self.pending_h3_is_owned(ports, view) {
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
            if mode == FeedMode::S1Only
                || self
                    .original_failures()
                    .any(|failure| failure.affects_domain(target.bootstrap().domain()))
            {
                continue;
            }
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
        consumers.extend(registry.joint_history_targets().map(|(target, mode)| {
            let affects = self
                .original_failures()
                .any(|failure| failure.affects_domain(target.bootstrap().domain()));
            FrameConsumer {
                target,
                state: if mode == FeedMode::Joint || affects {
                    ConsumerState::Pending
                } else {
                    ConsumerState::NegativeOnly
                },
                failure: FailureReplayCursor::default(),
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
        self.bound = true;
        Ok(())
    }

    fn advance_consumer(&mut self, state: ConsumerState) {
        debug_assert!(self.consumers[self.cursor].state == ConsumerState::Pending);
        self.consumers[self.cursor].state = state;
        self.pending -= 1;
        self.future += usize::from(state == ConsumerState::Future);
        self.skip_completed_consumers();
    }

    fn skip_completed_consumers(&mut self) {
        while self.cursor < self.consumers.len()
            && self.consumers[self.cursor].state != ConsumerState::Pending
        {
            self.cursor += 1;
        }
    }

    fn advance_pending_visit(&mut self) {
        self.cursor += 1;
        self.skip_completed_consumers();
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

    pub(crate) fn seal_next(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        births: &mut impl JointBirthEvidenceSource,
        fault: &impl FaultEpoch,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        self.preflight(ports)?;
        if !self.bound {
            return Err(RawQuantumRefusal::DispositionMismatch);
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
        let outcome = adapter.seal_in_audit(model, input, &mut selected, fault, replay);
        assert!(
            outcome_storage(&outcome).is_some_and(|actual| actual <= bytes),
            "retained seal result exceeds its checked preflight bound"
        );
        assert!(
            lookup_storage(&outcome).is_some_and(|actual| actual <= temporary),
            "retained original lookup exceeds its original preflight lease"
        );
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
                return Ok(QuantumSealProgress::DeliveryReady);
            }
            if failure.gap == JournalGap::BoundNotReady
                && adapter.awaits_future_terminal(target.bootstrap(), self.frontier)
            {
                self.advance_consumer(ConsumerState::Future);
                return Ok(QuantumSealProgress::AwaitFutureInput);
            }
        }
        self.active = Some(ActiveSeal {
            consumer: index,
            outcome,
            replay: SealReplayCursor::default(),
            _storage: storage,
        });
        Ok(QuantumSealProgress::DeliveryReady)
    }

    /// One shared service budget covers original effects, empty phases,
    /// completed-fallback preflight and exact head disposition. Yielding
    /// retains the same result, both negative originals and all held roles.
    pub(crate) fn deliver_next_bounded(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
        remaining: &mut usize,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        self.preflight(ports)?;
        if !self.bound {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        if self.pending == 0 {
            return Ok(self.progress());
        }
        if self.cursor == self.consumers.len() {
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
            let (registry, owner, _, _, _) = ports.split();
            let (adapter, model) = owner.parts();
            return match registry.deliver_joint_seal(
                target.id(),
                &mut batch,
                model,
                adapter.ledger_mut(),
                remaining,
            ) {
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
                return Ok(QuantumSealProgress::DeliveryReady);
            }
            return Ok(QuantumSealProgress::LocalPending);
        };
        let fallback = audited.disposition() == SealFailureDisposition::Fallback
            && ports.read().0.joint_history_mode(&target) == Some(FeedMode::Joint)
            && matches!(
                audited.h3(),
                H3DispositionEvidence::Clean {
                    pending_floor: None,
                    ..
                }
            );
        let mut batch = FailureBatchDelivery {
            audited,
            cursor: &mut self.consumers[index].failure,
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
        match outcome {
            FailureBatchProgress::NegativeDelivered(completed) => {
                if !completed.matches(&batch) {
                    return Err(RawQuantumRefusal::DispositionMismatch);
                }
                self.active = None;
                self.advance_consumer(ConsumerState::LossDelivered);
                Ok(self.progress())
            }
            FailureBatchProgress::Complete(
                FailureApplyOutcome::Degraded { .. } | FailureApplyOutcome::FellBack { .. },
            ) => {
                if batch.negative_delivered().is_none() {
                    return Err(RawQuantumRefusal::DispositionMismatch);
                }
                self.active = None;
                self.advance_consumer(ConsumerState::LossDelivered);
                Ok(self.progress())
            }
            FailureBatchProgress::Complete(FailureApplyOutcome::Retried) => {
                self.active = None;
                self.consumers[index].failure = FailureReplayCursor::default();
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
                    Ok(QuantumSealProgress::DeliveryReady)
                } else {
                    Ok(QuantumSealProgress::LocalPending)
                }
            }
            FailureBatchProgress::Held => Ok(QuantumSealProgress::LocalPending),
            #[cfg(test)]
            FailureBatchProgress::Complete(FailureApplyOutcome::Ignored) => {
                Ok(QuantumSealProgress::LocalPending)
            }
            FailureBatchProgress::Yielded => Ok(QuantumSealProgress::DeliveryReady),
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
        loop {
            let before = remaining;
            let progress = self.deliver_next_bounded(ports, &mut remaining)?;
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
        if !self.bound || self.active.is_some() || self.pending != 0 {
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
}
