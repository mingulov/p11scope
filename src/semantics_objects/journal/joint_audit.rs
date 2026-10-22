//! SPDX-License-Identifier: GPL-3.0-or-later
//! One original ingested collection, immutable audit and bounded all-domain delivery.
#![cfg_attr(not(test), allow(dead_code))] // Ordinary Joint activation remains gated.

use super::joint_driver::{
    IngestedRaw, JointCaptureOwner, RawProvenance, RawQuantumIdentity, RawQuantumRefusal,
};
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
use crate::semantics_key_use::{FailureApplyOutcome, SealApplyOutcome};
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
    size_of::<IngestedJointQuantum>()
        .checked_add(allocation_bytes::<ObjectDomain>(keys)?)?
        .checked_add(allocation_bytes::<ObjectEffect>(effect_capacity)?)
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
    Future,
    Delivered,
    LossDelivered,
}
struct FrameConsumer {
    target: JointFeedTarget,
    state: ConsumerState,
}
struct ActiveSeal {
    consumer: usize,
    outcome: Result<SealSuccess, SealFailure>,
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
    #[cfg(test)]
    pub(crate) fn identity(&self) -> RawQuantumIdentity {
        self.provenance.identity()
    }
    #[cfg(test)]
    pub(crate) fn frontier(&self) -> ConsumptionOrdinal {
        self.frontier
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
            .checked_add(allocation_bytes::<CallKey>(seal.prefix.open.capacity())?),
        Err(failure) => failure_storage(failure),
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
        let failure = adapter.audit_collected(model, &audit, fault).err();
        let frame = Self {
            provenance,
            frontier,
            audit,
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
            .checked_add(self.failure.as_ref().map_or(Some(0), failure_storage)?)?
            .checked_add(allocation_bytes::<FrameConsumer>(
                self.consumers.capacity(),
            )?)?
            .checked_add(
                self.active
                    .as_ref()
                    .map_or(Some(0), |active| outcome_storage(&active.outcome))?,
            )
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
        self.failure.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn audit_for_test(&self) -> &JournalAuditReceipt {
        &self.audit
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

    pub(crate) fn bind_targets(
        &mut self,
        ports: &JointPublicationPorts<'_>,
    ) -> Result<(), RawQuantumRefusal> {
        self.preflight(ports)?;
        if self.bound {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        let (registry, owner, bindings, _) = ports.read();
        let count = registry.joint_feed_targets().count();
        for target in registry.joint_feed_targets() {
            // Negative fanout still reaches history whose caller binding has
            // ended. Only a fresh positive seal needs the current binding.
            if self
                .failure
                .as_ref()
                .is_some_and(|failure| failure.affects_domain(target.bootstrap().domain()))
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
        consumers.extend(registry.joint_feed_targets().map(|target| FrameConsumer {
            target,
            state: ConsumerState::Pending,
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
        self.pending = consumers.len();
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
        while self.cursor < self.consumers.len()
            && self.consumers[self.cursor].state != ConsumerState::Pending
        {
            self.cursor += 1;
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
        let failure = self
            .failure
            .as_ref()
            .filter(|failure| failure.affects_domain(domain))
            .or_else(|| {
                self.active
                    .as_ref()?
                    .outcome
                    .as_ref()
                    .err()
                    .filter(|failure| failure.affects_domain(domain))
            })?;
        Some(AuditedFailure {
            failure,
            audit: &self.audit,
            provenance: &self.provenance,
            frontier: self.frontier,
            domain,
        })
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
        let index = self.cursor;
        if let Some(failure) = &self.failure {
            return Ok(
                if failure.affects_domain(self.consumers[index].target.bootstrap().domain()) {
                    QuantumSealProgress::DeliveryReady
                } else {
                    QuantumSealProgress::LocalPending
                },
            );
        }
        let target = self.consumers[index].target;
        let (_, owner, bindings, _, _) = ports.split();
        let binding = bindings
            .get(target.caller())
            .ok_or(RawQuantumRefusal::Admission)?;
        let bytes = result_storage_bound(owner.adapter(), owner.model())
            .ok_or(RawQuantumRefusal::Capacity)?;
        let storage = owner
            .ledger()
            .resource_reserver()
            .ok_or(RawQuantumRefusal::ForeignLedger)?
            .reserve(bytes)
            .map_err(RawQuantumRefusal::Resource)?;
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
        let outcome = adapter.seal_in_audit(model, input, &mut selected, fault);
        assert!(
            outcome_storage(&outcome).is_some_and(|actual| actual <= bytes),
            "retained seal result exceeds its checked preflight bound"
        );
        if let Err(failure) = &outcome {
            if matches!(failure.scope, SealFailureScope::AffectedDomains(_)) {
                let failure = outcome.expect_err("checked original broad failure");
                for consumer in &mut self.consumers {
                    if failure.affects_domain(consumer.target.bootstrap().domain()) {
                        self.pending += usize::from(consumer.state != ConsumerState::Pending);
                        self.future -= usize::from(consumer.state == ConsumerState::Future);
                        consumer.state = ConsumerState::Pending;
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
            _storage: storage,
        });
        Ok(QuantumSealProgress::DeliveryReady)
    }

    pub(crate) fn deliver_next(
        &mut self,
        ports: &mut JointPublicationPorts<'_>,
    ) -> Result<QuantumSealProgress, RawQuantumRefusal> {
        self.preflight(ports)?;
        if !self.bound {
            return Err(RawQuantumRefusal::DispositionMismatch);
        }
        if self.failure.is_some() {
            if self.pending == 0 {
                return Ok(self.progress());
            }
            let index = self.cursor;
            let target = self.consumers[index].target;
            let Some(failure) = self.failure_for(target.bootstrap().domain()) else {
                return Ok(QuantumSealProgress::LocalPending);
            };
            let (registry, owner, _, _, _) = ports.split();
            let (adapter, model) = owner.parts();
            match registry.deliver_joint_failure(target.id(), &failure, model, adapter.ledger_mut())
            {
                FailureApplyOutcome::Degraded { .. }
                | FailureApplyOutcome::FellBack { .. }
                | FailureApplyOutcome::Ignored => {
                    self.advance_consumer(ConsumerState::LossDelivered);
                    return Ok(self.progress());
                }
                FailureApplyOutcome::Retried | FailureApplyOutcome::HeldForCompleteness => {
                    return Ok(QuantumSealProgress::LocalPending);
                }
            }
        }
        let Some(active) = self.active.as_ref() else {
            return Ok(self.progress());
        };
        let index = active.consumer;
        let target = self.consumers[index].target;
        let (registry, owner, _, _, _) = ports.split();
        let (adapter, model) = owner.parts();
        let complete = match &active.outcome {
            Ok(seal) => {
                let outcome =
                    registry.deliver_joint_seal(target.id(), seal, model, adapter.ledger_mut());
                match outcome {
                    SealApplyOutcome::ReplayedOne | SealApplyOutcome::ResourceRefused => true,
                    // A genuinely empty prefix has no H9 payload to consume.
                    // This is disposal metadata, never a fabricated seal/replay.
                    SealApplyOutcome::Held => {
                        seal.prefix.settled().is_empty()
                            && seal.prefix.open_keys().is_empty()
                            && registry.joint_staged_count(&target) == Some(0)
                    }
                }
            }
            Err(_) => {
                let failure = self
                    .failure_for(target.bootstrap().domain())
                    .ok_or(RawQuantumRefusal::Admission)?;
                match registry.deliver_joint_failure(
                    target.id(),
                    &failure,
                    model,
                    adapter.ledger_mut(),
                ) {
                    FailureApplyOutcome::FellBack { .. }
                    | FailureApplyOutcome::Degraded { .. }
                    | FailureApplyOutcome::Ignored => true,
                    FailureApplyOutcome::Retried => {
                        self.active = None;
                        return Ok(QuantumSealProgress::LocalPending);
                    }
                    FailureApplyOutcome::HeldForCompleteness => false,
                }
            }
        };
        if complete {
            self.advance_consumer(ConsumerState::Delivered);
            self.active = None;
            Ok(self.progress())
        } else {
            Ok(QuantumSealProgress::LocalPending)
        }
    }

    #[allow(clippy::result_large_err)] // Refusal returns the same move-only frame and retained buffers.
    pub(crate) fn finish_frame(
        self,
        ports: &mut JointPublicationPorts<'_>,
    ) -> Result<DisposedJointQuantum, (Self, RawQuantumRefusal)> {
        if let Err(reason) = self.preflight(ports) {
            return Err((self, reason));
        }
        if !self.bound || self.active.is_some() || self.pending != 0 {
            return Err((self, RawQuantumRefusal::DispositionMismatch));
        }
        if let Some(failure) = &self.failure {
            if self.consumers.iter().any(|consumer| {
                failure.affects_domain(consumer.target.bootstrap().domain())
                    && consumer.state != ConsumerState::LossDelivered
            }) {
                return Err((self, RawQuantumRefusal::DispositionMismatch));
            }
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
