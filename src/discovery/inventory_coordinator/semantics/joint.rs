//! SPDX-License-Identifier: GPL-3.0-or-later
//! One original semantic handoff, before any Joint feed is activated.
#![cfg_attr(not(test), allow(dead_code))]

use super::*;
use crate::attach::SessionDrainProducers;
use crate::discovery::caller_registry::CallerRegistry;
use crate::inventory_semantics::{JointCommitIo, JointContinuationView, RetainedJointBirths};
use crate::semantics_objects::journal::joint_audit::{
    DisposedJointQuantum, IngestedJointQuantum, JointBirthEvidenceSource, QuantumSealProgress,
};
use crate::semantics_objects::journal::joint_driver::{
    IngestedRaw, JointCaptureOwner, RawJointQuantum, RawQuantumRefusal,
};
use crate::semantics_objects::journal::{AttestationRefusal, JournalAdapter, JournalDomainProof};
use crate::semantics_objects::journal::{FaultEpoch, FaultReadError};

/// Stack-only borrows of the same original service inputs. Erasing the I/O
/// leaf here keeps the ordinary and Joint callers on commit_batch_inner.
pub(in crate::discovery::engine::inventory_coordinator) struct JointCommitInput<'a> {
    continuation: JointContinuationInput<'a>,
    producers: &'a SessionDrainProducers,
    frame: &'a mut Option<IngestedJointQuantum>,
    births: &'a mut dyn JointBirthEvidenceSource,
    fault: &'a dyn FaultEpoch,
    remaining: &'a mut usize,
}

enum JointContinuationInput<'a> {
    Scoped(JointContinuationView<'a>),
    // Old fixtures retain a whole-owner RefCell. Borrow its actual view only
    // during pending checks, never across their separate birth callback.
    #[cfg(test)]
    Legacy(&'a AttestedSemanticLane),
}

impl JointContinuationInput<'_> {
    fn matches_producers(&self, producers: &SessionDrainProducers) -> bool {
        match self {
            Self::Scoped(view) => view.matches_producers(producers),
            #[cfg(test)]
            Self::Legacy(lane) => {
                lane.domain() == producers.native_domain() && lane.is_live() && !lane.is_finished()
            }
        }
    }

    fn with_view<R>(&self, inspect: impl FnOnce(&JointContinuationView<'_>) -> R) -> Option<R> {
        match self {
            Self::Scoped(view) => Some(inspect(view)),
            #[cfg(test)]
            Self::Legacy(lane) => lane.with_joint_continuation(inspect),
        }
    }
}

struct BorrowedBirths<'a>(&'a mut dyn JointBirthEvidenceSource);
impl JointBirthEvidenceSource for BorrowedBirths<'_> {
    fn take_for(
        &mut self,
        target: &crate::discovery::caller_registry::instance_input::JointFeedTarget,
        binding: &SemanticCallerBinding,
    ) -> Result<
        crate::semantics_objects::journal::SessionBirthEvidence,
        crate::attach::BirthObservationRefusal,
    > {
        self.0.take_for(target, binding)
    }
}

struct BorrowedFault<'a>(&'a dyn FaultEpoch);
impl FaultEpoch for BorrowedFault<'_> {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        self.0.fault_epoch()
    }
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    /// Finish physical preparation and its actual H0 cut while the original
    /// batch is still Collected. No admission, claim or frame audit exists yet.
    pub(crate) fn prepare_joint_publication(
        &mut self,
        engine_changed: bool,
        lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        producers: &SessionDrainProducers,
    ) -> Result<()> {
        raw.validate_preparation(self.joint_capture.adapter(), producers)
            .map_err(|reason| anyhow::anyhow!("Joint preparation original refused: {reason:?}"))?;
        if lane.domain() != producers.native_domain() || !lane.is_live() || lane.is_finished() {
            bail!("Joint preparation must retain its actual live lane");
        }
        lane.validate_collected_preparation(raw)
            .map_err(|reason| anyhow::anyhow!("Joint preparation H0 owner refused: {reason:?}"))?;
        if self.publication_pending() {
            self.registry.validate_joint_preparation(raw)?;
            if self.joint_publication.is_none() {
                bail!("Joint preparation has no original completion context");
            }
            return Ok(());
        }
        if !self
            .semantic_finalizer
            .as_ref()
            .is_some_and(|state| state.permits_joint_preparation(producers))
        {
            bail!(
                "Joint preparation requires the original collected semantic batch and no untaken H3"
            );
        }
        let storage = self
            .registry
            .reserve_semantic_storage(std::mem::size_of::<PendingJointPublication>())
            .map_err(|reason| anyhow::anyhow!("Joint completion storage refused: {reason:?}"))?;
        self.registry
            .begin_joint_publication(raw, &self.joint_capture, producers)?;
        let completion = match self.prepare_physical_publication(engine_changed, Some(lane)) {
            Ok(completion) => completion,
            Err(reason) => {
                self.registry.cancel_unapplied_joint_publication();
                return Err(reason);
            }
        };
        self.observe_pending_h0_images();
        let cut_barrier = self.finalize_physical_tail(lane, Some(raw));
        self.joint_publication = Some(PendingJointPublication {
            completion,
            cut_barrier,
            _storage: storage,
        });
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn commit_joint_batch(
        &mut self,
        lane: &mut AttestedSemanticLane,
        producers: &SessionDrainProducers,
        frame: &mut Option<IngestedJointQuantum>,
        births: &mut impl JointBirthEvidenceSource,
        fault: &impl FaultEpoch,
        remaining: &mut usize,
    ) -> Result<JointCommitProgress> {
        self.commit_batch_inner(
            false, // Its original engine tail already finished in preparation.
            None,
            Some(JointCommitInput {
                continuation: JointContinuationInput::Legacy(lane),
                producers,
                frame,
                births,
                fault,
                remaining,
            }),
        )
    }

    /// The live branch receives only disjoint immutable H0 custody and the
    /// same Session's scope-bound native readers, never the whole lane.
    pub(crate) fn commit_joint_batch_with_io(
        &mut self,
        io: JointCommitIo<'_>,
        producers: &SessionDrainProducers,
        frame: &mut Option<IngestedJointQuantum>,
        remaining: &mut usize,
    ) -> Result<JointCommitProgress> {
        let (continuation, births, fault) = io.into_parts();
        self.commit_batch_inner(
            false,
            None,
            Some(JointCommitInput {
                continuation: JointContinuationInput::Scoped(continuation),
                producers,
                frame,
                births,
                fault,
                remaining,
            }),
        )
    }

    pub(in crate::discovery::engine::inventory_coordinator) fn commit_joint_publication_inner(
        &mut self,
        input: JointCommitInput<'_>,
    ) -> Result<JointCommitProgress> {
        let JointCommitInput {
            continuation,
            producers,
            frame,
            births,
            fault,
            remaining,
        } = input;
        let original = frame
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Joint publication requires its original frame"))?;
        if self.joint_publication.is_none() || !self.registry.publication_pending() {
            bail!("Joint physical preparation must precede admissions and the original audit");
        }
        if !continuation.matches_producers(producers) {
            bail!("Joint publication must retain its original live lane");
        }
        // Every mismatch/refusal precedes engine/cgroup/finalizer/observer
        // work, including a retry with an equal-shaped foreign allocation.
        self.registry
            .validate_joint_publication(original, &self.joint_capture, producers)?;
        self.joint_frame_ports(producers)
            .map_err(|reason| anyhow::anyhow!("Joint publication ports refused: {reason:?}"))?;
        self.registry
            .bind_joint_publication_frame(original, &self.joint_capture, producers)?;
        if !self.registry.joint_publication_applied() {
            self.publish_registry(Some((
                frame.as_ref().expect("retained original frame"),
                producers,
            )))?;
        }
        if !self.registry.joint_publication_targets_bound() {
            let mut ports = self
                .joint_frame_ports(producers)
                .map_err(|reason| anyhow::anyhow!("Joint target ports refused: {reason:?}"))?;
            frame
                .as_mut()
                .expect("retained original frame")
                .bind_targets(&ports)
                .map_err(|reason| anyhow::anyhow!("Joint targets refused: {reason:?}"))?;
            // The private marker avoids repeating snapshot allocation. It
            // grants no permission: every seal/delivery rechecks the frame.
            ports.split().0.mark_joint_publication_targets_bound();
        }
        if let Some(disposed) = self.finish_joint_frame_if_ready(frame, producers, &continuation)? {
            return Ok(self.complete_joint_publication(disposed));
        }
        let mut births = BorrowedBirths(births);
        let fault = BorrowedFault(fault);
        while *remaining != 0 {
            let before = *remaining;
            {
                let mut ports = self
                    .joint_frame_ports(producers)
                    .map_err(|reason| anyhow::anyhow!("Joint service ports refused: {reason:?}"))?;
                let held = frame.as_mut().expect("same original service frame");
                held.seal_next(&mut ports, &mut births, &fault)
                    .map_err(|reason| anyhow::anyhow!("Joint seal refused: {reason:?}"))?;
                held.deliver_next_bounded(&mut ports, remaining)
                    .map_err(|reason| anyhow::anyhow!("Joint delivery refused: {reason:?}"))?;
            }
            if let Some(disposed) =
                self.finish_joint_frame_if_ready(frame, producers, &continuation)?
            {
                return Ok(self.complete_joint_publication(disposed));
            }
            if *remaining == before {
                break; // Same-frontier retry or real future-input dependency.
            }
        }
        Ok(JointCommitProgress::Pending)
    }

    // Refusal closures return the original move-only frame without allocating
    // while its charged buffers and pending H3 ownership are still retained.
    #[allow(clippy::result_large_err)]
    fn finish_joint_frame_if_ready(
        &mut self,
        frame: &mut Option<IngestedJointQuantum>,
        producers: &SessionDrainProducers,
        continuation: &JointContinuationInput<'_>,
    ) -> Result<Option<DisposedJointQuantum>> {
        let mut ports = self
            .joint_frame_ports(producers)
            .map_err(|reason| anyhow::anyhow!("Joint completion ports refused: {reason:?}"))?;
        let held = frame
            .take()
            .expect("same original frame until actual finish");
        let result = match held.finish_frame(&mut ports) {
            Ok(disposed) => return Ok(Some(disposed)),
            Err((held, RawQuantumRefusal::H3Undisposed)) => {
                let mut original = Some(held);
                continuation
                    .with_view(|view| {
                        let mut held = original.take().expect("one original pending frame");
                        match held.defer_pending_h3_with_view(&mut ports, view) {
                            Ok(
                                QuantumSealProgress::AwaitFutureInput
                                | QuantumSealProgress::Complete,
                            ) => held.finish_pending_h3_with_view(&mut ports, view),
                            Ok(_) => Err((held, RawQuantumRefusal::H3Undisposed)),
                            Err(reason) => Err((held, reason)),
                        }
                    })
                    .unwrap_or_else(|| {
                        Err((
                            original.expect("an unavailable view preserves the same frame"),
                            RawQuantumRefusal::H3Undisposed,
                        ))
                    })
            }
            Err(other) => Err(other),
        };
        match result {
            Ok(disposed) => Ok(Some(disposed)),
            Err((
                held,
                RawQuantumRefusal::DispositionMismatch | RawQuantumRefusal::H3Undisposed,
            )) => {
                *frame = Some(held);
                Ok(None)
            }
            Err((held, reason)) => {
                *frame = Some(held);
                bail!("Joint completion refused: {reason:?}");
            }
        }
    }

    fn complete_joint_publication(
        &mut self,
        disposed: DisposedJointQuantum,
    ) -> JointCommitProgress {
        let applied = self
            .registry
            .finish_joint_publication(&mut self.joint_capture, &disposed)
            .expect("exclusive original frame disposal matches its preflighted publication");
        let pending = self
            .joint_publication
            .take()
            .expect("original completion context");
        let receipt = self.finish_publication_context(pending.completion, applied);
        drop(pending._storage); // Original collection/events have moved or finished first.
        JointCommitProgress::Published(receipt)
    }
}

pub(crate) type PreparedClaim = (u64, Result<JournalDomainProof, AttestationRefusal>);

/// Completion counters only; the registry retains every actual grant and
/// missing/refused births remain permanent S1 at the original registration.
pub(crate) struct PreparedBirthDisposition {
    pub(crate) installed: usize,
}

struct BirthAssociation {
    image: (u64, u64),
    router: u64,
    current: usize,
    entry: Option<usize>,
}

fn disclose_s1_birth_refusal(
    registry: &mut CallerRegistry,
    caller: Option<CallerId>,
    reason: String,
) {
    registry.record_gap(RegistryGap {
        caller,
        module: None,
        pid: None,
        subject: "Joint birth unavailable; retained S1".into(),
        reason,
        budget: None,
    });
}

/// The existing single pending slot changes phase; preparation adds no queue.
pub(super) enum PendingSemanticBatch {
    Collected(SemanticBatch),
    Prepared(PreparedSemanticBatch),
}

impl From<SemanticBatch> for PendingSemanticBatch {
    fn from(batch: SemanticBatch) -> Self {
        Self::Collected(batch)
    }
}

impl PendingSemanticBatch {
    pub(super) fn min_outcome_position(&self) -> Option<u64> {
        match self {
            Self::Collected(batch) => batch.min_outcome_position(),
            Self::Prepared(batch) => batch
                .entries
                .get(batch.stage_cursor)
                .map(|entry| entry.token),
        }
    }

    pub(super) fn is_prepared(&self) -> bool {
        matches!(self, Self::Prepared(_))
    }
}

pub(super) struct PreparedAdmission {
    caller: Option<CallerId>,
    token: u64,
    input: Option<Result<AdmittedInstanceCall, ConversionRefusal>>,
    claim: Option<Result<JournalDomainProof, AttestationRefusal>>,
}

impl PreparedAdmission {
    pub(super) fn new(
        (caller, token, input): (
            Option<CallerId>,
            u64,
            Result<AdmittedInstanceCall, ConversionRefusal>,
        ),
    ) -> Self {
        Self {
            caller,
            token,
            input: Some(input),
            claim: None,
        }
    }
}

pub(super) struct PreparedH3 {
    pub(super) negatives: Vec<LaneNegative>,
    pub(super) staged_positions: Vec<Option<u64>>,
    pub(super) awaiting_floor: Option<u64>,
    pub(super) shed_floor: Option<u64>,
    pub(super) exhausted: bool,
}

/// Owns the original sorted inputs until each claim decision and staging move
/// completes. The cursor of one phase never acknowledges the other phase.
pub(crate) struct PreparedSemanticBatch {
    domain: NativeDomainId,
    entries: Vec<PreparedAdmission>,
    // Preserve actual H0 birth candidates for the later publication handoff.
    current: Vec<crate::semantic_capture::CurrentPartitionReceipt>,
    registrations: crate::discovery::caller_registry::instance_input::JointRegistrationWindow,
    h3: PreparedH3,
    claim_cursor: usize,
    stage_cursor: usize,
    births_decided: bool,
    // Buffers and nested owned payloads drop before their retained charge.
    storage: Option<ResourceLease>,
}

fn allocation_bytes<T>(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(std::mem::size_of::<T>())?
        .checked_add(if capacity == 0 {
            0
        } else {
            OWNED_ALLOCATION_PADDING
        })
}

impl PreparedSemanticBatch {
    pub(super) fn new(
        domain: NativeDomainId,
        entries: Vec<PreparedAdmission>,
        current: Vec<crate::semantic_capture::CurrentPartitionReceipt>,
        registrations: crate::discovery::caller_registry::instance_input::JointRegistrationWindow,
        h3: PreparedH3,
    ) -> Self {
        Self {
            domain,
            entries,
            current,
            registrations,
            h3,
            claim_cursor: 0,
            stage_cursor: 0,
            births_decided: false,
            storage: None,
        }
    }

    fn reserve_retention(&mut self, registry: &CallerRegistry) -> bool {
        // Synchronous S1 uses the same conversion temporaries as before.
        // Only the retained phase reserves their actual capacities, before
        // this owner enters the Session slot. Refusal drains direct S1 now.
        let bytes = (|| {
            let mut bytes = std::mem::size_of::<Self>()
                .checked_add(allocation_bytes::<PreparedAdmission>(
                    self.entries.capacity(),
                )?)?
                .checked_add(allocation_bytes::<
                    crate::semantic_capture::CurrentPartitionReceipt,
                >(self.current.capacity())?)?
                .checked_add(allocation_bytes::<LaneNegative>(
                    self.h3.negatives.capacity(),
                )?)?
                .checked_add(allocation_bytes::<Option<u64>>(
                    self.h3.staged_positions.capacity(),
                )?)?;
            for entry in &self.entries {
                if let Some(Ok(input)) = &entry.input {
                    bytes = bytes.checked_add(input.owned_storage_bytes()?)?;
                }
            }
            for receipt in &self.current {
                bytes = bytes.checked_add(receipt.owned_storage_bytes()?)?;
            }
            Some(bytes)
        })();
        self.storage = bytes.and_then(|bytes| registry.reserve_semantic_storage(bytes).ok());
        self.storage.is_some()
    }

    pub(crate) fn admissions(&self) -> impl Iterator<Item = &AdmittedInstanceCall> {
        self.entries
            .iter()
            .filter_map(|entry| entry.input.as_ref()?.as_ref().ok())
    }

    /// Original paid entry positions, including conversion refusals. The
    /// machine advances this index once rather than rescanning a suffix.
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn admission_at(&self, at: usize) -> Option<&AdmittedInstanceCall> {
        self.entries.get(at)?.input.as_ref()?.as_ref().ok()
    }

    pub(crate) fn current_receipts(&self) -> &[crate::semantic_capture::CurrentPartitionReceipt] {
        &self.current
    }

    pub(crate) fn claims(
        &self,
    ) -> impl Iterator<Item = (u64, &Result<JournalDomainProof, AttestationRefusal>)> {
        self.entries
            .iter()
            .filter_map(|entry| Some((entry.token, entry.claim.as_ref()?)))
    }

    pub(crate) fn next_admission(&self) -> Option<&AdmittedInstanceCall> {
        self.entries[self.stage_cursor..]
            .iter()
            .find_map(|entry| entry.input.as_ref()?.as_ref().ok())
    }

    pub(super) fn claim_next(
        &mut self,
        adapter: &mut JournalAdapter,
        ingested: &IngestedRaw,
    ) -> Result<Option<PreparedClaim>, RawQuantumRefusal> {
        let mut next = self.claim_cursor;
        while let Some(entry) = self.entries.get_mut(next) {
            // Conversion refusals need no journal claim. Their original
            // positions remain owned until the staging/refusal cursor moves.
            if let Some(Ok(input)) = &entry.input {
                if !ingested.matches_admission(input)
                    && !ingested.matches_retained_admission(input, adapter)
                {
                    return Err(RawQuantumRefusal::Admission);
                }
                let claim = adapter.attest_key(input);
                assert!(
                    entry.claim.is_none(),
                    "each actual original claim is retained once"
                );
                entry.claim = Some(claim);
                self.claim_cursor = next + 1;
                return Ok(Some((entry.token, claim)));
            }
            next += 1;
        }
        self.claim_cursor = next;
        Ok(None)
    }

    pub(super) fn dispose_claims_s1(&mut self) {
        // Direct S1 has no object-proof claim. This records that disposition,
        // without manufacturing a journal proof or invoking the adapter.
        self.claim_cursor = self.entries.len();
    }

    pub(super) fn stage_next(
        &mut self,
        registry: &mut CallerRegistry,
        seal_admission: &mut Option<AdmittedInstanceCall>,
    ) -> bool {
        if self.claim_cursor != self.entries.len() || self.stage_cursor >= self.claim_cursor {
            return false;
        }
        let Some(entry) = self.entries.get_mut(self.stage_cursor) else {
            return false;
        };
        let input = entry
            .input
            .take()
            .expect("only the original staging cursor moves an input");
        match input {
            Ok(input) => {
                if seal_admission.is_none() {
                    *seal_admission = Some(input.clone());
                }
                registry.observe_instance_semantic(input);
            }
            Err(reason) => {
                self.h3.shed_floor = Some(
                    self.h3
                        .shed_floor
                        .map_or(entry.token, |at| at.min(entry.token)),
                );
                registry.record_gap(RegistryGap {
                    caller: entry.caller,
                    module: None,
                    pid: None,
                    subject: "semantic input refused".into(),
                    reason: reason.code().into(),
                    budget: None,
                });
            }
        }
        self.stage_cursor += 1;
        true
    }

    fn complete(&self) -> bool {
        self.claim_cursor == self.entries.len() && self.stage_cursor == self.entries.len()
    }

    pub(super) fn into_h3(self) -> PreparedH3 {
        assert!(self.complete(), "H3 requires every original disposition");
        self.h3
    }
}

impl SessionFinalizerState {
    pub(super) fn take_collected(&mut self) -> Option<SemanticBatch> {
        if !matches!(
            self.pending_semantic,
            Some(PendingSemanticBatch::Collected(_))
        ) {
            return None;
        }
        match self.pending_semantic.take() {
            Some(PendingSemanticBatch::Collected(batch)) => Some(batch),
            _ => unreachable!("the single handoff phase was checked before take"),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))] // Staged ports; no Joint lane uses them yet.
impl<Source: ProcessSource> InventoryCoordinator<Source> {
    /// Test fixtures move the actual validated New receipts from the owning
    /// slot into the existing birth verifier. The production prepared view
    /// remains read-only; no receipt or birth authority is copied or minted.
    #[cfg(test)]
    pub(crate) fn take_prepared_current_for_birth_test(
        &mut self,
    ) -> Option<Vec<crate::semantic_capture::CurrentPartitionReceipt>> {
        match self
            .semantic_finalizer
            .as_mut()?
            .pending_semantic
            .as_mut()?
        {
            PendingSemanticBatch::Prepared(batch) => Some(std::mem::take(&mut batch.current)),
            PendingSemanticBatch::Collected(_) => None,
        }
    }

    pub(crate) fn prepared_semantic_batch(&self) -> Option<&PreparedSemanticBatch> {
        match self
            .semantic_finalizer
            .as_ref()?
            .pending_semantic
            .as_ref()?
        {
            PendingSemanticBatch::Prepared(batch) => Some(batch),
            PendingSemanticBatch::Collected(_) => None,
        }
    }

    /// Borrow the actual prepared originals beside the canonical capture
    /// owner for initial key binding and ingestion.
    pub(crate) fn prepared_joint_parts(
        &mut self,
    ) -> Option<(&PreparedSemanticBatch, &mut JointCaptureOwner)> {
        let Some(PendingSemanticBatch::Prepared(batch)) = self
            .semantic_finalizer
            .as_ref()
            .and_then(|state| state.pending_semantic.as_ref())
        else {
            return None;
        };
        Some((batch, &mut self.joint_capture))
    }

    /// Join the paid actual claim result to the original New exactly once.
    /// Native I/O borrows only disjoint registry/binding/adapter fields; no
    /// callback owns or replaces the coordinator. Storage failure precedes
    /// New consumption, while native/deadline refusal is final disclosed S1.
    pub(crate) fn prepare_joint_births(
        &mut self,
        ingested: &IngestedRaw,
        producers: &SessionDrainProducers,
        births: &mut RetainedJointBirths,
        mut consume: impl FnMut(
            crate::semantic_capture::H0BirthCandidate,
            Option<crate::semantic_capture::CommittedAbsenceBirth>,
            &AdmittedInstanceCall,
            &SemanticCallerBinding,
            &JournalDomainProof,
            &JournalAdapter,
        ) -> Result<
            crate::semantic_capture::RetainedBirthWitness,
            crate::attach::BirthObservationRefusal,
        >,
    ) -> Result<PreparedBirthDisposition, RawQuantumRefusal> {
        let adapter = self.joint_capture.adapter();
        ingested.validate_owner(adapter, producers)?;
        let Some(PendingSemanticBatch::Prepared(batch)) = self
            .semantic_finalizer
            .as_mut()
            .and_then(|state| state.pending_semantic.as_mut())
        else {
            return Err(RawQuantumRefusal::Admission);
        };
        if batch.domain != producers.native_domain() {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if batch.births_decided {
            return Ok(PreparedBirthDisposition { installed: 0 });
        }
        if batch.claim_cursor != batch.entries.len() || batch.stage_cursor != 0 {
            return Err(RawQuantumRefusal::Admission);
        }
        for entry in &batch.entries {
            if let Some(Ok(input)) = &entry.input
                && (entry.claim.is_none()
                    || entry.token != input.h0_ordinal()
                    || (!ingested.matches_admission(input)
                        && !ingested.matches_retained_admission(input, adapter)))
            {
                return Err(RawQuantumRefusal::Admission);
            }
        }
        let count = batch
            .current
            .iter()
            .filter(|receipt| receipt.birth_quantum().is_some())
            .try_fold(0usize, |count, receipt| {
                count.checked_add(receipt.instances().len())
            })
            .ok_or(RawQuantumRefusal::Capacity)?;
        if count == 0 {
            batch.births_decided = true;
            return Ok(PreparedBirthDisposition { installed: 0 });
        }
        let reserve = self.registry.semantic_storage_reserver();
        let bytes =
            allocation_bytes::<BirthAssociation>(count).ok_or(RawQuantumRefusal::Capacity)?;
        let Ok(_association_storage) = reserve.reserve(bytes) else {
            batch.births_decided = true;
            disclose_s1_birth_refusal(
                &mut self.registry,
                None,
                "semantic_resource_capacity".into(),
            );
            return Ok(PreparedBirthDisposition { installed: 0 });
        };
        let mut association = Vec::<BirthAssociation>::new();
        if association.try_reserve_exact(count).is_err() {
            batch.births_decided = true;
            disclose_s1_birth_refusal(
                &mut self.registry,
                None,
                "joint_birth_association_capacity".into(),
            );
            return Ok(PreparedBirthDisposition { installed: 0 });
        }
        assert!(
            association.capacity() <= count,
            "original association index was precharged"
        );
        for (current, receipt) in batch
            .current
            .iter()
            .enumerate()
            .filter(|(_, receipt)| receipt.birth_quantum().is_some())
        {
            let image = receipt.image();
            for router in receipt.instances() {
                association.push(BirthAssociation {
                    image: (image.task_cookie, image.exec_id),
                    router: router.get(),
                    current,
                    entry: None,
                });
            }
        }
        association.sort_unstable_by_key(|link| (link.image, link.router));
        if association
            .windows(2)
            .any(|pair| (pair[0].image, pair[0].router) == (pair[1].image, pair[1].router))
        {
            return Err(RawQuantumRefusal::Admission);
        }
        // One increasing admission walk and binary lookup; never scan the
        // whole retained suffix per key or re-attest a discarded Result arm.
        for (at, entry) in batch.entries.iter().enumerate() {
            let Some(Ok(input)) = &entry.input else {
                continue;
            };
            let (_, image, router, _) = input.journal_binding();
            if let Ok(index) = association.binary_search_by_key(
                &((image.task_cookie, image.exec_id), router.get()),
                |link| (link.image, link.router),
            ) {
                let link = &mut association[index];
                if link.entry.is_none()
                    && batch.current[link.current]
                        .birth_quantum()
                        .is_some_and(|quantum| {
                            input
                                .collected_origin()
                                .is_some_and(|origin| origin.in_quantum(quantum))
                        })
                {
                    link.entry = Some(at);
                }
            }
        }
        // Descending original positions allow moving each Current once with
        // swap_remove; earlier indices remain valid without another table.
        association.sort_unstable_by_key(|link| {
            (
                std::cmp::Reverse(link.current),
                link.entry.unwrap_or(usize::MAX),
            )
        });
        let mut registrations = match self.registry.joint_registration_plan() {
            Ok(registrations) => registrations,
            Err(_) => {
                batch.births_decided = true;
                return Ok(PreparedBirthDisposition { installed: 0 });
            }
        };
        batch.births_decided = true;
        let mut installed = 0;
        let mut cursor = 0;
        while cursor < association.len() {
            let current = association[cursor].current;
            let entry = association[cursor].entry;
            while cursor < association.len() && association[cursor].current == current {
                cursor += 1;
            }
            let Some(entry) = entry else {
                continue;
            };
            let Some(Ok(input)) = batch.entries[entry].input.as_ref() else {
                unreachable!("original index was checked");
            };
            let Some(Ok(proof)) = batch.entries[entry].claim else {
                // The FIRST actual same-key original governs permanent feed
                // selection. A later Ok cannot replace a refused claim.
                continue;
            };
            let Some(binding) = self.semantic_bindings.get(input.journal_binding().3) else {
                continue;
            };
            let receipt = &batch.current[current];
            if !receipt.matches_birth_admission(input, binding, &proof) {
                continue;
            }
            let Ok(mut slot) = births.reserve_for_current(&reserve, receipt) else {
                disclose_s1_birth_refusal(
                    registrations.registry_mut(),
                    Some(input.journal_binding().3),
                    "semantic_resource_capacity".into(),
                );
                continue;
            };
            let Ok(reservation) = registrations.reserve(input, &batch.registrations) else {
                continue;
            };
            let receipt = batch.current.swap_remove(current);
            let candidate = match receipt.into_birth_candidate() {
                Ok(candidate) => candidate,
                Err(receipt) => {
                    batch.current.push(receipt);
                    continue;
                }
            };
            let absence = slot.take_absence();
            let witness = match consume(candidate, absence, input, binding, &proof, adapter) {
                Ok(witness) => witness,
                Err(reason) => {
                    drop(reservation);
                    drop(slot);
                    disclose_s1_birth_refusal(
                        registrations.registry_mut(),
                        Some(input.journal_binding().3),
                        format!("joint_birth_native_{reason:?}"),
                    );
                    continue;
                }
            };
            if !witness.matches_original(input, binding, &proof) || !slot.accepts(&witness) {
                drop(reservation);
                drop(slot);
                disclose_s1_birth_refusal(
                    registrations.registry_mut(),
                    Some(input.journal_binding().3),
                    "joint_birth_original_mismatch".into(),
                );
                continue;
            }
            if reservation.install(input, &witness).is_err() {
                continue;
            }
            slot.retain(witness);
            installed += 1;
        }
        births.order_for_native_reads();
        Ok(PreparedBirthDisposition { installed })
    }

    /// The idle machine walks actual accepted image bindings and actual
    /// attached targets, including providers absent from the Mapped catalog.
    /// Only disjoint binding/adapter borrows cross the native acquisition.
    pub(crate) fn joint_absence_parts(
        &mut self,
        at: usize,
    ) -> Option<(&SemanticCallerBinding, &mut JournalAdapter)> {
        Some((
            self.semantic_bindings.bindings.get(at)?,
            self.joint_capture.adapter_mut(),
        ))
    }

    pub(crate) fn joint_absence_binding(&self, at: usize) -> Option<&SemanticCallerBinding> {
        self.semantic_bindings.bindings.get(at)
    }

    pub(crate) fn prepare_staged_semantic_batch(
        &mut self,
        lane: &mut AttestedSemanticLane,
        floor: Option<u64>,
    ) -> Result<(), SemanticRefusal> {
        let floor = floor
            .into_iter()
            .chain(
                self.joint_publication
                    .as_ref()
                    .and_then(|pending| pending.cut_barrier),
            )
            .max();
        let state = self
            .semantic_finalizer
            .as_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        if state.domain != lane.domain() {
            return Err(SemanticRefusal::Unavailable);
        }
        let batch = state.take_collected().ok_or(SemanticRefusal::Unavailable)?;
        let mut prepared = self
            .prepare_semantic_batch(lane, batch, floor)
            .ok_or(SemanticRefusal::Unavailable)?;
        if !prepared.reserve_retention(&self.registry) {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "semantic handoff storage refused".into(),
                reason: "semantic_resource_capacity".into(),
                budget: None,
            });
            self.drain_prepared_s1(&mut prepared);
            self.finish_semantic_preparation(prepared, lane.stash_pending_floor());
            return Err(SemanticRefusal::ProviderStorage);
        }
        self.semantic_finalizer
            .as_mut()
            .expect("matching namespace retained")
            .pending_semantic = Some(PendingSemanticBatch::Prepared(prepared));
        Ok(())
    }

    /// The exact original ingestion precedes every claim. A refused proof
    /// leaves the original inputs and both phase cursors untouched.
    pub(crate) fn claim_next_prepared_admission(
        &mut self,
        producers: &SessionDrainProducers,
        ingested: &IngestedRaw,
    ) -> Result<Option<PreparedClaim>, RawQuantumRefusal> {
        let adapter = self.joint_capture.adapter_mut();
        ingested.validate_owner(adapter, producers)?;
        let Some(PendingSemanticBatch::Prepared(batch)) = self
            .semantic_finalizer
            .as_mut()
            .and_then(|state| state.pending_semantic.as_mut())
        else {
            return Ok(None);
        };
        if batch.domain != producers.native_domain() {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        batch.claim_next(adapter, ingested)
    }

    pub(crate) fn dispose_prepared_claims_s1(&mut self) {
        if let Some(PendingSemanticBatch::Prepared(batch)) = self
            .semantic_finalizer
            .as_mut()
            .and_then(|state| state.pending_semantic.as_mut())
        {
            batch.dispose_claims_s1();
        }
    }

    pub(crate) fn stage_next_prepared_admission(&mut self) -> bool {
        let Some(state) = self.semantic_finalizer.as_mut() else {
            return false;
        };
        let Some(PendingSemanticBatch::Prepared(batch)) = state.pending_semantic.as_mut() else {
            return false;
        };
        batch.stage_next(&mut self.registry, &mut state.seal_admission)
    }

    /// Preserve the actual negative subject before moving the original
    /// admission into registry staging. Adjudication waits until H9 has joined
    /// its own originals; a foreign proof cannot move either phase cursor.
    pub(crate) fn stage_next_prepared_admission_with_disposition(
        &mut self,
        producers: &SessionDrainProducers,
        ingested: &mut IngestedRaw,
    ) -> Result<bool, RawQuantumRefusal> {
        let adapter = self.joint_capture.adapter_mut();
        ingested.validate_owner(adapter, producers)?;
        let Some(state) = self.semantic_finalizer.as_mut() else {
            return Ok(false);
        };
        let Some(PendingSemanticBatch::Prepared(batch)) = state.pending_semantic.as_mut() else {
            return Ok(false);
        };
        if batch.domain != producers.native_domain() {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if batch.claim_cursor != batch.entries.len() || batch.stage_cursor >= batch.claim_cursor {
            return Ok(false);
        }
        if let Some(Ok(input)) = batch.entries[batch.stage_cursor].input.as_ref()
            && self.registry.admitted_feed_is_s1only(input)
            && crate::kinds::function_id(&input.s1_facts().function)
                .and_then(crate::semantics_objects::journal::endpoint_class)
                == Some(crate::semantics_objects::journal::EndpointClass::ModeledAffecting)
        {
            ingested.retain_s1only_disposition(adapter, input)?;
        }
        Ok(batch.stage_next(&mut self.registry, &mut state.seal_admission))
    }

    pub(crate) fn finish_prepared_semantic_batch(&mut self, lane: &AttestedSemanticLane) -> bool {
        if !self
            .prepared_semantic_batch()
            .is_some_and(|batch| batch.domain == lane.domain() && batch.complete())
        {
            return false;
        }
        let Some(PendingSemanticBatch::Prepared(batch)) = self
            .semantic_finalizer
            .as_mut()
            .and_then(|state| state.pending_semantic.take())
        else {
            unreachable!("complete matching prepared handoff checked before take");
        };
        self.finish_semantic_preparation(batch, lane.stash_pending_floor());
        true
    }

    pub(super) fn drain_prepared_s1(&mut self, prepared: &mut PreparedSemanticBatch) {
        prepared.dispose_claims_s1();
        let state = self
            .semantic_finalizer
            .as_mut()
            .expect("matching finalizer namespace retained");
        while prepared.stage_next(&mut self.registry, &mut state.seal_admission) {}
    }
}
