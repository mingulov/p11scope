//! SPDX-License-Identifier: GPL-3.0-or-later
//! One original semantic handoff, before any Joint feed is activated.
#![cfg_attr(not(test), allow(dead_code))]

use super::*;
use crate::attach::SessionDrainProducers;
use crate::discovery::caller_registry::CallerRegistry;
use crate::semantics_objects::journal::joint_driver::{
    IngestedRaw, JointCaptureOwner, RawQuantumRefusal,
};
use crate::semantics_objects::journal::{AttestationRefusal, JournalAdapter, JournalDomainProof};

pub(crate) type PreparedClaim = (u64, Result<JournalDomainProof, AttestationRefusal>);

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
    h3: PreparedH3,
    claim_cursor: usize,
    stage_cursor: usize,
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
        h3: PreparedH3,
    ) -> Self {
        Self {
            domain,
            entries,
            current,
            h3,
            claim_cursor: 0,
            stage_cursor: 0,
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

    pub(crate) fn current_receipts(&self) -> &[crate::semantic_capture::CurrentPartitionReceipt] {
        &self.current
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
        while let Some(entry) = self.entries.get(next) {
            // Conversion refusals need no journal claim. Their original
            // positions remain owned until the staging/refusal cursor moves.
            if let Some(Ok(input)) = &entry.input {
                if !ingested.matches_admission(input)
                    && !ingested.matches_retained_admission(input, adapter)
                {
                    return Err(RawQuantumRefusal::Admission);
                }
                let claim = adapter.attest_key(input);
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

    pub(crate) fn prepare_staged_semantic_batch(
        &mut self,
        lane: &mut AttestedSemanticLane,
        floor: Option<u64>,
    ) -> Result<(), SemanticRefusal> {
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
