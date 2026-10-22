//! SPDX-License-Identifier: GPL-3.0-or-later
//! One original ingested collection, immutable H3 audit and global outcome.
#![cfg_attr(not(test), allow(dead_code))] // Domain delivery is the next staged slice.

use super::joint_driver::{
    IngestedRaw, JointCaptureOwner, RawProvenance, RawQuantumIdentity, RawQuantumRefusal,
};
use super::{
    ConsumptionOrdinal, FaultEpoch, JournalAdapter, JournalAuditReceipt, SealFailure,
    SealFailureScope, SessionClosureGrant,
};
use crate::attach::{AttachedSemanticSet, SessionDrainProducers};
use crate::discovery::engine::inventory_coordinator::semantics::SessionAuditInput;
use crate::semantics_edge::resources::{OWNED_ALLOCATION_PADDING, ResourceLease};
use crate::semantics_objects::{ObjectDomain, ObjectEffect, ObjectSemantics};
use std::mem::size_of;

/// No Clone or scalar constructor. The original provenance is moved intact;
/// collection-wide loss stays here for subsequent domain fanout. No domain
/// delivery, acknowledgement or ordinary Joint activation occurs in this slice.
pub(crate) struct IngestedJointQuantum {
    provenance: RawProvenance,
    frontier: ConsumptionOrdinal,
    audit: JournalAuditReceipt,
    failure: Option<SealFailure>,
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
        let Some(failure) = &self.failure else {
            return Some(size_of::<Self>());
        };
        let domains = match &failure.scope {
            SealFailureScope::AffectedDomains(domains) => domains.capacity(),
            SealFailureScope::Unqualified | SealFailureScope::Domain(_) => 0,
        };
        size_of::<Self>()
            .checked_add(allocation_bytes::<ObjectDomain>(domains)?)?
            .checked_add(allocation_bytes::<ObjectEffect>(
                failure.effects.effects.capacity(),
            )?)
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
