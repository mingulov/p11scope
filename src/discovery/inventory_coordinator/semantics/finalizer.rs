//! SPDX-License-Identifier: GPL-3.0-or-later
//! One retained Session's H0 disposition and H3 acknowledgement namespace.

use super::*;
use crate::attach::SessionDrainProducers;
use crate::semantics_objects::journal::{
    H3DispositionEvidence, H3EvidenceSource, H3FinalizerPort, H3VoidAcknowledgement,
};

pub(in crate::discovery::engine::inventory_coordinator) struct SessionFinalizerState {
    pub(super) domain: NativeDomainId,
    #[cfg_attr(not(test), allow(dead_code))] // Staged: tested only; no production seal path.
    producers: Option<SessionDrainProducers>,
    pub(super) pending_semantic: Option<PendingSemanticBatch>,
    pub(super) h3_last: H3DispositionEvidence,
    pub(super) h3_pending: Option<H3DispositionEvidence>,
    pub(super) h3_acked_below: u64,
    #[cfg(test)]
    h3_takes: usize,
    pub(super) pending_drop: Option<(u64, bool)>,
    /// The namespace's first admitted call (D9): the seal grant's
    /// association proof, set once at finalize, borrowed (never
    /// taken) by each seal mint. The grant proves the
    /// Session-stable domain↔EVENTS association, so one proof
    /// serves every quantum including quiet ones; per-quantum
    /// freshness comes from the retained quantum's own bindings.
    /// Dropped with the namespace at retire: no cross-domain reuse.
    pub(super) seal_admission:
        Option<crate::discovery::caller_registry::instance_input::AdmittedInstanceCall>,
}

impl SessionFinalizerState {
    pub(super) fn new(domain: NativeDomainId) -> Self {
        Self {
            domain,
            producers: None,
            pending_semantic: None,
            h3_last: H3DispositionEvidence::genesis(),
            h3_pending: None,
            h3_acked_below: 0,
            #[cfg(test)]
            h3_takes: 0,
            pending_drop: None,
            seal_admission: None,
        }
    }

    pub(super) fn take_disposition(&mut self) -> H3DispositionEvidence {
        #[cfg(test)]
        {
            self.h3_takes += 1;
        }
        self.h3_pending
            .take()
            .unwrap_or_else(H3DispositionEvidence::genesis)
    }

    #[cfg_attr(not(test), allow(dead_code))] // Staged H3 finalizer path: exercised by the finalizer tests; no production seal path wires it yet.
    fn bind_producers(&mut self, producers: &SessionDrainProducers) -> bool {
        if self.domain != producers.native_domain() {
            return false;
        }
        if let Some(retained) = &self.producers {
            return retained.same_producers(producers);
        }
        self.producers = Some(producers.clone());
        true
    }
}

/// A borrow of the actual Session producer pair and its private finalizer state.
/// A new lane cannot replace the namespace while a port is borrowed. Neither a
/// numeric domain nor a scalar void watermark can construct this port or ack it.
pub(crate) struct SessionH3Finalizer<'session> {
    state: &'session mut SessionFinalizerState,
    producers: &'session SessionDrainProducers,
}

/// Ephemeral authorization from this coordinator's disjoint original owner
/// and finalizer borrows. No other caller can pair independent owner/state
/// namespaces for an audit; construction remains private to this module.
pub(crate) struct SessionAuditInput<'session> {
    ingested: crate::semantics_objects::journal::joint_driver::IngestedRaw,
    owner: &'session mut crate::semantics_objects::journal::joint_driver::JointCaptureOwner,
    finalizer: SessionH3Finalizer<'session>,
    producers: &'session SessionDrainProducers,
}

impl<'session> SessionAuditInput<'session> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::semantics_objects::journal::joint_driver::IngestedRaw,
        &'session mut crate::semantics_objects::journal::joint_driver::JointCaptureOwner,
        SessionH3Finalizer<'session>,
        &'session SessionDrainProducers,
    ) {
        (self.ingested, self.owner, self.finalizer, self.producers)
    }
}

/// Ephemeral disjoint borrows from one canonical coordinator. Births borrow
/// the same move-only binding set as the target chosen by the audit frame.
pub(crate) struct JointPublicationPorts<'session> {
    registry: &'session mut crate::discovery::caller_registry::CallerRegistry,
    owner: &'session mut crate::semantics_objects::journal::joint_driver::JointCaptureOwner,
    bindings: &'session SemanticBindingSet,
    finalizer: SessionH3Finalizer<'session>,
    producers: &'session SessionDrainProducers,
}
type JointReadPorts<'a> = (
    &'a crate::discovery::caller_registry::CallerRegistry,
    &'a crate::semantics_objects::journal::joint_driver::JointCaptureOwner,
    &'a SemanticBindingSet,
    &'a SessionDrainProducers,
);
type JointMutablePorts<'a, 'session> = (
    &'a mut crate::discovery::caller_registry::CallerRegistry,
    &'a mut crate::semantics_objects::journal::joint_driver::JointCaptureOwner,
    &'a SemanticBindingSet,
    &'a mut SessionH3Finalizer<'session>,
    &'a SessionDrainProducers,
);
impl<'session> JointPublicationPorts<'session> {
    pub(crate) fn read(&self) -> JointReadPorts<'_> {
        (self.registry, self.owner, self.bindings, self.producers)
    }
    pub(crate) fn split(&mut self) -> JointMutablePorts<'_, 'session> {
        (
            self.registry,
            self.owner,
            self.bindings,
            &mut self.finalizer,
            self.producers,
        )
    }
}

impl SessionH3Finalizer<'_> {
    /// Read-only gate: originals must have left the one pending handoff and
    /// produced an untaken disposition in this exact retained Session.
    pub(crate) fn ready_for_audit(&self, producers: &SessionDrainProducers) -> bool {
        self.producers.same_producers(producers)
            && self.state.domain == producers.native_domain()
            && self
                .state
                .producers
                .as_ref()
                .is_none_or(|held| held.same_producers(producers))
            && self.state.pending_semantic.is_none()
            && self.state.pending_drop.is_none()
            && self.state.seal_admission.is_some()
            && self.state.h3_pending.is_some()
    }
}

impl H3EvidenceSource for SessionH3Finalizer<'_> {
    fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
        assert!(self.state.bind_producers(self.producers));
        self.state.take_disposition()
    }
}

impl H3FinalizerPort for SessionH3Finalizer<'_> {
    fn acknowledge_h3_void(&mut self, acknowledgement: H3VoidAcknowledgement) {
        // The exact retained native/EVENTS pair is checked BEFORE reading the
        // scalar. Old seals and equal numeric cuts cannot acknowledge B.
        if let Some(voided_below) = acknowledgement.for_producers(self.producers) {
            self.state.h3_acked_below = self.state.h3_acked_below.max(voided_below);
        }
    }
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    /// No insertion/rebinding, H3 take or revision change. The existing
    /// Session and retained EVENTS allocation must already match the owner.
    #[cfg_attr(not(test), allow(dead_code))] // Ordinary Joint activation remains gated.
    pub(crate) fn joint_frame_ports<'session>(
        &'session mut self,
        producers: &'session SessionDrainProducers,
    ) -> Result<
        JointPublicationPorts<'session>,
        crate::semantics_objects::journal::joint_driver::RawQuantumRefusal,
    > {
        use crate::semantics_objects::journal::joint_driver::RawQuantumRefusal;
        if !self.joint_capture.adapter().retains_producers(producers) {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        let state = self
            .semantic_finalizer
            .as_mut()
            .ok_or(RawQuantumRefusal::H3Undisposed)?;
        if state.domain != producers.native_domain()
            || !state
                .producers
                .as_ref()
                .is_some_and(|held| held.same_producers(producers))
        {
            return Err(RawQuantumRefusal::ForeignCapture);
        }
        if state.pending_semantic.is_some() || state.pending_drop.is_some() {
            return Err(RawQuantumRefusal::H3Undisposed);
        }
        Ok(JointPublicationPorts {
            registry: &mut self.registry,
            owner: &mut self.joint_capture,
            bindings: &self.semantic_bindings,
            finalizer: SessionH3Finalizer { state, producers },
            producers,
        })
    }

    /// The genuine fixture's initial history uses the canonical owner on
    /// both sides of delivery; no external model can be substituted.
    #[cfg(test)]
    pub(crate) fn deliver_canonical_joint_seal_for_test(
        &mut self,
        id: crate::discovery::caller_registry::instance_input::RegistryInstanceId,
        seal: &crate::semantics_objects::journal::SealSuccess,
    ) -> crate::semantics_key_use::SealApplyOutcome {
        let (adapter, model) = self.joint_capture.parts();
        self.registry
            .deliver_joint_algorithm_seal_for_test(id, seal, model, adapter.ledger_mut())
    }

    /// Take one actual finished collection into immutable audit custody,
    /// borrowing the canonical owner and finalizer state disjointly.
    #[cfg_attr(not(test), allow(dead_code))] // Ordinary Joint activation remains gated.
    #[allow(clippy::result_large_err)] // Refusal preserves the original nonallocating ingestion proof.
    pub(crate) fn audit_ingested_quantum(
        &mut self,
        ingested: crate::semantics_objects::journal::joint_driver::IngestedRaw,
        producers: &SessionDrainProducers,
        attachment: &crate::attach::AttachedSemanticSet,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) -> crate::semantics_objects::journal::joint_audit::AuditAcquisition {
        use crate::semantics_objects::journal::joint_driver::RawQuantumRefusal;
        if let Err(reason) = ingested.validate_owner(self.joint_capture.adapter(), producers) {
            return Err((ingested, reason));
        }
        let Some(state) = self.semantic_finalizer.as_mut() else {
            return Err((ingested, RawQuantumRefusal::H3Undisposed));
        };
        if state.domain != producers.native_domain()
            || state
                .producers
                .as_ref()
                .is_some_and(|held| !held.same_producers(producers))
        {
            return Err((ingested, RawQuantumRefusal::ForeignCapture));
        }
        let finalizer = SessionH3Finalizer { state, producers };
        let authorized = SessionAuditInput {
            ingested,
            owner: &mut self.joint_capture,
            finalizer,
            producers,
        };
        crate::semantics_objects::journal::joint_audit::IngestedJointQuantum::audit(
            authorized, attachment, fault,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))] // Staged H3 finalizer path: exercised by the H3 acknowledgement tests; no production seal path wires it yet.
    pub(crate) fn session_h3_finalizer<'session>(
        &'session mut self,
        producers: &'session SessionDrainProducers,
    ) -> Result<super::SessionH3Finalizer<'session>, SemanticRefusal> {
        let state = self
            .semantic_finalizer
            .get_or_insert_with(|| SessionFinalizerState::new(producers.native_domain()));
        if !state.bind_producers(producers) {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(SessionH3Finalizer { state, producers })
    }

    #[cfg(test)]
    pub(crate) fn reference_h3_acknowledged_below(&self) -> u64 {
        self.semantic_finalizer
            .as_ref()
            .map_or(0, |state| state.h3_acked_below)
    }

    #[cfg(test)]
    pub(crate) fn reference_h3_audit_state(&self) -> (usize, bool) {
        self.semantic_finalizer
            .as_ref()
            .map_or((0, false), |state| {
                (state.h3_takes, state.h3_pending.is_some())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_h3_finalizer_retains_exact_native_and_events_pair() {
        let native = NativeDomainId::mint();
        let events = crate::events::EventsDomain::test_standin(91);
        let own = SessionDrainProducers::test_pair(native, events.clone());
        let other_native = SessionDrainProducers::test_pair(NativeDomainId::mint(), events);
        let other_events =
            SessionDrainProducers::test_pair(native, crate::events::EventsDomain::test_standin(92));
        let equal_id_foreign =
            SessionDrainProducers::test_pair(native, crate::events::EventsDomain::test_standin(91));
        let mut state = SessionFinalizerState::new(native);
        assert!(!state.bind_producers(&other_native));
        assert!(state.producers.is_none());
        assert!(state.bind_producers(&own));
        assert!(state.bind_producers(&own.clone()));
        assert!(!state.bind_producers(&other_native));
        assert!(!state.bind_producers(&other_events));
        assert!(
            !state.bind_producers(&equal_id_foreign),
            "the same map id cannot replace the retained EVENTS allocation"
        );
        assert_eq!(
            state.producers.as_ref().unwrap().events_id(),
            own.events_id()
        );
        assert_eq!(state.h3_acked_below, 0);
    }
}
