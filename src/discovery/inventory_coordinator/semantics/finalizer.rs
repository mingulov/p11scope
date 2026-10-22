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
    pub(super) pending_semantic: Option<SemanticBatch>,
    pub(super) h3_last: H3DispositionEvidence,
    pub(super) h3_pending: Option<H3DispositionEvidence>,
    pub(super) h3_acked_below: u64,
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
            pending_drop: None,
            seal_admission: None,
        }
    }

    pub(super) fn take_disposition(&mut self) -> H3DispositionEvidence {
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
            return retained.native_domain() == producers.native_domain()
                && retained.events_id() == producers.events_id();
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

impl H3EvidenceSource for SessionH3Finalizer<'_> {
    fn take_h3_disposition(&mut self) -> H3DispositionEvidence {
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
