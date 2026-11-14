//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
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
    /// Route-labeled shed from stage-refused batches, by drop label:
    /// counted into the stop line and disclosed by the next finalize's
    /// unrouted gap. Drained on flush; at most one entry per route label
    /// per drop label.
    pub(super) pending_drop_shed: BTreeMap<&'static str, BTreeMap<&'static str, u64>>,
    /// The namespace's first admitted call (D9): the seal grant's
    /// association proof, set once at finalize, borrowed (never
    /// taken) by each seal mint. The grant proves the
    /// Session-stable domain↔EVENTS association, so one proof
    /// serves every quantum including quiet ones; per-quantum
    /// freshness comes from the retained quantum's own bindings.
    /// Dropped with the namespace at retire: no cross-domain reuse.
    pub(super) seal_admission:
        Option<crate::discovery::caller_registry::instance_input::AdmittedInstanceCall>,
    /// B17 W2 per-namespace reload disclosure ledger: one entry per
    /// tainted identity keyed by the private (task cookie, exec id,
    /// file slot), holding the watched slot plus the continued
    /// instance IDs. First disclosure wins; the router queues each
    /// identity once. Capped at the batch bound: past the cap new
    /// identities shed (counted below, disclosed as a named gap).
    /// Dropped with the namespace at retire.
    #[cfg_attr(not(test), allow(dead_code))]
    // Staged: tested only; no production render path reads it yet.
    pub(super) reload_not_excluded: BTreeMap<(u64, u64, u32), (u32, Vec<u64>)>,
    /// Cumulative identities shed past the ledger cap: saturating,
    /// disclosed through the shed gap's running total.
    pub(super) reload_shed: u64,
    /// Latest carried router count snapshots: capture-monotonic, so
    /// the maximum wins.
    #[cfg_attr(not(test), allow(dead_code))]
    // Staged: tested only; no production render path reads it yet.
    pub(super) continued_across_global: u64,
    #[cfg_attr(not(test), allow(dead_code))]
    // Staged: tested only; no production render path reads it yet.
    pub(super) joined_across_global: u64,
    /// Unrouted calls shed before the namespace's first binding (JK-18),
    /// held instead of barriering until a binding can prove their caller.
    pub(super) pre_binding: PreBindingHold,
    /// Set at the first finalize that sees a binding: holding ends there.
    pub(super) bound_once: bool,
    /// Shed-tainted images eligible to lift their taint (JK-19b): maps
    /// image (task cookie, exec id) to the finalize sequence of its
    /// first shed-taint. An entry that binds/admits within grace lifts;
    /// expired entries drop and stay refused. Bounded by distinct
    /// images; past the cap new taints simply never lift (fail closed).
    pub(super) taint_lift: BTreeMap<(u64, u64), u64>,
    /// Finalize sequence for lift grace expiry. Monotonic per namespace.
    pub(super) finalize_seq: u64,
}

/// JK-19b grace: finalizes a shed-tainted image stays eligible to lift
/// its taint by binding. Covers slow-scan bind latency with margin (a
/// bursting browser child binds within ~2); images that never bind
/// keep today's permanent refusal.
pub(super) const TAINT_LIFT_GRACE: u64 = 16;

/// Unrouted calls shed before any binding existed: their distinct images,
/// lowest position and route labels. They are disclosed and counted
/// when shed, and their positions are provisionally disposed (no bound key
/// can seal before a binding). The first finalize that sees a binding keeps
/// them disposed when every cookie proves another caller, and otherwise
/// (any match, overflow, or a stop before any binding) barriers at the
/// lowest held position. Bounded by distinct images.
pub(in crate::discovery::engine::inventory_coordinator) struct PreBindingHold {
    pub(super) images: BTreeSet<(u64, u64)>,
    pub(super) min: u64,
    pub(super) labels: Vec<(&'static str, u64)>,
    pub(super) pid: Option<Option<u32>>,
    pub(super) limit: usize,
}

impl PreBindingHold {
    fn new() -> Self {
        Self {
            images: BTreeSet::new(),
            min: u64::MAX,
            labels: Vec::new(),
            pid: None,
            // The capture-wide waiting-call queue: held calls are calls
            // still waiting for a caller proof.
            limit: crate::discovery::instances::MAX_PENDING,
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// Hold one positioned call. Refuses (holding nothing) when a new
    /// image would pass the limit.
    pub(super) fn hold(
        &mut self,
        image: (u64, u64),
        position: u64,
        label: &'static str,
        pid: u32,
    ) -> bool {
        if !self.images.contains(&image) {
            if self.images.len() >= self.limit {
                return false;
            }
            self.images.insert(image);
        }
        self.min = self.min.min(position);
        match self.labels.iter_mut().find(|(known, _)| *known == label) {
            Some((_, count)) => *count += 1,
            None => self.labels.push((label, 1)),
        }
        self.pid = match self.pid {
            None => Some(Some(pid)),
            Some(Some(seen)) if seen == pid => Some(Some(pid)),
            Some(_) => Some(None),
        };
        true
    }

    /// Take everything held, keeping the limit.
    pub(super) fn take(&mut self) -> Self {
        let limit = self.limit;
        let mut taken = std::mem::replace(self, Self::new());
        self.limit = limit;
        taken.limit = limit;
        taken
    }
}

impl SessionFinalizerState {
    pub(super) fn permits_joint_preparation(&self, producers: &SessionDrainProducers) -> bool {
        self.domain == producers.native_domain()
            && self
                .producers
                .as_ref()
                .is_none_or(|held| held.same_producers(producers))
            && matches!(
                self.pending_semantic,
                Some(PendingSemanticBatch::Collected(_))
            )
            && self.h3_pending.is_none()
    }

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
            pending_drop_shed: BTreeMap::new(),
            seal_admission: None,
            reload_not_excluded: BTreeMap::new(),
            reload_shed: 0,
            continued_across_global: 0,
            joined_across_global: 0,
            pre_binding: PreBindingHold::new(),
            bound_once: false,
            taint_lift: BTreeMap::new(),
            finalize_seq: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn reference_pre_binding_limit(&mut self, limit: usize) {
        self.pre_binding.limit = limit.min(crate::discovery::instances::MAX_PENDING);
    }

    /// Stage one batch's disclosure quadrant into the namespace
    /// ledger: the first disclosure per identity wins, and the count
    /// snapshots take the maximum. The batch's carried upstream shed
    /// joins the same cumulative counter, so every disclosure drop
    /// in the capture lands under one counter. Called for every
    /// same-domain staged batch, including backpressure drops, so a
    /// drained-once disclosure is never silently lost: ledgered, or
    /// shed past a cap with a counted return the stager discloses as
    /// a named gap. Refused and foreign batches drop theirs with the
    /// batch at the namespace boundary. Returns shed identities.
    pub(super) fn accumulate_reload_disclosures(
        &mut self,
        disclosures: Vec<crate::semantic_capture::ReloadNotExcludedReport>,
        continued_across_global: u64,
        joined_across_global: u64,
        carried_shed: u32,
    ) -> u64 {
        const MAX: usize = crate::discovery::instances::MAX_INSTANCES;
        let mut shed = u64::from(carried_shed);
        for disclosure in disclosures {
            let key = (
                disclosure.image.task_cookie,
                disclosure.image.exec_id,
                disclosure.file_slot,
            );
            if self.reload_not_excluded.contains_key(&key) {
                continue;
            }
            if self.reload_not_excluded.len() >= MAX {
                shed = shed.saturating_add(1);
                continue;
            }
            self.reload_not_excluded.insert(
                key,
                (
                    disclosure.file_slot,
                    disclosure.ids.iter().map(|id| id.get()).collect(),
                ),
            );
        }
        self.reload_shed = self.reload_shed.saturating_add(shed);
        self.continued_across_global = self.continued_across_global.max(continued_across_global);
        self.joined_across_global = self.joined_across_global.max(joined_across_global);
        shed
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

/// Negative-only ingress from this same canonical coordinator/finalizer.
/// An empty disposition never supplies a positive admission or genesis H3.
pub(crate) struct SessionDisposedAuditInput<'session> {
    disposed: crate::semantics_objects::journal::joint_driver::RawDisposition,
    owner: &'session mut crate::semantics_objects::journal::joint_driver::JointCaptureOwner,
    finalizer: SessionH3Finalizer<'session>,
    producers: &'session SessionDrainProducers,
}
impl<'session> SessionDisposedAuditInput<'session> {
    pub(crate) fn into_parts(
        self,
    ) -> (
        crate::semantics_objects::journal::joint_driver::RawDisposition,
        &'session mut crate::semantics_objects::journal::joint_driver::JointCaptureOwner,
        SessionH3Finalizer<'session>,
        &'session SessionDrainProducers,
    ) {
        (self.disposed, self.owner, self.finalizer, self.producers)
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
        self.ready_for_negative_audit(producers) && self.state.seal_admission.is_some()
    }

    pub(crate) fn ready_for_negative_audit(&self, producers: &SessionDrainProducers) -> bool {
        self.producers.same_producers(producers)
            && self.state.domain == producers.native_domain()
            && self
                .state
                .producers
                .as_ref()
                .is_none_or(|held| held.same_producers(producers))
            && self.state.pending_semantic.is_none()
            && self.state.pending_drop.is_none()
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

    /// Take the H3 disposition an ingested quantum's refused audit left
    /// untaken, exactly as that audit would have taken it (one take per
    /// audit, `JournalAuditReceipt::collect`). The running re-arm at the
    /// audit step then holds the same finalizer state an Audited re-arm
    /// leaves when it drops its audited frame; without this take every
    /// later preparation refuses (`h3_pending` gates it). The evidence
    /// carries positions, not calls: every call of the quantum is
    /// counted through its staged registry facts and the next collect's
    /// unlocalized void. Only the retained Session's own producers take
    /// it; returns whether a disposition was taken.
    pub(crate) fn take_unaudited_joint_h3(&mut self, producers: &SessionDrainProducers) -> bool {
        let Some(state) = self.semantic_finalizer.as_mut() else {
            return false;
        };
        if state.domain != producers.native_domain()
            || state.h3_pending.is_none()
            || state
                .producers
                .as_ref()
                .is_some_and(|held| !held.same_producers(producers))
        {
            return false;
        }
        let mut finalizer = SessionH3Finalizer { state, producers };
        // The taken evidence is discarded, as an Audited re-arm discards
        // its frame's audit receipt.
        let _taken = crate::semantics_objects::journal::H3EvidenceSource::take_h3_disposition(
            &mut finalizer,
        );
        true
    }

    #[cfg_attr(not(test), allow(dead_code))] // The actual Session machine consumes this staged negative port later.
    #[allow(clippy::result_large_err)] // Preserve the same original negative buffers on refusal.
    pub(crate) fn audit_disposed_quantum(
        &mut self,
        disposed: crate::semantics_objects::journal::joint_driver::RawDisposition,
        producers: &SessionDrainProducers,
        attachment: &crate::attach::AttachedSemanticSet,
        fault: &impl crate::semantics_objects::journal::FaultEpoch,
    ) -> crate::semantics_objects::journal::joint_audit::DisposedAuditAcquisition {
        use crate::semantics_objects::journal::joint_driver::RawQuantumRefusal;
        if let Err(reason) = disposed.validate_owner(self.joint_capture.adapter(), producers) {
            return Err((disposed, reason));
        }
        let Some(state) = self.semantic_finalizer.as_mut() else {
            return Err((disposed, RawQuantumRefusal::H3Undisposed));
        };
        if state.domain != producers.native_domain()
            || state
                .producers
                .as_ref()
                .is_some_and(|held| !held.same_producers(producers))
        {
            return Err((disposed, RawQuantumRefusal::ForeignCapture));
        }
        let authorized = SessionDisposedAuditInput {
            disposed,
            owner: &mut self.joint_capture,
            finalizer: SessionH3Finalizer { state, producers },
            producers,
        };
        crate::semantics_objects::journal::joint_audit::IngestedJointQuantum::audit_disposed(
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

    #[cfg(test)]
    pub(crate) fn reference_h3_last_disposition(
        &self,
    ) -> Option<crate::semantics_objects::journal::H3DispositionEvidence> {
        self.semantic_finalizer
            .as_ref()
            .map(|state| state.h3_last.clone())
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
