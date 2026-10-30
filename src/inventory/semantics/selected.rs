//! SPDX-License-Identifier: GPL-3.0-or-later
//! The selected native owner stays private through admission and activation.

use super::*;
use crate::attach::selected_detailed::{
    SelectedConstructionPermit, SelectedPreparationFailure, SelectedSessionIdentity,
};

/// Only the concrete native conversion can supply the move-only construction
/// permit. No raw Session, H0, current receipt or registration escapes this owner.
pub(crate) struct ProvisionalSelectedLane {
    lane: AttestedSemanticLane,
    permit: SelectedConstructionPermit,
    /// Disposal in flight (DR37): the first `poll_dispose` moves the
    /// live Session into a real failure owner and polls the exact
    /// joined-cleanup path. `Some` forbids installation: a lane that
    /// started disposal never installs, and vice versa.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): read by the lifecycle service.
    disposing: Option<SelectedPreparationFailure>,
}

impl ProvisionalSelectedLane {
    #[allow(clippy::result_large_err)] // Cold conversion: the failure retains the native owner for joined cleanup.
    pub(crate) fn from_closed_native(
        session: Session,
        attached: AttachedSemanticSet,
        permit: SelectedConstructionPermit,
        convert_subset: AttestedSubset,
    ) -> Result<Self, SelectedPreparationFailure> {
        if convert_subset.required().len() != 1 {
            return Err(SelectedPreparationFailure::from_factory_rejection(
                session,
                SemanticRefusal::IncompleteProvider,
            ));
        }
        if permit
            .validate_conversion(&session, &attached, &convert_subset)
            .is_err()
        {
            return Err(SelectedPreparationFailure::from_factory_rejection(
                session,
                SemanticRefusal::Attachment,
            ));
        }
        let lane = match AttestedSemanticLane::from_live_owner(session, attached, convert_subset) {
            Ok(lane) => lane,
            Err((session, reason)) => {
                return Err(SelectedPreparationFailure::from_factory_rejection(
                    session, reason,
                ));
            }
        };
        Ok(Self {
            lane,
            permit,
            disposing: None,
        })
    }

    #[allow(dead_code)] // STAGED: sealed-lane identity accessor for the lifecycle service, like its siblings; no test covers it yet.
    pub(crate) fn identity(&self) -> &SelectedSessionIdentity {
        self.permit.identity()
    }

    /// The activation binding this sealed lane carries (D3/D10): the
    /// permit's exact domain, generation and image. The CAS receipt
    /// and the install entry match against this; values only, never
    /// authority.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the lifecycle service.
    pub(crate) fn activation_binding(
        &self,
    ) -> crate::inventory_promotion::lifecycle::SelectedActivationBinding {
        crate::inventory_promotion::lifecycle::SelectedActivationBinding::of_permit(&self.permit)
    }

    /// The sealed live Session for the native activation CAS only.
    /// Borrowed, never moved: the CAS runs against this owner.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the lifecycle service.
    pub(crate) fn live_session(&self) -> Option<&Session> {
        self.lane.live.as_ref().map(|live| &live.session)
    }

    /// The sealed conversion envelope this lane was converted with:
    /// the prepared child's provider/endpoint coverage. The detail
    /// gate binds its reservation against this envelope (plus the
    /// sealed original and baseline below), never against
    /// caller-supplied values.
    pub(crate) fn convert_subset(&self) -> &AttestedSubset {
        self.lane.subset()
    }

    /// The sealed original custody this lane was prepared with.
    pub(crate) fn original(&self) -> &std::sync::Arc<crate::process::PidPin> {
        self.permit.original()
    }

    /// The sealed pre-view baseline this lane was prepared with.
    pub(crate) fn baseline(
        &self,
    ) -> &crate::attach::selected_detailed::baseline::PromotionImageBaseline {
        self.permit.baseline()
    }

    /// Poll joined disposal of a lane that must never install
    /// (cancelled, or CAS/mint/install refused). The first poll moves
    /// the live Session into a real failure owner; every poll runs
    /// the exact `SelectedPreparationFailure` joined-cleanup path, so
    /// a settled receipt here proves as much as a settled
    /// preparation failure. Never fabricates settlement.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the lifecycle service.
    pub(crate) fn poll_dispose(
        &mut self,
        out: &mut dyn std::io::Write,
    ) -> crate::attach::selected_detailed::SelectedCleanupStatus {
        if self.disposing.is_none() {
            let Some(live) = self.lane.live.take() else {
                // No live owner and no disposal running: nothing to
                // dispose (defense; the service disposes once).
                return crate::attach::selected_detailed::SelectedCleanupStatus::Settled;
            };
            // Only the Session needs joined disposal; the H0 driver,
            // attachment receipt and stash above are memory-only and
            // drop with the remaining live shell here.
            self.disposing = Some(SelectedPreparationFailure::from_factory_rejection(
                live.session,
                SemanticRefusal::Unavailable,
            ));
        }
        self.disposing
            .as_mut()
            .expect("disposal owner just installed")
            .poll_cleanup(out)
    }

    /// Tests-only sealed lane over a unit-test lane shell plus a
    /// scripted permit: the proof binding reads off the permit, so a
    /// proof minted over the same binding genuinely authorizes this
    /// lane. No live Session (disposal settles vacuously through the
    /// real `poll_dispose` path). Reclaim-path scenes only (I4): the
    /// lane must dispose, never install.
    #[cfg(test)]
    pub(crate) fn scripted_for_test(
        lane: AttestedSemanticLane,
        permit: crate::attach::selected_detailed::SelectedConstructionPermit,
    ) -> Self {
        Self {
            lane,
            permit,
            disposing: None,
        }
    }

    /// Consume the sealed lane into a live lane for coordinator
    /// install, gated on the activation proof naming exactly this
    /// lane's binding. A mismatched proof (or a lane that started
    /// disposal) returns the lane uninstalled for genuine disposal;
    /// nothing half-installs.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): called by the lifecycle service.
    #[allow(clippy::result_large_err)] // DR37: cold path returning the refused lane for genuine disposal.
    pub(crate) fn into_live_lane(
        self,
        proof: &crate::inventory_promotion::lifecycle::SelectedActivationProof,
    ) -> Result<AttestedSemanticLane, Self> {
        if self.disposing.is_some() || !proof.matches_lane(self.activation_binding()) {
            return Err(self);
        }
        Ok(self.lane)
    }
}

impl std::fmt::Debug for ProvisionalSelectedLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvisionalSelectedLane(<retained>)")
    }
}
