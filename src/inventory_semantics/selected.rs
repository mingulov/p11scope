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
}

impl ProvisionalSelectedLane {
    pub(crate) fn from_closed_native(
        session: Session,
        attached: AttachedSemanticSet,
        permit: SelectedConstructionPermit,
        convert_subset: AttestedSubset,
    ) -> Result<Self, SelectedPreparationFailure> {
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
        Ok(Self { lane, permit })
    }

    pub(crate) fn identity(&self) -> &SelectedSessionIdentity {
        self.permit.identity()
    }
}

impl std::fmt::Debug for ProvisionalSelectedLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProvisionalSelectedLane(<retained>)")
    }
}
