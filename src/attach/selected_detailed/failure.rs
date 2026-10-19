//! SPDX-License-Identifier: GPL-3.0-or-later
//! Failed preparation retains its original native cleanup owner.
use super::super::Session;
use crate::inventory_semantics::SemanticRefusal;

/// Only the actual joined receipt permits reuse. Pending and Unproved retain
/// their Session; neither empty link collections nor Drop prove settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedCleanupStatus {
    Pending,
    Settled,
    Unproved,
}

pub(crate) struct SelectedPreparationFailure {
    session: Option<Session>,
    reason: SemanticRefusal,
    diagnostic: anyhow::Error,
    status: SelectedCleanupStatus,
}
impl SelectedPreparationFailure {
    /// Called only before the first producer exists, after the failed local
    /// preparation has returned and its unlinked loader resources have closed.
    pub(super) fn before_links(diagnostic: anyhow::Error) -> Self {
        Self {
            session: None,
            reason: SemanticRefusal::Attachment,
            diagnostic,
            status: SelectedCleanupStatus::Settled,
        }
    }

    pub(super) fn retaining(session: Session, diagnostic: anyhow::Error) -> Self {
        Self {
            session: Some(session),
            reason: SemanticRefusal::Attachment,
            diagnostic,
            status: SelectedCleanupStatus::Pending,
        }
    }

    /// Failure-only custody handoff from the concrete sealed runtime factory.
    /// This cannot extract Session, construct a usable lane, or activate it.
    pub(crate) fn from_factory_rejection(session: Session, reason: SemanticRefusal) -> Self {
        Self {
            session: Some(session),
            reason,
            diagnostic: anyhow::anyhow!("selected provisional construction refused: {reason}"),
            status: SelectedCleanupStatus::Pending,
        }
    }

    /// Tests-only settled failure: the exact pre-producer state
    /// (`before_links`: no Session, cleanup already settled), so the
    /// DR37 service's disposal polling and terminal statuses run
    /// without native maps. Production failures always retain or
    /// settle real owners.
    #[cfg(test)]
    pub(crate) fn scripted_settled() -> Self {
        Self::before_links(anyhow::anyhow!("scripted pre-link preparation failure"))
    }

    /// Tests-only unproved failure: cleanup that proved nothing, so
    /// the DR37 service's process-lifetime retention runs without
    /// native maps. Production unproved owners always retain real
    /// Sessions.
    #[cfg(test)]
    pub(crate) fn scripted_unproved() -> Self {
        Self {
            session: None,
            reason: SemanticRefusal::Attachment,
            diagnostic: anyhow::anyhow!("scripted unproved preparation failure"),
            status: SelectedCleanupStatus::Unproved,
        }
    }

    pub(crate) fn semantic_refusal(&self) -> SemanticRefusal {
        self.reason
    }

    pub(crate) fn cleanup_status(&self) -> SelectedCleanupStatus {
        self.status
    }

    pub(super) fn requires_backend_fallback(&self) -> bool {
        self.diagnostic
            .downcast_ref::<super::super::BackendFallbackRequired>()
            .is_some()
    }

    /// Poll without consuming or abandoning the original cleanup worker. A
    /// ready worker is joined once; no second-signal predicate is used as a
    /// substitute for readiness. Unproved remains owned and cannot be retried.
    pub(crate) fn poll_cleanup(&mut self, out: &mut dyn std::io::Write) -> SelectedCleanupStatus {
        if self.status != SelectedCleanupStatus::Pending {
            return self.status;
        }
        let session = self
            .session
            .as_mut()
            .expect("pending cleanup retains Session");
        if let Err(error) = session.begin_owned_producer_detach() {
            self.diagnostic = anyhow::anyhow!(
                "selected cleanup submission: {error:#}; preparation: {:#}",
                self.diagnostic
            );
            self.status = SelectedCleanupStatus::Unproved;
            return self.status;
        }
        let ready = session.producer_detach.ready_to_finish();
        if !ready {
            return SelectedCleanupStatus::Pending;
        }
        match session.finish_owned_producer_detach_driven(|| false, out) {
            Ok(()) => {
                self.status = SelectedCleanupStatus::Settled;
                // Joined native owners have closed. Only now release the
                // remaining maps, targets and query descriptors together.
                drop(self.session.take());
            }
            Err(error) => {
                self.diagnostic = anyhow::anyhow!(
                    "selected cleanup settlement: {error:#}; preparation: {:#}",
                    self.diagnostic
                );
                self.status = SelectedCleanupStatus::Unproved;
            }
        }
        self.status
    }
}
impl std::fmt::Debug for SelectedPreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedPreparationFailure")
            .field("reason", &self.reason)
            .field("cleanup", &self.status)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for SelectedPreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (cleanup {:?})", self.reason, self.status)
    }
}
impl std::error::Error for SelectedPreparationFailure {}
