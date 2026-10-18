//! SPDX-License-Identifier: GPL-3.0-or-later
//! DR37 promotion requests: immutable actual-view requests over the real
//! presentation, the one-slot UI mailbox and the display snapshot.
//!
//! The dashboard builds an immutable [`PromotionView`] from the exact
//! displayed frame `Arc` plus capture/view serials; [`Promoter::request`]
//! verifies the selected caller/provider pair occurs in that immutable
//! view, then the pure-std [`PromotionControl`] child issues the request
//! serial, holds the one pending slot and runs the visible state
//! machine. Nothing here grants semantic or native authority: UI values
//! are expected identities the runtime owner re-validates, never proof.
//! `Active` is reported only when the runtime supplies a genuine
//! activation result through a status update.
//!
//! Driver integration (runtime owner; staged): the sole driver enables
//! the control once per run, polls the mailbox between normal capture
//! work and reports outcomes back:
//!
//! ```text
//! Display::promotion_enable(capture) -> bool       // once per run
//! Display::take_promotion_request() -> Option<PromotionRequest>  // at most one
//! Display::set_promotion_status(update) -> Option<PromotionState> // validated
//! Display::promotion_state() -> PromotionState     // poll for UI cancel/stop
//! ```
//!
//! An accepted status update consumes the mailbox. Stale, foreign or
//! illegal updates return `None` with state unchanged. The driver must
//! record each terminal transition it observes in the normal bounded
//! event/report path; the screen status alone is not that record.

mod state;

pub(crate) use state::{
    CaptureId, PromotionCancel, PromotionControl, PromotionNote, PromotionPair, PromotionRefusal,
    PromotionState, PromotionStatusUpdate, RequestId, ViewRevision,
};
// STAGED (DR37): named by tests today; the runtime owner names them from taken requests.
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use state::{PromotionEnd, PromotionOutcome};

use crate::discovery::caller_registry::{CallerId, ModuleId};
use crate::inventory_present::Presentation;
use std::sync::Arc;

/// The exact published frame actually viewed, immutably paired with the
/// capture and view serials. The `Arc` retains the viewed caller and
/// physical provider identity without cloning strings or retaining
/// target FDs in the UI.
pub(crate) struct PromotionView {
    capture: CaptureId,
    revision: ViewRevision,
    presentation: Arc<Presentation>,
}

impl PromotionView {
    pub(crate) fn new(
        capture: CaptureId,
        revision: ViewRevision,
        presentation: Arc<Presentation>,
    ) -> Self {
        Self {
            capture,
            revision,
            presentation,
        }
    }

    /// Whether the exact pair occurs in the immutable viewed frame.
    fn contains(&self, caller: CallerId, provider: ModuleId) -> bool {
        self.presentation
            .edges
            .iter()
            .any(|edge| edge.caller == caller && edge.module == provider)
    }
}

impl std::fmt::Debug for PromotionView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromotionView")
            .field("capture", &self.capture)
            .field("revision", &self.revision)
            .field("edges", &self.presentation.edges.len())
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): read by the runtime owner from taken requests.
impl PromotionView {
    pub(crate) fn capture(&self) -> CaptureId {
        self.capture
    }

    pub(crate) fn revision(&self) -> ViewRevision {
        self.revision
    }

    pub(crate) fn presentation(&self) -> &Arc<Presentation> {
        &self.presentation
    }
}

/// An immutable promotion request: the request serial, the retained
/// viewed frame and the exact caller/provider pair. The runtime treats
/// these values as expected identities only.
#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): constructed by take_request for the runtime owner; the take path is staged.
pub(crate) struct PromotionRequest {
    id: RequestId,
    viewed: Arc<PromotionView>,
    caller: CallerId,
    provider: ModuleId,
}

impl std::fmt::Debug for PromotionRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromotionRequest")
            .field("id", &self.id)
            .field("viewed", &self.viewed)
            .field("caller", &self.caller)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): read by the runtime owner from taken requests.
impl PromotionRequest {
    pub(crate) fn id(&self) -> RequestId {
        self.id
    }

    pub(crate) fn viewed(&self) -> &Arc<PromotionView> {
        &self.viewed
    }

    pub(crate) fn caller(&self) -> CallerId {
        self.caller
    }

    pub(crate) fn provider(&self) -> ModuleId {
        self.provider
    }

    /// Build a capture-qualified status update from this exact held
    /// request. The runtime calls this on the request it owns; it
    /// never substitutes a global last request.
    pub(crate) fn status_update(&self, outcome: PromotionOutcome) -> PromotionStatusUpdate {
        PromotionStatusUpdate::new(self.viewed.capture, self.id, outcome)
    }
}

/// Why [`Promoter::request`] failed without queueing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionRequestError {
    /// The control refused the request (busy, duplicate, exhausted…).
    Refused(PromotionRefusal),
    /// The pair is not in the bound immutable view: the selection raced
    /// a redraw and must be cleared, never replaced.
    PairNotInView,
    /// The view names a capture other than the bound one. Unreachable
    /// via the UI (the display builds the view with the bound capture);
    /// kept as defense, never silently accepted.
    ForeignCapture,
}

/// UI-side promoter: verifies exact pairs against the immutable viewed
/// presentation, then delegates serials, the one-slot mailbox and the
/// visible state to the pure-std core. Single-threaded: the sole driver
/// polls it between normal capture work.
#[derive(Debug)]
pub(crate) struct Promoter {
    control: PromotionControl,
    /// Mailbox payload for the outstanding ticket: the retained viewed
    /// `Arc` plus the exact IDs. One slot, overwritten by the next
    /// accepted request.
    pending: Option<PendingPromotion>,
}

#[derive(Debug)]
#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): payload is read by take_request for the runtime owner.
struct PendingPromotion {
    viewed: Arc<PromotionView>,
    caller: CallerId,
    provider: ModuleId,
    id: RequestId,
}

impl Promoter {
    pub(crate) fn new() -> Self {
        Self {
            control: PromotionControl::new(),
            pending: None,
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.control.enabled()
    }

    /// The bound capture, if enabled.
    pub(crate) fn capture(&self) -> Option<CaptureId> {
        self.control.capture()
    }

    /// Verify the exact pair occurs in the immutable viewed frame, then
    /// queue the request. A pair outside the view is never queued and
    /// never replaced by another row.
    pub(crate) fn request(
        &mut self,
        viewed: Arc<PromotionView>,
        caller: CallerId,
        provider: ModuleId,
    ) -> Result<RequestId, PromotionRequestError> {
        if Some(viewed.capture) != self.control.capture() {
            return Err(PromotionRequestError::ForeignCapture);
        }
        if !viewed.contains(caller, provider) {
            return Err(PromotionRequestError::PairNotInView);
        }
        let pair = PromotionPair::new(caller.0, provider.0);
        let id = self
            .control
            .request(viewed.revision, pair)
            .map_err(PromotionRequestError::Refused)?;
        self.pending = Some(PendingPromotion {
            viewed,
            caller,
            provider,
            id,
        });
        Ok(id)
    }

    /// Operator cancel; see [`PromotionControl::cancel`].
    pub(crate) fn cancel(&mut self) -> PromotionCancel {
        self.control.cancel()
    }

    /// The run stopped; see [`PromotionControl::note_run_stopped`].
    pub(crate) fn note_run_stopped(&mut self) -> bool {
        self.control.note_run_stopped()
    }

    pub(crate) fn set_note(&mut self, note: Option<PromotionNote>) {
        self.control.set_note(note);
    }

    /// Copy the display snapshot, preserving the caller's cursor
    /// selection. The display syncs this before every draw so control
    /// status survives latest-frame coalescing.
    pub(crate) fn snapshot(&self, selected: Option<PromotionPair>) -> PromotionUi {
        let ticket = self.control.outstanding();
        PromotionUi {
            enabled: self.control.enabled(),
            selected,
            state: self.control.state(),
            pair: ticket.map(|ticket| ticket.pair),
            request: ticket.map(|ticket| ticket.id),
            view: ticket.map(|ticket| ticket.view),
            note: self.control.note(),
        }
    }
}

impl Default for Promoter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): the runtime owner drives enable/take/set_status/state; the UI key paths run today.
impl Promoter {
    /// Bind the control to one capture run; see
    /// [`PromotionControl::enable`].
    pub(crate) fn enable(&mut self, capture: CaptureId) -> bool {
        self.control.enable(capture)
    }

    /// Yield the pending request at most once; see
    /// [`PromotionControl::take_ticket`].
    pub(crate) fn take_request(&mut self) -> Option<PromotionRequest> {
        let ticket = self.control.take_ticket()?;
        let pending = self.pending.as_ref()?;
        if pending.id != ticket.id {
            return None;
        }
        Some(PromotionRequest {
            id: ticket.id,
            viewed: Arc::clone(&pending.viewed),
            caller: pending.caller,
            provider: pending.provider,
        })
    }

    /// Apply a runtime outcome; see [`PromotionControl::set_status`].
    pub(crate) fn set_status(&mut self, update: PromotionStatusUpdate) -> Option<PromotionState> {
        self.control.set_status(update)
    }

    pub(crate) fn state(&self) -> PromotionState {
        self.control.state()
    }
}

/// Copyable UI snapshot synced from the control before each draw: the
/// cursor selection, the control state, the current (or last terminal)
/// request serials and the sticky key note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PromotionUi {
    pub enabled: bool,
    pub selected: Option<PromotionPair>,
    pub state: PromotionState,
    pub pair: Option<PromotionPair>,
    pub request: Option<RequestId>,
    pub view: Option<ViewRevision>,
    pub note: Option<PromotionNote>,
}

impl PromotionUi {
    /// Disabled: renders nothing, tracks nothing. Default dashboard
    /// behavior until the runtime/CLI enables the control.
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            selected: None,
            state: PromotionState::Idle,
            pair: None,
            request: None,
            view: None,
            note: None,
        }
    }

    /// The plain status line, or `None` when disabled. Static words plus
    /// stable numeric IDs only (`c{caller}/m{provider}` are display IDs
    /// minted by the observer, never target-controlled bytes), so the
    /// line needs no escaping and carries no ANSI.
    pub(crate) fn status_line(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let pair_words = |pair: PromotionPair| format!("c{}/m{}", pair.caller(), pair.provider());
        // The snapshot fills request/pair/view together from one ticket,
        // so the fallbacks below are unreachable defense, never guesses.
        let id = self.request.map_or(0, RequestId::get);
        let viewed = self.view.map_or(0, ViewRevision::get);
        let on = self.pair.map_or_else(|| "c?/m?".to_string(), pair_words);
        let mut line = match self.state {
            PromotionState::Idle => match self.selected {
                Some(selected) => {
                    format!("promotion: idle; selected {}", pair_words(selected))
                }
                None => "promotion: idle; no pair selected".to_string(),
            },
            PromotionState::Queued => {
                format!("promotion: request {id} queued for {on} (view {viewed})")
            }
            PromotionState::Preparing => {
                format!("promotion: request {id} preparing {on}")
            }
            PromotionState::Validating => {
                format!("promotion: request {id} validating {on}")
            }
            PromotionState::Active => {
                format!("promotion: request {id} active: detailed capture on {on}")
            }
            PromotionState::Refused(reason) => {
                format!(
                    "promotion: request {id} refused for {on}: {}",
                    reason.label()
                )
            }
            PromotionState::Stopping => {
                format!("promotion: request {id} cancelling {on}")
            }
            PromotionState::Ended(reason) => {
                format!("promotion: request {id} ended for {on}: {}", reason.label())
            }
        };
        if let Some(note) = self.note {
            line.push_str("; last key: ");
            line.push_str(note.label());
        }
        Some(line)
    }
}
