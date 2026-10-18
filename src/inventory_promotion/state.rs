//! SPDX-License-Identifier: GPL-3.0-or-later
//! DR37 promotion request/state core: the pure-std UI-side control.
//!
//! No crate dependencies: the request/state seam iterates standalone
//! (`rustc +1.98.1 --test` on this file). The outer promotion module
//! binds these serials to the real `Presentation` and caller/module
//! IDs; this core only orders serials, a one-slot mailbox and the
//! visible state machine. Nothing here grants semantic or native
//! authority — values are expected identities for the runtime owner
//! to re-validate, never proof.

/// Opaque Inventory-run identity, minted by the runtime owner once per
/// run and bound at enable time. Requests stamp it; the runtime rejects
/// replays naming a foreign capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct CaptureId(u64);

#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): runtime enables the per-run capture identity.
impl CaptureId {
    pub(crate) fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

/// Displayed-frame serial, minted by the display at frame-install time
/// (each frame actually viewed gets a unique revision). The request
/// binds the viewed revision, never a redrawn row index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ViewRevision(u64);

impl ViewRevision {
    pub(crate) fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

/// Per-run request serial, minted by this control. Serial 0 is never
/// issued; [`RequestId::EXHAUSTED`] is never issued either and marks
/// the exhausted counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct RequestId(u64);

impl RequestId {
    /// Reserved marker: the counter reached it, so no further request
    /// can take a serial. Compared, never issued.
    pub(crate) const EXHAUSTED: u64 = u64::MAX;

    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): runtime constructs status request IDs.
    pub(crate) fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(crate) fn get(self) -> u64 {
        self.0
    }
}

/// The exact caller/provider pair selected on screen, as raw display
/// IDs (`c{caller}/m{provider}`). Display data, not authority: the
/// runtime re-resolves both against live state before doing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PromotionPair {
    caller: u32,
    provider: u32,
}

impl PromotionPair {
    pub(crate) fn new(caller: u32, provider: u32) -> Self {
        Self { caller, provider }
    }

    pub(crate) fn caller(self) -> u32 {
        self.caller
    }

    pub(crate) fn provider(self) -> u32 {
        self.provider
    }
}

/// Why a promotion request was refused. The UI-side variants are
/// produced by [`PromotionControl::request`]; the runtime-side variants
/// arrive through status updates once the runtime owner integrates.
/// Every variant renders as plain static words plus numeric IDs only.
#[cfg_attr(not(test), allow(dead_code))]
// STAGED (DR37): runtime-side variants are constructed by the runtime owner via status updates; labels render today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionRefusal {
    /// The control was never enabled for this run.
    Disabled,
    /// Other promotion work is outstanding (a different pair, or the
    /// lane is winding down).
    Busy,
    /// The same pair is already requested and in flight.
    Duplicate,
    /// The same pair is already actively detailed.
    AlreadyDetailed,
    /// The per-run request serial counter is exhausted.
    Exhausted,
    /// The request names a foreign capture run.
    ForeignCapture,
    /// The bound view expired before preparation finished.
    StaleView,
    /// The caller is unknown to the live coordinator.
    UnknownCaller,
    /// The caller retired (exit, exec, reuse) before validation.
    CallerRetired,
    /// The caller's live identity no longer matches the expected one.
    CallerChanged,
    /// The mapped provider changed (inode, bytes, digest).
    ProviderChanged,
    /// The provider unloaded before validation.
    ProviderUnloaded,
    /// No retained manifest permission covers the pair.
    ManifestUnavailable,
    /// The selected endpoints are ambiguous.
    EndpointAmbiguous,
    /// The selection needs dependency endpoints outside the closure.
    EndpointDependency,
    /// The parent scope ended before activation.
    ScopeEnded,
    /// Preparation failed.
    PreparationFailed,
    /// Activation failed.
    ActivationFailed,
}

impl PromotionRefusal {
    /// Plain static words for the status line (ASCII, no escapes).
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Disabled => "control disabled",
            Self::Busy => "another promotion is outstanding",
            Self::Duplicate => "same pair already requested",
            Self::AlreadyDetailed => "pair already detailed",
            Self::Exhausted => "request serials exhausted",
            Self::ForeignCapture => "foreign capture",
            Self::StaleView => "view expired",
            Self::UnknownCaller => "unknown caller",
            Self::CallerRetired => "caller retired",
            Self::CallerChanged => "caller identity changed",
            Self::ProviderChanged => "provider changed",
            Self::ProviderUnloaded => "provider unloaded",
            Self::ManifestUnavailable => "no manifest permission",
            Self::EndpointAmbiguous => "ambiguous endpoints",
            Self::EndpointDependency => "dependency endpoints outside closure",
            Self::ScopeEnded => "parent scope ended",
            Self::PreparationFailed => "preparation failed",
            Self::ActivationFailed => "activation failed",
        }
    }
}

/// How a promotion lane ended (as distinct from refused).
#[cfg_attr(not(test), allow(dead_code))]
// STAGED (DR37): LaneClosed is reported by the runtime owner; Cancelled/RunStopped are produced here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionEnd {
    /// The operator cancelled the request.
    Cancelled,
    /// The run stopped with promotion work outstanding.
    RunStopped,
    /// The runtime closed an active lane (scope leave, exec, exit).
    LaneClosed,
}

impl PromotionEnd {
    /// Plain static words for the status line (ASCII, no escapes).
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled by operator",
            Self::RunStopped => "run stopped",
            Self::LaneClosed => "lane closed",
        }
    }
}

/// The visible promotion state machine. `Active` is reported only when
/// the runtime owner supplies a genuine activation result through a
/// status update — this control never self-activates.
#[cfg_attr(not(test), allow(dead_code))]
// STAGED (DR37): Preparing/Validating/Active/Refused/Ended are entered via runtime status updates; Queued/Stopping/Idle transitions run today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionState {
    /// Nothing requested (or the control is disabled).
    Idle,
    /// A request is accepted and awaits (or awaits acknowledgement of)
    /// runtime pickup.
    Queued,
    /// The runtime is preparing the selected lane.
    Preparing,
    /// The runtime is validating the selected pair.
    Validating,
    /// Detailed capture is armed for the pair (runtime-confirmed).
    Active,
    /// The request ended refused.
    Refused(PromotionRefusal),
    /// Cancellation was requested; the runtime confirms the end.
    Stopping,
    /// The request ended without refusal.
    Ended(PromotionEnd),
}

/// A runtime outcome for the outstanding request. Consumed by
/// [`PromotionControl::set_status`]; an accepted update consumes the
/// mailbox (the runtime evidently holds the request).
#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): constructed by the runtime owner; consumed by set_status today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionOutcome {
    Preparing,
    Validating,
    /// Activation is genuine only for the outstanding pair; a
    /// mismatched pair is rejected, never recorded.
    Active {
        pair: PromotionPair,
    },
    Refused {
        reason: PromotionRefusal,
    },
    Ended {
        reason: PromotionEnd,
    },
}

/// One runtime status update: the outcome plus the request serial it
/// answers. A serial that is not the outstanding one is stale/foreign
/// and ignored.
#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): constructed by the runtime owner; consumed by set_status today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PromotionStatusUpdate {
    pub(crate) request: RequestId,
    pub(crate) outcome: PromotionOutcome,
}

#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): runtime reports preparation and activation results.
impl PromotionStatusUpdate {
    pub(crate) fn new(request: RequestId, outcome: PromotionOutcome) -> Self {
        Self { request, outcome }
    }
}

/// The accepted request ticket held by the one-slot mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestTicket {
    pub(crate) id: RequestId,
    pub(crate) view: ViewRevision,
    pub(crate) pair: PromotionPair,
}

/// What an operator cancel did, honestly distinguished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionCancel {
    /// Nothing outstanding: no state changed.
    NothingToCancel,
    /// The pending request had not reached the runtime: dropped
    /// synchronously, lane ended cancelled.
    Cancelled,
    /// Work may have reached the runtime: cancellation requested, the
    /// runtime confirms the end.
    Stopping,
}

/// The last transient key outcome, kept in one bounded slot so it
/// survives frame coalescing until superseded by the next accepted
/// request, status update or key outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PromotionNote {
    Busy,
    Duplicate,
    AlreadyDetailed,
    Exhausted,
    NoSelection,
    StaleSelection,
    NothingToCancel,
}

impl PromotionNote {
    /// Map a request refusal to its sticky note, if it has one.
    /// Runtime-only and disabled refusals are unreachable from the key
    /// path and map to nothing.
    pub(crate) fn for_refusal(refusal: PromotionRefusal) -> Option<Self> {
        match refusal {
            PromotionRefusal::Busy => Some(Self::Busy),
            PromotionRefusal::Duplicate => Some(Self::Duplicate),
            PromotionRefusal::AlreadyDetailed => Some(Self::AlreadyDetailed),
            PromotionRefusal::Exhausted => Some(Self::Exhausted),
            _ => None,
        }
    }

    /// Plain static words for the status line (ASCII, no escapes).
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Duplicate => "duplicate of in-flight request",
            Self::AlreadyDetailed => "already detailed",
            Self::Exhausted => "request serials exhausted",
            Self::NoSelection => "no pair selected",
            Self::StaleSelection => "selection left the displayed view",
            Self::NothingToCancel => "nothing to cancel",
        }
    }
}

/// UI-side promotion control: enable gate, per-run serials, one pending
/// mailbox slot and the visible state machine. Single-threaded: the
/// sole driver polls it between normal capture work.
#[derive(Debug)]
pub(crate) struct PromotionControl {
    enabled: bool,
    capture: Option<CaptureId>,
    next_serial: u64,
    outstanding: Option<RequestTicket>,
    state: PromotionState,
    /// The mailbox slot was consumed (by `take_ticket` or by an
    /// accepted status update, which implies runtime custody).
    taken: bool,
    note: Option<PromotionNote>,
}

impl PromotionControl {
    /// Disabled, idle, serials from 1. The runtime/CLI enables the
    /// control explicitly per run; default behavior stays unchanged.
    pub(crate) fn new() -> Self {
        Self {
            enabled: false,
            capture: None,
            next_serial: 1,
            outstanding: None,
            state: PromotionState::Idle,
            taken: false,
            note: None,
        }
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    /// The bound capture, if enabled.
    pub(crate) fn capture(&self) -> Option<CaptureId> {
        self.capture
    }

    pub(crate) fn state(&self) -> PromotionState {
        self.state
    }

    /// The current (or, after a terminal transition, last) request
    /// ticket. Displayed, never re-issued.
    pub(crate) fn outstanding(&self) -> Option<RequestTicket> {
        self.outstanding
    }

    pub(crate) fn note(&self) -> Option<PromotionNote> {
        self.note
    }

    pub(crate) fn set_note(&mut self, note: Option<PromotionNote>) {
        self.note = note;
    }

    /// Accept a request for `pair` viewed at `view`. At most one
    /// request is outstanding: a second distinct request is [`Busy`](PromotionRefusal::Busy),
    /// a repeat of the in-flight pair is [`Duplicate`](PromotionRefusal::Duplicate),
    /// and a repeat of the active pair is [`AlreadyDetailed`](PromotionRefusal::AlreadyDetailed).
    /// Terminal states accept a fresh serial; the exhausted counter refuses.
    pub(crate) fn request(
        &mut self,
        view: ViewRevision,
        pair: PromotionPair,
    ) -> Result<RequestId, PromotionRefusal> {
        if !self.enabled {
            return Err(PromotionRefusal::Disabled);
        }
        let same_pair = self.outstanding.is_some_and(|ticket| ticket.pair == pair);
        match self.state {
            PromotionState::Active => {
                return Err(if same_pair {
                    PromotionRefusal::AlreadyDetailed
                } else {
                    PromotionRefusal::Busy
                });
            }
            PromotionState::Queued | PromotionState::Preparing | PromotionState::Validating => {
                return Err(if same_pair {
                    PromotionRefusal::Duplicate
                } else {
                    PromotionRefusal::Busy
                });
            }
            PromotionState::Stopping => return Err(PromotionRefusal::Busy),
            PromotionState::Idle | PromotionState::Refused(_) | PromotionState::Ended(_) => {}
        }
        if self.next_serial == RequestId::EXHAUSTED {
            return Err(PromotionRefusal::Exhausted);
        }
        let id = RequestId(self.next_serial);
        self.next_serial += 1;
        self.outstanding = Some(RequestTicket { id, view, pair });
        self.taken = false;
        self.state = PromotionState::Queued;
        self.note = None;
        Ok(id)
    }

    /// Operator cancel. A pending request the runtime never took is
    /// dropped synchronously; anything that may have reached the
    /// runtime (including an active lane) requests `Stopping` and waits
    /// for runtime confirmation. Never fabricates an end for work in
    /// runtime hands.
    pub(crate) fn cancel(&mut self) -> PromotionCancel {
        match self.state {
            PromotionState::Idle | PromotionState::Refused(_) | PromotionState::Ended(_) => {
                PromotionCancel::NothingToCancel
            }
            PromotionState::Stopping => PromotionCancel::Stopping,
            // An active lane is never synchronously ended from the UI:
            // the runtime winds it down and confirms.
            PromotionState::Active => {
                self.state = PromotionState::Stopping;
                PromotionCancel::Stopping
            }
            PromotionState::Queued | PromotionState::Preparing | PromotionState::Validating => {
                if self.taken {
                    self.state = PromotionState::Stopping;
                    PromotionCancel::Stopping
                } else {
                    self.taken = true;
                    self.state = PromotionState::Ended(PromotionEnd::Cancelled);
                    PromotionCancel::Cancelled
                }
            }
        }
    }

    /// The run stopped: outstanding work ends honestly as run-stopped
    /// without waiting for a runtime that is gone. Returns true when it
    /// ended outstanding work.
    pub(crate) fn note_run_stopped(&mut self) -> bool {
        match self.state {
            PromotionState::Idle | PromotionState::Refused(_) | PromotionState::Ended(_) => false,
            PromotionState::Queued
            | PromotionState::Preparing
            | PromotionState::Validating
            | PromotionState::Active
            | PromotionState::Stopping => {
                self.taken = true;
                self.state = PromotionState::Ended(PromotionEnd::RunStopped);
                true
            }
        }
    }

    /// Test seam: park the serial counter (exhaustion tests).
    #[cfg(test)]
    pub(crate) fn test_set_next_serial(&mut self, serial: u64) {
        self.next_serial = serial;
    }
}

#[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): the runtime owner drives enable/take/set_status; the UI key paths run today.
impl PromotionControl {
    /// Bind the control to one capture run. Idempotent for the same
    /// capture; a different capture never silently rebinds.
    pub(crate) fn enable(&mut self, capture: CaptureId) -> bool {
        if !self.enabled {
            self.enabled = true;
            self.capture = Some(capture);
            return true;
        }
        self.capture == Some(capture)
    }

    /// Yield the pending request ticket at most once. A second take
    /// (or a take after the runtime already reported on the request)
    /// yields nothing and never duplicates custody.
    pub(crate) fn take_ticket(&mut self) -> Option<RequestTicket> {
        if self.taken {
            return None;
        }
        match self.state {
            PromotionState::Queued => {
                self.taken = true;
                self.outstanding
            }
            _ => None,
        }
    }

    /// Apply a runtime outcome. Accepted only for the outstanding
    /// serial in a non-terminal state, along legal transitions: no
    /// activation (or further preparation) once stopping was
    /// requested, no refusal after activation, and an activation pair
    /// must match the requested pair. Returns the new state, or `None`
    /// for a stale/foreign/illegal update (state unchanged).
    pub(crate) fn set_status(&mut self, update: PromotionStatusUpdate) -> Option<PromotionState> {
        let outstanding = self.outstanding?;
        if outstanding.id != update.request {
            return None;
        }
        let next = match (self.state, update.outcome) {
            (PromotionState::Queued, PromotionOutcome::Preparing) => PromotionState::Preparing,
            (PromotionState::Queued, PromotionOutcome::Validating) => PromotionState::Validating,
            (PromotionState::Preparing, PromotionOutcome::Preparing) => PromotionState::Preparing,
            (PromotionState::Preparing, PromotionOutcome::Validating) => PromotionState::Validating,
            (PromotionState::Validating, PromotionOutcome::Validating) => {
                PromotionState::Validating
            }
            (
                PromotionState::Queued | PromotionState::Preparing | PromotionState::Validating,
                PromotionOutcome::Active { pair },
            ) if pair == outstanding.pair => PromotionState::Active,
            (
                PromotionState::Queued
                | PromotionState::Preparing
                | PromotionState::Validating
                | PromotionState::Stopping,
                PromotionOutcome::Refused { reason },
            ) => PromotionState::Refused(reason),
            (
                PromotionState::Queued
                | PromotionState::Preparing
                | PromotionState::Validating
                | PromotionState::Stopping
                | PromotionState::Active,
                PromotionOutcome::Ended { reason },
            ) => PromotionState::Ended(reason),
            _ => return None,
        };
        self.state = next;
        self.taken = true;
        self.note = None;
        Some(next)
    }
}

impl Default for PromotionControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(caller: u32, provider: u32) -> PromotionPair {
        PromotionPair::new(caller, provider)
    }

    fn enabled_control() -> PromotionControl {
        let mut control = PromotionControl::new();
        assert!(control.enable(CaptureId::new(7)));
        control
    }

    #[test]
    fn request_requires_enable() {
        let mut control = PromotionControl::new();
        assert!(!control.enabled());
        assert_eq!(control.state(), PromotionState::Idle);
        assert_eq!(
            control.request(ViewRevision::new(1), pair(3, 5)),
            Err(PromotionRefusal::Disabled)
        );
        assert_eq!(control.state(), PromotionState::Idle);
        assert_eq!(control.outstanding(), None);
    }

    #[test]
    fn enable_binds_one_capture() {
        let mut control = PromotionControl::new();
        assert!(control.enable(CaptureId::new(7)));
        assert!(control.enabled());
        assert_eq!(control.capture(), Some(CaptureId::new(7)));
        // Idempotent for the same capture.
        assert!(control.enable(CaptureId::new(7)));
        // A different capture never silently rebinds.
        assert!(!control.enable(CaptureId::new(9)));
        assert_eq!(control.capture(), Some(CaptureId::new(7)));
    }

    #[test]
    fn enable_refuses_rebind_while_work_is_outstanding() {
        let mut control = enabled_control();
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("first request queues");
        assert!(!control.enable(CaptureId::new(9)));
        assert_eq!(control.capture(), Some(CaptureId::new(7)));
        assert_eq!(control.state(), PromotionState::Queued);
    }

    #[test]
    fn requests_issue_increasing_serials() {
        let mut control = enabled_control();
        let first = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("first request queues");
        assert_eq!(first.get(), 1);
        assert_eq!(control.state(), PromotionState::Queued);
        assert_eq!(control.cancel(), PromotionCancel::Cancelled);
        assert_eq!(
            control.state(),
            PromotionState::Ended(PromotionEnd::Cancelled)
        );
        let second = control
            .request(ViewRevision::new(2), pair(1, 2))
            .expect("fresh request after terminal");
        assert_eq!(second.get(), 2);
    }

    #[test]
    fn second_request_while_queued_is_busy_and_keeps_first() {
        let mut control = enabled_control();
        let first = control
            .request(ViewRevision::new(4), pair(1, 2))
            .expect("first request queues");
        assert_eq!(
            control.request(ViewRevision::new(5), pair(9, 9)),
            Err(PromotionRefusal::Busy)
        );
        // The accepted work is untouched: the mailbox still yields it.
        let ticket = control.take_ticket().expect("mailbox holds the first");
        assert_eq!(ticket.id, first);
        assert_eq!(ticket.view, ViewRevision::new(4));
        assert_eq!(ticket.pair, pair(1, 2));
    }

    #[test]
    fn same_pair_while_queued_is_duplicate() {
        let mut control = enabled_control();
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("first request queues");
        assert_eq!(
            control.request(ViewRevision::new(2), pair(1, 2)),
            Err(PromotionRefusal::Duplicate)
        );
        assert_eq!(control.state(), PromotionState::Queued);
    }

    #[test]
    fn same_pair_while_preparing_is_duplicate() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("first request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Preparing)),
            Some(PromotionState::Preparing)
        );
        assert_eq!(
            control.request(ViewRevision::new(2), pair(1, 2)),
            Err(PromotionRefusal::Duplicate)
        );
    }

    #[test]
    fn active_repeat_is_already_detailed_and_other_is_busy() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("first request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Active { pair: pair(1, 2) }
            )),
            Some(PromotionState::Active)
        );
        assert_eq!(
            control.request(ViewRevision::new(2), pair(1, 2)),
            Err(PromotionRefusal::AlreadyDetailed)
        );
        assert_eq!(
            control.request(ViewRevision::new(2), pair(3, 4)),
            Err(PromotionRefusal::Busy)
        );
        assert_eq!(control.state(), PromotionState::Active);
    }

    #[test]
    fn request_while_stopping_is_busy() {
        let mut control = enabled_control();
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("first request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(control.cancel(), PromotionCancel::Stopping);
        assert_eq!(
            control.request(ViewRevision::new(2), pair(1, 2)),
            Err(PromotionRefusal::Busy)
        );
    }

    #[test]
    fn take_yields_at_most_once() {
        let mut control = enabled_control();
        assert_eq!(control.take_ticket(), None);
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        let ticket = control.take_ticket().expect("first take yields");
        assert_eq!(ticket.id, id);
        assert_eq!(control.take_ticket(), None);
    }

    #[test]
    fn accepted_status_consumes_the_mailbox() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        // The runtime evidently holds the request, so a later take
        // must not duplicate custody.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Preparing)),
            Some(PromotionState::Preparing)
        );
        assert_eq!(control.take_ticket(), None);
    }

    #[test]
    fn stale_status_is_rejected_and_changes_nothing() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        let stale = PromotionStatusUpdate::new(
            RequestId::new(id.get() + 1),
            PromotionOutcome::Active { pair: pair(1, 2) },
        );
        assert_eq!(control.set_status(stale), None);
        assert_eq!(control.state(), PromotionState::Queued);
        // The real request is still pending for the runtime.
        assert_eq!(control.take_ticket().map(|ticket| ticket.id), Some(id));
    }

    #[test]
    fn status_without_request_is_rejected() {
        let mut control = enabled_control();
        let update = PromotionStatusUpdate::new(RequestId::new(1), PromotionOutcome::Preparing);
        assert_eq!(control.set_status(update), None);
        assert_eq!(control.state(), PromotionState::Idle);
    }

    #[test]
    fn terminal_status_rejects_further_updates() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Refused {
                    reason: PromotionRefusal::CallerRetired
                }
            )),
            Some(PromotionState::Refused(PromotionRefusal::CallerRetired))
        );
        // A late activation for the refused request is not recorded.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Active { pair: pair(1, 2) }
            )),
            None
        );
        assert_eq!(
            control.state(),
            PromotionState::Refused(PromotionRefusal::CallerRetired)
        );
    }

    #[test]
    fn stopping_rejects_activation_then_accepts_the_end() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(control.cancel(), PromotionCancel::Stopping);
        // No activation after cancellation was requested.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Active { pair: pair(1, 2) }
            )),
            None
        );
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Preparing)),
            None
        );
        assert_eq!(control.state(), PromotionState::Stopping);
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Ended {
                    reason: PromotionEnd::Cancelled
                }
            )),
            Some(PromotionState::Ended(PromotionEnd::Cancelled))
        );
    }

    #[test]
    fn active_rejects_refusal_and_accepts_the_end() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Active { pair: pair(1, 2) }
            )),
            Some(PromotionState::Active)
        );
        // Refusal after activation is incoherent: the runtime ends.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Refused {
                    reason: PromotionRefusal::ScopeEnded
                }
            )),
            None
        );
        assert_eq!(control.state(), PromotionState::Active);
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Ended {
                    reason: PromotionEnd::LaneClosed
                }
            )),
            Some(PromotionState::Ended(PromotionEnd::LaneClosed))
        );
    }

    #[test]
    fn active_pair_mismatch_is_rejected() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Active { pair: pair(9, 9) }
            )),
            None
        );
        assert_eq!(control.state(), PromotionState::Queued);
    }

    #[test]
    fn full_transition_sequence_queues_prepares_validates_activates_ends() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(3), pair(4, 6))
            .expect("request queues");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Preparing)),
            Some(PromotionState::Preparing)
        );
        // An idempotent re-report is accepted without regressing.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Preparing)),
            Some(PromotionState::Preparing)
        );
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Validating)),
            Some(PromotionState::Validating)
        );
        // No backward step once validating.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Preparing)),
            None
        );
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Active { pair: pair(4, 6) }
            )),
            Some(PromotionState::Active)
        );
        // The control never self-activates: only the runtime update did.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Ended {
                    reason: PromotionEnd::RunStopped
                }
            )),
            Some(PromotionState::Ended(PromotionEnd::RunStopped))
        );
    }

    #[test]
    fn cancel_untaken_request_ends_synchronously() {
        let mut control = enabled_control();
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        assert_eq!(control.cancel(), PromotionCancel::Cancelled);
        assert_eq!(
            control.state(),
            PromotionState::Ended(PromotionEnd::Cancelled)
        );
        // The dropped request never reaches the runtime.
        assert_eq!(control.take_ticket(), None);
        // A fresh request is allowed after the terminal state.
        control
            .request(ViewRevision::new(2), pair(3, 4))
            .expect("fresh request after cancel");
    }

    #[test]
    fn cancel_after_take_requests_stopping() {
        let mut control = enabled_control();
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(control.cancel(), PromotionCancel::Stopping);
        assert_eq!(control.state(), PromotionState::Stopping);
        // Repeating the cancel while stopping stays stopping.
        assert_eq!(control.cancel(), PromotionCancel::Stopping);
    }

    #[test]
    fn cancel_active_lane_requests_stopping() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        control.take_ticket().expect("runtime takes it");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Active { pair: pair(1, 2) }
            )),
            Some(PromotionState::Active)
        );
        // An active lane is never synchronously ended from the UI: the
        // runtime winds it down.
        assert_eq!(control.cancel(), PromotionCancel::Stopping);
        assert_eq!(control.state(), PromotionState::Stopping);
    }

    #[test]
    fn cancel_idle_or_terminal_is_nothing() {
        let mut control = enabled_control();
        assert_eq!(control.cancel(), PromotionCancel::NothingToCancel);
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        assert_eq!(control.cancel(), PromotionCancel::Cancelled);
        assert_eq!(control.cancel(), PromotionCancel::NothingToCancel);
    }

    #[test]
    fn run_stop_ends_outstanding_work() {
        let mut control = enabled_control();
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        assert!(control.note_run_stopped());
        assert_eq!(
            control.state(),
            PromotionState::Ended(PromotionEnd::RunStopped)
        );
        assert_eq!(control.take_ticket(), None);
    }

    #[test]
    fn run_stop_idle_or_terminal_is_noop() {
        let mut control = enabled_control();
        assert!(!control.note_run_stopped());
        assert_eq!(control.state(), PromotionState::Idle);
        control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        assert_eq!(control.cancel(), PromotionCancel::Cancelled);
        assert!(!control.note_run_stopped());
    }

    #[test]
    fn serial_exhaustion_refuses_without_state_change() {
        let mut control = enabled_control();
        control.test_set_next_serial(RequestId::EXHAUSTED - 1);
        let last = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("last serial issues");
        assert_eq!(last.get(), RequestId::EXHAUSTED - 1);
        assert_eq!(control.cancel(), PromotionCancel::Cancelled);
        assert_eq!(
            control.request(ViewRevision::new(2), pair(3, 4)),
            Err(PromotionRefusal::Exhausted)
        );
        // The refused request leaves the terminal state and serial alone.
        assert_eq!(
            control.state(),
            PromotionState::Ended(PromotionEnd::Cancelled)
        );
        assert_eq!(
            control.request(ViewRevision::new(3), pair(3, 4)),
            Err(PromotionRefusal::Exhausted)
        );
    }

    #[test]
    fn fresh_request_allowed_after_refused_terminal() {
        let mut control = enabled_control();
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(
                id,
                PromotionOutcome::Refused {
                    reason: PromotionRefusal::ProviderUnloaded
                }
            )),
            Some(PromotionState::Refused(PromotionRefusal::ProviderUnloaded))
        );
        let retry = control
            .request(ViewRevision::new(2), pair(3, 4))
            .expect("fresh request after refusal");
        assert_eq!(retry.get(), id.get() + 1);
        assert_eq!(control.state(), PromotionState::Queued);
    }

    #[test]
    fn note_survives_until_superseded() {
        let mut control = enabled_control();
        assert_eq!(control.note(), None);
        control.set_note(Some(PromotionNote::Busy));
        assert_eq!(control.note(), Some(PromotionNote::Busy));
        // An accepted request clears the stale key outcome.
        let id = control
            .request(ViewRevision::new(1), pair(1, 2))
            .expect("request queues");
        assert_eq!(control.note(), None);
        control.set_note(Some(PromotionNote::Duplicate));
        // An accepted status update clears it too.
        assert_eq!(
            control.set_status(PromotionStatusUpdate::new(id, PromotionOutcome::Preparing)),
            Some(PromotionState::Preparing)
        );
        assert_eq!(control.note(), None);
        // A rejected update leaves a standing note alone.
        control.set_note(Some(PromotionNote::Busy));
        let stale = PromotionStatusUpdate::new(RequestId::new(999), PromotionOutcome::Validating);
        assert_eq!(control.set_status(stale), None);
        assert_eq!(control.note(), Some(PromotionNote::Busy));
    }

    #[test]
    fn refusal_note_mapping_covers_key_path_refusals() {
        assert_eq!(
            PromotionNote::for_refusal(PromotionRefusal::Busy),
            Some(PromotionNote::Busy)
        );
        assert_eq!(
            PromotionNote::for_refusal(PromotionRefusal::Duplicate),
            Some(PromotionNote::Duplicate)
        );
        assert_eq!(
            PromotionNote::for_refusal(PromotionRefusal::AlreadyDetailed),
            Some(PromotionNote::AlreadyDetailed)
        );
        assert_eq!(
            PromotionNote::for_refusal(PromotionRefusal::Exhausted),
            Some(PromotionNote::Exhausted)
        );
        assert_eq!(PromotionNote::for_refusal(PromotionRefusal::Disabled), None);
        assert_eq!(
            PromotionNote::for_refusal(PromotionRefusal::UnknownCaller),
            None
        );
    }

    #[test]
    fn status_words_are_plain_ascii_without_escapes() {
        let refusals = [
            PromotionRefusal::Disabled,
            PromotionRefusal::Busy,
            PromotionRefusal::Duplicate,
            PromotionRefusal::AlreadyDetailed,
            PromotionRefusal::Exhausted,
            PromotionRefusal::ForeignCapture,
            PromotionRefusal::StaleView,
            PromotionRefusal::UnknownCaller,
            PromotionRefusal::CallerRetired,
            PromotionRefusal::CallerChanged,
            PromotionRefusal::ProviderChanged,
            PromotionRefusal::ProviderUnloaded,
            PromotionRefusal::ManifestUnavailable,
            PromotionRefusal::EndpointAmbiguous,
            PromotionRefusal::EndpointDependency,
            PromotionRefusal::ScopeEnded,
            PromotionRefusal::PreparationFailed,
            PromotionRefusal::ActivationFailed,
        ];
        for refusal in refusals {
            let label = refusal.label();
            assert!(!label.is_empty(), "{refusal:?}");
            assert!(
                label.is_ascii() && !label.bytes().any(|byte| byte < 0x20 || byte == 0x7f),
                "{refusal:?}: {label:?}"
            );
        }
        for end in [
            PromotionEnd::Cancelled,
            PromotionEnd::RunStopped,
            PromotionEnd::LaneClosed,
        ] {
            let label = end.label();
            assert!(!label.is_empty(), "{end:?}");
            assert!(
                label.is_ascii() && !label.bytes().any(|byte| byte < 0x20 || byte == 0x7f),
                "{end:?}: {label:?}"
            );
        }
        for note in [
            PromotionNote::Busy,
            PromotionNote::Duplicate,
            PromotionNote::AlreadyDetailed,
            PromotionNote::Exhausted,
            PromotionNote::NoSelection,
            PromotionNote::StaleSelection,
            PromotionNote::NothingToCancel,
        ] {
            let label = note.label();
            assert!(!label.is_empty(), "{note:?}");
            assert!(
                label.is_ascii() && !label.bytes().any(|byte| byte < 0x20 || byte == 0x7f),
                "{note:?}: {label:?}"
            );
        }
    }

    #[test]
    fn serial_identities_compare_by_value() {
        assert_eq!(CaptureId::new(7), CaptureId::new(7));
        assert_ne!(CaptureId::new(7), CaptureId::new(8));
        assert_eq!(CaptureId::new(7).get(), 7);
        assert_eq!(ViewRevision::new(3).get(), 3);
        assert_eq!(RequestId::new(1).get(), 1);
        assert_eq!(pair(1, 2).caller(), 1);
        assert_eq!(pair(1, 2).provider(), 2);
        assert_eq!(
            PromotionStatusUpdate::new(RequestId::new(1), PromotionOutcome::Preparing).request,
            RequestId::new(1)
        );
    }
}
