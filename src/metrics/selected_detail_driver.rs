//! SPDX-License-Identifier: GPL-3.0-or-later
//! 6.15 driver packet: CLI endpoint selection plus live
//! counter→detail promotion/demotion orchestration over the
//! handoff→gate adapter (WF §D2.3 ordering as amended R2-D2-A…E).
//!
//! Stage 0 ([`resolve_selection`]) is production-live in the metrics
//! driver: the `--select-endpoint` name resolves against the live
//! broad plan (exactly one slot, never first-match) and the scope
//! resolves to one live original (`--pid`/owned only). The
//! K0 window ([`open_k0_window`]/[`close_k0_window`]) details the
//! selection from the broad banks' own cells between a
//! selection-time read and the close read; an exec of the selected
//! caller voids it via the broad exec witness. Unresolvable
//! selections and voided windows record their named refusal and the
//! aggregate capture continues untouched.
//!
//! The [`PromotionDriver`] runs the full D2.3 ordering over the real
//! seams — adapter reserve, lifecycle start with the gated source,
//! poll (cancel/stop/disposal/install), reclaim and close — with the
//! window ledger and the additive report composer. Twins and root
//! controls drive it end to end; the production metrics path reaches
//! it once the host composition lands (STAGED below).

use super::counter_collector::{
    CounterCollector, CounterDeltas, CounterLimits, CounterObservation, CounterRead, ReadStage,
};
use super::counter_reader::ReaderShapeCause;
use super::selected_detail::{
    AcceptedBracket, BoundWindow, BroadBracketCollector, BroadSession, DetailCloseRefusal,
    DetailCloseReport, DetailWindowCustody, DetailWindowEvent, GatedActivationSource,
    PreparedChildReceipt, ReserveRefusal, SelectedDetailRefusal,
};
use crate::attach::Scope;
use crate::attach::counter_banks::{BankRefusal, CounterDetailWindow, DetailToggleRefusal};
use crate::attach::{LifecycleFacts, PidContinuityRefusal, Session};
use crate::discovery::engine::inventory_coordinator::semantics::PromotionInstallCapacity;
use crate::discovery::identity::PinnedObjects;
use crate::inventory_promotion::lifecycle::{
    LifecycleEvent, NativeActivationSource, PendingInstall, PreparationBundle, PreparationOutcome,
    SelectedLifecycleService, validate_subset_shape,
};
use crate::inventory_promotion::{
    PromotionEnd, PromotionOutcome, PromotionRefusal, PromotionRequest, PromotionStatusUpdate,
    RequestId,
};
use crate::plan::{AdmissionPolicy, AttachKey, AttachPlan, Slot};
use crate::process::PidPin;
use crate::semantics_edge::resources::{SemanticResourcePool, SemanticResourceReserver};
use p11scope_ebpf_common::{
    CounterMode, DISCOVERY_KIND_EXEC, DISCOVERY_KIND_LEADER_EXIT, DiscoveryRecord,
};
use std::sync::Arc;

/// One resolved CLI selection: the unique broad slot plus the pinned
/// live original the detail child would be prepared for. Resolution
/// proves the endpoint is published NOW (live plan) and the original
/// is live NOW (pidfd + start-time + liveness); it grants no
/// preparation authority by itself.
pub(crate) struct ResolvedSelection {
    pub(crate) slot: u32,
    pub(crate) physical: AttachKey,
    /// Every name resolving at this slot, sorted (the slot's group;
    /// detail covers the group when the slot is aliased).
    pub(crate) names: Vec<String>,
    pub(crate) original: Arc<PidPin>,
}

impl std::fmt::Debug for ResolvedSelection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSelection")
            .field("slot", &self.slot)
            .field("physical", &self.physical)
            .field("names", &self.names)
            .field("original", &self.original.pid())
            .finish()
    }
}

/// Why the driver refused before/without touching the promotion
/// machinery. The lifecycle ([`PromotionRefusal`]) and adapter
/// ([`SelectedDetailRefusal`]) vocabularies pass through unwrapped;
/// the driver adds only its own selection/host words. The report
/// ledger records [`name`](Self::name) for every terminal refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedDriverRefusal {
    Promotion(PromotionRefusal),
    Detail(SelectedDetailRefusal),
    /// The CLI name matched zero broad slots.
    EndpointUnknown,
    // NOTE: the pre-K0 `bundle_unavailable` seam word is retired from
    // production; it stays in the schema vocabulary (schema JSON +
    // oracle) so reports written before K0 still validate.
}

impl SelectedDriverRefusal {
    /// Stable static words for the report ledger (ASCII, no escapes).
    /// The lifecycle vocabulary keeps its `promotion_` prefix so the
    /// two recorded vocabularies never collide; the adapter words
    /// pass through unchanged.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Promotion(reason) => match reason {
                PromotionRefusal::Disabled => "promotion_disabled",
                PromotionRefusal::Busy => "promotion_busy",
                PromotionRefusal::Duplicate => "promotion_duplicate",
                PromotionRefusal::AlreadyDetailed => "promotion_already_detailed",
                PromotionRefusal::Exhausted => "promotion_exhausted",
                PromotionRefusal::ForeignCapture => "promotion_foreign_capture",
                PromotionRefusal::StaleView => "promotion_stale_view",
                PromotionRefusal::UnknownCaller => "promotion_unknown_caller",
                PromotionRefusal::CallerRetired => "promotion_caller_retired",
                PromotionRefusal::CallerChanged => "promotion_caller_changed",
                PromotionRefusal::ProviderChanged => "promotion_provider_changed",
                PromotionRefusal::ProviderUnloaded => "promotion_provider_unloaded",
                PromotionRefusal::ManifestUnavailable => "promotion_manifest_unavailable",
                PromotionRefusal::EndpointAmbiguous => "promotion_endpoint_ambiguous",
                PromotionRefusal::EndpointDependency => "promotion_endpoint_dependency",
                PromotionRefusal::ScopeEnded => "promotion_scope_ended",
                PromotionRefusal::ScopeUnsupported => "promotion_scope_unsupported",
                PromotionRefusal::PreparationFailed => "promotion_preparation_failed",
                PromotionRefusal::ActivationFailed => "promotion_activation_failed",
                PromotionRefusal::Capacity => "promotion_capacity",
            },
            Self::Detail(detail) => detail.name(),
            Self::EndpointUnknown => "endpoint_unknown",
        }
    }
}

/// Resolve one `--select-endpoint` name against the live broad plan
/// and scope (driver stage 0, production-live):
/// - the plan must be a `Counters` broad (anything else is a driver
///   bug or a non-counter capture — refused, never adapted);
/// - the name must match exactly one slot's names (zero ⇒
///   [`EndpointUnknown`](SelectedDriverRefusal::EndpointUnknown),
///   two or more ⇒ [`PromotionRefusal::EndpointAmbiguous`], never
///   first-match; an aliased slot resolves as its whole group);
/// - the scope must resolve to one live original (`--pid` pins and
///   re-checks liveness; `--cgroup`/`--system` cannot name one
///   original ⇒ [`PromotionRefusal::ScopeUnsupported`]).
///
/// An empty name never resolves (fail-closed for programmatic
/// callers; the CLI already refuses it).
pub(crate) fn resolve_selection(
    spec: &str,
    broad_plan: &AttachPlan,
    scope: &Scope,
) -> Result<ResolvedSelection, SelectedDriverRefusal> {
    use SelectedDriverRefusal::{Detail, EndpointUnknown, Promotion};
    if !matches!(broad_plan.admission_policy(), AdmissionPolicy::Counters(_)) {
        return Err(Detail(SelectedDetailRefusal::BroadPlanTopology));
    }
    if spec.is_empty() {
        return Err(EndpointUnknown);
    }
    let mut matched: Option<&Slot> = None;
    for slot in &broad_plan.slots {
        if slot.names.iter().any(|name| name == spec) {
            if matched.is_some() {
                return Err(Promotion(PromotionRefusal::EndpointAmbiguous));
            }
            matched = Some(slot);
        }
    }
    let slot = matched.ok_or(EndpointUnknown)?;
    let pid = match scope {
        Scope::Pid(pid) => *pid,
        Scope::Cgroup { .. } | Scope::System => {
            return Err(Promotion(PromotionRefusal::ScopeUnsupported));
        }
    };
    let pin = Arc::new(PidPin::open(pid).map_err(|_| Promotion(PromotionRefusal::UnknownCaller))?);
    pin.open_proc_dir()
        .map_err(|_| Promotion(PromotionRefusal::CallerRetired))?;
    Ok(ResolvedSelection {
        slot: slot.index,
        physical: AttachKey {
            object: slot.object,
            file_offset: slot.file_offset,
        },
        names: slot.names.clone(),
        original: pin,
    })
}

/// One driver event for the host: a lifecycle status to apply to the
/// host's own promoter, or a proof-gated install handoff to install
/// (or return via [`PromotionDriver::reclaim`]).
#[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): consumed by the host composition; twins drive it today.
#[allow(clippy::large_enum_variant)] // 6.15: single-flight install handoff, moved once per promotion; sizes are native-owned.
pub(crate) enum DriverEvent {
    Status(PromotionStatusUpdate),
    // STAGED (6.15): yielded only by poll's Install arm on a genuine
    // Ready + CAS + mint, which needs a live-bundle host composition;
    // no twin or root control mints Ready yet (cf. O9's posed arrival).
    #[allow(dead_code)]
    Install(PendingInstall),
}

/// Why [`PromotionDriver::close`] did not close: no open window (host
/// sequencing bug — benign, nothing was held), or the genuine close
/// refusal with its after bracket (recorded, never fabricated).
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): returned to the host composition; twins drive it today.
pub(crate) enum DriverCloseError {
    NoOpenWindow,
    Close(DetailCloseRefusal),
}

/// The D2.3 promotion driver: one lifecycle service, one window
/// custody, one bracket collector backing, one capture-monotonic
/// bracket seq, the window ledger, the current request clone (for
/// ledger rows after the service consumes the request) and the open
/// window (Active while a lane is installed, Unactivated while a
/// reclaim settles). Single-threaded tick discipline like the
/// custody it owns: reserve → start → poll → install/reclaim →
/// close, then reselect.
#[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): owned by the host composition; twins + root controls drive it today.
pub(crate) struct PromotionDriver {
    lifecycle: SelectedLifecycleService,
    custody: DetailWindowCustody,
    brackets: Option<BroadBracketCollector>,
    seq: u64,
    ledger: SelectionLedger,
    current: Option<PromotionRequest>,
    open_window: Option<CounterDetailWindow>,
    /// The request that made the parked reservation (`None` once it
    /// is taken or abandoned): start-refusals abandon only their own
    /// orphan, never another flight's.
    reserved_for: Option<RequestId>,
}

// STAGED (6.15): the host composition calls the orchestration entries;
// twins + root controls drive every one of them today.
#[cfg_attr(not(test), allow(dead_code))]
impl PromotionDriver {
    pub(crate) fn new() -> Self {
        Self {
            lifecycle: SelectedLifecycleService::new(),
            custody: DetailWindowCustody::new(),
            brackets: None,
            seq: 0,
            ledger: SelectionLedger::new(),
            current: None,
            open_window: None,
            reserved_for: None,
        }
    }

    /// Whether the lifecycle service holds no work (host quiescence).
    pub(crate) fn is_idle(&self) -> bool {
        self.lifecycle.is_idle()
    }

    /// Adapter phase 1 through the shared session body: validate,
    /// charge, before-mark and place the reservation in custody
    /// before any worker starts. Production passes the live `&Session`
    /// with its live bracketing read; twins pass staged banks with
    /// scripted reads through the same body.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn reserve<B: BroadSession>(
        &mut self,
        broad: &B,
        broad_plan: &AttachPlan,
        broad_objects: &PinnedObjects,
        request: &PromotionRequest,
        bundle: &PreparationBundle,
        source: Result<CounterRead, ReadStage>,
        rows: usize,
        rv_keys: usize,
        pool: &SemanticResourcePool,
    ) -> Result<AcceptedBracket, ReserveRefusal> {
        use super::selected_detail::reserve_detail_window;
        let mut brackets = BroadBracketCollector::new(rows, rv_keys, pool.reserver());
        let gate = pool.reserver();
        match reserve_detail_window(
            broad,
            broad_plan,
            broad_objects,
            request,
            bundle,
            &mut brackets,
            &mut self.seq,
            source,
            &gate,
            &self.custody,
        ) {
            Ok(receipt) => {
                self.brackets = Some(brackets);
                self.reserved_for = Some(request.id());
                let note = request
                    .endpoint()
                    .map(|endpoint| format!("selected {:#x}", endpoint.file_offset()));
                self.ledger
                    .record_event(super::selected_detail::render_window_event(
                        DetailWindowEvent::Reserved,
                        request.id(),
                        request.caller(),
                        request.provider(),
                        receipt.seq,
                        note.as_deref(),
                    ));
                Ok(receipt)
            }
            Err(refusal) => {
                self.ledger
                    .record_event(reserve_refused_row(request, &refusal));
                Err(refusal)
            }
        }
    }

    /// Start the preparation worker with the gated activation source.
    /// Runs the coordinator-free pre-start gates first (subset shape,
    /// baseline/request agreement); the host's bundle seam ran the
    /// coordinator gates. A refused start abandons the orphan
    /// reservation so a reselect is never wedged.
    pub(crate) fn start(
        &mut self,
        request: PromotionRequest,
        bundle: &PreparationBundle,
        capacity: PromotionInstallCapacity,
        inner: Box<dyn NativeActivationSource>,
        job: impl FnOnce() -> PreparationOutcome + Send + 'static,
    ) -> Result<(), PromotionRefusal> {
        // Coordinator-free pre-start gates (the host's bundle seam ran
        // the coordinator gates): subset shape, then baseline/request
        // agreement, then service idleness. Every refusal abandons
        // only this request's own orphan and records its row before
        // any worker spawns.
        if let Err(reason) = validate_subset_shape(bundle.convert_subset()) {
            self.abandon_mine(request.id());
            self.ledger
                .record_event(start_refused_row(&request, reason));
            return Err(reason);
        }
        if !bundle.baseline.matches_request(&request) {
            self.abandon_mine(request.id());
            self.ledger
                .record_event(start_refused_row(&request, PromotionRefusal::StaleView));
            return Err(PromotionRefusal::StaleView);
        }
        if !self.lifecycle.is_idle() {
            self.abandon_mine(request.id());
            self.ledger
                .record_event(start_refused_row(&request, PromotionRefusal::Busy));
            return Err(PromotionRefusal::Busy);
        }
        let prepared = match PreparedChildReceipt::of_bundle(bundle) {
            Some(prepared) => prepared,
            None => {
                // Unreachable after a successful reserve of the same
                // bundle (reserve sealed it); fail closed without
                // starting so no worker runs unsealed.
                self.abandon_mine(request.id());
                self.ledger.record_event(start_refused_row(
                    &request,
                    PromotionRefusal::PreparationFailed,
                ));
                return Err(PromotionRefusal::PreparationFailed);
            }
        };
        let source = GatedActivationSource::new(inner, self.custody.clone(), prepared);
        // Single-threaded: idleness held above, so the service starts.
        // The defensive map keeps custody untouched (a refused start
        // never held a worker, so no orphan of this request can be
        // stranded by the service path itself).
        match self
            .lifecycle
            .start(request.clone(), capacity, Box::new(source), job)
        {
            Ok(()) => {
                self.current = Some(request);
                Ok(())
            }
            Err(reason) => {
                self.abandon_mine(request.id());
                self.ledger
                    .record_event(start_refused_row(&request, reason));
                Err(reason)
            }
        }
    }

    /// Abandon the parked reservation when it is `id`'s own (made by
    /// this request's reserve), releasing its bracket storage too: a
    /// window that never binds can never close, so its before-state
    /// is garbage. Anything else belongs to another flight and is
    /// left alone. Reports whether anything was abandoned.
    fn abandon_mine(&mut self, id: RequestId) -> bool {
        if self.reserved_for == Some(id) {
            self.reserved_for = None;
            self.brackets = None;
            if let Some(reserved) = self.custody.take_reserved() {
                let _ = reserved.abandon();
            }
            true
        } else {
            false
        }
    }

    /// Settle this flight's own parked custody on a terminal status,
    /// distinguishing never-bound abandonment from bound-window
    /// completion: a never-bound reservation abandons (its charge and
    /// bracket storage release, exactly as before); a parked bound
    /// window transfers to the pending-close context WITH its
    /// original request and bracket collector, so the host's close
    /// records the terminal result. Anything else belongs to another
    /// flight and is left alone. Reports whether a never-bound
    /// reservation was abandoned (the cancelled-before-delivery row
    /// still owes only to that case — a transferred window records
    /// its own close).
    fn settle_terminal(&mut self, id: RequestId) -> bool {
        if self.reserved_for != Some(id) {
            return false;
        }
        self.reserved_for = None;
        if let Some(reserved) = self.custody.take_reserved() {
            let _ = reserved.abandon();
            self.brackets = None;
            return true;
        }
        if let Some(bound) = self.custody.take_bound() {
            let window = match bound {
                BoundWindow::Active(window) | BoundWindow::Unactivated(window) => window,
            };
            self.open_window = Some(window);
        }
        false
    }

    /// Poll once (driver tick): reap service events, abandon orphan
    /// reservations with their ledger rows, take custody on install
    /// (Active installs; anything else reclaims for genuine
    /// disposal). Status events pass to the host's promoter.
    pub(crate) fn poll(&mut self, out: &mut dyn std::io::Write) -> Option<DriverEvent> {
        match self.lifecycle.poll(out)? {
            LifecycleEvent::Status(update) => {
                // The flight ended: settle this flight's own parked
                // custody. A never-bound reservation abandons (its
                // charge and bracket storage release, custody drains);
                // a parked bound window transfers to the pending-close
                // context with its original request and brackets. A
                // cancel/stop end records the adapter's
                // cancelled_unactivated row only for the never-bound
                // case; failures record only the outcome (nothing was
                // cancelled); a transferred window records its own
                // close.
                let orphaned = self.settle_terminal(update.request);
                if orphaned
                    && matches!(update.outcome, PromotionOutcome::Ended { .. })
                    && let Some(current) = self.current.as_ref()
                {
                    self.ledger
                        .record_event(super::selected_detail::render_window_event(
                            DetailWindowEvent::CancelledUnactivated,
                            current.id(),
                            current.caller(),
                            current.provider(),
                            self.seq,
                            Some("cancelled before delivery"),
                        ));
                }
                // A pending close keeps its context: the host closes
                // the open window next, and close needs the original
                // request plus the bracket collector. Single-flight:
                // an open window can only be this flight's own (a new
                // flight cannot reserve while admission is held).
                let pending_close = self.open_window.is_some();
                match update.outcome {
                    PromotionOutcome::Refused { reason } => {
                        self.ledger.record_event(promotion_outcome_row(
                            update.request,
                            "refused",
                            Some(reason.label()),
                            None,
                        ));
                        if !pending_close {
                            self.current = None;
                        }
                    }
                    PromotionOutcome::Ended { reason } => {
                        self.ledger.record_event(promotion_outcome_row(
                            update.request,
                            "ended",
                            Some(reason.label()),
                            None,
                        ));
                        if !pending_close {
                            self.current = None;
                        }
                    }
                    // The service emits terminal statuses only; anything
                    // else passes to the host without a row or state
                    // change.
                    PromotionOutcome::Preparing
                    | PromotionOutcome::Validating
                    | PromotionOutcome::Active { .. } => {}
                }
                Some(DriverEvent::Status(update))
            }
            LifecycleEvent::Install(pending) => {
                // D2.3 step 5: take custody first. An Active window
                // with the current request installs (Bound + CAS rows
                // record, the handoff goes to the host); anything else
                // reclaims for genuine disposal — a windowless lane
                // must never install (it would double-count silently).
                let taken = self.custody.take_bound();
                self.reserved_for = None;
                let current = self.current.clone();
                match (taken, current) {
                    (Some(BoundWindow::Active(window)), Some(current)) => {
                        self.open_window = Some(window);
                        for event in [DetailWindowEvent::Bound, DetailWindowEvent::CasWon] {
                            self.ledger
                                .record_event(super::selected_detail::render_window_event(
                                    event,
                                    current.id(),
                                    current.caller(),
                                    current.provider(),
                                    self.seq,
                                    None,
                                ));
                        }
                        Some(DriverEvent::Install(pending))
                    }
                    (taken, _) => {
                        if let Some(BoundWindow::Unactivated(window)) = taken {
                            self.open_window = Some(window);
                        }
                        self.lifecycle
                            .reclaim_install(pending, None)
                            .expect("an Install handoff always reclaims");
                        None
                    }
                }
            }
        }
    }

    /// Operator cancel or run stop: the worker runs to its genuine
    /// end, then its outcome is disposed and the end confirmed;
    /// nothing installs after this call.
    pub(crate) fn cancel(&mut self, end: PromotionEnd) {
        self.lifecycle.note_cancel(end);
    }

    /// Return a host-refused install handoff for genuine disposal.
    /// The open window stays open: the host polls for the settled
    /// Status, then closes.
    #[allow(clippy::result_large_err)] // 6.15: cold path returning the refused handoff for genuine disposal.
    pub(crate) fn reclaim(
        &mut self,
        pending: PendingInstall,
        end: Option<PromotionEnd>,
    ) -> Result<(), PendingInstall> {
        self.lifecycle.reclaim_install(pending, end)
    }

    /// The host installed the handoff through the coordinator entry:
    /// confirm `Active` for the exact requested pair and release the
    /// service to idle for the next promotion. Records the outcome
    /// row and returns the update for the host's promoter. `None`
    /// unless an install is outstanding.
    pub(crate) fn note_installed(&mut self) -> Option<PromotionStatusUpdate> {
        let update = self.lifecycle.note_installed()?;
        if let PromotionOutcome::Active { pair } = update.outcome {
            self.ledger.record_event(promotion_outcome_row(
                update.request,
                "active",
                None,
                Some((pair.caller(), pair.provider())),
            ));
        }
        Some(update)
    }

    /// Whether an open window awaits its close: an installed lane
    /// winding down, a reclaim settling, or a bound window a
    /// terminal status just transferred. The host's next call must be
    /// [`close`](Self::close), which records the terminal result and
    /// releases the window's charges and admission; only close clears
    /// this. Single-flight: the host closes before it reselects.
    pub(crate) fn pending_close(&self) -> bool {
        self.open_window.is_some()
    }

    /// Tests-only pose of the open context over state staged
    /// through the real adapter body (reservation, bind downstream of
    /// it, bracket collector, capture seq, current request): stands
    /// in for the CAS-win park (unrunnable unprivileged). Close-path
    /// scenes only: the window must close, never fabricate a CAS.
    /// Consumes the reservation like the Install arm does.
    #[cfg(test)]
    fn stage_open_window_for_test(
        &mut self,
        window: CounterDetailWindow,
        brackets: BroadBracketCollector,
        seq: u64,
        request: PromotionRequest,
    ) {
        self.open_window = Some(window);
        self.brackets = Some(brackets);
        self.seq = seq;
        self.current = Some(request);
        self.reserved_for = None;
    }

    /// Tests-only pose of the flight's current request for a
    /// bound-completion scene: stands in for [`start`](Self::start)
    /// recording the request (the worker half stays posed). The
    /// request must be the flight's own: close joins it to the
    /// window.
    #[cfg(test)]
    fn stage_current_for_test(&mut self, request: PromotionRequest) {
        self.current = Some(request);
    }

    /// Tests-only pose of the `Installing` state for a reclaim scene:
    /// stands in for the worker + poll + CAS + mint chain
    /// (unrunnable unprivileged). Panics unless idle.
    #[cfg(test)]
    fn seed_installing_for_test(&mut self, request: PromotionRequest) {
        self.lifecycle.seed_installing_for_test(request);
    }

    /// Adapter phase 3 through the shared session body: close the
    /// open window exactly once, after the host wound down its lane
    /// (installed path) or disposal settled (reclaim path). Records
    /// the lineage plus the aggregate bracket for the composer.
    #[allow(clippy::result_large_err)] // 6.15: cold path returning the genuine close refusal with its after bracket.
    pub(super) fn close<B: BroadSession>(
        &mut self,
        broad: &B,
        broad_plan: &AttachPlan,
        mode: CounterMode,
        source: Result<CounterRead, ReadStage>,
    ) -> Result<DetailCloseReport, DriverCloseError> {
        use super::selected_detail::close_detail_window;
        let Some(window) = self.open_window.take() else {
            return Err(DriverCloseError::NoOpenWindow);
        };
        let (Some(brackets), Some(current)) = (self.brackets.as_mut(), self.current.clone()) else {
            // Internal invariant: an open window always travels with
            // its bracket collector and current request (reserve and
            // the test stager install all three). Restore the window
            // and fail closed rather than closing unbracketed.
            self.open_window = Some(window);
            return Err(DriverCloseError::NoOpenWindow);
        };
        match close_detail_window(
            window,
            broad,
            broad_plan,
            mode,
            brackets,
            &mut self.seq,
            source,
        ) {
            Ok(report) => {
                self.current = None;
                self.brackets = None;
                self.ledger
                    .record_event(super::selected_detail::render_window_event(
                        DetailWindowEvent::Closed,
                        current.id(),
                        current.caller(),
                        current.provider(),
                        report.seq_after,
                        None,
                    ));
                self.ledger.record_close(&report, &current, mode);
                Ok(report)
            }
            Err(refusal) => {
                // The window is consumed (dropped, admission
                // released): the refusal is terminal for it. Record
                // the explicit close-refused row plus the true close
                // boundary's aggregate — never a fabricated lineage.
                self.current = None;
                self.brackets = None;
                self.ledger.record_close_refused(&refusal, &current, mode);
                Err(DriverCloseError::Close(refusal))
            }
        }
    }

    /// The window ledger for the report composer.
    pub(crate) fn ledger(&self) -> &SelectionLedger {
        &self.ledger
    }

    /// Record detail deltas the host read from the installed child's
    /// own stream (STAGED for the counter-child future: the current
    /// Detailed child serves detail through its installed lane, so
    /// production records none yet). Renders immediately through the
    /// real detail renderer; the driver never holds the deltas.
    /// Metrics-internal like the deltas themselves.
    pub(super) fn record_detail(
        &mut self,
        deltas: &CounterDeltas,
        mode: CounterMode,
        detail_generation: u64,
    ) {
        self.ledger.detail = Some(super::selected_detail::render_detail_rows(
            deltas,
            mode,
            detail_generation,
        ));
    }
}

/// One driver refusal row: the reserve attempt that never became a
/// window, with the adapter's refusal word and the accepted bracket
/// seq when the refusal came post-acceptance.
#[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): called from the staged orchestration entries.
fn reserve_refused_row(request: &PromotionRequest, refusal: &ReserveRefusal) -> serde_json::Value {
    serde_json::json!({
        "event": "reserve_refused",
        "request": request.id().get(),
        "caller": request.caller().0,
        "provider": request.provider().0,
        "refusal": refusal.refusal.name(),
        "seq": refusal.bracket.as_ref().map(|bracket| bracket.seq),
    })
}

/// One driver refusal row: the start that never spawned a worker.
#[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): called from the staged orchestration entries.
fn start_refused_row(request: &PromotionRequest, reason: PromotionRefusal) -> serde_json::Value {
    serde_json::json!({
        "event": "start_refused",
        "request": request.id().get(),
        "caller": request.caller().0,
        "provider": request.provider().0,
        "reason": reason.label(),
    })
}

/// One driver outcome row: a terminal promotion outcome the host also
/// applies to its own promoter. Refused/ended carry the human reason
/// word; active carries the confirmed pair.
#[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): called from the staged orchestration entries.
fn promotion_outcome_row(
    request: RequestId,
    outcome: &'static str,
    reason: Option<&'static str>,
    pair: Option<(u32, u32)>,
) -> serde_json::Value {
    let mut row = serde_json::json!({
        "event": "promotion_outcome",
        "request": request.get(),
        "outcome": outcome,
    });
    if let Some(reason) = reason {
        row["reason"] = serde_json::json!(reason);
    }
    if let Some((caller, provider)) = pair {
        row["caller"] = serde_json::json!(caller);
        row["provider"] = serde_json::json!(provider);
    }
    row
}

impl Default for PromotionDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// One selection record: the named endpoint plus either its resolved
/// slot or the named refusal. Both shapes publish; a refusal is a
/// record, never an absence.
pub(crate) struct SelectionRecord {
    pub(crate) endpoint: String,
    pub(crate) slot: Option<u32>,
    pub(crate) file_offset: Option<u64>,
    pub(crate) names: Vec<String>,
    /// The pin/PID stays private with the [`ResolvedSelection`] the
    /// stage returns to its caller: the public record never publishes
    /// process identity (allowlist-v1: profile and metrics do not
    /// publish raw PID/TID).
    pub(crate) refusal: Option<&'static str>,
}

/// The driver's window ledger: the selection record, the window and
/// driver event rows in tick order, and the close products (lineage,
/// aggregate bracket, staged detail rows) for the composer. Carries
/// no combined totals: aggregate intervals render only from broad
/// reads, detail only from the child's own stream, joined only
/// through lineage.
pub(crate) struct SelectionLedger {
    selection: Option<SelectionRecord>,
    events: Vec<serde_json::Value>,
    lineage: Option<serde_json::Value>,
    aggregate: Option<serde_json::Value>,
    detail: Option<serde_json::Value>,
}

impl SelectionLedger {
    pub(crate) fn new() -> Self {
        Self {
            selection: None,
            events: Vec::new(),
            lineage: None,
            aggregate: None,
            detail: None,
        }
    }

    fn record_selection(&mut self, endpoint: &str, resolved: &ResolvedSelection) {
        self.selection = Some(SelectionRecord {
            endpoint: endpoint.to_string(),
            slot: Some(resolved.slot),
            file_offset: Some(resolved.physical.file_offset),
            names: resolved.names.clone(),
            refusal: None,
        });
    }

    fn record_unresolved(&mut self, endpoint: &str, refusal: &'static str) {
        self.selection = Some(SelectionRecord {
            endpoint: endpoint.to_string(),
            slot: None,
            file_offset: None,
            names: Vec::new(),
            refusal: Some(refusal),
        });
    }

    fn mark_selection_refused(&mut self, refusal: &'static str) {
        if let Some(selection) = self.selection.as_mut() {
            selection.refusal = Some(refusal);
        }
    }

    #[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): called from the staged orchestration entries.
    fn record_event(&mut self, row: serde_json::Value) {
        self.events.push(row);
    }

    /// Record a delivered close: the lineage plus the aggregate
    /// bracket over the window's true interval. A close without an
    /// after receipt records lineage alone (no interval, never
    /// fabricated zeros).
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): called from the staged orchestration entries.
    fn record_close(
        &mut self,
        report: &DetailCloseReport,
        request: &PromotionRequest,
        mode: CounterMode,
    ) {
        use super::selected_detail::{render_aggregate_bracket, render_lineage_row};
        if let Some(receipt) = request.endpoint() {
            let lineage = render_lineage_row(request, receipt.file_offset(), report);
            if let Some(inner) = lineage.get("selected_detail") {
                self.lineage = Some(inner.clone());
            }
        }
        if let Some(deltas) = report
            .after_receipt
            .as_ref()
            .and_then(|receipt| receipt.deltas())
        {
            self.aggregate = Some(render_aggregate_bracket(
                deltas,
                mode,
                report.seq_before,
                report.seq_after,
            ));
        }
    }

    /// Record a refused close: the explicit close-refused row plus the
    /// true close boundary's aggregate when the refusal carries one —
    /// never a fabricated lineage.
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (6.15): called from the staged orchestration entries.
    fn record_close_refused(
        &mut self,
        refusal: &DetailCloseRefusal,
        request: &PromotionRequest,
        mode: CounterMode,
    ) {
        use super::selected_detail::{render_aggregate_bracket, render_close_refused_row};
        if let Some(receipt) = request.endpoint() {
            self.events.push(render_close_refused_row(
                request,
                receipt.file_offset(),
                refusal.refusal,
            ));
        }
        if let Some(deltas) = refusal
            .after_receipt
            .as_ref()
            .and_then(|receipt| receipt.deltas())
        {
            self.aggregate = Some(render_aggregate_bracket(
                deltas,
                mode,
                refusal.seq_before,
                refusal.seq_after,
            ));
        }
    }
}

impl Default for SelectionLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Production metrics selection stage (driver stage 0 in the capture
/// loop): resolve the CLI name and record the selection or its named
/// refusal. A resolution carries no refusal yet: the caller opens the
/// K0 window over it, and the close records the detail or its void.
/// Returns the resolution for the K0 open; the ledger is the durable
/// record either way. Aggregate capture is untouched on every path.
pub(crate) fn run_metrics_selection_stage(
    name: &str,
    broad_plan: &AttachPlan,
    scope: &Scope,
    ledger: &mut SelectionLedger,
) -> Option<ResolvedSelection> {
    match resolve_selection(name, broad_plan, scope) {
        Ok(resolved) => {
            ledger.record_selection(name, &resolved);
            Some(resolved)
        }
        Err(refusal) => {
            ledger.record_unresolved(name, refusal.name());
            None
        }
    }
}

/// One exec-witness snapshot for a K0 window bound: the broad tap's
/// facts, `None` when the session carries no PID witness, `Err` when
/// the witness failed. Production snapshots come from
/// `Session::pid_lifecycle_facts`; twins script them.
pub(crate) type K0Facts = Result<Option<LifecycleFacts>, PidContinuityRefusal>;

/// The open K0 window: the resolved selection, the detail collector
/// holding the selection-time read as its baseline, the
/// selection-time witness facts, and the collector limits (reused for
/// the close read so both bounds share one budget).
pub(crate) struct K0Window {
    resolved: ResolvedSelection,
    collector: CounterCollector,
    before: LifecycleFacts,
    limits: CounterLimits,
}

/// Map a failed K0 read to its ledger word: quarantine and pool
/// pressure name themselves, a missing binding names the broad, and
/// every other stage maps to the topology catch-all (the existing
/// `read_stage_refusal` precedent, with pool pressure named precisely
/// instead of folded into the catch-all).
fn k0_read_refusal(stage: ReadStage) -> SelectedDriverRefusal {
    match stage {
        ReadStage::Shape(ReaderShapeCause::BindingAbsent) => SelectedDriverRefusal::Detail(
            SelectedDetailRefusal::Gate(DetailToggleRefusal::BroadNotCounter),
        ),
        ReadStage::BankQuarantined => SelectedDriverRefusal::Detail(SelectedDetailRefusal::Gate(
            DetailToggleRefusal::Quarantined,
        )),
        ReadStage::Budget => {
            SelectedDriverRefusal::Detail(SelectedDetailRefusal::Gate(DetailToggleRefusal::Budget))
        }
        _ => SelectedDriverRefusal::Detail(SelectedDetailRefusal::BroadPlanTopology),
    }
}

/// Open the K0 window over an already-recorded resolution: validate
/// the selection-time witness facts, then observe the selection-time
/// broad read through a dedicated collector (`Initial` installs the
/// baseline). A failed read or unprovable witness records its mapped
/// refusal and opens nothing; aggregate capture is untouched.
/// Metrics-internal like the reads it observes: production enters
/// through [`open_k0_production`].
pub(super) fn open_k0_window(
    resolved: ResolvedSelection,
    limits: CounterLimits,
    reserve: SemanticResourceReserver,
    before: Result<CounterRead, ReadStage>,
    before_facts: K0Facts,
    ledger: &mut SelectionLedger,
) -> Option<K0Window> {
    let before_witness = match before_facts {
        Ok(Some(facts)) => facts,
        _ => {
            ledger.mark_selection_refused(
                SelectedDriverRefusal::Detail(SelectedDetailRefusal::BroadPlanTopology).name(),
            );
            return None;
        }
    };
    let mut collector = CounterCollector::new(limits, reserve);
    match collector.observe(before) {
        CounterObservation::Initial => {}
        CounterObservation::ReadFailed(stage) => {
            ledger.mark_selection_refused(k0_read_refusal(stage).name());
            return None;
        }
        // A first observation never advances (no baseline exists
        // yet) and never changes generation (none is installed);
        // both arms refuse closed if the collector ever says so.
        CounterObservation::Unavailable(_)
        | CounterObservation::GenerationChanged { .. }
        | CounterObservation::Advanced { .. } => {
            ledger.mark_selection_refused(
                SelectedDriverRefusal::Detail(SelectedDetailRefusal::BroadPlanTopology).name(),
            );
            return None;
        }
    }
    Some(K0Window {
        resolved,
        collector,
        before: before_witness,
        limits,
    })
}

/// Close the K0 window: close-boundary, slot-retirement,
/// exec-witness, and loss checks in contract order, then the close
/// read through the collector and the aggregate/detail render. Any
/// void records its named refusal; `lineage`, `aggregate` and
/// `detail` stay absent and the main report's aggregate alone
/// carries the capture. Metrics-internal like the reads it observes:
/// production enters through [`close_k0_production`].
#[cfg_attr(not(test), allow(dead_code))] // No-tail close for twins; production closes with its tail.
pub(super) fn close_k0_window(
    window: K0Window,
    close_plan: &AttachPlan,
    after: Result<CounterRead, ReadStage>,
    after_facts: K0Facts,
    clean_close: bool,
    ledger: &mut SelectionLedger,
) {
    close_k0_window_with_tail(
        window,
        close_plan,
        after,
        after_facts,
        clean_close,
        &[],
        0,
        ledger,
    );
}

/// Scan the shutdown-tail discovery records for a lifecycle hit on
/// the selected caller: an EXEC, a leader exit, or a tap fault
/// (malformed tail). PID-matched like the tap: other PIDs never hit.
/// An EXEC voids as caller-changed whatever its case (a faulting case
/// fails closed the same way); a leader exit voids as caller-retired
/// unless its timestamp is zero, which fails closed as caller-changed
/// like the tap's zero-timestamp fault. A malformed tail fails closed
/// as caller-changed: the witness would have faulted on it.
fn scan_k0_tail(
    pid: u32,
    records: &[DiscoveryRecord],
    malformed: u64,
) -> Option<SelectedDriverRefusal> {
    use SelectedDriverRefusal::Promotion;
    if malformed > 0 {
        return Some(Promotion(PromotionRefusal::CallerChanged));
    }
    let mut saw_exit = false;
    for record in records {
        if (record.pid_tgid >> 32) as u32 != pid {
            continue;
        }
        match record.kind {
            DISCOVERY_KIND_EXEC => {
                return Some(Promotion(PromotionRefusal::CallerChanged));
            }
            DISCOVERY_KIND_LEADER_EXIT => {
                if record.hook_ts_ns == 0 {
                    return Some(Promotion(PromotionRefusal::CallerChanged));
                }
                saw_exit = true;
            }
            _ => {}
        }
    }
    saw_exit.then_some(Promotion(PromotionRefusal::CallerRetired))
}

/// Close the K0 window with its shutdown-tail records: the shared
/// close body plus a PID-matched scan of the discovery records that
/// were staged during quiescence and drained in the terminal drain —
/// the tail the pre-quiescence witness snapshot cannot see. A tail
/// EXEC or fault voids as caller-changed, a tail leader exit as
/// caller-retired, in the witness step's contract position (after
/// retirement, before loss). Twins stage the tail directly;
/// production collects it from the terminal drains.
#[allow(clippy::too_many_arguments)] // One close over all retained inputs; twins drive it directly.
pub(super) fn close_k0_window_with_tail(
    window: K0Window,
    close_plan: &AttachPlan,
    after: Result<CounterRead, ReadStage>,
    after_facts: K0Facts,
    clean_close: bool,
    tail_records: &[DiscoveryRecord],
    tail_malformed: u64,
    ledger: &mut SelectionLedger,
) {
    use super::selected_detail::{render_aggregate_bracket, render_detail_rows};
    use SelectedDriverRefusal::{Detail, Promotion};
    let K0Window {
        resolved,
        mut collector,
        before,
        limits: _,
    } = window;
    if !clean_close {
        ledger.mark_selection_refused(
            Detail(SelectedDetailRefusal::Gate(
                DetailToggleRefusal::BroadStopping,
            ))
            .name(),
        );
        return;
    }
    let published = close_plan.slots.iter().any(|slot| {
        slot.index == resolved.slot
            && slot.object == resolved.physical.object
            && slot.file_offset == resolved.physical.file_offset
    });
    if !published {
        ledger.mark_selection_refused(
            Detail(SelectedDetailRefusal::Gate(
                DetailToggleRefusal::NotPublished,
            ))
            .name(),
        );
        return;
    }
    let after_witness = match after_facts {
        Ok(Some(facts)) => facts,
        _ => {
            ledger.mark_selection_refused(Promotion(PromotionRefusal::CallerChanged).name());
            return;
        }
    };
    if after_witness.fault_serial != before.fault_serial
        || after_witness.latest_exec != before.latest_exec
    {
        ledger.mark_selection_refused(Promotion(PromotionRefusal::CallerChanged).name());
        return;
    }
    if after_witness.greatest_break_ns != before.greatest_break_ns {
        ledger.mark_selection_refused(Promotion(PromotionRefusal::CallerRetired).name());
        return;
    }
    if let Some(refusal) = scan_k0_tail(resolved.original.pid(), tail_records, tail_malformed) {
        ledger.mark_selection_refused(refusal.name());
        return;
    }
    let mut deltas = match collector.observe(after) {
        CounterObservation::Advanced { deltas, .. } => deltas,
        CounterObservation::ReadFailed(stage) => {
            ledger.mark_selection_refused(k0_read_refusal(stage).name());
            return;
        }
        CounterObservation::Unavailable(_)
        | CounterObservation::GenerationChanged { .. }
        | CounterObservation::Initial => {
            ledger.mark_selection_refused(Detail(SelectedDetailRefusal::BroadPlanTopology).name());
            return;
        }
    };
    let current = collector
        .current()
        .expect("an advanced K0 collector holds its close read");
    let view = current.view();
    ledger.aggregate = Some(render_aggregate_bracket(&deltas, view.mode, 1, 2));
    deltas.retain_slot(resolved.slot);
    ledger.detail = Some(render_detail_rows(
        &deltas,
        view.mode,
        view.generation.get(),
    ));
}

/// One production K0 read off the broad banks: the binding comes only
/// from actual preparation, and a missing binding or a quarantined
/// broad maps to its own stage. Charges the caller's reserver — the
/// Engine's counter pool in production — exactly like a broad tick
/// read; no new pool, object, or reservation.
fn k0_broad_read(
    session: &Session,
    plan: &AttachPlan,
    pins: &PinnedObjects,
    limits: CounterLimits,
    reserve: &SemanticResourceReserver,
) -> Result<CounterRead, ReadStage> {
    let binding = session
        .counter_reader_binding()
        .map_err(|refusal| match refusal {
            BankRefusal::Quarantined => ReadStage::BankQuarantined,
            _ => ReadStage::BankRouting,
        })?;
    match binding {
        Some(binding) => super::counter_reader::read_bound(binding, plan, pins, limits, reserve),
        None => Err(ReadStage::Shape(ReaderShapeCause::BindingAbsent)),
    }
}

/// Production K0 open inside `capture_profile`: the selection-time
/// broad read plus the shared open body. Plain budget numbers cross
/// the metrics boundary (the limits type stays metrics-internal).
#[allow(clippy::too_many_arguments)] // One production open over all retained inputs; twins drive the core directly.
pub(crate) fn open_k0_production(
    resolved: ResolvedSelection,
    rows: usize,
    rv_keys: usize,
    reserve: SemanticResourceReserver,
    session: &Session,
    plan: &AttachPlan,
    pins: &PinnedObjects,
    before_facts: K0Facts,
    ledger: &mut SelectionLedger,
) -> Option<K0Window> {
    let limits = CounterLimits { rows, rv_keys };
    let before = k0_broad_read(session, plan, pins, limits, &reserve);
    open_k0_window(resolved, limits, reserve, before, before_facts, ledger)
}

/// Everything `run_terminal` needs to close an opened K0 window: the
/// window, the close witness facts snapshotted before quiescence, the
/// shutdown-tail discovery records drained after that snapshot, and
/// whether the close boundary is proven clean.
pub(crate) struct K0Close {
    pub(crate) window: K0Window,
    pub(crate) facts: K0Facts,
    pub(crate) clean: bool,
    pub(crate) tail_records: Vec<DiscoveryRecord>,
    pub(crate) tail_malformed: u64,
}

/// Production K0 close inside `run_terminal`: the close read off the
/// broad banks, then the shared close body with the tail. The close
/// read runs even when the boundary is unclean; the close body
/// discards it before observing and voids as broad-stopping.
pub(crate) fn close_k0_production(
    close: K0Close,
    session: &Session,
    plan: &AttachPlan,
    pins: &PinnedObjects,
    ledger: &mut SelectionLedger,
) {
    let K0Close {
        window,
        facts,
        clean,
        tail_records,
        tail_malformed,
    } = close;
    let after = k0_broad_read(
        session,
        plan,
        pins,
        window.limits,
        window.collector.reserver(),
    );
    close_k0_window_with_tail(
        window,
        plan,
        after,
        facts,
        clean,
        &tail_records,
        tail_malformed,
        ledger,
    );
}

/// Compose the additive `selected_detail` evidence object (M2
/// additive-first: this one object, no existing key touched):
/// `selection` (resolved slot or named refusal), `events` (window
/// and driver rows in tick order), `lineage` + `aggregate` (the
/// close products, absent without a close), `detail` (staged for
/// the counter-child future; absent until detail deltas record).
pub(crate) fn with_selected_detail(
    mut document: serde_json::Value,
    ledger: &SelectionLedger,
) -> serde_json::Value {
    let mut section = serde_json::Map::new();
    if let Some(selection) = ledger.selection.as_ref() {
        let mut record = serde_json::Map::new();
        record.insert(
            "endpoint".into(),
            serde_json::Value::String(selection.endpoint.clone()),
        );
        if let Some(slot) = selection.slot {
            record.insert("slot".into(), serde_json::json!(slot));
        }
        if let Some(offset) = selection.file_offset {
            record.insert("file_offset".into(), serde_json::json!(offset));
        }
        if !selection.names.is_empty() {
            record.insert("names".into(), serde_json::json!(selection.names));
        }
        if let Some(refusal) = selection.refusal {
            record.insert("refusal".into(), serde_json::json!(refusal));
        }
        section.insert("selection".into(), serde_json::Value::Object(record));
    }
    section.insert(
        "events".into(),
        serde_json::Value::Array(ledger.events.clone()),
    );
    for (key, fragment) in [
        ("lineage", &ledger.lineage),
        ("aggregate", &ledger.aggregate),
        ("detail", &ledger.detail),
    ] {
        if let Some(fragment) = fragment {
            section.insert(key.into(), fragment.clone());
        }
    }
    document["evidence"]
        .as_object_mut()
        .expect("capture renderer emits an evidence object")
        .insert("selected_detail".into(), serde_json::Value::Object(section));
    document
}

#[cfg(test)]
mod tests {
    use super::super::KernelEvidence;
    use super::super::counter_collector::{
        CounterCell, CounterCollector, CounterHealth, CounterLimits, CounterObservation,
        CounterRead, CounterRow, ReadReservation, ReadWindow,
    };
    use super::super::selected_detail::{BanksBroad, verify_reserve_inputs};
    use super::*;
    use crate::attach::counter_banks::tests::{
        stage_toggle_banks, toggle_object_plan, toggle_provider,
    };
    use crate::discovery::identity::PinnedObjectId;
    use crate::inventory_promotion::lifecycle::{
        SelectedActivationBinding, scripted_promotion_view_for_test,
        scripted_promotion_view_with_baseline_for_test,
    };
    use crate::inventory_promotion::{
        CaptureId, Promoter, PromotionCancel, PromotionEnd, PromotionRefusal, PromotionRequest,
        PromotionRequestError, PromotionState, PromotionView, SelectedEndpointReceipt,
        ViewRevision,
    };
    use crate::plan::Slot;
    use crate::semantics_edge::resources::SemanticResourcePool;
    use p11scope_ebpf_common::{CountStats, SlotStats, TimestampStats};
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;
    use std::time::{Duration, Instant};

    const BROAD_GENERATION: u64 = 7;

    fn test_pool() -> SemanticResourcePool {
        SemanticResourcePool::reference_limit(64 * 1024 * 1024)
    }

    fn limits_for(plan: &AttachPlan) -> CounterLimits {
        CounterLimits {
            rows: plan.slots.len(),
            rv_keys: 0,
        }
    }

    /// A real validated-shape read over `plan`: every row folded from
    /// explicit per-CPU cells through the genuine `CounterRow::fold`,
    /// packed through the genuine `CounterRead::new`. `counts`
    /// parallels `plan.slots`: (entered, returned, errors).
    fn scripted_read(
        pool: &SemanticResourcePool,
        plan: &AttachPlan,
        generation: NonZeroU64,
        mode: CounterMode,
        counts: &[(u64, u64, u64)],
        window: Option<ReadWindow>,
    ) -> CounterRead {
        assert_eq!(
            counts.len(),
            plan.slots.len(),
            "one explicit sample per plan slot"
        );
        let mut rows = Vec::with_capacity(plan.slots.len());
        let held_counts: Vec<CountStats> = counts
            .iter()
            .map(|&(entered, returned, errors)| CountStats {
                entered,
                returned,
                errors,
            })
            .collect();
        let held_timestamps: Vec<TimestampStats> = counts
            .iter()
            .map(|&(entered, returned, errors)| TimestampStats {
                entered,
                returned,
                errors,
                total_ns: 10 * returned,
                max_ns: u64::from(returned != 0) * 10,
            })
            .collect();
        let held_latency: Vec<SlotStats> = counts
            .iter()
            .map(|&(entered, returned, errors)| SlotStats {
                entered,
                returned,
                errors,
                total_ns: 10 * returned,
                max_ns: u64::from(returned != 0) * 10,
                buckets: [0; 32],
            })
            .collect();
        for (slot, index) in plan.slots.iter().zip(0..) {
            let cells: Vec<CounterCell<'_>> = match mode {
                CounterMode::Counts => {
                    vec![CounterCell::Counts(&held_counts[index])]
                }
                CounterMode::Timestamps => {
                    vec![CounterCell::Timestamps(&held_timestamps[index])]
                }
                CounterMode::Latency => {
                    vec![CounterCell::Latency(&held_latency[index])]
                }
            };
            rows.push(
                CounterRow::fold(slot, mode, cells, Vec::new(), limits_for(plan))
                    .expect("explicit cells fold"),
            );
        }
        let reservation =
            ReadReservation::reserve(rows.len(), 0, &pool.reserver()).expect("read reserves");
        CounterRead::new(
            generation,
            mode,
            window,
            Ok(rows),
            CounterHealth::default(),
            KernelEvidence::default(),
            reservation,
        )
        .expect("scripted read packs")
    }

    fn window_of(started: u64, finished: u64) -> Option<ReadWindow> {
        ReadWindow::new(Some(started), Some(finished))
    }

    fn counts_for(plan: &AttachPlan, entered: u64, returned: u64) -> Vec<(u64, u64, u64)> {
        vec![(entered, returned, 0); plan.slots.len()]
    }

    /// One staged broad capture: a real pinned provider file, a
    /// `Counters` plan over it, and banks staged through the genuine
    /// publication algorithm. The directory holds the scene alive.
    struct BroadScene {
        _dir: tempfile::TempDir,
        #[allow(dead_code)]
        path: std::path::PathBuf,
        objects: PinnedObjects,
        object: PinnedObjectId,
        plan: AttachPlan,
        banks: crate::attach::counter_banks::CounterBanks,
        pool: SemanticResourcePool,
    }

    fn stage_single_provider(pool: SemanticResourcePool, slots: u32) -> BroadScene {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"driver broad provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "Driver-digest",
        );
        let object = objects.pinned().next().unwrap().id;
        let mut plan = toggle_object_plan(object, slots);
        let banks = stage_toggle_banks(&pool, &objects, &mut plan);
        BroadScene {
            _dir: dir,
            path,
            objects,
            object,
            plan,
            banks,
            pool,
        }
    }

    /// Two provider files in one shared pin store, each with the same
    /// endpoint offsets, so file identity — never the offset alone —
    /// carries the distinction. Ids are read back after the merge,
    /// never assumed.
    struct MultiScene {
        _dir: tempfile::TempDir,
        objects: PinnedObjects,
        id_a: PinnedObjectId,
        id_b: PinnedObjectId,
        plan: AttachPlan,
        banks: crate::attach::counter_banks::CounterBanks,
        pool: SemanticResourcePool,
    }

    fn provider_slot(index: u32, object: PinnedObjectId, offset: u64, name: &str) -> Slot {
        Slot {
            index,
            descriptor_index: 0,
            object,
            object_path: "/multi-provider.so".into(),
            file_offset: offset,
            names: vec![name.into()],
            aliased: false,
            semantics: crate::kinds::DESCRIPTORS[0],
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![],
        }
    }

    fn stage_two_providers(pool: SemanticResourcePool) -> MultiScene {
        let dir = tempfile::tempdir().unwrap();
        let path_a = toggle_provider(&dir, "provider-a.so", b"provider A bytes for driver");
        let path_b = toggle_provider(&dir, "provider-b.so", b"provider B bytes for driver");
        let mut objects =
            crate::discovery::identity::test_fixture::real_scan_pin(&path_a, None, 1, "digest-a");
        let other =
            crate::discovery::identity::test_fixture::real_scan_pin(&path_b, None, 1, "digest-b");
        assert!(
            objects.absorb(other).is_empty(),
            "two distinct files merge without skips"
        );
        let mut id_a = None;
        let mut id_b = None;
        for pin in objects.pinned() {
            if pin.path.ends_with("provider-a.so") {
                id_a = Some(pin.id);
            } else if pin.path.ends_with("provider-b.so") {
                id_b = Some(pin.id);
            }
        }
        let (id_a, id_b) = (id_a.unwrap(), id_b.unwrap());
        assert_ne!(id_a, id_b, "two files pin as two objects");
        let mut plan = AttachPlan::from_slots_with_policy(
            vec![
                provider_slot(0, id_a, 0x80, "C_Sign"),
                provider_slot(1, id_a, 0x90, "C_Verify"),
                provider_slot(2, id_b, 0x80, "C_Sign"),
                provider_slot(3, id_b, 0x90, "C_Verify"),
            ],
            crate::plan::AdmissionPolicy::counters(
                crate::capacity::CounterBudget::new(8192).unwrap(),
            ),
        )
        .unwrap();
        let banks = stage_toggle_banks(&pool, &objects, &mut plan);
        MultiScene {
            _dir: dir,
            objects,
            id_a,
            id_b,
            plan,
            banks,
            pool,
        }
    }

    /// A proved request plus its preparation bundle, through the real
    /// guards: `Promoter::request_with_endpoint` verifies the pair
    /// against the immutable viewed frame, the pre-view baseline
    /// batch genuinely derives the image baseline for the live
    /// original, and the bundle carries scripted attach/convert
    /// envelopes over the provider's real pinned subset.
    struct PromotionScene {
        promoter: Promoter,
        request: PromotionRequest,
        bundle: crate::inventory_promotion::lifecycle::PreparationBundle,
    }

    fn promotion_scene(
        convert_plan: AttachPlan,
        convert_pins: PinnedObjects,
        required: PinnedObjectId,
        endpoint: Option<u64>,
        cookie: u64,
        exec_id: u64,
    ) -> PromotionScene {
        promotion_scene_with_required(
            convert_plan,
            convert_pins,
            BTreeMap::from([(required, BTreeSet::from([0]))]),
            endpoint,
            cookie,
            exec_id,
        )
    }

    fn promotion_scene_with_required(
        convert_plan: AttachPlan,
        convert_pins: PinnedObjects,
        required_map: BTreeMap<PinnedObjectId, BTreeSet<u32>>,
        endpoint: Option<u64>,
        cookie: u64,
        exec_id: u64,
    ) -> PromotionScene {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        let pin = Arc::new(crate::process::PidPin::open(std::process::id()).expect("self pins"));
        let custody = crate::process::WeakProcessCustody::pinned_for_test(&pin);
        let view = scripted_promotion_view_with_baseline_for_test(
            pin.pid(),
            pin.start_time(),
            1,
            custody,
            cookie,
            exec_id,
        );
        let mut promoter = Promoter::new();
        assert!(promoter.enable(crate::inventory_promotion::CaptureId::new(11)));
        match endpoint {
            Some(offset) => {
                let receipt = crate::inventory_promotion::SelectedEndpointReceipt::new(
                    view.revision(),
                    offset,
                );
                promoter
                    .request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), receipt)
                    .expect("exact pair with endpoint receipt queues");
            }
            None => {
                promoter
                    .request(Arc::clone(&view), CallerId(3), ModuleId(5))
                    .expect("exact legacy pair queues");
            }
        }
        let request = promoter.take_request().expect("mailbox holds it");
        let baseline = view
            .baseline()
            .expect("view carries its pre-view batch")
            .for_request(&request, &pin, 1)
            .expect("genuine baseline derivation");
        let bundle = crate::inventory_promotion::lifecycle::PreparationBundle {
            attach: crate::inventory_semantics::AttestedSubset::scripted(
                convert_plan.clone(),
                convert_pins.clone(),
                required_map.clone(),
            ),
            convert: crate::inventory_semantics::AttestedSubset::scripted(
                convert_plan,
                convert_pins,
                required_map,
            ),
            baseline,
            original: Arc::clone(&pin),
            parent: crate::attach::Scope::Pid(pin.pid()),
            backend: crate::attach::BackendSelection::Auto,
            window: crate::attach::capture::ReadWindow::new(
                1,
                Instant::now() + Duration::from_secs(30),
            )
            .expect("positive preparation window"),
        };
        PromotionScene {
            promoter,
            request,
            bundle,
        }
    }

    /// The convert envelope for one provider object: that provider's
    /// broad slots verbatim, reindexed dense.
    fn convert_for(plan: &AttachPlan, object: PinnedObjectId) -> AttachPlan {
        let mut slots: Vec<Slot> = plan
            .slots
            .iter()
            .filter(|slot| slot.object == object)
            .cloned()
            .collect();
        for (index, slot) in slots.iter_mut().enumerate() {
            slot.index = index as u32;
        }
        AttachPlan::from_slots(slots)
    }

    /// Counting inner activation source: records every CAS attempt
    /// through a shared counter. Production passes the genuine
    /// minter; twins assert zero attempts on every pre-CAS path.
    struct StubInner {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::inventory_promotion::lifecycle::NativeActivationSource for StubInner {
        fn activate(
            &mut self,
            _session: &crate::attach::Session,
            expected: &SelectedActivationBinding,
        ) -> Result<
            crate::inventory_promotion::lifecycle::NativeCasReceipt,
            crate::inventory_promotion::lifecycle::NativeActivationRefusal,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::inventory_promotion::lifecycle::NativeCasReceipt::scripted(*expected))
        }
    }

    fn stub_source() -> (Box<StubInner>, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Box::new(StubInner {
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }

    /// Genuine install capacity from a real (empty) coordinator: the
    /// reservation/charge path is real; only the coordinator is
    /// test-built.
    fn capacity() -> PromotionInstallCapacity {
        let coordinator =
            crate::discovery::engine::inventory_coordinator::InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                crate::discovery::caller_registry::OsProcessSource,
                crate::discovery::caller_registry::RegistryLimits::default_limits(),
            )
            .expect("test coordinator builds");
        coordinator
            .reserve_promotion_install()
            .expect("test capacity reserves")
    }

    /// Poll the driver until it emits an event or the bound lapses.
    /// Twins rendezvous on emitted events, never on naked sleeps.
    fn driver_poll_until(driver: &mut PromotionDriver, bound: Duration) -> Option<DriverEvent> {
        let deadline = Instant::now() + bound;
        let mut sink = std::io::sink();
        loop {
            if let Some(event) = driver.poll(&mut sink) {
                return Some(event);
            }
            assert!(
                Instant::now() < deadline,
                "driver emitted no event within the bound"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn broad_generation() -> NonZeroU64 {
        NonZeroU64::new(BROAD_GENERATION).unwrap()
    }

    fn expected_binding(
        domain: crate::attach::capture::NativeDomainId,
        generation: u64,
        cookie: u64,
        exec_id: u64,
    ) -> SelectedActivationBinding {
        SelectedActivationBinding::new(
            domain,
            generation,
            p11scope_ebpf_common::ImageIdentity {
                task_cookie: cookie,
                exec_id,
            },
        )
    }

    /// A scripted sealed lane over the scene's convert envelope plus
    /// a scripted permit: reclaim-path scenes only (I4) — the lane
    /// must dispose, never install.
    fn scripted_lane_for(
        proved: &PromotionScene,
        binding: SelectedActivationBinding,
    ) -> crate::inventory_semantics::selected::ProvisionalSelectedLane {
        let shell = crate::inventory_semantics::AttestedSemanticLane::start(
            crate::inventory_semantics::AttestedSubset::scripted(
                proved.bundle.convert_subset().plan().clone(),
                proved.bundle.convert_subset().pins().clone(),
                proved.bundle.convert_subset().required().clone(),
            ),
            &crate::attach::Scope::Pid(std::process::id()),
            crate::attach::BackendSelection::Auto,
        )
        .expect("scripted subset forms a shell lane");
        let permit =
            crate::attach::selected_detailed::SelectedConstructionPermit::scripted_for_test(
                crate::events::EventsDomain::test_standin(0x70),
                Arc::clone(&proved.bundle.original),
                crate::attach::Scope::Pid(proved.bundle.original.pid()),
                binding.domain(),
                binding.image(),
                binding.generation(),
                proved.bundle.baseline.clone(),
            );
        crate::inventory_semantics::selected::ProvisionalSelectedLane::scripted_for_test(
            shell, permit,
        )
    }

    /// A posed install handoff over the scene's sealed lane for the
    /// given binding: reclaim-path scenes only (I4) — the handoff
    /// must dispose, never install.
    fn scripted_pending_for(
        proved: &PromotionScene,
        binding: SelectedActivationBinding,
    ) -> crate::inventory_promotion::lifecycle::PendingInstall {
        use crate::inventory_promotion::lifecycle::{PendingInstall, SelectedActivationProof};
        let lane = scripted_lane_for(proved, binding);
        let proof = SelectedActivationProof::mint(
            &proved.request,
            binding,
            crate::inventory_promotion::lifecycle::NativeCasReceipt::scripted(binding),
        )
        .expect("matching receipt mints");
        PendingInstall::from_parts(proof, lane, capacity())
    }

    fn settled_failure() -> crate::inventory_promotion::lifecycle::PreparationOutcome {
        crate::inventory_promotion::lifecycle::PreparationOutcome::Failed(
            crate::attach::selected_detailed::SelectedPreparationFailure::scripted_settled(),
        )
    }

    #[test]
    fn resolve_selection_matches_exactly_one_plan_slot_by_name() {
        // 6.15 stage 0 through the real invoked path: the CLI name
        // resolves against the LIVE plan's names — exactly one slot
        // or a named refusal, never first-match. An aliased slot
        // resolves as its whole group (the gate binds the slot, so
        // the report carries every name resolving there).
        let pool = test_pool();
        let scene = stage_single_provider(pool, 8);
        let scope = Scope::Pid(std::process::id());
        let resolved =
            resolve_selection("C_Toggle0007", &scene.plan, &scope).expect("one live slot resolves");
        assert_eq!(resolved.slot, 7);
        assert_eq!(resolved.physical.object, scene.object);
        assert_eq!(resolved.physical.file_offset, 0x80 + 7 * 0x10);
        assert_eq!(resolved.names, vec!["C_Toggle0007".to_string()]);
        assert_eq!(resolved.original.pid(), std::process::id());

        let unknown = resolve_selection("C_NoSuchEndpoint", &scene.plan, &scope).unwrap_err();
        assert_eq!(unknown, SelectedDriverRefusal::EndpointUnknown);
        assert_eq!(unknown.name(), "endpoint_unknown");
        let empty = resolve_selection("", &scene.plan, &scope).unwrap_err();
        assert_eq!(empty, SelectedDriverRefusal::EndpointUnknown);

        let pool = test_pool();
        let multi = stage_two_providers(pool);
        let ambiguous = resolve_selection("C_Sign", &multi.plan, &scope).unwrap_err();
        assert_eq!(
            ambiguous,
            SelectedDriverRefusal::Promotion(PromotionRefusal::EndpointAmbiguous)
        );

        let mut aliased = multi.plan.clone();
        aliased.slots[0].names = vec!["C_Sign".into(), "C_SignAlias".into()];
        aliased.slots[0].aliased = true;
        aliased.slots.truncate(1);
        let grouped = resolve_selection("C_SignAlias", &aliased, &scope).expect("group resolves");
        assert_eq!(grouped.slot, 0);
        assert_eq!(grouped.names.len(), 2);
    }

    #[test]
    fn resolve_selection_pins_pid_original_and_refuses_other_shapes() {
        // Only `--pid` (and the owned run child, which is a pid scope
        // too) resolves to one live original: the pin opens live and
        // re-checks liveness. Cgroup/system scopes cannot name one
        // original; a non-`Counters` plan is a topology refusal, never
        // an adaptation.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let live = resolve_selection("C_Toggle0001", &scene.plan, &Scope::Pid(std::process::id()))
            .expect("live pid pins");
        assert_eq!(live.original.pid(), std::process::id());

        let no_such =
            resolve_selection("C_Toggle0001", &scene.plan, &Scope::Pid(u32::MAX)).unwrap_err();
        assert_eq!(
            no_such,
            SelectedDriverRefusal::Promotion(PromotionRefusal::UnknownCaller)
        );
        let system = resolve_selection("C_Toggle0001", &scene.plan, &Scope::System).unwrap_err();
        assert_eq!(
            system,
            SelectedDriverRefusal::Promotion(PromotionRefusal::ScopeUnsupported)
        );
        let dir = tempfile::tempdir().unwrap();
        let held =
            std::sync::Arc::new(std::fs::File::open(dir.path()).expect("cgroup stand-in opens"));
        let cgroup = resolve_selection(
            "C_Toggle0001",
            &scene.plan,
            &Scope::Cgroup {
                id: 7,
                path: dir.path().to_path_buf(),
                dir: held,
            },
        )
        .unwrap_err();
        assert_eq!(
            cgroup,
            SelectedDriverRefusal::Promotion(PromotionRefusal::ScopeUnsupported)
        );
        let detailed = AttachPlan::from_slots(scene.plan.slots.clone());
        let topology =
            resolve_selection("C_Toggle0001", &detailed, &Scope::Pid(std::process::id()))
                .unwrap_err();
        assert_eq!(
            topology,
            SelectedDriverRefusal::Detail(SelectedDetailRefusal::BroadPlanTopology)
        );
    }

    #[test]
    fn metrics_selection_stage_records_resolution_for_k0_window() {
        // The production metrics call-site through the real invoked
        // path: resolve genuinely and record the selection or its
        // named refusal. A resolution carries no refusal yet: the K0
        // open follows, and the close records the detail or its void.
        // The composer adds exactly one evidence object and touches
        // nothing else.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let scope = Scope::Pid(std::process::id());
        let mut ledger = SelectionLedger::new();
        let resolved =
            run_metrics_selection_stage("C_Toggle0002", &scene.plan, &scope, &mut ledger)
                .expect("live name resolves for the K0 window");
        assert_eq!(resolved.slot, 2);
        assert_eq!(
            resolved.original.pid(),
            std::process::id(),
            "the pin stays private with the resolution"
        );
        let record = ledger.selection.as_ref().expect("selection records");
        assert_eq!(record.endpoint, "C_Toggle0002");
        assert_eq!(record.slot, Some(2));
        assert_eq!(record.refusal, None, "resolution alone refuses nothing");
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let resolved_record = composed["evidence"]["selected_detail"]["selection"]
            .as_object()
            .expect("resolved selection composes");
        assert!(
            resolved_record.get("original_pid").is_none(),
            "no raw PID publishes: {resolved_record:?}"
        );
        assert_eq!(
            resolved_record.len(),
            4,
            "resolved selection carries exactly its closed keys: {resolved_record:?}"
        );
        for key in ["endpoint", "slot", "file_offset", "names"] {
            assert!(
                resolved_record.contains_key(key),
                "resolved selection names {key}: {resolved_record:?}"
            );
        }

        let mut refused = SelectionLedger::new();
        let none = run_metrics_selection_stage("C_Missing", &scene.plan, &scope, &mut refused);
        assert!(none.is_none(), "unknown names resolve to nothing");
        let record = refused.selection.as_ref().expect("refusal records");
        assert_eq!(record.slot, None);
        assert_eq!(record.refusal, Some("endpoint_unknown"));

        let document = serde_json::json!({
            "schema": "p11scope/observed-profile/v3-metrics",
            "evidence": {"counter_collection": {"state": "COMPLETE"}},
        });
        let composed = with_selected_detail(document.clone(), &refused);
        assert_eq!(
            composed["schema"], document["schema"],
            "composer touches no existing key"
        );
        assert_eq!(
            composed["evidence"]["counter_collection"], document["evidence"]["counter_collection"],
            "existing evidence survives verbatim"
        );
        let section = &composed["evidence"]["selected_detail"];
        assert_eq!(
            section["selection"]["endpoint"],
            serde_json::json!("C_Missing")
        );
        assert_eq!(
            section["selection"]["refusal"],
            serde_json::json!("endpoint_unknown")
        );
        assert!(section["selection"].get("original_pid").is_none());
        let unresolved = section["selection"]
            .as_object()
            .expect("unresolved selection composes");
        assert_eq!(
            unresolved.len(),
            2,
            "unresolved selection carries exactly its closed keys: {unresolved:?}"
        );
        assert!(section.get("lineage").is_none());
        assert!(section.get("aggregate").is_none());
        assert!(section.get("detail").is_none());
    }

    #[test]
    fn promotion_driver_select_cancel_reselect_conserves_both_ledgers() {
        // Real counter → selection → cancel/reselect through the
        // driver: the first attempt reserves and its worker fails
        // (no delivery, no CAS); the reselect reserves again on the
        // capture-monotonic seq, then cancels before delivery (no
        // CAS, cancelled_unactivated row). Both ledgers conserve:
        // bracket seqs order, charges return to baseline, custody
        // drains, and the report carries no combined totals.
        use crate::attach::counter_banks::BroadToggleFacts;
        use crate::inventory_promotion::PromotionOutcome;
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let convert = convert_for(&scene.plan, scene.object);
        let mut proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x90),
            0xC00,
            0xE9E,
        );
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let charged_baseline = scene.pool.snapshot().charged_bytes;
        let rows = scene.plan.slots.len();

        // Attempt 1: reserve, then the worker fails outright.
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 5),
            window_of(10, 20),
        );
        let accepted = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                Ok(before),
                rows,
                0,
                &scene.pool,
            )
            .expect("proved request reserves");
        assert_eq!(accepted.seq, 1);
        assert!(
            accepted.deltas().is_none(),
            "a fresh window opens no interval"
        );
        let (inner, calls) = stub_source();
        driver
            .start(
                proved.request,
                &proved.bundle,
                capacity(),
                inner,
                settled_failure,
            )
            .expect("idle service starts");
        let DriverEvent::Status(update) =
            driver_poll_until(&mut driver, Duration::from_secs(30)).expect("failure settles")
        else {
            panic!("a failed worker never installs");
        };
        assert!(
            matches!(
                update.outcome,
                PromotionOutcome::Refused {
                    reason: PromotionRefusal::PreparationFailed,
                }
            ),
            "failed preparation refuses by name: {:?}",
            update.outcome
        );
        proved.promoter.set_status(update);
        assert!(driver.is_idle(), "settled failure idles the service");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no delivery, no CAS"
        );

        // Reselect on the same driver: the fresh request reserves on
        // the continued seq, then cancels before delivery.
        let mut proved2 = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x90),
            0xC01,
            0xE9F,
        );
        let before2 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(30, 40),
        );
        let accepted2 = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved2.request,
                &proved2.bundle,
                Ok(before2),
                rows,
                0,
                &scene.pool,
            )
            .expect("reselect reserves after the orphan drained");
        assert_eq!(accepted2.seq, 2, "bracket seqs continue across reselect");
        let (tx, rx) =
            std::sync::mpsc::channel::<crate::inventory_promotion::lifecycle::PreparationOutcome>();
        let (inner2, calls2) = stub_source();
        driver
            .start(
                proved2.request,
                &proved2.bundle,
                capacity(),
                inner2,
                move || rx.recv().expect("gated delivery"),
            )
            .expect("reselect starts");
        driver.cancel(PromotionEnd::Cancelled);
        tx.send(settled_failure())
            .expect("cancelled delivery lands");
        let DriverEvent::Status(update2) =
            driver_poll_until(&mut driver, Duration::from_secs(30)).expect("cancel settles")
        else {
            panic!("cancel before delivery never installs");
        };
        assert!(
            matches!(
                update2.outcome,
                PromotionOutcome::Ended {
                    reason: PromotionEnd::Cancelled,
                }
            ),
            "cancel confirms by name: {:?}",
            update2.outcome
        );
        proved2.promoter.set_status(update2);
        assert_eq!(
            calls2.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "cancel before delivery skips the CAS"
        );

        // Both ledgers conserve: window rows order, charges return,
        // and nothing sums the ledgers.
        let events = &driver.ledger().events;
        let names: Vec<&str> = events
            .iter()
            .map(|row| row["event"].as_str().unwrap_or("<?>"))
            .collect();
        assert_eq!(
            names,
            vec![
                "reserved",
                "promotion_outcome",
                "reserved",
                "cancelled_unactivated",
                "promotion_outcome",
            ],
            "window rows order across reselect: {names:?}"
        );
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged_baseline,
            "abandoned reservations release every charge"
        );
        assert!(
            events.iter().all(|row| row.get("total").is_none()),
            "no combined totals anywhere: {events:?}"
        );
        // A third reserve still works: custody drained, nothing wedged.
        let proved3 = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x90),
            0xC02,
            0xEA0,
        );
        let before3 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 11, 11),
            window_of(50, 60),
        );
        let accepted3 = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved3.request,
                &proved3.bundle,
                Ok(before3),
                rows,
                0,
                &scene.pool,
            )
            .expect("custody drains across attempts");
        assert_eq!(accepted3.seq, 3);
    }

    #[test]
    fn promotion_driver_held_return_brackets_window_without_transfer() {
        // A call that enters before the window and returns inside it
        // is bracketed, never transferred: the entry stays in its own
        // interval, the return lands in the window delta, and
        // unrelated slots keep their full counts on their own terms.
        // The window stages through the real adapter body (bind
        // downstream of a genuine reservation); the close, ledger and
        // composer under test are the driver's.
        use super::super::selected_detail::reserve_detail_window_on_banks_collecting;
        use crate::attach::counter_banks::BroadToggleFacts;
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let convert = convert_for(&scene.plan, scene.object);
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x90),
            0xC00,
            0xE9E,
        );
        let facts = BroadToggleFacts {
            generation: broad_generation(),
            stopped: false,
        };
        let custody = DetailWindowCustody::new();
        let mut brackets = BroadBracketCollector::new(4, 0, scene.pool.reserver());
        let mut seq = 0u64;
        // Slot 1 holds one entered-but-unreturned call at the before
        // mark; every other slot is quiet.
        let mut held = counts_for(&scene.plan, 0, 0);
        held[1] = (1, 0, 0);
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &held,
            window_of(10, 20),
        );
        let accepted = reserve_detail_window_on_banks_collecting(
            &scene.banks,
            facts,
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &mut brackets,
            &mut seq,
            Ok(before),
            &scene.pool.reserver(),
            &custody,
        )
        .expect("held call reserves");
        assert_eq!(accepted.seq, 1);
        let reservation = custody.take_reserved().expect("reservation parks");
        let window = reservation.bind_generation(9);
        let mut driver = PromotionDriver::new();
        driver.stage_open_window_for_test(window, brackets, seq, proved.request);
        // The held call returns inside the window while unrelated
        // slots run three full calls each.
        let mut after = counts_for(&scene.plan, 3, 3);
        after[1] = (1, 1, 0);
        let after_read = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &after,
            window_of(30, 40),
        );
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts,
        };
        let report = driver
            .close(&broad, &scene.plan, CounterMode::Counts, Ok(after_read))
            .expect("ordered close delivers lineage");
        assert_eq!((report.seq_before, report.seq_after), (1, 2));
        assert_eq!(report.lineage.broad_original_index, 1);
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), driver.ledger());
        let section = &composed["evidence"]["selected_detail"];
        let aggregate = &section["aggregate"];
        assert_eq!(aggregate["rows"][1]["entered"], serde_json::json!(0));
        assert_eq!(aggregate["rows"][1]["returned"], serde_json::json!(1));
        assert_eq!(aggregate["rows"][0]["entered"], serde_json::json!(3));
        assert_eq!(aggregate["rows"][0]["returned"], serde_json::json!(3));
        assert!(aggregate.get("total").is_none());
        // The staged detail span renders beside it through the real
        // detail renderer: the collector observes two genuine reads
        // over the convert envelope and the interval — same endpoint,
        // separate units — is never summed with the aggregate.
        let convert_plan = proved.bundle.convert_subset().plan().clone();
        let mut detail_collector =
            CounterCollector::new(limits_for(&convert_plan), scene.pool.reserver());
        let detail_first = scripted_read(
            &scene.pool,
            &convert_plan,
            NonZeroU64::new(9).unwrap(),
            CounterMode::Counts,
            &counts_for(&convert_plan, 0, 0),
            window_of(10, 20),
        );
        assert!(matches!(
            detail_collector.observe(Ok(detail_first)),
            CounterObservation::Initial
        ));
        let mut detail_counts = counts_for(&convert_plan, 0, 0);
        detail_counts[1] = (0, 1, 0);
        let detail_second = scripted_read(
            &scene.pool,
            &convert_plan,
            NonZeroU64::new(9).unwrap(),
            CounterMode::Counts,
            &detail_counts,
            window_of(20, 30),
        );
        let CounterObservation::Advanced { deltas, .. } =
            detail_collector.observe(Ok(detail_second))
        else {
            panic!("the detail interval advances");
        };
        driver.record_detail(&deltas, CounterMode::Counts, 9);
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), driver.ledger());
        let detail_rows = &composed["evidence"]["selected_detail"]["detail"];
        assert_eq!(detail_rows["rows"][1]["returned"], serde_json::json!(1));
        assert!(detail_rows.get("total").is_none());
    }

    #[test]
    fn promotion_driver_install_confirm_reports_active_for_the_exact_pair() {
        // O9 install-confirm leg: after a genuine reservation, the
        // Installing arrival is posed (the worker + poll + CAS + mint
        // chain that yields DriverEvent::Install is unrunnable
        // unprivileged — see seed_installing_for_test); the
        // confirmation under test is genuine: note_installed emits
        // Active for exactly the held request's pair, records the
        // "active" row, and idles the service. The window-open half —
        // poll's Install arm taking custody bound — needs a genuine
        // Ready and stays with the host composition: the reservation
        // parks untouched here.
        use crate::attach::counter_banks::BroadToggleFacts;
        use crate::inventory_promotion::PromotionOutcome;
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let convert = convert_for(&scene.plan, scene.object);
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x90),
            0xC00,
            0xE9E,
        );
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let rows = scene.plan.slots.len();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 5),
            window_of(10, 20),
        );
        let accepted = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                Ok(before),
                rows,
                0,
                &scene.pool,
            )
            .expect("proved request reserves");
        assert_eq!(accepted.seq, 1);
        let (caller, provider) = (proved.request.caller().0, proved.request.provider().0);
        let request_id = proved.request.id();
        driver.seed_installing_for_test(proved.request);
        let update = driver
            .note_installed()
            .expect("outstanding install confirms");
        assert_eq!(update.request, request_id);
        assert!(
            matches!(
                update.outcome,
                PromotionOutcome::Active { pair }
                    if pair.caller() == caller && pair.provider() == provider
            ),
            "Active names exactly the held pair: {:?}",
            update.outcome
        );
        assert!(driver.is_idle(), "confirm releases the service");
        assert!(
            driver.note_installed().is_none(),
            "confirm fires once: no outstanding install remains"
        );
        let events = &driver.ledger().events;
        let names: Vec<&str> = events
            .iter()
            .map(|row| row["event"].as_str().unwrap_or("<?>"))
            .collect();
        assert_eq!(
            names,
            vec!["reserved", "promotion_outcome"],
            "confirm records beside the reservation: {names:?}"
        );
        let outcome = events
            .iter()
            .find(|row| row["event"] == "promotion_outcome")
            .expect("the active row records");
        assert_eq!(outcome["outcome"], serde_json::json!("active"));
        assert_eq!(outcome["caller"], serde_json::json!(caller));
        assert_eq!(outcome["provider"], serde_json::json!(provider));
        assert!(
            outcome.get("total").is_none(),
            "no combined totals: {outcome:?}"
        );
        // The window-open half stays parked: only poll's Install arm
        // (genuine Ready, host composition) takes custody bound.
        assert_eq!(driver.reserved_for, Some(request_id));
        assert!(driver.open_window.is_none());
    }

    #[test]
    fn promotion_driver_shared_target_second_request_stays_aggregate_only() {
        // One open window per broad: while provider A holds the
        // window, provider B's identical-offset endpoint refuses
        // `WindowActive` and keeps serving exact aggregate counts
        // (nothing held, nothing diverted). After the first window
        // winds down, the second endpoint reserves cleanly.
        use crate::attach::counter_banks::BroadToggleFacts;
        use crate::inventory_promotion::PromotionOutcome;
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut proved_a = promotion_scene(
            convert_for(&scene.plan, scene.id_a),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let proved_b = promotion_scene(
            convert_for(&scene.plan, scene.id_b),
            scene.objects.clone(),
            scene.id_b,
            Some(0x80),
            0xC01,
            0xE9F,
        );
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let rows = scene.plan.slots.len();
        let before_a = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 4, 4),
            window_of(10, 20),
        );
        driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_a.request,
                &proved_a.bundle,
                Ok(before_a),
                rows,
                0,
                &scene.pool,
            )
            .expect("first endpoint reserves");
        let before_b = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 6, 6),
            window_of(20, 30),
        );
        let refused = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_b.request,
                &proved_b.bundle,
                Ok(before_b),
                rows,
                0,
                &scene.pool,
            )
            .unwrap_err();
        assert_eq!(
            refused.refusal,
            SelectedDetailRefusal::WindowActive,
            "the shared gate refuses the second window"
        );
        assert!(
            refused.bracket.is_none(),
            "a pre-acceptance refusal mints no receipt"
        );
        // B's aggregate is intact and exact: a fresh collector over
        // two genuine reads shows every count on its own terms.
        let mut aggregate = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        let base = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 6, 6),
            window_of(20, 30),
        );
        assert!(matches!(
            aggregate.observe(Ok(base)),
            CounterObservation::Initial
        ));
        let live = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(30, 40),
        );
        let CounterObservation::Advanced { deltas, .. } = aggregate.observe(Ok(live)) else {
            panic!("aggregate advances beside the open window");
        };
        assert_eq!((deltas[2].entered, deltas[2].returned), (3, 3));
        // The first window winds down (cancel → settle → abandon);
        // then the second endpoint reserves on the continued seq.
        let (inner, _) = stub_source();
        driver
            .start(
                proved_a.request,
                &proved_a.bundle,
                capacity(),
                inner,
                settled_failure,
            )
            .expect("first attempt starts");
        driver.cancel(PromotionEnd::Cancelled);
        let DriverEvent::Status(update) =
            driver_poll_until(&mut driver, Duration::from_secs(30)).expect("cancel settles")
        else {
            panic!("cancel before delivery never installs");
        };
        assert!(matches!(
            update.outcome,
            PromotionOutcome::Ended {
                reason: PromotionEnd::Cancelled,
            }
        ));
        proved_a.promoter.set_status(update);
        let before_b2 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 12, 12),
            window_of(40, 50),
        );
        let accepted_b = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_b.request,
                &proved_b.bundle,
                Ok(before_b2),
                rows,
                0,
                &scene.pool,
            )
            .expect("admission releases after wind-down");
        assert_eq!(accepted_b.seq, 2);
    }

    #[test]
    fn promotion_driver_capacity_and_gate_refusals_lose_nothing() {
        // The refusal matrix through the driver: every refusal names
        // itself in the ledger, releases its charges, mints nothing
        // it cannot honor, and leaves a clean reselect. Pre-start
        // gates refuse before any worker spawns (no wasted
        // preparation); post-acceptance gate refusals carry their
        // bracket for aggregate rendering.
        use crate::attach::counter_banks::{BroadToggleFacts, DetailToggleRefusal};
        use crate::inventory_promotion::PromotionOutcome;
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let rows = scene.plan.slots.len();
        let mut driver = PromotionDriver::new();

        // (a) Start without reserve: the worker fails, nothing was
        // ever held, and the ledger shows only the outcome.
        let proved = promotion_scene(
            convert_for(&scene.plan, scene.id_a),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let (inner, calls) = stub_source();
        driver
            .start(
                proved.request,
                &proved.bundle,
                capacity(),
                inner,
                settled_failure,
            )
            .expect("vacant custody still runs the worker path");
        let DriverEvent::Status(update) =
            driver_poll_until(&mut driver, Duration::from_secs(30)).expect("failure settles")
        else {
            panic!("a failed worker never installs");
        };
        assert!(matches!(
            update.outcome,
            PromotionOutcome::Refused {
                reason: PromotionRefusal::PreparationFailed,
            }
        ));
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no delivery, no CAS"
        );
        let names: Vec<&str> = driver
            .ledger()
            .events
            .iter()
            .map(|row| row["event"].as_str().unwrap_or("<?>"))
            .collect();
        assert_eq!(
            names,
            vec!["promotion_outcome"],
            "no reservation, no window rows: {names:?}"
        );

        // (b) A two-provider bundle refuses at the pre-start gate
        // before any worker spawns.
        let two_provider = promotion_scene_with_required(
            convert_for(&scene.plan, scene.id_a),
            scene.objects.clone(),
            BTreeMap::from([
                (scene.id_a, BTreeSet::from([0])),
                (scene.id_b, BTreeSet::from([0])),
            ]),
            Some(0x80),
            0xC01,
            0xE9F,
        );
        let spawned = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let spawned_worker = Arc::clone(&spawned);
        let (inner_b, _) = stub_source();
        let refused = driver
            .start(
                two_provider.request,
                &two_provider.bundle,
                capacity(),
                inner_b,
                move || {
                    spawned_worker.store(true, std::sync::atomic::Ordering::SeqCst);
                    settled_failure()
                },
            )
            .unwrap_err();
        assert_eq!(refused, PromotionRefusal::EndpointAmbiguous);
        assert!(
            !spawned.load(std::sync::atomic::Ordering::SeqCst),
            "gated starts spawn no worker"
        );
        assert!(driver.is_idle());

        // (c) The same shape refuses at reserve (pre-acceptance: no
        // receipt, no seq), then a proved request reserves cleanly.
        let two_provider_c = promotion_scene_with_required(
            convert_for(&scene.plan, scene.id_a),
            scene.objects.clone(),
            BTreeMap::from([
                (scene.id_a, BTreeSet::from([0])),
                (scene.id_b, BTreeSet::from([0])),
            ]),
            Some(0x80),
            0xC01,
            0xE9F,
        );
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 2, 2),
            window_of(10, 20),
        );
        let refused = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &two_provider_c.request,
                &two_provider_c.bundle,
                Ok(before),
                rows,
                0,
                &scene.pool,
            )
            .unwrap_err();
        assert_eq!(refused.refusal, SelectedDetailRefusal::EndpointUnresolved);
        assert!(refused.bracket.is_none());
        let proved2 = promotion_scene(
            convert_for(&scene.plan, scene.id_a),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC02,
            0xEA0,
        );
        let before2 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 3),
            window_of(20, 30),
        );
        let accepted = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved2.request,
                &proved2.bundle,
                Ok(before2),
                rows,
                0,
                &scene.pool,
            )
            .expect("clean reselect after refusals");
        assert_eq!(accepted.seq, 1, "refusals minted no seq");

        // (d) Quarantined banks refuse post-acceptance: the bracket
        // carries its interval, the charge is refunded.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        scene.banks.poison_directory_for_test();
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let proved = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let charged = scene.pool.snapshot().charged_bytes;
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 2, 2),
            window_of(10, 20),
        );
        let refused = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                Ok(before),
                rows,
                0,
                &scene.pool,
            )
            .unwrap_err();
        assert_eq!(
            refused.refusal,
            SelectedDetailRefusal::Gate(DetailToggleRefusal::Quarantined)
        );
        let bracket = refused
            .bracket
            .as_ref()
            .expect("post-acceptance refusal carries its bracket");
        assert_eq!(bracket.seq, 1);
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged,
            "refused reserves refund every charge"
        );

        // (e) A stopping broad refuses the same way.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut driver = PromotionDriver::new();
        let stopping = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: true,
            },
        };
        let proved = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 2, 2),
            window_of(10, 20),
        );
        let refused = driver
            .reserve(
                &stopping,
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                Ok(before),
                rows,
                0,
                &scene.pool,
            )
            .unwrap_err();
        assert_eq!(
            refused.refusal,
            SelectedDetailRefusal::Gate(DetailToggleRefusal::BroadStopping)
        );
        assert!(refused.bracket.is_some());
        // (`NotPublished`/`Foreign`/`Changed`/`Budget` ride the same
        // driver passthrough; the adapter twins pin each gate word.)
    }

    #[test]
    fn promotion_driver_stop_races_disclose_once_and_never_install() {
        // Stop during preparation: the worker runs to its genuine
        // end, its outcome is disposed (never CASed), and the stop
        // confirms exactly once with the orphan abandoned.
        use crate::attach::counter_banks::BroadToggleFacts;
        use crate::inventory_promotion::PromotionOutcome;
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let convert = convert_for(&scene.plan, scene.object);
        let mut proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let rows = scene.plan.slots.len();

        // (a) Stop lands while the worker is still preparing.
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 5),
            window_of(10, 20),
        );
        driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                Ok(before),
                rows,
                0,
                &scene.pool,
            )
            .expect("stop race reserves");
        let (tx, rx) =
            std::sync::mpsc::channel::<crate::inventory_promotion::lifecycle::PreparationOutcome>();
        let (inner, calls) = stub_source();
        driver
            .start(
                proved.request,
                &proved.bundle,
                capacity(),
                inner,
                move || rx.recv().expect("gated delivery"),
            )
            .expect("stop race starts");
        driver.cancel(PromotionEnd::RunStopped);
        tx.send(settled_failure()).expect("stopped delivery lands");
        let DriverEvent::Status(update) =
            driver_poll_until(&mut driver, Duration::from_secs(30)).expect("stop settles")
        else {
            panic!("a stopped worker never installs");
        };
        assert!(
            matches!(
                update.outcome,
                PromotionOutcome::Ended {
                    reason: PromotionEnd::RunStopped,
                }
            ),
            "stop confirms by name: {:?}",
            update.outcome
        );
        assert!(proved.promoter.set_status(update).is_some());
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "stop before delivery skips the CAS"
        );
        let mut sink = std::io::sink();
        assert!(
            driver.poll(&mut sink).is_none(),
            "the stop discloses exactly once"
        );
        let names: Vec<&str> = driver
            .ledger()
            .events
            .iter()
            .map(|row| row["event"].as_str().unwrap_or("<?>"))
            .collect();
        assert_eq!(
            names,
            vec!["reserved", "cancelled_unactivated", "promotion_outcome"],
            "stop rows order: {names:?}"
        );
    }

    #[test]
    fn promotion_driver_refused_binding_transfers_parked_window_to_close() {
        // An activation refusal parks its bound window in custody
        // BEFORE the terminal status: the status transfers the
        // parked window to the pending-close context (never strands
        // it), and the close records the terminal result — one
        // outcome row, one close row, released charges and admission,
        // and a reselect that succeeds.
        use crate::attach::counter_banks::BroadToggleFacts;
        use crate::inventory_promotion::PromotionOutcome;
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let rows = scene.plan.slots.len();
        let proved_b1 = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x80),
            0xC01,
            0xE9F,
        );
        let charged_b1 = scene.pool.snapshot().charged_bytes;
        let before_b1 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 7, 7),
            window_of(50, 60),
        );
        driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_b1.request,
                &proved_b1.bundle,
                Ok(before_b1),
                rows,
                0,
                &scene.pool,
            )
            .expect("refusal scene reserves");
        // The CAS seam's park, through the driver's own custody: take
        // the reservation once, bind its sealed generation, park
        // Unactivated — exactly the state a binding refusal leaves.
        let reservation = driver.custody.take_reserved().expect("reservation parks");
        driver
            .custody
            .place_bound(BoundWindow::Unactivated(reservation.bind_generation(9)))
            .expect("vacant slot parks the bound window");
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
        let pending = scripted_pending_for(&proved_b1, expected_binding(domain, 9, 0xC01, 0xE9F));
        let request_b1 = proved_b1.request.id();
        // `start` would have recorded the flight's request; the
        // worker half stays posed, so the request poses with it.
        driver.stage_current_for_test(proved_b1.request.clone());
        driver.seed_installing_for_test(proved_b1.request);
        driver
            .reclaim(pending, None)
            .expect("activation failure reclaims for genuine disposal");
        assert!(
            !driver.pending_close(),
            "nothing awaits its close before the terminal status"
        );
        let DriverEvent::Status(update) =
            driver_poll_until(&mut driver, Duration::from_secs(30)).expect("reclaim settles")
        else {
            panic!("a reclaimed handoff never installs");
        };
        assert!(
            matches!(
                update.outcome,
                PromotionOutcome::Refused {
                    reason: PromotionRefusal::ActivationFailed,
                }
            ),
            "activation failure refuses by name: {:?}",
            update.outcome
        );
        assert_eq!(update.request, request_b1);
        assert!(driver.is_idle(), "settled refusal idles the service");
        assert!(
            driver.pending_close(),
            "the terminal status transfers the parked window to its close"
        );
        let after_b1 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 10, 10),
            window_of(60, 70),
        );
        let report = driver
            .close(&broad, &scene.plan, CounterMode::Counts, Ok(after_b1))
            .expect("transferred window closes");
        assert_eq!((report.seq_before, report.seq_after), (1, 2));
        // The close report is caller-owned: its after-receipt lease
        // releases with it, before the charge accounting below.
        drop(report);
        assert!(
            !driver.pending_close(),
            "the close consumes the pending context"
        );
        let names: Vec<&str> = driver
            .ledger()
            .events
            .iter()
            .map(|row| row["event"].as_str().unwrap_or("<?>"))
            .collect();
        assert_eq!(
            names,
            vec!["reserved", "promotion_outcome", "closed"],
            "refusal rows order: {names:?}"
        );
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged_b1,
            "the terminal close releases every charge"
        );
        assert!(
            !driver.custody.is_occupied(),
            "the terminal close releases admission"
        );
        // A reselect reserves: nothing stranded, nothing wedged.
        let proved_b1_next = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x80),
            0xC02,
            0xEA0,
        );
        let before_next = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 11, 11),
            window_of(70, 80),
        );
        driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_b1_next.request,
                &proved_b1_next.bundle,
                Ok(before_next),
                rows,
                0,
                &scene.pool,
            )
            .expect("reselect reserves after the terminal close");
    }

    #[test]
    fn promotion_driver_reclaimed_open_window_closes_after_terminal_status() {
        // A host-refused install with the open window already in
        // place BEFORE disposal settles (as the Install arm leaves
        // it): the terminal status keeps the window's context, and
        // the close records it directly — no post-status restore.
        // Reclaim with nothing outstanding still fails closed,
        // returning the handoff.
        use crate::attach::counter_banks::BroadToggleFacts;
        use crate::inventory_promotion::PromotionOutcome;
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let rows = scene.plan.slots.len();
        let proved_b2 = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x80),
            0xC03,
            0xEA1,
        );
        let charged_b2 = scene.pool.snapshot().charged_bytes;
        let before_b2 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 7, 7),
            window_of(50, 60),
        );
        driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_b2.request,
                &proved_b2.bundle,
                Ok(before_b2),
                rows,
                0,
                &scene.pool,
            )
            .expect("reclaim scene reserves");
        // Open through the driver's own custody, as the CAS seam and
        // Install arm do: take once, bind, hold open with the
        // reserve's own brackets, seq and request.
        let reservation = driver.custody.take_reserved().expect("reservation parks");
        let window = reservation.bind_generation(9);
        let brackets = driver.brackets.take().expect("reserve staged brackets");
        let seq = driver.seq;
        let request_b2 = proved_b2.request.id();
        driver.stage_open_window_for_test(window, brackets, seq, proved_b2.request.clone());
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
        let binding = expected_binding(domain, 9, 0xC03, 0xEA1);
        let probe = scripted_pending_for(&proved_b2, binding);
        driver
            .reclaim(probe, Some(PromotionEnd::Cancelled))
            .expect_err("nothing outstanding, nothing reclaims");
        let pending = scripted_pending_for(&proved_b2, binding);
        driver.seed_installing_for_test(proved_b2.request);
        driver
            .reclaim(pending, Some(PromotionEnd::Cancelled))
            .expect("posed handoff reclaims");
        assert!(
            driver.pending_close(),
            "the open window awaits its close across disposal"
        );
        let DriverEvent::Status(update) =
            driver_poll_until(&mut driver, Duration::from_secs(30)).expect("reclaim settles")
        else {
            panic!("a reclaimed handoff never installs");
        };
        assert!(
            matches!(
                update.outcome,
                PromotionOutcome::Ended {
                    reason: PromotionEnd::Cancelled,
                }
            ),
            "reclaim confirms by name: {:?}",
            update.outcome
        );
        assert_eq!(update.request, request_b2);
        assert!(driver.is_idle(), "settled reclaim idles the service");
        assert!(
            driver.pending_close(),
            "the terminal status keeps the open context"
        );
        let after_b2 = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 10, 10),
            window_of(60, 70),
        );
        let report = driver
            .close(&broad, &scene.plan, CounterMode::Counts, Ok(after_b2))
            .expect("open window closes after its terminal status");
        assert_eq!((report.seq_before, report.seq_after), (1, 2));
        // The close report is caller-owned: its after-receipt lease
        // releases with it, before the charge accounting below.
        drop(report);
        assert!(
            !driver.pending_close(),
            "the close consumes the pending context"
        );
        let names: Vec<&str> = driver
            .ledger()
            .events
            .iter()
            .map(|row| row["event"].as_str().unwrap_or("<?>"))
            .collect();
        assert_eq!(
            names,
            vec!["reserved", "promotion_outcome", "closed"],
            "reclaim rows order: {names:?}"
        );
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged_b2,
            "the terminal close releases every charge"
        );
        assert!(
            !driver.custody.is_occupied(),
            "the terminal close releases admission"
        );
        // A reselect reserves: nothing stranded, nothing wedged.
        let proved_b2_next = promotion_scene(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            scene.object,
            Some(0x80),
            0xC04,
            0xEA2,
        );
        let before_next = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 11, 11),
            window_of(70, 80),
        );
        driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_b2_next.request,
                &proved_b2_next.bundle,
                Ok(before_next),
                rows,
                0,
                &scene.pool,
            )
            .expect("reselect reserves after the terminal close");
    }

    #[test]
    fn promotion_driver_unrelated_endpoint_stays_aggregate_only() {
        // Negative twin: selecting provider A's endpoint leaves
        // provider B aggregate-only. B's slots appear in the window's
        // aggregate rows with exact counts, but B is named nowhere
        // else — no lineage, no events, no detail — and B's own
        // intervals serve full counts beside the window.
        use super::super::selected_detail::reserve_detail_window_on_banks_collecting;
        use crate::attach::counter_banks::BroadToggleFacts;
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut plan = scene.plan.clone();
        plan.slots[2].names = vec!["C_Other".into()];
        plan.slots[3].names = vec!["C_OtherVerify".into()];
        let proved = promotion_scene(
            convert_for(&plan, scene.id_a),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let facts = BroadToggleFacts {
            generation: broad_generation(),
            stopped: false,
        };
        let custody = DetailWindowCustody::new();
        let mut brackets = BroadBracketCollector::new(4, 0, scene.pool.reserver());
        let mut seq = 0u64;
        let before = scripted_read(
            &scene.pool,
            &plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&plan, 1, 1),
            window_of(10, 20),
        );
        reserve_detail_window_on_banks_collecting(
            &scene.banks,
            facts,
            &plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &mut brackets,
            &mut seq,
            Ok(before),
            &scene.pool.reserver(),
            &custody,
        )
        .expect("provider A reserves");
        let reservation = custody.take_reserved().expect("reservation parks");
        let mut driver = PromotionDriver::new();
        driver.stage_open_window_for_test(
            reservation.bind_generation(9),
            brackets,
            seq,
            proved.request,
        );
        let mut during = counts_for(&plan, 4, 4);
        during[2] = (10, 10, 0);
        during[3] = (10, 10, 0);
        let after = scripted_read(
            &scene.pool,
            &plan,
            broad_generation(),
            CounterMode::Counts,
            &during,
            window_of(20, 30),
        );
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts,
        };
        driver
            .close(&broad, &plan, CounterMode::Counts, Ok(after))
            .expect("ordered close delivers");
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), driver.ledger());
        let section = &composed["evidence"]["selected_detail"];
        assert_eq!(
            section["lineage"]["broad_original_index"],
            serde_json::json!(0)
        );
        assert_eq!(
            section["aggregate"]["rows"][2]["entered"],
            serde_json::json!(9),
            "B's window counts stay in the aggregate rows"
        );
        assert_eq!(
            section["aggregate"]["rows"][2]["returned"],
            serde_json::json!(9)
        );
        let text = serde_json::to_string(section).expect("section serializes");
        assert!(
            !text.contains("\"selected\":2") && !text.contains("\"selected\":3"),
            "B is never the selection: {text}"
        );
        assert!(
            !text.contains("C_Other"),
            "B's names appear nowhere in the window record: {text}"
        );
        assert!(
            section.get("detail").is_none(),
            "no detail records without detail deltas"
        );
        // B's own intervals serve full counts beside the window.
        let mut aggregate = CounterCollector::new(limits_for(&plan), scene.pool.reserver());
        let base = scripted_read(
            &scene.pool,
            &plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&plan, 4, 4),
            window_of(20, 30),
        );
        assert!(matches!(
            aggregate.observe(Ok(base)),
            CounterObservation::Initial
        ));
        let mut live_counts = counts_for(&plan, 7, 7);
        live_counts[2] = (13, 13, 0);
        let live = scripted_read(
            &scene.pool,
            &plan,
            broad_generation(),
            CounterMode::Counts,
            &live_counts,
            window_of(30, 40),
        );
        let CounterObservation::Advanced { deltas, .. } = aggregate.observe(Ok(live)) else {
            panic!("aggregate advances beside the window");
        };
        assert_eq!((deltas[2].entered, deltas[2].returned), (9, 9));
        assert_eq!((deltas[0].entered, deltas[0].returned), (3, 3));
    }

    #[test]
    fn promotion_driver_selected_detail_isolates_unrelated_endpoint_by_identity() {
        // Isolation twin with positive detail: provider A's endpoint
        // carries genuine detail rows while provider B stays exact
        // aggregate. B's slots appear in the aggregate rows with exact
        // counts, and B is absent from the detail rows by structured
        // endpoint identity (slot/object/file_offset) — the detail
        // section is present and exact for A, so the absence proves
        // isolation rather than globally disabled detail.
        use super::super::selected_detail::reserve_detail_window_on_banks_collecting;
        use crate::attach::counter_banks::BroadToggleFacts;
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut plan = scene.plan.clone();
        plan.slots[2].names = vec!["C_Other".into()];
        plan.slots[3].names = vec!["C_OtherVerify".into()];
        let proved = promotion_scene(
            convert_for(&plan, scene.id_a),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let facts = BroadToggleFacts {
            generation: broad_generation(),
            stopped: false,
        };
        let custody = DetailWindowCustody::new();
        let mut brackets = BroadBracketCollector::new(4, 0, scene.pool.reserver());
        let mut seq = 0u64;
        let before = scripted_read(
            &scene.pool,
            &plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&plan, 1, 1),
            window_of(10, 20),
        );
        reserve_detail_window_on_banks_collecting(
            &scene.banks,
            facts,
            &plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &mut brackets,
            &mut seq,
            Ok(before),
            &scene.pool.reserver(),
            &custody,
        )
        .expect("provider A reserves");
        let reservation = custody.take_reserved().expect("reservation parks");
        let mut driver = PromotionDriver::new();
        driver.stage_open_window_for_test(
            reservation.bind_generation(9),
            brackets,
            seq,
            proved.request,
        );
        let mut during = counts_for(&plan, 4, 4);
        during[2] = (10, 10, 0);
        during[3] = (10, 10, 0);
        let after = scripted_read(
            &scene.pool,
            &plan,
            broad_generation(),
            CounterMode::Counts,
            &during,
            window_of(20, 30),
        );
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts,
        };
        let report = driver
            .close(&broad, &plan, CounterMode::Counts, Ok(after))
            .expect("ordered close delivers");
        drop(report);
        // Positive detail for A alone: the collector observes two
        // genuine reads over A's convert envelope and the interval
        // records through the real detail renderer.
        let convert_plan = proved.bundle.convert_subset().plan().clone();
        let mut detail_collector =
            CounterCollector::new(limits_for(&convert_plan), scene.pool.reserver());
        let detail_first = scripted_read(
            &scene.pool,
            &convert_plan,
            NonZeroU64::new(9).unwrap(),
            CounterMode::Counts,
            &counts_for(&convert_plan, 0, 0),
            window_of(10, 20),
        );
        assert!(matches!(
            detail_collector.observe(Ok(detail_first)),
            CounterObservation::Initial
        ));
        let mut detail_counts = counts_for(&convert_plan, 0, 0);
        detail_counts[0] = (5, 4, 0);
        detail_counts[1] = (7, 7, 0);
        let detail_second = scripted_read(
            &scene.pool,
            &convert_plan,
            NonZeroU64::new(9).unwrap(),
            CounterMode::Counts,
            &detail_counts,
            window_of(20, 30),
        );
        let CounterObservation::Advanced { deltas, .. } =
            detail_collector.observe(Ok(detail_second))
        else {
            panic!("the detail interval advances");
        };
        driver.record_detail(&deltas, CounterMode::Counts, 9);
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), driver.ledger());
        let section = &composed["evidence"]["selected_detail"];
        // B stays exact aggregate beside the window.
        assert_eq!(
            section["aggregate"]["rows"][2]["entered"],
            serde_json::json!(9),
            "B's window counts stay in the aggregate rows"
        );
        assert_eq!(
            section["aggregate"]["rows"][2]["returned"],
            serde_json::json!(9)
        );
        // The detail section is present and exact for A.
        let detail = section.get("detail").expect("A records detail");
        assert_eq!(detail["scope"], serde_json::json!("detail"));
        assert_eq!(detail["detail_generation"], serde_json::json!(9));
        let rows = detail["rows"].as_array().expect("detail rows render");
        assert_eq!(rows.len(), 2, "detail covers A's two slots: {rows:?}");
        assert_eq!(rows[0]["entered"], serde_json::json!(5));
        assert_eq!(rows[0]["returned"], serde_json::json!(4));
        assert_eq!(rows[1]["entered"], serde_json::json!(7));
        assert_eq!(rows[1]["returned"], serde_json::json!(7));
        // Every detail row names A's endpoint identity, and no row
        // names B's: A and B share file offsets, so the pinned
        // object id carries the distinction.
        for (row, offset) in rows.iter().zip([0x80u64, 0x90u64]) {
            assert_eq!(
                row["object"],
                serde_json::json!(scene.id_a.0),
                "detail row names A's object: {row:?}"
            );
            assert_eq!(row["file_offset"], serde_json::json!(offset));
            assert_ne!(
                row["object"],
                serde_json::json!(scene.id_b.0),
                "no detail row names B's object: {row:?}"
            );
        }
        let text = serde_json::to_string(detail).expect("detail serializes");
        assert!(
            !text.contains("C_Other"),
            "B's names appear nowhere in the detail record: {text}"
        );
    }

    #[test]
    fn promotion_driver_child_envelope_refuses_past_detailed_ceiling() {
        // Negative twin: no de facto Detailed capacity expansion. A
        // convert envelope past the Detailed slot ceiling refuses at
        // the gate before any window opens; charges refund, custody
        // stays vacant, and a small envelope reserves right after on
        // the same banks.
        use crate::attach::counter_banks::{BroadToggleFacts, DetailToggleRefusal};
        // Sized from the configured Detailed ceiling, so the negative
        // overhangs by exactly one slot under both the default (512)
        // and wide-detailed-2112 builds. The WIDE-scale staging
        // envelope needs headroom past the small-scene pool (an
        // accounting limit only; staged bytes stay far below it).
        let overhang = p11scope_ebpf_common::MAX_SLOTS;
        let overhang_offset = 0x80 + u64::from(overhang) * 0x10;
        let pool = SemanticResourcePool::reference_limit(128 * 1024 * 1024);
        let scene = stage_single_provider(pool, overhang + 1);
        let mut driver = PromotionDriver::new();
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts: BroadToggleFacts {
                generation: broad_generation(),
                stopped: false,
            },
        };
        let rows = scene.plan.slots.len();
        let ceiling = p11scope_ebpf_common::MAX_SLOTS as usize;
        assert_eq!(rows, ceiling + 1, "the scene overhangs the ceiling");
        let full_map: BTreeSet<u32> = (0..rows as u32).collect();
        let proved = promotion_scene_with_required(
            convert_for(&scene.plan, scene.object),
            scene.objects.clone(),
            BTreeMap::from([(scene.object, full_map)]),
            Some(overhang_offset),
            0xC00,
            0xE9E,
        );
        let charged = scene.pool.snapshot().charged_bytes;
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 2, 2),
            window_of(10, 20),
        );
        let refused = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                Ok(before),
                rows,
                0,
                &scene.pool,
            )
            .unwrap_err();
        assert_eq!(
            refused.refusal,
            SelectedDetailRefusal::Gate(DetailToggleRefusal::ChildShape)
        );
        assert!(
            refused.bracket.is_some(),
            "post-acceptance refusal carries its bracket"
        );
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged,
            "the refused envelope refunds every charge"
        );
        // A small envelope over the same banks reserves cleanly: no
        // capacity grew, nothing wedged.
        let mut small_slots: Vec<Slot> = scene
            .plan
            .slots
            .iter()
            .filter(|slot| slot.index == overhang)
            .cloned()
            .collect();
        small_slots[0].index = 0;
        let small_convert = AttachPlan::from_slots(small_slots);
        let proved_small = promotion_scene_with_required(
            small_convert,
            scene.objects.clone(),
            BTreeMap::from([(scene.object, BTreeSet::from([0]))]),
            Some(overhang_offset),
            0xC01,
            0xE9F,
        );
        let before_small = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 3),
            window_of(20, 30),
        );
        let accepted = driver
            .reserve(
                &broad,
                &scene.plan,
                &scene.objects,
                &proved_small.request,
                &proved_small.bundle,
                Ok(before_small),
                rows,
                0,
                &scene.pool,
            )
            .expect("small envelope reserves after the refusal");
        assert_eq!(accepted.seq, 2);
    }

    #[test]
    fn promotion_driver_close_composes_lineage_and_aggregate_bracket() {
        // The close path through the driver: the staged window closes
        // exactly once (a second close fails benignly with no window),
        // and the composer publishes lineage plus the aggregate
        // bracket with exact counts. The whole section carries no
        // combined totals anywhere, recursively.
        use super::super::selected_detail::reserve_detail_window_on_banks_collecting;
        use crate::attach::counter_banks::BroadToggleFacts;
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let convert = convert_for(&scene.plan, scene.object);
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x90),
            0xC00,
            0xE9E,
        );
        let facts = BroadToggleFacts {
            generation: broad_generation(),
            stopped: false,
        };
        let custody = DetailWindowCustody::new();
        let mut brackets = BroadBracketCollector::new(4, 0, scene.pool.reserver());
        let mut seq = 0u64;
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 5),
            window_of(10, 20),
        );
        reserve_detail_window_on_banks_collecting(
            &scene.banks,
            facts,
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &mut brackets,
            &mut seq,
            Ok(before),
            &scene.pool.reserver(),
            &custody,
        )
        .expect("close scene reserves");
        let reservation = custody.take_reserved().expect("reservation parks");
        let mut driver = PromotionDriver::new();
        driver.stage_open_window_for_test(
            reservation.bind_generation(9),
            brackets,
            seq,
            proved.request,
        );
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            broad_generation(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        let broad = BanksBroad {
            banks: Some(&scene.banks),
            facts,
        };
        let report = driver
            .close(&broad, &scene.plan, CounterMode::Counts, Ok(after))
            .expect("ordered close delivers lineage");
        assert_eq!(report.drift, None);
        assert_eq!((report.seq_before, report.seq_after), (1, 2));
        assert_eq!(
            driver
                .close(
                    &broad,
                    &scene.plan,
                    CounterMode::Counts,
                    Ok(scripted_read(
                        &scene.pool,
                        &scene.plan,
                        broad_generation(),
                        CounterMode::Counts,
                        &counts_for(&scene.plan, 8, 9),
                        window_of(40, 50),
                    ))
                )
                .unwrap_err(),
            DriverCloseError::NoOpenWindow,
            "a second close fails benignly"
        );
        let names: Vec<&str> = driver
            .ledger()
            .events
            .iter()
            .map(|row| row["event"].as_str().unwrap_or("<?>"))
            .collect();
        assert_eq!(names, vec!["closed"], "close records once: {names:?}");
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), driver.ledger());
        let section = &composed["evidence"]["selected_detail"];
        let lineage = &section["lineage"];
        assert_eq!(lineage["broad_original_index"], serde_json::json!(1));
        assert_eq!(lineage["endpoint_offset"], serde_json::json!(0x90));
        assert_eq!(lineage["broad_generation"], serde_json::json!(7));
        assert_eq!(lineage["broad_read_seq_before"], serde_json::json!(1));
        assert_eq!(lineage["broad_read_seq_after"], serde_json::json!(2));
        assert_eq!(lineage["detail_generation"], serde_json::json!(9));
        let aggregate = &section["aggregate"];
        assert_eq!(aggregate["rows"][1]["entered"], serde_json::json!(3));
        assert_eq!(aggregate["rows"][1]["returned"], serde_json::json!(4));
        assert_eq!(aggregate["mode"], serde_json::json!("counts"));
        assert_eq!(aggregate["seq_before"], serde_json::json!(1));
        assert_eq!(aggregate["seq_after"], serde_json::json!(2));
        assert!(section.get("selection").is_none());
        assert!(section.get("detail").is_none());
        fn assert_no_totals(value: &serde_json::Value) {
            match value {
                serde_json::Value::Object(map) => {
                    assert!(
                        !map.contains_key("total"),
                        "no combined totals anywhere: {value:?}"
                    );
                    for nested in map.values() {
                        assert_no_totals(nested);
                    }
                }
                serde_json::Value::Array(items) => {
                    for nested in items {
                        assert_no_totals(nested);
                    }
                }
                _ => {}
            }
        }
        assert_no_totals(section);
    }

    /// Headless mailbox (P1a): a receipt naming another revision is
    /// stale — the selection raced a redraw — and refuses without
    /// queueing, never rebound to the viewed frame. The control stays
    /// idle and a receipt naming the viewed revision still queues.
    #[test]
    fn headless_request_stale_view_refuses() {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        let mut promoter = Promoter::new();
        assert!(promoter.enable(CaptureId::new(11)));
        let view = scripted_promotion_view_for_test();
        assert_eq!(view.revision(), ViewRevision::new(3));
        let stale = SelectedEndpointReceipt::new(ViewRevision::new(4), 0x80);
        assert_eq!(
            promoter.request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), stale),
            Err(PromotionRequestError::Refused(PromotionRefusal::StaleView)),
            "a receipt for another view is stale, never rebound"
        );
        assert!(
            promoter.take_request().is_none(),
            "a stale request queues nothing"
        );
        assert_eq!(promoter.state(), PromotionState::Idle, "control stays idle");
        assert!(promoter.enabled(), "the run stays bound");
        // The mailbox is unpoisoned: the viewed revision still queues.
        let fresh = SelectedEndpointReceipt::new(view.revision(), 0x80);
        let id = promoter
            .request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), fresh)
            .expect("viewed revision queues after a stale refusal");
        let taken = promoter.take_request().expect("mailbox holds it");
        assert_eq!(taken.id(), id);
        assert_eq!(taken.endpoint(), Some(fresh));
    }

    /// Headless mailbox (P1a): a pair outside the fixed viewed frame
    /// refuses `PairNotInView` — never queued, never replaced by
    /// another row — on either axis. The control stays idle and the
    /// exact pair still queues.
    #[test]
    fn headless_request_pair_not_in_view() {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        let mut promoter = Promoter::new();
        assert!(promoter.enable(CaptureId::new(11)));
        let view = scripted_promotion_view_for_test();
        let receipt = SelectedEndpointReceipt::new(view.revision(), 0x80);
        for (caller, provider) in [(CallerId(3), ModuleId(6)), (CallerId(4), ModuleId(5))] {
            assert_eq!(
                promoter.request_with_endpoint(Arc::clone(&view), caller, provider, receipt),
                Err(PromotionRequestError::PairNotInView),
                "off-view pair refuses: {caller:?}/{provider:?}"
            );
        }
        assert!(
            promoter.take_request().is_none(),
            "off-view requests queue nothing"
        );
        assert_eq!(promoter.state(), PromotionState::Idle, "control stays idle");
        // The mailbox is unpoisoned: the exact pair still queues.
        let id = promoter
            .request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), receipt)
            .expect("exact pair queues after off-view refusals");
        let taken = promoter.take_request().expect("mailbox holds it");
        assert_eq!(taken.id(), id);
        assert_eq!(taken.endpoint(), Some(receipt));
    }

    /// Headless mailbox (P1a): a view naming another capture refuses
    /// `ForeignCapture` even when the receipt names the viewed
    /// revision, so the stale check cannot be what refuses it. The
    /// inputs refuse the same way under either check order, so this
    /// twin does not pin the order.
    #[test]
    fn headless_request_foreign_capture() {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        let mut promoter = Promoter::new();
        assert!(promoter.enable(CaptureId::new(11)));
        let base = scripted_promotion_view_for_test();
        let foreign = Arc::new(PromotionView::new(
            CaptureId::new(12),
            base.revision(),
            Arc::clone(base.presentation()),
        ));
        let receipt = SelectedEndpointReceipt::new(foreign.revision(), 0x80);
        assert_eq!(
            receipt.view(),
            foreign.revision(),
            "the stale check passes by construction"
        );
        assert_eq!(
            promoter.request_with_endpoint(Arc::clone(&foreign), CallerId(3), ModuleId(5), receipt),
            Err(PromotionRequestError::ForeignCapture),
            "a view from another capture never queues"
        );
        assert!(
            promoter.take_request().is_none(),
            "a foreign view queues nothing"
        );
        assert_eq!(promoter.state(), PromotionState::Idle, "control stays idle");
        assert_eq!(promoter.capture(), Some(CaptureId::new(11)));
        // The mailbox is unpoisoned: the bound capture still queues.
        let fresh = SelectedEndpointReceipt::new(base.revision(), 0x80);
        promoter
            .request_with_endpoint(Arc::clone(&base), CallerId(3), ModuleId(5), fresh)
            .expect("bound capture queues after a foreign refusal");
        let taken = promoter.take_request().expect("mailbox holds it");
        assert_eq!(taken.endpoint(), Some(fresh));
    }

    /// Headless mailbox (P1a): the one-slot mailbox refuses a repeat
    /// of the in-flight pair as `Duplicate` and a distinct pair as
    /// `Busy`, holding the first ticket throughout; cancel drains the
    /// untaken request and the next request queues with a fresh serial.
    #[test]
    fn headless_mailbox_busy_duplicate() {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        let mut promoter = Promoter::new();
        assert!(promoter.enable(CaptureId::new(11)));
        let base = scripted_promotion_view_for_test();
        let mut presentation = (**base.presentation()).clone();
        let second = crate::inventory_present::EdgeView {
            caller: CallerId(7),
            module: ModuleId(9),
            ..base.presentation().edges[0].clone()
        };
        presentation.edges.push(second);
        let view = Arc::new(PromotionView::new(
            CaptureId::new(11),
            base.revision(),
            Arc::new(presentation),
        ));
        let first = SelectedEndpointReceipt::new(view.revision(), 0x80);
        let id1 = promoter
            .request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), first)
            .expect("first request queues");
        assert_eq!(promoter.state(), PromotionState::Queued);
        assert_eq!(
            promoter.snapshot(None).request,
            Some(id1),
            "mailbox holds the first ticket"
        );
        assert_eq!(
            promoter.request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), first),
            Err(PromotionRequestError::Refused(PromotionRefusal::Duplicate)),
            "a repeat of the in-flight pair is a duplicate"
        );
        let other = SelectedEndpointReceipt::new(view.revision(), 0x90);
        assert_eq!(
            promoter.request_with_endpoint(Arc::clone(&view), CallerId(7), ModuleId(9), other),
            Err(PromotionRequestError::Refused(PromotionRefusal::Busy)),
            "a distinct pair while outstanding is busy"
        );
        assert_eq!(
            promoter.snapshot(None).request,
            Some(id1),
            "refusals queue nothing over the first ticket"
        );
        assert_eq!(promoter.cancel(), PromotionCancel::Cancelled);
        assert_eq!(
            promoter.state(),
            PromotionState::Ended(PromotionEnd::Cancelled),
            "cancel ends the untaken request"
        );
        assert!(
            promoter.take_request().is_none(),
            "cancel drains the mailbox"
        );
        let id2 = promoter
            .request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), first)
            .expect("requeue succeeds after cancel");
        assert_ne!(id2, id1, "the requeue takes a fresh serial");
        let taken = promoter.take_request().expect("mailbox holds the requeue");
        assert_eq!(taken.id(), id2);
        assert_eq!(taken.endpoint(), Some(first));
        assert_eq!(
            (taken.caller(), taken.provider()),
            (CallerId(3), ModuleId(5))
        );
    }

    /// Headless mailbox (P1a): a legacy `None`-endpoint request taken
    /// from a headless (display-less) promoter reaches the adapter and
    /// refuses `EndpointUnresolved` on the `verify_reserve_inputs`
    /// path — closed, with no window parked and no charge taken. The
    /// baseline genuinely agrees with the request, so the refusal is
    /// the missing receipt, not a mismatch; a receipt-carrying request
    /// then verifies clean on the same custody.
    #[test]
    fn headless_legacy_none_endpoint_refused_closed() {
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let convert = convert_for(&scene.plan, scene.object);
        let legacy = promotion_scene(
            convert.clone(),
            scene.objects.clone(),
            scene.object,
            None,
            0xC00,
            0xE9E,
        );
        assert_eq!(legacy.request.endpoint(), None);
        assert!(
            legacy.bundle.baseline.matches_request(&legacy.request),
            "the baseline agrees: the refusal is the missing receipt"
        );
        let custody = DetailWindowCustody::new();
        let before = scene.pool.snapshot().charged_bytes;
        assert_eq!(
            verify_reserve_inputs(
                &legacy.request,
                &legacy.bundle,
                &scene.plan,
                &scene.objects,
                &custody,
            ),
            Err(SelectedDetailRefusal::EndpointUnresolved),
            "a legacy request refuses closed at the adapter"
        );
        assert!(!custody.is_occupied(), "no window parks on refusal");
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            before,
            "no charge is taken on refusal"
        );
        // The custody is unpoisoned: a receipt-carrying request over a
        // fresh bundle verifies clean on the same custody.
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x90),
            0xC00,
            0xE9E,
        );
        let resolved = verify_reserve_inputs(
            &proved.request,
            &proved.bundle,
            &scene.plan,
            &scene.objects,
            &custody,
        )
        .expect("receipt request verifies after a legacy refusal");
        assert_eq!(resolved.selected, 1);
        assert_eq!(resolved.physical.file_offset, 0x90);
    }

    // --- K0 (broad-cells detail) twins ---
    //
    // The K0 window opens over a resolved selection with the
    // selection-time broad read as its baseline, and closes with the
    // close read: the detail is the selected slot's own broad cells
    // over the window. Twins drive the same open/close bodies
    // production runs, with scripted reads through the genuine fold
    // and witness facts through the genuine tap.

    use crate::attach::PidLifecycleTap;
    use p11scope_ebpf_common::{
        DISCOVERY_EXEC_TASK_REPLACED, DISCOVERY_KIND_EXEC, DISCOVERY_KIND_LEADER_EXIT,
        DiscoveryRecord,
    };

    /// One K0 selection through the production stage: resolve
    /// genuinely against the live plan and record the attempt.
    fn k0_stage(
        scene: &BroadScene,
        name: &str,
        ledger: &mut SelectionLedger,
    ) -> Option<ResolvedSelection> {
        run_metrics_selection_stage(name, &scene.plan, &Scope::Pid(std::process::id()), ledger)
    }

    fn k0_exec_record(pid: u32, ts: u64) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.hook_ts_ns = ts;
        record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
        record.kind = DISCOVERY_KIND_EXEC;
        record.case_id = DISCOVERY_EXEC_TASK_REPLACED;
        record
    }

    fn k0_exit_record(pid: u32, ts: u64) -> DiscoveryRecord {
        let mut record: DiscoveryRecord = unsafe { std::mem::zeroed() };
        record.hook_ts_ns = ts;
        record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
        record.kind = DISCOVERY_KIND_LEADER_EXIT;
        record
    }

    /// Witness facts through the genuine tap: open a read, apply the
    /// scripted records, snapshot. A failed read-open fails loudly so
    /// an exotic clock never silently rewords a twin.
    fn k0_facts_after(pid: u32, apply: impl FnOnce(&PidLifecycleTap)) -> LifecycleFacts {
        let tap = PidLifecycleTap::test_for(pid, crate::events::DiscoveryDomain::test_standin(7));
        assert!(
            tap.begin_read(Some(100)).is_some(),
            "the K0 twin read opens"
        );
        apply(&tap);
        tap.test_facts().expect("the K0 twin tap stays readable")
    }

    fn k0_clean() -> K0Facts {
        Ok(Some(LifecycleFacts::default()))
    }

    /// A scripted read with explicit producer health, through the
    /// genuine fold and pack (mirrors `scripted_read`, which is
    /// always healthy).
    fn k0_scripted_read(
        pool: &SemanticResourcePool,
        plan: &AttachPlan,
        generation: NonZeroU64,
        mode: CounterMode,
        counts: &[(u64, u64, u64)],
        window: Option<ReadWindow>,
        health: CounterHealth,
    ) -> CounterRead {
        assert_eq!(
            counts.len(),
            plan.slots.len(),
            "one explicit sample per plan slot"
        );
        let mut rows = Vec::with_capacity(plan.slots.len());
        let held: Vec<CountStats> = counts
            .iter()
            .map(|&(entered, returned, errors)| CountStats {
                entered,
                returned,
                errors,
            })
            .collect();
        for (slot, index) in plan.slots.iter().zip(0..) {
            let cells = vec![CounterCell::Counts(&held[index])];
            rows.push(
                CounterRow::fold(slot, mode, cells, Vec::new(), limits_for(plan))
                    .expect("explicit cells fold"),
            );
        }
        let reservation =
            ReadReservation::reserve(rows.len(), 0, &pool.reserver()).expect("read reserves");
        CounterRead::new(
            generation,
            mode,
            window,
            Ok(rows),
            health,
            KernelEvidence::default(),
            reservation,
        )
        .expect("scripted read packs")
    }

    #[test]
    fn k0_detail_equals_broad_slot_delta_over_window() {
        // Healthy K0 (counts): the detail is the selected slot's own
        // broad cells between the selection-time read and the close
        // read — (15, 12, 1) here — while other slots carry their own
        // (10, 10, 0). No refusal records on success.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        assert_eq!(resolved.slot, 2);
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &[(100, 100, 0), (100, 100, 0), (100, 100, 0), (100, 100, 0)],
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &[(110, 110, 0), (110, 110, 0), (115, 112, 1), (110, 110, 0)],
            window_of(20, 30),
        );
        close_k0_window(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &mut ledger,
        );
        let record = ledger.selection.as_ref().expect("selection records");
        assert_eq!(record.refusal, None, "success records no refusal");
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        let detail = section.get("detail").expect("detail renders");
        assert_eq!(detail["scope"], serde_json::json!("detail"));
        assert_eq!(detail["mode"], serde_json::json!("counts"));
        assert_eq!(
            detail["detail_generation"],
            serde_json::json!(BROAD_GENERATION),
            "K0 detail names the broad banks it comes from"
        );
        let rows = detail["rows"].as_array().expect("detail rows");
        assert_eq!(rows.len(), 1, "detail carries only the selected slot");
        assert_eq!(rows[0]["slot"], serde_json::json!(2));
        assert_eq!(rows[0]["entered"], serde_json::json!(15));
        assert_eq!(rows[0]["returned"], serde_json::json!(12));
        assert_eq!(rows[0]["errors"], serde_json::json!(1));
        assert!(
            rows[0].get("total_ns").is_none(),
            "counts rows carry no time"
        );
        let aggregate = section.get("aggregate").expect("aggregate renders");
        assert_eq!(aggregate["seq_before"], serde_json::json!(1));
        assert_eq!(aggregate["seq_after"], serde_json::json!(2));
        let aggregate_rows = aggregate["rows"].as_array().expect("aggregate rows");
        assert_eq!(aggregate_rows.len(), 4, "aggregate stays scope-wide");
        assert_eq!(aggregate_rows[2]["entered"], serde_json::json!(15));
        assert_eq!(aggregate_rows[0]["entered"], serde_json::json!(10));
        assert!(section.get("lineage").is_none(), "K0 joins no lineage");
    }

    #[test]
    fn k0_detail_carries_per_mode_cells() {
        // One mode per measurement: counts rows carry no time keys,
        // timestamps rows add totals, latency rows add buckets. Values
        // are the selected slot's window deltas in every mode.
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let pool = test_pool();
            let scene = stage_single_provider(pool, 4);
            let mut ledger = SelectionLedger::new();
            let resolved = k0_stage(&scene, "C_Toggle0001", &mut ledger)
                .expect("live name resolves for the K0 window");
            let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
            let before = scripted_read(
                &scene.pool,
                &scene.plan,
                generation,
                mode,
                &counts_for(&scene.plan, 100, 100),
                window_of(10, 20),
            );
            let window = open_k0_window(
                resolved,
                limits_for(&scene.plan),
                scene.pool.reserver(),
                Ok(before),
                k0_clean(),
                &mut ledger,
            )
            .expect("a healthy selection-time read opens the window");
            let after = scripted_read(
                &scene.pool,
                &scene.plan,
                generation,
                mode,
                &counts_for(&scene.plan, 110, 110),
                window_of(20, 30),
            );
            close_k0_window(
                window,
                &scene.plan,
                Ok(after),
                k0_clean(),
                true,
                &mut ledger,
            );
            assert_eq!(
                ledger
                    .selection
                    .as_ref()
                    .expect("selection records")
                    .refusal,
                None,
                "success records no refusal in {mode:?}"
            );
            let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
            let detail = composed["evidence"]["selected_detail"]
                .get("detail")
                .expect("detail renders");
            assert_eq!(detail["mode"], serde_json::json!(mode.name()));
            let rows = detail["rows"].as_array().expect("detail rows");
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0]["slot"], serde_json::json!(1));
            assert_eq!(rows[0]["entered"], serde_json::json!(10));
            assert_eq!(rows[0]["returned"], serde_json::json!(10));
            match mode {
                CounterMode::Counts => {
                    assert!(rows[0].get("total_ns").is_none(), "counts: no time");
                    assert!(rows[0].get("max_ns").is_none(), "counts: no time");
                    assert!(rows[0].get("buckets").is_none(), "counts: no buckets");
                }
                CounterMode::Timestamps => {
                    assert_eq!(rows[0]["total_ns"], serde_json::json!(100));
                    assert_eq!(rows[0]["max_ns"], serde_json::json!(10));
                    assert!(rows[0].get("buckets").is_none(), "timestamps: no buckets");
                }
                CounterMode::Latency => {
                    assert_eq!(rows[0]["total_ns"], serde_json::json!(100));
                    assert_eq!(rows[0]["max_ns"], serde_json::json!(10));
                    assert_eq!(
                        rows[0]["buckets"].as_array().expect("buckets").len(),
                        32,
                        "latency carries its buckets"
                    );
                }
            }
        }
    }

    #[test]
    fn k0_exec_in_window_voids_detail() {
        // An exec of the selected caller between the bounds voids the
        // detail with the caller-changed word: the window's calls can
        // no longer be attributed to the selected caller. A witness
        // fault fails closed the same way. Nothing renders on a void.
        for (label, after_facts) in [
            (
                "exec",
                Ok(Some(k0_facts_after(7, |tap| {
                    tap.observe_record(&k0_exec_record(7, 200));
                }))),
            ),
            (
                "fault",
                Ok(Some(k0_facts_after(7, |tap| {
                    tap.observe_malformed();
                }))),
            ),
            ("unreadable", Err(PidContinuityRefusal::Terminal)),
        ] {
            let pool = test_pool();
            let scene = stage_single_provider(pool, 4);
            let mut ledger = SelectionLedger::new();
            let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
                .expect("live name resolves for the K0 window");
            let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
            let before = scripted_read(
                &scene.pool,
                &scene.plan,
                generation,
                CounterMode::Counts,
                &counts_for(&scene.plan, 100, 100),
                window_of(10, 20),
            );
            let window = open_k0_window(
                resolved,
                limits_for(&scene.plan),
                scene.pool.reserver(),
                Ok(before),
                k0_clean(),
                &mut ledger,
            )
            .expect("a healthy selection-time read opens the window");
            let after = scripted_read(
                &scene.pool,
                &scene.plan,
                generation,
                CounterMode::Counts,
                &counts_for(&scene.plan, 110, 110),
                window_of(20, 30),
            );
            close_k0_window(
                window,
                &scene.plan,
                Ok(after),
                after_facts,
                true,
                &mut ledger,
            );
            let record = ledger.selection.as_ref().expect("selection records");
            assert_eq!(
                record.refusal,
                Some("promotion_caller_changed"),
                "{label} voids the detail"
            );
            let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
            let section = &composed["evidence"]["selected_detail"];
            assert!(section.get("detail").is_none(), "{label}: no detail");
            assert!(
                section.get("aggregate").is_none(),
                "{label}: no window aggregate"
            );
            assert!(section.get("lineage").is_none(), "{label}: no lineage");
            assert_eq!(
                section["events"],
                serde_json::json!([]),
                "{label}: no events"
            );
        }
    }

    #[test]
    fn k0_break_without_exec_voids_as_retired() {
        // A pure break (leader exit with no exec record) voids as a
        // retirement, not a change: the caller is gone, not replaced.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        let break_only = k0_facts_after(7, |tap| {
            tap.observe_record(&k0_exit_record(7, 200));
        });
        assert!(
            break_only.latest_exec.is_none(),
            "the twin stages a break with no exec"
        );
        assert!(
            break_only.greatest_break_ns.is_some(),
            "the twin stages a break"
        );
        close_k0_window(
            window,
            &scene.plan,
            Ok(after),
            Ok(Some(break_only)),
            true,
            &mut ledger,
        );
        let record = ledger.selection.as_ref().expect("selection records");
        assert_eq!(record.refusal, Some("promotion_caller_retired"));
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("detail").is_none());
        assert!(section.get("aggregate").is_none());
    }

    #[test]
    fn k0_unresolvable_or_ambiguous_selection_refuses() {
        // Preservation: an unknown or ambiguous endpoint refuses at
        // the stage exactly as today, and opens no window.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        assert!(
            k0_stage(&scene, "C_Missing", &mut ledger).is_none(),
            "unknown names open nothing"
        );
        assert_eq!(
            ledger.selection.as_ref().expect("refusal records").refusal,
            Some("endpoint_unknown")
        );
        let pool = test_pool();
        let multi = stage_two_providers(pool);
        let scope = Scope::Pid(std::process::id());
        let mut ledger = SelectionLedger::new();
        assert!(
            run_metrics_selection_stage("C_Sign", &multi.plan, &scope, &mut ledger).is_none(),
            "ambiguous names open nothing"
        );
        assert_eq!(
            ledger.selection.as_ref().expect("refusal records").refusal,
            Some("promotion_endpoint_ambiguous")
        );
    }

    #[test]
    fn k0_cgroup_and_system_scopes_refuse_without_detail() {
        // Preservation: scopes without one original keep today's
        // named refusal and open no window.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        assert!(
            run_metrics_selection_stage("C_Toggle0001", &scene.plan, &Scope::System, &mut ledger)
                .is_none(),
            "system scope opens nothing"
        );
        assert_eq!(
            ledger.selection.as_ref().expect("refusal records").refusal,
            Some("promotion_scope_unsupported")
        );
        let dir = tempfile::tempdir().unwrap();
        let held =
            std::sync::Arc::new(std::fs::File::open(dir.path()).expect("cgroup stand-in opens"));
        let mut ledger = SelectionLedger::new();
        assert!(
            run_metrics_selection_stage(
                "C_Toggle0001",
                &scene.plan,
                &Scope::Cgroup {
                    id: 7,
                    path: dir.path().to_path_buf(),
                    dir: held,
                },
                &mut ledger,
            )
            .is_none(),
            "cgroup scope opens nothing"
        );
        assert_eq!(
            ledger.selection.as_ref().expect("refusal records").refusal,
            Some("promotion_scope_unsupported")
        );
    }

    #[test]
    fn k0_zero_call_window_renders_explicit_zeros() {
        // Nothing happens in the window: the detail still renders,
        // with explicit zero rows and the reported window — measured
        // zeros over a proven window, never absence.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0003", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(20, 30),
        );
        close_k0_window(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            None,
            "an idle window is still a success"
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        let detail = section.get("detail").expect("detail renders");
        let rows = detail["rows"].as_array().expect("detail rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["entered"], serde_json::json!(0));
        assert_eq!(rows[0]["returned"], serde_json::json!(0));
        assert_eq!(rows[0]["errors"], serde_json::json!(0));
        let aggregate = section.get("aggregate").expect("the window still reports");
        assert_eq!(aggregate["seq_before"], serde_json::json!(1));
        assert_eq!(aggregate["seq_after"], serde_json::json!(2));
    }

    #[test]
    fn k0_composer_renders_empty_envelope_for_empty_ledger() {
        // The composer with an empty ledger renders an empty envelope:
        // a present `selected_detail` with empty events, no selection
        // and no window products. Production never calls it this way
        // (flag absent → composer never called); the no-flag property
        // lives at the CLI seam, not here.
        let ledger = SelectionLedger::new();
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("selection").is_none(), "no selection staged");
        assert_eq!(section["events"], serde_json::json!([]));
        assert!(section.get("lineage").is_none());
        assert!(section.get("aggregate").is_none());
        assert!(section.get("detail").is_none());
    }

    #[test]
    fn k0_detail_matches_aggregate_cells_parity() {
        // Output parity: the detail row equals the aggregate
        // bracket's row for the selected slot over the same window —
        // the same cells, the same mode fields, never a combined
        // total — under the envelope's closed keys.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0000", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Timestamps,
            &[(50, 40, 1), (100, 100, 0), (100, 100, 0), (100, 100, 0)],
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Timestamps,
            &[(70, 55, 3), (110, 110, 0), (110, 110, 0), (110, 110, 0)],
            window_of(20, 30),
        );
        close_k0_window(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &mut ledger,
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        let detail = section.get("detail").expect("detail renders");
        let aggregate = section.get("aggregate").expect("aggregate renders");
        let detail_rows = detail["rows"].as_array().expect("detail rows");
        let aggregate_rows = aggregate["rows"].as_array().expect("aggregate rows");
        assert_eq!(detail_rows.len(), 1);
        let selected = aggregate_rows
            .iter()
            .find(|row| row["slot"] == serde_json::json!(0))
            .expect("aggregate carries the selected slot");
        assert_eq!(
            detail_rows[0], *selected,
            "detail cells equal the aggregate cells for the slot"
        );
        for fragment in [detail, aggregate] {
            assert!(fragment.get("total").is_none(), "no combined total renders");
        }
        let section_map = section.as_object().expect("envelope is an object");
        assert!(
            section_map.keys().all(|key| {
                ["selection", "events", "lineage", "aggregate", "detail"].contains(&key.as_str())
            }),
            "the envelope keeps its closed keys: {section_map:?}"
        );
    }

    #[test]
    fn k0_retired_slot_voids_detail() {
        // The close plan no longer publishes the selected slot: the
        // detail voids as not-published. The after read runs over the
        // retired plan, so observing before checking would latch a
        // topology issue instead — the word pins the order.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let mut retired = scene.plan.clone();
        retired.slots.retain(|slot| slot.index != 2);
        let retired_counts: Vec<(u64, u64, u64)> =
            retired.slots.iter().map(|_| (110, 110, 0)).collect();
        let after = scripted_read(
            &scene.pool,
            &retired,
            generation,
            CounterMode::Counts,
            &retired_counts,
            window_of(20, 30),
        );
        close_k0_window(window, &retired, Ok(after), k0_clean(), true, &mut ledger);
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("not_published")
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("detail").is_none());
        assert!(section.get("aggregate").is_none());
    }

    #[test]
    fn k0_failed_close_read_maps_stage() {
        // A failed close read voids with the read's mapped word —
        // quarantine, pool pressure and a missing binding name
        // themselves, every other stage maps to the topology
        // catch-all — and renders nothing.
        for (label, stage, word) in [
            ("quarantined", ReadStage::BankQuarantined, "quarantined"),
            ("routing", ReadStage::BankRouting, "broad_plan_topology"),
            ("budget", ReadStage::Budget, "budget"),
            (
                "absent",
                ReadStage::Shape(ReaderShapeCause::BindingAbsent),
                "broad_not_counter",
            ),
        ] {
            let pool = test_pool();
            let scene = stage_single_provider(pool, 4);
            let mut ledger = SelectionLedger::new();
            let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
                .expect("live name resolves for the K0 window");
            let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
            let before = scripted_read(
                &scene.pool,
                &scene.plan,
                generation,
                CounterMode::Counts,
                &counts_for(&scene.plan, 100, 100),
                window_of(10, 20),
            );
            let window = open_k0_window(
                resolved,
                limits_for(&scene.plan),
                scene.pool.reserver(),
                Ok(before),
                k0_clean(),
                &mut ledger,
            )
            .expect("a healthy selection-time read opens the window");
            close_k0_window(
                window,
                &scene.plan,
                Err(stage),
                k0_clean(),
                true,
                &mut ledger,
            );
            assert_eq!(
                ledger
                    .selection
                    .as_ref()
                    .expect("selection records")
                    .refusal,
                Some(word),
                "{label} maps to {word}"
            );
            let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
            let section = &composed["evidence"]["selected_detail"];
            assert!(section.get("detail").is_none(), "{label}: no detail");
            assert!(section.get("aggregate").is_none(), "{label}: no aggregate");
        }
    }

    #[test]
    fn k0_capture_loss_latches_unknown() {
        // Capture loss or overflow in the window — a saturated
        // producer at either bound, or regressed counters at close —
        // latches the collector, and the detail voids as unknown
        // rather than reporting partial numbers.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        // Saturated selection-time read: no window opens.
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let saturated_before = k0_scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
            CounterHealth {
                saturated: true,
                contended: false,
            },
        );
        assert!(
            open_k0_window(
                resolved,
                limits_for(&scene.plan),
                scene.pool.reserver(),
                Ok(saturated_before),
                k0_clean(),
                &mut ledger,
            )
            .is_none(),
            "a saturated selection-time read opens nothing"
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("broad_plan_topology")
        );
        // Saturated close read: the opened window voids.
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let saturated_after = k0_scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
            CounterHealth {
                saturated: true,
                contended: false,
            },
        );
        close_k0_window(
            window,
            &scene.plan,
            Ok(saturated_after),
            k0_clean(),
            true,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("broad_plan_topology"),
            "a saturated close read voids the window"
        );
        // Regressed close read: counters ran backwards, so no honest
        // interval exists.
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let regressed = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 50, 50),
            window_of(20, 30),
        );
        close_k0_window(
            window,
            &scene.plan,
            Ok(regressed),
            k0_clean(),
            true,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("broad_plan_topology"),
            "a regressed close read voids the window"
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("detail").is_none());
        assert!(section.get("aggregate").is_none());
    }

    #[test]
    fn k0_unclean_close_boundary_voids() {
        // No proven quiescence (or a blind post-quiescence tail): the
        // witness may have missed an exec, so the window voids as
        // broad-stopping and discards the close read before observing.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        close_k0_window(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            false,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("broad_stopping")
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("detail").is_none());
        assert!(section.get("aggregate").is_none());
    }

    #[test]
    fn k0_failed_selection_read_refuses_at_open() {
        // A failed selection-time read refuses immediately with the
        // read's mapped word and opens no window.
        for (label, stage, word) in [
            ("quarantined", ReadStage::BankQuarantined, "quarantined"),
            ("routing", ReadStage::BankRouting, "broad_plan_topology"),
            (
                "absent",
                ReadStage::Shape(ReaderShapeCause::BindingAbsent),
                "broad_not_counter",
            ),
        ] {
            let pool = test_pool();
            let scene = stage_single_provider(pool, 4);
            let mut ledger = SelectionLedger::new();
            let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
                .expect("live name resolves for the K0 window");
            assert!(
                open_k0_window(
                    resolved,
                    limits_for(&scene.plan),
                    scene.pool.reserver(),
                    Err(stage),
                    k0_clean(),
                    &mut ledger,
                )
                .is_none(),
                "{label} opens no window"
            );
            assert_eq!(
                ledger
                    .selection
                    .as_ref()
                    .expect("selection records")
                    .refusal,
                Some(word),
                "{label} maps to {word}"
            );
        }
    }

    #[test]
    fn k0_unreadable_open_witness_refuses() {
        // No provable witness at selection time — a failed tap, or a
        // session with no PID witness at all — refuses at open: no
        // provable window can open on this broad.
        for (label, facts) in [
            ("failed", Err(PidContinuityRefusal::Terminal)),
            ("absent", Ok(None)),
        ] {
            let pool = test_pool();
            let scene = stage_single_provider(pool, 4);
            let mut ledger = SelectionLedger::new();
            let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
                .expect("live name resolves for the K0 window");
            let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
            let before = scripted_read(
                &scene.pool,
                &scene.plan,
                generation,
                CounterMode::Counts,
                &counts_for(&scene.plan, 100, 100),
                window_of(10, 20),
            );
            assert!(
                open_k0_window(
                    resolved,
                    limits_for(&scene.plan),
                    scene.pool.reserver(),
                    Ok(before),
                    facts,
                    &mut ledger,
                )
                .is_none(),
                "{label} witness opens no window"
            );
            assert_eq!(
                ledger
                    .selection
                    .as_ref()
                    .expect("selection records")
                    .refusal,
                Some("broad_plan_topology"),
                "{label} witness refuses at open"
            );
        }
    }

    #[test]
    fn k0_tail_exec_voids_detail() {
        // A tail EXEC for the selected caller — staged after the last
        // loop drain, past the pre-quiescence snapshot — voids as
        // caller-changed. The witness facts stay clean; only the tail
        // hits.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let pid = resolved.original.pid();
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        let tail = vec![k0_exec_record(pid, 200)];
        close_k0_window_with_tail(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &tail,
            0,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("promotion_caller_changed"),
            "a tail exec voids the detail"
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("detail").is_none());
        assert!(section.get("aggregate").is_none());
    }

    #[test]
    fn k0_tail_exit_voids_as_retired() {
        // A tail leader exit for the selected caller voids as a
        // retirement, not a change: the caller is gone, not replaced.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let pid = resolved.original.pid();
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        let tail = vec![k0_exit_record(pid, 200)];
        close_k0_window_with_tail(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &tail,
            0,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("promotion_caller_retired"),
            "a tail exit retires the detail"
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("detail").is_none());
        assert!(section.get("aggregate").is_none());
    }

    #[test]
    fn k0_tail_malformed_voids_as_changed() {
        // A malformed tail record fails closed as caller-changed: the
        // witness would have faulted on it had the tap been live.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        close_k0_window_with_tail(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &[],
            1,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("promotion_caller_changed"),
            "a malformed tail fails closed"
        );
    }

    #[test]
    fn k0_tail_other_pid_ignores() {
        // Preservation: a tail EXEC for a different PID leaves the
        // window alone — the scan matches the selected caller only.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let other = resolved.original.pid().wrapping_add(7);
        assert_ne!(other, resolved.original.pid());
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        let tail = vec![k0_exec_record(other, 200)];
        close_k0_window_with_tail(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &tail,
            0,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            None,
            "another PID's tail exec is not our caller"
        );
        let composed = with_selected_detail(serde_json::json!({"evidence": {}}), &ledger);
        let section = &composed["evidence"]["selected_detail"];
        assert!(section.get("detail").is_some());
    }

    #[test]
    fn k0_no_tail_records_unchanged() {
        // Preservation: an empty tail through the tail close leaves a
        // healthy window unchanged — the same success as the plain
        // close.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        close_k0_window_with_tail(
            window,
            &scene.plan,
            Ok(after),
            k0_clean(),
            true,
            &[],
            0,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            None,
            "an empty tail changes nothing"
        );
    }

    #[test]
    fn k0_unclean_and_retired_voids_as_broad_stopping() {
        // Precedence: an unclean close boundary beats a retired slot —
        // contract step 1 wins over step 2, so the word pins the order.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let mut retired = scene.plan.clone();
        retired.slots.retain(|slot| slot.index != 2);
        let retired_counts: Vec<(u64, u64, u64)> =
            retired.slots.iter().map(|_| (110, 110, 0)).collect();
        let after = scripted_read(
            &scene.pool,
            &retired,
            generation,
            CounterMode::Counts,
            &retired_counts,
            window_of(20, 30),
        );
        close_k0_window(window, &retired, Ok(after), k0_clean(), false, &mut ledger);
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("broad_stopping"),
            "unclean beats retired"
        );
    }

    #[test]
    fn k0_retired_and_exec_voids_as_not_published() {
        // Precedence: a retired slot beats an in-window exec —
        // contract step 2 wins over step 3, so the word pins the order.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let mut retired = scene.plan.clone();
        retired.slots.retain(|slot| slot.index != 2);
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        let exec = k0_facts_after(7, |tap| {
            tap.observe_record(&k0_exec_record(7, 200));
        });
        close_k0_window(
            window,
            &retired,
            Ok(after),
            Ok(Some(exec)),
            true,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("not_published"),
            "retired beats exec"
        );
    }

    #[test]
    fn k0_exec_and_failed_read_voids_as_caller_changed() {
        // Precedence: an in-window exec beats a failed close read —
        // contract step 3 wins over step 4, so the word pins the order.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 4);
        let mut ledger = SelectionLedger::new();
        let resolved = k0_stage(&scene, "C_Toggle0002", &mut ledger)
            .expect("live name resolves for the K0 window");
        let generation = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            generation,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let window = open_k0_window(
            resolved,
            limits_for(&scene.plan),
            scene.pool.reserver(),
            Ok(before),
            k0_clean(),
            &mut ledger,
        )
        .expect("a healthy selection-time read opens the window");
        let exec = k0_facts_after(7, |tap| {
            tap.observe_record(&k0_exec_record(7, 200));
        });
        close_k0_window(
            window,
            &scene.plan,
            Err(ReadStage::BankQuarantined),
            Ok(Some(exec)),
            true,
            &mut ledger,
        );
        assert_eq!(
            ledger
                .selection
                .as_ref()
                .expect("selection records")
                .refusal,
            Some("promotion_caller_changed"),
            "exec beats a failed read"
        );
    }
}
