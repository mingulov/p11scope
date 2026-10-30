//! SPDX-License-Identifier: GPL-3.0-or-later
//! Selected-detail handoff→gate adapter (6.15 phase 2).
//!
//! Maps a proved caller/provider request plus its selected-endpoint receipt
//! to the published physical index and the genuine child envelope, across
//! the two-phase reserve/bind shape. Design basis: WF §D2.3 as amended by
//! R2-D2-A…E, on the adjudicated M1 (re-host on Inventory: the promotion
//! lifecycle service owns the runtime; the pre-view broad-banks read is the
//! baseline; the promotion request path carries the endpoint receipt;
//! existing cancel + reselect), M2 (additive-first report rows, no schema
//! v2) and M3 (reserve-split, `WindowActive` as a product rule).
//!
//! The driver flow this module serves (driver wiring itself is a follow-up
//! packet; tests in this module act as the driver against the real seams):
//! take the request once → resolve the bundle exactly as the Inventory
//! resolver does → [`reserve_detail_window`] (validate + charge +
//! before-mark, no generation; the reservation is placed in driver-owned
//! custody before the worker starts) → `SelectedLifecycleService::start`
//! with [`GatedActivationSource`] wrapping the genuine minter → on delivery
//! the CAS seam binds the sealed generation, parks the window in custody
//! and delegates the one CAS → on `Install` the driver takes the `Active`
//! window (absent/`Unactivated` ⇒ reclaim for disposal, never install) →
//! at end the lane winds down through genuine disposal first, then
//! [`close_detail_window`] runs against the still-live broad banks.
//!
//! Stop linearization: the CAS inside `activate` is the point. A stop or
//! cancel observed before delivery skips the CAS (the existing lifecycle
//! cancel check) and the reservation closes as `Unactivated`; once the CAS
//! has won, the stop owns the tail (lane disposal, then window close, then
//! broad teardown). The activation source is `'static` and holds no broad
//! handle, so no stopped re-read can run inside `activate` itself: that
//! half of R2-D2-D needs a native-owned stop/CAS ordering and stays a
//! recorded follow-up. What this module does instead is structural: the
//! reservation reaches shared custody before the worker starts, so every
//! cancel/failure path still ends in exactly one of {close `Active`, close
//! `Unactivated`, explicit `close_refused` ledger entry} — never a silent
//! charge drop with the source.

use super::counter_collector::{
    CounterCollector, CounterDeltas, CounterLimits, CounterObservation, CounterRead, ReadStage,
};
use crate::attach::Session;
use crate::attach::capture::NativeDomainId;
use crate::attach::counter_banks::{
    AdmissionGuard, BroadReadMark, BroadToggleFacts, CounterBanks, CounterDetailLineage,
    CounterDetailWindow, DetailToggleDrift, DetailToggleRefusal, DetailWindowReservation,
    ReservationAbandonment,
};
use crate::attach::selected_detailed::baseline::PromotionImageBaseline;
use crate::discovery::caller_registry::{CallerId, ModuleId};
use crate::discovery::identity::{PinnedContentKey, PinnedObjects};
use crate::inventory_promotion::lifecycle::{
    NativeActivationRefusal, NativeActivationSource, NativeCasReceipt, PreparationBundle,
    SelectedActivationBinding,
};
use crate::inventory_promotion::{PromotionRequest, RequestId};
use crate::inventory_semantics::AttestedSubset;
use crate::inventory_semantics::selected::ProvisionalSelectedLane;
use crate::plan::{AdmissionPolicy, AttachKey, AttachPlan};
use crate::process::PidPin;
use crate::semantics_edge::resources::SemanticResourceReserver;
use p11scope_ebpf_common::CounterMode;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Why the adapter refused before/without touching the lifecycle service.
/// [`DetailToggleRefusal`] stays the gate's own error; this maps the
/// adapter's pre-checks. Never merged into `PromotionRefusal` silently:
/// the driver records both vocabularies in the window ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectedDetailRefusal {
    Gate(DetailToggleRefusal),
    /// The endpoint is not uniquely resolved for this request: the
    /// request carries no receipt, the receipt names another view, the
    /// provider subset is not exactly one object, the offset matches
    /// other than one child slot, or the broad plan matches other than
    /// one row. Never first-match.
    EndpointUnresolved,
    /// A child slot points outside the single required provider object
    /// (forwarded/dependency entry): the gate would refuse `Foreign`;
    /// the adapter names it distinctly before charging.
    ChildForeignSlot,
    /// The broad plan or the bracketing read is not this broad capture:
    /// misindexed slots, a non-`Counters` admission policy, a stale or
    /// foreign bracketing read, or a failed read offered as a bracket.
    BroadPlanTopology,
    /// One detail window at a time (M3 product rule): custody already
    /// holds a reservation or a bound window.
    WindowActive,
}

/// The resolved selection: the published broad original index plus the
/// physical key it names. The gate re-validates both against live banks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResolvedEndpoint {
    pub(crate) selected: u32,
    pub(crate) physical: AttachKey,
}

/// Resolve the request's endpoint receipt to the published broad row
/// (R2-D2-A): the unique broad plan slot whose file offset equals the
/// receipt's offset on the convert subset's required provider file.
/// Content keys narrow the file match across pin stores; the gate's
/// reserve authoritatively proves it against live custody. Anything
/// other than exactly one candidate refuses, never first-matches.
pub(crate) fn resolve_endpoint(
    request: &PromotionRequest,
    convert: &AttestedSubset,
    broad_plan: &AttachPlan,
    broad_objects: &PinnedObjects,
) -> Result<ResolvedEndpoint, SelectedDetailRefusal> {
    // The viewed request must carry the selected endpoint (R2-D2-A);
    // a receipt for another view is stale, never rebound.
    let receipt = request
        .endpoint()
        .ok_or(SelectedDetailRefusal::EndpointUnresolved)?;
    if receipt.view() != request.viewed().revision() {
        return Err(SelectedDetailRefusal::EndpointUnresolved);
    }
    // Exactly one required provider object: an ambiguous or empty
    // subset never picks a first.
    let required = convert.required();
    if required.len() != 1 {
        return Err(SelectedDetailRefusal::EndpointUnresolved);
    }
    let (&required_object, _) = required.iter().next().expect("exactly one required object");
    let slots = convert.plan().slots.as_slice();
    // Every child slot on the required object: a slot outside it is
    // a forwarded/dependency entry (the gate would refuse Foreign;
    // the adapter names it before charging).
    if slots.iter().any(|slot| slot.object != required_object) {
        return Err(SelectedDetailRefusal::ChildForeignSlot);
    }
    // The unique child slot for the receipt's offset.
    let mut child = None;
    for slot in slots {
        if slot.file_offset == receipt.file_offset() {
            if child.is_some() {
                return Err(SelectedDetailRefusal::EndpointUnresolved);
            }
            child = Some(slot);
        }
    }
    let child = child.ok_or(SelectedDetailRefusal::EndpointUnresolved)?;
    // The unique broad row: the receipt's offset on the same file.
    // Content keys narrow the file match across pin stores (raw ids
    // are never compared); the gate's reserve then proves the match
    // authoritatively against live custody.
    let child_content = convert
        .pins()
        .content_key(child.object)
        .ok_or(SelectedDetailRefusal::EndpointUnresolved)?;
    let mut selected = None;
    for (index, slot) in broad_plan.slots.iter().enumerate() {
        if slot.file_offset != receipt.file_offset() {
            continue;
        }
        let Ok(index) = u32::try_from(index) else {
            return Err(SelectedDetailRefusal::BroadPlanTopology);
        };
        if slot.index != index {
            return Err(SelectedDetailRefusal::BroadPlanTopology);
        }
        let Some(content) = broad_objects.content_key(slot.object) else {
            continue;
        };
        if content != child_content {
            continue;
        }
        if selected.is_some() {
            return Err(SelectedDetailRefusal::EndpointUnresolved);
        }
        selected = Some((index, slot));
    }
    let (selected, slot) = selected.ok_or(SelectedDetailRefusal::EndpointUnresolved)?;
    Ok(ResolvedEndpoint {
        selected,
        physical: AttachKey {
            object: slot.object,
            file_offset: slot.file_offset,
        },
    })
}

/// A bound window: `Active` once the CAS has won (or may have), or
/// `Unactivated` when the reservation never reached a successful CAS
/// (bind refusal, CAS refusal, cancel, preparation failure). Both close
/// through [`close_detail_window`]; only the ledger state differs.
#[derive(Debug)]
pub(crate) enum BoundWindow {
    Active(CounterDetailWindow),
    Unactivated(CounterDetailWindow),
}

/// The sealed prepared-child identity for one reservation (R2-D2-B):
/// the original custody, the pre-view baseline, and the required
/// provider/endpoint coverage the reservation was proved against.
/// Minted ONLY from a [`PreparationBundle`] (reserve and worker sides)
/// or from the sealed [`ProvisionalSelectedLane`] (delivered side):
/// the reserve side seals one into custody, the worker side carries
/// one in the activation source, and the bind refuses unless both the
/// worker-side and the delivered-lane identities agree with the
/// reservation — so a reservation for provider A can never bind a
/// prepared child for provider B, even with an identical original and
/// image. Numeric object ids are never compared: they are store-local.
pub(crate) struct PreparedChildReceipt {
    original: Arc<PidPin>,
    baseline: PromotionImageBaseline,
    required: PinnedContentKey,
    slots: Vec<(PinnedContentKey, u64)>,
}

impl PreparedChildReceipt {
    /// Seal the bundle's prepared-child identity: the original custody,
    /// the pre-view baseline, the one required provider's content key
    /// and every child slot's (content key, offset), sorted. `None`
    /// when the subset is not exactly one pinned provider (ambiguous,
    /// empty or unpinned): such a bundle never seals a reservation.
    pub(crate) fn of_bundle(bundle: &PreparationBundle) -> Option<Self> {
        Self::of_parts(
            bundle.convert_subset(),
            &bundle.original,
            &bundle.baseline,
        )
    }

    /// Seal the delivered lane's prepared-child identity: the sealed
    /// original custody, baseline, and conversion envelope the worker
    /// actually prepared. `None` when the lane's subset is not exactly
    /// one pinned provider: such a lane never binds.
    pub(crate) fn of_lane(lane: &ProvisionalSelectedLane) -> Option<Self> {
        Self::of_parts(lane.convert_subset(), lane.original(), lane.baseline())
    }

    fn of_parts(
        convert: &AttestedSubset,
        original: &Arc<PidPin>,
        baseline: &PromotionImageBaseline,
    ) -> Option<Self> {
        if convert.required().len() != 1 {
            return None;
        }
        let (&required_object, _) = convert
            .required()
            .iter()
            .next()
            .expect("exactly one required object");
        let required = convert.pins().content_key(required_object)?;
        let mut slots = Vec::with_capacity(convert.plan().slots.len());
        for slot in &convert.plan().slots {
            slots.push((convert.pins().content_key(slot.object)?, slot.file_offset));
        }
        slots.sort();
        Some(Self {
            original: Arc::clone(original),
            baseline: baseline.clone(),
            required,
            slots,
        })
    }

    /// Whether two sealed identities name the same prepared child: the
    /// SAME original custody (one `Arc`, never re-pinned numbers — the
    /// reserve, source and worker share one bundle), the same required
    /// provider file and the same child slot coverage. The baseline
    /// rides along for the bind-time image check; same-bundle
    /// construction (proved by custody plus coverage) implies it.
    pub(crate) fn agrees_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.original, &other.original)
            && self.required == other.required
            && self.slots == other.slots
    }

    pub(crate) fn baseline(&self) -> &PromotionImageBaseline {
        &self.baseline
    }

    pub(crate) fn original(&self) -> &Arc<PidPin> {
        &self.original
    }
}

impl std::fmt::Debug for PreparedChildReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedChildReceipt(<retained>)")
    }
}

/// A placed reservation plus its sealed prepared-child identity: the two
/// move together through custody (take-once), so the bind always
/// compares the worker-side identity against the identity sealed at
/// reserve — never against re-derived or caller-supplied values.
#[derive(Debug)]
pub(crate) struct ReservedDetailWindow {
    reservation: DetailWindowReservation,
    receipt: PreparedChildReceipt,
}

impl ReservedDetailWindow {
    pub(crate) fn new(reservation: DetailWindowReservation, receipt: PreparedChildReceipt) -> Self {
        Self {
            reservation,
            receipt,
        }
    }

    pub(crate) fn selected(&self) -> u32 {
        self.reservation.selected()
    }

    pub(crate) fn physical(&self) -> AttachKey {
        self.reservation.physical()
    }

    pub(crate) fn mark_before(&self) -> &BroadReadMark {
        self.reservation.mark_before()
    }

    /// Attach the custody's admission guard at placement.
    pub(crate) fn admit(&mut self, guard: AdmissionGuard) {
        self.reservation.admit(guard);
    }

    /// Abandon a never-bound reservation (releases the charge and the
    /// admission; the seal drops with it — nothing was ever bound).
    pub(crate) fn abandon(self) -> ReservationAbandonment {
        self.reservation.abandon()
    }

    /// Bind the sealed detail generation, dropping the seal: for direct
    /// binds outside the CAS seam (tests, never-bound paths). The bind
    /// seam compares through [`bind_with_receipt`] instead.
    pub(crate) fn bind_generation(self, generation: u64) -> CounterDetailWindow {
        self.reservation.bind_generation(generation)
    }

    /// Bind for the CAS seam, keeping the sealed identity for the
    /// agreement check.
    pub(crate) fn bind_with_receipt(
        self,
        generation: u64,
    ) -> (CounterDetailWindow, PreparedChildReceipt) {
        (self.reservation.bind_generation(generation), self.receipt)
    }
}

#[derive(Debug)]
enum DetailWindowSlot {
    Vacant,
    Reserved(ReservedDetailWindow),
    Bound(BoundWindow),
}

/// Driver-owned take-once custody for the reservation/window. The
/// reservation is placed here by [`reserve_detail_window`] before the
/// worker starts (so cancel/failure paths still close it); the
/// activation source holds a clone of this handle, takes the
/// reservation exactly once at the CAS seam, and parks the bound
/// window back for the driver. `PendingInstall` stays untouched.
///
/// Driver-ownership boundary: custody assumes a single-threaded
/// driver tick (reserve → take → park → take → close). The
/// `Arc`/`Mutex`/`AtomicUsize` make sharing safe, but they do NOT
/// serialize multi-step operations: concurrent drivers must serialize
/// externally, or a take-bind-park sequence races. Ordinary drop of a
/// taken value releases admission (fail-safe) but emits no ledger
/// event: the driver still owes exactly one explicit terminal
/// (close, abandon, or a recorded close-refused entry).
#[derive(Debug, Clone)]
pub(crate) struct DetailWindowCustody {
    slot: Arc<Mutex<DetailWindowSlot>>,
    admissions: Arc<AtomicUsize>,
}

impl DetailWindowCustody {
    pub(crate) fn new() -> Self {
        Self {
            slot: Arc::new(Mutex::new(DetailWindowSlot::Vacant)),
            admissions: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, DetailWindowSlot> {
        self.slot.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Whether a window is admitted: custody holds a reservation or a
    /// bound window, OR a taken reservation/window is still alive (its
    /// admission guard travels with the value until the terminal
    /// close/abandon). The reserve-time `WindowActive` product rule
    /// reads this.
    pub(crate) fn is_occupied(&self) -> bool {
        !matches!(*self.lock(), DetailWindowSlot::Vacant)
            || self.admissions.load(Ordering::SeqCst) > 0
    }

    /// Place a fresh reservation; fails (returning it) when occupied —
    /// including while a taken reservation/window is still alive. On
    /// success the reservation is admitted: its guard travels with it
    /// through take, bind and park until the terminal disposition.
    #[allow(clippy::result_large_err)] // Cold path returning the unplaced reservation for explicit handling.
    pub(crate) fn place_reserved(
        &self,
        mut reservation: ReservedDetailWindow,
    ) -> Result<(), ReservedDetailWindow> {
        let mut slot = self.lock();
        if !matches!(*slot, DetailWindowSlot::Vacant) || self.admissions.load(Ordering::SeqCst) > 0
        {
            return Err(reservation);
        }
        reservation.admit(AdmissionGuard::mint(&self.admissions));
        *slot = DetailWindowSlot::Reserved(reservation);
        Ok(())
    }

    /// Take the reservation exactly once; `None` unless reserved.
    /// A bound window is never taken through this path.
    pub(crate) fn take_reserved(&self) -> Option<ReservedDetailWindow> {
        let mut slot = self.lock();
        match std::mem::replace(&mut *slot, DetailWindowSlot::Vacant) {
            DetailWindowSlot::Reserved(reservation) => Some(reservation),
            taken => {
                *slot = taken;
                None
            }
        }
    }

    /// Park a bound window; fails (returning it) when the slot is
    /// occupied. The window normally inherits its admission guard
    /// from its reservation; a guard-less window is admitted here so
    /// parking never creates an untracked window.
    #[allow(clippy::result_large_err)] // Cold path returning the unparked window for explicit handling.
    pub(crate) fn place_bound(&self, mut window: BoundWindow) -> Result<(), BoundWindow> {
        let mut slot = self.lock();
        match *slot {
            DetailWindowSlot::Vacant => {
                match &mut window {
                    BoundWindow::Active(inner) | BoundWindow::Unactivated(inner) => {
                        inner.admit_unadmitted(AdmissionGuard::mint(&self.admissions));
                    }
                }
                *slot = DetailWindowSlot::Bound(window);
                Ok(())
            }
            _ => Err(window),
        }
    }

    /// Take the bound window exactly once; `None` unless bound.
    pub(crate) fn take_bound(&self) -> Option<BoundWindow> {
        let mut slot = self.lock();
        match std::mem::replace(&mut *slot, DetailWindowSlot::Vacant) {
            DetailWindowSlot::Bound(window) => Some(window),
            taken => {
                *slot = taken;
                None
            }
        }
    }
}

impl Default for DetailWindowCustody {
    fn default() -> Self {
        Self::new()
    }
}

/// The driver's bracket collector: the broad [`CounterCollector`] the
/// window's before/after acquisitions observe through, owned by the
/// driver across the window (one collector, so latch state is shared
/// between the brackets). A metrics-private collector behind a
/// driver-visible handle: only metrics code observes through it, via
/// [`accept_before_bracket`]/[`accept_after_bracket`].
pub(crate) struct BroadBracketCollector {
    collector: CounterCollector,
}

impl BroadBracketCollector {
    /// One bracket collector over the broad plan's shape (`rows` plan
    /// slots, `rv_keys` return-value keys) with a reserver handle for
    /// the collector's own baseline storage (handles are cheap:
    /// `pool.reserver()` mints them on demand).
    pub(crate) fn new(rows: usize, rv_keys: usize, reserve: SemanticResourceReserver) -> Self {
        Self {
            collector: CounterCollector::new(CounterLimits { rows, rv_keys }, reserve),
        }
    }

    /// Tests-only direct observe: drives the collector into latched
    /// state exactly as a production read path would, so twins prove
    /// acceptance refuses on pre-latched collectors. Production
    /// observes only through the accept functions.
    #[cfg(test)]
    pub(super) fn observe_for_test(
        &mut self,
        source: Result<CounterRead, ReadStage>,
    ) -> CounterObservation {
        self.collector.observe(source)
    }
}

impl std::fmt::Debug for BroadBracketCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BroadBracketCollector(<held>)")
    }
}

/// An accepted bracketing acquisition: the seq assigned to it, its
/// real acquisition identity (generation, mode, window, row count),
/// and — for `Advanced` observations only — the exact interval deltas
/// from the previously installed baseline to this read, with their
/// charged storage. Minted ONLY by observing the exact acquisition
/// through the broad collector
/// ([`accept_before_bracket`]/[`accept_after_bracket`]); the session
/// reserve path brackets on these, never on driver counts or
/// discarded reads. `Initial` and `GenerationChanged` carry no
/// interval (`None`, never fabricated zeros); failed acquisitions
/// mint no receipt at all.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AcceptedBracket {
    pub(crate) seq: u64,
    pub(crate) generation: NonZeroU64,
    pub(crate) mode: CounterMode,
    pub(crate) window: Option<(u64, u64)>,
    pub(crate) rows: usize,
    deltas: Option<CounterDeltas>,
}

impl AcceptedBracket {
    /// The accepted interval's deltas, when this receipt closes an
    /// interval (`Advanced` only). Metrics-owned: only metrics code
    /// renders these (the driver packet's report composer calls
    /// [`render_aggregate_bracket`]); the driver never holds a
    /// `CounterDeltas`.
    pub(super) fn deltas(&self) -> Option<&CounterDeltas> {
        self.deltas.as_ref()
    }
}

/// How the final acquisition checked at close: fresh (seq assigned),
/// explicitly unavailable (the acquisition failed — the last accepted
/// seq brackets the close but never masquerades as fresh), or
/// mismatched (acquired but defective or collector-rejected, disclosed
/// and never promoted).
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AfterBracketAcceptance {
    Fresh(AcceptedBracket),
    Unavailable,
    Mismatched(&'static str),
}

/// Map an acquisition-stage failure to the adapter refusal (reads the
/// banks never produced): a missing counter binding and quarantine
/// keep their gate word; anything else is an unbracketable topology.
fn read_stage_refusal(stage: ReadStage) -> SelectedDetailRefusal {
    use super::counter_collector::ReadStage as Stage;
    use super::counter_reader::ReaderShapeCause;
    match stage {
        Stage::Shape(ReaderShapeCause::BindingAbsent) => {
            SelectedDetailRefusal::Gate(DetailToggleRefusal::BroadNotCounter)
        }
        Stage::BankQuarantined => SelectedDetailRefusal::Gate(DetailToggleRefusal::Quarantined),
        _ => SelectedDetailRefusal::BroadPlanTopology,
    }
}

/// Read the accepted receipt off the collector's installed baseline:
/// the real acquisition window and identity of the exact read the
/// collector just accepted — never a reconstructed or earlier read —
/// plus that observation's interval deltas when it closed one
/// (`Advanced` only; `Initial`/`GenerationChanged` carry none).
fn accepted_receipt(
    collector: &CounterCollector,
    assigned: u64,
    deltas: Option<CounterDeltas>,
) -> AcceptedBracket {
    let installed = collector
        .current()
        .expect("acceptance installs the observed read");
    let view = installed.view();
    AcceptedBracket {
        seq: assigned,
        generation: view.generation,
        mode: view.mode,
        window: view
            .window
            .map(|window| (window.started_ns, window.finished_ns)),
        rows: view.rows.map(|rows| rows.len()).unwrap_or(0),
        deltas,
    }
}

/// Observe the exact before acquisition through the broad collector
/// and assign its bracket seq (R2-D2-C): the seq advances ONLY on
/// actual acceptance (`Initial`/`Advanced`/`GenerationChanged`). A
/// failed, foreign, or healthy-topology mismatch refuses with the
/// collector baseline and the seq untouched. A same-generation
/// unhealthy or failed-rows acquisition also refuses with the seq
/// untouched, but latches the collector's sticky loss first: a later
/// healthy same-generation read must stay unavailable, per the
/// collector contract. Only a fresh generation recovers.
pub(super) fn accept_before_bracket(
    brackets: &mut BroadBracketCollector,
    source: Result<CounterRead, ReadStage>,
    broad_plan: &AttachPlan,
    facts_generation: NonZeroU64,
    seq: &mut u64,
) -> Result<AcceptedBracket, SelectedDetailRefusal> {
    let read = match source {
        Ok(read) => read,
        Err(stage) => {
            brackets.collector.observe(Err(stage));
            return Err(read_stage_refusal(stage));
        }
    };
    {
        let view = read.view();
        if view.generation != facts_generation {
            // Foreign generation: refuse without observing, so a
            // foreign input can never poison the owner's sticky state.
            return Err(SelectedDetailRefusal::BroadPlanTopology);
        }
        let rows = match view.rows {
            Ok(rows) => rows,
            Err(_) => {
                // Same-generation failed rows: latch the sticky loss
                // with the seq untouched.
                let _ = brackets.collector.observe(Ok(read));
                return Err(SelectedDetailRefusal::BroadPlanTopology);
            }
        };
        if bracket_signal_defect(view).is_some() {
            // Same-generation unhealthy signals: latch the sticky loss
            // with the seq untouched.
            let _ = brackets.collector.observe(Ok(read));
            return Err(SelectedDetailRefusal::BroadPlanTopology);
        }
        if !bracket_rows_match_plan(rows, broad_plan) {
            // Healthy topology mismatch: refuse without observing.
            return Err(SelectedDetailRefusal::BroadPlanTopology);
        }
    }
    // The u64 seq space is effectively inexhaustible; refusing rather
    // than reusing a seq keeps exhaustion fail-closed.
    let assigned = seq
        .checked_add(1)
        .ok_or(SelectedDetailRefusal::BroadPlanTopology)?;
    match brackets.collector.observe(Ok(read)) {
        CounterObservation::Initial | CounterObservation::GenerationChanged { .. } => {
            *seq = assigned;
            Ok(accepted_receipt(&brackets.collector, assigned, None))
        }
        CounterObservation::Advanced { deltas, .. } => {
            *seq = assigned;
            Ok(accepted_receipt(&brackets.collector, assigned, Some(deltas)))
        }
        CounterObservation::ReadFailed(stage) => Err(read_stage_refusal(stage)),
        CounterObservation::Unavailable(_) => Err(SelectedDetailRefusal::BroadPlanTopology),
    }
}

/// Observe the exact after acquisition through the broad collector
/// (R2-D2-C): a fresh acceptance assigns the close seq; a failed
/// acquisition is explicitly unavailable; a defective or
/// collector-rejected acquisition is mismatched — never Matched,
/// never promoted to fresh. The seq advances only on acceptance. A
/// same-generation unhealthy or failed-rows acquisition latches the
/// collector's sticky loss first (seq untouched), so a later healthy
/// same-generation read stays mismatched; foreign and
/// healthy-topology mismatches disclose without observing.
pub(super) fn accept_after_bracket(
    brackets: &mut BroadBracketCollector,
    source: Result<CounterRead, ReadStage>,
    broad_plan: &AttachPlan,
    mode: CounterMode,
    generation: NonZeroU64,
    seq: &mut u64,
) -> AfterBracketAcceptance {
    let read = match source {
        Ok(read) => read,
        Err(stage) => {
            brackets.collector.observe(Err(stage));
            return AfterBracketAcceptance::Unavailable;
        }
    };
    if let Some(reason) = after_bracket_mismatch(&read, mode, generation, broad_plan) {
        // Same-generation genuine loss evidence latches the sticky
        // state with the seq untouched; anything else discloses
        // without observing.
        let view = read.view();
        if view.generation == generation
            && (view.rows.is_err() || bracket_signal_defect(view).is_some())
        {
            let _ = brackets.collector.observe(Ok(read));
        }
        return AfterBracketAcceptance::Mismatched(reason);
    }
    let Some(assigned) = seq.checked_add(1) else {
        // u64 seq space exhausted (unreachable): disclose as rejected
        // without advancing or promoting anything.
        return AfterBracketAcceptance::Mismatched("rejected");
    };
    match brackets.collector.observe(Ok(read)) {
        CounterObservation::Initial | CounterObservation::GenerationChanged { .. } => {
            *seq = assigned;
            AfterBracketAcceptance::Fresh(accepted_receipt(&brackets.collector, assigned, None))
        }
        CounterObservation::Advanced { deltas, .. } => {
            *seq = assigned;
            AfterBracketAcceptance::Fresh(accepted_receipt(
                &brackets.collector,
                assigned,
                Some(deltas),
            ))
        }
        CounterObservation::ReadFailed(_) | CounterObservation::Unavailable(_) => {
            AfterBracketAcceptance::Mismatched("rejected")
        }
    }
}

/// Phase 1 (driver tick, BEFORE `SelectedLifecycleService::start`):
/// resolve the endpoint receipt, validate the broad plan, observe the
/// live bracketing acquisition through the bracket collector, charge
/// and mark through the gate, and place the reservation in custody.
/// Refusal records the [`SelectedDetailRefusal`], queues nothing and
/// starts no worker; aggregate capture is untouched. The bracket seq
/// assigns only on actual collector acceptance (the read-seq rule:
/// seqs count successful observes only, minted here, never by the
/// gate) and returns with the accepted receipt; `seq` is untouched on
/// refusal. STAGED (6.15): the live bracketing read needs running
/// maps; unit coverage runs through
/// [`reserve_detail_window_on_banks`] with an injected accepted read
/// over the same shared checks, plus [`accept_before_bracket`].
#[allow(clippy::too_many_arguments)] // One driver orchestration over all retained inputs; the bundle keeps preparation inputs together.
#[allow(dead_code)] // STAGED (6.15): the driver packet calls this; unit coverage runs banks-level.
pub(crate) fn reserve_detail_window(
    broad: &Session,
    broad_plan: &AttachPlan,
    broad_objects: &PinnedObjects,
    request: &PromotionRequest,
    bundle: &PreparationBundle,
    brackets: &mut BroadBracketCollector,
    seq: &mut u64,
    reserve: &SemanticResourceReserver,
    custody: &DetailWindowCustody,
) -> Result<AcceptedBracket, SelectedDetailRefusal> {
    let resolved = verify_reserve_inputs(request, bundle, broad_plan, broad_objects, custody)?;
    // The sealed prepared-child identity travels with the reservation
    // (R2-D2-B): a bundle that cannot seal it (ambiguous, empty or
    // unpinned subset) never reserves, before any charge.
    let receipt =
        PreparedChildReceipt::of_bundle(bundle).ok_or(SelectedDetailRefusal::EndpointUnresolved)?;
    // The live bracketing acquisition (R2-D2-C): the metrics
    // orchestration observes the EXACT acquisition through the broad
    // collector and assigns the bracket seq only on actual acceptance.
    let limits = CounterLimits {
        rows: broad_plan.slots.len(),
        rv_keys: crate::attach::counter_banks::COUNTER_RV_KEY_POOL,
    };
    let acquired =
        super::counter_reader::read_banked(broad, broad_plan, broad_objects, limits, reserve);
    let bracket = accept_before_bracket(
        brackets,
        acquired,
        broad_plan,
        broad.counter_collection_generation(),
        seq,
    )?;
    // The gate resolves child slot ids in the CONVERT store (its own
    // id space); broad objects only narrowed the bridge. Passing the
    // broad store here would misresolve every split-store child.
    let reservation = broad
        .reserve_gate_window(
            broad_plan,
            bundle.convert_subset().pins(),
            resolved.selected,
            bundle.convert_subset().plan().slots.as_slice(),
            bracket.seq,
            reserve,
        )
        .map_err(SelectedDetailRefusal::Gate)?;
    // Custody owns the reservation from before the worker starts; on
    // the impossible occupied race, abandon immediately (never a
    // silent drop) and report WindowActive.
    match custody.place_reserved(ReservedDetailWindow::new(reservation, receipt)) {
        Ok(()) => Ok(bracket),
        Err(reserved) => {
            reserved.abandon();
            Err(SelectedDetailRefusal::WindowActive)
        }
    }
}

/// Banks-level phase 1 with an injected accepted bracketing read: the
/// unit seam for the full reserve matrix (live Session/maps are
/// unavailable to unit tests). Production reaches the same shared
/// checks through [`reserve_detail_window`], which performs the
/// bracketing read internally.
#[allow(clippy::too_many_arguments)] // Test seam mirroring the driver orchestration above.
pub(super) fn reserve_detail_window_on_banks(
    banks: &CounterBanks,
    facts: BroadToggleFacts,
    broad_plan: &AttachPlan,
    broad_objects: &PinnedObjects,
    request: &PromotionRequest,
    bundle: &PreparationBundle,
    before_read: &CounterRead,
    read_seq_before: u64,
    reserve: &SemanticResourceReserver,
    custody: &DetailWindowCustody,
) -> Result<(), SelectedDetailRefusal> {
    let resolved = verify_reserve_inputs(request, bundle, broad_plan, broad_objects, custody)?;
    let receipt =
        PreparedChildReceipt::of_bundle(bundle).ok_or(SelectedDetailRefusal::EndpointUnresolved)?;
    verify_before_bracket(before_read, facts.generation, broad_plan)?;
    // The gate resolves child slot ids in the CONVERT store (its own
    // id space); broad objects only narrowed the bridge. Passing the
    // broad store here would misresolve every split-store child.
    let reservation = banks
        .reserve_detail_window(
            facts,
            broad_plan,
            bundle.convert_subset().pins(),
            resolved.selected,
            bundle.convert_subset().plan().slots.as_slice(),
            read_seq_before,
            reserve,
        )
        .map_err(SelectedDetailRefusal::Gate)?;
    match custody.place_reserved(ReservedDetailWindow::new(reservation, receipt)) {
        Ok(()) => Ok(()),
        Err(reserved) => {
            reserved.abandon();
            Err(SelectedDetailRefusal::WindowActive)
        }
    }
}

/// The shared reserve checks both entry points run: custody vacancy,
/// receipt binding, baseline/request agreement (against the bundle's
/// pre-view baseline), provider shape, endpoint uniqueness,
/// child-envelope closure, and broad-plan topology. Returns the
/// resolved selection; the caller then verifies its bracketing read
/// and calls the gate.
pub(crate) fn verify_reserve_inputs(
    request: &PromotionRequest,
    bundle: &PreparationBundle,
    broad_plan: &AttachPlan,
    broad_objects: &PinnedObjects,
    custody: &DetailWindowCustody,
) -> Result<ResolvedEndpoint, SelectedDetailRefusal> {
    // One window at a time, checked before any work (M3 product rule).
    if custody.is_occupied() {
        return Err(SelectedDetailRefusal::WindowActive);
    }
    // The bundle's pre-view baseline must agree with this request
    // (the driver checks this too per D10; the adapter checks its own
    // inputs): a mismatch untrusts the endpoint for this request.
    if !bundle.baseline.matches_request(request) {
        return Err(SelectedDetailRefusal::EndpointUnresolved);
    }
    // Broad-plan topology: densely indexed slots and the metrics
    // Counters admission policy (an Inventory/Detailed plan can never
    // satisfy the gate; passing one is a driver bug, refused here).
    for (index, slot) in broad_plan.slots.iter().enumerate() {
        let Ok(index) = u32::try_from(index) else {
            return Err(SelectedDetailRefusal::BroadPlanTopology);
        };
        if slot.index != index {
            return Err(SelectedDetailRefusal::BroadPlanTopology);
        }
    }
    if !matches!(broad_plan.admission_policy(), AdmissionPolicy::Counters(_)) {
        return Err(SelectedDetailRefusal::BroadPlanTopology);
    }
    resolve_endpoint(request, bundle.convert_subset(), broad_plan, broad_objects)
}

/// Read-intrinsic rejection of a bracketing acquisition, mirroring
/// the fail-closed inputs of the collector's own validation: a
/// saturated or contended producer, or nonzero kernel loss/control
/// evidence. `Some(reason)` names the defect for the after bracket;
/// the before bracket refuses on any of them. The session path
/// observes through the collector itself, which rejects these same
/// reads; this is the shared read-intrinsic half both paths enforce.
fn bracket_signal_defect(
    view: super::counter_collector::CounterReadView<'_>,
) -> Option<&'static str> {
    if view.health.saturated || view.health.contended {
        return Some("health");
    }
    // Exactly the evidence list the collector's validation rejects on
    // (counter_collector.rs): any nonzero count fails the read.
    let kernel = &view.kernel;
    if [
        kernel.ring_loss,
        kernel.start_insert_failures,
        kernel.unmatched_returns,
        kernel.rv_update_failures,
        kernel.cgroup_scope_failures,
        kernel.semantic_capture_failures,
        kernel.template_tail_failures,
        kernel.unregistered_mechanisms,
        kernel.abi_refusals,
        kernel.control.owner_poison,
        kernel.control.owner_admission_failures,
        kernel.control.identity_unavailable,
        kernel.control.root_failures,
    ]
    .into_iter()
    .any(|count| count != 0)
    {
        return Some("kernel");
    }
    None
}

/// Every row of a bracketing read names its plan slot exactly
/// (subset-tolerant like the gate's prefix rule: unpublished holes
/// legitimately read no row, but no row may name another broad's
/// slot).
fn bracket_rows_match_plan(
    rows: &[super::counter_collector::CounterRow],
    broad_plan: &AttachPlan,
) -> bool {
    rows.iter().all(|row| {
        let cell = row.view();
        broad_plan
            .slots
            .get(cell.slot as usize)
            .is_some_and(|slot| {
                slot.index == cell.slot
                    && slot.object == cell.target.object
                    && slot.file_offset == cell.target.file_offset
            })
    })
}

/// The shared before-bracket check: the offered read must be an
/// accepted read of this broad capture (generation, health, kernel
/// evidence, rows and plan all agree). A failed, foreign or unhealthy
/// read refuses; reserve never opens on an unbracketed mark.
pub(super) fn verify_before_bracket(
    before_read: &CounterRead,
    facts_generation: NonZeroU64,
    broad_plan: &AttachPlan,
) -> Result<(), SelectedDetailRefusal> {
    let view = before_read.view();
    // The bracketing read is fresh for this broad capture: stale or
    // foreign reads never bracket a reserve.
    if view.generation != facts_generation {
        return Err(SelectedDetailRefusal::BroadPlanTopology);
    }
    // A failed read is no bracket: reserve needs an accepted read.
    let rows = view
        .rows
        .map_err(|_| SelectedDetailRefusal::BroadPlanTopology)?;
    // A read the collector would reject is no bracket either.
    if bracket_signal_defect(view).is_some() {
        return Err(SelectedDetailRefusal::BroadPlanTopology);
    }
    if !bracket_rows_match_plan(rows, broad_plan) {
        return Err(SelectedDetailRefusal::BroadPlanTopology);
    }
    Ok(())
}

/// Phase 2 (inside the CAS seam): binds the sealed generation, then
/// delegates to the genuine minter. This is the ONLY new
/// [`NativeActivationSource`] in the packet; the raw donor Session
/// path is never used. The source holds no broad handle (`'static`
/// service ownership): bind validation runs on owned retained data
/// (per-object retained targets with live file checks, the sealed
/// prepared-child receipt) plus the presented child session and
/// binding.
pub(crate) struct GatedActivationSource {
    inner: Box<dyn NativeActivationSource>,
    custody: DetailWindowCustody,
    prepared: PreparedChildReceipt,
}

impl std::fmt::Debug for GatedActivationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GatedActivationSource(<retained>)")
    }
}

impl GatedActivationSource {
    /// The worker-side prepared-child identity comes sealed from the
    /// same bundle the worker prepares — never as loose baseline and
    /// original values independent of the reservation.
    pub(crate) fn new(
        inner: Box<dyn NativeActivationSource>,
        custody: DetailWindowCustody,
        prepared: PreparedChildReceipt,
    ) -> Self {
        Self {
            inner,
            custody,
            prepared,
        }
    }

    /// Bind validation (R2-D2-B) without the native CAS: takes the
    /// reservation exactly once, binds `expected.generation()`, then
    /// requires the worker-side prepared child AND the actually
    /// delivered lane to agree with the reservation's sealed identity
    /// (same original custody, same provider/endpoint coverage), the
    /// binding's domain to name the presented child session, the
    /// binding image's exec to still match the pre-view baseline row
    /// for the resolved original, and the retained child slots to
    /// still cover the reserved physical key on the same retained
    /// object (live file checks). Any mismatch parks the window
    /// `Unactivated` and refuses WITHOUT running the CAS; the
    /// lifecycle maps the refusal to its unchanged `ActivationFailed`
    /// path. Factored out of the activation seam so the full
    /// validation matrix runs without a live child Session.
    pub(crate) fn validate_and_bind(
        &mut self,
        expected: &SelectedActivationBinding,
        child_domain: Option<NativeDomainId>,
        delivered: &PreparedChildReceipt,
    ) -> Result<CounterDetailWindow, NativeActivationRefusal> {
        // Take the reservation exactly once: a missing reservation
        // (double activation, or a driver that never reserved)
        // refuses without a CAS and parks nothing.
        let Some(reserved) = self.custody.take_reserved() else {
            return Err(NativeActivationRefusal::BindingMismatch);
        };
        // Bind first (infallible): every failure below parks a
        // closeable Unactivated window instead of dropping the lease.
        let (window, sealed) = reserved.bind_with_receipt(expected.generation());
        // The prepared child the worker was built for must agree with
        // the reservation (same original custody, same provider and
        // endpoint coverage): an A-reservation never binds a B-child,
        // even with an identical original and image.
        if !sealed.agrees_with(&self.prepared) {
            self.park_unactivated(window);
            return Err(NativeActivationRefusal::BindingMismatch);
        }
        // The actually delivered lane must agree with the reservation
        // too: a reservation for A with a worker-side receipt for A
        // still refuses when the worker delivered B.
        if !sealed.agrees_with(delivered) {
            self.park_unactivated(window);
            return Err(NativeActivationRefusal::BindingMismatch);
        }
        // The binding's domain must name the presented child session
        // (the inner minter re-checks this at the CAS; the adapter
        // pre-check parks Unactivated without attempting it).
        if child_domain != Some(expected.domain()) {
            self.park_unactivated(window);
            return Err(NativeActivationRefusal::BindingMismatch);
        }
        // The binding image's exec plus the resolved original custody
        // must still match the pre-view baseline row. Only the exec
        // compares across the baseline: cookies are tickets inside
        // one domain, and the live cookie agreement is the permit's
        // and the minter's (against the live child), not the
        // reservation's.
        if !self
            .prepared
            .baseline()
            .matches_original_and_exec(self.prepared.original(), expected.image().exec_id)
        {
            self.park_unactivated(window);
            return Err(NativeActivationRefusal::BindingMismatch);
        }
        // The retained child slots must still cover the reserved
        // physical key on the same retained object (live file checks;
        // no banks access at this seam by construction).
        if window.validate_live_match().is_err() {
            self.park_unactivated(window);
            return Err(NativeActivationRefusal::BindingMismatch);
        }
        Ok(window)
    }

    fn park_unactivated(&self, window: CounterDetailWindow) {
        self.custody
            .place_bound(BoundWindow::Unactivated(window))
            .expect("take_reserved succeeded, so the slot is vacant");
    }
}

impl NativeActivationSource for GatedActivationSource {
    fn activate(
        &mut self,
        _session: &Session,
        expected: &SelectedActivationBinding,
    ) -> Result<NativeCasReceipt, NativeActivationRefusal> {
        // Without the sealed delivered lane, the delivered-child
        // binding cannot be established: refuse fail-closed without a
        // CAS, parking Unactivated. Production reaches
        // `activate_with_lane` through the lifecycle service instead.
        let Some(reserved) = self.custody.take_reserved() else {
            return Err(NativeActivationRefusal::BindingMismatch);
        };
        let (window, _) = reserved.bind_with_receipt(expected.generation());
        self.park_unactivated(window);
        Err(NativeActivationRefusal::BindingMismatch)
    }

    fn activate_with_lane(
        &mut self,
        session: &Session,
        expected: &SelectedActivationBinding,
        lane: &ProvisionalSelectedLane,
    ) -> Result<NativeCasReceipt, NativeActivationRefusal> {
        // Seal the delivered lane's identity from the actual sealed
        // lane (never from caller-supplied values); a lane that
        // cannot seal never binds.
        let Some(delivered) = PreparedChildReceipt::of_lane(lane) else {
            let Some(reserved) = self.custody.take_reserved() else {
                return Err(NativeActivationRefusal::BindingMismatch);
            };
            let (window, _) = reserved.bind_with_receipt(expected.generation());
            self.park_unactivated(window);
            return Err(NativeActivationRefusal::BindingMismatch);
        };
        // 1. take the reservation + bind the sealed generation +
        //    validate (parks Unactivated on any failure, no CAS).
        let window =
            self.validate_and_bind(expected, session.native_domain(), &delivered)?;
        // 2. delegate the one genuine CAS to the inner minter.
        match self.inner.activate(session, expected) {
            // 3. park Active on success, Unactivated on CAS refusal.
            Ok(receipt) => {
                self.custody
                    .place_bound(BoundWindow::Active(window))
                    .expect("take_reserved succeeded, so the slot is vacant");
                Ok(receipt)
            }
            Err(refusal) => {
                self.park_unactivated(window);
                Err(refusal)
            }
        }
    }
}

/// The after bracket for [`close_detail_window`]: the driver's final
/// successful-observe seq plus the collection mode and, when the final
/// broad read was accepted, that read. `read: None` is the explicit
/// failed-acquisition boundary: the last accepted seq brackets the
/// close but must never masquerade as a fresh after-read. The read
/// stays metrics-private (`CounterRead` is a collector type): only
/// metrics code builds brackets, from live or injected reads.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CloseBracket<'a> {
    seq_after: u64,
    mode: CounterMode,
    read: Option<&'a CounterRead>,
}

impl<'a> CloseBracket<'a> {
    pub(super) fn new(seq_after: u64, mode: CounterMode, read: Option<&'a CounterRead>) -> Self {
        Self {
            seq_after,
            mode,
            read,
        }
    }
}

/// How the after bracket checked against the live close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseBracketVerdict {
    /// The after read is fresh for this broad (generation, rows, mode,
    /// health and kernel evidence all match the close).
    Matched,
    /// No accepted final read (acquisition failed): the lineage still
    /// delivers with the live after-mark, but the read bracket is
    /// explicitly unavailable.
    AfterUnavailable,
    /// The offered after read does not bracket this close. The static
    /// names the first mismatch (`generation`, `rows`, `mode`,
    /// `read_failed`, `health`, `kernel`, or `rejected`); the close
    /// still delivers its true live marks, and the report carries the
    /// defect — never a quiet mismatch.
    Mismatched(&'static str),
}

/// A closed window: the lineage joining detail rows to broad rows,
/// the first broad-identity drift if any, the bracketing successful-
/// observe seqs, the after-bracket verdict, and — when the final
/// acquisition was freshly accepted — its receipt with that
/// interval's deltas for aggregate rendering. Carries no combined
/// totals: broad intervals render only from their own broad reads,
/// detail only from the child's own stream.
#[derive(Debug)]
pub(crate) struct DetailCloseReport {
    pub(crate) lineage: CounterDetailLineage,
    pub(crate) drift: Option<DetailToggleDrift>,
    pub(crate) seq_before: u64,
    pub(crate) seq_after: u64,
    pub(crate) bracket: CloseBracketVerdict,
    pub(crate) after_receipt: Option<AcceptedBracket>,
}

/// Map a session-path after acceptance to its close verdict plus the
/// preserved after receipt: `Fresh` stays `Matched` with its
/// interval; `Unavailable` and `Mismatched` carry no receipt (never
/// a fabricated delta). Shared by [`close_detail_window`] and its
/// twins (the live close needs running maps; twins drive this
/// mapping with receipts from [`accept_after_bracket`]).
fn map_after_acceptance(
    acceptance: AfterBracketAcceptance,
) -> (CloseBracketVerdict, Option<AcceptedBracket>) {
    match acceptance {
        AfterBracketAcceptance::Fresh(receipt) => (CloseBracketVerdict::Matched, Some(receipt)),
        AfterBracketAcceptance::Unavailable => (CloseBracketVerdict::AfterUnavailable, None),
        AfterBracketAcceptance::Mismatched(reason) => {
            (CloseBracketVerdict::Mismatched(reason), None)
        }
    }
}

/// Phase 3 (driver tick): close exactly once, after the child's own
/// terminal state is genuine (installed lane wound down / disposal
/// settled / reclaim settled). Consumes the window; the after-mark
/// comes from live banks, and the after acquisition is observed
/// through the bracket collector (R2-D2-C): a fresh acceptance
/// assigns the close seq, a failed final acquisition closes with an
/// explicit unavailable bracket, and a rejected one is disclosed as
/// mismatched — the last accepted read never masquerades as fresh. A
/// quarantined close refuses with no lineage (the driver records a
/// [`render_close_refused_row`] entry instead) — never a fabricated
/// after-mark. STAGED (6.15): the live after read needs running
/// maps; unit coverage runs through
/// [`close_detail_window_on_banks`] with an injected bracket over
/// the same shared verdict, plus [`accept_after_bracket`].
#[allow(clippy::too_many_arguments)]
// One driver orchestration over all retained inputs; the bracket collector and seq travel together.
#[allow(dead_code)] // STAGED (6.15): the driver packet calls this; unit coverage runs banks-level.
pub(crate) fn close_detail_window(
    window: CounterDetailWindow,
    broad: &Session,
    broad_plan: &AttachPlan,
    broad_objects: &PinnedObjects,
    mode: CounterMode,
    brackets: &mut BroadBracketCollector,
    seq: &mut u64,
    reserve: &SemanticResourceReserver,
) -> Result<DetailCloseReport, DetailToggleRefusal> {
    let generation = broad.counter_collection_generation();
    let seq_before = window.mark_before().seq;
    // The live after acquisition when the final scrape runs: observed
    // through the collector, with the close seq assigned only on
    // actual acceptance.
    let limits = CounterLimits {
        rows: broad_plan.slots.len(),
        rv_keys: crate::attach::counter_banks::COUNTER_RV_KEY_POOL,
    };
    let acquired =
        super::counter_reader::read_banked(broad, broad_plan, broad_objects, limits, reserve);
    let acceptance = accept_after_bracket(brackets, acquired, broad_plan, mode, generation, seq);
    let (bracket, after_receipt) = map_after_acceptance(acceptance);
    // On rejection `seq` is untouched: the last accepted seq brackets
    // the close, explicitly not fresh.
    let seq_after = *seq;
    let (lineage, drift) = window.close_on(broad, seq_after)?;
    Ok(DetailCloseReport {
        lineage,
        drift,
        seq_before,
        seq_after,
        bracket,
        after_receipt,
    })
}

/// Banks-level phase 3 with an injected after bracket: the unit seam
/// for the full close matrix (live Session/maps are unavailable to
/// unit tests). Production reaches the same shared verdict through
/// [`close_detail_window`], which performs the after read internally.
pub(super) fn close_detail_window_on_banks(
    window: CounterDetailWindow,
    banks: &CounterBanks,
    generation: NonZeroU64,
    broad_plan: &AttachPlan,
    bracket: &CloseBracket<'_>,
) -> Result<DetailCloseReport, DetailToggleRefusal> {
    let verdict = verify_after_bracket(bracket, generation, broad_plan);
    let seq_before = window.mark_before().seq;
    // The close always delivers its true live marks; a defective
    // bracket is reported in the verdict, never fixed up or hidden.
    // The banks-level seam observes no collector, so it carries no
    // after receipt (never a fabricated interval).
    let (lineage, drift) = window.close(banks, generation, bracket.seq_after)?;
    Ok(DetailCloseReport {
        lineage,
        drift,
        seq_before,
        seq_after: bracket.seq_after,
        bracket: verdict,
        after_receipt: None,
    })
}

/// The first defect of an offered after read, if any (generation,
/// mode, failed rows, unhealthy signals, foreign rows), shared by the
/// banks-level verdict and the session path's acceptance.
fn after_bracket_mismatch(
    read: &CounterRead,
    mode: CounterMode,
    generation: NonZeroU64,
    broad_plan: &AttachPlan,
) -> Option<&'static str> {
    let view = read.view();
    if view.generation != generation {
        return Some("generation");
    }
    if view.mode != mode {
        return Some("mode");
    }
    let rows = match view.rows {
        Ok(rows) => rows,
        Err(_) => return Some("read_failed"),
    };
    if let Some(reason) = bracket_signal_defect(view) {
        return Some(reason);
    }
    if !bracket_rows_match_plan(rows, broad_plan) {
        return Some("rows");
    }
    None
}

/// The shared after-bracket verdict both close paths report: the
/// offered read must be fresh for this broad (generation, rows, mode,
/// health and kernel evidence all agree) for
/// [`CloseBracketVerdict::Matched`]; no offered read is
/// [`CloseBracketVerdict::AfterUnavailable`]; anything else names its
/// first mismatch.
pub(super) fn verify_after_bracket(
    bracket: &CloseBracket<'_>,
    generation: NonZeroU64,
    broad_plan: &AttachPlan,
) -> CloseBracketVerdict {
    let Some(read) = bracket.read else {
        return CloseBracketVerdict::AfterUnavailable;
    };
    match after_bracket_mismatch(read, bracket.mode, generation, broad_plan) {
        None => CloseBracketVerdict::Matched,
        Some(reason) => CloseBracketVerdict::Mismatched(reason),
    }
}

/// The window-lifecycle events the driver records in the normal
/// bounded report path. Terminal transitions are recorded there;
/// screen/custody state alone is never that record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetailWindowEvent {
    Reserved,
    Bound,
    CasWon,
    CasRefused,
    Closed,
    CloseRefused,
    CancelledUnactivated,
}

impl DetailWindowEvent {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Bound => "bound",
            Self::CasWon => "cas_won",
            Self::CasRefused => "cas_refused",
            Self::Closed => "closed",
            Self::CloseRefused => "close_refused",
            Self::CancelledUnactivated => "cancelled_unactivated",
        }
    }
}

/// One additive window-ledger row for a lifecycle event. Static words
/// plus stable numeric IDs only, so the row needs no escaping.
pub(crate) fn render_window_event(
    event: DetailWindowEvent,
    request: RequestId,
    caller: CallerId,
    provider: ModuleId,
    seq: u64,
    note: Option<&str>,
) -> serde_json::Value {
    let mut row = serde_json::json!({
        "event": event.name(),
        "request": request.get(),
        "caller": caller.0,
        "provider": provider.0,
        "seq": seq,
    });
    if let Some(note) = note {
        row["note"] = serde_json::Value::String(note.to_string());
    }
    row
}

/// The additive lineage row joining one window's detail rows to its
/// broad rows (M2 additive-first: new `selected_detail` object, no
/// existing key touched, no schema v2). The only join between the
/// aggregate and detail ledgers; carries no sums.
pub(crate) fn render_lineage_row(
    request: &PromotionRequest,
    endpoint_offset: u64,
    report: &DetailCloseReport,
) -> serde_json::Value {
    let lineage = &report.lineage;
    serde_json::json!({
        "selected_detail": {
            "request": request.id().get(),
            "caller": request.caller().0,
            "provider": request.provider().0,
            "view": request.viewed().revision().get(),
            "endpoint_offset": endpoint_offset,
            "broad_original_index": lineage.broad_original_index,
            "broad_generation": lineage.broad_generation.get(),
            "detail_generation": lineage.detail_generation,
            "broad_read_seq_before": lineage.broad_read_seq_before,
            "broad_read_seq_after": lineage.broad_read_seq_after,
            "broad_mark_before": render_mark(&lineage.broad_mark_before),
            "broad_mark_after": render_mark(&lineage.broad_mark_after),
            "drift": render_drift(report.drift.as_ref()),
            "after_read": bracket_name(report.bracket),
        }
    })
}

fn render_mark(mark: &BroadReadMark) -> serde_json::Value {
    serde_json::json!({
        "seq": mark.seq,
        "generation": mark.generation.get(),
        "indices": mark.indices,
        "bank_ids": mark.bank_ids,
        "transaction": mark.transaction.map(NonZeroU64::get),
    })
}

fn render_drift(drift: Option<&DetailToggleDrift>) -> serde_json::Value {
    match drift {
        None => serde_json::Value::Null,
        Some(DetailToggleDrift::Generation { before, after }) => serde_json::json!({
            "kind": "generation",
            "before": before.get(),
            "after": after.get(),
        }),
        Some(DetailToggleDrift::Indices { before, after }) => serde_json::json!({
            "kind": "indices",
            "before": before,
            "after": after,
        }),
        Some(DetailToggleDrift::BankIds {
            bank,
            before,
            after,
        }) => serde_json::json!({
            "kind": "bank_ids",
            "bank": bank,
            "before": before,
            "after": after,
        }),
        Some(DetailToggleDrift::Transaction { before, after }) => serde_json::json!({
            "kind": "transaction",
            "before": before.map(NonZeroU64::get),
            "after": after.map(NonZeroU64::get),
        }),
    }
}

fn bracket_name(bracket: CloseBracketVerdict) -> String {
    match bracket {
        CloseBracketVerdict::Matched => "matched".to_string(),
        CloseBracketVerdict::AfterUnavailable => "unavailable".to_string(),
        CloseBracketVerdict::Mismatched(reason) => format!("mismatched:{reason}"),
    }
}

fn refusal_name(refusal: DetailToggleRefusal) -> &'static str {
    match refusal {
        DetailToggleRefusal::BroadNotCounter => "broad_not_counter",
        DetailToggleRefusal::BroadStopping => "broad_stopping",
        DetailToggleRefusal::ChildShape => "child_shape",
        DetailToggleRefusal::NotPublished => "not_published",
        DetailToggleRefusal::Foreign => "foreign",
        DetailToggleRefusal::Changed => "changed",
        DetailToggleRefusal::Quarantined => "quarantined",
        DetailToggleRefusal::Budget => "budget",
    }
}

/// The additive aggregate bracket: broad deltas between the window's
/// bracketing seqs, scope-wide, per published original index.
/// Metrics-internal: deltas are collector types, so only metrics code
/// (unit seams now, the driver packet's report composer later) renders
/// them; the driver never holds a `CounterDeltas`.
pub(super) fn render_aggregate_bracket(
    deltas: &CounterDeltas,
    mode: CounterMode,
    seq_before: u64,
    seq_after: u64,
) -> serde_json::Value {
    serde_json::json!({
        "scope": "broad",
        "unit": "calls",
        "mode": mode.name(),
        "seq_before": seq_before,
        "seq_after": seq_after,
        "mode_mixed": deltas.iter().any(|delta| delta.mode != mode),
        "rows": deltas.iter().map(|delta| render_cell_row(delta, mode)).collect::<Vec<_>>(),
    })
}

/// The additive detail rows: the selected child's per-endpoint detail
/// for the original caller only, keyed by detail generation and child
/// slot, with per-mode units (counts vs timestamps vs latency).
/// Metrics-internal, like [`render_aggregate_bracket`]: deltas are
/// collector types.
pub(super) fn render_detail_rows(
    deltas: &CounterDeltas,
    mode: CounterMode,
    detail_generation: u64,
) -> serde_json::Value {
    serde_json::json!({
        "scope": "detail",
        "unit": "calls",
        "mode": mode.name(),
        "detail_generation": detail_generation,
        "mode_mixed": deltas.iter().any(|delta| delta.mode != mode),
        "rows": deltas.iter().map(|delta| render_cell_row(delta, mode)).collect::<Vec<_>>(),
    })
}

/// One additive delta row: slot identity plus per-mode units. The
/// unit is always calls; time/buckets appear exactly in the modes
/// that measure them (counts rows have no time keys, timestamps
/// rows have no buckets). `rv_counts` always renders (possibly
/// empty): return-value observation is orthogonal to mode.
fn render_cell_row(
    delta: &super::counter_collector::CounterCellDelta,
    mode: CounterMode,
) -> serde_json::Value {
    let mut row = serde_json::json!({
        "slot": delta.slot,
        "object": delta.target.object.0,
        "file_offset": delta.target.file_offset,
        "entered": delta.entered,
        "returned": delta.returned,
        "errors": delta.errors,
        "rv_counts": delta.rv_counts,
    });
    match mode {
        CounterMode::Counts => {}
        CounterMode::Timestamps => {
            row["total_ns"] = serde_json::json!(delta.total_ns);
            row["max_ns"] = serde_json::json!(delta.max_ns);
        }
        CounterMode::Latency => {
            row["total_ns"] = serde_json::json!(delta.total_ns);
            row["max_ns"] = serde_json::json!(delta.max_ns);
            row["buckets"] = serde_json::json!(delta.buckets);
        }
    }
    row
}

/// The explicit ledger entry for an impossible close (quarantined
/// banks): names the refusal, brackets nothing, fabricates nothing.
pub(crate) fn render_close_refused_row(
    request: &PromotionRequest,
    endpoint_offset: u64,
    refusal: DetailToggleRefusal,
) -> serde_json::Value {
    serde_json::json!({
        "event": DetailWindowEvent::CloseRefused.name(),
        "request": request.id().get(),
        "caller": request.caller().0,
        "provider": request.provider().0,
        "view": request.viewed().revision().get(),
        "endpoint_offset": endpoint_offset,
        "refusal": refusal_name(refusal),
    })
}

#[cfg(test)]
mod tests {
    use super::super::KernelEvidence;
    use super::super::counter_collector::{
        CounterCell, CounterCollector, CounterHealth, CounterIssue, CounterLimits,
        CounterObservation, CounterRow, ReadReservation, ReadWindow,
    };
    use super::*;
    use crate::attach::counter_banks::tests::{
        stage_toggle_banks, toggle_object_plan, toggle_provider,
    };
    use crate::discovery::identity::PinnedObjectId;
    use crate::inventory_promotion::lifecycle::{
        SelectedActivationBinding, scripted_promotion_view_with_baseline_for_test,
    };
    use crate::inventory_promotion::{Promoter, PromotionRequest};
    use crate::plan::Slot;
    use crate::semantics_edge::resources::SemanticResourcePool;
    use p11scope_ebpf_common::{CountStats, SlotStats, TimestampStats};
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::{Duration, Instant};

    const BROAD_GENERATION: u64 = 7;
    const DETAIL_GENERATION: u64 = 9;
    const SEQ_BEFORE: u64 = 41;
    const SEQ_AFTER: u64 = 87;

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
    /// explicit per-CPU cells through the genuine `CounterRow::fold`
    /// (checked folds, per-plan-cell binding), packed through the
    /// genuine `CounterRead::new` (charged storage, capacity checks).
    /// `counts` parallels `plan.slots`: (entered, returned, errors).
    fn scripted_read(
        pool: &SemanticResourcePool,
        plan: &AttachPlan,
        generation: NonZeroU64,
        mode: CounterMode,
        counts: &[(u64, u64, u64)],
        window: Option<ReadWindow>,
    ) -> CounterRead {
        scripted_read_with_signals(
            pool,
            plan,
            generation,
            mode,
            counts,
            window,
            CounterHealth::default(),
            KernelEvidence::default(),
        )
    }

    /// [`scripted_read`] with explicit producer/kernel signals: the rows
    /// stay valid while the health/kernel evidence varies, so bracket
    /// twins offer reads the collector would reject for their signals.
    #[allow(clippy::too_many_arguments)] // Test seam mirroring scripted_read plus the two signal inputs.
    fn scripted_read_with_signals(
        pool: &SemanticResourcePool,
        plan: &AttachPlan,
        generation: NonZeroU64,
        mode: CounterMode,
        counts: &[(u64, u64, u64)],
        window: Option<ReadWindow>,
        health: CounterHealth,
        kernel: KernelEvidence,
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
            health,
            kernel,
            reservation,
        )
        .expect("scripted read packs")
    }

    fn window_of(started: u64, finished: u64) -> Option<ReadWindow> {
        ReadWindow::new(Some(started), Some(finished))
    }

    /// One staged broad capture: a real pinned provider file, a
    /// `Counters` plan over it, and banks staged through the genuine
    /// publication algorithm. The directory holds the scene alive.
    struct BroadScene {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        objects: PinnedObjects,
        object: PinnedObjectId,
        plan: AttachPlan,
        banks: CounterBanks,
        pool: SemanticResourcePool,
    }

    fn stage_single_provider(pool: SemanticResourcePool, slots: u32) -> BroadScene {
        let dir = tempfile::tempdir().unwrap();
        let path = toggle_provider(&dir, "provider.so", b"selected-detail broad provider bytes");
        let objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &path,
            None,
            1,
            "detail-digest",
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

    /// Two provider files in one shared pin store (the M1 host shape:
    /// broad and convert resolve in the same id space), each with the
    /// same endpoint offsets, so file identity — never the offset
    /// alone — carries the distinction. Ids are read back after the
    /// merge, never assumed.
    struct MultiScene {
        _dir: tempfile::TempDir,
        path_a: std::path::PathBuf,
        path_b: std::path::PathBuf,
        objects: PinnedObjects,
        id_a: PinnedObjectId,
        id_b: PinnedObjectId,
        plan: AttachPlan,
        banks: CounterBanks,
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
        let path_a = toggle_provider(&dir, "provider-a.so", b"provider A bytes for detail");
        let path_b = toggle_provider(&dir, "provider-b.so", b"provider B bytes for detail");
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
            path_a,
            path_b,
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
        pin: Arc<PidPin>,
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
        let pin = Arc::new(crate::process::PidPin::open(std::process::id()).expect("self pins"));
        promotion_scene_with_pin(
            pin,
            convert_plan,
            convert_pins,
            required_map,
            endpoint,
            cookie,
            exec_id,
        )
    }

    /// [`promotion_scene_with_required`] over a caller-held original:
    /// two bundles sharing one pin isolate provider/coverage checks
    /// from original-custody checks (identical original, same image).
    #[allow(clippy::too_many_arguments)] // Test seam mirroring promotion_scene_with_required plus the shared pin.
    fn promotion_scene_with_pin(
        pin: Arc<PidPin>,
        convert_plan: AttachPlan,
        convert_pins: PinnedObjects,
        required_map: BTreeMap<PinnedObjectId, BTreeSet<u32>>,
        endpoint: Option<u64>,
        cookie: u64,
        exec_id: u64,
    ) -> PromotionScene {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
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
            pin,
            bundle,
        }
    }

    /// The convert envelope for one provider object: that provider's
    /// broad slots verbatim, reindexed dense (the child envelope IS
    /// this subset).
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

    /// The convert envelope for one provider object when the broad
    /// plan holds more endpoints than a Detailed child admits: the
    /// provider's LAST `take` broad slots, reindexed dense.
    fn convert_tail(plan: &AttachPlan, object: PinnedObjectId, take: usize) -> AttachPlan {
        let mut slots: Vec<Slot> = plan
            .slots
            .iter()
            .filter(|slot| slot.object == object)
            .cloned()
            .collect();
        let skip = slots.len().saturating_sub(take);
        slots.drain(..skip);
        for (index, slot) in slots.iter_mut().enumerate() {
            slot.index = index as u32;
        }
        AttachPlan::from_slots(slots)
    }

    /// Counting inner activation source: records every CAS attempt
    /// in a shared counter (the service owns and drops the source, so
    /// tests observe attempts through the handle). Production passes
    /// the genuine minter; tests assert zero attempts on every
    /// pre-CAS refusal path.
    struct StubInner {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        refusal: Option<crate::inventory_promotion::lifecycle::NativeActivationRefusal>,
    }

    impl StubInner {
        fn succeeding(calls: Arc<std::sync::atomic::AtomicUsize>) -> Self {
            Self {
                calls,
                refusal: None,
            }
        }
    }

    impl crate::inventory_promotion::lifecycle::NativeActivationSource for StubInner {
        fn activate(
            &mut self,
            _session: &Session,
            expected: &SelectedActivationBinding,
        ) -> Result<
            crate::inventory_promotion::lifecycle::NativeCasReceipt,
            crate::inventory_promotion::lifecycle::NativeActivationRefusal,
        > {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            match self.refusal {
                Some(refusal) => Err(refusal),
                None => Ok(
                    crate::inventory_promotion::lifecycle::NativeCasReceipt::scripted(*expected),
                ),
            }
        }
    }

    fn broad_facts(generation: u64, stopped: bool) -> BroadToggleFacts {
        BroadToggleFacts {
            generation: NonZeroU64::new(generation).unwrap(),
            stopped,
        }
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

    fn counts_for(plan: &AttachPlan, entered: u64, returned: u64) -> Vec<(u64, u64, u64)> {
        vec![(entered, returned, 0); plan.slots.len()]
    }

    #[test]
    fn selected_detail_promotion_request_carries_endpoint_receipt() {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        use crate::inventory_promotion::{
            PromotionRefusal, PromotionRequestError, SelectedEndpointReceipt, ViewRevision,
        };
        let pin = Arc::new(crate::process::PidPin::open(std::process::id()).expect("self pins"));
        let custody = crate::process::WeakProcessCustody::pinned_for_test(&pin);
        let view = scripted_promotion_view_with_baseline_for_test(
            pin.pid(),
            pin.start_time(),
            1,
            custody,
            0xC00,
            0xE9E,
        );
        // The receipt rides the request path structurally: queue with it,
        // take it back with it.
        let mut promoter = Promoter::new();
        assert!(promoter.enable(crate::inventory_promotion::CaptureId::new(11)));
        let receipt = SelectedEndpointReceipt::new(view.revision(), 0x80);
        assert_eq!(receipt.view(), view.revision());
        assert_eq!(receipt.file_offset(), 0x80);
        promoter
            .request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), receipt)
            .expect("exact pair with receipt queues");
        let request = promoter.take_request().expect("mailbox holds it");
        assert_eq!(request.endpoint(), Some(receipt));
        // A receipt naming another view is stale, never rebound.
        let mut stale = Promoter::new();
        assert!(stale.enable(crate::inventory_promotion::CaptureId::new(11)));
        let foreign = SelectedEndpointReceipt::new(ViewRevision::new(999), 0x80);
        assert_eq!(
            stale
                .request_with_endpoint(Arc::clone(&view), CallerId(3), ModuleId(5), foreign)
                .unwrap_err(),
            PromotionRequestError::Refused(PromotionRefusal::StaleView)
        );
        // The legacy path carries no receipt; the adapter must refuse
        // such requests closed (covered at resolve), never default.
        let mut legacy = Promoter::new();
        assert!(legacy.enable(crate::inventory_promotion::CaptureId::new(11)));
        legacy
            .request(Arc::clone(&view), CallerId(3), ModuleId(5))
            .expect("exact legacy pair queues");
        let taken: PromotionRequest = legacy.take_request().expect("mailbox holds it");
        assert_eq!(taken.endpoint(), None);
    }

    #[test]
    fn selected_detail_window_event_names_are_stable_words() {
        // Every lifecycle event renders a stable static word (the
        // ledger vocabulary); constructing each pins the set.
        for (event, name) in [
            (DetailWindowEvent::Reserved, "reserved"),
            (DetailWindowEvent::Bound, "bound"),
            (DetailWindowEvent::CasWon, "cas_won"),
            (DetailWindowEvent::CasRefused, "cas_refused"),
            (DetailWindowEvent::Closed, "closed"),
            (DetailWindowEvent::CloseRefused, "close_refused"),
            (
                DetailWindowEvent::CancelledUnactivated,
                "cancelled_unactivated",
            ),
        ] {
            assert_eq!(event.name(), name);
        }
    }

    #[test]
    fn selected_detail_endpoint_unresolved_never_first_matches() {
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let convert_a = convert_for(&scene.plan, scene.id_a);
        // The positive control: provider A's 0x80 resolves to broad
        // row 0 — exactly one of the two same-offset rows.
        let proved = promotion_scene(
            convert_a.clone(),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let resolved = resolve_endpoint(
            &proved.request,
            proved.bundle.convert_subset(),
            &scene.plan,
            &scene.objects,
        )
        .expect("one file plus one offset resolves");
        assert_eq!(resolved.selected, 0);
        assert_eq!(
            resolved.physical,
            AttachKey {
                object: scene.id_a,
                file_offset: 0x80,
            }
        );
        // No receipt: the legacy request fails closed, never defaults
        // to a first row.
        let legacy = promotion_scene(
            convert_a.clone(),
            scene.objects.clone(),
            scene.id_a,
            None,
            0xC00,
            0xE9E,
        );
        assert_eq!(
            resolve_endpoint(
                &legacy.request,
                legacy.bundle.convert_subset(),
                &scene.plan,
                &scene.objects,
            )
            .unwrap_err(),
            SelectedDetailRefusal::EndpointUnresolved
        );
        // Offset absent from the provider subset: no child slot.
        let absent = promotion_scene(
            convert_a.clone(),
            scene.objects.clone(),
            scene.id_a,
            Some(0xDEAD),
            0xC00,
            0xE9E,
        );
        assert_eq!(
            resolve_endpoint(
                &absent.request,
                absent.bundle.convert_subset(),
                &scene.plan,
                &scene.objects,
            )
            .unwrap_err(),
            SelectedDetailRefusal::EndpointUnresolved
        );
        // Ambiguous provider subset: two required objects for one
        // request never pick a first.
        let ambiguous = promotion_scene_with_required(
            convert_a.clone(),
            scene.objects.clone(),
            BTreeMap::from([
                (scene.id_a, BTreeSet::from([0])),
                (scene.id_b, BTreeSet::from([0])),
            ]),
            Some(0x80),
            0xC00,
            0xE9E,
        );
        assert_eq!(
            resolve_endpoint(
                &ambiguous.request,
                ambiguous.bundle.convert_subset(),
                &scene.plan,
                &scene.objects,
            )
            .unwrap_err(),
            SelectedDetailRefusal::EndpointUnresolved
        );
        // Empty provider subset: nothing required, nothing resolved.
        let empty = promotion_scene_with_required(
            convert_a.clone(),
            scene.objects.clone(),
            BTreeMap::new(),
            Some(0x80),
            0xC00,
            0xE9E,
        );
        assert_eq!(
            resolve_endpoint(
                &empty.request,
                empty.bundle.convert_subset(),
                &scene.plan,
                &scene.objects,
            )
            .unwrap_err(),
            SelectedDetailRefusal::EndpointUnresolved
        );
        // Provider file absent from broad: the child names a file the
        // broad plan never published.
        let dir = tempfile::tempdir().unwrap();
        let path_c = toggle_provider(&dir, "provider-c.so", b"provider C bytes, unpublished");
        let pins_c =
            crate::discovery::identity::test_fixture::real_scan_pin(&path_c, None, 1, "digest-c");
        let id_c = pins_c.pinned().next().unwrap().id;
        let convert_c = AttachPlan::from_slots(vec![provider_slot(0, id_c, 0x80, "C_Sign")]);
        let missing = promotion_scene(convert_c, pins_c, id_c, Some(0x80), 0xC00, 0xE9E);
        assert_eq!(
            resolve_endpoint(
                &missing.request,
                missing.bundle.convert_subset(),
                &scene.plan,
                &scene.objects,
            )
            .unwrap_err(),
            SelectedDetailRefusal::EndpointUnresolved
        );
        // Unpinned child object: without a content key the file match
        // is incomparable and fails closed.
        let unpinned = promotion_scene(
            convert_a.clone(),
            PinnedObjects::empty(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        assert_eq!(
            resolve_endpoint(
                &unpinned.request,
                unpinned.bundle.convert_subset(),
                &scene.plan,
                &scene.objects,
            )
            .unwrap_err(),
            SelectedDetailRefusal::EndpointUnresolved
        );
        // Forwarded entry: a child slot outside the required object
        // names ChildForeignSlot distinctly (the gate would refuse
        // Foreign; the adapter refuses before charging).
        let mut mixed_slots: Vec<Slot> = convert_a.slots.clone();
        mixed_slots.push(provider_slot(2, scene.id_b, 0xA0, "C_Forwarded"));
        let mixed = AttachPlan::from_slots(mixed_slots);
        let forwarded = promotion_scene(
            mixed,
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        assert_eq!(
            resolve_endpoint(
                &forwarded.request,
                forwarded.bundle.convert_subset(),
                &scene.plan,
                &scene.objects,
            )
            .unwrap_err(),
            SelectedDetailRefusal::ChildForeignSlot
        );
    }

    #[test]
    fn selected_detail_custody_is_take_once() {
        let pool = test_pool();
        let scene = stage_single_provider(pool, 513);
        let convert = convert_tail(&scene.plan, scene.object, 13);
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        assert!(!custody.is_occupied());
        assert!(custody.take_reserved().is_none());
        assert!(custody.take_bound().is_none());
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("first reserve places its reservation");
        assert!(custody.is_occupied());
        assert!(custody.take_bound().is_none(), "reserved is not bound");
        let reservation = custody.take_reserved().expect("take-once yields it");
        assert_eq!(reservation.selected(), 512);
        // Take moves the value but NOT the admission: the live
        // reservation still occupies until its terminal disposition.
        assert!(
            custody.is_occupied(),
            "take moves the reservation; admission follows it"
        );
        assert!(custody.take_reserved().is_none(), "no second take");
        // A parked bound window takes through the bound path only.
        let window = reservation.bind_generation(DETAIL_GENERATION);
        custody
            .place_bound(BoundWindow::Active(window))
            .expect("vacant custody parks");
        assert!(custody.is_occupied());
        assert!(custody.take_reserved().is_none(), "bound is not reserved");
        let parked = custody.take_bound().expect("bound takes once");
        assert!(
            matches!(parked, BoundWindow::Active(_)),
            "the parked state survives the take"
        );
        assert!(
            custody.is_occupied(),
            "a taken window still occupies until its terminal"
        );
        assert!(custody.take_bound().is_none(), "no second bound take");
        // Dropping the taken window releases admission (fail-safe
        // against a permanent WindowActive); the ledger still needs
        // its explicit terminal, which the lifecycle twins prove.
        drop(parked);
        assert!(!custody.is_occupied());
    }

    #[test]
    fn selected_detail_reserve_bind_close_conserves_both_ledgers() {
        // Full window lifecycle through the real seams: staged broad
        // banks, genuine collector observes, reserve, bind validation,
        // ordered close. The CAS itself needs a live child Session
        // (live-only, like the lifecycle's own CAS path), so this
        // scene parks the validated window FORGED-ACTIVE to prove
        // everything downstream of the CAS: custody handoff, the
        // bracketing seqs, both ledgers, lineage, and charge release.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 513);
        let convert = convert_tail(&scene.plan, scene.object, 13);
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let mut broad = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        let mut seq = 0;
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        assert_eq!(broad.observe(Ok(r0)), CounterObservation::Initial);
        seq += 1;
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        assert!(matches!(
            broad.observe(Ok(r1)),
            CounterObservation::Advanced { .. }
        ));
        seq += 1;
        let charged_before = scene.pool.snapshot().charged_bytes;
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        assert!(matches!(
            broad.observe(Ok(before)),
            CounterObservation::Advanced { .. }
        ));
        seq += 1;
        // The bracketing read is a fresh accepted read, not the
        // collector's retained baseline: rebuild it identically.
        let bracket_before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &bracket_before,
            seq,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("proved request reserves");
        let charged_reserved = scene.pool.snapshot().charged_bytes;
        assert!(
            charged_reserved > charged_before,
            "reserve holds the child envelope charge"
        );
        // Bind validation against the sealed binding: the domain names
        // the presented child, the exec still matches the pre-view
        // baseline row, the slots still cover on the same file.
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
        let expected = expected_binding(domain, DETAIL_GENERATION, 0xC00, 0xE9E);
        let cas_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut source = GatedActivationSource::new(
            Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
            custody.clone(),
            PreparedChildReceipt::of_bundle(&proved.bundle)
                .expect("scene seals its prepared child"),
        );
        let delivered = PreparedChildReceipt::of_bundle(&proved.bundle)
            .expect("scene seals its prepared child");
        let window = source
            .validate_and_bind(&expected, Some(domain), &delivered)
            .expect("sealed binding validates");
        assert_eq!(
            cas_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "bind validation never attempts the CAS"
        );
        assert_eq!(window.detail_generation(), DETAIL_GENERATION);
        assert_eq!(window.selected(), 512);
        // FORGED-ACTIVE: `activate` would run the one genuine CAS here
        // and park Active on its receipt; without a live child Session
        // the scene parks the validated window directly. Everything
        // below the CAS (handoff, close, ledgers, lineage) is real.
        custody
            .place_bound(BoundWindow::Active(window))
            .expect("CAS-won window parks");
        // Broad keeps counting across the window; the detail stream
        // telescopes on its own generation.
        let r2 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 11, 12),
            window_of(40, 50),
        );
        let CounterObservation::Advanced { deltas: span, .. } = broad.observe(Ok(r2)) else {
            panic!("broad advances across the window");
        };
        assert_eq!((span[512].entered, span[512].returned), (3, 3));
        seq += 1;
        let mut detail = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        let d0 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(DETAIL_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 0, 0),
            window_of(40, 50),
        );
        assert_eq!(detail.observe(Ok(d0)), CounterObservation::Initial);
        let d1 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(DETAIL_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 2, 2),
            window_of(50, 60),
        );
        let CounterObservation::Advanced {
            deltas: detail_span,
            ..
        } = detail.observe(Ok(d1))
        else {
            panic!("detail telescopes on its own stream");
        };
        assert_eq!(
            (detail_span[512].entered, detail_span[512].returned),
            (2, 2)
        );
        // Driver takes the Active window on Install, then closes after
        // genuine disposal with a fresh accepted after read.
        let taken = custody.take_bound().expect("Install takes Active");
        let BoundWindow::Active(active) = taken else {
            panic!("a CAS-won window installs Active, never Unactivated");
        };
        let r3 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 13, 15),
            window_of(60, 70),
        );
        assert!(matches!(
            broad.observe(Ok(r3)),
            CounterObservation::Advanced { .. }
        ));
        seq += 1;
        let bracket_after = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 13, 15),
            window_of(60, 70),
        );
        let bracket = CloseBracket::new(seq, CounterMode::Counts, Some(&bracket_after));
        let charged_before_close = scene.pool.snapshot().charged_bytes;
        let report = close_detail_window_on_banks(
            active,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("ordered close delivers lineage");
        assert_eq!(report.drift, None);
        assert_eq!((report.seq_before, report.seq_after), (3, 5));
        assert_eq!(report.bracket, CloseBracketVerdict::Matched);
        assert_eq!(
            (
                report.lineage.broad_generation.get(),
                report.lineage.broad_original_index,
                report.lineage.detail_generation,
            ),
            (BROAD_GENERATION, 512, DETAIL_GENERATION)
        );
        assert_eq!(
            (
                report.lineage.broad_read_seq_before,
                report.lineage.broad_read_seq_after
            ),
            (3, 5)
        );
        assert!(!custody.is_occupied(), "close drains custody");
        // Measured across the close itself (later reads charge and
        // release around it): the close releases the sized envelope
        // plus the retained bind-time identity, strictly more than
        // the envelope alone.
        let released = charged_before_close - scene.pool.snapshot().charged_bytes;
        let envelope = crate::attach::counter_banks::detail_child_envelope(
            proved.bundle.convert_subset().plan().slots.as_slice(),
            proved.bundle.convert_subset().pins(),
            aya::util::nr_cpus().unwrap(),
        )
        .expect("child envelope sizes");
        assert!(
            released > envelope.bytes,
            "close releases envelope plus retention: {released} > {}",
            envelope.bytes
        );
        // Never summed: the selected endpoint appears in both ledgers
        // by design; the report joins them only through lineage.
        let aggregate = render_aggregate_bracket(
            &span,
            CounterMode::Counts,
            report.seq_before,
            report.seq_after,
        );
        let detail_rows = render_detail_rows(&detail_span, CounterMode::Counts, DETAIL_GENERATION);
        assert_eq!(aggregate["rows"][512]["entered"], serde_json::json!(3));
        assert_eq!(detail_rows["rows"][512]["entered"], serde_json::json!(2));
        assert!(aggregate.get("total").is_none());
        assert!(detail_rows.get("total").is_none());
        let lineage = render_lineage_row(&proved.request, 0x80 + 512 * 0x10, &report);
        assert_eq!(
            lineage["selected_detail"]["broad_original_index"],
            serde_json::json!(512)
        );
        assert_eq!(
            lineage["selected_detail"]["detail_generation"],
            serde_json::json!(9)
        );
    }

    #[test]
    fn selected_detail_cancel_before_delivery_parks_unactivated_without_cas() {
        // The stop-during-preparation race through the REAL lifecycle
        // service: reserve places the reservation in driver custody
        // before the worker starts; a cancel observed before delivery
        // skips the CAS (existing linearization); the service drops
        // the source, and the driver still abandons the surviving
        // reservation with its charge released and a ledger row.
        use crate::inventory_promotion::lifecycle::{
            LifecycleEvent, PreparationOutcome, SelectedLifecycleService,
        };
        let pool = test_pool();
        let scene = stage_single_provider(pool, 513);
        let convert = convert_tail(&scene.plan, scene.object, 13);
        let mut proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        let charged_before = scene.pool.snapshot().charged_bytes;
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("proved request reserves");
        let coordinator =
            crate::discovery::engine::inventory_coordinator::InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                crate::discovery::caller_registry::OsProcessSource,
                crate::discovery::caller_registry::RegistryLimits::default_limits(),
            )
            .expect("a test coordinator builds");
        let cas_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ledger_ids = (
            proved.request.id(),
            proved.request.caller(),
            proved.request.provider(),
        );
        let source = GatedActivationSource::new(
            Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
            custody.clone(),
            PreparedChildReceipt::of_bundle(&proved.bundle)
                .expect("scene seals its prepared child"),
        );
        let mut service = SelectedLifecycleService::new();
        service
            .start(
                proved.request,
                coordinator.reserve_promotion_install().expect("capacity"),
                Box::new(source),
                || {
                    PreparationOutcome::Failed(
                        crate::attach::selected_detailed::SelectedPreparationFailure::scripted_settled(
                        ),
                    )
                },
            )
            .expect("start runs");
        service.note_cancel(crate::inventory_promotion::PromotionEnd::Cancelled);
        let mut sink = std::io::sink();
        let deadline = Instant::now() + Duration::from_secs(5);
        let event = loop {
            if let Some(event) = service.poll(&mut sink) {
                break event;
            }
            assert!(
                Instant::now() < deadline,
                "the service emits its terminal event"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        let LifecycleEvent::Status(update) = event else {
            panic!("a cancelled job must not install");
        };
        assert!(
            matches!(
                proved.promoter.set_status(update),
                Some(crate::inventory_promotion::PromotionState::Ended(_))
            ),
            "cancel confirms an ended status"
        );
        assert!(service.is_idle());
        assert_eq!(
            cas_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "cancel before delivery never attempts the CAS"
        );
        // The source died with the service, but the reservation
        // survived in driver custody: abandon it explicitly (never
        // bound — no lineage to join) and record the ledger row.
        let reservation = custody.take_reserved().expect("reservation survives");
        assert_eq!(reservation.selected(), 512);
        assert_eq!(reservation.mark_before().seq, SEQ_BEFORE);
        let abandoned = reservation.abandon();
        assert_eq!(abandoned.selected, 512);
        assert!(!custody.is_occupied());
        assert!(
            scene.pool.snapshot().charged_bytes <= charged_before,
            "abandon releases the envelope charge"
        );
        let (req_id, caller, provider) = ledger_ids;
        let row = render_window_event(
            DetailWindowEvent::CancelledUnactivated,
            req_id,
            caller,
            provider,
            SEQ_BEFORE,
            Some("cancelled before delivery"),
        );
        assert_eq!(row["event"], serde_json::json!("cancelled_unactivated"));
        assert_eq!(row["seq"], serde_json::json!(SEQ_BEFORE));
        assert_eq!(row["caller"], serde_json::json!(3));
        assert_eq!(row["provider"], serde_json::json!(5));
    }

    #[test]
    fn selected_detail_bind_mismatch_parks_unactivated() {
        use crate::inventory_promotion::lifecycle::NativeActivationRefusal;
        // Every bind mismatch parks the window Unactivated and refuses
        // WITHOUT running the CAS; the parked window still closes with
        // a true lineage. The cookie positive control pins the
        // documented semantics: across the pre-view baseline only the
        // exec id plus original custody compare (cookies are tickets
        // inside one domain, never compared across the baseline).
        for (cookie, exec_id, child_domain_case, rewrite) in [
            (0xC00, 0xFFF, "match", false),
            (0xC00, 0xE9E, "other", false),
            (0xC00, 0xE9E, "none", false),
            (0xC00, 0xE9E, "match", true),
        ] {
            let pool = test_pool();
            let scene = stage_single_provider(pool, 513);
            let convert = convert_tail(&scene.plan, scene.object, 13);
            let proved = promotion_scene(
                convert,
                scene.objects.clone(),
                scene.object,
                Some(0x80 + 512 * 0x10),
                0xC00,
                0xE9E,
            );
            let custody = DetailWindowCustody::new();
            let before = scripted_read(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                CounterMode::Counts,
                &counts_for(&scene.plan, 8, 9),
                window_of(30, 40),
            );
            reserve_detail_window_on_banks(
                &scene.banks,
                broad_facts(BROAD_GENERATION, false),
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                &before,
                SEQ_BEFORE,
                &scene.pool.reserver(),
                &custody,
            )
            .expect("proved request reserves");
            if rewrite {
                std::fs::write(
                    &scene.path,
                    b"selected-detail broad provider bytes, rewritten",
                )
                .unwrap();
            }
            let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
            let other = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
            let expected = expected_binding(domain, DETAIL_GENERATION, cookie, exec_id);
            let child_domain = match child_domain_case {
                "match" => Some(domain),
                "other" => Some(other),
                _ => None,
            };
            let cas_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut source = GatedActivationSource::new(
                Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
                custody.clone(),
                PreparedChildReceipt::of_bundle(&proved.bundle)
                    .expect("scene seals its prepared child"),
            );
            let delivered = PreparedChildReceipt::of_bundle(&proved.bundle)
                .expect("scene seals its prepared child");
            assert_eq!(
                source
                    .validate_and_bind(&expected, child_domain, &delivered)
                    .unwrap_err(),
                NativeActivationRefusal::BindingMismatch,
                "case exec={exec_id:#x} domain={child_domain_case} rewrite={rewrite}"
            );
            assert_eq!(
                cas_attempts.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "bind refusal never attempts the CAS"
            );
            let parked = custody.take_bound().expect("mismatch parks");
            let BoundWindow::Unactivated(window) = parked else {
                panic!("a refused bind parks Unactivated, never Active");
            };
            assert_eq!(window.detail_generation(), DETAIL_GENERATION);
            let after = scripted_read(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                CounterMode::Counts,
                &counts_for(&scene.plan, 11, 12),
                window_of(40, 50),
            );
            let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&after));
            let report = close_detail_window_on_banks(
                window,
                &scene.banks,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                &scene.plan,
                &bracket,
            )
            .expect("Unactivated close delivers lineage");
            assert_eq!(
                (report.seq_before, report.seq_after),
                (SEQ_BEFORE, SEQ_AFTER)
            );
            assert!(!custody.is_occupied());
        }
        // Cookie positive control: a binding whose cookie differs from
        // the baseline row but whose exec and custody agree validates.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 513);
        let convert = convert_tail(&scene.plan, scene.object, 13);
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("proved request reserves");
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
        let expected = expected_binding(domain, DETAIL_GENERATION, 0xBAD, 0xE9E);
        let cas_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut source = GatedActivationSource::new(
            Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
            custody.clone(),
            PreparedChildReceipt::of_bundle(&proved.bundle)
                .expect("scene seals its prepared child"),
        );
        let delivered = PreparedChildReceipt::of_bundle(&proved.bundle)
            .expect("scene seals its prepared child");
        source
            .validate_and_bind(&expected, Some(domain), &delivered)
            .expect("cookie differences do not fail the bind");
    }

    #[test]
    fn selected_detail_window_active_refuses_second_reserve_without_loss() {
        // One detail window at a time (M3 product rule): a second
        // reserve while custody is occupied refuses WindowActive with
        // both charges intact (no envelope bytes, no worker), and the
        // first reservation still closes cleanly; reselect then works.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 513);
        let convert = convert_tail(&scene.plan, scene.object, 13);
        let first = promotion_scene(
            convert.clone(),
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &first.request,
            &first.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("first reserve places");
        let charged_held = scene.pool.snapshot().charged_bytes;
        // The second request selects another endpoint inside the same
        // convert tail (broad row 511).
        let second = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 511 * 0x10),
            0xC00,
            0xE9E,
        );
        let before2 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        let charged_before_second = scene.pool.snapshot().charged_bytes;
        assert_eq!(
            reserve_detail_window_on_banks(
                &scene.banks,
                broad_facts(BROAD_GENERATION, false),
                &scene.plan,
                &scene.objects,
                &second.request,
                &second.bundle,
                &before2,
                SEQ_BEFORE + 1,
                &scene.pool.reserver(),
                &custody,
            )
            .unwrap_err(),
            SelectedDetailRefusal::WindowActive
        );
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged_before_second,
            "a refused reserve charges nothing"
        );
        assert!(custody.is_occupied(), "the first window still holds");
        // The first reservation abandons cleanly (never bound), and
        // the reselect then reserves on the freed custody.
        let reservation = custody.take_reserved().expect("first survives");
        assert_eq!(reservation.selected(), 512);
        reservation.abandon();
        assert!(
            scene.pool.snapshot().charged_bytes < charged_held,
            "abandon releases the first envelope"
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &second.request,
            &second.bundle,
            &before2,
            SEQ_BEFORE + 1,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("reselect reserves after abandon");
        let reselect = custody.take_reserved().expect("reselect placed");
        assert_eq!(reselect.selected(), 511);
        reselect.abandon();
        assert!(!custody.is_occupied());
    }

    #[test]
    fn selected_detail_read_seq_counts_successful_observes_only() {
        // The read-seq rule through the genuine collector: seqs count
        // successful `observe` accepts only. A failed scrape keeps the
        // baseline and advances no seq; the lineage carries exactly
        // the minted seqs. Stale, foreign and failed bracketing reads
        // refuse at reserve; a failed final acquisition closes with an
        // explicit unavailable bracket.
        use super::super::counter_collector::ReadStage;
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let convert_a = convert_for(&scene.plan, scene.id_a);
        let proved = promotion_scene(
            convert_a,
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let mut broad = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        let mut seq = 0;
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        assert_eq!(broad.observe(Ok(r0)), CounterObservation::Initial);
        seq += 1;
        assert_eq!(
            broad.observe(Err(ReadStage::Budget)),
            CounterObservation::ReadFailed(ReadStage::Budget)
        );
        assert!(
            broad.current().is_some(),
            "a failed scrape keeps its baseline"
        );
        // No seq for the failure: the next accepted read is still seq 2.
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        assert!(matches!(
            broad.observe(Ok(r1)),
            CounterObservation::Advanced { .. }
        ));
        seq += 1;
        // A stale bracketing read (another generation) refuses: the
        // mark must bracket a read of THIS broad capture.
        let stale = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION + 1).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        assert_eq!(
            reserve_detail_window_on_banks(
                &scene.banks,
                broad_facts(BROAD_GENERATION, false),
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                &stale,
                seq,
                &scene.pool.reserver(),
                &custody,
            )
            .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology
        );
        assert!(!custody.is_occupied(), "refused reserve places nothing");
        // The accepted read brackets the reserve at exactly seq 2.
        let bracket_before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &bracket_before,
            seq,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("accepted read brackets");
        let reservation = custody.take_reserved().expect("placed");
        assert_eq!(reservation.mark_before().seq, 2);
        let window = reservation.bind_generation(DETAIL_GENERATION);
        // Failed final acquisition: close against the last accepted
        // seq with NO fresh read. The lineage delivers with the live
        // after-mark, but the bracket is explicitly unavailable — the
        // last accepted read never masquerades as fresh.
        let unavailable = CloseBracket::new(seq, CounterMode::Counts, None);
        let report = close_detail_window_on_banks(
            window,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &unavailable,
        )
        .expect("close delivers with unavailable bracket");
        assert_eq!((report.seq_before, report.seq_after), (2, 2));
        assert_eq!(report.bracket, CloseBracketVerdict::AfterUnavailable);
        assert_eq!(
            (
                report.lineage.broad_read_seq_before,
                report.lineage.broad_read_seq_after
            ),
            (2, 2)
        );
    }

    #[test]
    fn selected_detail_held_return_brackets_without_transfer() {
        // A call that began before the window and returns inside it
        // belongs to whichever ledger its own records land in: broad
        // (spanning the whole capture) shows entered and returned,
        // while the detail stream (starting at bind) shows the return
        // without the start under the existing child start-key rules.
        // The adapter performs no transfer, subtraction, or stitching:
        // each ledger telescopes exactly on its own reads.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let convert_a = convert_for(&scene.plan, scene.id_a);
        let proved = promotion_scene(
            convert_a,
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let mut broad = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        // The held call enters before the window: row 0 shows one
        // entered call with no return yet.
        let mut held_entered = counts_for(&scene.plan, 0, 0);
        held_entered[0] = (1, 0, 0);
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &held_entered,
            window_of(10, 20),
        );
        assert_eq!(broad.observe(Ok(r0)), CounterObservation::Initial);
        let bracket_before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &held_entered,
            window_of(10, 20),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &bracket_before,
            1,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("proved request reserves");
        let reservation = custody.take_reserved().expect("placed");
        let bound = reservation.bind_generation(DETAIL_GENERATION);
        custody
            .place_bound(BoundWindow::Active(bound))
            .expect("FORGED-ACTIVE parks (CAS is live-only)");
        // The held call returns inside the window; a fresh call both
        // enters and returns inside it on row 1.
        let mut held_returned = counts_for(&scene.plan, 0, 0);
        held_returned[0] = (1, 1, 0);
        held_returned[1] = (1, 1, 0);
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &held_returned,
            window_of(20, 30),
        );
        let CounterObservation::Advanced { deltas: span, .. } = broad.observe(Ok(r1)) else {
            panic!("broad advances across the held return");
        };
        assert_eq!((span[0].entered, span[0].returned), (0, 1));
        assert_eq!((span[1].entered, span[1].returned), (1, 1));
        // The detail stream starts at bind: its baseline has no
        // entered record for the held call, so its span shows the
        // return without the start — no backfill from broad.
        let mut detail = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        let d0 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(DETAIL_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 0, 0),
            window_of(20, 30),
        );
        assert_eq!(detail.observe(Ok(d0)), CounterObservation::Initial);
        let mut detail_returned = counts_for(&scene.plan, 0, 0);
        detail_returned[0] = (0, 1, 0);
        detail_returned[1] = (1, 1, 0);
        let d1 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(DETAIL_GENERATION).unwrap(),
            CounterMode::Counts,
            &detail_returned,
            window_of(30, 40),
        );
        let CounterObservation::Advanced {
            deltas: detail_span,
            ..
        } = detail.observe(Ok(d1))
        else {
            panic!("detail advances on its own stream");
        };
        assert_eq!((detail_span[0].entered, detail_span[0].returned), (0, 1));
        assert_eq!((detail_span[1].entered, detail_span[1].returned), (1, 1));
        // Close and prove the rows join only through lineage with no
        // transfer between the ledgers.
        let taken = custody.take_bound().expect("Install takes Active");
        let BoundWindow::Active(active) = taken else {
            panic!("FORGED-ACTIVE installs Active");
        };
        let bracket_after = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &held_returned,
            window_of(20, 30),
        );
        let bracket = CloseBracket::new(2, CounterMode::Counts, Some(&bracket_after));
        let report = close_detail_window_on_banks(
            active,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("ordered close delivers");
        assert_eq!(report.drift, None);
        let aggregate = render_aggregate_bracket(
            &span,
            CounterMode::Counts,
            report.seq_before,
            report.seq_after,
        );
        let detail_rows = render_detail_rows(&detail_span, CounterMode::Counts, DETAIL_GENERATION);
        assert_eq!(
            aggregate["rows"][0]["returned"],
            serde_json::json!(1),
            "broad counts the held return"
        );
        assert_eq!(
            detail_rows["rows"][0]["entered"],
            serde_json::json!(0),
            "Detail shows the return without a backfilled start"
        );
        assert_eq!(detail_rows["rows"][0]["returned"], serde_json::json!(1));
    }

    #[test]
    fn selected_detail_shared_target_stays_aggregate_only() {
        // A second request sharing the target while a window is
        // active refuses WindowActive (no second window, no shared
        // detail): the target's rows keep counting only in the broad
        // aggregate ledger, and the detail rows name exactly the one
        // original caller the window was reserved for. (Per-caller
        // filtering inside one window is the existing native
        // selected gate, covered by its own host twin.)
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let convert_a = convert_for(&scene.plan, scene.id_a);
        let first = promotion_scene(
            convert_a.clone(),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &first.request,
            &first.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("first request reserves");
        // A second request sharing the target cannot open detail on it.
        let second = promotion_scene(
            convert_a,
            scene.objects.clone(),
            scene.id_a,
            Some(0x90),
            0xC00,
            0xE9E,
        );
        let before2 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        assert_eq!(
            reserve_detail_window_on_banks(
                &scene.banks,
                broad_facts(BROAD_GENERATION, false),
                &scene.plan,
                &scene.objects,
                &second.request,
                &second.bundle,
                &before2,
                SEQ_BEFORE + 1,
                &scene.pool.reserver(),
                &custody,
            )
            .unwrap_err(),
            SelectedDetailRefusal::WindowActive
        );
        // The shared target keeps counting in broad only: its rows
        // telescope in the aggregate ledger while no detail exists.
        let mut broad = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        assert_eq!(broad.observe(Ok(r0)), CounterObservation::Initial);
        let mut shared = counts_for(&scene.plan, 8, 9);
        shared[1] = (12, 14, 0);
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &shared,
            window_of(40, 50),
        );
        let CounterObservation::Advanced { deltas, .. } = broad.observe(Ok(r1)) else {
            panic!("broad advances on the shared target");
        };
        assert_eq!((deltas[1].entered, deltas[1].returned), (4, 5));
        let aggregate =
            render_aggregate_bracket(&deltas, CounterMode::Counts, SEQ_BEFORE, SEQ_BEFORE + 1);
        assert_eq!(aggregate["rows"][1]["entered"], serde_json::json!(4));
        // The window's lineage names exactly the first caller: detail
        // rows for this window can only ever join to that caller.
        let reservation = custody.take_reserved().expect("first survives");
        let window = reservation.bind_generation(DETAIL_GENERATION);
        let bracket_after = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &shared,
            window_of(40, 50),
        );
        let bracket = CloseBracket::new(SEQ_BEFORE + 1, CounterMode::Counts, Some(&bracket_after));
        let report = close_detail_window_on_banks(
            window,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("close delivers");
        let lineage = render_lineage_row(&first.request, 0x80, &report);
        assert_eq!(lineage["selected_detail"]["caller"], serde_json::json!(3));
        assert_eq!(lineage["selected_detail"]["provider"], serde_json::json!(5));
        assert_eq!(
            lineage["selected_detail"]["broad_original_index"],
            serde_json::json!(0)
        );
    }

    #[test]
    fn selected_detail_failed_bracket_close_discloses_without_fabrication() {
        // A close offered a bracketing read that does not belong to it
        // still delivers its TRUE live marks and seqs, and reports the
        // bracket defect loudly — the read is disclaimed, never
        // quietly mismatched, and nothing is fabricated. (Retirement
        // between reserve and bind, and quarantine at close, need
        // banks internals and are pinned by gate-section twins.)
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let convert_a = convert_for(&scene.plan, scene.id_a);
        for (label, make_read, make_mode, expected) in [
            ("generation", 8u64, CounterMode::Counts, "generation"),
            ("mode", 7u64, CounterMode::Latency, "mode"),
        ] {
            let proved = promotion_scene(
                convert_a.clone(),
                scene.objects.clone(),
                scene.id_a,
                Some(0x80),
                0xC00,
                0xE9E,
            );
            let custody = DetailWindowCustody::new();
            let before = scripted_read(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                CounterMode::Counts,
                &counts_for(&scene.plan, 8, 9),
                window_of(30, 40),
            );
            reserve_detail_window_on_banks(
                &scene.banks,
                broad_facts(BROAD_GENERATION, false),
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                &before,
                SEQ_BEFORE,
                &scene.pool.reserver(),
                &custody,
            )
            .expect("proved request reserves");
            let reservation = custody.take_reserved().expect("placed");
            let window = reservation.bind_generation(DETAIL_GENERATION);
            let minted = make_read;
            let wrong = scripted_read(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(minted).unwrap(),
                CounterMode::Counts,
                &counts_for(&scene.plan, 11, 12),
                window_of(40, 50),
            );
            let bracket = CloseBracket::new(SEQ_AFTER, make_mode, Some(&wrong));
            let report = close_detail_window_on_banks(
                window,
                &scene.banks,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                &scene.plan,
                &bracket,
            )
            .expect("close delivers its true marks");
            assert_eq!(
                report.bracket,
                CloseBracketVerdict::Mismatched(expected),
                "case {label} names its mismatch"
            );
            assert_eq!(
                (report.seq_before, report.seq_after),
                (SEQ_BEFORE, SEQ_AFTER)
            );
            assert_eq!(
                report.lineage.broad_mark_after.generation.get(),
                BROAD_GENERATION,
                "case {label}: the after-mark stays the live broad identity"
            );
        }
        // Rows from another broad (same generation, same shape, but
        // targets in another id space) name the rows mismatch. The
        // foreign store pins B-then-A while broad pinned A-then-B, so
        // the ids — store-local ordinals — genuinely differ.
        let proved = promotion_scene(
            convert_a.clone(),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("proved request reserves");
        let reservation = custody.take_reserved().expect("placed");
        let window = reservation.bind_generation(DETAIL_GENERATION);
        let mut foreign_objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &scene.path_b,
            None,
            1,
            "digest-b",
        );
        let foreign_a = crate::discovery::identity::test_fixture::real_scan_pin(
            &scene.path_a,
            None,
            1,
            "digest-a",
        );
        assert!(foreign_objects.absorb(foreign_a).is_empty());
        let foreign_id_a = foreign_objects
            .pinned()
            .find(|pin| pin.path.ends_with("provider-a.so"))
            .unwrap()
            .id;
        let foreign_id_b = foreign_objects
            .pinned()
            .find(|pin| pin.path.ends_with("provider-b.so"))
            .unwrap()
            .id;
        assert_ne!(
            (foreign_id_a, foreign_id_b),
            (scene.id_a, scene.id_b),
            "the premise: the foreign id space differs"
        );
        let foreign_plan = AttachPlan::from_slots(vec![
            provider_slot(0, foreign_id_a, 0x80, "C_Sign"),
            provider_slot(1, foreign_id_a, 0x90, "C_Verify"),
            provider_slot(2, foreign_id_b, 0x80, "C_Sign"),
            provider_slot(3, foreign_id_b, 0x90, "C_Verify"),
        ]);
        let foreign = scripted_read(
            &scene.pool,
            &foreign_plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&foreign_plan, 11, 12),
            window_of(40, 50),
        );
        let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&foreign));
        let report = close_detail_window_on_banks(
            window,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("close delivers its true marks");
        assert_eq!(report.bracket, CloseBracketVerdict::Mismatched("rows"));
        // A failed read offered as the after bracket names read_failed.
        let proved = promotion_scene(
            convert_a,
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("proved request reserves");
        let reservation = custody.take_reserved().expect("placed");
        let window = reservation.bind_generation(DETAIL_GENERATION);
        let storage =
            ReadReservation::reserve(4, 0, &scene.pool.reserver()).expect("failed read reserves");
        let failed = CounterRead::new(
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            window_of(40, 50),
            Err(CounterIssue::Topology),
            CounterHealth::default(),
            KernelEvidence::default(),
            storage,
        )
        .expect("failed read packs");
        let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&failed));
        let report = close_detail_window_on_banks(
            window,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("close delivers its true marks");
        assert_eq!(
            report.bracket,
            CloseBracketVerdict::Mismatched("read_failed")
        );
        // The impossible-close ledger entry names the refusal and
        // brackets nothing.
        let refused =
            render_close_refused_row(&proved.request, 0x80, DetailToggleRefusal::Quarantined);
        assert_eq!(refused["event"], serde_json::json!("close_refused"));
        assert_eq!(refused["refusal"], serde_json::json!("quarantined"));
        assert!(refused.get("broad_read_seq_after").is_none());
        assert!(refused.get("lineage").is_none());
    }

    #[test]
    fn selected_detail_report_rows_never_sum_with_per_mode_units() {
        // Additive-first report rows (M2): aggregate and detail render
        // under distinct keys with no combined total, and each mode
        // carries exactly its own fields (counts rows have no time
        // keys, timestamps rows have no buckets). No existing counter
        // JSON key is touched: everything new nests under
        // `selected_detail` with mode-labeled units.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        for mode in [
            CounterMode::Counts,
            CounterMode::Timestamps,
            CounterMode::Latency,
        ] {
            let mut collector =
                CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
            let first = scripted_read(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                mode,
                &counts_for(&scene.plan, 3, 5),
                window_of(10, 20),
            );
            assert_eq!(collector.observe(Ok(first)), CounterObservation::Initial);
            let second = scripted_read(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                mode,
                &counts_for(&scene.plan, 5, 9),
                window_of(20, 30),
            );
            let CounterObservation::Advanced { deltas, .. } = collector.observe(Ok(second)) else {
                panic!("{mode:?} telescopes");
            };
            let aggregate = render_aggregate_bracket(&deltas, mode, SEQ_BEFORE, SEQ_AFTER);
            let detail = render_detail_rows(&deltas, mode, DETAIL_GENERATION);
            assert_eq!(aggregate["unit"], serde_json::json!("calls"));
            assert_eq!(aggregate["mode"], serde_json::json!(mode.name()));
            assert_eq!(detail["unit"], serde_json::json!("calls"));
            assert_eq!(detail["mode"], serde_json::json!(mode.name()));
            assert_eq!(
                detail["detail_generation"],
                serde_json::json!(DETAIL_GENERATION)
            );
            assert_eq!(aggregate["rows"][0]["entered"], serde_json::json!(2));
            assert_eq!(detail["rows"][0]["returned"], serde_json::json!(4));
            assert!(aggregate.get("total").is_none(), "{mode:?} has no total");
            assert!(detail.get("total").is_none(), "{mode:?} has no total");
            match mode {
                CounterMode::Counts => {
                    assert!(aggregate["rows"][0].get("total_ns").is_none());
                    assert!(detail["rows"][0].get("total_ns").is_none());
                    assert!(detail["rows"][0].get("buckets").is_none());
                }
                CounterMode::Timestamps => {
                    assert_eq!(
                        detail["rows"][0]["total_ns"],
                        serde_json::json!(40),
                        "timestamps rows carry time"
                    );
                    assert!(detail["rows"][0].get("buckets").is_none());
                }
                CounterMode::Latency => {
                    assert!(
                        detail["rows"][0].get("buckets").is_some(),
                        "latency rows carry buckets"
                    );
                    assert_eq!(detail["rows"][0]["buckets"].as_array().unwrap().len(), 32);
                }
            }
        }
    }

    #[test]
    fn selected_detail_multi_provider_distinguishes_per_provider_files() {
        // Multi-provider acceptance (owner-asked): one process with two
        // loaded providers whose endpoints share file offsets. This
        // test pins the measured behavior — per-provider distinction
        // in selection, counting and detail — in all three dimensions.
        // If any dimension ever aggregates, this test fails and the
        // aggregation is a measured gap, never a silent one.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        // COUNTING: rows key by {object, offset}, so the two
        // same-offset endpoints fold as distinct rows with distinct
        // targets — never one aggregated row.
        let mut broad = CounterCollector::new(limits_for(&scene.plan), scene.pool.reserver());
        let mut counts = counts_for(&scene.plan, 0, 0);
        counts[0] = (3, 3, 0);
        counts[2] = (7, 7, 0);
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts,
            window_of(10, 20),
        );
        {
            let view = r0.view();
            let rows = view.rows.expect("accepted read has rows");
            assert_eq!(rows.len(), 4, "one row per plan slot, never merged");
            assert_eq!(rows[0].view().target.object, scene.id_a);
            assert_eq!(rows[2].view().target.object, scene.id_b);
            assert_eq!(
                rows[0].view().target.file_offset,
                rows[2].view().target.file_offset
            );
            assert_eq!(rows[0].view().entered, 3);
            assert_eq!(rows[2].view().entered, 7);
        }
        assert_eq!(broad.observe(Ok(r0)), CounterObservation::Initial);
        let mut counts = counts_for(&scene.plan, 0, 0);
        counts[0] = (5, 5, 0);
        counts[2] = (11, 11, 0);
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts,
            window_of(20, 30),
        );
        let CounterObservation::Advanced { deltas, .. } = broad.observe(Ok(r1)) else {
            panic!("broad advances");
        };
        assert_eq!(deltas.len(), 4, "deltas stay per row, never merged");
        assert_eq!(deltas[0].target.object, scene.id_a);
        assert_eq!(deltas[2].target.object, scene.id_b);
        assert_eq!((deltas[0].entered, deltas[2].entered), (2, 4));
        // SELECTION: provider A's 0x80 resolves to broad row 0 only —
        // never to provider B's same-offset row 2, never first-match.
        let convert_a = convert_for(&scene.plan, scene.id_a);
        let proved = promotion_scene(
            convert_a.clone(),
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let resolved = resolve_endpoint(
            &proved.request,
            proved.bundle.convert_subset(),
            &scene.plan,
            &scene.objects,
        )
        .expect("provider file plus offset resolves");
        assert_eq!(resolved.selected, 0);
        assert_eq!(resolved.physical.object, scene.id_a);
        // The ModuleId→file binding the driver's D10 liveness gate
        // resolves: the convert subset proves provider A's live module
        // key and refuses provider B's key for the same object.
        let key_for = |name: &str| {
            let pin = scene
                .objects
                .pinned()
                .find(|pin| pin.path.ends_with(name))
                .unwrap();
            crate::discovery::caller_registry::ModuleKey::Physical {
                dev_major: pin.key.device.major,
                dev_minor: pin.key.device.minor,
                ino: pin.key.inode,
                sha256: Some(pin.sha256.to_string()),
            }
        };
        assert!(
            proved
                .bundle
                .convert_subset()
                .proves_provider_module(scene.id_a, &key_for("provider-a.so")),
            "the subset proves its own provider file"
        );
        assert!(
            !proved
                .bundle
                .convert_subset()
                .proves_provider_module(scene.id_a, &key_for("provider-b.so")),
            "the subset refuses the other provider file"
        );
        // DETAIL: the window opens on provider A's row with A's
        // physical key; provider B's endpoints stay aggregate-only
        // (present in broad rows, absent from any detail window).
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 5),
            window_of(20, 30),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("provider A reserves");
        let reservation = custody.take_reserved().expect("placed");
        assert_eq!(reservation.selected(), 0);
        assert_eq!(reservation.physical().object, scene.id_a);
        let window = reservation.bind_generation(DETAIL_GENERATION);
        assert_eq!(window.physical().object, scene.id_a);
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(30, 40),
        );
        let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&after));
        let report = close_detail_window_on_banks(
            window,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("close delivers");
        assert_eq!(report.lineage.broad_original_index, 0);
        assert_eq!(report.lineage.broad_physical.object, scene.id_a);
        assert_ne!(
            report.lineage.broad_physical.object, scene.id_b,
            "detail never names the other provider file"
        );
    }

    #[test]
    fn selected_detail_install_handoff_requires_active_window() {
        // The Install handoff rule through the REAL service: a handoff
        // with no Active window in custody reclaims for genuine
        // disposal instead of installing (installing a detail lane
        // with no open window would double-count silently). Scripted
        // lanes dispose but never install (I4), so the genuine-install
        // positive stays a controller-scheduled live cell; this scene
        // proves the refusal side with a FORGED-ACTIVE close proving
        // the Active-window close path (the CAS itself is live-only).
        use crate::inventory_promotion::lifecycle::{
            LifecycleEvent, PendingInstall, SelectedActivationProof, SelectedLifecycleService,
        };
        let pool = test_pool();
        let scene = stage_single_provider(pool, 513);
        let convert = convert_tail(&scene.plan, scene.object, 13);
        let proved = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("proved request reserves");
        // A posed install handoff over a scripted lane (reclaim-path
        // scene): proof and lane agree, so only the missing Active
        // window blocks the install.
        let coordinator =
            crate::discovery::engine::inventory_coordinator::InventoryCoordinator::new(
                crate::attach::Scope::Pid(std::process::id()),
                crate::discovery::hooks::HookRegistry::builtin(),
                Vec::new(),
                crate::discovery::caller_registry::OsProcessSource,
                crate::discovery::caller_registry::RegistryLimits::default_limits(),
            )
            .expect("a test coordinator builds");
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
        let binding = expected_binding(domain, DETAIL_GENERATION, 0xC00, 0xE9E);
        let lane = scripted_lane_for(&proved, binding);
        let proof = SelectedActivationProof::mint(
            &proved.request,
            binding,
            crate::inventory_promotion::lifecycle::NativeCasReceipt::scripted(binding),
        )
        .expect("matching receipt mints");
        let pending = PendingInstall::from_parts(
            proof,
            lane,
            coordinator.reserve_promotion_install().expect("capacity"),
        );
        let mut service = SelectedLifecycleService::new();
        // The driver takes custody on Install: Reserved (never bound)
        // is not Active, so the handoff reclaims for disposal.
        assert!(
            custody.take_bound().is_none(),
            "a never-bound reservation is not an installable window"
        );
        service.seed_installing_for_test(take_request_like(&proved));
        service
            .reclaim_install(pending, None)
            .expect("a windowless handoff reclaims");
        let mut sink = std::io::sink();
        let deadline = Instant::now() + Duration::from_secs(5);
        let event = loop {
            if let Some(event) = service.poll(&mut sink) {
                break event;
            }
            assert!(
                Instant::now() < deadline,
                "disposal settles to its terminal event"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(
            matches!(event, LifecycleEvent::Status(_)),
            "reclaim ends in a terminal status"
        );
        assert!(service.is_idle());
        // The reservation never bound: abandon it explicitly, then
        // prove the Active-window close path with a FORGED-ACTIVE
        // park (downstream of the CAS only).
        let reservation = custody.take_reserved().expect("reservation survives");
        reservation.abandon();
        assert!(!custody.is_occupied());
        let proved2 = promotion_scene(
            convert_tail(&scene.plan, scene.object, 13),
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved2.request,
            &proved2.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("second request reserves after reclaim");
        let reservation = custody.take_reserved().expect("placed");
        let window = reservation.bind_generation(DETAIL_GENERATION);
        custody
            .place_bound(BoundWindow::Active(window))
            .expect("FORGED-ACTIVE parks");
        let taken = custody.take_bound().expect("Install takes Active");
        let BoundWindow::Active(active) = taken else {
            panic!("an Active window installs");
        };
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 11, 12),
            window_of(40, 50),
        );
        let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&after));
        let report = close_detail_window_on_banks(
            active,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("Active close delivers");
        assert_eq!(report.drift, None);
        assert_eq!(
            (report.seq_before, report.seq_after),
            (SEQ_BEFORE, SEQ_AFTER)
        );
    }

    /// A scripted sealed lane over the scene's bundle (reclaim-path
    /// scenes only: the lane must dispose, never install).
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
                Arc::clone(&proved.pin),
                crate::attach::Scope::Pid(proved.pin.pid()),
                binding.domain(),
                binding.image(),
                binding.generation(),
                proved.bundle.baseline.clone(),
            );
        crate::inventory_semantics::selected::ProvisionalSelectedLane::scripted_for_test(
            shell, permit,
        )
    }

    /// A taken request over the same viewed pair for posing the
    /// `Installing` state (the reclaim scene's own request serial).
    fn take_request_like(proved: &PromotionScene) -> PromotionRequest {
        use crate::discovery::caller_registry::{CallerId, ModuleId};
        let mut promoter = Promoter::new();
        assert!(promoter.enable(crate::inventory_promotion::CaptureId::new(11)));
        let receipt = crate::inventory_promotion::SelectedEndpointReceipt::new(
            proved.request.viewed().revision(),
            proved
                .request
                .endpoint()
                .expect("scene carries a receipt")
                .file_offset(),
        );
        promoter
            .request_with_endpoint(
                Arc::clone(proved.request.viewed()),
                CallerId(3),
                ModuleId(5),
                receipt,
            )
            .expect("same pair queues again");
        promoter.take_request().expect("mailbox holds it")
    }

    #[test]
    fn selected_detail_bridge_matches_across_pin_stores() {
        // The bridge matches files, never raw object ids: the convert
        // subset may resolve the provider in another pin store (other
        // id space) than the broad plan. Here the convert store pins
        // B-then-A while broad pinned A-then-B, so provider A's id
        // differs across the stores; the same file still resolves to
        // the same broad row, by content key plus offset.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut convert_objects = crate::discovery::identity::test_fixture::real_scan_pin(
            &scene.path_b,
            None,
            1,
            "digest-b",
        );
        let pins_a = crate::discovery::identity::test_fixture::real_scan_pin(
            &scene.path_a,
            None,
            1,
            "digest-a",
        );
        assert!(convert_objects.absorb(pins_a).is_empty());
        let convert_id_a = convert_objects
            .pinned()
            .find(|pin| pin.path.ends_with("provider-a.so"))
            .unwrap()
            .id;
        assert_ne!(
            convert_id_a, scene.id_a,
            "the premise: provider A's id differs across stores"
        );
        let convert_a = AttachPlan::from_slots(vec![
            provider_slot(0, convert_id_a, 0x80, "C_Sign"),
            provider_slot(1, convert_id_a, 0x90, "C_Verify"),
        ]);
        let proved = promotion_scene(
            convert_a,
            convert_objects,
            convert_id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let resolved = resolve_endpoint(
            &proved.request,
            proved.bundle.convert_subset(),
            &scene.plan,
            &scene.objects,
        )
        .expect("same file across stores resolves");
        assert_eq!(resolved.selected, 0);
        assert_eq!(resolved.physical.object, scene.id_a);
        // And the full reserve works across the stores: the gate
        // proves the same retained file authoritatively.
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved.request,
            &proved.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("cross-store reserve proves the same file");
        let reservation = custody.take_reserved().expect("placed");
        assert_eq!(reservation.selected(), 0);
        reservation.abandon();
        assert!(!custody.is_occupied());
    }

    #[test]
    fn selected_detail_bind_refuses_reservation_for_other_provider() {
        use crate::inventory_promotion::lifecycle::NativeActivationRefusal;
        // A reservation for provider A must never bind when the
        // worker-side receipt names provider B, even with identical
        // original custody and image. Healthy A→A binds; worker-B
        // refuses WITHOUT a CAS and parks Unactivated. Both bundles
        // share one pin so only the provider/coverage identity
        // distinguishes them. The delivered lane agrees (A) in both
        // arms, isolating the worker-side check; the delivered-child
        // twin covers worker-A/delivered-B.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let pin = Arc::new(crate::process::PidPin::open(std::process::id()).expect("self pins"));
        let convert_a = convert_for(&scene.plan, scene.id_a);
        let convert_b = convert_for(&scene.plan, scene.id_b);
        let proved_a = promotion_scene_with_pin(
            Arc::clone(&pin),
            convert_a,
            scene.objects.clone(),
            BTreeMap::from([(scene.id_a, BTreeSet::from([0]))]),
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let proved_b = promotion_scene_with_pin(
            Arc::clone(&pin),
            convert_b,
            scene.objects.clone(),
            BTreeMap::from([(scene.id_b, BTreeSet::from([0]))]),
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved_a.request,
            &proved_a.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("A reserves");
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
        let expected = expected_binding(domain, DETAIL_GENERATION, 0xC00, 0xE9E);
        let cas_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut healthy = GatedActivationSource::new(
            Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
            custody.clone(),
            PreparedChildReceipt::of_bundle(&proved_a.bundle)
                .expect("scene seals its prepared child"),
        );
        let delivered_a = PreparedChildReceipt::of_bundle(&proved_a.bundle)
            .expect("scene seals its prepared child");
        healthy
            .validate_and_bind(&expected, Some(domain), &delivered_a)
            .expect("A-reservation→A-child binds");
        assert_eq!(
            cas_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "bind validation never attempts the CAS"
        );
        // The healthy bind took the reservation; reserve A again, then
        // offer B's prepared child with the identical original/image.
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved_a.request,
            &proved_a.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("A reserves again");
        let mut mixed = GatedActivationSource::new(
            Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
            custody.clone(),
            PreparedChildReceipt::of_bundle(&proved_b.bundle)
                .expect("scene seals its prepared child"),
        );
        let delivered_a2 = PreparedChildReceipt::of_bundle(&proved_a.bundle)
            .expect("scene seals its prepared child");
        assert_eq!(
            mixed
                .validate_and_bind(&expected, Some(domain), &delivered_a2)
                .unwrap_err(),
            NativeActivationRefusal::BindingMismatch,
            "A-reservation→worker-B refuses before the CAS"
        );
        assert_eq!(
            cas_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a refused bind never attempts the CAS"
        );
        let parked = custody.take_bound().expect("the refusal parks");
        assert!(
            matches!(parked, BoundWindow::Unactivated(_)),
            "a refused bind parks Unactivated, never Active"
        );
    }

    #[test]
    fn selected_detail_bind_refuses_delivered_child_for_other_provider() {
        use crate::inventory_promotion::lifecycle::NativeActivationRefusal;
        // A reservation for A with a worker-side receipt for A must
        // still refuse when the actually delivered lane prepared B —
        // even with identical original custody and image. Healthy
        // A/A/A binds; A/A/B refuses WITHOUT a CAS, parks
        // Unactivated, and retains its resources until a genuine
        // close. Both bundles share one pin so only the
        // provider/coverage identity distinguishes them.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let pin = Arc::new(crate::process::PidPin::open(std::process::id()).expect("self pins"));
        let convert_a = convert_for(&scene.plan, scene.id_a);
        let convert_b = convert_for(&scene.plan, scene.id_b);
        let proved_a = promotion_scene_with_pin(
            Arc::clone(&pin),
            convert_a,
            scene.objects.clone(),
            BTreeMap::from([(scene.id_a, BTreeSet::from([0]))]),
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let proved_b = promotion_scene_with_pin(
            Arc::clone(&pin),
            convert_b,
            scene.objects.clone(),
            BTreeMap::from([(scene.id_b, BTreeSet::from([0]))]),
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved_a.request,
            &proved_a.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("A reserves");
        let domain = crate::attach::capture::NativeDomainId::try_mint().expect("domain mints");
        let expected = expected_binding(domain, DETAIL_GENERATION, 0xC00, 0xE9E);
        let cas_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Healthy control: reservation A, worker A, delivered A binds.
        let mut healthy = GatedActivationSource::new(
            Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
            custody.clone(),
            PreparedChildReceipt::of_bundle(&proved_a.bundle)
                .expect("scene seals its prepared child"),
        );
        let delivered_a = PreparedChildReceipt::of_bundle(&proved_a.bundle)
            .expect("scene seals its prepared child");
        healthy
            .validate_and_bind(&expected, Some(domain), &delivered_a)
            .expect("A/A/A binds");
        assert_eq!(
            cas_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "bind validation never attempts the CAS"
        );
        // The healthy bind took the reservation; reserve A again, then
        // deliver B's prepared child under worker-A credentials.
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &proved_a.request,
            &proved_a.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("A reserves again");
        let charged_after_reserve = scene.pool.snapshot().charged_bytes;
        let mut injected = GatedActivationSource::new(
            Box::new(StubInner::succeeding(Arc::clone(&cas_attempts))),
            custody.clone(),
            PreparedChildReceipt::of_bundle(&proved_a.bundle)
                .expect("scene seals its prepared child"),
        );
        let delivered_b = PreparedChildReceipt::of_bundle(&proved_b.bundle)
            .expect("scene seals its prepared child");
        assert_eq!(
            injected
                .validate_and_bind(&expected, Some(domain), &delivered_b)
                .unwrap_err(),
            NativeActivationRefusal::BindingMismatch,
            "A/A/B refuses before the CAS"
        );
        assert_eq!(
            cas_attempts.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a refused bind never attempts the CAS"
        );
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged_after_reserve,
            "a refused bind retains its resources until genuine cleanup"
        );
        let parked = custody.take_bound().expect("the refusal parks");
        let BoundWindow::Unactivated(window) = parked else {
            panic!("a refused bind parks Unactivated, never Active");
        };
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 11, 12),
            window_of(40, 50),
        );
        let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&after));
        let report = close_detail_window_on_banks(
            window,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("Unactivated close delivers lineage");
        assert!(
            report.after_receipt.is_none(),
            "the banks-level seam observes no collector, so it carries no receipt"
        );
        assert!(
            scene.pool.snapshot().charged_bytes < charged_after_reserve,
            "genuine close releases the retained charge"
        );
        assert!(!custody.is_occupied());
    }

    #[test]
    fn selected_detail_before_bracket_refuses_unhealthy_acquisitions() {
        // A bracketing read the collector would reject — saturated or
        // contended producer, nonzero kernel loss — must refuse reserve,
        // never open a window on it.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let convert_a = convert_for(&scene.plan, scene.id_a);
        let proved = promotion_scene(
            convert_a,
            scene.objects.clone(),
            scene.id_a,
            Some(0x80),
            0xC00,
            0xE9E,
        );
        let base = counts_for(&scene.plan, 8, 9);
        for (label, health, kernel) in [
            (
                "saturated",
                CounterHealth {
                    saturated: true,
                    contended: false,
                },
                KernelEvidence::default(),
            ),
            (
                "contended",
                CounterHealth {
                    saturated: false,
                    contended: true,
                },
                KernelEvidence::default(),
            ),
            (
                "kernel-loss",
                CounterHealth::default(),
                KernelEvidence {
                    ring_loss: 1,
                    ..Default::default()
                },
            ),
        ] {
            let custody = DetailWindowCustody::new();
            let read = scripted_read_with_signals(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                CounterMode::Counts,
                &base,
                window_of(30, 40),
                health,
                kernel,
            );
            assert_eq!(
                reserve_detail_window_on_banks(
                    &scene.banks,
                    broad_facts(BROAD_GENERATION, false),
                    &scene.plan,
                    &scene.objects,
                    &proved.request,
                    &proved.bundle,
                    &read,
                    SEQ_BEFORE,
                    &scene.pool.reserver(),
                    &custody,
                )
                .unwrap_err(),
                SelectedDetailRefusal::BroadPlanTopology,
                "case {label} refuses reserve"
            );
            assert!(
                !custody.is_occupied(),
                "case {label}: a refused reserve places nothing"
            );
        }
    }

    #[test]
    fn selected_detail_after_bracket_discloses_unhealthy_acquisitions() {
        // An after-bracket read the collector would reject must never
        // verify Matched: the close discloses the defect and still
        // delivers its true live marks and seqs.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let convert_a = convert_for(&scene.plan, scene.id_a);
        for (label, health, kernel, expected) in [
            (
                "saturated",
                CounterHealth {
                    saturated: true,
                    contended: false,
                },
                KernelEvidence::default(),
                "health",
            ),
            (
                "kernel-loss",
                CounterHealth::default(),
                KernelEvidence {
                    ring_loss: 1,
                    ..Default::default()
                },
                "kernel",
            ),
        ] {
            let proved = promotion_scene(
                convert_a.clone(),
                scene.objects.clone(),
                scene.id_a,
                Some(0x80),
                0xC00,
                0xE9E,
            );
            let custody = DetailWindowCustody::new();
            let before = scripted_read(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                CounterMode::Counts,
                &counts_for(&scene.plan, 8, 9),
                window_of(30, 40),
            );
            reserve_detail_window_on_banks(
                &scene.banks,
                broad_facts(BROAD_GENERATION, false),
                &scene.plan,
                &scene.objects,
                &proved.request,
                &proved.bundle,
                &before,
                SEQ_BEFORE,
                &scene.pool.reserver(),
                &custody,
            )
            .expect("proved request reserves");
            let reservation = custody.take_reserved().expect("placed");
            let window = reservation.bind_generation(DETAIL_GENERATION);
            let after = scripted_read_with_signals(
                &scene.pool,
                &scene.plan,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                CounterMode::Counts,
                &counts_for(&scene.plan, 11, 12),
                window_of(40, 50),
                health,
                kernel,
            );
            let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&after));
            let report = close_detail_window_on_banks(
                window,
                &scene.banks,
                NonZeroU64::new(BROAD_GENERATION).unwrap(),
                &scene.plan,
                &bracket,
            )
            .expect("close delivers its true marks");
            assert_eq!(
                report.bracket,
                CloseBracketVerdict::Mismatched(expected),
                "case {label} names its mismatch, never Matched"
            );
            assert_eq!(
                (report.seq_before, report.seq_after),
                (SEQ_BEFORE, SEQ_AFTER),
                "case {label}: the close still delivers its true seqs"
            );
        }
    }

    #[test]
    fn selected_detail_taken_active_window_blocks_second_reserve() {
        // An Active window taken for install still occupies admission
        // until its terminal close: a second reserve refuses WindowActive
        // with the first charge intact, and reselect succeeds after the
        // close.
        let pool = test_pool();
        let scene = stage_single_provider(pool, 513);
        let convert = convert_tail(&scene.plan, scene.object, 13);
        let first = promotion_scene(
            convert.clone(),
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 512 * 0x10),
            0xC00,
            0xE9E,
        );
        let custody = DetailWindowCustody::new();
        let before = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &first.request,
            &first.bundle,
            &before,
            SEQ_BEFORE,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("first reserves");
        let reservation = custody.take_reserved().expect("placed");
        let window = reservation.bind_generation(DETAIL_GENERATION);
        custody
            .place_bound(BoundWindow::Active(window))
            .expect("FORGED-ACTIVE parks (CAS is live-only)");
        let taken = custody.take_bound().expect("Install takes Active");
        let BoundWindow::Active(active) = taken else {
            panic!("a CAS-won window installs Active, never Unactivated");
        };
        // A second request while the first Active window is still open.
        let second = promotion_scene(
            convert,
            scene.objects.clone(),
            scene.object,
            Some(0x80 + 511 * 0x10),
            0xC00,
            0xE9E,
        );
        let before2 = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 8, 9),
            window_of(30, 40),
        );
        let charged_before_second = scene.pool.snapshot().charged_bytes;
        assert_eq!(
            reserve_detail_window_on_banks(
                &scene.banks,
                broad_facts(BROAD_GENERATION, false),
                &scene.plan,
                &scene.objects,
                &second.request,
                &second.bundle,
                &before2,
                SEQ_BEFORE + 1,
                &scene.pool.reserver(),
                &custody,
            )
            .unwrap_err(),
            SelectedDetailRefusal::WindowActive,
            "a taken Active window still occupies admission"
        );
        assert_eq!(
            scene.pool.snapshot().charged_bytes,
            charged_before_second,
            "a refused reserve charges nothing"
        );
        // The terminal close releases admission; reselect then succeeds.
        let after = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 11, 12),
            window_of(40, 50),
        );
        let bracket = CloseBracket::new(SEQ_AFTER, CounterMode::Counts, Some(&after));
        let report = close_detail_window_on_banks(
            active,
            &scene.banks,
            NonZeroU64::new(BROAD_GENERATION).unwrap(),
            &scene.plan,
            &bracket,
        )
        .expect("ordered close delivers");
        assert_eq!(report.bracket, CloseBracketVerdict::Matched);
        reserve_detail_window_on_banks(
            &scene.banks,
            broad_facts(BROAD_GENERATION, false),
            &scene.plan,
            &scene.objects,
            &second.request,
            &second.bundle,
            &before2,
            SEQ_BEFORE + 1,
            &scene.pool.reserver(),
            &custody,
        )
        .expect("reselect reserves after close");
        let reselect = custody.take_reserved().expect("reselect placed");
        assert_eq!(reselect.selected(), 511);
        reselect.abandon();
        assert!(!custody.is_occupied());
    }

    #[test]
    fn selected_detail_bracket_acceptance_assigns_seq_on_observe_only() {
        use super::super::counter_collector::ReadStage;
        // The session path's shared orchestration: seqs assign only on
        // actual collector acceptance of the exact acquisition. Failed
        // and foreign acquisitions leave the collector baseline and
        // the seq untouched (the next healthy acceptance still
        // advances); same-generation unhealthy acquisitions latch the
        // collector's sticky loss (the next healthy same-generation
        // read stays unavailable) with the seq still untouched; only
        // a fresh generation recovers.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut brackets =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut seq = 0;
        let brgen = NonZeroU64::new(BROAD_GENERATION).unwrap();
        // Positive control: the accepted read assigns seq 1 and
        // retains its real acquisition window and identity.
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        let receipt = accept_before_bracket(&mut brackets, Ok(r0), &scene.plan, brgen, &mut seq)
            .expect("healthy acquisition accepts");
        assert_eq!(seq, 1);
        assert_eq!(receipt.seq, 1);
        assert_eq!(receipt.generation, brgen);
        assert_eq!(receipt.mode, CounterMode::Counts);
        assert_eq!(receipt.window, Some((10, 20)));
        assert_eq!(receipt.rows, 4);
        // A failed acquisition refuses with seq and baseline untouched.
        assert_eq!(
            accept_before_bracket(
                &mut brackets,
                Err(ReadStage::Budget),
                &scene.plan,
                brgen,
                &mut seq
            )
            .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology
        );
        assert_eq!(seq, 1, "a failed acquisition assigns no seq");
        // A foreign generation refuses without observing (no pollution).
        let foreign = scripted_read(
            &scene.pool,
            &scene.plan,
            NonZeroU64::new(BROAD_GENERATION + 1).unwrap(),
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        assert_eq!(
            accept_before_bracket(&mut brackets, Ok(foreign), &scene.plan, brgen, &mut seq)
                .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology
        );
        assert_eq!(seq, 1, "a foreign acquisition assigns no seq");
        // A same-generation unhealthy acquisition refuses (seq
        // untouched) but latches the collector's sticky loss: the
        // failed and foreign rejections above left the baseline
        // pristine, this one does not.
        let saturated = scripted_read_with_signals(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
            CounterHealth {
                saturated: true,
                contended: false,
            },
            KernelEvidence::default(),
        );
        assert_eq!(
            accept_before_bracket(&mut brackets, Ok(saturated), &scene.plan, brgen, &mut seq)
                .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology
        );
        assert_eq!(seq, 1, "an unhealthy acquisition assigns no seq");
        // Sticky loss: the next healthy same-generation acquisition
        // stays unavailable (it must not erase the observed loss).
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        assert_eq!(
            accept_before_bracket(&mut brackets, Ok(r1), &scene.plan, brgen, &mut seq)
                .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology,
            "healthy after unhealthy in one generation stays unavailable"
        );
        assert_eq!(seq, 1, "a latched-out acquisition assigns no seq");
        // A shape-correct acquisition the collector rejects (failed
        // differences: fewer rows than the baseline) refuses with the
        // seq untouched. Fresh collector, so the sticky latch above
        // cannot satisfy this case for it.
        let mut diff_brackets =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut diff_seq = 0;
        let diff_r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        accept_before_bracket(
            &mut diff_brackets,
            Ok(diff_r0),
            &scene.plan,
            brgen,
            &mut diff_seq,
        )
        .expect("diff collector accepts its baseline");
        assert_eq!(diff_seq, 1);
        let short_plan = AttachPlan::from_slots(scene.plan.slots[..2].to_vec());
        let short = scripted_read(
            &scene.pool,
            &short_plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&short_plan, 9, 9),
            window_of(30, 40),
        );
        assert_eq!(
            accept_before_bracket(&mut diff_brackets, Ok(short), &scene.plan, brgen, &mut diff_seq)
                .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology
        );
        assert_eq!(
            diff_seq, 1,
            "a collector-rejected acquisition assigns no seq"
        );
        // A restarted broad capture adopts cleanly: the collector moves
        // to the fresh generation (superseding the latched one) and the
        // bracket assigns.
        let brgen8 = NonZeroU64::new(BROAD_GENERATION + 1).unwrap();
        let r8 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen8,
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(40, 50),
        );
        let receipt = accept_before_bracket(&mut brackets, Ok(r8), &scene.plan, brgen8, &mut seq)
            .expect("the fresh generation adopts");
        assert_eq!((seq, receipt.seq), (2, 2));
        assert_eq!(receipt.generation, brgen8);
        // A shape-correct acquisition refused by pre-latched collector
        // state assigns nothing and installs nothing.
        let mut stuck =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut stuck_seq = 0;
        let bad = scripted_read_with_signals(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
            CounterHealth {
                saturated: true,
                contended: false,
            },
            KernelEvidence::default(),
        );
        assert!(
            matches!(
                stuck.observe_for_test(Ok(bad)),
                CounterObservation::Unavailable(_)
            ),
            "the premise: the collector latches on the bad read"
        );
        let good = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        assert_eq!(
            accept_before_bracket(&mut stuck, Ok(good), &scene.plan, brgen, &mut stuck_seq)
                .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology
        );
        assert_eq!(stuck_seq, 0, "a latched-out acquisition assigns no seq");
    }

    #[test]
    fn selected_detail_after_bracket_acceptance_discloses_without_promotion() {
        use super::super::counter_collector::ReadStage;
        // accept_after_bracket: a fresh acceptance assigns; a failed
        // acquisition is explicitly unavailable; a defective or
        // collector-rejected one is mismatched — never Matched, never
        // promoted to fresh. The seq advances only on acceptance.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut brackets =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut seq = 0;
        let brgen = NonZeroU64::new(BROAD_GENERATION).unwrap();
        // Chain a before-accept first, as the session path does.
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        accept_before_bracket(&mut brackets, Ok(r0), &scene.plan, brgen, &mut seq)
            .expect("before accepts");
        assert_eq!(seq, 1);
        // Fresh final acquisition: assigns and returns its identity.
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        let fresh = accept_after_bracket(
            &mut brackets,
            Ok(r1),
            &scene.plan,
            CounterMode::Counts,
            brgen,
            &mut seq,
        );
        let AfterBracketAcceptance::Fresh(receipt) = fresh else {
            panic!("a fresh acquisition accepts: {fresh:?}");
        };
        assert_eq!((seq, receipt.seq), (2, 2));
        assert_eq!(receipt.window, Some((20, 30)));
        // Failed acquisition: explicitly unavailable with the seq
        // untouched (the preserved failed-final-acquisition boundary:
        // the last accepted seq brackets, never fresh).
        assert_eq!(
            accept_after_bracket(
                &mut brackets,
                Err(ReadStage::Budget),
                &scene.plan,
                CounterMode::Counts,
                brgen,
                &mut seq
            ),
            AfterBracketAcceptance::Unavailable
        );
        assert_eq!(seq, 2, "a failed acquisition assigns no seq");
        // Collector-rejected acquisition: mismatched, never Matched.
        let mut stuck =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut stuck_seq = 0;
        let bad = scripted_read_with_signals(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
            CounterHealth {
                saturated: true,
                contended: false,
            },
            KernelEvidence::default(),
        );
        assert!(
            matches!(
                stuck.observe_for_test(Ok(bad)),
                CounterObservation::Unavailable(_)
            ),
            "the premise: the collector latches on the bad read"
        );
        let good = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        assert_eq!(
            accept_after_bracket(
                &mut stuck,
                Ok(good),
                &scene.plan,
                CounterMode::Counts,
                brgen,
                &mut stuck_seq
            ),
            AfterBracketAcceptance::Mismatched("rejected")
        );
        assert_eq!(stuck_seq, 0, "a latched-out acquisition assigns no seq");
        // Wrong-mode acquisition: mismatched without observing.
        let wrong = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(30, 40),
        );
        assert_eq!(
            accept_after_bracket(
                &mut brackets,
                Ok(wrong),
                &scene.plan,
                CounterMode::Latency,
                brgen,
                &mut seq
            ),
            AfterBracketAcceptance::Mismatched("mode")
        );
        assert_eq!(seq, 2, "a mismatched acquisition assigns no seq");
    }

    #[test]
    fn selected_detail_after_bracket_sticky_loss_persists() {
        // Healthy → unhealthy → healthy in one generation: the
        // unhealthy after bracket discloses its defect (seq untouched)
        // and latches the collector's sticky loss, so the next
        // healthy same-generation after bracket stays mismatched
        // (never Fresh). Only a fresh generation recovers.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut brackets =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut seq = 0;
        let brgen = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        accept_before_bracket(&mut brackets, Ok(r0), &scene.plan, brgen, &mut seq)
            .expect("before accepts");
        assert_eq!(seq, 1);
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        let fresh = accept_after_bracket(
            &mut brackets,
            Ok(r1),
            &scene.plan,
            CounterMode::Counts,
            brgen,
            &mut seq,
        );
        let AfterBracketAcceptance::Fresh(receipt) = fresh else {
            panic!("a fresh acquisition accepts: {fresh:?}");
        };
        assert_eq!((seq, receipt.seq), (2, 2));
        let saturated = scripted_read_with_signals(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(30, 40),
            CounterHealth {
                saturated: true,
                contended: false,
            },
            KernelEvidence::default(),
        );
        assert_eq!(
            accept_after_bracket(
                &mut brackets,
                Ok(saturated),
                &scene.plan,
                CounterMode::Counts,
                brgen,
                &mut seq
            ),
            AfterBracketAcceptance::Mismatched("health"),
            "an unhealthy after bracket names its defect"
        );
        assert_eq!(seq, 2, "an unhealthy acquisition assigns no seq");
        let r2 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(30, 40),
        );
        assert_eq!(
            accept_after_bracket(
                &mut brackets,
                Ok(r2),
                &scene.plan,
                CounterMode::Counts,
                brgen,
                &mut seq
            ),
            AfterBracketAcceptance::Mismatched("rejected"),
            "healthy after unhealthy in one generation stays mismatched"
        );
        assert_eq!(seq, 2, "a latched-out acquisition assigns no seq");
        let brgen8 = NonZeroU64::new(BROAD_GENERATION + 1).unwrap();
        let r8 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen8,
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(40, 50),
        );
        let fresh = accept_after_bracket(
            &mut brackets,
            Ok(r8),
            &scene.plan,
            CounterMode::Counts,
            brgen8,
            &mut seq,
        );
        let AfterBracketAcceptance::Fresh(receipt) = fresh else {
            panic!("the fresh generation adopts: {fresh:?}");
        };
        assert_eq!((seq, receipt.seq), (3, 3));
        assert_eq!(receipt.generation, brgen8);
    }

    #[test]
    fn selected_detail_bracket_deltas_conserve_across_accepts() {
        // Before/inside/after nonzero conservation through the actual
        // accept functions: each accepted `Advanced` interval carries
        // its exact nonzero deltas once (100→110 and 110→120 emit 10
        // each, never 0/0, never a 20 cumulative), `Initial` carries
        // none, and the close mapping preserves the fresh interval
        // for aggregate rendering without summing detail into broad.
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut brackets =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut seq = 0;
        let brgen = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 100, 100),
            window_of(10, 20),
        );
        let before = accept_before_bracket(&mut brackets, Ok(r0), &scene.plan, brgen, &mut seq)
            .expect("before accepts");
        assert_eq!((seq, before.seq), (1, 1));
        assert_eq!(before.window, Some((10, 20)));
        assert_eq!(before.rows, 4);
        assert!(
            before.deltas().is_none(),
            "Initial installs the baseline with no interval"
        );
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 110, 110),
            window_of(20, 30),
        );
        let inside = accept_before_bracket(&mut brackets, Ok(r1), &scene.plan, brgen, &mut seq)
            .expect("inside accepts");
        assert_eq!((seq, inside.seq), (2, 2));
        assert_eq!(inside.window, Some((20, 30)));
        let span10 = inside
            .deltas()
            .expect("the 100→110 interval carries its deltas");
        assert_eq!((span10[0].entered, span10[0].returned), (10, 10));
        assert_eq!((span10[3].entered, span10[3].returned), (10, 10));
        let aggregate10 =
            render_aggregate_bracket(span10, CounterMode::Counts, before.seq, inside.seq);
        assert_eq!(aggregate10["rows"][0]["entered"], serde_json::json!(10));
        assert_eq!(aggregate10["rows"][0]["returned"], serde_json::json!(10));
        assert_eq!(aggregate10["mode_mixed"], serde_json::json!(false));
        assert!(aggregate10.get("total").is_none());
        let r2 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 120, 120),
            window_of(30, 40),
        );
        let fresh = accept_after_bracket(
            &mut brackets,
            Ok(r2),
            &scene.plan,
            CounterMode::Counts,
            brgen,
            &mut seq,
        );
        let AfterBracketAcceptance::Fresh(after) = fresh else {
            panic!("a fresh acquisition accepts: {fresh:?}");
        };
        assert_eq!((seq, after.seq), (3, 3));
        assert_eq!(after.window, Some((30, 40)));
        let span20 = after
            .deltas()
            .expect("the 110→120 interval carries its deltas");
        assert_eq!((span20[0].entered, span20[0].returned), (10, 10));
        let aggregate20 =
            render_aggregate_bracket(span20, CounterMode::Counts, inside.seq, after.seq);
        assert_eq!(aggregate20["rows"][0]["entered"], serde_json::json!(10));
        assert!(aggregate20.get("total").is_none());
        let (verdict, preserved) = map_after_acceptance(AfterBracketAcceptance::Fresh(after));
        assert_eq!(verdict, CloseBracketVerdict::Matched);
        let kept = preserved.expect("the close preserves its fresh interval");
        assert_eq!(kept.seq, 3);
        let kept_span = kept.deltas().expect("the preserved receipt keeps deltas");
        assert_eq!((kept_span[0].entered, kept_span[0].returned), (10, 10));
    }

    #[test]
    fn selected_detail_bracket_deltas_emit_nothing_on_failure() {
        // Failed observations emit no fabricated delta: refused
        // before brackets mint no receipt, `Initial` and
        // `GenerationChanged` carry `None` (never zeros), failed and
        // mismatched after brackets carry no receipt, and the close
        // mapping preserves nothing for them.
        use super::super::counter_collector::ReadStage;
        let pool = test_pool();
        let scene = stage_two_providers(pool);
        let mut brackets =
            BroadBracketCollector::new(scene.plan.slots.len(), 0, scene.pool.reserver());
        let mut seq = 0;
        let brgen = NonZeroU64::new(BROAD_GENERATION).unwrap();
        let r0 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
        );
        let before = accept_before_bracket(&mut brackets, Ok(r0), &scene.plan, brgen, &mut seq)
            .expect("before accepts");
        assert_eq!(seq, 1);
        assert!(
            before.deltas().is_none(),
            "Initial carries no interval, never zeros"
        );
        let saturated = scripted_read_with_signals(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 3, 5),
            window_of(10, 20),
            CounterHealth {
                saturated: true,
                contended: false,
            },
            KernelEvidence::default(),
        );
        assert_eq!(
            accept_before_bracket(&mut brackets, Ok(saturated), &scene.plan, brgen, &mut seq)
                .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology,
            "an unhealthy acquisition mints no receipt"
        );
        assert_eq!(seq, 1);
        let r1 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen,
            CounterMode::Counts,
            &counts_for(&scene.plan, 5, 7),
            window_of(20, 30),
        );
        assert_eq!(
            accept_before_bracket(&mut brackets, Ok(r1), &scene.plan, brgen, &mut seq)
                .unwrap_err(),
            SelectedDetailRefusal::BroadPlanTopology,
            "a latched-out acquisition mints no receipt"
        );
        assert_eq!(seq, 1);
        let brgen8 = NonZeroU64::new(BROAD_GENERATION + 1).unwrap();
        let r8 = scripted_read(
            &scene.pool,
            &scene.plan,
            brgen8,
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(40, 50),
        );
        let jumped = accept_before_bracket(&mut brackets, Ok(r8), &scene.plan, brgen8, &mut seq)
            .expect("the fresh generation adopts");
        assert_eq!((seq, jumped.seq), (2, 2));
        assert!(
            jumped.deltas().is_none(),
            "GenerationChanged carries no interval across generations"
        );
        assert_eq!(
            accept_after_bracket(
                &mut brackets,
                Err(ReadStage::Budget),
                &scene.plan,
                CounterMode::Counts,
                brgen8,
                &mut seq
            ),
            AfterBracketAcceptance::Unavailable,
            "a failed acquisition carries no receipt"
        );
        assert_eq!(seq, 2);
        let bad = scripted_read_with_signals(
            &scene.pool,
            &scene.plan,
            brgen8,
            CounterMode::Counts,
            &counts_for(&scene.plan, 9, 9),
            window_of(40, 50),
            CounterHealth {
                saturated: true,
                contended: false,
            },
            KernelEvidence::default(),
        );
        assert_eq!(
            accept_after_bracket(
                &mut brackets,
                Ok(bad),
                &scene.plan,
                CounterMode::Counts,
                brgen8,
                &mut seq
            ),
            AfterBracketAcceptance::Mismatched("health"),
            "an unhealthy after bracket carries no receipt"
        );
        assert_eq!(seq, 2);
        let (verdict, preserved) = map_after_acceptance(AfterBracketAcceptance::Unavailable);
        assert_eq!(verdict, CloseBracketVerdict::AfterUnavailable);
        assert!(preserved.is_none(), "no receipt is fabricated for loss");
        let (verdict, preserved) =
            map_after_acceptance(AfterBracketAcceptance::Mismatched("rejected"));
        assert_eq!(verdict, CloseBracketVerdict::Mismatched("rejected"));
        assert!(preserved.is_none(), "no receipt is fabricated for rejection");
    }
}
