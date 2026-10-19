//! SPDX-License-Identifier: GPL-3.0-or-later
//! DR37 selected-lane lifecycle: the activation proof, the preparation
//! worker service and the native-authority boundaries.
//!
//! Decision record (joint DR37/H8 implementer; rationale beside each
//! binding site):
//!
//! * D1 seal gate: no unification flag. [`JointSealTick`](crate::semantics_objects::journal::JointSealTick)
//!   keeps `allow(dead_code)` + test-only driving until a live-loop
//!   caller exists; a flag nobody sets would be dead scaffolding.
//! * D2 worker model: one worker thread per preparation (this service),
//!   polled from the driver tick. Preparation does blocking BPF loads
//!   and 10ms sleep loops (`selected_detailed.rs` fallback poll), so a
//!   tick state machine cannot host it. Precedent: `MetadataLane`
//!   (`service_caller_metadata` + bounded join in
//!   `finish_caller_metadata_cleanup`).
//! * D3 activation CAS: `2 == ACTIVE` holds by implication
//!   (`StateControl::close` CASes `2 -> TERMINAL`), but the joint lane
//!   authors neither the constant nor the CAS: the native owner owns
//!   the state machine single-authored. This module defines only the
//!   receipt ([`NativeCasReceipt`]) and the minter interface
//!   ([`NativeActivationSource`]) the joint service consumes.
//! * D4 completion minter: the native owner (Q/drain bounds, scrub,
//!   joined detach). This module defines the opaque
//!   [`SessionNativeCompletion`] and [`NativeCompletionSource`]; the
//!   native lane implements the minter.
//! * D5 A->B transfer: `mem::replace` of the coordinator's
//!   `joint_capture` field with a fresh owner, never an in-place
//!   reset. The single proof-gated entry is
//!   `InventoryCoordinator::retire_joint_domain`.
//! * D10 validation: new narrow checks, not `consume_semantic_admission`:
//!   per-pair request re-validation is a different shape from
//!   per-caller admission, and reuse would manufacture
//!   candidate/prepared values. The driver composes three genuine
//!   pre-start gates: [`validate_subset_shape`] (pure: the bundle's
//!   conversion envelope names exactly one provider object),
//!   `PromotionImageBaseline::matches_request` (pre-tested bundle
//!   agreement), and the coordinator's
//!   `validate_selected_pair_liveness` (live registry re-check
//!   returning the provider key for the subset's
//!   `proves_provider_module`). The native permit validation stays
//!   the authority downstream.
//!
//! Genuine behavior only: the worker runs the real closed
//! preparation (via [`PreparationBundle::prepare`]); the sealed
//! conversion runs on the consuming thread through the sanctioned
//! one-way handoff; failures dispose through the real joined-cleanup
//! polls; no status `Active` is emitted without a genuine coordinator
//! install; no completion is manufactured.

use super::PromotionRequest;
use super::state::{
    PromotionEnd, PromotionOutcome, PromotionPair, PromotionRefusal, PromotionStatusUpdate,
    RequestId,
};
use crate::attach::capture::NativeDomainId;
use crate::attach::selected_detailed::baseline::PromotionImageBaseline;
use crate::attach::selected_detailed::{
    PreparedSelectedSession, SelectedConstructionPermit, SelectedPreparationFailure,
};
use crate::attach::{BackendSelection, Scope, Session};
#[cfg(test)]
use crate::discovery::caller_registry::{CallerId, MappingEvidence, ModuleId, UseCoverage};
use crate::discovery::engine::inventory_coordinator::semantics::PromotionInstallCapacity;
#[cfg(test)]
use crate::inventory_present::Presentation;
use crate::inventory_semantics::AttestedSubset;
use crate::inventory_semantics::selected::ProvisionalSelectedLane;
use p11scope_ebpf_common::ImageIdentity;
use std::sync::Arc;

/// The agreement point between the native permit, the CAS receipt and
/// the activation proof: the exact native domain, attachment
/// generation and frozen image the activation binds. `Copy`: values,
/// never authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SelectedActivationBinding {
    domain: NativeDomainId,
    generation: u64,
    image: ImageIdentity,
}

impl SelectedActivationBinding {
    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): read by tests and the native minter.
    pub(crate) fn new(domain: NativeDomainId, generation: u64, image: ImageIdentity) -> Self {
        Self {
            domain,
            generation,
            image,
        }
    }

    /// Read the binding off a live construction permit. The permit's
    /// own `validate` remains the authority; this only projects the
    /// agreed values for receipt/proof matching.
    pub(crate) fn of_permit(permit: &SelectedConstructionPermit) -> Self {
        Self {
            domain: permit.domain(),
            generation: permit.generation(),
            image: permit.image(),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): read by tests and the native minter.
    pub(crate) fn domain(self) -> NativeDomainId {
        self.domain
    }

    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): read by tests and the native minter.
    pub(crate) fn generation(self) -> u64 {
        self.generation
    }

    #[cfg_attr(not(test), allow(dead_code))] // STAGED (DR37): read by tests and the native minter.
    pub(crate) fn image(self) -> ImageIdentity {
        self.image
    }
}

/// The native owner's activation receipt: proves the selected
/// `CLOSED -> ACTIVE` CAS ran exactly once for this binding, with
/// readback. Opaque and move-only (no `Clone`, no numeric
/// constructor): only the native [`NativeActivationSource`]
/// implementation mints production receipts; tests script them.
pub(crate) struct NativeCasReceipt {
    binding: SelectedActivationBinding,
}

impl NativeCasReceipt {
    /// Production mint, called only by a [`NativeActivationSource`]
    /// implementation immediately after its genuine `CLOSED -> ACTIVE`
    /// CAS with readback. The type cannot name the native-only
    /// caller; the trust chain carries it instead: the resolver
    /// (native-owned) supplies the service's source, so only a
    /// native implementation's receipts reach the proof mint in
    /// production. Test doubles script instead and never run live.
    pub(crate) fn minted(binding: SelectedActivationBinding) -> Self {
        Self { binding }
    }

    pub(crate) fn matches(&self, binding: SelectedActivationBinding) -> bool {
        self.binding == binding
    }

    /// Tests-only receipt: the binding checks run without native maps.
    /// Production construction stays inside the native minter.
    #[cfg(test)]
    pub(crate) fn scripted(binding: SelectedActivationBinding) -> Self {
        Self { binding }
    }
}

impl std::fmt::Debug for NativeCasReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NativeCasReceipt(<retained>)")
    }
}

/// Why the native activation CAS minted nothing. The joint service
/// maps every variant to `PromotionRefusal::ActivationFailed`; the
/// variants stay distinct so native tests pin the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeActivationRefusal {
    /// The state cell was not `CLOSED` (already active, terminal, or
    /// never published): the CAS ran and failed closed. Custody gates
    /// (unbound or exited original) refuse before the CAS through the
    /// same variant: no receipt mints either way.
    NotClosed,
    /// The live native owner disagrees with the expected binding.
    BindingMismatch,
}

/// The exact interface the joint service needs from the native
/// activation minter (D3). The native lane implements this in attach
/// code, where the `SELECTED_DETAILED_STATE` cell lives: exactly one
/// `CLOSED -> ACTIVE` CAS with readback per accepted request, after
/// validation, before install. Failure mints nothing.
pub(crate) trait NativeActivationSource: Send {
    fn activate(
        &mut self,
        session: &Session,
        expected: &SelectedActivationBinding,
    ) -> Result<NativeCasReceipt, NativeActivationRefusal>;
}

/// The native owner's domain-completion proof: Q/drain bounds proved,
/// object-start scrubbed, producer detach really joined. Opaque and
/// move-only: only the native [`NativeCompletionSource`]
/// implementation mints production completions, after genuine
/// disposal; tests script them. Consumed by value by
/// `InventoryCoordinator::retire_joint_domain`, which hands it back
/// with every refusal: the source delivers once, so the driver
/// retains the returned proof across retryable attempts instead of
/// re-polling.
pub(crate) struct SessionNativeCompletion {
    domain: NativeDomainId,
}

impl SessionNativeCompletion {
    /// Production mint, called only by a [`NativeCompletionSource`]
    /// implementation after its genuine disposal proof (Q/drain
    /// bounds, object-start scrub, joined producer detach). Same
    /// trust chain as [`NativeCasReceipt::minted`]: only the
    /// native-owned source's completions reach the retire entry in
    /// production.
    #[allow(dead_code)] // STAGED (DR37): called by the native minter; tests script completions instead.
    pub(crate) fn completed(domain: NativeDomainId) -> Self {
        Self { domain }
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    /// Tests-only completion: retire-gate checks run without native
    /// disposal. Production construction stays in the native minter.
    #[cfg(test)]
    pub(crate) fn scripted(domain: NativeDomainId) -> Self {
        Self { domain }
    }
}

impl std::fmt::Debug for SessionNativeCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionNativeCompletion(<retained>)")
    }
}

/// The exact interface the joint driver needs from the native
/// completion minter (D4): poll whether one domain's native disposal
/// genuinely completed. `None` means pending (or unknown): the driver
/// holds B and polls again; it never manufactures a completion, never
/// resets history and never recycles a ticket.
pub(crate) trait NativeCompletionSource: Send {
    fn poll_completion(&mut self, domain: NativeDomainId) -> Option<SessionNativeCompletion>;
}

/// Why proof minting refused. Every variant leaves the lane
/// uninstalled and the capacity refunded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofMintRefusal {
    /// The CAS receipt names another binding than the prepared lane.
    CasMismatch,
}

/// The move-only activation proof: the outstanding request, the exact
/// pair it promotes, the agreed native binding and the consumed CAS
/// receipt. Minted only by [`SelectedActivationProof::mint`] after
/// validation plus a matching native receipt; consumed by value by
/// the coordinator install entry. No `Clone`, no numeric constructor.
pub(crate) struct SelectedActivationProof {
    // STAGED (DR37): the audit link from proof to taken request. No
    // current reader: the single-flight Installing state already
    // holds the request, so no keying is needed. The unification
    // wave records this link in finalizer history at install.
    #[allow(dead_code)]
    request: RequestId,
    pair: PromotionPair,
    binding: SelectedActivationBinding,
    cas: NativeCasReceipt,
}

impl SelectedActivationProof {
    /// Mint the proof for a taken request over a prepared lane: the
    /// receipt must name exactly the lane's binding (domain,
    /// generation and image). A foreign, stale or mismatched receipt
    /// refuses with nothing installed.
    pub(crate) fn mint(
        request: &PromotionRequest,
        lane: SelectedActivationBinding,
        cas: NativeCasReceipt,
    ) -> Result<Self, ProofMintRefusal> {
        if !cas.matches(lane) {
            return Err(ProofMintRefusal::CasMismatch);
        }
        Ok(Self {
            request: request.id(),
            pair: PromotionPair::new(request.caller().0, request.provider().0),
            binding: lane,
            cas,
        })
    }

    pub(crate) fn pair(&self) -> PromotionPair {
        self.pair
    }

    /// Whether this proof authorizes installing a lane with this
    /// binding: the minted binding must name the lane, and the
    /// retained receipt must confirm the lane independently. The
    /// install entry calls this before moving anything.
    pub(crate) fn matches_lane(&self, lane: SelectedActivationBinding) -> bool {
        self.binding == lane && self.cas.matches(lane)
    }
}

impl std::fmt::Debug for SelectedActivationProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedActivationProof")
            .field("request", &self.request)
            .field("pair", &self.pair)
            .finish_non_exhaustive()
    }
}

/// The resolved preparation inputs for one taken request: two subset
/// mints from the same retained sources (`attach` seals the Session
/// attachment and is consumed by the seal; `convert` stays the lane's
/// conversion envelope), the pre-view image baseline, the original
/// custody, the parent scope, the backend selection and the read
/// window. Built by the pair resolver (carry: manifest permission
/// lookup per clicked pair); the driver validates the bundle against
/// the request, then the worker consumes it.
pub(crate) struct PreparationBundle {
    pub(crate) attach: AttestedSubset,
    pub(crate) convert: AttestedSubset,
    pub(crate) baseline: PromotionImageBaseline,
    pub(crate) original: Arc<crate::process::PidPin>,
    pub(crate) parent: Scope,
    pub(crate) backend: BackendSelection,
    pub(crate) window: crate::attach::capture::ReadWindow,
}

impl std::fmt::Debug for PreparationBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparationBundle(<retained>)")
    }
}

/// What one preparation produced. `Ready` carries the genuine
/// closed preparation plus the conversion envelope; the sealed
/// conversion (`into_provisional_lane`) runs on the consuming thread,
/// which is tick-safe (pure H0 init plus fast map-read checks) and
/// keeps the one-way handoff intact. `Failed` carries the real
/// retained failure owner, whose cleanup the service polls to a
/// joined receipt. Both variants are `Send` in every build: no H0 and
/// no substituted test I/O cross the worker boundary.
#[allow(clippy::large_enum_variant)] // DR37: single-flight worker handoff, moved once per promotion; sizes are native-owned.
pub(crate) enum PreparationOutcome {
    Ready(PreparedSelectedWork),
    Failed(SelectedPreparationFailure),
}

/// The worker's sealed product: the closed preparation (Session,
/// attachment and permit, no H0 yet) plus the conversion envelope.
/// The consumer converts exactly once via the sanctioned one-way
/// handoff; this type offers no parts, no callbacks and no session
/// access of its own.
pub(crate) struct PreparedSelectedWork {
    prepared: PreparedSelectedSession,
    convert: AttestedSubset,
}

impl PreparedSelectedWork {
    /// Run the sanctioned one-way conversion into the sealed
    /// provisional lane. A refusal retains its Session in the failure
    /// owner for joined cleanup.
    #[allow(clippy::result_large_err)] // DR37: cold path returning the retained native owner for joined disposal.
    fn into_provisional_lane(self) -> Result<ProvisionalSelectedLane, SelectedPreparationFailure> {
        self.prepared.into_provisional_lane(self.convert)
    }
}

impl std::fmt::Debug for PreparationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(_) => f.write_str("PreparationOutcome::Ready(<retained>)"),
            Self::Failed(failure) => f
                .debug_tuple("PreparationOutcome::Failed")
                .field(&failure.semantic_refusal())
                .field(&failure.cleanup_status())
                .finish(),
        }
    }
}

impl PreparationBundle {
    /// Run the real closed preparation on the worker: session start,
    /// bootstrap, identity completion and attachment seal (which
    /// validates the permit against the live owner internally). The
    /// sealed conversion runs consumer-side (see
    /// [`PreparationOutcome`]).
    pub(crate) fn prepare(self) -> PreparationOutcome {
        let convert = self.convert;
        match PreparedSelectedSession::prepare(
            self.attach,
            self.baseline,
            self.original,
            self.parent,
            self.backend,
            self.window,
        ) {
            Ok(prepared) => PreparationOutcome::Ready(PreparedSelectedWork { prepared, convert }),
            Err(failure) => PreparationOutcome::Failed(failure),
        }
    }

    /// The conversion envelope the driver validates against the taken
    /// request before the worker consumes the bundle.
    pub(crate) fn convert_subset(&self) -> &AttestedSubset {
        &self.convert
    }
}

/// One lifecycle event for the driver: a validated status update to
/// apply to the mailbox, or a proof-gated install handoff. The driver
/// applies statuses through `set_promotion_status` (stale/foreign
/// updates return `None` there) and records every terminal transition
/// in the normal bounded report path; it installs through the
/// coordinator install entry, which consumes the proof.
#[allow(clippy::large_enum_variant)] // DR37: single-flight driver handoff, moved once per promotion; sizes are native-owned.
pub(crate) enum LifecycleEvent {
    Status(PromotionStatusUpdate),
    Install(PendingInstall),
}

impl std::fmt::Debug for LifecycleEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(outcome) => f
                .debug_tuple("LifecycleEvent::Status")
                .field(outcome)
                .finish(),
            Self::Install(pending) => f
                .debug_tuple("LifecycleEvent::Install")
                .field(pending)
                .finish(),
        }
    }
}

/// A proof-gated install handoff held by the driver while the slot is
/// occupied: the minted proof, the sealed lane and the pre-reserved
/// capacity. Opaque: the driver either installs it (consuming all
/// three through the coordinator entry) or reclaims it into the
/// service for genuine disposal; it can neither split nor forge one.
pub(crate) struct PendingInstall {
    proof: SelectedActivationProof,
    lane: ProvisionalSelectedLane,
    capacity: PromotionInstallCapacity,
}

impl PendingInstall {
    /// Rebuild a handoff from its genuine parts (driver install
    /// refusal path): the parts are unforgeable values, so the only
    /// constructible handoffs are real ones.
    pub(crate) fn from_parts(
        proof: SelectedActivationProof,
        lane: ProvisionalSelectedLane,
        capacity: PromotionInstallCapacity,
    ) -> Self {
        Self {
            proof,
            lane,
            capacity,
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        SelectedActivationProof,
        ProvisionalSelectedLane,
        PromotionInstallCapacity,
    ) {
        (self.proof, self.lane, self.capacity)
    }

    pub(crate) fn pair(&self) -> PromotionPair {
        self.proof.pair()
    }
}

impl std::fmt::Debug for PendingInstall {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingInstall")
            .field("proof", &self.proof)
            .finish_non_exhaustive()
    }
}

/// Pre-start gate (D10): the bundle's conversion envelope must name
/// exactly one required provider object, matching what the native
/// conversion accepts. Empty coverage means no manifest permission
/// covers the pair; several means the selected endpoints are
/// ambiguous. Pure: no coordinator state, no native I/O.
pub(crate) fn validate_subset_shape(subset: &AttestedSubset) -> Result<(), PromotionRefusal> {
    match subset.required().len() {
        0 => Err(PromotionRefusal::ManifestUnavailable),
        1 => Ok(()),
        _ => Err(PromotionRefusal::EndpointAmbiguous),
    }
}

/// How a disposing outcome ends once its cleanup settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalDisposition {
    Refused(PromotionRefusal),
    Ended(PromotionEnd),
}

impl TerminalDisposition {
    fn into_outcome(self) -> PromotionOutcome {
        match self {
            Self::Refused(reason) => PromotionOutcome::Refused { reason },
            Self::Ended(reason) => PromotionOutcome::Ended { reason },
        }
    }
}

/// An outcome whose native owner still needs joined disposal: either
/// the worker's retained failure or a sealed lane that must never
/// install (cancelled, or CAS/mint/install refused).
#[allow(clippy::large_enum_variant)] // DR37: single retained owner per preparation; sizes are native-owned.
enum DisposingOutcome {
    Preparation(SelectedPreparationFailure),
    Lane(ProvisionalSelectedLane),
}

impl std::fmt::Debug for DisposingOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DisposingOutcome(<retained>)")
    }
}

/// A native owner whose cleanup proved nothing: retained for process
/// lifetime, never retried (mirrors `SelectedPreparationFailure`'s
/// `Unproved`: neither an empty collection nor `Drop` proves
/// settlement).
#[allow(clippy::large_enum_variant)] // DR37: one retained record per unproved owner; sizes are native-owned.
enum UnprovedOwner {
    Preparation(SelectedPreparationFailure),
    Lane(ProvisionalSelectedLane),
    /// A delivered worker outcome the service never handled (dropped
    /// past the stop budget): retained whole, never retried.
    Outcome(PreparationOutcome),
}

impl std::fmt::Debug for UnprovedOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Retained for process lifetime as the non-retry record;
            // formatted only for diagnostics.
            Self::Preparation(failure) => f
                .debug_tuple("UnprovedOwner::Preparation")
                .field(&failure.semantic_refusal())
                .field(&failure.cleanup_status())
                .finish(),
            Self::Lane(lane) => f.debug_tuple("UnprovedOwner::Lane").field(lane).finish(),
            Self::Outcome(outcome) => f
                .debug_tuple("UnprovedOwner::Outcome")
                .field(outcome)
                .finish(),
        }
    }
}

/// Process-lifetime custody for unresolved native owners: a dropped
/// service (or driver) retains its unproved owners, its queued worker
/// outcome and any disposal in flight instead of destroying them.
/// Retention is by `mem::forget` (the `release_terminal_owner`
/// precedent): nothing here needs `Send`, and the forgotten owners
/// live until process exit. Tests observe retention through specific
/// identities (tagged failures, retained channels), never a shared
/// counter parallel tests could satisfy for each other; production
/// never reads them.
#[cfg(test)]
static CUSTODY_RETAINED_IDS: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
static NEXT_CUSTODY_TEST_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[cfg(test)]
fn record_retained_id(id: u64) {
    CUSTODY_RETAINED_IDS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .push(id);
}

fn retain_for_process_exit<T>(owner: T) {
    std::mem::forget(owner);
}

#[allow(clippy::large_enum_variant)] // DR37: one state per service; the payloads move once per promotion.
enum ServiceState {
    Idle,
    Preparing {
        request: PromotionRequest,
        capacity: PromotionInstallCapacity,
        source: Box<dyn NativeActivationSource>,
        outcome: std::sync::mpsc::Receiver<PreparationOutcome>,
        /// The worker thread. Dropped (detached, never joined) once
        /// its message is reaped: delivery ends the worker's role,
        /// and no tick waits out thread termination — not even
        /// behind `is_finished`, which goes true before thread-local
        /// destruction runs while `join` waits for it.
        worker: Option<std::thread::JoinHandle<()>>,
        /// Cancel/stop was requested while the worker ran: the CAS is
        /// skipped and the outcome is disposed, never installed.
        cancel: Option<PromotionEnd>,
        /// Tests-only retention identity for the worker channel: the
        /// live-worker twin observes this specific channel surviving,
        /// never a shared counter.
        #[cfg(test)]
        channel_id: u64,
    },
    Disposing {
        request: PromotionRequest,
        outcome: DisposingOutcome,
        terminal: TerminalDisposition,
    },
    /// The install handoff is in driver hands. The driver confirms
    /// with [`SelectedLifecycleService::note_installed`] or reclaims
    /// with [`SelectedLifecycleService::reclaim_install`].
    Installing {
        request: PromotionRequest,
    },
}

/// The DR37 preparation worker service (D2): one worker thread per
/// preparation, polled from the driver tick. Single-flight: a second
/// `start` while busy refuses with [`PromotionRefusal::Busy`].
///
/// State flow: `Idle -> Preparing -> Installing -> Idle`, with
/// `Disposing` between any refused/cancelled outcome and its terminal
/// status. Every terminal status is emitted exactly once, from the
/// held request, after genuine disposal; `Active` is emitted only via
/// `note_installed`, after the driver reports a genuine coordinator
/// install.
pub(crate) struct SelectedLifecycleService {
    state: ServiceState,
    unproved: Vec<UnprovedOwner>,
    /// Tests-only negative control: disable retention itself while
    /// recording still runs, so the destruction probe must observe
    /// the owner die. Production always retains.
    #[cfg(test)]
    retention_disabled: bool,
    /// Tests-only post-send rendezvous: the next `start` moves this
    /// sender into its worker, which signals after its outcome send
    /// resolves (delivered, or settled after a failed late send),
    /// so retention twins check survival after
    /// delivery/destruction — never on a naked sleep past the
    /// job's own pre-send signal.
    #[cfg(test)]
    post_send_hook: Option<std::sync::mpsc::Sender<()>>,
}

impl SelectedLifecycleService {
    pub(crate) fn new() -> Self {
        Self {
            state: ServiceState::Idle,
            unproved: Vec::new(),
            #[cfg(test)]
            retention_disabled: false,
            #[cfg(test)]
            post_send_hook: None,
        }
    }

    /// Tests-only negative control: disable retention itself (not
    /// recording) so the twin's destruction probe must observe the
    /// owner die.
    #[cfg(test)]
    pub(crate) fn disable_retention_for_test(&mut self) {
        self.retention_disabled = true;
    }

    /// Arm the post-send rendezvous for the next `start`: the
    /// worker signals the returned receiver after its outcome send
    /// resolves. Consumed by `start`; a refused start keeps the
    /// armed hook for the next attempt.
    #[cfg(test)]
    pub(crate) fn observe_post_send_for_test(&mut self) -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        self.post_send_hook = Some(tx);
        rx
    }

    /// Process-lifetime custody for one teardown owner. Production
    /// always retains; tests disable retention for the negative
    /// control above.
    fn retain_custody<T>(&self, owner: T) {
        #[cfg(test)]
        if self.retention_disabled {
            drop(owner);
            return;
        }
        retain_for_process_exit(owner);
    }

    pub(crate) fn is_idle(&self) -> bool {
        matches!(self.state, ServiceState::Idle)
    }

    /// Start preparing one taken request on the worker thread. The
    /// capacity was reserved before the CAS (it refunds by drop on
    /// every refused path); the source mints the native CAS receipt
    /// after the worker delivers a closed preparation and the sealed
    /// conversion runs consumer-side. Refuses `Busy` unless idle:
    /// preparations never overlap.
    pub(crate) fn start(
        &mut self,
        request: PromotionRequest,
        capacity: PromotionInstallCapacity,
        source: Box<dyn NativeActivationSource>,
        job: impl FnOnce() -> PreparationOutcome + Send + 'static,
    ) -> Result<(), PromotionRefusal> {
        if !self.is_idle() {
            return Err(PromotionRefusal::Busy);
        }
        #[cfg(test)]
        let post_send_hook = self.post_send_hook.take();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let outcome = job();
            if let Err(returned) = tx.send(outcome) {
                // The service is gone (process teardown past the
                // stop bound): settle in-worker on a bounded best
                // effort instead of dropping a live native owner.
                // Best effort only: teardown already gave up polling.
                settle_outcome_best_effort(returned.0);
            }
            // Tests-only: the send resolved (delivered, or settled
            // after the late send failed), so a twin waiting here
            // observes survival after delivery/destruction.
            #[cfg(test)]
            if let Some(hook) = post_send_hook {
                let _ = hook.send(());
            }
        });
        #[cfg(test)]
        let channel_id = NEXT_CUSTODY_TEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.state = ServiceState::Preparing {
            request,
            capacity,
            source,
            outcome: rx,
            worker: Some(worker),
            cancel: None,
            #[cfg(test)]
            channel_id,
        };
        Ok(())
    }

    /// Operator cancel or run stop while work is outstanding. A
    /// preparing worker runs to its genuine end (blocking native work
    /// cannot be killed), then its outcome is disposed and the end
    /// confirmed; nothing installs after this call.
    pub(crate) fn note_cancel(&mut self, end: PromotionEnd) {
        match &mut self.state {
            ServiceState::Preparing { cancel, .. } => {
                *cancel = Some(match (*cancel, end) {
                    (Some(PromotionEnd::RunStopped), _) | (_, PromotionEnd::RunStopped) => {
                        PromotionEnd::RunStopped
                    }
                    _ => PromotionEnd::Cancelled,
                });
            }
            ServiceState::Disposing { terminal, .. } => {
                *terminal = match (*terminal, end) {
                    (TerminalDisposition::Ended(PromotionEnd::RunStopped), _)
                    | (_, PromotionEnd::RunStopped) => {
                        TerminalDisposition::Ended(PromotionEnd::RunStopped)
                    }
                    _ => TerminalDisposition::Ended(PromotionEnd::Cancelled),
                };
            }
            // Idle holds nothing; Installing already handed the
            // proof, lane and capacity to the driver, which observes
            // the stop/cancel itself and reclaims for disposal.
            ServiceState::Idle | ServiceState::Installing { .. } => {}
        }
    }

    /// Poll once (driver tick): reap a delivered worker outcome, run
    /// the CAS + mint for a sealed lane, advance joined disposal, and
    /// emit at most one event. Never blocks on the worker: a reaped
    /// delivery detaches its thread (delivery ends the worker's role;
    /// the thread exits on its own) and handles the outcome at once.
    /// Disposal diagnostics sink here; the terminal report path
    /// carries the finite reason.
    pub(crate) fn poll(&mut self, out: &mut dyn std::io::Write) -> Option<LifecycleEvent> {
        // Reap a delivery first, without holding state borrows across
        // the detach and the outcome handling below.
        let delivery: Option<Option<PreparationOutcome>> = match &mut self.state {
            ServiceState::Preparing { outcome, .. } => Some(match outcome.try_recv() {
                Err(std::sync::mpsc::TryRecvError::Empty) => return None,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => None,
                Ok(delivered) => Some(delivered),
            }),
            _ => None,
        };
        if let Some(delivery) = delivery {
            let ServiceState::Preparing {
                request,
                capacity,
                source,
                worker,
                cancel,
                ..
            } = std::mem::replace(&mut self.state, ServiceState::Idle)
            else {
                unreachable!("delivery implies preparing");
            };
            // Detach, never join: the message (or the sender's death)
            // is the complete handoff. Joining here would wait out
            // thread termination on the tick; the detached thread
            // exits on its own and the OS reclaims it. A panicked
            // worker still reports through the panic hook exactly as
            // before; its payload was never read.
            drop(worker);
            return match delivery {
                // The worker died without delivering (panic or
                // abort): nothing retained, nothing installed.
                None => {
                    drop(capacity);
                    drop(source);
                    let update = request.status_update(PromotionOutcome::Refused {
                        reason: PromotionRefusal::PreparationFailed,
                    });
                    Some(LifecycleEvent::Status(update))
                }
                Some(delivered) => {
                    self.outcome_received(request, capacity, source, delivered, cancel)
                }
            };
        }
        match &mut self.state {
            ServiceState::Idle
            | ServiceState::Installing { .. }
            | ServiceState::Preparing { .. } => None,
            ServiceState::Disposing {
                request,
                outcome,
                terminal,
            } => {
                let status = match outcome {
                    DisposingOutcome::Preparation(failure) => failure.poll_cleanup(out),
                    DisposingOutcome::Lane(lane) => lane.poll_dispose(out),
                };
                match status {
                    crate::attach::selected_detailed::SelectedCleanupStatus::Pending => None,
                    crate::attach::selected_detailed::SelectedCleanupStatus::Settled => {
                        let update = request.status_update(terminal.into_outcome());
                        self.state = ServiceState::Idle;
                        Some(LifecycleEvent::Status(update))
                    }
                    crate::attach::selected_detailed::SelectedCleanupStatus::Unproved => {
                        // Retain for process lifetime, never retry;
                        // the terminal status still reports honestly.
                        let update = request.status_update(terminal.into_outcome());
                        let old = std::mem::replace(&mut self.state, ServiceState::Idle);
                        if let ServiceState::Disposing { outcome, .. } = old {
                            self.unproved.push(match outcome {
                                DisposingOutcome::Preparation(failure) => {
                                    UnprovedOwner::Preparation(failure)
                                }
                                DisposingOutcome::Lane(lane) => UnprovedOwner::Lane(lane),
                            });
                        }
                        Some(LifecycleEvent::Status(update))
                    }
                }
            }
        }
    }

    /// Handle a delivered worker outcome: worker detached, parts
    /// reaped. Cancel wins over install: a cancelled outcome is
    /// disposed and ends, never CASed. Otherwise a sealed lane runs
    /// the native CAS plus proof mint and hands to the driver for
    /// install.
    fn outcome_received(
        &mut self,
        request: PromotionRequest,
        capacity: PromotionInstallCapacity,
        mut source: Box<dyn NativeActivationSource>,
        delivered: PreparationOutcome,
        cancel: Option<PromotionEnd>,
    ) -> Option<LifecycleEvent> {
        // Convert eagerly, even on cancel: the conversion is
        // tick-safe validation, and its refusal retains the Session
        // in the same failure owner the disposal poll drains.
        let converted = match delivered {
            PreparationOutcome::Ready(work) => work
                .into_provisional_lane()
                .map_err(DisposingOutcome::Preparation),
            PreparationOutcome::Failed(failure) => Err(DisposingOutcome::Preparation(failure)),
        };
        if let Some(end) = cancel {
            drop(capacity);
            self.state = ServiceState::Disposing {
                request,
                outcome: match converted {
                    Ok(lane) => DisposingOutcome::Lane(lane),
                    Err(outcome) => outcome,
                },
                terminal: TerminalDisposition::Ended(end),
            };
            return None;
        }
        match converted {
            Err(outcome) => {
                drop(capacity);
                self.state = ServiceState::Disposing {
                    request,
                    outcome,
                    terminal: TerminalDisposition::Refused(PromotionRefusal::PreparationFailed),
                };
                None
            }
            Ok(lane) => {
                let binding = lane.activation_binding();
                let receipt = match lane
                    .live_session()
                    .map(|session| source.activate(session, &binding))
                {
                    Some(Ok(receipt)) => receipt,
                    _ => {
                        drop(capacity);
                        self.state = ServiceState::Disposing {
                            request,
                            outcome: DisposingOutcome::Lane(lane),
                            terminal: TerminalDisposition::Refused(
                                PromotionRefusal::ActivationFailed,
                            ),
                        };
                        return None;
                    }
                };
                match SelectedActivationProof::mint(&request, binding, receipt) {
                    Ok(proof) => {
                        self.state = ServiceState::Installing { request };
                        Some(LifecycleEvent::Install(PendingInstall {
                            proof,
                            lane,
                            capacity,
                        }))
                    }
                    Err(_) => {
                        drop(capacity);
                        self.state = ServiceState::Disposing {
                            request,
                            outcome: DisposingOutcome::Lane(lane),
                            terminal: TerminalDisposition::Refused(
                                PromotionRefusal::ActivationFailed,
                            ),
                        };
                        None
                    }
                }
            }
        }
    }

    /// The driver installed the handoff through the coordinator entry:
    /// confirm `Active` for the exact requested pair, from the held
    /// request. Returns `None` unless an install is outstanding.
    pub(crate) fn note_installed(&mut self) -> Option<PromotionStatusUpdate> {
        match std::mem::replace(&mut self.state, ServiceState::Idle) {
            ServiceState::Installing { request } => {
                Some(request.status_update(PromotionOutcome::Active {
                    pair: PromotionPair::new(request.caller().0, request.provider().0),
                }))
            }
            other => {
                self.state = other;
                None
            }
        }
    }

    /// The driver could not install (cancelled while held, or the
    /// install entry refused): reclaim the handoff for genuine lane
    /// disposal. `end` selects the terminal status once disposal
    /// settles; `None` reports `ActivationFailed`.
    #[allow(clippy::result_large_err)] // DR37: cold path returning the handoff for disposal, never in a loop.
    pub(crate) fn reclaim_install(
        &mut self,
        pending: PendingInstall,
        end: Option<PromotionEnd>,
    ) -> Result<(), PendingInstall> {
        if !matches!(self.state, ServiceState::Installing { .. }) {
            return Err(pending);
        }
        let ServiceState::Installing { request } =
            std::mem::replace(&mut self.state, ServiceState::Idle)
        else {
            unreachable!("installing checked above");
        };
        let (_proof, lane, capacity) = pending.into_parts();
        // The proof authorizes exactly the install it just failed;
        // its scope ends here unconsumed, and dropping the capacity
        // refunds its precharge. The lane still needs joined disposal
        // below.
        drop(capacity);
        let terminal = match end {
            Some(end) => TerminalDisposition::Ended(end),
            None => TerminalDisposition::Refused(PromotionRefusal::ActivationFailed),
        };
        self.state = ServiceState::Disposing {
            request,
            outcome: DisposingOutcome::Lane(lane),
            terminal,
        };
        Ok(())
    }

    /// Retain one unresolved lane for process lifetime: the
    /// driver-drop path for a held handoff the service would not take
    /// back.
    pub(crate) fn retain_lane_for_process_exit(lane: ProvisionalSelectedLane) {
        retain_for_process_exit(UnprovedOwner::Lane(lane));
    }

    /// Mint one custody-twin identity: each twin tags its own failure
    /// (or observes its own channel), so parallel twins can never
    /// satisfy each other.
    #[cfg(test)]
    pub(crate) fn next_custody_test_id_for_test() -> u64 {
        NEXT_CUSTODY_TEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// The identities that reached process-lifetime custody in this
    /// process: twins assert their own identity is present, never a
    /// shared counter increase.
    #[cfg(test)]
    pub(crate) fn custody_retained_ids_for_test() -> Vec<u64> {
        CUSTODY_RETAINED_IDS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    /// The live worker channel's retention identity, while preparing:
    /// the channel twins observe this specific channel surviving.
    #[cfg(test)]
    pub(crate) fn preparing_channel_id_for_test(&self) -> Option<u64> {
        match &self.state {
            ServiceState::Preparing { channel_id, .. } => Some(*channel_id),
            _ => None,
        }
    }
}

/// Tests-only retention identity for an unproved owner: tagged
/// failures carry their twin's id; lanes and ready outcomes record
/// nothing (no custody twin tags them).
#[cfg(test)]
fn unproved_owner_test_id(owner: &UnprovedOwner) -> Option<u64> {
    match owner {
        UnprovedOwner::Preparation(failure) => failure.retention_test_id(),
        UnprovedOwner::Outcome(PreparationOutcome::Failed(failure)) => failure.retention_test_id(),
        UnprovedOwner::Outcome(PreparationOutcome::Ready(_)) | UnprovedOwner::Lane(_) => None,
    }
}

impl Default for SelectedLifecycleService {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SelectedLifecycleService {
    /// Teardown retention: unproved owners, a queued worker outcome
    /// and any disposal in flight move to process-lifetime custody
    /// instead of dying with the service. Never blocks, never joins:
    /// a live worker is detached and its late send lands in the
    /// retained channel; a dead worker's handle detaches.
    fn drop(&mut self) {
        #[cfg(test)]
        let preparing_channel_id = match &self.state {
            ServiceState::Preparing { channel_id, .. } => Some(*channel_id),
            _ => None,
        };
        for owner in std::mem::take(&mut self.unproved) {
            #[cfg(test)]
            if let Some(id) = unproved_owner_test_id(&owner) {
                record_retained_id(id);
            }
            self.retain_custody(owner);
        }
        let state = std::mem::replace(&mut self.state, ServiceState::Idle);
        match state {
            ServiceState::Preparing {
                outcome, worker, ..
            } => {
                // Detach first: no join on any teardown path.
                drop(worker);
                match outcome.try_recv() {
                    Ok(delivered) => {
                        #[cfg(test)]
                        if let PreparationOutcome::Failed(failure) = &delivered
                            && let Some(id) = failure.retention_test_id()
                        {
                            record_retained_id(id);
                        }
                        self.retain_custody(UnprovedOwner::Outcome(delivered));
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        // The worker died without delivering: nothing
                        // was ever retained, nothing to keep.
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        // The worker is still live: retain the channel
                        // itself so its late send lands in custody
                        // instead of dying with the receiver. The
                        // detached worker then exits on its own.
                        #[cfg(test)]
                        if let Some(id) = preparing_channel_id {
                            record_retained_id(id);
                        }
                        self.retain_custody(outcome);
                    }
                }
            }
            ServiceState::Disposing { outcome, .. } => {
                let owner = match outcome {
                    DisposingOutcome::Preparation(failure) => UnprovedOwner::Preparation(failure),
                    DisposingOutcome::Lane(lane) => UnprovedOwner::Lane(lane),
                };
                #[cfg(test)]
                if let Some(id) = unproved_owner_test_id(&owner) {
                    record_retained_id(id);
                }
                self.retain_custody(owner);
            }
            // Idle holds nothing; Installing already handed its parts
            // to the driver, which reclaims them on its own drop.
            ServiceState::Idle | ServiceState::Installing { .. } => {}
        }
    }
}

// The worker thread moves the job in and the outcome out: both must
// be Send in every build. This guard fails future !Send regressions
// (including test-only fields) at compile time.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<PreparationBundle>();
    assert_send::<PreparationOutcome>();
    assert_send::<PreparedSelectedWork>();
    assert_send::<crate::attach::Session>();
    assert_send::<crate::attach::selected_detailed::SelectedPreparationFailure>();
    assert_send::<PromotionRequest>();
    assert_send::<PromotionInstallCapacity>();
    assert_send::<NativeCasReceipt>();
};

/// Teardown-only best effort: the service stopped polling (process
/// teardown past the stop bound), so the worker settles its own
/// outcome before exiting instead of dropping a live native owner.
/// Bounded (100 x 10ms, the preparation sleep precedent): whatever is
/// still pending at the bound is dropped at thread exit, which is the
/// documented teardown fate, not a polled path.
fn settle_outcome_best_effort(outcome: PreparationOutcome) {
    use crate::attach::selected_detailed::SelectedCleanupStatus;
    let mut sink = std::io::sink();
    match outcome {
        PreparationOutcome::Ready(work) => match work.into_provisional_lane() {
            Ok(mut lane) => {
                for _ in 0..100 {
                    if lane.poll_dispose(&mut sink) != SelectedCleanupStatus::Pending {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
            Err(mut failure) => {
                for _ in 0..100 {
                    if failure.poll_cleanup(&mut sink) != SelectedCleanupStatus::Pending {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        },
        PreparationOutcome::Failed(mut failure) => {
            for _ in 0..100 {
                if failure.poll_cleanup(&mut sink) != SelectedCleanupStatus::Pending {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }
}

/// Tests-only one-edge view (capture 11, revision 3, pair c3/m5)
/// for queueing promotion requests through a live Display or Promoter.
#[cfg(test)]
pub(crate) fn scripted_promotion_view_for_test() -> std::sync::Arc<super::PromotionView> {
    use crate::discovery::caller_registry::MappingState;
    use crate::inventory_present::{
        Activity, BudgetView, Capture, EdgeSemanticsView, EdgeView, Presence,
    };
    let edge = EdgeView {
        caller: CallerId(3),
        module: ModuleId(5),
        mapping: MappingState::Mapped,
        mapping_reason: None,
        mapping_evidence: MappingEvidence::DeepScan,
        mapping_first_seen_ns: 0,
        mapping_last_seen_ns: 0,
        mapping_interruptions: 0,
        entry_count: 0,
        entry_saturated: false,
        entry_first_seen_ns: None,
        entry_last_seen_ns: None,
        entry_in_flight: false,
        entry_observation: "",
        coverage: UseCoverage::Counted {
            since_ns: 0,
            lossy: false,
        },
        presence: Presence::Mapped,
        capture: Capture::Armed,
        activity: Activity::Quiet,
        semantics: EdgeSemanticsView {
            label: "",
            mechanisms: Vec::new(),
            operations: None,
        },
    };
    let presentation = Presentation {
        scope_label: String::new(),
        started_ns: 0,
        ended_ns: 0,
        passes: 0,
        usage_feed: false,
        native_witnesses: crate::discovery::native_binding::BindingCensus {
            rows: 0,
            bound: 0,
            unbound: std::collections::BTreeMap::new(),
            pending: 0,
            integrity: 0,
        },
        witness_placement: crate::discovery::caller_registry::WitnessPlacement {
            edge: 0,
            module: 0,
            ambiguous: 0,
            unresolved: 0,
        },
        caller_metadata: crate::caller_metadata::runtime::MetadataFrame::default(),
        callers: Vec::new(),
        modules: Vec::new(),
        edges: vec![edge],
        instances: Vec::new(),
        semantic_edges: Vec::new(),
        gaps: Vec::new(),
        gaps_suppressed: 0,
        budgets: BudgetView {
            callers_limit: 0,
            callers_occupied: 0,
            callers_refused: 0,
            modules_limit: 0,
            modules_occupied: 0,
            modules_refused: 0,
            edges_limit: 0,
            edges_occupied: 0,
            edges_refused: 0,
            endpoints_limit: 0,
            endpoints_occupied: 0,
            endpoints_refused: 0,
            inventory_endpoints_limit: 0,
            inventory_endpoints_occupied: 0,
            inventory_endpoints_refused: 0,
            inventory_modules_limit: 0,
            inventory_modules_occupied: 0,
            inventory_modules_refused: 0,
            counters_observed: 0,
            counters_saturated: 0,
            semantic_limit: 0,
            semantic_occupied: 0,
            semantic_unknown_edges: 0,
            semantic_refused: 0,
            instances_limit: 0,
            instances_occupied: 0,
            instances_refused: 0,
            instance_semantic_occupied: 0,
            instance_semantic_unknown_edges: 0,
            instance_semantic_refused: 0,
            instance_negative_limit: 0,
            instance_negative_occupied: 0,
            instance_negative_refused: 0,
            instance_negative_exhausted: false,
            instance_semantic_resources: crate::inventory_present::SemanticResourceView::default(),
            retained_limit: 0,
            retained: 0,
            retained_suppressed: 0,
            preadmission: None,
        },
        semantic_capture: crate::inventory_semantics::SemanticCaptureSummary::default(),
        object_observations: crate::key_operation_projection::ObjectObservations::unavailable(
            0,
            "bootstrap_unavailable",
        ),
    };
    std::sync::Arc::new(super::PromotionView::new(
        super::CaptureId::new(11),
        super::ViewRevision::new(3),
        std::sync::Arc::new(presentation),
    ))
}

/// Tests-only taken request over the scripted view, with its live
/// promoter for applying the service status updates.
#[cfg(test)]
pub(crate) fn taken_request_for_test() -> (super::Promoter, PromotionRequest) {
    use crate::discovery::caller_registry::{CallerId, ModuleId};
    let mut promoter = super::Promoter::new();
    assert!(promoter.enable(super::CaptureId::new(11)));
    let view = scripted_promotion_view_for_test();
    promoter
        .request(std::sync::Arc::clone(&view), CallerId(3), ModuleId(5))
        .expect("exact pair queues");
    let request = promoter.take_request().expect("mailbox holds it");
    (promoter, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn domain() -> NativeDomainId {
        NativeDomainId::try_mint().expect("test domain mints")
    }

    fn image(cookie: u64, exec: u64) -> ImageIdentity {
        ImageIdentity {
            task_cookie: cookie,
            exec_id: exec,
        }
    }

    fn binding() -> SelectedActivationBinding {
        SelectedActivationBinding::new(domain(), 7, image(71, 72))
    }

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

    /// Scripted CAS source: mints for the expected binding, or refuses
    /// on command. Records calls through a shared counter so tests pin
    /// CAS-skipped-on-cancel.
    struct StubSource {
        refuse: Option<NativeActivationRefusal>,
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl NativeActivationSource for StubSource {
        fn activate(
            &mut self,
            _session: &Session,
            expected: &SelectedActivationBinding,
        ) -> Result<NativeCasReceipt, NativeActivationRefusal> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(refusal) = self.refuse {
                return Err(refusal);
            }
            Ok(NativeCasReceipt::scripted(*expected))
        }
    }

    fn stub_source(
        refuse: Option<NativeActivationRefusal>,
    ) -> (Box<StubSource>, Arc<std::sync::atomic::AtomicUsize>) {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        (
            Box::new(StubSource {
                refuse,
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }

    /// Poll until an event or the bound; tests fail loudly past it
    /// instead of hanging on a wedged worker.
    /// A destruction probe: the twin's liveness token moves into
    /// the worker job and then into the built failure, so the twin's
    /// `Weak` observes that specific owner's survival — alive while
    /// retained, dead once destroyed. Never a recorded marker.
    fn liveness_probe() -> (Arc<()>, std::sync::Weak<()>) {
        let probe = Arc::new(());
        let weak = Arc::downgrade(&probe);
        (probe, weak)
    }

    /// Wait for the probe to die: destruction past a detached worker
    /// is asynchronous, so the negative control polls instead of
    /// asserting on a single racy read.
    fn wait_for_destruction(weak: &std::sync::Weak<()>, bound: Duration) -> bool {
        let deadline = Instant::now() + bound;
        loop {
            if weak.upgrade().is_none() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn poll_until(
        service: &mut SelectedLifecycleService,
        bound: Duration,
    ) -> Option<LifecycleEvent> {
        let deadline = Instant::now() + bound;
        let mut sink = std::io::sink();
        loop {
            if let Some(event) = service.poll(&mut sink) {
                return Some(event);
            }
            assert!(
                Instant::now() < deadline,
                "service emitted no event within the bound"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn proof_mint_binds_request_pair_and_binding() {
        let (_promoter, request) = taken_request_for_test();
        let lane = binding();
        let proof = SelectedActivationProof::mint(&request, lane, NativeCasReceipt::scripted(lane))
            .expect("matching receipt mints");
        assert_eq!(proof.pair(), PromotionPair::new(3, 5));
        assert!(proof.matches_lane(lane));
        let other = SelectedActivationBinding::new(lane.domain(), lane.generation(), image(9, 9));
        assert!(!proof.matches_lane(other));
    }

    #[test]
    fn proof_mint_refuses_foreign_stale_and_mismatched_receipts() {
        let (_promoter, request) = taken_request_for_test();
        let lane = binding();
        let foreign = SelectedActivationBinding::new(domain(), lane.generation(), lane.image());
        let stale =
            SelectedActivationBinding::new(lane.domain(), lane.generation() + 1, lane.image());
        let mismatched =
            SelectedActivationBinding::new(lane.domain(), lane.generation(), image(9, 9));
        for wrong in [foreign, stale, mismatched] {
            assert_eq!(
                SelectedActivationProof::mint(&request, lane, NativeCasReceipt::scripted(wrong))
                    .unwrap_err(),
                ProofMintRefusal::CasMismatch
            );
            assert!(!NativeCasReceipt::scripted(wrong).matches(lane));
        }
        assert!(
            !SelectedActivationProof::mint(&request, lane, NativeCasReceipt::scripted(lane))
                .expect("matching receipt mints")
                .matches_lane(foreign)
        );
    }

    #[test]
    fn second_start_while_busy_refuses_and_keeps_first() {
        let (_promoter, first) = taken_request_for_test();
        let (_promoter, second) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        let (gate, release) = std::sync::mpsc::channel::<()>();
        service
            .start(first, capacity(), stub_source(None).0, move || {
                release.recv().expect("test releases the worker");
                PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
            })
            .expect("first start runs");
        assert!(!service.is_idle());
        assert_eq!(
            service
                .start(second, capacity(), stub_source(None).0, || {
                    PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
                })
                .unwrap_err(),
            PromotionRefusal::Busy
        );
        gate.send(()).expect("test releases the worker");
        let event = poll_until(&mut service, Duration::from_secs(5)).expect("terminal event");
        assert!(
            matches!(event, LifecycleEvent::Status(_)),
            "failed job ends refused, never installing"
        );
        assert!(service.is_idle());
    }

    #[test]
    fn failed_job_disposes_and_reports_preparation_failed() {
        let (mut promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        service
            .start(request, capacity(), stub_source(None).0, || {
                PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
            })
            .expect("start runs");
        let event = poll_until(&mut service, Duration::from_secs(5)).expect("terminal event");
        let LifecycleEvent::Status(update) = event else {
            panic!("failed job must not install");
        };
        assert_eq!(
            promoter.set_status(update),
            Some(super::super::PromotionState::Refused(
                PromotionRefusal::PreparationFailed
            ))
        );
        assert!(service.is_idle());
    }

    #[test]
    fn worker_panic_reports_preparation_failed_without_installing() {
        let (mut promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        service
            .start(
                request,
                capacity(),
                stub_source(None).0,
                || -> PreparationOutcome { panic!("scripted worker panic") },
            )
            .expect("start runs");
        let event = poll_until(&mut service, Duration::from_secs(5)).expect("terminal event");
        let LifecycleEvent::Status(update) = event else {
            panic!("panicked worker must not install");
        };
        assert_eq!(
            promoter.set_status(update),
            Some(super::super::PromotionState::Refused(
                PromotionRefusal::PreparationFailed
            ))
        );
        assert!(service.is_idle());
    }

    #[test]
    fn cancel_before_delivery_skips_cas_and_confirms_cancelled() {
        let (mut promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        let (gate, release) = std::sync::mpsc::channel::<()>();
        let (source, calls) = stub_source(None);
        service
            .start(request, capacity(), source, move || {
                release.recv().expect("test releases the worker");
                PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
            })
            .expect("start runs");
        service.note_cancel(PromotionEnd::Cancelled);
        gate.send(()).expect("test releases the worker");
        let event = poll_until(&mut service, Duration::from_secs(5)).expect("terminal event");
        let LifecycleEvent::Status(update) = event else {
            panic!("cancelled job must not install");
        };
        assert_eq!(
            promoter.set_status(update),
            Some(super::super::PromotionState::Ended(PromotionEnd::Cancelled))
        );
        assert!(service.is_idle());
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no activation CAS runs after cancellation was requested"
        );
    }

    fn scripted_subset(objects: &[(u32, u32)]) -> AttestedSubset {
        use crate::discovery::identity::PinnedObjectId;
        use std::collections::{BTreeMap, BTreeSet};
        let required: BTreeMap<PinnedObjectId, BTreeSet<u32>> = objects
            .iter()
            .map(|(object, slot)| (PinnedObjectId(*object), BTreeSet::from([*slot])))
            .collect();
        AttestedSubset::scripted(
            crate::plan::AttachPlan::from_slots(Vec::new()),
            crate::discovery::identity::PinnedObjects::empty(),
            required,
        )
    }

    #[test]
    fn subset_shape_accepts_exactly_one_required_object() {
        assert_eq!(validate_subset_shape(&scripted_subset(&[(3, 7)])), Ok(()));
    }

    #[test]
    fn subset_shape_refuses_empty_and_ambiguous_coverage() {
        assert_eq!(
            validate_subset_shape(&scripted_subset(&[])),
            Err(PromotionRefusal::ManifestUnavailable)
        );
        assert_eq!(
            validate_subset_shape(&scripted_subset(&[(3, 7), (5, 9)])),
            Err(PromotionRefusal::EndpointAmbiguous)
        );
    }

    /// A thread-exit lag: dropped at worker termination, after the
    /// outcome send. Models delivery preceding termination: the tick
    /// must reap the message without waiting out thread exit.
    struct ExitLag;
    impl Drop for ExitLag {
        fn drop(&mut self) {
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    #[test]
    fn poll_reaps_delivery_without_joining_a_live_worker() {
        thread_local! {
            static EXIT_LAG: std::cell::RefCell<Option<ExitLag>> =
                const { std::cell::RefCell::new(None) };
        }
        let (mut promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        service
            .start(request, capacity(), stub_source(None).0, || {
                EXIT_LAG.with(|slot| *slot.borrow_mut() = Some(ExitLag));
                PreparationOutcome::Failed(SelectedPreparationFailure::scripted_settled())
            })
            .expect("start runs");
        // No single poll waits out thread termination, even the one
        // that reaps the delivered outcome; the genuine terminal
        // status arrives from the detached delivery while the worker
        // still exits.
        let deadline = Instant::now() + Duration::from_secs(5);
        let event = loop {
            let tick = Instant::now();
            let mut sink = std::io::sink();
            if let Some(event) = service.poll(&mut sink) {
                break event;
            }
            assert!(
                tick.elapsed() < Duration::from_millis(100),
                "no single poll joins a live worker"
            );
            assert!(
                Instant::now() < deadline,
                "service emitted no event within the bound"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        let LifecycleEvent::Status(update) = event else {
            panic!("failed job must not install");
        };
        assert_eq!(
            promoter.set_status(update),
            Some(super::super::PromotionState::Refused(
                PromotionRefusal::PreparationFailed
            ))
        );
        assert!(service.is_idle());
    }

    #[test]
    fn dropped_service_retains_unproved_owner_for_process_exit() {
        let id = SelectedLifecycleService::next_custody_test_id_for_test();
        let (probe, weak) = liveness_probe();
        let (mut promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        service
            .start(request, capacity(), stub_source(None).0, move || {
                PreparationOutcome::Failed(
                    SelectedPreparationFailure::scripted_unproved_with_id(id)
                        .with_liveness_probe(probe),
                )
            })
            .expect("start runs");
        let event = poll_until(&mut service, Duration::from_secs(5)).expect("terminal event");
        let LifecycleEvent::Status(update) = event else {
            panic!("unproved job must not install");
        };
        assert_eq!(
            promoter.set_status(update),
            Some(super::super::PromotionState::Refused(
                PromotionRefusal::PreparationFailed
            ))
        );
        assert!(service.is_idle());
        drop(service);
        assert!(
            SelectedLifecycleService::custody_retained_ids_for_test().contains(&id),
            "this twin's unproved owner survives the service: {id}"
        );
        assert!(
            weak.upgrade().is_some(),
            "the destruction probe survives: the specific owner was retained, not just recorded"
        );
    }

    #[test]
    fn dropped_service_without_retention_destroys_unproved_owner() {
        // Negative control: retention disabled (recording still
        // runs), so the marker still records while the probe must
        // observe destruction. Passes only if the probe is sensitive
        // to the owner's actual fate.
        let id = SelectedLifecycleService::next_custody_test_id_for_test();
        let (probe, weak) = liveness_probe();
        let (mut promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        service
            .start(request, capacity(), stub_source(None).0, move || {
                PreparationOutcome::Failed(
                    SelectedPreparationFailure::scripted_unproved_with_id(id)
                        .with_liveness_probe(probe),
                )
            })
            .expect("start runs");
        let event = poll_until(&mut service, Duration::from_secs(5)).expect("terminal event");
        let LifecycleEvent::Status(update) = event else {
            panic!("unproved job must not install");
        };
        assert_eq!(
            promoter.set_status(update),
            Some(super::super::PromotionState::Refused(
                PromotionRefusal::PreparationFailed
            ))
        );
        assert!(service.is_idle());
        service.disable_retention_for_test();
        drop(service);
        assert!(
            SelectedLifecycleService::custody_retained_ids_for_test().contains(&id),
            "recording still runs with retention disabled: the marker alone cannot tell"
        );
        assert!(
            weak.upgrade().is_none(),
            "the probe dies: without retention the owner is destroyed"
        );
    }

    #[test]
    fn dropped_service_retains_queued_outcome_for_process_exit() {
        let outcome_id = SelectedLifecycleService::next_custody_test_id_for_test();
        let (probe, weak) = liveness_probe();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let (_promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        let sent_rx = service.observe_post_send_for_test();
        service
            .start(request, capacity(), stub_source(None).0, move || {
                let outcome = PreparationOutcome::Failed(
                    SelectedPreparationFailure::scripted_settled_with_id(outcome_id)
                        .with_liveness_probe(probe),
                );
                let _ = done_tx.send(());
                outcome
            })
            .expect("start runs");
        let channel_id = service
            .preparing_channel_id_for_test()
            .expect("preparing holds its channel");
        // Drop without polling: a delivered outcome is retained whole,
        // and a still-running worker's channel is retained so its late
        // send lands in custody. Either way this twin's own identity
        // survives; the drop itself never blocks and never joins.
        std::thread::sleep(Duration::from_millis(100));
        drop(service);
        let retained = SelectedLifecycleService::custody_retained_ids_for_test();
        assert!(
            retained.contains(&outcome_id) || retained.contains(&channel_id),
            "this twin's queued outcome ({outcome_id}) or its channel ({channel_id}) survives"
        );
        // The probe observes the specific outcome surviving — whether
        // retained directly (delivered) or through the retained
        // channel (late send). The job-done signal fires before the
        // wrapper's outcome send, so the twin also waits on the
        // post-send rendezvous: past it a descheduled worker no
        // longer owns the probe, and a broken retention would
        // already have settled and destroyed the outcome. No naked
        // sleep gates the survival check.
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the job builds its outcome");
        sent_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the wrapper's outcome send resolves");
        assert!(
            weak.upgrade().is_some(),
            "the destruction probe survives: the specific outcome was retained, not just recorded"
        );
    }

    #[test]
    fn dropped_service_without_retention_destroys_queued_outcome() {
        // Negative control: retention disabled (recording still
        // runs). A delivered outcome drops in teardown; a late send
        // fails into the settle-and-drop path. Either way the probe
        // must observe destruction.
        let outcome_id = SelectedLifecycleService::next_custody_test_id_for_test();
        let (probe, weak) = liveness_probe();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let (_promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        service
            .start(request, capacity(), stub_source(None).0, move || {
                let outcome = PreparationOutcome::Failed(
                    SelectedPreparationFailure::scripted_settled_with_id(outcome_id)
                        .with_liveness_probe(probe),
                );
                let _ = done_tx.send(());
                outcome
            })
            .expect("start runs");
        let channel_id = service
            .preparing_channel_id_for_test()
            .expect("preparing holds its channel");
        std::thread::sleep(Duration::from_millis(100));
        service.disable_retention_for_test();
        drop(service);
        let retained = SelectedLifecycleService::custody_retained_ids_for_test();
        assert!(
            retained.contains(&outcome_id) || retained.contains(&channel_id),
            "recording still runs with retention disabled: the marker alone cannot tell"
        );
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the job builds its outcome");
        assert!(
            wait_for_destruction(&weak, Duration::from_secs(5)),
            "the probe dies: without retention the queued outcome is destroyed"
        );
    }

    #[test]
    fn dropped_service_retains_live_worker_channel_for_process_exit() {
        let (probe, weak) = liveness_probe();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let (_promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        let sent_rx = service.observe_post_send_for_test();
        let (gate, release) = std::sync::mpsc::channel::<()>();
        service
            .start(request, capacity(), stub_source(None).0, move || {
                release.recv().expect("test releases the worker");
                let outcome = PreparationOutcome::Failed(
                    SelectedPreparationFailure::scripted_settled().with_liveness_probe(probe),
                );
                let _ = done_tx.send(());
                outcome
            })
            .expect("start runs");
        let channel_id = service
            .preparing_channel_id_for_test()
            .expect("preparing holds its channel");
        // Drop while the worker still runs: no delivery, no join, no
        // hang — this twin's own channel is retained for the late send.
        drop(service);
        assert!(
            SelectedLifecycleService::custody_retained_ids_for_test().contains(&channel_id),
            "this twin's live worker channel survives the service: {channel_id}"
        );
        // End-to-end channel liveness: the released worker's late
        // send must land in the retained channel instead of failing
        // into the settle-and-drop path. The probe rides the outcome
        // through the real channel — no marker. The job-done signal
        // fires before the wrapper's outcome send, so the twin waits
        // on the post-send rendezvous instead of a naked sleep: past
        // it a descheduled worker no longer owns the probe.
        gate.send(()).expect("the detached worker still exits");
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the worker builds its outcome");
        sent_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the wrapper's outcome send resolves");
        assert!(
            weak.upgrade().is_some(),
            "the late send lands in the retained channel: the outcome survives"
        );
    }

    #[test]
    fn dropped_service_without_retention_drops_late_send() {
        // Negative control: the channel drops with the service, so
        // the released worker's late send fails into the
        // settle-and-drop path and the probe must observe the
        // outcome's destruction.
        let (probe, weak) = liveness_probe();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let (_promoter, request) = taken_request_for_test();
        let mut service = SelectedLifecycleService::new();
        let (gate, release) = std::sync::mpsc::channel::<()>();
        service
            .start(request, capacity(), stub_source(None).0, move || {
                release.recv().expect("test releases the worker");
                let outcome = PreparationOutcome::Failed(
                    SelectedPreparationFailure::scripted_settled().with_liveness_probe(probe),
                );
                let _ = done_tx.send(());
                outcome
            })
            .expect("start runs");
        let channel_id = service
            .preparing_channel_id_for_test()
            .expect("preparing holds its channel");
        service.disable_retention_for_test();
        drop(service);
        assert!(
            SelectedLifecycleService::custody_retained_ids_for_test().contains(&channel_id),
            "recording still runs with retention disabled: the marker alone cannot tell"
        );
        gate.send(()).expect("the detached worker still exits");
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the worker builds its outcome");
        assert!(
            wait_for_destruction(&weak, Duration::from_secs(5)),
            "the probe dies: without retention the late send fails and the outcome is destroyed"
        );
    }

    #[test]
    fn quiet_service_polls_none_and_confirms_nothing() {
        let mut service = SelectedLifecycleService::new();
        assert!(service.is_idle());
        let mut sink = std::io::sink();
        assert!(service.poll(&mut sink).is_none());
        assert!(service.note_installed().is_none());
        service.note_cancel(PromotionEnd::Cancelled);
        assert!(service.poll(&mut sink).is_none());
    }
}
