//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private collect/audit/route/scan orchestration. This does not activate a
//! semantic reducer or alter physical counts (the later activation tasks).
#![cfg_attr(not(test), allow(dead_code))]

use crate::attach::Session;
use crate::attach::capture::{NativeDomainId, ReadWindow};
use crate::attach::image_query::{CompleteEpochs, ImageQueryRefusal, ImageScanProof};
use crate::discovery::identity::{PinnedObjectId, RetainedInventoryTarget};
use crate::discovery::instances::{
    CallFacts, EntryIp, InstanceId, InstanceRouter, MAX_INSTANCES, MAX_PENDING, ObserveOutcome,
    Route, RouterLimits, UnknownReason,
};
use crate::events::DecodedEventRecord;
use crate::process::PidPin;
use crate::semantics_objects::journal::joint_driver::{CollectedCallOrigin, H0Delivery};
use crate::semantics_objects::journal::{
    BirthKind, BootstrapReceipt, JournalAdapter, JournalBirthCut, JournalDomainProof,
};
use p11scope_ebpf_common::object_wire::ValidatedObjectCall;
use p11scope_ebpf_common::{EventRecord, ImageIdentity, event_type};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub(crate) object: PinnedObjectId,
    pub(crate) file_slot: u32,
    pub(crate) offset: u64,
}

/// Current registration authority is separate from historical Joined calls.
/// Only the synchronous accepted scan path may mint this move-only receipt.
pub(crate) struct CurrentPartitionReceipt {
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
    endpoint: Endpoint,
    attachment_slot: u32,
    watched: RetainedInventoryTarget,
    epochs: CompleteEpochs,
    fence: u64,
    deadline: Instant,
    ids: Vec<InstanceId>,
    birth: Option<(
        u64,
        JournalBirthCut,
        crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
    )>,
}
impl CurrentPartitionReceipt {
    /// Tests-only receipt: merge tests script receipt plumbing (order,
    /// bounds) that only the synchronous accepted scan path mints.
    /// Production construction stays move-only.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        image: ImageIdentity,
        pin: Arc<PidPin>,
        endpoint: Endpoint,
        attachment_slot: u32,
        watched: RetainedInventoryTarget,
        epochs: CompleteEpochs,
        fence: u64,
        deadline: Instant,
        ids: Vec<InstanceId>,
    ) -> Self {
        Self {
            domain,
            image,
            pin,
            endpoint,
            attachment_slot,
            watched,
            epochs,
            fence,
            deadline,
            ids,
            birth: None,
        }
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.image
    }
    pub(crate) fn endpoint(&self) -> Endpoint {
        self.endpoint
    }
    pub(crate) fn instances(&self) -> &[InstanceId] {
        &self.ids
    }
    pub(crate) fn original_pin(&self) -> &Arc<PidPin> {
        &self.pin
    }
    pub(crate) fn attachment_slot(&self) -> u32 {
        self.attachment_slot
    }
    /// The actual watched file retained by the accepted owner scan. This
    /// accessor transfers no construction or renewal authority.
    pub(crate) fn watched(&self) -> &RetainedInventoryTarget {
        &self.watched
    }
    /// Nested allocations owned by this receipt. Its inline holder and
    /// shared file/export Arcs are accounted for by their existing owners.
    pub(crate) fn owned_storage_bytes(&self) -> Option<usize> {
        let capacity = self.ids.capacity();
        capacity
            .checked_mul(std::mem::size_of::<InstanceId>())?
            .checked_add(if capacity == 0 {
                0
            } else {
                crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING
            })?
            .checked_add(self.watched.retained_copy_allocation_charge()?)
    }
    #[allow(clippy::result_large_err)] // Refusal returns the original receipt without allocating or discarding its custody.
    pub(crate) fn into_birth_candidate(mut self) -> Result<H0BirthCandidate, Self> {
        let Some((capture, cut, quantum)) = self.birth.take() else {
            return Err(self);
        };
        Ok(H0BirthCandidate {
            receipt: self,
            capture,
            cut,
            quantum,
        })
    }
}

/// Moves the existing bounded H0 receipt; no duplicate partition or queue.
pub(crate) struct H0BirthCandidate {
    receipt: CurrentPartitionReceipt,
    capture: u64,
    cut: JournalBirthCut,
    quantum: crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
}

pub(crate) struct CommittedAbsenceBirth {
    proof: crate::attach::image_query::ImageAbsenceProof,
    pin: Arc<PidPin>,
    watched: RetainedInventoryTarget,
    capture: u64,
    cut: JournalBirthCut,
}

/// One-shot authorization minted only after the original H0 candidate, its
/// admission and any required committed absence have been checked together.
/// Native freshness observations cannot construct this subject-bound value.
pub(crate) struct ValidatedH0Birth {
    proof: JournalDomainProof,
    birth: BirthKind,
    cut: JournalBirthCut,
    closure_generation: u64,
    evidence: crate::semantics_objects::journal::SessionBirthEvidence,
}
impl ValidatedH0Birth {
    pub(crate) fn into_parts(
        self,
    ) -> (
        JournalDomainProof,
        BirthKind,
        JournalBirthCut,
        u64,
        crate::semantics_objects::journal::SessionBirthEvidence,
    ) {
        (
            self.proof,
            self.birth,
            self.cut,
            self.closure_generation,
            self.evidence,
        )
    }
}

pub(crate) struct RetainedBirthWitness {
    candidate: H0BirthCandidate,
    admission: crate::attach::BirthAdmissionBinding,
    receipt: BootstrapReceipt,
}
impl RetainedBirthWitness {
    pub(crate) fn receipt(&self) -> &BootstrapReceipt {
        &self.receipt
    }

    fn validate_scope(
        &self,
        attachment: &crate::attach::AttachedSemanticSet,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    ) -> Result<(), crate::attach::BirthObservationRefusal> {
        if !Arc::ptr_eq(&binding.pin(), &self.candidate.receipt.pin) {
            return Err(crate::attach::BirthObservationRefusal::BindingMismatch);
        }
        if attachment.generation() != self.receipt.closure_generation() {
            return Err(crate::attach::BirthObservationRefusal::GenerationMismatch);
        }
        Ok(())
    }

    #[allow(dead_code)] // The later lane activation borrows this actual Session port.
    pub(crate) fn fresh_evidence(
        &self,
        session: &mut Session,
        capture: &SemanticCapture,
        attachment: &crate::attach::AttachedSemanticSet,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    ) -> Result<
        crate::semantics_objects::journal::SessionBirthEvidence,
        crate::attach::BirthObservationRefusal,
    > {
        self.validate_scope(attachment, binding)?;
        let deadline = Instant::now()
            .checked_add(capture.limits.scan_slice)
            .ok_or(crate::attach::BirthObservationRefusal::CurrentPartition)?;
        capture.validate_birth_candidate(
            &mut SessionIo {
                session,
                targets: &[],
            },
            &self.candidate,
            true,
        )?;
        let evidence = {
            let maps = session.instance_maps();
            let mut rows = crate::attach::LiveBirthRows::over(&maps, binding);
            crate::attach::observe_retained_birth(
                &mut rows,
                binding,
                attachment,
                &self.admission,
                self.receipt.birth(),
            )?
        };
        capture.validate_birth_candidate(
            &mut SessionIo {
                session,
                targets: &[],
            },
            &self.candidate,
            true,
        )?;
        if Instant::now() >= deadline {
            return Err(crate::attach::BirthObservationRefusal::CurrentPartition);
        }
        Ok(evidence)
    }

    #[cfg(test)]
    fn fresh_evidence_with(
        &self,
        io: &mut impl CaptureIo,
        rows: &mut impl crate::attach::BirthRowReader,
        capture: &SemanticCapture,
        attachment: &crate::attach::AttachedSemanticSet,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    ) -> Result<
        crate::semantics_objects::journal::SessionBirthEvidence,
        crate::attach::BirthObservationRefusal,
    > {
        self.validate_scope(attachment, binding)?;
        let deadline = Instant::now()
            .checked_add(capture.limits.scan_slice)
            .ok_or(crate::attach::BirthObservationRefusal::CurrentPartition)?;
        capture.validate_birth_candidate(io, &self.candidate, true)?;
        let evidence = crate::attach::observe_retained_birth(
            rows,
            binding,
            attachment,
            &self.admission,
            self.receipt.birth(),
        )?;
        capture.validate_birth_candidate(io, &self.candidate, true)?;
        if Instant::now() >= deadline {
            return Err(crate::attach::BirthObservationRefusal::CurrentPartition);
        }
        Ok(evidence)
    }
}

/// A seal borrows fresh Session I/O over the same retained witness each time.
#[allow(dead_code)] // Kept inactive until the controller accepts the authority foundation.
pub(crate) struct RetainedBirthSource<'a> {
    pub(crate) witness: &'a RetainedBirthWitness,
    pub(crate) session: &'a mut Session,
    pub(crate) capture: &'a SemanticCapture,
    pub(crate) attachment: &'a crate::attach::AttachedSemanticSet,
    pub(crate) binding:
        &'a crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
}
impl crate::semantics_objects::journal::BirthEvidenceSource for RetainedBirthSource<'_> {
    fn take_birth_evidence(
        &mut self,
    ) -> Result<
        crate::semantics_objects::journal::SessionBirthEvidence,
        crate::attach::BirthObservationRefusal,
    > {
        self.witness
            .fresh_evidence(self.session, self.capture, self.attachment, self.binding)
    }
}
impl fmt::Debug for CurrentPartitionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CurrentPartitionReceipt(<private>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CurrentReceiptRefusal {
    Domain,
    Custody,
    Attachment,
    Epoch,
    Partition,
    Deadline,
    Audit,
    Stopped,
}

/// I/O observations only. The capture owner applies all receipt decisions.
struct ReceiptState {
    image: ImageIdentity,
    epochs: CompleteEpochs,
    watched: RetainedInventoryTarget,
}

/// One latch belongs to one retained physical-authority episode, within the
/// coordinator's existing record budgets. H0 scans cannot reopen an episode.
struct PhysicalGapEpisode {
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
    applied: AtomicBool,
}

/// Task3's completed physical adjudicator alone gains the production factory.
/// A provisional scan marker or scalar caller fact cannot construct a gap.
/// This slice requires an already accepted H0 cookie-to-original-Arc binding;
/// handling a genuine gap before that first scan remains a Task3 prerequisite.
pub(crate) struct PhysicalSemanticGap {
    episode: Arc<PhysicalGapEpisode>,
}
impl fmt::Debug for PhysicalSemanticGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PhysicalSemanticGap(<private>)")
    }
}
impl PhysicalSemanticGap {
    /// Sole production factory: the coordinator's final physical
    /// adjudication mints one gap per proven genuine-loss episode from
    /// the binding's domain, image and stable custody Arc. Fields stay
    /// private, Debug stays redacted, and the episode starts unapplied;
    /// H0 re-checks custody, image and association at the cut. The finite
    /// loss cause travels with the finalizer's loss mapping, not here.
    pub(crate) fn adjudicated(
        domain: NativeDomainId,
        image: ImageIdentity,
        pin: Arc<PidPin>,
    ) -> Self {
        Self {
            episode: Arc::new(PhysicalGapEpisode {
                domain,
                image,
                pin,
                applied: AtomicBool::new(false),
            }),
        }
    }
    #[cfg(test)]
    fn test_episode(domain: NativeDomainId, image: ImageIdentity, pin: Arc<PidPin>) -> Self {
        Self {
            episode: Arc::new(PhysicalGapEpisode {
                domain,
                image,
                pin,
                applied: AtomicBool::new(false),
            }),
        }
    }
    #[cfg(test)]
    fn test_repeat(&self) -> Self {
        Self {
            episode: self.episode.clone(),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TickLimits {
    pub(crate) records: usize,
    pub(crate) scans: usize,
    pub(crate) terminal_reads: usize,
    pub(crate) bindings: usize,
    pub(crate) pending_for: Duration,
    pub(crate) scan_slice: Duration,
}
impl Default for TickLimits {
    fn default() -> Self {
        Self {
            records: MAX_PENDING,
            scans: 4,
            terminal_reads: 16,
            bindings: MAX_INSTANCES,
            pending_for: Duration::from_secs(2),
            scan_slice: Duration::from_millis(50),
        }
    }
}

/// Opaque result of the actual audited router; raw inputs never render.
/// Slice D carries the private validated object tail alongside the base
/// record through the same owned call; S1 keeps reading the base.
pub(crate) struct RoutedCall {
    domain: NativeDomainId,
    decoded: DecodedEventRecord,
    route: Route,
    endpoint: Option<Endpoint>,
    token: Option<u64>,
    collected_origin: Option<CollectedCallOrigin>,
}
impl RoutedCall {
    /// Tests-only call: finalizer and terminal tests script Joined calls
    /// with timeline tokens that only the audited router mints.
    /// Production construction stays move-only.
    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        decoded: DecodedEventRecord,
        route: Route,
        endpoint: Option<Endpoint>,
        token: Option<u64>,
    ) -> Self {
        Self {
            domain,
            decoded,
            route,
            endpoint,
            token,
            collected_origin: None,
        }
    }

    pub(crate) fn token(&self) -> Option<u64> {
        self.token
    }
    pub(crate) fn collected_origin(&self) -> Option<CollectedCallOrigin> {
        self.collected_origin
    }
    pub(crate) fn position(&self) -> Option<u64> {
        self.token
    }
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn record(&self) -> &EventRecord {
        &self.decoded.base
    }
    pub(crate) fn joint_resource(
        &self,
    ) -> Option<crate::semantics_objects::journal::joint_driver::JointResourceOrigin> {
        self.decoded
            .joint_resource
            .filter(|origin| origin.matches_native(self.domain))
    }
    /// Move-only tail handoff to the sole consuming runtime adapter
    /// (`CallEvidence::from_routed`): no borrower observes the tail.
    pub(crate) fn into_object_tail(self) -> Option<ValidatedObjectCall> {
        self.decoded.object
    }
    pub(crate) fn image(&self) -> ImageIdentity {
        self.decoded.base.event.image
    }
    pub(crate) fn route(&self) -> Route {
        self.route
    }
    pub(crate) fn endpoint(&self) -> Option<Endpoint> {
        self.endpoint
    }
}
impl fmt::Debug for RoutedCall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutedCall")
            .field("route", &self.route)
            .finish_non_exhaustive()
    }
}

/// Tests-only record: finalizer and terminal tests script Joined calls
/// with routing continuity that only the audited router mints. The helper
/// lives in the allowlisted router plumbing so non-allowed test fixtures
/// never name the private routing fields. Production construction stays
/// move-only.
#[cfg(test)]
pub(crate) fn event_record_with_routing(
    event: p11scope_ebpf_common::Event,
    stamp: p11scope_ebpf_common::InstanceStamp,
    ip: u64,
) -> EventRecord {
    EventRecord {
        event,
        continuity: p11scope_ebpf_common::InstanceContinuity {
            entry_stamp: stamp,
            return_stamp: stamp,
            entry_ip: ip,
        },
    }
}

pub(crate) enum InvalidationScope {
    CoverageFailed,
    AuthorityExhausted,
    FaultEra,
    ImageRetired(ImageIdentity),
    TaskRetired(u64),
    File {
        image: ImageIdentity,
        file_slot: u32,
    },
    InstancesRetired {
        image: ImageIdentity,
        file_slot: u32,
        ids: Vec<InstanceId>,
    },
    Stopped,
}
pub(crate) struct Invalidation {
    domain: NativeDomainId,
    scope: InvalidationScope,
    position: Option<u64>,
}
impl Invalidation {
    pub(crate) fn position(&self) -> Option<u64> {
        self.position
    }
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn scope(&self) -> &InvalidationScope {
        &self.scope
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        scope: InvalidationScope,
        position: Option<u64>,
    ) -> Self {
        Self {
            domain,
            scope,
            position,
        }
    }
}
impl fmt::Debug for Invalidation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match &self.scope {
            InvalidationScope::CoverageFailed => "Invalidation(CoverageFailed)",
            InvalidationScope::AuthorityExhausted => "Invalidation(AuthorityExhausted)",
            InvalidationScope::FaultEra => "Invalidation(FaultEra)",
            InvalidationScope::ImageRetired(_) => "Invalidation(ImageRetired)",
            InvalidationScope::TaskRetired(_) => "Invalidation(TaskRetired)",
            InvalidationScope::File { .. } => "Invalidation(File)",
            InvalidationScope::InstancesRetired { .. } => "Invalidation(InstancesRetired)",
            InvalidationScope::Stopped => "Invalidation(Stopped)",
        })
    }
}
pub(crate) struct OtherRecord {
    domain: NativeDomainId,
    record: EventRecord,
    position: Option<u64>,
}
impl OtherRecord {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn record(&self) -> &EventRecord {
        &self.record
    }
    pub(crate) fn position(&self) -> Option<u64> {
        self.position
    }
}
impl fmt::Debug for OtherRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtherRecord(<private>)")
    }
}
#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // H7 slice D: Call is the common outcome and carries the 240 B validated object tail inline; outcomes stay allocation-free per tick.
pub(crate) enum TickOutcome {
    Call(RoutedCall),
    Invalidation(Invalidation),
    Other(OtherRecord),
}
impl TickOutcome {
    /// Whether this outcome is an H0 invalidation (a negative):
    /// bounded stashes and merges shed positives first so loss
    /// boundaries survive overflow.
    pub(crate) fn is_invalidation(&self) -> bool {
        matches!(self, TickOutcome::Invalidation(_))
    }

    /// This outcome's H0 position, when the allocator issued one. A
    /// missing position means allocator exhaustion, never a gap the
    /// finalizer may skip.
    pub(crate) fn position(&self) -> Option<u64> {
        match self {
            TickOutcome::Call(call) => call.token(),
            TickOutcome::Invalidation(invalidation) => invalidation.position(),
            TickOutcome::Other(other) => other.position(),
        }
    }
}
#[derive(Default, Debug)]
pub(crate) struct TickReport {
    outcomes: Vec<TickOutcome>,
    current: Vec<CurrentPartitionReceipt>,
    pub(crate) collected_calls: usize,
    pub(crate) scans: usize,
    pub(crate) observations: Vec<ObserveOutcome>,
    pub(crate) scan_refusals: Vec<ImageQueryRefusal>,
    /// H3 disposition inputs (H8): every position below the watermark
    /// was allocated by this tick or earlier; the awaiting floor is the
    /// minimum route-waiting position; the shed floor is the minimum
    /// merge-shed position; exhaustion marks a dead allocator.
    allocated_below: u64,
    awaiting_floor: Option<u64>,
    shed_floor: Option<u64>,
    exhausted: bool,
}

/// Only this module constructs an owner from the nonrecycled Capture identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CollectedH0Owner(u64);

/// Move-only acknowledgement minted only after the real collected leaf ran
/// all H0 routing and stamped its actual allocation watermark. The retained
/// raw quantum checks the exact identity before applying any scalar.
pub(crate) struct CollectedH0Disposition {
    quantum: crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
    native: NativeDomainId,
    owner: CollectedH0Owner,
    allocated_below: u64,
    pending: bool,
}

impl CollectedH0Disposition {
    pub(crate) fn for_quantum(
        self,
        quantum: crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
        native: NativeDomainId,
    ) -> Option<(CollectedH0Owner, u64, bool)> {
        (self.quantum == quantum && self.native == native && self.allocated_below != 0).then_some((
            self.owner,
            self.allocated_below,
            self.pending,
        ))
    }
}

impl TickReport {
    /// Tests-only report: finalizer and terminal tests script batches
    /// that only the audited collect→audit→route path mints. Production
    /// construction stays move-only.
    #[cfg(test)]
    pub(crate) fn scripted(
        outcomes: Vec<TickOutcome>,
        current: Vec<CurrentPartitionReceipt>,
    ) -> Self {
        Self {
            outcomes,
            current,
            ..Self::default()
        }
    }

    /// Drain this report's current-partition receipts (refresh stashing).
    pub(crate) fn take_current(&mut self) -> Vec<CurrentPartitionReceipt> {
        std::mem::take(&mut self.current)
    }

    /// Drain this report's outcomes (refresh stashing preserves
    /// invalidations beside the receipts).
    pub(crate) fn take_outcomes(&mut self) -> Vec<TickOutcome> {
        std::mem::take(&mut self.outcomes)
    }

    /// Merge lane-stashed refresh receipts behind this tick's own: fresh
    /// receipts first, stashed appended, truncated to batch capacity so
    /// the merged batch never refuses on bounds. Returns shed receipts.
    pub(crate) fn merge_stashed_current(&mut self, stashed: Vec<CurrentPartitionReceipt>) -> u64 {
        self.current.extend(stashed);
        let shed = self.current.len().saturating_sub(MAX_INSTANCES);
        self.current.truncate(MAX_INSTANCES);
        debug_assert!(self.current.len() <= MAX_INSTANCES);
        shed as u64
    }

    /// Merge lane-stashed refresh outcomes behind this tick's own,
    /// truncated to batch capacity like the receipts. Returns shed
    /// outcomes. Truncation sheds positives first: a merged
    /// invalidation is H2's loss boundary, while a shed call is
    /// disclosed through the refusal count. Positions increase
    /// monotonically, so the oldest outcome still carries the minimum
    /// barrier when only invalidations remain. Sheds record their
    /// minimum position for H3 disposition; a shed outcome without a
    /// position records allocator exhaustion.
    pub(crate) fn merge_stashed_outcomes(&mut self, stashed: Vec<TickOutcome>) -> u64 {
        self.outcomes.extend(stashed);
        let mut shed = 0u64;
        while self.outcomes.len() > MAX_INSTANCES {
            let at = self
                .outcomes
                .iter()
                .position(|outcome| !outcome.is_invalidation())
                .unwrap_or(0);
            let dropped = self.outcomes.remove(at);
            match dropped.position() {
                Some(position) => {
                    self.shed_floor = Some(
                        self.shed_floor
                            .map_or(position, |floor| floor.min(position)),
                    );
                }
                None => self.exhausted = true,
            }
            shed += 1;
        }
        debug_assert!(self.outcomes.len() <= MAX_INSTANCES);
        shed
    }

    /// H3 disposition inputs for the finalizer: the allocation
    /// watermark, route-waiting floor, shed floor, and exhaustion.
    pub(crate) fn allocated_below(&self) -> u64 {
        self.allocated_below
    }
    pub(crate) fn awaiting_floor(&self) -> Option<u64> {
        self.awaiting_floor
    }
    pub(crate) fn shed_floor(&self) -> Option<u64> {
        self.shed_floor
    }
    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Absorb the lane stash's shed floor at merge time: shed positions
    /// from stash overflow join this batch's own merge sheds. The stash
    /// resets on handoff, so each shed reports exactly once.
    pub(crate) fn absorb_shed_floor(&mut self, floor: Option<u64>) {
        if let Some(floor) = floor {
            self.shed_floor = Some(self.shed_floor.map_or(floor, |at| at.min(floor)));
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted_with_disposition(
        outcomes: Vec<TickOutcome>,
        current: Vec<CurrentPartitionReceipt>,
        awaiting_floor: Option<u64>,
        shed_floor: Option<u64>,
        exhausted: bool,
    ) -> Self {
        Self {
            outcomes,
            current,
            awaiting_floor,
            shed_floor,
            exhausted,
            ..Self::default()
        }
    }

    pub(crate) fn into_outcomes(self) -> Vec<TickOutcome> {
        self.outcomes
    }
    pub(crate) fn outcomes(&self) -> &[TickOutcome] {
        &self.outcomes
    }
    pub(crate) fn current(&self) -> &[CurrentPartitionReceipt] {
        &self.current
    }
    pub(crate) fn into_parts(self) -> (Vec<TickOutcome>, Vec<CurrentPartitionReceipt>) {
        (self.outcomes, self.current)
    }
    pub(crate) fn calls(&self) -> impl Iterator<Item = &RoutedCall> {
        self.outcomes.iter().filter_map(|item| match item {
            TickOutcome::Call(call) => Some(call),
            _ => None,
        })
    }
}

#[derive(Clone, Copy)]
struct Health {
    fault: u64,
    sticky: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CollectionStatus {
    Complete,
    Malformed,
    ReadError,
}
struct Collection {
    records: Vec<DecodedEventRecord>,
    status: CollectionStatus,
}

struct ScanJob {
    image: ImageIdentity,
    endpoint: Endpoint,
    slot: u32,
    pin: Arc<PidPin>,
    deadline: Instant,
    birth_cut: Option<(
        JournalBirthCut,
        crate::semantics_objects::journal::joint_driver::RawQuantumIdentity,
    )>,
}
impl ScanJob {
    fn key(&self) -> (u64, u64, u32) {
        (
            self.image.task_cookie,
            self.image.exec_id,
            self.endpoint.file_slot,
        )
    }
}

/// Only I/O is substituted in tests; all decisions use the same tick below.
trait CaptureIo {
    fn domain(&self) -> Option<NativeDomainId>;
    fn now(&self) -> Instant;
    fn collect(&mut self, limit: usize) -> Collection;
    fn health(&mut self) -> Result<Health, ()>;
    fn raise_fault(&mut self) -> Result<u64, ()>;
    fn retained_attachment(
        &self,
        slot: u32,
    ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal>;
    fn receipt_state(
        &mut self,
        pin: &Arc<PidPin>,
        image: ImageIdentity,
        endpoint: Endpoint,
        slot: u32,
        deadline: Instant,
    ) -> Result<ReceiptState, CurrentReceiptRefusal>;
    fn endpoint(&self, slot: u32) -> Option<Endpoint>;
    fn target(&self, pid: u32) -> Option<Arc<PidPin>>;
    fn scan(
        &mut self,
        job: &ScanJob,
        deadline: Instant,
        fence: u64,
        current_fence: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal>;
    fn scan_selected(
        &mut self,
        pin: &Arc<PidPin>,
        endpoint: Endpoint,
        deadline: Instant,
        fence: u64,
        current_fence: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal>;
}

struct SessionIo<'a> {
    session: &'a mut Session,
    targets: &'a [Arc<PidPin>],
}
impl CaptureIo for SessionIo<'_> {
    fn domain(&self) -> Option<NativeDomainId> {
        self.session.native_domain()
    }
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn collect(&mut self, limit: usize) -> Collection {
        let Ok((drain, table)) = self.session.event_drain_with_object_table() else {
            return Collection {
                records: Vec::new(),
                status: CollectionStatus::ReadError,
            };
        };
        let malformed = drain.malformed();
        let mut records = Vec::with_capacity(limit);
        // Only the attested allowlisted lane decodes 608-byte records;
        // every other lane stays 368-byte-only through the same cursor.
        match table {
            Some(table) => {
                drain.poll_object_records(Some(limit), table, |record| {
                    records.push(record);
                    ControlFlow::Continue(())
                });
            }
            None => {
                drain.poll_records(Some(limit), |record| {
                    records.push(DecodedEventRecord {
                        joint_resource: None,
                        base: record,
                        object: None,
                    });
                    ControlFlow::Continue(())
                });
            }
        }
        let status = if drain.malformed() != malformed {
            CollectionStatus::Malformed
        } else {
            CollectionStatus::Complete
        };
        Collection { records, status }
    }
    fn health(&mut self) -> Result<Health, ()> {
        self.session.audit_image_continuity().map_err(|_| ())?;
        let maps = self.session.instance_maps();
        Ok(Health {
            fault: maps.fault().map_err(|_| ())?,
            sticky: maps.sticky().map_err(|_| ())?,
        })
    }
    fn raise_fault(&mut self) -> Result<u64, ()> {
        self.session.instance_maps().raise_fault().map_err(|_| ())
    }
    fn retained_attachment(
        &self,
        slot: u32,
    ) -> Result<RetainedInventoryTarget, CurrentReceiptRefusal> {
        self.session.semantic_receipt_target(slot)
    }
    fn receipt_state(
        &mut self,
        pin: &Arc<PidPin>,
        image: ImageIdentity,
        endpoint: Endpoint,
        slot: u32,
        deadline: Instant,
    ) -> Result<ReceiptState, CurrentReceiptRefusal> {
        let (image, epochs, watched) = self
            .session
            .semantic_receipt_state(pin, image, endpoint, slot, deadline)?;
        Ok(ReceiptState {
            image,
            epochs,
            watched,
        })
    }
    fn endpoint(&self, slot: u32) -> Option<Endpoint> {
        self.session.instance_endpoint(slot)
    }
    fn target(&self, pid: u32) -> Option<Arc<PidPin>> {
        self.targets.iter().find(|pin| pin.pid() == pid).cloned()
    }
    fn scan(
        &mut self,
        job: &ScanJob,
        deadline: Instant,
        fence: u64,
        current: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        let window = ReadWindow::new(16_384, deadline).map_err(|_| ImageQueryRefusal::Deadline)?;
        self.session
            .scan_image(&job.pin, job.endpoint.object, window, fence, current)
    }
    fn scan_selected(
        &mut self,
        pin: &Arc<PidPin>,
        endpoint: Endpoint,
        deadline: Instant,
        fence: u64,
        current: &dyn Fn() -> u64,
    ) -> Result<ImageScanProof, ImageQueryRefusal> {
        let window = ReadWindow::new(16_384, deadline).map_err(|_| ImageQueryRefusal::Deadline)?;
        self.session
            .scan_image(pin, endpoint.object, window, fence, current)
    }
}

struct Awaiting {
    record: DecodedEventRecord,
    endpoint: Option<Endpoint>,
    collected_origin: Option<CollectedCallOrigin>,
}

/// Only this owner's actual collection allocator constructs the position.
pub(crate) struct H0Allocation(u64);
impl H0Allocation {
    pub(crate) fn ordinal(self) -> u64 {
        self.0
    }
}
struct TaskBinding {
    domain: NativeDomainId,
    image: ImageIdentity,
    pin: Arc<PidPin>,
    current: bool,
}

/// Only a retained owning binding can mint this proof, and only after the
/// original pidfd itself becomes READY. Retain the Arc through deadbit commit.
pub(crate) struct TerminalTaskProof {
    domain: NativeDomainId,
    cookie: u64,
    _pin: Arc<PidPin>,
}
impl TerminalTaskProof {
    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }
    pub(crate) fn cookie(&self) -> u64 {
        self.cookie
    }
}

pub(crate) struct SemanticCapture {
    identity: u64,
    router: InstanceRouter,
    limits: TickLimits,
    next_token: u64,
    awaiting: BTreeMap<u64, Awaiting>,
    jobs: VecDeque<ScanJob>,
    bindings: BTreeMap<u64, TaskBinding>,
    terminal_cursor: u64,
    /// Fairness among tick-local Joined partitions when Pending scans leave
    /// fewer scan slots than the later calls need. This carries no authority.
    joined_refresh_cursor: Option<(u64, u64, u32)>,
    fault: u64,
    sticky: u64,
    image_failed: bool,
    exhausted: bool,
    stopped: bool,
    continuity_cuts: u64,
}

pub(crate) type PendingH3Original<'a> = (
    Option<u64>,
    Option<CollectedCallOrigin>,
    &'a EventRecord,
    Option<crate::semantics_objects::journal::joint_driver::JointResourceOrigin>,
);
static NEXT_SEMANTIC_CAPTURE: AtomicU64 = AtomicU64::new(0);
impl SemanticCapture {
    pub(crate) fn new(session: &Session, limits: TickLimits) -> anyhow::Result<Self> {
        let domain = session
            .native_domain()
            .ok_or_else(|| anyhow::anyhow!("native image domain unavailable"))?;
        Self::in_domain(domain, limits)
    }
    fn in_domain(domain: NativeDomainId, limits: TickLimits) -> anyhow::Result<Self> {
        anyhow::ensure!(
            limits.records > 0
                && limits.records <= MAX_PENDING
                && limits.scans > 0
                && limits.scans <= MAX_PENDING
                && limits.terminal_reads > 0
                && limits.terminal_reads <= MAX_INSTANCES
                && limits.bindings > 0
                && limits.bindings <= MAX_INSTANCES
                && !limits.pending_for.is_zero()
                && !limits.scan_slice.is_zero(),
            "invalid semantic work limits"
        );
        let identity = NEXT_SEMANTIC_CAPTURE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                last.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("semantic capture identity exhausted"))?
            + 1;
        Ok(Self {
            identity,
            router: InstanceRouter::new(domain, RouterLimits::default()),
            limits,
            next_token: 1,
            awaiting: BTreeMap::new(),
            jobs: VecDeque::new(),
            bindings: BTreeMap::new(),
            terminal_cursor: 0,
            joined_refresh_cursor: None,
            fault: 0,
            sticky: 0,
            image_failed: false,
            exhausted: false,
            stopped: false,
            continuity_cuts: 0,
        })
    }
    pub(crate) fn router(&self) -> &InstanceRouter {
        &self.router
    }
    pub(crate) fn continuity_cuts(&self) -> u64 {
        self.continuity_cuts
    }

    /// Acquire while the original H0 owner is idle, after the quiet prefix was
    /// ingested and before any later appearance. Both cursor snapshots must
    /// be empty; a BUSY reservation is not an absence boundary.
    #[allow(dead_code)] // The later lane activation calls this idle acquisition port.
    pub(crate) fn acquire_absence_birth(
        &mut self,
        session: &mut Session,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        attachment: &crate::attach::AttachedSemanticSet,
        slot: u32,
        adapter: &mut JournalAdapter,
    ) -> Result<CommittedAbsenceBirth, crate::attach::BirthObservationRefusal> {
        use crate::attach::BirthObservationRefusal as Refusal;
        if !self.awaiting.is_empty() || !self.jobs.is_empty() || self.stopped {
            return Err(Refusal::CurrentPartition);
        }
        let producers = session.drain_producers().ok_or(Refusal::StreamCut)?;
        let before = session
            .event_drain()
            .map_err(|_| Refusal::StreamCut)?
            .consumption_cut()
            .map_err(|_| Refusal::StreamCut)?;
        if !before.is_drained() {
            return Err(Refusal::StreamCut);
        }
        let endpoint = session
            .instance_endpoint(slot)
            .ok_or(Refusal::AttachmentMismatch)?;
        let pin = binding.pin();
        let deadline = Instant::now()
            .checked_add(self.limits.scan_slice)
            .ok_or(Refusal::CurrentPartition)?;
        let proof = session
            .prove_image_absence(
                &pin,
                endpoint.object,
                ReadWindow::new(16_384, deadline).map_err(|_| Refusal::CurrentPartition)?,
                self.router.fence(),
                || self.router.fence(),
            )
            .map_err(|_| Refusal::CurrentPartition)?;
        let after = session
            .event_drain()
            .map_err(|_| Refusal::StreamCut)?
            .consumption_cut()
            .map_err(|_| Refusal::StreamCut)?;
        self.commit_absence_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            proof,
            before,
            after,
            binding,
            attachment,
            slot,
            adapter,
            &producers,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_absence_with(
        &self,
        io: &mut impl CaptureIo,
        proof: crate::attach::image_query::ImageAbsenceProof,
        before: crate::events::EventsConsumptionCut,
        after: crate::events::EventsConsumptionCut,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        attachment: &crate::attach::AttachedSemanticSet,
        slot: u32,
        adapter: &mut JournalAdapter,
        producers: &crate::attach::SessionDrainProducers,
    ) -> Result<CommittedAbsenceBirth, crate::attach::BirthObservationRefusal> {
        use crate::attach::BirthObservationRefusal as Refusal;
        self.birth_health_with(io)?;
        if self.stopped
            || !self.awaiting.is_empty()
            || !self.jobs.is_empty()
            || io.domain() != Some(self.router.domain())
            || !binding.scope_current()
            || proof.domain() != self.router.domain()
            || proof.image() != binding.image()
            || attachment.domain() != self.router.domain()
            || proof.attach_generation() != attachment.generation()
            || proof.fence() != self.router.fence()
        {
            return Err(Refusal::CurrentPartition);
        }
        if proof.fence() != self.router.fence()
            || proof.epochs().fault != self.fault
            || proof.epochs().sticky != self.sticky
        {
            return Err(Refusal::NegativeFenceMismatch);
        }
        let endpoint = io.endpoint(slot).ok_or(Refusal::AttachmentMismatch)?;
        if proof.file_slot() != endpoint.file_slot {
            return Err(Refusal::AppearanceForeign);
        }
        let pin = binding.pin();
        if !self
            .bindings
            .get(&proof.image().task_cookie)
            .is_some_and(|retained| {
                retained.current
                    && retained.image == proof.image()
                    && Arc::ptr_eq(&retained.pin, &pin)
            })
            || !matches!(
                pin.original_generation_state(),
                Ok(crate::process::OriginalGenerationState::Current)
            )
        {
            return Err(Refusal::CustodyLost);
        }
        if !before.is_drained() || !after.is_drained() || !before.same_boundary(&after) {
            return Err(Refusal::StreamCut);
        }
        let cut = adapter
            .resolve_birth_cut(&after, producers)
            .map_err(|_| Refusal::StreamCut)?;
        if !adapter.quiet_sighting_at(proof.image(), &cut) {
            return Err(Refusal::AbsenceHistory);
        }
        let watched = io
            .retained_attachment(slot)
            .map_err(|_| Refusal::AttachmentMismatch)?;
        if watched.check_unchanged() != Ok(true) {
            return Err(Refusal::AttachmentMismatch);
        }
        Ok(CommittedAbsenceBirth {
            proof,
            pin,
            watched,
            capture: self.identity,
            cut,
        })
    }

    fn birth_health_with(
        &self,
        io: &mut impl CaptureIo,
    ) -> Result<(), crate::attach::BirthObservationRefusal> {
        use crate::attach::BirthObservationRefusal as Refusal;
        if self.stopped
            || self.exhausted
            || self.image_failed
            || io.domain() != Some(self.router.domain())
        {
            return Err(Refusal::CurrentPartition);
        }
        let health = io.health().map_err(|_| Refusal::CurrentPartition)?;
        if health.fault != self.fault || health.sticky != self.sticky || health.sticky != 0 {
            return Err(Refusal::CurrentPartition);
        }
        Ok(())
    }

    /// Read-only birth checks never run H0's mutating audit or consume pending
    /// originals. The next actual H0 tick publishes every negative/resolution.
    fn validate_birth_candidate(
        &self,
        io: &mut impl CaptureIo,
        candidate: &H0BirthCandidate,
        retained: bool,
    ) -> Result<(), crate::attach::BirthObservationRefusal> {
        use crate::attach::BirthObservationRefusal as Refusal;
        if candidate.capture != self.identity {
            return Err(Refusal::CurrentPartition);
        }
        self.birth_health_with(io)?;
        let receipt = &candidate.receipt;
        let binding = self
            .bindings
            .get(&receipt.image.task_cookie)
            .ok_or(Refusal::CustodyLost)?;
        if !binding.current
            || binding.domain != receipt.domain
            || binding.image != receipt.image
            || !Arc::ptr_eq(&binding.pin, &receipt.pin)
            || receipt.pin.pidfd().is_err()
        {
            return Err(Refusal::CustodyLost);
        }
        if !retained && io.now() >= receipt.deadline {
            return Err(Refusal::CurrentPartition);
        }
        if !self.receipt_partition_matches(receipt) {
            return Err(Refusal::CurrentPartition);
        }
        if io.endpoint(receipt.attachment_slot) != Some(receipt.endpoint) {
            return Err(Refusal::AttachmentMismatch);
        }
        let target = io
            .retained_attachment(receipt.attachment_slot)
            .map_err(|_| Refusal::AttachmentMismatch)?;
        if !Arc::ptr_eq(
            &target.retirement_lease(),
            &receipt.watched.retirement_lease(),
        ) || target.check_unchanged() != Ok(true)
            || receipt.watched.check_unchanged() != Ok(true)
        {
            return Err(Refusal::AttachmentMismatch);
        }
        let deadline = io
            .now()
            .checked_add(self.limits.scan_slice)
            .ok_or(Refusal::CurrentPartition)?;
        let deadline = if retained {
            deadline
        } else {
            deadline.min(receipt.deadline)
        };
        let state = io
            .receipt_state(
                &receipt.pin,
                receipt.image,
                receipt.endpoint,
                receipt.attachment_slot,
                deadline,
            )
            .map_err(|_| Refusal::CurrentPartition)?;
        self.birth_health_with(io)?;
        if io.now() >= deadline
            || state.image != receipt.image
            || state.epochs != receipt.epochs
            || !self.receipt_partition_matches(receipt)
        {
            return Err(Refusal::CurrentPartition);
        }
        if io.endpoint(receipt.attachment_slot) != Some(receipt.endpoint)
            || !Arc::ptr_eq(
                &state.watched.retirement_lease(),
                &receipt.watched.retirement_lease(),
            )
            || state.watched.check_unchanged() != Ok(true)
        {
            return Err(Refusal::AttachmentMismatch);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_birth(
        &self,
        mut candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        attachment: &crate::attach::AttachedSemanticSet,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
        rows: &mut impl crate::attach::BirthRowReader,
    ) -> Result<RetainedBirthWitness, crate::attach::BirthObservationRefusal> {
        use crate::attach::BirthObservationRefusal as Refusal;
        let (native, image, router, _) = admitted.journal_binding();
        if native != candidate.receipt.domain
            || image != candidate.receipt.image
            || !candidate.receipt.ids.contains(&router)
            || !proof.matches_admitted(admitted)
            || !admitted
                .collected_origin()
                .is_some_and(|origin| origin.in_quantum(candidate.quantum))
            || !Arc::ptr_eq(&binding.pin(), &candidate.receipt.pin)
        {
            return Err(Refusal::BindingMismatch);
        }
        let birth = if let Some(absence) = absence {
            if absence.capture != self.identity
                || !Arc::ptr_eq(&absence.pin, &candidate.receipt.pin)
                || !Arc::ptr_eq(
                    &absence.watched.retirement_lease(),
                    &candidate.receipt.watched.retirement_lease(),
                )
                || absence.proof.domain() != native
                || absence.proof.image().task_cookie != image.task_cookie
                || absence.proof.file_slot() != candidate.receipt.endpoint.file_slot
                || absence.proof.attach_generation() != attachment.generation()
            {
                return Err(Refusal::AppearanceForeign);
            }
            if absence.proof.fence() != self.router.fence()
                || candidate.receipt.fence != absence.proof.fence()
            {
                return Err(Refusal::NegativeFenceMismatch);
            }
            let before = absence.proof.epochs();
            let after = candidate.receipt.epochs;
            if after.local < before.local
                || after.global < before.global
                || (after.local == before.local && after.global == before.global)
                || after.fault != before.fault
            {
                return Err(Refusal::AppearanceNotAdvanced);
            }
            if !absence.cut.same_stream(&candidate.cut)
                || !adapter.quiet_sighting_at(image, &absence.cut)
            {
                return Err(Refusal::AbsenceHistory);
            }
            candidate.cut = absence.cut;
            BirthKind::AbsenceAppearance
        } else {
            BirthKind::ExecMarker
        };
        if !adapter.accepts_birth_cut(&candidate.cut) {
            return Err(Refusal::StreamCut);
        }
        let admission = crate::attach::BirthAdmissionBinding::from_admitted(admitted);
        let evidence =
            crate::attach::observe_retained_birth(rows, binding, attachment, &admission, birth)?;
        let authorization = ValidatedH0Birth {
            proof: *proof,
            birth,
            cut: candidate.cut.clone(),
            closure_generation: attachment.generation(),
            evidence,
        };
        let grant = crate::semantics_objects::journal::SessionBirthGrant::issue(authorization);
        let receipt =
            BootstrapReceipt::attest(adapter, &grant).map_err(|_| Refusal::AbsenceHistory)?;
        Ok(RetainedBirthWitness {
            candidate,
            admission,
            receipt,
        })
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)] // The later lane activation consumes this actual H0 handoff.
    pub(crate) fn consume_birth(
        &mut self,
        session: &mut Session,
        candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        attachment: &crate::attach::AttachedSemanticSet,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
    ) -> Result<RetainedBirthWitness, crate::attach::BirthObservationRefusal> {
        let deadline = Instant::now()
            .checked_add(self.limits.scan_slice)
            .ok_or(crate::attach::BirthObservationRefusal::CurrentPartition)?;
        self.validate_birth_candidate(
            &mut SessionIo {
                session,
                targets: &[],
            },
            &candidate,
            false,
        )?;
        let witness = {
            let maps = session.instance_maps();
            let mut rows = crate::attach::LiveBirthRows::over(&maps, binding);
            self.finish_birth(
                candidate, absence, admitted, binding, attachment, proof, adapter, &mut rows,
            )?
        };
        self.validate_birth_candidate(
            &mut SessionIo {
                session,
                targets: &[],
            },
            &witness.candidate,
            false,
        )?;
        if Instant::now() >= deadline {
            return Err(crate::attach::BirthObservationRefusal::CurrentPartition);
        }
        Ok(witness)
    }
    pub(crate) fn validate_current(
        &mut self,
        session: &mut Session,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal> {
        self.validate_current_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            receipt,
            report,
        )
    }
    fn validate_current_with(
        &mut self,
        io: &mut impl CaptureIo,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal> {
        use CurrentReceiptRefusal as Refusal;
        if io.domain() != Some(self.router.domain()) || receipt.domain != self.router.domain() {
            return Err(Refusal::Domain);
        }
        if self.stopped {
            return Err(Refusal::Stopped);
        }
        let binding = self
            .bindings
            .get(&receipt.image.task_cookie)
            .ok_or(Refusal::Custody)?;
        if !binding.current
            || binding.domain != receipt.domain
            || binding.image != receipt.image
            || !Arc::ptr_eq(&binding.pin, &receipt.pin)
            || receipt.pin.pidfd().is_err()
        {
            return Err(Refusal::Custody);
        }
        if io.now() >= receipt.deadline {
            return Err(Refusal::Deadline);
        }
        if io.endpoint(receipt.attachment_slot) != Some(receipt.endpoint) {
            return Err(Refusal::Attachment);
        }
        let target = io.retained_attachment(receipt.attachment_slot)?;
        if !Arc::ptr_eq(
            &target.retirement_lease(),
            &receipt.watched.retirement_lease(),
        ) || target.check_unchanged() != Ok(true)
            || receipt.watched.check_unchanged() != Ok(true)
        {
            return Err(Refusal::Attachment);
        }
        if !self.audit(io, report) {
            return Err(Refusal::Audit);
        }
        if !self.receipt_partition_matches(receipt) {
            return Err(Refusal::Partition);
        }
        let Some(slice_end) = io.now().checked_add(self.limits.scan_slice) else {
            self.exhaust(report);
            return Err(Refusal::Deadline);
        };
        let deadline = slice_end.min(receipt.deadline);
        let state = io.receipt_state(
            &receipt.pin,
            receipt.image,
            receipt.endpoint,
            receipt.attachment_slot,
            deadline,
        );
        if !self.audit(io, report) {
            return Err(Refusal::Audit);
        }
        // A failed native read is permanent even when the later audit itself
        // succeeded. Ordinary epoch/attachment refusals do not restamp proof.
        let state = match state {
            Err(Refusal::Audit) => {
                self.fail_coverage(io, report);
                return Err(Refusal::Audit);
            }
            result => result?,
        };
        if io.now() >= deadline {
            return Err(Refusal::Deadline);
        }
        if state.image != receipt.image || state.epochs != receipt.epochs {
            return Err(Refusal::Epoch);
        }
        if io.endpoint(receipt.attachment_slot) != Some(receipt.endpoint)
            || !Arc::ptr_eq(
                &state.watched.retirement_lease(),
                &receipt.watched.retirement_lease(),
            )
            || state.watched.check_unchanged() != Ok(true)
        {
            return Err(Refusal::Attachment);
        }
        if !self.receipt_partition_matches(receipt) {
            return Err(Refusal::Partition);
        }
        Ok(())
    }
    fn receipt_partition_matches(&self, receipt: &CurrentPartitionReceipt) -> bool {
        self.router.current_partition_matches(
            receipt.domain,
            receipt.image,
            receipt.endpoint.file_slot,
            receipt.epochs,
            receipt.fence,
            &receipt.ids,
        )
    }
    pub(crate) fn apply_physical_gaps(
        &mut self,
        session: &mut Session,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> anyhow::Result<TickReport> {
        self.apply_physical_gaps_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            gaps,
        )
    }

    /// Only the Capture that routed this actual collection may extend its
    /// H0 disposition. Native-domain equality alone does not bind an owner.
    pub(crate) fn validate_collected_preparation(
        &self,
        quantum: &crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> Result<(), crate::semantics_objects::journal::joint_driver::RawQuantumRefusal> {
        quantum.validate_h0_cut(CollectedH0Owner(self.identity))
    }

    pub(crate) fn apply_physical_gaps_collected(
        &mut self,
        session: &mut Session,
        gaps: Vec<PhysicalSemanticGap>,
        quantum: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> anyhow::Result<TickReport> {
        self.apply_physical_gaps_collected_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            gaps,
            quantum,
        )
    }

    fn apply_physical_gaps_collected_with(
        &mut self,
        io: &mut impl CaptureIo,
        gaps: Vec<PhysicalSemanticGap>,
        quantum: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> anyhow::Result<TickReport> {
        self.validate_collected_preparation(quantum)
            .map_err(|reason| anyhow::anyhow!("retained semantic cut owner: {reason:?}"))?;
        let mut report = self.apply_physical_gaps_with(io, gaps)?;
        // Even an already-applied or exhausted cut carries the real current
        // floors and allocator state. Do not manufacture a clean watermark.
        self.stamp_disposition(&mut report);
        self.note_collected_disposition(quantum, &report)?;
        Ok(report)
    }
    fn apply_physical_gaps_with(
        &mut self,
        io: &mut impl CaptureIo,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(
            io.domain() == Some(self.router.domain()),
            "foreign semantic Session"
        );
        anyhow::ensure!(
            !self.stopped && gaps.len() <= MAX_INSTANCES,
            "invalid physical gap publication"
        );
        // Validate the whole bounded publication before audit, CAS or state
        // mutation. Equal numeric PID or a duplicated fd is not this Arc.
        for gap in &gaps {
            let episode = &gap.episode;
            let binding = self
                .bindings
                .get(&episode.image.task_cookie)
                .ok_or_else(|| anyhow::anyhow!("physical gap custody unavailable"))?;
            anyhow::ensure!(
                episode.domain == self.router.domain()
                    && binding.domain == episode.domain
                    && Arc::ptr_eq(&episode.pin, &binding.pin)
                    && (episode.applied.load(Ordering::SeqCst) || binding.image == episode.image),
                "foreign physical gap authority"
            );
        }
        let mut report = TickReport::default();
        if gaps
            .iter()
            .all(|gap| gap.episode.applied.load(Ordering::SeqCst))
            || self.image_failed
            || self.exhausted
        {
            return Ok(report);
        }
        if !self.audit(io, &mut report) {
            return Ok(report);
        }
        let Some(cuts) = self.continuity_cuts.checked_add(1) else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        let Ok(raised) = io.raise_fault() else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        self.continuity_cuts = cuts; // Count actual successful userspace advances.
        let Ok(health) = io.health() else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        if raised <= self.fault
            || raised > u64::from(u32::MAX)
            || health.fault < raised
            || health.fault > u64::from(u32::MAX)
            || health.sticky != 0
        {
            self.exhaust(&mut report);
            return Ok(report);
        }
        // This shared audited path clears old observations, resolves old
        // pending calls and allocates one position after all issued records.
        if !self.audit_health(health, &mut report) {
            return Ok(report);
        }
        for gap in gaps {
            gap.episode.applied.store(true, Ordering::SeqCst);
        }
        Ok(report)
    }
    pub(crate) fn tick(
        &mut self,
        session: &mut Session,
        targets: &[Arc<PidPin>],
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(targets.len() <= MAX_PENDING, "semantic target capacity");
        self.tick_with(&mut SessionIo { session, targets })
    }
    /// One bounded no-call refresh through the same owned Session, endpoint
    /// and original pin. The freshly selected image comes only from the seal.
    pub(crate) fn refresh(
        &mut self,
        session: &mut Session,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> anyhow::Result<TickReport> {
        self.refresh_with(
            &mut SessionIo {
                session,
                targets: &[],
            },
            pin,
            slot,
        )
    }
    fn refresh_with(
        &mut self,
        io: &mut impl CaptureIo,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> anyhow::Result<TickReport> {
        let mut report = self.refresh_with_inner(io, pin, slot)?;
        self.stamp_disposition(&mut report);
        Ok(report)
    }

    /// Stamp one tick's H3 disposition inputs: the allocation watermark
    /// (every position below it was minted by this tick or earlier),
    /// the route-waiting floor, and allocator exhaustion. The finalizer
    /// carries these into disposition evidence.
    fn stamp_disposition(&self, report: &mut TickReport) {
        report.allocated_below = self.next_token;
        report.awaiting_floor = self.awaiting.keys().next().copied();
        report.exhausted = report.exhausted || self.exhausted;
    }

    pub(crate) fn pending_h3_watermark(&self) -> Option<(u64, Option<u64>, u64)> {
        (!self.stopped && !self.image_failed && !self.exhausted && self.sticky == 0).then_some((
            self.next_token,
            self.awaiting.keys().next().copied(),
            self.fault,
        ))
    }

    /// Borrow the original pending records; no copied queue or manufactured
    /// allocation accompanies the lane's continuation inspection.
    pub(crate) fn pending_h3_originals(&self) -> impl Iterator<Item = PendingH3Original<'_>> {
        self.awaiting.iter().map(|(position, waiting)| {
            (
                Some(*position),
                waiting.collected_origin,
                &waiting.record.base,
                waiting.record.joint_resource,
            )
        })
    }

    fn refresh_with_inner(
        &mut self,
        io: &mut impl CaptureIo,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(
            io.domain() == Some(self.router.domain()),
            "foreign semantic Session"
        );
        anyhow::ensure!(!self.stopped, "semantic capture stopped");
        let mut report = TickReport::default();
        if !self.audit(io, &mut report) {
            return Ok(report);
        }
        let Some(endpoint) = io.endpoint(slot) else {
            report.scan_refusals.push(ImageQueryRefusal::Coverage);
            return Ok(report);
        };
        // The scan I/O window stays one slice (as in the tick path's
        // attempt deadline), while the minted proof stays provable for
        // the full pending window: a quiet provider's refresh receipt
        // waits the normal pass interval for the next tick batch, and a
        // 50ms receipt deadline would expire it first. Validation still
        // re-proves custody, attachment, epochs and partition live.
        let Some(scan_deadline) = io.now().checked_add(self.limits.scan_slice) else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        let Some(proof_deadline) = io.now().checked_add(self.limits.pending_for) else {
            self.exhaust(&mut report);
            return Ok(report);
        };
        let fence = self.router.fence();
        report.scans = 1;
        let result = io.scan_selected(&pin, endpoint, scan_deadline, fence, &|| {
            self.router.fence()
        });
        let healthy = self.audit(io, &mut report);
        if io.now() >= scan_deadline {
            report.scan_refusals.push(ImageQueryRefusal::Deadline);
        } else if healthy {
            match result {
                Ok(proof) => {
                    // Retry custody: when an earlier accepted refresh
                    // retained an Arc for this task and the bind then
                    // failed, the retry offers a fresh duplicate. Adopt
                    // H0's retained Arc instead so the retry reuses the
                    // same custody; `accept_scan` still gates domain,
                    // exec monotonicity and currency afterwards.
                    let pin = self
                        .bindings
                        .get(&proof.image().task_cookie)
                        .map(|binding| binding.pin.clone())
                        .unwrap_or(pin);
                    let job = ScanJob {
                        image: proof.image(),
                        endpoint,
                        slot,
                        pin,
                        deadline: proof_deadline,
                        birth_cut: None,
                    };
                    self.accept_scan(io, proof, &job, fence, &mut report);
                }
                Err(refusal) => report.scan_refusals.push(refusal),
            }
        }
        Ok(report)
    }
    fn emit(
        &self,
        token: Option<u64>,
        record: DecodedEventRecord,
        endpoint: Option<Endpoint>,
        route: Route,
        collected_origin: Option<CollectedCallOrigin>,
        report: &mut TickReport,
    ) {
        report.outcomes.push(TickOutcome::Call(RoutedCall {
            domain: self.router.domain(),
            decoded: record,
            route,
            endpoint,
            token,
            collected_origin,
        }));
    }
    fn allocate_position(&mut self) -> Option<u64> {
        if self.exhausted {
            return None;
        }
        let next = self
            .next_token
            .checked_add(1)
            .filter(|_| self.next_token != 0)?;
        let position = self.next_token;
        self.next_token = next;
        Some(position)
    }
    fn invalidate(&mut self, scope: InvalidationScope, report: &mut TickReport) {
        let position = self.allocate_position();
        report
            .outcomes
            .push(TickOutcome::Invalidation(Invalidation {
                domain: self.router.domain(),
                scope,
                position,
            }));
        if position.is_none() && !self.exhausted {
            self.exhaust(report);
        }
    }
    fn resolve(&mut self, outcomes: Vec<(u64, Route)>, report: &mut TickReport) {
        for (token, route) in outcomes {
            if let Some(waiting) = self.awaiting.remove(&token) {
                self.emit(
                    Some(token),
                    waiting.record,
                    waiting.endpoint,
                    route,
                    waiting.collected_origin,
                    report,
                );
            }
        }
    }
    fn fail_coverage(&mut self, io: &mut impl CaptureIo, report: &mut TickReport) {
        if !self.image_failed {
            self.image_failed = true;
            self.invalidate(InvalidationScope::CoverageFailed, report);
            // Permanent router failure does not depend on this ordinary raise.
            let _ = io.raise_fault();
        }
        let resolved = self.router.fail_image_coverage();
        self.resolve(resolved, report);
        self.jobs.clear();
    }
    fn exhaust(&mut self, report: &mut TickReport) {
        if !self.exhausted {
            let position = self.allocate_position();
            self.exhausted = true;
            report
                .outcomes
                .push(TickOutcome::Invalidation(Invalidation {
                    domain: self.router.domain(),
                    scope: InvalidationScope::AuthorityExhausted,
                    position,
                }));
        }
        let resolved = self.router.refuse_exhaustion();
        self.resolve(resolved, report);
        self.jobs.clear();
    }
    fn audit(&mut self, io: &mut impl CaptureIo, report: &mut TickReport) -> bool {
        let Ok(health) = io.health() else {
            self.fail_coverage(io, report);
            return false;
        };
        self.audit_health(health, report)
    }
    fn audit_health(&mut self, health: Health, report: &mut TickReport) -> bool {
        if health.fault > u64::from(u32::MAX) || health.fault < self.fault {
            self.exhaust(report);
            return false;
        }
        if health.fault != self.fault || health.sticky != self.sticky {
            self.invalidate(InvalidationScope::FaultEra, report);
            self.fault = health.fault;
            self.sticky = health.sticky;
        }
        let resolved = self.router.audit(health.fault, health.sticky, 0);
        self.resolve(resolved, report);
        self.prune_jobs();
        !self.image_failed && !self.exhausted && health.sticky == 0
    }
    fn pending_key(waiting: &Awaiting) -> (u64, u64, u32) {
        let image = waiting.record.base.event.image;
        (
            image.task_cookie,
            image.exec_id,
            u32::from(waiting.record.base.continuity.entry_stamp.file_slot_plus1).saturating_sub(1),
        )
    }
    fn prune_jobs(&mut self) {
        let keys: std::collections::BTreeSet<_> =
            self.awaiting.values().map(Self::pending_key).collect();
        self.jobs.retain(|job| keys.contains(&job.key()));
    }
    fn expire(&mut self, image: ImageIdentity, report: &mut TickReport) {
        let resolved = self.router.expire_image(image);
        self.resolve(resolved, report);
    }

    fn refuse_binding(&mut self, image: ImageIdentity, report: &mut TickReport) {
        let resolved = self.router.refuse_image_pending(
            self.router.domain(),
            image,
            UnknownReason::BindingCapacity,
        );
        self.resolve(resolved, report);
        self.prune_jobs();
    }

    fn terminal_tasks(&mut self, report: &mut TickReport) {
        // Cursor advances for errors and nonready pins too; one READY pin
        // with aliases still spends one work unit per cookie association.
        let mut keys: Vec<_> = self
            .bindings
            .range((
                std::ops::Bound::Excluded(self.terminal_cursor),
                std::ops::Bound::Unbounded,
            ))
            .map(|(&cookie, _)| cookie)
            .take(self.limits.terminal_reads)
            .collect();
        if keys.len() < self.limits.terminal_reads {
            keys.extend(
                self.bindings
                    .range(..=self.terminal_cursor)
                    .map(|(&cookie, _)| cookie)
                    .take(self.limits.terminal_reads - keys.len()),
            );
        }
        for cookie in keys {
            self.terminal_cursor = cookie;
            let binding = &self.bindings[&cookie];
            if binding.domain != self.router.domain()
                || binding.pin.pidfd().is_err()
                || !matches!(binding.pin.wait_ready(Some(Duration::ZERO)), Ok(true))
            {
                continue;
            }
            let proof = TerminalTaskProof {
                domain: binding.domain,
                cookie,
                _pin: binding.pin.clone(),
            };
            if let Some(resolved) = self.router.retire_task(proof) {
                self.invalidate(InvalidationScope::TaskRetired(cookie), report);
                self.resolve(resolved, report);
                self.bindings.remove(&cookie); // deadbit committed before pin release
            }
        }
        self.prune_jobs();
    }

    fn accept_scan(
        &mut self,
        io: &mut impl CaptureIo,
        proof: ImageScanProof,
        job: &ScanJob,
        fence: u64,
        report: &mut TickReport,
    ) {
        // Production calls this immediately after the fresh synchronous scan
        // and its postscan audit. No deferred seal queue can roll bindings back.
        if proof.domain() != self.router.domain()
            || proof.image() != job.image
            || proof.file_slot() != job.endpoint.file_slot
            || proof.fence() != fence
            || fence != self.router.fence()
        {
            report.scan_refusals.push(ImageQueryRefusal::Fence);
            return;
        }
        if io.endpoint(job.slot) != Some(job.endpoint) {
            report.scan_refusals.push(ImageQueryRefusal::Custody);
            return;
        }
        if let Some(existing) = self.bindings.get(&job.image.task_cookie) {
            if existing.domain != self.router.domain()
                || !Arc::ptr_eq(&existing.pin, &job.pin)
                || job.image.exec_id < existing.image.exec_id
                || !existing.current
            {
                report.scan_refusals.push(ImageQueryRefusal::Custody);
                return;
            }
        } else if self.bindings.len() >= self.limits.bindings {
            self.refuse_binding(job.image, report);
            return;
        }
        let prior_ids =
            self.router
                .current_instances(self.router.domain(), job.image, job.endpoint.file_slot);
        let epochs = proof.epochs();
        let watched = io.retained_attachment(job.slot).ok();
        let (outcome, resolved) = self.router.observe(proof);
        let accepted = matches!(outcome, ObserveOutcome::New | ObserveOutcome::Continued);
        // These losses come from the actual eviction, not a counter inference.
        for loss in self.router.take_observation_losses() {
            self.invalidate(
                InvalidationScope::InstancesRetired {
                    image: loss.image,
                    file_slot: loss.file_slot,
                    ids: loss.ids,
                },
                report,
            );
        }
        if outcome == ObserveOutcome::New && !prior_ids.is_empty() {
            self.invalidate(
                InvalidationScope::InstancesRetired {
                    image: job.image,
                    file_slot: job.endpoint.file_slot,
                    ids: prior_ids,
                },
                report,
            );
        }
        if outcome == ObserveOutcome::CoverageFault {
            self.invalidate(
                InvalidationScope::File {
                    image: job.image,
                    file_slot: job.endpoint.file_slot,
                },
                report,
            );
        }
        if accepted && !self.exhausted {
            let prior: Vec<_> = self
                .bindings
                .values()
                .filter(|binding| {
                    binding.current
                        && binding.image != job.image
                        && Arc::ptr_eq(&binding.pin, &job.pin)
                })
                .map(|binding| binding.image)
                .collect();
            for image in prior {
                self.bindings
                    .get_mut(&image.task_cookie)
                    .expect("retained binding")
                    .current = false;
                let retired = self.router.retire_image(image);
                self.invalidate(InvalidationScope::ImageRetired(image), report);
                self.resolve(retired, report);
            }
            self.bindings.insert(
                job.image.task_cookie,
                TaskBinding {
                    domain: self.router.domain(),
                    image: job.image,
                    pin: job.pin.clone(),
                    current: true,
                },
            );
            let ids = self.router.current_instances(
                self.router.domain(),
                job.image,
                job.endpoint.file_slot,
            );
            if self.router.current_partition_matches(
                self.router.domain(),
                job.image,
                job.endpoint.file_slot,
                epochs,
                fence,
                &ids,
            ) && let Some(watched) = watched
                && watched.check_unchanged() == Ok(true)
            {
                report.current.push(CurrentPartitionReceipt {
                    domain: self.router.domain(),
                    image: job.image,
                    pin: job.pin.clone(),
                    endpoint: job.endpoint,
                    attachment_slot: job.slot,
                    watched,
                    epochs,
                    fence,
                    deadline: job.deadline,
                    ids,
                    birth: if outcome == ObserveOutcome::New {
                        job.birth_cut
                            .clone()
                            .map(|(cut, quantum)| (self.identity, cut, quantum))
                    } else {
                        None
                    },
                });
            }
        }
        report.observations.push(outcome);
        // Invalidation exhaustion cannot leak a previously computed join.
        if self.exhausted {
            self.resolve(
                resolved
                    .into_iter()
                    .map(|(token, _)| (token, Route::Unknown(UnknownReason::AuthorityExhausted)))
                    .collect(),
                report,
            );
        } else {
            self.resolve(resolved, report);
        }
    }
    fn tick_with(&mut self, io: &mut impl CaptureIo) -> anyhow::Result<TickReport> {
        let mut report = self.tick_with_inner(io, None)?;
        self.stamp_disposition(&mut report);
        Ok(report)
    }

    fn tick_collected_with(
        &mut self,
        io: &mut impl CaptureIo,
        quantum: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(
            io.domain() == Some(self.router.domain()),
            "foreign semantic Session"
        );
        anyhow::ensure!(!self.stopped, "semantic capture stopped");
        quantum
            .h0_input(self.router.domain(), self.limits.records)
            .map_err(|reason| anyhow::anyhow!("retained semantic collection: {reason:?}"))?;
        // Pin before routing, including a tick that later refuses. A second
        // Capture must not consume an original after a partial first tick.
        quantum
            .pin_h0_owner(CollectedH0Owner(self.identity))
            .map_err(|reason| anyhow::anyhow!("retained semantic owner: {reason:?}"))?;
        let delivery = quantum
            .h0_delivery(self.router.domain(), self.limits.records)
            .map_err(|reason| anyhow::anyhow!("retained semantic collection: {reason:?}"))?;
        let mut report = self.tick_with_inner(io, Some(delivery))?;
        self.stamp_disposition(&mut report);
        self.note_collected_disposition(quantum, &report)?;
        Ok(report)
    }

    fn note_collected_disposition(
        &self,
        quantum: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
        report: &TickReport,
    ) -> anyhow::Result<()> {
        quantum
            .note_h0_report(CollectedH0Disposition {
                quantum: quantum.h0_identity(),
                native: self.router.domain(),
                owner: CollectedH0Owner(self.identity),
                allocated_below: report.allocated_below(),
                pending: report.awaiting_floor().is_some(),
            })
            .map_err(|reason| anyhow::anyhow!("retained semantic disposition: {reason:?}"))?;
        Ok(())
    }

    #[allow(dead_code)] // Thin Session wrapper; ordinary lane selection remains inactive.
    pub(crate) fn tick_collected(
        &mut self,
        session: &mut Session,
        targets: &[Arc<PidPin>],
        quantum: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(targets.len() <= MAX_PENDING, "semantic target capacity");
        self.tick_collected_with(&mut SessionIo { session, targets }, quantum)
    }

    fn tick_with_inner(
        &mut self,
        io: &mut impl CaptureIo,
        collected: Option<H0Delivery<'_>>,
    ) -> anyhow::Result<TickReport> {
        anyhow::ensure!(
            io.domain() == Some(self.router.domain()),
            "foreign semantic Session"
        );
        anyhow::ensure!(!self.stopped, "semantic capture stopped");
        let mut report = TickReport::default();
        let owned;
        let (records, status, mut positions, birth_cut) = match collected {
            Some(input) => (
                input.records,
                if input.failed {
                    CollectionStatus::ReadError
                } else {
                    CollectionStatus::Complete
                },
                Some(input.positions),
                input.birth_cut.map(|cut| (cut, input.quantum)),
            ),
            None => {
                owned = io.collect(self.limits.records);
                (owned.records.as_slice(), owned.status, None, None)
            }
        };
        let collection_failed =
            status != CollectionStatus::Complete || records.len() > self.limits.records;
        // Positions belong to first collection, including noncalls. Pending
        // resolutions retain them; delivery order is deliberately not FIFO.
        let batch: Vec<_> = records
            .iter()
            .take(self.limits.records)
            .copied()
            .enumerate()
            .map(|(index, record)| {
                let position = self.allocate_position();
                if position.is_none() {
                    self.exhaust(&mut report);
                }
                let origin = position.and_then(|position| {
                    positions
                        .as_mut()
                        .map(|positions| positions.allocate(index, H0Allocation(position)))
                });
                (position, record, origin)
            })
            .collect();
        // Joined calls already have a route, but later publications need a
        // fresh owner proof. These interests are bounded by this collection
        // and never enter the Pending queue or renew its original deadlines.
        let mut joined_interests = BTreeMap::new();
        // A malformed/read-error prefix still contains genuine consumed
        // records. Keep their positions, then forbid every positive route.
        if collection_failed {
            self.fail_coverage(io, &mut report);
        }
        // Collection never routes; every batch (including empty batches) audits.
        let _ = self.audit(io, &mut report);
        self.terminal_tasks(&mut report);
        for (position, record, origin) in batch {
            if record.base.event.event_type != event_type::CALL {
                report.outcomes.push(TickOutcome::Other(OtherRecord {
                    domain: self.router.domain(),
                    record: record.base,
                    position,
                }));
                continue;
            }
            report.collected_calls += 1;
            let endpoint = io.endpoint(record.base.event.slot);
            let Some(token) = position else {
                self.emit(
                    None,
                    record,
                    endpoint,
                    Route::Unknown(UnknownReason::AuthorityExhausted),
                    origin,
                    &mut report,
                );
                continue;
            };
            if endpoint.is_none_or(|ep| {
                u32::from(record.base.continuity.entry_stamp.file_slot_plus1) != ep.file_slot + 1
            }) {
                self.emit(
                    Some(token),
                    record,
                    endpoint,
                    Route::Unknown(UnknownReason::NoFile),
                    origin,
                    &mut report,
                );
                continue;
            }
            let facts = CallFacts {
                token,
                domain: self.router.domain(),
                image: record.base.event.image,
                entry: record.base.continuity.entry_stamp,
                ret: record.base.continuity.return_stamp,
                ip: EntryIp::new(record.base.continuity.entry_ip),
                attached_offset: endpoint.map(|e| e.offset),
            };
            let route = self.router.route(facts);
            if route != Route::Pending {
                if matches!(route, Route::Joined(_)) {
                    let endpoint = endpoint.expect("checked owned endpoint");
                    let image = record.base.event.image;
                    let key = (image.task_cookie, image.exec_id, endpoint.file_slot);
                    joined_interests.entry(key).or_insert((
                        image,
                        endpoint,
                        record.base.event.slot,
                        (record.base.event.pid_tgid >> 32) as u32,
                    ));
                }
                self.emit(Some(token), record, endpoint, route, origin, &mut report);
                continue;
            }
            self.awaiting.insert(
                token,
                Awaiting {
                    record,
                    endpoint,
                    collected_origin: origin,
                },
            );
            let image = record.base.event.image;
            if !self.bindings.contains_key(&image.task_cookie)
                && self.bindings.len() >= self.limits.bindings
            {
                self.refuse_binding(image, &mut report);
                continue;
            }
            let Some(pin) = io.target((record.base.event.pid_tgid >> 32) as u32) else {
                self.expire(image, &mut report);
                continue;
            };
            let endpoint = endpoint.expect("checked owned endpoint");
            let key = (image.task_cookie, image.exec_id, endpoint.file_slot);
            if !self.jobs.iter().any(|job| job.key() == key) {
                let Some(deadline) = io.now().checked_add(self.limits.pending_for) else {
                    self.exhaust(&mut report);
                    continue;
                };
                self.jobs.push_back(ScanJob {
                    image,
                    endpoint,
                    slot: record.base.event.slot,
                    pin,
                    deadline,
                    birth_cut: birth_cut.clone(),
                });
            }
        }
        self.prune_jobs();
        let expired: Vec<_> = self
            .jobs
            .iter()
            .filter(|job| io.now() >= job.deadline)
            .map(|job| job.image)
            .collect();
        for image in expired {
            self.expire(image, &mut report);
        }
        self.prune_jobs();
        // Visit each initial queued job at most once. Refused peers rotate.
        let attempts = self.limits.scans.min(self.jobs.len());
        let mut attempted_keys = BTreeSet::new();
        for _ in 0..attempts {
            let Some(job) = self.jobs.pop_front() else {
                break;
            };
            if io.now() >= job.deadline {
                self.expire(job.image, &mut report);
                continue;
            }
            report.scans += 1;
            attempted_keys.insert(job.key());
            let fence = self.router.fence();
            let Some(slice_end) = io.now().checked_add(self.limits.scan_slice) else {
                self.exhaust(&mut report);
                break;
            };
            let attempt_deadline = slice_end.min(job.deadline);
            let result = io.scan(&job, attempt_deadline, fence, &|| self.router.fence());
            let healthy = self.audit(io, &mut report);
            if io.now() >= job.deadline {
                self.expire(job.image, &mut report);
            } else if healthy && io.now() < attempt_deadline {
                match result {
                    Ok(proof) => {
                        self.accept_scan(io, proof, &job, fence, &mut report);
                    }
                    Err(refusal) => report.scan_refusals.push(refusal),
                }
            }
            if self
                .awaiting
                .values()
                .any(|waiting| Self::pending_key(waiting) == job.key())
            {
                self.jobs.push_back(job);
            }
        }
        // Pending keeps its existing queue, deadlines, and first claim on
        // the shared scan cap. Sweep only this tick's Joined interests in a
        // separate cyclic order; a refusal advances the cursor as well.
        let mut joined_keys: Vec<_> = joined_interests
            .keys()
            .filter(|key| !attempted_keys.contains(*key))
            .copied()
            .collect();
        let split = self.joined_refresh_cursor.map_or(0, |cursor| {
            joined_keys.partition_point(|key| *key <= cursor)
        });
        joined_keys.rotate_left(split);
        for key in joined_keys {
            if report.scans >= self.limits.scans
                || self.image_failed
                || self.exhausted
                || self.sticky != 0
            {
                break;
            }
            let (image, endpoint, slot, pid) = joined_interests[&key];
            let Some(pin) = io.target(pid) else {
                continue;
            };
            let Some(binding) = self.bindings.get(&image.task_cookie) else {
                continue;
            };
            if binding.domain != self.router.domain()
                || !binding.current
                || binding.image != image
                || pin.pid() != pid
                || !Arc::ptr_eq(&pin, &binding.pin)
                || !pin.still_the_same()
            {
                continue;
            }
            let now = io.now();
            let (Some(proof_deadline), Some(slice_end)) = (
                now.checked_add(self.limits.pending_for),
                now.checked_add(self.limits.scan_slice),
            ) else {
                self.exhaust(&mut report);
                break;
            };
            let job = ScanJob {
                image,
                endpoint,
                slot,
                pin,
                deadline: proof_deadline,
                birth_cut: birth_cut.clone(),
            };
            report.scans += 1;
            self.joined_refresh_cursor = Some(key);
            let fence = self.router.fence();
            let attempt_deadline = slice_end.min(proof_deadline);
            let result = io.scan(&job, attempt_deadline, fence, &|| self.router.fence());
            let healthy = self.audit(io, &mut report);
            if io.now() >= attempt_deadline {
                report.scan_refusals.push(ImageQueryRefusal::Deadline);
            } else if healthy {
                match result {
                    Ok(proof) => self.accept_scan(io, proof, &job, fence, &mut report),
                    Err(refusal) => report.scan_refusals.push(refusal),
                }
            }
        }
        Ok(report)
    }
    pub(crate) fn stop(&mut self) -> TickReport {
        let mut report = TickReport::default();
        if self.stopped {
            self.stamp_disposition(&mut report);
            return report;
        }
        self.stopped = true;
        self.invalidate(InvalidationScope::Stopped, &mut report);
        let images: Vec<_> = self
            .awaiting
            .values()
            .map(|w| w.record.base.event.image)
            .collect();
        for image in images {
            self.expire(image, &mut report);
        }
        self.jobs.clear();
        self.stamp_disposition(&mut report);
        report
    }
}

#[cfg(test)]
pub(crate) fn assert_actual_absence_birth_fixture() {
    tests::actual_absence_birth_fixture();
}

#[cfg(test)]
pub(crate) fn deliver_collected_raw_for_resource_test(
    raw: &mut crate::semantics_objects::journal::joint_driver::RawJointQuantum,
    domain: NativeDomainId,
) -> TickReport {
    tests::deliver_collected_raw_for_resource_test(raw, domain)
}

#[cfg(test)]
mod tests;
