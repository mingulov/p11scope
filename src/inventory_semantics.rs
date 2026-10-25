//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private authority carried from retained Inventory inputs to a Detailed lane.

mod joint;
#[cfg(test)]
mod joint_cells;
pub(crate) mod selected;

pub(crate) use joint::{
    JointCommitIo, JointContinuationView, RetainedJointBirths, bind_semantic_callers_inner,
};
#[allow(unused_imports)]
// Private Session service types; the ordinary driver remains inactive.
pub(crate) use joint::{
    JointCommitRefusal, JointServiceMode, JointServiceProgress, JointWorkBudget,
};
#[cfg(test)]
pub(crate) use joint::{
    JointMachineIo, JointNativeIo, LiveJointMachine, bind_collected_semantic_callers,
    with_joint_commit_io_for_births_test, with_joint_commit_io_for_test,
};

use crate::attach::capture::NativeDomainId;
use crate::attach::image_query::ImageQueryRefusal;
use crate::attach::{
    AttachedSemanticSet, BackendSelection, ProducerDetachProgress, Scope, Session,
};
use crate::discovery::caller_registry::ModuleKey;
use crate::discovery::caller_registry::{OsProcessSource, now_ns};
use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::discovery::identity::RetainedInventoryTarget;
use crate::process::PidPin;
use crate::run::{STOP_QUIESCE_BUDGET, StopState, TerminalQuiescence};
use crate::semantic_capture::{
    CurrentPartitionReceipt, CurrentReceiptRefusal, Endpoint, InvalidationScope,
    PhysicalSemanticGap, SemanticCapture, TickLimits, TickOutcome, TickReport,
    unjoined_shed_counts,
};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceRefusal,
};
use crate::semantics_objects::journal::JournalAdapter;
use crate::semantics_objects::journal::joint_driver::RawJointQuantum;
use p11scope_ebpf_common::ImageIdentity;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Finite refusal; no private manifest or native record is rendered here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticRefusal {
    ManifestInput,
    Unattested,
    IncompleteProvider,
    Attachment,
    Descriptor,
    ProviderInstanceUnproven,
    ProviderStorage,
    /// The lane cannot serve this operation yet: Task 5 owns Session
    /// startup and H0 driving; the Task 3 shell refuses honestly.
    Unavailable,
}

impl std::fmt::Display for SemanticRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl SemanticRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::ManifestInput => "manifest_input_refused",
            Self::Unattested => "unattested",
            Self::IncompleteProvider => "incomplete_provider",
            Self::Attachment => "semantic_attachment_refused",
            Self::Descriptor => "semantic_descriptor_refused",
            Self::ProviderInstanceUnproven => "provider_instance_unproven",
            Self::ProviderStorage => "provider_storage_refused",
            Self::Unavailable => "semantic_unavailable",
        }
    }
}

/// Which admission-preparation site refused with
/// [`SemanticRefusal::Unavailable`]. Finite vocabulary for the
/// `semantic admission refused` gap: the reason carries
/// `semantic_unavailable:<label>`. The production-live leg is the
/// refresh scan outcome ([`Self::NoReceipt`]); the rest are
/// teardown races, defense-in-depth (a lane that lost its live
/// owner between the driver's liveness guard and the check) or
/// test/collected-only legs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionUnavailableSite {
    /// The test H0 seam refused (gate or scripted refusal). Tests only.
    #[cfg_attr(not(test), allow(dead_code))]
    RefreshTestSeam,
    /// The lane holds no live H0 owner.
    RefreshNoLive,
    /// The live lane finished, or gated before a terminal collection.
    RefreshFinishedOrGated,
    /// The terminal collection I/O was unavailable.
    RefreshCollectionIo,
    /// The H0 refresh itself errored (foreign domain, stopped capture).
    RefreshFailed,
    /// The refresh minted no receipt for this caller and slot: its
    /// scan refused (the live pre-cookie leg).
    NoReceipt,
    /// The provider-subject attachment check found no live owner.
    ProviderSubjectUnavailable,
    /// The collected quantum failed refresh preflight.
    CollectedRefreshInvalid,
    /// The collected quantum failed Q validation.
    CollectedQInvalid,
}

impl AdmissionUnavailableSite {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::RefreshTestSeam => "refresh_test_seam",
            Self::RefreshNoLive => "refresh_no_live",
            Self::RefreshFinishedOrGated => "refresh_finished_or_gated",
            Self::RefreshCollectionIo => "refresh_collection_io",
            Self::RefreshFailed => "refresh_failed",
            Self::NoReceipt => "no_receipt",
            Self::ProviderSubjectUnavailable => "provider_subject_unavailable",
            Self::CollectedRefreshInvalid => "collected_refresh_invalid",
            Self::CollectedQInvalid => "collected_q_invalid",
        }
    }
}

/// An admission-preparation refusal: the finite [`SemanticRefusal`]
/// plus, for `Unavailable`, the exact firing site. Displays as the
/// refusal code, with `:<site>` appended for `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AdmissionPreparationError {
    refusal: SemanticRefusal,
    site: Option<AdmissionUnavailableSite>,
}

impl AdmissionPreparationError {
    /// Total constructor: every production prepare leg is `Unavailable`;
    /// only the test seam passes other refusals through.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn refused(refusal: SemanticRefusal) -> Self {
        Self {
            refusal,
            site: None,
        }
    }
    pub(crate) fn unavailable(site: AdmissionUnavailableSite) -> Self {
        Self {
            refusal: SemanticRefusal::Unavailable,
            site: Some(site),
        }
    }
    /// The plain refusal, for the compatibility wrapper below.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn refusal(self) -> SemanticRefusal {
        self.refusal
    }
    /// The firing site, set only for `Unavailable`.
    #[cfg(test)]
    pub(crate) fn site(self) -> Option<AdmissionUnavailableSite> {
        self.site
    }
}

impl std::fmt::Display for AdmissionPreparationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.refusal, self.site) {
            (SemanticRefusal::Unavailable, Some(site)) => {
                write!(f, "{}:{}", self.refusal.code(), site.label())
            }
            _ => f.write_str(self.refusal.code()),
        }
    }
}

pub(crate) use crate::discovery::engine::inventory_coordinator::semantics::AttestedSubset;

/// The actual attached provider, proved by the Detailed owner before scope's
/// final sample. Coordinates select the retained file; they never mint it.
pub(crate) struct SemanticProviderTarget {
    module: ModuleKey,
    endpoint: Endpoint,
    _retained: RetainedInventoryTarget,
    _storage: ResourceLease,
}

impl SemanticProviderTarget {
    pub(crate) fn module(&self) -> &ModuleKey {
        &self.module
    }
    pub(crate) fn matches(&self, endpoint: Endpoint) -> bool {
        self.endpoint.object == endpoint.object && self.endpoint.file_slot == endpoint.file_slot
    }

    pub(crate) fn has_file_slot(&self, file_slot: u32) -> bool {
        self.endpoint.file_slot == file_slot
    }

    pub(crate) fn same_association(&self, other: &Self) -> bool {
        self.module == other.module && self.matches(other.endpoint)
    }

    pub(crate) fn conflicts_with(&self, other: &Self) -> bool {
        self.endpoint.object == other.endpoint.object
            || self.endpoint.file_slot == other.endpoint.file_slot
    }

    /// Requested copies plus the final real inline type. The latter also
    /// conservatively covers the move-only prepared target before insertion;
    /// retained container capacity is reserved independently.
    fn copy_charge(module: &ModuleKey, watched: &RetainedInventoryTarget) -> Option<usize> {
        let text = match module {
            ModuleKey::Physical { sha256, .. } => sha256.as_ref(),
            ModuleKey::Unidentified { path } => Some(path),
        };
        let module_bytes = match text.filter(|text| text.capacity() != 0) {
            Some(text) => text.capacity().checked_add(OWNED_ALLOCATION_PADDING)?,
            None => 0,
        };
        std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<SemanticCallerBinding>())?
            .checked_add(watched.retained_copy_allocation_charge()?)?
            .checked_add(module_bytes)
    }
}

/// Borrowed coordinates checked against this lane's actual attachment. Only
/// the owner validator below can turn them into a retained provider; this
/// private stack value cannot move or replace the original Current/New.
struct CurrentProviderSubject<'a> {
    receipt: &'a CurrentPartitionReceipt,
    module: &'a ModuleKey,
}

/// Move-only bootstrap evidence. The owner receipt is delivered exactly once
/// to normal finalization after consuming (or refusing) scoped admission.
pub(crate) struct PreparedSemanticAdmission {
    receipt: CurrentPartitionReceipt,
    // Even a refused validation follows an accepted owner scan. Its original
    // receipt must reach the coordinator's refusal-only history exactly once.
    provider: Result<SemanticProviderTarget, SemanticRefusal>,
}

impl PreparedSemanticAdmission {
    pub(crate) fn into_parts(
        self,
    ) -> (
        CurrentPartitionReceipt,
        Result<SemanticProviderTarget, SemanticRefusal>,
    ) {
        (self.receipt, self.provider)
    }
}

/// Lane-staged negative facts: the accompanying negatives one owned H0
/// outcome batch carries. The cut barrier ordinal is H0-timeline evidence
/// (allocated by H0's checked counter after all issued positions), never
/// caller-selected; tests script it exactly as H2 scripts positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task5 lane stages negatives.
pub(crate) enum LaneNegative {
    /// One coalesced physical cut applied before every unpublished call.
    CutBarrier { ordinal: u64 },
    /// A refused collection, recorded through the audited path.
    CollectionRefused { reason: LaneCollectionRefusal },
}

/// Finite lane-collection refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Task5 lane stages negatives.
pub(crate) enum LaneCollectionRefusal {
    Backpressure,
    CollectionFailed,
}

impl LaneCollectionRefusal {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Backpressure => "backpressure",
            Self::CollectionFailed => "collection_failed",
        }
    }
}

/// One owned H0 outcome batch plus its current-partition receipts and
/// lane-staged negative facts. Move-only: private fields, no
/// Clone/Default/from_parts, redacted Debug. The lane alone constructs
/// it; the coordinator finalizer alone consumes it.
pub(crate) struct SemanticBatch {
    domain: NativeDomainId,
    outcomes: Vec<TickOutcome>,
    current: Vec<CurrentPartitionReceipt>,
    negatives: Vec<LaneNegative>,
    observed_ns: u64,
    /// H3 disposition inputs carried from the tick report: the
    /// route-waiting floor, the merge-shed floor, and exhaustion.
    awaiting_floor: Option<u64>,
    shed_floor: Option<u64>,
    exhausted: bool,
}

/// Lane negatives per batch: one cut barrier plus bounded collection
/// refusals for the quantum. H0 outcomes and receipts keep H0's own
/// capacity; the lane re-checks them defensively below.
pub(crate) const MAX_LANE_NEGATIVES: usize = 64;

impl std::fmt::Debug for SemanticBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticBatch")
            .field("outcomes", &self.outcomes.len())
            .field("current", &self.current.len())
            .field("negatives", &self.negatives.len())
            .finish_non_exhaustive()
    }
}

impl SemanticBatch {
    /// A final Stop may follow only an empty owned batch. Current receipts or
    /// calls must be prepared/validated/published while Capture is still live.
    pub(crate) fn permits_collected_stop(&self) -> bool {
        self.current.is_empty()
            && !self
                .outcomes
                .iter()
                .any(|outcome| matches!(outcome, TickOutcome::Call(_)))
    }

    pub(crate) fn reserve_collected_stop_union(&mut self) -> Result<(), SemanticRefusal> {
        if !self.permits_collected_stop()
            || self.outcomes.len() >= crate::discovery::instances::MAX_INSTANCES
            || self.outcomes.len() == self.outcomes.capacity()
        {
            return Err(SemanticRefusal::ProviderStorage);
        }
        // The original collected accumulator already paid/reserved its full
        // bounded outcome capacity before any H0 work. Transfer the Stop into
        // that same allocation; never grow an unpaid replacement after Stop.
        Ok(())
    }

    /// The machine holds both incoming/union capacities before actual Stop.
    /// Every refusal leaves the incoming report and this original untouched.
    pub(crate) fn merge_collected_stop(
        &mut self,
        report: &mut TickReport,
    ) -> Result<(), SemanticRefusal> {
        if !self.permits_collected_stop()
            || !report.current().is_empty()
            || report.outcomes().len() != 1
            || self.outcomes.len() == self.outcomes.capacity()
        {
            return Err(SemanticRefusal::ProviderStorage);
        }
        self.awaiting_floor = report.awaiting_floor();
        self.shed_floor = match (self.shed_floor, report.shed_floor()) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.exhausted |= report.exhausted();
        let (mut outcomes, current) = std::mem::take(report).into_parts();
        self.outcomes.append(&mut outcomes);
        drop(outcomes);
        drop(current);
        Ok(())
    }
    /// The lane's batch constructor: bounds-checked before ownership.
    pub(crate) fn from_tick_report(
        domain: NativeDomainId,
        report: TickReport,
        negatives: Vec<LaneNegative>,
        observed_ns: u64,
    ) -> Result<Self, SemanticRefusal> {
        let awaiting_floor = report.awaiting_floor();
        let shed_floor = report.shed_floor();
        let exhausted = report.exhausted();
        let (outcomes, current) = report.into_parts();
        if outcomes.len() > crate::discovery::instances::MAX_INSTANCES
            || current.len() > crate::discovery::instances::MAX_INSTANCES
            || negatives.len() > MAX_LANE_NEGATIVES
        {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(Self {
            domain,
            outcomes,
            current,
            negatives,
            observed_ns,
            awaiting_floor,
            shed_floor,
            exhausted,
        })
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        negatives: Vec<LaneNegative>,
        observed_ns: u64,
    ) -> Self {
        Self::from_tick_report(domain, TickReport::default(), negatives, observed_ns)
            .expect("scripted batch respects lane bounds")
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    pub(crate) fn observed_ns(&self) -> u64 {
        self.observed_ns
    }

    /// H3 disposition inputs for the finalizer derivation.
    pub(crate) fn awaiting_floor(&self) -> Option<u64> {
        self.awaiting_floor
    }
    pub(crate) fn shed_floor(&self) -> Option<u64> {
        self.shed_floor
    }
    pub(crate) fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// Minimum outcome position without consuming: the unpublished
    /// floor for a staged-but-unfinalized batch. An empty batch
    /// constrains nothing; an unpositioned outcome floors at zero
    /// (undisposed, never skipped).
    pub(crate) fn min_outcome_position(&self) -> Option<u64> {
        if self.outcomes.is_empty() {
            return None;
        }
        Some(
            self.outcomes
                .iter()
                .map(|outcome| outcome.position().unwrap_or(0))
                .min()
                .unwrap_or(0),
        )
    }

    /// Current receipts must reach validation promptly, preserving
    /// their original window even after time spent in the refresh stash.
    pub(crate) fn has_current_receipts(&self) -> bool {
        !self.current.is_empty()
    }

    /// Borrow the original accepted H0 receipts before physical adjudication.
    /// Presence records an observed image; current authority still revalidates.
    pub(crate) fn current_receipts(&self) -> &[CurrentPartitionReceipt] {
        &self.current
    }

    /// Borrow the batch outcomes for drop accounting: a refused batch
    /// sheds its unjoined calls without consuming the batch's negatives.
    pub(crate) fn outcomes(&self) -> &[TickOutcome] {
        &self.outcomes
    }

    /// Whether the batch carries no outcomes, receipts or negatives:
    /// tests assert quiet ticks stage or commit nothing.
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.outcomes.is_empty() && self.current.is_empty() && self.negatives.is_empty()
    }

    /// The batch's own cut fence, if any: the maximum cut-barrier
    /// ordinal the lane staged. The finalizer carries the cut's
    /// barrier into the queued ordinary quantum; tokens admitted by
    /// the finalization itself never feed it.
    pub(crate) fn cut_barrier(&self) -> Option<u64> {
        self.negatives
            .iter()
            .filter_map(|negative| match negative {
                LaneNegative::CutBarrier { ordinal } => Some(*ordinal),
                LaneNegative::CollectionRefused { .. } => None,
            })
            .max()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Vec<TickOutcome>,
        Vec<CurrentPartitionReceipt>,
        Vec<LaneNegative>,
    ) {
        (self.outcomes, self.current, self.negatives)
    }
}

/// Validated current-partition coverage, decomposed from a receipt the
/// lane owner validated against current retained binding/router state.
/// The coverage is the conversion's registration and standing proof.
pub(crate) struct LaneCoverage {
    domain: NativeDomainId,
    image: ImageIdentity,
    endpoint: Endpoint,
    ids: Vec<crate::discovery::instances::InstanceId>,
}

impl std::fmt::Debug for LaneCoverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaneCoverage(<private>)")
    }
}

impl LaneCoverage {
    /// Decompose a receipt the lane owner just validated through H0
    /// into the conversion's registration and standing proof. The
    /// caller validated this exact receipt; the coverage carries its
    /// fields unchanged.
    pub(crate) fn from_validated_receipt(receipt: &CurrentPartitionReceipt) -> Self {
        Self {
            domain: receipt.domain(),
            image: receipt.image(),
            endpoint: receipt.endpoint(),
            ids: receipt.instances().to_vec(),
        }
    }

    #[cfg(test)]
    pub(crate) fn scripted(
        domain: NativeDomainId,
        image: ImageIdentity,
        endpoint: Endpoint,
        ids: Vec<crate::discovery::instances::InstanceId>,
    ) -> Self {
        Self {
            domain,
            image,
            endpoint,
            ids,
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

    pub(crate) fn instances(&self) -> &[crate::discovery::instances::InstanceId] {
        &self.ids
    }
}

/// Tests-only substituted H0 I/O behind the lane: the lane's tick,
/// refresh, receipt validation and stop servicing run the real H0
/// collect→audit→route decisions through this I/O instead of the live
/// Session. No live Session exists in tests, so production never
/// installs it; every batch it produces still funnels through the
/// production stash/merge/batch/finalize/commit path.
#[cfg(test)]
pub(crate) trait LaneTestIo {
    fn stash_pending_floor(&self) -> Option<u64> {
        None
    }
    /// Forward a borrow of the actual substituted H0/stash and the producers
    /// retained from its collected input. This scripts no pending fact.
    fn inspect_pending_h3(
        &self,
        _inspect: &mut dyn FnMut(
            &SemanticCapture,
            &RefreshReceiptStash,
            &crate::attach::SessionDrainProducers,
        ),
    ) {
    }
    /// Observe the real driver publication notification; grants no permission.
    fn semantic_published(&mut self) {}
    /// Substitute native terminal ownership I/O beneath the real driver/H0
    /// ordering. A real cleanup worker may own the injected close leaf.
    fn begin_terminal_cleanup(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn finish_terminal_cleanup(
        &mut self,
        _second_signal: &dyn Fn() -> bool,
        _out: &mut dyn std::io::Write,
    ) -> anyhow::Result<()> {
        Ok(())
    }
    /// Substitute owned-detach reap beneath the wound-down poll:
    /// scripted progress for lanes without a live Session. Pending
    /// keeps every original; only Complete advances to retired-file
    /// closing. An Unproved detach is an error the owner keeps.
    fn poll_terminal_detach(
        &mut self,
        _out: &mut dyn std::io::Write,
    ) -> anyhow::Result<ProducerDetachProgress> {
        Ok(ProducerDetachProgress::Pending)
    }
    /// The exact targets the production driver selected for this tick.
    fn tick_targets(&mut self, _pins: &[Arc<PidPin>]) {}
    /// First-drain stamp of a retained image, for registration
    /// backdating. Test owners without a real H0 retain nothing.
    fn retained_registration_ns(&self, _image: ImageIdentity) -> Option<u64> {
        None
    }
    /// Substitute Session attachment I/O, retaining the production subset
    /// matching and owner receipt checks around it.
    fn validate_attachment(&mut self, _subset: &AttestedSubset) -> Result<(), SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    fn take_refresh_receipt(
        &mut self,
        _pin: &Arc<PidPin>,
        _slot: u32,
    ) -> Option<CurrentPartitionReceipt> {
        None
    }
    fn stash_admission_evidence(
        &mut self,
        _receipts: Vec<CurrentPartitionReceipt>,
        _outcomes: Vec<TickOutcome>,
    ) {
        unreachable!("an admission-capable test owner must retain its evidence")
    }
    /// Optional real H0 cut servicing. A handler drains `gaps`; otherwise
    /// the existing shell cut seam retains them for its own assertions.
    fn physical_gaps(
        &mut self,
        _domain: NativeDomainId,
        _gaps: &mut Vec<PhysicalSemanticGap>,
    ) -> Option<Result<SemanticBatch, SemanticRefusal>> {
        None
    }
    /// Borrow the same actual H0 owner that routed this collected quantum.
    fn validate_collected_preparation(
        &self,
        _raw: &RawJointQuantum,
    ) -> Result<(), SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    fn physical_gaps_collected(
        &mut self,
        _domain: NativeDomainId,
        _gaps: &mut Vec<PhysicalSemanticGap>,
        _raw: &mut RawJointQuantum,
    ) -> Option<Result<SemanticBatch, SemanticRefusal>> {
        None
    }
    /// The real H0 receipt validation through substituted I/O.
    fn validate_current(
        &mut self,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<(), CurrentReceiptRefusal>;
    /// The real H0 tick plus the production stash merge and batch
    /// construction.
    fn tick(&mut self, domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal>;
    /// The real H0 refresh plus the production stash and custody
    /// derivation.
    fn refresh(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal>;
    fn refresh_collected(
        &mut self,
        _pin: Arc<PidPin>,
        _slot: u32,
        _raw: &mut RawJointQuantum,
        _adapter: &JournalAdapter,
        _producers: &crate::attach::SessionDrainProducers,
    ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    /// Whether stashed evidence awaits a tick (the stop pre-flush gate).
    fn has_pending_evidence(&self) -> bool;
    /// The real H0 stop plus the production Finish batch construction.
    fn finish(&mut self, domain: NativeDomainId) -> SemanticBatch;
    /// Whether the substituted producer is quiescent (scripted per
    /// test; servicing advances it).
    fn quiescent(&mut self) -> bool;
    /// Current (consumer, producer) for the owned EVENTS and DISCOVERY
    /// cursors, in that order. `None` is an unreadable ring.
    fn positions(&mut self) -> Option<[(usize, usize); 2]>;
    /// Bounded EVENTS remainder drain to `stop`.
    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
    /// Bounded DISCOVERY drain to `stop`: cursor servicing only.
    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
}

/// Fault-injection sites for the Joint Finish latch tests. Each variant
/// names a real `Err` site on the machine Finish path; the machine returns
/// that site's error once when armed. Defined beside the lane because the
/// joint module boundary is owned by another task.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinishSite {
    ValidateOwner,
    DiscoveryDomain,
    CompleteFinish,
    MissingReceipt,
    PendingReport,
    PendingPhase,
}

/// Bound on retryable `ProviderStorage` refusals inside one Joint Finish.
/// The counter is never reset; the 100th refusal latches the disposition.
pub(crate) const JOINT_FINISH_STORAGE_RETRIES: u16 = 100;

/// Grant half of the Finish Q guard (machine `drive_finish`): the Q's
/// retained grant, or the machine's first genuine Raw-minted grant after a
/// grant-less observation. STOP may precede the first Joint admission, so a
/// grant-less Q plus an own-producers grant stays admissible.
pub(crate) fn finish_grant_admissible(
    q: &crate::attach::CollectedFinishQ,
    grant: &crate::semantics_objects::journal::SessionDrainGrant,
    producers: &crate::attach::SessionDrainProducers,
) -> bool {
    q.matches_retained_grant(grant)
        || (q.observed_without_grant() && grant.matches_producers(producers))
}

/// One optional Detailed lane: the Session owner, H0 `SemanticCapture`
/// driver and proof-bearing batch supplier. Without a live Session (no
/// manifests, or a refused startup) every H0-driving method refuses
/// honestly and broad Inventory is preserved; only a live lane drives
/// H0 collect→audit→route, and no other `SemanticCall` producer exists.
pub(crate) struct AttestedSemanticLane {
    subset: AttestedSubset,
    domain: NativeDomainId,
    live: Option<Box<LiveLane>>,
    startup_failed: bool,
    // Negative admission/legacy-Finish gate only. Completion requires the
    // constructor-private token from the matching actual publication below.
    collected_finish_requested: bool,
    /// First Finish refusal latched for this lane: a pre-machine error from
    /// the lane wrapper, or a driver-noted terminal refusal. The machine
    /// holds its own latch; the lane query reports either.
    joint_finish_failure: Option<SemanticRefusal>,
    /// Set by the I2 abandon: the lane finished without a published
    /// Finish and stays retained for process exit. Wound-down and take
    /// refuse forever; the Session never begins owned detach.
    #[cfg_attr(not(test), allow(dead_code))] // The joint driver consumes the terminal API.
    exit_retained: bool,
    /// Set by the wound-down poll that first reports drained
    /// (§8.3): the recorded wound-down the take requires. Never
    /// cleared; abandon exit-retains past it and refuses anyway.
    wound_down_complete: bool,
    /// When the lane's latest batch was staged for commit: the driver
    /// stamps it on stage and clears it on publish, bounding the wait
    /// for receipt-free evidence and backing off failed commits.
    staged_at: Option<Instant>,
    /// Calls shed without a route across finalizations (the aggregate
    /// unrouted gap's lifetime total), for the honest stop line.
    disclosed_calls_shed: u64,
    /// Route-labeled shed from oversized tick reports (batch construction
    /// refused): counted into the stop line at the drop, disclosed by the
    /// next finalize's unrouted gap. At most one entry per route label.
    oversized_drop_shed: BTreeMap<&'static str, u64>,
    /// Tests-only substituted H0 I/O (see [`LaneTestIo`]): installed
    /// by tests that drive the production finalize path without a
    /// live Session.
    #[cfg(test)]
    test_io: Option<Box<dyn LaneTestIo>>,
    /// Tests-only stop/finish state beside `test_io`, mirroring the
    /// live lane's gate: regular ticks refuse once stopping.
    #[cfg(test)]
    test_gated: bool,
    /// Tests-only pre-machine Finish refusal seam: when set, the lane's
    /// machine wrapper refuses before the machine runs, so the lane flag
    /// path is exercised without a live Session.
    #[cfg(test)]
    inject_pre_machine: bool,
    #[cfg(test)]
    test_finished: bool,
    /// Tests-only retained-frame answer, checked first by
    /// `has_joint_frame` (mirrors `test_finished`).
    #[cfg(test)]
    test_joint_frame: bool,
    #[cfg(test)]
    recorded_gaps: Vec<PhysicalSemanticGap>,
    #[cfg(test)]
    scripted_barrier: Option<u64>,
    #[cfg(test)]
    fail_next_cut: bool,
    /// The conversion barrier the finalizer last carried into queued
    /// calls (the cut floor plus this batch's own negatives): tests
    /// assert the fence queued calls met without forging H0 outcomes.
    #[cfg(test)]
    last_conversion_barrier: Option<u64>,
}

/// Bound on refresh receipts stashed ahead of the next tick: one tick
/// quantum's worth of quiet no-call registrations.
pub(crate) const MAX_STASHED_REFRESH_RECEIPTS: usize = crate::discovery::instances::MAX_PENDING;

/// Bounded lane stash for refresh evidence: a no-call refresh proves
/// a current partition for a quiet provider, and that proof must reach
/// a batch (the next tick merges it) instead of dropping. The refresh's
/// accompanying outcomes (invalidations from superseded proof) stash
/// beside the receipts, never discarded. Beyond
/// [`MAX_STASHED_REFRESH_RECEIPTS`] the oldest of each shed (counted);
/// a later scan re-mints superseded proof.
#[derive(Debug, Default)]
pub(crate) struct RefreshReceiptStash {
    stashed: std::collections::VecDeque<CurrentPartitionReceipt>,
    outcomes: std::collections::VecDeque<TickOutcome>,
    shed: u64,
    /// Minimum shed outcome position: stash overflow drops positioned
    /// history, so the next merge carries it as a loss barrier. Taken
    /// on handoff; each shed reports exactly once.
    shed_floor: Option<u64>,
}

/// A live lane's original pending custody, borrowed for one read-only
/// disposition check. Construction is private; no scalar floor or supplied
/// record collection can create this continuation authority.
pub(crate) struct PendingH3Continuation<'a> {
    capture: &'a SemanticCapture,
    stash: &'a RefreshReceiptStash,
    producers: &'a crate::attach::SessionDrainProducers,
}

impl PendingH3Continuation<'_> {
    pub(crate) fn matches(
        &self,
        producers: &crate::attach::SessionDrainProducers,
        allocated_below: u64,
        pending_floor: u64,
        fault: u64,
    ) -> bool {
        self.producers.same_producers(producers)
            && self.capture.router().domain() == producers.native_domain()
            && self.stash.shed_floor.is_none()
            && self
                .capture
                .pending_h3_watermark()
                .is_some_and(|(below, awaiting, epoch)| {
                    below == allocated_below
                        && epoch == fault
                        && awaiting
                            .into_iter()
                            .chain(self.stash.min_outcome_position())
                            .min()
                            == Some(pending_floor)
                })
    }

    pub(crate) fn originals(
        &self,
    ) -> impl Iterator<Item = crate::semantic_capture::PendingH3Original<'_>> {
        self.capture
            .pending_h3_originals()
            .chain(self.stash.outcomes.iter().filter_map(|outcome| {
                let TickOutcome::Call(call) = outcome else {
                    return None;
                };
                Some((
                    call.position(),
                    call.collected_origin(),
                    call.record(),
                    call.joint_resource(),
                ))
            }))
    }
}

impl RefreshReceiptStash {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Stash one refresh's receipts and outcomes in order. Returns items
    /// shed past the cap: the caller discloses the count as refused
    /// endpoints. Outcome overflow sheds positives first: an
    /// invalidation is H2's loss boundary (a shed boundary is silent
    /// semantic loss), while a shed call is disclosed through the
    /// refusal count. Positions increase monotonically, so the oldest
    /// outcome still carries the minimum barrier when only
    /// invalidations remain.
    pub(crate) fn push_all(
        &mut self,
        receipts: Vec<CurrentPartitionReceipt>,
        outcomes: Vec<TickOutcome>,
    ) -> u64 {
        let mut shed = 0;
        self.stashed.extend(receipts);
        while self.stashed.len() > MAX_STASHED_REFRESH_RECEIPTS {
            self.stashed.pop_front();
            shed += 1;
        }
        self.outcomes.extend(outcomes);
        while self.outcomes.len() > MAX_STASHED_REFRESH_RECEIPTS {
            let dropped = if let Some(at) = self
                .outcomes
                .iter()
                .position(|outcome| !outcome.is_invalidation())
            {
                self.outcomes.remove(at)
            } else {
                self.outcomes.pop_front()
            };
            if let Some(outcome) = dropped
                && let Some(position) = outcome.position()
            {
                self.shed_floor = Some(self.shed_floor.map_or(position, |at| at.min(position)));
            }
            shed += 1;
        }
        self.shed = self.shed.saturating_add(shed);
        shed
    }

    /// Take the stash's shed floor for one merge handoff, resetting it.
    pub(crate) fn take_shed_floor(&mut self) -> Option<u64> {
        self.shed_floor.take()
    }

    /// Minimum stashed outcome position without consuming: undisposed
    /// history awaiting the next merge. An empty stash constrains
    /// nothing; an unpositioned outcome floors at zero.
    pub(crate) fn min_outcome_position(&self) -> Option<u64> {
        if self.outcomes.is_empty() {
            return None;
        }
        Some(
            self.outcomes
                .iter()
                .map(|outcome| outcome.position().unwrap_or(0))
                .min()
                .unwrap_or(0),
        )
    }

    /// Whether the stash holds nothing to merge.
    pub(crate) fn is_empty(&self) -> bool {
        self.stashed.is_empty() && self.outcomes.is_empty()
    }

    /// Tests-only shed count: production discloses `push_all`'s return
    /// as refused endpoints instead.
    #[cfg(test)]
    pub(crate) fn shed(&self) -> u64 {
        self.shed
    }

    /// Drain the stashed receipts in order into the next tick batch.
    pub(crate) fn take(&mut self) -> Vec<CurrentPartitionReceipt> {
        std::mem::take(&mut self.stashed).into_iter().collect()
    }

    /// Drain the stashed outcomes in order into the next tick batch.
    pub(crate) fn take_outcomes(&mut self) -> Vec<TickOutcome> {
        std::mem::take(&mut self.outcomes).into_iter().collect()
    }

    pub(crate) fn take_for_admission(
        &mut self,
        pin: &Arc<PidPin>,
        slot: u32,
    ) -> Option<CurrentPartitionReceipt> {
        let at = self.stashed.iter().rposition(|receipt| {
            Arc::ptr_eq(receipt.original_pin(), pin) && receipt.attachment_slot() == slot
        })?;
        self.stashed.remove(at)
    }
}

/// Stash one refresh report's receipts and outcomes for the next tick
/// batch, returning the binding-hint images and the shed count. Shared
/// by the live refresh path; tests drive it with real H0 reports.
pub(crate) fn stash_refresh_report(
    stash: &mut RefreshReceiptStash,
    report: &mut TickReport,
) -> (Vec<ImageIdentity>, u64) {
    let images = report
        .current()
        .iter()
        .map(|receipt| receipt.image())
        .collect();
    let shed = stash.push_all(report.take_current(), report.take_outcomes());
    (images, shed)
}

/// Merge the lane's stashed refresh evidence behind a tick report's
/// own, returning the merge shed count. Shared by regular ticks and
/// terminal quanta so quiet proofs register on every path.
pub(crate) fn merge_stash_into_report(
    stash: &mut RefreshReceiptStash,
    report: &mut TickReport,
) -> u64 {
    let shed = report.merge_stashed_current(stash.take());
    let shed = shed.saturating_add(report.merge_stashed_outcomes(stash.take_outcomes()));
    report.absorb_shed_floor(stash.take_shed_floor());
    shed
}

/// The custody Arc H0 actually retained for a refresh report: the
/// minted receipt's pin (adopted across a failed-bind retry), else the
/// passed pin when the refresh minted nothing. Shared by the live
/// refresh path and the retry test so both derive it identically.
pub(crate) fn effective_refresh_custody(report: &TickReport, pin: Arc<PidPin>) -> Arc<PidPin> {
    report
        .current()
        .first()
        .map(|receipt| receipt.original_pin().clone())
        .unwrap_or(pin)
}

/// Finite scan-refusal vocabulary for disclosure surfaces (gaps, stderr
/// counts). Index-aligned with the per-reason counters the live lane keeps
/// beside the existing `refused_endpoints` total.
pub(crate) const SCAN_REFUSAL_LABELS: [&str; 12] = [
    "policy",
    "coverage",
    "custody",
    "deadline",
    "capacity",
    "exhausted",
    "stream",
    "unknown",
    "unstable",
    "empty",
    "fence",
    "present",
];

/// Per-reason slot for one scan refusal. Same order as
/// [`SCAN_REFUSAL_LABELS`].
pub(crate) fn image_query_refusal_index(refusal: ImageQueryRefusal) -> usize {
    match refusal {
        ImageQueryRefusal::Policy => 0,
        ImageQueryRefusal::Coverage => 1,
        ImageQueryRefusal::Custody => 2,
        ImageQueryRefusal::Deadline => 3,
        ImageQueryRefusal::Capacity => 4,
        ImageQueryRefusal::Exhausted => 5,
        ImageQueryRefusal::Stream => 6,
        ImageQueryRefusal::Unknown => 7,
        ImageQueryRefusal::Unstable => 8,
        ImageQueryRefusal::Empty => 9,
        ImageQueryRefusal::Fence => 10,
        ImageQueryRefusal::Present => 11,
    }
}

/// Finite vocabulary label for one scan refusal. Tests pin the
/// vocabulary through this; production formats counts by index.
#[cfg(test)]
pub(crate) fn image_query_refusal_label(refusal: ImageQueryRefusal) -> &'static str {
    SCAN_REFUSAL_LABELS[image_query_refusal_index(refusal)]
}

/// Count one report's scan refusals into per-reason slots. The live
/// tick/refresh sites call this beside the existing total; tests drive
/// it with scripted refusals.
pub(crate) fn count_scan_refusals(into: &mut [u64; 12], refusals: &[ImageQueryRefusal]) {
    for refusal in refusals {
        let slot = &mut into[image_query_refusal_index(*refusal)];
        *slot = slot.saturating_add(1);
    }
}

/// Aggregate gap reason for per-reason scan-refusal counts: the total
/// plus sorted `label=count` pairs. `None` when nothing was refused.
/// Counts only; no pids, paths or payloads.
pub(crate) fn scan_refusals_gap_reason(counts: &[u64; 12]) -> Option<String> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let mut parts: Vec<String> = counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count > 0)
        .map(|(index, count)| format!("{}={count}", SCAN_REFUSAL_LABELS[index]))
        .collect();
    parts.sort();
    Some(format!("{total} scan refusals ({})", parts.join(" ")))
}

/// One stderr stop line for the semantic lane: lifetime collected,
/// joined, shed, bound and refused call counts. Counts only; no
/// identities, paths or payloads.
pub(crate) fn semantic_stop_line(
    collected: u64,
    joined: u64,
    shed: u64,
    bindings: u64,
    refused: u64,
) -> String {
    format!(
        "p11scope: semantic calls: collected {collected}, joined {joined}, \
         shed {shed}, bindings {bindings}, refused {refused}"
    )
}

/// The live lane: the owned Detailed `Session` (the sole retained EVENTS
/// cursor, maps and links), its H0 `SemanticCapture` driver, the sealed
/// attachment receipt, and the terminal ownership state. Counts only;
/// no record contents ever leave the H0 path.
pub(crate) struct LiveLane {
    session: Session,
    capture: SemanticCapture,
    attached: AttachedSemanticSet,
    gated: bool,
    finished: bool,
    stop_state: StopState,
    final_drain: bool,
    ticks: u64,
    scan_refusals: u64,
    /// CALL records drained across ticks and the terminal drain.
    collected_calls: u64,
    /// Per-reason scan refusals behind [`Self::scan_refusals`].
    refusal_counts: [u64; 12],
    continuity_cuts: u64,
    unrouted_returns: u64,
    drained_batches: u64,
    semantic_loss: bool,
    stashed_refresh: RefreshReceiptStash,
    /// Lazy, paid from the canonical registry pool at the initial Joint
    /// service. The ordinary driver does not select it in this slice.
    joint_machine: Option<joint::LiveJointMachine>,
}

impl std::fmt::Debug for LiveLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveLane")
            .field("attached", &self.attached)
            .field("gated", &self.gated)
            .field("finished", &self.finished)
            .field("ticks", &self.ticks)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AttestedSemanticLane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttestedSemanticLane(<retained>)")
    }
}

impl AttestedSemanticLane {
    pub(crate) fn with_pending_h3_continuation<R>(
        &self,
        inspect: impl FnOnce(PendingH3Continuation<'_>) -> R,
    ) -> Option<R> {
        #[cfg(test)]
        if let Some(io) = &self.test_io {
            let mut inspect = Some(inspect);
            let mut result = None;
            io.inspect_pending_h3(&mut |capture, stash, producers| {
                let inspect = inspect.take().expect("one actual H0 owner");
                result = Some(inspect(PendingH3Continuation {
                    capture,
                    stash,
                    producers,
                }));
            });
            return result;
        }
        let live = self.live.as_ref()?;
        if live.finished {
            return None;
        }
        let producers = live.session.drain_producers()?;
        Some(inspect(PendingH3Continuation {
            capture: &live.capture,
            stash: &live.stashed_refresh,
            producers: &producers,
        }))
    }
    pub(crate) fn start(
        subset: AttestedSubset,
        _scope: &Scope,
        _backend: BackendSelection,
    ) -> Result<Self, SemanticRefusal> {
        // The shell: no Detailed Session, maps, links or cursor. Live
        // startup is `start_live`; the shell refuses H0-driving work.
        if subset.plan().slots.is_empty() {
            return Err(SemanticRefusal::Unattested);
        }
        let domain = NativeDomainId::try_mint().map_err(|_| SemanticRefusal::Unavailable)?;
        Ok(Self {
            subset,
            domain,
            live: None,
            startup_failed: false,
            collected_finish_requested: false,
            joint_finish_failure: None,
            exit_retained: false,
            wound_down_complete: false,
            staged_at: None,
            disclosed_calls_shed: 0,
            oversized_drop_shed: BTreeMap::new(),
            #[cfg(test)]
            test_io: None,
            #[cfg(test)]
            test_gated: false,
            #[cfg(test)]
            inject_pre_machine: false,
            #[cfg(test)]
            test_finished: false,
            #[cfg(test)]
            test_joint_frame: false,
            #[cfg(test)]
            recorded_gaps: Vec::new(),
            #[cfg(test)]
            scripted_barrier: None,
            #[cfg(test)]
            fail_next_cut: false,
            #[cfg(test)]
            last_conversion_barrier: None,
        })
    }

    /// First-drain stamp of a retained image, for registration
    /// backdating: the calls were observed then, even though the binding
    /// proof only completed later. `None` for images that were never
    /// retained (including every pre-attach image, which sheds at once).
    pub(crate) fn retained_registration_ns(&self, image: ImageIdentity) -> Option<u64> {
        #[cfg(test)]
        if let Some(io) = &self.test_io {
            return io.retained_registration_ns(image);
        }
        self.live
            .as_ref()
            .and_then(|live| live.capture.retained_registration_ns(image))
    }

    /// Lane-stash pending floor for the finalizer's disposition: the
    /// minimum stashed (undisposed, awaiting merge) outcome position. A
    /// shell lane stashes nothing. Stash overflow sheds ride the merged
    /// report's shed floor instead (taken at merge handoff).
    pub(crate) fn stash_pending_floor(&self) -> Option<u64> {
        #[cfg(test)]
        if let Some(io) = &self.test_io {
            return io.stash_pending_floor();
        }
        self.live
            .as_ref()
            .and_then(|live| live.stashed_refresh.min_outcome_position())
    }

    /// Live startup over two subset mints from the same retained accepted
    /// sources: `attach_subset` seals the Session attachment (it is
    /// consumed by the seal), `convert_subset` stays the lane's
    /// conversion envelope. A second mint fails only when the retained
    /// inputs moved under the startup, which refuses honestly. The
    /// minted shell domain is replaced with the Session's native domain.
    pub(crate) fn start_live(
        attach_subset: AttestedSubset,
        convert_subset: AttestedSubset,
        scope: &Scope,
        backend: BackendSelection,
    ) -> Result<Self, SemanticRefusal> {
        if convert_subset.plan().slots.is_empty() {
            return Err(SemanticRefusal::Unattested);
        }
        let (session, attached) = Session::start_attested(attach_subset, scope, backend)
            .map_err(|_| SemanticRefusal::Attachment)?;
        Self::from_live_owner(session, attached, convert_subset).map_err(|(_, reason)| reason)
    }

    /// Share the real H0 construction with selected startup. A rejected owner
    /// returns its Session so selected preparation can retain and join cleanup.
    /// This private helper cannot extract a usable provisional lane for callers.
    #[allow(clippy::result_large_err)] // Cold startup path: a rejected owner returns its Session for retained joined cleanup.
    fn from_live_owner(
        session: Session,
        attached: AttachedSemanticSet,
        convert_subset: AttestedSubset,
    ) -> Result<Self, (Session, SemanticRefusal)> {
        if convert_subset.plan().slots.is_empty() {
            return Err((session, SemanticRefusal::Unattested));
        }
        if session.validate_semantic_set(&attached).is_err() {
            return Err((session, SemanticRefusal::Attachment));
        }
        let Some(domain) = session.native_domain() else {
            return Err((session, SemanticRefusal::Unavailable));
        };
        let capture = match SemanticCapture::new(&session, TickLimits::default()) {
            Ok(capture) => capture,
            Err(_) => return Err((session, SemanticRefusal::Unavailable)),
        };
        Ok(Self {
            subset: convert_subset,
            domain,
            live: Some(Box::new(LiveLane {
                session,
                capture,
                attached,
                gated: false,
                finished: false,
                stop_state: StopState::Running,
                final_drain: false,
                ticks: 0,
                scan_refusals: 0,
                collected_calls: 0,
                refusal_counts: [0; 12],
                continuity_cuts: 0,
                unrouted_returns: 0,
                drained_batches: 0,
                semantic_loss: false,
                stashed_refresh: RefreshReceiptStash::new(),
                joint_machine: None,
            })),
            startup_failed: false,
            collected_finish_requested: false,
            joint_finish_failure: None,
            exit_retained: false,
            wound_down_complete: false,
            staged_at: None,
            disclosed_calls_shed: 0,
            oversized_drop_shed: BTreeMap::new(),
            #[cfg(test)]
            test_io: None,
            #[cfg(test)]
            test_gated: false,
            #[cfg(test)]
            inject_pre_machine: false,
            #[cfg(test)]
            test_finished: false,
            #[cfg(test)]
            test_joint_frame: false,
            #[cfg(test)]
            recorded_gaps: Vec::new(),
            #[cfg(test)]
            scripted_barrier: None,
            #[cfg(test)]
            fail_next_cut: false,
            #[cfg(test)]
            last_conversion_barrier: None,
        })
    }

    /// Whether live startup was attempted and refused. The shell stays
    /// for summary; it drives no H0 work.
    pub(crate) fn mark_startup_failed(&mut self) {
        self.live = None;
        self.startup_failed = true;
    }

    pub(crate) fn subset(&self) -> &AttestedSubset {
        &self.subset
    }

    pub(crate) fn domain(&self) -> NativeDomainId {
        self.domain
    }

    /// Stamp the lane's latest batch staged: the driver calls this
    /// when it stages a tick batch for commit.
    pub(crate) fn note_semantic_staged(&mut self) {
        self.staged_at = Some(Instant::now());
    }

    /// Clear the staged stamp: the driver calls this when a commit
    /// publishes the staged quantum.
    pub(crate) fn note_semantic_published(&mut self) {
        self.staged_at = None;
        #[cfg(test)]
        if let Some(io) = self.test_io.as_mut() {
            io.semantic_published();
        }
    }

    /// How long the staged quantum has awaited publication, if one is
    /// staged: the driver commits stale staged evidence on tick.
    pub(crate) fn staged_semantic_age(&self) -> Option<Duration> {
        self.staged_at.map(|at| at.elapsed())
    }

    /// Backdate the staged stamp (tests age a staged batch without
    /// sleeping through the staleness deadline).
    #[cfg(test)]
    pub(crate) fn age_staged_for_test(&mut self, at: Instant) {
        self.staged_at = Some(at);
    }

    /// Install tests-only substituted H0 I/O (see [`LaneTestIo`]):
    /// the lane then drives the real H0 decisions through it, so tests
    /// exercise the production finalize path without a live Session.
    /// Production never installs it.
    #[cfg(test)]
    pub(crate) fn install_test_io(&mut self, io: Box<dyn LaneTestIo>) {
        self.test_io = Some(io);
    }

    /// Whether the lane owns a live Session and H0 driver (or, in
    /// tests, substituted H0 I/O).
    pub(crate) fn is_live(&self) -> bool {
        #[cfg(test)]
        if self.test_io.is_some() {
            return true;
        }
        self.live.is_some()
    }

    /// Whether the terminal sequence finished (H0 stopped).
    pub(crate) fn is_finished(&self) -> bool {
        #[cfg(test)]
        if self.test_finished {
            return true;
        }
        self.live.as_ref().is_some_and(|live| live.finished)
    }

    /// Note calls shed without a route by one finalization (the
    /// finalizer counts them beside the aggregate unrouted gap).
    pub(crate) fn note_shed_calls(&mut self, shed: u64) {
        self.disclosed_calls_shed = self.disclosed_calls_shed.saturating_add(shed);
    }

    /// Take stashed oversized-report shed for the next finalize's
    /// disclosure gap. The stop-line count was already noted at the
    /// drop; this drains the labels once.
    pub(crate) fn take_oversized_drop_shed(&mut self) -> BTreeMap<&'static str, u64> {
        std::mem::take(&mut self.oversized_drop_shed)
    }

    /// Calls shed without a route across finalizations.
    #[cfg(test)]
    pub(crate) fn shed_calls_disclosed(&self) -> u64 {
        self.disclosed_calls_shed
    }

    /// Lifetime (collected, joined, shed, refused) call counters for
    /// the honest stop line. Joined is H0's cumulative router count;
    /// without a live lane only finalized sheds are known.
    pub(crate) fn semantic_stop_call_counts(&self) -> (u64, u64, u64, u64) {
        let (collected, joined, refused) = self.live.as_ref().map_or((0, 0, 0), |live| {
            (
                live.collected_calls,
                live.capture.router().counters().joined,
                live.scan_refusals,
            )
        });
        (collected, joined, self.disclosed_calls_shed, refused)
    }

    /// Lifetime per-reason scan-refusal counts (zeros without a live
    /// lane), index-aligned with [`SCAN_REFUSAL_LABELS`].
    pub(crate) fn scan_refusal_counts(&self) -> [u64; 12] {
        self.live
            .as_ref()
            .map_or([0; 12], |live| live.refusal_counts)
    }

    pub(crate) fn mark_collected_finish_requested(&mut self) {
        self.collected_finish_requested = true;
    }

    /// The authorization is constructor-private to the actual coordinator
    /// completion, not derived from a Copy batch revision or a Stop callback.
    pub(crate) fn complete_collected_finish(
        &mut self,
        completed: &crate::discovery::engine::inventory_coordinator::semantics::CompletedJointFinish,
        q: &crate::attach::CollectedFinishQ,
    ) -> Result<(), SemanticRefusal> {
        if !self.collected_finish_requested || self.is_finished() {
            return Err(SemanticRefusal::Unavailable);
        }
        #[cfg(test)]
        if let Some(io) = self.test_io.as_ref() {
            let mut matches = false;
            io.inspect_pending_h3(&mut |capture, _, producers| {
                matches = completed.matches_capture(capture, producers);
            });
            if !matches {
                return Err(SemanticRefusal::Unavailable);
            }
            self.test_finished = true;
            return Ok(());
        }
        let live = self
            .live
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        live.session
            .collected_finish_discovery_domain(q)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        let producers = live
            .session
            .drain_producers()
            .ok_or(SemanticRefusal::Unavailable)?;
        if !completed.matches_capture(&live.capture, &producers) {
            return Err(SemanticRefusal::Unavailable);
        }
        live.finished = true;
        live.continuity_cuts = live.capture.continuity_cuts();
        Ok(())
    }

    /// Begin native closes only after the driver's H0 Finish publication.
    /// No wait, success receipt or owner release occurs at this boundary.
    pub(crate) fn begin_owned_terminal_cleanup(&mut self) -> anyhow::Result<()> {
        if !self.is_live() {
            return Ok(());
        }
        anyhow::ensure!(self.is_finished(), "Detailed cleanup preceded H0 Finish");
        #[cfg(test)]
        if let Some(io) = self.test_io.as_mut() {
            return io.begin_terminal_cleanup();
        }
        self.live
            .as_mut()
            .unwrap()
            .session
            .begin_owned_producer_detach()
    }

    /// Consume the complete Detailed owner after Inventory's output/retirement
    /// boundary. Only a real joined successful receipt releases its maps,
    /// readers, H0 state, retained targets and residual Aya registry normally.
    /// Failure/second signal retains the whole owner for process exit, so an
    /// implicit Session/Ebpf destructor cannot introduce foreground blocking.
    pub(crate) fn finish_owned_terminal_cleanup(
        mut self,
        second_signal: &dyn Fn() -> bool,
        out: &mut dyn std::io::Write,
    ) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(mut io) = self.test_io.take() {
            let result = if self.test_finished {
                io.finish_terminal_cleanup(second_signal, out)
            } else {
                Err(anyhow::anyhow!("Detailed cleanup preceded H0 Finish"))
            };
            return release_terminal_owner(io, result);
        }
        let Some(mut live) = self.live.take() else {
            return Ok(());
        };
        let result = if live.finished {
            // A failed Finish publication withheld early start; after the
            // output boundary, negative cleanup can still retire ownership.
            live.session.begin_owned_producer_detach().and_then(|()| {
                live.session
                    .finish_owned_producer_detach_driven(second_signal, out)
            })
        } else {
            Err(anyhow::anyhow!("Detailed cleanup preceded H0 Finish"))
        };
        release_terminal_owner(live, result)
    }

    /// Release a promotion-installed lane into its wound-down Session
    /// for completion-polled retire (DR37 A→B). Consumes the lane like
    /// the terminal cleanup: drives the owned producer detach to its
    /// joined receipt under the caller's bound, then hands the live
    /// Session (detach joined, selection terminal, stop requested) to
    /// the completion minter, which proves genuine disposal on poll.
    /// Memory-only lane state (H0 capture, attachment, stash) drops
    /// here; only the Session needs joined disposal. A shell lane has
    /// no native session and yields `None` without a gap: nothing
    /// native ran, so nothing needs proving. Failure retains the whole
    /// owner for process exit through the existing forget path, like
    /// the terminal cleanup.
    pub(crate) fn into_wound_down_session(
        mut self,
        second_signal: &dyn Fn() -> bool,
        out: &mut dyn std::io::Write,
    ) -> anyhow::Result<Option<Session>> {
        #[cfg(test)]
        if let Some(mut io) = self.test_io.take() {
            // Mirror the terminal cleanup's substituted verdict, then
            // yield no native session: substituted lanes never ran one.
            let result = if self.test_finished {
                io.finish_terminal_cleanup(second_signal, out)
            } else {
                Err(anyhow::anyhow!("Detailed cleanup preceded H0 Finish"))
            };
            release_terminal_owner(io, result)?;
            return Ok(None);
        }
        let Some(mut live) = self.live.take() else {
            return Ok(None);
        };
        let result = if live.finished {
            // A failed Finish publication withheld early start; the
            // wind-down still drives the owned detach before handing
            // the Session to the minter.
            live.session.begin_owned_producer_detach().and_then(|()| {
                live.session
                    .finish_owned_producer_detach_driven(second_signal, out)
            })
        } else {
            Err(anyhow::anyhow!("Detailed cleanup preceded H0 Finish"))
        };
        match result {
            Ok(()) => Ok(Some(live.session)),
            Err(error) => release_terminal_owner(live, Err(error)).map(|()| None),
        }
    }

    /// Whether this lane owns a Joint machine (§8.3).
    #[cfg_attr(not(test), allow(dead_code))] // The joint driver consumes the terminal API.
    pub(crate) fn has_joint_machine(&self) -> bool {
        self.live
            .as_deref()
            .is_some_and(|live| live.joint_machine.is_some())
    }

    /// Whether the lane retains a Joint frame (§8.3): the test seam,
    /// checked first, or a live machine on an unfinished lane. The
    /// machine phase itself is joint-module state; until Finish
    /// publication marks the lane finished, any lane with a machine
    /// may still hold its frame. Conservative while unfinished, exact
    /// once published; lanes without a machine read false.
    #[cfg_attr(not(test), allow(dead_code))] // The joint driver consumes the terminal API.
    pub(crate) fn has_joint_frame(&self) -> bool {
        #[cfg(test)]
        if self.test_joint_frame {
            return true;
        }
        self.has_joint_machine() && !self.is_finished()
    }

    /// Force the retained-frame answer for the retire-gate tests.
    #[cfg(test)]
    pub(crate) fn set_test_joint_frame(&mut self, on: bool) {
        self.test_joint_frame = on;
    }

    /// Non-consuming wound-down poll for the Joint driver (§8.3):
    /// requires a finished, non-retained lane; begins owned terminal
    /// cleanup (idempotent); reaps the owned detach without joining.
    /// `Pending` keeps the worker and reports false; `Complete`
    /// closes retired graph files (256 per call) and reports true
    /// only once the chain drains. An Unproved detach or an
    /// exit-retained lane refuses; the first error stays owned.
    #[cfg_attr(not(test), allow(dead_code))] // The joint driver consumes the terminal API.
    pub(crate) fn poll_wound_down(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
    ) -> Result<bool, SemanticRefusal> {
        if self.exit_retained {
            return Err(SemanticRefusal::Unavailable);
        }
        if !self.is_finished() {
            return Err(SemanticRefusal::Unavailable);
        }
        self.begin_owned_terminal_cleanup()
            .map_err(|_| SemanticRefusal::Unavailable)?;
        #[cfg(test)]
        if let Some(io) = self.test_io.as_mut() {
            let progress = io
                .poll_terminal_detach(&mut std::io::sink())
                .map_err(|_| SemanticRefusal::Unavailable)?;
            return match progress {
                ProducerDetachProgress::Pending => Ok(false),
                ProducerDetachProgress::Complete => {
                    let drained = coordinator.close_retired_graph_files(256);
                    if drained {
                        self.wound_down_complete = true;
                    }
                    Ok(drained)
                }
            };
        }
        let Some(live) = self.live.as_mut() else {
            // No native session: nothing to detach; still drain the
            // shared retired-file chain the Engine may hold.
            let drained = coordinator.close_retired_graph_files(256);
            if drained {
                self.wound_down_complete = true;
            }
            return Ok(drained);
        };
        match live
            .session
            .poll_owned_producer_detach(&mut std::io::sink())
        {
            Ok(ProducerDetachProgress::Pending) => Ok(false),
            Ok(ProducerDetachProgress::Complete) => {
                let drained = coordinator.close_retired_graph_files(256);
                if drained {
                    self.wound_down_complete = true;
                }
                Ok(drained)
            }
            Err(_) => Err(SemanticRefusal::Unavailable),
        }
    }

    /// Take the wound-down Session for completion-polled retire
    /// (§8.3): `Some` only after the owned detach joined, Finish
    /// published and no Joint frame retained. Memory-only lane state
    /// drops with the handoff, like the promotion wind-down. An
    /// unfinished or framed lane yields `None`; a finished frameless
    /// lane without a recorded wound-down refuses, enforcing the
    /// poll-before-take order in-API. An exit-retained lane refuses.
    #[cfg_attr(not(test), allow(dead_code))] // The joint driver consumes the terminal API.
    pub(crate) fn take_joined_session(&mut self) -> Result<Option<Session>, SemanticRefusal> {
        if self.exit_retained {
            return Err(SemanticRefusal::Unavailable);
        }
        if !self.is_finished() || self.has_joint_frame() {
            return Ok(None);
        }
        if !self.wound_down_complete {
            return Err(SemanticRefusal::Unavailable);
        }
        #[cfg(test)]
        if self.test_io.is_some() {
            // Substituted lanes never ran a native session.
            return Ok(None);
        }
        let Some(live) = self.live.as_mut() else {
            return Ok(None);
        };
        // A Pending poll keeps the worker; only Complete hands over.
        match live
            .session
            .poll_owned_producer_detach(&mut std::io::sink())
        {
            Ok(ProducerDetachProgress::Complete) => {
                let live = self.live.take().expect("session observed above");
                Ok(Some(live.session))
            }
            Ok(ProducerDetachProgress::Pending) | Err(_) => Ok(None),
        }
    }

    /// Finite stop on the lane (I2, §8.4): admitted only on a latched
    /// Finish disposition. A refused graph also latches that
    /// disposition first (its finish progress reports failed), so no
    /// reachable refusal bypasses this gate. Builds the terminal
    /// batch through the H0 stop — unresolved routes expire into
    /// terminal negatives — justifies the abandon with `reason`,
    /// marks the lane finished and exit-retained, and drops nothing:
    /// later wound-down and take refuse forever and the Session never
    /// begins owned detach. A second call refuses: the first abandon
    /// already exit-retained the lane.
    #[cfg_attr(not(test), allow(dead_code))] // The joint driver consumes the terminal API.
    pub(crate) fn abandon_finish_for_exit(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        reason: &'static str,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        if self.exit_retained {
            return Err(SemanticRefusal::Unavailable);
        }
        if !self.joint_finish_disposition_required() {
            return Err(SemanticRefusal::Unavailable);
        }
        let domain = self.domain;
        #[cfg(test)]
        if let Some(test) = self.test_io.as_mut() {
            let batch = test.finish(domain);
            self.finish_for_exit();
            coordinator.note_scope_gap("joint finish abandoned for exit".into(), reason.into());
            return Ok(batch);
        }
        let batch = match self.live.as_mut() {
            Some(live) => {
                let live = &mut **live;
                let mut io = LiveStopIo {
                    session: &mut live.session,
                    capture: &mut live.capture,
                    pins: Vec::new(),
                    domain,
                    stash: None,
                    collected: &mut live.collected_calls,
                };
                io.finish_h0()
            }
            None => {
                SemanticBatch::from_tick_report(domain, TickReport::default(), Vec::new(), now_ns())
                    .map_err(|_| SemanticRefusal::Unavailable)?
            }
        };
        self.finish_for_exit();
        coordinator.note_scope_gap("joint finish abandoned for exit".into(), reason.into());
        Ok(batch)
    }

    /// Mark the lane finished and exit-retained: nothing else moves.
    #[cfg_attr(not(test), allow(dead_code))] // The joint driver consumes the terminal API.
    fn finish_for_exit(&mut self) {
        if let Some(live) = self.live.as_mut() {
            live.finished = true;
        }
        #[cfg(test)]
        {
            self.test_finished = true;
        }
        self.exit_retained = true;
    }

    /// One H0 collect→audit→route quantum over the bound callers' stable
    /// custody Arcs. The only producer of lane call batches; a gated,
    /// finished or shell lane refuses instead of inventing calls.
    pub(crate) fn tick(
        &mut self,
        bindings: &[SemanticCallerBinding],
    ) -> Result<SemanticBatch, SemanticRefusal> {
        let domain = self.domain;
        #[cfg(test)]
        if let Some(test) = self.test_io.as_mut() {
            if self.test_gated || self.test_finished {
                return Err(SemanticRefusal::Unavailable);
            }
            // Targets resolve through the substituted I/O; the H0 tick,
            // stash merge and batch construction are the shared ones.
            test.tick_targets(
                &bindings
                    .iter()
                    .filter(|binding| binding.scope_current())
                    .map(SemanticCallerBinding::pin)
                    .collect::<Vec<_>>(),
            );
            return test.tick(domain);
        }
        let Some(live) = self.live.as_mut() else {
            return Err(SemanticRefusal::Unavailable);
        };
        if live.gated || live.finished || live.joint_machine.is_some() {
            return Err(SemanticRefusal::Unavailable);
        }
        let pins: Vec<Arc<PidPin>> = bindings
            .iter()
            .filter(|binding| binding.scope_current())
            .map(SemanticCallerBinding::pin)
            .collect();
        let mut report = live
            .capture
            .tick(&mut live.session, &pins)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        live.ticks += 1;
        live.scan_refusals = live
            .scan_refusals
            .saturating_add(report.scan_refusals.len() as u64);
        count_scan_refusals(&mut live.refusal_counts, &report.scan_refusals);
        live.collected_calls = live
            .collected_calls
            .saturating_add(report.collected_calls as u64);
        live.continuity_cuts = live.capture.continuity_cuts();
        // Quiet no-call registrations stashed since the last tick join
        // this batch behind its own fresh evidence.
        let shed = merge_stash_into_report(&mut live.stashed_refresh, &mut report);
        live.scan_refusals = live.scan_refusals.saturating_add(shed);
        let counted = unjoined_shed_counts(report.outcomes());
        match SemanticBatch::from_tick_report(domain, report, Vec::new(), now_ns()) {
            Ok(batch) => Ok(batch),
            Err(_) => {
                // Defensive: the report exceeded batch caps (one tick
                // holds at most records + pending resolutions, far below
                // the caps). Its collected calls are already counted
                // above, so its unjoined calls shed here with the
                // oversized label; the next finalize discloses them.
                self.stash_oversized_shed(counted);
                Err(SemanticRefusal::Unavailable)
            }
        }
    }

    /// Count a refused report's unjoined calls into shed now and stash
    /// their route labels for the next finalize's disclosure gap.
    fn stash_oversized_shed(&mut self, counted: BTreeMap<&'static str, u64>) {
        for (label, count) in counted {
            let slot = self.oversized_drop_shed.entry(label).or_default();
            *slot = slot.saturating_add(count);
            self.disclosed_calls_shed = self.disclosed_calls_shed.saturating_add(count);
        }
    }

    /// Route only the machine's original retained records. This never polls
    /// EVENTS; empty retries resolve the same Capture jobs and merge its stash.
    #[allow(dead_code)] // Actual Session bridge; the ordinary driver remains inactive.
    fn tick_collected(
        &mut self,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.tick_collected_inner(bindings, raw, None)
    }

    #[allow(dead_code)] // Actual Session bridge; the ordinary driver remains inactive.
    fn tick_collected_at_q(
        &mut self,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
        q: &crate::attach::CollectedFinishQ,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.tick_collected_inner(bindings, raw, Some(q))
    }

    fn tick_collected_inner(
        &mut self,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
        q: Option<&crate::attach::CollectedFinishQ>,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        let live = self
            .live
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        if live.finished || (live.gated && q.is_none()) {
            return Err(SemanticRefusal::Unavailable);
        }
        if let Some(q) = q {
            live.session
                .joint_collection_io_at_q(q)
                .map_err(|_| SemanticRefusal::Unavailable)?;
        }
        let pins: Vec<_> = bindings
            .iter()
            .filter(|binding| binding.scope_current())
            .map(SemanticCallerBinding::pin)
            .collect();
        let mut report = live
            .capture
            .tick_collected(&mut live.session, &pins, raw)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        live.ticks = live.ticks.saturating_add(1);
        live.scan_refusals = live
            .scan_refusals
            .saturating_add(report.scan_refusals.len() as u64);
        count_scan_refusals(&mut live.refusal_counts, &report.scan_refusals);
        live.collected_calls = live
            .collected_calls
            .saturating_add(report.collected_calls as u64);
        live.continuity_cuts = live.capture.continuity_cuts();
        let shed = merge_stash_into_report(&mut live.stashed_refresh, &mut report);
        live.scan_refusals = live.scan_refusals.saturating_add(shed);
        let counted = unjoined_shed_counts(report.outcomes());
        match SemanticBatch::from_tick_report(self.domain, report, Vec::new(), now_ns()) {
            Ok(batch) => Ok(batch),
            Err(_) => {
                self.stash_oversized_shed(counted);
                Err(SemanticRefusal::Unavailable)
            }
        }
    }

    /// One bounded no-call refresh for an unbound candidate pin through
    /// the same owned Session: the accepted scan's images come back as
    /// binding hints, still to be re-proven by the coordinator proof.
    /// The images are claims only; custody and attachment re-verify. The
    /// scan's receipts stash for the next tick batch, so a quiet
    /// provider's proof registers instead of dropping.
    #[cfg(test)]
    pub(crate) fn refresh_candidate(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> Result<Vec<ImageIdentity>, SemanticRefusal> {
        self.refresh_candidate_with_custody(pin, slot)
            .map(|(images, _)| images)
    }

    /// The custody-preserving refresh behind [`refresh_candidate`](Self::refresh_candidate):
    /// the same images plus the effective custody Arc H0 retained for
    /// them. An accepted refresh after a failed bind adopts H0's retained
    /// Arc instead of the fresh duplicate, so the stored binding must
    /// share the returned Arc (H0's `ptr_eq` gates refuse any other).
    /// Compatibility wrapper: the plain refusal without the firing
    /// site. Production admission calls the inner function directly;
    /// the test seam keeps this signature.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn refresh_candidate_with_custody(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
    ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
        self.refresh_candidate_with_custody_inner(pin, slot, None, None)
            .map_err(|error| error.refusal())
    }

    fn refresh_candidate_with_custody_inner(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
        collected: Option<(
            &mut RawJointQuantum,
            &JournalAdapter,
            &crate::attach::SessionDrainProducers,
        )>,
        terminal: Option<&crate::attach::CollectedFinishQ>,
    ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), AdmissionPreparationError> {
        use AdmissionUnavailableSite as Site;
        #[cfg(test)]
        if let Some(test) = self.test_io.as_mut() {
            if self.test_finished || (self.test_gated && terminal.is_none()) {
                return Err(AdmissionPreparationError::unavailable(
                    Site::RefreshTestSeam,
                ));
            }
            return match collected {
                Some((raw, adapter, producers)) => {
                    test.refresh_collected(pin, slot, raw, adapter, producers)
                }
                None => test.refresh(pin, slot),
            }
            .map_err(|refusal| match refusal {
                SemanticRefusal::Unavailable => {
                    AdmissionPreparationError::unavailable(Site::RefreshTestSeam)
                }
                other => AdmissionPreparationError::refused(other),
            });
        }
        let Some(live) = self.live.as_mut() else {
            return Err(AdmissionPreparationError::unavailable(Site::RefreshNoLive));
        };
        if live.finished || (live.gated && terminal.is_none()) {
            return Err(AdmissionPreparationError::unavailable(
                Site::RefreshFinishedOrGated,
            ));
        }
        if let Some(q) = terminal {
            live.session
                .joint_collection_io_at_q(q)
                .map_err(|_| AdmissionPreparationError::unavailable(Site::RefreshCollectionIo))?;
        }
        let mut report = match collected {
            Some((raw, adapter, producers)) => live.capture.refresh_collected(
                &mut live.session,
                pin.clone(),
                slot,
                raw,
                adapter,
                producers,
            ),
            None => live.capture.refresh(&mut live.session, pin.clone(), slot),
        }
        .map_err(|_| AdmissionPreparationError::unavailable(Site::RefreshFailed))?;
        live.scan_refusals = live
            .scan_refusals
            .saturating_add(report.scan_refusals.len() as u64);
        count_scan_refusals(&mut live.refusal_counts, &report.scan_refusals);
        // The minted receipt carries the Arc H0 actually retained
        // (adopted across a failed-bind retry, else the passed pin).
        let effective = effective_refresh_custody(&report, pin);
        let (images, shed) = stash_refresh_report(&mut live.stashed_refresh, &mut report);
        live.scan_refusals = live.scan_refusals.saturating_add(shed);
        Ok((images, effective))
    }

    /// Bootstrap from H0's accepted original-custody scan, independent of
    /// Inventory's native identity domain. Every fallible owner/provider read
    /// happens here, before cgroup's final membership sample.
    pub(crate) fn prepare_caller_admission(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
        module: &ModuleKey,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<PreparedSemanticAdmission, AdmissionPreparationError> {
        let (_, effective) = self.refresh_candidate_with_custody_inner(pin, slot, None, None)?;
        self.prepare_refreshed_caller_admission(effective, slot, module, reserve)
    }

    /// The same admission consumer, with New tied to the original collected
    /// prefix before any ordinary H0 input is acknowledged.
    #[allow(clippy::too_many_arguments)] // Original collection and existing owners are borrowed, never duplicated.
    pub(crate) fn prepare_caller_admission_collected(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
        module: &ModuleKey,
        raw: &mut RawJointQuantum,
        adapter: &JournalAdapter,
        producers: &crate::attach::SessionDrainProducers,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<PreparedSemanticAdmission, AdmissionPreparationError> {
        raw.validate_refresh(adapter, producers).map_err(|_| {
            AdmissionPreparationError::unavailable(
                AdmissionUnavailableSite::CollectedRefreshInvalid,
            )
        })?;
        let (_, effective) = self.refresh_candidate_with_custody_inner(
            pin,
            slot,
            Some((raw, adapter, producers)),
            None,
        )?;
        self.prepare_refreshed_caller_admission(effective, slot, module, reserve)
    }

    #[allow(clippy::too_many_arguments)] // Same original/producers/Q precede the retained provider query.
    pub(crate) fn prepare_caller_admission_collected_at_q(
        &mut self,
        pin: Arc<PidPin>,
        slot: u32,
        module: &ModuleKey,
        raw: &mut RawJointQuantum,
        adapter: &JournalAdapter,
        producers: &crate::attach::SessionDrainProducers,
        discovery: &crate::events::DiscoveryDomain,
        q: &crate::attach::CollectedFinishQ,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<PreparedSemanticAdmission, AdmissionPreparationError> {
        raw.validate_refresh(adapter, producers).map_err(|_| {
            AdmissionPreparationError::unavailable(
                AdmissionUnavailableSite::CollectedRefreshInvalid,
            )
        })?;
        raw.validate_collected_q(producers, discovery, q)
            .map_err(|_| {
                AdmissionPreparationError::unavailable(AdmissionUnavailableSite::CollectedQInvalid)
            })?;
        let (_, effective) = self.refresh_candidate_with_custody_inner(
            pin,
            slot,
            Some((raw, adapter, producers)),
            Some(q),
        )?;
        self.prepare_refreshed_caller_admission(effective, slot, module, reserve)
    }

    fn prepare_refreshed_caller_admission(
        &mut self,
        effective: Arc<PidPin>,
        slot: u32,
        module: &ModuleKey,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<PreparedSemanticAdmission, AdmissionPreparationError> {
        #[cfg(test)]
        let receipt = if let Some(test) = self.test_io.as_mut() {
            test.take_refresh_receipt(&effective, slot)
        } else {
            self.live
                .as_mut()
                .and_then(|live| live.stashed_refresh.take_for_admission(&effective, slot))
        };
        #[cfg(not(test))]
        let receipt = self
            .live
            .as_mut()
            .and_then(|live| live.stashed_refresh.take_for_admission(&effective, slot));
        let receipt = receipt.ok_or(AdmissionPreparationError::unavailable(
            AdmissionUnavailableSite::NoReceipt,
        ))?;

        let mut validation = TickReport::default();
        let result = (|| {
            // Preserve the owned refresh's existing preflight/refusal order.
            // Subject errors land in the provider result (the OwnerRefused
            // surface names them at consume); only scan/receipt failures
            // fail preparation itself.
            let subject = self.current_provider_subject(&receipt, &effective, slot, module)?;
            let (_, provider) = self
                .validate_current_provider_subject(&receipt, Ok(subject), &mut validation, reserve)
                .map_err(|_| SemanticRefusal::ProviderInstanceUnproven)?;
            provider
        })();
        // Validation may consume invalidations even on refusal. Keep them
        // beside the original receipt, never copy that receipt into two paths.
        self.stash_admission_evidence(Vec::new(), validation.into_outcomes());
        Ok(PreparedSemanticAdmission {
            receipt,
            provider: result,
        })
    }

    fn current_provider_subject<'a>(
        &mut self,
        receipt: &'a CurrentPartitionReceipt,
        effective: &Arc<PidPin>,
        slot: u32,
        module: &'a ModuleKey,
    ) -> Result<CurrentProviderSubject<'a>, SemanticRefusal> {
        #[cfg(test)]
        if let Some(test) = self.test_io.as_mut() {
            test.validate_attachment(&self.subset)?;
        } else {
            let live = self.live.as_ref().ok_or(SemanticRefusal::Unavailable)?;
            live.session
                .validate_semantic_set(&live.attached)
                .map_err(|_| SemanticRefusal::Attachment)?;
        }
        #[cfg(not(test))]
        {
            let live = self.live.as_ref().ok_or(SemanticRefusal::Unavailable)?;
            live.session
                .validate_semantic_set(&live.attached)
                .map_err(|_| SemanticRefusal::Attachment)?;
        }
        let endpoint = receipt.endpoint();
        if receipt.domain() != self.domain
            || !Arc::ptr_eq(receipt.original_pin(), effective)
            || !self.subset.proves_provider_module(endpoint.object, module)
            || !receipt
                .watched()
                .same_object_as(self.subset.pins(), endpoint.object)
            || receipt.watched().check_unchanged() != Ok(true)
            || !self
                .subset
                .required()
                .get(&endpoint.object)
                .is_some_and(|required| required.contains(&slot))
            || !self.subset.plan().slots.iter().any(|actual| {
                actual.index == slot
                    && actual.object == endpoint.object
                    && actual.file_offset == endpoint.offset
            })
        {
            return Err(SemanticRefusal::ProviderInstanceUnproven);
        }
        Ok(CurrentProviderSubject { receipt, module })
    }

    fn validate_current_provider_subject(
        &mut self,
        receipt: &CurrentPartitionReceipt,
        subject: Result<CurrentProviderSubject<'_>, SemanticRefusal>,
        report: &mut TickReport,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<
        (
            LaneCoverage,
            Result<SemanticProviderTarget, SemanticRefusal>,
        ),
        CurrentReceiptRefusal,
    > {
        // Exactly the normal conversion's actual owner validation. Its
        // negatives remain in the caller's SAME report, even on refusal.
        let coverage = self.validate_current(receipt, report)?;
        let provider = subject.and_then(|subject| {
            let bytes =
                SemanticProviderTarget::copy_charge(subject.module, subject.receipt.watched())
                    .ok_or(SemanticRefusal::ProviderStorage)?;
            let storage = reserve(bytes).map_err(|_| SemanticRefusal::ProviderStorage)?;
            Ok(SemanticProviderTarget {
                module: subject.module.clone(),
                endpoint: subject.receipt.endpoint(),
                _retained: subject.receipt.watched().share(),
                _storage: storage,
            })
        });
        Ok((coverage, provider))
    }

    /// Validate this original Current once for conversion and, when a
    /// physical-context label exists, for provider admission. This path never
    /// takes/stashes a receipt or queries a replacement New.
    pub(crate) fn validate_current_for_provider(
        &mut self,
        receipt: &CurrentPartitionReceipt,
        module: Option<&ModuleKey>,
        report: &mut TickReport,
        reserve: impl FnOnce(usize) -> Result<ResourceLease, SemanticResourceRefusal>,
    ) -> Result<
        (
            LaneCoverage,
            Result<SemanticProviderTarget, SemanticRefusal>,
        ),
        CurrentReceiptRefusal,
    > {
        let subject = match module {
            Some(module) => self.current_provider_subject(
                receipt,
                receipt.original_pin(),
                receipt.attachment_slot(),
                module,
            ),
            None => Err(SemanticRefusal::ProviderInstanceUnproven),
        };
        self.validate_current_provider_subject(receipt, subject, report, reserve)
    }

    pub(crate) fn deliver_admission_receipt(&mut self, receipt: CurrentPartitionReceipt) {
        self.stash_admission_evidence(vec![receipt], Vec::new());
    }

    fn stash_admission_evidence(
        &mut self,
        receipts: Vec<CurrentPartitionReceipt>,
        outcomes: Vec<TickOutcome>,
    ) {
        #[cfg(test)]
        if let Some(test) = self.test_io.as_mut() {
            test.stash_admission_evidence(receipts, outcomes);
            return;
        }
        if let Some(live) = self.live.as_mut() {
            let shed = live.stashed_refresh.push_all(receipts, outcomes);
            live.scan_refusals = live.scan_refusals.saturating_add(shed);
        }
    }

    pub(crate) fn validate_collected_preparation(
        &self,
        raw: &RawJointQuantum,
    ) -> Result<(), SemanticRefusal> {
        #[cfg(test)]
        if let Some(test) = self.test_io.as_ref() {
            return test.validate_collected_preparation(raw);
        }
        let live = self.live.as_ref().ok_or(SemanticRefusal::Unavailable)?;
        if live.finished {
            return Err(SemanticRefusal::Unavailable);
        }
        live.capture
            .validate_collected_preparation(raw)
            .map_err(|_| SemanticRefusal::Unavailable)
    }

    /// Extend only the original collected quantum through this lane's real
    /// physical-cut path. The shell cannot manufacture a collected report.
    pub(crate) fn apply_physical_gaps_collected(
        &mut self,
        gaps: Vec<PhysicalSemanticGap>,
        raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.validate_collected_preparation(raw)?;
        #[cfg(test)]
        let gaps = {
            let mut gaps = gaps;
            if let Some(test) = self.test_io.as_mut() {
                return test
                    .physical_gaps_collected(self.domain, &mut gaps, raw)
                    .unwrap_or(Err(SemanticRefusal::Unavailable));
            }
            gaps
        };
        let live = self.live.as_mut().ok_or(SemanticRefusal::Unavailable)?;
        if live.finished {
            return Err(SemanticRefusal::Unavailable);
        }
        let report = live
            .capture
            .apply_physical_gaps_collected(&mut live.session, gaps, raw)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        live.continuity_cuts = live.capture.continuity_cuts();
        let negatives = report
            .outcomes()
            .iter()
            .filter_map(|outcome| match outcome {
                TickOutcome::Invalidation(invalidation)
                    if matches!(invalidation.scope(), InvalidationScope::FaultEra) =>
                {
                    invalidation.position()
                }
                _ => None,
            })
            .max()
            .map(|ordinal| vec![LaneNegative::CutBarrier { ordinal }])
            .unwrap_or_default();
        SemanticBatch::from_tick_report(self.domain, report, negatives, now_ns())
    }

    pub(crate) fn apply_physical_gaps(
        &mut self,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        #[cfg(test)]
        let gaps = {
            let mut gaps = gaps;
            if let Some(test) = self.test_io.as_mut()
                && let Some(batch) = test.physical_gaps(self.domain, &mut gaps)
            {
                return batch;
            }
            gaps
        };
        if let Some(live) = self.live.as_mut() {
            let domain = self.domain;
            if live.finished {
                return Err(SemanticRefusal::Unavailable);
            }
            let report = live
                .capture
                .apply_physical_gaps(&mut live.session, gaps)
                .map_err(|_| SemanticRefusal::Unavailable)?;
            live.continuity_cuts = live.capture.continuity_cuts();
            // The cut's barrier is H0-timeline evidence: the maximum
            // fault-era position this publication allocated, after all
            // issued records. The finalizer carries it into the queued
            // ordinary quantum.
            let barrier = report
                .outcomes()
                .iter()
                .filter_map(|outcome| match outcome {
                    TickOutcome::Invalidation(invalidation)
                        if matches!(invalidation.scope(), InvalidationScope::FaultEra) =>
                    {
                        invalidation.position()
                    }
                    _ => None,
                })
                .max();
            let negatives = barrier
                .map(|ordinal| vec![LaneNegative::CutBarrier { ordinal }])
                .unwrap_or_default();
            return SemanticBatch::from_tick_report(domain, report, negatives, now_ns());
        }
        self.apply_physical_gaps_shell(gaps)
    }

    /// The shell cut: records adjudication for tests without a Session.
    /// Production without a live lane refuses, and the finalizer treats
    /// the refusal as a cut failure, preserving broad Inventory.
    fn apply_physical_gaps_shell(
        &mut self,
        gaps: Vec<PhysicalSemanticGap>,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        #[cfg(not(test))]
        {
            let _ = gaps;
            Err(SemanticRefusal::Unavailable)
        }
        #[cfg(test)]
        {
            if self.fail_next_cut {
                self.fail_next_cut = false;
                self.recorded_gaps.extend(gaps);
                return Err(SemanticRefusal::Unavailable);
            }
            self.recorded_gaps.extend(gaps);
            let mut negatives = Vec::new();
            if let Some(ordinal) = self.scripted_barrier.take() {
                negatives.push(LaneNegative::CutBarrier { ordinal });
            }
            Ok(SemanticBatch::scripted(self.domain, negatives, 0))
        }
    }

    /// The actual-owner receipt validator: the live lane re-proves
    /// custody, attachment, epoch and partition against the Session's
    /// retained binding/router state through H0. The shell has no
    /// Session to re-prove through and refuses. In tests with
    /// substituted H0 I/O, the same H0 validation runs through it.
    pub(crate) fn validate_current(
        &mut self,
        receipt: &CurrentPartitionReceipt,
        report: &mut TickReport,
    ) -> Result<LaneCoverage, CurrentReceiptRefusal> {
        #[cfg(test)]
        if let Some(test) = self.test_io.as_mut() {
            test.validate_current(receipt, report)?;
            return Ok(LaneCoverage::from_validated_receipt(receipt));
        }
        let Some(live) = self.live.as_mut() else {
            return Err(CurrentReceiptRefusal::Custody);
        };
        live.capture
            .validate_current(&mut live.session, receipt, report)?;
        Ok(LaneCoverage::from_validated_receipt(receipt))
    }

    /// Gaps the shell consumed, in order. Tests assert adjudication
    /// reached the lane; the gaps stay opaque.
    #[cfg(test)]
    pub(crate) fn recorded_gaps(&self) -> &[PhysicalSemanticGap] {
        &self.recorded_gaps
    }

    /// Script the next cut's barrier ordinal (test H0-timeline evidence).
    #[cfg(test)]
    pub(crate) fn script_cut_barrier(&mut self, ordinal: u64) {
        self.scripted_barrier = Some(ordinal);
    }

    /// Fail the next cut (test cut-failure handling).
    #[cfg(test)]
    pub(crate) fn fail_cut_once(&mut self) {
        self.fail_next_cut = true;
    }

    /// Drain recorded gaps (test isolation between publications).
    #[cfg(test)]
    pub(crate) fn take_recorded_gaps(&mut self) -> Vec<PhysicalSemanticGap> {
        std::mem::take(&mut self.recorded_gaps)
    }

    /// Record the conversion barrier the finalizer carried into this
    /// batch's queued calls (finalizer side only).
    #[cfg(test)]
    pub(crate) fn note_conversion_barrier(&mut self, barrier: Option<u64>) {
        self.last_conversion_barrier = barrier;
    }

    /// Drain the last conversion barrier (test isolation).
    #[cfg(test)]
    pub(crate) fn take_last_conversion_barrier(&mut self) -> Option<u64> {
        self.last_conversion_barrier.take()
    }
}

/// Bounded terminal drain quanta per owned cursor (H0's fair terminal
/// poll bound) and records per quantum (one H0 collection quantum).
pub(crate) const TERMINAL_DRAIN_QUANTA: usize = 16;
pub(crate) const TERMINAL_DRAIN_QUANTUM: usize = 1024;

/// Keep the complete original envelope on any unproved terminal result. This
/// is process-exit retention, never a fabricated native settlement receipt.
fn release_terminal_owner<T>(owner: T, result: anyhow::Result<()>) -> anyhow::Result<()> {
    if result.is_ok() {
        drop(owner);
    } else {
        std::mem::forget(owner);
    }
    result
}

/// Bound on terminal batches staged ahead of commit: one
/// [`TERMINAL_DRAIN_QUANTA`] window each for the quiesce wait and the
/// post-Q drain, plus one spare. The terminal Finish batch bypasses the
/// stage: it commits separately after H0 stops.
#[cfg(test)]
pub(crate) const TERMINAL_STAGED_BATCH_CAP: usize = 2 * TERMINAL_DRAIN_QUANTA + 1;

/// Tests-only bounded terminal staging: the scripted stop tests feed
/// `on_batch` here to pin bound/order/Finish-last behavior. Production
/// commits every drained batch promptly during the drain instead of
/// staging through the wait, so drained receipts never expire ahead
/// of validation; the quiesce wait is time-budgeted, not
/// batch-budgeted, so a noisy producer can deliver an unbounded number
/// of batches before Q, and beyond [`TERMINAL_STAGED_BATCH_CAP`] the
/// oldest staged batch sheds (counted) so staging stays bounded.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct TerminalBatchStage {
    staged: std::collections::VecDeque<SemanticBatch>,
    shed: usize,
}

#[cfg(test)]
impl TerminalBatchStage {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, batch: SemanticBatch) {
        if self.staged.len() >= TERMINAL_STAGED_BATCH_CAP {
            self.staged.pop_front();
            self.shed += 1;
        }
        self.staged.push_back(batch);
    }

    /// Batches currently staged, at most [`TERMINAL_STAGED_BATCH_CAP`].
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.staged.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// Oldest batches shed beyond the cap: the caller discloses this
    /// count through the audited gap path.
    pub(crate) fn shed(&self) -> usize {
        self.shed
    }

    pub(crate) fn into_batches(self) -> impl Iterator<Item = SemanticBatch> {
        self.staged.into_iter()
    }
}

/// One bounded cursor drain's outcome: records consumed (routed calls
/// come back as batches through `on_batch`; the remainder counts as
/// unrouted), whether the producer moved past Q, whether work remains,
/// and whether the read itself failed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LaneDrainOutcome {
    pub records: u64,
    pub post_q: bool,
    pub backlog: bool,
    pub failed: bool,
}

/// The userspace terminal surface the stop orchestration drives, so
/// ordinary tests run the same code against a scripted fake. The live
/// implementation owns the lane's Session and H0 driver; every method
/// below touches only that lane's own cursors, never Inventory-domain
/// authority and never another consumer.
pub(crate) trait SemanticStopIo {
    /// Gate the producer immediately (idempotent).
    fn request_stop(&self);
    fn quiescent(&self) -> bool;
    /// One bounded audited H0 quantum plus servicing of the lane's own
    /// DISCOVERY cursor (serviced, never staged anywhere). `None` is a
    /// quiet tick; `Err` counts a quiesce refusal and the wait continues.
    fn service_quantum(&mut self) -> Result<Option<SemanticBatch>, SemanticRefusal>;
    /// Current (consumer, producer) for the owned EVENTS and DISCOVERY
    /// cursors, in that order. `None` is an unreadable ring.
    fn positions(&mut self) -> Option<[(usize, usize); 2]>;
    /// Bounded EVENTS remainder drain to `stop`: records H0 never
    /// routed count as unrouted; post-Q movement is reported, never
    /// silently consumed.
    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
    /// Bounded DISCOVERY drain to `stop`: cursor servicing only, the
    /// records feed no authority.
    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
    /// H0 `stop()` exactly once: terminal negatives and the semantic
    /// Finish batch. Called only after every drained batch was consumed
    /// and published, so no eligible call sits behind Stopped.
    fn finish_h0(&mut self) -> SemanticBatch;
    /// Actual successful continuity-cut advances (count only). Only the
    /// tests-only composed stop reads it; production summaries read the
    /// live capture directly.
    #[cfg(test)]
    fn continuity_cuts(&self) -> u64;
}

/// The terminal sequence's outcome. `q` holds the proven producer
/// positions; `final_drain` is true only when quiescence was proven,
/// both owned cursors drained exactly to Q, no post-Q writer appeared
/// and no semantic loss was declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SemanticStopSummary {
    pub quiesced: bool,
    pub waited: Duration,
    pub q: Option<TerminalQuiescence>,
    pub drain_batches: usize,
    pub quiesce_refusals: u64,
    pub post_q_events: bool,
    pub post_q_discovery: bool,
    pub unrouted_returns: u64,
    pub continuity_cuts: u64,
    pub semantic_loss: bool,
    pub final_drain: bool,
}

/// The terminal drain phases over any [`SemanticStopIo`]: gate
/// immediately, run bounded audited H0 work while waiting up to
/// `budget` for Q, capture both producer positions at proven Q and drain
/// the same owned cursors to those positions in bounded quanta. H0 keeps
/// running: every drained batch reaches `on_batch` (the caller finalizes,
/// consumes and publishes each) before any Finish batch is produced, so
/// the caller commits drained batches before stopping H0. On unproven Q
/// or a read failure, positive history is preserved, semantic loss is
/// declared, and only one explicitly bounded poll drains each cursor.
///
/// Tests-only: scripted stop tests drive the phases through fakes.
/// Production drains through
/// [`AttestedSemanticLane::run_semantic_drain_committing`], which
/// mirrors these phases while committing every batch promptly.
#[cfg(test)]
pub(crate) fn run_semantic_drain(
    io: &mut impl SemanticStopIo,
    budget: Duration,
    quanta: usize,
    quantum: usize,
    mut now: impl FnMut() -> Instant,
    mut on_batch: impl FnMut(SemanticBatch),
) -> SemanticStopSummary {
    io.request_stop();
    let start = now();
    let mut summary = SemanticStopSummary {
        quiesced: false,
        waited: Duration::ZERO,
        q: None,
        drain_batches: 0,
        quiesce_refusals: 0,
        post_q_events: false,
        post_q_discovery: false,
        unrouted_returns: 0,
        continuity_cuts: io.continuity_cuts(),
        semantic_loss: false,
        final_drain: false,
    };
    summary.quiesced = loop {
        if io.quiescent() {
            break true;
        }
        if now().saturating_duration_since(start) >= budget {
            break false;
        }
        match io.service_quantum() {
            Ok(Some(batch)) => {
                summary.drain_batches += 1;
                on_batch(batch);
            }
            Ok(None) => {}
            Err(_) => summary.quiesce_refusals += 1,
        }
    };
    summary.waited = now().saturating_duration_since(start);
    // At proven Q, capture both producer positions and drain the same
    // owned cursors to those positions in bounded quanta. H0 ticks
    // route what they can (each batch finalizes before Finish); the
    // remainder drain counts what H0 never routed and detects post-Q
    // writers. Never another consumer, never past Q.
    if summary.quiesced {
        match io.positions() {
            Some(current) => {
                let q = TerminalQuiescence {
                    events_q: current[0].1,
                    discovery_q: current[1].1,
                };
                summary.q = Some(q);
                let mut reached = current[0].0 >= q.events_q && current[1].0 >= q.discovery_q;
                for _ in 0..quanta {
                    if reached {
                        break;
                    }
                    match io.service_quantum() {
                        Ok(Some(batch)) => {
                            summary.drain_batches += 1;
                            on_batch(batch);
                        }
                        Ok(None) => {}
                        Err(_) => summary.quiesce_refusals += 1,
                    }
                    match io.positions() {
                        Some(current) => {
                            reached = current[0].0 >= q.events_q && current[1].0 >= q.discovery_q;
                        }
                        None => {
                            summary.semantic_loss = true;
                            break;
                        }
                    }
                }
                if !summary.semantic_loss {
                    let events = io.drain_events_to(q.events_q, quantum);
                    let discovery = io.drain_discovery_to(q.discovery_q, quantum);
                    summary.post_q_events = events.post_q;
                    summary.post_q_discovery = discovery.post_q;
                    summary.unrouted_returns =
                        summary.unrouted_returns.saturating_add(events.records);
                    if events.failed || discovery.failed {
                        summary.semantic_loss = true;
                    } else if reached
                        && !events.backlog
                        && !discovery.backlog
                        && !events.post_q
                        && !discovery.post_q
                    {
                        summary.final_drain = true;
                    }
                }
            }
            None => summary.semantic_loss = true,
        }
    }
    if !summary.quiesced || summary.semantic_loss {
        // Unproven Q or a read failure: preserve positive history,
        // declare semantic loss, and drain only one explicitly bounded
        // poll per cursor under the existing terminal bound.
        summary.semantic_loss = true;
        if let Some(current) = io.positions() {
            let events = io.drain_events_to(current[0].1, quantum);
            let _ = io.drain_discovery_to(current[1].1, quantum);
            summary.unrouted_returns = summary.unrouted_returns.saturating_add(events.records);
        }
    }
    summary
}

/// Tests-only composed stop over any [`SemanticStopIo`]:
/// [`run_semantic_drain`] delivers every drained batch to `on_batch`,
/// then H0 stops once and its terminal batch finalizes separately.
/// Production commits between the split drain/finish phases instead.
#[cfg(test)]
pub(crate) fn run_semantic_stop(
    io: &mut impl SemanticStopIo,
    budget: Duration,
    quanta: usize,
    quantum: usize,
    now: impl FnMut() -> Instant,
    mut on_batch: impl FnMut(SemanticBatch),
) -> SemanticStopSummary {
    let mut summary = run_semantic_drain(io, budget, quanta, quantum, now, &mut on_batch);
    // After all drained batches are consumed and published, H0 stops
    // once: unresolved joins expire and the terminal negatives plus
    // semantic Finish finalize separately, never ahead of drained calls.
    on_batch(io.finish_h0());
    summary.continuity_cuts = io.continuity_cuts();
    summary
}

/// The terminal stash drain: quiet refresh evidence stashed since
/// the last tick merges into terminal quanta (a stop before the next
/// tick must not strand it), with merge shed disclosed through the
/// lane's refusal counter.
struct LiveStashDrain<'a> {
    stash: &'a mut RefreshReceiptStash,
    shed: &'a mut u64,
}

/// The live [`SemanticStopIo`]: the lane's own Session and H0 driver.
/// DISCOVERY servicing and remainder drains touch only this lane's
/// cursors; nothing here stages Inventory-domain authority.
struct LiveStopIo<'a> {
    session: &'a mut Session,
    capture: &'a mut SemanticCapture,
    pins: Vec<Arc<PidPin>>,
    domain: NativeDomainId,
    stash: Option<LiveStashDrain<'a>>,
    collected: &'a mut u64,
}

impl SemanticStopIo for LiveStopIo<'_> {
    fn request_stop(&self) {
        self.session.stop_gate().request_stop();
    }

    fn quiescent(&self) -> bool {
        self.session.stop_gate().quiescent()
    }

    fn service_quantum(&mut self) -> Result<Option<SemanticBatch>, SemanticRefusal> {
        // The lane's own DISCOVERY cursor is serviced and discarded:
        // quiescence needs a flowing ring, not Inventory authority.
        for _ in 0..TERMINAL_DRAIN_QUANTA {
            match self.session.discovery_dequeue() {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let mut report = self
            .capture
            .tick(&mut *self.session, &self.pins)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        *self.collected = self.collected.saturating_add(report.collected_calls as u64);
        // Quiet evidence stashed since the last tick joins this
        // terminal quantum behind its own: a stop before the next tick
        // still registers it. The merge runs before the emptiness
        // check, so stashed-only evidence still produces a batch.
        if let Some(drain) = self.stash.as_mut() {
            let shed = merge_stash_into_report(drain.stash, &mut report);
            *drain.shed = drain.shed.saturating_add(shed);
        }
        if report.outcomes().is_empty() && report.current().is_empty() {
            return Ok(None);
        }
        SemanticBatch::from_tick_report(self.domain, report, Vec::new(), now_ns()).map(Some)
    }

    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        let events = self.session.event_drain_positions().ok()?;
        let discovery = self.session.discovery_positions().ok()?;
        Some([
            (events.consumer, events.producer),
            (discovery.consumer, discovery.producer),
        ])
    }

    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        let mut records = 0;
        let drained = (|| -> anyhow::Result<(bool, bool)> {
            let (drain, table) = self.session.event_drain_with_object_table()?;
            // The stop-time drain counts through the same gate as live
            // collection: only the attested allowlisted lane decodes
            // 608-byte records (bare decode stays 368-only, so the plain
            // stop poll would strand them as malformed here).
            match table {
                Some(table) => crate::events::poll_object_records_to_position(
                    drain,
                    stop,
                    Some(quantum),
                    table,
                    |_| {
                        records += 1;
                        std::ops::ControlFlow::Continue(())
                    },
                ),
                None => crate::events::poll_records_to_position(drain, stop, Some(quantum), |_| {
                    records += 1;
                    std::ops::ControlFlow::Continue(())
                }),
            }
        })();
        match drained {
            Ok((post_q, backlog)) => LaneDrainOutcome {
                records,
                post_q,
                backlog,
                failed: false,
            },
            Err(_) => LaneDrainOutcome {
                records,
                post_q: false,
                backlog: true,
                failed: true,
            },
        }
    }

    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        match self.session.collect_discovery_to_position(stop, quantum) {
            Ok((records, _, post_q, backlog)) => LaneDrainOutcome {
                records: records.len() as u64,
                post_q,
                backlog,
                failed: false,
            },
            Err(_) => LaneDrainOutcome {
                records: 0,
                post_q: false,
                backlog: true,
                failed: true,
            },
        }
    }

    fn finish_h0(&mut self) -> SemanticBatch {
        let report = self.capture.stop();
        *self.collected = self.collected.saturating_add(report.collected_calls as u64);
        SemanticBatch::from_tick_report(self.domain, report, Vec::new(), now_ns())
            .expect("H0 stop batches respect lane bounds")
    }

    #[cfg(test)]
    fn continuity_cuts(&self) -> u64 {
        self.capture.continuity_cuts()
    }
}

/// One terminal stop-io over the live lane's parts, built per quantum
/// so the lane borrows release for the commit between quanta.
fn terminal_io_for<'a>(
    live: &'a mut LiveLane,
    domain: NativeDomainId,
    pins: &[Arc<PidPin>],
) -> LiveStopIo<'a> {
    LiveStopIo {
        session: &mut live.session,
        capture: &mut live.capture,
        pins: pins.to_vec(),
        domain,
        stash: Some(LiveStashDrain {
            stash: &mut live.stashed_refresh,
            shed: &mut live.scan_refusals,
        }),
        collected: &mut live.collected_calls,
    }
}

/// The production terminal-drain backend: servicing, committing and
/// cursor operations behind one interface, so the drain phases below
/// run identically over the live lane and (in tests) substituted H0
/// I/O. Only I/O is substituted; the phases and every commit are the
/// shared production path.
pub(crate) trait CommittingDrainBackend {
    /// Gate the producer immediately (idempotent).
    fn request_stop(&mut self);
    fn quiescent(&mut self) -> bool;
    /// Whether stashed evidence awaits a quantum: a stop before the
    /// next tick must not strand it, so the drain flushes one quantum
    /// first when this holds.
    fn has_pending_evidence(&mut self) -> bool;
    /// Service one bounded audited H0 quantum and commit its batch
    /// promptly through the running lane. `Ok(true)` is a committed
    /// batch, `Ok(false)` a quiet tick, `Err` a quiesce refusal (the
    /// wait continues).
    fn service_and_commit(&mut self) -> Result<bool, SemanticRefusal>;
    /// Current (consumer, producer) for the owned EVENTS and DISCOVERY
    /// cursors, in that order. `None` is an unreadable ring.
    fn positions(&mut self) -> Option<[(usize, usize); 2]>;
    /// Bounded EVENTS remainder drain to `stop`: records H0 never
    /// routed count as unrouted; post-Q movement is reported, never
    /// silently consumed.
    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
    /// Bounded DISCOVERY drain to `stop`: cursor servicing only, the
    /// records feed no authority.
    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome;
}

/// The production terminal drain phases over any
/// [`CommittingDrainBackend`]: gate immediately, run bounded audited
/// H0 work while waiting up to `budget` for Q, capture both producer
/// positions at proven Q and drain the same owned cursors to those
/// positions in bounded quanta. Every serviced batch commits
/// promptly — through the running lane, before the next quantum —
/// instead of buffering through the wait: a drained receipt
/// otherwise expires (2s pending window) inside a long quiescence
/// wait (5s budget) before validation. On unproven Q or a read
/// failure, positive history is preserved, semantic loss is declared,
/// and only one explicitly bounded poll drains each cursor.
pub(crate) fn run_committing_drain(
    backend: &mut impl CommittingDrainBackend,
    budget: Duration,
    quanta: usize,
    quantum: usize,
    mut now: impl FnMut() -> Instant,
) -> SemanticStopSummary {
    let mut summary = SemanticStopSummary {
        quiesced: false,
        waited: Duration::ZERO,
        q: None,
        drain_batches: 0,
        quiesce_refusals: 0,
        post_q_events: false,
        post_q_discovery: false,
        unrouted_returns: 0,
        continuity_cuts: 0,
        semantic_loss: false,
        final_drain: false,
    };
    backend.request_stop();
    // A stop before the next tick must not strand stashed quiet
    // evidence: flush it through one terminal quantum first, since
    // the quiesce wait below may service nothing on immediate Q.
    if backend.has_pending_evidence() {
        match backend.service_and_commit() {
            Ok(true) => summary.drain_batches += 1,
            Ok(false) => {}
            Err(_) => summary.quiesce_refusals += 1,
        }
    }
    let start = now();
    summary.quiesced = loop {
        if backend.quiescent() {
            break true;
        }
        if now().saturating_duration_since(start) >= budget {
            break false;
        }
        match backend.service_and_commit() {
            Ok(true) => summary.drain_batches += 1,
            Ok(false) => {}
            Err(_) => summary.quiesce_refusals += 1,
        }
    };
    summary.waited = now().saturating_duration_since(start);
    if summary.quiesced {
        match backend.positions() {
            Some(current) => {
                let q = TerminalQuiescence {
                    events_q: current[0].1,
                    discovery_q: current[1].1,
                };
                summary.q = Some(q);
                let mut reached = current[0].0 >= q.events_q && current[1].0 >= q.discovery_q;
                for _ in 0..quanta {
                    if reached {
                        break;
                    }
                    match backend.service_and_commit() {
                        Ok(true) => summary.drain_batches += 1,
                        Ok(false) => {}
                        Err(_) => summary.quiesce_refusals += 1,
                    }
                    match backend.positions() {
                        Some(current) => {
                            reached = current[0].0 >= q.events_q && current[1].0 >= q.discovery_q;
                        }
                        None => {
                            summary.semantic_loss = true;
                            break;
                        }
                    }
                }
                if !summary.semantic_loss {
                    let events = backend.drain_events_to(q.events_q, quantum);
                    let discovery = backend.drain_discovery_to(q.discovery_q, quantum);
                    summary.post_q_events = events.post_q;
                    summary.post_q_discovery = discovery.post_q;
                    summary.unrouted_returns =
                        summary.unrouted_returns.saturating_add(events.records);
                    if events.failed || discovery.failed {
                        summary.semantic_loss = true;
                    } else if reached
                        && !events.backlog
                        && !discovery.backlog
                        && !events.post_q
                        && !discovery.post_q
                    {
                        summary.final_drain = true;
                    }
                }
            }
            None => summary.semantic_loss = true,
        }
    }
    if !summary.quiesced || summary.semantic_loss {
        // Unproven Q or a read failure: preserve positive history,
        // declare semantic loss, and drain only one explicitly bounded
        // poll per cursor under the existing terminal bound.
        summary.semantic_loss = true;
        if let Some(current) = backend.positions() {
            let events = backend.drain_events_to(current[0].1, quantum);
            let _ = backend.drain_discovery_to(current[1].1, quantum);
            summary.unrouted_returns = summary.unrouted_returns.saturating_add(events.records);
        }
    }
    if summary.post_q_events {
        eprintln!(
            "p11scope: terminal semantic EVENTS drain: post-quiescence record past the Q \
             positions (ungated writer)"
        );
    }
    if summary.post_q_discovery {
        eprintln!(
            "p11scope: terminal semantic DISCOVERY drain: post-quiescence record past the Q \
             positions (ungated writer)"
        );
    }
    summary
}

/// The live lane the committing drain wrapper checked: liveness
/// cannot lapse mid-drain, since nothing here unsets it.
fn expect_live_drain_lane(lane: &mut AttestedSemanticLane) -> &mut LiveLane {
    lane.live
        .as_mut()
        .expect("committing drain needs a live lane")
}

/// The live [`CommittingDrainBackend`]: the lane's own Session and H0
/// driver plus the committing coordinator. Servicing borrows the lane
/// per quantum and releases for the commit between quanta, so each
/// batch commits through the lane's validation authority; holding
/// one stop-io borrow across the whole drain cannot commit mid-drain.
struct LiveCommittingDrain<'a> {
    lane: &'a mut AttestedSemanticLane,
    coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
    pins: &'a [Arc<PidPin>],
}

impl CommittingDrainBackend for LiveCommittingDrain<'_> {
    fn request_stop(&mut self) {
        let domain = self.lane.domain;
        let pins = self.pins;
        let live = expect_live_drain_lane(self.lane);
        terminal_io_for(&mut *live, domain, pins).request_stop();
        live.gated = true;
    }

    fn quiescent(&mut self) -> bool {
        let domain = self.lane.domain;
        let pins = self.pins;
        let live = expect_live_drain_lane(self.lane);
        terminal_io_for(&mut *live, domain, pins).quiescent()
    }

    fn has_pending_evidence(&mut self) -> bool {
        !expect_live_drain_lane(self.lane).stashed_refresh.is_empty()
    }

    fn service_and_commit(&mut self) -> Result<bool, SemanticRefusal> {
        self.lane
            .service_terminal_quantum_committing(&mut *self.coordinator, self.pins)
    }

    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        let domain = self.lane.domain;
        let pins = self.pins;
        let live = expect_live_drain_lane(self.lane);
        terminal_io_for(&mut *live, domain, pins).positions()
    }

    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        let domain = self.lane.domain;
        let pins = self.pins;
        let live = expect_live_drain_lane(self.lane);
        terminal_io_for(&mut *live, domain, pins).drain_events_to(stop, quantum)
    }

    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        let domain = self.lane.domain;
        let pins = self.pins;
        let live = expect_live_drain_lane(self.lane);
        terminal_io_for(&mut *live, domain, pins).drain_discovery_to(stop, quantum)
    }
}

/// Tests-only [`CommittingDrainBackend`] over substituted H0 I/O: the
/// lane services real quanta and commits through the production path.
/// Quiescence and cursor positions are scripted per test through the
/// installed I/O; servicing advances them.
#[cfg(test)]
struct TestCommittingDrain<'a> {
    lane: &'a mut AttestedSemanticLane,
    coordinator: &'a mut InventoryCoordinator<OsProcessSource>,
}

#[cfg(test)]
impl TestCommittingDrain<'_> {
    fn test_io(&mut self) -> &mut dyn LaneTestIo {
        self.lane
            .test_io
            .as_mut()
            .expect("test drain needs substituted H0 I/O")
            .as_mut()
    }
}

#[cfg(test)]
impl CommittingDrainBackend for TestCommittingDrain<'_> {
    fn request_stop(&mut self) {
        self.lane.request_semantic_stop();
    }

    fn quiescent(&mut self) -> bool {
        self.test_io().quiescent()
    }

    fn has_pending_evidence(&mut self) -> bool {
        self.test_io().has_pending_evidence()
    }

    fn service_and_commit(&mut self) -> Result<bool, SemanticRefusal> {
        // Targets resolve through the substituted I/O; pins stay empty.
        self.lane
            .service_terminal_quantum_committing(&mut *self.coordinator, &[])
    }

    fn positions(&mut self) -> Option<[(usize, usize); 2]> {
        self.test_io().positions()
    }

    fn drain_events_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        self.test_io().drain_events_to(stop, quantum)
    }

    fn drain_discovery_to(&mut self, stop: usize, quantum: usize) -> LaneDrainOutcome {
        self.test_io().drain_discovery_to(stop, quantum)
    }
}

impl AttestedSemanticLane {
    /// Gate the Detailed producer immediately on stop request. New
    /// regular ticks refuse from here; only the terminal sequence runs
    /// bounded audited H0 work. One producer's stop never certifies the
    /// other: Inventory's own terminal path is independent.
    pub(crate) fn request_semantic_stop(&mut self) {
        #[cfg(test)]
        if self.test_io.is_some() {
            self.test_gated = true;
            return;
        }
        let Some(live) = self.live.as_mut() else {
            return;
        };
        live.session.stop_gate().request_stop();
        live.gated = true;
        live.stop_state = StopState::StopRequested;
    }

    /// Tests-only composed terminal sequence over the live lane: drain
    /// first (every drained batch reaches `on_batch`), then stop H0 once
    /// and deliver its Finish batch to `on_batch` last. Production
    /// commits between the split phases instead. A shell lane (failed
    /// startup) finishes nothing and reports no drain: positive history
    /// elsewhere is untouched.
    #[cfg(test)]
    pub(crate) fn run_semantic_stop(
        &mut self,
        pins: &[Arc<PidPin>],
        now: impl FnMut() -> Instant,
        mut on_batch: impl FnMut(SemanticBatch),
    ) -> SemanticStopSummary {
        let mut summary = self.run_semantic_drain(pins, now, &mut on_batch);
        if let Some(finish) = self.finish_semantic_stop() {
            on_batch(finish);
            if let Some(live) = self.live.as_ref() {
                summary.continuity_cuts = live.continuity_cuts;
            }
        }
        summary
    }

    /// The terminal drain phases over the live lane: gate (if not
    /// already), wait up to [`STOP_QUIESCE_BUDGET`] with bounded audited
    /// H0 work and drain owned cursors to Q. H0 keeps running: the caller
    /// commits every drained batch before finishing H0, so no eligible
    /// drained call sits behind Stopped. A shell lane (failed startup)
    /// drains nothing and reports no drain.
    ///
    /// Tests-only (used by the composed test stop): production drains
    /// through [`run_semantic_drain_committing`](Self::run_semantic_drain_committing).
    #[cfg(test)]
    pub(crate) fn run_semantic_drain(
        &mut self,
        pins: &[Arc<PidPin>],
        now: impl FnMut() -> Instant,
        on_batch: impl FnMut(SemanticBatch),
    ) -> SemanticStopSummary {
        let Some(live) = self.live.as_mut() else {
            return SemanticStopSummary {
                quiesced: false,
                waited: Duration::ZERO,
                q: None,
                drain_batches: 0,
                quiesce_refusals: 0,
                post_q_events: false,
                post_q_discovery: false,
                unrouted_returns: 0,
                continuity_cuts: 0,
                semantic_loss: false,
                final_drain: false,
            };
        };
        live.session.stop_gate().request_stop();
        live.gated = true;
        let domain = self.domain;
        let live = &mut **live;
        let mut io = LiveStopIo {
            session: &mut live.session,
            capture: &mut live.capture,
            pins: pins.to_vec(),
            domain,
            stash: Some(LiveStashDrain {
                stash: &mut live.stashed_refresh,
                shed: &mut live.scan_refusals,
            }),
            collected: &mut live.collected_calls,
        };
        let summary = run_semantic_drain(
            &mut io,
            STOP_QUIESCE_BUDGET,
            TERMINAL_DRAIN_QUANTA,
            TERMINAL_DRAIN_QUANTUM,
            now,
            on_batch,
        );
        live.stop_state = if summary.quiesced {
            StopState::Quiesced { at: Instant::now() }
        } else {
            StopState::QuiescenceUnproven {
                waited: summary.waited,
            }
        };
        live.final_drain = summary.final_drain;
        live.unrouted_returns = live
            .unrouted_returns
            .saturating_add(summary.unrouted_returns);
        live.drained_batches = live
            .drained_batches
            .saturating_add(summary.drain_batches as u64);
        live.semantic_loss = summary.semantic_loss;
        live.continuity_cuts = summary.continuity_cuts;
        if summary.post_q_events {
            eprintln!(
                "p11scope: terminal semantic EVENTS drain: post-quiescence record past the Q \
                 positions (ungated writer)"
            );
        }
        if summary.post_q_discovery {
            eprintln!(
                "p11scope: terminal semantic DISCOVERY drain: post-quiescence record past the Q \
                 positions (ungated writer)"
            );
        }
        summary
    }

    /// The production terminal drain over the live lane: the shared
    /// [`run_committing_drain`] phases, so every serviced batch commits
    /// immediately — through the running lane, before the next
    /// quantum — instead of buffering through the wait. A shell lane
    /// (failed startup) drains nothing and reports no drain. In tests
    /// with substituted H0 I/O, the same phases run through it.
    pub(crate) fn run_semantic_drain_committing(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        pins: &[Arc<PidPin>],
        now: impl FnMut() -> Instant,
    ) -> SemanticStopSummary {
        #[cfg(test)]
        if self.test_io.is_some() {
            let mut backend = TestCommittingDrain {
                lane: &mut *self,
                coordinator,
            };
            return run_committing_drain(
                &mut backend,
                STOP_QUIESCE_BUDGET,
                TERMINAL_DRAIN_QUANTA,
                TERMINAL_DRAIN_QUANTUM,
                now,
            );
        }
        if self.live.is_none() {
            return SemanticStopSummary {
                quiesced: false,
                waited: Duration::ZERO,
                q: None,
                drain_batches: 0,
                quiesce_refusals: 0,
                post_q_events: false,
                post_q_discovery: false,
                unrouted_returns: 0,
                continuity_cuts: 0,
                semantic_loss: false,
                final_drain: false,
            };
        }
        let mut backend = LiveCommittingDrain {
            lane: &mut *self,
            coordinator,
            pins,
        };
        let mut summary = run_committing_drain(
            &mut backend,
            STOP_QUIESCE_BUDGET,
            TERMINAL_DRAIN_QUANTA,
            TERMINAL_DRAIN_QUANTUM,
            now,
        );
        if let Some(live) = self.live.as_mut() {
            live.stop_state = if summary.quiesced {
                StopState::Quiesced { at: Instant::now() }
            } else {
                StopState::QuiescenceUnproven {
                    waited: summary.waited,
                }
            };
            live.final_drain = summary.final_drain;
            live.unrouted_returns = live
                .unrouted_returns
                .saturating_add(summary.unrouted_returns);
            live.drained_batches = live
                .drained_batches
                .saturating_add(summary.drain_batches as u64);
            live.semantic_loss = summary.semantic_loss;
            // Commits during the drain advance cuts through the lane,
            // so the end value reads the capture fresh.
            live.continuity_cuts = live.capture.continuity_cuts();
            summary.continuity_cuts = live.continuity_cuts;
        }
        summary
    }

    /// Service one terminal quantum and commit its batch immediately
    /// through the running lane. `Ok(true)` is a committed batch,
    /// `Ok(false)` a quiet tick, `Err` a quiesce refusal (the wait
    /// continues). In tests with substituted H0 I/O, the same
    /// service-plus-commit runs through it, past the stop gate like
    /// the live drain.
    pub(crate) fn service_terminal_quantum_committing(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        pins: &[Arc<PidPin>],
    ) -> Result<bool, SemanticRefusal> {
        #[cfg(test)]
        if self.test_io.is_some() {
            let domain = self.domain;
            let batch = self
                .test_io
                .as_mut()
                .expect("substituted H0 I/O checked above")
                .tick(domain)?;
            if batch.is_empty() {
                return Ok(false);
            }
            Self::commit_drained_batch(coordinator, self, batch);
            return Ok(true);
        }
        let domain = self.domain;
        let batch = {
            let Some(live) = self.live.as_mut() else {
                return Err(SemanticRefusal::Unavailable);
            };
            terminal_io_for(live, domain, pins).service_quantum()?
        };
        match batch {
            Some(batch) => {
                Self::commit_drained_batch(coordinator, self, batch);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Commit one drained batch beside the lane's stop: stage, then
    /// finalize through the running lane's validation authority. A
    /// terminal failure records a gap instead of losing Inventory's
    /// stop.
    pub(crate) fn commit_drained_batch(
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        lane: &mut AttestedSemanticLane,
        batch: SemanticBatch,
    ) {
        coordinator.stage_semantic_batch(batch);
        if let Err(error) = coordinator.commit_batch_with_semantics(false, Some(lane)) {
            coordinator.note_scope_gap(
                "semantic terminal commit failed".into(),
                format!("{error:#}"),
            );
        }
    }

    /// Stop H0 once and return its terminal Finish batch, after every
    /// drained batch was consumed and published. Unresolved joins expire;
    /// the terminal negatives plus semantic Finish finalize separately,
    /// never ahead of drained calls. Sets the lane finished. A shell lane
    /// (failed startup) has nothing to finish: `None`. In tests with
    /// substituted H0 I/O, the same H0 stop runs through it.
    pub(crate) fn finish_semantic_stop(&mut self) -> Option<SemanticBatch> {
        if self.collected_finish_requested {
            return None; // Its real Stop report/publication belongs to the retained machine.
        }
        let domain = self.domain;
        #[cfg(test)]
        if let Some(test) = self.test_io.as_mut() {
            let batch = test.finish(domain);
            self.test_finished = true;
            return Some(batch);
        }
        let live = self.live.as_mut()?;
        let live = &mut **live;
        // Finish touches only the capture: the stop batch constructor
        // stays shared with the drain's stop io. The stash already
        // drained through the terminal quanta, never behind Stopped.
        let mut io = LiveStopIo {
            session: &mut live.session,
            capture: &mut live.capture,
            pins: Vec::new(),
            domain,
            stash: None,
            collected: &mut live.collected_calls,
        };
        let batch = io.finish_h0();
        live.finished = true;
        live.continuity_cuts = live.capture.continuity_cuts();
        Some(batch)
    }

    /// The sanitized lane summary: counts only, never instance
    /// API-entry totals. The summary grants no semantic permission.
    pub(crate) fn semantic_summary(&self) -> SemanticCaptureSummary {
        let admitted_endpoints: u64 = self
            .subset
            .required()
            .values()
            .map(|slots| slots.len() as u64)
            .sum();
        let Some(live) = self.live.as_ref() else {
            return SemanticCaptureSummary {
                status: if self.startup_failed {
                    SemanticCaptureStatus::Unavailable
                } else {
                    SemanticCaptureStatus::Disabled
                },
                admitted_endpoints: 0,
                refused_endpoints: 0,
                continuity_cuts: 0,
                unrouted_returns: 0,
                stop_quiescence: SemanticStopQuiescence::NotRequested,
                final_drain: None,
            };
        };
        SemanticCaptureSummary {
            status: if live.finished {
                SemanticCaptureStatus::Stopped
            } else if live.scan_refusals > 0 || live.semantic_loss {
                SemanticCaptureStatus::Partial
            } else {
                SemanticCaptureStatus::Active
            },
            admitted_endpoints,
            refused_endpoints: live.scan_refusals,
            continuity_cuts: live.continuity_cuts,
            unrouted_returns: live.unrouted_returns,
            stop_quiescence: match live.stop_state {
                StopState::Quiesced { .. } => SemanticStopQuiescence::Quiesced,
                StopState::QuiescenceUnproven { .. } => SemanticStopQuiescence::Unproven,
                StopState::Running | StopState::StopRequested => {
                    SemanticStopQuiescence::NotRequested
                }
            },
            final_drain: live.finished.then_some(live.final_drain),
        }
    }
}

/// `observation.semantic_capture.status`: the lane's sanitized state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SemanticCaptureStatus {
    #[default]
    Disabled,
    Active,
    Partial,
    Unavailable,
    Stopped,
}

impl SemanticCaptureStatus {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Active => "active",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
            Self::Stopped => "stopped",
        }
    }
}

/// `observation.semantic_capture.stop_quiescence`: the stop-gate outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SemanticStopQuiescence {
    #[default]
    NotRequested,
    Quiesced,
    Unproven,
}

impl SemanticStopQuiescence {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Quiesced => "quiesced",
            Self::Unproven => "unproven",
        }
    }
}

/// The sanitized `observation.semantic_capture` summary: counts only,
/// never instance API-entry totals. Per-provider/edge gaps stay
/// authoritative for availability; this summary grants no permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct SemanticCaptureSummary {
    pub status: SemanticCaptureStatus,
    pub admitted_endpoints: u64,
    pub refused_endpoints: u64,
    pub continuity_cuts: u64,
    pub unrouted_returns: u64,
    pub stop_quiescence: SemanticStopQuiescence,
    pub final_drain: Option<bool>,
}

impl SemanticCaptureSummary {
    /// The exact `observation.semantic_capture` shape: `{status,
    /// admitted_endpoints, refused_endpoints, continuity_cuts,
    /// unrouted_returns, stop_quiescence, final_drain}`. `final_drain`
    /// is null before stop, then a boolean.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status.label(),
            "admitted_endpoints": self.admitted_endpoints,
            "refused_endpoints": self.refused_endpoints,
            "continuity_cuts": self.continuity_cuts,
            "unrouted_returns": self.unrouted_returns,
            "stop_quiescence": self.stop_quiescence.label(),
            "final_drain": self.final_drain,
        })
    }
}

#[cfg(test)]
mod refresh_stash_tests {
    use super::*;
    use crate::attach::image_query::CompleteEpochs;
    use crate::discovery::identity::PinnedObjectId;
    use crate::discovery::identity::RetainedInventoryTarget;
    use crate::discovery::identity::test_fixture;

    fn stashed_receipt(
        domain: NativeDomainId,
        cookie: u64,
        watched: &RetainedInventoryTarget,
    ) -> CurrentPartitionReceipt {
        CurrentPartitionReceipt::scripted(
            domain,
            ImageIdentity {
                task_cookie: cookie,
                exec_id: 1,
            },
            Arc::new(PidPin::test_proc_only(4321)),
            Endpoint {
                object: PinnedObjectId(0),
                file_slot: 0,
                offset: 0x1200,
            },
            0,
            watched.share(),
            CompleteEpochs {
                local: 0,
                global: 0,
                fault: 0,
                sticky: 0,
                record_flags: 0,
            },
            0,
            Instant::now() + Duration::from_secs(60),
            Vec::new(),
        )
    }

    #[test]
    fn refresh_stash_bounds_sheds_oldest_and_drains_in_order() {
        let domain = NativeDomainId::mint();
        let pins = test_fixture::real_scan_pin(
            &std::env::current_exe().unwrap(),
            None,
            1,
            "held-test-image",
        );
        let watched = pins.retain_inventory_target(PinnedObjectId(0)).unwrap();
        let mut stash = RefreshReceiptStash::new();
        assert!(stash.take().is_empty());
        let receipts: Vec<_> = (0..MAX_STASHED_REFRESH_RECEIPTS as u64 + 2)
            .map(|cookie| stashed_receipt(domain, cookie, &watched))
            .collect();
        assert_eq!(stash.push_all(receipts, Vec::new()), 2);
        assert_eq!(stash.shed(), 2);
        let drained = stash.take();
        assert_eq!(drained.len(), MAX_STASHED_REFRESH_RECEIPTS);
        assert_eq!(
            drained[0].image().task_cookie,
            2,
            "beyond the cap the oldest receipts shed"
        );
        assert!(stash.take().is_empty(), "take drains the stash");
    }
}

#[cfg(test)]
mod terminal_drain_tests {
    //! Drained batches reach `on_batch` before H0 stops: a legitimately
    //! drained last return still completes under ordinary adjudication,
    //! never behind Stopped.
    use super::*;
    use crate::discovery::identity::PinnedObjectId;
    use crate::discovery::instances::{
        CallFacts, EntryIp, EpochReading, InstanceId, InstanceRouter, MapRange, Route,
        RouterLimits, StableObservation,
    };
    use crate::semantic_capture::RoutedCall;
    use p11scope_ebpf_common::instance::STAMP_VALID;
    use p11scope_ebpf_common::{Event, InstanceStamp};

    #[test]
    fn owner_terminal_unproved_result_retains_the_complete_owner() {
        struct Owner(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Owner {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        release_terminal_owner(Box::new(Owner(Arc::clone(&drops))), Ok(())).unwrap();
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        let original = Arc::downgrade(&drops);
        let error = release_terminal_owner(
            Box::new(Owner(Arc::clone(&drops))),
            Err(crate::attach::CleanupInterrupted.into()),
        )
        .unwrap_err();
        assert!(error.is::<crate::attach::CleanupInterrupted>());
        assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(drops);
        assert!(
            original.upgrade().is_some(),
            "the original complete owner remains retained for exit"
        );
    }

    fn router_ids(domain: NativeDomainId, count: usize) -> Vec<InstanceId> {
        let mut router = InstanceRouter::new(domain, RouterLimits::default());
        let ranges = (0..count)
            .map(|n| {
                let base = 0x7000_0000 + n as u64 * 0x10000;
                MapRange::new(base, base + 0x3000, 0, true)
            })
            .collect();
        router.observe_legacy(StableObservation {
            file_slot: 0,
            reading: EpochReading {
                cookie: 71,
                local: 1,
                global: 0,
                fault: 0,
                record_flags: 0,
                sticky: 0,
            },
            ranges,
            fence: 0,
        });
        (0..count)
            .map(|n| {
                let stamp = InstanceStamp {
                    epoch: 1,
                    file_slot_plus1: 1,
                    flags: STAMP_VALID,
                    ..InstanceStamp::default()
                };
                match router.route(CallFacts {
                    token: n as u64 + 1,
                    domain,
                    image: ImageIdentity {
                        task_cookie: 71,
                        exec_id: 0,
                    },
                    entry: stamp,
                    ret: stamp,
                    ip: EntryIp::new(0x7000_0000 + n as u64 * 0x10000 + 0x1000),
                    attached_offset: Some(0x1000),
                }) {
                    Route::Joined(id) => id,
                    other => panic!("fixture must route a real instance: {other:?}"),
                }
            })
            .collect()
    }

    /// One drained batch script: an empty quantum or a real Joined last
    /// return with a timeline token.
    enum BatchScript {
        Empty,
        LastReturn,
    }

    struct OrderIo {
        domain: NativeDomainId,
        quiesce_after: usize,
        services: usize,
        positions: [(usize, usize); 2],
        scripts: Vec<BatchScript>,
        finish_calls: usize,
    }

    impl OrderIo {
        fn new(domain: NativeDomainId) -> Self {
            Self {
                domain,
                quiesce_after: 0,
                services: 0,
                positions: [(0, 0), (0, 0)],
                scripts: Vec::new(),
                finish_calls: 0,
            }
        }

        fn batch(&self, marker: u64, script: &BatchScript) -> SemanticBatch {
            match script {
                BatchScript::Empty => SemanticBatch::scripted(self.domain, Vec::new(), marker),
                BatchScript::LastReturn => {
                    let r0 = router_ids(self.domain, 1)[0];
                    let stamp = InstanceStamp {
                        epoch: 1,
                        file_slot_plus1: 1,
                        flags: STAMP_VALID,
                        ..InstanceStamp::default()
                    };
                    let routed = RoutedCall::scripted(
                        self.domain,
                        crate::events::DecodedEventRecord {
                            joint_resource: None,
                            base: crate::semantic_capture::event_record_with_routing(
                                Event {
                                    slot: 0,
                                    image: ImageIdentity {
                                        task_cookie: 71,
                                        exec_id: 0,
                                    },
                                    ..Default::default()
                                },
                                stamp,
                                0x2200,
                            ),
                            object: None,
                        },
                        Route::Joined(r0),
                        Some(Endpoint {
                            object: PinnedObjectId(0),
                            file_slot: 0,
                            offset: 0x1200,
                        }),
                        Some(7),
                    );
                    SemanticBatch::from_tick_report(
                        self.domain,
                        TickReport::scripted(vec![TickOutcome::Call(routed)], Vec::new()),
                        Vec::new(),
                        marker,
                    )
                    .unwrap()
                }
            }
        }
    }

    impl SemanticStopIo for OrderIo {
        fn request_stop(&self) {}

        fn quiescent(&self) -> bool {
            self.services >= self.quiesce_after
        }

        fn service_quantum(&mut self) -> Result<Option<SemanticBatch>, SemanticRefusal> {
            self.services += 1;
            if self.scripts.is_empty() {
                return Ok(None);
            }
            let marker = self.services as u64;
            let script = self.scripts.remove(0);
            Ok(Some(self.batch(marker, &script)))
        }

        fn positions(&mut self) -> Option<[(usize, usize); 2]> {
            Some(self.positions)
        }

        fn drain_events_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
            LaneDrainOutcome::default()
        }

        fn drain_discovery_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
            LaneDrainOutcome::default()
        }

        fn finish_h0(&mut self) -> SemanticBatch {
            self.finish_calls += 1;
            SemanticBatch::scripted(self.domain, Vec::new(), u64::MAX)
        }

        fn continuity_cuts(&self) -> u64 {
            0
        }
    }

    fn test_clock(ticks: Vec<Duration>) -> impl FnMut() -> Instant {
        let start = Instant::now();
        let mut at = 0;
        move || {
            let step = ticks
                .get(at)
                .copied()
                .unwrap_or(Duration::from_secs(3600 * 24 * 365));
            at += 1;
            start + step
        }
    }

    #[test]
    fn stop_orders_drained_last_return_before_finish() {
        let domain = NativeDomainId::mint();
        let mut io = OrderIo::new(domain);
        io.quiesce_after = 2;
        io.scripts = vec![BatchScript::LastReturn, BatchScript::Empty];
        let mut markers = Vec::new();
        let mut joined_tokens = Vec::new();
        let summary = run_semantic_stop(
            &mut io,
            Duration::from_secs(5),
            16,
            1024,
            test_clock(vec![Duration::ZERO; 4]),
            |batch| {
                markers.push(batch.observed_ns());
                let (outcomes, _, _) = batch.into_parts();
                for outcome in outcomes {
                    if let TickOutcome::Call(call) = outcome {
                        joined_tokens.push(call.token());
                    }
                }
            },
        );
        assert_eq!(markers, vec![1, 2, u64::MAX]);
        assert_eq!(io.finish_calls, 1, "H0 stops exactly once, last");
        assert_eq!(
            joined_tokens,
            vec![Some(7)],
            "the drained last return arrives before the Finish batch"
        );
        assert!(summary.final_drain);
    }

    #[test]
    fn drain_phases_deliver_batches_without_finishing_h0() {
        let domain = NativeDomainId::mint();
        let mut io = OrderIo::new(domain);
        io.quiesce_after = 2;
        io.scripts = vec![BatchScript::LastReturn, BatchScript::Empty];
        let mut markers = Vec::new();
        let summary = run_semantic_drain(
            &mut io,
            Duration::from_secs(5),
            16,
            1024,
            test_clock(vec![Duration::ZERO; 4]),
            |batch| markers.push(batch.observed_ns()),
        );
        assert_eq!(markers, vec![1, 2]);
        assert_eq!(io.finish_calls, 0, "drain phases never stop H0");
        assert!(summary.quiesced);
        assert!(summary.final_drain);
    }
}

#[cfg(test)]
mod joint_terminal_tests {
    use super::*;
    use crate::attach::ProducerDetachProgress;
    use crate::discovery::caller_registry::RegistryLimits;
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
    use p11scope_ebpf_common::SlotSemantics;
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;
    use std::rc::Rc;

    /// Scripted owned-detach progress for lanes without a live Session.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DetachScript {
        Pending,
        Complete,
        Unproved,
    }

    /// Scripted stash floor proving calls still route to this stub:
    /// a lane without substituted I/O answers `None`.
    const STUB_STASH_FLOOR: u64 = 77;

    /// Shared stub state: the lane owns the stub, the test owns this.
    struct WoundDownState {
        detach: DetachScript,
        failures: Vec<String>,
        detach_polls: usize,
        begin_calls: usize,
        finish_calls: usize,
    }

    /// Drop spy: proves the lane retains (or releases) its substituted I/O.
    struct DropWatch(Rc<Cell<bool>>);

    impl Drop for DropWatch {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    /// Substituted terminal I/O beneath the wound-down path: scripted
    /// detach progress with kept failures, an H0 stop batch, and call
    /// counts. Every other method is inert.
    struct WoundDownStub {
        state: Rc<RefCell<WoundDownState>>,
        _watch: DropWatch,
    }

    impl LaneTestIo for WoundDownStub {
        fn stash_pending_floor(&self) -> Option<u64> {
            Some(STUB_STASH_FLOOR)
        }

        fn begin_terminal_cleanup(&mut self) -> anyhow::Result<()> {
            self.state.borrow_mut().begin_calls += 1;
            Ok(())
        }

        fn poll_terminal_detach(
            &mut self,
            _out: &mut dyn std::io::Write,
        ) -> anyhow::Result<ProducerDetachProgress> {
            let mut state = self.state.borrow_mut();
            state.detach_polls += 1;
            match state.detach {
                DetachScript::Pending => Ok(ProducerDetachProgress::Pending),
                DetachScript::Complete => Ok(ProducerDetachProgress::Complete),
                DetachScript::Unproved => {
                    anyhow::bail!("terminal detach unproved: {}", state.failures.join("; "))
                }
            }
        }

        fn validate_current(
            &mut self,
            _receipt: &CurrentPartitionReceipt,
            _report: &mut TickReport,
        ) -> Result<(), CurrentReceiptRefusal> {
            Err(CurrentReceiptRefusal::Stopped)
        }

        fn tick(&mut self, _domain: NativeDomainId) -> Result<SemanticBatch, SemanticRefusal> {
            Err(SemanticRefusal::Unavailable)
        }

        fn refresh(
            &mut self,
            _pin: Arc<PidPin>,
            _slot: u32,
        ) -> Result<(Vec<ImageIdentity>, Arc<PidPin>), SemanticRefusal> {
            Err(SemanticRefusal::Unavailable)
        }

        fn has_pending_evidence(&self) -> bool {
            false
        }

        fn finish(&mut self, domain: NativeDomainId) -> SemanticBatch {
            self.state.borrow_mut().finish_calls += 1;
            SemanticBatch::scripted(domain, Vec::new(), 0)
        }

        fn quiescent(&mut self) -> bool {
            true
        }

        fn positions(&mut self) -> Option<[(usize, usize); 2]> {
            None
        }

        fn drain_events_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
            LaneDrainOutcome {
                records: 0,
                post_q: false,
                backlog: false,
                failed: false,
            }
        }

        fn drain_discovery_to(&mut self, _stop: usize, _quantum: usize) -> LaneDrainOutcome {
            LaneDrainOutcome {
                records: 0,
                post_q: false,
                backlog: false,
                failed: false,
            }
        }
    }

    /// One scripted slot forms a shell lane: no Session, maps or cursor.
    fn shell_lane_for_test() -> AttestedSemanticLane {
        let slot = crate::plan::Slot {
            index: 0,
            descriptor_index: 0,
            object: PinnedObjectId(7),
            object_path: "joint-terminal-test".into(),
            file_offset: 0x1000,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: Vec::new(),
        };
        let plan = crate::plan::AttachPlan::from_slots(vec![slot]);
        let subset = AttestedSubset::scripted(plan, PinnedObjects::empty(), BTreeMap::new());
        AttestedSemanticLane::start(
            subset,
            &Scope::Pid(std::process::id()),
            BackendSelection::Auto,
        )
        .expect("one scripted slot forms a shell lane")
    }

    fn coordinator_for_test() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .expect("a test coordinator builds")
    }

    fn io_lane_for_test(
        detach: DetachScript,
    ) -> (
        AttestedSemanticLane,
        Rc<RefCell<WoundDownState>>,
        Rc<Cell<bool>>,
    ) {
        let mut lane = shell_lane_for_test();
        let state = Rc::new(RefCell::new(WoundDownState {
            detach,
            failures: Vec::new(),
            detach_polls: 0,
            begin_calls: 0,
            finish_calls: 0,
        }));
        let dropped = Rc::new(Cell::new(false));
        lane.install_test_io(Box::new(WoundDownStub {
            state: Rc::clone(&state),
            _watch: DropWatch(Rc::clone(&dropped)),
        }));
        (lane, state, dropped)
    }

    #[test]
    fn joint_lane_without_machine_has_no_machine_or_frame() {
        let lane = shell_lane_for_test();
        assert!(!lane.has_joint_machine());
        assert!(!lane.has_joint_frame());
    }

    #[test]
    fn joint_lane_test_frame_seam_reports_first() {
        let mut lane = shell_lane_for_test();
        assert!(!lane.has_joint_frame());
        lane.set_test_joint_frame(true);
        assert!(lane.has_joint_frame());
        // The seam wins even over a finished lane: it is checked first.
        lane.test_finished = true;
        assert!(lane.has_joint_frame());
        lane.set_test_joint_frame(false);
        assert!(!lane.has_joint_frame());
    }

    #[test]
    fn wound_down_before_finished_refuses() {
        let mut coordinator = coordinator_for_test();
        let mut lane = shell_lane_for_test();
        assert_eq!(
            lane.poll_wound_down(&mut coordinator),
            Err(SemanticRefusal::Unavailable)
        );
        // Substituted I/O does not waive the gate, and the detach is
        // never polled before Finish.
        let (mut lane, shared, _) = io_lane_for_test(DetachScript::Complete);
        assert_eq!(
            lane.poll_wound_down(&mut coordinator),
            Err(SemanticRefusal::Unavailable)
        );
        assert_eq!(shared.borrow().detach_polls, 0);
        // An exit-retained lane refuses before any other gate, still
        // without touching the detach — even unfinished.
        lane.exit_retained = true;
        assert_eq!(
            lane.poll_wound_down(&mut coordinator),
            Err(SemanticRefusal::Unavailable)
        );
        assert_eq!(shared.borrow().detach_polls, 0);
    }

    #[test]
    fn wound_down_pending_detach_returns_false() {
        let mut coordinator = coordinator_for_test();
        let (mut lane, shared, _) = io_lane_for_test(DetachScript::Pending);
        lane.test_finished = true;
        assert_eq!(lane.poll_wound_down(&mut coordinator), Ok(false));
        assert_eq!(shared.borrow().detach_polls, 1);
        assert_eq!(lane.poll_wound_down(&mut coordinator), Ok(false));
        assert_eq!(shared.borrow().detach_polls, 2);
    }

    #[test]
    fn wound_down_complete_detach_reports_drained_true() {
        let mut coordinator = coordinator_for_test();
        let (mut lane, shared, _) = io_lane_for_test(DetachScript::Complete);
        lane.test_finished = true;
        assert_eq!(lane.poll_wound_down(&mut coordinator), Ok(true));
        assert_eq!(lane.poll_wound_down(&mut coordinator), Ok(true));
        assert_eq!(shared.borrow().detach_polls, 2);
        // A finished shell lane has nothing to detach; the shared
        // retired-file chain is already empty.
        let mut lane = shell_lane_for_test();
        lane.test_finished = true;
        assert_eq!(lane.poll_wound_down(&mut coordinator), Ok(true));
    }

    #[test]
    fn wound_down_unproved_detach_errors_and_keeps_first_failure() {
        let mut coordinator = coordinator_for_test();
        let (mut lane, shared, _) = io_lane_for_test(DetachScript::Unproved);
        lane.test_finished = true;
        shared.borrow_mut().failures = vec![
            "joined producer cleanup did not prove complete settlement".into(),
            "a later poll failure".into(),
        ];
        assert_eq!(
            lane.poll_wound_down(&mut coordinator),
            Err(SemanticRefusal::Unavailable)
        );
        assert_eq!(
            shared.borrow().failures,
            vec![
                "joined producer cleanup did not prove complete settlement".to_string(),
                "a later poll failure".to_string(),
            ],
            "the first error is kept, nothing consumed or overwritten"
        );
        assert_eq!(
            lane.poll_wound_down(&mut coordinator),
            Err(SemanticRefusal::Unavailable)
        );
        assert_eq!(shared.borrow().detach_polls, 2);
    }

    #[test]
    fn take_before_wound_down_refuses() {
        let mut lane = shell_lane_for_test();
        assert!(lane.take_joined_session().unwrap().is_none());
        // A finished frameless lane without a recorded wound-down
        // refuses: the poll-before-take order is enforced in-API.
        lane.test_finished = true;
        assert!(matches!(
            lane.take_joined_session(),
            Err(SemanticRefusal::Unavailable)
        ));
        // A retained frame blocks the take even when finished.
        lane.set_test_joint_frame(true);
        assert!(lane.take_joined_session().unwrap().is_none());
        lane.set_test_joint_frame(false);
        // Substituted lanes never ran a native session, but the
        // recorded wound-down is still required first.
        let (mut lane, _, _) = io_lane_for_test(DetachScript::Complete);
        lane.test_finished = true;
        assert!(matches!(
            lane.take_joined_session(),
            Err(SemanticRefusal::Unavailable)
        ));
    }

    #[test]
    fn take_after_abandon_refuses() {
        let mut coordinator = coordinator_for_test();
        let mut lane = shell_lane_for_test();
        lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        lane.abandon_finish_for_exit(&mut coordinator, "native ownership uncertain")
            .expect("disposition-required admits abandon");
        assert!(matches!(
            lane.take_joined_session(),
            Err(SemanticRefusal::Unavailable)
        ));
        assert!(matches!(
            lane.take_joined_session(),
            Err(SemanticRefusal::Unavailable)
        ));
    }

    #[test]
    fn abandon_when_not_admitted_refuses() {
        let mut coordinator = coordinator_for_test();
        let mut lane = shell_lane_for_test();
        assert!(matches!(
            lane.abandon_finish_for_exit(&mut coordinator, "native ownership uncertain"),
            Err(SemanticRefusal::Unavailable)
        ));
        assert!(!lane.is_finished());
        assert!(!lane.exit_retained);
        assert!(coordinator.registry().gaps().is_empty());
        // A refused abandon drops nothing: the substituted I/O stays
        // installed and answers afterwards.
        let (mut lane, shared, dropped) = io_lane_for_test(DetachScript::Pending);
        assert!(matches!(
            lane.abandon_finish_for_exit(&mut coordinator, "native ownership uncertain"),
            Err(SemanticRefusal::Unavailable)
        ));
        assert!(!dropped.get());
        assert_eq!(shared.borrow().finish_calls, 0);
        assert_eq!(lane.stash_pending_floor(), Some(STUB_STASH_FLOOR));
        assert!(!dropped.get());
    }

    #[test]
    fn abandon_on_disposition_builds_terminal_batch_and_retains() {
        let mut coordinator = coordinator_for_test();
        let (mut lane, shared, dropped) = io_lane_for_test(DetachScript::Pending);
        lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        let domain = lane.domain();
        let batch = lane
            .abandon_finish_for_exit(&mut coordinator, "native ownership uncertain")
            .expect("disposition-required admits abandon");
        assert!(lane.is_finished());
        assert!(lane.exit_retained);
        assert_eq!(shared.borrow().finish_calls, 1);
        assert_eq!(batch.domain(), domain);
        assert!(batch.is_empty());
        // Scope gaps stage until publication; commit, then read back.
        coordinator
            .commit_batch(false)
            .expect("a fresh coordinator commits");
        let gaps = coordinator.registry().gaps();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].subject, "joint finish abandoned for exit");
        assert_eq!(gaps[0].reason, "native ownership uncertain");
        // Nothing is dropped and no detach begins: the substituted I/O
        // stays installed, unpolled, and answers afterwards.
        assert!(!dropped.get());
        assert_eq!(shared.borrow().detach_polls, 0);
        assert_eq!(shared.borrow().begin_calls, 0);
        assert!(lane.is_live());
        assert_eq!(lane.stash_pending_floor(), Some(STUB_STASH_FLOOR));
        assert!(!dropped.get());
        drop(lane);
        assert!(
            dropped.get(),
            "the drop watch fires: retention was real, not a dead spy"
        );
    }

    #[test]
    fn abandon_then_poll_and_take_refuse_forever() {
        let mut coordinator = coordinator_for_test();
        let (mut lane, shared, _) = io_lane_for_test(DetachScript::Complete);
        lane.note_joint_finish_failure(SemanticRefusal::ProviderStorage);
        lane.abandon_finish_for_exit(&mut coordinator, "native ownership uncertain")
            .expect("disposition-required admits abandon");
        for _ in 0..2 {
            assert_eq!(
                lane.poll_wound_down(&mut coordinator),
                Err(SemanticRefusal::Unavailable)
            );
            assert!(matches!(
                lane.take_joined_session(),
                Err(SemanticRefusal::Unavailable)
            ));
        }
        assert_eq!(
            shared.borrow().detach_polls,
            0,
            "refused polls never touch the detach"
        );
    }
}
