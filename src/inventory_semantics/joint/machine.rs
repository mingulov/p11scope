//! SPDX-License-Identifier: GPL-3.0-or-later
//! Inactive, single-owner service of the actual collected Joint pipeline.
//! This module retains originals and scheduling positions; all authority stays
//! in Capture, prepared admissions, the canonical ledger and the real frame.

use super::{JointCommitIo, RetainedJointBirths};
use crate::attach::{BirthObservationRefusal, CollectedFinishQ, SessionDrainProducers};
use crate::discovery::caller_registry::OsProcessSource;
use crate::discovery::caller_registry::instance_input::AdmittedInstanceCall;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::discovery::engine::inventory_coordinator::{
    BatchReceipt, InventoryCoordinator, JointCommitProgress,
};
use crate::discovery::identity::PinnedObjectId;
use crate::discovery::instances::{InstanceId, MAX_INSTANCES, MAX_PENDING};
use crate::events::{DiscoveryDomain, DispatchPoll};
use crate::inventory_semantics::{
    AttestedSemanticLane, LaneDrainOutcome, LaneNegative, MAX_LANE_NEGATIVES, SemanticBatch,
    SemanticRefusal,
};
use crate::semantic_capture::{
    CommittedAbsenceBirth, CurrentPartitionReceipt, H0BirthCandidate, RetainedBirthWitness,
    TickOutcome, TickReport,
};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
#[cfg(test)]
use crate::semantics_objects::journal::joint_audit::DisposedJointQuantum;
use crate::semantics_objects::journal::joint_audit::IngestedJointQuantum;
use crate::semantics_objects::journal::joint_driver::{
    CollectedLedgerBinding, IngestedRaw, RawDisposeReason, RawDisposition, RawJointQuantum,
    RawQuantumIdentity, RawQuantumRefusal,
};
use crate::semantics_objects::journal::{
    EndpointClass, FaultEpoch, FaultReadError, JournalAdapter, JournalDomainProof,
    SessionClosureGrant, SessionDrainGrant,
};
use std::time::Instant;

const RAW_CAPACITY: usize = 4_096;
// The actual shared binder selects at most four caller/provider pairs. Its
// no-call receipts join the same original H0 report, never a second stage.
const REFRESHES_PER_BIND: usize = 4;

pub(crate) struct JointWorkBudget {
    pub(crate) remaining_actions: usize,
    pub(crate) deadline: Instant,
}
impl JointWorkBudget {
    fn available(&self) -> bool {
        self.remaining_actions != 0 && Instant::now() < self.deadline
    }
    fn spend(&mut self, actions: usize) {
        self.remaining_actions = self.remaining_actions.saturating_sub(actions);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum JointServiceMode {
    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JointServiceProgress {
    Pending,
    Published,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JointCommitRefusal {
    NotInitialized,
    OutstandingRequest,
    DispositionRequired,
}

/// The real Session implementation below and the genuine H0 fixture replace
/// only native/cursor leaves. No method supplies a prepared call, H3, audit,
/// seal, receipt or publication-completion word.
pub(crate) trait JointMachineIo {
    fn producers(&self) -> &SessionDrainProducers;
    /// The normal Session keeps this inactive until the owning Finish path
    /// exists. A test may forward only the existing immediate admission gate.
    #[allow(dead_code)] // Inert Finish surface in normal and libtest builds.
    fn request_finish_stop(
        &mut self,
        _lane: &mut AttestedSemanticLane,
    ) -> Result<(), SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    #[allow(dead_code)] // Q observation is not yet called by the inert machine.
    fn observe_finish_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _grant: Option<&SessionDrainGrant>,
    ) -> Result<Option<CollectedFinishQ>, SemanticRefusal> {
        Ok(None)
    }
    #[allow(dead_code)] // No terminal native-owner bridge is active yet.
    fn finish_discovery_domain(&self) -> Result<&DiscoveryDomain, SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    #[allow(dead_code)] // The inert port never allocates or polls a Raw.
    fn collect_raw_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _adapter: &mut JournalAdapter,
        _reserve: &SemanticResourceReserver,
        _q: &CollectedFinishQ,
        _capacity: usize,
        _work: usize,
    ) -> Result<(RawJointQuantum, Option<DispatchPoll>), RawQuantumRefusal> {
        Err(RawQuantumRefusal::DispositionMismatch)
    }
    #[allow(dead_code)] // The inert port never advances the original cursor.
    fn continue_raw_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _raw: &mut RawJointQuantum,
        _adapter: &mut JournalAdapter,
        _q: &CollectedFinishQ,
        _work: usize,
    ) -> Result<DispatchPoll, RawQuantumRefusal> {
        Err(RawQuantumRefusal::DispositionMismatch)
    }
    #[allow(dead_code)] // Bounded real Engine service is not implemented yet.
    fn service_finish_discovery(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _coordinator: &mut InventoryCoordinator<OsProcessSource>,
        _q: &CollectedFinishQ,
        _work: usize,
    ) -> Result<LaneDrainOutcome, SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    #[allow(dead_code)] // No Stop output allowance is invented by this scaffold.
    fn finish_h0_storage_bytes(
        &self,
        _lane: &AttestedSemanticLane,
        _raw: &RawJointQuantum,
        _adapter: &JournalAdapter,
        _q: &CollectedFinishQ,
    ) -> Result<usize, SemanticRefusal> {
        Err(SemanticRefusal::ProviderStorage)
    }
    #[allow(dead_code)] // Capture.stop and its report remain inactive.
    fn finish_h0_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _coordinator: &InventoryCoordinator<OsProcessSource>,
        _raw: &mut RawJointQuantum,
        _q: &CollectedFinishQ,
        _report: &mut TickReport,
    ) -> Result<(), SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    fn collect_raw(
        &mut self,
        lane: &mut AttestedSemanticLane,
        adapter: &mut JournalAdapter,
        reserve: &SemanticResourceReserver,
        capacity: usize,
        work: usize,
    ) -> Result<(RawJointQuantum, Option<DispatchPoll>), RawQuantumRefusal>;
    fn continue_raw(
        &mut self,
        lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        adapter: &mut JournalAdapter,
        work: usize,
    ) -> Result<DispatchPoll, RawQuantumRefusal>;
    fn tick_collected(
        &mut self,
        lane: &mut AttestedSemanticLane,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal>;
    /// Fail closed unless an implementation reads the actual owning Capture.
    fn pending_h0_at_q_storage_bytes(
        &self,
        _lane: &AttestedSemanticLane,
        _raw: &RawJointQuantum,
        _adapter: &JournalAdapter,
        _q: &CollectedFinishQ,
        _discovery: &DiscoveryDomain,
    ) -> Result<usize, SemanticRefusal> {
        Err(SemanticRefusal::ProviderStorage)
    }
    /// Fail closed unless the same native/Capture owner supplies the operation.
    fn resolve_pending_h0_at_q(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _raw: &mut RawJointQuantum,
        _adapter: &JournalAdapter,
        _q: &CollectedFinishQ,
        _discovery: &DiscoveryDomain,
        _report: &mut TickReport,
    ) -> Result<(), SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    fn prepare_publication(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        engine_changed: bool,
    ) -> anyhow::Result<()>;
    #[allow(clippy::too_many_arguments)] // Move the original optional negative beside the existing subject borrows.
    fn consume_birth(
        &mut self,
        lane: &mut AttestedSemanticLane,
        candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        input: &AdmittedInstanceCall,
        binding: &SemanticCallerBinding,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
    ) -> Result<RetainedBirthWitness, BirthObservationRefusal>;
    fn acquire_absence(
        &mut self,
        lane: &mut AttestedSemanticLane,
        binding: &SemanticCallerBinding,
        slot: u32,
        adapter: &mut JournalAdapter,
    ) -> Result<CommittedAbsenceBirth, BirthObservationRefusal>;
    fn absence_query_storage_bytes(
        &self,
        lane: &AttestedSemanticLane,
        object: PinnedObjectId,
        target_copy: usize,
    ) -> Option<usize>;
    fn with_native<R>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        witnesses: &RetainedJointBirths,
        inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal>;
}

enum Demand {
    Requested {
        engine_changed: bool,
    },
    Bound {
        original: RawQuantumIdentity,
        base_revision: u64,
    },
    Published(BatchReceipt),
}

enum RunState {
    Runnable,
    // Blocks callbacks; it grants no disposal or replay permission. The
    // original phase and the coordinator's completion context remain owned.
    DispositionRequired(SemanticRefusal),
}

/// Scalar failure, H3 and active-result tags; no proof payload is copied.
#[cfg(test)]
type JointAuditDiagnostic = (
    Option<crate::semantics_objects::journal::JournalGap>,
    &'static str,
    Option<u64>,
    Option<u64>,
    &'static str,
);

struct Collected {
    raw: RawJointQuantum,
    attempted: usize,
    poll: DispatchPoll,
    reports: Option<CollectedReports>,
}

enum PendingQResolution {
    Attempted,
    Resolved,
}

/// One output slot beside the SAME Collected owner. Its state records whether
/// the actual Capture callback returned; neither state grants Q/H3 authority.
/// Buffers must drop before their original prepaid lease.
struct PendingQReport {
    report: TickReport,
    resolution: PendingQResolution,
    bytes: usize,
    _storage: ResourceLease,
}

#[allow(clippy::large_enum_variant)] // The complete bounded original stays inline in the paid machine.
enum Phase {
    Idle,
    Collecting(Collected),
    Binding(Collected),
    AwaitH0(Collected),
    PendingQ {
        original: Collected,
        pending: PendingQReport,
    },
    Preparing(Collected),
    PreparationAttempted(Collected),
    PreparingAdmissions(Collected),
    BindingKeys {
        original: Collected,
        cursor: usize,
    },
    Ingesting(Collected),
    StagingNegative(Collected),
    Claiming {
        original: IngestedRaw,
        identity: RawQuantumIdentity,
        base: u64,
    },
    InstallingClosure {
        original: IngestedRaw,
        identity: RawQuantumIdentity,
        base: u64,
    },
    Births {
        original: IngestedRaw,
        identity: RawQuantumIdentity,
        base: u64,
    },
    Staging {
        original: IngestedRaw,
        identity: RawQuantumIdentity,
        base: u64,
    },
    Auditing {
        original: IngestedRaw,
        identity: RawQuantumIdentity,
        base: u64,
    },
    Negative {
        original: RawDisposition,
        identity: RawQuantumIdentity,
        base: u64,
    },
    Audited {
        frame: Option<IngestedJointQuantum>,
        identity: RawQuantumIdentity,
        base: u64,
    },
}

/// One paid accumulator for the original collection's H0 reports. Incoming
/// reports move here before another retry. The extra inline slot preserves an
/// unmerged original on a bounds refusal; it is not another staging queue.
struct CollectedReports {
    batch: Option<SemanticBatch>,
    refused: Option<SemanticBatch>,
    receipt_limit: usize,
    nested_per_receipt: usize,
    _storage: ResourceLease,
}

fn array_bytes<T>(capacity: usize) -> Option<usize> {
    capacity
        .checked_mul(size_of::<T>())?
        .checked_add(if capacity == 0 {
            0
        } else {
            OWNED_ALLOCATION_PADDING
        })
}

impl CollectedReports {
    fn new(
        lane: &AttestedSemanticLane,
        inputs: usize,
        reserve: &SemanticResourceReserver,
    ) -> Result<Self, SemanticRefusal> {
        let receipt_limit = inputs
            .checked_add(REFRESHES_PER_BIND)
            .ok_or(SemanticRefusal::ProviderStorage)?;
        let allocation_limit = receipt_limit
            .checked_next_power_of_two()
            .ok_or(SemanticRefusal::ProviderStorage)?;
        let mut watched_bound = 0;
        for object in lane.subset().required().keys() {
            watched_bound = watched_bound.max(
                lane.subset()
                    .pins()
                    .retained_target_copy_allocation_charge(*object)
                    .ok_or(SemanticRefusal::ProviderStorage)?,
            );
        }
        let nested_per_receipt = array_bytes::<InstanceId>(MAX_INSTANCES)
            .and_then(|bytes| bytes.checked_add(watched_bound))
            .ok_or(SemanticRefusal::ProviderStorage)?;
        // Both the accumulator and the current callback's original buffers
        // coexist. Each Current keeps its actual IDs/watched-file allocation.
        // There are at most input-partition receipts plus the four refreshes:
        // empty-input retries resolve those same jobs, never add interests.
        let bytes = (|| {
            size_of::<Self>()
                .checked_add(array_bytes::<TickOutcome>(MAX_INSTANCES)?.checked_mul(2)?)?
                .checked_add(
                    array_bytes::<CurrentPartitionReceipt>(allocation_limit)?.checked_mul(2)?,
                )?
                .checked_add(array_bytes::<LaneNegative>(MAX_LANE_NEGATIVES)?.checked_mul(2)?)?
                .checked_add(
                    nested_per_receipt
                        .checked_mul(receipt_limit)?
                        .checked_mul(2)?,
                )
        })()
        .ok_or(SemanticRefusal::ProviderStorage)?;
        let storage = reserve
            .reserve(bytes)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        let mut outcomes = Vec::new();
        let mut current = Vec::new();
        let mut negatives = Vec::new();
        outcomes
            .try_reserve_exact(MAX_INSTANCES)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        current
            .try_reserve_exact(receipt_limit)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        negatives
            .try_reserve_exact(MAX_LANE_NEGATIVES)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        if outcomes.capacity() != MAX_INSTANCES
            || current.capacity() != receipt_limit
            || negatives.capacity() != MAX_LANE_NEGATIVES
        {
            return Err(SemanticRefusal::ProviderStorage);
        }
        Ok(Self {
            batch: Some(SemanticBatch {
                domain: lane.domain(),
                outcomes,
                current,
                negatives,
                observed_ns: 0,
                awaiting_floor: None,
                shed_floor: None,
                exhausted: false,
            }),
            refused: None,
            receipt_limit,
            nested_per_receipt,
            _storage: storage,
        })
    }

    fn merge(&mut self, mut incoming: SemanticBatch) -> Result<bool, SemanticRefusal> {
        let batch = self.batch.as_mut().expect("not staged until H0 finishes");
        let fits = incoming.domain == batch.domain
            && batch
                .outcomes
                .len()
                .checked_add(incoming.outcomes.len())
                .is_some_and(|count| count <= MAX_INSTANCES)
            && batch
                .current
                .len()
                .checked_add(incoming.current.len())
                .is_some_and(|count| count <= self.receipt_limit)
            && batch
                .negatives
                .len()
                .checked_add(incoming.negatives.len())
                .is_some_and(|count| count <= MAX_LANE_NEGATIVES)
            && incoming.current.iter().all(|receipt| {
                receipt
                    .owned_storage_bytes()
                    .is_some_and(|bytes| bytes <= self.nested_per_receipt)
            });
        if !fits {
            self.refused = Some(incoming);
            return Err(SemanticRefusal::ProviderStorage);
        }
        batch.outcomes.append(&mut incoming.outcomes);
        batch.current.append(&mut incoming.current);
        batch.negatives.append(&mut incoming.negatives);
        batch.observed_ns = batch.observed_ns.max(incoming.observed_ns);
        // A resolved old floor must not strand its own collection forever.
        batch.awaiting_floor = incoming.awaiting_floor;
        batch.shed_floor = batch
            .shed_floor
            .into_iter()
            .chain(incoming.shed_floor)
            .min();
        batch.exhausted |= incoming.exhausted;
        Ok(batch.awaiting_floor.is_none())
    }

    /// Refuse before taking any produced field. The accumulator's original
    /// capacities already cover the union, so this transfer cannot allocate.
    fn merge_pending_q(
        &mut self,
        domain: crate::attach::capture::NativeDomainId,
        incoming: &mut TickReport,
    ) -> Result<bool, SemanticRefusal> {
        let batch = self.batch.as_mut().ok_or(SemanticRefusal::Unavailable)?;
        let outcomes = batch.outcomes.len().checked_add(incoming.outcomes().len());
        let current = batch.current.len().checked_add(incoming.current().len());
        if self.refused.is_some()
            || domain != batch.domain
            || !outcomes
                .is_some_and(|count| count <= MAX_INSTANCES && count <= batch.outcomes.capacity())
            || !current.is_some_and(|count| {
                count <= self.receipt_limit && count <= batch.current.capacity()
            })
            || !incoming.current().iter().all(|receipt| {
                receipt
                    .owned_storage_bytes()
                    .is_some_and(|bytes| bytes <= self.nested_per_receipt)
            })
        {
            return Err(SemanticRefusal::ProviderStorage);
        }
        batch.awaiting_floor = incoming.awaiting_floor();
        batch.shed_floor = batch
            .shed_floor
            .into_iter()
            .chain(incoming.shed_floor())
            .min();
        batch.exhausted |= incoming.exhausted();
        batch.observed_ns = batch
            .observed_ns
            .max(crate::discovery::caller_registry::now_ns());
        let mut outcomes = incoming.take_outcomes();
        let mut current = incoming.take_current();
        batch.outcomes.append(&mut outcomes);
        batch.current.append(&mut current);
        drop(outcomes);
        drop(current);
        Ok(batch.awaiting_floor.is_none())
    }
}

/// Scheduling state over the original owner, not an alternate capture/model.
pub(crate) struct LiveJointMachine {
    producers: SessionDrainProducers,
    ledger: Option<CollectedLedgerBinding>,
    phase: Option<Phase>,
    state: RunState,
    grant: Option<SessionDrainGrant>,
    births: RetainedJointBirths,
    // Index-only idle selection; no copied image/candidate table. Every
    // inspected pair/query spends an action before collection can begin.
    absence_binding: usize,
    absence_after: Option<PinnedObjectId>,
    absence_entry: usize,
    demand: Option<Demand>,
    prepared_base: u64,
    // A request-attempt latch only; it proves no Q, Stop or publication.
    // Its inline bytes are included in the existing size_of::<Self>() lease.
    finish_requested: bool,
    #[cfg(test)]
    refuse_pending_q_merge_once: bool,
    // All original phase buffers and birth leases drop before inline storage.
    _storage: ResourceLease,
}

struct ActualFault<'a>(&'a dyn FaultEpoch);
impl FaultEpoch for ActualFault<'_> {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        self.0.fault_epoch()
    }
}

impl LiveJointMachine {
    pub(crate) fn new(
        producers: &SessionDrainProducers,
        reserve: &SemanticResourceReserver,
    ) -> Result<Self, SemanticRefusal> {
        let storage = reserve
            .reserve(size_of::<Self>())
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        Ok(Self {
            producers: producers.clone(),
            ledger: None,
            phase: Some(Phase::Idle),
            state: RunState::Runnable,
            grant: None,
            births: RetainedJointBirths::new(),
            absence_binding: 0,
            absence_after: None,
            absence_entry: 0,
            demand: None,
            prepared_base: 0,
            finish_requested: false,
            #[cfg(test)]
            refuse_pending_q_merge_once: false,
            _storage: storage,
        })
    }

    pub(crate) fn begin_commit(&mut self, engine_changed: bool) -> Result<(), JointCommitRefusal> {
        if matches!(self.state, RunState::DispositionRequired(_)) {
            return Err(JointCommitRefusal::DispositionRequired);
        }
        if self.demand.is_some() {
            return Err(JointCommitRefusal::OutstandingRequest);
        }
        self.demand = Some(Demand::Requested { engine_changed });
        Ok(())
    }

    /// Inert request-only scaffold. The test override may request the existing
    /// admission STOP gate; the normal Session default refuses. No Q, record,
    /// report, finalizer or publication is consumed here.
    #[allow(dead_code)] // Ordinary Finish selection is intentionally inactive.
    pub(crate) fn begin_finish_with_io<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
    ) -> Result<(), SemanticRefusal> {
        self.validate_owner(lane, coordinator, io)?;
        if let RunState::DispositionRequired(reason) = self.state {
            return Err(reason);
        }
        if self.finish_requested {
            return Err(SemanticRefusal::Unavailable);
        }
        // Preserve an attempted error instead of automatically repeating the
        // native gate callback. This is not a successful Finish disposition.
        self.finish_requested = true;
        match io.request_finish_stop(lane) {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.state = RunState::DispositionRequired(reason);
                Err(reason)
            }
        }
    }

    /// Preserve the request and all original owners without servicing work.
    #[allow(dead_code)] // The actual terminal machine remains unimplemented.
    pub(crate) fn poll_finish_with_io<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        _budget: &mut JointWorkBudget,
    ) -> Result<JointCommitProgress, SemanticRefusal> {
        self.validate_owner(lane, coordinator, io)?;
        if let RunState::DispositionRequired(reason) = self.state {
            return Err(reason);
        }
        if !self.finish_requested {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(JointCommitProgress::Pending)
    }

    /// Resolve this live Capture's pending originals at actual Q, then transfer
    /// the retained report once. A refused receiver retries only that transfer.
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::too_many_arguments)] // Preserve disjoint original owners, Q and explicit work.
    pub(crate) fn resolve_pending_h0_at_q_with_io<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        q: &CollectedFinishQ,
        discovery: &DiscoveryDomain,
        budget: &mut JointWorkBudget,
    ) -> Result<JointServiceProgress, SemanticRefusal> {
        if !budget.available() {
            return Ok(JointServiceProgress::Pending);
        }
        self.validate_owner(lane, coordinator, io)?;
        if let RunState::DispositionRequired(reason) = self.state {
            return Err(reason);
        }
        if !q.matches_owner(&self.producers, discovery)
            || self
                .grant
                .as_ref()
                .is_some_and(|grant| !q.matches_retained_grant(grant))
        {
            return Err(SemanticRefusal::Unavailable);
        }
        if let Some(Phase::PendingQ { original, .. }) = self.phase.as_ref() {
            original
                .raw
                .validate_pending_finish_report(
                    coordinator.joint_capture().adapter(),
                    &self.producers,
                    discovery,
                    q,
                )
                .map_err(|_| SemanticRefusal::Unavailable)?;
            let phase = self.phase.take().ok_or(SemanticRefusal::Unavailable)?;
            let (phase, result) = self.merge_pending_q_phase(phase, lane, coordinator, budget);
            self.phase = Some(phase);
            if let Err(reason) = result {
                if reason != SemanticRefusal::ProviderStorage {
                    self.state = RunState::DispositionRequired(reason);
                }
                return Err(reason);
            }
            return Ok(JointServiceProgress::Pending);
        }
        let Some(Phase::AwaitH0(original)) = self.phase.as_ref() else {
            return Err(SemanticRefusal::Unavailable);
        };
        original
            .raw
            .validate_pending_finish(
                coordinator.joint_capture().adapter(),
                &self.producers,
                discovery,
                q,
            )
            .map_err(|_| SemanticRefusal::Unavailable)?;
        if original
            .reports
            .as_ref()
            .is_none_or(|reports| reports.refused.is_some())
        {
            return Err(SemanticRefusal::Unavailable);
        }
        let bytes = io.pending_h0_at_q_storage_bytes(
            lane,
            &original.raw,
            coordinator.joint_capture().adapter(),
            q,
            discovery,
        )?;
        if bytes == 0 {
            return Err(SemanticRefusal::ProviderStorage);
        }
        let storage = coordinator
            .registry()
            .semantic_storage_reserver()
            .reserve(bytes)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        let phase = self.phase.take().ok_or(SemanticRefusal::Unavailable)?;
        let Phase::AwaitH0(mut original) = phase else {
            self.phase = Some(phase);
            return Err(SemanticRefusal::Unavailable);
        };
        let mut pending = PendingQReport {
            report: TickReport::default(),
            resolution: PendingQResolution::Attempted,
            bytes,
            _storage: storage,
        };
        budget.spend(1);
        let result = io.resolve_pending_h0_at_q(
            lane,
            &mut original.raw,
            coordinator.joint_capture().adapter(),
            q,
            discovery,
            &mut pending.report,
        );
        let result = result.and_then(|()| {
            original
                .raw
                .matches_pending_finish_report(&pending.report)
                .then_some(())
                .ok_or(SemanticRefusal::Unavailable)
        });
        if result.is_ok() {
            pending.resolution = PendingQResolution::Resolved;
        }
        // Retain even a refused callback's partially produced report. It must
        // never be silently dropped or cause another expiry attempt.
        self.phase = Some(Phase::PendingQ { original, pending });
        if let Err(reason) = result {
            self.state = RunState::DispositionRequired(reason);
            return Err(reason);
        }
        if budget.available() {
            let phase = self.phase.take().ok_or(SemanticRefusal::Unavailable)?;
            let (phase, result) = self.merge_pending_q_phase(phase, lane, coordinator, budget);
            self.phase = Some(phase);
            if let Err(reason) = result {
                if reason != SemanticRefusal::ProviderStorage {
                    self.state = RunState::DispositionRequired(reason);
                }
                return Err(reason);
            }
        }
        Ok(JointServiceProgress::Pending)
    }

    fn merge_pending_q_phase(
        &mut self,
        phase: Phase,
        lane: &AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        budget: &mut JointWorkBudget,
    ) -> (Phase, Result<Step, SemanticRefusal>) {
        let Phase::PendingQ {
            mut original,
            mut pending,
        } = phase
        else {
            return (phase, Err(SemanticRefusal::Unavailable));
        };
        if !matches!(pending.resolution, PendingQResolution::Resolved) || pending.bytes == 0 {
            return (
                Phase::PendingQ { original, pending },
                Err(SemanticRefusal::Unavailable),
            );
        }
        if original
            .raw
            .validate_collected_report_owner(coordinator.joint_capture().adapter(), &self.producers)
            .is_err()
            || !original.raw.matches_pending_finish_report(&pending.report)
        {
            return (
                Phase::PendingQ { original, pending },
                Err(SemanticRefusal::Unavailable),
            );
        }
        if !budget.available() {
            return (Phase::PendingQ { original, pending }, Ok(Step::Yield));
        }
        budget.spend(1);
        #[cfg(test)]
        if self.refuse_pending_q_merge_once {
            self.refuse_pending_q_merge_once = false;
            return (
                Phase::PendingQ { original, pending },
                Err(SemanticRefusal::ProviderStorage),
            );
        }
        let result = original
            .reports
            .as_mut()
            .ok_or(SemanticRefusal::Unavailable)
            .and_then(|reports| reports.merge_pending_q(lane.domain(), &mut pending.report));
        let complete = match result {
            Ok(complete) => complete,
            Err(reason) => return (Phase::PendingQ { original, pending }, Err(reason)),
        };
        drop(pending); // Dropped incoming buffers precede their exact lease refund.
        if !complete {
            return (Phase::AwaitH0(original), Ok(Step::Yield));
        }
        let Some(batch) = original
            .reports
            .as_mut()
            .and_then(|reports| reports.batch.take())
        else {
            return (Phase::AwaitH0(original), Err(SemanticRefusal::Unavailable));
        };
        coordinator.stage_semantic_batch(batch);
        (Phase::Preparing(original), Ok(Step::Continue))
    }

    pub(crate) fn poll_commit_with_io<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        budget: &mut JointWorkBudget,
    ) -> Result<JointCommitProgress, SemanticRefusal> {
        self.validate_owner(lane, coordinator, io)?;
        if matches!(self.demand, Some(Demand::Published(_))) {
            return Ok(self.take_published());
        }
        if self.demand.is_none() {
            return Ok(JointCommitProgress::Pending);
        }
        self.service_with_io(lane, coordinator, io, JointServiceMode::Running, budget)?;
        Ok(self.take_published())
    }

    fn take_published(&mut self) -> JointCommitProgress {
        if !matches!(self.demand, Some(Demand::Published(_))) {
            return JointCommitProgress::Pending;
        }
        let Some(Demand::Published(receipt)) = self.demand.take() else {
            unreachable!()
        };
        JointCommitProgress::Published(receipt)
    }

    pub(crate) fn service_with_io<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        _mode: JointServiceMode,
        budget: &mut JointWorkBudget,
    ) -> Result<JointServiceProgress, SemanticRefusal> {
        self.validate_owner(lane, coordinator, io)?;
        if let RunState::DispositionRequired(reason) = self.state {
            return Err(reason);
        }
        while budget.available() {
            let phase = self.phase.take().expect("one original machine phase");
            let (phase, result) = self.advance(phase, lane, coordinator, io, budget);
            self.phase = Some(phase);
            match result {
                Ok(Step::Continue) => {}
                Ok(Step::Yield) => return Ok(JointServiceProgress::Pending),
                Ok(Step::Published) => return Ok(JointServiceProgress::Published),
                Err(reason) => {
                    // This exact produced report remains the retry input.
                    // Other failed phases keep their existing disposition gate.
                    if reason != SemanticRefusal::ProviderStorage
                        || !matches!(
                            self.phase,
                            Some(Phase::PendingQ {
                                pending: PendingQReport {
                                    resolution: PendingQResolution::Resolved,
                                    ..
                                },
                                ..
                            })
                        )
                    {
                        self.state = RunState::DispositionRequired(reason);
                    }
                    return Err(reason);
                }
            }
        }
        Ok(JointServiceProgress::Pending)
    }

    fn validate_owner<I: JointMachineIo>(
        &self,
        lane: &AttestedSemanticLane,
        coordinator: &InventoryCoordinator<OsProcessSource>,
        io: &I,
    ) -> Result<(), SemanticRefusal> {
        if !self.producers.same_producers(io.producers())
            || lane.domain() != self.producers.native_domain()
            || !lane.is_live()
            || lane.is_finished()
            || self
                .ledger
                .as_ref()
                .is_some_and(|ledger| !ledger.matches_owner(coordinator.joint_capture()))
        {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn retained_drain_grant_for_test(&self) -> Option<&SessionDrainGrant> {
        self.grant.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn finish_stop_ready_for_test(&self) -> bool {
        false // No final Raw/preparation exists in the inert scaffold.
    }

    #[cfg(test)]
    pub(crate) fn retained_finish_q_for_test(&self) -> Option<&CollectedFinishQ> {
        None
    }

    #[cfg(test)]
    pub(crate) fn retained_finish_report_for_test(&self) -> Option<(&TickReport, usize)> {
        None
    }

    #[cfg(test)]
    pub(crate) fn retained_finish_disposition_for_test(&self) -> Option<&DisposedJointQuantum> {
        None
    }

    /// Refusal-only hook has no receiver to affect until real output exists.
    #[cfg(test)]
    pub(crate) fn reference_refuse_finish_q_merge_once(&mut self) {}

    /// Borrow the actual receiver-owned report and its retained lease size.
    #[cfg(test)]
    pub(crate) fn retained_pending_q_report_for_test(&self) -> Option<(&TickReport, usize)> {
        let Phase::PendingQ { pending, .. } = self.phase.as_ref()? else {
            return None;
        };
        Some((&pending.report, pending.bytes))
    }

    /// Refusal only, consumed after actual output and lease are retained.
    #[cfg(test)]
    pub(crate) fn reference_refuse_pending_q_merge_once(&mut self) {
        self.refuse_pending_q_merge_once = true;
    }

    #[cfg(test)]
    pub(crate) fn retained_raw_for_test(&self) -> Option<&RawJointQuantum> {
        match self.phase.as_ref()? {
            Phase::Collecting(value)
            | Phase::Binding(value)
            | Phase::AwaitH0(value)
            | Phase::PendingQ {
                original: value, ..
            }
            | Phase::Preparing(value)
            | Phase::PreparationAttempted(value)
            | Phase::PreparingAdmissions(value)
            | Phase::Ingesting(value)
            | Phase::StagingNegative(value)
            | Phase::BindingKeys {
                original: value, ..
            } => Some(&value.raw),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn diagnostic_snapshot_for_test(
        &self,
    ) -> (&'static str, &'static str, Option<(usize, usize)>, u64) {
        let (phase, original) = match self.phase.as_ref() {
            None => ("NoPhase", None),
            Some(Phase::Idle) => ("Idle", None),
            Some(Phase::Collecting(value)) => ("Collecting", Some(value)),
            Some(Phase::Binding(value)) => ("Binding", Some(value)),
            Some(Phase::AwaitH0(value)) => ("AwaitH0", Some(value)),
            Some(Phase::PendingQ { original, .. }) => ("PendingQReport", Some(original)),
            Some(Phase::Preparing(value)) => ("Preparing", Some(value)),
            Some(Phase::PreparationAttempted(value)) => ("PreparationAttempted", Some(value)),
            Some(Phase::PreparingAdmissions(value)) => ("PreparingAdmissions", Some(value)),
            Some(Phase::BindingKeys { original, .. }) => ("BindingKeys", Some(original)),
            Some(Phase::Ingesting(value)) => ("Ingesting", Some(value)),
            Some(Phase::StagingNegative(value)) => ("StagingNegative", Some(value)),
            Some(Phase::Claiming { .. }) => ("Claiming", None),
            Some(Phase::InstallingClosure { .. }) => ("InstallingClosure", None),
            Some(Phase::Births { .. }) => ("Births", None),
            Some(Phase::Staging { .. }) => ("Staging", None),
            Some(Phase::Auditing { .. }) => ("Auditing", None),
            Some(Phase::Negative { .. }) => ("Negative", None),
            Some(Phase::Audited { .. }) => ("Audited", None),
        };
        let demand = match self.demand {
            None => "None",
            Some(Demand::Requested { .. }) => "Requested",
            Some(Demand::Bound { .. }) => "Bound",
            Some(Demand::Published(_)) => "Published",
        };
        (
            phase,
            demand,
            original.map(|value| (value.attempted, value.raw.pending_h0_records())),
            self.prepared_base,
        )
    }

    #[cfg(test)]
    pub(crate) fn diagnostic_audit_for_test(&self) -> Option<JointAuditDiagnostic> {
        use crate::semantics_objects::journal::H3DispositionEvidence;
        let Phase::Audited {
            frame: Some(frame), ..
        } = self.phase.as_ref()?
        else {
            return None;
        };
        let (h3, bound, pending) = match frame.audit_for_test().h3_for_test() {
            H3DispositionEvidence::Clean {
                staged_max,
                pending_floor,
            } => ("Clean", Some(*staged_max), *pending_floor),
            H3DispositionEvidence::StagedLoss { barrier } => ("StagedLoss", Some(*barrier), None),
            H3DispositionEvidence::Exhausted => ("Exhausted", None, None),
        };
        Some((
            frame.failure_for_test().map(|failure| failure.gap),
            h3,
            bound,
            pending,
            if frame.active_seal_for_test().is_some() {
                "ActiveSuccess"
            } else {
                "NoActiveSuccess"
            },
        ))
    }

    #[cfg(test)]
    pub(crate) fn retained_h0_for_test(
        &self,
    ) -> Option<(&[TickOutcome], &[CurrentPartitionReceipt])> {
        let original = match self.phase.as_ref()? {
            Phase::AwaitH0(original) | Phase::PendingQ { original, .. } => original,
            _ => return None,
        };
        let batch = original.reports.as_ref()?.batch.as_ref()?;
        Some((&batch.outcomes, &batch.current))
    }

    #[cfg(test)]
    pub(crate) fn report_preparation_pending_for_test(&self) -> bool {
        matches!(self.phase, Some(Phase::Binding(_)))
    }

    #[cfg(test)]
    pub(crate) fn retained_negative_for_test(&self) -> Option<&RawDisposition> {
        let Phase::Negative { original, .. } = self.phase.as_ref()? else {
            return None;
        };
        Some(original)
    }

    #[cfg(test)]
    pub(crate) fn retained_births_for_test(&self) -> &RetainedJointBirths {
        &self.births
    }

    #[cfg(test)]
    pub(crate) fn next_absence_allocation_for_test(
        &self,
        lane: &AttestedSemanticLane,
        coordinator: &InventoryCoordinator<OsProcessSource>,
    ) -> Option<(usize, usize, usize)> {
        let binding = coordinator.joint_absence_binding(self.absence_binding)?;
        let (object, _) = match self.absence_after {
            Some(after) => lane
                .subset()
                .required()
                .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                .next(),
            None => lane.subset().required().iter().next(),
        }?;
        if self
            .births
            .contains_subject(binding, lane.subset().pins(), *object)
        {
            return None;
        }
        let nested = lane
            .subset()
            .pins()
            .retained_target_copy_allocation_charge(*object)?;
        self.births.next_allocation_for_test(nested)
    }

    #[cfg(test)]
    pub(crate) fn retained_storage_for_test(&self) -> usize {
        assert!(
            matches!(self.phase, Some(Phase::Idle)),
            "this observer measures the actual idle machine and birth leases"
        );
        size_of::<Self>() + self.births.retained_storage_for_test()
    }
}

enum Step {
    Continue,
    Yield,
    Published,
}

// Returning the actual owned phase on every error prevents a failed callback
// from dropping Raw/H8/report/frame custody or replaying its earlier phase.
macro_rules! retain_on_refusal {
    ($phase:expr, $result:expr) => {
        match $result {
            Ok(value) => value,
            Err(_) => return ($phase, Err(SemanticRefusal::Unavailable)),
        }
    };
}

impl LiveJointMachine {
    #[allow(clippy::too_many_arguments)] // Disjoint canonical owners plus one finite shared budget.
    #[allow(clippy::result_large_err)] // Native callbacks return the original proof/frame without allocating.
    fn advance<I: JointMachineIo>(
        &mut self,
        phase: Phase,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        budget: &mut JointWorkBudget,
    ) -> (Phase, Result<Step, SemanticRefusal>) {
        match phase {
            phase @ Phase::PendingQ { .. } => {
                self.merge_pending_q_phase(phase, lane, coordinator, budget)
            }
            Phase::Idle => {
                let reserve = coordinator.registry().semantic_storage_reserver();
                // No collection, binder or New can precede this scan. One
                // accepted current image is paired with one real attached
                // target per action; no Mapped-only selector/cross-product.
                if self.grant.is_some()
                    && let Some((binding, adapter)) =
                        coordinator.joint_absence_parts(self.absence_binding)
                {
                    let target = match self.absence_after {
                        Some(after) => lane
                            .subset()
                            .required()
                            .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                            .next(),
                        None => lane.subset().required().iter().next(),
                    }
                    .map(|(object, slots)| (*object, slots.first().copied()));
                    budget.spend(1);
                    let Some((object, slot)) = target else {
                        self.absence_binding += 1;
                        self.absence_after = None;
                        self.absence_entry = 0;
                        return (Phase::Idle, Ok(Step::Continue));
                    };
                    if !binding.scope_current() || binding.domain() != lane.domain() {
                        self.absence_after = Some(object);
                        self.absence_entry = 0;
                        return (Phase::Idle, Ok(Step::Continue));
                    }
                    // The retained table is inspected one entry per shared
                    // action. A budget-one retry resumes its exact position,
                    // rather than rescanning every prior witness/negative.
                    if let Some(matches) = self.births.subject_at(
                        self.absence_entry,
                        binding,
                        lane.subset().pins(),
                        object,
                    ) {
                        if matches {
                            self.absence_after = Some(object);
                            self.absence_entry = 0;
                        } else {
                            self.absence_entry += 1;
                        }
                        return (Phase::Idle, Ok(Step::Continue));
                    }
                    let Some(slot) = slot else {
                        return (Phase::Idle, Err(SemanticRefusal::Attachment));
                    };
                    let Some(nested) = lane
                        .subset()
                        .pins()
                        .retained_target_copy_allocation_charge(object)
                    else {
                        return (Phase::Idle, Err(SemanticRefusal::ProviderStorage));
                    };
                    let Some(query_bytes) = io.absence_query_storage_bytes(lane, object, nested)
                    else {
                        return (Phase::Idle, Err(SemanticRefusal::ProviderStorage));
                    };
                    let slot_storage = match self.births.reserve_for(&reserve, nested) {
                        Ok(storage) => storage,
                        Err(()) => return (Phase::Idle, Err(SemanticRefusal::ProviderStorage)),
                    };
                    let query_storage = match reserve.reserve(query_bytes) {
                        Ok(storage) => storage,
                        Err(_) => return (Phase::Idle, Err(SemanticRefusal::ProviderStorage)),
                    };
                    let acquired = io.acquire_absence(lane, binding, slot, adapter);
                    // Native maps/parsed paths/confirmation/watch temporaries
                    // have dropped. The returned negative's original watched
                    // copy remains covered by slot_storage's nested lease.
                    drop(query_storage);
                    match acquired {
                        Ok(negative) => {
                            if !negative.matches_binding_target(
                                binding,
                                lane.subset().pins(),
                                object,
                            ) || slot_storage.retain_absence(negative).is_err()
                            {
                                return (Phase::Idle, Err(SemanticRefusal::Unavailable));
                            }
                            self.absence_after = Some(object);
                            self.absence_entry = 0;
                            return (Phase::Idle, Ok(Step::Yield));
                        }
                        Err(_) => {
                            // No absence authority was acquired. The actual
                            // later New may still choose only its real Exec
                            // path; this does not manufacture a negative.
                            self.absence_after = Some(object);
                            self.absence_entry = 0;
                            return (Phase::Idle, Ok(Step::Continue));
                        }
                    }
                }
                self.absence_binding = 0;
                self.absence_after = None;
                self.absence_entry = 0;
                let work = budget.remaining_actions.min(MAX_PENDING);
                let (raw, poll) = retain_on_refusal!(
                    Phase::Idle,
                    io.collect_raw(
                        lane,
                        coordinator.joint_capture_mut().adapter_mut(),
                        &reserve,
                        RAW_CAPACITY,
                        work,
                    )
                );
                let poll = poll.expect("positive initial work actually polls the original cursor");
                budget.spend(poll.attempted.max(1));
                let Some(ledger) = raw.ledger_binding() else {
                    return (
                        Phase::Collecting(Collected {
                            raw,
                            attempted: poll.attempted,
                            poll,
                            reports: None,
                        }),
                        Err(SemanticRefusal::Unavailable),
                    );
                };
                self.ledger = Some(ledger);
                (
                    Phase::Collecting(Collected {
                        raw,
                        attempted: poll.attempted,
                        poll,
                        reports: None,
                    }),
                    Ok(Step::Continue),
                )
            }
            Phase::Collecting(mut original) => {
                // The H0 leaf accepts at most MAX_PENDING ordinary records.
                // Total wire capacity and actual ordinary/H0 room are
                // independent. BEGIN-only prefixes may cross wire1024.
                if !original.poll.backlog
                    || original.attempted >= RAW_CAPACITY
                    || original.raw.pending_h0_records() >= MAX_PENDING
                {
                    let failed = retain_on_refusal!(
                        Phase::Collecting(original),
                        original.raw.h0_input(lane.domain(), MAX_PENDING)
                    )
                    .1;
                    let requested = matches!(self.demand, Some(Demand::Requested { .. }));
                    let unrequested_empty = original.attempted == 0 && !requested;
                    let needs_first_end = original.attempted != 0
                        && original.raw.pending_h0_records() == 0
                        && self.grant.is_none()
                        && !failed
                        && !requested
                        && original.attempted < RAW_CAPACITY;
                    if !unrequested_empty && !needs_first_end {
                        budget.spend(1);
                        return (Phase::Binding(original), Ok(Step::Continue));
                    }
                }
                let work = budget
                    .remaining_actions
                    .min(MAX_PENDING)
                    .min(RAW_CAPACITY - original.attempted)
                    .min(MAX_PENDING - original.raw.pending_h0_records());
                if work == 0 {
                    return (Phase::Collecting(original), Ok(Step::Yield));
                }
                let poll = retain_on_refusal!(
                    Phase::Collecting(original),
                    io.continue_raw(
                        lane,
                        &mut original.raw,
                        coordinator.joint_capture_mut().adapter_mut(),
                        work,
                    )
                );
                original.attempted += poll.attempted;
                original.poll = poll;
                budget.spend(poll.attempted.max(1));
                let step = if poll.attempted == 0 {
                    Step::Yield
                } else {
                    Step::Continue
                };
                (Phase::Collecting(original), Ok(step))
            }
            Phase::Binding(mut original) => {
                let reserve = coordinator.registry().semantic_storage_reserver();
                let reports = match CollectedReports::new(
                    lane,
                    original.raw.pending_h0_records(),
                    &reserve,
                ) {
                    Ok(reports) => reports,
                    Err(reason) => return (Phase::Binding(original), Err(reason)),
                };
                original.reports = Some(reports);
                retain_on_refusal!(
                    Phase::Binding(original),
                    super::bind_collected_semantic_callers(
                        coordinator,
                        lane,
                        &mut original.raw,
                        &self.producers,
                    )
                );
                budget.spend(1);
                (Phase::AwaitH0(original), Ok(Step::Continue))
            }
            Phase::AwaitH0(mut original) => {
                let batch = retain_on_refusal!(
                    Phase::AwaitH0(original),
                    io.tick_collected(
                        lane,
                        coordinator.semantic_bindings_mut().bindings_for_tick(),
                        &mut original.raw
                    )
                );
                budget.spend(1);
                let complete = match original
                    .reports
                    .as_mut()
                    .expect("prepaid before New")
                    .merge(batch)
                {
                    Ok(complete) => complete,
                    Err(reason) => return (Phase::AwaitH0(original), Err(reason)),
                };
                if !complete {
                    return (Phase::AwaitH0(original), Ok(Step::Yield));
                }
                let batch = original
                    .reports
                    .as_mut()
                    .expect("same reports")
                    .batch
                    .take()
                    .expect("stage once");
                coordinator.stage_semantic_batch(batch);
                (Phase::Preparing(original), Ok(Step::Continue))
            }
            Phase::Preparing(mut original) => {
                let identity = original.raw.h0_identity();
                self.prepared_base = coordinator.registry().published_revision();
                let changed = match self.demand {
                    Some(Demand::Requested { engine_changed }) => {
                        // Attempt recorded before the engine/cgroup callback.
                        self.demand = Some(Demand::Bound {
                            original: identity,
                            base_revision: self.prepared_base,
                        });
                        engine_changed
                    }
                    _ => false,
                };
                budget.spend(1);
                retain_on_refusal!(
                    Phase::PreparationAttempted(original),
                    io.prepare_publication(lane, coordinator, &mut original.raw, changed,)
                );
                (Phase::PreparingAdmissions(original), Ok(Step::Continue))
            }
            Phase::PreparationAttempted(original) => (
                Phase::PreparationAttempted(original),
                Err(SemanticRefusal::Unavailable),
            ),
            Phase::PreparingAdmissions(mut original) => {
                budget.spend(1);
                retain_on_refusal!(
                    Phase::PreparingAdmissions(original),
                    coordinator.prepare_staged_semantic_batch(lane, None)
                );
                // The actual prepared entry/current lease now owns the nested
                // buffers. Refund the overlapping original-report allowance.
                drop(original.reports.take());
                (
                    Phase::BindingKeys {
                        original,
                        cursor: 0,
                    },
                    Ok(Step::Continue),
                )
            }
            Phase::BindingKeys {
                mut original,
                mut cursor,
            } => {
                let Some((prepared, owner)) = coordinator.prepared_joint_parts() else {
                    return (
                        Phase::BindingKeys { original, cursor },
                        Err(SemanticRefusal::Unavailable),
                    );
                };
                if cursor == prepared.entry_count() {
                    budget.spend(1);
                    return (Phase::Ingesting(original), Ok(Step::Continue));
                }
                if let Some(input) = prepared.admission_at(cursor) {
                    if owner.adapter_mut().bind_admitted_key(input).is_ok() && self.grant.is_none()
                    {
                        let grant = retain_on_refusal!(
                            Phase::BindingKeys { original, cursor },
                            SessionDrainGrant::observe(&self.producers, input)
                        );
                        retain_on_refusal!(
                            Phase::BindingKeys { original, cursor },
                            owner.adapter_mut().bind_session_drain(&grant)
                        );
                        self.grant = Some(grant);
                    }
                    if crate::kinds::function_id(&input.s1_facts().function)
                        .and_then(crate::semantics_objects::journal::endpoint_class)
                        == Some(EndpointClass::ProvedIrrelevant)
                    {
                        retain_on_refusal!(
                            Phase::BindingKeys { original, cursor },
                            original.raw.classify_ordinary(input)
                        );
                    }
                }
                cursor += 1;
                budget.spend(1);
                (Phase::BindingKeys { original, cursor }, Ok(Step::Continue))
            }
            Phase::Ingesting(original) => {
                budget.spend(1);
                let identity = original.raw.h0_identity();
                // Retained COMPLETE/claims need actual ingestion even when
                // no new wire arrived. A canonically quiet original may use
                // the existing negative-only path and its mandatory audit.
                let empty_disposition = if self.grant.is_some() {
                    retain_on_refusal!(
                        Phase::Ingesting(original),
                        original.raw.can_dispose_empty(
                            coordinator.joint_capture().adapter(),
                            &self.producers,
                        )
                    )
                } else {
                    false
                };
                if self.grant.is_none() || empty_disposition {
                    coordinator.dispose_prepared_claims_s1();
                    return (Phase::StagingNegative(original), Ok(Step::Continue));
                }
                let result = original.raw.ingest(
                    coordinator.joint_capture_mut().adapter_mut(),
                    &self.producers,
                    self.grant.as_ref().expect("real retained admission grant"),
                );
                match result {
                    Ok(ingested) => (
                        Phase::Claiming {
                            original: ingested,
                            identity,
                            base: self.prepared_base,
                        },
                        Ok(Step::Continue),
                    ),
                    Err((raw, _)) => (
                        Phase::Ingesting(Collected { raw, ..original }),
                        Err(SemanticRefusal::Unavailable),
                    ),
                }
            }
            Phase::StagingNegative(original) => {
                budget.spend(1);
                if coordinator.stage_next_prepared_admission() {
                    return (Phase::StagingNegative(original), Ok(Step::Continue));
                }
                if !coordinator.finish_prepared_semantic_batch(lane) {
                    return (
                        Phase::StagingNegative(original),
                        Err(SemanticRefusal::Unavailable),
                    );
                }
                let identity = original.raw.h0_identity();
                let reason = if original.attempted == 0 {
                    RawDisposeReason::Empty
                } else if original.attempted == RAW_CAPACITY {
                    RawDisposeReason::Capacity
                } else {
                    RawDisposeReason::NoAdmission
                };
                match original.raw.dispose_without_ingest(
                    coordinator.joint_capture_mut(),
                    &self.producers,
                    reason,
                ) {
                    Ok(disposed) => (
                        Phase::Negative {
                            original: disposed,
                            identity,
                            base: self.prepared_base,
                        },
                        Ok(Step::Continue),
                    ),
                    Err((raw, _)) => (
                        Phase::StagingNegative(Collected { raw, ..original }),
                        Err(SemanticRefusal::Unavailable),
                    ),
                }
            }
            Phase::Claiming {
                original,
                identity,
                base,
            } => {
                budget.spend(1);
                let next = retain_on_refusal!(
                    Phase::Claiming {
                        original,
                        identity,
                        base
                    },
                    coordinator.claim_next_prepared_admission(&self.producers, &original)
                );
                let phase = if next.is_some() {
                    Phase::Claiming {
                        original,
                        identity,
                        base,
                    }
                } else {
                    Phase::InstallingClosure {
                        original,
                        identity,
                        base,
                    }
                };
                (phase, Ok(Step::Continue))
            }
            Phase::InstallingClosure {
                original,
                identity,
                base,
            } => {
                budget.spend(1);
                let installed = retain_on_refusal!(
                    Phase::InstallingClosure {
                        original,
                        identity,
                        base
                    },
                    io.with_native(lane, &self.births, |io| coordinator
                        .joint_capture_mut()
                        .adapter_mut()
                        .install_closure_grant(&SessionClosureGrant::observe(io.attachment())))
                );
                if !installed {
                    return (
                        Phase::InstallingClosure {
                            original,
                            identity,
                            base,
                        },
                        Err(SemanticRefusal::Unavailable),
                    );
                }
                // End the immutable Capture/native view before the actual
                // candidate consumer mutably validates that same Capture.
                (
                    Phase::Births {
                        original,
                        identity,
                        base,
                    },
                    Ok(Step::Continue),
                )
            }
            Phase::Births {
                original,
                identity,
                base,
            } => {
                budget.spend(1);
                retain_on_refusal!(
                    Phase::Births {
                        original,
                        identity,
                        base
                    },
                    coordinator.prepare_joint_births(
                        &original,
                        &self.producers,
                        &mut self.births,
                        |candidate, absence, input, binding, proof, adapter| io.consume_birth(
                            lane, candidate, absence, input, binding, proof, adapter
                        ),
                    )
                );
                (
                    Phase::Staging {
                        original,
                        identity,
                        base,
                    },
                    Ok(Step::Continue),
                )
            }
            Phase::Staging {
                mut original,
                identity,
                base,
            } => {
                budget.spend(1);
                let more = retain_on_refusal!(
                    Phase::Staging {
                        original,
                        identity,
                        base
                    },
                    coordinator.stage_next_prepared_admission_with_disposition(
                        &self.producers,
                        &mut original
                    )
                );
                if more {
                    return (
                        Phase::Staging {
                            original,
                            identity,
                            base,
                        },
                        Ok(Step::Continue),
                    );
                }
                if !coordinator.finish_prepared_semantic_batch(lane) {
                    return (
                        Phase::Staging {
                            original,
                            identity,
                            base,
                        },
                        Err(SemanticRefusal::Unavailable),
                    );
                }
                (
                    Phase::Auditing {
                        original,
                        identity,
                        base,
                    },
                    Ok(Step::Continue),
                )
            }
            Phase::Auditing {
                original,
                identity,
                base,
            } => {
                budget.spend(1);
                let mut original = Some(original);
                let result = io.with_native(lane, &self.births, |io| {
                    let attachment = io.attachment();
                    let (_, _, fault) = io.into_parts();
                    coordinator.audit_ingested_quantum(
                        original.take().expect("one actual ingestion"),
                        &self.producers,
                        attachment,
                        &ActualFault(fault),
                    )
                });
                match result {
                    Ok(Ok(frame)) => (
                        Phase::Audited {
                            frame: Some(frame),
                            identity,
                            base,
                        },
                        Ok(Step::Continue),
                    ),
                    Ok(Err((ingested, _))) => (
                        Phase::Auditing {
                            original: ingested,
                            identity,
                            base,
                        },
                        Err(SemanticRefusal::Unavailable),
                    ),
                    Err(reason) => (
                        Phase::Auditing {
                            original: original
                                .expect("native construction refused before acquisition"),
                            identity,
                            base,
                        },
                        Err(reason),
                    ),
                }
            }
            Phase::Negative {
                original,
                identity,
                base,
            } => {
                budget.spend(1);
                let mut original = Some(original);
                let result = io.with_native(lane, &self.births, |io| {
                    let attachment = io.attachment();
                    let (_, _, fault) = io.into_parts();
                    coordinator.audit_disposed_quantum(
                        original.take().expect("one original negative"),
                        &self.producers,
                        attachment,
                        &ActualFault(fault),
                    )
                });
                match result {
                    Ok(Ok(frame)) => (
                        Phase::Audited {
                            frame: Some(frame),
                            identity,
                            base,
                        },
                        Ok(Step::Continue),
                    ),
                    Ok(Err((disposed, _))) => (
                        Phase::Negative {
                            original: disposed,
                            identity,
                            base,
                        },
                        Err(SemanticRefusal::Unavailable),
                    ),
                    Err(reason) => (
                        Phase::Negative {
                            original: original
                                .expect("native construction refused before acquisition"),
                            identity,
                            base,
                        },
                        Err(reason),
                    ),
                }
            }
            Phase::Audited {
                mut frame,
                identity,
                base,
            } => {
                let before = budget.remaining_actions;
                let result = io.with_native(lane, &self.births, |io| {
                    coordinator.commit_joint_batch_with_io(
                        io,
                        &self.producers,
                        &mut frame,
                        &mut budget.remaining_actions,
                    )
                });
                if before == budget.remaining_actions {
                    budget.spend(1);
                }
                match result {
                    Ok(Ok(JointCommitProgress::Published(receipt))) => {
                        if let Some(Demand::Bound {
                            original,
                            base_revision,
                        }) = self.demand
                        {
                            if original != identity || base_revision != base {
                                return (Phase::Idle, Err(SemanticRefusal::Unavailable));
                            }
                            self.demand = Some(Demand::Published(receipt));
                        }
                        (Phase::Idle, Ok(Step::Published))
                    }
                    Ok(Ok(JointCommitProgress::Pending)) => (
                        Phase::Audited {
                            frame,
                            identity,
                            base,
                        },
                        Ok(Step::Yield),
                    ),
                    Ok(Err(_)) => (
                        Phase::Audited {
                            frame,
                            identity,
                            base,
                        },
                        Err(SemanticRefusal::Unavailable),
                    ),
                    Err(reason) => (
                        Phase::Audited {
                            frame,
                            identity,
                            base,
                        },
                        Err(reason),
                    ),
                }
            }
        }
    }
}

/// No Session borrow survives a leaf call. The retained producer allocation
/// is captured once; every operation checks it against the same live owner.
#[allow(dead_code)] // The actual Session bridge is staged until ordinary driver selection.
pub(super) struct SessionMachineIo {
    pub(super) producers: SessionDrainProducers,
}

#[allow(dead_code)] // Paired with the inactive actual Session entrypoints below.
impl SessionMachineIo {
    fn live<'a>(
        &self,
        lane: &'a mut AttestedSemanticLane,
    ) -> Result<&'a mut crate::inventory_semantics::LiveLane, SemanticRefusal> {
        if lane.domain() != self.producers.native_domain() {
            return Err(SemanticRefusal::Unavailable);
        }
        let live = lane
            .live
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        if live.gated
            || live.finished
            || !live
                .session
                .drain_producers()
                .as_ref()
                .is_some_and(|own| own.same_producers(&self.producers))
        {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(live)
    }
}

impl JointMachineIo for SessionMachineIo {
    fn producers(&self) -> &SessionDrainProducers {
        &self.producers
    }

    fn collect_raw(
        &mut self,
        lane: &mut AttestedSemanticLane,
        adapter: &mut JournalAdapter,
        reserve: &SemanticResourceReserver,
        capacity: usize,
        work: usize,
    ) -> Result<(RawJointQuantum, Option<DispatchPoll>), RawQuantumRefusal> {
        let live = self.live(lane).map_err(|_| RawQuantumRefusal::Stopped)?;
        let (drain, rows, fault) = live
            .session
            .joint_collection_io()
            .map_err(|_| RawQuantumRefusal::DrainUnbound)?;
        let rows = rows.ok_or(RawQuantumRefusal::ForeignDescriptors)?;
        RawJointQuantum::begin_bounded_with_adapter(
            drain,
            rows,
            capacity,
            work,
            None,
            &fault,
            &self.producers,
            |bytes| reserve.reserve(bytes),
            adapter,
        )
    }

    fn continue_raw(
        &mut self,
        lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        adapter: &mut JournalAdapter,
        work: usize,
    ) -> Result<DispatchPoll, RawQuantumRefusal> {
        let live = self.live(lane).map_err(|_| RawQuantumRefusal::Stopped)?;
        let (drain, rows, fault) = live
            .session
            .joint_collection_io()
            .map_err(|_| RawQuantumRefusal::DrainUnbound)?;
        let rows = rows.ok_or(RawQuantumRefusal::ForeignDescriptors)?;
        raw.continue_bounded_with_adapter(drain, rows, work, None, &fault, &self.producers, adapter)
    }

    fn tick_collected(
        &mut self,
        lane: &mut AttestedSemanticLane,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.live(lane)?;
        lane.tick_collected(bindings, raw)
    }

    fn pending_h0_at_q_storage_bytes(
        &self,
        lane: &AttestedSemanticLane,
        raw: &RawJointQuantum,
        adapter: &JournalAdapter,
        q: &CollectedFinishQ,
        discovery: &DiscoveryDomain,
    ) -> Result<usize, SemanticRefusal> {
        let live = lane.live.as_deref().ok_or(SemanticRefusal::Unavailable)?;
        if live.gated
            || live.finished
            || !live.session.matches_collected_finish_q(q)
            || !live
                .session
                .drain_producers()
                .as_ref()
                .is_some_and(|own| own.same_producers(&self.producers))
        {
            return Err(SemanticRefusal::Unavailable);
        }
        live.capture
            .pending_h0_at_q_storage_bytes(raw, adapter, &self.producers, discovery, q)
            .map_err(|_| SemanticRefusal::ProviderStorage)
    }

    fn resolve_pending_h0_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        adapter: &JournalAdapter,
        q: &CollectedFinishQ,
        discovery: &DiscoveryDomain,
        report: &mut TickReport,
    ) -> Result<(), SemanticRefusal> {
        let live = self.live(lane)?;
        live.capture
            .resolve_collected_pending_at_q(
                &mut live.session,
                raw,
                adapter,
                &self.producers,
                discovery,
                q,
                report,
            )
            .map_err(|_| SemanticRefusal::Unavailable)
    }

    fn prepare_publication(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        engine_changed: bool,
    ) -> anyhow::Result<()> {
        self.live(lane).map_err(anyhow::Error::msg)?;
        coordinator.prepare_joint_publication(engine_changed, lane, raw, &self.producers)
    }

    #[allow(clippy::too_many_arguments)] // Delegate the same original candidate/negative/native subject to Capture.
    fn consume_birth(
        &mut self,
        lane: &mut AttestedSemanticLane,
        candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        input: &AdmittedInstanceCall,
        binding: &SemanticCallerBinding,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
    ) -> Result<RetainedBirthWitness, BirthObservationRefusal> {
        let live = self
            .live(lane)
            .map_err(|_| BirthObservationRefusal::BindingMismatch)?;
        live.capture.consume_birth(
            &mut live.session,
            candidate,
            absence,
            input,
            binding,
            &live.attached,
            proof,
            adapter,
        )
    }

    fn acquire_absence(
        &mut self,
        lane: &mut AttestedSemanticLane,
        binding: &SemanticCallerBinding,
        slot: u32,
        adapter: &mut JournalAdapter,
    ) -> Result<CommittedAbsenceBirth, BirthObservationRefusal> {
        let live = self
            .live(lane)
            .map_err(|_| BirthObservationRefusal::BindingMismatch)?;
        live.capture.acquire_absence_birth(
            &mut live.session,
            binding,
            &live.attached,
            slot,
            adapter,
        )
    }

    fn absence_query_storage_bytes(
        &self,
        lane: &AttestedSemanticLane,
        object: PinnedObjectId,
        target_copy: usize,
    ) -> Option<usize> {
        let live = lane.live.as_deref()?;
        if live.gated
            || live.finished
            || !self
                .producers
                .same_producers(&live.session.drain_producers()?)
        {
            return None;
        }
        live.session
            .absence_query_storage_bytes(object, target_copy)
    }

    fn with_native<R>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        witnesses: &RetainedJointBirths,
        inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        self.live(lane)?;
        lane.with_joint_commit_io_for_births(witnesses, inspect)
    }
}

#[allow(dead_code)] // Source/type-checked actual Session entrypoints; ordinary selection remains gated.
impl AttestedSemanticLane {
    /// Bind the initial machine to the actual Session and canonical pool,
    /// before the first publication request. This performs no EVENTS/H0 work.
    pub(crate) fn initialize_joint(
        &mut self,
        coordinator: &InventoryCoordinator<OsProcessSource>,
    ) -> Result<(), SemanticRefusal> {
        let live = self
            .live
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        if live.gated || live.finished {
            return Err(SemanticRefusal::Unavailable);
        }
        if live.joint_machine.is_none() {
            if live.ticks != 0 || !live.stashed_refresh.is_empty() {
                return Err(SemanticRefusal::Unavailable);
            }
            let producers = live
                .session
                .drain_producers()
                .ok_or(SemanticRefusal::Unavailable)?;
            live.joint_machine = Some(LiveJointMachine::new(
                &producers,
                &coordinator.registry().semantic_storage_reserver(),
            )?);
        }
        Ok(())
    }

    /// Inactive entrypoint: callers have not yet selected this machine in the
    /// ordinary driver. The temporary move splits scheduling state only; the
    /// canonical Capture/model/ledger and native Session stay in place.
    fn with_machine<R>(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        service: impl FnOnce(
            &mut LiveJointMachine,
            &mut Self,
            &mut InventoryCoordinator<OsProcessSource>,
            &mut SessionMachineIo,
        ) -> Result<R, SemanticRefusal>,
    ) -> Result<R, SemanticRefusal> {
        self.initialize_joint(coordinator)?;
        let live = self
            .live
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        if live.gated || live.finished {
            return Err(SemanticRefusal::Unavailable);
        }
        let producers = live
            .session
            .drain_producers()
            .ok_or(SemanticRefusal::Unavailable)?;
        let mut machine = live
            .joint_machine
            .take()
            .expect("one original scheduling owner");
        let mut io = SessionMachineIo { producers };
        let result = service(&mut machine, self, coordinator, &mut io);
        self.live
            .as_deref_mut()
            .expect("service cannot extract its native owner")
            .joint_machine = Some(machine);
        result
    }

    pub(crate) fn service_joint(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        mode: JointServiceMode,
        budget: &mut JointWorkBudget,
    ) -> Result<JointServiceProgress, SemanticRefusal> {
        self.with_machine(coordinator, |machine, lane, coordinator, io| {
            machine.service_with_io(lane, coordinator, io, mode, budget)
        })
    }

    pub(crate) fn begin_joint_commit(
        &mut self,
        engine_changed: bool,
    ) -> Result<(), JointCommitRefusal> {
        let machine = self
            .live
            .as_deref_mut()
            .and_then(|live| live.joint_machine.as_mut())
            .ok_or(JointCommitRefusal::NotInitialized)?;
        machine.begin_commit(engine_changed)
    }

    pub(crate) fn poll_joint_commit(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        budget: &mut JointWorkBudget,
    ) -> Result<JointCommitProgress, SemanticRefusal> {
        self.with_machine(coordinator, |machine, lane, coordinator, io| {
            machine.poll_commit_with_io(lane, coordinator, io, budget)
        })
    }
}
