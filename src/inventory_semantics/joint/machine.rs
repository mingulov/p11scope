//! SPDX-License-Identifier: GPL-3.0-or-later
//! Inactive, single-owner service of the actual collected Joint pipeline.
//! This module retains originals and scheduling positions; all authority stays
//! in Capture, prepared admissions, the canonical ledger and the real frame.

use super::{JointCommitIo, RetainedJointBirths};
use crate::attach::{BirthObservationRefusal, CollectedFinishQ, SessionDrainProducers};
use crate::discovery::caller_registry::OsProcessSource;
use crate::discovery::caller_registry::instance_input::AdmittedInstanceCall;
use crate::discovery::engine::inventory_coordinator::semantics::CompletedJointFinish;
use crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding;
use crate::discovery::engine::inventory_coordinator::{
    BatchReceipt, InventoryCoordinator, JointCommitProgress,
};
use crate::discovery::identity::PinnedObjectId;
use crate::discovery::instances::{InstanceId, MAX_INSTANCES, MAX_PENDING};
use crate::events::{DiscoveryDomain, DispatchPoll};
#[cfg(test)]
use crate::inventory_semantics::FinishSite;
use crate::inventory_semantics::{
    AttestedSemanticLane, JOINT_FINISH_NO_PROGRESS_LIMIT, JOINT_FINISH_STORAGE_RETRIES,
    LaneDrainOutcome, LaneNegative, MAX_LANE_NEGATIVES, SemanticBatch, SemanticRefusal,
    finish_grant_admissible,
};
use crate::semantic_capture::{
    CommittedAbsenceBirth, CurrentPartitionReceipt, H0BirthCandidate, RetainedBirthWitness,
    TickOutcome, TickReport,
};
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceReserver,
};
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
use p11scope_ebpf_common::event_type;
use std::time::{Duration, Instant};

const RAW_CAPACITY: usize = 4_096;
// The actual shared binder selects at most four caller/provider pairs. Its
// no-call receipts join the same original H0 report, never a second stage.
const REFRESHES_PER_BIND: usize = 4;
// Consecutive true no-job stalls before the guard expires the stuck
// waiters as unobserved and publishes with the joined outcomes kept.
// A pass counts only when it appends no outcome or receipt AND attempts
// no scan for an awaited key AND no job for an awaited key has a future
// deadline AND no retained hold is inside its horizon. Refused-scan
// passes never count: a scan attempted (even if refused), a future
// deadline, a hold inside its horizon, or any appended outcome or
// receipt resets the count, so honest slow drains and deadline waits
// can never trip it.
const H0_NO_PROGRESS_BOUND: u32 = 16;

// Wall-time bound on a consecutive no-progress Audited stall inside one
// Joint Finish: polls that spend no budget action and publish nothing.
// The stall clock starts at the first consecutive stall; any spending,
// publication or non-finish visit resets it, and reaching the bound
// records a named gap and refuses, so a wedged finish ends finitely
// through the disposition hold instead of polling Pending forever.
// Calibrated to the retained 600-poll horizon: the retained stop wait
// paces every poll to 10 ms, so 600 polls is about 6 s there. Unlike a
// poll count, the wall-time horizon is the same on the retained wait
// and the promotion-winding tick path (whose unpaced polls would
// otherwise trip the same count far sooner). Matches the cells'
// established wedge threshold; legitimate stalls are handfuls of polls
// over milliseconds.
pub(crate) const JOINT_FINISH_NO_PROGRESS_TIMEOUT: Duration =
    Duration::from_millis(10 * (JOINT_FINISH_NO_PROGRESS_LIMIT as u64));

// Wall-time backstop for the driver's Joint Finish settle loop: twice
// the machine's Audited no-progress timeout plus a margin, so a
// consecutively stalled finish always trips the machine's correctly
// named bound first (the next settle step then abandons via the latch)
// and the settle bound only fires on finishes that keep making
// progress yet never complete. The settle measures total time, never
// progress, so its gap is worded as total time with its own cause.
pub(crate) const JOINT_FINISH_SETTLE_TIMEOUT: Duration =
    Duration::from_millis(10 * (JOINT_FINISH_NO_PROGRESS_LIMIT as u64) * 2 + 1000);

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
    /// The Session override admits the live Finish request against the
    /// owning lane; the default refuses. A test may forward only the
    /// existing immediate admission gate.
    #[allow(dead_code)] // Default refuses; the Session override serves the live Finish.
    fn request_finish_stop(
        &mut self,
        _lane: &mut AttestedSemanticLane,
    ) -> Result<(), SemanticRefusal> {
        Err(SemanticRefusal::Unavailable)
    }
    #[allow(dead_code)] // Default observes no Q; the Session override serves the live Finish.
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
    /// Whether the last discovery service call progressed the Engine
    /// without moving records. The discovery loop yields only after 64
    /// consecutive credits without progress, so graph work is not capped
    /// by the record count.
    #[allow(dead_code)] // Observed once the discovery loop spends graph credits.
    fn finish_discovery_progressed(
        &self,
        coordinator: &InventoryCoordinator<OsProcessSource>,
    ) -> bool {
        coordinator.collected_finish_progressed()
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
    /// Terminal forwarding keeps the ordinary gate closed. The actual Session
    /// overrides these leaves with current-Q checks; test I/O still runs its
    /// same real Capture/owner implementation beneath that boundary.
    fn tick_collected_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
        _q: &CollectedFinishQ,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.tick_collected(lane, bindings, raw)
    }

    fn prepare_publication_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        changed: bool,
        _q: &CollectedFinishQ,
    ) -> anyhow::Result<()> {
        self.prepare_publication(lane, coordinator, raw, changed)
    }

    #[allow(clippy::too_many_arguments)] // Original candidate and actual Q remain separate borrowed authority.
    fn consume_birth_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        input: &AdmittedInstanceCall,
        binding: &SemanticCallerBinding,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
        _q: &CollectedFinishQ,
    ) -> Result<RetainedBirthWitness, BirthObservationRefusal> {
        self.consume_birth(lane, candidate, absence, input, binding, proof, adapter)
    }

    fn with_native_at_q<R>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        witnesses: &RetainedJointBirths,
        _q: &CollectedFinishQ,
        inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        self.with_native(lane, witnesses, inspect)
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
    /// Expire the no-progress guard's true stall through the owning Capture.
    /// Fail closed unless the same H0 owner supplies the operation.
    fn expire_collected_h0_for_guard(
        &mut self,
        _lane: &mut AttestedSemanticLane,
        _raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal> {
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
    /// A Requested demand already took its one fresh pull past a stale
    /// no-backlog poll, so the quiet case still binds after one pull.
    request_pulled: bool,
    /// Consecutive true no-job stalls: incomplete merges that appended no
    /// outcome or receipt, attempted no scan for an awaited key, and saw
    /// no future-deadline job or in-horizon hold. Any progress, scan,
    /// future deadline or hold resets it; reaching the bound expires the
    /// stuck waiters as unobserved and publishes with joined outcomes kept.
    h0_idle_passes: u32,
    /// The guard trip cause, set when the bound expires the stall and
    /// cleared by the next progressing merge.
    h0_guard_trip: Option<&'static str>,
}

impl Collected {
    fn h0_accumulated(&self) -> Option<(usize, usize)> {
        self.reports.as_ref().and_then(|reports| {
            reports
                .batch
                .as_ref()
                .map(|batch| (batch.outcomes.len(), batch.current.len()))
        })
    }

    /// Count one incomplete merge toward the no-progress bound. Returns
    /// true when the bound trips a true no-job stall. Any newly
    /// accumulated outcome or receipt resets the count and clears a
    /// stale trip cause, as does any scan attempted for an awaited key
    /// (even if refused), any job for an awaited key with a future
    /// deadline, or any retained hold inside its horizon — so only a
    /// waiter set with no job, no hold, no deadline and no scan can
    /// trip, and the drive line never publishes a trip that expired
    /// nothing.
    fn note_h0_merge(
        &mut self,
        before: Option<(usize, usize)>,
        has_pending_scans: bool,
        has_future_job: bool,
        has_hold: bool,
    ) -> bool {
        if self.h0_accumulated() != before {
            self.h0_idle_passes = 0;
            self.h0_guard_trip = None;
            return false;
        }
        if has_pending_scans || has_future_job || has_hold {
            self.h0_idle_passes = 0;
            self.h0_guard_trip = None;
            return false;
        }
        self.h0_idle_passes = self.h0_idle_passes.saturating_add(1);
        self.h0_idle_passes >= H0_NO_PROGRESS_BOUND
    }
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

enum FinishDiscovery {
    Pending,
    AtQ,
}
struct FinishControl {
    q: Option<Box<CollectedFinishQ>>,
    // Held only: the Q-box lease refunds when the Finish control drops.
    #[allow(dead_code)]
    q_storage: Option<ResourceLease>,
    discovery: FinishDiscovery,
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
    FinishStopReady(Collected),
    FinishStopReport {
        original: Collected,
        pending: PendingQReport,
    },
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
    nested_limit: usize,
    nested_used: usize,
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

/// Binding budgets computed from measured Binding inputs. A pure function
/// of its arguments so tests can exercise the exact production formula.
struct CollectedBudgets {
    receipt_limit: usize,
    nested_per_receipt: usize,
    nested_limit: usize,
    bytes: usize,
}

fn collected_budgets(
    partitions: usize,
    stashed_count: usize,
    stashed_nested: usize,
    watched_bound: usize,
) -> Option<CollectedBudgets> {
    let receipt_limit = partitions
        .checked_add(stashed_count)?
        .checked_add(REFRESHES_PER_BIND)?;
    let allocation_limit = receipt_limit.checked_next_power_of_two()?;
    let nested_per_receipt =
        array_bytes::<InstanceId>(MAX_INSTANCES)?.checked_add(watched_bound)?;
    // Nested bytes are bounded globally, not per receipt times the
    // count: every pass receipt names its own partition's current
    // instances from the router's shared minted pool, so the distinct
    // keys together name at most MAX_INSTANCES ids. Each id list is
    // collected with capacity at most twice its length plus one
    // minimal allocation (pinned-toolchain growth law), plus its own
    // padding and one watched-file copy. The merge checks below
    // enforce this cumulative limit before taking any batch.
    let tick_nested = (|| {
        MAX_INSTANCES
            .checked_mul(2)?
            .checked_add(partitions.checked_mul(4)?)?
            .checked_mul(size_of::<InstanceId>())?
            .checked_add(partitions.checked_mul(OWNED_ALLOCATION_PADDING)?)?
            .checked_add(partitions.checked_mul(watched_bound)?)
    })()?;
    // The binder runs after the reservation measured the stash and leaves
    // up to REFRESHES_PER_BIND receipts there, each within
    // nested_per_receipt by the merge-time per-receipt check. Reserve four
    // full per-receipt allowances so any four post-reservation receipts
    // fit regardless of id overlap with the tick scans.
    let binder_margin = REFRESHES_PER_BIND.checked_mul(nested_per_receipt)?;
    // Outcome-owned invalidation id lists merge into the same accumulator
    // with no receipt of their own, so they need their own bounded term:
    // at most one id list per merged outcome (merged outcomes are capped
    // at MAX_INSTANCES by the count checks), the lists together name at
    // most MAX_INSTANCES distinct minted ids (observation losses name
    // evicted keys, prior-id invalidations name live keys, disjoint
    // within the mint budget), each collected with the pinned growth law.
    let outcome_nested = (|| {
        MAX_INSTANCES
            .checked_mul(2)?
            .checked_add(MAX_INSTANCES.checked_mul(4)?)?
            .checked_mul(size_of::<InstanceId>())?
            .checked_add(MAX_INSTANCES.checked_mul(OWNED_ALLOCATION_PADDING)?)
    })()?;
    let nested_limit = tick_nested
        .checked_add(stashed_nested)?
        .checked_add(binder_margin)?
        .checked_add(outcome_nested)?;
    // Both the accumulator and the current callback's original buffers
    // coexist. Each Current keeps its actual IDs/watched-file allocation.
    // Empty-input retries resolve those same jobs, never add interests.
    let bytes = (|| {
        size_of::<CollectedReports>()
            .checked_add(array_bytes::<TickOutcome>(MAX_INSTANCES)?.checked_mul(2)?)?
            .checked_add(array_bytes::<CurrentPartitionReceipt>(allocation_limit)?.checked_mul(2)?)?
            .checked_add(array_bytes::<LaneNegative>(MAX_LANE_NEGATIVES)?.checked_mul(2)?)?
            .checked_add(nested_limit.checked_mul(2)?)
    })()?;
    Some(CollectedBudgets {
        receipt_limit,
        nested_per_receipt,
        nested_limit,
        bytes,
    })
}

impl CollectedReports {
    fn new(
        lane: &AttestedSemanticLane,
        raw: &RawJointQuantum,
        reserve: &SemanticResourceReserver,
    ) -> Result<Self, SemanticRefusal> {
        // Receipts are minted per input partition, never per record: one
        // scan job per (caller image, provider slot) key, one accepted scan
        // per job per pass (an accepted scan resolves every waiting call of
        // its key, so the job is never requeued), plus whatever the refresh
        // stash still holds and the binder's at most four refresh receipts.
        // Count the distinct CALL partitions with an allocation-free scalar
        // scan, so counting itself needs no lease. Event slots over-approximate
        // attachment file slots (the slot-to-endpoint map is a function), and
        // non-call records mint no jobs, so this count still dominates.
        let records = raw
            .h0_input(lane.domain(), MAX_PENDING)
            .map_err(|_| SemanticRefusal::ProviderStorage)?
            .0;
        let mut partitions = 0usize;
        for (index, record) in records.iter().enumerate() {
            if record.base.event.event_type != event_type::CALL {
                continue;
            }
            let image = record.base.event.image;
            let key = (image.task_cookie, image.exec_id, record.base.event.slot);
            let seen = records[..index].iter().any(|prior| {
                prior.base.event.event_type == event_type::CALL
                    && prior.base.event.image.task_cookie == key.0
                    && prior.base.event.image.exec_id == key.1
                    && prior.base.event.slot == key.2
            });
            if !seen {
                partitions += 1;
            }
        }
        // Stashed refresh receipts drain into this same pass's first tick.
        // They already exist, so measure their exact nested bytes instead
        // of bounding them. An unmeasurable receipt cannot be covered.
        let mut stashed_count = 0usize;
        let mut stashed_nested = 0usize;
        if let Some(live) = lane.live.as_deref() {
            for receipt in live.stashed_refresh.stashed.iter() {
                stashed_count = stashed_count
                    .checked_add(1)
                    .ok_or(SemanticRefusal::ProviderStorage)?;
                stashed_nested = stashed_nested
                    .checked_add(
                        receipt
                            .owned_storage_bytes()
                            .ok_or(SemanticRefusal::ProviderStorage)?,
                    )
                    .ok_or(SemanticRefusal::ProviderStorage)?;
            }
        }
        let mut watched_bound = 0;
        for object in lane.subset().required().keys() {
            watched_bound = watched_bound.max(
                lane.subset()
                    .pins()
                    .retained_target_copy_allocation_charge(*object)
                    .ok_or(SemanticRefusal::ProviderStorage)?,
            );
        }
        let budgets = collected_budgets(partitions, stashed_count, stashed_nested, watched_bound)
            .ok_or(SemanticRefusal::ProviderStorage)?;
        let storage = reserve
            .reserve(budgets.bytes)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        let mut outcomes = Vec::new();
        let mut current = Vec::new();
        let mut negatives = Vec::new();
        outcomes
            .try_reserve_exact(MAX_INSTANCES)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        current
            .try_reserve_exact(budgets.receipt_limit)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        negatives
            .try_reserve_exact(MAX_LANE_NEGATIVES)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        if outcomes.capacity() != MAX_INSTANCES
            || current.capacity() != budgets.receipt_limit
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
                has_pending_scans: false,
                awaited_jobs_pending: false,
                awaited_hold_pending: false,
            }),
            refused: None,
            receipt_limit: budgets.receipt_limit,
            nested_per_receipt: budgets.nested_per_receipt,
            nested_limit: budgets.nested_limit,
            nested_used: 0,
            _storage: storage,
        })
    }

    #[cfg(test)]
    fn for_test(
        domain: crate::attach::capture::NativeDomainId,
        budgets: CollectedBudgets,
        storage: ResourceLease,
    ) -> Result<Self, SemanticRefusal> {
        let mut outcomes = Vec::new();
        let mut current = Vec::new();
        let mut negatives = Vec::new();
        outcomes
            .try_reserve_exact(MAX_INSTANCES)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        current
            .try_reserve_exact(budgets.receipt_limit)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        negatives
            .try_reserve_exact(MAX_LANE_NEGATIVES)
            .map_err(|_| SemanticRefusal::ProviderStorage)?;
        if outcomes.capacity() != MAX_INSTANCES
            || current.capacity() != budgets.receipt_limit
            || negatives.capacity() != MAX_LANE_NEGATIVES
        {
            return Err(SemanticRefusal::ProviderStorage);
        }
        Ok(Self {
            batch: Some(SemanticBatch {
                domain,
                outcomes,
                current,
                negatives,
                observed_ns: 0,
                awaiting_floor: None,
                shed_floor: None,
                exhausted: false,
                has_pending_scans: false,
                awaited_jobs_pending: false,
                awaited_hold_pending: false,
            }),
            refused: None,
            receipt_limit: budgets.receipt_limit,
            nested_per_receipt: budgets.nested_per_receipt,
            nested_limit: budgets.nested_limit,
            nested_used: 0,
            _storage: storage,
        })
    }

    #[cfg(test)]
    fn receipt_limit_for_test(&self) -> usize {
        self.receipt_limit
    }

    #[cfg(test)]
    fn nested_per_receipt_for_test(&self) -> usize {
        self.nested_per_receipt
    }

    #[cfg(test)]
    fn nested_limit_for_test(&self) -> usize {
        self.nested_limit
    }

    #[cfg(test)]
    fn nested_used_for_test(&self) -> usize {
        self.nested_used
    }

    fn merge(&mut self, mut incoming: SemanticBatch) -> Result<bool, SemanticRefusal> {
        let batch = self.batch.as_mut().expect("not staged until H0 finishes");
        // The cumulative nested check mirrors the count checks: measure the
        // incoming receipts' and outcomes' exact bytes first. An
        // unmeasurable entry, an overflowing sum, or a total past the
        // prepaid limit refuses before any field moves; the retained
        // incoming batch keeps its diagnosis.
        let incoming_nested: Option<usize> = incoming
            .current
            .iter()
            .try_fold(0usize, |sum, receipt| {
                sum.checked_add(receipt.owned_storage_bytes()?)
            })
            .and_then(|sum| {
                incoming.outcomes.iter().try_fold(sum, |sum, outcome| {
                    sum.checked_add(outcome.owned_storage_bytes()?)
                })
            });
        let nested_total = incoming_nested.and_then(|nested| self.nested_used.checked_add(nested));
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
            })
            && nested_total.is_some_and(|total| total <= self.nested_limit);
        if !fits {
            self.refused = Some(incoming);
            return Err(SemanticRefusal::ProviderStorage);
        }
        self.nested_used = nested_total.expect("the fits check measured this same total");
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
        let incoming_nested: Option<usize> = incoming
            .current()
            .iter()
            .try_fold(0usize, |sum, receipt| {
                sum.checked_add(receipt.owned_storage_bytes()?)
            })
            .and_then(|sum| {
                incoming.outcomes().iter().try_fold(sum, |sum, outcome| {
                    sum.checked_add(outcome.owned_storage_bytes()?)
                })
            });
        let nested_total = incoming_nested.and_then(|nested| self.nested_used.checked_add(nested));
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
            || !nested_total.is_some_and(|total| total <= self.nested_limit)
        {
            return Err(SemanticRefusal::ProviderStorage);
        }
        self.nested_used = nested_total.expect("the merge checks measured this same total");
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

/// Which Staging sub-exit refused, retained for diagnosis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StagingDetail {
    /// The per-admission staging step refused with its exact variant,
    /// at this stage cursor.
    StageNext { reason: &'static str, stage: usize },
    /// The batch completion check found this cursor state.
    Finish {
        claim: usize,
        stage: usize,
        len: usize,
        domain: bool,
    },
}

impl std::fmt::Display for StagingDetail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StageNext { reason, stage } => write!(f, "stage_next:{reason}@{stage}"),
            Self::Finish {
                claim,
                stage,
                len,
                domain,
            } => write!(
                f,
                "finish:claim={claim},stage={stage},len={len},domain={domain}"
            ),
        }
    }
}

/// The recorded Audited no-progress trip: the wall-time bound fired on a
/// wedged finish. Commit-free by necessity: the wedged publication stands
/// in front of the commit, so the staged gap cannot commit while the
/// wedge stands; the exit hold reads this flag and names the wedge on
/// stderr instead. Counts only; no identities, paths or payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FinishNoProgressTrip {
    /// Consecutive no-progress Audited polls observed when the bound fired.
    pub(crate) polls: u32,
    /// Wall time stalled without progress when the bound fired.
    pub(crate) stalled: Duration,
}

/// Scheduling state over the original owner, not an alternate capture/model.
pub(crate) struct LiveJointMachine {
    producers: SessionDrainProducers,
    ledger: Option<CollectedLedgerBinding>,
    phase: Option<Phase>,
    state: RunState,
    grant: Option<SessionDrainGrant>,
    /// Staging diagnosis. Set only on the cold refusal path; a
    /// refused machine retains Staging, so no later success can make
    /// it stale. Read by tests only.
    #[cfg_attr(not(test), allow(dead_code))]
    staging_detail: Option<StagingDetail>,
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
    finish: Option<FinishControl>,
    finish_original: Option<RawQuantumIdentity>,
    finish_disposed: Option<DisposedJointQuantum>,
    finish_completed: Option<CompletedJointFinish>,
    finish_receipt: Option<BatchReceipt>,
    /// Retryable `ProviderStorage` refusals seen inside this Finish. Never
    /// reset: retryable refusals occur only in the Finish tail, so the cap
    /// bounds the tail. The 100th latches the disposition.
    finish_storage_retries: u16,
    /// Consecutive no-progress Audited polls inside this Finish: a
    /// diagnostic count for the gap text and the recorded trip. Any
    /// spending, publication or running visit resets it; the
    /// wall-time bound (not the count) trips the refusal.
    finish_no_progress_polls: u32,
    /// Wall-clock start of the current consecutive no-progress Audited
    /// stall, if any. Shared by the finish and running bounds: any
    /// spending or publication clears it, and a mode flip restarts
    /// it; the wall-time bound trips when the stall reaches it.
    finish_no_progress_since: Option<Instant>,
    /// The recorded Audited no-progress trip, if the wall-time bound
    /// fired. Set once per Finish, never cleared: the trip latches the
    /// disposition and the lane is held past it.
    finish_no_progress_trip: Option<FinishNoProgressTrip>,
    /// Consecutive no-progress Audited polls on the running commit
    /// path: a diagnostic count for the gap text and the recorded
    /// trip. Any spending, publication or finish visit resets it;
    /// the wall-time bound (not the count) trips the refusal.
    audit_no_progress_polls: u32,
    /// The recorded running-commit Audited no-progress trip, if the
    /// wall-time bound fired. Set once per demand, never cleared:
    /// the trip latches the disposition and the lane is held past it.
    audit_no_progress_trip: Option<FinishNoProgressTrip>,
    #[cfg(test)]
    refuse_finish_q_merge_once: bool,
    #[cfg(test)]
    refuse_pending_q_merge_once: bool,
    // Armed one-shot fault for the latch tests (read at each site).
    #[cfg(test)]
    inject: Option<FinishSite>,
    // Posed Audited stall for the no-progress twin: the arm skips its
    // commit, spends nothing and stays Audited, the same observable as
    // a live no-progress poll. Production never sets this.
    #[cfg(test)]
    pose_no_progress_poll: bool,
    // All original phase buffers and birth leases drop before inline storage.
    _storage: ResourceLease,
}

#[cfg(test)]
thread_local! {
    static FINISH_Q_ADDR: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

struct ActualFault<'a>(&'a dyn FaultEpoch);
impl FaultEpoch for ActualFault<'_> {
    fn fault_epoch(&self) -> Result<u64, FaultReadError> {
        self.0.fault_epoch()
    }
}

fn native_for_phase<I: JointMachineIo, R>(
    io: &mut I,
    lane: &mut AttestedSemanticLane,
    births: &RetainedJointBirths,
    q: Option<&CollectedFinishQ>,
    inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
) -> Result<R, SemanticRefusal> {
    match q {
        Some(q) => io.with_native_at_q(lane, births, q, inspect),
        None => io.with_native(lane, births, inspect),
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
            staging_detail: None,
            births: RetainedJointBirths::new(),
            absence_binding: 0,
            absence_after: None,
            absence_entry: 0,
            demand: None,
            prepared_base: 0,
            finish: None,
            finish_original: None,
            finish_disposed: None,
            finish_completed: None,
            finish_receipt: None,
            finish_storage_retries: 0,
            finish_no_progress_polls: 0,
            finish_no_progress_since: None,
            finish_no_progress_trip: None,
            audit_no_progress_polls: 0,
            audit_no_progress_trip: None,
            #[cfg(test)]
            refuse_finish_q_merge_once: false,
            #[cfg(test)]
            refuse_pending_q_merge_once: false,
            #[cfg(test)]
            inject: None,
            #[cfg(test)]
            pose_no_progress_poll: false,
            _storage: storage,
        })
    }

    /// Pose (or clear) an Audited stall: while posed, Audited polls
    /// skip the commit and report Pending without spending, as a live
    /// no-progress poll would. The pose covers running polls too (the
    /// finish twin only poses around finish polls, so it is unaffected).
    #[cfg(test)]
    pub(crate) fn pose_no_progress_poll_for_test(&mut self, on: bool) {
        self.pose_no_progress_poll = on;
    }

    /// Backdate (or clear) the current stall-clock start, so the twin
    /// can pose a stall of any wall-time age without waiting it out.
    #[cfg(test)]
    pub(crate) fn set_finish_no_progress_since_for_test(&mut self, since: Option<Instant>) {
        self.finish_no_progress_since = since;
    }

    /// The recorded Audited no-progress trip, if the wall-time bound fired.
    #[cfg(test)]
    pub(crate) fn finish_no_progress_trip_for_test(&self) -> Option<FinishNoProgressTrip> {
        self.finish_no_progress_trip
    }

    /// The recorded running-commit Audited no-progress trip, if fired.
    #[cfg(test)]
    pub(crate) fn audit_no_progress_trip_for_test(&self) -> Option<FinishNoProgressTrip> {
        self.audit_no_progress_trip
    }

    /// The current transaction's Collected, across every phase that
    /// carries one (the same coverage as `h0_guard_trip_for_test`).
    #[cfg(test)]
    fn collected_mut_for_test(&mut self) -> Option<&mut Collected> {
        match self.phase.as_mut()? {
            Phase::Collecting(value)
            | Phase::Binding(value)
            | Phase::AwaitH0(value)
            | Phase::Preparing(value)
            | Phase::PreparationAttempted(value)
            | Phase::FinishStopReady(value)
            | Phase::PreparingAdmissions(value)
            | Phase::Ingesting(value)
            | Phase::StagingNegative(value) => Some(value),
            Phase::PendingQ { original, .. }
            | Phase::FinishStopReport { original, .. }
            | Phase::BindingKeys { original, .. } => Some(original),
            _ => None,
        }
    }

    /// Pose (or clear) a stale guard-trip cause on the current
    /// transaction, so the twin can stage the cause the PendingQ path
    /// would leave behind without reaching that unreachable path.
    #[cfg(test)]
    pub(crate) fn pose_h0_guard_trip_for_test(&mut self, cause: Option<&'static str>) {
        self.collected_mut_for_test()
            .expect("a transaction Collected carries the guard cause")
            .h0_guard_trip = cause;
    }

    /// Drive one real `note_h0_merge` against the current transaction
    /// with chosen signals, so the twin can pin each reset site
    /// deterministically.
    #[cfg(test)]
    pub(crate) fn note_h0_merge_for_test(
        &mut self,
        before: Option<(usize, usize)>,
        has_pending_scans: bool,
        has_future_job: bool,
        has_hold: bool,
    ) -> bool {
        self.collected_mut_for_test()
            .expect("a transaction Collected carries the guard count")
            .note_h0_merge(before, has_pending_scans, has_future_job, has_hold)
    }

    /// Take the retained audit frame for the exit-hold abandon, if
    /// the machine holds one: only the Audited phase carries a
    /// finished audit frame. Anything else leaves the phase
    /// untouched and yields None (the unapplied abandon needs no
    /// frame).
    pub(crate) fn take_abandoned_frame(
        &mut self,
    ) -> Option<crate::semantics_objects::journal::joint_audit::IngestedJointQuantum> {
        match self.phase.as_mut() {
            Some(Phase::Audited { frame, .. }) => frame.take(),
            _ => None,
        }
    }

    pub(crate) fn begin_commit(&mut self, engine_changed: bool) -> Result<(), JointCommitRefusal> {
        if self.finish.is_some() {
            return Err(JointCommitRefusal::OutstandingRequest);
        }
        if matches!(self.state, RunState::DispositionRequired(_)) {
            return Err(JointCommitRefusal::DispositionRequired);
        }
        if self.demand.is_some() {
            return Err(JointCommitRefusal::OutstandingRequest);
        }
        self.demand = Some(Demand::Requested { engine_changed });
        Ok(())
    }

    /// Keep the first Finish refusal. A state already latched at its site
    /// keeps its reason; a retryable `ProviderStorage` refusal counts
    /// toward the per-Finish bound instead of latching at once.
    fn latch_finish(&mut self, reason: SemanticRefusal) {
        if matches!(self.state, RunState::DispositionRequired(_)) {
            return;
        }
        if reason == SemanticRefusal::ProviderStorage {
            self.finish_storage_retries = self.finish_storage_retries.saturating_add(1);
            if self.finish_storage_retries < JOINT_FINISH_STORAGE_RETRIES {
                return;
            }
        }
        self.state = RunState::DispositionRequired(reason);
    }

    /// Whether this Finish latched a disposition refusal.
    pub(crate) fn finish_disposition_required(&self) -> bool {
        matches!(self.state, RunState::DispositionRequired(_))
    }

    /// The latched disposition refusal, if the machine latched one.
    /// The commit-path hold names it in its stop gap so the trigger
    /// stays diagnosable without a diagnostic build.
    pub(crate) fn disposition_reason(&self) -> Option<SemanticRefusal> {
        if let RunState::DispositionRequired(reason) = self.state {
            Some(reason)
        } else {
            None
        }
    }

    /// Whether a Finish began and still owns its control.
    pub(crate) fn finish_begun(&self) -> bool {
        self.finish.is_some()
    }

    /// Latch the request before invoking the existing immediate admission
    /// gate. The same machine retains every later Q/report/frame owner.
    #[allow(dead_code)] // Live Finish entry: the Joint finish driver begins here.
    pub(crate) fn begin_finish_with_io<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
    ) -> Result<(), SemanticRefusal> {
        let finished_before = lane.is_finished();
        let duplicate = self.finish.is_some();
        let result = self.begin_finish_inner(lane, coordinator, io);
        if let Err(reason) = &result
            && !finished_before
            && !duplicate
        {
            self.latch_finish(*reason);
        }
        result
    }

    fn begin_finish_inner<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
    ) -> Result<(), SemanticRefusal> {
        #[cfg(test)]
        if self.take_inject(FinishSite::ValidateOwner) {
            return Err(SemanticRefusal::Unavailable);
        }
        self.validate_owner(lane, coordinator, io)?;
        if let RunState::DispositionRequired(reason) = self.state {
            return Err(reason);
        }
        if self.finish.is_some() {
            return Err(SemanticRefusal::Unavailable);
        }
        // A requested Running pull may have set the pulled flag and yielded
        // on an empty drain just before this begin; rows landing after that
        // pull are still unread. Clear the flag so the finish's first
        // advance takes its own fresh pull past the begin.
        if let Some(Phase::Collecting(original)) = self.phase.as_mut() {
            original.request_pulled = false;
        }
        // The observed Q is boxed once so the transfer owner the native
        // carrier compares stays stable across machine moves. A refused
        // box latches at once; no Finish starts without it.
        let q_storage = match coordinator
            .registry()
            .semantic_storage_reserver()
            .reserve(size_of::<CollectedFinishQ>() + OWNED_ALLOCATION_PADDING)
        {
            Ok(storage) => storage,
            Err(_) => {
                self.state = RunState::DispositionRequired(SemanticRefusal::ProviderStorage);
                return Err(SemanticRefusal::ProviderStorage);
            }
        };
        // Preserve an attempted error instead of automatically repeating the
        // native gate callback. This is not a successful Finish disposition.
        self.finish = Some(FinishControl {
            q: None,
            q_storage: Some(q_storage),
            discovery: FinishDiscovery::Pending,
        });
        lane.mark_collected_finish_requested();
        match io.request_finish_stop(lane) {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.state = RunState::DispositionRequired(reason);
                Err(reason)
            }
        }
    }

    /// Bounded service of the same original until actual Finish publication.
    #[allow(dead_code)] // Live Finish entry: the Joint finish driver polls here.
    pub(crate) fn poll_finish_with_io<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        budget: &mut JointWorkBudget,
    ) -> Result<JointCommitProgress, SemanticRefusal> {
        let finished_before = lane.is_finished();
        let result = self.poll_finish_inner(lane, coordinator, io, budget);
        if let Err(reason) = &result
            && !finished_before
        {
            self.latch_finish(*reason);
        }
        result
    }

    fn poll_finish_inner<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        budget: &mut JointWorkBudget,
    ) -> Result<JointCommitProgress, SemanticRefusal> {
        #[cfg(test)]
        if self.take_inject(FinishSite::ValidateOwner) {
            return Err(SemanticRefusal::Unavailable);
        }
        self.validate_owner(lane, coordinator, io)?;
        if let RunState::DispositionRequired(reason) = self.state {
            return Err(reason);
        }
        let mut finish = self.finish.take().ok_or(SemanticRefusal::Unavailable)?;
        let result = self.drive_finish(lane, coordinator, io, &mut finish, budget);
        self.finish = Some(finish); // Every result retains this SAME owned Q.
        result
    }

    fn drive_finish<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        finish: &mut FinishControl,
        budget: &mut JointWorkBudget,
    ) -> Result<JointCommitProgress, SemanticRefusal> {
        if !budget.available() {
            return Ok(JointCommitProgress::Pending);
        }
        if finish.q.is_none() {
            budget.spend(1);
            match io.observe_finish_q(lane, self.grant.as_ref()) {
                Ok(q) => finish.q = q.map(Box::new),
                Err(reason) => {
                    self.state = RunState::DispositionRequired(reason);
                    return Err(reason);
                }
            }
            return Ok(JointCommitProgress::Pending);
        }
        let q = finish.q.as_deref().expect("owned observed Q");
        #[cfg(test)]
        if self.take_inject(FinishSite::DiscoveryDomain) {
            return Err(SemanticRefusal::Unavailable);
        }
        let discovery = io.finish_discovery_domain()?.clone();
        if !q.matches_owner(&self.producers, &discovery)
            || self
                .grant
                .as_ref()
                .is_some_and(|grant| !finish_grant_admissible(q, grant, &self.producers))
        {
            return Err(SemanticRefusal::Unavailable);
        }
        if matches!(finish.discovery, FinishDiscovery::Pending) {
            // Spend discovery credits up to the hook budget. A credit
            // without moved records still counts when the Engine
            // progressed; only 64 consecutive idle credits yield.
            let mut idle = 0;
            while budget.available() {
                budget.spend(1);
                #[cfg(test)]
                FINISH_Q_ADDR.with(|addr| addr.set(q as *const _ as usize));
                let progress = match io.service_finish_discovery(lane, coordinator, q, 1) {
                    Ok(progress) => progress,
                    Err(reason) => {
                        self.state = RunState::DispositionRequired(reason);
                        return Err(reason);
                    }
                };
                if progress.failed || progress.post_q {
                    self.state = RunState::DispositionRequired(SemanticRefusal::Unavailable);
                    return Err(SemanticRefusal::Unavailable);
                }
                if !progress.backlog {
                    finish.discovery = FinishDiscovery::AtQ;
                    break;
                }
                let moved = progress.records > 0 || io.finish_discovery_progressed(coordinator);
                if moved {
                    idle = 0;
                } else {
                    idle += 1;
                    if idle >= 64 {
                        return Ok(JointCommitProgress::Pending);
                    }
                }
            }
            if matches!(finish.discovery, FinishDiscovery::Pending) {
                return Ok(JointCommitProgress::Pending);
            }
        }
        while budget.available() {
            if matches!(self.phase.as_ref(), Some(Phase::AwaitH0(original)) if original.raw.h0_waiting())
            {
                // The owned Finish guard above permits only its first genuine
                // Raw-minted grant after an observed None. Q itself stays
                // unchanged; the standalone pending-Q wrapper remains strict.
                self.resolve_checked_pending_h0_at_q(lane, coordinator, io, q, &discovery, budget)?;
                return Ok(JointCommitProgress::Pending);
            }
            let phase = self.phase.take().expect("retained original Finish phase");
            let (phase, progress) = self.advance(phase, lane, coordinator, io, budget, Some(q));
            self.phase = Some(phase);
            match progress {
                Ok(Step::Published) => {
                    if self.finish_completed.is_some() {
                        #[cfg(test)]
                        if self.take_inject(FinishSite::CompleteFinish) {
                            return Err(SemanticRefusal::Unavailable);
                        }
                        let completed = self.finish_completed.as_ref().expect("checked just above");
                        lane.complete_collected_finish(completed, q)?;
                        drop(self.finish_completed.take());
                        #[cfg(test)]
                        if self.take_inject(FinishSite::MissingReceipt) {
                            return Err(SemanticRefusal::Unavailable);
                        }
                        return self
                            .finish_receipt
                            .take()
                            .map(JointCommitProgress::Published)
                            .ok_or(SemanticRefusal::Unavailable);
                    }
                    return Ok(JointCommitProgress::Pending); // Yield after each actual live publication.
                }
                Ok(Step::Yield) => return Ok(JointCommitProgress::Pending),
                Ok(Step::Continue) => {}
                Err(reason) => {
                    let retryable = reason == SemanticRefusal::ProviderStorage
                        && matches!(
                            self.phase,
                            Some(Phase::FinishStopReady(_))
                                | Some(Phase::FinishStopReport {
                                    pending: PendingQReport {
                                        resolution: PendingQResolution::Resolved,
                                        ..
                                    },
                                    ..
                                })
                                | Some(Phase::PendingQ {
                                    pending: PendingQReport {
                                        resolution: PendingQResolution::Resolved,
                                        ..
                                    },
                                    ..
                                })
                        );
                    if !retryable {
                        self.state = RunState::DispositionRequired(reason);
                    }
                    return Err(reason);
                }
            }
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
        self.resolve_checked_pending_h0_at_q(lane, coordinator, io, q, discovery, budget)
    }

    /// Reuse the actual original resolution after the caller's Q/grant guard.
    /// Every report/expiry still checks the same Raw, ledger and Capture.
    #[allow(clippy::too_many_arguments)] // Keep disjoint owners and their shared work budget borrowed.
    fn resolve_checked_pending_h0_at_q<I: JointMachineIo>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        q: &CollectedFinishQ,
        discovery: &DiscoveryDomain,
        budget: &mut JointWorkBudget,
    ) -> Result<JointServiceProgress, SemanticRefusal> {
        // A pending report refusal latches at its site: this branch also
        // serves the standalone pending-Q entry, which has no wrapper.
        if matches!(self.phase, Some(Phase::PendingQ { .. })) {
            #[cfg(test)]
            if self.take_inject(FinishSite::PendingReport) {
                self.state = RunState::DispositionRequired(SemanticRefusal::Unavailable);
                return Err(SemanticRefusal::Unavailable);
            }
            let Some(Phase::PendingQ { original, .. }) = self.phase.as_ref() else {
                unreachable!("matched just above");
            };
            if original
                .raw
                .validate_pending_finish_report(
                    coordinator.joint_capture().adapter(),
                    &self.producers,
                    discovery,
                    q,
                )
                .is_err()
            {
                self.state = RunState::DispositionRequired(SemanticRefusal::Unavailable);
                return Err(SemanticRefusal::Unavailable);
            }
            #[cfg(test)]
            if self.take_inject(FinishSite::PendingPhase) {
                self.state = RunState::DispositionRequired(SemanticRefusal::Unavailable);
                return Err(SemanticRefusal::Unavailable);
            }
            let Some(phase) = self.phase.take() else {
                self.state = RunState::DispositionRequired(SemanticRefusal::Unavailable);
                return Err(SemanticRefusal::Unavailable);
            };
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
        let before = original.h0_accumulated();
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
            // The increment path is unreachable-in-practice: a PendingQ merge
            // with anything pending always appends (the Q resolve expires all
            // quantum waiters into outcomes), so reaching here needs an empty
            // yet incomplete pending report, i.e. origin-less awaitings, which
            // collected ticks cannot produce (unpositioned records never enter
            // awaiting; the machine is single-flight with empty awaiting at
            // transaction start). Sixteen via PendingQ alone is structurally
            // impossible (one merge per PendingQ phase, then leave). Keep the
            // note call: its reset on a progressing PendingQ merge matters to
            // the shared count. On the unreachable trip, never refuse the
            // lane; AwaitH0's ticks or its own guard trip expire and publish.
            if original.note_h0_merge(before, false, false, false) {
                original.h0_guard_trip = Some("h0_no_progress_no_job_no_hold_expired");
            }
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
        if self.finish.is_some() {
            return Err(SemanticRefusal::Unavailable);
        }
        if let RunState::DispositionRequired(reason) = self.state {
            return Err(reason);
        }
        while budget.available() {
            let phase = self.phase.take().expect("one original machine phase");
            let (phase, result) = self.advance(phase, lane, coordinator, io, budget, None);
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

    /// Arm a one-shot fault at a real Finish `Err` site (latch tests).
    #[cfg(test)]
    pub(crate) fn inject_finish_site_for_test(&mut self, site: FinishSite) {
        self.inject = Some(site);
    }

    /// Take an armed fault once. Each injection fires a single time so the
    /// next poll observes the latched first reason, not a fresh fault.
    #[cfg(test)]
    fn take_inject(&mut self, site: FinishSite) -> bool {
        if self.inject == Some(site) {
            self.inject = None;
            true
        } else {
            false
        }
    }

    /// Last Q address observed by Finish discovery service (Q-box test).
    #[cfg(test)]
    pub(crate) fn finish_q_addr_for_test() -> usize {
        FINISH_Q_ADDR.with(|addr| addr.get())
    }

    #[cfg(test)]
    pub(crate) fn finish_stop_ready_for_test(&self) -> bool {
        matches!(self.phase, Some(Phase::FinishStopReady(_)))
    }

    #[cfg(test)]
    pub(crate) fn retained_finish_q_for_test(&self) -> Option<&CollectedFinishQ> {
        self.finish.as_ref()?.q.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn retained_finish_report_for_test(&self) -> Option<(&TickReport, usize)> {
        let Phase::FinishStopReport { pending, .. } = self.phase.as_ref()? else {
            return None;
        };
        Some((&pending.report, pending.bytes))
    }

    #[cfg(test)]
    pub(crate) fn retained_finish_disposition_for_test(&self) -> Option<&DisposedJointQuantum> {
        self.finish_disposed.as_ref()
    }

    /// Refusal-only hook has no receiver to affect until real output exists.
    #[cfg(test)]
    pub(crate) fn reference_refuse_finish_q_merge_once(&mut self) {
        self.refuse_finish_q_merge_once = true;
    }

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
            | Phase::FinishStopReady(value)
            | Phase::FinishStopReport {
                original: value, ..
            }
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
            Some(Phase::FinishStopReady(value)) => ("FinishStopReady", Some(value)),
            Some(Phase::FinishStopReport { original, .. }) => ("FinishStopReport", Some(original)),
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

    /// Staging diagnosis, if Staging refused.
    #[cfg(test)]
    pub(crate) fn staging_detail_for_test(&self) -> Option<StagingDetail> {
        self.staging_detail
    }

    /// The no-progress guard trip cause for the current transaction, if the
    /// bound expired a true stall (waiters disclosed as unobserved, joined
    /// outcomes kept, transaction published).
    #[cfg(test)]
    pub(crate) fn h0_guard_trip_for_test(&self) -> Option<&'static str> {
        match self.phase.as_ref()? {
            Phase::Collecting(value)
            | Phase::Binding(value)
            | Phase::AwaitH0(value)
            | Phase::Preparing(value)
            | Phase::PreparationAttempted(value)
            | Phase::FinishStopReady(value)
            | Phase::PreparingAdmissions(value)
            | Phase::Ingesting(value)
            | Phase::StagingNegative(value) => value.h0_guard_trip,
            Phase::PendingQ { original, .. }
            | Phase::FinishStopReport { original, .. }
            | Phase::BindingKeys { original, .. } => original.h0_guard_trip,
            _ => None,
        }
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
    fn advance_finish_stop<I: JointMachineIo>(
        &mut self,
        phase: Phase,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        budget: &mut JointWorkBudget,
        q: Option<&CollectedFinishQ>,
    ) -> (Phase, Result<Step, SemanticRefusal>) {
        let Some(q) = q else {
            return (phase, Err(SemanticRefusal::Unavailable));
        };
        let phase = match phase {
            Phase::FinishStopReady(mut original) => {
                if coordinator.collected_finish_discovery_pending(0) {
                    return (
                        Phase::FinishStopReady(original),
                        Err(SemanticRefusal::Unavailable),
                    );
                }
                let bytes = match io.finish_h0_storage_bytes(
                    lane,
                    &original.raw,
                    coordinator.joint_capture().adapter(),
                    q,
                ) {
                    Ok(bytes) if bytes != 0 => bytes,
                    Ok(_) => {
                        return (
                            Phase::FinishStopReady(original),
                            Err(SemanticRefusal::ProviderStorage),
                        );
                    }
                    Err(reason) => return (Phase::FinishStopReady(original), Err(reason)),
                };
                let storage = match coordinator
                    .registry()
                    .semantic_storage_reserver()
                    .reserve(bytes)
                {
                    Ok(storage) => storage,
                    Err(_) => {
                        return (
                            Phase::FinishStopReady(original),
                            Err(SemanticRefusal::ProviderStorage),
                        );
                    }
                };
                if let Err(reason) = coordinator.reserve_collected_stop_union(&original.raw) {
                    return (Phase::FinishStopReady(original), Err(reason));
                }
                let mut pending = PendingQReport {
                    report: TickReport::default(),
                    resolution: PendingQResolution::Attempted,
                    bytes,
                    _storage: storage,
                };
                budget.spend(1);
                let result = io
                    .finish_h0_at_q(lane, coordinator, &mut original.raw, q, &mut pending.report)
                    .and_then(|()| {
                        original
                            .raw
                            .matches_final_stop_report(&pending.report)
                            .then_some(())
                            .ok_or(SemanticRefusal::Unavailable)
                    });
                if result.is_ok() {
                    pending.resolution = PendingQResolution::Resolved;
                }
                let retained = Phase::FinishStopReport { original, pending };
                if let Err(reason) = result {
                    return (retained, Err(reason));
                }
                retained
            }
            other => other,
        };
        let Phase::FinishStopReport {
            mut original,
            mut pending,
        } = phase
        else {
            return (phase, Err(SemanticRefusal::Unavailable));
        };
        if !matches!(pending.resolution, PendingQResolution::Resolved)
            || !original.raw.matches_final_stop_report(&pending.report)
        {
            return (
                Phase::FinishStopReport { original, pending },
                Err(SemanticRefusal::Unavailable),
            );
        }
        if !budget.available() {
            return (
                Phase::FinishStopReport { original, pending },
                Ok(Step::Yield),
            );
        }
        budget.spend(1);
        #[cfg(test)]
        if self.refuse_finish_q_merge_once {
            self.refuse_finish_q_merge_once = false;
            return (
                Phase::FinishStopReport { original, pending },
                Err(SemanticRefusal::ProviderStorage),
            );
        }
        if let Err(reason) =
            coordinator.merge_collected_stop_report(&mut original.raw, &mut pending.report)
        {
            return (Phase::FinishStopReport { original, pending }, Err(reason));
        }
        self.finish_original = Some(original.raw.h0_identity());
        drop(pending); // Both incoming buffers have dropped before the allowance refunds.
        (Phase::PreparingAdmissions(original), Ok(Step::Continue))
    }

    #[allow(clippy::too_many_arguments)] // Disjoint canonical owners plus one finite shared budget.
    #[allow(clippy::result_large_err)] // Native callbacks return the original proof/frame without allocating.
    fn advance<I: JointMachineIo>(
        &mut self,
        phase: Phase,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        io: &mut I,
        budget: &mut JointWorkBudget,
        q: Option<&CollectedFinishQ>,
    ) -> (Phase, Result<Step, SemanticRefusal>) {
        match phase {
            phase @ (Phase::FinishStopReady(_) | Phase::FinishStopReport { .. }) => {
                self.advance_finish_stop(phase, lane, coordinator, io, budget, q)
            }
            phase @ Phase::PendingQ { .. } => {
                self.merge_pending_q_phase(phase, lane, coordinator, budget)
            }
            Phase::Idle => {
                let reserve = coordinator.registry().semantic_storage_reserver();
                // No collection, binder or New can precede this scan. One
                // accepted current image is paired with one real attached
                // target per action; no Mapped-only selector/cross-product.
                if q.is_none()
                    && self.grant.is_some()
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
                let collected = match q {
                    Some(q) => io.collect_raw_at_q(
                        lane,
                        coordinator.joint_capture_mut().adapter_mut(),
                        &reserve,
                        q,
                        RAW_CAPACITY,
                        work,
                    ),
                    None => io.collect_raw(
                        lane,
                        coordinator.joint_capture_mut().adapter_mut(),
                        &reserve,
                        RAW_CAPACITY,
                        work,
                    ),
                };
                let (raw, poll) = retain_on_refusal!(Phase::Idle, collected);
                let poll = poll.expect("positive initial work actually polls the original cursor");
                budget.spend(poll.attempted.max(1));
                let Some(ledger) = raw.ledger_binding() else {
                    return (
                        Phase::Collecting(Collected {
                            raw,
                            attempted: poll.attempted,
                            poll,
                            reports: None,
                            request_pulled: false,
                            h0_idle_passes: 0,
                            h0_guard_trip: None,
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
                        request_pulled: false,
                        h0_idle_passes: 0,
                        h0_guard_trip: None,
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
                    let requested =
                        q.is_some() || matches!(self.demand, Some(Demand::Requested { .. }));
                    let unrequested_empty = original.attempted == 0 && !requested;
                    let needs_first_end = original.attempted != 0
                        && original.raw.pending_h0_records() == 0
                        && self.grant.is_none()
                        && !failed
                        && !requested
                        && original.attempted < RAW_CAPACITY;
                    if !unrequested_empty && !needs_first_end {
                        // A requested transaction must not bind on a stale
                        // no-backlog poll: rows may have landed since idle
                        // services last pulled. The finish's first advance
                        // is requested too (it carries Q), so it takes the
                        // same one fresh pull past the begin; the flag keeps
                        // the quiet case to a single wasted pull per
                        // transaction.
                        if requested && original.attempted == 0 && !original.request_pulled {
                            original.request_pulled = true;
                        } else {
                            budget.spend(1);
                            return (Phase::Binding(original), Ok(Step::Continue));
                        }
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
                let continued = match q {
                    Some(q) => io.continue_raw_at_q(
                        lane,
                        &mut original.raw,
                        coordinator.joint_capture_mut().adapter_mut(),
                        q,
                        work,
                    ),
                    None => io.continue_raw(
                        lane,
                        &mut original.raw,
                        coordinator.joint_capture_mut().adapter_mut(),
                        work,
                    ),
                };
                let poll = retain_on_refusal!(Phase::Collecting(original), continued);
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
                let reports = match CollectedReports::new(lane, &original.raw, &reserve) {
                    Ok(reports) => reports,
                    Err(reason) => return (Phase::Binding(original), Err(reason)),
                };
                original.reports = Some(reports);
                let bound = match q {
                    Some(q) => {
                        let discovery = match io.finish_discovery_domain() {
                            Ok(domain) => domain.clone(),
                            Err(reason) => return (Phase::Binding(original), Err(reason)),
                        };
                        super::bind_collected_semantic_callers_at_q(
                            coordinator,
                            lane,
                            &mut original.raw,
                            &self.producers,
                            &discovery,
                            q,
                        )
                    }
                    None => super::bind_collected_semantic_callers(
                        coordinator,
                        lane,
                        &mut original.raw,
                        &self.producers,
                    ),
                };
                retain_on_refusal!(Phase::Binding(original), bound);
                budget.spend(1);
                (Phase::AwaitH0(original), Ok(Step::Continue))
            }
            Phase::AwaitH0(mut original) => {
                let ticked = match q {
                    Some(q) => io.tick_collected_at_q(
                        lane,
                        coordinator.semantic_bindings_mut().bindings_for_tick(),
                        &mut original.raw,
                        q,
                    ),
                    None => io.tick_collected(
                        lane,
                        coordinator.semantic_bindings_mut().bindings_for_tick(),
                        &mut original.raw,
                    ),
                };
                let batch = retain_on_refusal!(Phase::AwaitH0(original), ticked);
                budget.spend(1);
                let before = original.h0_accumulated();
                let has_pending_scans = batch.has_pending_scans();
                let has_future_job = batch.awaited_jobs_pending();
                let has_hold = batch.awaited_hold_pending();
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
                    if original.note_h0_merge(before, has_pending_scans, has_future_job, has_hold) {
                        original.h0_guard_trip = Some("h0_no_progress_no_job_no_hold_expired");
                        let expired =
                            match io.expire_collected_h0_for_guard(lane, &mut original.raw) {
                                Ok(expired) => expired,
                                Err(reason) => {
                                    return (Phase::AwaitH0(original), Err(reason));
                                }
                            };
                        let complete = match original
                            .reports
                            .as_mut()
                            .expect("prepaid before New")
                            .merge(expired)
                        {
                            Ok(complete) => complete,
                            Err(reason) => return (Phase::AwaitH0(original), Err(reason)),
                        };
                        if !complete {
                            return (Phase::AwaitH0(original), Err(SemanticRefusal::Unavailable));
                        }
                        let batch = original
                            .reports
                            .as_mut()
                            .expect("same reports")
                            .batch
                            .take()
                            .expect("stage once");
                        coordinator.stage_semantic_batch(batch);
                        return (Phase::Preparing(original), Ok(Step::Continue));
                    }
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
                let prepared = match q {
                    Some(q) => io.prepare_publication_at_q(
                        lane,
                        coordinator,
                        &mut original.raw,
                        changed,
                        q,
                    ),
                    None => io.prepare_publication(lane, coordinator, &mut original.raw, changed),
                };
                retain_on_refusal!(Phase::PreparationAttempted(original), prepared);
                if q.is_some() && original.attempted == 0 && coordinator.collected_stop_candidate()
                {
                    (Phase::FinishStopReady(original), Ok(Step::Yield))
                } else {
                    (Phase::PreparingAdmissions(original), Ok(Step::Continue))
                }
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
                    if self.grant.is_none()
                        && let Some(q) = q
                    {
                        let discovery = retain_on_refusal!(
                            Phase::BindingKeys { original, cursor },
                            io.finish_discovery_domain()
                        );
                        // A later association comes only from this machine's
                        // real prepared original, never Q's optional metadata.
                        retain_on_refusal!(
                            Phase::BindingKeys { original, cursor },
                            original
                                .raw
                                .validate_preparation(owner.adapter(), &self.producers)
                        );
                        retain_on_refusal!(
                            Phase::BindingKeys { original, cursor },
                            original
                                .raw
                                .validate_collected_q(&self.producers, discovery, q)
                        );
                    }
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
                let reason = if self.finish_original == Some(identity) {
                    RawDisposeReason::TerminalLoss
                } else if original.attempted == 0 {
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
                    native_for_phase(io, lane, &self.births, q, |io| coordinator
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
                        |candidate, absence, input, binding, proof, adapter| match q {
                            Some(q) => io.consume_birth_at_q(
                                lane, candidate, absence, input, binding, proof, adapter, q
                            ),
                            None => io.consume_birth(
                                lane, candidate, absence, input, binding, proof, adapter
                            ),
                        },
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
                let staged = coordinator
                    .stage_next_prepared_admission_with_disposition(&self.producers, &mut original);
                let more = match staged {
                    Ok(more) => more,
                    Err(reason) => {
                        let stage = coordinator
                            .prepared_staging_progress(lane)
                            .map_or(0, |(_, stage, _, _)| stage);
                        self.staging_detail = Some(StagingDetail::StageNext {
                            reason: reason.code(),
                            stage,
                        });
                        return (
                            Phase::Staging {
                                original,
                                identity,
                                base,
                            },
                            Err(SemanticRefusal::Unavailable),
                        );
                    }
                };
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
                    let (claim, stage, len, domain) = coordinator
                        .prepared_staging_progress(lane)
                        .unwrap_or((0, 0, 0, false));
                    self.staging_detail = Some(StagingDetail::Finish {
                        claim,
                        stage,
                        len,
                        domain,
                    });
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
                let result = native_for_phase(io, lane, &self.births, q, |io| {
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
                let result = native_for_phase(io, lane, &self.births, q, |io| {
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
                let final_original = self.finish_original == Some(identity);
                #[cfg(test)]
                let wedged = self.pose_no_progress_poll;
                #[cfg(not(test))]
                let wedged = false;
                let result = if wedged {
                    Ok(Ok(JointCommitProgress::Pending))
                } else {
                    native_for_phase(io, lane, &self.births, q, |io| {
                        if final_original {
                            coordinator.commit_joint_finish_batch_with_io(
                                io,
                                &self.producers,
                                &mut frame,
                                &mut self.finish_disposed,
                                &mut self.finish_completed,
                                &mut budget.remaining_actions,
                            )
                        } else {
                            coordinator.commit_joint_batch_with_io(
                                io,
                                &self.producers,
                                &mut frame,
                                &mut budget.remaining_actions,
                            )
                        }
                    })
                };
                // No-progress signal for the finish bound, measured before
                // the yield below forces its own action spend.
                let progressed = budget.remaining_actions != before;
                if !progressed {
                    budget.spend(1);
                }
                match result {
                    Ok(Ok(JointCommitProgress::Published(receipt))) => {
                        self.finish_no_progress_polls = 0;
                        self.audit_no_progress_polls = 0;
                        self.finish_no_progress_since = None;
                        if final_original {
                            self.finish_receipt = Some(receipt);
                        }
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
                    Ok(Ok(JointCommitProgress::Pending)) => {
                        // Wall-time no-progress bound, finish and
                        // running alike: a wedged audit spends nothing
                        // and publishes nothing, forever. Spending and
                        // publication reset the stall clock; the bound
                        // records a named gap, latches the trip cause
                        // for the exit hold's stderr disclosure, and
                        // refuses, keeping the retained frame and its
                        // audit tags for the disposition hold and
                        // diagnosis. The two modes share the clock but
                        // count separately; a mode flip restarts it, so
                        // a running stall and a finish stall never fuse
                        // into one trip.
                        if !progressed {
                            if q.is_some() {
                                if self.audit_no_progress_polls > 0 {
                                    self.finish_no_progress_since = None;
                                }
                                self.audit_no_progress_polls = 0;
                                self.finish_no_progress_polls =
                                    self.finish_no_progress_polls.saturating_add(1);
                                let now = Instant::now();
                                let since = *self.finish_no_progress_since.get_or_insert(now);
                                let stalled = now.duration_since(since);
                                if stalled >= JOINT_FINISH_NO_PROGRESS_TIMEOUT {
                                    let polls = self.finish_no_progress_polls;
                                    self.finish_no_progress_trip =
                                        Some(FinishNoProgressTrip { polls, stalled });
                                    coordinator.note_scope_gap(
                                        "joint finish made no progress".to_string(),
                                        format!(
                                            "{}s without progress across {} consecutive finish polls in \
                                             Audited; abandoning the finish for exit",
                                            stalled.as_secs(),
                                            polls,
                                        ),
                                    );
                                    return (
                                        Phase::Audited {
                                            frame,
                                            identity,
                                            base,
                                        },
                                        Err(SemanticRefusal::Unavailable),
                                    );
                                }
                            } else {
                                if self.finish_no_progress_polls > 0 {
                                    self.finish_no_progress_since = None;
                                }
                                self.finish_no_progress_polls = 0;
                                self.audit_no_progress_polls =
                                    self.audit_no_progress_polls.saturating_add(1);
                                let now = Instant::now();
                                let since = *self.finish_no_progress_since.get_or_insert(now);
                                let stalled = now.duration_since(since);
                                if stalled >= JOINT_FINISH_NO_PROGRESS_TIMEOUT {
                                    let polls = self.audit_no_progress_polls;
                                    self.audit_no_progress_trip =
                                        Some(FinishNoProgressTrip { polls, stalled });
                                    coordinator.note_scope_gap(
                                        "joint audit made no progress".to_string(),
                                        format!(
                                            "{}s without progress across {} consecutive commit polls in \
                                             Audited; the semantic lane stops",
                                            stalled.as_secs(),
                                            polls,
                                        ),
                                    );
                                    return (
                                        Phase::Audited {
                                            frame,
                                            identity,
                                            base,
                                        },
                                        Err(SemanticRefusal::Unavailable),
                                    );
                                }
                            }
                        } else {
                            self.finish_no_progress_polls = 0;
                            self.audit_no_progress_polls = 0;
                            self.finish_no_progress_since = None;
                        }
                        (
                            Phase::Audited {
                                frame,
                                identity,
                                base,
                            },
                            Ok(Step::Yield),
                        )
                    }
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
    discovery: Option<DiscoveryDomain>,
}

#[allow(dead_code)] // Paired with the inactive actual Session entrypoints below.
impl SessionMachineIo {
    fn live_owner<'a>(
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
        if live.finished
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

    fn live<'a>(
        &self,
        lane: &'a mut AttestedSemanticLane,
    ) -> Result<&'a mut crate::inventory_semantics::LiveLane, SemanticRefusal> {
        let live = self.live_owner(lane)?;
        if live.gated {
            return Err(SemanticRefusal::Unavailable);
        }
        Ok(live)
    }

    fn live_at_q<'a>(
        &self,
        lane: &'a mut AttestedSemanticLane,
        q: &CollectedFinishQ,
    ) -> Result<&'a mut crate::inventory_semantics::LiveLane, SemanticRefusal> {
        let live = self.live_owner(lane)?;
        let discovery = live
            .session
            .collected_finish_discovery_domain(q)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        if !q.matches_owner(&self.producers, discovery)
            || self
                .discovery
                .as_ref()
                .is_some_and(|own| !own.same_allocation(discovery))
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

    fn request_finish_stop(
        &mut self,
        lane: &mut AttestedSemanticLane,
    ) -> Result<(), SemanticRefusal> {
        self.live_owner(lane)?;
        lane.request_semantic_stop();
        Ok(())
    }

    fn observe_finish_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        grant: Option<&SessionDrainGrant>,
    ) -> Result<Option<CollectedFinishQ>, SemanticRefusal> {
        let live = self.live_owner(lane)?;
        let observed = live
            .session
            .observe_collected_finish_q(&self.producers, grant)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        if let Some(q) = observed.as_ref() {
            self.discovery = Some(
                live.session
                    .collected_finish_discovery_domain(q)
                    .map_err(|_| SemanticRefusal::Unavailable)?
                    .clone(),
            );
        }
        Ok(observed)
    }

    fn finish_discovery_domain(&self) -> Result<&DiscoveryDomain, SemanticRefusal> {
        self.discovery.as_ref().ok_or(SemanticRefusal::Unavailable)
    }

    fn collect_raw_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        adapter: &mut JournalAdapter,
        reserve: &SemanticResourceReserver,
        q: &CollectedFinishQ,
        capacity: usize,
        work: usize,
    ) -> Result<(RawJointQuantum, Option<DispatchPoll>), RawQuantumRefusal> {
        let live = self
            .live_at_q(lane, q)
            .map_err(|_| RawQuantumRefusal::Stopped)?;
        let (drain, rows, fault) = live
            .session
            .joint_collection_io_at_q(q)
            .map_err(|_| RawQuantumRefusal::DrainUnbound)?;
        let rows = rows.ok_or(RawQuantumRefusal::ForeignDescriptors)?;
        RawJointQuantum::begin_bounded_with_adapter(
            drain,
            rows,
            capacity,
            work,
            Some(q.events_stop()),
            &fault,
            &self.producers,
            |bytes| reserve.reserve(bytes),
            adapter,
        )
    }

    fn continue_raw_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
        adapter: &mut JournalAdapter,
        q: &CollectedFinishQ,
        work: usize,
    ) -> Result<DispatchPoll, RawQuantumRefusal> {
        let live = self
            .live_at_q(lane, q)
            .map_err(|_| RawQuantumRefusal::Stopped)?;
        let (drain, rows, fault) = live
            .session
            .joint_collection_io_at_q(q)
            .map_err(|_| RawQuantumRefusal::DrainUnbound)?;
        raw.continue_bounded_with_adapter(
            drain,
            rows.ok_or(RawQuantumRefusal::ForeignDescriptors)?,
            work,
            Some(q.events_stop()),
            &fault,
            &self.producers,
            adapter,
        )
    }

    fn service_finish_discovery(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        q: &CollectedFinishQ,
        work: usize,
    ) -> Result<LaneDrainOutcome, SemanticRefusal> {
        let live = self.live_at_q(lane, q)?;
        coordinator.service_collected_finish_session(&mut live.session, q, work)
    }

    fn finish_h0_storage_bytes(
        &self,
        lane: &AttestedSemanticLane,
        raw: &RawJointQuantum,
        adapter: &JournalAdapter,
        q: &CollectedFinishQ,
    ) -> Result<usize, SemanticRefusal> {
        let live = lane.live.as_deref().ok_or(SemanticRefusal::Unavailable)?;
        let discovery = live
            .session
            .collected_finish_discovery_domain(q)
            .map_err(|_| SemanticRefusal::Unavailable)?;
        if live.finished || !q.matches_owner(&self.producers, discovery) {
            return Err(SemanticRefusal::Unavailable);
        }
        live.capture
            .collected_stop_at_q_storage_bytes(raw, adapter, &self.producers, discovery, q)
            .map_err(|_| SemanticRefusal::ProviderStorage)
    }

    fn finish_h0_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        q: &CollectedFinishQ,
        report: &mut TickReport,
    ) -> Result<(), SemanticRefusal> {
        let live = self.live_at_q(lane, q)?;
        let discovery = live
            .session
            .collected_finish_discovery_domain(q)
            .map_err(|_| SemanticRefusal::Unavailable)?
            .clone();
        let positions = live
            .session
            .discovery_positions()
            .map_err(|_| SemanticRefusal::Unavailable)?;
        if positions.consumer != q.discovery_stop()
            || coordinator.collected_finish_discovery_pending(live.session.staged_discovery_len())
        {
            return Err(SemanticRefusal::Unavailable);
        }
        live.capture
            .stop_collected_at_q(
                raw,
                coordinator.joint_capture().adapter(),
                &self.producers,
                &discovery,
                q,
                report,
            )
            .map_err(|_| SemanticRefusal::Unavailable)
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
        if live.finished
            || !live
                .session
                .collected_finish_discovery_domain(q)
                .is_ok_and(|actual| actual.same_allocation(discovery))
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
        let live = self.live_at_q(lane, q)?;
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

    fn expire_collected_h0_for_guard(
        &mut self,
        lane: &mut AttestedSemanticLane,
        raw: &mut RawJointQuantum,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.live(lane)?;
        lane.expire_joint_h0_stall_for_guard(raw)
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

    fn tick_collected_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        bindings: &[SemanticCallerBinding],
        raw: &mut RawJointQuantum,
        q: &CollectedFinishQ,
    ) -> Result<SemanticBatch, SemanticRefusal> {
        self.live_at_q(lane, q)?;
        lane.tick_collected_at_q(bindings, raw, q)
    }

    fn prepare_publication_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        raw: &mut RawJointQuantum,
        changed: bool,
        q: &CollectedFinishQ,
    ) -> anyhow::Result<()> {
        self.live_at_q(lane, q).map_err(anyhow::Error::msg)?;
        coordinator.prepare_joint_publication(changed, lane, raw, &self.producers)
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

    #[allow(clippy::too_many_arguments)] // The same original candidate is checked against its Q-bound owner.
    fn consume_birth_at_q(
        &mut self,
        lane: &mut AttestedSemanticLane,
        candidate: H0BirthCandidate,
        absence: Option<CommittedAbsenceBirth>,
        input: &AdmittedInstanceCall,
        binding: &SemanticCallerBinding,
        proof: &JournalDomainProof,
        adapter: &JournalAdapter,
        q: &CollectedFinishQ,
    ) -> Result<RetainedBirthWitness, BirthObservationRefusal> {
        let live = self
            .live_at_q(lane, q)
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

    fn with_native_at_q<R>(
        &mut self,
        lane: &mut AttestedSemanticLane,
        witnesses: &RetainedJointBirths,
        q: &CollectedFinishQ,
        inspect: impl for<'io> FnOnce(JointCommitIo<'io>) -> R,
    ) -> Result<R, SemanticRefusal> {
        self.live_at_q(lane, q)?;
        lane.with_joint_commit_io_for_births(witnesses, inspect)
    }
}

#[cfg(test)]
thread_local! {
    /// Posed no-progress trip for the exit-hold twin: substituted lanes
    /// carry no live machine to trip, so the twin stages the trip here
    /// (like the lane's `scripted_*` seams stage machine behavior) and
    /// the accessor returns it. Cleared by the twin when done.
    static POSED_NO_PROGRESS_TRIP: std::cell::Cell<Option<FinishNoProgressTrip>> =
        const { std::cell::Cell::new(None) };
}

impl AttestedSemanticLane {
    /// Bind the initial machine to the actual Session and canonical pool,
    /// before the first publication request. This performs no EVENTS/H0 work.
    pub(crate) fn initialize_joint(
        &mut self,
        coordinator: &InventoryCoordinator<OsProcessSource>,
    ) -> Result<(), SemanticRefusal> {
        #[cfg(test)]
        {
            self.joint_init_calls += 1;
        }
        #[cfg(test)]
        if let Some(scripted) = self.scripted_joint_init {
            if scripted.is_ok() {
                // A scripted success marks the lane Joint: substituted
                // lanes carry no live machine to install.
                self.test_joint_machine = true;
            }
            return scripted;
        }
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
        self.with_machine_owner(coordinator, false, service)
    }

    fn with_machine_owner<R>(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        terminal: bool,
        service: impl FnOnce(
            &mut LiveJointMachine,
            &mut Self,
            &mut InventoryCoordinator<OsProcessSource>,
            &mut SessionMachineIo,
        ) -> Result<R, SemanticRefusal>,
    ) -> Result<R, SemanticRefusal> {
        #[cfg(test)]
        if self.inject_pre_machine {
            return Err(SemanticRefusal::Unavailable);
        }
        if self.live.as_deref().is_some_and(|live| !live.gated) {
            self.initialize_joint(coordinator)?;
        }
        let live = self
            .live
            .as_deref_mut()
            .ok_or(SemanticRefusal::Unavailable)?;
        if live.finished || (live.gated && !terminal) {
            return Err(SemanticRefusal::Unavailable);
        }
        let producers = live
            .session
            .drain_producers()
            .ok_or(SemanticRefusal::Unavailable)?;
        let discovery = live
            .joint_machine
            .as_ref()
            .and_then(|machine| machine.finish.as_ref())
            .and_then(|finish| finish.q.as_deref())
            .map(|q| live.session.collected_finish_discovery_domain(q).cloned())
            .transpose()
            .map_err(|_| SemanticRefusal::Unavailable)?;
        let mut machine = live
            .joint_machine
            .take()
            .ok_or(SemanticRefusal::Unavailable)?;
        let mut io = SessionMachineIo {
            producers,
            discovery,
        };
        let result = service(&mut machine, self, coordinator, &mut io);
        self.live
            .as_deref_mut()
            .expect("service cannot extract its native owner")
            .joint_machine = Some(machine);
        result
    }

    /// Whether this lane's Finish latched a disposition refusal, on the
    /// lane flag or in the machine.
    pub(crate) fn joint_finish_disposition_required(&self) -> bool {
        self.joint_finish_failure.is_some()
            || self.live.as_deref().is_some_and(|live| {
                live.joint_machine
                    .as_ref()
                    .is_some_and(|machine| machine.finish_disposition_required())
            })
    }

    /// The machine's latched disposition refusal, if it latched one.
    /// Reads only the machine latch (the commit-path trigger), never
    /// the lane's Finish flag, so a Finish refusal cannot misname a
    /// commit hold.
    pub(crate) fn joint_disposition_reason(&self) -> Option<SemanticRefusal> {
        self.live.as_deref().and_then(|live| {
            live.joint_machine
                .as_ref()
                .and_then(|machine| machine.disposition_reason())
        })
    }

    /// The recorded Audited no-progress trip, if the wall-time bound
    /// fired on this lane's machine. The exit hold names it on stderr:
    /// the wedged publication stands in front of the commit, so the
    /// staged gap cannot commit while the wedge stands. In tests, a
    /// posed trip wins (substituted lanes carry no live machine).
    pub(crate) fn joint_finish_no_progress_trip(&self) -> Option<FinishNoProgressTrip> {
        #[cfg(test)]
        if let Some(posed) = POSED_NO_PROGRESS_TRIP.with(|posed| posed.get()) {
            return Some(posed);
        }
        self.live.as_deref().and_then(|live| {
            live.joint_machine
                .as_ref()
                .and_then(|machine| machine.finish_no_progress_trip)
        })
    }

    /// Pose (or clear) the no-progress trip the accessor returns, so
    /// the exit-hold twin can stage a tripped lane without a live
    /// machine. Associated rather than a method: substituted lanes
    /// carry no live machine, so there is no lane state to hang it
    /// on. Takes raw parts because the trip type stays inside the
    /// joint module. The twin clears it when done (thread-local).
    #[cfg(test)]
    pub(crate) fn pose_no_progress_trip_for_test(trip: Option<(u32, Duration)>) {
        POSED_NO_PROGRESS_TRIP.with(|posed| {
            posed.set(trip.map(|(polls, stalled)| FinishNoProgressTrip { polls, stalled }));
        });
    }

    /// Whether this lane's machine began a Finish that still owns control.
    #[allow(dead_code)] // Staged Finish query; the driver reads the latched failure instead.
    pub(crate) fn joint_finish_begun(&self) -> bool {
        self.live.as_deref().is_some_and(|live| {
            live.joint_machine
                .as_ref()
                .is_some_and(|machine| machine.finish_begun())
        })
    }

    /// Latch a terminal Finish refusal noted by the driver. Keeps the first.
    pub(crate) fn note_joint_finish_failure(&mut self, reason: SemanticRefusal) {
        self.joint_finish_failure.get_or_insert(reason);
    }

    /// Arm the pre-machine Finish refusal seam (lane-flag test).
    #[cfg(test)]
    pub(crate) fn set_inject_pre_machine_for_test(&mut self, on: bool) {
        self.inject_pre_machine = on;
    }

    /// Request admission STOP, retaining this lane's original machine/Session.
    pub(crate) fn begin_joint_finish(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
    ) -> Result<(), SemanticRefusal> {
        #[cfg(test)]
        if let Some(scripted) = self.scripted_finish_begin {
            // A scripted error latches like a pre-machine refusal on
            // unfinished lanes; Ok runs the begun arm latch-free.
            if let Err(reason) = &scripted
                && !self.is_finished()
            {
                self.joint_finish_failure.get_or_insert(*reason);
            }
            return scripted;
        }
        let mut ran = false;
        let result =
            self.with_machine_owner(coordinator, true, |machine, lane, coordinator, io| {
                ran = true;
                machine.begin_finish_with_io(lane, coordinator, io)
            });
        if let Err(reason) = &result
            && !ran
            && !self.is_finished()
        {
            self.joint_finish_failure.get_or_insert(*reason);
        }
        result
    }

    /// No Session or scheduling owner escapes while bounded Finish is pending.
    pub(crate) fn poll_joint_finish(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        budget: &mut JointWorkBudget,
    ) -> Result<JointCommitProgress, SemanticRefusal> {
        #[cfg(test)]
        {
            self.finish_poll_calls += 1;
        }
        #[cfg(test)]
        if let Some(scripted) = self
            .scripted_finish_poll_queue
            .pop_front()
            .or(self.scripted_finish_poll)
        {
            // A scripted error latches like a pre-machine refusal on
            // unfinished lanes; scripted progress runs latch-free.
            if let Err(reason) = &scripted
                && !self.is_finished()
            {
                self.joint_finish_failure.get_or_insert(*reason);
            }
            return scripted;
        }
        let mut ran = false;
        let result =
            self.with_machine_owner(coordinator, true, |machine, lane, coordinator, io| {
                ran = true;
                machine.poll_finish_with_io(lane, coordinator, io, budget)
            });
        if let Err(reason) = &result
            && !ran
            && !self.is_finished()
        {
            self.joint_finish_failure.get_or_insert(*reason);
        }
        result
    }

    pub(crate) fn service_joint(
        &mut self,
        coordinator: &mut InventoryCoordinator<OsProcessSource>,
        mode: JointServiceMode,
        budget: &mut JointWorkBudget,
    ) -> Result<JointServiceProgress, SemanticRefusal> {
        #[cfg(test)]
        {
            self.joint_service_calls += 1;
        }
        self.with_machine(coordinator, |machine, lane, coordinator, io| {
            machine.service_with_io(lane, coordinator, io, mode, budget)
        })
    }

    pub(crate) fn begin_joint_commit(
        &mut self,
        engine_changed: bool,
    ) -> Result<(), JointCommitRefusal> {
        #[cfg(test)]
        {
            self.joint_commit_begin_calls += 1;
        }
        #[cfg(test)]
        if let Some(scripted) = self.scripted_joint_begin {
            return scripted;
        }
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
        #[cfg(test)]
        if let Some(scripted) = self
            .scripted_commit_poll_queue
            .pop_front()
            .or(self.scripted_commit_poll)
        {
            // A scripted error never latches: the driver's
            // conversion owns the verdict for commit refusals.
            return scripted;
        }
        self.with_machine(coordinator, |machine, lane, coordinator, io| {
            machine.poll_commit_with_io(lane, coordinator, io, budget)
        })
    }
}

#[cfg(test)]
mod binding_reservation_tests {
    use super::*;
    use crate::attach::capture::NativeDomainId;
    use crate::attach::image_query::CompleteEpochs;
    use crate::discovery::identity::RetainedInventoryTarget;
    use crate::discovery::identity::test_fixture::real_scan_pin;
    use crate::process::PidPin;
    use crate::semantic_capture::{Endpoint, Invalidation, InvalidationScope};
    use crate::semantics_edge::resources::{SEMANTIC_RESOURCE_LIMIT, SemanticResourcePool};
    use p11scope_ebpf_common::ImageIdentity;
    use std::sync::Arc;
    use std::time::Duration;

    fn watched_target() -> RetainedInventoryTarget {
        let pins = real_scan_pin(
            &std::env::current_exe().unwrap(),
            None,
            1,
            "binding-reservation-test",
        );
        pins.retain_inventory_target(PinnedObjectId(0)).unwrap()
    }

    /// Id lists built with the exact production shape
    /// (`filter_map(...).collect()`, as `current_instances` builds them),
    /// so capacities follow the pinned-toolchain growth law for real.
    fn growth_ids(base: u64, len: usize) -> Vec<InstanceId> {
        let partitions: Vec<(u64, Option<InstanceId>)> = (0..len as u64)
            .map(|offset| (base + offset, Some(InstanceId::from_raw(base + offset))))
            .collect();
        partitions.iter().filter_map(|(_, id)| *id).collect()
    }

    fn scripted_receipt(
        domain: NativeDomainId,
        cookie: u64,
        watched: &RetainedInventoryTarget,
        ids: Vec<InstanceId>,
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
            ids,
        )
    }

    fn scripted_invalidation(
        domain: NativeDomainId,
        cookie: u64,
        ids: Vec<InstanceId>,
    ) -> TickOutcome {
        TickOutcome::Invalidation(Invalidation::scripted(
            domain,
            InvalidationScope::InstancesRetired {
                image: ImageIdentity {
                    task_cookie: cookie,
                    exec_id: 1,
                },
                file_slot: 0,
                ids,
            },
            None,
        ))
    }

    fn accumulator(domain: NativeDomainId, budgets: CollectedBudgets) -> CollectedReports {
        let pool = SemanticResourcePool::reference_limit(SEMANTIC_RESOURCE_LIMIT);
        let lease = pool
            .reserve(budgets.bytes)
            .expect("the test pool covers the computed budgets");
        CollectedReports::for_test(domain, budgets, lease).expect("exact test capacities")
    }

    /// The binder's up to four refresh receipts reach the stash after the
    /// reservation measured it, so the nested limit must carry an explicit
    /// binder margin: a saturated tick (1,024 receipts naming the full
    /// 4,096-id mint budget with growth-law capacities) plus four binder
    /// receipts re-naming that pool must still fit the production limit
    /// and merge. Count and per-receipt checks pass on both trees; only
    /// the cumulative nested limit distinguishes them.
    #[test]
    fn binding_nested_limit_covers_binder_receipts_at_saturation() {
        const PARTITIONS: usize = 1_024;
        let domain = NativeDomainId::mint();
        let watched = watched_target();
        let watched_bound = watched
            .retained_copy_allocation_charge()
            .expect("a measurable watched copy");
        let mut receipts = Vec::with_capacity(PARTITIONS + REFRESHES_PER_BIND);
        let mut next_id = 0u64;
        for index in 0..PARTITIONS {
            let len = if index < 819 {
                5
            } else if index == 819 {
                1
            } else {
                0
            };
            let ids = growth_ids(next_id, len);
            next_id += len as u64;
            if len == 5 {
                assert_eq!(
                    ids.capacity(),
                    8,
                    "the twin's saturation shape needs the pinned growth law"
                );
            }
            if len == 1 {
                assert_eq!(
                    ids.capacity(),
                    4,
                    "the twin's saturation shape needs the pinned growth law"
                );
            }
            receipts.push(scripted_receipt(
                domain,
                1_000 + index as u64,
                &watched,
                ids,
            ));
        }
        assert_eq!(
            next_id, MAX_INSTANCES as u64,
            "the saturated tick names the whole mint budget"
        );
        let mut binder_base = 0u64;
        for (slot, len) in [1_025usize, 1_025, 1_025, 1_021].iter().enumerate() {
            let ids = growth_ids(binder_base, *len);
            binder_base += *len as u64;
            receipts.push(scripted_receipt(domain, 2_000 + slot as u64, &watched, ids));
        }
        assert_eq!(binder_base, MAX_INSTANCES as u64);
        assert_eq!(receipts.len(), PARTITIONS + REFRESHES_PER_BIND);
        // The four binder receipts re-scan bound pairs, so overlap with
        // tick keys is honest; disjointness among the four follows from
        // the binder's distinct pairs.
        let binder_ids: usize = receipts[PARTITIONS..]
            .iter()
            .map(|receipt| receipt.instances().len())
            .sum();
        assert_eq!(binder_ids, MAX_INSTANCES);

        let budgets =
            collected_budgets(PARTITIONS, 0, 0, watched_bound).expect("saturated budgets");
        assert_eq!(budgets.receipt_limit, PARTITIONS + REFRESHES_PER_BIND);
        // The margin term is load-bearing and exact: varying only the
        // watched bound must move the production nested limit by one
        // watched copy per tick receipt plus exactly four per-receipt
        // allowances for the post-reservation binder receipts.
        let shifted =
            collected_budgets(PARTITIONS, 0, 0, watched_bound + 1_000).expect("shifted budgets");
        assert_eq!(
            shifted.nested_limit - budgets.nested_limit,
            (PARTITIONS + REFRESHES_PER_BIND) * 1_000
        );
        let measured: usize = receipts
            .iter()
            .map(|receipt| receipt.owned_storage_bytes().expect("a measurable receipt"))
            .sum();
        assert!(
            measured <= budgets.nested_limit,
            "a saturated tick plus 4 binder receipts must fit the nested limit: \
             measured={measured} limit={}",
            budgets.nested_limit
        );
        let mut reports = accumulator(domain, budgets);
        assert_eq!(
            reports.receipt_limit_for_test(),
            PARTITIONS + REFRESHES_PER_BIND
        );
        assert!(
            receipts.iter().all(|receipt| {
                receipt
                    .owned_storage_bytes()
                    .is_some_and(|bytes| bytes <= reports.nested_per_receipt_for_test())
            }),
            "every receipt passes the per-receipt sanity check"
        );
        let batch = SemanticBatch::from_tick_report(
            domain,
            TickReport::scripted(Vec::new(), receipts),
            Vec::new(),
            0,
        )
        .expect("a scripted batch respects lane bounds");
        reports
            .merge(batch)
            .expect("an honest saturated transaction must merge");
        assert_eq!(reports.nested_used_for_test(), measured);
    }

    /// Outcome-owned invalidation id lists count toward the same
    /// cumulative nested limit in `merge`: an over-bound invalidation
    /// batch refuses with the named storage reason, while an honest
    /// saturated shape binds with exact accounting.
    #[test]
    fn merge_measures_invalidation_id_bytes() {
        let domain = NativeDomainId::mint();
        let watched = watched_target();
        let watched_bound = watched
            .retained_copy_allocation_charge()
            .expect("a measurable watched copy");
        let budgets = collected_budgets(0, 0, 0, watched_bound).expect("unpartitioned budgets");
        let heavy: Vec<TickOutcome> = (0..128u64)
            .map(|slot| scripted_invalidation(domain, slot, growth_ids(slot * 1_024, 1_024)))
            .collect();
        let heavy_bytes: usize = heavy
            .iter()
            .map(|outcome| outcome.owned_storage_bytes().expect("measurable"))
            .sum();
        assert!(
            heavy_bytes > budgets.nested_limit,
            "the over-bound shape must exceed the whole nested limit: \
             {heavy_bytes} vs {}",
            budgets.nested_limit
        );
        let mut reports = accumulator(domain, budgets);
        let batch = SemanticBatch::from_tick_report(
            domain,
            TickReport::scripted(heavy, Vec::new()),
            Vec::new(),
            0,
        )
        .expect("a scripted batch respects lane bounds");
        assert_eq!(
            reports.merge(batch).unwrap_err(),
            SemanticRefusal::ProviderStorage
        );

        let budgets = collected_budgets(0, 0, 0, watched_bound).expect("unpartitioned budgets");
        let mut reports = accumulator(domain, budgets);
        let saturated: Vec<TickOutcome> = (0..MAX_INSTANCES as u64)
            .map(|slot| scripted_invalidation(domain, slot, growth_ids(slot, 1)))
            .collect();
        let saturated_bytes: usize = saturated
            .iter()
            .map(|outcome| outcome.owned_storage_bytes().expect("measurable"))
            .sum();
        assert!(
            saturated_bytes <= reports.nested_limit_for_test(),
            "honest saturation (one id per outcome, the full mint budget) must fit: \
             {saturated_bytes} vs {}",
            reports.nested_limit_for_test()
        );
        let batch = SemanticBatch::from_tick_report(
            domain,
            TickReport::scripted(saturated, Vec::new()),
            Vec::new(),
            0,
        )
        .expect("a scripted batch respects lane bounds");
        reports
            .merge(batch)
            .expect("honest invalidation saturation must merge");
        assert_eq!(reports.nested_used_for_test(), saturated_bytes);
    }

    /// The pending-Q merge measures outcome-owned id lists exactly like
    /// `merge`: over-bound invalidations refuse, honest saturation binds.
    #[test]
    fn merge_pending_q_measures_invalidation_id_bytes() {
        let domain = NativeDomainId::mint();
        let watched = watched_target();
        let watched_bound = watched
            .retained_copy_allocation_charge()
            .expect("a measurable watched copy");
        let budgets = collected_budgets(0, 0, 0, watched_bound).expect("unpartitioned budgets");
        let heavy: Vec<TickOutcome> = (0..128u64)
            .map(|slot| scripted_invalidation(domain, slot, growth_ids(slot * 1_024, 1_024)))
            .collect();
        let heavy_bytes: usize = heavy
            .iter()
            .map(|outcome| outcome.owned_storage_bytes().expect("measurable"))
            .sum();
        assert!(
            heavy_bytes > budgets.nested_limit,
            "the over-bound shape must exceed the whole nested limit: \
             {heavy_bytes} vs {}",
            budgets.nested_limit
        );
        let mut reports = accumulator(domain, budgets);
        let mut report = TickReport::scripted(heavy, Vec::new());
        assert_eq!(
            reports.merge_pending_q(domain, &mut report).unwrap_err(),
            SemanticRefusal::ProviderStorage
        );

        let budgets = collected_budgets(0, 0, 0, watched_bound).expect("unpartitioned budgets");
        let mut reports = accumulator(domain, budgets);
        let saturated: Vec<TickOutcome> = (0..MAX_INSTANCES as u64)
            .map(|slot| scripted_invalidation(domain, slot, growth_ids(slot, 1)))
            .collect();
        let saturated_bytes: usize = saturated
            .iter()
            .map(|outcome| outcome.owned_storage_bytes().expect("measurable"))
            .sum();
        assert!(
            saturated_bytes <= reports.nested_limit_for_test(),
            "honest saturation (one id per outcome, the full mint budget) must fit: \
             {saturated_bytes} vs {}",
            reports.nested_limit_for_test()
        );
        let mut report = TickReport::scripted(saturated, Vec::new());
        reports
            .merge_pending_q(domain, &mut report)
            .expect("honest invalidation saturation must merge");
        assert_eq!(reports.nested_used_for_test(), saturated_bytes);
    }
}
