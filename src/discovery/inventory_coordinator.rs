//! SPDX-License-Identifier: GPL-3.0-or-later
//! The I3/I4b inventory coordinator: owns the I4a scan window, drives
//! scan→reconcile→publish, revalidates every prepared candidate at its
//! publication boundary, and commits through the explicit seam.
//!
//! Two lanes share the caller adapter, the caller registry, and the batch
//! boundary:
//!
//! - native: exact image authority through the inventory core — open,
//!   lease, windowed scan, prepare, revalidate-at-commit, publish. Used
//!   when the caller supplies BPF image identity (privileged) or a
//!   scripted guard over owned fixtures (tests).
//! - scan: unprivileged catalog collection with pidfd/start-time
//!   incarnations. Exact-image authority is unavailable here, so every
//!   record reads `scan_pinned` and the gaps say why.
//!
//! I3/I4 mapping: the coordinator owns the I4a window (`begin_window`
//! per scan, monotonically increasing IDs, lease held across the scan);
//! preparation never implies publication (`commit` revalidates after any
//! gap since preparation); the I4b batch is `commit_batch`, which runs
//! the engine tail and the registry publish as one synchronous step, so
//! inventory facts publish through the same batch boundary the Phase 2
//! ordering test pins.

use super::inventory::{
    ExecProof, ImageGuard, InventoryCommit, InventoryDiscoveryConfig, InventoryOwnerLimits,
    RefreshCause, ScanReceipt,
};
use super::*;
#[cfg(test)]
use crate::attach::capture::ScopeIncarnation;
use crate::attach::capture::{
    CallerCountUpdate, CaptureScopeCoverage, DiscoveryBatch, DomainCookie, ExtendReceipt,
    LifecycleLoss, NativeDomainId, ScopeCustody, WitnessBatch, WitnessRow,
};
use crate::capacity::InventoryBudget;
use crate::discovery::caller_registry::{
    AdmissionState, AdmitFailure, BudgetRefusal, CallerAdapter, CallerEvent, CallerId,
    CallerRegistry, CountPublication, CoverageNote, EdgeRecord, ExeIdentity, ImageAuthority,
    MappingState, ModuleId, ModuleInfo, ModuleKey, PendingCountOutcome, PendingRejection,
    ProcessSource, RegistryGap, RegistryLimits, UnknownReason, UseCoverage,
};
use crate::discovery::inventory_attach_set::{
    AbsorbOutcome, AttachModuleKey, AttachObjectId, AttachVerdict, ENDPOINT_RESOURCE, EndpointId,
    InventoryAttachSet, MEMBERSHIP_RESOURCE, ModuleMembers, TargetDelta,
};
use crate::discovery::native_binding::{
    BinderLimits, Binding, CurrentBindingCheck, CurrentBindingRequest, CurrentBindingSighting,
    Decision, ExecTransition, NativeBinder, NativeIdentity, UnboundReason,
};
use crate::discovery::scan::{
    InventoryDiscoveryLimits, InventoryRetainedLimits, InventoryWindowLimits, WindowId,
};
use crate::discovery::sweep_attribution::AttributionLoss;
use crate::inspect_system::inventory_cgroup::{
    CgroupCollectRequest, CgroupCollection, CgroupFence, ScopedCollectionOutcome,
};
use crate::inventory_diagnostics::{
    Decision as DiagnosticDecision, DiagnosticConfig, DiagnosticKind, DiagnosticOutcome,
    DiagnosticReason, DiagnosticRecord, Eligibility, FinishedDiagnostics, InitError, NativePairKey,
    ReadOrigin, Recorder,
};
use crate::inventory_semantics::{AttestedSemanticLane, SemanticBatch};
use crate::scope::inventory_cgroup::{CgroupWalkLimits, CgroupWalkState, CollectionControl};
use p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
use p11scope_ebpf_common::inventory_callers::CallerEvidence;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

#[path = "inventory_count_eligibility.rs"]
mod count_eligibility;
use count_eligibility::{
    CountOwnership, CurrentCandidates, OwnershipEpoch, OwnershipScan, ReceiptDisposition,
    ReceiptView, ReceiptWork, RecoveryWorkBudget,
};

#[path = "inventory_coordinator/semantics.rs"]
pub(crate) mod semantics;

/// What one inventory pass scans: one named process, or the machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InventoryScope {
    Pid(u32),
    System,
}

/// What one scan pass concluded. Registry mutations staged by the pass
/// stay invisible until `commit_batch` publishes them.
#[derive(Debug, Clone)]
pub(crate) struct PassReport {
    pub pass: u64,
    /// Members observed this pass: deep-scanned plus maps-matched.
    pub scanned: usize,
    /// Of `scanned`, the members attributed by exact maps identity (C1b).
    pub maps_matched: usize,
    pub native_callers: usize,
    pub scan_callers: usize,
    pub engine_changed: bool,
    pub pending_refresh: Vec<CallerId>,
    pub events: Vec<CallerEvent>,
    /// Per-stage wall time of the pass: the catalog collection's stages
    /// plus reconcile, native scans, and projection.
    pub timings: crate::timing::StageTimings,
}

/// What one batch commit published: both revisions, which the ordering
/// test pins as advanced synchronously with the commit return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BatchReceipt {
    pub engine_facts: u64,
    pub engine_published: u64,
    pub registry_facts: u64,
    pub registry_published: u64,
    pub registry_applied: usize,
}

/// Delivered after the actual publication boundary. Cg4 must service its
/// newly available target delta and emit these delayed admission events.
#[cfg_attr(not(test), allow(dead_code))] // Cg4 consumes completion after commit.
pub(crate) struct CgroupCompletion {
    pub(crate) state: CgroupWalkState,
    pub(crate) outcome: ScopedCollectionOutcome,
    pub(crate) events: Vec<CallerEvent>,
    pub(crate) admitted: usize,
    /// Validated callers in this pass, including already-published same images.
    pub(crate) scan_callers: usize,
}

/// Static reason carried when a scan defers past its deadline. The
/// refresh request stays pending (no commit ran), so the next pass with
/// a fresh deadline retries the same owner.
const DEADLINE_DEFERRED: &str = "inventory scan deadline passed; the scan defers to the next pass";

/// O1 endpoint evidence: failed endpoints make their module undercount.
/// Pinned verbatim: the oracle matches this subject.
const PARTIAL_ATTACH_SUBJECT: &str = "native endpoint attach failed";

/// Per-pid authority resolution with a native open attempt: the open is
/// the check, so the native path is attempted honestly on every pass
/// and the scan lane is a recorded fallback, not a compile-time fork.
struct AuthorityResolver<'a, Pin> {
    engine: &'a mut Engine,
    pending: &'a mut BTreeMap<u32, ProcessViewId>,
    guard: &'a mut dyn ImageGuard,
    identity: &'a mut dyn NativeIdentity<Pin>,
    native_failures: Vec<(u32, String)>,
    scan_pinned: usize,
}

impl<Pin> AuthorityResolver<'_, Pin> {
    fn resolve(&mut self, pid: u32) -> ImageAuthority {
        match self
            .identity
            .owner_image(pid)
            .filter(|image| image.task_cookie != 0)
        {
            Some(image) => match self
                .engine
                .open_inventory_owner(pid, image, &mut *self.guard)
            {
                Ok(owner) => {
                    self.pending.insert(pid, owner);
                    ImageAuthority::NativeExact {
                        task_cookie: image.task_cookie,
                        exec_id: image.exec_id,
                    }
                }
                Err(error) => {
                    self.native_failures.push((pid, format!("{error:#}")));
                    ImageAuthority::ScanPinned
                }
            },
            None => {
                self.scan_pinned += 1;
                ImageAuthority::ScanPinned
            }
        }
    }

    fn finish(self) -> (Vec<(u32, String)>, usize) {
        (self.native_failures, self.scan_pinned)
    }
}

/// One held exec handoff (H6 slice 2): the ended incarnation's identity
/// and revision, its original held custody, and the native transition
/// evidence. Minted only by the coordinator's ended-incarnation path
/// (`apply_exec_transition` via `mint_pending_successor`); committed by
/// `commit_pending_successor` (or the scoped collection commit) or released
/// on refusal/stop. Holds no borrowed cgroup permit across async work:
/// scope proof is borrowed fresh at commit. Move-only: private fields, no
/// public scalar constructor, `Clone`, `Default`, serialization, or
/// authority booleans.
struct PendingExecSuccessor<Pin> {
    old: CallerId,
    old_incarnation: u32,
    pid: u32,
    custody: Pin,
    /// Current generation/image reads at mint: commit refuses when they
    /// moved (a newer image or generation arrived before commit).
    mint_start: Option<u64>,
    mint_exe: Option<ExeIdentity>,
    transition: ExecTransition,
}

/// The coordinator: an Inventory-policy engine, the caller adapter, and
/// the caller registry behind one batch boundary, plus the attach set the
/// catalog's Inventory lowering feeds every pass.
pub(crate) struct InventoryCoordinator<Source: ProcessSource> {
    engine: Engine,
    /// Explicit semantic inputs are independent of broad physical admission.
    semantic_inputs: semantics::SemanticInputs,
    adapter: CallerAdapter<Source>,
    registry: CallerRegistry,
    attach_set: InventoryAttachSet,
    /// Endpoints and objects the attach set added since the capture facade
    /// last took them. Bounded by the endpoint budget: every endpoint
    /// enters exactly once.
    pending_targets: TargetDelta,
    /// What the capture facade's receipts say per endpoint, once native
    /// capture runs (Task 6 C3); `None` in the scan lane.
    capture: Option<CaptureCoverage>,
    /// The native witness binder (Task 6 C4): every native row enters
    /// through `stage_native`.
    binder: NativeBinder,
    /// Accepted semantic caller bindings (H3 Task 3): one stable custody
    /// Arc per accepted caller, owned by the coordinator semantic child.
    semantic_bindings: semantics::SemanticBindingSet,
    /// At most one ordinary semantic collection quantum, finalized after
    /// the commit tail and before registry publication.
    pending_semantic: Option<SemanticBatch>,
    /// Detailed domains whose semantic authority ended permanently
    /// (cut/writeback/counter failure): new batches refuse, broad
    /// Inventory continues.
    refused_semantic_domains: HashSet<NativeDomainId>,
    /// Pending physical adjudication (H3 Task 3): one marker per live
    /// caller whose unscanned placeholder waits for the commit tail.
    /// Bounded by the caller budget; drained every commit.
    pending_adjudication: BTreeMap<CallerId, u32>,
    /// Callers with genuine physical uncertainty this publication
    /// (unscanned members, incomplete absences): the tail-gap source.
    tail_uncertain: BTreeSet<CallerId>,
    /// Callers with complete same-custody caller/provider/full-image
    /// proof this publication: the suppression source.
    complete_scanned: BTreeSet<CallerId>,
    /// Latest observed exec per Detailed ticket: H0-association proof
    /// for gap minting, keyed conservatively for refusal.
    proven_images: HashMap<(NativeDomainId, u64), u64>,
    /// The latest known count per witnessed pair (C7 C4): first-sight
    /// and refresh counts merge here (the maximum wins, with its
    /// observing read) and stage to the edge once the pair binds. One
    /// entry per CALLER_USE row at most.
    pair_counts: HashMap<PairKey, HeldPairCount>,
    /// Decided pairs (C7 C4): bound pairs stage their counts to one
    /// edge, dropped pairs (binder-unbound, ambiguous, or edgeless)
    /// never publish — DR-C51-PREADMIT stays out. One entry per
    /// decided row at most.
    pair_targets: HashMap<PairKey, PairTarget>,
    /// Outstanding publication-time count placements (P3): each staged
    /// pending count's opaque handle back to its pair. Drained with the
    /// publication's decisions; one entry per staged pending count.
    pending_ids: HashMap<u64, PendingCountObservation>,
    placement_generations: HashMap<PairKey, Option<u64>>,
    count_ownership: CountOwnership,
    recoveries: HashMap<PairKey, PairRecovery>,
    recovery_order: Vec<PairKey>,
    recovery_cursor: usize,
    /// The next pending-count handle (P3): minted in staging order.
    next_pending_id: u64,
    owners: BTreeMap<CallerId, ProcessViewId>,
    pending_owners: BTreeMap<u32, ProcessViewId>,
    /// Held exec handoffs (H6 slice 2): at most one per ended caller, keyed
    /// by it — no new unbounded table, one entry per retired caller
    /// reservation at most. Unscoped handoffs commit immediately; scoped
    /// ones wait for a fresh collection transaction.
    pending_successors: BTreeMap<CallerId, PendingExecSuccessor<Source::Pin>>,
    /// Leader exits already recorded as link loss (H6 slice 2): one entry
    /// per incarnation at most, never cleared (IDs never reuse).
    leader_link_loss_noted: BTreeSet<CallerId>,
    /// Retirements already staged in the registry (H6 slice 2): held
    /// handoffs report the old incarnation at mint and again at commit;
    /// the second report binds owners without restaging the retirement.
    /// One entry per retired caller at most, never cleared.
    staged_retirements: BTreeSet<CallerId>,
    /// Coordinator stop (H6 slice 2): set once, never cleared. No new scan,
    /// attach, successor/name admission, or retry starts afterwards; staged
    /// facts still drain through `commit_batch`.
    stopped: bool,
    cgroup_fence: CgroupFence,
    pending_cgroup: Option<(CgroupCollection, u64)>,
    completed_cgroup: Option<CgroupCompletion>,
    scanned_owners: BTreeSet<ProcessViewId>,
    churned_owners: BTreeSet<ProcessViewId>,
    next_window: u64,
    passes: u64,
    authority_gap_recorded: bool,
    /// The run's lifecycle-ring high-water: the maximum fill any staged
    /// drain reported. Timings telemetry only (the stage-timings pass
    /// lines), never schema.
    lifecycle_high_water_bytes: Option<u64>,
    diagnostics: Option<Recorder>,
    diagnostic_health: Option<u16>,
    diagnostic_refresh_loss: bool,
    diagnostic_native_unavailable: bool,
}

fn inventory_config(endpoint_budget: InventoryBudget) -> Result<InventoryDiscoveryConfig> {
    let window = InventoryWindowLimits::new(16 << 20, 1 << 20, 4096, 32768, 4096)
        .map_err(anyhow::Error::msg)?;
    let retained = InventoryRetainedLimits::new(8192, 32768, 8192, 128, 128, 16 << 20)
        .map_err(anyhow::Error::msg)?;
    let work =
        InventoryDiscoveryLimits::new(8 << 20, window, retained).map_err(anyhow::Error::msg)?;
    Ok(InventoryDiscoveryConfig::new(
        work,
        InventoryOwnerLimits::new(1024, 8, 32768).map_err(anyhow::Error::msg)?,
        endpoint_budget,
    ))
}

impl<Source: ProcessSource> InventoryCoordinator<Source> {
    // Retain the default constructor for existing internal harness callers;
    // the public runtime always supplies its already-resolved budget.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(
        scope: Scope,
        hooks: HookRegistry,
        hints: Vec<PathBuf>,
        source: Source,
        registry_limits: RegistryLimits,
    ) -> Result<Self> {
        Self::new_with_budget(
            scope,
            hooks,
            hints,
            source,
            registry_limits,
            crate::capacity::inventory_endpoint_budget(None).map_err(anyhow::Error::msg)?,
        )
    }

    /// One immutable endpoint policy for engine admission, catalog lowering,
    /// the append-only attach set, and subsequent native preparation.
    pub(crate) fn new_with_budget(
        scope: Scope,
        hooks: HookRegistry,
        hints: Vec<PathBuf>,
        source: Source,
        registry_limits: RegistryLimits,
        endpoint_budget: InventoryBudget,
    ) -> Result<Self> {
        let mut adapter = CallerAdapter::new(source);
        // One caller budget, enforced where incarnations are minted; the
        // registry's caller cap stands behind it as a backstop.
        adapter.set_max_callers(registry_limits.max_callers);
        Ok(Self {
            engine: Engine::inventory(inventory_config(endpoint_budget)?, scope, hooks, hints)?,
            semantic_inputs: semantics::SemanticInputs::new(Vec::new()),
            adapter,
            registry: CallerRegistry::new(registry_limits),
            attach_set: InventoryAttachSet::new(endpoint_budget),
            pending_targets: TargetDelta::default(),
            capture: None,
            binder: NativeBinder::new(BinderLimits::default()),
            semantic_bindings: semantics::SemanticBindingSet::new(),
            pending_semantic: None,
            refused_semantic_domains: HashSet::new(),
            pending_adjudication: BTreeMap::new(),
            tail_uncertain: BTreeSet::new(),
            complete_scanned: BTreeSet::new(),
            proven_images: HashMap::new(),
            pair_counts: HashMap::new(),
            pair_targets: HashMap::new(),
            pending_ids: HashMap::new(),
            placement_generations: HashMap::new(),
            count_ownership: CountOwnership::new(registry_limits),
            recoveries: HashMap::new(),
            recovery_order: Vec::new(),
            recovery_cursor: 0,
            next_pending_id: 0,
            owners: BTreeMap::new(),
            pending_owners: BTreeMap::new(),
            pending_successors: BTreeMap::new(),
            leader_link_loss_noted: BTreeSet::new(),
            staged_retirements: BTreeSet::new(),
            stopped: false,
            cgroup_fence: CgroupFence::default(),
            pending_cgroup: None,
            completed_cgroup: None,
            scanned_owners: BTreeSet::new(),
            churned_owners: BTreeSet::new(),
            next_window: 0,
            passes: 0,
            authority_gap_recorded: false,
            lifecycle_high_water_bytes: None,
            diagnostics: None,
            diagnostic_health: None,
            diagnostic_refresh_loss: false,
            diagnostic_native_unavailable: false,
        })
    }

    /// The run's lifecycle-ring high-water so far, for the stage-timings
    /// pass lines. `None` until a native drain stages (the scan lane).
    pub(crate) fn lifecycle_high_water_bytes(&self) -> Option<u64> {
        self.lifecycle_high_water_bytes
    }

    pub(crate) fn set_semantic_manifests(&mut self, manifests: Vec<PathBuf>) {
        self.semantic_inputs = semantics::SemanticInputs::new(manifests);
    }

    pub(crate) fn prepare_semantic_subset(&mut self) -> semantics::SubsetPreparation {
        self.semantic_inputs.prepare(&self.engine)
    }

    pub(crate) fn enable_diagnostics(&mut self, config: DiagnosticConfig) -> Result<(), InitError> {
        self.diagnostics = Some(Recorder::try_new(config)?);
        Ok(())
    }

    pub(crate) fn take_diagnostics(
        &mut self,
        outcome: DiagnosticOutcome,
    ) -> Option<FinishedDiagnostics> {
        self.diagnostics
            .take()
            .map(|recorder| recorder.finish(outcome))
    }

    pub(crate) fn note_diagnostics_native_unavailable(&mut self) {
        if let Some(recorder) = &mut self.diagnostics
            && !self.diagnostic_native_unavailable
        {
            let mut record = DiagnosticRecord::new(DiagnosticKind::CaptureHealth);
            record.reason = Some(DiagnosticReason::NativeUnavailable);
            recorder.record(record);
            self.diagnostic_native_unavailable = true;
        }
    }

    fn diagnostic_identity(&self, record: &mut DiagnosticRecord, caller: CallerId) {
        record.caller = Some(caller.0);
        if let Some(caller) = self.adapter.record(caller) {
            record.pid = Some(caller.pid);
            record.incarnation = Some(u64::from(caller.incarnation));
        } else {
            record.context_unavailable = true;
        }
    }

    fn diagnostic_count_record(
        &self,
        key: PairKey,
        caller: CallerId,
        observation: PairCount,
        base: u64,
        staged: u64,
        since: u64,
    ) -> DiagnosticRecord {
        let recovery = self.recoveries.get(&key);
        let mut record = DiagnosticRecord::new(DiagnosticKind::CountDecision)
            .with_pair(key.diagnostic_key())
            .with_private_ids(
                None,
                recovery.and_then(|recovery| recovery.epoch.map(|epoch| epoch.0)),
                None,
            );
        self.diagnostic_identity(&mut record, caller);
        record.absolute = Some(observation.count);
        record.base = Some(base);
        record.staged = Some(staged);
        record.after = Some(base);
        record.through = Some(observation.count);
        record.pre = Some(observation.anchor_ns);
        record.post = Some(observation.last_ns);
        record.baseline_pre = (base != 0).then_some(since);
        record.fence = recovery.and_then(|recovery| recovery.fence.map(|read| read.count));
        record.observation_ref = nonzero_ref(observation.diagnostic_observation);
        record.transition_ref = recovery
            .and_then(|recovery| nonzero_ref(recovery.diagnostic.transition_ref))
            .or_else(|| nonzero_ref(observation.diagnostic_transition));
        // Ordinary targets retain PRE only; a matching immutable recovery fence
        // also retains the genuine read POST. Never infer it from newer counts.
        if let Some(fence) = recovery.and_then(|recovery| recovery.fence)
            && fence.count == base
            && fence.anchor_ns == since
        {
            record.baseline_pre = Some(fence.anchor_ns);
            record.baseline_post = Some(fence.last_ns);
        }
        record.context_unavailable = record.pid.is_none()
            || record.observation_ref.is_none()
            || base != 0 && record.baseline_post.is_none();
        record
    }

    fn diagnostic_raw_count(
        &mut self,
        key: PairKey,
        pid: Option<u32>,
        origin: ReadOrigin,
        count: u64,
        interval: (u64, u64),
        valid: bool,
    ) {
        if self.diagnostics.is_none() {
            return;
        }
        let previous = self.pair_counts.get(&key).copied();
        let reason = if previous.is_some_and(|held| count < held.count) {
            Some(DiagnosticReason::StaleObservation)
        } else if !valid {
            Some(DiagnosticReason::CountInvalid)
        } else {
            None
        };
        if previous.is_some_and(|held| held.diagnostic_last_raw == Some(count)) {
            if let Some(reason) = reason {
                self.diagnostics
                    .as_mut()
                    .expect("enabled recorder")
                    .note_reason(reason);
            }
            return;
        }
        let caller = match self.pair_targets.get(&key) {
            Some(
                PairTarget::Bound { caller, .. }
                | PairTarget::Pending { caller, .. }
                | PairTarget::Suspended { caller, .. },
            ) => Some(*caller),
            _ => None,
        };
        let mut record =
            DiagnosticRecord::new(DiagnosticKind::CountObservation).with_pair(key.diagnostic_key());
        record.pid = pid;
        if let Some(caller) = caller {
            self.diagnostic_identity(&mut record, caller);
        }
        record.origin = Some(origin);
        record.absolute = Some(count);
        let (pre, post) = interval;
        record.pre = Some(pre);
        record.post = Some(post);
        record.reason = reason;
        let seq = self
            .diagnostics
            .as_mut()
            .expect("enabled recorder")
            .record_changed(previous.and_then(|held| held.diagnostic_last_raw), record)
            .unwrap_or(0);
        if let Some(held) = self.pair_counts.get_mut(&key) {
            held.diagnostic_last_raw = Some(count);
            if count > held.count {
                held.diagnostic_observation = seq;
            }
        }
    }

    fn diagnostic_recovery_decision(
        &mut self,
        key: PairKey,
        recovery: &mut PairRecovery,
        reason: DiagnosticReason,
        held: Option<PairCount>,
        decision: DiagnosticDecision,
    ) {
        if self.diagnostics.is_none() {
            return;
        }
        let state = (
            reason,
            decision,
            held.map_or(0, |held| held.diagnostic_observation),
            recovery.watermark,
            recovery.fence.map_or(0, |read| read.count),
        );
        if recovery.diagnostic.wait == Some(state) {
            self.diagnostics
                .as_mut()
                .expect("enabled recorder")
                .note_reason(reason);
            return;
        }
        let mut record = if let Some(held) = held {
            self.diagnostic_count_record(
                key,
                recovery.caller,
                held,
                recovery.watermark,
                recovery.watermark,
                recovery.fence.map_or(0, |read| read.anchor_ns),
            )
        } else {
            let mut record = DiagnosticRecord::new(DiagnosticKind::CountDecision)
                .with_pair(key.diagnostic_key());
            self.diagnostic_identity(&mut record, recovery.caller);
            record.context_unavailable = true;
            record
        };
        record = record.with_private_ids(None, recovery.epoch.map(|epoch| epoch.0), None);
        record.fence = recovery.fence.map(|read| read.count);
        record.transition_ref = nonzero_ref(recovery.diagnostic.transition_ref);
        record.decision = Some(decision);
        record.reason = Some(reason);
        self.diagnostics
            .as_mut()
            .expect("enabled recorder")
            .record(record);
        recovery.diagnostic.wait = Some(state);
    }

    fn diagnostic_recovery_wait(
        &mut self,
        key: PairKey,
        recovery: &mut PairRecovery,
        reason: DiagnosticReason,
        held: Option<PairCount>,
    ) {
        self.diagnostic_recovery_decision(key, recovery, reason, held, DiagnosticDecision::Pending);
    }

    fn diagnostic_ownership(
        &mut self,
        key: PairKey,
        recovery: &mut PairRecovery,
        candidate: &CurrentCandidates,
    ) {
        if self.diagnostics.is_none() {
            return;
        }
        let (eligibility, module, epoch, interval, reason) = match candidate {
            CurrentCandidates::Unknown => (
                Eligibility::Unknown,
                None,
                None,
                None,
                DiagnosticReason::OwnershipUnknown,
            ),
            CurrentCandidates::Shared => (
                Eligibility::SharedOwner,
                None,
                None,
                None,
                DiagnosticReason::SharedOwner,
            ),
            CurrentCandidates::Sole {
                module,
                epoch,
                scan,
            } => (
                Eligibility::SoleOwner,
                self.registry.module_id_for(module),
                Some(epoch.0),
                Some((scan.started_ns(), scan.finished_ns())),
                DiagnosticReason::SoleOwner,
            ),
        };
        let state = (eligibility, module, epoch);
        if recovery.diagnostic.ownership == Some(state) {
            return;
        }
        let mut record = DiagnosticRecord::new(DiagnosticKind::OwnershipTransition)
            .with_pair(key.diagnostic_key())
            .with_private_ids(None, epoch, None);
        self.diagnostic_identity(&mut record, recovery.caller);
        record.reason = Some(reason);
        record.prior_eligibility = recovery.diagnostic.ownership.map(|state| state.0);
        record.new_eligibility = Some(eligibility);
        record.module = module.map(|module| module.0);
        record.base = Some(recovery.watermark);
        record.fence = recovery.fence.map(|read| read.count);
        if recovery.epoch.map(|epoch| epoch.0) != epoch {
            record.fence = None;
            record.context_unavailable = true;
        }
        if let Some((pre, post)) = interval {
            record.baseline_pre = Some(pre);
            record.baseline_post = Some(post);
        }
        record.transition_ref = nonzero_ref(recovery.diagnostic.transition_ref);
        recovery.diagnostic.transition_ref = self
            .diagnostics
            .as_mut()
            .expect("enabled recorder")
            .record(record)
            .unwrap_or(0);
        recovery.diagnostic.ownership = Some(state);
        recovery.diagnostic.wait = None;
    }

    fn diagnostic_recovery_selection(
        &mut self,
        key: PairKey,
        recovery: &mut PairRecovery,
        proven: bool,
    ) {
        if self.diagnostics.is_none() {
            return;
        }
        let state = (
            recovery.epoch.map(|epoch| epoch.0),
            recovery.fence.map_or(0, |read| read.count),
            proven,
        );
        if recovery.diagnostic.selection == Some(state) {
            return;
        }
        let mut record = DiagnosticRecord::new(DiagnosticKind::OwnershipTransition)
            .with_pair(key.diagnostic_key())
            .with_private_ids(None, state.0, None);
        self.diagnostic_identity(&mut record, recovery.caller);
        record.reason = Some(if proven {
            DiagnosticReason::SoleOwner
        } else {
            DiagnosticReason::OwnershipTransition
        });
        record.prior_eligibility = recovery.diagnostic.selection.map(|state| {
            if state.2 {
                Eligibility::SoleOwner
            } else {
                Eligibility::Unproven
            }
        });
        record.new_eligibility = Some(if proven {
            Eligibility::SoleOwner
        } else {
            Eligibility::Unproven
        });
        record.base = Some(recovery.watermark);
        record.fence = nonzero_ref(state.1);
        record.transition_ref = nonzero_ref(recovery.diagnostic.transition_ref);
        if let Some(scan) = &recovery.scan {
            record.baseline_pre = Some(scan.started_ns());
            record.baseline_post = Some(scan.finished_ns());
        }
        if let Some(read) = recovery.fence {
            record.absolute = Some(read.count);
            record.pre = Some(read.anchor_ns);
            record.post = Some(read.last_ns);
            record.observation_ref = nonzero_ref(read.diagnostic_observation);
        } else {
            record.context_unavailable = true;
        }
        recovery.diagnostic.transition_ref = self
            .diagnostics
            .as_mut()
            .expect("enabled recorder")
            .record(record)
            .unwrap_or(0);
        recovery.diagnostic.selection = Some(state);
    }

    fn diagnostic_pending_refusal(
        &mut self,
        key: PairKey,
        caller: CallerId,
        observation: PairCount,
        base: u64,
        since: u64,
        reason: DiagnosticReason,
    ) {
        if self.diagnostics.is_none() {
            return;
        }
        let state = (reason, observation.count, base);
        if self
            .pair_counts
            .get(&key)
            .is_some_and(|held| held.diagnostic_refusal == Some(state))
        {
            self.diagnostics
                .as_mut()
                .expect("enabled recorder")
                .note_reason(reason);
            return;
        }
        let mut record = self.diagnostic_count_record(key, caller, observation, base, base, since);
        record.decision = Some(DiagnosticDecision::Rejected);
        record.reason = Some(reason);
        self.diagnostics
            .as_mut()
            .expect("enabled recorder")
            .record(record);
        if let Some(held) = self.pair_counts.get_mut(&key) {
            held.diagnostic_refusal = Some(state);
        }
    }

    fn diagnostic_pending_result(
        &mut self,
        pending_id: u64,
        pending: &PendingCountObservation,
        outcome: Option<&PendingCountOutcome>,
    ) {
        if self.diagnostics.is_none() {
            return;
        }
        let mut record = self
            .diagnostic_count_record(
                pending.key,
                pending.caller,
                pending.observation,
                pending.diagnostic.map_or(0, |diagnostic| diagnostic.base),
                pending.diagnostic.map_or(0, |diagnostic| diagnostic.staged),
                pending.diagnostic.map_or(0, |diagnostic| diagnostic.since),
            )
            .with_private_ids(
                None,
                match pending.origin {
                    PendingCountOrigin::Recovered(epoch) => Some(epoch.0),
                    _ => None,
                },
                Some(pending_id),
            );
        if let Some(diagnostic) = pending.diagnostic {
            record.fence = nonzero_ref(diagnostic.fence);
            record.baseline_post = nonzero_ref(diagnostic.baseline_post);
            record.transition_ref = nonzero_ref(diagnostic.transition_ref);
            record.context_unavailable = record.pid.is_none()
                || record.observation_ref.is_none()
                || diagnostic.base != 0 && record.baseline_post.is_none();
        } else {
            record.base = None;
            record.staged = None;
            record.after = None;
            record.baseline_pre = None;
            record.fence = None;
            record.transition_ref = None;
            record.context_unavailable = true;
        }
        match outcome {
            Some(PendingCountOutcome::Placed { module }) => {
                record.kind = DiagnosticKind::Publication;
                record.decision = Some(DiagnosticDecision::Placed);
                record.reason = Some(DiagnosticReason::SoleOwner);
                record.module = self.registry.module_id_for(module).map(|module| module.0);
                record.edge_total = self
                    .registry
                    .module_id_for(module)
                    .and_then(|module| self.registry.edge(pending.caller, module))
                    .map(|edge| edge.entry_count);
            }
            Some(PendingCountOutcome::Rejected { reason }) => {
                record.decision = Some(DiagnosticDecision::Rejected);
                record.reason = Some(match reason {
                    PendingRejection::Ambiguous => DiagnosticReason::SharedOwner,
                    PendingRejection::NoEdge => DiagnosticReason::OwnershipUnknown,
                });
            }
            Some(PendingCountOutcome::Unadmitted { module }) => {
                record.decision = Some(DiagnosticDecision::Pending);
                record.reason = Some(DiagnosticReason::NotAdmitted);
                record.module = self.registry.module_id_for(module).map(|module| module.0);
            }
            None => {
                record.decision = Some(DiagnosticDecision::Rejected);
                record.reason = Some(DiagnosticReason::StaleDecision);
            }
        }
        self.diagnostics
            .as_mut()
            .expect("enabled recorder")
            .record(record);
    }

    fn diagnostic_withheld(
        &mut self,
        key: PairKey,
        recovery: &PairRecovery,
        after: u64,
        through: u64,
        reason: DiagnosticReason,
        read: Option<PairCount>,
    ) {
        if self.diagnostics.is_none() || through <= after {
            return;
        }
        let mut record = DiagnosticRecord::new(DiagnosticKind::CountDecision)
            .with_pair(key.diagnostic_key())
            .with_private_ids(None, recovery.epoch.map(|epoch| epoch.0), None);
        self.diagnostic_identity(&mut record, recovery.caller);
        record.decision = Some(DiagnosticDecision::Withheld);
        record.reason = Some(reason);
        record.base = Some(after);
        record.after = Some(after);
        record.through = Some(through);
        record.fence = recovery.fence.map(|read| read.count);
        record.transition_ref = nonzero_ref(recovery.diagnostic.transition_ref);
        if let Some(read) = read {
            record.absolute = Some(read.count);
            record.pre = Some(read.anchor_ns);
            record.post = Some(read.last_ns);
            record.observation_ref = nonzero_ref(read.diagnostic_observation);
        }
        record.context_unavailable = true;
        self.diagnostics
            .as_mut()
            .expect("enabled recorder")
            .record(record);
    }

    pub(crate) fn adapter(&self) -> &CallerAdapter<Source> {
        &self.adapter
    }

    /// Mutable adapter access for the workload harness (scripted
    /// reconciles over programmed pids) and tests. The production
    /// command never mutates the adapter except through `scan_pass`.
    // Test-only seam: the cfg(test) harness and unit tests pin it.
    #[cfg(test)]
    pub(crate) fn adapter_mut(&mut self) -> &mut CallerAdapter<Source> {
        &mut self.adapter
    }

    pub(crate) fn registry(&self) -> &CallerRegistry {
        &self.registry
    }

    /// Stages one scope-level gap (no caller, module or PID) that
    /// publishes with the next pass: the run-wide PID-numbering mismatch
    /// (`pidns::numbering_gap`, review F4) is the only producer.
    pub(crate) fn note_scope_gap(&mut self, subject: String, reason: String) {
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject,
            reason,
            budget: None,
        });
    }

    /// Stages one pass-wide count-refresh loss boundary from the lane
    /// itself (P1-5 terminal-first): an incomplete terminal refresh
    /// demotes the retained counts to lower bounds exactly like a
    /// failed live read — a scope gap alone would leave them
    /// loss-free. The loss is a gap too, never silent loss.
    pub(crate) fn note_refresh_loss(&mut self, reason: String) {
        if let Some(recorder) = &mut self.diagnostics {
            if !self.diagnostic_refresh_loss {
                let mut record = DiagnosticRecord::new(DiagnosticKind::CaptureHealth);
                record.reason = Some(DiagnosticReason::CaptureLoss);
                recorder.record(record);
                self.diagnostic_refresh_loss = true;
            } else {
                recorder.note_reason(DiagnosticReason::CaptureLoss);
            }
        }
        self.registry.note_refresh_loss(reason);
    }

    // Test seam: production stages only through `scan_pass` (and, from
    // Task 6 C5, the native staging call).
    #[cfg(test)]
    pub(crate) fn registry_mut(&mut self) -> &mut CallerRegistry {
        &mut self.registry
    }

    /// Accepted semantic bindings (H3 Task 3): the tick window borrows
    /// from here; tests observe stable custody through it.
    pub(crate) fn semantic_bindings(&self) -> &semantics::SemanticBindingSet {
        &self.semantic_bindings
    }

    /// Mutable binding-set access for the tick window and tests.
    pub(crate) fn semantic_bindings_mut(&mut self) -> &mut semantics::SemanticBindingSet {
        &mut self.semantic_bindings
    }

    /// Test seam: stage one provisional marker the way cgroup collection
    /// does, so the tail adjudicator's genuine arm fires without a full
    /// scoped pass.
    #[cfg(test)]
    pub(crate) fn reference_stage_adjudication(&mut self, caller: CallerId, pid: u32) {
        self.pending_adjudication.insert(caller, pid);
    }

    /// Test seam: retained proven-image count, bounded by live bindings.
    #[cfg(test)]
    pub(crate) fn proven_image_count(&self) -> usize {
        self.proven_images.len()
    }

    /// Test seam: script the binder's current-binding clock so scripted
    /// horizons can cover scripted sightings.
    #[cfg(test)]
    pub(crate) fn set_semantic_binding_clock(&mut self, clock: fn() -> Option<u64>) {
        self.binder.set_current_binding_clock(clock);
    }

    /// The run's attach set (read side): presentation reports its
    /// endpoint budget and occupancy.
    pub(crate) fn attach_set(&self) -> &InventoryAttachSet {
        &self.attach_set
    }

    /// Takes what the attach set added since the last take: new endpoints
    /// in ID order plus newly retained objects, never a whole plan. The
    /// capture facade (Task 6 C3) is the production consumer; until it
    /// lands only tests take.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn take_target_delta(&mut self) -> TargetDelta {
        std::mem::take(&mut self.pending_targets)
    }

    /// Native capture starts: from now on each scan projection stages a
    /// coverage note per mapped edge from the capture's attach receipts.
    /// `scope` is explicitly System, Cgroup, or the capture's PID incarnation:
    /// only a caller of that pid whose start time matches, and the first
    /// such caller (image) only, is in scope — a reused pid never is.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 starts native capture.
    pub(crate) fn begin_capture_coverage(&mut self, scope: CaptureScopeCoverage) {
        self.capture = Some(CaptureCoverage {
            scope,
            bound: None,
            attached_at: BTreeMap::new(),
            failed: BTreeSet::new(),
            unproven: None,
            changed_objects: BTreeSet::new(),
            health_unproven: None,
            pairs_unproven: None,
            pairs_uncounted: None,
            last_clean_ns: None,
            sweep_began_ns: None,
            preadmission: PreadmissionStash::new(PREADMISSION_STASH_LIMIT),
            stopped: false,
        });
    }

    /// Forgets a capture coverage whose capture never activated (the
    /// `--capture auto` fallback): the run is the scan lane again.
    pub(crate) fn abandon_capture_coverage(&mut self) {
        self.capture = None;
    }

    /// The reason an edge no coverage note reached reads (`scan_only` by
    /// default; the native lane sets `not_attached`).
    pub(crate) fn set_uncovered_reason(&mut self, reason: UnknownReason) {
        self.registry.set_uncovered_reason(reason);
    }

    /// Absorbs one extend receipt: attached endpoints with their instants,
    /// failed endpoints (sticky), and the scope custody.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 forwards receipts.
    pub(crate) fn note_extend_receipt(&mut self, receipt: &ExtendReceipt) {
        // Exec coverage is the binder's, whatever capture coverage holds.
        if let Some(coverage) = receipt.exec_coverage {
            self.binder.note_exec_coverage(coverage);
        }
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        for attached in &receipt.attached {
            capture.attached_at.insert(attached.id, attached.at_ns);
        }
        for failed in &receipt.failed {
            capture.attached_at.remove(&failed.id);
            capture.failed.insert(failed.id);
        }
        self.note_partial_attach(receipt);
        if let Some(custody) = &receipt.custody {
            self.note_capture_custody(custody);
        }
    }

    /// O1 endpoint evidence: one gap per module with new failures or
    /// deferrals in this receipt. Failed endpoints are sticky (never
    /// retried — bounded: every failed endpoint lands in exactly one
    /// receipt); deferred endpoints are retried, but the deferral
    /// window's calls never come back, so the gap is sticky too even
    /// when a later receipt attaches the endpoint. Failed or deferred
    /// members make the module undercount, so its counted uses are
    /// lower bounds; the oracle withholds COUNT-EXACT over it
    /// (explicitly nonqualifying). Endpoints no module claims (evicted
    /// before the receipt) report run-wide. The subject and reason
    /// shapes are pinned verbatim: the oracle matches them.
    fn note_partial_attach(&mut self, receipt: &ExtendReceipt) {
        // Deferred endpoints dedupe: a receipt may carry the same
        // endpoint twice across its defer calls.
        let deferred: BTreeSet<EndpointId> = receipt
            .deferred
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id)
            .collect();
        if receipt.failed.is_empty() && deferred.is_empty() {
            return;
        }
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        let mut by_module: BTreeMap<AttachModuleKey, (usize, usize)> = BTreeMap::new();
        let mut unclaimed = (0usize, 0usize);
        for failed in &receipt.failed {
            let owners: Vec<AttachModuleKey> = self
                .attach_set
                .modules_with_member(failed.id)
                .cloned()
                .collect();
            if owners.is_empty() {
                unclaimed.0 += 1;
            } else {
                for key in owners {
                    by_module.entry(key).or_default().0 += 1;
                }
            }
        }
        for id in &deferred {
            let owners: Vec<AttachModuleKey> =
                self.attach_set.modules_with_member(*id).cloned().collect();
            if owners.is_empty() {
                unclaimed.1 += 1;
            } else {
                for key in owners {
                    by_module.entry(key).or_default().1 += 1;
                }
            }
        }
        for (key, (failed_here, deferred_here)) in by_module {
            let (total, failed_total) = match self.attach_set.module_members(&key) {
                Some(ModuleMembers::Known(members)) => (
                    members.len(),
                    members
                        .iter()
                        .filter(|id| capture.failed.contains(id))
                        .count(),
                ),
                // Unrecorded membership: no cumulative total exists, so
                // the reason carries this receipt's new failures.
                _ => (0, failed_here),
            };
            let registry_key = ModuleKey::physical(
                key.object.device.major,
                key.object.device.minor,
                key.object.inode,
                Some(key.sha256.clone()),
                "",
            );
            let mut parts = Vec::new();
            if failed_total > 0 {
                if total > 0 {
                    parts.push(format!(
                        "{failed_total} of {total} endpoints failed to attach (sticky, never retried)"
                    ));
                } else {
                    parts.push(format!(
                        "{failed_total} endpoints failed to attach (sticky, never retried)"
                    ));
                }
            }
            if deferred_here > 0 {
                parts.push(format!(
                    "{deferred_here} endpoint(s) still deferred when the receipt closed"
                ));
            }
            parts.push("counted uses are lower bounds".to_string());
            // Keyed (F3-04): the module may be staged-but-uncommitted
            // (first-discovered this pass — receipts run pre-commit),
            // so the ID resolves at publication, after its mapping
            // commits, instead of reporting run-wide.
            self.registry.record_gap_for_key(
                None,
                registry_key,
                None,
                PARTIAL_ATTACH_SUBJECT.into(),
                parts.join("; "),
                None,
            );
        }
        if unclaimed.0 > 0 || unclaimed.1 > 0 {
            let mut parts = Vec::new();
            if unclaimed.0 > 0 {
                parts.push(format!(
                    "{} endpoint(s) with no recorded module failed to attach (sticky, never retried)",
                    unclaimed.0
                ));
            }
            if unclaimed.1 > 0 {
                parts.push(format!(
                    "{} endpoint(s) with no recorded module still deferred when the receipt closed",
                    unclaimed.1
                ));
            }
            parts.push("counted uses are lower bounds".to_string());
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: PARTIAL_ATTACH_SUBJECT.into(),
                reason: parts.join("; "),
                budget: None,
            });
        }
    }

    /// Absorbs the capture's scope custody (`InventoryCapture::custody`,
    /// receipts, witness batches). The first unproven or lost custody ends
    /// every watch before stop (C5.2 D2): each ongoing interval freezes at
    /// `min(custody at_ns, last clean read)` — watches staged earlier in
    /// the same batch freeze with the rest, and one no clean read proved
    /// reads unknown — the loss is a gap, and no watch starts after.
    /// After stop it stages nothing: ended intervals are frozen facts.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 forwards custody.
    pub(crate) fn note_capture_custody(&mut self, custody: &ScopeCustody) {
        let Some(capture) = self.capture.as_mut().filter(|capture| !capture.stopped) else {
            return;
        };
        let (at_ns, reason) = match custody {
            ScopeCustody::System | ScopeCustody::PidHeld | ScopeCustody::CgroupHeld => return,
            ScopeCustody::PidUnproven { at_ns, reason } => (*at_ns, reason.clone()),
            ScopeCustody::PidLost { at_ns, reason } => (*at_ns, reason.clone()),
        };
        if capture.unproven.is_some() {
            return;
        }
        capture.unproven = Some(reason.clone());
        let until = capture.last_clean_ns.map_or(0, |clean| clean.min(at_ns));
        self.registry.note_watch_end(
            format!(
                "no clean read proved the watch before native capture scope custody became unproven: {reason}"
            ),
            until,
        );
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "native capture scope custody unproven".into(),
            reason: format!(
                "{reason}; every watched no-use interval ends at the earlier of the custody instant and the last clean read; a watch starting at or after that instant reads unknown, and no watch starts again"
            ),
            budget: None,
        });
    }

    /// Absorbs one witness batch's health and custody: a counter rise
    /// demotes every watch (dated at the batch's health baseline, the
    /// earliest instant of the drop) and lets a new watch start only from
    /// the detecting read on; an unproven health withholds watches until a
    /// batch proves it again; changed objects make their modules unknown
    /// from now on. The pair precondition (`pair_precondition_failure`,
    /// sticky) withholds every watch without demoting one. A batch that
    /// completes a gap-free CALLER_USE sweep with proven health, the pair
    /// precondition intact, no rise, and held custody is the latest
    /// proven-clean instant: the `health_read_ns` of the batch that sweep
    /// began in, but never past its custody proof (`custody_proven_ns`, the
    /// last held poll) or its lifecycle drain horizon (`lifecycle_proven_ns`:
    /// any lifecycle loss found later dates at or after it, so it never
    /// falls inside an interval — what makes "nothing after stop" sound).
    /// A system-scope lifecycle loss is a sticky demotion (C5.2 D4): see
    /// `note_lifecycle_loss`; a batch carrying one is never clean.
    /// A batch that leaves a stamped row pending is never clean either:
    /// the row's use is undecided, so the proven-clean instant is not
    /// extended over it (DR-LIVE-LABEL-LAG). `stage_native` absorbs the
    /// batch before this runs, so this batch's rows are already pending.
    /// After stop the watch half stages nothing (forward the terminal
    /// read before `end_capture_coverage`), but count freshness still
    /// consumes: the post-stop terminal refresh stages through this
    /// same call, and a failure beginning there demotes the retained
    /// counts exactly like a live one (P1-5 terminal-first).
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 forwards batches.
    pub(crate) fn note_witness_batch(&mut self, batch: &WitnessBatch) {
        if let Some(recorder) = &mut self.diagnostics {
            let health = u16::from(batch.health_unproven.is_some())
                | (u16::from(batch.health_regression.is_some()) << 1)
                | (u16::from(!batch.read_failures.is_empty()) << 2)
                | (u16::from(batch.refresh_sweep_gaps) << 3)
                | (u16::from(batch.refresh_deadline_reached) << 4)
                | (u16::from(batch.lifecycle_loss.is_some()) << 5)
                | (u16::from(!batch.changed_objects.is_empty()) << 6)
                | (u16::from(!batch.health.failures.is_empty()) << 7)
                | (u16::from(batch.health.malformed_discovery != 0) << 8)
                | (u16::from(batch.health.pin_check_failures != 0) << 9)
                | (u16::from(batch.health.caller_evidence.is_some_and(|counters| {
                    counters[CallerEvidence::PairInsertFailure.counter_index() as usize] != 0
                })) << 10)
                | (u16::from(batch.sweep_gaps) << 11);
            if self.diagnostic_health != Some(health) {
                let mut record = DiagnosticRecord::new(DiagnosticKind::CaptureHealth);
                record.reason = (health != 0).then_some(DiagnosticReason::CaptureLoss);
                record.pre = Some(batch.health_baseline_ns);
                record.post = Some(batch.health_read_ns);
                recorder.record(record);
                self.diagnostic_health = Some(health);
            } else if health != 0 {
                recorder.note_reason(DiagnosticReason::CaptureLoss);
            }
        }
        self.note_count_freshness(batch);
        let Some(capture) = self.capture.as_mut().filter(|capture| !capture.stopped) else {
            return;
        };
        capture.health_unproven = batch.health_unproven.clone();
        if capture.pairs_unproven.is_none() {
            capture.pairs_unproven = pair_precondition_failure(batch);
        }
        // C7 C4: a pair insert failure is sticky evidence that some
        // pair has use but no row. First sight only: the map never
        // deletes, so the first failure voids no-use for the capture.
        let uncounted_new = capture.pairs_uncounted.is_none();
        if uncounted_new && let Some(evidence) = batch.health.caller_evidence {
            let index = CallerEvidence::PairInsertFailure.counter_index() as usize;
            if let Some(&failed) = evidence.get(index)
                && failed > 0
            {
                capture.pairs_uncounted = Some(
                    format!(
                        "CALLER_EVIDENCE[{index}] PairInsertFailure showed {failed} failed pair insert(s)"
                    )
                    .into(),
                );
            }
        }
        capture
            .changed_objects
            .extend(batch.changed_objects.iter().copied());
        let custody_held = matches!(
            batch.custody,
            ScopeCustody::System | ScopeCustody::PidHeld | ScopeCustody::CgroupHeld
        );
        // Only a completed, gap-free CALLER_USE sweep has visited every row
        // present when it began, so it proves that sweep's first health
        // read; a bounded read that stopped mid-sweep proves nothing.
        let sweep_began_ns = *capture.sweep_began_ns.get_or_insert(batch.health_read_ns);
        if batch.sweep_completed {
            capture.sweep_began_ns = None;
        }
        if batch.sweep_completed
            && !batch.sweep_gaps
            && batch.health_unproven.is_none()
            && capture.pairs_unproven.is_none()
            && batch.health_regression.is_none()
            && custody_held
            && batch.lifecycle_loss.is_none()
            && capture.unproven.is_none()
            && !self.binder.has_stamped_pending()
        {
            let clean_ns = sweep_began_ns
                .min(batch.custody_proven_ns.unwrap_or(u64::MAX))
                .min(batch.lifecycle_proven_ns);
            capture.last_clean_ns = Some(
                capture
                    .last_clean_ns
                    .map_or(clean_ns, |last| last.max(clean_ns)),
            );
        }
        // The pair evidence demotes before the coincident loss demotion
        // (a PairInsertFailure rise is a watch-counter rise): demotions
        // only touch ongoing watches, so the first reason wins and
        // `uncounted` stands while both gaps stay recorded.
        if uncounted_new && let Some(reason) = capture.pairs_uncounted.clone() {
            self.registry
                .note_pairs_uncounted(reason, batch.health_baseline_ns);
        }
        if let Some(reason) = &batch.health_regression {
            self.registry.note_health_regression(
                reason.clone(),
                batch.health_baseline_ns,
                batch.health_read_ns,
            );
        }
        if let Some(loss) = &batch.lifecycle_loss {
            self.note_lifecycle_loss(loss);
        }
        self.note_capture_custody(&batch.custody);
    }

    /// Consumes one witness batch's count freshness (C7 C4 refresh
    /// loss): the batch's refresh failures, a completed-with-gaps
    /// refresh sweep, and a deadline-starved refresh sweep are count
    /// freshness, never silent: observed counts stand as lower bounds
    /// while every counted column reads lossy, withholding quiet.
    /// Bounded: one reason per batch (the first failure plus the
    /// count), memoized into gap repeats by the registry. Runs before
    /// AND after stop: a terminal-first failure demotes exactly like a
    /// live one (P1-5).
    fn note_count_freshness(&mut self, batch: &WitnessBatch) {
        let refresh_failures: Vec<&String> = batch
            .read_failures
            .iter()
            .filter(|failure| crate::attach::capture::is_refresh_failure(failure))
            .collect();
        // F1: a starved refresh (the window deadline hit before the
        // sweep completed) leaves tracked rows unvisited with no
        // failures or gaps — their counts may be stale, so quiet is
        // withheld exactly like a failed read.
        let starved = batch.refresh_deadline_reached && !batch.refresh_sweep_completed;
        if !refresh_failures.is_empty() || batch.refresh_sweep_gaps || starved {
            let mut reason = match refresh_failures.as_slice() {
                [] if starved && !batch.refresh_sweep_gaps => {
                    "the count-refresh sweep was starved by the window deadline before completing; \
                     tracked rows went unvisited and their counts may be stale"
                        .to_string()
                }
                [] => "a count-refresh sweep skipped a tracked row".to_string(),
                [first] => format!("1 count-refresh read failure: {first}"),
                [first, ..] => format!(
                    "{} count-refresh read failures (first: {first})",
                    refresh_failures.len()
                ),
            };
            if batch.refresh_sweep_gaps && !refresh_failures.is_empty() {
                reason.push_str("; the sweep skipped a tracked row");
            }
            if starved && (!refresh_failures.is_empty() || batch.refresh_sweep_gaps) {
                reason.push_str("; the refresh sweep was also starved by the window deadline");
            }
            self.registry.note_refresh_loss(reason);
        }
    }

    /// System scope: lifecycle evidence was lost (C5.2 D4). A lost exec or
    /// exit record may belong to any watched caller and cannot be
    /// localized, so every watch interval reaching past `at_ns` demotes to
    /// unknown, the loss is a gap, and — sticky — no watch starts again in
    /// this capture. Only the first loss stages anything.
    fn note_lifecycle_loss(&mut self, loss: &LifecycleLoss) {
        let Some(capture) = self.capture.as_mut().filter(|capture| !capture.stopped) else {
            return;
        };
        if capture.unproven.is_some() {
            return;
        }
        capture.unproven = Some(loss.reason.clone());
        if let Some(recorder) = &mut self.diagnostics {
            let mut record = DiagnosticRecord::new(DiagnosticKind::CaptureHealth);
            record.reason = Some(DiagnosticReason::CaptureLoss);
            record.post = Some(loss.at_ns);
            recorder.record(record);
        }
        self.registry.note_watch_demotion(
            "native capture lifecycle evidence lost",
            loss.reason.clone(),
            loss.at_ns,
        );
    }

    /// Native capture stops (stop begins or producers detach): no watch
    /// starts afterwards, and every ongoing watch ends at the last
    /// proven-clean witness read — its interval stays a frozen fact
    /// (`WatchedNoUse{since, until}`). A watch no clean read proved after
    /// its start reads unknown. A terminal read with unproven health is
    /// not clean, so it never extends an interval.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 stops native capture.
    pub(crate) fn end_capture_coverage(&mut self, at_ns: u64) {
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        if capture.stopped {
            return;
        }
        capture.stopped = true;
        if let Some(recorder) = &mut self.diagnostics {
            let mut record = DiagnosticRecord::new(DiagnosticKind::CaptureHealth);
            record.reason = Some(DiagnosticReason::CaptureStopped);
            record.post = Some(at_ns);
            recorder.record(record);
        }
        let until = capture.last_clean_ns.map_or(0, |clean| clean.min(at_ns));
        self.registry.note_watch_end(
            "native capture stopped before a clean health read proved the watch",
            until,
        );
    }

    /// Whether `caller` (at `pid`) is the capture's scope incarnation.
    /// Binds the first matching caller.
    fn capture_scope_verdict(&mut self, caller: CallerId, pid: u32) -> ScopeVerdict {
        let Some(capture) = self.capture.as_mut() else {
            return ScopeVerdict::Outside;
        };
        let scope = match capture.scope {
            CaptureScopeCoverage::System => return ScopeVerdict::Inside,
            CaptureScopeCoverage::Cgroup => return ScopeVerdict::Cgroup,
            CaptureScopeCoverage::Pid(scope) => scope,
        };
        if scope.pid != pid {
            return ScopeVerdict::Outside;
        }
        let start_time = self
            .adapter
            .record(caller)
            .and_then(|record| record.start_time);
        match (scope.start_time, start_time) {
            (Some(expected), Some(actual)) if expected != actual => return ScopeVerdict::Outside,
            (Some(_), Some(_)) => {}
            _ => return ScopeVerdict::Unproven,
        }
        match capture.bound {
            None => {
                capture.bound = Some(caller);
                ScopeVerdict::Inside
            }
            Some(bound) if bound == caller => ScopeVerdict::Inside,
            // Same incarnation, later image: an exec the entries may not
            // follow (custody reports it too).
            Some(_) => ScopeVerdict::LaterImage,
        }
    }

    /// The coverage note one mapped observation earns from the capture's
    /// receipts, or `None` (no native capture, the caller is outside the
    /// capture's scope, the module is not admitted — the registry then
    /// derives the edge's unknown reason itself — or health is unproven
    /// this pass, which withholds a watch without demoting one).
    ///
    /// `Watched` needs every endpoint the attach set admitted for the
    /// module attached, none failed, no member object modified in place, a
    /// whole (not partial) admission, scope custody intact, and the
    /// capture not stopped; `since` is the last of those attaches.
    fn capture_coverage_note(
        &self,
        scope: ScopeVerdict,
        key: &AttachModuleKey,
        verdict: Option<&AttachVerdict>,
    ) -> Option<CoverageNote> {
        let capture = self.capture.as_ref()?;
        let Some(AttachVerdict::Admitted { reasons, .. }) = verdict else {
            return None;
        };
        let unknown = |reason| Some(CoverageNote::Unknown(reason));
        let loss = |reason: &str| unknown(UnknownReason::Loss(reason.into()));
        match scope {
            ScopeVerdict::Outside => return None,
            ScopeVerdict::Unproven => return unknown(UnknownReason::IdentityUnavailable),
            ScopeVerdict::LaterImage => {
                return loss(
                    "a later image of the PID target: its scope custody covers the first image only",
                );
            }
            ScopeVerdict::Inside | ScopeVerdict::Cgroup => {}
        }
        if let Some(reason) = &capture.unproven {
            return loss(reason);
        }
        if capture.stopped {
            // Ended watches are frozen facts: stage nothing over them.
            return None;
        }
        if !reasons.is_empty() {
            return if reasons
                .iter()
                .any(|reason| crate::plan::growth_omitted_count(reason).is_some())
            {
                unknown(UnknownReason::CapacityLimited(ENDPOINT_RESOURCE))
            } else {
                unknown(UnknownReason::NotAttached)
            };
        }
        let members = match self.attach_set.module_members(key) {
            Some(ModuleMembers::Known(members)) => members,
            Some(ModuleMembers::Unrecorded) => {
                return unknown(UnknownReason::CapacityLimited(MEMBERSHIP_RESOURCE));
            }
            // The verdict came from this set, so it holds the module.
            None => return unknown(UnknownReason::NotAttached),
        };
        if members.iter().any(|member| capture.failed.contains(member)) {
            return unknown(UnknownReason::AttachFailed);
        }
        if members.iter().any(|member| {
            self.attach_set
                .endpoint(*member)
                .is_some_and(|endpoint| capture.changed_objects.contains(&endpoint.object))
        }) {
            return loss("the provider was modified in place after it was attached");
        }
        let mut since_ns: Option<u64> = None;
        for member in members {
            let Some(&at_ns) = capture.attached_at.get(member) else {
                // Admitted, not attached yet (deferred to a later extend).
                return unknown(UnknownReason::NotAttached);
            };
            since_ns = Some(since_ns.map_or(at_ns, |since| since.max(at_ns)));
        }
        // C7 C4: pair-insert evidence voids no-use for good — the edge
        // reads `uncounted`, sticky, whatever this pass proves.
        if since_ns.is_some()
            && let Some(reason) = &capture.pairs_uncounted
        {
            return unknown(UnknownReason::Uncounted(reason.clone()));
        }
        match since_ns {
            Some(_) if scope == ScopeVerdict::Cgroup => {
                unknown(UnknownReason::ScopeMembershipUnproven)
            }
            Some(_) if capture.health_unproven.is_some() || capture.pairs_unproven.is_some() => {
                None
            }
            Some(since_ns) => Some(CoverageNote::Watched { since_ns }),
            // Admitted with no endpoint: nothing could observe its use.
            None => unknown(UnknownReason::NotAttached),
        }
    }

    /// Stages the capture coverage note for one mapped edge, right after
    /// its mapping note (so the edge exists when the batch applies it).
    fn stage_capture_coverage(
        &mut self,
        caller: CallerId,
        pid: u32,
        key: &ModuleKey,
        attach_key: Option<&AttachModuleKey>,
        verdict: Option<&AttachVerdict>,
    ) {
        let Some(attach_key) = attach_key else {
            return;
        };
        if self.capture.is_none() {
            return;
        }
        let scope = self.capture_scope_verdict(caller, pid);
        if let Some(loss) = self.preadmission_holds(caller, pid, key) {
            self.downgrade(caller, Some(key.clone()), loss);
            return;
        }
        if let Some(note) = self.capture_coverage_note(scope, attach_key, verdict) {
            self.registry.note_coverage(caller, key, note);
        }
    }

    /// The edge's coverage as presented: the staged coverage, except a
    /// watched edge reads unknown while the binder holds a pending row of
    /// its caller's pid on its module (DR-LIVE-LABEL-LAG). The row is a
    /// first use that may belong to this caller, so the watch cannot
    /// claim quiet; the staged watch is untouched and resumes once the
    /// row binds elsewhere. Positives, staged unknowns, and edges no
    /// pending row matches read as staged. Every consumer (JSON, the
    /// event stream, dashboard frames) presents through this.
    pub(crate) fn presented_coverage(&self, edge: &EdgeRecord) -> UseCoverage {
        let staged = self.registry.coverage(edge);
        if !matches!(staged, UseCoverage::WatchedNoUse { .. }) {
            return staged;
        }
        let pid = self.adapter.record(edge.caller).map(|record| record.pid);
        let key = self.registry.module(edge.module).map(|record| &record.key);
        let (Some(pid), Some(key)) = (pid, key) else {
            return staged;
        };
        let pending = self.binder.pending_rows().any(|row| {
            row.host_tgid == pid
                && self
                    .witness_modules(row)
                    .is_ok_and(|modules| modules.contains(key))
        });
        if pending {
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        } else {
            staged
        }
    }

    #[cfg(test)]
    pub(crate) fn owner_of(&self, caller: CallerId) -> Option<ProcessViewId> {
        self.owners.get(&caller).copied()
    }

    /// Owned-fixture growth path: open one native owner through the real
    /// engine call, admit its caller, and bind the two — the same three
    /// steps `scan_pass` performs per pid, without a scope collection.
    /// Scale tests drive this over owned sleepers; admission failure
    /// after a successful open keeps the owner retained (no removal API
    /// exists) and says so in the error.
    #[cfg(test)]
    pub(crate) fn test_open_native_owner(
        &mut self,
        pid: u32,
        image: p11scope_ebpf_common::ImageIdentity,
        guard: &mut dyn super::inventory::ImageGuard,
        now_ns: u64,
    ) -> Result<CallerId> {
        let owner = self.engine.open_inventory_owner(pid, image, guard)?;
        let authority = ImageAuthority::NativeExact {
            task_cookie: image.task_cookie,
            exec_id: image.exec_id,
        };
        match self.adapter.admit(pid, authority, now_ns) {
            Ok(caller) => {
                self.owners.insert(caller, owner);
                Ok(caller)
            }
            Err(error) => Err(anyhow::anyhow!(
                "{error:#} (the native owner opened and stays retained)"
            )),
        }
    }

    pub(crate) fn passes(&self) -> u64 {
        self.passes
    }

    /// Refuse one scan pass after `stop` (H6 slice 2): no pass number is
    /// consumed and nothing is scanned, reconciled, or projected.
    fn stopped_pass_report(&mut self, what: &str) -> PassReport {
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "scan refused after stop".into(),
            reason: format!(
                "the coordinator stopped; {what} starts no new scan, attach, \
                 successor admission, or retry"
            ),
            budget: None,
        });
        PassReport {
            pass: self.passes,
            scanned: 0,
            maps_matched: 0,
            native_callers: 0,
            scan_callers: 0,
            engine_changed: false,
            pending_refresh: Vec::new(),
            events: Vec::new(),
            timings: crate::timing::StageTimings::new(),
        }
    }

    /// One scan pass: collect the scope, reconcile caller incarnations
    /// (attempting a native owner per newly admitted pid), scan every
    /// native owner through the core, and project scan-lane mappings.
    /// Every staged fact publishes at the next `commit_batch`, never
    /// before. `identity` supplies the owner lane's exact image per pid, or
    /// none (the scan lane: `ScanOnlyIdentity`). Hints and hooks are the
    /// engine's, fixed for the run. Production collects through
    /// `collector` (C5.7) and applies with `apply_catalog`.
    #[cfg(test)]
    pub(crate) fn scan_pass(
        &mut self,
        scope: &InventoryScope,
        max_scan_pids: Option<usize>,
        guard: &mut dyn ImageGuard,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<PassReport> {
        let catalog = self.collector(*scope, max_scan_pids)()?;
        Ok(self.apply_catalog(catalog, guard, identity, deadline_ns, now_ns))
    }

    /// The pass's collection as an owned job (Task 6 C5.7): it reads
    /// `/proc` only, over its own copies of the run's fixed hints and hooks,
    /// and hands back its catalog. It borrows nothing of the coordinator, so
    /// it can run on a worker thread while the caller keeps servicing the
    /// native capture; every registry and binder mutation stays with
    /// `apply_catalog` on the caller's thread.
    pub(crate) fn collector(
        &self,
        scope: InventoryScope,
        max_scan_pids: Option<usize>,
    ) -> impl FnOnce() -> Result<crate::inspect_system::Catalog> + Send + 'static {
        // The catalog lowers its admission under the Inventory policy and
        // budget the attach set enforces, never the Detailed slot ceiling
        // `inspect` reports.
        let cgroup_requires_transaction = matches!(self.engine.scope, Scope::Cgroup { .. });
        let policy = crate::plan::AdmissionPolicy::Inventory(self.attach_set.budget());
        let hints = self.engine.module_hints.clone();
        let hooks = self.engine.hooks.clone();
        move || {
            if cgroup_requires_transaction {
                bail!("cgroup inventory requires the bounded scoped collection job");
            }
            match scope {
                InventoryScope::Pid(pid) => {
                    crate::inspect_system::collect_pid(pid, &hints, &hooks, policy)
                }
                InventoryScope::System => {
                    crate::inspect_system::collect(&hints, &hooks, max_scan_pids, policy)
                }
            }
        }
    }

    /// The D3d System pass with capture-owned identity state: the job
    /// shares the `Send` disclosure state plus the one capture-owned
    /// session, taken for this pass and returned afterwards. PID scope
    /// ignores the handle and stays userspace without identity output.
    pub(crate) fn collector_with_identity(
        &self,
        scope: InventoryScope,
        max_scan_pids: Option<usize>,
        shared: crate::inspect_system::IdentityShared,
    ) -> impl FnOnce() -> Result<crate::inspect_system::Catalog> + Send + 'static {
        let cgroup_requires_transaction = matches!(self.engine.scope, Scope::Cgroup { .. });
        let policy = crate::plan::AdmissionPolicy::Inventory(self.attach_set.budget());
        let hints = self.engine.module_hints.clone();
        let hooks = self.engine.hooks.clone();
        move || {
            if cgroup_requires_transaction {
                bail!("cgroup inventory requires the bounded scoped collection job");
            }
            match scope {
                InventoryScope::Pid(pid) => {
                    crate::inspect_system::collect_pid(pid, &hints, &hooks, policy)
                }
                InventoryScope::System => crate::inspect_system::collect_system_with_identity(
                    &hints,
                    &hooks,
                    max_scan_pids,
                    policy,
                    shared,
                ),
            }
        }
    }

    /// Prepare one bounded cgroup job over exactly the root retained by the
    /// engine. A legacy System/PID job can never stand in for this request.
    #[cfg_attr(not(test), allow(dead_code))] // Cg4 supplies the runtime owner.
    pub(crate) fn cgroup_collector(
        &self,
        state: CgroupWalkState,
        limits: CgroupWalkLimits,
        control: CollectionControl,
        max_scan_pids: Option<usize>,
    ) -> Result<impl FnOnce() -> CgroupCollection + Send + 'static> {
        let Scope::Cgroup { dir, .. } = &self.engine.scope else {
            bail!("scoped cgroup collection requires a retained cgroup root");
        };
        let crate::discovery::scan::DiscoveryPolicy::Inventory(work) = self.engine.budget.policy()
        else {
            bail!("cgroup inventory collection requires the immutable Inventory work policy");
        };
        let request = CgroupCollectRequest {
            root: Arc::clone(dir),
            fence: self.cgroup_fence.issue(),
            state,
            limits,
            control,
            max_scan_pids,
            scan_budget: crate::discovery::scan::CaptureWorkBudget::for_inventory(work),
        };
        let hints = self.engine.module_hints.clone();
        let hooks = self.engine.hooks.clone();
        let policy = crate::plan::AdmissionPolicy::Inventory(self.attach_set.budget());
        Ok(move || {
            crate::inspect_system::inventory_cgroup::collect(request, &hints, &hooks, policy)
        })
    }

    /// Store custody until commit, reconcile old lifecycle only, and withhold
    /// all new facts. The final grouped sample runs inside commit_batch.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn apply_cgroup_collection(
        &mut self,
        collection: CgroupCollection,
        now_ns: u64,
    ) -> Result<PassReport> {
        if self.stopped {
            bail!(
                "the coordinator stopped; the collection starts no new scan, attach, \
                 successor admission, or retry"
            );
        }
        let Scope::Cgroup { dir, .. } = &self.engine.scope else {
            bail!("scoped cgroup collection cannot apply to a PID/System coordinator");
        };
        if !collection.issued_by(&self.cgroup_fence) {
            bail!("cgroup collection was not issued by this coordinator");
        }
        if !Arc::ptr_eq(dir, collection.root()) {
            bail!("cgroup collection retained a different root from the coordinator");
        }
        if self.pending_cgroup.is_some() || self.completed_cgroup.is_some() {
            bail!(
                "previous cgroup transaction must be committed and its continuation consumed first"
            );
        }
        let work = collection.work();
        let events = self
            .adapter
            .reconcile_scoped(now_ns, &mut || work.charge(5));
        self.apply_reconcile_events(&events, now_ns);
        // Any history absent from this bounded pass stays live and uncertain;
        // a partial census is never an exit or physical-unmap proof. The
        // marker is provisional, not an early placeholder: the commit tail
        // proves continued authority or stages the genuine uncertainty,
        // never before the catalog is known. The loop charges nothing:
        // records are admission-bounded (one marker per live caller), and
        // failed walks exhaust the collection work that a charge would
        // draw on — those passes need their markers most.
        for record in self.adapter.records() {
            if !record.retired {
                self.pending_adjudication.insert(record.id, record.pid);
            }
        }
        let scanned = collection.member_pids().count();
        self.pending_cgroup = Some((collection, now_ns));
        let pass = self.passes;
        self.passes += 1;
        Ok(PassReport {
            pass,
            scanned,
            maps_matched: 0,
            native_callers: 0,
            scan_callers: 0,
            engine_changed: false,
            pending_refresh: Vec::new(),
            events,
            timings: crate::timing::StageTimings::new(),
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn take_cgroup_completion(&mut self) -> Option<CgroupCompletion> {
        self.completed_cgroup.take()
    }

    /// The pass after collection: absorb the lowering into the attach set,
    /// reconcile caller incarnations over every attributable member
    /// (deep-scanned or maps-matched), scan native owners, and project the
    /// catalog. Split from collection so scripted catalogs drive the same
    /// path (the workload harness).
    pub(crate) fn apply_catalog(
        &mut self,
        mut catalog: crate::inspect_system::Catalog,
        guard: &mut dyn ImageGuard,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        deadline_ns: u64,
        now_ns: u64,
    ) -> PassReport {
        if self.stopped {
            return self.stopped_pass_report("a catalog pass");
        }
        if matches!(self.engine.scope, Scope::Cgroup { .. }) {
            return self.observe_empty_pass(
                guard,
                identity,
                "catalog without retained cgroup transaction authority was withheld",
                now_ns,
            );
        }
        let mut timings = std::mem::take(&mut catalog.stage_timings);
        // Absorb at once: the aggregate pins and their fds drop here, never
        // living across reconcile or the native owner scans below.
        let absorb_start = crate::attach::monotonic_ns();
        let verdicts = self.absorb_lowering(catalog.lowering.take());
        // Mapper counts size uprobe-multi links (C5.11 review M1), from a
        // whole-system view only (review R4).
        self.attach_set.note_mappers(
            self.engine.sees_whole_system(),
            catalog
                .objects
                .iter()
                .map(|object| (&object.key, object.mappings.len())),
        );
        timings.span(
            crate::timing::StageKind::Plan,
            "absorb",
            absorb_start,
            crate::attach::monotonic_ns(),
        );
        // Maps-matched members register exactly like deep-scanned ones:
        // same authority resolution (native owners included), same
        // incarnation pin. Their projection joins the generation below.
        let observed: BTreeSet<u32> = catalog
            .processes
            .iter()
            .filter(|process| process.status.attributable())
            .map(|process| process.pid)
            .collect();
        let scanned = observed.len();
        let maps_matched = catalog
            .processes
            .iter()
            .filter(|process| process.status == crate::inspect_system::MemberStatus::MapsMatched)
            .count();
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard,
            identity,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let reconcile_start = crate::attach::monotonic_ns();
        let mut events =
            self.adapter
                .reconcile(&observed, &mut |pid| resolver.resolve(pid), now_ns);
        let (native_failures, scan_pinned) = resolver.finish();
        self.apply_reconcile_events(&events, now_ns);
        self.record_authority_gaps(native_failures, scan_pinned);
        events.extend(self.revalidate_for_exec_coverage(identity, now_ns));
        timings.span(
            crate::timing::StageKind::Projection,
            "reconcile",
            reconcile_start,
            crate::attach::monotonic_ns(),
        );
        // Native scans for live native callers, through the core.
        let mut pending_refresh = Vec::new();
        let mut engine_changed = false;
        let native: Vec<(CallerId, ProcessViewId)> = self
            .owners
            .iter()
            .filter(|(caller, _)| {
                self.adapter
                    .record(**caller)
                    .is_some_and(|record| !record.retired)
            })
            .map(|(caller, owner)| (*caller, *owner))
            .collect();
        for (caller, owner) in &native {
            match self.scan_owner(*owner, guard, deadline_ns, now_ns) {
                Ok(commit) => {
                    engine_changed |= commit.changed;
                    if commit.refresh_pending {
                        pending_refresh.push(*caller);
                    }
                    self.project_native_commit(*caller, *owner, &commit, &verdicts, now_ns);
                }
                Err(error) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "native inventory scan failed".into(),
                        reason: format!("{error:#}"),
                        budget: None,
                    });
                }
            }
        }
        // Scan-lane projection for every inventoried member, including
        // native callers (the catalog carries admission verdicts the
        // registry needs either way).
        let project_start = crate::attach::monotonic_ns();
        self.project_catalog(&catalog, &verdicts, now_ns);
        timings.span(
            crate::timing::StageKind::Projection,
            "project",
            project_start,
            crate::attach::monotonic_ns(),
        );
        // Owners that never committed a complete receipt cannot back
        // absence claims: absences for their callers stay uncertain, and
        // the gap says so.
        for (caller, owner) in &native {
            match self.engine.inventory_last_complete(*owner) {
                Ok(Some(_)) => {}
                Ok(None) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "no complete inventory scan".into(),
                        reason: "only partial receipts committed for this owner; absences for its caller are uncertain"
                            .into(),
                        budget: None,
                    });
                }
                Err(error) => {
                    self.registry.record_gap(RegistryGap {
                        caller: Some(*caller),
                        module: None,
                        pid: self.adapter.record(*caller).map(|record| record.pid),
                        subject: "native owner lost".into(),
                        reason: format!("{error:#}"),
                        budget: None,
                    });
                }
            }
        }
        self.reconcile_count_eligibility(identity, &mut RecoveryWorkBudget::new());
        let native_callers = native.len();
        let pass = self.passes;
        self.passes += 1;
        PassReport {
            pass,
            scanned,
            maps_matched,
            native_callers,
            scan_callers: observed.len().saturating_sub(native_callers),
            engine_changed,
            pending_refresh,
            events,
            timings,
        }
    }

    /// One pass with no scan behind it: the collection failed after at
    /// least one successful pass (a `--pid` target that exited
    /// mid-observation, a transient enumeration loss). Lifecycle still
    /// reconciles — pins and exit proofs need no scan — while live
    /// callers become unscanned-uncertain and the failure is a gap.
    /// Never a silent skip, and never a reason to drop the run.
    pub(crate) fn observe_empty_pass(
        &mut self,
        guard: &mut dyn ImageGuard,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        reason: &str,
        now_ns: u64,
    ) -> PassReport {
        if self.stopped {
            return self.stopped_pass_report("an empty pass");
        }
        self.count_ownership.begin_catalog_pass();
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard,
            identity,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let mut events = if matches!(resolver.engine.scope, Scope::Cgroup { .. }) {
            self.adapter.reconcile_scoped(now_ns, &mut || true)
        } else {
            self.adapter
                .reconcile(&BTreeSet::new(), &mut |pid| resolver.resolve(pid), now_ns)
        };
        let (native_failures, scan_pinned) = resolver.finish();
        self.apply_reconcile_events(&events, now_ns);
        self.record_authority_gaps(native_failures, scan_pinned);
        events.extend(self.revalidate_for_exec_coverage(identity, now_ns));
        let live: Vec<CallerId> = self
            .adapter
            .records()
            .filter(|record| !record.retired)
            .map(|record| record.id)
            .collect();
        for caller in &live {
            self.registry.note_member_unscanned(*caller);
            self.tail_uncertain.insert(*caller);
        }
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "scan pass produced no observation".into(),
            reason: reason.to_string(),
            budget: None,
        });
        self.reconcile_count_eligibility(identity, &mut RecoveryWorkBudget::new());
        let native_callers = live
            .iter()
            .filter(|caller| self.owners.contains_key(caller))
            .count();
        let pass = self.passes;
        self.passes += 1;
        PassReport {
            pass,
            scanned: 0,
            maps_matched: 0,
            native_callers,
            scan_callers: live.len().saturating_sub(native_callers),
            engine_changed: false,
            pending_refresh: Vec::new(),
            events,
            timings: crate::timing::StageTimings::new(),
        }
    }

    /// Stage retirements for reconciled events, bind freshly opened
    /// native owners to their callers, and gap admission failures. The
    /// workload harness reuses this after scripted reconciles so staged
    /// facts follow the same path as scanned ones.
    pub(crate) fn apply_reconcile_events(&mut self, events: &[CallerEvent], now_ns: u64) {
        let mut failed: Vec<(u32, &str, Option<BudgetRefusal>)> = Vec::new();
        for event in events {
            let id = match event {
                CallerEvent::Admitted { id }
                | CallerEvent::ExecRetired { new: id, .. }
                | CallerEvent::Reused { new: id, .. } => *id,
                CallerEvent::Exited { id, .. } | CallerEvent::Retired { id, .. } => {
                    self.retire_caller_in_registry(*id, now_ns);
                    continue;
                }
                CallerEvent::AdmitFailed {
                    pid,
                    reason,
                    budget,
                } => {
                    if self.pending_owners.remove(pid).is_some() {
                        // The native owner opened but the caller pin
                        // failed (an exit raced admission): no removal
                        // API exists, so the owner stays retained under
                        // the owner cap and the gap says so.
                        self.registry.record_gap(RegistryGap {
                            caller: None,
                            module: None,
                            pid: Some(*pid),
                            subject: "native owner without caller".into(),
                            reason: format!(
                                "the native owner opened but caller admission failed ({reason}); the owner stays retained"
                            ),
                            budget: None,
                        });
                    }
                    failed.push((*pid, reason.as_str(), *budget));
                    continue;
                }
            };
            if let CallerEvent::ExecRetired { old, .. } | CallerEvent::Reused { old, .. } = event {
                self.retire_caller_in_registry(*old, now_ns);
            }
            let pid = self.adapter.record(id).map(|record| record.pid);
            if let Some(pid) = pid
                && let Some(owner) = self.pending_owners.remove(&pid)
            {
                self.owners.insert(id, owner);
            }
        }
        self.record_admission_failures(&failed);
    }

    /// Admission failures, one gap per pass and kind rather than one per
    /// pid per pass (C1b ruling 4): at system scale a full caller budget
    /// refuses every new caller every pass. A single failure keeps its
    /// exact per-pid record; several aggregate with a count — budget
    /// refusals carry the budget (the highest occupancy requested), pin
    /// failures name the first.
    fn record_admission_failures(&mut self, failed: &[(u32, &str, Option<BudgetRefusal>)]) {
        let (refused, unpinned): (Vec<_>, Vec<_>) =
            failed.iter().partition(|(_, _, budget)| budget.is_some());
        for group in [refused, unpinned] {
            match group.as_slice() {
                [] => {}
                [(pid, reason, budget)] => self.registry.record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: Some(*pid),
                    subject: "caller admission failed".into(),
                    reason: (*reason).to_string(),
                    budget: *budget,
                }),
                [(first_pid, first_reason, _), ..] => {
                    let budget = group
                        .iter()
                        .filter_map(|(_, _, budget)| *budget)
                        .max_by_key(|budget| budget.requested);
                    let reason = match budget {
                        Some(budget) => format!(
                            "{} admissions refused this pass: caller budget exhausted: the \
                             registry retains at most {} callers; the admissions were refused",
                            group.len(),
                            budget.limit
                        ),
                        None => format!(
                            "{} pids could not be admitted this pass; first: pid {first_pid}: \
                             {first_reason}",
                            group.len()
                        ),
                    };
                    self.registry.record_gap(RegistryGap {
                        caller: None,
                        module: None,
                        pid: None,
                        subject: "caller admission failed".into(),
                        reason,
                        budget,
                    });
                }
            }
        }
    }

    fn retire_caller_in_registry(&mut self, id: CallerId, now_ns: u64) {
        // Each retirement stages once: held handoffs report the old
        // incarnation at mint and again at commit, and the second report
        // is a no-op here (owner binding rides the normal event path).
        if !self.staged_retirements.insert(id) {
            return;
        }
        self.count_ownership.forget_live(id);
        let reason = self
            .adapter
            .record(id)
            .and_then(|record| record.lifecycle_reason.clone())
            .unwrap_or_else(|| "caller retired".into());
        self.registry.retire_caller(id, reason, now_ns);
    }

    /// Authority gaps: per-caller where a native open was attempted and
    /// failed (a real signal), once per run where no native identity
    /// exists at all (the scan lane).
    fn record_authority_gaps(&mut self, native_failures: Vec<(u32, String)>, scan_pinned: usize) {
        for (pid, reason) in native_failures {
            self.registry.record_gap(RegistryGap {
                caller: self.adapter.live_id(pid),
                module: None,
                pid: Some(pid),
                subject: "native inventory owner unavailable".into(),
                reason: format!("{reason}; scan-lane incarnation by pidfd/start-time"),
                budget: None,
            });
        }
        if scan_pinned > 0 && !self.authority_gap_recorded {
            self.authority_gap_recorded = true;
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "exact image authority unavailable".into(),
                reason: "no BPF image identity; scan-lane incarnations by pidfd/start-time with exe-identity exec detection"
                    .into(),
                budget: None,
            });
        }
    }

    /// One native owner through the core: refresh request, lease, I4a
    /// window, scan, prepare, commit (which revalidates at the
    /// publication boundary). The lease releases on every path.
    fn scan_owner(
        &mut self,
        owner: ProcessViewId,
        guard: &mut dyn ImageGuard,
        deadline_ns: u64,
        now_ns: u64,
    ) -> Result<InventoryCommit> {
        let cause = if !self.scanned_owners.contains(&owner) {
            // Admission scan: scope membership was verified at open;
            // re-verify it at the first scan boundary.
            RefreshCause::ScopeRecheck
        } else if self.churned_owners.remove(&owner) {
            // The previous pass observed mapping churn for this owner:
            // a post-hoc loader hint, honestly labeled.
            RefreshCause::LoaderHint
        } else {
            RefreshCause::Periodic
        };
        self.engine.request_inventory_refresh(owner, cause)?;
        if deadline_ns <= now_ns {
            // The pass ran out of time before this owner: defer through
            // the receipt vocabulary, so preparation refuses with the
            // canonical reason and the refresh request stays pending.
            let receipt = ScanReceipt::Deferred {
                owner,
                reason: DEADLINE_DEFERRED,
            };
            let prepared = self
                .engine
                .prepare_inventory_reconciliation(receipt, guard)?;
            return self.engine.commit_inventory_reconciliation(prepared, guard);
        }
        let lease = self.engine.acquire_inventory_scan(owner)?;
        let result = (|| {
            let id = self.next_window;
            self.next_window = self.next_window.saturating_add(1);
            let window = self
                .engine
                .budget
                .begin_window(WindowId::new(id), deadline_ns)
                .map_err(anyhow::Error::msg)?;
            let checkpoint = self
                .engine
                .budget
                .checkpoint(window.clone())
                .map_err(anyhow::Error::msg)?;
            let receipt = self.engine.scan_inventory_owner(&lease, guard)?;
            self.engine
                .budget
                .finish_scan(checkpoint)
                .map_err(anyhow::Error::msg)?;
            self.engine
                .budget
                .finish_window(window)
                .map_err(anyhow::Error::msg)?;
            let prepared = self
                .engine
                .prepare_inventory_reconciliation(receipt, guard)?;
            // I3: commit revalidates after the synchronous gap above;
            // preparation alone grants nothing.
            self.engine.commit_inventory_reconciliation(prepared, guard)
        })();
        let release = self.engine.release_inventory_scan(&lease);
        match (result, release) {
            (Ok(commit), Ok(())) => {
                self.scanned_owners.insert(owner);
                Ok(commit)
            }
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    /// Project one native commit into the registry: committed modules of
    /// this owner become mapping evidence; previously mapped edges the
    /// commit no longer shows become absences (authoritative only when
    /// the receipt was complete).
    fn project_native_commit(
        &mut self,
        caller: CallerId,
        owner: ProcessViewId,
        commit: &InventoryCommit,
        verdicts: &BTreeMap<AttachModuleKey, AttachVerdict>,
        now_ns: u64,
    ) {
        let pid = self
            .adapter
            .record(caller)
            .map(|record| record.pid)
            .unwrap_or(0);
        let modules: Vec<(ModuleKey, ModuleInfo, AttachModuleKey)> = self
            .engine
            .modules
            .iter()
            .filter(|module| module.scanned.view == owner)
            .filter_map(|module| {
                let summary = self.engine.pinned.summary(module.object)?;
                let sha256 = summary.sha256.to_string();
                let attach_key = AttachModuleKey {
                    object: module.scanned.key,
                    sha256: sha256.clone(),
                };
                let verdict = verdicts.get(&attach_key);
                let key = ModuleKey::physical(
                    module.scanned.key.device.major,
                    module.scanned.key.device.minor,
                    module.scanned.key.inode,
                    Some(sha256),
                    &module.scanned.path,
                );
                Some((
                    key.clone(),
                    native_module_info(&self.engine, module, key, verdict),
                    attach_key,
                ))
            })
            .collect();
        for (key, info, attach_key) in &modules {
            self.registry
                .note_mapping(caller, pid, info.clone(), now_ns);
            let verdict = verdicts.get(attach_key);
            self.stage_capture_coverage(caller, pid, key, Some(attach_key), verdict);
        }
        // Absences are evaluated against the last published snapshot:
        // edges the commit no longer shows, for this caller only.
        let committed: BTreeSet<ModuleKey> =
            modules.iter().map(|(key, _, _)| key.clone()).collect();
        let mut absent = false;
        for edge in self
            .registry
            .edges_of(caller)
            .filter(|edge| matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain))
            .map(|edge| (edge.module, edge.mapping))
            .collect::<Vec<_>>()
        {
            let shown = self
                .registry
                .module(edge.0)
                .is_some_and(|module| committed.contains(&module.key));
            if !shown {
                self.registry
                    .note_module_absent(caller, edge.0, commit.complete, now_ns);
                if !commit.complete {
                    self.tail_uncertain.insert(caller);
                }
                absent = commit.complete && edge.1 == MappingState::Mapped;
            }
        }
        if absent {
            // Mapping churn observed: the next pass scans this owner
            // under a loader hint.
            self.churned_owners.insert(owner);
        }
    }

    /// The attach set absorbs one pass's Inventory lowering: its delta
    /// joins the pending targets, its gaps stage in the registry, and its
    /// verdicts return for the catalog projection. The lowering — the
    /// aggregate pins and their fds included — drops on return; the set
    /// keeps only the objects it retained.
    fn absorb_lowering(
        &mut self,
        lowering: Option<crate::inspect_system::CatalogLowering>,
    ) -> BTreeMap<AttachModuleKey, AttachVerdict> {
        let Some(lowering) = lowering else {
            return BTreeMap::new();
        };
        let absorbed = self.attach_set.absorb(&lowering.plan, &lowering.pins);
        drop(lowering);
        self.record_absorbed(absorbed)
    }

    fn record_absorbed(
        &mut self,
        absorbed: AbsorbOutcome,
    ) -> BTreeMap<AttachModuleKey, AttachVerdict> {
        self.pending_targets.append(absorbed.delta);
        for gap in absorbed.gaps {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: gap.subject,
                reason: gap.reason,
                budget: gap
                    .budget
                    .map(|(resource, limit, requested)| BudgetRefusal {
                        resource,
                        limit,
                        requested,
                    }),
            });
        }
        absorbed.verdicts
    }

    /// Project one catalog pass into the registry, per member: its
    /// mappings (deep-scanned or maps-matched) carrying the attach set's
    /// admission verdicts, its absences (authoritative only for a complete
    /// deep scan — never for a maps match), unscanned-member uncertainty,
    /// and the catalog gaps. A member projects only when the generation it
    /// was collected under joins the caller incarnation reconcile holds
    /// for its pid (start time, both present; and the exe identity), so a
    /// reused pid or a later exec never inherits mappings. Each caller's
    /// edges come from a per-caller range query, never a scan of all edges.
    fn project_catalog(
        &mut self,
        catalog: &crate::inspect_system::Catalog,
        verdicts: &BTreeMap<AttachModuleKey, AttachVerdict>,
        now_ns: u64,
    ) {
        use crate::inspect_system::{MemberStatus, ObservationEvidence};
        self.count_ownership.begin_catalog_pass();
        self.count_ownership
            .invalidate_memberships(self.attach_set.count_revision());
        let mut by_pid: BTreeMap<u32, Vec<(usize, usize)>> = BTreeMap::new();
        for (object_index, object) in catalog.objects.iter().enumerate() {
            for (observation_index, observation) in object.observations.iter().enumerate() {
                by_pid
                    .entry(observation.pid)
                    .or_default()
                    .push((object_index, observation_index));
            }
        }
        let mut join_losses: BTreeMap<AttributionLoss, usize> = BTreeMap::new();
        for process in &catalog.processes {
            let Some(caller) = self.adapter.live_id(process.pid) else {
                continue;
            };
            if !process.status.attributable() {
                self.registry.note_member_unscanned(caller);
                self.tail_uncertain.insert(caller);
                self.count_ownership
                    .queue_observation(caller, Vec::new(), None);
                continue;
            }
            if let Err(loss) = self.generation_join(caller, process) {
                *join_losses.entry(loss).or_default() += 1;
                // The collected mappings belong to another generation or
                // image: they neither confirm nor refute this caller's.
                self.registry.note_member_unscanned(caller);
                self.tail_uncertain.insert(caller);
                self.count_ownership
                    .queue_observation(caller, Vec::new(), None);
                continue;
            }
            let mut retirement_admission_known = true;
            let mut deep_scanned = false;
            // One mapping note per observation (not per object path):
            // aliased objects are observed under several paths and the
            // registry accumulates every spelling.
            for &(object_index, observation_index) in by_pid.get(&process.pid).into_iter().flatten()
            {
                let object = &catalog.objects[object_index];
                let observation = &object.observations[observation_index];
                let attach_key = object.sha256.as_ref().map(|sha256| AttachModuleKey {
                    object: object.key,
                    sha256: sha256.clone(),
                });
                let verdict = attach_key.as_ref().and_then(|key| verdicts.get(key));
                retirement_admission_known &= !observation.double_loaded
                    && matches!(verdict, Some(AttachVerdict::Admitted { reasons, .. }) if reasons.is_empty());
                let mut info = catalog_module_info(object, verdict);
                info.path = observation.path.clone();
                info.double_loaded = observation.double_loaded;
                let key = info.key.clone();
                match observation.evidence {
                    ObservationEvidence::DeepScan => {
                        self.registry
                            .note_mapping(caller, process.pid, info, now_ns);
                        deep_scanned = true;
                    }
                    ObservationEvidence::MapsMatch => {
                        self.registry
                            .note_maps_match(caller, process.pid, info, now_ns);
                    }
                }
                self.stage_capture_coverage(
                    caller,
                    process.pid,
                    &key,
                    attach_key.as_ref(),
                    verdict,
                );
            }
            // Only a complete deep scan makes absence authoritative: a
            // maps match decoded nothing, so its absences read uncertain.
            let complete = matches!(process.status, MemberStatus::Scanned);
            if complete && deep_scanned {
                // Complete same-custody caller/provider/full-image proof:
                // the generation join held above, the member image
                // scanned completely, and provider mappings re-observed.
                self.complete_scanned.insert(caller);
            }
            let shown: BTreeSet<ModuleKey> = process
                .objects
                .iter()
                .filter_map(|index| catalog.objects.get(*index))
                .map(catalog_module_key)
                .collect();
            let mut absent = false;
            for (module, mapping) in self
                .registry
                .edges_of(caller)
                .filter(|edge| {
                    matches!(edge.mapping, MappingState::Mapped | MappingState::Uncertain)
                })
                .map(|edge| (edge.module, edge.mapping))
                .collect::<Vec<_>>()
            {
                let shown = self
                    .registry
                    .module(module)
                    .is_some_and(|record| shown.contains(&record.key));
                if !shown {
                    self.registry
                        .note_module_absent(caller, module, complete, now_ns);
                    if !complete {
                        self.tail_uncertain.insert(caller);
                    }
                    absent = complete && mapping == MappingState::Mapped;
                }
            }
            let complete_scan = process
                .complete_scan
                .as_ref()
                .filter(|receipt| {
                    retirement_admission_known
                        && matches!(process.status, MemberStatus::Scanned)
                        && process.generation.as_ref() == Some(receipt.generation())
                        && self.adapter.record(caller).is_some_and(|record| {
                            !record.retired
                                && record.start_time.is_some()
                                && record.start_time == receipt.generation().start_time
                                && record.exe.is_some()
                                && record.exe == receipt.generation().exe
                                && record.first_seen_ns <= receipt.started_ns()
                        })
                        && receipt.started_ns() > 0
                        && receipt.finished_ns() > receipt.started_ns()
                })
                .cloned();
            if !self.count_ownership.queue_observation(
                caller,
                shown.into_iter().collect(),
                complete_scan,
            ) {
                self.registry.record_gap(RegistryGap { caller: Some(caller), module: None, pid: Some(process.pid), subject: "current count ownership storage refused".into(), reason: "the bounded ownership observation could not be retained; historical evidence remains, current count eligibility is unknown".into(), budget: Some(BudgetRefusal { resource: "inventory_count_observations", limit: self.registry.limits().max_edges, requested: self.registry.limits().max_edges.saturating_add(1) }) });
            }
            if absent && let Some(owner) = self.owners.get(&caller).copied() {
                self.churned_owners.insert(owner);
            }
        }
        if !join_losses.is_empty() {
            let parts: Vec<String> = join_losses
                .iter()
                .map(|(loss, count)| format!("{count} {}", loss.label()))
                .collect();
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "caller generation join refused".into(),
                reason: format!(
                    "members whose collected generation is not the admitted caller incarnation \
                     were not projected (their edges read uncertain): {}",
                    parts.join(", ")
                ),
                budget: None,
            });
        }
        for gap in catalog.skipped.iter().chain(catalog.notes.iter()) {
            self.registry.record_gap(RegistryGap {
                caller: gap.pid.and_then(|pid| self.adapter.live_id(pid)),
                module: None,
                pid: gap.pid,
                subject: gap.subject.clone(),
                reason: gap.reason.clone(),
                budget: None,
            });
        }
    }

    /// Whether a member's collected generation is the caller incarnation
    /// reconcile holds: equal start times, both present (both lanes); for a
    /// maps match also equal exe identities, both present; for a deep scan
    /// unequal exe identities refuse when both were read.
    fn generation_join(
        &self,
        caller: CallerId,
        process: &crate::inspect_system::ProcessRecord,
    ) -> Result<(), AttributionLoss> {
        let record = self
            .adapter
            .record(caller)
            .ok_or(AttributionLoss::GenerationChanged)?;
        let generation = process
            .generation
            .as_ref()
            .ok_or(AttributionLoss::GenerationChanged)?;
        match (generation.start_time, record.start_time) {
            (Some(collected), Some(admitted)) if collected == admitted => {}
            _ => return Err(AttributionLoss::GenerationChanged),
        }
        let matched = process.status == crate::inspect_system::MemberStatus::MapsMatched;
        match (&generation.exe, &record.exe) {
            (Some(collected), Some(admitted)) if collected != admitted => {
                Err(AttributionLoss::ExecChanged)
            }
            (Some(_), Some(_)) => Ok(()),
            _ if matched => Err(AttributionLoss::ConfirmUnreadable),
            _ => Ok(()),
        }
    }

    /// The one native staging call (plan §3.6): witness reads, lifecycle
    /// quanta and the final flush all enter here, before `commit_batch`.
    /// A witness read also forwards its health and custody to capture
    /// coverage (`note_witness_batch`); after `end_capture_coverage` that
    /// half stages nothing, while witnessed use — a positive fact — still
    /// binds and stages. Rows are decided by the binder (§3.3); decided
    /// rows stage as edge witnesses or module-level unbound use, and a
    /// proven exec transition retires its incarnation and admits the
    /// successor (the receipt carries those events). The binder census is
    /// staged with every call.
    #[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 drives native capture.
    pub(crate) fn stage_native(
        &mut self,
        batch: NativeBatch,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        now_ns: u64,
    ) -> NativeReceipt {
        match batch {
            NativeBatch::Witness(batch) => {
                // The binder absorbs before the batch's health is noted:
                // the clean-read decision must see this batch's undecided
                // rows (a stamped pending row withholds the proven-clean
                // instant). Absorption stages no registry mutation, so
                // staging order is unchanged.
                self.binder
                    .absorb_witnesses(&batch, &self.adapter, &mut *identity);
                self.note_witness_batch(&batch);
                self.record_witness_integrity(&batch);
                // Counts merge before the binder's decisions stage, so a
                // row that binds in this batch stages with its refresh.
                self.absorb_pair_counts(&batch);
            }
            NativeBatch::Lifecycle(batch) => {
                self.lifecycle_high_water_bytes = self
                    .lifecycle_high_water_bytes
                    .max(batch.drain_high_water_bytes);
                self.binder.absorb_lifecycle(&batch);
                self.note_leader_exits(&batch);
            }
            NativeBatch::Finish { domain } => self.binder.finish(domain),
            NativeBatch::Semantic(batch) => self.stage_semantic_batch(batch),
        }
        let receipt = self.stage_binder_output(identity, now_ns);
        self.reconcile_count_eligibility(identity, &mut RecoveryWorkBudget::new());
        receipt
    }

    /// `LEADER_EXIT` records (H6 slice 2): a leader exit whose generation
    /// pin still holds is link loss, not death — record it once, keep the
    /// original custody, and make no permanent dead tombstone. A later EXEC
    /// still renews recovery, in the same or a later batch. Whole-group
    /// death (a dead pin or no live caller) is reconcile's business, never
    /// this record's.
    fn note_leader_exits(&mut self, batch: &DiscoveryBatch) {
        for record in &batch.records {
            if record.kind != DISCOVERY_KIND_LEADER_EXIT {
                continue;
            }
            let pid = (record.pid_tgid >> 32) as u32;
            let Some(caller) = self.adapter.live_id(pid) else {
                continue;
            };
            let holds = self
                .adapter
                .live_pin(pid)
                .is_some_and(|(_, pin)| self.adapter.source().still_the_same(pin));
            if !holds || !self.leader_link_loss_noted.insert(caller) {
                continue;
            }
            self.registry.record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: Some(pid),
                subject: "leader task link loss".into(),
                reason: "the leader task exited while the generation pin holds (live \
                     threads); original custody is retained with no tombstone, and a \
                     later EXEC may renew recovery"
                    .into(),
                budget: None,
            });
            // Bound callers carry the loss into the commit tail, where H3's
            // once-per-gap cut fences unpublished semantic positives.
            if self.semantic_bindings.get(caller).is_some() {
                self.tail_uncertain.insert(caller);
            }
        }
    }

    /// The exec-coverage revalidation (C1 ruling): for every domain whose
    /// coverage began no later than this pass started (`pass_start_ns`),
    /// the incarnations admitted before that coverage that this pass —
    /// after its reconcile — still finds unchanged. Rows of the others
    /// become `exec_coverage_gap`. Only the first qualifying pass counts.
    /// Returns the incarnation events of rows the pass released.
    fn revalidate_for_exec_coverage(
        &mut self,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        pass_start_ns: u64,
    ) -> Vec<CallerEvent> {
        let due = self.binder.revalidation_due(pass_start_ns);
        if due.is_empty() {
            return Vec::new();
        }
        for (domain, coverage_start) in due {
            let revalidated = self.adapter.revalidate_admitted_before(coverage_start);
            self.binder
                .note_revalidation(domain, pass_start_ns, revalidated);
        }
        self.stage_binder_output(identity, pass_start_ns).events
    }

    /// Stages what the binder decided since the last call: decided rows,
    /// then proven exec transitions, then the census.
    fn stage_binder_output(
        &mut self,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        now_ns: u64,
    ) -> NativeReceipt {
        let decisions = self.binder.take_decisions();
        let decided = decisions.len();
        let mut unresolved: Vec<String> = Vec::new();
        for decision in decisions {
            if let Err(reason) = self.stage_witness(decision) {
                self.registry.note_unresolved_witness();
                unresolved.push(reason);
            }
        }
        if let Some(first) = unresolved.first() {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "native witness without a module".into(),
                reason: format!(
                    "{} witness row(s) named no admitted module this batch (first: {first}); \
                     their use is object-level only and is not shown",
                    unresolved.len()
                ),
                budget: None,
            });
        }
        let mut events = Vec::new();
        for transition in self.binder.take_transitions() {
            events.extend(self.apply_exec_transition(transition, &mut *identity, now_ns));
        }
        self.apply_reconcile_events(&events, now_ns);
        self.registry
            .note_witness_census(self.binder.census().clone());
        NativeReceipt { events, decided }
    }

    /// One witness read's integrity rows: never bound, never dropped
    /// silently — one gap per read that had any.
    fn record_witness_integrity(&mut self, batch: &WitnessBatch) {
        let Some(first) = batch.integrity.first() else {
            return;
        };
        self.registry.record_gap(RegistryGap {
            caller: None,
            module: None,
            pid: None,
            subject: "native witness rows failed validation".into(),
            reason: format!(
                "{} CALLER_USE row(s) failed validation in this read (first: {}); {} so far \
                 this capture; they are integrity evidence and never bind",
                batch.integrity.len(),
                first.reason,
                batch.integrity_total
            ),
            budget: None,
        });
    }

    /// Merges one witness read's counts (C7 C4): each row's first-sight
    /// `entry_count` and each refresh count join their pair by maximum
    /// (with the observing read), and bound pairs whose count advanced
    /// past the registry stage — after re-resolving their placement
    /// (F7). Counts for dropped pairs never merge: the row persists in
    /// the map, so its refresh would otherwise hold memory for a pair
    /// that never publishes. Runs after stop too: a count is a
    /// positive fact, like its witness.
    fn absorb_pair_counts(&mut self, batch: &WitnessBatch) {
        for row in &batch.rows {
            let key = PairKey::of(row);
            if matches!(
                self.pair_targets.get(&key),
                Some(PairTarget::Dropped { .. })
            ) {
                continue;
            }
            self.pair_counts
                .entry(key)
                .or_insert(HeldPairCount::new(PairCount {
                    count: 0,
                    first_ns: row.recorded_at_ns,
                    anchor_ns: batch.rows_anchor_ns,
                    last_ns: batch.rows_read_ns,
                    retirement_usable: false,
                    diagnostic_observation: 0,
                    diagnostic_transition: 0,
                }));
            if self.diagnostics.is_some() {
                self.diagnostic_raw_count(
                    key,
                    Some(row.host_tgid),
                    ReadOrigin::Initial,
                    row.entry_count,
                    (batch.rows_anchor_ns, batch.rows_read_ns),
                    row.entry_count > 0,
                );
            }
            let held = self.pair_counts.get_mut(&key).expect("inserted row count");
            // The row sets its first record whatever arrived before: a
            // refresh can only precede it in a scripted batch.
            held.first_ns = row.recorded_at_ns;
            if row.entry_count > held.count {
                held.count = row.entry_count;
                held.anchor_ns = batch.rows_anchor_ns;
                held.last_ns = batch.rows_read_ns;
                held.retirement_usable = false;
            }
        }
        let mut recheck = Vec::new();
        let mut retry = Vec::new();
        for update in &batch.counts {
            let key = PairKey::of_update(batch.domain, update);
            if matches!(
                self.pair_targets.get(&key),
                Some(PairTarget::Dropped { .. })
            ) {
                continue;
            }
            // Keep the refresh PRE bound for future base coverage and
            // the common POST bound for this count's observation. Neither
            // claims exactly when this particular pair was looked up.
            self.pair_counts
                .entry(key)
                .or_insert(HeldPairCount::new(PairCount {
                    count: 0,
                    first_ns: batch.rows_read_ns,
                    anchor_ns: batch.counts_read_ns,
                    last_ns: batch.rows_read_ns,
                    retirement_usable: false,
                    diagnostic_observation: 0,
                    diagnostic_transition: 0,
                }));
            if self.diagnostics.is_some() {
                self.diagnostic_raw_count(
                    key,
                    None,
                    ReadOrigin::Refresh,
                    update.count,
                    (batch.counts_read_ns, batch.rows_read_ns),
                    valid_retirement_refresh(batch, update.count),
                );
            }
            let (held, advanced) = {
                let held = self
                    .pair_counts
                    .get_mut(&key)
                    .expect("inserted refresh count");
                let advanced = update.count > held.count;
                if advanced {
                    held.count = update.count;
                    held.anchor_ns = batch.counts_read_ns;
                    held.last_ns = batch.rows_read_ns;
                    held.retirement_usable = valid_retirement_refresh(batch, update.count);
                }
                (held.read, advanced)
            };
            // The rotating proof service may not visit this pair before the next
            // read. Preserve its first eligible actual advance at this accounting
            // boundary, before a later held maximum can replace the read bracket.
            self.remember_retirement_advance(key, held, advanced);
            match self.pair_targets.get(&key) {
                Some(PairTarget::Bound {
                    caller,
                    module,
                    endpoint,
                    staged,
                    staged_ns,
                    ..
                }) => recheck.push((
                    key,
                    *caller,
                    module.clone(),
                    *endpoint,
                    update.object,
                    held,
                    *staged,
                    *staged_ns,
                )),
                Some(PairTarget::Pending {
                    caller,
                    modules,
                    staged,
                    base,
                    base_since,
                    ..
                }) => retry.push((
                    key,
                    *caller,
                    modules.clone(),
                    held,
                    *staged,
                    *base,
                    *base_since,
                )),
                _ => {}
            }
        }
        // Pending pairs never resolve against the pre-publish
        // committed snapshot here (P3): a mapping staged in this same
        // window is invisible to it, and a later mapping must not
        // promote a count whose witness already went module-level. An
        // advance past what is staged re-stages pending; the publication
        // decides, and its decisions finalize the target.
        for (key, caller, modules, count, staged, base, base_since) in retry {
            if self.recoveries.get(&key).is_some_and(|recovery| {
                recovery.deferred_count || (recovery.blocked && recovery.epoch.is_some())
            }) {
                continue;
            }
            if count.count > staged {
                self.stage_pending_count(key, caller, &modules, count, base_since, base);
                if let Some(PairTarget::Pending {
                    staged: was,
                    staged_ns: was_ns,
                    ..
                }) = self.pair_targets.get_mut(&key)
                {
                    *was = count.count;
                    *was_ns = count.anchor_ns;
                }
            }
        }
        // Bound pairs re-resolve (F7): sharing that appeared after the
        // pair bound makes further growth ambiguous, so the pair
        // re-resolves pending at publication instead of staging to its
        // cached edge. Staging compares against the registry, not a
        // coordinator copy: only an advance past the staged count
        // stages, so a repeated refresh is free and several reads per
        // commit stay sound.
        for (key, caller, module, endpoint, object, count, staged_abs, staged_ns) in recheck {
            // Once current retirement authority is involved, its exact guards and
            // immutable fence decide growth in the single reconciliation slice.
            if self
                .recoveries
                .get(&key)
                .is_some_and(|recovery| recovery.blocked || recovery.deferred_count)
            {
                continue;
            }
            let admitted = self.update_modules_for_endpoint(endpoint, object);
            let confirmed = match &admitted {
                Ok(modules) => {
                    // The admitted set itself must be exactly the cached
                    // module (round 3, F3-01): an admitted-but-unpublished
                    // sharer (its mapping stages, no commit yet) reads
                    // edged == [cached] against the committed snapshot,
                    // and confirming there would stage up to one pass's
                    // shared growth to the cached arm. Anything else
                    // re-resolves pending and lets publication decide.
                    if modules.len() != 1 || modules[0] != module {
                        false
                    } else {
                        let mut edged = modules.iter().filter(|key| {
                            self.registry
                                .module_id_for(key)
                                .is_some_and(|id| self.registry.edge(caller, id).is_some())
                        });
                        matches!((edged.next(), edged.next()), (Some(only), None) if *only == module)
                    }
                }
                Err(()) => false,
            };
            if confirmed {
                // Only an advance past the absolute staged so far stages
                // (round 4, re-place): growth stages rebased past the
                // staged absolute and the publication accumulates it
                // onto the edge, so a re-place onto the history holder
                // adds instead of `max`ing growth against history. The
                // staging folds into the base (round 5, confirmed path):
                // staging past a frozen base would re-add, on every
                // later publish, growth the edge already holds.
                if count.count > staged_abs {
                    let growth = rebased_count(count, staged_abs);
                    self.stage_pair_count(
                        caller,
                        &module,
                        growth,
                        staged_ns,
                        staged_abs,
                        Some((key, count.count)),
                    );
                    if let Some(recovery) = self.recoveries.get_mut(&key) {
                        recovery.watermark = recovery.watermark.max(count.count);
                    }
                    if let Some(PairTarget::Bound {
                        base,
                        staged,
                        staged_ns,
                        base_since,
                        ..
                    }) = self.pair_targets.get_mut(&key)
                    {
                        *base = count.count;
                        *staged = count.count;
                        *staged_ns = count.anchor_ns;
                        *base_since = count.anchor_ns;
                    }
                }
                continue;
            }
            let modules = admitted.unwrap_or_default();
            // The demoted total stays behind (F3-03): the absolute
            // staged so far — attributed or in flight — is the new
            // base, so only post-demotion growth ever stages elsewhere;
            // the stale edge keeps exactly its history. The staged
            // growth executed after the staged read, so it windows
            // from there (round 4, window anchor).
            let new_base = staged_abs;
            if !self.recoveries.contains_key(&key) {
                // A successful ordinary placement may have no optional retirement
                // metadata. It keeps counting while confirmed above; a changed
                // carrier cannot recover without that bounded state.
                self.note_retirement_metadata_refusal(caller);
                if self.diagnostics.is_some() {
                    let mut record = self.diagnostic_count_record(
                        key, caller, count, new_base, staged_abs, staged_ns,
                    );
                    record.decision = Some(DiagnosticDecision::Withheld);
                    record.reason = Some(DiagnosticReason::BudgetRefused);
                    if let Some(recorder) = &mut self.diagnostics {
                        recorder.record(record);
                    }
                }
                self.registry
                    .note_retirement_count_gap(caller, new_base, count.count);
                self.pair_targets.insert(
                    key,
                    PairTarget::Dropped {
                        base: count.count,
                        base_since: count.anchor_ns,
                    },
                );
                self.pair_counts.remove(&key);
                continue;
            }
            self.bump_placement_generation(key);
            if let Some(recovery) = self.recoveries.get_mut(&key) {
                recovery.blocked = modules.len() != 1;
            }
            self.pair_targets.insert(
                key,
                PairTarget::Pending {
                    caller,
                    modules: modules.clone(),
                    staged: new_base,
                    staged_ns,
                    endpoint,
                    base: new_base,
                    base_since: staged_ns,
                },
            );
            if count.count > new_base {
                self.stage_pending_count(key, caller, &modules, count, staged_ns, new_base);
                if let Some(PairTarget::Pending {
                    staged: was,
                    staged_ns: was_ns,
                    ..
                }) = self.pair_targets.get_mut(&key)
                {
                    *was = count.count;
                    *was_ns = count.anchor_ns;
                }
            }
        }
    }

    /// Constant indexed work for this actual update only: normalize at most
    /// three receipt tags before capturing the current receipt's first advance.
    fn remember_retirement_advance(&mut self, key: PairKey, count: PairCount, advanced: bool) {
        let Some(recovery) = self.recoveries.get(&key) else {
            return;
        };
        let ownership = self
            .count_ownership
            .ordinary_view(recovery.caller, key.object);
        let sole = match ownership.candidate {
            Some(CurrentCandidates::Sole { module, epoch, .. }) => Some((module, *epoch)),
            _ => None,
        };
        let deferred = self.count_ownership.deferred(recovery.caller, key.object);
        let changed = sole.is_some_and(|(module, _)| {
            self.registry.module_id_for(module) != Some(recovery.carrier)
        });
        let continuing = sole.is_some_and(|(_, epoch)| recovery.epoch == Some(epoch));
        let continuity = recovery.ordinary_checkpoint != 0
            && recovery.ordinary_checkpoint == ownership.sequence
            && (ownership.startup || sole.is_some() && !changed)
            && !deferred;
        let ordinary = !recovery.blocked
            && !recovery.recovered
            && continuity
            && (recovery.epoch.is_none() || recovery.epoch_pending && continuing);
        let view = self.count_ownership.receipt_view(recovery.caller);
        let scan = if continuing {
            recovery.scan.clone()
        } else {
            self.count_ownership.supporting_scan(recovery.caller)
        };
        let recovery = self.recoveries.get_mut(&key).expect("checked exact pair");
        let mut work = ReceiptWork::new();
        // Candidate lookup already visits the caller, index and summary. Charge
        // the additional failure, checkpoint and publication-interlock guards.
        work.spend(3);
        recovery.deferred_count |= deferred || changed || !continuity;
        let was_refused = recovery.receipt_refused;
        recovery.normalize_reads(&view, continuing || ordinary, &mut work);
        if !was_refused && recovery.receipt_refused {
            if let Some(recorder) = &mut self.diagnostics {
                record_recovery_refusal(
                    recorder,
                    &self.adapter,
                    key,
                    recovery,
                    DiagnosticReason::CountInvalid,
                );
            }
            self.registry.record_gap(RegistryGap {
                caller: Some(recovery.caller), module: None, pid: None,
                subject: "count retirement earlier read invariant refused".into(),
                reason: "a late earlier equivalent read contradicts a finalized boundary; history remains immutable and future retirement attribution is refused".into(), budget: None,
            });
        }
        if recovery.receipt_refused || ordinary {
            return;
        }
        let Some(scan) = scan else { return };
        // Historical Pending requests retain their observation and generation.
        // Deferral protects newer reads even when blocked=true and epoch=None.
        if (continuing && recovery.fence.is_some())
            || !advanced
            || !count.retirement_usable
            || count.count <= recovery.watermark
            || count.anchor_ns <= scan.finished_ns()
        {
            return;
        }
        let mut vacant = None;
        for index in 0..3 {
            work.visit();
            match &recovery.pending_reads[index] {
                Some(tag) if Arc::ptr_eq(&tag.scan, &scan) || tag.scan.equivalent(&scan) => return,
                None => vacant = Some(index),
                _ => {}
            }
        }
        work.visit();
        if let Some(index) = vacant {
            recovery.pending_reads[index] = Some(TaggedCountRead { scan, read: count });
        } else {
            // Three identities are the caller's entire retained receipt view.
            // A fourth after normalization is an invariant failure, not a spill
            // queue, an overwritten first read or a successful conservative path.
            recovery.receipt_refused = true;
            recovery.deferred_count = true;
            recovery.withhold_reads();
            recovery.discarded_through = recovery.discarded_through.max(count.count);
            if let Some(read) = recovery.fence.take() {
                recovery.withheld_through = recovery.withheld_through.max(read.count);
            }
            recovery.epoch = None;
            recovery.scan = None;
            recovery.sighting = None;
            if let Some(recorder) = &mut self.diagnostics {
                record_recovery_refusal(
                    recorder,
                    &self.adapter,
                    key,
                    recovery,
                    DiagnosticReason::BudgetRefused,
                );
            }
            self.registry.record_gap(RegistryGap {
                caller: Some(recovery.caller), module: None, pid: None,
                subject: "count retirement receipt invariant refused".into(),
                reason: "a fourth unresolved current receipt remained after fixed-slot normalization; future retirement attribution is refused".into(),
                budget: Some(BudgetRefusal { resource: "inventory_count_retirements", limit: 3, requested: 4 }),
            });
        }
    }

    fn note_retirement_metadata_refusal(&mut self, caller: CallerId) {
        if self.diagnostics.is_some() {
            let mut record = DiagnosticRecord::new(DiagnosticKind::OwnershipTransition);
            self.diagnostic_identity(&mut record, caller);
            record.reason = Some(DiagnosticReason::BudgetRefused);
            record.context_unavailable = true;
            if let Some(recorder) = &mut self.diagnostics {
                recorder.record(record);
            }
        }
        let limit = self.registry.limits().max_edges;
        self.registry.record_gap(RegistryGap {
            caller: Some(caller),
            module: None,
            pid: None,
            subject: "count retirement metadata refused".into(),
            reason: "the bounded retirement metadata was not retained; ordinary exact single-owner counting continues, but a later ownership change has unknown count eligibility and cannot recover".into(),
            budget: Some(BudgetRefusal {
                resource: "inventory_count_retirements",
                limit,
                requested: limit.saturating_add(1),
            }),
        });
    }

    /// The admitted modules a count update's endpoint resolves to (F7):
    /// the update-side twin of [`Self::witness_modules`] — the
    /// endpoint must be in the attach set and name the update's
    /// object. `Err` fails closed (the pair re-resolves pending with
    /// no modules and finalizes dropped).
    fn update_modules_for_endpoint(
        &self,
        endpoint: EndpointId,
        object: AttachObjectId,
    ) -> Result<Vec<ModuleKey>, ()> {
        let entry = self.attach_set.endpoint(endpoint).ok_or(())?;
        if entry.object != object {
            return Err(());
        }
        self.admitted_modules_for_endpoint(endpoint).map_err(|_| ())
    }

    /// Stages one pair's count to its edge (C7 C4): the (base-rebased,
    /// growth-only past demotion — absolute for an unbased pair) count
    /// plus the counting-feed note, so the edge reads `counted`. Only
    /// for admitted modules and counts ≥ 1 — anything else leaves the
    /// witness standing, and the staging self-heals on the next
    /// refresh after admission. `base` is the accounted absolute the
    /// count rebases past (0 installs absolute); `since_ns` is the read
    /// that observed `base`: the coverage windows from there (round 4,
    /// window anchor).
    fn stage_pair_count(
        &mut self,
        caller: CallerId,
        module: &ModuleKey,
        count: PairCount,
        since_ns: u64,
        base: u64,
        diagnostic_source: Option<(PairKey, u64)>,
    ) {
        if count.count == 0 {
            return;
        }
        let admitted = self
            .registry
            .module_id_for(module)
            .and_then(|id| self.registry.module(id))
            .is_some_and(|record| record.admission == AdmissionState::Admitted);
        if let Some(recorder) = &mut self.diagnostics {
            let mut record = DiagnosticRecord::new(DiagnosticKind::CountDecision);
            record.caller = Some(caller.0);
            if let Some(caller) = self.adapter.record(caller) {
                record.pid = Some(caller.pid);
                record.incarnation = Some(u64::from(caller.incarnation));
            }
            record.module = self.registry.module_id_for(module).map(|module| module.0);
            record.base = Some(base);
            record.staged = Some(count.count);
            record.pre = Some(count.anchor_ns);
            record.post = Some(count.last_ns);
            record.baseline_pre = (base != 0).then_some(since_ns);
            record.observation_ref = nonzero_ref(count.diagnostic_observation);
            record.transition_ref = nonzero_ref(count.diagnostic_transition);
            record.context_unavailable = base != 0 || record.observation_ref.is_none();
            if let Some((key, absolute)) = diagnostic_source {
                record = record.with_pair(key.diagnostic_key());
                record.absolute = Some(absolute);
                record.after = Some(base);
                record.through = Some(absolute);
            } else {
                record.context_unavailable = true;
            }
            record.decision = Some(if admitted {
                DiagnosticDecision::Staged
            } else {
                DiagnosticDecision::Rejected
            });
            record.reason = Some(if admitted {
                DiagnosticReason::SoleOwner
            } else {
                DiagnosticReason::NotAdmitted
            });
            recorder.record(record);
        }
        if !admitted {
            return;
        }
        self.registry.note_counted_use(
            caller,
            module,
            count.count,
            count.first_ns,
            count.last_ns,
            base,
        );
        self.registry
            .note_coverage(caller, module, CoverageNote::Counted { since_ns });
    }

    /// Records one bound row's pair target (P3): the pair always
    /// (re-)binds pending — placement resolves at publication, together
    /// with the witness, against the mappings the publication commits
    /// (including this same window's). Nothing here reads the
    /// pre-publish committed snapshot: a single committed edge proves
    /// nothing while a second mapping stages, and caching `Bound` from
    /// it would attribute the count where the witness reads ambiguous.
    /// A rebind carries the pair's attributed history: rebinding over a
    /// live or dropped target keeps its base (and staged absolute), so
    /// only a genuine advance past what is staged stages — and demoted
    /// past what the base holds (round 4, rebind). The publication's
    /// decisions finalize the target as `Bound` or `Dropped`.
    fn bind_pair_count(&mut self, row: &WitnessRow, caller: CallerId, modules: &[ModuleKey]) {
        let key = PairKey::of(row);
        let held_first = self
            .pair_counts
            .get(&key)
            .map(|count| count.first_ns)
            .unwrap_or(row.recorded_at_ns);
        let (base, staged, staged_ns, base_since) = match self.pair_targets.get(&key) {
            Some(PairTarget::Pending {
                base,
                staged,
                staged_ns,
                base_since,
                ..
            }) => (*base, *staged, *staged_ns, *base_since),
            Some(PairTarget::Bound {
                base,
                staged,
                staged_ns,
                base_since,
                ..
            }) => (*base, *staged, *staged_ns, *base_since),
            Some(
                PairTarget::Dropped { base, base_since }
                | PairTarget::Suspended {
                    base, base_since, ..
                },
            ) => (*base, *base, *base_since, *base_since),
            None => (0, 0, 0, held_first),
        };
        if self.diagnostics.is_some() {
            let mut record = if let Some(count) = self.pair_counts.get(&key).map(|held| held.read) {
                self.diagnostic_count_record(key, caller, count, base, staged, base_since)
            } else {
                let mut record = DiagnosticRecord::new(DiagnosticKind::OwnershipTransition)
                    .with_pair(key.diagnostic_key());
                self.diagnostic_identity(&mut record, caller);
                record.context_unavailable = true;
                record
            };
            record.kind = DiagnosticKind::OwnershipTransition;
            record.prior_eligibility = self.pair_targets.get(&key).map(|target| match target {
                PairTarget::Bound { .. } => Eligibility::SoleOwner,
                PairTarget::Pending { .. } => Eligibility::Unproven,
                _ => Eligibility::Unknown,
            });
            record.new_eligibility = Some(Eligibility::Unproven);
            record.reason = Some(DiagnosticReason::PendingPublication);
            record.module = (modules.len() == 1)
                .then(|| {
                    self.registry
                        .module_id_for(&modules[0])
                        .map(|module| module.0)
                })
                .flatten();
            let seq = self
                .diagnostics
                .as_mut()
                .and_then(|recorder| recorder.record(record))
                .unwrap_or(0);
            if let Some(count) = self.pair_counts.get_mut(&key) {
                count.diagnostic_transition = seq;
            }
            if let Some(recovery) = self.recoveries.get_mut(&key) {
                recovery.diagnostic.transition_ref = seq;
            }
        }
        // A new, generically bound witness still owns its ordinary publication
        // placement. It does not borrow or discharge an armed retirement proof.
        if modules.len() == 1
            && let Some(recovery) = self
                .recoveries
                .get_mut(&key)
                .filter(|recovery| recovery.epoch.is_none())
        {
            recovery.blocked = false;
        }
        self.bump_placement_generation(key);
        self.pair_targets.insert(
            key,
            PairTarget::Pending {
                caller,
                modules: modules.to_vec(),
                staged,
                staged_ns,
                endpoint: row.endpoint,
                base,
                base_since,
            },
        );
        if let Some(count) = self.pair_counts.get(&key).map(|held| held.read)
            && count.count > staged
        {
            self.stage_pending_count(key, caller, modules, count, base_since, base);
            if let Some(PairTarget::Pending {
                staged, staged_ns, ..
            }) = self.pair_targets.get_mut(&key)
            {
                *staged = count.count;
                *staged_ns = count.anchor_ns;
            }
        }
    }

    /// Stages one pending pair's held count for publication-time
    /// placement (P3): the (base-rebased, growth-only past demotion —
    /// absolute for an unbased pair) count, only for counts ≥ 1 —
    /// anything else leaves the witness standing, and a later advance
    /// re-stages. `base` is the accounted absolute the count rebases
    /// past (0 for a first-sight pair): a nonzero base marks a
    /// re-resolved pair, whose rejection the publication discloses
    /// (F3-02) and whose placement accumulates by segment. `since_ns`
    /// is the PRE bound for the `base` read: a placement windows its
    /// coverage from there (round 4, window anchor). The minted handle
    /// maps the publication's decision back to the pair.
    fn stage_pending_count(
        &mut self,
        key: PairKey,
        caller: CallerId,
        modules: &[ModuleKey],
        observation: PairCount,
        since_ns: u64,
        base: u64,
    ) -> bool {
        let count = rebased_count(observation, base);
        if count.count == 0 {
            return false;
        }
        let generation = *self.placement_generations.entry(key).or_insert(Some(0));
        let Some(next) = self.next_pending_id.checked_add(1) else {
            self.diagnostic_pending_refusal(
                key,
                caller,
                observation,
                base,
                since_ns,
                DiagnosticReason::BudgetRefused,
            );
            self.registry
                .note_retirement_count_gap(caller, base, observation.count);
            if let Some(recovery) = self.recoveries.get_mut(&key) {
                recovery.watermark = recovery.watermark.max(observation.count);
            }
            self.placement_generations.insert(key, None);
            return false;
        };
        if generation.is_none() || self.pending_ids.len() >= self.registry.limits().max_edges {
            self.diagnostic_pending_refusal(
                key,
                caller,
                observation,
                base,
                since_ns,
                DiagnosticReason::BudgetRefused,
            );
            self.registry
                .note_retirement_count_gap(caller, base, observation.count);
            if let Some(recovery) = self.recoveries.get_mut(&key) {
                recovery.watermark = recovery.watermark.max(observation.count);
            }
            return false;
        }
        let endpoint = match self.pair_targets.get(&key) {
            Some(
                PairTarget::Pending {
                    caller: bound,
                    endpoint,
                    ..
                }
                | PairTarget::Bound {
                    caller: bound,
                    endpoint,
                    ..
                }
                | PairTarget::Suspended {
                    caller: bound,
                    endpoint,
                    ..
                },
            ) if *bound == caller => *endpoint,
            _ => {
                self.diagnostic_pending_refusal(
                    key,
                    caller,
                    observation,
                    base,
                    since_ns,
                    DiagnosticReason::BindingUnproven,
                );
                return false;
            }
        };
        let mut work = ReceiptWork::new();
        let origin = if let Some(recovery) = self.recoveries.get(&key) {
            work.visit();
            match recovery.epoch.filter(|_| recovery.blocked) {
                Some(epoch) => PendingCountOrigin::Recovered(epoch),
                None => PendingCountOrigin::Ordinary(recovery.ordinary_checkpoint),
            }
        } else {
            // Registration moves before the original immutable handle. Its
            // cell/tombstone remains charged even if placement later rejects.
            work.spend(7); // bounded registration/caller barrier and three origin lookups
            if self.count_ownership.register_pair(caller, key.object) {
                let ownership = self.count_ownership.ordinary_view(caller, key.object);
                if ownership.initial_metadata_refused {
                    // Optional index storage failed before any accepted source
                    // or completed result. Preserve generic physical admission;
                    // this exception cannot erase established failure history.
                    PendingCountOrigin::Untracked
                } else {
                    PendingCountOrigin::Ordinary(ownership.checkpoint(observation.anchor_ns))
                }
            } else {
                PendingCountOrigin::Untracked
            }
        };
        let pending_id = self.next_pending_id;
        self.next_pending_id = next;
        let diagnostic = if self.diagnostics.is_some() {
            // This is the exact rebased value queued below, not the prior
            // absolute watermark retained by PairTarget.
            let staged = count.count;
            let mut record = self
                .diagnostic_count_record(key, caller, observation, base, staged, since_ns)
                .with_private_ids(
                    None,
                    match origin {
                        PendingCountOrigin::Recovered(epoch) => Some(epoch.0),
                        _ => None,
                    },
                    Some(pending_id),
                );
            record.decision = Some(DiagnosticDecision::Staged);
            record.reason = Some(DiagnosticReason::PendingPublication);
            record.module = (modules.len() == 1)
                .then(|| {
                    self.registry
                        .module_id_for(&modules[0])
                        .map(|module| module.0)
                })
                .flatten();
            let diagnostic = PendingDiagnostics {
                base,
                staged,
                since: since_ns,
                baseline_post: record.baseline_post.unwrap_or(0),
                fence: record.fence.unwrap_or(0),
                transition_ref: record.transition_ref.unwrap_or(0),
            };
            if let Some(recorder) = &mut self.diagnostics {
                recorder.record(record);
            }
            Some(diagnostic)
        } else {
            None
        };
        self.pending_ids.insert(
            pending_id,
            PendingCountObservation {
                key,
                caller,
                endpoint,
                observation,
                generation,
                origin,
                diagnostic,
            },
        );
        self.registry.note_pending_count(
            pending_id,
            caller,
            modules.to_vec(),
            count.count,
            count.first_ns,
            count.last_ns,
            since_ns,
            base,
        );
        true
    }

    fn bump_placement_generation(&mut self, key: PairKey) {
        let generation = self.placement_generations.entry(key).or_insert(Some(0));
        *generation = generation.and_then(|generation| generation.checked_add(1));
    }

    /// Finalization consumes only the immutable observation that produced the decision.
    /// Stale decisions may preserve registry history but never authorize newer growth.
    fn finalize_pending_counts(&mut self) {
        for decision in self.registry.take_pending_count_decisions() {
            let Some(pending) = self.pending_ids.remove(&decision.pending_id) else {
                continue;
            };
            let key = pending.key;
            self.diagnostic_pending_result(decision.pending_id, &pending, Some(&decision.outcome));
            if pending.generation.is_none()
                || self.placement_generations.get(&key).copied().flatten() != pending.generation
            {
                self.diagnostic_pending_result(decision.pending_id, &pending, None);
                continue;
            }
            if let PendingCountOrigin::Recovered(epoch) = pending.origin {
                let valid = self.recovery_is_current(key, epoch);
                if !valid {
                    self.diagnostic_pending_result(decision.pending_id, &pending, None);
                    continue;
                }
            }
            let accounted = match self.pair_targets.get(&key) {
                Some(
                    PairTarget::Bound { base, .. }
                    | PairTarget::Suspended { base, .. }
                    | PairTarget::Pending { base, .. },
                ) => *base,
                _ => {
                    self.diagnostic_pending_result(decision.pending_id, &pending, None);
                    continue;
                }
            };
            if pending.observation.count < accounted {
                self.diagnostic_pending_result(decision.pending_id, &pending, None);
                continue;
            }
            match decision.outcome {
                PendingCountOutcome::Placed { module } => {
                    if !self.recoveries.contains_key(&key) {
                        if self.recoveries.len() < self.registry.limits().max_edges
                            && matches!(pending.origin, PendingCountOrigin::Ordinary(_))
                        {
                            self.recoveries.insert(
                                key,
                                PairRecovery {
                                    caller: pending.caller,
                                    endpoint: pending.endpoint,
                                    carrier: self
                                        .registry
                                        .module_id_for(&module)
                                        .expect("placed module is registered"),
                                    ordinary_checkpoint: match pending.origin {
                                        PendingCountOrigin::Ordinary(checkpoint) => checkpoint,
                                        _ => unreachable!("checked original token"),
                                    },
                                    epoch: None,
                                    scan: None,
                                    sighting: None,
                                    fence: None,
                                    pending_reads: [None, None, None],
                                    withheld_through: pending.observation.count,
                                    discarded_through: pending.observation.count,
                                    watermark: pending.observation.count,
                                    blocked: false,
                                    recovered: false,
                                    deferred_count: false,
                                    receipt_refused: false,
                                    epoch_pending: false,
                                    diagnostic: RecoveryDiagnostics::default(),
                                },
                            );
                            self.recovery_order.push(key);
                        } else {
                            // Retirement metadata is optional for this ordinary
                            // successful placement, not a physical-pair admission cap.
                            self.note_retirement_metadata_refusal(pending.caller);
                        }
                    }
                    if let Some(recovery) = self.recoveries.get_mut(&key) {
                        recovery.carrier = self
                            .registry
                            .module_id_for(&module)
                            .expect("placed module is registered");
                        recovery.watermark = recovery.watermark.max(pending.observation.count);
                        recovery.recovered |=
                            matches!(pending.origin, PendingCountOrigin::Recovered(_));
                        recovery.blocked =
                            matches!(pending.origin, PendingCountOrigin::Recovered(_));
                    }
                    self.pair_targets.insert(
                        key,
                        PairTarget::Bound {
                            caller: pending.caller,
                            module,
                            endpoint: pending.endpoint,
                            base: pending.observation.count,
                            staged: pending.observation.count,
                            staged_ns: pending.observation.anchor_ns,
                            base_since: pending.observation.anchor_ns,
                        },
                    );
                }
                PendingCountOutcome::Rejected { .. } => {
                    if let Some(recovery) = self.recoveries.get_mut(&key) {
                        recovery.blocked = true;
                        recovery.recovered = false;
                        recovery.watermark = recovery.watermark.max(pending.observation.count);
                        self.pair_targets.insert(
                            key,
                            PairTarget::Suspended {
                                caller: pending.caller,
                                endpoint: pending.endpoint,
                                base: pending.observation.count,
                                base_since: pending.observation.anchor_ns,
                            },
                        );
                    } else {
                        self.pair_targets.insert(
                            key,
                            PairTarget::Dropped {
                                base: pending.observation.count,
                                base_since: pending.observation.anchor_ns,
                            },
                        );
                        self.pair_counts.remove(&key);
                    }
                }
                PendingCountOutcome::Unadmitted { .. } => {}
            }
        }
    }

    fn recovery_is_current(&self, key: PairKey, epoch: OwnershipEpoch) -> bool {
        let Some(recovery) = self.recoveries.get(&key) else {
            return false;
        };
        if recovery.epoch != Some(epoch) || recovery.epoch_pending || recovery.receipt_refused {
            return false;
        }
        let Some(record) = self.adapter.record(recovery.caller) else {
            return false;
        };
        if record.retired
            || self.adapter.live_id(record.pid) != Some(recovery.caller)
            || self
                .adapter
                .live_pin(record.pid)
                .is_none_or(|(_, pin)| !self.adapter.source().still_the_same(pin))
            || !self.binder.domain_active(key.image.domain())
        {
            return false;
        }
        let Some(scan) = recovery.scan.as_ref() else {
            return false;
        };
        if record.start_time != scan.generation().start_time
            || record.exe != scan.generation().exe
            || record.first_seen_ns > scan.started_ns()
        {
            return false;
        }
        if self.capture.as_ref().is_some_and(|capture| {
            capture.stopped
                || capture.unproven.is_some()
                || self
                    .attach_set
                    .endpoint(recovery.endpoint)
                    .is_none_or(|endpoint| {
                        endpoint.object.index() != key.object
                            || capture.changed_objects.contains(&endpoint.object)
                    })
        }) {
            return false;
        }
        matches!(self.count_ownership.candidates(recovery.caller, key.object), CurrentCandidates::Sole { epoch: current, module, .. }
            if current == epoch && self.registry.module_id_for(&module)
                .and_then(|id| self.registry.module(id).zip(self.registry.edge(recovery.caller, id)))
                .is_some_and(|(module, edge)| module.admission == AdmissionState::Admitted
                    && edge.mapping == MappingState::Mapped && !edge.double_loaded))
            && recovery.sighting.as_ref().is_some_and(|sighting| {
                matches!(
                    self.binder.check_current_binding(sighting),
                    CurrentBindingCheck::Proven
                )
            })
    }

    fn suspend_recovery(&mut self, key: PairKey, recovery: &mut PairRecovery) {
        recovery.blocked = true;
        recovery.recovered = false;
        self.pair_targets.insert(
            key,
            PairTarget::Suspended {
                caller: recovery.caller,
                endpoint: recovery.endpoint,
                base: recovery.watermark,
                base_since: recovery.fence.map_or(0, |fence| fence.anchor_ns),
            },
        );
    }

    /// A bounded comparison resolved to the carrier that already placed this
    /// pair. Resume its full ordinary growth, with its original staged base.
    fn resume_deferred_count(
        &mut self,
        key: PairKey,
        recovery: &mut PairRecovery,
        module: &ModuleKey,
        held: Option<PairCount>,
    ) {
        recovery.deferred_count = false;
        recovery.clear_reads();
        recovery.epoch_pending = false;
        recovery.epoch = None;
        recovery.scan = None;
        recovery.sighting = None;
        recovery.fence = None;
        let Some(PairTarget::Bound {
            staged, staged_ns, ..
        }) = self.pair_targets.get(&key)
        else {
            return;
        };
        let (staged, staged_ns) = (*staged, *staged_ns);
        let Some(count) = held.filter(|count| count.count > staged) else {
            return;
        };
        self.stage_pair_count(
            recovery.caller,
            module,
            rebased_count(count, staged),
            staged_ns,
            staged,
            Some((key, count.count)),
        );
        recovery.watermark = recovery.watermark.max(count.count);
        if let Some(PairTarget::Bound {
            base,
            staged,
            staged_ns,
            base_since,
            ..
        }) = self.pair_targets.get_mut(&key)
        {
            *base = count.count;
            *staged = count.count;
            *staged_ns = count.anchor_ns;
            *base_since = count.anchor_ns;
        }
    }

    /// Only a classified contiguous unknown prefix is disclosed here. Callers
    /// first resolve historical generic decisions and continuing ownership.
    fn flush_withheld_prefix(&mut self, key: PairKey, recovery: &mut PairRecovery) {
        self.diagnostic_withheld(
            key,
            recovery,
            recovery.watermark,
            recovery.withheld_through,
            DiagnosticReason::OwnershipTransition,
            None,
        );
        self.registry.note_retirement_count_gap(
            recovery.caller,
            recovery.watermark,
            recovery.withheld_through,
        );
        recovery.watermark = recovery.watermark.max(recovery.withheld_through);
        recovery.withheld_through = recovery.watermark;
    }

    fn generic_predecessor(&self, key: PairKey, recovery: &PairRecovery) -> bool {
        (recovery.epoch.is_none() || recovery.epoch_pending)
            && matches!(self.pair_targets.get(&key), Some(PairTarget::Pending { base, staged, .. }) if staged > base)
    }

    fn cancel_retirement_candidate(
        &mut self,
        key: PairKey,
        recovery: &mut PairRecovery,
        held: Option<PairCount>,
        reason: DiagnosticReason,
    ) {
        self.diagnostic_recovery_decision(
            key,
            recovery,
            reason,
            held,
            DiagnosticDecision::Rejected,
        );
        let predecessor = self.generic_predecessor(key, recovery);
        let protected = recovery.deferred_count
            || recovery.epoch.is_some()
            || recovery.scan.is_some()
            || recovery.pending_reads.iter().any(Option::is_some);
        recovery.withhold_reads();
        if let Some(read) = recovery.fence.take() {
            recovery.withheld_through = recovery.withheld_through.max(read.count);
        }
        recovery.epoch = None;
        recovery.epoch_pending = false;
        recovery.scan = None;
        recovery.sighting = None;
        recovery.deferred_count = predecessor && protected;
        if !predecessor {
            // No surviving allocation candidate remains after genuine revocation.
            recovery.withheld_through = recovery.withheld_through.max(recovery.discarded_through);
            recovery.discarded_through = recovery.watermark;
            self.flush_withheld_prefix(key, recovery);
            if let Some(held) = held {
                self.diagnostic_withheld(
                    key,
                    recovery,
                    recovery.watermark,
                    held.count,
                    reason,
                    Some(held),
                );
                self.registry.note_retirement_count_gap(
                    recovery.caller,
                    recovery.watermark,
                    held.count,
                );
                recovery.watermark = recovery.watermark.max(held.count);
                recovery.withheld_through = recovery.watermark;
            }
            self.suspend_recovery(key, recovery);
        }
    }

    /// One top-level call shares a single visit/query allowance. Reserved proof
    /// work prevents a large observation/index rebuild from starving later pairs.
    fn reconcile_count_eligibility(
        &mut self,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        budget: &mut RecoveryWorkBudget,
    ) {
        budget.limit_visits(64);
        self.count_ownership
            .advance(&self.attach_set, &self.registry, budget);
        budget.limit_visits(128);
        let mut serviced = 0;
        while budget.remaining() >= 48 && serviced < self.recovery_order.len() {
            let key = self.recovery_order[self.recovery_cursor];
            self.recovery_cursor = (self.recovery_cursor + 1) % self.recovery_order.len();
            serviced += 1;
            // 16 existing exact target/count/caller/pin/domain guards plus 32
            // fixed receipt resolution operations, including refused branches.
            // The allowance is reserved once, never refilled for another pair.
            budget.spend(48);
            let Some(mut recovery) = self.recoveries.remove(&key) else {
                continue;
            };
            let held = self.pair_counts.get(&key).map(|held| held.read);
            let ownership = self
                .count_ownership
                .ordinary_view(recovery.caller, key.object);
            let candidate = ownership
                .candidate
                .cloned()
                .unwrap_or(CurrentCandidates::Unknown);
            let continuing = matches!(&candidate, CurrentCandidates::Sole { epoch, .. } if recovery.epoch == Some(*epoch));
            let ordinary = matches!(&candidate, CurrentCandidates::Sole { module, .. }
                if !recovery.blocked && self.registry.module_id_for(module) == Some(recovery.carrier)
                    && !recovery.recovered
                    && (recovery.epoch.is_none() || recovery.epoch_pending && continuing)
                    && recovery.ordinary_checkpoint != 0
                    && recovery.ordinary_checkpoint == ownership.sequence);
            self.diagnostic_ownership(key, &mut recovery, &candidate);
            let mut work = ReceiptWork::new();
            work.spend(3); // ordinary source/checkpoint guards within the fixed reservation
            let was_refused = recovery.receipt_refused;
            recovery.normalize_reads(
                &self.count_ownership.receipt_view(recovery.caller),
                continuing || ordinary,
                &mut work,
            );
            if !was_refused && recovery.receipt_refused {
                if let Some(recorder) = &mut self.diagnostics {
                    record_recovery_refusal(
                        recorder,
                        &self.adapter,
                        key,
                        &mut recovery,
                        DiagnosticReason::CountInvalid,
                    );
                }
                self.registry.record_gap(RegistryGap {
                    caller: Some(recovery.caller), module: None, pid: None,
                    subject: "count retirement earlier read invariant refused".into(),
                    reason: "a late earlier equivalent read contradicts a finalized boundary; history remains immutable and future retirement attribution is refused".into(), budget: None,
                });
            }
            let live = self
                .adapter
                .record(recovery.caller)
                .filter(|record| {
                    !record.retired
                        && self.adapter.live_id(record.pid) == Some(recovery.caller)
                        && self
                            .adapter
                            .live_pin(record.pid)
                            .is_some_and(|(_, pin)| self.adapter.source().still_the_same(pin))
                })
                .cloned();
            let canceled = recovery.receipt_refused
                || live.is_none()
                || !self.binder.domain_active(key.image.domain())
                || self.capture.as_ref().is_some_and(|capture| {
                    capture.stopped
                        || capture.unproven.is_some()
                        || self
                            .attach_set
                            .endpoint(recovery.endpoint)
                            .is_none_or(|endpoint| {
                                endpoint.object.index() != key.object
                                    || capture.changed_objects.contains(&endpoint.object)
                            })
                });
            if canceled {
                let reason = if recovery.receipt_refused {
                    DiagnosticReason::CountInvalid
                } else if self.capture.as_ref().is_some_and(|capture| capture.stopped) {
                    DiagnosticReason::CaptureStopped
                } else if self
                    .capture
                    .as_ref()
                    .is_some_and(|capture| capture.unproven.is_some())
                {
                    DiagnosticReason::CaptureLoss
                } else {
                    DiagnosticReason::IdentityChanged
                };
                self.cancel_retirement_candidate(key, &mut recovery, held, reason);
                self.recoveries.insert(key, recovery);
                continue;
            }
            let predecessor = self.generic_predecessor(key, &recovery);
            let CurrentCandidates::Sole {
                module,
                epoch,
                scan,
            } = candidate
            else {
                let deferred = self.count_ownership.deferred(recovery.caller, key.object);
                let reason = if deferred {
                    DiagnosticReason::ScanIncomplete
                } else if matches!(candidate, CurrentCandidates::Shared) {
                    DiagnosticReason::SharedOwner
                } else {
                    DiagnosticReason::OwnershipUnknown
                };
                if !self.count_ownership.deferred(recovery.caller, key.object)
                    && (recovery.blocked || recovery.deferred_count || recovery.epoch.is_some())
                {
                    self.cancel_retirement_candidate(key, &mut recovery, held, reason);
                } else {
                    self.diagnostic_recovery_wait(key, &mut recovery, reason, held);
                }
                self.recoveries.insert(key, recovery);
                continue;
            };
            if ordinary {
                if predecessor {
                    self.recoveries.insert(key, recovery);
                    continue;
                }
                if recovery.deferred_count || recovery.epoch_pending {
                    self.resume_deferred_count(key, &mut recovery, &module, held);
                } else {
                    recovery.clear_reads();
                }
                self.recoveries.insert(key, recovery);
                continue;
            }
            if recovery.epoch != Some(epoch) {
                let selected = recovery.take_read(&scan, &mut work);
                if let Some(read) = recovery.fence.take() {
                    recovery.withheld_through = recovery.withheld_through.max(read.count);
                }
                recovery.epoch = Some(epoch);
                recovery.scan = Some(
                    selected
                        .as_ref()
                        .map_or_else(|| scan.clone(), |tag| tag.scan.clone()),
                );
                recovery.fence = selected.map(|tag| tag.read);
                recovery.sighting = None;
                recovery.deferred_count = true;
                recovery.epoch_pending = true;
            } else if recovery.fence.is_none()
                && let Some(selected) = recovery.take_read(&scan, &mut work)
            {
                // The bounded current summary established this continuing
                // logical epoch, including any unrelated global revision.
                recovery.fence = Some(selected.read);
                if recovery
                    .scan
                    .as_ref()
                    .is_none_or(|old| selected.scan.started_ns() < old.started_ns())
                {
                    recovery.scan = Some(selected.scan);
                }
            }
            // Ownership selection above may coexist with old generic handles.
            // It changes neither their generation/target nor any H/D disposition.
            if predecessor {
                self.diagnostic_recovery_wait(
                    key,
                    &mut recovery,
                    DiagnosticReason::PendingPublication,
                    held,
                );
                self.diagnostic_recovery_selection(key, &mut recovery, false);
                self.recoveries.insert(key, recovery);
                continue;
            }
            if recovery.epoch_pending {
                self.bump_placement_generation(key);
                self.suspend_recovery(key, &mut recovery);
                recovery.epoch_pending = false;
                recovery.deferred_count = false;
            }
            // Classify surviving full current candidates BEFORE D conversion.
            // A later detached11 cannot consume valid new-epoch10 at rollover.
            if let Some(read) = recovery.fence {
                if recovery.discarded_through <= read.count {
                    // This actually saved obsolete prefix precedes the full
                    // source-validated boundary. H is independent old history.
                    recovery.withheld_through =
                        recovery.withheld_through.max(recovery.discarded_through);
                }
                // A qualifying full tag/selected epoch independently proves
                // current sampled continuation. D above it supplies no loss.
                recovery.discarded_through = recovery.watermark;
                if recovery.withheld_through > read.count
                    && recovery.withheld_through > recovery.watermark
                {
                    // Independently unknown H contradicts this candidate. All
                    // affected future claims are revoked before true loss.
                    recovery.fence = None;
                    recovery.withhold_reads();
                    recovery.withheld_through =
                        recovery.withheld_through.max(recovery.discarded_through);
                    recovery.discarded_through = recovery.watermark;
                    self.registry.record_gap(RegistryGap {
                        caller: Some(recovery.caller), module: None, pid: None,
                        subject: "count retirement candidate revoked".into(),
                        reason: "independently unknown historical coverage crosses the retained candidate after genuine revocation; future recovery needs a new actual advancing read".into(),
                        budget: None,
                    });
                }
            } else {
                // All conditional tags are detached from this new current
                // authority and no full surviving candidate claims their range.
                recovery.withheld_through =
                    recovery.withheld_through.max(recovery.discarded_through);
                recovery.discarded_through = recovery.watermark;
            }
            self.flush_withheld_prefix(key, &mut recovery);
            let scan = recovery
                .scan
                .as_ref()
                .expect("epoch owns its original scan")
                .clone();
            let record = live.expect("checked live caller");
            if record.start_time != scan.generation().start_time
                || record.exe != scan.generation().exe
                || record.first_seen_ns > scan.started_ns()
            {
                self.cancel_retirement_candidate(
                    key,
                    &mut recovery,
                    held,
                    DiagnosticReason::IdentityChanged,
                );
                self.recoveries.insert(key, recovery);
                continue;
            }
            if recovery.sighting.is_none() {
                if !budget.query() {
                    self.recoveries.insert(key, recovery);
                    continue;
                }
                let request = CurrentBindingRequest {
                    caller: recovery.caller,
                    pid: record.pid,
                    image: key.image,
                    exec_id: key.exec,
                };
                match self
                    .binder
                    .sight_current_binding(request, &self.adapter, identity)
                {
                    Ok(sighting) => {
                        if sighting.sighted_ns() > scan.finished_ns() {
                            recovery.sighting = Some(sighting);
                        }
                    }
                    Err(UnboundReason::CookieUnavailable) => {
                        self.diagnostic_recovery_wait(
                            key,
                            &mut recovery,
                            DiagnosticReason::BindingUnproven,
                            held,
                        );
                    }
                    Err(
                        reason @ (UnboundReason::NoLiveCaller
                        | UnboundReason::CallerExited
                        | UnboundReason::CookieMismatch
                        | UnboundReason::BeforeAdmission
                        | UnboundReason::ExecAfterAdmission
                        | UnboundReason::LifecycleLoss
                        | UnboundReason::ExecAmbiguous
                        | UnboundReason::ExecTransition
                        | UnboundReason::ExecCoverageGap
                        | UnboundReason::EvidenceIncomplete
                        | UnboundReason::Capacity),
                    ) => {
                        // A failed completion clock also supplies no authority.
                        // Preserve history, but never retry a rejected read as
                        // though its original identity proof merely waited.
                        self.cancel_retirement_candidate(
                            key,
                            &mut recovery,
                            held,
                            diagnostic_binding_reason(reason),
                        );
                        self.recoveries.insert(key, recovery);
                        continue;
                    }
                }
            }
            // Selection above retained an unproven candidate only. A genuine
            // post-scan sighting now permits classifying the saved prefix and
            // first-read uncertainty. Allocation still waits for Proven horizons.
            if recovery.sighting.is_some()
                && let Some(read) = recovery.fence.filter(|read| {
                    read.count > recovery.watermark
                        && read.retirement_usable
                        && read.anchor_ns > scan.finished_ns()
                })
            {
                self.flush_withheld_prefix(key, &mut recovery);
                self.diagnostic_withheld(
                    key,
                    &recovery,
                    recovery.watermark,
                    read.count,
                    DiagnosticReason::AwaitingFence,
                    Some(read),
                );
                self.registry.note_retirement_count_gap(
                    recovery.caller,
                    recovery.watermark,
                    read.count,
                );
                recovery.watermark = read.count;
                recovery.withheld_through = recovery.watermark;
                self.suspend_recovery(key, &mut recovery);
            }
            let proof = recovery
                .sighting
                .as_ref()
                .map(|sighting| self.binder.check_current_binding(sighting));
            self.diagnostic_recovery_selection(
                key,
                &mut recovery,
                matches!(proof, Some(CurrentBindingCheck::Proven)),
            );
            if let Some(CurrentBindingCheck::Rejected(reason)) = proof {
                self.cancel_retirement_candidate(
                    key,
                    &mut recovery,
                    held,
                    diagnostic_binding_reason(reason),
                );
            }
            let stage = matches!(proof, Some(CurrentBindingCheck::Proven))
                && recovery.fence.is_some()
                && held
                    .is_some_and(|held| held.count > recovery.watermark && held.retirement_usable);
            if !stage && !matches!(proof, Some(CurrentBindingCheck::Rejected(_))) {
                let reason = if recovery.fence.is_none() {
                    DiagnosticReason::AwaitingFence
                } else if !matches!(proof, Some(CurrentBindingCheck::Proven)) {
                    DiagnosticReason::BindingUnproven
                } else if held.is_some_and(|held| !held.retirement_usable) {
                    DiagnosticReason::CountInvalid
                } else {
                    DiagnosticReason::AwaitingFence
                };
                self.diagnostic_recovery_wait(key, &mut recovery, reason, held);
            }
            self.recoveries.insert(key, recovery);
            if stage && self.recovery_is_current(key, epoch) {
                let held = held.expect("stage has held observation");
                let recovery = self.recoveries.get(&key).expect("retained recovery");
                let caller = recovery.caller;
                let base = recovery.watermark;
                let since = recovery.fence.expect("stage has fence").anchor_ns;
                if self.stage_pending_count(
                    key,
                    caller,
                    std::slice::from_ref(&module),
                    held,
                    since,
                    base,
                ) {
                    self.recoveries
                        .get_mut(&key)
                        .expect("retained recovery")
                        .watermark = held.count;
                }
            }
        }
    }

    /// Drops one pair's counts (C7 C4): binder-unbound, or no module at
    /// all — held and later counts never publish. The drop still
    /// remembers the held absolute, so a later row rebinds past it
    /// instead of attributing pre-drop calls to a new owner (round 4,
    /// rebind).
    fn drop_pair_count(&mut self, row: &WitnessRow, reason: DiagnosticReason) {
        let key = PairKey::of(row);
        let (base, base_since) = self
            .pair_counts
            .get(&key)
            .map(|count| (count.count, count.anchor_ns))
            .unwrap_or((0, 0));
        if let Some(recorder) = &mut self.diagnostics {
            let held = self.pair_counts.get(&key).map(|held| held.read);
            let mut record = DiagnosticRecord::new(DiagnosticKind::CountDecision)
                .with_pair(key.diagnostic_key());
            record.pid = Some(row.host_tgid);
            record.decision = Some(DiagnosticDecision::Rejected);
            record.reason = Some(reason);
            record.absolute = Some(base);
            record.through = Some(base);
            record.context_unavailable = true;
            if let Some(held) = held {
                record.pre = Some(held.anchor_ns);
                record.post = Some(held.last_ns);
                record.observation_ref = nonzero_ref(held.diagnostic_observation);
                record.transition_ref = nonzero_ref(held.diagnostic_transition);
            }
            recorder.record(record);
        }
        self.pair_targets
            .insert(key, PairTarget::Dropped { base, base_since });
        self.pair_counts.remove(&key);
    }

    /// Stages one decided row against the modules its witness endpoint is
    /// admitted for. `Err` names a row whose endpoint resolves to no
    /// module.
    fn stage_witness(&mut self, decision: Decision) -> Result<(), String> {
        let Decision { row, binding } = decision;
        let modules = match self.witness_modules(&row) {
            Ok(modules) => modules,
            Err(reason) => {
                self.drop_pair_count(&row, DiagnosticReason::NotAdmitted);
                if let Binding::Unbound(unbound) = binding {
                    self.note_preadmission(row.host_tgid, &[None], unbound);
                }
                return Err(reason);
            }
        };
        match binding {
            Binding::Bound(caller) => {
                self.bind_pair_count(&row, caller, &modules);
                self.registry
                    .note_bound_witness(caller, modules, row.recorded_at_ns)
            }
            Binding::Unbound(reason) => {
                self.drop_pair_count(&row, diagnostic_binding_reason(reason));
                let keys: Vec<Option<ModuleKey>> = modules.iter().cloned().map(Some).collect();
                self.note_preadmission(row.host_tgid, &keys, reason);
                self.registry
                    .note_unbound_witness(modules, row.recorded_at_ns, reason)
            }
        }
        Ok(())
    }

    /// R-C51-1 (fail-safe): an unbound CALLER_USE row of `pid` — refused
    /// as `before_admission` or unmatched for any other reason — is the
    /// pair's only row ever (BPF inserts it `NOEXIST` and never deletes
    /// it), so a later use of that module by `pid` leaves no row and no
    /// watch of it can be a fact. Every caller record of `pid` (live or
    /// retired: a reused pid also downgrades, failing safe) reads
    /// `use_before_admission` on those modules, and so does any caller
    /// admitted with `pid` later (`stage_capture_coverage`) unless both
    /// start times are known and differ. Entries of exited or reused pids
    /// are pruned (R-C51-5) before the stash may overflow. Past the
    /// stash bound every caller of the scope reads it, with a gap. A row
    /// left unbound by lifecycle loss downgrades the same way but reads
    /// `loss` (R-C51-3): the loss, not an early use, is what it shows.
    fn note_preadmission(
        &mut self,
        pid: u32,
        modules: &[Option<ModuleKey>],
        unbound: UnboundReason,
    ) {
        let loss = unbound == UnboundReason::LifecycleLoss;
        let Some(capture) = self.capture.as_mut() else {
            return;
        };
        let stash = &mut capture.preadmission;
        if stash.overflowed {
            stash.refused += modules.len() as u64;
            return;
        }
        let source = self.adapter.source();
        // An entry of an earlier holder of this pid no longer applies.
        stash.prune_pid(pid, source);
        let mut fresh: Vec<Option<ModuleKey>> = Vec::new();
        for module in modules {
            let held = stash.entries.get(&pid).is_some_and(|entry| {
                entry.modules.contains_key(module) || entry.modules.contains_key(&None)
            });
            if held {
                continue;
            }
            if stash.len >= stash.limit {
                stash.prune(source);
            }
            if stash.len >= stash.limit {
                stash.overflowed = true;
                stash.refused += 1;
                self.registry.record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: "native pre-admission rows past their bound".into(),
                    reason: format!(
                        "more than {} (pid, module) pairs of unbound CALLER_USE rows: a caller's \
                         use before its admission can no longer be told apart, so every watch \
                         of this capture reads unknown use_before_admission",
                        stash.limit
                    ),
                    budget: None,
                });
                let callers: Vec<CallerId> =
                    self.adapter.records().map(|record| record.id).collect();
                for caller in callers {
                    self.registry.note_use_before_admission(caller, None);
                }
                return;
            }
            let entry = stash
                .entries
                .entry(pid)
                .or_insert_with(|| PreadmissionEntry {
                    start_time: source.start_time(pid),
                    modules: BTreeMap::new(),
                });
            entry.modules.insert(module.clone(), loss);
            stash.len += 1;
            fresh.push(module.clone());
        }
        if fresh.is_empty() {
            return;
        }
        let callers: Vec<CallerId> = self
            .adapter
            .records()
            .filter(|record| record.pid == pid)
            .map(|record| record.id)
            .collect();
        for caller in callers {
            for module in &fresh {
                self.downgrade(caller, module.clone(), loss);
            }
        }
    }

    fn downgrade(&mut self, caller: CallerId, module: Option<ModuleKey>, loss: bool) {
        if loss {
            self.registry
                .note_unbound_row_loss(caller, module, UNBOUND_ROW_LOSS);
        } else {
            self.registry.note_use_before_admission(caller, module);
        }
    }

    /// Whether R-C51-1 downgrades `caller`'s edge on `key`: `Some(loss)`.
    /// An entry stashed under another process's start time does not apply
    /// (R-C51-5); liveness is not consulted here — a caller that exits
    /// right after its maps were read still owes its downgrade.
    fn preadmission_holds(&self, caller: CallerId, pid: u32, key: &ModuleKey) -> Option<bool> {
        let stash = &self.capture.as_ref()?.preadmission;
        if stash.overflowed {
            return Some(false);
        }
        let entry = stash.entries.get(&pid)?;
        let caller_start = self
            .adapter
            .record(caller)
            .and_then(|record| record.start_time);
        if matches!(
            (entry.start_time, caller_start),
            (Some(stashed), Some(own)) if stashed != own
        ) {
            return None;
        }
        entry
            .modules
            .get(&None)
            .or_else(|| entry.modules.get(&Some(key.clone())))
            .copied()
    }

    /// The pre-admission stash's counters (R-C51-5), `None` without a
    /// native capture.
    pub(crate) fn preadmission_counters(&self) -> Option<PreadmissionCounters> {
        self.capture
            .as_ref()
            .map(|capture| capture.preadmission.counters())
    }

    /// The registry modules a row witnesses: every admitted module whose
    /// recorded membership holds the row's endpoint (the same endpoint set
    /// a watch negates). The endpoint must be the attach set's, in the
    /// row's object. No key equality is joined here: endpoints and their
    /// memberships come from the attach set's retained pins.
    fn witness_modules(&self, row: &WitnessRow) -> Result<Vec<ModuleKey>, String> {
        let endpoint = self
            .attach_set
            .endpoint(row.endpoint)
            .ok_or_else(|| format!("endpoint {} is not in the attach set", row.endpoint.0))?;
        if endpoint.object != row.object {
            return Err(format!(
                "endpoint {} belongs to another attach object than the row names",
                row.endpoint.0
            ));
        }
        self.admitted_modules_for_endpoint(row.endpoint)
    }

    /// The admitted modules recording `endpoint` as a member: distinct
    /// registry keys — one module never counts as two sharers. Shared
    /// by witness rows ([`Self::witness_modules`]) and count updates
    /// ([`Self::update_modules_for_endpoint`]).
    fn admitted_modules_for_endpoint(
        &self,
        endpoint: EndpointId,
    ) -> Result<Vec<ModuleKey>, String> {
        let modules: BTreeSet<ModuleKey> = self
            .attach_set
            .modules_with_member(endpoint)
            .filter(|key| {
                key.object.device.major != 0
                    || key.object.device.minor != 0
                    || key.object.inode != 0
            })
            .map(|key| {
                ModuleKey::physical(
                    key.object.device.major,
                    key.object.device.minor,
                    key.object.inode,
                    Some(key.sha256.clone()),
                    "",
                )
            })
            .collect();
        if modules.is_empty() {
            return Err(format!(
                "no admitted module records endpoint {} as a member",
                endpoint.0
            ));
        }
        Ok(modules.into_iter().collect())
    }

    /// A proven exec transition: the incarnation's image ended. The
    /// coordinator's ended-incarnation path mints one held handoff
    /// (`mint_pending_successor`) and commits it: immediately outside scope
    /// transactions, at the next fresh collection inside them. One the scan
    /// lane already retired needs nothing. A native owner gets the
    /// `ExecProof` the transition carries; a stale owner refuses the whole
    /// handoff while the old incarnation still retires.
    fn apply_exec_transition(
        &mut self,
        transition: ExecTransition,
        identity: &mut dyn NativeIdentity<Source::Pin>,
        now_ns: u64,
    ) -> Vec<CallerEvent> {
        let caller = transition.caller();
        let transition_pid = transition.pid();
        if matches!(self.engine.scope, Scope::Cgroup { .. }) {
            self.cgroup_fence.invalidate();
        }
        if let Some((collection, _)) = &mut self.pending_cgroup {
            collection.invalidate(transition_pid);
        }
        // The binder emits a transition only for the live incarnation that
        // held the row's tgid, so the pid matches by construction; whether
        // that incarnation is still live is what may have changed since.
        let live = self
            .adapter
            .record(caller)
            .is_some_and(|record| !record.retired);
        if !live {
            return Vec::new();
        }
        if let Some(owner) = self.owners.get(&caller).copied()
            && let Err(error) = self.engine.request_inventory_refresh(
                owner,
                RefreshCause::ValidatedExec(ExecProof::from_transition(owner, transition)),
            )
        {
            self.registry.record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: Some(transition_pid),
                subject: "native exec proof not applied".into(),
                reason: format!("{error:#}; the caller incarnation still retires"),
                budget: None,
            });
            // A stale owner refuses the handoff: the image end is fact (the
            // old incarnation retires) but no successor is minted for it.
            return self.adapter.exec_transition_scoped(caller, now_ns);
        }
        if self.stopped {
            // Stop wins before successor admission: the old incarnation
            // still retires on the proven image end, but no handoff is
            // minted and no retry is scheduled.
            self.registry.record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: Some(transition_pid),
                subject: "successor admission refused while stopped".into(),
                reason: "the coordinator stopped; the proved old incarnation retires \
                     without a successor and no retry is scheduled"
                    .into(),
                budget: None,
            });
            return self.adapter.exec_transition_scoped(caller, now_ns);
        }
        if self.mint_pending_successor(transition, now_ns).is_none() {
            // Defensive only: live callers never hold a handoff and never
            // lack their pin. Refuse rather than double-mint.
            return self.adapter.exec_transition_scoped(caller, now_ns);
        }
        if matches!(self.engine.scope, Scope::Cgroup { .. }) {
            // An out-of-scope exec ends the old image but cannot admit its
            // successor: re-entry needs a new current-scope transaction,
            // which commits the held handoff.
            return vec![self.adapter.retired_event(caller)];
        }
        let mut resolver = AuthorityResolver {
            engine: &mut self.engine,
            pending: &mut self.pending_owners,
            guard: &mut super::inventory::UnavailableImageGuard,
            identity,
            native_failures: Vec::new(),
            scan_pinned: 0,
        };
        let authority = resolver.resolve(transition_pid);
        let (native_failures, scan_pinned) = resolver.finish();
        self.record_authority_gaps(native_failures, scan_pinned);
        self.commit_pending_successor(caller, authority, now_ns)
    }

    /// Mint one held exec handoff for a proven transition (H6 slice 2).
    /// The sole minter: `apply_exec_transition` is the only caller. The
    /// original held pin moves into the handoff first, then the old
    /// incarnation retires; at most one handoff per ended caller. `None`
    /// when one is already held or custody is gone (both defensive: live
    /// callers hold neither state).
    fn mint_pending_successor(&mut self, transition: ExecTransition, now_ns: u64) -> Option<()> {
        let caller = transition.caller();
        if self.pending_successors.contains_key(&caller) {
            self.registry.record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: Some(transition.pid()),
                subject: "duplicate exec handoff refused".into(),
                reason: "an exec handoff is already held for this caller; \
                     at most one successor commits per ended caller"
                    .into(),
                budget: None,
            });
            return None;
        }
        let Some((pid, pin)) = self.adapter.retire_for_exec_handoff(caller, now_ns) else {
            self.registry.record_gap(RegistryGap {
                caller: Some(caller),
                module: None,
                pid: Some(transition.pid()),
                subject: "exec handoff without custody refused".into(),
                reason: "the live incarnation holds no pin to hand over; \
                     the successor is never reopened by scalar PID"
                    .into(),
                budget: None,
            });
            return None;
        };
        let old_incarnation = self
            .adapter
            .record(caller)
            .expect("the retired caller retains its record")
            .incarnation;
        self.pending_successors.insert(
            caller,
            PendingExecSuccessor {
                old: caller,
                old_incarnation,
                pid,
                custody: pin,
                mint_start: self.adapter.source().start_time(pid),
                mint_exe: self.adapter.source().exe_identity(pid),
                transition,
            },
        );
        Some(())
    }

    /// Commit one held exec handoff: the fresh admission transaction (H6
    /// slice 2). Unscoped commits run here; the scoped collection commit
    /// verifies through `verify_pending_successor` under its own permit.
    /// The handoff is consumed either way; every refusal is an honest
    /// event, never silent.
    fn commit_pending_successor(
        &mut self,
        old: CallerId,
        authority: ImageAuthority,
        now_ns: u64,
    ) -> Vec<CallerEvent> {
        let Some(pending) = self.pending_successors.remove(&old) else {
            return Vec::new();
        };
        let pid = pending.pid;
        match self.verify_pending_successor(&pending) {
            Ok(Some(_)) => {
                // An already-admitted same-incarnation candidate stands on
                // its own admission; the handoff links to it by retirement
                // order (same pid, next incarnation) without minting again.
                Vec::new()
            }
            Ok(None) => {
                match self
                    .adapter
                    .admit_retained_successor(pid, pending.custody, authority, now_ns)
                {
                    Ok(new) => vec![CallerEvent::ExecRetired { old, new }],
                    Err(failure) => vec![CallerEvent::AdmitFailed {
                        pid,
                        reason: format!("post-exec re-admission failed: {}", failure.reason),
                        budget: failure.budget,
                    }],
                }
            }
            Err(failure) => vec![CallerEvent::AdmitFailed {
                pid,
                reason: failure.reason,
                budget: failure.budget,
            }],
        }
    }

    /// Verify one held handoff against current truth (H6 slice 2): the
    /// ended incarnation is unchanged since mint, original custody still
    /// holds the same process, and no newer image or generation arrived
    /// before commit. Returns the adoptable live candidate when one
    /// already holds this pid's current incarnation — pid equality alone
    /// never selects it.
    fn verify_pending_successor(
        &self,
        pending: &PendingExecSuccessor<Source::Pin>,
    ) -> Result<Option<CallerId>, AdmitFailure> {
        let failed = |reason: &str| AdmitFailure {
            reason: reason.into(),
            budget: None,
        };
        // The held evidence names this handoff's ended incarnation (the
        // binder's domain-carrying proof; never rendered, only matched).
        if pending.transition.caller() != pending.old || pending.transition.pid() != pending.pid {
            return Err(failed(
                "stale exec handoff: the held transition names another incarnation",
            ));
        }
        let unchanged = self.adapter.record(pending.old).is_some_and(|record| {
            record.retired
                && record.pid == pending.pid
                && record.incarnation == pending.old_incarnation
        });
        if !unchanged {
            return Err(failed(
                "stale exec handoff: the ended incarnation changed since the handoff was minted",
            ));
        }
        if !self.adapter.source().still_the_same(&pending.custody) {
            return Err(failed(
                "original process custody lost: the process exited or the pid was reused",
            ));
        }
        if self.adapter.source().start_time(pending.pid) != pending.mint_start
            || self.adapter.source().exe_identity(pending.pid) != pending.mint_exe
        {
            return Err(failed(
                "stale exec handoff: a newer image or generation arrived before commit; \
                 the stale candidate is rejected and the renewed request services separately",
            ));
        }
        if let Some(live) = self.adapter.live_id(pending.pid) {
            let adoptable = self.adapter.record(live).is_some_and(|record| {
                !record.retired
                    && record.start_time == pending.mint_start
                    && record.exe == pending.mint_exe
            });
            if !adoptable {
                return Err(failed(
                    "the pid's live caller is not this handoff's current incarnation; \
                     pid equality alone never adopts it",
                ));
            }
            return Ok(Some(live));
        }
        Ok(None)
    }

    /// Release held exec handoffs whose original custody died (H6 slice
    /// 2): a dead pin can never commit, so the handoff drops now instead
    /// of holding its FD for a re-entry that cannot come. Live-but-absent
    /// handoffs stay held: the member may re-enter.
    fn release_dead_handoffs(&mut self) {
        let dead: Vec<CallerId> = self
            .pending_successors
            .iter()
            .filter(|(_, pending)| !self.adapter.source().still_the_same(&pending.custody))
            .map(|(old, _)| *old)
            .collect();
        for old in dead {
            if let Some(pending) = self.pending_successors.remove(&old) {
                self.registry.record_gap(RegistryGap {
                    caller: Some(old),
                    module: None,
                    pid: Some(pending.pid),
                    subject: "held exec handoff released".into(),
                    reason: "original process custody died while the handoff was held; \
                         no successor commits and the pin is released"
                        .into(),
                    budget: None,
                });
            }
        }
    }

    /// Stop the coordinator (H6 slice 2): no new scan, attach,
    /// successor/name admission, or retry starts afterwards. Held exec
    /// handoffs release their custody now; staged facts still drain
    /// through `commit_batch`.
    #[cfg_attr(not(test), allow(dead_code))] // Production stop wiring lands with the runtime consumer.
    pub(crate) fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let held = self.pending_successors.len();
        self.pending_successors.clear();
        if held > 0 {
            self.registry.record_gap(RegistryGap {
                caller: None,
                module: None,
                pid: None,
                subject: "held exec handoffs released at stop".into(),
                reason: format!(
                    "{held} held exec handoff(s) released their custody at stop; \
                     no successor commits and no retry is scheduled"
                ),
                budget: None,
            });
        }
    }

    /// The I4b batch: the engine tail and the registry publish as one
    /// synchronous step. Facts from every scan since the last commit are
    /// invisible before this returns and visible after — the ordering
    /// the Phase 2 test pins, extended to caller/edge facts.
    pub(crate) fn commit_batch(&mut self, engine_changed: bool) -> Result<BatchReceipt> {
        self.commit_batch_inner(engine_changed, None)
    }

    /// The commit with an attested Detailed lane: pending semantic batches
    /// finalize after all reconciliation/catalog work and immediately
    /// before registry publication. `commit_batch` delegates with `None`.
    pub(crate) fn commit_batch_with_semantics(
        &mut self,
        engine_changed: bool,
        lane: Option<&mut AttestedSemanticLane>,
    ) -> Result<BatchReceipt> {
        self.commit_batch_inner(engine_changed, lane)
    }

    fn commit_batch_inner(
        &mut self,
        engine_changed: bool,
        lane: Option<&mut AttestedSemanticLane>,
    ) -> Result<BatchReceipt> {
        // Original cgroup custody is still in self during the fallible engine
        // tail. Scoped preparation/staging then has no later fallible tail.
        self.engine.publish_batch_tail(engine_changed)?;
        // Fresh per-publication proof tracking for the tail adjudication.
        // Tail bits are NOT cleared here: they join this publication's
        // cut directly, and drain in the finalizer either way.
        self.complete_scanned.clear();
        let mut publishing_cgroup = self.pending_cgroup.take();
        let mut scoped_events = Vec::new();
        let mut scoped_admitted = 0;
        let mut scoped_scan_callers = 0;
        let mut cgroup_proof_complete = false;
        if let Some((collection, now_ns)) = &mut publishing_cgroup {
            // Dead custody can never re-enter: release those handoffs
            // before the transaction prepares anything.
            self.release_dead_handoffs();
            // At most one held handoff commits per pid in a transaction.
            let mut handoff_pids = BTreeMap::new();
            for (old, pending) in &self.pending_successors {
                let previous = handoff_pids.insert(pending.pid, *old);
                debug_assert!(previous.is_none(), "at most one held handoff per pid");
            }
            let work = collection.work();
            let pids: Vec<u32> = if work.charge(
                collection
                    .member_pids()
                    .count()
                    .saturating_mul(2)
                    .saturating_add(1),
            ) {
                collection.member_pids().collect() // private cap128; charged before allocation
            } else {
                Vec::new()
            };
            let mut prepared = BTreeMap::new();
            let mut prepared_handoffs = BTreeMap::new();
            for pid in pids {
                if !work.charge(6) {
                    break;
                }
                if let Some(&old) = handoff_pids.get(&pid) {
                    // Handoff members never take the ordinary fresh-open
                    // path: verify the held handoff against current truth
                    // and require the walk to show its current image.
                    // Anything unproven here stays held silently for a
                    // fresher walk; only terminal refusals consume.
                    let Some(pending) = self.pending_successors.get(&old) else {
                        continue;
                    };
                    let verified = self.verify_pending_successor(pending);
                    let (mint_start, mint_exe) = (pending.mint_start, pending.mint_exe.clone());
                    if let Err(failure) = verified {
                        self.pending_successors.remove(&old);
                        collection.preparation_failed();
                        scoped_events.push(CallerEvent::AdmitFailed {
                            pid,
                            reason: failure.reason,
                            budget: failure.budget,
                        });
                        continue;
                    }
                    let Some(preparation) = collection.preparation(pid) else {
                        continue;
                    };
                    if preparation.generation().start_time == mint_start
                        && preparation.generation().exe == mint_exe
                    {
                        prepared_handoffs.insert(pid, old);
                    }
                    continue;
                }
                let Some(preparation) = collection.preparation(pid) else {
                    continue;
                };
                match self.adapter.prepare_scoped_caller(&preparation) {
                    Ok(pin) => {
                        prepared.insert(pid, pin);
                    }
                    Err(failure) => {
                        collection.preparation_failed();
                        scoped_events.push(CallerEvent::AdmitFailed {
                            pid,
                            reason: failure.reason,
                            budget: failure.budget,
                        });
                    }
                }
            }
            // Prepare every provider read while retaining exclusive attach-set
            // custody. No aliases/endpoints/memberships are published here.
            let provider = if collection.reserve_projection(self.registry.edge_count()) {
                match self
                    .attach_set
                    .prepare_absorption(collection.provider_inputs(), |units| work.charge(units))
                {
                    Ok(provider) => Some(provider),
                    Err(reason) => {
                        collection.preparation_incomplete();
                        self.registry.record_gap(RegistryGap {
                            caller: None,
                            module: None,
                            pid: None,
                            subject: "cgroup provider preparation incomplete".into(),
                            reason,
                            budget: None,
                        });
                        None
                    }
                }
            } else {
                None
            };
            let requested = if provider.is_some()
                && work.charge(
                    prepared
                        .len()
                        .saturating_add(prepared_handoffs.len())
                        .saturating_mul(8)
                        .saturating_add(1),
                ) {
                prepared
                    .keys()
                    .copied()
                    .chain(prepared_handoffs.keys().copied())
                    .collect()
            } else {
                BTreeSet::new()
            };
            collection.sample_end(&requested);
            let mut allowed = BTreeSet::new();
            for (pid, pin) in prepared {
                let Some(permit) = collection.permit(pid) else {
                    continue;
                };
                match self.adapter.commit_scoped_caller(pin, permit, *now_ns) {
                    Ok((id, admitted)) => {
                        allowed.insert(pid);
                        if admitted {
                            scoped_admitted += 1;
                            scoped_events.push(CallerEvent::Admitted { id });
                        }
                    }
                    Err(failure) => scoped_events.push(CallerEvent::AdmitFailed {
                        pid,
                        reason: failure.reason,
                        budget: failure.budget,
                    }),
                }
            }
            // Held handoffs commit under their own exact member permits:
            // borrow the permit, commit the moved custody, finish. No
            // permit this transaction holds the handoff for a fresher one.
            for (pid, old) in prepared_handoffs {
                let Some(pending) = self.pending_successors.remove(&old) else {
                    continue;
                };
                let Some(permit) = collection.permit(pid) else {
                    self.pending_successors.insert(old, pending);
                    continue;
                };
                match self
                    .adapter
                    .commit_handoff_caller(pid, pending.custody, permit, *now_ns)
                {
                    Ok((new, admitted)) => {
                        allowed.insert(pid);
                        if admitted {
                            scoped_admitted += 1;
                            scoped_events.push(CallerEvent::ExecRetired { old, new });
                        }
                    }
                    Err(failure) => scoped_events.push(CallerEvent::AdmitFailed {
                        pid,
                        reason: failure.reason,
                        budget: failure.budget,
                    }),
                }
            }
            scoped_scan_callers = allowed.len();
            let mut catalog = collection.catalog(&allowed);
            let absorbed = match (provider, catalog.lowering.take()) {
                (Some(provider), Some(lowering)) => {
                    match provider
                        .absorb(&lowering.plan, &lowering.pins, |units| work.charge(units))
                    {
                        Ok(absorbed) => Some(absorbed),
                        Err(reason) => {
                            collection.preparation_incomplete();
                            self.registry.record_gap(RegistryGap {
                                caller: None,
                                module: None,
                                pid: None,
                                subject: "cgroup provider consumption incomplete".into(),
                                reason,
                                budget: None,
                            });
                            None
                        }
                    }
                }
                _ => None,
            };
            // The prepared guard has been consumed/dropped, so ordinary staging
            // can borrow the coordinator again. It performed no provider reads.
            self.apply_reconcile_events(&scoped_events, *now_ns);
            let verdicts =
                absorbed.map_or_else(BTreeMap::new, |absorbed| self.record_absorbed(absorbed));
            self.project_catalog(&catalog, &verdicts, *now_ns);
            self.registry.record_gap(RegistryGap { caller: None, module: None, pid: None,
                subject: "scoped native owner admission deferred".into(),
                reason: "native owner activation and refresh cannot yet be enclosed by the final cgroup membership bracket; sampled scan-pinned callers and retained native totals remain available".into(), budget: None });
            let outcome = collection.outcome(); // final cancellation/deadline poll
            if outcome != ScopedCollectionOutcome::Complete {
                self.registry.record_gap(RegistryGap {
                    caller: None,
                    module: None,
                    pid: None,
                    subject: "cgroup scope transaction incomplete".into(),
                    reason: outcome.reason().into(),
                    budget: None,
                });
            } else {
                cgroup_proof_complete = true;
            }
        }
        // Provisional adjudication runs at the end of the commit's catalog
        // work, before any semantic input stages: suppression needs a
        // complete publication's proof, never less.
        self.adjudicate_provisional_unscanned(cgroup_proof_complete);
        // Semantic finalization runs after all reconciliation/catalog work
        // and immediately before registry publication: negatives first,
        // validated registrations second, eligible calls in position
        // order. No semantic positive sits ahead of a physical decision.
        self.finalize_semantic_batches(lane);
        // Pure projection performs no additional generation/admission reads.
        // Keep the original handles through this actual publication call.
        let registry_applied = if let Some(recorder) = &mut self.diagnostics {
            let adapter = &self.adapter;
            self.registry
                .publish_with_count_observer(Some(&mut |count: CountPublication| {
                    let mut record = DiagnosticRecord::new(DiagnosticKind::Publication);
                    record.caller = Some(count.caller.0);
                    if let Some(caller) = adapter.record(count.caller) {
                        record.pid = Some(caller.pid);
                        record.incarnation = Some(u64::from(caller.incarnation));
                    }
                    record.module = count.module.map(|module| module.0);
                    record.staged = Some(count.staged);
                    record.base = Some(count.base);
                    record.edge_total = count.edge_total;
                    // The registry mutation has no genuine raw pair/read reference.
                    record.reason = Some(DiagnosticReason::ContextUnavailable);
                    record.context_unavailable = true;
                    recorder.record(record);
                }))
        } else {
            self.registry.publish()
        };
        self.finalize_pending_counts();
        if let Some((collection, _)) = publishing_cgroup {
            let (state, outcome) = collection.finish();
            self.completed_cgroup = Some(CgroupCompletion {
                state,
                outcome,
                events: scoped_events,
                admitted: scoped_admitted,
                scan_callers: scoped_scan_callers,
            });
        }
        Ok(BatchReceipt {
            engine_facts: self.engine.facts_revision,
            engine_published: self.engine.published_facts_revision,
            registry_facts: self.registry.facts_revision(),
            registry_published: self.registry.published_revision(),
            registry_applied,
        })
    }
}

/// One native input for `stage_native` (plan §3.6). S2/S3 add an object
/// fact variant here.
#[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 constructs them.
pub(crate) enum NativeBatch {
    /// One witness read of a capture domain (rows, health, custody).
    Witness(Box<WitnessBatch>),
    /// One lifecycle quantum, tagged by the facade with the domain it was
    /// drained from and stamped with its own drain instants (the binder
    /// orders evidence by those stamps, never by call order).
    Lifecycle(DiscoveryBatch),
    /// No later lifecycle or health evidence will arrive for `domain` (its
    /// capture retired): every row of that domain still waiting is decided
    /// unbound. Pass the retired facade's `domain()`.
    Finish { domain: NativeDomainId },
    /// One owned lane batch (H0 outcomes, current-partition receipts and
    /// lane negatives) queued for finalization after the commit tail.
    Semantic(SemanticBatch),
}

/// What one `stage_native` call did.
#[derive(Debug, Default)]
#[cfg_attr(not(test), allow(dead_code))] // Task 6 C5 reads it.
pub(crate) struct NativeReceipt {
    /// Incarnation changes the native lane made (exec transitions), for the
    /// event stream; already staged in the registry.
    pub events: Vec<CallerEvent>,
    /// Rows decided by this call.
    pub decided: usize,
}

/// One CALLER_USE pair (C7 C4): the image that owns the row plus the
/// object it names. A row and its refresh counts join on this: the
/// cookie is domain-tagged (tickets are per-domain), the exec sequence
/// disambiguates the ticket's images, and the object is the map key's
/// (`u32`: `AttachObjectId` has no hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PairKey {
    image: DomainCookie,
    exec: u64,
    object: u32,
}

impl PairKey {
    fn of(row: &WitnessRow) -> Self {
        Self {
            image: row.cookie(),
            exec: row.exec_id(),
            object: row.object.index(),
        }
    }

    fn diagnostic_key(self) -> NativePairKey {
        NativePairKey::new(self.image, self.exec, self.object)
    }

    fn of_update(domain: NativeDomainId, update: &CallerCountUpdate) -> Self {
        Self {
            image: DomainCookie::new(domain, update.image.task_cookie),
            exec: update.image.exec_id,
            object: update.object.index(),
        }
    }
}

/// The latest known count of one pair (C7 C4): an absolute saturating
/// lower bound since the pair's first record, with the read that
/// observed it. First-sight `entry_count` and refresh counts merge by
/// maximum, so any arrival order stages the same count.
#[derive(Debug, Clone, Copy)]
struct PairCount {
    count: u64,
    first_ns: u64,
    /// Batch PRE lower bound on the lookup that observed this absolute.
    /// Kept separately from POST observation time when it becomes a base.
    anchor_ns: u64,
    last_ns: u64,
    /// The original strict advance had a valid, healthy observation bracket.
    retirement_usable: bool,
    diagnostic_observation: u64,
    diagnostic_transition: u64,
}

/// Poll suppression belongs only to the mutable held entry, not immutable reads.
#[derive(Debug, Clone, Copy)]
struct HeldPairCount {
    read: PairCount,
    diagnostic_last_raw: Option<u64>,
    diagnostic_refusal: Option<(DiagnosticReason, u64, u64)>,
}
impl HeldPairCount {
    fn new(read: PairCount) -> Self {
        Self {
            read,
            diagnostic_last_raw: None,
            diagnostic_refusal: None,
        }
    }
}
impl std::ops::Deref for HeldPairCount {
    type Target = PairCount;
    fn deref(&self) -> &Self::Target {
        &self.read
    }
}
impl std::ops::DerefMut for HeldPairCount {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.read
    }
}

/// Rebase one held absolute count past `base` (F3-03): what stages is
/// only growth past the accounted absolute. The first sight travels
/// with the base: an unbased count keeps the pair's first record,
/// while rebased growth starts at the observing read — a new owner
/// never inherits the pair's backdated history.
fn rebased_count(count: PairCount, base: u64) -> PairCount {
    PairCount {
        count: count.count.saturating_sub(base),
        first_ns: if base == 0 {
            count.first_ns
        } else {
            count.last_ns
        },
        anchor_ns: count.anchor_ns,
        last_ns: count.last_ns,
        retirement_usable: count.retirement_usable,
        diagnostic_observation: count.diagnostic_observation,
        diagnostic_transition: count.diagnostic_transition,
    }
}

fn valid_retirement_refresh(batch: &WitnessBatch, count: u64) -> bool {
    batch.counts_read_ns > 0
        && batch.rows_read_ns >= batch.counts_read_ns
        && batch.rows_read_ns != u64::MAX
        && count < u64::MAX
        && batch.health_unproven.is_none()
        && batch.health_regression.is_none()
        && batch.read_failures.is_empty()
        && !batch.refresh_sweep_gaps
        && !batch.refresh_deadline_reached
}

/// Where one decided pair's counts go (C7 C4).
#[derive(Debug, Clone)]
enum PairTarget {
    /// The pair bound to `caller` and its witness resolved to exactly
    /// one edged module: counts stage there — after re-resolving the
    /// endpoint's placement (F7), since sharing that appeared after
    /// the pair bound makes further growth ambiguous. `base` is the
    /// absolute count accounted so far (placed or disclosed; folded
    /// from `staged` at every placement and every confirmed staging):
    /// only growth past it ever
    /// stages, so a re-resolved pair never duplicates history
    /// elsewhere (F3-03), and a re-place onto the history holder
    /// accumulates onto its edge instead of `max`ing growth against
    /// history (round 4, re-place). `staged` is the absolute count
    /// staged so far (including in-flight stagings this publication
    /// has not applied yet): demotion re-roots at it, so in-flight
    /// growth is never staged twice.
    Bound {
        caller: CallerId,
        module: ModuleKey,
        endpoint: EndpointId,
        base: u64,
        staged: u64,
        /// The PRE bound on the read that observed `staged`:
        /// demotion re-roots the base (and its anchor) here.
        staged_ns: u64,
        /// The PRE bound on the read that observed `base`:
        /// demoted growth stages with this as its coverage anchor, so
        /// the ledger window covers the segment the growth executed
        /// in. 0 only when `base` is 0 (nothing accounted yet).
        base_since: u64,
    },
    /// The pair bound to `caller` and waiting on its publication-time
    /// placement: counts stage pending and resolve at publication,
    /// together with the witness. `staged` is the absolute count
    /// staged so far, so only advances re-stage; `base` is the
    /// absolute count accounted so far (0 for a first-sight pair, the
    /// demoted total for a re-resolved one): only growth past it
    /// stages. The publication's decisions finalize it as
    /// [`Self::Bound`] (folding `staged` into the new base) or
    /// [`Self::Dropped`]; an unadmitted single stays pending and
    /// re-resolves on the next advance.
    Pending {
        caller: CallerId,
        modules: Vec<ModuleKey>,
        staged: u64,
        /// The PRE bound on the read that observed `staged`:
        /// finalization folds it into the new base's anchor.
        staged_ns: u64,
        endpoint: EndpointId,
        base: u64,
        /// The PRE bound on the read that observed `base`:
        /// demoted growth stages with this as its coverage anchor.
        /// The pair's first record while unbased.
        base_since: u64,
    },
    /// The pair never publishes from here: binder-unbound, no module
    /// at all, or a rejected publication. Held and later counts drop —
    /// but `base` remembers the absolute count through the drop
    /// (attributed or disclosed history), so a later witness row for
    /// the same pair rebinds past it instead of re-absorbing it (round
    /// 4, rebind). `base_since` is the PRE bound for the `base` read: a
    /// revival's growth windows from the drop.
    Dropped { base: u64, base_since: u64 },
    /// Exact, previously placed history remains; future ownership needs a fresh fence.
    Suspended {
        caller: CallerId,
        endpoint: EndpointId,
        base: u64,
        base_since: u64,
    },
}

/// One immutable publication request. A decision cannot borrow a newer held maximum.
struct PendingCountObservation {
    key: PairKey,
    caller: CallerId,
    endpoint: EndpointId,
    observation: PairCount,
    generation: Option<u64>,
    origin: PendingCountOrigin,
    diagnostic: Option<PendingDiagnostics>,
}

#[derive(Clone, Copy)]
enum PendingCountOrigin {
    Untracked,
    Ordinary(u64),
    Recovered(OwnershipEpoch),
}

/// Fixed-size recovery state per exact pair with successfully placed history.
struct PairRecovery {
    caller: CallerId,
    endpoint: EndpointId,
    carrier: ModuleId,
    /// Frozen with this exact pair's original ordinary observation. Historical
    /// handles never refresh it; selected recovery has its independent epoch.
    ordinary_checkpoint: u64,
    epoch: Option<OwnershipEpoch>,
    scan: Option<Arc<OwnershipScan>>,
    sighting: Option<CurrentBindingSighting>,
    /// Ownership-selected original read. Retention is unproven: until a genuine
    /// sighting exists it causes no accounting, gap or allocation side effect.
    /// Only the subsequent Proven binding check permits new-owner allocation.
    fence: Option<PairCount>,
    pending_reads: [Option<TaggedCountRead>; 3],
    /// Actual saved obsolete reads can justify an unknown prefix after any
    /// historical generic predecessor finishes. At/below watermark it is only
    /// normalized storage: watermark may include an immutable staged request,
    /// not successful placement. Only its excess can be new unknown coverage.
    /// This never supplies a fence.
    withheld_through: u64,
    /// Conditional actual detached reads: no known loss or read authority.
    /// Current logical-epoch classification precedes any historical conversion.
    discarded_through: u64,
    watermark: u64,
    blocked: bool,
    recovered: bool,
    deferred_count: bool,
    receipt_refused: bool,
    /// Selected ownership may wait for original generic publication handles.
    /// Its placement generation and target are untouched until those finish.
    epoch_pending: bool,
    diagnostic: RecoveryDiagnostics,
}

#[derive(Clone, Copy)]
struct PendingDiagnostics {
    base: u64,
    staged: u64,
    since: u64,
    baseline_post: u64,
    fence: u64,
    transition_ref: u64,
}

#[derive(Default)]
struct RecoveryDiagnostics {
    ownership: Option<(Eligibility, Option<ModuleId>, Option<u64>)>,
    transition_ref: u64,
    wait: Option<(DiagnosticReason, DiagnosticDecision, u64, u64, u64)>,
    selection: Option<(Option<u64>, u64, bool)>,
}

fn record_recovery_refusal<Source: ProcessSource>(
    recorder: &mut Recorder,
    adapter: &CallerAdapter<Source>,
    key: PairKey,
    recovery: &mut PairRecovery,
    reason: DiagnosticReason,
) {
    let mut record = DiagnosticRecord::new(DiagnosticKind::OwnershipTransition)
        .with_pair(key.diagnostic_key())
        .with_private_ids(None, recovery.epoch.map(|epoch| epoch.0), None);
    record.caller = Some(recovery.caller.0);
    if let Some(caller) = adapter.record(recovery.caller) {
        record.pid = Some(caller.pid);
        record.incarnation = Some(u64::from(caller.incarnation));
    }
    record.reason = Some(reason);
    record.new_eligibility = Some(Eligibility::Unknown);
    record.base = Some(recovery.watermark);
    record.transition_ref = nonzero_ref(recovery.diagnostic.transition_ref);
    record.context_unavailable = true;
    recovery.diagnostic.transition_ref = recorder.record(record).unwrap_or(0);
}

fn diagnostic_binding_reason(reason: UnboundReason) -> DiagnosticReason {
    match reason {
        UnboundReason::CookieUnavailable
        | UnboundReason::ExecCoverageGap
        | UnboundReason::EvidenceIncomplete => DiagnosticReason::BindingUnproven,
        UnboundReason::LifecycleLoss => DiagnosticReason::CaptureLoss,
        UnboundReason::Capacity => DiagnosticReason::BudgetRefused,
        _ => DiagnosticReason::IdentityChanged,
    }
}

fn nonzero_ref(seq: u64) -> Option<u64> {
    (seq != 0).then_some(seq)
}

struct TaggedCountRead {
    scan: Arc<OwnershipScan>,
    read: PairCount,
}
impl PairRecovery {
    fn clear_reads(&mut self) {
        self.pending_reads = [None, None, None];
        self.withheld_through = self.watermark;
        self.discarded_through = self.watermark;
    }
    fn withhold_reads(&mut self) {
        for slot in &mut self.pending_reads {
            if let Some(tag) = slot.take() {
                self.discarded_through = self.discarded_through.max(tag.read.count);
            }
        }
    }
    fn normalize_reads(
        &mut self,
        view: &ReceiptView<'_>,
        continuing: bool,
        work: &mut ReceiptWork,
    ) {
        if continuing {
            // Only speculative D is resolved by proven current continuation.
            // Independently justified old H remains until predecessor settlement.
            self.discarded_through = self.watermark;
        }
        let mut retained = 0;
        for slot in &mut self.pending_reads {
            work.visit();
            let Some(tag) = slot else { continue };
            let disposition = view.disposition(&tag.scan, work);
            work.visit();
            let selected_equivalent = self
                .scan
                .as_ref()
                .is_some_and(|scan| tag.scan.equivalent(scan));
            if disposition == ReceiptDisposition::Retained
                && selected_equivalent
                && self.fence.is_some()
            {
                work.visit();
                if let Some(fence) = self.fence.as_mut()
                    && tag.read.count < fence.count
                {
                    if fence.count > self.watermark {
                        // Full read and brackets move together before first use.
                        *fence = tag.read;
                        if self
                            .scan
                            .as_ref()
                            .is_none_or(|scan| tag.scan.started_ns() < scan.started_ns())
                        {
                            self.scan = Some(tag.scan.clone());
                        }
                    } else {
                        self.receipt_refused = true;
                        self.deferred_count = true;
                    }
                }
                *slot = None;
                continue;
            }
            if disposition == ReceiptDisposition::Obsolete || tag.read.count <= self.watermark {
                work.visit();
                if !continuing && tag.read.count > self.watermark {
                    self.discarded_through = self.discarded_through.max(tag.read.count);
                }
                *slot = None;
            } else {
                retained += 1;
            }
        }
        // The slot visits already established cardinality. Empty/singleton
        // sets have no pair comparison to perform. With the added continuity
        // guards, the full capture/service branch still fits 32 operations.
        if retained < 2 {
            return;
        }
        // Three constant comparisons, never a position-based overwrite.
        for (left, right) in [(0, 1), (0, 2), (1, 2)] {
            work.visit();
            let equal = match (&self.pending_reads[left], &self.pending_reads[right]) {
                (Some(left), Some(right)) => {
                    Arc::ptr_eq(&left.scan, &right.scan) || left.scan.equivalent(&right.scan)
                }
                _ => false,
            };
            if equal {
                work.visit();
                let right = self.pending_reads[right]
                    .take()
                    .expect("equal occupied tag");
                let left = self.pending_reads[left]
                    .as_mut()
                    .expect("equal occupied tag");
                if right.read.count < left.read.count {
                    left.read = right.read;
                }
                if right.scan.started_ns() < left.scan.started_ns() {
                    left.scan = right.scan;
                }
            }
        }
    }
    fn take_read(
        &mut self,
        scan: &Arc<OwnershipScan>,
        work: &mut ReceiptWork,
    ) -> Option<TaggedCountRead> {
        let mut selected = None;
        for index in 0..3 {
            work.visit();
            if self.pending_reads[index]
                .as_ref()
                .is_some_and(|tag| tag.scan.equivalent(scan))
            {
                selected = Some(index);
            }
        }
        selected.and_then(|index| {
            work.visit();
            self.pending_reads[index].take()
        })
    }
}

/// Per-endpoint attach state from the capture facade's receipts. Bounded by
/// the endpoint budget N: each endpoint is attached or failed at most once.
struct CaptureCoverage {
    scope: CaptureScopeCoverage,
    /// The first caller proven to be the scope incarnation.
    bound: Option<CallerId>,
    attached_at: BTreeMap<EndpointId, u64>,
    /// Sticky: a failed endpoint is never retried, so its modules never
    /// read watched.
    failed: BTreeSet<EndpointId>,
    /// Sticky: coverage is unproven from here on (PID custody lost, an
    /// exec or leader exit of the PID target, lifecycle loss — PID or
    /// system scope).
    unproven: Option<String>,
    /// Sticky: objects modified in place after they were attached.
    changed_objects: BTreeSet<AttachObjectId>,
    /// The last witness batch's unproven health (not sticky).
    health_unproven: Option<String>,
    /// Sticky: the WatchedNoUse pair precondition failed (the seen set is
    /// full, or a row went unrecorded): no read proves no-use again, so
    /// no watch starts and no read extends one (C5.2).
    pairs_unproven: Option<String>,
    /// Sticky: CALLER_EVIDENCE showed a pair insert failure (C7 C4), so
    /// some pair has use but no row and absence proves nothing: edges
    /// without positive history read `uncounted` and no watch starts
    /// again. The map never deletes, so a full map stays full.
    pairs_uncounted: Option<Arc<str>>,
    /// The latest witness read with proven health, no rise, and held
    /// custody: where a watch ends at stop.
    last_clean_ns: Option<u64>,
    /// The health read of the batch the open CALLER_USE sweep began in
    /// (`None`: the next batch begins one).
    sweep_began_ns: Option<u64>,
    /// Pids of unbound CALLER_USE rows (R-C51-1): their callers' watches
    /// on the rows' modules read `use_before_admission`, whichever is
    /// staged first, the row or the caller's admission.
    preadmission: PreadmissionStash,
    stopped: bool,
}

/// The loss detail of an edge whose caller's use row lifecycle loss left
/// unbound (R-C51-3).
const UNBOUND_ROW_LOSS: &str =
    "lifecycle evidence was lost before this caller's use row could bind";

/// (pid, module) pairs the stash holds before it overflows.
const PREADMISSION_STASH_LIMIT: usize = 4096;

/// The (pid, module) pairs of every unbound CALLER_USE row, bounded. A
/// `None` module is a row whose endpoint resolved to no module: every
/// module of that pid. Past the bound the whole scope reads
/// `use_before_admission` (sticky).
#[derive(Debug)]
struct PreadmissionStash {
    entries: BTreeMap<u32, PreadmissionEntry>,
    len: usize,
    limit: usize,
    overflowed: bool,
    /// (pid, module) pairs dropped because their process exited or the
    /// pid now names another process (R-C51-5).
    pruned: u64,
    /// (pid, module) notes refused once the stash overflowed.
    refused: u64,
}

/// The unbound rows of one pid: the process's start time when the first
/// row was stashed (`None`: unreadable then — kept until the pid is gone,
/// failing safe), and module -> whether lifecycle loss left the row
/// unbound.
#[derive(Debug, Default)]
struct PreadmissionEntry {
    start_time: Option<u64>,
    modules: BTreeMap<Option<ModuleKey>, bool>,
}

/// The stash's counters (R-C51-5), published under
/// `observation.native_witnesses.preadmission`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PreadmissionCounters {
    pub held: usize,
    pub limit: usize,
    pub pruned: u64,
    pub refused: u64,
}

impl PreadmissionStash {
    fn new(limit: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            len: 0,
            limit,
            overflowed: false,
            pruned: 0,
            refused: 0,
        }
    }

    /// The entry can no longer matter (R-C51-5): its process is gone (a
    /// dead pid is never admitted again), or the pid now names a process
    /// with another start time. Each fork or exec writes rows under its
    /// own image key, so a later holder's use leaves rows of its own.
    fn stale<S: ProcessSource>(entry: &PreadmissionEntry, pid: u32, source: &S) -> bool {
        source.gone(pid)
            || matches!(
                (entry.start_time, source.start_time(pid)),
                (Some(stashed), Some(now)) if stashed != now
            )
    }

    fn prune_pid<S: ProcessSource>(&mut self, pid: u32, source: &S) {
        if self
            .entries
            .get(&pid)
            .is_some_and(|entry| Self::stale(entry, pid, source))
        {
            let entry = self.entries.remove(&pid).expect("checked above");
            self.len -= entry.modules.len();
            self.pruned += entry.modules.len() as u64;
        }
    }

    fn prune<S: ProcessSource>(&mut self, source: &S) {
        let pids: Vec<u32> = self.entries.keys().copied().collect();
        for pid in pids {
            self.prune_pid(pid, source);
        }
    }

    fn counters(&self) -> PreadmissionCounters {
        PreadmissionCounters {
            held: self.len,
            limit: self.limit,
            pruned: self.pruned,
            refused: self.refused,
        }
    }
}

/// The WatchedNoUse pair precondition (C3 open item, C5.2): the userspace
/// seen set below its bound and no row unrecorded past it. A full set
/// cannot report a later first use, and an unrecorded row is a use nobody
/// will ever bind, so no-use is no longer provable.
///
/// Withholding (not demoting) is sound only because the seen-set bound
/// equals the capacity of the insert-only CALLER_USE map
/// (`attach::inventory::callers::seen_limit`, pinned by a test): the set
/// fills exactly when the map does, so every first use before saturation
/// was reported, and every later one either was too or failed its insert
/// into CALLER_EVIDENCE, whose rise demotes every watch.
fn pair_precondition_failure(batch: &WitnessBatch) -> Option<String> {
    if batch.unrecorded_rows > 0 {
        Some(format!(
            "{} CALLER_USE row(s) went unrecorded past the pair limit {}: no-use is unprovable",
            batch.unrecorded_rows, batch.pair_limit
        ))
    } else if batch.seen_rows >= batch.pair_limit {
        Some(format!(
            "the CALLER_USE seen set is full ({}/{} pairs): a later first use could go unrecorded",
            batch.seen_rows, batch.pair_limit
        ))
    } else {
        None
    }
}

/// Whether one mapped caller is the capture's scope incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeVerdict {
    Inside,
    /// Admitted cgroup caller, with no continuous-membership timeline.
    Cgroup,
    /// Another process (a different pid, or a reused one).
    Outside,
    /// The pid matches but a start time is unreadable: unprovable.
    Unproven,
    /// The scope incarnation's later image (after an exec).
    LaterImage,
}

/// The run's attach set is the ONE admission source the inventory output
/// shows (Task 6 C2 review I1): its verdict replaces any other, and an
/// object it never judged has no admitted verdict. `None` here means "not
/// judged".
fn attach_admission(
    verdict: Option<&AttachVerdict>,
) -> Option<(AdmissionState, Option<usize>, Vec<String>)> {
    match verdict? {
        AttachVerdict::Admitted { endpoints, reasons } => {
            Some((AdmissionState::Admitted, Some(*endpoints), reasons.clone()))
        }
        AttachVerdict::Refused { reason } => {
            Some((AdmissionState::Refused, None, vec![reason.clone()]))
        }
    }
}

const UNJUDGED_REASON: &str = "the inventory attach set did not judge this object (no comparable \
     pin or digest in this pass's lowering); it is not instrumented";

/// One natively committed module's registry record. Admission comes only
/// from the attach set's verdict for the same physical module; the
/// engine's own plan is never an admission source (it is lowered for the
/// native owner lane, not for what this run instruments). Unjudged reads
/// unresolved.
fn native_module_info(
    engine: &Engine,
    module: &ReconciledModule,
    key: ModuleKey,
    verdict: Option<&AttachVerdict>,
) -> ModuleInfo {
    let (admission, endpoints, reasons) = attach_admission(verdict).unwrap_or_else(|| {
        (
            AdmissionState::Unresolved,
            None,
            vec![UNJUDGED_REASON.to_string()],
        )
    });
    let summary = engine.pinned.summary(module.object);
    ModuleInfo {
        path: module.scanned.path.clone(),
        key,
        double_loaded: module.scanned.double_loaded,
        build_id: summary.and_then(|summary| summary.build_id.map(str::to_string)),
        identity_source: summary.map(|summary| summary.identity_source.to_string()),
        admission,
        admission_class: None,
        admission_endpoints: endpoints,
        admission_reasons: reasons,
    }
}

fn catalog_module_key(object: &crate::inspect_system::CatalogObject) -> ModuleKey {
    ModuleKey::physical(
        object.key.device.major,
        object.key.device.minor,
        object.key.inode,
        object.sha256.clone(),
        &object.path,
    )
}

/// One catalog object's registry record. `verdict` is the attach set's
/// Inventory verdict and is the admission source. An object the attach set
/// did not judge keeps the catalog's refusal or unresolved verdict (true:
/// nothing attaches), but never its `admitted` — that object is not
/// instrumented, so it reads unresolved.
fn catalog_module_info(
    object: &crate::inspect_system::CatalogObject,
    verdict: Option<&AttachVerdict>,
) -> ModuleInfo {
    let (admission, endpoints, reasons) =
        attach_admission(verdict).unwrap_or_else(|| match object.admission.state() {
            "refused" => (AdmissionState::Refused, None, object.admission.reasons()),
            "admitted" => (
                AdmissionState::Unresolved,
                None,
                vec![UNJUDGED_REASON.to_string()],
            ),
            _ => {
                let mut reasons = object.admission.reasons();
                reasons.push(UNJUDGED_REASON.to_string());
                (AdmissionState::Unresolved, None, reasons)
            }
        });
    ModuleInfo {
        path: object.path.clone(),
        key: catalog_module_key(object),
        // Per-observation evidence: the projection loop below
        // overwrites this with the observing member's verdict.
        double_loaded: false,
        build_id: object.build_id.clone(),
        identity_source: object.identity_source.map(str::to_string),
        admission,
        // The catalog class describes its own lowering; without an attach-set
        // verdict it would contradict the `unresolved` admission above.
        admission_class: verdict.and(object.admission.class()).map(str::to_string),
        admission_endpoints: endpoints,
        admission_reasons: reasons,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::super::inventory::{ImageCheck, UnavailableImageGuard};
    use super::*;
    use crate::discovery::caller_registry::OsProcessSource;
    use crate::discovery::native_binding::{OwnerImages, ScanOnlyIdentity};
    use p11scope_ebpf_common::ImageIdentity;
    use std::cell::Cell;

    // Only the native query is scripted. This never purports to read the
    // host's task-storage identity map or qualify a running capture.
    struct FixtureImages;

    fn fixture_image(pid: u32) -> Option<ImageIdentity> {
        Some(ImageIdentity {
            task_cookie: u64::from(pid) + 1,
            exec_id: 7,
        })
    }

    impl ImageGuard for FixtureImages {
        fn check(&mut self, view: &ProcessView, expected: ImageIdentity) -> ImageCheck {
            assert_eq!(expected.task_cookie, u64::from(view.pid()) + 1);
            ImageCheck::Exact
        }
    }

    fn coordinator() -> InventoryCoordinator<OsProcessSource> {
        InventoryCoordinator::new(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap()
    }

    /// Heap-built PID-scope coordinator (H6 slice 2 oracles): see
    /// `NativeScene::boxed` for why multi-scene oracles box.
    fn boxed_os_coordinator(pid: u32) -> Box<InventoryCoordinator<OsProcessSource>> {
        Box::new(
            InventoryCoordinator::new(
                Scope::Pid(pid),
                HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::default_limits(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn inventory_selected_budget_reaches_plan_and_attach_set() {
        for n in [1, 4097, 6531, 8192] {
            let budget = crate::capacity::inventory_endpoint_budget(Some(n)).unwrap();
            let selected = InventoryCoordinator::new_with_budget(
                Scope::Pid(std::process::id()),
                HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::default_limits(),
                budget,
            )
            .unwrap();
            assert_eq!(selected.attach_set().budget(), budget);
            assert_eq!(
                selected.engine.plan().admission_policy(),
                crate::plan::AdmissionPolicy::Inventory(budget)
            );
        }
        let default = coordinator();
        let budget = crate::capacity::inventory_endpoint_budget(None).unwrap();
        assert_eq!(default.attach_set().budget(), budget);
        assert_eq!(
            default.engine.plan().admission_policy(),
            crate::plan::AdmissionPolicy::Inventory(budget)
        );
    }

    #[test]
    fn inventory_selected_budget_growth_refusal_keeps_ids_and_positive_history() {
        use crate::discovery::inventory_attach_set::tests as fx;
        let mut scene = CaptureScene::new(2);
        let budget = crate::capacity::inventory_endpoint_budget(Some(3)).unwrap();
        scene.coordinator = InventoryCoordinator::new_with_budget(
            Scope::Pid(std::process::id()),
            HookRegistry::builtin(),
            Vec::new(),
            scene.source.clone(),
            RegistryLimits::default_limits(),
            budget,
        )
        .unwrap();
        let other = fx::provider(&scene._dir, "b.so", "provider-b");
        scene.pins = fx::pass_pins(&[(&scene.path, "sha-a"), (&other, "sha-b")]);
        let policy = crate::plan::AdmissionPolicy::Inventory(budget);
        let initial = [
            fx::module(&scene.pins, &scene.path, &fx::offsets(2)),
            fx::module(&scene.pins, &other, &fx::offsets(1)),
        ];
        let absorbed = scene
            .coordinator
            .attach_set
            .absorb(&fx::lower_named(&initial, &scene.pins, policy), &scene.pins);
        scene.delta = absorbed.delta;
        scene.verdicts = absorbed.verdicts;
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let path = scene.path.clone();
        scene.project_paths(7, &[&path, &other], 60);
        scene.coordinator.commit_batch(false).unwrap();
        let mut native = NativeScene::over(scene, 0);
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 5;
        native.witness(vec![row]);
        let retained: Vec<_> = native
            .scene
            .coordinator
            .attach_set
            .endpoints()
            .copied()
            .collect();
        let positive = native
            .scene
            .coordinator
            .registry
            .edges()
            .find(|edge| edge.caller == caller && edge.entry_count == 5)
            .map(|edge| {
                (
                    edge.module,
                    edge.entry_count,
                    edge.entry_first_seen_ns,
                    edge.entry_last_seen_ns,
                )
            })
            .expect("initial positive");

        // Lowering fits A's new3 whole first, then refuses B. The lifetime
        // set already holds A2+B1, so it must refuse A's one new ID too.
        let growth = [
            fx::module(&native.scene.pins, &path, &fx::offsets(3)),
            fx::module(&native.scene.pins, &other, &fx::offsets(1)),
        ];
        let absorbed = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(&growth, &native.scene.pins, policy),
            &native.scene.pins,
        );
        assert!(absorbed.delta.is_empty());
        assert_eq!(absorbed.gaps.len(), 1);
        assert_eq!(absorbed.gaps[0].budget, Some((ENDPOINT_RESOURCE, 3, 4)));
        native.scene.verdicts.extend(absorbed.verdicts);
        native.scene.project_paths(7, &[&path, &other], 10_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native
                .scene
                .coordinator
                .attach_set
                .endpoints()
                .copied()
                .collect::<Vec<_>>(),
            retained
        );
        let preserved = native
            .scene
            .coordinator
            .registry
            .edge(caller, positive.0)
            .unwrap();
        assert_eq!(preserved.entry_count, positive.1);
        assert_eq!(preserved.entry_first_seen_ns, positive.2);
        assert_eq!(preserved.entry_last_seen_ns, positive.3);
    }

    /// E-test-style fixture build: compile one C source with gcc into the
    /// test tmp dir.
    fn gcc(
        dir: &std::path::Path,
        out: &str,
        source: &std::path::Path,
        args: &[&str],
        libs: &[&str],
    ) -> PathBuf {
        let bin = dir.join(out);
        let mut cmd = std::process::Command::new("gcc");
        cmd.args(args).arg("-o").arg(&bin).arg(source).args(libs);
        assert!(
            cmd.status().unwrap().success(),
            "gcc failed for {out}: {cmd:?}"
        );
        bin
    }

    /// Poll for a driver ready file, like the observe helpers.
    fn wait_ready(ready: &std::path::Path) {
        for _ in 0..300 {
            if std::fs::metadata(ready).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("fixture driver never became ready: {}", ready.display());
    }

    /// Kills the owned fixture child on drop, so a failed assert cannot
    /// leak a sleeper.
    struct ChildReaper(std::process::Child);

    impl Drop for ChildReaper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    fn native_pass_over_self_commits_and_publishes_through_one_batch() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut FixtureImages,
                &mut OwnerImages(fixture_image),
                u64::MAX,
                crate::discovery::caller_registry::now_ns(),
            )
            .unwrap();
        assert_eq!(report.pass, 0);
        assert_eq!(report.scanned, 1);
        assert_eq!(report.native_callers, 1);
        assert!(report.pending_refresh.is_empty());
        let caller = coordinator.adapter().live_id(pid).unwrap();
        let record = coordinator.adapter().record(caller).unwrap();
        assert!(matches!(
            record.authority,
            ImageAuthority::NativeExact { .. }
        ));
        assert!(coordinator.owner_of(caller).is_some());
        // Staged: the registry snapshot is empty until the batch commits.
        assert_eq!(coordinator.registry().modules().count(), 0);
        let receipt = coordinator.commit_batch(true).unwrap();
        assert_eq!(receipt.engine_facts, receipt.engine_published);
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        assert!(receipt.registry_facts > 1);
        // The engine tail ran through the same boundary.
        assert!(coordinator.engine.tail_publishes > 0);
        // The owner closed its serviced epoch with nothing pending.
        let owner = coordinator.owner_of(caller).unwrap();
        let epochs = coordinator.engine.inventory_owner_epochs(owner).unwrap();
        assert_eq!(epochs.serviced, 1);
        assert_eq!(epochs.requested, 1);
        assert_eq!(epochs.dirty, 0);
    }

    #[test]
    fn staged_lifecycle_batches_fold_their_high_water_maximum() {
        let mut coordinator = coordinator();
        assert_eq!(coordinator.lifecycle_high_water_bytes(), None);
        let domain = NativeDomainId::mint();
        let now = crate::discovery::caller_registry::now_ns();
        // The maximum is staged before smaller and absent reports, so only
        // a maximum (not the last report) reads 300.
        for high_water in [Some(100), Some(300), None, Some(50)] {
            let mut batch = DiscoveryBatch::scripted(domain, Vec::new(), now);
            batch.drain_high_water_bytes = high_water;
            coordinator.stage_native(NativeBatch::Lifecycle(batch), &mut ScanOnlyIdentity, now);
        }
        assert_eq!(coordinator.lifecycle_high_water_bytes(), Some(300));
    }

    #[test]
    fn unavailable_guard_falls_back_to_scan_lane_with_an_authority_gap() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut UnavailableImageGuard,
                &mut ScanOnlyIdentity,
                u64::MAX,
                crate::discovery::caller_registry::now_ns(),
            )
            .unwrap();
        assert_eq!(report.native_callers, 0);
        assert_eq!(report.scan_callers, 1);
        let caller = coordinator.adapter().live_id(pid).unwrap();
        assert_eq!(
            coordinator.adapter().record(caller).unwrap().authority,
            ImageAuthority::ScanPinned
        );
        assert!(coordinator.owner_of(caller).is_none());
        coordinator.commit_batch(false).unwrap();
        assert!(
            coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "exact image authority unavailable"),
            "scan-lane fallback must record why: {:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn commit_revalidates_after_prepare_and_refuses_changed_images() {
        struct FlipGuard {
            exact: Cell<bool>,
        }
        impl ImageGuard for FlipGuard {
            fn check(&mut self, _: &ProcessView, _: ImageIdentity) -> ImageCheck {
                if self.exact.get() {
                    ImageCheck::Exact
                } else {
                    ImageCheck::Changed
                }
            }
        }
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let image = fixture_image(pid).unwrap();
        let mut guard = FlipGuard {
            exact: Cell::new(true),
        };
        let owner = coordinator
            .engine
            .open_inventory_owner(pid, image, &mut guard)
            .unwrap();
        let lease = coordinator.engine.acquire_inventory_scan(owner).unwrap();
        let window = coordinator
            .engine
            .budget
            .begin_window(WindowId::new(0), u64::MAX)
            .unwrap();
        let checkpoint = coordinator
            .engine
            .budget
            .checkpoint(window.clone())
            .unwrap();
        let receipt = coordinator
            .engine
            .scan_inventory_owner(&lease, &mut guard)
            .unwrap();
        coordinator.engine.budget.finish_scan(checkpoint).unwrap();
        coordinator.engine.budget.finish_window(window).unwrap();
        coordinator.engine.release_inventory_scan(&lease).unwrap();
        let prepared = coordinator
            .engine
            .prepare_inventory_reconciliation(receipt, &mut guard)
            .unwrap();
        // Asynchronous gap: the image changes after preparation. I3
        // revalidates at commit and refuses; existing claims are retained.
        guard.exact.set(false);
        let modules_before = coordinator.engine.modules.len();
        assert!(
            coordinator
                .engine
                .commit_inventory_reconciliation(prepared, &mut guard)
                .is_err()
        );
        assert_eq!(coordinator.engine.modules.len(), modules_before);
        assert_eq!(
            coordinator
                .engine
                .inventory_owner_epochs(owner)
                .unwrap()
                .image_state,
            ImageCheck::Changed
        );
    }

    #[test]
    fn expired_deadline_defers_and_keeps_the_refresh_pending() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut FixtureImages,
                &mut OwnerImages(fixture_image),
                1,
                1_000_000,
            )
            .unwrap();
        assert_eq!(report.native_callers, 1);
        let caller = coordinator.adapter().live_id(pid).unwrap();
        let owner = coordinator.owner_of(caller).unwrap();
        // No commit ran: the refresh request stays pending for the next
        // pass with a fresh deadline.
        let epochs = coordinator.engine.inventory_owner_epochs(owner).unwrap();
        assert_eq!(epochs.requested, 1);
        assert_eq!(epochs.serviced, 0);
        assert_ne!(epochs.dirty, 0);
        coordinator.commit_batch(false).unwrap();
        assert!(
            coordinator.registry().gaps().iter().any(|gap| {
                gap.subject == "native inventory scan failed" && gap.reason.contains("defer")
            }),
            "deferral must surface as a gap: {:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn empty_pass_reconciles_exits_without_a_scan() {
        use crate::discovery::caller_registry::CallerLifecycle;
        use std::process::{Command, Stdio};

        struct Exiter(std::process::Child);
        impl Drop for Exiter {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        // An owned sleeper, reaped before the empty pass: the pin dies
        // and the pid names nothing, so lifecycle needs no scan.
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut exiter = Exiter(child);
        let mut coordinator = InventoryCoordinator::new(
            Scope::System,
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let now = crate::discovery::caller_registry::now_ns();
        let mut observed = BTreeSet::new();
        observed.insert(pid);
        let events = coordinator.adapter_mut().reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            now,
        );
        assert_eq!(events.len(), 1);
        let caller = coordinator.adapter().live_id(pid).unwrap();
        exiter.0.kill().unwrap();
        exiter.0.wait().unwrap();
        let report = coordinator.observe_empty_pass(
            &mut UnavailableImageGuard,
            &mut ScanOnlyIdentity,
            "boom",
            now + 1,
        );
        assert_eq!(report.scanned, 0);
        assert!(report.events.iter().any(|event| matches!(
            event,
            CallerEvent::Exited { id, .. } if *id == caller
        )));
        coordinator.commit_batch(false).unwrap();
        let record = coordinator.adapter().record(caller).unwrap();
        assert_eq!(record.lifecycle, CallerLifecycle::Exited);
        assert!(record.retired);
        assert!(
            coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "scan pass produced no observation"
                    && gap.reason == "boom"),
            "empty passes gap their reason: {:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn batch_publishes_registry_edges_synchronously_with_the_return() {
        // Sibling: scripted_entries_flow_from_a_scan_built_edge_through_commit_to_json
        // pins the same batch boundary for entry counts through render_json.
        let mut coordinator = coordinator();
        let key = ModuleKey::physical(8, 1, 11, Some("sha0011".into()), "/lib/a.so");
        coordinator.registry_mut().note_mapping(
            CallerId(0),
            50,
            ModuleInfo {
                path: "/lib/a.so".into(),
                key: key.clone(),
                double_loaded: false,
                build_id: None,
                identity_source: Some("mountinfo".into()),
                admission: AdmissionState::Admitted,
                admission_class: Some("exact".into()),
                admission_endpoints: Some(2),
                admission_reasons: Vec::new(),
            },
            100,
        );
        coordinator
            .registry_mut()
            .observe_entries(CallerId(0), &key, 3, 110);
        // Invisible before the batch returns.
        assert!(coordinator.registry().module_id_for(&key).is_none());
        let tails_before = coordinator.engine.tail_publishes;
        let receipt = coordinator.commit_batch(false).unwrap();
        // Visible after: the batch return already carries the arrival,
        // on both revisions at once.
        let id = coordinator.registry().module_id_for(&key).unwrap();
        let edge = coordinator.registry().edge(CallerId(0), id).unwrap();
        assert_eq!(edge.entry_count, 3);
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        assert_eq!(receipt.engine_facts, receipt.engine_published);
        assert!(coordinator.engine.tail_publishes > tails_before || receipt.engine_facts > 1);
    }

    #[test]
    fn scripted_entries_flow_from_a_scan_built_edge_through_commit_to_json() {
        // Sibling: batch_publishes_registry_edges_synchronously_with_the_return
        // pins the same batch boundary for mapping edges.
        use crate::discovery::caller_registry::{MAX_EDGE_ENTRY_COUNT, ModuleId};

        fn rendered_edge(
            document: &serde_json::Value,
            caller: CallerId,
            module: ModuleId,
        ) -> &serde_json::Value {
            document["edges"]
                .as_array()
                .unwrap()
                .iter()
                .find(|edge| edge["caller"] == caller.label() && edge["module"] == module.label())
                .unwrap()
        }

        // Owned fixture, E1-style: a driver child mapping a version-matrix
        // provider. Hints name the provider, so the scan lane projects the
        // edge deterministically (empty hints only keep objects exporting a
        // registry symbol, which a bare self scan has none of).
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("coordinator-entry-flow");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let provider = gcc(
            &dir,
            "f1-p1.so",
            &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
            &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
            &[],
        );
        let driver = gcc(
            &dir,
            "f1-driver",
            &manifest.join("tests/fixtures/catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let ready = dir.join("A.ready");
        let child = std::process::Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg(&provider)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let driver_pid = child.id();
        let _reaper = ChildReaper(child);
        wait_ready(&ready);
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(driver_pid),
            HookRegistry::builtin(),
            vec![provider.clone()],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let started = crate::discovery::caller_registry::now_ns();
        let scope = format!("pid:{driver_pid}");
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(driver_pid),
                None,
                &mut UnavailableImageGuard,
                &mut ScanOnlyIdentity,
                u64::MAX,
                started,
            )
            .unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.scan_callers, 1);
        coordinator.commit_batch(false).unwrap();
        let caller = coordinator.adapter().live_id(driver_pid).unwrap();
        // The edge under test is scan-built: the pass projected it, so no
        // hand-staged mapping stands in for the staging path.
        let provider_name = provider.file_name().unwrap().to_string_lossy().into_owned();
        let module = coordinator
            .registry()
            .edges()
            .filter(|edge| edge.caller == caller)
            .map(|edge| edge.module)
            .find(|module| {
                coordinator
                    .registry()
                    .module(*module)
                    .is_some_and(|record| {
                        record
                            .paths
                            .iter()
                            .any(|path| path.contains(&provider_name))
                    })
            })
            .expect("the hinted scan maps the fixture provider");
        let key = coordinator.registry().module(module).unwrap().key.clone();

        // Scripted entries (+ in-flight) stage behind the batch boundary:
        // the pre-commit render still shows the quiet edge.
        let t1 = started.saturating_add(10);
        coordinator
            .registry_mut()
            .observe_entries(caller, &key, 7, t1);
        coordinator.registry_mut().set_in_flight(caller, &key, true);
        let staged = crate::inventory::render_json(&coordinator, &scope, started, t1, 1);
        assert_eq!(
            rendered_edge(&staged, caller, module)["entries"]["count"],
            0
        );
        let receipt = coordinator.commit_batch(false).unwrap();
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        let document = crate::inventory::render_json(&coordinator, &scope, started, t1, 1);
        let edge = rendered_edge(&document, caller, module);
        assert_eq!(edge["entries"]["count"], 7);
        assert_eq!(edge["entries"]["observation"], "observed");
        assert!(edge["entries"]["in_flight"].as_bool().unwrap());
        assert_eq!(edge["entries"]["saturated"], false);
        assert_eq!(edge["entries"]["last_seen_ns"], t1);

        // Fill to MAX - 1, then +5 overflows: the count stops at the cap
        // with the saturation flag set while recency keeps advancing.
        let t2 = t1 + 10;
        let t3 = t2 + 10;
        coordinator
            .registry_mut()
            .observe_entries(caller, &key, MAX_EDGE_ENTRY_COUNT - 1 - 7, t2);
        coordinator
            .registry_mut()
            .observe_entries(caller, &key, 5, t3);
        let receipt = coordinator.commit_batch(false).unwrap();
        assert_eq!(receipt.registry_facts, receipt.registry_published);
        let document = crate::inventory::render_json(&coordinator, &scope, started, t3, 1);
        let edge = rendered_edge(&document, caller, module);
        assert_eq!(edge["entries"]["count"], u64::MAX);
        assert!(edge["entries"]["saturated"].as_bool().unwrap());
        assert_eq!(edge["entries"]["observation"], "observed");
        assert_eq!(edge["entries"]["last_seen_ns"], t3);
        assert_eq!(edge["entries"]["first_seen_ns"], t1);
        assert!(edge["entries"]["in_flight"].as_bool().unwrap());
    }

    #[test]
    fn scan_passes_feed_the_attach_set_once_under_the_inventory_budget() {
        // Owned fixture: a driver child mapping the NSS-shaped provider,
        // whose 8 interface-linked tables of 68 distinct targets are 544
        // endpoints — past the Detailed 512-slot ceiling, inside the
        // 4096-endpoint Inventory budget.
        let base = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join("coordinator-attach-set");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let provider = gcc(
            &dir,
            "as-nss.so",
            &manifest.join("tests/fixtures/catalog-nss/provider.c"),
            &[
                "-std=c11", "-O0", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
            ],
            &[],
        );
        let driver = gcc(
            &dir,
            "as-driver",
            &manifest.join("tests/fixtures/catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let ready = dir.join("A.ready");
        let child = std::process::Command::new(&driver)
            .arg("--ready")
            .arg(&ready)
            .arg(&provider)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let driver_pid = child.id();
        let _reaper = ChildReaper(child);
        wait_ready(&ready);
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(driver_pid),
            HookRegistry::builtin(),
            vec![provider.clone()],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        for pass in 0..2u64 {
            coordinator
                .scan_pass(
                    &InventoryScope::Pid(driver_pid),
                    None,
                    &mut UnavailableImageGuard,
                    &mut ScanOnlyIdentity,
                    u64::MAX,
                    crate::discovery::caller_registry::now_ns(),
                )
                .unwrap();
            coordinator.commit_batch(false).unwrap();
            let delta = coordinator.take_target_delta();
            if pass == 0 {
                assert_eq!(
                    delta
                        .endpoints
                        .iter()
                        .map(|endpoint| endpoint.id.0)
                        .collect::<Vec<_>>(),
                    (0..544).collect::<Vec<u32>>()
                );
                assert_eq!(delta.objects.len(), 1, "one physical provider object");
            } else {
                assert!(delta.is_empty(), "a rescan adds nothing: {delta:?}");
            }
            assert_eq!(coordinator.attach_set().len(), 544);
        }
        let provider_name = provider.file_name().unwrap().to_string_lossy().into_owned();
        let record = coordinator
            .registry()
            .modules()
            .find(|module| {
                module
                    .paths
                    .iter()
                    .any(|path| path.ends_with(&provider_name))
            })
            .expect("the hinted scan maps the fixture provider");
        assert_eq!(record.admission, AdmissionState::Admitted);
        assert_eq!(record.admission_endpoints, Some(544));
        assert!(record.admission_reasons.is_empty());
        assert!(
            !coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject.starts_with("inventory attach")),
            "{:?}",
            coordinator.registry().gaps()
        );
    }

    #[test]
    fn native_and_catalog_projections_take_admission_only_from_the_attach_set() {
        // I1 (review): the engine plan admits `a`, the run's attach set
        // refused it. Both projections note the module each pass; the
        // attach set is the one admission source, so the module reads
        // refused — never a false `refused->admitted` rise.
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let module = fx::module(&pins, &a, &fx::offsets(3));
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        coordinator.engine.plan = fx::lower_named(std::slice::from_ref(&module), &pins, policy);
        assert_eq!(
            coordinator.engine.plan.refused_modules().count(),
            0,
            "the engine plan admits the module"
        );
        let refused = AttachVerdict::Refused {
            reason: "a.so needs 3 more endpoints; the attach set is full".into(),
        };
        let path = a.to_str().unwrap();
        let key = ModuleKey::physical(
            module.scanned.key.device.major,
            module.scanned.key.device.minor,
            module.scanned.key.inode,
            Some("sha-a".into()),
            path,
        );
        let object = crate::inspect_system::CatalogObject {
            path: path.into(),
            key: module.scanned.key,
            sha256: Some("sha-a".into()),
            build_id: None,
            identity_source: Some("mountinfo"),
            note: None,
            mappings: Vec::new(),
            observations: Vec::new(),
            admission: crate::inspect_system::AdmissionRecord::Admitted {
                class: "exact",
                endpoints: 3,
            },
        };
        let pid = std::process::id();
        let caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 100)
            .unwrap();
        for pass in 0..2u64 {
            let native =
                native_module_info(&coordinator.engine, &module, key.clone(), Some(&refused));
            let catalog = catalog_module_info(&object, Some(&refused));
            assert_eq!(native.admission, AdmissionState::Refused, "native note");
            assert_eq!(catalog.admission, AdmissionState::Refused, "catalog note");
            // scan_pass order: the native projection first, then the catalog.
            coordinator
                .registry
                .note_mapping(caller, pid, native, 100 + pass);
            coordinator
                .registry
                .note_mapping(caller, pid, catalog, 100 + pass);
            coordinator.registry.publish();
        }
        let id = coordinator.registry.module_id_for(&key).unwrap();
        let record = coordinator.registry.module(id).unwrap();
        assert_eq!(record.admission, AdmissionState::Refused);
        assert!(
            record.admission_history.is_empty(),
            "{:?}",
            record.admission_history
        );
        assert!(
            !coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "module admission changed"),
            "{:?}",
            coordinator.registry.gaps()
        );
        // An object the attach set never judged: the native note has no
        // opinion and the catalog's own `admitted` is not taken over —
        // both read unresolved, never admitted.
        let native = native_module_info(&coordinator.engine, &module, key.clone(), None);
        assert_eq!(native.admission, AdmissionState::Unresolved);
        let catalog = catalog_module_info(&object, None);
        assert_eq!(catalog.admission, AdmissionState::Unresolved);
        assert_eq!(catalog.admission_endpoints, None);
        // No attach-set verdict: no catalog class either, matching the
        // native note, so the class cannot flip within one pass.
        assert_eq!(catalog.admission_class, None);
        assert_eq!(native.admission_class, None);
        assert!(
            catalog.admission_reasons[0].contains("did not judge"),
            "{:?}",
            catalog.admission_reasons
        );
        // A catalog refusal the attach set did not judge stays a refusal.
        let refused_object = crate::inspect_system::CatalogObject {
            admission: crate::inspect_system::AdmissionRecord::Refused {
                class: "closure-array",
                reason: "closure arrays are not attached".into(),
            },
            ..object
        };
        let catalog = catalog_module_info(&refused_object, None);
        assert_eq!(catalog.admission, AdmissionState::Refused);
        assert_eq!(catalog.admission_class, None);
    }

    /// One catalog object per path, each observed by `pid`, plus that
    /// member's complete scan record.
    pub(super) fn capture_catalog(
        pins: &crate::discovery::identity::PinnedObjects,
        paths: &[&std::path::Path],
        pid: u32,
        generation: Option<crate::inspect_system::MemberGeneration>,
    ) -> crate::inspect_system::Catalog {
        let objects = paths
            .iter()
            .map(|path| {
                let summary = pins
                    .pinned()
                    .find(|summary| summary.path == path.to_str().unwrap())
                    .unwrap();
                crate::inspect_system::CatalogObject {
                    path: summary.path.to_string(),
                    key: summary.key,
                    sha256: Some(summary.sha256.to_string()),
                    build_id: None,
                    identity_source: Some("mountinfo"),
                    note: None,
                    mappings: Vec::new(),
                    observations: vec![crate::inspect_system::Observation {
                        pid,
                        path: summary.path.to_string(),
                        exports: Vec::new(),
                        tables: Vec::new(),
                        interfaces: Vec::new(),
                        double_loaded: false,
                        evidence: crate::inspect_system::ObservationEvidence::DeepScan,
                    }],
                    admission: crate::inspect_system::AdmissionRecord::Admitted {
                        class: "exact",
                        endpoints: 3,
                    },
                }
            })
            .collect::<Vec<_>>();
        crate::inspect_system::Catalog {
            scan_status: "complete",
            lowering: None,
            enumerated: 1,
            selected: 1,
            scanned: 1,
            maps_matched: 0,
            unexamined: 0,
            unexamined_objects: 0,
            snapshots_unavailable: 0,
            attribution_losses: std::collections::BTreeMap::new(),
            cap: 1,
            scan_ms: 0,
            processes: vec![crate::inspect_system::ProcessRecord {
                application: crate::inspect_identity::InspectApplicationResult::Unknown(
                    crate::inspect_identity::InspectIdentityUnknown::NotExamined,
                ),
                complete_scan: None,
                pid,
                status: crate::inspect_system::MemberStatus::Scanned,
                objects: (0..objects.len()).collect(),
                generation,
            }],
            objects,
            relationships: Vec::new(),
            admission: crate::inspect_system::AdmissionSummary {
                uncorroborated_candidates: 0,
                module_ambiguous: 0,
                admitted: paths.len(),
                refused: 0,
                unresolved: 0,
            },
            skipped: Vec::new(),
            notes: Vec::new(),
            explanation: None,
            stage_timings: crate::timing::StageTimings::new(),
        }
    }

    /// Review R3/R4: a pass notes the catalog's mapper counts into the
    /// attach set (which sizes uprobe-multi links), from a whole-system
    /// view only; a PID-scoped pass marks the counts scope-limited.
    #[test]
    fn a_pass_notes_mapper_counts_from_a_system_view_only() {
        use crate::attach::capture::MapperEstimate;
        use crate::discovery::inventory_attach_set::tests as fx;
        let pid = std::process::id();
        for (scope, expected) in [
            (Scope::System, MapperEstimate::System(3)),
            (Scope::Pid(pid), MapperEstimate::ScopeLimited),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let a = fx::provider(&dir, "a.so", "provider-a");
            let pins = fx::pass_pins(&[(&a, "sha-a")]);
            let modules = [fx::module(&pins, &a, &fx::offsets(3))];
            let mut coordinator = InventoryCoordinator::new(
                scope,
                HookRegistry::builtin(),
                Vec::new(),
                OsProcessSource,
                RegistryLimits::default_limits(),
            )
            .unwrap();
            let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
            let plan = fx::lower_named(&modules, &pins, policy);
            let object = coordinator.attach_set.absorb(&plan, &pins).delta.endpoints[0].object;
            assert_eq!(
                coordinator.attach_set.mappers(object),
                MapperEstimate::Unknown
            );
            let mut catalog = capture_catalog(&pins, &[&a], pid, None);
            catalog.objects[0].mappings = vec![(pid, None), (pid + 1, None), (pid + 2, None)];
            coordinator.apply_catalog(
                catalog,
                &mut UnavailableImageGuard,
                &mut ScanOnlyIdentity,
                u64::MAX,
                100,
            );
            assert_eq!(coordinator.attach_set.mappers(object), expected);
        }
    }

    #[test]
    fn capture_receipts_stage_watched_only_for_completely_attached_modules() {
        use crate::attach::capture::{AttachedEndpoint, EndpointFailure, ExtendReceipt};
        use crate::discovery::caller_registry::UseCoverage;
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let b = fx::provider(&dir, "b.so", "provider-b");
        let c = fx::provider(&dir, "c.so", "provider-c");
        let pins = fx::pass_pins(&[(&a, "sha-a"), (&b, "sha-b"), (&c, "sha-c")]);
        let modules = [
            fx::module(&pins, &a, &fx::offsets(3)),
            fx::module(&pins, &b, &fx::offsets(2)),
            fx::module(&pins, &c, &fx::offsets(1)),
        ];
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let plan = fx::lower_named(&modules, &pins, policy);
        let absorbed = coordinator.attach_set.absorb(&plan, &pins);
        let ids: Vec<u32> = absorbed.delta.endpoints.iter().map(|e| e.id.0).collect();
        assert_eq!(ids, [0, 1, 2, 3, 4, 5]);
        let verdicts = absorbed.verdicts;
        let pid = std::process::id();
        let caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        // The generation collection reads for this (live) process.
        let generation = Some(crate::inspect_system::MemberGeneration {
            start_time: crate::process::process_start_time(pid).ok(),
            exe: crate::discovery::caller_registry::read_exe_identity(pid),
        });
        let catalog = capture_catalog(&pins, &[&a, &b, &c], pid, generation);
        let coverage_of = |coordinator: &InventoryCoordinator<_>, path: &std::path::Path| {
            let edge = coordinator
                .registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && coordinator
                            .registry
                            .module(edge.module)
                            .is_some_and(|module| module.paths.contains(path.to_str().unwrap()))
                })
                .unwrap();
            coordinator.registry.coverage(edge)
        };

        // Scan lane: no capture, every edge stays scan-only.
        coordinator.project_catalog(&catalog, &verdicts, 60);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::Unknown(UnknownReason::ScanOnly)
        );

        // A capture scoped to another process stages nothing for this one.
        coordinator.begin_capture_coverage(CaptureScopeCoverage::Pid(ScopeIncarnation {
            pid: pid + 1,
            start_time: crate::process::process_start_time(pid).ok(),
        }));
        coordinator.project_catalog(&catalog, &verdicts, 70);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::Unknown(UnknownReason::ScanOnly)
        );

        coordinator.begin_capture_coverage(CaptureScopeCoverage::Pid(ScopeIncarnation {
            pid,
            start_time: crate::process::process_start_time(pid).ok(),
        }));
        let endpoint = |id: u32| absorbed.delta.endpoints[id as usize];
        let attached = |id: u32, at_ns: u64| AttachedEndpoint {
            id: endpoint(id).id,
            object: endpoint(id).object,
            at_ns,
        };
        // a.so complete (0..2), b.so one failed (3) one attached (4),
        // c.so (5) deferred.
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![attached(0, 100), attached(2, 120), attached(4, 130)],
            failed: vec![EndpointFailure {
                id: endpoint(3).id,
                object: endpoint(3).object,
                reason: "kernel refused".into(),
                link_retained: false,
            }],
            ..ExtendReceipt::default()
        });
        coordinator.project_catalog(&catalog, &verdicts, 140);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::Unknown(UnknownReason::NotAttached),
            "one of a.so's endpoints is not attached yet"
        );
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![attached(1, 110)],
            ..ExtendReceipt::default()
        });
        coordinator.project_catalog(&catalog, &verdicts, 150);
        coordinator.registry.publish();
        assert_eq!(
            coverage_of(&coordinator, &a),
            UseCoverage::WatchedNoUse {
                since_ns: 120,
                until_ns: None
            },
            "since is the last of the module's attaches"
        );
        assert_eq!(
            coverage_of(&coordinator, &b),
            UseCoverage::Unknown(UnknownReason::AttachFailed)
        );
        assert_eq!(
            coverage_of(&coordinator, &c),
            UseCoverage::Unknown(UnknownReason::NotAttached)
        );

        // An exec of the PID target makes coverage unproven, sticky.
        coordinator.note_capture_custody(&ScopeCustody::PidUnproven {
            at_ns: 160,
            reason: "an exec of the PID target was observed".into(),
        });
        coordinator.note_capture_custody(&ScopeCustody::PidHeld);
        coordinator.project_catalog(&catalog, &verdicts, 170);
        coordinator.registry.publish();
        assert!(
            matches!(
                coverage_of(&coordinator, &a),
                UseCoverage::Unknown(UnknownReason::Loss(ref reason)) if reason.contains("exec")
            ),
            "{:?}",
            coverage_of(&coordinator, &a)
        );
    }

    #[test]
    fn failed_endpoints_stage_a_partial_attach_gap_per_module() {
        // O1 endpoint evidence (fix round 1): failed endpoints are sticky
        // (never retried), so a module with failed members undercounts —
        // its counted uses are lower bounds. Each receipt with new
        // failures stages one gap per affected module (bounded: every
        // failed endpoint lands in exactly one receipt): the oracle
        // withholds COUNT-EXACT over it. The subject and reason shapes
        // are pinned verbatim: the oracle matches them.
        use crate::attach::capture::{AttachedEndpoint, EndpointFailure, ExtendReceipt};
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed = coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&pins, &a, &fx::offsets(3))),
                &pins,
                policy,
            ),
            &pins,
        );
        let verdicts = absorbed.verdicts;
        let pid = std::process::id();
        let _caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let generation = Some(crate::inspect_system::MemberGeneration {
            start_time: crate::process::process_start_time(pid).ok(),
            exe: crate::discovery::caller_registry::read_exe_identity(pid),
        });
        let catalog = capture_catalog(&pins, &[&a], pid, generation);
        coordinator.begin_capture_coverage(CaptureScopeCoverage::System);
        coordinator.project_catalog(&catalog, &verdicts, 60);
        coordinator.registry.publish();
        let endpoint = |id: u32| absorbed.delta.endpoints[id as usize];
        let failed = |id: u32| EndpointFailure {
            id: endpoint(id).id,
            object: endpoint(id).object,
            reason: "kernel refused".into(),
            link_retained: false,
        };
        // One attached, one failed: partial attach.
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: endpoint(0).id,
                object: endpoint(0).object,
                at_ns: 100,
            }],
            failed: vec![failed(1)],
            ..ExtendReceipt::default()
        });
        // A second failure for the same module: a second gap with the
        // cumulative count.
        coordinator.note_extend_receipt(&ExtendReceipt {
            failed: vec![failed(2)],
            ..ExtendReceipt::default()
        });
        // An endpoint no module claims: unattributed, run-wide.
        coordinator.note_extend_receipt(&ExtendReceipt {
            failed: vec![EndpointFailure {
                id: crate::discovery::inventory_attach_set::EndpointId(9999),
                object: endpoint(0).object,
                reason: "kernel refused".into(),
                link_retained: false,
            }],
            ..ExtendReceipt::default()
        });
        coordinator.commit_batch(false).unwrap();
        let gaps: Vec<_> = coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == PARTIAL_ATTACH_SUBJECT)
            .collect();
        assert_eq!(
            gaps.len(),
            3,
            "one gap per module per failure receipt, plus the unattributed one: {:?}",
            coordinator.registry.gaps()
        );
        assert_eq!(
            gaps[0].reason,
            "1 of 3 endpoints failed to attach (sticky, never retried); counted uses are lower bounds"
        );
        assert_eq!(
            gaps[1].reason,
            "2 of 3 endpoints failed to attach (sticky, never retried); counted uses are lower bounds"
        );
        assert!(
            gaps[0].module.is_some() && gaps[1].module.is_some(),
            "attributed to the failed module: {:?}",
            gaps[0].module
        );
        assert_eq!(
            gaps[2].module, None,
            "the unclaimed endpoint reports run-wide"
        );
    }

    #[test]
    fn deferred_endpoints_stage_a_partial_attach_gap() {
        // O1 endpoint evidence (fix round 2, F3): attachment deferred
        // past the receipt leaves the endpoint's calls uncounted, so a
        // module with deferred members undercounts exactly like one
        // with failed members — its counted uses are lower bounds and
        // the oracle withholds COUNT-EXACT over it. The gap is sticky
        // even when a later receipt attaches the endpoint: calls made
        // while it was unattached never come back.
        use crate::attach::capture::{AttachedEndpoint, ExtendReceipt};
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed = coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&pins, &a, &fx::offsets(3))),
                &pins,
                policy,
            ),
            &pins,
        );
        let verdicts = absorbed.verdicts;
        let pid = std::process::id();
        let _caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let generation = Some(crate::inspect_system::MemberGeneration {
            start_time: crate::process::process_start_time(pid).ok(),
            exe: crate::discovery::caller_registry::read_exe_identity(pid),
        });
        let catalog = capture_catalog(&pins, &[&a], pid, generation);
        coordinator.begin_capture_coverage(CaptureScopeCoverage::System);
        coordinator.project_catalog(&catalog, &verdicts, 60);
        coordinator.registry.publish();
        let endpoint = |id: u32| absorbed.delta.endpoints[id as usize];
        let deferred = |id: u32| crate::discovery::inventory_attach_set::TargetDelta {
            endpoints: vec![endpoint(id)],
            objects: vec![endpoint(id).object],
        };
        // One attached, one deferred: partial attach.
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: endpoint(0).id,
                object: endpoint(0).object,
                at_ns: 100,
            }],
            deferred: deferred(1),
            ..ExtendReceipt::default()
        });
        // A retry attaches the deferred endpoint: no new gap, but the
        // earlier one stands (the deferral window's calls are lost).
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: endpoint(1).id,
                object: endpoint(1).object,
                at_ns: 200,
            }],
            ..ExtendReceipt::default()
        });
        coordinator.commit_batch(false).unwrap();
        let gaps: Vec<_> = coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == PARTIAL_ATTACH_SUBJECT)
            .collect();
        assert_eq!(
            gaps.len(),
            1,
            "the deferred receipt stages one gap, the clean retry none: {:?}",
            coordinator.registry.gaps()
        );
        assert!(
            gaps[0].module.is_some(),
            "attributed to the deferred module: {:?}",
            gaps[0].module
        );
        assert!(
            gaps[0].reason.contains("still deferred"),
            "the reason names the deferral: {}",
            gaps[0].reason
        );
    }

    #[test]
    fn pre_publish_deferral_attributes_to_the_staged_module() {
        // O1 endpoint evidence (round 3, F3-04): a module
        // first-discovered this pass has no committed ID when its
        // deferred receipt processes (receipts run pre-commit), but its
        // mapping stages in the same publication — so the partial-attach
        // gap attributes to the staged module instead of reporting
        // run-wide (a module-less gap would void every edge's COUNT-EXACT
        // in the oracle). No call happens before the deferral, and a
        // clean attach next pass adds no second gap.
        use crate::attach::capture::{AttachedEndpoint, ExtendReceipt};
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let b = fx::provider(&dir, "b.so", "provider-b");
        let pins = fx::pass_pins(&[(&a, "sha-a"), (&b, "sha-b")]);
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed_a = coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&pins, &a, &fx::offsets(2))),
                &pins,
                policy,
            ),
            &pins,
        );
        let mut verdicts = absorbed_a.verdicts;
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed_b = coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&pins, &b, &fx::offsets(2))),
                &pins,
                policy,
            ),
            &pins,
        );
        verdicts.extend(absorbed_b.verdicts);
        let pid = std::process::id();
        let _caller = coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let generation = Some(crate::inspect_system::MemberGeneration {
            start_time: crate::process::process_start_time(pid).ok(),
            exe: crate::discovery::caller_registry::read_exe_identity(pid),
        });
        // A commits; B's mapping stages but does NOT publish before its
        // deferred receipt.
        let catalog_a = capture_catalog(&pins, &[&a], pid, generation.clone());
        coordinator.begin_capture_coverage(CaptureScopeCoverage::System);
        coordinator.project_catalog(&catalog_a, &verdicts, 60);
        coordinator.registry.publish();
        let catalog_b = capture_catalog(&pins, &[&b], pid, generation);
        coordinator.project_catalog(&catalog_b, &verdicts, 70);
        let b_endpoint = absorbed_b.delta.endpoints[0];
        coordinator.note_extend_receipt(&ExtendReceipt {
            deferred: crate::discovery::inventory_attach_set::TargetDelta {
                endpoints: vec![b_endpoint],
                objects: vec![b_endpoint.object],
            },
            ..ExtendReceipt::default()
        });
        coordinator.commit_batch(false).unwrap();
        let gaps: Vec<_> = coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == PARTIAL_ATTACH_SUBJECT)
            .collect();
        assert_eq!(
            gaps.len(),
            1,
            "the pre-publish deferral stages one gap: {:?}",
            coordinator.registry.gaps()
        );
        let registry = &coordinator.registry;
        let b_module = registry
            .edges()
            .find(|edge| {
                registry
                    .module(edge.module)
                    .is_some_and(|module| module.paths.iter().any(|path| path.contains("b.so")))
            })
            .map(|edge| edge.module);
        assert_eq!(
            gaps[0].module, b_module,
            "the gap attributes to the staged module, never run-wide: {:?}",
            gaps[0]
        );
        assert!(
            gaps[0].reason.contains("still deferred"),
            "the reason names the deferral: {}",
            gaps[0].reason
        );
        // A clean attach next pass adds no second gap.
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: vec![AttachedEndpoint {
                id: b_endpoint.id,
                object: b_endpoint.object,
                at_ns: 200,
            }],
            ..ExtendReceipt::default()
        });
        coordinator.commit_batch(false).unwrap();
        assert_eq!(
            coordinator
                .registry
                .gaps()
                .iter()
                .filter(|gap| gap.subject == PARTIAL_ATTACH_SUBJECT)
                .count(),
            1,
            "the clean retry adds no gap: {:?}",
            coordinator.registry.gaps()
        );
    }

    #[test]
    fn partial_or_unrecorded_admission_is_never_watched() {
        use crate::discovery::inventory_attach_set::tests as fx;
        let dir = tempfile::tempdir().unwrap();
        let a = fx::provider(&dir, "a.so", "provider-a");
        let pins = fx::pass_pins(&[(&a, "sha-a")]);
        let module = fx::module(&pins, &a, &fx::offsets(2));
        let mut coordinator = coordinator();
        let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
        let absorbed = coordinator.attach_set.absorb(
            &fx::lower_named(std::slice::from_ref(&module), &pins, policy),
            &pins,
        );
        let key = absorbed.verdicts.keys().next().unwrap().clone();
        coordinator.begin_capture_coverage(CaptureScopeCoverage::System);
        coordinator.note_extend_receipt(&ExtendReceipt {
            attached: absorbed
                .delta
                .endpoints
                .iter()
                .map(|endpoint| crate::attach::capture::AttachedEndpoint {
                    id: endpoint.id,
                    object: endpoint.object,
                    at_ns: 10,
                })
                .collect(),
            ..ExtendReceipt::default()
        });
        let whole = AttachVerdict::Admitted {
            endpoints: 2,
            reasons: Vec::new(),
        };
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, Some(&whole)),
            Some(CoverageNote::Watched { since_ns: 10 })
        );
        let partial = AttachVerdict::Admitted {
            endpoints: 2,
            reasons: vec![
                "admitted module needs 3 more; the set is full — 3 endpoints not added; kept its 2 retained endpoints"
                    .into(),
            ],
        };
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, Some(&partial)),
            Some(CoverageNote::Unknown(UnknownReason::CapacityLimited(
                ENDPOINT_RESOURCE
            )))
        );
        let refused = AttachVerdict::Refused {
            reason: "no".into(),
        };
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, Some(&refused)),
            None
        );
        assert_eq!(
            coordinator.capture_coverage_note(ScopeVerdict::Inside, &key, None),
            None
        );
    }

    // ---- C3 review fixes: incarnation-scoped, demotable capture coverage ----

    /// A coordinator over a scripted process source, its attach set holding
    /// one provider with `endpoints` entries, and that provider's catalog
    /// for `pid`.
    pub(super) struct CaptureScene {
        pub(super) _dir: tempfile::TempDir,
        pub(super) source: crate::discovery::caller_registry::tests::ScriptedSource,
        pub(super) coordinator:
            InventoryCoordinator<crate::discovery::caller_registry::tests::ScriptedSource>,
        pub(super) delta: TargetDelta,
        pub(super) verdicts: BTreeMap<AttachModuleKey, AttachVerdict>,
        pub(super) pins: crate::discovery::identity::PinnedObjects,
        pub(super) path: PathBuf,
    }

    impl CaptureScene {
        pub(super) fn new(endpoints: u64) -> Self {
            use crate::discovery::inventory_attach_set::tests as fx;
            let dir = tempfile::tempdir().unwrap();
            let path = fx::provider(&dir, "a.so", "provider-a");
            let pins = fx::pass_pins(&[(&path, "sha-a")]);
            let module = fx::module(&pins, &path, &fx::offsets(endpoints));
            let source = crate::discovery::caller_registry::tests::ScriptedSource::default();
            let mut coordinator = InventoryCoordinator::new(
                Scope::Pid(std::process::id()),
                HookRegistry::builtin(),
                Vec::new(),
                source.clone(),
                RegistryLimits::default_limits(),
            )
            .unwrap();
            let policy = crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget());
            let absorbed = coordinator.attach_set.absorb(
                &fx::lower_named(std::slice::from_ref(&module), &pins, policy),
                &pins,
            );
            Self {
                _dir: dir,
                source,
                coordinator,
                delta: absorbed.delta,
                verdicts: absorbed.verdicts,
                pins,
                path,
            }
        }

        pub(super) fn attach_all(&mut self, at_ns: u64, custody: ScopeCustody) {
            let receipt = ExtendReceipt {
                attached: self
                    .delta
                    .endpoints
                    .iter()
                    .map(|endpoint| crate::attach::capture::AttachedEndpoint {
                        id: endpoint.id,
                        object: endpoint.object,
                        at_ns,
                    })
                    .collect(),
                custody: Some(custody),
                ..ExtendReceipt::default()
            };
            self.coordinator.note_extend_receipt(&receipt);
        }

        pub(super) fn project(&mut self, pid: u32, now_ns: u64) {
            let path = self.path.clone();
            self.project_paths(pid, &[&path], now_ns);
        }

        pub(super) fn project_paths(&mut self, pid: u32, paths: &[&std::path::Path], now_ns: u64) {
            // Collected under the incarnation reconcile holds for the pid.
            let generation = self
                .coordinator
                .adapter
                .live_id(pid)
                .and_then(|caller| self.coordinator.adapter.record(caller))
                .map(|record| crate::inspect_system::MemberGeneration {
                    start_time: record.start_time,
                    exe: record.exe.clone(),
                });
            let catalog = capture_catalog(&self.pins, paths, pid, generation);
            self.coordinator
                .project_catalog(&catalog, &self.verdicts, now_ns);
        }

        pub(super) fn coverage(
            &self,
            caller: CallerId,
        ) -> crate::discovery::caller_registry::UseCoverage {
            let registry = &self.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has an edge");
            registry.coverage(edge)
        }
    }

    fn watched(coverage: &crate::discovery::caller_registry::UseCoverage) -> bool {
        matches!(
            coverage,
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse { .. }
        )
    }

    fn lost_with(coverage: &crate::discovery::caller_registry::UseCoverage, needle: &str) -> bool {
        matches!(
            coverage,
            crate::discovery::caller_registry::UseCoverage::Unknown(UnknownReason::Loss(reason))
                if reason.contains(needle)
        )
    }

    fn incarnation(pid: u32, start_time: u64) -> CaptureScopeCoverage {
        CaptureScopeCoverage::Pid(ScopeIncarnation {
            pid,
            start_time: Some(start_time),
        })
    }

    fn witness_batch() -> WitnessBatch {
        WitnessBatch {
            domain: crate::attach::capture::NativeDomainId::mint(),
            phase: crate::attach::capture::CapturePhase::Active,
            rows: Vec::new(),
            integrity: Vec::new(),
            integrity_total: 0,
            visited: 0,
            sweep_completed: true,
            sweeps_completed: 1,
            row_bound_reached: false,
            deadline_reached: false,
            read_failures: Vec::new(),
            unrecorded_rows: 0,
            sweep_gaps: false,
            counts: Vec::new(),
            refresh_sweep_completed: true,
            refresh_sweep_gaps: false,
            refresh_deadline_reached: false,
            refresh_sweeps_completed: 1,
            seen_rows: 0,
            pair_limit: 64,
            health: crate::attach::capture::CaptureHealth::default(),
            health_regression: None,
            health_unproven: None,
            health_baseline_ns: 0,
            health_read_ns: 150,
            rows_anchor_ns: 151,
            rows_read_ns: 151,
            counts_read_ns: 151,
            changed_objects: Vec::new(),
            custody: ScopeCustody::PidHeld,
            custody_proven_ns: None,
            lifecycle_proven_ns: u64::MAX,
            lifecycle_loss: None,
            unsettled: false,
        }
    }

    #[test]
    fn cgroup_receipts_and_clean_reads_never_claim_quiet_membership() {
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        scene.attach_all(100, ScopeCustody::CgroupHeld);
        let mut clean = witness_batch();
        clean.custody = ScopeCustody::CgroupHeld;
        for at in [120, 180] {
            scene.coordinator.note_witness_batch(&clean);
            scene.project(7, at);
            scene.coordinator.commit_batch(false).unwrap();
            assert_eq!(
                scene.coverage(caller),
                UseCoverage::Unknown(UnknownReason::ScopeMembershipUnproven)
            );
        }
        assert_eq!(
            scene.coordinator.capture_scope_verdict(caller, 7),
            ScopeVerdict::Cgroup
        );
        scene.coordinator.end_capture_coverage(200);
        scene.project(7, 250);
        scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            scene.coverage(caller),
            UseCoverage::Unknown(UnknownReason::ScopeMembershipUnproven)
        );
    }

    #[test]
    fn cgroup_membership_uncertainty_preserves_counted_positive_history() {
        let (mut native, caller) = NativeScene::new();
        native
            .scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        native.scene.attach_all(100, ScopeCustody::CgroupHeld);
        native.scene.project(7, 120);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Unknown(UnknownReason::ScopeMembershipUnproven)
        );
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        let cgroup_read = |native: &NativeScene, rows| {
            let NativeBatch::Witness(mut batch) = native.stamps.read(native.domain, rows) else {
                unreachable!("the scripted read constructs a witness batch")
            };
            batch.custody = ScopeCustody::CgroupHeld;
            batch
        };
        native.stage(NativeBatch::Witness(cgroup_read(&native, vec![row])));
        native.drain();
        native.stage(NativeBatch::Witness(cgroup_read(&native, Vec::new())));
        native.scene.coordinator.commit_batch(false).unwrap();
        let mut refreshed = cgroup_read(&native, Vec::new());
        refreshed.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: native.scene.delta.endpoints[0].object,
            count: 7,
        }];
        native.stage(NativeBatch::Witness(refreshed));
        native.scene.project(7, 2000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
        let edge = native
            .scene
            .coordinator
            .registry
            .edges()
            .find(|edge| edge.caller == caller)
            .unwrap();
        assert_eq!(edge.entry_count, 7);
    }

    fn cgroup_retained_history_scene() -> (NativeScene, CallerId) {
        let (mut native, caller) = NativeScene::new();
        std::fs::write(native.scene._dir.path().join("cgroup.procs"), b"").unwrap();
        native.scene.coordinator.engine.scope =
            crate::scope::cgroup(native.scene._dir.path()).unwrap();
        native
            .scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        native.scene.attach_all(100, ScopeCustody::CgroupHeld);
        native.scene.project(7, 120);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.answer(7, 500, 41);
        let first = native.row(41, 1, 7, 100, 0);
        let cgroup_read = |native: &NativeScene, rows| {
            let NativeBatch::Witness(mut batch) = native.stamps.read(native.domain, rows) else {
                unreachable!("the scripted read constructs a witness batch")
            };
            batch.custody = ScopeCustody::CgroupHeld;
            batch
        };
        native.stage(NativeBatch::Witness(cgroup_read(&native, vec![first])));
        native.drain();
        native.stage(NativeBatch::Witness(cgroup_read(&native, Vec::new())));
        native.scene.coordinator.commit_batch(false).unwrap();
        let mut refreshed = cgroup_read(&native, Vec::new());
        refreshed.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: native.scene.delta.endpoints[0].object,
            count: 7,
        }];
        native.stage(NativeBatch::Witness(refreshed));
        native.scene.project(7, 2_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false,
            }
        );
        (native, caller)
    }

    fn assert_cgroup_old_history_only(native: &NativeScene, caller: CallerId) {
        let adapter = &native.scene.coordinator.adapter;
        assert!(adapter.record(caller).unwrap().retired);
        assert_eq!(
            adapter.live_id(7),
            None,
            "a tracked PID cannot authorize an outside or unproven successor"
        );
        assert_eq!(
            adapter.len(),
            1,
            "never mint a successor just to retire old"
        );
        let edge = native
            .scene
            .coordinator
            .registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the old history stays retained");
        assert_eq!(edge.entry_count, 7);
        assert_eq!(
            edge.mapping,
            crate::discovery::caller_registry::MappingState::Ended,
            "registry retirement must be consumed"
        );
    }

    #[test]
    fn cgroup_reconcile_empty_scope_never_admits_outside_exec_successor() {
        let (mut native, caller) = cgroup_retained_history_scene();
        native.scene.source.exec(7, 200, "/bin/outside");
        native.scene.coordinator.observe_empty_pass(
            &mut UnavailableImageGuard,
            &mut native.cookies,
            "scoped collection has no positive member transaction",
            2_000,
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_cgroup_old_history_only(&native, caller);
        assert_eq!(
            native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .lifecycle,
            crate::discovery::caller_registry::CallerLifecycle::ExecRetired
        );
    }

    #[test]
    fn cgroup_reconcile_partial_scope_never_admits_unknown_reused_successor() {
        let (mut native, caller) = cgroup_retained_history_scene();
        native.scene.source.spawn(7, 700);
        native.scene.source.blind(7);
        native.scene.coordinator.observe_empty_pass(
            &mut UnavailableImageGuard,
            &mut native.cookies,
            "scoped membership sampling was interrupted",
            2_000,
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_cgroup_old_history_only(&native, caller);
    }

    #[test]
    fn cgroup_exec_transition_never_admits_successor_without_current_scope_transaction() {
        let (mut native, caller) = cgroup_retained_history_scene();
        let later = native.row(41, 2, 7, 200, 1);
        native.witness(vec![later]);
        assert_cgroup_old_history_only(&native, caller);
        assert_eq!(
            native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .lifecycle,
            crate::discovery::caller_registry::CallerLifecycle::ExecRetired
        );
    }

    fn cgroup_os_scene() -> (
        tempfile::TempDir,
        crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild,
        InventoryCoordinator<crate::discovery::caller_registry::OsProcessSource>,
    ) {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("cgroup.procs"),
            format!("{}\n", child.id()),
        )
        .unwrap();
        let mut coordinator = InventoryCoordinator::new(
            crate::scope::cgroup(fixture.path()).unwrap(),
            HookRegistry::builtin(),
            Vec::new(),
            crate::discovery::caller_registry::OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        coordinator.begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        (fixture, child, coordinator)
    }

    pub(crate) fn cgroup_provider_scene() -> (
        tempfile::TempDir,
        crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild,
        InventoryCoordinator<OsProcessSource>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let provider = gcc(
            dir.path(),
            "scoped-provider.so",
            &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
            &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
            &[],
        );
        gcc(
            dir.path(),
            "scoped-driver",
            &manifest.join("tests/fixtures/catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let child = spawn_cgroup_provider_child(dir.path(), &provider, "ready");
        std::fs::write(dir.path().join("cgroup.procs"), format!("{}\n", child.id())).unwrap();
        let mut coordinator = InventoryCoordinator::new(
            crate::scope::cgroup(dir.path()).unwrap(),
            HookRegistry::builtin(),
            vec![provider],
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        coordinator.begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        (dir, child, coordinator)
    }

    fn spawn_cgroup_provider_child(
        dir: &std::path::Path,
        provider: &std::path::Path,
        ready_name: &str,
    ) -> crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild {
        use crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild;
        let ready = dir.join(ready_name);
        OwnedStoppedChild::spawn_stopped(
            std::process::Command::new(dir.join("scoped-driver"))
                .arg("--ready")
                .arg(&ready)
                .arg("--call")
                .arg(provider)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null()),
            |pid| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !ready.exists() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "owned provider child did not finish startup"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                // SAFETY: pid names the child retained by spawn_stopped.
                assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) }, 0);
            },
        )
    }

    struct ReturningLivenessSource {
        control: CollectionControl,
        armed: std::rc::Rc<std::cell::Cell<bool>>,
        returned: std::rc::Rc<std::cell::Cell<usize>>,
        successful: std::rc::Rc<std::cell::Cell<usize>>,
        stop_on_return: bool,
        proc_fallback: bool,
        signal_on_return: Option<Arc<std::sync::atomic::AtomicUsize>>,
    }

    impl crate::discovery::caller_registry::ProcessSource for ReturningLivenessSource {
        type Pin = crate::process::PidPin;

        fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
            OsProcessSource.open(pid)
        }
        fn still_the_same(&self, pin: &Self::Pin) -> bool {
            // The fallback branch performs the same actual /proc start-time
            // operation as PidPin's documented fallback, without changing the
            // ordinary source or forcing the host's pidfd capability off.
            let same = if self.proc_fallback {
                crate::process::process_start_time(pin.pid()).ok() == pin.start_time()
            } else {
                OsProcessSource.still_the_same(pin)
            };
            if self.armed.get() {
                self.returned.set(self.returned.get() + 1);
                if same {
                    self.successful.set(self.successful.get() + 1);
                }
                if self.stop_on_return {
                    if let Some(signals) = &self.signal_on_return {
                        signals.store(1, std::sync::atomic::Ordering::SeqCst);
                    } else {
                        self.control.cancel();
                    }
                }
            }
            same
        }
        fn start_time(&self, pid: u32) -> Option<u64> {
            OsProcessSource.start_time(pid)
        }
        fn exe_identity(&self, pid: u32) -> Option<crate::discovery::caller_registry::ExeIdentity> {
            OsProcessSource.exe_identity(pid)
        }
        fn gone(&self, pid: u32) -> bool {
            OsProcessSource.gone(pid)
        }
    }

    fn cgroup_returning_liveness_control(
        stop_on_return: bool,
        proc_fallback: bool,
        original_signal_source: bool,
    ) {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (fixture, child, old_coordinator) = cgroup_provider_scene();
        drop(old_coordinator);
        let signal_flag = original_signal_source
            .then(crate::inventory_dashboard::StopFlag::test_without_handlers);
        let signals = signal_flag.as_ref().map(|flag| flag.signal_source());
        let control = signals.as_ref().map_or_else(
            || CollectionControl::new(None),
            |source| CollectionControl::new(None).with_operator_stop_source(Arc::clone(source)),
        );
        let armed = std::rc::Rc::new(std::cell::Cell::new(false));
        let returned = std::rc::Rc::new(std::cell::Cell::new(0));
        let successful = std::rc::Rc::new(std::cell::Cell::new(0));
        let source = ReturningLivenessSource {
            control: control.clone(),
            armed: armed.clone(),
            returned: returned.clone(),
            successful: successful.clone(),
            stop_on_return,
            proc_fallback,
            signal_on_return: signals,
        };
        let mut coordinator = InventoryCoordinator::new(
            crate::scope::cgroup(fixture.path()).unwrap(),
            HookRegistry::builtin(),
            vec![fixture.path().join("scoped-provider.so")],
            source,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        coordinator.begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                control,
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(child.id())
                .is_some_and(|preparation| preparation.check()),
            "the real provider child supplies attributable facts before preparation"
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        provider_read_test::observe(
            move || armed.set(true), // after actual provider retention, before final sampling
            || coordinator.commit_batch(false).unwrap(),
        );
        assert_eq!(
            returned.get(),
            1,
            "exactly the final source liveness operation returned"
        );
        assert_eq!(
            successful.get(),
            1,
            "the retained child remained the same generation"
        );
        if let Some(flag) = &signal_flag {
            assert_eq!(flag.signal_count(), usize::from(stop_on_return));
        }
        let completion = coordinator.take_cgroup_completion().unwrap();
        if stop_on_return {
            assert_eq!(
                completion.admitted, 0,
                "stop during returning liveness must precede ID mint"
            );
            assert_eq!(coordinator.adapter.live_id(child.id()), None);
            assert_eq!(coordinator.adapter.records().count(), 0);
            assert_eq!(coordinator.attach_set.len(), 0);
            assert_eq!(coordinator.registry.caller_count(), 0);
            assert_eq!(
                completion.outcome,
                ScopedCollectionOutcome::Cancelled(
                    crate::scope::inventory_cgroup::CollectionStop::OperatorStop
                )
            );
        } else {
            assert_eq!(completion.admitted, 1);
            assert!(coordinator.adapter.live_id(child.id()).is_some());
            assert!(coordinator.attach_set.len() > 0);
            assert!(coordinator.registry.edges().next().is_some());
        }
    }

    #[test]
    fn cgroup_returning_liveness_stop_prevents_caller_mint() {
        cgroup_returning_liveness_control(true, false, false);
    }

    #[test]
    fn cgroup_returning_liveness_proc_fallback_stop_prevents_caller_mint() {
        cgroup_returning_liveness_control(true, true, false);
    }

    #[test]
    fn cgroup_returning_liveness_healthy_child_keeps_admission() {
        cgroup_returning_liveness_control(false, false, false);
    }

    #[test]
    fn cgroup_runtime_original_signal_after_returning_liveness_prevents_mint() {
        cgroup_returning_liveness_control(true, false, true);
    }

    #[test]
    fn cgroup_runtime_original_signal_liveness_healthy_keeps_admission() {
        cgroup_returning_liveness_control(false, false, true);
    }

    fn cgroup_original_signal_retention_control(stop_on_return: bool) {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (_fixture, child, mut coordinator) = cgroup_provider_scene();
        let flag = crate::inventory_dashboard::StopFlag::test_without_handlers();
        let original_source = flag.signal_source();
        let control =
            CollectionControl::new(None).with_operator_stop_source(Arc::clone(&original_source));
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                control,
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(child.id())
                .is_some_and(|preparation| preparation.check()),
            "real provider child has attributable facts"
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        let returned = std::rc::Rc::new(std::cell::Cell::new(0));
        let count = returned.clone();
        provider_read_test::observe(
            move || {
                count.set(count.get() + 1);
                if stop_on_return {
                    original_source.store(1, std::sync::atomic::Ordering::SeqCst);
                }
            },
            || coordinator.commit_batch(false).unwrap(),
        );
        assert!(
            returned.get() > 0,
            "actual held provider metadata read returned"
        );
        assert_eq!(flag.signal_count(), usize::from(stop_on_return));
        let completion = coordinator.take_cgroup_completion().unwrap();
        if stop_on_return {
            assert_eq!(
                completion.admitted, 0,
                "original signal during final preparation must stop ID mint"
            );
            assert_eq!(coordinator.adapter.live_id(child.id()), None);
            assert_eq!(coordinator.attach_set.len(), 0);
            assert_eq!(coordinator.registry.caller_count(), 0);
            assert_eq!(
                completion.outcome,
                ScopedCollectionOutcome::Cancelled(
                    crate::scope::inventory_cgroup::CollectionStop::OperatorStop
                )
            );
        } else {
            assert_eq!(completion.admitted, 1);
            assert!(coordinator.attach_set.len() > 0);
            assert!(coordinator.registry.edges().next().is_some());
        }
    }

    #[test]
    fn cgroup_runtime_original_signal_after_returning_provider_prevents_mint() {
        cgroup_original_signal_retention_control(true);
    }

    #[test]
    fn cgroup_runtime_original_signal_provider_healthy_keeps_admission() {
        cgroup_original_signal_retention_control(false);
    }

    #[test]
    fn cgroup_review_provider_transaction_admits_after_retention_and_final_sample() {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (_fixture, child, mut coordinator) = cgroup_provider_scene();
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(child.id())
                .is_some_and(|preparation| preparation.check()),
            "a real provider scan produced attributable facts for the held child"
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let read_counter = reads.clone();
        provider_read_test::observe(
            move || read_counter.set(read_counter.get() + 1),
            || coordinator.commit_batch(false).unwrap(),
        );
        assert!(
            reads.get() > 0,
            "real provider retention metadata reads ran"
        );
        assert!(
            coordinator.attach_set.len() > 0,
            "provider endpoints actually admitted"
        );
        assert!(coordinator.registry.edges().count() > 0);
        assert_eq!(coordinator.take_cgroup_completion().unwrap().admitted, 1);
    }

    #[test]
    fn cgroup_review_movement_during_retention_prevents_admission_and_targets() {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (fixture, child, mut coordinator) = cgroup_provider_scene();
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(child.id())
                .is_some_and(|preparation| preparation.check())
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        let membership = fixture.path().join("cgroup.procs");
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let read_counter = reads.clone();
        provider_read_test::observe(
            move || {
                read_counter.set(read_counter.get() + 1);
                std::fs::write(&membership, b"").unwrap();
            },
            || coordinator.commit_batch(false).unwrap(),
        );
        assert!(
            reads.get() > 0,
            "movement occurred after actual provider retention read"
        );
        assert_eq!(
            coordinator.adapter.len(),
            0,
            "the final sample must enclose provider reads"
        );
        assert_eq!(coordinator.attach_set.len(), 0);
        assert_eq!(coordinator.registry.edges().count(), 0);
        assert!(coordinator.take_target_delta().is_empty());
        assert_ne!(
            coordinator.take_cgroup_completion().unwrap().outcome,
            ScopedCollectionOutcome::Complete
        );
    }

    #[test]
    fn cgroup_review_mixed_retention_move_keeps_the_other_valid_member() {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (fixture, moved, mut coordinator) = cgroup_provider_scene();
        let provider = &coordinator.engine.module_hints[0];
        let kept = spawn_cgroup_provider_child(fixture.path(), provider, "ready-second");
        let membership = fixture.path().join("cgroup.procs");
        std::fs::write(&membership, format!("{}\n{}\n", moved.id(), kept.id())).unwrap();
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(moved.id())
                .is_some_and(|preparation| preparation.check())
        );
        assert!(
            collection
                .preparation(kept.id())
                .is_some_and(|preparation| preparation.check())
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        let retained_member = format!("{}\n", kept.id());
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let read_counter = reads.clone();
        provider_read_test::observe(
            move || {
                read_counter.set(read_counter.get() + 1);
                std::fs::write(&membership, &retained_member).unwrap();
            },
            || coordinator.commit_batch(false).unwrap(),
        );
        assert!(
            reads.get() > 0,
            "movement occurred at actual retention metadata read"
        );
        assert_eq!(
            coordinator.adapter.live_id(moved.id()),
            None,
            "the member removed before the final sample is withheld"
        );
        let kept_id = coordinator
            .adapter
            .live_id(kept.id())
            .expect("valid member remains useful");
        assert_eq!(coordinator.adapter.len(), 1);
        assert!(coordinator.attach_set.len() > 0);
        assert!(
            coordinator
                .registry
                .edges()
                .any(|edge| edge.caller == kept_id)
        );
        let completion = coordinator.take_cgroup_completion().unwrap();
        assert_eq!(completion.admitted, 1);
        assert_ne!(completion.outcome, ScopedCollectionOutcome::Complete);
    }

    #[test]
    fn cgroup_review_stop_during_retention_prevents_admission_and_targets() {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (_fixture, child, mut coordinator) = cgroup_provider_scene();
        let control = CollectionControl::new(None);
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                control.clone(),
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(child.id())
                .is_some_and(|preparation| preparation.check())
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let read_counter = reads.clone();
        provider_read_test::observe(
            move || {
                read_counter.set(read_counter.get() + 1);
                control.cancel();
            },
            || coordinator.commit_batch(false).unwrap(),
        );
        assert!(
            reads.get() > 0,
            "stop was requested after actual provider retention read"
        );
        assert_eq!(
            coordinator.adapter.len(),
            0,
            "stop cannot authorize a caller before provider reads end"
        );
        assert_eq!(coordinator.attach_set.len(), 0);
        assert_eq!(coordinator.registry.edges().count(), 0);
        assert!(coordinator.take_target_delta().is_empty());
        assert_eq!(
            coordinator.take_cgroup_completion().unwrap().outcome,
            ScopedCollectionOutcome::Cancelled(
                crate::scope::inventory_cgroup::CollectionStop::OperatorStop
            )
        );
    }

    #[test]
    fn cgroup_tiny_remaining_budget_stops_before_provider_preparation() {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (_fixture, child, mut coordinator) = cgroup_provider_scene();
        let limits = CgroupWalkLimits::default();
        let maximum = limits.work_units;
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                limits,
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(collection.preparation(child.id()).is_some());
        let remaining = maximum - collection.used_work();
        assert!(remaining > 1);
        assert!(collection.work().charge(remaining - 1));
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let counter = reads.clone();
        provider_read_test::observe(
            move || counter.set(counter.get() + 1),
            || coordinator.commit_batch(false).unwrap(),
        );
        assert_eq!(
            reads.get(),
            0,
            "no next provider identity read after allowance exhaustion"
        );
        assert_eq!(coordinator.adapter.len(), 0);
        assert_eq!(coordinator.attach_set.len(), 0);
        assert_ne!(
            coordinator.take_cgroup_completion().unwrap().outcome,
            ScopedCollectionOutcome::Complete
        );
    }

    #[test]
    fn cgroup_exhausted_exec_fence_never_wraps_or_reads_provider_inputs() {
        use crate::discovery::inventory_attach_set::provider_read_test;
        let (_fixture, child, mut coordinator) = cgroup_provider_scene();
        let old = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(old.preparation(child.id()).is_some());
        coordinator.cgroup_fence.exhaust();
        coordinator.cgroup_fence.invalidate();
        let stale_work = old.work();
        assert!(!stale_work.charge(0));
        coordinator.apply_cgroup_collection(old, 1_000).unwrap();
        let reads = std::rc::Rc::new(std::cell::Cell::new(0));
        let counter = reads.clone();
        provider_read_test::observe(
            move || counter.set(counter.get() + 1),
            || coordinator.commit_batch(false).unwrap(),
        );
        let stale = coordinator.take_cgroup_completion().unwrap();
        assert_eq!(
            stale.outcome,
            ScopedCollectionOutcome::Incomplete(
                crate::inspect_system::inventory_cgroup::ScopedCollectionGap::GenerationChanged
            )
        );
        assert_eq!(reads.get(), 0);
        assert_eq!(coordinator.adapter.len(), 0);
        let fresh = coordinator
            .cgroup_collector(
                stale.state,
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert_eq!(fresh.member_pids().count(), 0);
        coordinator.apply_cgroup_collection(fresh, 2_000).unwrap();
        coordinator.commit_batch(false).unwrap();
        assert_eq!(coordinator.adapter.len(), 0);
        assert_eq!(coordinator.attach_set.len(), 0);
        assert_ne!(
            coordinator.take_cgroup_completion().unwrap().outcome,
            ScopedCollectionOutcome::Complete
        );
    }

    #[test]
    fn cgroup_admission_waits_for_true_commit_and_releases_original_after_publish() {
        let (_fixture, child, mut coordinator) = cgroup_os_scene();
        let pid = child.id();
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        let original = collection
            .original_weak(pid)
            .expect("fresh begin retained the original child");
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        assert_eq!(
            coordinator.adapter.len(),
            0,
            "preparation cannot mint an ID"
        );
        assert!(
            original.upgrade().is_some(),
            "pending state retains original custody"
        );
        assert!(coordinator.take_cgroup_completion().is_none());
        coordinator.commit_batch(false).unwrap();
        let completion = coordinator.take_cgroup_completion().unwrap();
        assert_eq!(completion.admitted, 1);
        let id = coordinator
            .adapter
            .live_id(pid)
            .expect("both fresh samples authorize the held generation");
        assert_eq!(completion.events, vec![CallerEvent::Admitted { id }]);
        assert!(
            original.upgrade().is_none(),
            "custody drops only after actual publication"
        );
        assert_eq!(
            coordinator.adapter.record(id).unwrap().authority,
            ImageAuthority::ScanPinned
        );
    }

    #[test]
    fn cgroup_final_sample_occurs_after_apply_and_prevents_moved_member_admission() {
        let (fixture, child, mut coordinator) = cgroup_os_scene();
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert_eq!(
            collection.member_pids().collect::<Vec<_>>(),
            vec![child.id()]
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        std::fs::write(fixture.path().join("cgroup.procs"), b"").unwrap();
        coordinator.commit_batch(false).unwrap();
        assert_eq!(coordinator.adapter.len(), 0);
        assert_eq!(coordinator.registry.edges().count(), 0);
        assert!(coordinator.take_target_delta().endpoints.is_empty());
        let completion = coordinator.take_cgroup_completion().unwrap();
        assert_eq!(completion.admitted, 0);
        assert_ne!(completion.outcome, ScopedCollectionOutcome::Complete);
    }

    #[test]
    fn cgroup_stop_after_apply_never_admits_or_publishes_complete_scope_receipt() {
        let (_fixture, child, mut coordinator) = cgroup_os_scene();
        let control = CollectionControl::new(None);
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                control.clone(),
                None,
            )
            .unwrap()();
        let original = collection.original_weak(child.id()).unwrap();
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        control.cancel();
        coordinator.commit_batch(false).unwrap();
        assert_eq!(coordinator.adapter.len(), 0);
        assert!(original.upgrade().is_none());
        assert_eq!(
            coordinator.take_cgroup_completion().unwrap().outcome,
            ScopedCollectionOutcome::Cancelled(
                crate::scope::inventory_cgroup::CollectionStop::OperatorStop
            )
        );
    }

    #[test]
    fn cgroup_generation_exit_after_preparation_never_mints_a_caller() {
        let (_fixture, child, mut coordinator) = cgroup_os_scene();
        let collection = coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert_eq!(
            collection.member_pids().collect::<Vec<_>>(),
            vec![child.id()]
        );
        coordinator
            .apply_cgroup_collection(collection, 1_000)
            .unwrap();
        drop(child); // RAII kills and reaps only the owned process.
        coordinator.commit_batch(false).unwrap();
        assert_eq!(coordinator.adapter.len(), 0);
        assert_ne!(
            coordinator.take_cgroup_completion().unwrap().outcome,
            ScopedCollectionOutcome::Complete
        );
    }

    #[test]
    fn cgroup_same_image_reentry_keeps_the_original_caller_id() {
        let (fixture, child, mut coordinator) = cgroup_os_scene();
        let pid = child.id();
        let mut state = CgroupWalkState::default();
        let mut admitted = None;
        for (pass, members) in [format!("{pid}\n"), String::new(), format!("{pid}\n")]
            .into_iter()
            .enumerate()
        {
            std::fs::write(fixture.path().join("cgroup.procs"), members).unwrap();
            let collection = coordinator
                .cgroup_collector(
                    state,
                    CgroupWalkLimits::default(),
                    CollectionControl::new(None),
                    None,
                )
                .unwrap()();
            coordinator
                .apply_cgroup_collection(collection, 1_000 + pass as u64)
                .unwrap();
            coordinator.commit_batch(false).unwrap();
            let completion = coordinator.take_cgroup_completion().unwrap();
            state = completion.state;
            let current = coordinator.adapter.live_id(pid).unwrap();
            if pass == 0 {
                admitted = Some(current);
                assert_eq!(completion.admitted, 1);
            } else {
                assert_eq!(Some(current), admitted);
                assert_eq!(completion.admitted, 0);
            }
            assert!(
                !coordinator.adapter.record(current).unwrap().retired,
                "mere scope movement does not prove exit"
            );
        }
        assert_eq!(coordinator.adapter.len(), 1);
    }

    #[test]
    fn cgroup_partial_candidate_passes_eventually_admit_a_later_member() {
        let (fixture, child, mut coordinator) = cgroup_os_scene();
        let pid = child.id();
        std::fs::write(
            fixture.path().join("cgroup.procs"),
            format!("4000000000\n4000000001\n4000000002\n{pid}\n"),
        )
        .unwrap();
        let mut state = CgroupWalkState::default();
        let mut reached = false;
        for pass in 0..6 {
            let limits = CgroupWalkLimits {
                members: 1,
                ..CgroupWalkLimits::default()
            };
            let collection = coordinator
                .cgroup_collector(state, limits, CollectionControl::new(None), Some(1))
                .unwrap()();
            coordinator
                .apply_cgroup_collection(collection, 1_000 + pass)
                .unwrap();
            coordinator.commit_batch(false).unwrap();
            let completion = coordinator.take_cgroup_completion().unwrap();
            assert_ne!(
                completion.outcome,
                ScopedCollectionOutcome::Complete,
                "partial passes never union into complete scope absence"
            );
            state = completion.state;
            if coordinator.adapter.live_id(pid).is_some() {
                reached = true;
                break;
            }
        }
        assert!(
            reached,
            "later candidate can be admitted when both fresh samples and scan fit"
        );
        assert_eq!(coordinator.adapter.len(), 1);
    }

    #[test]
    fn cgroup_wrong_root_and_legacy_catalog_jobs_cannot_supply_authority() {
        let (_fixture, _child, mut coordinator) = cgroup_os_scene();
        assert!(coordinator.collector(InventoryScope::System, None)().is_err());
        let (_other_fixture, _, other) = cgroup_os_scene();
        let collection = other
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(
            coordinator
                .apply_cgroup_collection(collection, 1_000)
                .is_err()
        );
        assert_eq!(coordinator.adapter.len(), 0);
    }

    #[test]
    fn cgroup_catalog_without_transaction_cannot_admit_a_fresh_outside_caller() {
        let (_fixture, child, mut coordinator) = cgroup_os_scene();
        let catalog = crate::inspect_system::collect_pid(
            child.id(),
            &[],
            &HookRegistry::builtin(),
            crate::plan::AdmissionPolicy::Inventory(coordinator.attach_set.budget()),
        )
        .unwrap();
        assert!(
            catalog
                .processes
                .iter()
                .any(|process| process.pid == child.id() && process.status.attributable()),
            "the unscoped catalog actually observed the positive child"
        );
        coordinator.apply_catalog(
            catalog,
            &mut UnavailableImageGuard,
            &mut ScanOnlyIdentity,
            u64::MAX,
            1_000,
        );
        coordinator.commit_batch(false).unwrap();
        assert_eq!(coordinator.adapter.len(), 0);
        assert_eq!(coordinator.registry.edges().count(), 0);
    }

    #[test]
    fn cgroup_native_exec_invalidates_pending_transaction_even_with_unchanged_scalars() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let mut scene = CaptureScene::new(2);
        scene.source.spawn_matching_process(pid);
        let birth = scene.source.start_time(pid).unwrap();
        let caller = scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene.project(pid, 60);
        scene.coordinator.commit_batch(false).unwrap();
        std::fs::write(scene._dir.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
        scene.coordinator.engine.scope = crate::scope::cgroup(scene._dir.path()).unwrap();
        scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        scene.attach_all(100, ScopeCustody::CgroupHeld);
        let mut native = NativeScene::over(scene, 0);
        native.answer(pid, birth, 41);
        native.witness(vec![native.row(41, 1, pid, 100, 0)]);
        let collection = native
            .scene
            .coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(pid)
                .is_some_and(|preparation| preparation.check()),
            "the pending scan transaction is usable before EXEC invalidation"
        );
        let before = native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .unwrap()
            .exe
            .clone();
        native
            .scene
            .coordinator
            .apply_cgroup_collection(collection, 2_000)
            .unwrap();
        native.witness(vec![native.row(41, 2, pid, 200, 1)]);
        assert_eq!(
            native.scene.source.exe_identity(pid),
            before,
            "same scalar executable identity cannot reconstruct the invalidated proof"
        );
        assert!(
            native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .retired
        );
        assert_eq!(native.scene.coordinator.adapter.live_id(pid), None);
        assert_eq!(native.scene.coordinator.adapter.len(), 1);
        assert_eq!(
            native
                .scene
                .coordinator
                .registry
                .edges()
                .find(|edge| edge.caller == caller)
                .unwrap()
                .mapping,
            MappingState::Ended
        );
        assert_eq!(
            native
                .scene
                .coordinator
                .take_cgroup_completion()
                .unwrap()
                .admitted,
            0
        );
    }

    #[test]
    fn cgroup_review_exec_between_collect_and_apply_invalidates_stale_job() {
        let child =
            crate::inspect_system::demotion_retirement_producer_tests::OwnedStoppedChild::new();
        let pid = child.id();
        let mut scene = CaptureScene::new(2);
        scene.source.spawn_matching_process(pid);
        let birth = scene.source.start_time(pid).unwrap();
        let caller = scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene.project(pid, 60);
        scene.coordinator.commit_batch(false).unwrap();
        std::fs::write(scene._dir.path().join("cgroup.procs"), format!("{pid}\n")).unwrap();
        scene.coordinator.engine.scope = crate::scope::cgroup(scene._dir.path()).unwrap();
        scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::Cgroup);
        scene.attach_all(100, ScopeCustody::CgroupHeld);
        let mut native = NativeScene::over(scene, 0);
        native.answer(pid, birth, 41);
        native.witness(vec![native.row(41, 1, pid, 100, 0)]);
        let collection = native
            .scene
            .coordinator
            .cgroup_collector(
                CgroupWalkState::default(),
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        assert!(
            collection
                .preparation(pid)
                .is_some_and(|preparation| preparation.check()),
            "the collected transaction is usable before EXEC invalidation"
        );
        let before = native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .unwrap()
            .exe
            .clone();
        native.witness(vec![native.row(41, 2, pid, 200, 1)]);
        native
            .scene
            .coordinator
            .apply_cgroup_collection(collection, 2_000)
            .unwrap();
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.source.exe_identity(pid),
            before,
            "same scalar executable identity cannot reconstruct the invalidated proof"
        );
        assert!(
            native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .retired
        );
        assert_eq!(native.scene.coordinator.adapter.live_id(pid), None);
        assert_eq!(native.scene.coordinator.adapter.len(), 1);
        assert_eq!(
            native
                .scene
                .coordinator
                .registry
                .edges()
                .find(|edge| edge.caller == caller)
                .unwrap()
                .mapping,
            MappingState::Ended
        );
        let stale = native.scene.coordinator.take_cgroup_completion().unwrap();
        assert_eq!(stale.admitted, 0);
        assert_ne!(stale.outcome, ScopedCollectionOutcome::Complete);
        let fresh = native
            .scene
            .coordinator
            .cgroup_collector(
                stale.state,
                CgroupWalkLimits::default(),
                CollectionControl::new(None),
                None,
            )
            .unwrap()();
        native
            .scene
            .coordinator
            .apply_cgroup_collection(fresh, 4_000)
            .unwrap();
        native.scene.coordinator.commit_batch(false).unwrap();
        let fresh = native.scene.coordinator.take_cgroup_completion().unwrap();
        assert_eq!(
            fresh.admitted, 1,
            "a fresh next job can authorize the current image"
        );
        assert_ne!(native.scene.coordinator.adapter.live_id(pid), Some(caller));
        assert_eq!(native.scene.coordinator.adapter.len(), 2);
        assert!(
            native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .retired
        );
    }

    #[test]
    fn pid_reuse_within_a_pass_is_never_watched_and_demotes_the_original() {
        // I2/M10: coverage is scoped by incarnation (pid + start time), and
        // a custody loss ends watches already staged in the same batch (no
        // clean read proved them, so they read unknown; C5.2 D2).
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let original = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(7, 500));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(7, 120);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(original),
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
                since_ns: 100,
                until_ns: None
            }
        );

        // Within the next pass the original exits and pid 7 is reused.
        scene.source.kill(7);
        scene.source.spawn(7, 600);
        let observed: BTreeSet<u32> = [7].into();
        let events = scene.coordinator.adapter.reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            130,
        );
        let reused = match events.as_slice() {
            [crate::discovery::caller_registry::CallerEvent::Reused { old, new }] => {
                assert_eq!(*old, original);
                *new
            }
            other => panic!("expected one reuse, got {other:?}"),
        };
        // The pass stages the reused pid's edge, then (later in the same
        // batch) the facade's custody poll reports the loss.
        scene.project(7, 140);
        assert_eq!(
            scene.coordinator.capture_scope_verdict(reused, 7),
            ScopeVerdict::Outside,
            "a reused pid is another incarnation"
        );
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidLost {
                at_ns: 125,
                reason: "PID custody lost: the PID target exited".into(),
            });
        scene.coordinator.registry.publish();
        assert!(
            !watched(&scene.coverage(reused)),
            "{:?}",
            scene.coverage(reused)
        );
        assert!(
            lost_with(&scene.coverage(original), "PID target exited"),
            "{:?}",
            scene.coverage(original)
        );
        assert!(
            scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native capture scope custody unproven"),
        );
        // A later pass still never watches the reused incarnation.
        scene.project(7, 160);
        scene.coordinator.registry.publish();
        assert!(!watched(&scene.coverage(reused)));
    }

    #[test]
    fn a_nonleader_exec_before_the_first_pass_never_reads_watched() {
        // I2/M10: the exec record arrives after the first projection staged
        // a watch in the same batch; the custody end wins (no clean read
        // proved the watch), and every later pass reads the exec loss.
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(9, 700);
        scene.source.exec(9, 200, "/bin/successor");
        let caller = scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(9, 700));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(9, 120);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 90,
                reason: "an exec of the PID target was observed".into(),
            });
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "exec"),
            "{:?}",
            scene.coverage(caller)
        );
        scene.project(9, 140);
        scene.coordinator.registry.publish();
        assert!(lost_with(&scene.coverage(caller), "exec"));
        // A start time that cannot be proven never matches either.
        let mut blind = CaptureScene::new(1);
        blind.source.spawn(11, 800);
        let other = blind
            .coordinator
            .adapter
            .admit(11, ImageAuthority::ScanPinned, 50)
            .unwrap();
        blind
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::Pid(ScopeIncarnation {
                pid: 11,
                start_time: None,
            }));
        assert_eq!(
            blind.coordinator.capture_scope_verdict(other, 11),
            ScopeVerdict::Unproven
        );
    }

    #[test]
    fn a_second_image_of_the_scope_incarnation_is_not_the_bound_caller() {
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(5, 300);
        let first = scene
            .coordinator
            .adapter
            .admit(5, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(5, 300));
        assert_eq!(
            scene.coordinator.capture_scope_verdict(first, 5),
            ScopeVerdict::Inside
        );
        scene.source.exec(5, 201, "/bin/next");
        let observed: BTreeSet<u32> = [5].into();
        let events =
            scene
                .coordinator
                .adapter
                .reconcile(&observed, &mut |_| ImageAuthority::ScanPinned, 60);
        let [crate::discovery::caller_registry::CallerEvent::ExecRetired { new, .. }] =
            events.as_slice()
        else {
            panic!("expected an exec retirement: {events:?}");
        };
        assert_eq!(
            scene.coordinator.capture_scope_verdict(*new, 5),
            ScopeVerdict::LaterImage
        );
    }

    #[test]
    fn health_and_changed_objects_withhold_demote_or_restart_watches() {
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(7, 500));
        // I5: unproven health withholds the first watch; it is not sticky.
        let mut unproven = witness_batch();
        unproven.health_unproven = Some("native capture health was unreadable".into());
        scene.coordinator.note_witness_batch(&unproven);
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(7, 120);
        scene.coordinator.registry.publish();
        assert!(!watched(&scene.coverage(caller)));
        scene.coordinator.note_witness_batch(&witness_batch());
        scene.project(7, 130);
        scene.coordinator.registry.publish();
        assert!(watched(&scene.coverage(caller)));
        // Closure 2: a rise demotes the interval (dated at the baseline);
        // a new interval starts only from the detecting read.
        let mut rose = witness_batch();
        rose.health_regression =
            Some("native capture health counters rose: EVIDENCE[3] 0->1".into());
        rose.health_baseline_ns = 125;
        rose.health_read_ns = 160;
        scene.coordinator.note_witness_batch(&rose);
        scene.coordinator.registry.publish();
        assert!(lost_with(&scene.coverage(caller), "EVIDENCE[3]"));
        scene.project(7, 170);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(caller),
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
                since_ns: 160,
                until_ns: None
            },
            "the restarted watch never covers the baseline..detection window"
        );
        // M8: a provider modified in place makes its module unknown.
        let mut changed = witness_batch();
        changed.changed_objects = vec![scene.delta.endpoints[0].object];
        scene.coordinator.note_witness_batch(&changed);
        scene.project(7, 180);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "modified in place"),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn stop_freezes_watches_at_the_last_clean_read() {
        // Closure 1/4: stop never wipes no-use; each watch ends at the last
        // proven-clean read, an unproven terminal read never extends it,
        // and a watch no clean read proved reads unknown.
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(8, 510);
        let caller = scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(8, 510));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(8, 120);
        let mut clean = witness_batch();
        clean.health_read_ns = 200;
        scene.coordinator.note_witness_batch(&clean);
        let mut terminal = witness_batch();
        terminal.health_read_ns = 280;
        terminal.health_unproven = Some("native capture health was unreadable".into());
        terminal.unsettled = true;
        scene.coordinator.note_witness_batch(&terminal);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        let frozen = crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
            since_ns: 100,
            until_ns: Some(200),
        };
        assert_eq!(scene.coverage(caller), frozen);
        scene.project(8, 320);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(caller),
            frozen,
            "nothing restarts after stop"
        );

        let mut unproved = CaptureScene::new(1);
        unproved.source.spawn(9, 520);
        let caller = unproved
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 50)
            .unwrap();
        unproved
            .coordinator
            .begin_capture_coverage(incarnation(9, 520));
        unproved.attach_all(100, ScopeCustody::PidHeld);
        unproved.project(9, 120);
        unproved.coordinator.end_capture_coverage(300);
        unproved.coordinator.registry.publish();
        assert!(
            lost_with(&unproved.coverage(caller), "clean health read"),
            "{:?}",
            unproved.coverage(caller)
        );
    }

    /// A scene with one caller watched since 100 and a clean read at 200.
    fn watched_scene(pid: u32, start: u64) -> (CaptureScene, CallerId) {
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(pid, start);
        let caller = scene
            .coordinator
            .adapter
            .admit(pid, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(pid, start));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(pid, 120);
        let mut clean = witness_batch();
        clean.health_read_ns = 200;
        scene.coordinator.note_witness_batch(&clean);
        (scene, caller)
    }

    fn last_clean(scene: &CaptureScene) -> Option<u64> {
        scene.coordinator.capture.as_ref().unwrap().last_clean_ns
    }

    #[test]
    fn nothing_noted_after_stop_touches_a_frozen_interval() {
        // Closure 2 I-1: the normal end of a --pid run. The target exits
        // after stop; the terminal batch carries the lost custody, dated
        // at the last held poll (before the clean read's stamp).
        let (mut scene, caller) = watched_scene(7, 500);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        let frozen = crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
            since_ns: 100,
            until_ns: Some(200),
        };
        assert_eq!(scene.coverage(caller), frozen);
        let mut terminal = witness_batch();
        terminal.health_read_ns = 310;
        terminal.health_regression =
            Some("native capture health counters rose: EVIDENCE[0] 0->1".into());
        terminal.health_baseline_ns = 150;
        terminal.custody = ScopeCustody::PidLost {
            at_ns: 199,
            reason: "PID custody lost: the PID target exited".into(),
        };
        scene.coordinator.note_witness_batch(&terminal);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 150,
                reason: "an exec of the PID target was observed".into(),
            });
        scene.coordinator.note_extend_receipt(&ExtendReceipt {
            custody: Some(ScopeCustody::PidLost {
                at_ns: 199,
                reason: "PID custody lost".into(),
            }),
            ..ExtendReceipt::default()
        });
        scene.project(7, 320);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen, "a post-stop note wiped it");
        assert_eq!(last_clean(&scene), Some(200));
    }

    #[test]
    fn a_clean_read_never_claims_past_its_custody_proof() {
        // Closure 2 I-1(b): the custody poll precedes the health stamp.
        let (mut scene, _) = watched_scene(7, 500);
        let mut read = witness_batch();
        read.health_read_ns = 260;
        read.custody_proven_ns = Some(240);
        scene.coordinator.note_witness_batch(&read);
        assert_eq!(last_clean(&scene), Some(240));
    }

    #[test]
    fn each_clean_read_gate_blocks_the_clean_instant() {
        // Closure 2 M-1: unproven health, a rise, unheld custody, and an
        // already-unproven capture each keep the last clean instant.
        let gated: [fn(&mut WitnessBatch); 3] = [
            |batch| batch.health_unproven = Some("unreadable".into()),
            |batch| batch.health_regression = Some("EVIDENCE[1] 0->1".into()),
            |batch| {
                batch.custody = ScopeCustody::PidUnproven {
                    at_ns: 250,
                    reason: "leader exited".into(),
                }
            },
        ];
        for gate in gated {
            let (mut scene, _) = watched_scene(7, 500);
            let mut read = witness_batch();
            read.health_read_ns = 260;
            gate(&mut read);
            scene.coordinator.note_witness_batch(&read);
            assert_eq!(last_clean(&scene), Some(200), "{read:?}");
        }
        let (mut scene, _) = watched_scene(7, 500);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 210,
                reason: "ring loss".into(),
            });
        let mut read = witness_batch();
        read.health_read_ns = 260;
        scene.coordinator.note_witness_batch(&read);
        assert_eq!(
            last_clean(&scene),
            Some(200),
            "an unproven capture is never clean again"
        );
    }

    // ---- Task 6 C5.2: settle native reads at stop ----

    fn frozen(since_ns: u64, until_ns: u64) -> crate::discovery::caller_registry::UseCoverage {
        crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
            since_ns,
            until_ns: Some(until_ns),
        }
    }

    #[test]
    fn a_custody_loss_before_stop_freezes_watches_at_the_last_clean_read() {
        // C5.2 D2: watch at 100, clean read at 200, custody lost at 250,
        // stop at 300 → `WatchedNoUse{100, Some(200)}`, not a demotion.
        let (mut scene, caller) = watched_scene(7, 500);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidLost {
                at_ns: 250,
                reason: "PID custody lost: the PID target exited".into(),
            });
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 200));
        assert!(
            scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native capture scope custody unproven"
                    && gap.reason.contains("PID target exited")
                    && gap
                        .reason
                        .contains("earlier of the custody instant and the last clean read")),
            "the custody loss is disclosed with what it ends"
        );
        scene.project(7, 280);
        scene.coordinator.end_capture_coverage(300);
        scene.project(7, 320);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 200), "stop keeps it");

        // A loss dated before the last clean read (an exec record serviced
        // after that read) ends the interval at the loss.
        let (mut scene, caller) = watched_scene(9, 510);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 150,
                reason: "an exec of the PID target was observed".into(),
            });
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 150));

        // Review fix 1: an undecodable record dated at the last proven
        // drain (60, before the watch) leaves no clean interval at all.
        let (mut scene, caller) = watched_scene(11, 520);
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidUnproven {
                at_ns: 60,
                reason: "a lifecycle record was lost: short DISCOVERY record".into(),
            });
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "short DISCOVERY record")
                && lost_with(
                    &scene.coverage(caller),
                    "no clean read proved the watch before native capture scope custody became unproven"
                ),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_clean_read_never_claims_past_the_lifecycle_drain_horizon() {
        // C5.2 closure I-1: drained at 1000, a record reserved at 1010,
        // clean terminal read at 1020, stop at 1030: the interval ends at
        // 1000, so the loss found after stop (dated >= 1000) is outside it.
        let (mut scene, caller) = watched_scene(7, 500);
        let mut terminal = witness_batch();
        terminal.health_read_ns = 1020;
        terminal.lifecycle_proven_ns = 1000;
        scene.coordinator.note_witness_batch(&terminal);
        assert_eq!(last_clean(&scene), Some(1000));
        scene.coordinator.end_capture_coverage(1030);
        scene.coordinator.registry.publish();
        assert_eq!(scene.coverage(caller), frozen(100, 1000));

        // D2, PID: the only clean read is capped at a drain at 60, before
        // the watch began, so a later exit at 200 never freezes {100, 200}.
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(9, 510);
        let caller = scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(9, 510));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(9, 120);
        let mut read = witness_batch();
        read.health_read_ns = 200;
        read.lifecycle_proven_ns = 60;
        scene.coordinator.note_witness_batch(&read);
        assert_eq!(last_clean(&scene), Some(60));
        scene
            .coordinator
            .note_capture_custody(&ScopeCustody::PidLost {
                at_ns: 200,
                reason: "PID custody lost: the PID target exited".into(),
            });
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "PID target exited"),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_system_lifecycle_loss_is_a_sticky_demotion() {
        // C5.2 D4: DISCOVERY loss in system scope may hide an exec or exit
        // of any watched caller: every watch demotes, and none restarts.
        let mut scene = CaptureScene::new(1);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::System);
        scene.attach_all(100, ScopeCustody::System);
        scene.project(7, 120);
        let mut clean = witness_batch();
        clean.custody = ScopeCustody::System;
        clean.health_read_ns = 200;
        scene.coordinator.note_witness_batch(&clean);
        scene.coordinator.registry.publish();
        assert!(watched(&scene.coverage(caller)));
        let mut lost = witness_batch();
        lost.custody = ScopeCustody::System;
        lost.health_read_ns = 260;
        lost.lifecycle_loss = Some(crate::attach::capture::LifecycleLoss {
            at_ns: 200,
            reason: "the lifecycle ring lost records (DISCOVERY ring loss 0 -> 3)".into(),
        });
        scene.coordinator.note_witness_batch(&lost);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "ring loss"),
            "{:?}",
            scene.coverage(caller)
        );
        assert_eq!(last_clean(&scene), Some(200), "a lossy read is not clean");
        assert!(
            scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .any(
                    |gap| gap.subject == "native capture lifecycle evidence lost"
                        && gap.reason.contains("no watch starts again in this capture")
                        && !gap.reason.contains("may start")
                ),
            "{:?}",
            scene.coordinator.registry.gaps()
        );
        // Sticky: a later clean read and projection never restart a watch.
        let mut later = witness_batch();
        later.custody = ScopeCustody::System;
        later.health_read_ns = 280;
        scene.coordinator.note_witness_batch(&later);
        scene.project(7, 290);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert!(
            lost_with(&scene.coverage(caller), "ring loss"),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_saturated_pair_set_withholds_the_watch() {
        // C5.2 pair precondition: once the seen set is full, or a row went
        // unrecorded, no read proves no-use: no watch starts and no read
        // extends one.
        let saturations: [fn(&mut WitnessBatch); 2] = [
            |batch| batch.seen_rows = batch.pair_limit,
            |batch| batch.unrecorded_rows = 1,
        ];
        for saturate in saturations {
            let (mut scene, caller) = watched_scene(7, 500);
            let mut read = witness_batch();
            read.health_read_ns = 260;
            saturate(&mut read);
            scene.coordinator.note_witness_batch(&read);
            assert_eq!(last_clean(&scene), Some(200), "{read:?}");
            scene.coordinator.end_capture_coverage(300);
            scene.coordinator.registry.publish();
            assert_eq!(scene.coverage(caller), frozen(100, 200), "{read:?}");

            let mut scene = CaptureScene::new(1);
            scene.source.spawn(8, 510);
            let caller = scene
                .coordinator
                .adapter
                .admit(8, ImageAuthority::ScanPinned, 50)
                .unwrap();
            scene
                .coordinator
                .begin_capture_coverage(incarnation(8, 510));
            let mut read = witness_batch();
            saturate(&mut read);
            scene.coordinator.note_witness_batch(&read);
            scene.attach_all(100, ScopeCustody::PidHeld);
            scene.project(8, 120);
            scene.coordinator.registry.publish();
            assert!(
                !watched(&scene.coverage(caller)),
                "{read:?}: {:?}",
                scene.coverage(caller)
            );
        }
    }

    // ---- Task 6 C4: native witness binding through the coordinator ----

    type ScriptedPin = (u32, u64);

    /// Scripted cookie answers per (pin, domain); never a host read.
    #[derive(Default)]
    pub(super) struct ScriptedCookies {
        answers: std::collections::HashMap<(ScriptedPin, NativeDomainId), CookieQuery>,
        pub(super) queries: usize,
    }

    impl NativeIdentity<ScriptedPin> for ScriptedCookies {
        fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
            None
        }

        fn query_cookie(&mut self, domain: NativeDomainId, pin: &ScriptedPin) -> CookieQuery {
            self.queries += 1;
            self.answers
                .get(&(*pin, domain))
                .cloned()
                .unwrap_or(CookieQuery::NoCookie)
        }
    }

    use crate::attach::capture::{CookieQuery, DomainCookie, ExecCoverage};
    use crate::discovery::caller_registry::{UnboundUse, UseCoverage};

    /// Facade stamps for scripted native batches: strictly increasing, so
    /// each batch follows the one staged before it.
    pub(super) struct Stamps(std::cell::Cell<u64>);

    impl Stamps {
        pub(super) fn from(start: u64) -> Self {
            Self(std::cell::Cell::new(start))
        }

        pub(super) fn tick(&self) -> u64 {
            let at = self.0.get() + 10;
            self.0.set(at);
            at
        }

        /// One readable witness read of `domain`: health at the stamp, rows
        /// read just after it.
        pub(super) fn read(&self, domain: NativeDomainId, rows: Vec<WitnessRow>) -> NativeBatch {
            let at = self.tick();
            let mut read = witness_batch();
            read.domain = domain;
            read.rows = rows;
            read.health.discovery_counters = Some([0; 5]);
            read.health_read_ns = at;
            read.rows_anchor_ns = at + 1;
            read.rows_read_ns = at + 1;
            read.counts_read_ns = at + 1;
            NativeBatch::Witness(Box::new(read))
        }

        /// One complete lifecycle drain of `domain`.
        pub(super) fn drain(&self, domain: NativeDomainId) -> NativeBatch {
            NativeBatch::Lifecycle(DiscoveryBatch::scripted(domain, Vec::new(), self.tick()))
        }
    }

    pub(super) struct NativeScene {
        pub(super) scene: CaptureScene,
        pub(super) domain: NativeDomainId,
        pub(super) cookies: ScriptedCookies,
        pub(super) stamps: Stamps,
    }

    impl NativeScene {
        /// One provider with two endpoints in the attach set, pid 7
        /// spawned (start 500) and admitted at 50 and mapped.
        pub(super) fn new() -> (Self, CallerId) {
            let mut scene = CaptureScene::new(2);
            scene.source.spawn(7, 500);
            let caller = scene
                .coordinator
                .adapter
                .admit(7, ImageAuthority::ScanPinned, 50)
                .unwrap();
            scene.project(7, 60);
            scene.coordinator.commit_batch(false).unwrap();
            (Self::over(scene, 0), caller)
        }

        /// A native lane over `scene` whose exec coverage began at
        /// `coverage_ns`, forwarded the way C5 forwards it: through the
        /// activating extend receipt.
        pub(super) fn over(mut scene: CaptureScene, coverage_ns: u64) -> Self {
            let domain = NativeDomainId::mint();
            scene.coordinator.note_extend_receipt(&ExtendReceipt {
                activated_roots: true,
                exec_coverage: Some(ExecCoverage::scripted(domain, coverage_ns)),
                ..ExtendReceipt::default()
            });
            Self {
                scene,
                domain,
                cookies: ScriptedCookies::default(),
                stamps: Stamps::from(1_000),
            }
        }

        pub(super) fn answer(&mut self, pid: u32, start: u64, ticket: u64) {
            self.cookies.answers.insert(
                ((pid, start), self.domain),
                CookieQuery::Cookie(DomainCookie::scripted(self.domain, ticket)),
            );
        }

        pub(super) fn forget_answer(&mut self, pid: u32, start: u64) {
            self.cookies.answers.remove(&((pid, start), self.domain));
        }

        pub(super) fn query_answer(&mut self, pid: u32, start: u64, answer: CookieQuery) {
            self.cookies
                .answers
                .insert(((pid, start), self.domain), answer);
        }

        pub(super) fn unavailable_answer(&mut self, pid: u32, start: u64) {
            self.query_answer(
                pid,
                start,
                CookieQuery::Unavailable("scripted temporary cookie-query failure".into()),
            );
        }

        pub(super) fn row(
            &self,
            ticket: u64,
            exec: u64,
            tgid: u32,
            t0: u64,
            member: usize,
        ) -> WitnessRow {
            let endpoint = self.scene.delta.endpoints[member];
            WitnessRow::scripted(
                self.domain,
                ticket,
                exec,
                endpoint.object,
                endpoint.id,
                tgid,
                t0,
            )
        }

        pub(super) fn stage(&mut self, batch: NativeBatch) -> NativeReceipt {
            let now = self.stamps.tick();
            self.scene
                .coordinator
                .stage_native(batch, &mut self.cookies, now)
        }

        pub(super) fn read(&mut self, rows: Vec<WitnessRow>) -> NativeReceipt {
            let batch = self.stamps.read(self.domain, rows);
            self.stage(batch)
        }

        /// One witness read carrying `counts` (C4): each `(ticket, exec,
        /// member, count)` names the image, the member's object, and the
        /// re-read count. `rows` ride along: a read may carry both.
        pub(super) fn counts_read(
            &mut self,
            rows: Vec<WitnessRow>,
            counts: Vec<(u64, u64, usize, u64)>,
        ) -> NativeReceipt {
            let at = self.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = self.domain;
            batch.rows = rows;
            batch.counts = counts
                .into_iter()
                .map(
                    |(ticket, exec, member, count)| crate::attach::capture::CallerCountUpdate {
                        image: p11scope_ebpf_common::ImageIdentity {
                            task_cookie: ticket,
                            exec_id: exec,
                        },
                        object: self.scene.delta.endpoints[member].object,
                        count,
                    },
                )
                .collect();
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_anchor_ns = at + 1;
            batch.rows_read_ns = at + 1;
            batch.counts_read_ns = at + 1;
            self.stage(NativeBatch::Witness(Box::new(batch)))
        }

        pub(super) fn drain(&mut self) -> NativeReceipt {
            let batch = self.stamps.drain(self.domain);
            self.stage(batch)
        }

        /// Read `rows`, then both horizons, then publish.
        pub(super) fn witness(&mut self, rows: Vec<WitnessRow>) -> Vec<CallerEvent> {
            let mut events = self.read(rows).events;
            events.extend(self.drain().events);
            events.extend(self.read(Vec::new()).events);
            self.scene.coordinator.commit_batch(false).unwrap();
            events
        }

        /// Heap-built scene (H6 slice 2 oracles): the ~54 KiB scene
        /// value is constructed and boxed inside this call, so only the
        /// box lives in the oracle's frame and multi-scene oracles fit
        /// the default test stack (debug builds retain every local's
        /// slot, so inline scenes would overflow it).
        pub(super) fn boxed() -> (Box<NativeScene>, CallerId) {
            let (scene, caller) = NativeScene::new();
            (Box::new(scene), caller)
        }

        /// Drive `rows` through the binder only (H6 slice 2): no
        /// coordinator staging runs, so the caller captures proven
        /// transitions for manual application. Returns what the binder
        /// proved, in emission order.
        pub(super) fn binder_only(&mut self, rows: Vec<WitnessRow>) -> Vec<ExecTransition> {
            for batch in [
                self.stamps.read(self.domain, rows),
                self.stamps.drain(self.domain),
                self.stamps.read(self.domain, Vec::new()),
            ] {
                match batch {
                    NativeBatch::Witness(read) => {
                        let coordinator = &mut self.scene.coordinator;
                        coordinator.binder.absorb_witnesses(
                            &read,
                            &coordinator.adapter,
                            &mut self.cookies,
                        );
                    }
                    NativeBatch::Lifecycle(drain) => {
                        self.scene.coordinator.binder.absorb_lifecycle(&drain);
                    }
                    _ => unreachable!("scripted read/drain only"),
                }
            }
            self.scene.coordinator.binder.take_transitions()
        }

        pub(super) fn module_unbound(&self) -> Option<UnboundUse> {
            self.scene
                .coordinator
                .registry
                .modules()
                .next()
                .and_then(|module| module.unbound_use.clone())
        }

        pub(super) fn preadmission(&self) -> PreadmissionCounters {
            self.scene.coordinator.preadmission_counters().unwrap()
        }

        pub(super) fn gap_subjects(&self) -> Vec<String> {
            self.scene
                .coordinator
                .registry
                .gaps()
                .iter()
                .map(|gap| gap.subject.clone())
                .collect()
        }
    }

    #[test]
    fn a_bound_row_marks_its_edge_counted() {
        // C7 C4: the scripted row carries a first-sight count of one, so
        // the bound edge reads `counted`.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
        assert_eq!(native.module_unbound(), None);
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!((census.rows, census.bound, census.pending), (1, 1, 0));
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 1);
        // Counted needs a count ≥ 1: a bound row reporting zero (only
        // scripted rows do) stays witnessed.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 0;
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Witnessed { first_ns: 100 }
        );
    }

    #[test]
    fn exit_before_the_poll_is_module_level_use_with_a_named_gap() {
        let (mut native, caller) = NativeScene::new();
        // The row's process (tgid 9) exited before the poll; nothing holds
        // its tgid.
        let row = native.row(41, 1, 9, 100, 1);
        native.witness(vec![row]);
        let unbound = native.module_unbound().expect("module-level positive");
        assert_eq!(unbound.first_ns, 100);
        assert_eq!(unbound.rows, 1);
        assert_eq!(unbound.reasons.get("no_live_caller"), Some(&1));
        assert!(
            native
                .gap_subjects()
                .contains(&"used by an unidentified caller image".to_string()),
            "{:?}",
            native.gap_subjects()
        );
        assert!(
            !native.scene.coverage(caller).is_witnessed(),
            "another caller never inherits it"
        );
    }

    #[test]
    fn a_reused_pid_never_inherits_a_witness_by_pid() {
        let (mut native, caller) = NativeScene::new();
        // pid 7 now holds ticket 99; the row's ticket 41 was its previous
        // owner's.
        native.answer(7, 500, 99);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        let unbound = native.module_unbound().unwrap();
        assert_eq!(unbound.reasons.get("cookie_mismatch"), Some(&1));
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!(census.unbound.get(&UnboundReason::CookieMismatch), Some(&1));
    }

    #[test]
    fn a_proven_exec_transition_retires_the_caller_and_admits_its_successor() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let first = native.row(41, 1, 7, 100, 0);
        native.witness(vec![first]);
        let later = native.row(41, 2, 7, 1_100, 1);
        let events = native.witness(vec![later]);
        let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
            panic!("{events:?}");
        };
        assert_eq!(*old, caller);
        let adapter = &native.scene.coordinator.adapter;
        assert!(adapter.record(caller).unwrap().retired);
        assert_eq!(adapter.live_id(7), Some(*new));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            },
            "the old image keeps its count"
        );
        assert_eq!(
            native
                .module_unbound()
                .unwrap()
                .reasons
                .get("exec_transition"),
            Some(&1)
        );
    }

    #[test]
    fn a_bound_caller_without_a_mapping_edge_stays_module_level() {
        let (mut native, _) = NativeScene::new();
        native.scene.source.spawn(8, 600);
        native
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 70)
            .unwrap();
        native.answer(8, 600, 55);
        let row = native.row(55, 1, 8, 100, 0);
        native.witness(vec![row]);
        let unbound = native.module_unbound().unwrap();
        assert_eq!(unbound.reasons.get("no_mapping_edge"), Some(&1));
        assert!(
            native
                .gap_subjects()
                .contains(&"native witness without mapping evidence".to_string())
        );
        assert_eq!(
            native.scene.coordinator.registry.edge_count(),
            1,
            "a witness never invents a mapping"
        );
    }

    #[test]
    fn counted_use_still_binds_after_capture_coverage_ended() {
        // C7 C4: a count is a positive fact like its witness, so it
        // stages after stop too.
        let (mut native, caller) = NativeScene::new();
        native
            .scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::System);
        native.scene.coordinator.end_capture_coverage(90);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
    }

    #[test]
    fn a_bound_row_publishes_its_first_sight_count() {
        // C7 C4: bound to an admitted caller incarnation with a count ≥
        // 1, the edge reads `counted` — the count, first record, and
        // pass-resolution recency publish together.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 3;
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 3);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(1011));
        assert_eq!(
            registry.entry_observation(edge),
            crate::discovery::caller_registry::EntryObservation::Observed
        );
    }

    #[test]
    fn refresh_counts_advance_the_published_count_at_pass_resolution() {
        // Recency names the read that observed the rise (1011, then
        // 1071) — never the first record, never the commit. The
        // wrong-pass mutation restamps this and fails here.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 10)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 10);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(1071));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
        // A stale refresh (below the staged count) moves nothing.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 10);
        assert_eq!(edge.entry_last_seen_ns, Some(1071));
    }

    #[test]
    fn counts_for_a_pending_row_stage_when_it_binds() {
        // The refresh arrives while the row waits for its horizons: the
        // edge reads pending-unknown with no count, and binds with the
        // maximum of first sight and refresh once the horizons arrive.
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 2;
        native.read(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 0, "nothing stages while pending");
        assert_eq!(
            native.scene.coordinator.presented_coverage(edge),
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        );
        native.drain();
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 5);
        assert_eq!(edge.entry_first_seen_ns, Some(100));
        assert_eq!(edge.entry_last_seen_ns, Some(1031));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            }
        );
    }

    #[test]
    fn counts_for_an_unbound_row_never_publish() {
        // R-C51-1 and DR-C51-PREADMIT: the row never binds, so its
        // first-sight count, its refreshes, and any later refresh all
        // drop — the edge keeps `use_before_admission` with a zero no
        // consumer reads as fact.
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 99);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 7;
        native.read(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 9)]);
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        native.counts_read(Vec::new(), vec![(41, 1, 0, 20)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        );
        let registry = &native.scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 0);
        assert_eq!(edge.entry_first_seen_ns, None);
        assert_eq!(edge.entry_last_seen_ns, None);
        assert_eq!(
            native
                .module_unbound()
                .unwrap()
                .reasons
                .get("cookie_mismatch"),
            Some(&1)
        );
    }

    #[test]
    fn counted_use_for_a_refused_module_stages_no_count() {
        // Counted needs an admitted module: the backstop drops the
        // count (the witness stands); the absolute staging self-heals
        // on the next refresh after admission.
        let (mut native, caller) = NativeScene::new();
        let refused = ModuleKey::physical(8, 1, 77, Some("sha0077".into()), "/lib/r.so");
        let info = ModuleInfo {
            path: "/lib/r.so".into(),
            key: refused.clone(),
            double_loaded: false,
            build_id: None,
            identity_source: None,
            admission: AdmissionState::Refused,
            admission_class: None,
            admission_endpoints: None,
            admission_reasons: Vec::new(),
        };
        native
            .scene
            .coordinator
            .registry_mut()
            .note_mapping(caller, 7, info, 60);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.scene.coordinator.stage_pair_count(
            caller,
            &refused,
            PairCount {
                count: 5,
                first_ns: 100,
                anchor_ns: 100,
                last_ns: 200,
                retirement_usable: false,
                diagnostic_observation: 0,
                diagnostic_transition: 0,
            },
            100,
            0,
            None,
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let id = registry.module_id_for(&refused).expect("edge retained");
        let edge = registry.edge(caller, id).expect("edge retained");
        assert_eq!(edge.entry_count, 0);
        assert_eq!(
            registry.coverage(edge),
            UseCoverage::Unknown(UnknownReason::NotAdmitted)
        );
    }

    #[test]
    fn a_pair_insert_failure_reads_absent_pairs_uncounted() {
        // C7 C4: CALLER_EVIDENCE[2] fires, so some pair has use but no
        // row — absence proves nothing. The edge reads `uncounted`
        // (never 0), the uncounted reason wins over the coincident
        // loss demotion, and no later pass starts a watch.
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(incarnation(7, 500));
        scene.attach_all(100, ScopeCustody::PidHeld);
        scene.project(7, 120);
        scene.coordinator.registry.publish();
        assert!(watched(&scene.coverage(caller)));
        let mut bad = witness_batch();
        bad.health.caller_evidence = Some([0, 0, 1, 0]);
        bad.health_regression =
            Some("native capture health counters rose: CALLER_EVIDENCE[2] 0->1".into());
        bad.health_baseline_ns = 120;
        bad.health_read_ns = 160;
        scene.coordinator.note_witness_batch(&bad);
        scene.coordinator.registry.publish();
        match scene.coverage(caller) {
            UseCoverage::Unknown(UnknownReason::Uncounted(evidence)) => {
                assert!(
                    evidence.contains("PairInsertFailure"),
                    "points at the evidence: {evidence}"
                );
            }
            other => panic!("an absent pair reads uncounted, got {other:?}"),
        }
        let registry = &scene.coordinator.registry;
        let edge = registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge");
        assert_eq!(edge.entry_count, 0);
        assert_eq!(
            registry.entry_observation(edge),
            crate::discovery::caller_registry::EntryObservation::UnknownUnavailable,
            "a zero under uncounted is never observed"
        );
        assert!(
            registry
                .gaps()
                .iter()
                .any(|gap| gap.subject == "usage coverage pair insert failure"),
            "{:?}",
            registry.gaps()
        );
        // A later pass withholds the watch: still uncounted, not watched.
        scene.project(7, 170);
        scene.coordinator.registry.publish();
        assert!(
            matches!(
                scene.coverage(caller),
                UseCoverage::Unknown(UnknownReason::Uncounted(_))
            ),
            "{:?}",
            scene.coverage(caller)
        );
    }

    #[test]
    fn a_rising_count_reads_recent_on_the_dashboard_display_while_in_window() {
        // Dashboard display only: a counted edge reads recently-observed
        // on screen while its rise is in the trailing window, quiet once
        // stale — and a fresh rise always beats quiet. (Each capture is
        // an independent snapshot; only the stamps order them. The
        // recorded signal is per-pass; see
        // `per_pass_activity_reads_a_rise_then_quiet_on_unchanged_passes`.)
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let activity_at = |native: &NativeScene, now_ns: u64, window_ns: u64| {
            Presentation::capture_dashboard(
                &native.scene.coordinator,
                "s",
                0,
                now_ns,
                1,
                now_ns,
                window_ns,
            )
            .edges
            .into_iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has an edge")
            .activity
        };
        assert_eq!(activity_at(&native, 1500, 1000), Activity::RecentlyObserved);
        assert_eq!(
            activity_at(&native, 3000, 1000),
            Activity::Quiet,
            "stale with no fresh rise"
        );
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            activity_at(&native, 1571, 1000),
            Activity::RecentlyObserved,
            "the rise at 1071 beats quiet"
        );
    }

    #[test]
    fn a_late_mapped_module_keeps_its_first_use_count() {
        // P1-3: a caller already bound through module A loads module B;
        // the pass that stages B's mapping also reads B's first-use row
        // (bound at once through the cached caller identity) before
        // committing the mapping. The witness resolves onto the committed
        // edge — and so must the count: later refreshes advance it,
        // never skip a permanently dropped pair.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        // Bound through A first: the image's identity is cached.
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        assert!(
            matches!(native.scene.coverage(caller), UseCoverage::Counted { .. }),
            "the A edge is counted: {:?}",
            native.scene.coverage(caller)
        );
        // The late module: absorbed (attach set knows it at once, like
        // the scan's absorb_lowering) but mapped only in the same
        // staging window as its first-use row.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &b, &fx::offsets(2))),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        let endpoint_b = absorbed_b.delta.endpoints[0];
        native.scene.verdicts.extend(absorbed_b.verdicts);
        // One staging window, no commit between: project A+B (B's mapping
        // stages, uncommitted) then read B's first-use row (immediate
        // bind through the cached identity).
        native.scene.project_paths(7, &[&a_path, &b], 200);
        let row_b = WitnessRow::scripted(
            native.domain,
            41,
            1,
            endpoint_b.object,
            endpoint_b.id,
            7,
            210,
        );
        native.read(vec![row_b]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_b = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry
                            .module(edge.module)
                            .is_some_and(|module| module.paths.iter().any(|p| p.contains("b.so")))
                })
                .expect("the caller has its B edge");
            (edge.entry_count, registry.coverage(edge))
        };
        // Premise: the witness resolved onto the committed edge.
        assert!(
            matches!(
                edge_b(&native).1,
                UseCoverage::Witnessed { .. } | UseCoverage::Counted { .. }
            ),
            "the B witness resolved: {:?}",
            edge_b(&native).1
        );
        // A later count increase must advance the edge, not skip it.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: endpoint_b.object,
            count: 9,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let (count, coverage) = edge_b(&native);
        assert_eq!(count, 9, "the B edge advanced to 9");
        assert!(
            matches!(coverage, UseCoverage::Counted { .. }),
            "the B edge reads counted: {coverage:?}"
        );
    }

    #[test]
    fn a_count_never_lands_where_its_witness_reads_ambiguous() {
        // P3 commit-visibility (astra#1, round 2 F7): the caller is
        // already cached — bound through a DIFFERENT physical object
        // (C) whose edge is committed — then B's mapping stages in the
        // same window as the shared object's ACTUAL FIRST-EVER row
        // (production delivers first sights once: the reader skips
        // seen rows and sends rises as count updates, never a second
        // first sight). The witness resolves ambiguous at publication
        // — and so must the count: a Bound(A) cached from the
        // pre-publish committed snapshot would attribute the shared
        // use to A.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        // Cache the caller through C, a separate physical object with
        // its own endpoint: C's edge commits with its first-sight
        // count before the shared object is ever seen.
        let c = fx::provider(&native.scene._dir, "c.so", "provider-c");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&c, "sha-c")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_c = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &c, &fx::offsets(1))),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_c.verdicts);
        let endpoint_c = absorbed_c.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &c], 140);
        let row_c = WitnessRow::scripted(
            native.domain,
            41,
            1,
            endpoint_c.object,
            endpoint_c.id,
            7,
            150,
        );
        native.witness(vec![row_c]);
        // B shares A's first endpoint: its table targets A's object.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&c, "sha-c"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        let members: Vec<_> = native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(shared.id)
            .collect();
        assert_eq!(
            members.len(),
            2,
            "A and B share the witnessed endpoint: {members:?}"
        );
        // One staging window, no commit between: project A+B+C (B's
        // mapping stages, uncommitted — the committed snapshot sees A
        // and C only) then read the shared endpoint's first-ever row
        // with a risen first-sight count.
        native.scene.project_paths(7, &[&a_path, &b, &c], 200);
        let mut row = WitnessRow::scripted(native.domain, 41, 1, shared.object, shared.id, 7, 210);
        row.entry_count = 9;
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Premise: the witness resolved ambiguous at publication.
        let placement = native.scene.coordinator.registry.witness_placement();
        assert_eq!(
            placement.ambiguous, 1,
            "the shared-endpoint witness reads ambiguous: {placement:?}"
        );
        let counts = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let mut counts: Vec<(String, u64)> = registry
                .edges()
                .filter(|edge| edge.caller == caller)
                .map(|edge| {
                    let path = registry
                        .module(edge.module)
                        .map(|module| module.paths.iter().next().cloned().unwrap_or_default())
                        .unwrap_or_default();
                    (path, edge.entry_count)
                })
                .collect();
            counts.sort();
            counts
        };
        let counts = counts(&native);
        assert_eq!(counts.len(), 3, "all three edges exist: {counts:?}");
        assert!(
            counts.iter().all(|(_, count)| *count <= 1),
            "no edge carries the ambiguous use's count: {counts:?}"
        );
        assert_eq!(
            counts
                .iter()
                .find(|(path, _)| path.contains("c.so"))
                .map(|(_, count)| *count),
            Some(1),
            "C keeps only its own first-sight count: {counts:?}"
        );
        assert_eq!(
            counts
                .iter()
                .find(|(path, _)| path.contains("a.so"))
                .map(|(_, count)| *count),
            Some(0),
            "the shared use's count never lands on A: {counts:?}"
        );
    }

    #[test]
    fn count_only_growth_after_sharing_appears_is_withheld() {
        // P3 sharing (round 2, F7/S5): the pair binds to A while A is
        // the sole owner and commits Bound(A) with its history; then B
        // appears sharing the endpoint and commits. A
        // production-shaped count-only update (the reader skips the
        // seen row — rises ride as updates, never a second first
        // sight) preserves history while withholding attribution of
        // the now-ambiguous growth.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        // Sharing appears and commits: B's edge exists alongside A's.
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(edge_count(&native, "a.so"), Some(1), "history stands");
        assert_eq!(edge_count(&native, "b.so"), Some(0), "B starts unused");
        // Production-shaped count-only growth: no rows (seen), only
        // the risen count — twice, so stickiness is pinned too.
        for count in [9u64, 20] {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.counts = vec![crate::attach::capture::CallerCountUpdate {
                image: p11scope_ebpf_common::ImageIdentity {
                    task_cookie: 41,
                    exec_id: 1,
                },
                object: shared.object,
                count,
            }];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            batch.counts_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(1),
            "history is preserved while ambiguous growth is withheld"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(0),
            "ambiguous growth never lands on B either"
        );
    }

    #[test]
    fn staged_but_unpublished_sharer_withholds_count_only_growth() {
        // P3 sharing window (round 3, F3-01): the pair binds to A while
        // A is the sole owner and commits Bound(A) with its history;
        // then B is admitted (extend) and its mapping stages but does
        // NOT commit before a production-shaped count-only update
        // arrives in the same window. Admitted [A, B] but edged [A]:
        // the cached arm must NOT confirm — the growth withholds from
        // A and the publication (which commits B's mapping alongside)
        // resolves the pair ambiguous.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        // One staging window, no commit between: B's mapping stages
        // (admitted, uncommitted — the committed snapshot still sees A
        // only), then the risen count arrives.
        native.scene.project_paths(7, &[&a_path, &b], 200);
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 20,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(1),
            "staged-but-unpublished sharing withholds the window's growth from the cached edge"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(0),
            "the window's growth never lands on B either"
        );
    }

    #[test]
    fn ownership_transfer_forwards_only_post_demotion_growth() {
        // P3 ownership transfer (round 3, F3-03): the pair binds to A
        // while A is the sole owner and builds history; then B shares
        // the endpoint and commits edged, and A's endpoint membership
        // is removed (per-pass re-lowering re-records A memberless)
        // while B stays the sole admitted member. The next count
        // advance demotes: B must carry only post-demotion growth and
        // A keeps exactly its history — never `Placed`-elsewhere with
        // the absolute count (duplication plus backdated `first_ns`).
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // History while A is the sole owner.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        // Sharing appears and commits: B's edge exists alongside A's.
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // A's membership is removed (re-record memberless); B stays
        // the sole admitted member, edged.
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        let members: Vec<_> = native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(shared.id)
            .collect();
        assert_eq!(
            members.len(),
            1,
            "B is the sole admitted member after A's membership is removed: {members:?}"
        );
        // One advance past the history.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 6,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_of = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| (edge.entry_count, edge.entry_first_seen_ns))
        };
        let (a_count, _) = edge_of(&native, "a.so").expect("A keeps its edge");
        assert_eq!(a_count, 5, "A keeps exactly its history");
        let (b_count, b_first) = edge_of(&native, "b.so").expect("B keeps its edge");
        assert_eq!(b_count, 1, "B carries only post-demotion growth");
        assert_eq!(
            a_count + b_count,
            6,
            "no duplication: the edges sum to the pair's absolute count"
        );
        assert_eq!(
            b_first,
            Some(at + 1),
            "B's first sight is the demoting read, never the pair's backdated history"
        );
    }

    #[test]
    fn demote_then_reject_discloses_the_unattributed_growth() {
        // P3 demotion disclosure (round 3, F3-02): A commits count 1
        // sole-owned; B shares and commits; a count-only advance to 20
        // demotes and rejects ambiguous. The 19-call growth must not
        // finalize silently: a shared-endpoint gap records it (the
        // pair's witness resolved cleanly when A was sole owner, so no
        // witness gap covers this window), while history withholds on
        // the stale edge.
        use crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED;
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        // Sharing appears and commits: B's edge exists alongside A's.
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Production-shaped count-only growth, 1 -> 20.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 20,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(1),
            "history is preserved while ambiguous growth is withheld"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(0),
            "ambiguous growth never lands on B either"
        );
        let gaps: Vec<_> = native
            .scene
            .coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == DEMOTED_COUNT_REJECTED)
            .collect();
        assert_eq!(
            gaps.len(),
            2,
            "the rejected demoted growth stages one disclosure gap per sharer: {:?}",
            native.scene.coordinator.registry.gaps()
        );
        assert!(
            gaps.iter()
                .all(|gap| gap.reason.contains("19 unattributed calls")),
            "the gap discloses the unattributed growth: {:?}",
            gaps.iter().map(|gap| &gap.reason).collect::<Vec<_>>()
        );
        let _ = at;
    }

    #[test]
    fn demoted_rejection_discloses_without_inventing_witness_placements() {
        // Round 4, census (sol-N1 / R4-N5): the F3-02 shape — one decided
        // row (A's first sight, edged) plus a count-only demoted
        // rejection — must keep the placement census exact: the rejected
        // count has no witness row, so disclosing it must not account
        // another witness (`ambiguous` stays 0, the total stays 1).
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, _caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 20,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let placement = registry.witness_placement();
        let census = registry.witness_census();
        assert_eq!(
            (
                placement.edge,
                placement.module,
                placement.ambiguous,
                placement.unresolved
            ),
            (1, 0, 0, 0),
            "one decided row accounts exactly one edge placement: {placement:?}"
        );
        assert_eq!(
            placement.total(),
            census.bound + census.unbound_total(),
            "the placement census sums to the decided rows: {placement:?} vs {census:?}"
        );
        assert!(
            registry
                .modules()
                .all(|module| module.unbound_use.is_none()),
            "a rejected count invents no module-level use row"
        );
        let _ = at;
    }

    #[test]
    fn demoted_no_edge_rejection_discloses_without_module_rows() {
        // Round 4, census (sol-N1 / R4-N5), NoEdge-single arm: B is the
        // sole admitted member but never projected (no edge), so the
        // demoted count rejects with no edge. Disclosing it must neither
        // account a witness placement nor invent a module-level use row.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, _caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        // A's membership is removed (re-record memberless); B stays the
        // sole admitted member but is never projected: no B edge exists.
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        let shared = native.scene.delta.endpoints[0];
        let members: Vec<_> = native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(shared.id)
            .collect();
        assert_eq!(
            members.len(),
            1,
            "B is the sole admitted member after A's membership is removed: {members:?}"
        );
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 6,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let placement = registry.witness_placement();
        let census = registry.witness_census();
        assert_eq!(
            (
                placement.edge,
                placement.module,
                placement.ambiguous,
                placement.unresolved
            ),
            (1, 0, 0, 0),
            "one decided row accounts exactly one edge placement: {placement:?}"
        );
        assert_eq!(
            placement.total(),
            census.bound + census.unbound_total(),
            "the placement census sums to the decided rows: {placement:?} vs {census:?}"
        );
        assert!(
            registry
                .modules()
                .all(|module| module.unbound_use.is_none()),
            "a rejected count invents no module-level use row"
        );
        let _ = at;
    }

    #[test]
    fn demoted_rejection_discloses_despite_an_earlier_witness_gap() {
        // Round 4, memo (sol F3-02 hole): an earlier ambiguous witness
        // involving A and B records the generic shared-endpoint gaps; a
        // later demoted count rejecting Ambiguous must still disclose —
        // the witness memo must not swallow the count disclosure.
        use crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED;
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, _caller) = NativeScene::new();
        native.answer(7, 500, 41);
        native.answer(8, 500, 42);
        native.scene.source.spawn(8, 500);
        native
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.project_paths(8, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Another caller's first-sight shared row fails closed at the
        // witness: the generic gaps memoize (module, subject),
        // caller-blind and endpoint-blind.
        let row_wit = native.row(42, 1, 8, 100, 0);
        native.witness(vec![row_wit]);
        // The demoted count rejects Ambiguous on the same modules.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 20,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let gaps: Vec<_> = native
            .scene
            .coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.reason.contains("19 unattributed calls"))
            .collect();
        assert_eq!(
            gaps.len(),
            2,
            "the demoted rejection discloses despite the earlier witness gap: {:?}",
            native.scene.coordinator.registry.gaps()
        );
        assert!(
            gaps.iter().all(|gap| gap.subject == DEMOTED_COUNT_REJECTED),
            "count disclosures carry their own subject: {:?}",
            gaps.iter().map(|gap| &gap.subject).collect::<Vec<_>>()
        );
        let _ = at;
    }

    #[test]
    fn repeated_demoted_rejections_each_disclose() {
        // Round 4, memo (R4-N3a): two demoted rejects over the same
        // modules must each disclose — the first disclosure must not
        // memoize the second away.
        use crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED;
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, _caller) = NativeScene::new();
        native.answer(7, 500, 41);
        native.answer(8, 500, 42);
        native.scene.source.spawn(8, 500);
        native
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 50)
            .unwrap();
        native.scene.project(8, 60);
        // Two bound pairs on one endpoint, one per caller (one cookie
        // answers each caller).
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let row_b = native.row(42, 1, 8, 100, 0);
        native.witness(vec![row_b]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.project_paths(8, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Both pairs advance in one window; both demote and reject.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![
            crate::attach::capture::CallerCountUpdate {
                image: p11scope_ebpf_common::ImageIdentity {
                    task_cookie: 41,
                    exec_id: 1,
                },
                object: shared.object,
                count: 20,
            },
            crate::attach::capture::CallerCountUpdate {
                image: p11scope_ebpf_common::ImageIdentity {
                    task_cookie: 42,
                    exec_id: 1,
                },
                object: shared.object,
                count: 6,
            },
        ];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        for (growth, want) in [("19 unattributed calls", 2), ("5 unattributed calls", 2)] {
            let gaps: Vec<_> = registry
                .gaps()
                .iter()
                .filter(|gap| gap.reason.contains(growth))
                .collect();
            assert_eq!(
                gaps.len(),
                want,
                "each rejected demoted count discloses its own growth ({growth}): {:?}",
                registry.gaps()
            );
        }
        assert!(
            registry
                .gaps()
                .iter()
                .filter(|gap| gap.reason.contains("unattributed calls"))
                .all(|gap| gap.subject == DEMOTED_COUNT_REJECTED),
            "count disclosures carry their own subject: {:?}",
            registry.gaps()
        );
        let _ = at;
    }

    #[test]
    fn demoted_rejection_leaves_later_witness_gaps_undisturbed() {
        // Round 4, memo (R4-N3b): a demoted rejection must not memoize
        // the witness subjects — a later first-sight ambiguous witness
        // over the same modules still records its own witness gaps.
        use crate::discovery::caller_registry::WITNESS_SHARED_ENDPOINT;
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, _caller) = NativeScene::new();
        native.answer(7, 500, 41);
        native.answer(8, 500, 42);
        native.scene.source.spawn(8, 500);
        native
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 50)
            .unwrap();
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.project_paths(8, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // The demoted count rejects first.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 20,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        // Then another caller's first-sight shared row fails closed
        // at the witness.
        let row_b = native.row(42, 1, 8, 100, 0);
        native.witness(vec![row_b]);
        let gaps: Vec<_> = native
            .scene
            .coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| {
                gap.subject == WITNESS_SHARED_ENDPOINT
                    && gap.reason.contains("bound to a caller incarnation")
            })
            .collect();
        assert_eq!(
            gaps.len(),
            2,
            "the later witness records its own gaps: {:?}",
            native.scene.coordinator.registry.gaps()
        );
        let _ = at;
    }

    #[test]
    fn repeated_witness_row_after_demotion_keeps_the_base() {
        // Round 4, rebind (R4-N1 R1): A=5 transfers to B=1 at absolute 6;
        // a repeated witness row plus an advance to 7 must not reset the
        // demotion base — B reads 2 (its growth), never the absolute 7.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // A repeated witness row plus an advance, in one read.
        let repeat = native.row(41, 1, 7, 100, 0);
        native.counts_read(vec![repeat], vec![(41, 1, 0, 7)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(5),
            "A keeps exactly its history"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(2),
            "a repeated row after demote+place stages growth, never the absolute"
        );
        assert_eq!(
            edge_count(&native, "a.so").unwrap() + edge_count(&native, "b.so").unwrap(),
            7,
            "no duplication: the edges sum to the pair's absolute count"
        );
        let _ = shared;
    }

    #[test]
    fn dropped_pair_revival_rebases_past_the_drop() {
        // Round 4, rebind (R4-N1 R2): demote (A=1) then reject over 19
        // disclosed calls; sharing resolves; a repeated row plus an
        // advance to 22 must stage only post-drop growth (B=2) — never
        // re-absorb the dropped absolute.
        use crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED;
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.counts_read(Vec::new(), vec![(41, 1, 0, 20)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Sharing resolves: A leaves, B stays the sole admitted member.
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        // A repeated witness row rebinds the dropped pair (its refresh
        // was skipped while dropped, so nothing stages yet).
        let repeat = native.row(41, 1, 7, 100, 0);
        native.read(vec![repeat]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // The next advance stages only post-drop growth.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 22)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(1),
            "A keeps exactly its history"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(2),
            "a revived pair stages post-drop growth, never the dropped absolute"
        );
        let gaps: Vec<_> = native
            .scene
            .coordinator
            .registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == DEMOTED_COUNT_REJECTED)
            .collect();
        assert_eq!(
            gaps.len(),
            2,
            "the drop's disclosure stands exactly once: {:?}",
            native.scene.coordinator.registry.gaps()
        );
        let _ = shared;
    }

    #[test]
    fn same_owner_replace_accumulates_growth() {
        // Round 4, re-place (R4-N4a freeze): A=1 with B admitted but
        // unedged; advances 2, 3, 4 demote and re-place onto A each
        // time. The edge must accumulate (A=4), never freeze at `max`
        // of history against growth.
        use crate::discovery::caller_registry::DEMOTED_COUNT_REJECTED;
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // B joins the endpoint (admitted) but is never projected: no B
        // edge exists, so every re-resolution places back onto A.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        native.scene.coordinator.commit_batch(false).unwrap();
        for absolute in [2, 3, 4] {
            native.counts_read(Vec::new(), vec![(41, 1, 0, absolute)]);
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        let registry = &native.scene.coordinator.registry;
        let edge_a = registry
            .edges()
            .find(|edge| {
                edge.caller == caller
                    && registry
                        .module(edge.module)
                        .is_some_and(|module| module.paths.iter().any(|path| path.contains("a.so")))
            })
            .expect("A keeps its edge");
        assert_eq!(
            edge_a.entry_count, 4,
            "re-placed growth accumulates onto the history holder"
        );
        assert!(
            registry
                .gaps()
                .iter()
                .all(|gap| gap.subject != DEMOTED_COUNT_REJECTED),
            "nothing rejects: every advance places: {:?}",
            registry.gaps()
        );
    }

    #[test]
    fn aba_ownership_return_keeps_every_call() {
        // Round 4, re-place (R4-N4b / sol-N2 cycle): A=5 transfers to
        // B=1 at absolute 6; B's membership is removed (A sole owner
        // again, B's stale edge keeps its history); the advance to 7
        // re-places onto A. A reads 6 (its 5 + the new call), B keeps 1:
        // the edges sum to 7 with no gap and no silent loss.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // A out, B sole owner: the transfer demotes onto B.
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // B out, A sole owner again (A rejoins the endpoint).
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let rejoined = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[0x1000])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(rejoined.verdicts);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &b, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        let shared = native.scene.delta.endpoints[0];
        let members: Vec<_> = native
            .scene
            .coordinator
            .attach_set
            .modules_with_member(shared.id)
            .collect();
        assert_eq!(
            members.len(),
            1,
            "A is the sole admitted member on the return leg: {members:?}"
        );
        native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(6),
            "the return leg accumulates the new call onto A's history"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(1),
            "B's stale edge keeps exactly its history"
        );
        assert_eq!(
            edge_count(&native, "a.so").unwrap() + edge_count(&native, "b.so").unwrap(),
            7,
            "no duplication, no loss: the edges sum to the absolute"
        );
    }

    #[test]
    fn demoted_edge_windows_from_the_base_read() {
        // Round 4, window anchor (R4-N2): the demoted growth executed
        // after the base read, so the demoted edge's coverage anchors
        // there — not at the demoting read (which would window genuine
        // growth out of its own ledger window).
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // History while A is the sole owner, at an explicit read.
        let h = native.stamps.tick();
        let mut history = witness_batch();
        history.domain = native.domain;
        history.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: native.scene.delta.endpoints[0].object,
            count: 5,
        }];
        history.health.discovery_counters = Some([0; 5]);
        history.health_read_ns = h;
        history.rows_read_ns = h + 1;
        history.counts_read_ns = h + 1;
        native.stage(NativeBatch::Witness(Box::new(history)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        // One advance past the history, at a later read.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 6,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_ne!(h + 1, at + 1, "the base read predates the demoting read");
        let registry = &native.scene.coordinator.registry;
        let edge_of = |needle: &str| {
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .unwrap()
        };
        let edge_b = edge_of("b.so");
        assert_eq!(edge_b.entry_count, 1, "B carries only post-demotion growth");
        assert_eq!(
            registry.coverage(edge_b),
            UseCoverage::Counted {
                since_ns: h + 1,
                lossy: false
            },
            "the demoted edge windows from the base read, not the demoting read"
        );
        let edge_a = edge_of("a.so");
        assert_eq!(
            registry.coverage(edge_a),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            },
            "the history holder keeps the pair's first record as its anchor"
        );
    }

    #[test]
    fn demoted_edge_windows_from_the_lookup_stamp() {
        // Round 5, anchor skew (astra-R5-N2): the base read's lookup
        // stamp predates its late batch stamp (the count lookup ran
        // mid-quantum, the batch stamped after it) — the demoted
        // edge's coverage anchors at the lookup, so genuine growth
        // between the lookup and the late stamp lands at or after its
        // own anchor instead of strictly before it.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // History while A is the sole owner, at a skewed read: looked
        // up at `h`, batch-stamped after the quantum.
        let h = native.stamps.tick();
        let mut history = witness_batch();
        history.domain = native.domain;
        history.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: native.scene.delta.endpoints[0].object,
            count: 5,
        }];
        history.health.discovery_counters = Some([0; 5]);
        history.health_read_ns = h;
        history.rows_read_ns = h + 20;
        history.counts_read_ns = h;
        native.stage(NativeBatch::Witness(Box::new(history)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        // One advance past the history, at a later read.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 6,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge_of = |needle: &str| {
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .unwrap()
        };
        let edge_b = edge_of("b.so");
        assert_eq!(edge_b.entry_count, 1, "B carries only post-demotion growth");
        assert_eq!(
            registry.coverage(edge_b),
            UseCoverage::Counted {
                since_ns: h,
                lossy: false
            },
            "the demoted edge windows from the base lookup, not the late batch stamp"
        );
    }

    fn assert_demoted_read_brackets(initial_row: bool) {
        // A baseline lookup sees five calls; growth after that lookup
        // must transfer once. The pre-read anchor and post-read observation
        // bound are different instants on both first-row and refresh paths.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        if !initial_row {
            let row_a = native.row(41, 1, 7, 100, 0);
            native.witness(vec![row_a]);
        }
        // History while A is the sole owner, at a skewed read: looked
        // up at `h`, batch-stamped after the quantum.
        let h = native.stamps.tick();
        let mut history = witness_batch();
        history.domain = native.domain;
        if initial_row {
            let mut row = native.row(41, 1, 7, 100, 0);
            row.entry_count = 5;
            history.rows = vec![row];
        } else {
            history.counts = vec![crate::attach::capture::CallerCountUpdate {
                image: p11scope_ebpf_common::ImageIdentity {
                    task_cookie: 41,
                    exec_id: 1,
                },
                object: native.scene.delta.endpoints[0].object,
                count: 5,
            }];
        }
        history.health.discovery_counters = Some([0; 5]);
        history.health_read_ns = h;
        history.rows_anchor_ns = h;
        let base_lookup = h + 10;
        let base_post = h + 30;
        history.rows_read_ns = base_post;
        history.counts_read_ns = if initial_row { h + 20 } else { h };
        native.stage(NativeBatch::Witness(Box::new(history)));
        if initial_row {
            // Binding needs a lifecycle drain strictly after this read's
            // POST, followed by its count horizon. The skewed POST is later
            // than the next ordinary fixture tick.
            native.stamps.0.set(base_post);
            native.drain();
            native.read(Vec::new());
        }
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        // One advance past the history, at a later read.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: p11scope_ebpf_common::ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 6,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        let growth_lookup = at + 20;
        let growth_post = at + 30;
        batch.rows_read_ns = growth_post;
        batch.counts_read_ns = at + 10;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge_of = |needle: &str| {
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .unwrap()
        };
        let edge_b = edge_of("b.so");
        assert_eq!(edge_b.entry_count, 1, "B carries only post-demotion growth");
        let edge_a = edge_of("a.so");
        assert_eq!(
            edge_a.entry_count, 5,
            "A keeps exactly its historical count"
        );
        assert_eq!(
            edge_a.entry_count + edge_b.entry_count,
            6,
            "no growth duplication"
        );
        let UseCoverage::Counted { since_ns, lossy } = registry.coverage(edge_b) else {
            panic!("the demoted growth must retain counted coverage");
        };
        assert!(!lossy);
        assert!(
            since_ns <= base_lookup,
            "coverage cannot begin after its base lookup"
        );
        assert_eq!(
            since_ns, h,
            "coverage keeps the base PRE bound, not its observation POST"
        );
        assert!(
            edge_a.entry_last_seen_ns.unwrap() >= base_lookup,
            "the history observation cannot predate its baseline lookup"
        );
        assert_eq!(edge_a.entry_last_seen_ns, Some(base_post));
        assert!(
            edge_b.entry_first_seen_ns.unwrap() >= growth_lookup,
            "the growth observation cannot predate its own lookup"
        );
        assert_eq!(edge_b.entry_first_seen_ns, Some(growth_post));
        assert_eq!(edge_b.entry_last_seen_ns, Some(growth_post));
    }

    #[test]
    fn demoted_initial_row_keeps_anchor_before_lookup_and_observation_after_lookup() {
        assert_demoted_read_brackets(true);
    }

    #[test]
    fn demoted_refresh_keeps_anchor_before_lookup_and_observation_after_lookup() {
        assert_demoted_read_brackets(false);
    }

    #[test]
    fn demoted_place_marks_its_edge() {
        // Round 4, window anchor (R4-N2): a demoted placement marks its
        // edge (caller-scoped, memoized once), so the oracle judges the
        // segment-relative count upper-bound-only instead of exact.
        use crate::discovery::caller_registry::DEMOTED_COUNT_PLACED;
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // A second demoted advance: the marker stands exactly once.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let id_of = |needle: &str| {
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.module)
                .unwrap()
        };
        let (id_a, id_b) = (id_of("a.so"), id_of("b.so"));
        let markers: Vec<_> = registry
            .gaps()
            .iter()
            .filter(|gap| gap.subject == DEMOTED_COUNT_PLACED)
            .collect();
        assert_eq!(
            markers.len(),
            1,
            "one demotion marker, memoized across placements: {:?}",
            registry.gaps()
        );
        assert_eq!(
            (markers[0].caller, markers[0].module),
            (Some(caller), Some(id_b)),
            "the marker scopes to the demoted edge: {:?}",
            markers[0]
        );
        assert_ne!(id_a, id_b, "the history holder carries no marker");
    }

    #[test]
    fn confirmed_then_demoted_growth_in_one_publish_accumulates() {
        // Round 4, re-place hardening: one publish stages confirmed
        // growth (against the old base) and then, after sharing
        // appears mid-publish, demoted growth (against the new base)
        // for the same pair onto the same edge. The two segments are
        // disjoint — both must accumulate (A=3), never `max` away.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // First advance while A is the sole owner — staged, unpublished.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 2)]);
        // Sharing appears mid-publish: B joins (admitted) but stays
        // unedged, so the demotion re-places onto A.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        // Second advance demotes — same publish, same edge.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 3)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge_a = registry
            .edges()
            .find(|edge| {
                edge.caller == caller
                    && registry
                        .module(edge.module)
                        .is_some_and(|module| module.paths.iter().any(|path| path.contains("a.so")))
            })
            .expect("A keeps its edge");
        assert_eq!(
            edge_a.entry_count, 3,
            "disjoint same-publish segments both accumulate"
        );
    }

    #[test]
    fn continued_confirmed_growth_installs_each_absolute() {
        // Round 5, confirmed-path base (sol-N1 + astra-R5-N1): a
        // sole-owner pair advancing 1,2,3,4 across four publishes
        // installs exactly each absolute — confirmed staging folds
        // staged into base, so no publish re-adds growth since a
        // frozen base.
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        let edge_a = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains("a.so"))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_a(&native),
            Some(1),
            "the first sight installs the absolute"
        );
        for absolute in [2, 3, 4] {
            native.counts_read(Vec::new(), vec![(41, 1, 0, absolute)]);
            native.scene.coordinator.commit_batch(false).unwrap();
            assert_eq!(
                edge_a(&native),
                Some(absolute),
                "confirmed publish installs the absolute, never growth since a frozen base"
            );
        }
    }

    #[test]
    fn rebound_pair_advance_conserves() {
        // Round 5, rebind continuation (sol-N1 + astra-R5-N1): the R1
        // scene (A=5 transfers to B=2 at absolute 7) advanced once
        // more — B reads 3 (its growth), A keeps 5, the edges sum to
        // the absolute 8.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let repeat = native.row(41, 1, 7, 100, 0);
        native.counts_read(vec![repeat], vec![(41, 1, 0, 7)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // The continuation: one more advancing refresh past the rebind.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 8)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(5),
            "A keeps exactly its history"
        );
        assert_eq!(
            edge_count(&native, "b.so"),
            Some(3),
            "the post-rebind advance stages growth, never the absolute"
        );
        assert_eq!(
            edge_count(&native, "a.so").unwrap() + edge_count(&native, "b.so").unwrap(),
            8,
            "no duplication: the edges sum to the pair's absolute count"
        );
        let _ = shared;
    }

    #[test]
    fn aba_return_advance_conserves() {
        // Round 5, ABA continuation (sol-N1 + astra-R5-N1): the ABA
        // scene (A=6, B=1 at absolute 7) advanced twice past the
        // return — A reads 7 then 8, B keeps 1, the edges sum to each
        // absolute.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 5)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let rejoined = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &a_path, &[0x1000])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(rejoined.verdicts);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let relowered = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &b, &[])),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(relowered.verdicts);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 7)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let edge_count = |native: &NativeScene, needle: &str| {
            let registry = &native.scene.coordinator.registry;
            registry
                .edges()
                .find(|edge| {
                    edge.caller == caller
                        && registry.module(edge.module).is_some_and(|module| {
                            module.paths.iter().any(|path| path.contains(needle))
                        })
                })
                .map(|edge| edge.entry_count)
        };
        assert_eq!(
            edge_count(&native, "a.so"),
            Some(6),
            "premise: the return leg accumulates the new call onto A's history"
        );
        // The continuation: two advancing refreshes past the return.
        for (absolute, want_a) in [(8, 7), (9, 8)] {
            native.counts_read(Vec::new(), vec![(41, 1, 0, absolute)]);
            native.scene.coordinator.commit_batch(false).unwrap();
            assert_eq!(
                edge_count(&native, "a.so"),
                Some(want_a),
                "the post-return advance stages growth at absolute {absolute}"
            );
            assert_eq!(
                edge_count(&native, "b.so"),
                Some(1),
                "B's stale edge keeps exactly its history at absolute {absolute}"
            );
            assert_eq!(
                edge_count(&native, "a.so").unwrap() + edge_count(&native, "b.so").unwrap(),
                absolute,
                "no duplication, no loss at absolute {absolute}"
            );
        }
    }

    #[test]
    fn a_rejected_count_is_never_promoted_by_a_later_mapping() {
        // P3 finalization (sol#2): a bound row with no mapping edge
        // places its witness module-level and rejects its count; the
        // rejection finalizes — a mapping that appears later must not
        // promote the held count onto the new edge.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // B is known to the attach set (admitted) but never projected:
        // no mapping edge exists for it.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module(&native.scene.pins, &b, &fx::offsets(2))),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        let endpoint_b = absorbed_b.delta.endpoints[0];
        native.scene.verdicts.extend(absorbed_b.verdicts);
        // B's first-use row binds through the cached identity with no
        // mapping staged at all.
        let row_b = WitnessRow::scripted(
            native.domain,
            41,
            1,
            endpoint_b.object,
            endpoint_b.id,
            7,
            210,
        );
        native.read(vec![row_b]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Premise: the witness went module-level (no edge to place on).
        let placement = native.scene.coordinator.registry.witness_placement();
        assert_eq!(
            (placement.edge, placement.module + placement.unresolved),
            (1, 1),
            "A's witness took its edge, B's went module-level: {placement:?}"
        );
        // The mapping appears later and the count advances: the rejected
        // count must not promote onto the new edge.
        native.scene.project_paths(7, &[&a_path, &b], 300);
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: endpoint_b.object,
            count: 9,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        let edge_b = registry
            .edges()
            .find(|edge| {
                edge.caller == caller
                    && registry
                        .module(edge.module)
                        .is_some_and(|module| module.paths.iter().any(|p| p.contains("b.so")))
            })
            .expect("the later mapping created the B edge");
        assert_eq!(
            edge_b.entry_count, 0,
            "the rejected count never promotes onto the later edge"
        );
        assert!(
            !matches!(registry.coverage(edge_b), UseCoverage::Counted { .. }),
            "the B edge never reads counted: {:?}",
            registry.coverage(edge_b)
        );
    }

    #[test]
    fn a_previously_placed_ambiguous_count_suspends_without_retirement_authority() {
        // P3 finalization (sol#2): a shared-endpoint use both edges hold
        // reads ambiguous. Its successfully placed prefix remains recoverable
        // only through private retirement authority, absent from this fixture.
        use crate::discovery::inventory_attach_set::tests as fx;
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row_a = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row_a]);
        // B shares A's first endpoint; both mappings commit up front,
        // so the committed snapshot itself reads ambiguous.
        let b = fx::provider(&native.scene._dir, "b.so", "provider-b");
        let a_path = native.scene.path.clone();
        native.scene.pins = fx::pass_pins(&[(&a_path, "sha-a"), (&b, "sha-b")]);
        let policy =
            crate::plan::AdmissionPolicy::Inventory(native.scene.coordinator.attach_set.budget());
        let absorbed_b = native.scene.coordinator.attach_set.absorb(
            &fx::lower_named(
                std::slice::from_ref(&fx::module_with_targets(
                    &native.scene.pins,
                    &b,
                    &[(&a_path, 0x1000)],
                )),
                &native.scene.pins,
                policy,
            ),
            &native.scene.pins,
        );
        native.scene.verdicts.extend(absorbed_b.verdicts);
        let shared = native.scene.delta.endpoints[0];
        native.scene.project_paths(7, &[&a_path, &b], 200);
        native.scene.coordinator.commit_batch(false).unwrap();
        // The shared use with a risen first-sight count.
        let mut row = WitnessRow::scripted(native.domain, 41, 1, shared.object, shared.id, 7, 210);
        row.entry_count = 9;
        let key = PairKey::of(&row);
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        // Premise: the witness read ambiguous.
        let placement = native.scene.coordinator.registry.witness_placement();
        assert_eq!(
            placement.ambiguous, 1,
            "the shared-endpoint witness reads ambiguous: {placement:?}"
        );
        // The rejection suspends the previously placed exact pair.
        assert!(
            matches!(
                native.scene.coordinator.pair_targets.get(&key),
                Some(PairTarget::Suspended { .. })
            ),
            "the previously placed pair suspends: {:?}",
            native.scene.coordinator.pair_targets.get(&key)
        );
        assert!(
            native.scene.coordinator.pair_counts.contains_key(&key),
            "the recoverable exact pair keeps its bounded held maximum"
        );
        // Permanence: a later advance attributes nowhere.
        let at = native.stamps.tick();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.counts = vec![crate::attach::capture::CallerCountUpdate {
            image: ImageIdentity {
                task_cookie: 41,
                exec_id: 1,
            },
            object: shared.object,
            count: 12,
        }];
        batch.health.discovery_counters = Some([0; 5]);
        batch.health_read_ns = at;
        batch.rows_read_ns = at + 1;
        batch.counts_read_ns = at + 1;
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.scene.coordinator.commit_batch(false).unwrap();
        let registry = &native.scene.coordinator.registry;
        for edge in registry.edges().filter(|edge| edge.caller == caller) {
            let path = registry
                .module(edge.module)
                .map(|module| module.paths.iter().next().cloned().unwrap_or_default())
                .unwrap_or_default();
            let count = edge.entry_count;
            if path.contains("a.so") {
                assert_eq!(count, 1, "A keeps only its own first-sight count");
            } else {
                assert_eq!(count, 0, "B never carries the ambiguous use: {path}");
            }
        }
    }

    #[test]
    fn persistent_refresh_failure_keeps_the_lower_bound_but_withholds_quiet() {
        // P1-5: after a successful positive read, persistent refresh
        // failures keep the observed count as a lower bound while the
        // coverage reads lossy — live AND terminal output withhold a
        // quiet claim over the stale count.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        // Production order: capture coverage begins before the reads, so
        // witness batches run the coverage half (health, freshness).
        native
            .scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::System);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let edge_of = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge");
            (
                edge.entry_count,
                edge.entry_last_seen_ns,
                registry.coverage(edge),
            )
        };
        assert!(
            matches!(
                edge_of(&native).2,
                UseCoverage::Counted { lossy: false, .. }
            ),
            "a clean positive read is loss-free: {:?}",
            edge_of(&native).2
        );
        // Persistent refresh failures: reads carrying only the failure.
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.read_failures = vec!["count refresh: lookup of cookie 41 failed".into()];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            batch.counts_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        let (count, last_seen, coverage) = edge_of(&native);
        assert_eq!(count, 1, "the observed lower bound stands");
        assert!(
            matches!(coverage, UseCoverage::Counted { lossy: true, .. }),
            "failed refreshes publish lossy freshness: {coverage:?}"
        );
        // Live: the per-pass signal withholds quiet over the stale
        // count, window-free.
        let last_seen = last_seen.expect("the positive read left a last-seen");
        let live = Presentation::capture(&native.scene.coordinator, "s", 0, last_seen, 1);
        let activity = live
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity;
        assert_eq!(
            activity,
            Activity::Lossy,
            "a stale count under failed refresh withholds quiet"
        );
        // Terminal: the loss survives the stop; the document keeps the
        // lower bound with lossy freshness, never quiet.
        let end_ns = last_seen + 2000;
        native.scene.coordinator.end_capture_coverage(end_ns);
        let document = crate::inventory::render_json(&native.scene.coordinator, "s", 0, end_ns, 1);
        assert_eq!(document["edges"][0]["entries"]["count"], 1);
        assert_eq!(
            document["edges"][0]["entries"]["coverage"]["lossy"], true,
            "{}",
            document["edges"][0]["entries"]["coverage"]
        );
        assert_ne!(
            document["edges"][0]["activity"], "quiet",
            "{}",
            document["edges"][0]
        );
    }

    #[test]
    fn repeated_refresh_starvation_keeps_the_lower_bound_but_withholds_quiet() {
        // F1: after a successful positive read, repeated deadline
        // starvation of the refresh — no failures, no gaps, no sweep —
        // keeps the observed count as a lower bound while the coverage
        // reads lossy, so live output withholds a quiet claim over the
        // stale count.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native
            .scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::System);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let edge_of = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge");
            (
                edge.entry_count,
                edge.entry_last_seen_ns,
                registry.coverage(edge),
            )
        };
        assert!(
            matches!(
                edge_of(&native).2,
                UseCoverage::Counted { lossy: false, .. }
            ),
            "a clean positive read is loss-free: {:?}",
            edge_of(&native).2
        );
        // Repeated starvation: reads carrying only the starved flag.
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.refresh_deadline_reached = true;
            batch.refresh_sweep_completed = false;
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            batch.counts_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        let (count, last_seen, coverage) = edge_of(&native);
        assert_eq!(count, 1, "the observed lower bound stands");
        assert!(
            matches!(coverage, UseCoverage::Counted { lossy: true, .. }),
            "starved refreshes publish lossy freshness: {coverage:?}"
        );
        let last_seen = last_seen.expect("the positive read left a last-seen");
        let live = Presentation::capture(&native.scene.coordinator, "s", 0, last_seen, 1);
        let activity = live
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity;
        assert_eq!(
            activity,
            Activity::Lossy,
            "a stale count under starved refresh withholds quiet"
        );
    }

    #[test]
    fn a_refresh_failure_beginning_after_stop_withholds_quiet() {
        // P1-5 terminal-first (sol#1 + astra#2): reads succeed while
        // live, then stop begins, and only the post-stop terminal
        // refresh fails. The stale count must demote to lossy — quiet
        // is withheld even though no live loss was ever recorded.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native
            .scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::System);
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.witness(vec![row]);
        let edge_of = |native: &NativeScene| {
            let registry = &native.scene.coordinator.registry;
            let edge = registry
                .edges()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge");
            (
                edge.entry_count,
                edge.entry_last_seen_ns,
                registry.coverage(edge),
            )
        };
        assert!(
            matches!(
                edge_of(&native).2,
                UseCoverage::Counted { lossy: false, .. }
            ),
            "live reads succeed loss-free: {:?}",
            edge_of(&native).2
        );
        // Stop begins (production order: the coverage ends before the
        // post-stop terminal refresh, inventory_capture.rs).
        let live_last_seen = edge_of(&native)
            .1
            .expect("the positive read left a last-seen");
        let end_ns = live_last_seen + 2000;
        native.scene.coordinator.end_capture_coverage(end_ns);
        // The terminal refresh fails after stop: reads carrying only
        // the failure, staged the way the terminal loop stages them.
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.read_failures = vec!["count refresh: lookup of cookie 41 failed".into()];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            batch.counts_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        let (count, _, coverage) = edge_of(&native);
        assert_eq!(count, 1, "the observed lower bound stands");
        assert!(
            matches!(coverage, UseCoverage::Counted { lossy: true, .. }),
            "a terminal-first refresh failure publishes lossy freshness: {coverage:?}"
        );
        // Terminal: the stale count withholds quiet.
        let live = Presentation::capture(&native.scene.coordinator, "s", 0, end_ns, 1);
        let activity = live
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity;
        assert_eq!(
            activity,
            Activity::Lossy,
            "a stale count under failed terminal refresh withholds quiet"
        );
        let document = crate::inventory::render_json(&native.scene.coordinator, "s", 0, end_ns, 1);
        assert_eq!(document["edges"][0]["entries"]["count"], 1);
        assert_eq!(
            document["edges"][0]["entries"]["coverage"]["lossy"], true,
            "{}",
            document["edges"][0]["entries"]["coverage"]
        );
        assert_ne!(
            document["edges"][0]["activity"], "quiet",
            "{}",
            document["edges"][0]
        );
    }

    #[test]
    fn per_pass_activity_reads_a_rise_then_quiet_on_unchanged_passes() {
        // ACT (Choice 3 re-rule): activity is per-pass ("rose since
        // previous pass"), pinned with production clock ordering: a rise
        // reads recently observed; following unchanged passes read quiet
        // (never a window echo); unreadable refreshes read lossy; a later
        // rise reads recently observed again.
        use crate::inventory_present::{Activity, Presentation};
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        // Production ordering: passes commit in stamp order, and every
        // presentation reads the pass it presents after it committed.
        // The signal is per-pass (window-free): only the pass sequence
        // orders it.
        let activity_of = |native: &NativeScene| {
            Presentation::capture(&native.scene.coordinator, "s", 0, 0, 1)
                .edges
                .into_iter()
                .find(|edge| edge.caller == caller)
                .expect("the caller has its edge")
                .activity
        };
        // Rising: first sight, then an advance.
        native.witness(vec![native.row(41, 1, 7, 100, 0)]);
        assert_eq!(
            activity_of(&native),
            Activity::RecentlyObserved,
            "first sight rose"
        );
        native.counts_read(Vec::new(), vec![(41, 1, 0, 6)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            activity_of(&native),
            Activity::RecentlyObserved,
            "the advance rose"
        );
        // Unchanged, then stale: quiet, whatever any window covers.
        for _ in 0..2 {
            native.read(Vec::new());
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        assert_eq!(
            activity_of(&native),
            Activity::Quiet,
            "unchanged passes read quiet, never a window echo"
        );
        // The dashboard display keeps its window: the stale rise still
        // reads recently observed on screen while in the trailing
        // window, quiet once past it.
        let display_of = |native: &NativeScene, now_ns: u64| {
            Presentation::capture_dashboard(
                &native.scene.coordinator,
                "s",
                0,
                now_ns,
                1,
                now_ns,
                crate::inventory_present::DASHBOARD_ACTIVITY_WINDOW_NS,
            )
            .edges
            .into_iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .activity
        };
        let last_seen = native
            .scene
            .coordinator
            .registry
            .edges()
            .find(|edge| edge.caller == caller)
            .expect("the caller has its edge")
            .entry_last_seen_ns
            .expect("the rise left a last-seen");
        assert_eq!(
            display_of(&native, last_seen + 1_000),
            Activity::RecentlyObserved,
            "the display keeps window recency"
        );
        assert_eq!(
            display_of(
                &native,
                last_seen + crate::inventory_present::DASHBOARD_ACTIVITY_WINDOW_NS + 1
            ),
            Activity::Quiet,
            "the display goes quiet past its window"
        );
        // Unreadable: the refresh fails persistently.
        native
            .scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::System);
        for _ in 0..2 {
            let at = native.stamps.tick();
            let mut batch = witness_batch();
            batch.domain = native.domain;
            batch.read_failures = vec!["count refresh: lookup of cookie 41 failed".into()];
            batch.health.discovery_counters = Some([0; 5]);
            batch.health_read_ns = at;
            batch.rows_read_ns = at + 1;
            batch.counts_read_ns = at + 1;
            native.stage(NativeBatch::Witness(Box::new(batch)));
            native.scene.coordinator.commit_batch(false).unwrap();
        }
        assert_eq!(
            activity_of(&native),
            Activity::Lossy,
            "unreadable refreshes withhold quiet"
        );
        // A later rise beats lossy.
        native.counts_read(Vec::new(), vec![(41, 1, 0, 12)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            activity_of(&native),
            Activity::RecentlyObserved,
            "a fresh rise beats lossy"
        );
    }

    #[test]
    fn native_counts_render_identically_in_json_jsonl_and_dashboard() {
        // C7 C4 three-consumer equality: a natively counted edge —
        // count, coverage, observation, activity — reads the same in
        // the JSON document, the JSONL edge event, the pager snapshot,
        // and the dashboard frame.
        use crate::inventory_dashboard::{
            DashboardState, DisplayFrame, LogTail, Viewport, render_frame,
        };
        use crate::inventory_present::{
            Presentation, coverage_label, entries_display, render_snapshot,
        };
        let (mut native, _) = NativeScene::new();
        native.answer(7, 500, 41);
        let mut row = native.row(41, 1, 7, 100, 0);
        row.entry_count = 4;
        native.witness(vec![row]);
        native.counts_read(Vec::new(), vec![(41, 1, 0, 9)]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let presentation = Presentation::capture(&native.scene.coordinator, "native", 0, 2000, 1);
        let document =
            crate::inventory::render_json(&native.scene.coordinator, "native", 0, 2000, 1);
        assert_eq!(presentation.edges.len(), 1);
        let edge = &presentation.edges[0];
        let edge_json = &document["edges"][0];
        assert_eq!(edge_json["entries"]["count"], 9);
        assert_eq!(edge_json["entries"]["coverage"]["state"], "counted");
        assert_eq!(edge_json["entries"]["coverage"]["since_ns"], 100);
        assert_eq!(edge_json["entries"]["coverage"]["lossy"], false);
        assert_eq!(edge_json["entries"]["observation"], "observed");
        assert_eq!(edge_json["entries"]["last_seen_ns"], 1071);
        assert_eq!(edge.activity.label(), "recently observed");
        assert_eq!(edge.capture.label(), "armed");
        // JSONL: the edge event carries the JSON edge verbatim.
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            dir.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let path = dir.path().join("events.jsonl");
        let mut writer = crate::inventory_events::EventWriter::create(&path, 1 << 20, 5).unwrap();
        crate::inventory_events::emit_snapshot_as_events(&mut writer, &presentation, 1).unwrap();
        drop(writer);
        let body = std::fs::read_to_string(&path).unwrap();
        let events: Vec<serde_json::Value> = body
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|line| line["kind"] == "edge_observed")
            .map(|line| line["event"].clone())
            .collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["entries"], edge_json["entries"]);
        assert_eq!(events[0]["activity"], "recently observed");
        assert_eq!(events[0]["capture"], "armed");
        // Pager snapshot and dashboard frame: the same labels.
        let snapshot = render_snapshot(&presentation);
        let label = coverage_label(&edge.coverage);
        let line = snapshot
            .lines()
            .find(|line| {
                line.starts_with(&format!(
                    "edge {} -> {} ",
                    edge.caller.label(),
                    edge.module.label()
                ))
            })
            .unwrap();
        assert!(line.contains(&format!("coverage {label}")), "{line}");
        assert_eq!(entries_display(edge), "9");
        let mut tail = LogTail::bounded();
        tail.push("p11scope: pass 1: 1 scanned (1 native, 0 scan-pinned)");
        // The frame reads the dashboard display's windowed view.
        let display = Presentation::capture_dashboard(
            &native.scene.coordinator,
            "native",
            0,
            2000,
            1,
            2000,
            crate::inventory_present::DASHBOARD_ACTIVITY_WINDOW_NS,
        );
        let frame = DisplayFrame {
            presentation: std::sync::Arc::new(display),
            log: tail.snapshot(),
        };
        let text = String::from_utf8(render_frame(
            &frame,
            Viewport {
                width: 200,
                height: 120,
            },
            &DashboardState::new(),
        ))
        .unwrap()
        .replace("\x1b[H", "")
        .replace("\x1b[K", "");
        assert!(text.contains("entries 9"), "{text}");
        assert!(text.contains("activity recently observed"), "{text}");
        assert!(text.contains("capture armed"), "{text}");
    }

    #[test]
    fn integrity_rows_and_unresolved_endpoints_are_gaps() {
        let (mut native, _) = NativeScene::new();
        let mut batch = witness_batch();
        batch.domain = native.domain;
        batch.health.discovery_counters = Some([0; 5]);
        batch.integrity_total = 1;
        batch
            .integrity
            .push(crate::attach::capture::WitnessIntegrity {
                key: p11scope_ebpf_common::inventory_callers::CallerObjectKey {
                    image: ImageIdentity {
                        task_cookie: 1,
                        exec_id: 1,
                    },
                    object_id: 0,
                    reserved: 0,
                },
                value: None,
                reason: "scripted".into(),
            });
        // An endpoint the attach set never admitted.
        batch.rows.push(WitnessRow::scripted(
            native.domain,
            41,
            1,
            native.scene.delta.endpoints[0].object,
            EndpointId(9),
            9,
            100,
        ));
        native.stage(NativeBatch::Witness(Box::new(batch)));
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        let subjects = native.gap_subjects();
        assert!(subjects.contains(&"native witness rows failed validation".to_string()));
        assert!(subjects.contains(&"native witness without a module".to_string()));
        assert_eq!(native.module_unbound(), None);
        assert_eq!(
            native.scene.coordinator.registry.witness_census().integrity,
            1
        );
        // M3/M4: the unresolved row is counted where it went, the counts
        // reconcile with the census, and no gap reads as attribution.
        let registry = &native.scene.coordinator.registry;
        let census = registry.witness_census();
        let placement = registry.witness_placement();
        assert_eq!(placement.unresolved, 1);
        assert_eq!(placement.total(), census.bound + census.unbound_total());
        assert!(registry.gaps().iter().all(|gap| gap.pid.is_none()));
    }

    #[test]
    fn finish_decides_every_waiting_row_unbound() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 100, 0);
        native.read(vec![row]);
        let receipt = native.stage(NativeBatch::Finish {
            domain: native.domain,
        });
        assert_eq!(receipt.decided, 1);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(!native.scene.coverage(caller).is_witnessed());
        assert_eq!(
            native
                .module_unbound()
                .unwrap()
                .reasons
                .get("evidence_incomplete"),
            Some(&1)
        );
    }

    /// Answers one ticket for every pin of one domain (self-process tests).
    struct OneTicket {
        domain: NativeDomainId,
        ticket: u64,
    }

    impl NativeIdentity<crate::process::PidPin> for OneTicket {
        fn owner_image(&mut self, _: u32) -> Option<ImageIdentity> {
            None
        }

        fn query_cookie(
            &mut self,
            domain: NativeDomainId,
            _: &crate::process::PidPin,
        ) -> CookieQuery {
            if domain == self.domain {
                CookieQuery::Cookie(DomainCookie::scripted(domain, self.ticket))
            } else {
                CookieQuery::Unavailable("another domain".into())
            }
        }
    }

    #[test]
    fn a_native_owner_gets_the_exec_proof_and_its_caller_still_retires() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let now = crate::discovery::caller_registry::now_ns();
        let caller = coordinator
            .test_open_native_owner(pid, fixture_image(pid).unwrap(), &mut FixtureImages, now)
            .unwrap();
        let domain = NativeDomainId::mint();
        let mut identity = OneTicket { domain, ticket: 41 };
        let object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
        let stamps = Stamps::from(now);
        coordinator
            .binder
            .note_exec_coverage(ExecCoverage::scripted(domain, 0));
        let mut stage = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                         rows: Vec<WitnessRow>| {
            let mut events = Vec::new();
            for batch in [
                stamps.read(domain, rows),
                stamps.drain(domain),
                stamps.read(domain, Vec::new()),
            ] {
                events.extend(
                    coordinator
                        .stage_native(batch, &mut identity, now + 10)
                        .events,
                );
            }
            events
        };
        let bound = WitnessRow::scripted(domain, 41, 1, object, EndpointId(0), pid, now + 1);
        assert!(stage(&mut coordinator, vec![bound]).is_empty());
        let later = WitnessRow::scripted(domain, 41, 2, object, EndpointId(1), pid, now + 2);
        let events = stage(&mut coordinator, vec![later]);
        assert!(
            matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == caller),
            "{events:?}"
        );
        coordinator.commit_batch(false).unwrap();
        assert!(
            !coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native exec proof not applied"),
            "the lifecycle adapter applies the proof: {:?}",
            coordinator.registry().gaps()
        );
        let owner = coordinator.owner_of(caller).unwrap();
        assert_eq!(
            coordinator
                .engine
                .inventory_owner_epochs(owner)
                .unwrap()
                .image_state,
            ImageCheck::Changed,
            "the proved old owner is invalidated"
        );
        assert!(coordinator.adapter().record(caller).unwrap().retired);
    }

    /// H6 slice 2: a proved old incarnation invalidates all prepared old
    /// leases/receipts before publication, with retained history. A generic
    /// EXEC hint does not grant exact image state. Fresh correctly scoped
    /// successor scan/physical names remain useful without a manifest or H0.
    #[test]
    fn automatic_exec_invalidates_old_inventory_leases() {
        // Real provider child under PID scope: its mapped provider gives the
        // owner committed module history to retain.
        let dir = tempfile::tempdir().unwrap();
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let provider = gcc(
            dir.path(),
            "scoped-provider.so",
            &manifest.join("crates/discover/tests/fixture/version_matrix.c"),
            &["-shared", "-fPIC", "-DLEGACY_MINOR=40"],
            &[],
        );
        gcc(
            dir.path(),
            "scoped-driver",
            &manifest.join("tests/fixtures/catalog-driver.c"),
            &["-O2", "-Wall", "-Wextra", "-Werror"],
            &["-ldl"],
        );
        let child = spawn_cgroup_provider_child(dir.path(), &provider, "ready");
        let pid = child.id();
        let mut coordinator = InventoryCoordinator::new(
            Scope::Pid(pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let now = crate::discovery::caller_registry::now_ns();
        // Committed history first: a full native pass over the child.
        let report = coordinator
            .scan_pass(
                &InventoryScope::Pid(pid),
                None,
                &mut FixtureImages,
                &mut OwnerImages(fixture_image),
                u64::MAX,
                now,
            )
            .unwrap();
        assert_eq!(report.native_callers, 1);
        coordinator.commit_batch(true).unwrap();
        let caller = coordinator.adapter().live_id(pid).unwrap();
        let owner = coordinator.owner_of(caller).unwrap();
        let modules_before = coordinator.engine.modules.len();
        assert!(modules_before > 0, "the owner committed real history");
        let complete_before = coordinator.engine.inventory_last_complete(owner).unwrap();
        assert!(
            complete_before.is_some(),
            "the owner committed a complete receipt"
        );
        // A prepared old lease and a prepared old receipt, held across the
        // proof: both must die with the proved old image.
        let lease = coordinator.engine.acquire_inventory_scan(owner).unwrap();
        let receipt = coordinator
            .engine
            .scan_inventory_owner(&lease, &mut FixtureImages)
            .unwrap();
        let prepared = coordinator
            .engine
            .prepare_inventory_reconciliation(receipt, &mut FixtureImages)
            .unwrap();
        // Natively proven transition: image (41,1) binds, then (41,2).
        let domain = NativeDomainId::mint();
        let mut identity = OneTicket { domain, ticket: 41 };
        let object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
        let stamps = Stamps::from(now);
        coordinator
            .binder
            .note_exec_coverage(ExecCoverage::scripted(domain, 0));
        let mut stage = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                         rows: Vec<WitnessRow>| {
            let mut events = Vec::new();
            for batch in [
                stamps.read(domain, rows),
                stamps.drain(domain),
                stamps.read(domain, Vec::new()),
            ] {
                events.extend(
                    coordinator
                        .stage_native(batch, &mut identity, now + 10)
                        .events,
                );
            }
            events
        };
        let bound = WitnessRow::scripted(domain, 41, 1, object, EndpointId(0), pid, now + 1);
        assert!(stage(&mut coordinator, vec![bound]).is_empty());
        let later = WitnessRow::scripted(domain, 41, 2, object, EndpointId(1), pid, now + 2);
        let events = stage(&mut coordinator, vec![later]);
        assert!(
            matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == caller),
            "{events:?}"
        );
        coordinator.commit_batch(false).unwrap();
        // Decisive: the proof applies (no refusal gap) and the old owner is
        // invalidated before publication.
        assert!(
            !coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native exec proof not applied"),
            "the proof must apply, not refuse: {:?}",
            coordinator.registry().gaps()
        );
        let epochs = coordinator.engine.inventory_owner_epochs(owner).unwrap();
        assert_eq!(
            epochs.image_state,
            ImageCheck::Changed,
            "the proved old image is invalidated"
        );
        assert!(
            coordinator.engine.release_inventory_scan(&lease).is_err(),
            "the prepared old scan lease dies with the image"
        );
        assert!(
            coordinator
                .engine
                .commit_inventory_reconciliation(prepared, &mut FixtureImages)
                .is_err(),
            "the prepared old receipt dies with the image"
        );
        // History is retained, not rewritten.
        assert_eq!(coordinator.engine.modules.len(), modules_before);
        assert_eq!(
            coordinator.engine.inventory_last_complete(owner).unwrap(),
            complete_before
        );
        assert!(
            coordinator.adapter().record(caller).unwrap().retired,
            "the proved old caller retires"
        );
        let successor = coordinator.adapter().live_id(pid).unwrap();
        assert_ne!(successor, caller);

        // A generic EXEC hint grants nothing exact: an EXEC lifecycle
        // record alone proves no transition and touches no owner.
        let mut hinted = DiscoveryBatch::scripted(domain, Vec::new(), now + 20);
        // SAFETY: DiscoveryRecord contains only integer fields; this is the
        // same fixed, zero-reserved lifecycle wire shape the real producer emits.
        let mut hint_record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
        hint_record.hook_ts_ns = now + 20;
        hint_record.pid_tgid = (u64::from(pid) << 32) | u64::from(pid);
        hint_record.kind = p11scope_ebpf_common::DISCOVERY_KIND_EXEC;
        hinted.records.push(hint_record);
        let receipt = coordinator.stage_native(
            NativeBatch::Lifecycle(hinted),
            &mut OneTicket { domain, ticket: 41 },
            now + 21,
        );
        assert!(receipt.events.is_empty(), "{:?}", receipt.events);
        assert!(
            coordinator.binder.take_transitions().is_empty(),
            "a hint alone is not an ended-incarnation proof"
        );

        // Fresh successor authority comes from its own validated admission:
        // LoaderHint/Periodic touch neither image state nor the revision, and
        // the successor scans usefully with no manifest and no H0 receipt.
        let image2 = ImageIdentity {
            task_cookie: u64::from(pid) + 1,
            exec_id: 9,
        };
        let owner2 = coordinator
            .engine
            .open_inventory_owner(pid, image2, &mut FixtureImages)
            .unwrap();
        coordinator.owners.insert(successor, owner2);
        for cause in [RefreshCause::LoaderHint, RefreshCause::Periodic] {
            coordinator
                .engine
                .request_inventory_refresh(owner2, cause)
                .unwrap();
        }
        assert_eq!(
            coordinator
                .engine
                .inventory_owner_epochs(owner2)
                .unwrap()
                .image_state,
            ImageCheck::Exact,
            "generic hints grant nothing exact and change nothing proven"
        );
        let commit2 = coordinator
            .scan_owner(owner2, &mut FixtureImages, u64::MAX, now + 100)
            .unwrap();
        assert!(commit2.complete, "the successor scan commits");
        assert!(
            coordinator.engine.manifests.is_empty(),
            "physical recovery needs no manifest"
        );
        assert_eq!(
            coordinator.semantic_bindings().len(),
            0,
            "physical recovery needs no H0 receipt"
        );
        assert!(
            coordinator
                .engine
                .modules
                .iter()
                .any(|module| module.scanned.view == owner2 && !module.scanned.path.is_empty()),
            "the successor scan names its modules"
        );
        assert!(
            coordinator
                .engine
                .modules
                .iter()
                .any(|module| module.scanned.view == owner),
            "the old owner's module history stays retained alongside"
        );

        // A proof naming another owner is refused and changes nothing; the
        // guard is never consulted and no Detailed cookie is assigned.
        let self_pid = std::process::id();
        let mut prover = InventoryCoordinator::new(
            Scope::Pid(self_pid),
            HookRegistry::builtin(),
            Vec::new(),
            OsProcessSource,
            RegistryLimits::default_limits(),
        )
        .unwrap();
        let proof_owner = prover
            .test_open_native_owner(
                self_pid,
                fixture_image(self_pid).unwrap(),
                &mut FixtureImages,
                now,
            )
            .unwrap();
        let proof_domain = NativeDomainId::mint();
        let mut proof_identity = OneTicket {
            domain: proof_domain,
            ticket: 41,
        };
        prover
            .binder
            .note_exec_coverage(ExecCoverage::scripted(proof_domain, 0));
        let proof_stamps = Stamps::from(now);
        let mut proof_stage = |prover: &mut InventoryCoordinator<OsProcessSource>,
                               rows: Vec<WitnessRow>| {
            for batch in [
                proof_stamps.read(proof_domain, rows),
                proof_stamps.drain(proof_domain),
                proof_stamps.read(proof_domain, Vec::new()),
            ] {
                prover.stage_native(batch, &mut proof_identity, now + 10);
            }
        };
        let proof_object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
        proof_stage(
            &mut prover,
            vec![WitnessRow::scripted(
                proof_domain,
                41,
                1,
                proof_object,
                EndpointId(0),
                self_pid,
                now + 1,
            )],
        );
        // The proving row goes through the binder only, so the transition
        // can be captured for proof-construction without being applied.
        let proving = WitnessRow::scripted(
            proof_domain,
            41,
            2,
            proof_object,
            EndpointId(1),
            self_pid,
            now + 2,
        );
        for batch in [
            proof_stamps.read(proof_domain, vec![proving]),
            proof_stamps.drain(proof_domain),
            proof_stamps.read(proof_domain, Vec::new()),
        ] {
            match batch {
                NativeBatch::Witness(read) => {
                    prover
                        .binder
                        .absorb_witnesses(&read, &prover.adapter, &mut proof_identity);
                }
                NativeBatch::Lifecycle(drain) => prover.binder.absorb_lifecycle(&drain),
                _ => unreachable!("scripted read/drain only"),
            }
        }
        let transitions = prover.binder.take_transitions();
        assert_eq!(transitions.len(), 1, "one proven transition captured");
        let stale_owner = ProcessViewId(999_999);
        let before = coordinator.engine.inventory_owner_epochs(owner2).unwrap();
        assert!(
            coordinator
                .engine
                .request_inventory_refresh(
                    owner2,
                    RefreshCause::ValidatedExec(ExecProof::from_transition(
                        stale_owner,
                        transitions[0]
                    )),
                )
                .is_err(),
            "a proof naming another owner is refused"
        );
        assert_eq!(
            coordinator.engine.inventory_owner_epochs(owner2).unwrap(),
            before,
            "a refused proof changes nothing"
        );
        // Re-proving the ended owner is idempotent: history stays intact and
        // no new exact authority is granted.
        let epochs_before = coordinator.engine.inventory_owner_epochs(owner).unwrap();
        coordinator
            .engine
            .request_inventory_refresh(
                owner,
                RefreshCause::ValidatedExec(ExecProof::from_transition(owner, transitions[0])),
            )
            .unwrap();
        assert_eq!(
            coordinator.engine.inventory_owner_epochs(owner).unwrap(),
            epochs_before,
            "re-proving an ended owner changes nothing"
        );
        // No guard can resurrect the ended owner: acquisition refuses before
        // any guard check, so invalidation grants no new exact result and
        // assigns no Detailed cookie.
        struct CountingGuard(std::cell::Cell<usize>);
        impl ImageGuard for CountingGuard {
            fn check(&mut self, _: &ProcessView, _: ImageIdentity) -> ImageCheck {
                self.0.set(self.0.get() + 1);
                ImageCheck::Exact
            }
        }
        let mut counting = CountingGuard(std::cell::Cell::new(0));
        assert!(
            coordinator
                .scan_owner(owner, &mut counting, u64::MAX, now + 200)
                .is_err(),
            "an ended owner scans nothing new"
        );
        assert_eq!(
            counting.0.get(),
            0,
            "the ended owner refuses before any guard check"
        );
        let _ = proof_owner;
    }

    /// H6 slice 2: poison the numeric-PID reopen path; the successful
    /// same-process successor still admits using original custody. Changed
    /// process, wrong original Arc/domain, stale owner/revision and
    /// mismatched current receipt refuse. Inventory and Detailed colliding
    /// numeric cookies do not join. Replayed/delayed second-domain
    /// transition creates no second successor.
    #[test]
    fn automatic_exec_successor_keeps_original_custody() {
        // Scenes are boxed below: each coordinator value is ~54 KiB and
        // debug builds retain every local's stack slot, so the oracle's
        // scenes live on the heap to fit the default test stack.
        use crate::discovery::native_binding::CallerLookup;
        let pid = std::process::id();
        let now = crate::discovery::caller_registry::now_ns();

        // Native proof with reopen poisoned: the successor admits on the
        // original held pin, with no numeric reopen attempted.
        {
            let (mut native, caller) = NativeScene::boxed();
            native.scene.source.exec(7, 200, "/bin/other");
            native.scene.source.poison_reopen();
            let opens_before = native.scene.source.reopen_attempts();
            native.answer(7, 500, 41);
            let first = native.row(41, 1, 7, 100, 0);
            native.witness(vec![first]);
            let later = native.row(41, 2, 7, 1_100, 1);
            let events = native.witness(vec![later]);
            let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
                panic!("poisoned reopen must still admit the successor: {events:?}");
            };
            assert_eq!(*old, caller);
            let adapter = &native.scene.coordinator.adapter;
            assert!(adapter.record(caller).unwrap().retired);
            assert_eq!(adapter.live_id(7), Some(*new));
            let successor = adapter.record(*new).unwrap();
            assert_eq!(successor.start_time, Some(500), "same process");
            assert_eq!(successor.incarnation, 1);
            assert_eq!(
                successor.exe.as_ref().unwrap().path.as_deref(),
                Some("/bin/other"),
                "the successor carries the current image"
            );
            let (_, pin) = adapter.live_pin(7).unwrap();
            assert_eq!(*pin, (7, 500), "the original held pin moves over");
            assert_eq!(
                native.scene.source.reopen_attempts(),
                opens_before,
                "no numeric-PID reopen during the handoff"
            );
            assert_eq!(
                native.scene.coverage(caller),
                UseCoverage::Counted {
                    since_ns: 100,
                    lossy: false
                },
                "the old image keeps its count"
            );
        }

        // Scan-proven exec with reopen poisoned: same retained custody.
        {
            let (mut scan, caller) = NativeScene::boxed();
            scan.scene.source.exec(7, 200, "/bin/other");
            scan.scene.source.poison_reopen();
            let opens_before = scan.scene.source.reopen_attempts();
            let observed: BTreeSet<u32> = [7].into_iter().collect();
            let events = scan.scene.coordinator.adapter.reconcile(
                &observed,
                &mut |_| ImageAuthority::ScanPinned,
                1_200,
            );
            let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
                panic!("poisoned scan handoff must still admit: {events:?}");
            };
            assert_eq!(*old, caller);
            let adapter = &scan.scene.coordinator.adapter;
            assert_eq!(adapter.live_id(7), Some(*new));
            assert_eq!(adapter.live_pin(7).unwrap().1, &(7, 500));
            assert_eq!(
                scan.scene.source.reopen_attempts(),
                opens_before,
                "scan handoff never reopens by PID"
            );
        }

        // Same-file reexec: the scan lane sees no change and splits
        // nothing; actual native evidence still establishes the transition.
        {
            let (mut same, caller) = NativeScene::boxed();
            same.scene.source.poison_reopen();
            let observed: BTreeSet<u32> = [7].into_iter().collect();
            let events = same.scene.coordinator.adapter.reconcile(
                &observed,
                &mut |_| ImageAuthority::ScanPinned,
                1_200,
            );
            assert!(events.is_empty(), "{events:?}");
            assert_eq!(same.scene.coordinator.adapter.live_id(7), Some(caller));
            same.answer(7, 500, 41);
            same.witness(vec![same.row(41, 1, 7, 100, 0)]);
            let events = same.witness(vec![same.row(41, 2, 7, 1_100, 1)]);
            assert!(
                matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == caller),
                "{events:?}"
            );
            let adapter = &same.scene.coordinator.adapter;
            let successor = adapter.record(adapter.live_id(7).unwrap()).unwrap();
            assert_eq!(
                successor.exe,
                adapter.record(caller).unwrap().exe,
                "same-file successor keeps the shared exe identity"
            );
        }

        // Changed process refuses: a dead pin ends the old incarnation but
        // mints no successor, attempts no reopen, and the reused pid later
        // admits fresh with no inherited history.
        {
            let (mut dead, caller) = NativeScene::boxed();
            dead.scene.source.poison_reopen();
            dead.scene.source.kill(7);
            let opens_before = dead.scene.source.reopen_attempts();
            let events = dead.scene.coordinator.adapter.exec_transition(
                caller,
                &mut |_| ImageAuthority::ScanPinned,
                2_000,
            );
            let [
                CallerEvent::AdmitFailed {
                    pid,
                    reason,
                    budget,
                },
            ] = events.as_slice()
            else {
                panic!("a dead pin must refuse the successor: {events:?}");
            };
            assert_eq!(*pid, 7);
            assert!(
                reason.contains("custody lost"),
                "the refusal names custody, not a pin failure: {reason}"
            );
            assert_eq!(*budget, None);
            assert_eq!(
                dead.scene.source.reopen_attempts(),
                opens_before,
                "no reopen is attempted without custody"
            );
            let adapter = &dead.scene.coordinator.adapter;
            assert!(adapter.record(caller).unwrap().retired);
            assert_eq!(adapter.live_id(7), None);
            assert_eq!(adapter.len(), 1, "no successor incarnation was minted");
        }

        // Caller budget N/N+1 at the shared reservation: N works, N+1
        // refuses with the exact requested occupancy.
        {
            let (mut full, caller) = NativeScene::boxed();
            full.scene.coordinator.adapter.set_max_callers(2);
            full.scene.source.spawn(8, 600);
            full.scene
                .coordinator
                .adapter
                .admit(8, ImageAuthority::ScanPinned, 60)
                .unwrap();
            let events = full.scene.coordinator.adapter.exec_transition(
                caller,
                &mut |_| ImageAuthority::ScanPinned,
                2_000,
            );
            let [CallerEvent::AdmitFailed { budget, .. }] = events.as_slice() else {
                panic!("a full budget must refuse the successor: {events:?}");
            };
            assert_eq!(
                budget.unwrap(),
                BudgetRefusal {
                    resource: "callers",
                    limit: 2,
                    requested: 3,
                }
            );
            assert_eq!(
                full.scene.coordinator.adapter.admit_refused(),
                1,
                "the refusal counts exactly once"
            );
            let (mut roomy, caller) = NativeScene::boxed();
            roomy.scene.coordinator.adapter.set_max_callers(3);
            roomy.scene.source.spawn(8, 600);
            roomy
                .scene
                .coordinator
                .adapter
                .admit(8, ImageAuthority::ScanPinned, 60)
                .unwrap();
            let events = roomy.scene.coordinator.adapter.exec_transition(
                caller,
                &mut |_| ImageAuthority::ScanPinned,
                2_000,
            );
            assert!(
                matches!(events.as_slice(), [CallerEvent::ExecRetired { .. }]),
                "{events:?}"
            );
            assert_eq!(roomy.scene.coordinator.adapter.len(), 3);
        }

        // Mismatched current-image queries refuse: wrong exec, wrong pid,
        // foreign domain, and a post-admission exec record.
        {
            let (mut current, caller) = NativeScene::boxed();
            current.answer(7, 500, 41);
            current.witness(vec![current.row(41, 1, 7, 100, 0)]);
            let image = DomainCookie::scripted(current.domain, 41);
            let request = |exec_id: u64, pid: u32| CurrentBindingRequest {
                caller,
                pid,
                image,
                exec_id,
            };
            let sight = |scene: &mut NativeScene, req: CurrentBindingRequest| {
                let coordinator = &scene.scene.coordinator;
                let lookup = &coordinator.adapter as &dyn CallerLookup<(u32, u64)>;
                coordinator
                    .binder
                    .sight_current_binding(req, lookup, &mut scene.cookies)
            };
            // CurrentBindingSighting carries no Debug by design; match instead.
            let refused =
                |scene: &mut NativeScene, req: CurrentBindingRequest| match sight(scene, req) {
                    Err(reason) => reason,
                    Ok(_) => panic!("a mismatched current image must refuse"),
                };
            assert_eq!(
                refused(&mut current, request(2, 7)),
                UnboundReason::ExecAmbiguous,
                "a mismatched exec refuses"
            );
            assert_eq!(
                refused(&mut current, request(1, 999)),
                UnboundReason::NoLiveCaller,
                "a mismatched pid refuses"
            );
            let foreign = DomainCookie::scripted(NativeDomainId::mint(), 41);
            assert_eq!(
                refused(
                    &mut current,
                    CurrentBindingRequest {
                        caller,
                        pid: 7,
                        image: foreign,
                        exec_id: 1
                    }
                ),
                UnboundReason::EvidenceIncomplete,
                "a foreign domain proves nothing here"
            );
            current
                .scene
                .coordinator
                .binder
                .set_current_binding_clock(|| Some(1_005));
            let sighted = match sight(&mut current, request(1, 7)) {
                Ok(sighted) => sighted,
                Err(reason) => panic!("the matched current image must sight: {reason:?}"),
            };
            assert!(
                matches!(
                    current
                        .scene
                        .coordinator
                        .binder
                        .check_current_binding(&sighted),
                    CurrentBindingCheck::Proven
                ),
                "the matched current image proves"
            );
            // SAFETY: DiscoveryRecord contains only integer fields.
            let mut exec_record: p11scope_ebpf_common::DiscoveryRecord =
                unsafe { std::mem::zeroed() };
            exec_record.hook_ts_ns = 60;
            exec_record.pid_tgid = (u64::from(7u32) << 32) | u64::from(7u32);
            exec_record.kind = p11scope_ebpf_common::DISCOVERY_KIND_EXEC;
            let at = current.stamps.tick();
            current.stage(NativeBatch::Lifecycle(DiscoveryBatch::scripted(
                current.domain,
                vec![exec_record],
                at,
            )));
            assert_eq!(
                refused(&mut current, request(1, 7)),
                UnboundReason::ExecAfterAdmission,
                "an exec record after admission refuses the old proof"
            );
        }

        // Colliding numeric cookies across domains never join: a Detailed
        // transition for pid 7 leaves the Inventory-bound pid 8 alone, and
        // pid 8 keeps binding its own ticket afterwards.
        {
            let (mut split, caller) = NativeScene::boxed();
            let detailed = split.domain;
            split.scene.source.spawn(8, 600);
            let caller8 = split
                .scene
                .coordinator
                .adapter
                .admit(8, ImageAuthority::ScanPinned, 150)
                .unwrap();
            let inventory = NativeDomainId::mint();
            split
                .scene
                .coordinator
                .binder
                .note_exec_coverage(ExecCoverage::scripted(inventory, 0));
            split.cookies.answers.insert(
                ((8, 600), inventory),
                CookieQuery::Cookie(DomainCookie::scripted(inventory, 41)),
            );
            let endpoint = split.scene.delta.endpoints[0];
            let bind8 =
                WitnessRow::scripted(inventory, 41, 1, endpoint.object, endpoint.id, 8, 200);
            split.stage(split.stamps.read(inventory, vec![bind8]));
            split.stage(split.stamps.drain(inventory));
            split.stage(split.stamps.read(inventory, Vec::new()));
            split.scene.coordinator.commit_batch(false).unwrap();
            assert_eq!(
                split.scene.coordinator.binder.census().bound,
                1,
                "pid 8 binds ticket 41 in the Inventory domain"
            );
            split.answer(7, 500, 41);
            split.witness(vec![split.row(41, 1, 7, 100, 0)]);
            let events = split.witness(vec![split.row(41, 2, 7, 1_100, 1)]);
            assert!(
                matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == caller),
                "{events:?}"
            );
            assert_eq!(
                split.scene.coordinator.adapter.live_id(8),
                Some(caller8),
                "the Detailed transition touches no Inventory caller"
            );
            assert_eq!(
                split.scene.coordinator.adapter.live_id(7).unwrap(),
                match events.as_slice() {
                    [CallerEvent::ExecRetired { new, .. }] => *new,
                    _ => unreachable!(),
                }
            );
            let _ = detailed;
        }

        // Held handoff, changed process: the generation turns over while
        // the handoff is held, so commit refuses with custody lost and the
        // handoff is consumed without minting.
        {
            let (mut held, caller) = NativeScene::boxed();
            held.answer(7, 500, 41);
            held.witness(vec![held.row(41, 1, 7, 100, 0)]);
            let captured = held.binder_only(vec![held.row(41, 2, 7, 1_100, 1)]);
            assert_eq!(captured.len(), 1);
            assert!(
                held.scene
                    .coordinator
                    .mint_pending_successor(captured[0], 1_200)
                    .is_some()
            );
            assert!(
                held.scene
                    .coordinator
                    .pending_successors
                    .contains_key(&caller),
                "the handoff is held, not committed"
            );
            held.scene.source.kill(7);
            held.scene.source.spawn(7, 900);
            let events = held.scene.coordinator.commit_pending_successor(
                caller,
                ImageAuthority::ScanPinned,
                1_300,
            );
            let [CallerEvent::AdmitFailed { reason, .. }] = events.as_slice() else {
                panic!("a turned-over generation must refuse: {events:?}");
            };
            assert!(reason.contains("custody lost"), "{reason}");
            assert!(
                held.scene.coordinator.pending_successors.is_empty(),
                "a refused handoff is consumed"
            );
            assert_eq!(held.scene.coordinator.adapter.live_id(7), None);
            assert_eq!(held.scene.coordinator.adapter.len(), 1);
        }

        // Held handoff, newer image: a second exec before commit rejects
        // the stale candidate; the renewed request services separately.
        {
            let (mut stale, caller) = NativeScene::boxed();
            stale.answer(7, 500, 41);
            stale.witness(vec![stale.row(41, 1, 7, 100, 0)]);
            let captured = stale.binder_only(vec![stale.row(41, 2, 7, 1_100, 1)]);
            stale
                .scene
                .coordinator
                .mint_pending_successor(captured[0], 1_200)
                .unwrap();
            stale.scene.source.exec(7, 300, "/bin/newer");
            let events = stale.scene.coordinator.commit_pending_successor(
                caller,
                ImageAuthority::ScanPinned,
                1_300,
            );
            let [CallerEvent::AdmitFailed { reason, .. }] = events.as_slice() else {
                panic!("a newer image before commit must refuse: {events:?}");
            };
            assert!(reason.contains("newer image"), "{reason}");
        }

        // Held handoff, clean commit: the manually held handoff commits to
        // exactly one successor on original custody.
        {
            let (mut manual, caller) = NativeScene::boxed();
            manual.answer(7, 500, 41);
            manual.witness(vec![manual.row(41, 1, 7, 100, 0)]);
            let captured = manual.binder_only(vec![manual.row(41, 2, 7, 1_100, 1)]);
            manual
                .scene
                .coordinator
                .mint_pending_successor(captured[0], 1_200)
                .unwrap();
            let events = manual.scene.coordinator.commit_pending_successor(
                caller,
                ImageAuthority::ScanPinned,
                1_300,
            );
            let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
                panic!("a clean held handoff must commit: {events:?}");
            };
            assert_eq!(*old, caller);
            assert_eq!(manual.scene.coordinator.adapter.live_id(7), Some(*new));
            assert!(manual.scene.coordinator.pending_successors.is_empty());
            assert!(
                manual
                    .scene
                    .coordinator
                    .mint_pending_successor(captured[0], 1_400)
                    .is_none(),
                "no second handoff for an ended caller"
            );
        }

        // Delayed proof from a second domain allocates no second
        // successor: both transitions name the old incarnation, the first
        // commits, and the replayed/delayed remainder changes nothing.
        {
            let (mut two, caller) = NativeScene::boxed();
            let second = NativeDomainId::mint();
            two.scene
                .coordinator
                .binder
                .note_exec_coverage(ExecCoverage::scripted(second, 0));
            two.cookies.answers.insert(
                ((7, 500), second),
                CookieQuery::Cookie(DomainCookie::scripted(second, 41)),
            );
            two.answer(7, 500, 41);
            two.witness(vec![two.row(41, 1, 7, 100, 0)]);
            let endpoint = two.scene.delta.endpoints[0];
            let other = WitnessRow::scripted(second, 41, 1, endpoint.object, endpoint.id, 7, 100);
            two.stage(two.stamps.read(second, vec![other]));
            two.stage(two.stamps.drain(second));
            two.stage(two.stamps.read(second, Vec::new()));
            two.scene.coordinator.commit_batch(false).unwrap();
            let first = two.binder_only(vec![two.row(41, 2, 7, 1_100, 1)]);
            assert_eq!(first.len(), 1);
            let proving =
                WitnessRow::scripted(second, 41, 2, endpoint.object, endpoint.id, 7, 1_100);
            let batches = [
                two.stamps.read(second, vec![proving]),
                two.stamps.drain(second),
                two.stamps.read(second, Vec::new()),
            ];
            for batch in batches {
                match batch {
                    NativeBatch::Witness(read) => {
                        let coordinator = &mut two.scene.coordinator;
                        coordinator.binder.absorb_witnesses(
                            &read,
                            &coordinator.adapter,
                            &mut two.cookies,
                        );
                    }
                    NativeBatch::Lifecycle(drain) => {
                        two.scene.coordinator.binder.absorb_lifecycle(&drain);
                    }
                    _ => unreachable!("scripted read/drain only"),
                }
            }
            let delayed = two.scene.coordinator.binder.take_transitions();
            assert_eq!(delayed.len(), 1, "the second domain proves independently");
            assert_eq!(delayed[0].caller(), caller);
            let events =
                two.scene
                    .coordinator
                    .apply_exec_transition(first[0], &mut two.cookies, 1_200);
            assert!(
                matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == caller),
                "{events:?}"
            );
            let events =
                two.scene
                    .coordinator
                    .apply_exec_transition(delayed[0], &mut two.cookies, 1_300);
            assert!(events.is_empty(), "delayed proof mints nothing: {events:?}");
            let events =
                two.scene
                    .coordinator
                    .apply_exec_transition(first[0], &mut two.cookies, 1_400);
            assert!(
                events.is_empty(),
                "replayed proof mints nothing: {events:?}"
            );
            assert_eq!(two.scene.coordinator.adapter.len(), 2);
        }

        // Stale owner refuses the handoff: a desynced owner mapping ends
        // the old incarnation without minting, and the real owner is
        // untouched.
        {
            let mut stale_owner = boxed_os_coordinator(pid);
            let caller = stale_owner
                .test_open_native_owner(pid, fixture_image(pid).unwrap(), &mut FixtureImages, now)
                .unwrap();
            let owner = stale_owner.owner_of(caller).unwrap();
            stale_owner.owners.insert(caller, ProcessViewId(999_999));
            let domain = NativeDomainId::mint();
            let mut identity = OneTicket { domain, ticket: 41 };
            let object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
            let stamps = Stamps::from(now);
            stale_owner
                .binder
                .note_exec_coverage(ExecCoverage::scripted(domain, 0));
            let mut stage = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                             rows: Vec<WitnessRow>| {
                let mut events = Vec::new();
                for batch in [
                    stamps.read(domain, rows),
                    stamps.drain(domain),
                    stamps.read(domain, Vec::new()),
                ] {
                    events.extend(
                        coordinator
                            .stage_native(batch, &mut identity, now + 10)
                            .events,
                    );
                }
                events
            };
            assert!(
                stage(
                    &mut stale_owner,
                    vec![WitnessRow::scripted(
                        domain,
                        41,
                        1,
                        object,
                        EndpointId(0),
                        pid,
                        now + 1
                    )]
                )
                .is_empty()
            );
            let events = stage(
                &mut stale_owner,
                vec![WitnessRow::scripted(
                    domain,
                    41,
                    2,
                    object,
                    EndpointId(1),
                    pid,
                    now + 2,
                )],
            );
            assert!(
                matches!(events.as_slice(), [CallerEvent::Retired { id, .. }] if *id == caller),
                "a stale owner retires without a successor: {events:?}"
            );
            stale_owner.commit_batch(false).unwrap();
            assert!(
                stale_owner
                    .registry()
                    .gaps()
                    .iter()
                    .any(|gap| gap.subject == "native exec proof not applied"),
                "the stale handoff records its refusal"
            );
            assert_eq!(stale_owner.adapter.live_id(pid), None);
            assert_eq!(stale_owner.adapter.len(), 1);
            assert_eq!(
                stale_owner
                    .engine
                    .inventory_owner_epochs(owner)
                    .unwrap()
                    .image_state,
                ImageCheck::Exact,
                "the real owner is untouched by the desync"
            );
        }

        // Exhausted owner revision refuses permanently with history
        // intact: the old incarnation retires, nothing is minted, and the
        // owner stays readable.
        {
            let mut exhausted = boxed_os_coordinator(pid);
            let object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
            let stamps = Stamps::from(now);
            let caller = exhausted
                .test_open_native_owner(pid, fixture_image(pid).unwrap(), &mut FixtureImages, now)
                .unwrap();
            let owner = exhausted.owner_of(caller).unwrap();
            exhausted.engine.test_exhaust_owner_revision(owner).unwrap();
            let domain = NativeDomainId::mint();
            let mut identity = OneTicket { domain, ticket: 41 };
            exhausted
                .binder
                .note_exec_coverage(ExecCoverage::scripted(domain, 0));
            let mut stage = |coordinator: &mut InventoryCoordinator<OsProcessSource>,
                             rows: Vec<WitnessRow>| {
                let mut events = Vec::new();
                for batch in [
                    stamps.read(domain, rows),
                    stamps.drain(domain),
                    stamps.read(domain, Vec::new()),
                ] {
                    events.extend(
                        coordinator
                            .stage_native(batch, &mut identity, now + 10)
                            .events,
                    );
                }
                events
            };
            assert!(
                stage(
                    &mut exhausted,
                    vec![WitnessRow::scripted(
                        domain,
                        41,
                        1,
                        object,
                        EndpointId(0),
                        pid,
                        now + 1
                    )]
                )
                .is_empty()
            );
            let events = stage(
                &mut exhausted,
                vec![WitnessRow::scripted(
                    domain,
                    41,
                    2,
                    object,
                    EndpointId(1),
                    pid,
                    now + 2,
                )],
            );
            assert!(
                matches!(events.as_slice(), [CallerEvent::Retired { id, .. }] if *id == caller),
                "an exhausted revision retires without a successor: {events:?}"
            );
            exhausted.commit_batch(false).unwrap();
            assert!(
                exhausted
                    .registry()
                    .gaps()
                    .iter()
                    .any(|gap| gap.subject == "native exec proof not applied"),
                "the exhausted handoff records its refusal"
            );
            assert!(exhausted.engine.inventory_owner_epochs(owner).is_ok());
        }

        // Stop wins before successor admission: a held handoff releases
        // its custody at stop and no commit follows.
        {
            let (mut held_stop, caller) = NativeScene::boxed();
            held_stop.answer(7, 500, 41);
            held_stop.witness(vec![held_stop.row(41, 1, 7, 100, 0)]);
            let captured = held_stop.binder_only(vec![held_stop.row(41, 2, 7, 1_100, 1)]);
            held_stop
                .scene
                .coordinator
                .mint_pending_successor(captured[0], 1_200)
                .unwrap();
            held_stop.scene.coordinator.stop();
            assert!(
                held_stop.scene.coordinator.pending_successors.is_empty(),
                "stop releases held handoffs"
            );
            assert!(
                held_stop
                    .scene
                    .coordinator
                    .commit_pending_successor(caller, ImageAuthority::ScanPinned, 1_300)
                    .is_empty(),
                "no commit after the release"
            );
            held_stop.scene.coordinator.commit_batch(false).unwrap();
            assert!(
                held_stop
                    .gap_subjects()
                    .iter()
                    .any(|subject| subject == "held exec handoffs released at stop"),
                "the release is recorded"
            );
        }

        // Stop wins before successor admission and new scans: the proved
        // old incarnation still retires, no successor is minted, new
        // passes refuse without consuming a pass number, and staged facts
        // still drain.
        {
            let (mut stopped, caller) = NativeScene::boxed();
            stopped.answer(7, 500, 41);
            stopped.witness(vec![stopped.row(41, 1, 7, 100, 0)]);
            stopped.scene.coordinator.stop();
            stopped.scene.coordinator.stop();
            let events = stopped.witness(vec![stopped.row(41, 2, 7, 1_100, 1)]);
            assert!(
                matches!(events.as_slice(), [CallerEvent::Retired { id, .. }] if *id == caller),
                "stop retires the proved caller without a successor: {events:?}"
            );
            assert_eq!(stopped.scene.coordinator.adapter.live_id(7), None);
            assert_eq!(stopped.scene.coordinator.adapter.len(), 1);
            let passes_before = stopped.scene.coordinator.passes();
            let report = stopped.scene.coordinator.observe_empty_pass(
                &mut super::inventory::UnavailableImageGuard,
                &mut stopped.cookies,
                "post-stop pass",
                1_500,
            );
            assert_eq!(report.scanned, 0);
            assert!(report.events.is_empty());
            assert_eq!(report.pass, passes_before);
            assert_eq!(
                stopped.scene.coordinator.passes(),
                passes_before,
                "a refused pass consumes no pass number"
            );
            stopped.scene.coordinator.commit_batch(false).unwrap();
            let subjects = stopped.gap_subjects();
            for want in [
                "successor admission refused while stopped",
                "scan refused after stop",
            ] {
                assert!(
                    subjects.iter().any(|subject| subject == want),
                    "the refusal is recorded: {subjects:?}"
                );
            }
        }
    }

    /// H6 slice 2: leader exit with live sibling keeps original custody and
    /// explicit link loss; later EXEC in the same and a later batch restores
    /// useful endpoints. Whole-group death and delayed pre-admission EXEC
    /// for reused PID cannot attach. Owned-initial-exec acknowledgement
    /// happens exactly once.
    #[test]
    fn automatic_exec_live_group_exit_then_exec_recovers() {
        // Leader exit with a live sibling: explicit link loss once, custody
        // kept, no tombstone, sibling untouched.
        let (mut native, leader) = NativeScene::new();
        native.scene.source.spawn(8, 600);
        let sibling = native
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 150)
            .unwrap();
        native.answer(7, 500, 41);
        native.answer(8, 600, 42);
        native.witness(vec![native.row(41, 1, 7, 100, 0)]);
        native.witness(vec![native.row(42, 1, 8, 200, 0)]);
        // SAFETY: DiscoveryRecord contains only integer fields.
        let mut exit_record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
        exit_record.hook_ts_ns = 1_500;
        exit_record.pid_tgid = (u64::from(7u32) << 32) | u64::from(7u32);
        exit_record.kind = p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
        let receipt = native.stage(NativeBatch::Lifecycle(DiscoveryBatch::scripted(
            native.domain,
            vec![exit_record],
            native.stamps.tick(),
        )));
        assert!(receipt.events.is_empty(), "{:?}", receipt.events);
        native.scene.coordinator.commit_batch(false).unwrap();
        let adapter = &native.scene.coordinator.adapter;
        assert_eq!(adapter.live_id(7), Some(leader), "custody kept");
        assert_eq!(adapter.live_pin(7).unwrap().1, &(7, 500));
        assert!(!adapter.record(leader).unwrap().retired, "no tombstone");
        assert_eq!(
            adapter.live_id(8),
            Some(sibling),
            "the live sibling is untouched"
        );
        let losses = native
            .gap_subjects()
            .iter()
            .filter(|subject| subject.as_str() == "leader task link loss")
            .count();
        assert_eq!(losses, 1, "explicit link loss, recorded once");
        // A replayed exit, an unknown pid, and a truly dead caller add no
        // further link-loss record.
        let receipt = native.stage(NativeBatch::Lifecycle(DiscoveryBatch::scripted(
            native.domain,
            vec![exit_record],
            native.stamps.tick(),
        )));
        assert!(receipt.events.is_empty());
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native
                .gap_subjects()
                .iter()
                .filter(|subject| subject.as_str() == "leader task link loss")
                .count(),
            1,
            "link loss is recorded once per incarnation"
        );

        // Later EXEC in the next cycle restores useful endpoints.
        native.scene.source.exec(7, 200, "/bin/other");
        let events = native.witness(vec![native.row(41, 2, 7, 1_600, 1)]);
        let [CallerEvent::ExecRetired { old, new }] = events.as_slice() else {
            panic!("EXEC after link loss must recover: {events:?}");
        };
        assert_eq!(*old, leader);
        let successor = *new;
        assert_eq!(native.scene.coordinator.adapter.live_id(7), Some(successor));
        native.scene.project(7, 1_700);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.answer(7, 500, 41);
        native.witness(vec![native.row(41, 2, 7, 1_800, 0)]);
        // The recovery row binds the successor (useful endpoints). Its pair
        // stays count-dropped by the proving row's unbound decision — the
        // pre-existing C7 dropped-pair rule, unchanged by this slice — so
        // the edge reads witnessed, not counted.
        assert_eq!(
            native.scene.coverage(successor),
            UseCoverage::Witnessed { first_ns: 1_800 },
            "the successor serves useful endpoints"
        );
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!(census.bound, 3, "leader, sibling, and successor rows bind");
        assert_eq!(
            census.unbound.get(&UnboundReason::ExecTransition),
            Some(&1),
            "only the proving row stays unbound"
        );
        assert_eq!(
            native.scene.coverage(leader),
            UseCoverage::Counted {
                since_ns: 100,
                lossy: false
            },
            "the old image keeps its count"
        );

        // Later EXEC in a later batch (after unrelated work) recovers too.
        let (mut later, leader) = NativeScene::new();
        later.scene.source.spawn(8, 600);
        later
            .scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 150)
            .unwrap();
        later.answer(7, 500, 41);
        later.answer(8, 600, 42);
        later.witness(vec![later.row(41, 1, 7, 100, 0)]);
        let mut exit_record: p11scope_ebpf_common::DiscoveryRecord = unsafe { std::mem::zeroed() };
        exit_record.pid_tgid = (u64::from(7u32) << 32) | u64::from(7u32);
        exit_record.kind = p11scope_ebpf_common::DISCOVERY_KIND_LEADER_EXIT;
        later.stage(NativeBatch::Lifecycle(DiscoveryBatch::scripted(
            later.domain,
            vec![exit_record],
            later.stamps.tick(),
        )));
        later.scene.coordinator.commit_batch(false).unwrap();
        later.witness(vec![later.row(42, 1, 8, 1_550, 0)]);
        later.scene.source.exec(7, 200, "/bin/other");
        let events = later.witness(vec![later.row(41, 2, 7, 1_600, 1)]);
        assert!(
            matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == leader),
            "EXEC in a later batch must recover: {events:?}"
        );

        // Whole-group death twin: both incarnations exit, the pid is reused
        // by a fresh generation, and a delayed pre-admission EXEC for the
        // old incarnation cannot attach to anything.
        let (mut dead, leader) = NativeScene::new();
        dead.scene.source.spawn(8, 600);
        dead.scene
            .coordinator
            .adapter
            .admit(8, ImageAuthority::ScanPinned, 150)
            .unwrap();
        dead.answer(7, 500, 41);
        dead.witness(vec![dead.row(41, 1, 7, 100, 0)]);
        let proving = dead.row(41, 2, 7, 1_600, 1);
        let delayed = dead.binder_only(vec![proving]);
        assert_eq!(delayed.len(), 1, "one transition captured pre-death");
        dead.scene.source.kill(7);
        dead.scene.source.kill(8);
        let events = dead.scene.coordinator.adapter.reconcile(
            &BTreeSet::new(),
            &mut |_| ImageAuthority::ScanPinned,
            2_000,
        );
        assert_eq!(events.len(), 2, "{events:?}");
        assert!(
            events
                .iter()
                .all(|event| matches!(event, CallerEvent::Exited { .. })),
            "whole-group death exits every incarnation: {events:?}"
        );
        dead.scene
            .coordinator
            .apply_reconcile_events(&events, 2_000);
        dead.scene.coordinator.commit_batch(false).unwrap();
        dead.scene.source.spawn(7, 900);
        let observed: BTreeSet<u32> = [7].into_iter().collect();
        let events = dead.scene.coordinator.adapter.reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            2_100,
        );
        let [CallerEvent::Admitted { id }] = events.as_slice() else {
            panic!("the reused pid admits fresh: {events:?}");
        };
        let fresh = *id;
        assert_ne!(fresh, leader);
        let adapter = &dead.scene.coordinator.adapter;
        let record = adapter.record(fresh).unwrap();
        assert_eq!(record.start_time, Some(900));
        assert_eq!(record.incarnation, 1);
        dead.scene
            .coordinator
            .apply_reconcile_events(&events, 2_100);
        dead.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            dead.scene
                .coordinator
                .registry
                .edges()
                .all(|edge| edge.caller != fresh),
            "the fresh incarnation inherits no history"
        );
        let stale =
            dead.scene
                .coordinator
                .apply_exec_transition(delayed[0], &mut dead.cookies, 2_200);
        assert!(
            stale.is_empty(),
            "a delayed transition for a dead caller attaches nothing: {stale:?}"
        );
        assert_eq!(dead.scene.coordinator.adapter.live_id(7), Some(fresh));
        assert_eq!(dead.scene.coordinator.adapter.len(), 3);

        // Owned-initial-exec acknowledgement happens exactly once: the
        // initial image binds without emitting, the real exec emits one
        // transition, and a replay emits nothing further.
        let (mut once, leader) = NativeScene::new();
        once.answer(7, 500, 41);
        assert!(
            once.binder_only(vec![once.row(41, 1, 7, 100, 0)])
                .is_empty(),
            "the initial image binds; it never transitions"
        );
        let emitted = once.binder_only(vec![once.row(41, 2, 7, 1_100, 1)]);
        assert_eq!(emitted.len(), 1, "the real exec emits one transition");
        assert_eq!(emitted[0].caller(), leader);
        assert!(
            once.binder_only(vec![once.row(41, 2, 7, 1_100, 1)])
                .is_empty(),
            "a replayed proof emits no second transition"
        );
        let events =
            once.scene
                .coordinator
                .apply_exec_transition(emitted[0], &mut once.cookies, 1_200);
        assert!(
            matches!(events.as_slice(), [CallerEvent::ExecRetired { old, .. }] if *old == leader),
            "{events:?}"
        );
        let again =
            once.scene
                .coordinator
                .apply_exec_transition(emitted[0], &mut once.cookies, 1_300);
        assert!(
            again.is_empty(),
            "one successor per ended caller: {again:?}"
        );
        assert_eq!(once.scene.coordinator.adapter.len(), 2);
    }

    #[test]
    fn a_row_naming_another_object_for_its_endpoint_never_stages() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let endpoint = native.scene.delta.endpoints[0];
        let row = WitnessRow::scripted(
            native.domain,
            41,
            1,
            crate::discovery::inventory_attach_set::AttachObjectId::scripted(
                endpoint.object.index() + 1,
            ),
            endpoint.id,
            7,
            100,
        );
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        assert_eq!(native.module_unbound(), None);
        assert!(
            native
                .gap_subjects()
                .contains(&"native witness without a module".to_string())
        );
    }

    #[test]
    fn a_transition_for_a_caller_the_scan_lane_already_retired_changes_nothing() {
        let (mut native, caller) = NativeScene::new();
        native.answer(7, 500, 41);
        let first = native.row(41, 1, 7, 100, 0);
        native.witness(vec![first]);
        // The later image's row is read while the caller is still live ...
        let later = native.row(41, 2, 7, 1_100, 1);
        native.read(vec![later]);
        // ... then the scan lane sees the exe change and splits first.
        native.scene.source.exec(7, 200, "/bin/other");
        let observed: BTreeSet<u32> = [7].into_iter().collect();
        let events = native.scene.coordinator.adapter.reconcile(
            &observed,
            &mut |_| ImageAuthority::ScanPinned,
            1_200,
        );
        let [CallerEvent::ExecRetired { new: successor, .. }] = events.as_slice() else {
            panic!("{events:?}");
        };
        let successor = *successor;
        let mut native_events = native.drain().events;
        native_events.extend(native.read(Vec::new()).events);
        assert!(native_events.is_empty(), "{native_events:?}");
        let adapter = &native.scene.coordinator.adapter;
        assert!(adapter.record(caller).unwrap().retired);
        assert_eq!(adapter.live_id(7), Some(successor));
        assert_eq!(adapter.len(), 2, "no extra incarnation was minted");
    }

    #[test]
    fn an_owner_whose_caller_already_retired_gets_no_exec_proof() {
        let mut coordinator = coordinator();
        let pid = std::process::id();
        let now = crate::discovery::caller_registry::now_ns();
        let caller = coordinator
            .test_open_native_owner(pid, fixture_image(pid).unwrap(), &mut FixtureImages, now)
            .unwrap();
        let domain = NativeDomainId::mint();
        let mut identity = OneTicket { domain, ticket: 41 };
        let object = crate::discovery::inventory_attach_set::AttachObjectId::scripted(0);
        let stamps = Stamps::from(now);
        coordinator
            .binder
            .note_exec_coverage(ExecCoverage::scripted(domain, 0));
        let read = |rows: Vec<WitnessRow>| stamps.read(domain, rows);
        let drain = || stamps.drain(domain);
        let bound = WitnessRow::scripted(domain, 41, 1, object, EndpointId(0), pid, now + 1);
        for batch in [read(vec![bound]), drain(), read(Vec::new())] {
            coordinator.stage_native(batch, &mut identity, now + 10);
        }
        // The later image's row is read while the caller is live; then the
        // caller retires before the row's horizon arrives.
        let later = WitnessRow::scripted(domain, 41, 2, object, EndpointId(1), pid, now + 2);
        coordinator.stage_native(read(vec![later]), &mut identity, now + 10);
        coordinator.adapter_mut().exec_transition(
            caller,
            &mut |_| ImageAuthority::ScanPinned,
            now + 11,
        );
        let mut events = Vec::new();
        for batch in [drain(), read(Vec::new())] {
            events.extend(
                coordinator
                    .stage_native(batch, &mut identity, now + 12)
                    .events,
            );
        }
        assert!(events.is_empty(), "{events:?}");
        coordinator.commit_batch(false).unwrap();
        assert!(
            !coordinator
                .registry()
                .gaps()
                .iter()
                .any(|gap| gap.subject == "native exec proof not applied"),
            "a retired incarnation's owner is never sent a proof"
        );
    }

    /// A scene whose pid 7 (start 500) was admitted and mapped at 100,
    /// before the native lane's exec coverage began at 200.
    fn pre_activation_scene() -> (NativeScene, CallerId) {
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 100)
            .unwrap();
        scene.project(7, 110);
        scene.coordinator.commit_batch(false).unwrap();
        (NativeScene::over(scene, 200), caller)
    }

    fn empty_pass(native: &mut NativeScene, start_ns: u64) -> PassReport {
        let report = native.scene.coordinator.observe_empty_pass(
            &mut UnavailableImageGuard,
            &mut native.cookies,
            "scripted pass",
            start_ns,
        );
        native.scene.coordinator.commit_batch(false).unwrap();
        report
    }

    /// C1 (C4 review), end to end: X admitted at 100 (foo maps M); T execs
    /// bar at 150, unrecorded; coverage begins at 200; bar's row at 210
    /// answers X's ticket. It waits for the revalidation pass, which sees
    /// bar's exe: the row is a coverage gap and nothing joins X.
    #[test]
    fn a_caller_that_exec_d_before_coverage_never_joins_through_the_coordinator() {
        let (mut native, caller) = pre_activation_scene();
        native.scene.source.exec(7, 200, "/bin/bar");
        native.answer(7, 500, 41);
        let row = native.row(41, 2, 7, 210, 0);
        native.witness(vec![row]);
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (1, 0), "waits for the pass");

        // A pass that started before the coverage start does not qualify,
        // even though its reconcile already retired X as exec'd.
        let report = empty_pass(&mut native, 150);
        assert!(
            report.events.iter().any(
                |event| matches!(event, CallerEvent::ExecRetired { old, .. } if *old == caller)
            ),
            "{:?}",
            report.events
        );
        assert_eq!(native.scene.coordinator.binder.census().pending, 1);

        empty_pass(&mut native, 250);
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (0, 0));
        assert_eq!(
            census.unbound.get(&UnboundReason::ExecCoverageGap),
            Some(&1)
        );
        assert!(!native.scene.coverage(caller).is_witnessed());
        let unbound = native.module_unbound().expect("module-level positive use");
        assert_eq!(unbound.reasons.get("exec_coverage_gap"), Some(&1));
    }

    /// C1 named boundary, end to end: without an exe change the pass
    /// revalidates X, and the row binds to it.
    #[test]
    fn a_caller_unchanged_since_before_coverage_binds_after_the_pass() {
        let (mut native, caller) = pre_activation_scene();
        native.answer(7, 500, 41);
        let row = native.row(41, 2, 7, 210, 0);
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        let report = empty_pass(&mut native, 250);
        assert!(report.events.is_empty(), "{:?}", report.events);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 210,
                lossy: false
            }
        );
    }

    /// The revalidation also runs on a full scan pass (`apply_catalog`),
    /// not only on an observation-less one.
    #[test]
    fn a_full_scan_pass_revalidates_a_caller_from_before_coverage() {
        let (mut native, caller) = pre_activation_scene();
        native.answer(7, 500, 41);
        let row = native.row(41, 2, 7, 210, 0);
        native.witness(vec![row]);
        assert!(!native.scene.coverage(caller).is_witnessed());
        let generation = native
            .scene
            .coordinator
            .adapter
            .record(caller)
            .map(|record| crate::inspect_system::MemberGeneration {
                start_time: record.start_time,
                exe: record.exe.clone(),
            });
        let catalog = capture_catalog(&native.scene.pins, &[&native.scene.path], 7, generation);
        let report = native.scene.coordinator.apply_catalog(
            catalog,
            &mut UnavailableImageGuard,
            &mut native.cookies,
            u64::MAX,
            250,
        );
        assert!(report.events.is_empty(), "{:?}", report.events);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 210,
                lossy: false
            }
        );
    }

    /// C5.1 carry (C5.2 review): a read proves a clean instant only when it
    /// completes a gap-free CALLER_USE sweep, and that instant is the health
    /// read of the batch the sweep began in — a bounded read that stopped
    /// mid-sweep may have left a use dated before its stamp unvisited.
    #[test]
    fn only_a_completed_gap_free_sweep_proves_a_clean_read() {
        let (mut scene, caller) = watched_scene(7, 500);
        assert_eq!(last_clean(&scene), Some(200));
        // A sweep begins at 250 and stops at its row bound.
        let mut partial = witness_batch();
        partial.health_read_ns = 250;
        partial.sweep_completed = false;
        partial.row_bound_reached = true;
        scene.coordinator.note_witness_batch(&partial);
        assert_eq!(last_clean(&scene), Some(200));
        // It completes at 280: every row present at 250 was visited.
        let mut rest = witness_batch();
        rest.health_read_ns = 280;
        scene.coordinator.note_witness_batch(&rest);
        assert_eq!(last_clean(&scene), Some(250));
        // A sweep that completes with skipped rows proves nothing.
        let mut gaps = witness_batch();
        gaps.health_read_ns = 290;
        gaps.sweep_gaps = true;
        scene.coordinator.note_witness_batch(&gaps);
        assert_eq!(last_clean(&scene), Some(250));
        // A terminal read that stopped mid-sweep never extends the interval.
        let mut terminal = witness_batch();
        terminal.health_read_ns = 295;
        terminal.sweep_completed = false;
        terminal.deadline_reached = true;
        scene.coordinator.note_witness_batch(&terminal);
        scene.coordinator.end_capture_coverage(300);
        scene.coordinator.registry.publish();
        assert_eq!(
            scene.coverage(caller),
            crate::discovery::caller_registry::UseCoverage::WatchedNoUse {
                since_ns: 100,
                until_ns: Some(250),
            }
        );
    }

    // ---- DR-LIVE-LABEL-LAG: a pending first-use row reads unknown ----

    /// The shared presentation over a native scene's coordinator: the one
    /// view JSON and the event stream read (per-pass activity signal).
    fn presented(native: &NativeScene) -> crate::inventory_present::Presentation {
        crate::inventory_present::Presentation::capture(
            &native.scene.coordinator,
            "system",
            0,
            3_000,
            3,
        )
    }

    /// While the binder holds a pending row of the watched caller's pid
    /// on the edge's module, the edge presents unknown (`activity
    /// unknown`, `entries ?`); the staged watch is untouched, so the row
    /// still binds and counts the same edge once decided.
    #[test]
    fn a_pending_first_use_row_presents_the_edge_as_unknown_until_it_binds() {
        use crate::discovery::caller_registry::EntryObservation;
        use crate::inventory_present::{Activity, entries_display};
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (1, 0));
        // The staged watch stands: the overlay is presentation only.
        assert!(watched(&native.scene.coverage(caller)));
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        );
        assert_eq!(edge.activity, Activity::Unknown);
        assert_eq!(entries_display(edge), "?");
        assert_eq!(
            edge.entry_observation,
            EntryObservation::UnknownUnavailable.label()
        );
        let payload = crate::inventory::edge_json(edge);
        assert_eq!(payload["entries"]["coverage"]["state"], "unknown");
        assert_eq!(
            payload["entries"]["coverage"]["reason"],
            "pending_first_use"
        );
        // The horizons arrive: the row binds and the edge is counted.
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!((census.pending, census.bound), (0, 1));
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 200,
                lossy: false
            }
        );
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Counted {
                since_ns: 200,
                lossy: false
            }
        );
        assert_eq!(edge.activity, Activity::RecentlyObserved);
    }

    /// A row still pending at finish unbinds and downgrades the watch, as
    /// today: the edge presents the staged unknown, never the transient one.
    #[test]
    fn a_row_unbound_at_finish_presents_the_staged_unknown() {
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        native.read(vec![row]);
        let receipt = native.stage(NativeBatch::Finish {
            domain: native.domain,
        });
        assert_eq!(receipt.decided, 1);
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census().clone();
        assert_eq!(census.pending, 0);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        );
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        );
    }

    /// A batch that leaves a stamped row pending never extends the
    /// proven-clean instant; once the row decides, clean batches extend
    /// it again.
    #[test]
    fn a_pending_row_withholds_the_proven_clean_instant_until_it_decides() {
        let (mut native, _) = watched_native();
        native.answer(7, 500, 41);
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(last_clean(&native.scene), Some(1_010));
        let row = native.row(41, 1, 7, 200, 0);
        native.read(vec![row]);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coordinator.registry.witness_census().pending,
            1
        );
        assert_eq!(
            last_clean(&native.scene),
            Some(1_010),
            "a stamped pending row withholds the clean instant"
        );
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coordinator.registry.witness_census().pending,
            0
        );
        assert!(
            last_clean(&native.scene).is_some_and(|clean| clean > 1_010),
            "a decided row releases the clean instant: {:?}",
            last_clean(&native.scene)
        );
    }

    /// An unstamped pending row never decides before the finish flush, so
    /// it never stalls the proven-clean instant — but the edge still
    /// presents unknown while the row waits.
    #[test]
    fn an_unstamped_pending_row_does_not_stall_the_proven_clean_instant() {
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        let mut batch = native.stamps.read(native.domain, vec![row]);
        let NativeBatch::Witness(read) = &mut batch else {
            panic!("a witness read stages a witness batch");
        };
        read.rows_read_ns = u64::MAX;
        read.counts_read_ns = u64::MAX;
        native.stage(batch);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert_eq!(
            native.scene.coordinator.registry.witness_census().pending,
            1
        );
        assert_eq!(
            last_clean(&native.scene),
            Some(1_010),
            "the clean instant extends through an undecidable row"
        );
        let presentation = presented(&native);
        let edge = presentation
            .edges
            .iter()
            .find(|edge| edge.caller == caller)
            .expect("the caller has a presented edge");
        assert_eq!(
            edge.coverage,
            UseCoverage::Unknown(UnknownReason::PendingFirstUse)
        );
    }

    // ---- R-C51-1: an unbound row of a watched caller's pid ----

    /// A system-scope native lane with pid 7 (start 500) admitted at 50,
    /// every endpoint attached at 100, and its edge watched since 120.
    fn watched_native() -> (NativeScene, CallerId) {
        let mut scene = CaptureScene::new(2);
        scene.source.spawn(7, 500);
        let caller = scene
            .coordinator
            .adapter
            .admit(7, ImageAuthority::ScanPinned, 50)
            .unwrap();
        scene
            .coordinator
            .begin_capture_coverage(CaptureScopeCoverage::System);
        let mut native = NativeScene::over(scene, 0);
        native.scene.attach_all(100, ScopeCustody::System);
        native.scene.project(7, 120);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(watched(&native.scene.coverage(caller)));
        (native, caller)
    }

    fn use_before_admission(coverage: &UseCoverage) -> bool {
        matches!(
            coverage,
            UseCoverage::Unknown(UnknownReason::UseBeforeAdmission)
        )
    }

    #[test]
    fn a_row_from_before_admission_downgrades_the_watch_for_good() {
        // Read after the admission: the row predates it (t0 40 < 50).
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 40, 0);
        native.witness(vec![row]);
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!(
            census.unbound.get(&UnboundReason::BeforeAdmission),
            Some(&1)
        );
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
        // Sticky: later passes and the stop never restore a watch.
        native.scene.project(7, 2_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        native.scene.coordinator.end_capture_coverage(3_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(use_before_admission(&native.scene.coverage(caller)));
    }

    #[test]
    fn a_row_read_before_its_callers_admission_downgrades_the_later_watch() {
        // Read before the admission: pid 9 holds no caller yet.
        let (mut native, _) = watched_native();
        let row = native.row(77, 1, 9, 1_000, 1);
        native.witness(vec![row]);
        native.scene.source.spawn(9, 900);
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(9, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            use_before_admission(&native.scene.coverage(later)),
            "{:?}",
            native.scene.coverage(later)
        );
    }

    #[test]
    fn a_full_preadmission_stash_degrades_the_scope_with_a_gap() {
        let (mut native, caller) = watched_native();
        native
            .scene
            .coordinator
            .capture
            .as_mut()
            .unwrap()
            .preadmission
            .limit = 1;
        // Live writers: pruning cannot make room (R-C51-5).
        native.scene.source.spawn(9, 90);
        native.scene.source.spawn(11, 110);
        let rows = vec![
            native.row(77, 1, 9, 1_000, 0),
            native.row(78, 1, 11, 1_000, 0),
        ];
        native.witness(rows);
        assert_eq!(
            native.preadmission(),
            PreadmissionCounters {
                held: 1,
                limit: 1,
                pruned: 0,
                refused: 1,
            }
        );
        assert!(
            native
                .gap_subjects()
                .contains(&"native pre-admission rows past their bound".to_string()),
            "{:?}",
            native.gap_subjects()
        );
        // pid 7 had no unbound row, yet its watch degrades with the scope.
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
        native.scene.project(7, 2_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(use_before_admission(&native.scene.coverage(caller)));
        // A caller admitted after the overflow, with no row of its own.
        native.scene.source.spawn(13, 1_300);
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(13, ImageAuthority::ScanPinned, 2_100)
            .unwrap();
        native.scene.project(13, 2_200);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            use_before_admission(&native.scene.coverage(later)),
            "{:?}",
            native.scene.coverage(later)
        );
    }

    fn stash_limit(native: &mut NativeScene, limit: usize) {
        native
            .scene
            .coordinator
            .capture
            .as_mut()
            .unwrap()
            .preadmission
            .limit = limit;
    }

    #[test]
    fn an_exited_writer_is_pruned_before_the_stash_overflows() {
        let (mut native, caller) = watched_native();
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        native.scene.source.spawn(11, 110);
        let row = native.row(77, 1, 9, 1_000, 0);
        native.witness(vec![row]);
        // pid 9 exits unadmitted: its entry can never apply again.
        native.scene.source.kill(9);
        let row = native.row(78, 1, 11, 1_010, 0);
        native.witness(vec![row]);
        assert!(
            !native
                .gap_subjects()
                .contains(&"native pre-admission rows past their bound".to_string()),
            "{:?}",
            native.gap_subjects()
        );
        assert_eq!(
            native.preadmission(),
            PreadmissionCounters {
                held: 1,
                limit: 1,
                pruned: 1,
                refused: 0,
            }
        );
        let document =
            crate::inventory::render_json(&native.scene.coordinator, "system", 0, 1_020, 1);
        assert_eq!(
            document["budgets"]["native_preadmission"],
            serde_json::json!({"limit": 1, "occupied": 1, "refused": 0, "pruned": 1})
        );
        assert!(!use_before_admission(&native.scene.coverage(caller)));
        // pid 11's entry stays and still downgrades its later admission.
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(11, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(11, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(use_before_admission(&native.scene.coverage(later)));
    }

    #[test]
    fn a_reused_pid_drops_the_earlier_holders_entry() {
        let (mut native, _) = watched_native();
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        let row = native.row(77, 1, 9, 1_000, 0);
        native.witness(vec![row]);
        // pid 9 now names another process, admitted with no row of its own.
        native.scene.source.kill(9);
        native.scene.source.spawn(9, 950);
        let reused = native
            .scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(9, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            !use_before_admission(&native.scene.coverage(reused)),
            "{:?}",
            native.scene.coverage(reused)
        );
        // A full stash prunes the stale entry instead of overflowing.
        native.scene.source.spawn(11, 110);
        let row = native.row(78, 1, 11, 1_700, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.preadmission(),
            PreadmissionCounters {
                held: 1,
                limit: 1,
                pruned: 1,
                refused: 0,
            }
        );
        assert!(!use_before_admission(&native.scene.coverage(reused)));
    }

    #[test]
    fn an_entry_with_an_unreadable_start_is_held_while_its_pid_lives() {
        // Fail safe: with no start time to compare, only exit releases it.
        let (mut native, _) = watched_native();
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        native.scene.source.blind(9);
        native.scene.source.spawn(11, 110);
        let row = native.row(77, 1, 9, 1_000, 0);
        native.witness(vec![row]);
        let row = native.row(78, 1, 11, 1_010, 0);
        native.witness(vec![row]);
        assert!(
            native
                .gap_subjects()
                .contains(&"native pre-admission rows past their bound".to_string())
        );
        assert_eq!(native.preadmission().pruned, 0);
    }

    /// A row whose endpoint resolves to no module still names its pid:
    /// every module of that pid's callers downgrades (the `None` entry).
    #[test]
    fn an_unresolved_row_downgrades_every_module_of_its_pid() {
        let (mut native, caller) = watched_native();
        let mut row = native.row(77, 1, 7, 1_000, 0);
        row.endpoint = EndpointId(9_999);
        native.witness(vec![row]);
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
    }

    #[test]
    fn an_unresolved_row_downgrades_a_later_admission_of_its_pid() {
        let (mut native, _) = watched_native();
        native.scene.source.spawn(9, 900);
        let mut row = native.row(77, 1, 9, 1_000, 0);
        row.endpoint = EndpointId(9_999);
        native.witness(vec![row]);
        let later = native
            .scene
            .coordinator
            .adapter
            .admit(9, ImageAuthority::ScanPinned, 1_500)
            .unwrap();
        native.scene.project(9, 1_600);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            use_before_admission(&native.scene.coverage(later)),
            "{:?}",
            native.scene.coverage(later)
        );
    }

    /// The overflow reaches retained retired callers too: a frozen
    /// `watched_no_use` is no more a fact than a live one.
    #[test]
    fn an_overflow_downgrades_a_retired_callers_frozen_watch() {
        let (mut native, caller) = watched_native();
        native.read(Vec::new());
        native.scene.source.kill(7);
        let events = native.scene.coordinator.adapter.reconcile(
            &BTreeSet::new(),
            &mut |_| ImageAuthority::ScanPinned,
            1_050,
        );
        assert_eq!(events.len(), 1, "{events:?}");
        native
            .scene
            .coordinator
            .registry
            .retire_caller(caller, "exited".into(), 1_050);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(
            native
                .scene
                .coordinator
                .adapter
                .record(caller)
                .unwrap()
                .retired,
            "the record is retained, retired"
        );
        assert!(
            watched(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
        stash_limit(&mut native, 1);
        native.scene.source.spawn(9, 90);
        native.scene.source.spawn(11, 110);
        let rows = vec![
            native.row(77, 1, 9, 1_100, 0),
            native.row(78, 1, 11, 1_100, 0),
        ];
        native.witness(rows);
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
    }

    #[test]
    fn a_bound_row_of_the_same_pid_keeps_the_caller_counted() {
        // Positives stay positives: the rule only replaces a watch.
        // C7 C4: the scripted row carries a count, so the positive is
        // `counted`.
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        native.witness(vec![row]);
        assert_eq!(
            native.scene.coverage(caller),
            UseCoverage::Counted {
                since_ns: 200,
                lossy: false
            }
        );
        assert!(
            native
                .scene
                .coordinator
                .capture
                .as_ref()
                .unwrap()
                .preadmission
                .entries
                .is_empty()
        );
    }

    #[test]
    fn a_row_decided_after_stop_still_downgrades_a_frozen_watch() {
        let (mut native, caller) = watched_native();
        // A clean read at 1_010, then the stop freezes the watch there.
        native.read(Vec::new());
        native.scene.coordinator.end_capture_coverage(1_100);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(watched(&native.scene.coverage(caller)));
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 40, 0);
        native.witness(vec![row]);
        assert!(
            use_before_admission(&native.scene.coverage(caller)),
            "{:?}",
            native.scene.coverage(caller)
        );
    }

    /// R-C51-3: a row lifecycle loss left unbound downgrades the same way,
    /// sticky, but the edge reads unknown `loss` — never watched, and not
    /// `use_before_admission`.
    #[test]
    fn a_row_lifecycle_loss_left_unbound_reads_loss() {
        let (mut native, caller) = watched_native();
        native.answer(7, 500, 41);
        let row = native.row(41, 1, 7, 200, 0);
        let mut batch = native.stamps.read(native.domain, vec![row]);
        let NativeBatch::Witness(read) = &mut batch else {
            unreachable!()
        };
        // The ring lost a record before this read: the binder dates a loss.
        read.health.discovery_counters = Some([1, 0, 0, 0, 0]);
        native.stage(batch);
        native.drain();
        native.read(Vec::new());
        native.scene.coordinator.commit_batch(false).unwrap();
        let census = native.scene.coordinator.registry.witness_census();
        assert_eq!(census.unbound.get(&UnboundReason::LifecycleLoss), Some(&1));
        assert!(
            lost_with(&native.scene.coverage(caller), "use row could bind"),
            "{:?}",
            native.scene.coverage(caller)
        );
        native.scene.project(7, 2_000);
        native.scene.coordinator.commit_batch(false).unwrap();
        assert!(lost_with(
            &native.scene.coverage(caller),
            "use row could bind"
        ));
    }
}

#[cfg(test)]
#[path = "demotion_retirement_tests.rs"]
mod demotion_retirement_tests;

#[cfg(test)]
#[path = "inventory_diagnostics_tests.rs"]
mod inventory_diagnostics_tests;
