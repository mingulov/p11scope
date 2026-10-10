//! SPDX-License-Identifier: GPL-3.0-or-later
//! Initial and incremental provider discovery ownership.

use crate::attach::{
    BackendSelection, CapturePolicy, CounterSnapshot, DetachOutcome, DynamicExportIdentity,
    DynamicLoaderAttachFailure, OwnedPauseGeneration, ReplacementOutcome, Scope, Session,
};
use crate::cli::CaptureArgs;
use crate::discovery::attribution;
use crate::discovery::hooks::{HookAbi, HookRegistry};
use crate::discovery::identity::{
    KernelSelfMappingProbe, ManifestStaleReason, PinnedObjectId, PinnedObjects, PinnedTimingKey,
    ReconciledModule, SelfMappingProbe, StaleManifestObject, bind_scanned_modules,
    canonicalize_scanned_overlays, open_view_object, open_view_object_cached,
    pin_manifest_objects_deferred_in_views_with_budget, pin_scanned_view_objects,
    preexec_object_key, retained_object_key_cached, self_mapped_fallback_key, target_paths_equal,
    view_object_key_cached,
};
use crate::discovery::loader::{LoaderContextId, LoaderContextSpec, LoaderRegistry};
use crate::discovery::noise::DiscoveryNoiseAggregator;
use crate::discovery::scan::{
    CaptureWorkBudget, MapsReadBuffers, MapsReadLimits, ObjectExports, ScanOutcome, ScanRequest,
    ScannedEntry, ScannedInterface, ScannedModule, ScannedTable, Skipped, TableIdentity,
    decode_exact_table, exact_table_addresses, exact_table_bytes, export_agreement,
    index_maps_or_refuse, read_elf_snapshot, read_maps_or_refuse, read_maps_or_refuse_with_buffers,
    scan_process_view, scan_process_view_without_memory, scan_skip_truncates, spans_for,
    table_evidence_score, table_linkage, target_layout,
};
use crate::discovery::scheduler::{
    DiscoveryScheduler, InventoryCadence, MAX_PENDING_REFRESH, MAX_POLLING_RESCANS,
};
use crate::discovery::sweep_shards;
use crate::manifest_input::{read_manifest, selection_surface_usable, validate_structure};
use crate::process::{self, OriginalGenerationState, ProcessView, ProcessViewId};
use crate::run::OwnedChild;
use crate::{plan, render};
use anyhow::{Context as _, Result, anyhow, bail};
use p11scope_ebpf_common::{
    DISCOVERY_INTERFACES, DISCOVERY_KIND_EXEC, DISCOVERY_KIND_FUNCTION_LIST_RETURN,
    DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN, DISCOVERY_KIND_INTERFACE_RETURN,
    DISCOVERY_KIND_LEADER_EXIT, DISCOVERY_KIND_LOADER, DISCOVERY_NAME_EXACT_STANDARD,
    DISCOVERY_NAME_NULL, DISCOVERY_NAME_OTHER, DISCOVERY_NAME_UNREADABLE,
    DISCOVERY_STATUS_LOADER_CONTEXT_INVALID, DISCOVERY_VERSION_NULL, DISCOVERY_VERSION_OTHER,
    DISCOVERY_VERSION_UNREADABLE, DISCOVERY_VERSION_V2_40, DISCOVERY_VERSION_V3_0,
    DISCOVERY_VERSION_V3_1, DISCOVERY_VERSION_V3_2, DiscoveryRecord, export_attach_cookie,
    valid_discovery_record,
};
use p11scope_manifest::elf::{ElfAbi, ElfSnapshot};
use p11scope_manifest::manifest::{
    Acquisition, Manifest, Resolution, SCHEMA, SelectionAcquisition, SelectionAuthority,
    SelectionNameClass, SelectionRequest, SelectionVersionClass, SurfaceSource, WalkOutcome,
};
use p11scope_manifest::maps::{Device, MapEntry, MapIndex, MappedPath, ObjectKey, Resolved};
use pkcs11_module::{LinuxLayout, read_function_pointer};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::num::NonZeroU64;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Arc;

#[path = "inventory.rs"]
pub(crate) mod inventory;
#[path = "inventory_coordinator.rs"]
pub(crate) mod inventory_coordinator;

use crate::attach::detailed_identity::{
    CgroupAction, ProofSession, SeedId, TraceCandidateBody, TraceIo, TraceProofUnknown,
    TraceServiceProgress, TraceWorkError, VerifiedTraceSeed,
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupWorkRefusal {
    BudgetDeferred,
    Refused(TraceProofUnknown),
}
impl From<CgroupWorkRefusal> for TraceWorkError {
    fn from(reason: CgroupWorkRefusal) -> Self {
        match reason {
            CgroupWorkRefusal::BudgetDeferred => Self::Deferred,
            CgroupWorkRefusal::Refused(reason) => Self::Unknown(reason),
        }
    }
}
/// Constructors remain inside this scheduling owner; copies share allowance.
#[derive(Clone, Default)]
pub(crate) struct TraceWorkTicket {
    state: Option<std::sync::Arc<std::sync::Mutex<TraceWorkState>>>,
    cgroup_deadline: Option<u64>,
    cgroup_pending: Option<SeedId>,
}
struct TraceWorkState {
    proof: ProofSession,
    deadline: u64,
    last_clock: u64,
    visits: u32,
    reads: u32,
    health_attempted: bool,
    closed: Option<CgroupWorkRefusal>,
    terminal: bool,
    cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}
impl TraceWorkTicket {
    fn new(
        proof: ProofSession,
        start: u64,
        deadline: u64,
        terminal: bool,
        cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        Self {
            cgroup_deadline: None,
            cgroup_pending: None,
            state: Some(std::sync::Arc::new(std::sync::Mutex::new(TraceWorkState {
                proof,
                deadline,
                last_clock: start,
                visits: 32,
                reads: 32,
                health_attempted: false,
                closed: None,
                terminal,
                cancel,
            }))),
        }
    }
    fn same_allocation(&self, other: &Self) -> bool {
        match (&self.state, &other.state) {
            (Some(a), Some(b)) => std::sync::Arc::ptr_eq(a, b),
            _ => false,
        }
    }
    pub(crate) fn check(&self, proof: &ProofSession) -> Result<(), TraceWorkError> {
        if let Some(deadline) = self.cgroup_deadline {
            self.cgroup_check(proof, deadline)?;
            if let Some(id) = self.cgroup_pending {
                proof.cgroup_read_status(id)?;
            }
            return Ok(());
        }
        self.checked(proof, None)
            .map(|_| ())
            .map_err(|_| TraceWorkError::Deferred)
    }
    fn checked(
        &self,
        proof: &ProofSession,
        candidate_deadline: Option<u64>,
    ) -> Result<u64, CgroupWorkRefusal> {
        use CgroupWorkRefusal::{BudgetDeferred, Refused};
        let mut state = self
            .state
            .as_ref()
            .ok_or(Refused(TraceProofUnknown::Unreadable))?
            .lock()
            .map_err(|_| Refused(TraceProofUnknown::Unreadable))?;
        if !state.proof.same_allocation(proof) {
            return Err(Refused(TraceProofUnknown::DomainMismatch));
        }
        if state
            .cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        {
            state.closed = Some(Refused(TraceProofUnknown::TargetGone));
        }
        if let Some(reason @ Refused(_)) = state.closed {
            return Err(reason);
        }
        let Some(now) = (if candidate_deadline.is_some() && proof.is_cgroup() {
            proof.cgroup_now()
        } else {
            proof.now()
        }) else {
            state.closed = Some(Refused(TraceProofUnknown::Unreadable));
            return Err(Refused(TraceProofUnknown::Unreadable));
        };
        if now < state.last_clock {
            state.closed = Some(Refused(TraceProofUnknown::Unreadable));
            return Err(Refused(TraceProofUnknown::Unreadable));
        }
        // Even an expired observation constrains the next clock. Otherwise a
        // later regression could keep a budget-closed ticket retryable.
        state.last_clock = now;
        if candidate_deadline.is_some_and(|deadline| now >= deadline) {
            return Err(Refused(TraceProofUnknown::AfterEvent));
        }
        if state.closed.is_some() || now >= state.deadline {
            state.closed = Some(BudgetDeferred);
            return Err(BudgetDeferred);
        }
        Ok(now)
    }
    pub(crate) fn cgroup_check(
        &self,
        proof: &ProofSession,
        candidate_deadline: u64,
    ) -> Result<u64, CgroupWorkRefusal> {
        self.checked(proof, Some(candidate_deadline))
    }
    pub(crate) fn external_read(&mut self, proof: &ProofSession) -> Result<(), TraceWorkError> {
        if let Some(deadline) = self.cgroup_deadline {
            return self
                .cgroup_external_read(proof, deadline)
                .map(|_| ())
                .map_err(Into::into);
        }
        self.external_read_checked(proof)
            .map_err(|_| TraceWorkError::Deferred)
    }
    pub(crate) fn cgroup_reader(&self, deadline: u64, pending: Option<SeedId>) -> Self {
        Self {
            state: self.state.clone(),
            cgroup_deadline: Some(deadline),
            cgroup_pending: pending,
        }
    }
    pub(crate) fn cgroup_external_read(
        &mut self,
        proof: &ProofSession,
        deadline: u64,
    ) -> Result<u64, CgroupWorkRefusal> {
        let now = self.cgroup_check(proof, deadline)?;
        if let Some(id) = self.cgroup_pending {
            proof
                .cgroup_read_status(id)
                .map_err(CgroupWorkRefusal::Refused)?;
        }
        let mut state = self
            .state
            .as_ref()
            .ok_or(CgroupWorkRefusal::Refused(TraceProofUnknown::Unreadable))?
            .lock()
            .map_err(|_| CgroupWorkRefusal::Refused(TraceProofUnknown::Unreadable))?;
        if state.reads == 0 {
            return Err(CgroupWorkRefusal::BudgetDeferred);
        }
        state.reads -= 1;
        Ok(now)
    }
    fn external_read_checked(&mut self, proof: &ProofSession) -> Result<(), CgroupWorkRefusal> {
        self.checked(proof, None)?;
        let mut state = self
            .state
            .as_ref()
            .ok_or(CgroupWorkRefusal::Refused(TraceProofUnknown::Unreadable))?
            .lock()
            .map_err(|_| CgroupWorkRefusal::Refused(TraceProofUnknown::Unreadable))?;
        if state.reads == 0 {
            return Err(CgroupWorkRefusal::BudgetDeferred);
        }
        state.reads -= 1;
        Ok(())
    }
    pub(crate) fn claim_health(&mut self, proof: &ProofSession) -> Result<(), TraceWorkError> {
        self.check(proof)?;
        let mut state = self
            .state
            .as_ref()
            .ok_or(TraceWorkError::Deferred)?
            .lock()
            .map_err(|_| TraceWorkError::Deferred)?;
        if state.health_attempted {
            return Err(TraceWorkError::Deferred);
        }
        state.health_attempted = true;
        Ok(())
    }
    fn health_attempted(&self) -> bool {
        self.state
            .as_ref()
            .and_then(|s| s.lock().ok())
            .is_none_or(|s| s.health_attempted)
    }
    fn visit(&mut self, proof: &ProofSession) -> Result<(), TraceWorkError> {
        self.visit_checked(proof)
            .map_err(|_| TraceWorkError::Deferred)
    }
    fn visit_checked(&mut self, proof: &ProofSession) -> Result<(), CgroupWorkRefusal> {
        self.checked(proof, None)?;
        let mut state = self
            .state
            .as_ref()
            .ok_or(CgroupWorkRefusal::Refused(TraceProofUnknown::Unreadable))?
            .lock()
            .map_err(|_| CgroupWorkRefusal::Refused(TraceProofUnknown::Unreadable))?;
        if state.visits == 0 {
            return Err(CgroupWorkRefusal::BudgetDeferred);
        }
        state.visits -= 1;
        Ok(())
    }
    pub(crate) fn terminal(&self) -> bool {
        self.state
            .as_ref()
            .and_then(|s| s.lock().ok())
            .is_some_and(|s| s.terminal)
    }
    fn close(&self) {
        if let Some(state) = &self.state
            && let Ok(mut state) = state.lock()
        {
            state.closed = Some(CgroupWorkRefusal::Refused(TraceProofUnknown::Unreadable));
        }
    }
    #[cfg(test)]
    pub(crate) fn test_new(proof: ProofSession, start: u64, deadline: u64) -> Self {
        Self::new(proof, start, deadline, false, None)
    }
}
struct TraceCandidate {
    body: TraceCandidateBody,
    position: usize,
}
#[derive(Clone, Copy)]
enum TracePhase {
    Arming,
    Health,
    Settlement,
    Seeding,
}

pub struct Engine {
    plan: plan::AttachPlan,
    pinned: PinnedObjects,
    discovery: render::DiscoveryEvidence,
    capture_facts: CaptureFacts,
    views: Vec<ProcessView>,
    trace_seeds: BTreeMap<SeedId, TraceCandidate>,
    trace_by_view: BTreeMap<ProcessViewId, SeedId>,
    trace_owner: Option<ProofSession>,
    trace_active: Option<TraceWorkTicket>,
    /// Inherited frame limit; only with_live_frame activates ordinary deferral.
    trace_frame_deadline_ns: Option<u64>,
    trace_terminal: Option<TraceWorkTicket>,
    trace_phase: TracePhase,
    trace_phase_visits: u32,
    trace_arm_cursor: Option<SeedId>,
    trace_settle_cursor: Option<SeedId>,
    trace_view_cursor: usize,
    trace_needs_health: bool,
    trace_health_seed: Option<SeedId>,
    modules: Vec<ReconciledModule>,
    manifests: Vec<Manifest>,
    manifest_ordinals: Vec<u32>,
    counters: DiscoveryCounters,
    identity_mismatches: usize,
    scan_inputs: BTreeMap<ProcessViewId, ScanInput>,
    manifest_inputs: Vec<ManifestInput>,
    base_counters: DiscoveryCounters,
    budget: CaptureWorkBudget,
    inventory: Option<inventory::InventoryState>,
    next_view_id: u32,
    /// Retired live-view IDs available for reuse. Allocation pops before
    /// minting, so only simultaneously live views count against the ceiling.
    retired_view_ids: Vec<u32>,
    /// `--max-scan-pids`: how many scope members each scan pass covers.
    max_scan_pids: usize,
    loader_registry: LoaderRegistry,
    owned_initial_exec: Option<OwnedInitialExec>,
    terminal_batch: Option<TerminalBatch>,
    terminal_journal: Option<TerminalJournal>,
    pending_discovery_records: Vec<QueuedDiscoveryRecord>,
    /// Set while a pause cycle applies its batch (the owned child stopped).
    pause_owned_batch: bool,
    /// Set while a pressure service pass runs inside record dispatch. Nested
    /// record passes observe it and dispatch normally instead of starting a
    /// second service pass, and retirement paths shield the protected pids.
    pressure_service_active: bool,
    /// Set while an inventory tick runs. A tick's own leftover-record passes
    /// dispatch normally; only live-batch dispatch parks a pressure head, so
    /// a service pass can never nest inside the tick it is servicing.
    in_refresh_tick: bool,
    /// The single queued request a pressure service pass may complete. Set
    /// only while `pressure_service_active` holds; the tick scopes every
    /// retirement, rescan, admission and completion set to this pid and
    /// retains every other request with its serial and age.
    pressure_selected: Option<PressureSelection>,
    /// What a pressure service pass must leave untouched: pids named by
    /// undispatched owned records (parked, pending, diverted, terminal and
    /// pause-held), plus the owner views of loader contexts, terminal
    /// owners and selection bindings those records name. Meaningful while
    /// `pressure_service_active` or `pressure_rotation_pending` holds. When
    /// an owned record's ownership cannot be narrowed, `block_all` shields
    /// every retained context instead of guessing an owner from PID alone.
    pressure_protection: PressureProtection,
    /// The held head's service episode: its request snapshot and the
    /// entries one bounded rotation already ruled out. Discarded when the
    /// head settles (dispatch or refusal); a new head starts a new episode.
    pressure_episode: Option<PressureEpisode>,
    /// Set when a head episode re-parks its prefix for another rotation
    /// opportunity: the ordinary tick behind it is suppressed, and
    /// retirement stays shielded until the head settles. Cleared at every
    /// record-pass entry and whenever the head settles.
    pressure_rotation_pending: bool,
    /// Selected-request service passes run (including deferrals): the
    /// rotation instrument. H1 fairness cursors are checkpointed around
    /// each pass, so this — not an H1 counter — measures service.
    pressure_service_passes: u64,
    /// Service passes that ran a real attempt: a scan, an arm, an admission
    /// or a completion with a working clock. Quantum/clock deferrals and
    /// absent candidates advance no attempt.
    pressure_attempts: u64,
    /// The last frame collect stopped at the shared allowance with the
    /// queue not observed empty. Sticky until the scheduler takes it: a
    /// set flag schedules backlog service instead of a full sleep.
    frame_fresh_blocked: bool,
    /// Terminal-drain quanta that stopped at the shared allowance with
    /// terminal work unfinished. Sticky evidence, like quiescence
    /// overflow: a terminal drain that ends here never claims complete.
    terminal_capacity_backlog: u64,
    /// Diagnostic high-water mark of held ordinary discovery records
    /// (pending plus terminal plus in-flight batch records). Never evidence.
    discovery_held_high_water: usize,
    /// The records the running pause-owned batch was handed.
    held_records: BTreeSet<(u64, u64, u8)>,
    /// Views with at least one loader hit held by a pause stop, and views
    /// where a loader hit, export return, deferred scan or static attach
    /// happened while the child ran. A bound loader context is
    /// pause-protected only in the first set and not in the second.
    paused_loader_views: BTreeSet<ProcessViewId>,
    unpaused_loader_views: BTreeSet<ProcessViewId>,
    /// A live frame's work budget (H-1); `LIVE_FRAME_WORK_BUDGET_NS` except
    /// in tests.
    frame_work_budget_ns: u64,
    /// When the running live frame's work budget ends; `None` outside a
    /// live frame (pause cycles, terminal drains and startup run unbounded).
    frame_deadline_ns: Option<u64>,
    /// Set when this live frame deferred work to the next one.
    frame_deferred: bool,
    /// Live frames that deferred work (F4): scheduling evidence.
    frame_deferrals: u64,
    /// Under-cap polling rescans queued (internal evidence).
    polling_rescans_queued: u64,
    /// Pids whose queued refresh is a polling rescan of an unarmed,
    /// provider-free view (F1). A subset of `refresh_requested`: every site
    /// that drops a refresh without a rescan (retirement, link loss, the
    /// idle-tick clear) drops the poll with it, and the settle drops polls
    /// whose rescan failed (already published) or whose view retired first
    /// (nothing to settle). Only a quantum-deferred poll stays pending,
    /// until its retry settles it. Exploratory eviction needs no prune: a
    /// queued refresh makes a view unevictable, so a polled view is never
    /// a victim.
    polled_pids: BTreeSet<u32>,
    /// The capture's operator-stop flag, checked between work items.
    cancel_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    scope: Scope,
    hooks: HookRegistry,
    module_hints: Vec<PathBuf>,
    counter_snapshot: CounterSnapshot,
    malformed_discovery: u64,
    /// Requests retain their original age; each consumed-record renewal gets
    /// a unique serial so an older inventory pass cannot complete newer work.
    refresh_requested: BTreeMap<u32, RefreshRequest>,
    last_refresh_serial: u64,
    scheduler: DiscoveryScheduler,
    loader_records_accepted: u64,
    timings: CausalTimings,
    /// Per-stage wall-time accumulation (Phase 2): scan, pin, bind, plan,
    /// merge, projection, attach, plus the terminal cleanup overhead. The
    /// run loop merges these into its own drain/cleanup spans at snapshot.
    stage_timings: crate::timing::StageTimings,
    /// First-seen arrival marks for diff-discovered newcomers, keyed by pid.
    /// Marked eagerly at diff time (arrival is the first diff); removed on
    /// admission; pruned to the enumerated scope every inventory tick.
    /// Bounded by `MAX_NEWCOMER_MARKS`, overflow counted, never silent.
    newcomer_first_seen: crate::timing::NewcomerMarks,
    /// Cumulative newcomer queue-age evidence (admissions and drops sample
    /// here; pending counts fill in at snapshot time).
    newcomer_ages: crate::timing::NewcomerStats,
    /// Publication-input revision: bumped on every live-batch mutation of
    /// plan, pins, modules, corroboration, fallback, skips or scan time.
    facts_revision: u64,
    /// The revision whose complete facts were successfully projected publicly.
    /// A staged merge is private and cannot advance this marker.
    published_facts_revision: u64,
    /// One stationary full loader transaction's exact pre-projection plan.
    /// Historical public surfaces can differ, so the projected plan is not
    /// a substitute for the next unchanged planner result.
    loader_plan_cache: Option<LoaderPlanCache>,
    /// Batch-tail publications executed (counter, not timing: the B1 proof).
    tail_publishes: u64,
    /// Batch-tail publications skipped as provably redundant (same proof).
    tail_skips: u64,
    discovery_truncated: u64,
    pending_rejected_keys: BTreeSet<ObjectKey>,
    pending_retirements: BTreeSet<ProcessViewId>,
    retirement_intents: PendingViewRetirements,
    ready_expected_removals: BTreeSet<ProcessViewId>,
    expected_target_exit_pending: Option<ProcessViewId>,
    expected_target_exit: bool,
    pending_leader_exit_views: BTreeSet<ProcessViewId>,
    counted_leader_exit_views: BTreeSet<ProcessViewId>,
    /// Views with a matched EXEC whose PID-bound static links may be dead
    /// while still recorded as attached. At most one marker per retained
    /// view: the next refresh rearms even an unchanged plan, ordinary-delta
    /// churn or a completed rearm clears it, and view removal prunes it.
    exec_rearm_views: BTreeSet<ProcessViewId>,
    pid_descendant_gaps: u64,
    /// Multi-group rebuild windows this capture published: one per rebuilt
    /// group per rebuild transaction. Ungated by scope — a rebuild blinds
    /// its members wherever the capture runs.
    multi_rebuild_gaps: u64,
    // Both ledgers are capture-local and bounded by the process-view ceiling;
    // only the scalar crosses the render boundary.
    admitted_cgroup_views: BTreeMap<ProcessViewId, CgroupAdmission>,
    unmatched_leader_exit_events: BTreeSet<(u32, u64)>,
    cgroup_ingress_overflow: bool,
    task_uprobe_link_losses: u64,
    next_selection_binding_id: Option<u64>,
    selection_bindings: BTreeMap<u64, SelectionBindingFact>,
    /// The deduplicated bound-context set behind `loader_discovery`'s
    /// strategy/timing/capture counts (design §9.2). Keyed by the exact
    /// internal `{process generation, bound identity state, load kind}` — so
    /// one context contributes exactly once no matter how many records it
    /// produces, while initial-set and ordinary contexts stay partitioned.
    /// All identity stays out: only the classification is kept, and it is all
    /// that can be rendered.
    loader_contexts: BTreeMap<(ProcessViewId, LoaderAggregateKey, bool), LoaderContextClass>,
    pending_loader_scans: BTreeMap<PendingLoaderScanKey, u64>,
    selection_claims: BTreeMap<SelectionClaimKey, SelectionClaim>,
    selection_tables: BTreeMap<SelectionTableKey, SelectionTableFact>,
    /// Task 1.6 experiment: broad admission. Set once from
    /// `P11SCOPE_BROAD_ADMIT=1` in `discover_plan` (production) or directly
    /// by broad tests; `false` preserves selected admission everywhere.
    broad_admit: bool,
    /// View IDs that have ever contributed provider evidence (a scan or a
    /// live record observed modules for them). Eviction eligibility needs
    /// this history, not just the current state: the capture budget keys
    /// runtime (non-file-backed) table/interface identities by view ID, and
    /// `scan.rs` offers no per-view scrub — so an ID that ever carried such
    /// evidence must never be recycled into a new generation's scan. Only
    /// never-dirty, currently-empty views rotate. Never cleared: IDs are
    /// reused, and a reused dirty ID stays non-rotatable. Bounded by the
    /// view-ID space.
    exploratory_dirty: BTreeSet<ProcessViewId>,
    /// Actual deep-scan executions driven by discovery and inventory
    /// (initial scans, refresh rescans, new-view admissions, loader
    /// rescans) — the E06 oracle alongside maps bytes, never derived from
    /// them.
    deep_scans: u64,
    /// Loader-arm attempts driven by inventory (`arm_loader_or_partial`
    /// calls) — the hook half of the same oracle.
    loader_arms: u64,
    /// Cumulative exploratory views evicted by rotation.
    exploratory_evictions: u64,
    #[cfg(test)]
    loader_memory_scan_attempts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoaderAggregateKey {
    Unbound,
    Bound(PinnedTimingKey),
    BoundUnkeyed(LoaderContextId),
}

impl Ord for LoaderAggregateKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        match (self, other) {
            (Self::Unbound, Self::Unbound) => Ordering::Equal,
            (Self::Unbound, _) => Ordering::Less,
            (_, Self::Unbound) => Ordering::Greater,
            (Self::Bound(left), Self::Bound(right)) => left.cmp(right),
            (Self::Bound(_), Self::BoundUnkeyed(_)) => Ordering::Less,
            (Self::BoundUnkeyed(_), Self::Bound(_)) => Ordering::Greater,
            (Self::BoundUnkeyed(left), Self::BoundUnkeyed(right)) => left.get().cmp(&right.get()),
        }
    }
}

impl PartialOrd for LoaderAggregateKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// One exact live-loader context, classified. `bound` is the §9.2 strategy
/// (`debug_state_every_hit` when the exact `_dl_debug_state` context was
/// armed, `unavailable` otherwise); `initial_set` selects which of the two
/// timing groups it counts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoaderContextClass {
    bound: bool,
    initial_set: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingLoaderScanKey {
    view: ProcessViewId,
    context: LoaderContextId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoaderScanMode {
    Memory,
    MetadataOnly,
}

impl Ord for PendingLoaderScanKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.view, self.context.get()).cmp(&(other.view, other.context.get()))
    }
}

impl PartialOrd for PendingLoaderScanKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Default)]
struct CaptureFacts {
    next_module_id: u32,
    module_ids: BTreeMap<PinnedTimingKey, plan::ModuleId>,
    module_keys: BTreeMap<plan::ModuleId, PinnedTimingKey>,
    history: CaptureHistory,
    staged: Option<CaptureHistory>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum DecodedOccurrence {
    /// One exact decoded target occurrence, in the one keyspace every source
    /// shares: a manifest corroborating a scanned entry names the same
    /// occurrence and is counted once, as the schema requires.
    Target {
        module: plan::ModuleId,
        name: String,
        object: PinnedTimingKey,
        file_offset: u64,
        occurrence: usize,
    },
    ScanSkip {
        module: plan::ModuleId,
        subject: String,
        reason: String,
        occurrence: usize,
    },
    ManifestFunction {
        module: plan::ModuleId,
        manifest: u32,
        surface: usize,
        function: usize,
    },
    Selection {
        module: plan::ModuleId,
        provider: PinnedTimingKey,
        table_file_offset: u64,
        version: (u8, u8),
        ordinal: u16,
        name: &'static str,
        object: Option<(PinnedTimingKey, u64)>,
    },
}

impl DecodedOccurrence {
    fn module(&self) -> plan::ModuleId {
        match self {
            Self::Target { module, .. }
            | Self::ScanSkip { module, .. }
            | Self::ManifestFunction { module, .. }
            | Self::Selection { module, .. } => *module,
        }
    }
}

impl TableOccurrence {
    fn module(&self) -> plan::ModuleId {
        match self {
            Self::Scan { module, .. } | Self::Manifest { module, .. } => *module,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SurfaceOccurrence {
    Scan {
        module: plan::ModuleId,
        version: (u8, u8),
        walk: String,
        functions: usize,
        occurrence: usize,
    },
    Interface {
        module: plan::ModuleId,
        index: usize,
        name_class: &'static str,
        version: (u8, u8),
        walk: String,
        functions: usize,
    },
    Manifest {
        module: plan::ModuleId,
        manifest: u32,
        surface: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum TableOccurrence {
    Scan {
        module: plan::ModuleId,
        version: (u8, u8),
        entries: usize,
        occurrence: usize,
    },
    Manifest {
        module: plan::ModuleId,
        manifest: u32,
        surface: usize,
    },
}

#[derive(Debug, Clone, Default)]
struct CaptureHistory {
    modules: BTreeMap<plan::ModuleId, render::DiscoveredModule>,
    decoded: BTreeSet<DecodedOccurrence>,
    surfaces: BTreeMap<SurfaceOccurrence, plan::SurfaceSummary>,
    tables: BTreeMap<TableOccurrence, plan::TableSummary>,
    skips: BTreeMap<DecodedOccurrence, Skipped>,
    losses: BTreeMap<(String, String), Skipped>,
    /// Scan gaps contradicted by a later same-path nonempty table; exact keys
    /// keep persistent counters from resurrecting them after that table retires.
    scan_gap_tombstones: BTreeSet<(String, String)>,
    refusals: BTreeMap<plan::ModuleId, Skipped>,
    fallbacks: BTreeMap<(u32, u32), render::ManifestObjectFallback>,
    corroboration_tombstones: BTreeSet<plan::ModuleId>,
    /// §4.12 outcomes re-derived after attach. Corroboration is a
    /// capture-lifetime fact: once the scan reached this object, a view
    /// retiring later does not unsay it, so the outcome is retained here
    /// rather than recomputed from whatever the current pin set happens to
    /// show. A fresher reading replaces it; only a corroboration tombstone
    /// revokes it.
    recorroborated: BTreeMap<plan::ModuleId, Corroboration>,
    /// Every module the capture-end pass has ever derived a `Conflict` for.
    /// Corroboration is revocable and replaceable, so `recorroborated` above
    /// changes; a disagreement the capture actually observed is neither, and
    /// counting it off that map would let a tombstone or a later agreement
    /// decrement `discovery_conflicts`. Nothing is ever removed from this set —
    /// it is the derived half of the same high-water mark `conflicts` is.
    conflicted: BTreeSet<plan::ModuleId>,
    fallback_tombstones: BTreeSet<(u32, u32)>,
    conflicts: u64,
    /// The latched attach-time base only — never the published value. It stays
    /// a pure high-water mark of `current.uncorroborated`, so it can never drop
    /// below what the plan reports; the derived corroborations subtracted from
    /// it and the tombstone gaps added to it are separate facts, kept
    /// separately and combined once, in `discovery`.
    uncorroborated: u64,
    /// Proofs a later exact identity collision revoked, for modules that were
    /// *not* corroborated by the capture-end re-derivation. Each is a gap the
    /// base above never counted, so it is additive and permanent — mixing it
    /// into the base would let another module's re-derivation subtract it away.
    uncorroborated_tombstones: u64,
    /// The high-water mark of `plan.uncorroborated_candidates`. The plan's
    /// counter is current-state — a live merge that bypasses a spilled table
    /// resolves it — but omission exposure is capture-lifetime evidence: a
    /// run that spilled and then settled must still report the earlier
    /// omission, so every merge latches the maximum and `discovery`
    /// publishes it. Nothing here ever decreases.
    uncorroborated_candidates: u64,
    scan_unavailable: Option<String>,
    scan_ms: u64,
    vendor_interfaces: usize,
    interface_list: String,
    selection_inventory: BTreeMap<ExactSelectionTable, Vec<InventorySurfaceKey>>,
    selection_surfaces: BTreeSet<InventorySurfaceKey>,
    manifest_selection_ordinals: BTreeSet<u32>,
    selections: Vec<LiveSelectionTuple>,
    selection_truncated: bool,
    standard_exports: BTreeMap<plan::ModuleId, BTreeSet<StandardExportFact>>,
    standard_requirements: BTreeMap<plan::ModuleId, BTreeSet<StandardRequirementFact>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StandardExportFact {
    Present,
    Absent,
    Outside,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum StandardRequirementFact {
    Legacy,
    V3,
}

fn standard_export_status(
    exports: Option<&BTreeSet<StandardExportFact>>,
    requirements: Option<&BTreeSet<StandardRequirementFact>>,
) -> &'static str {
    match (exports, requirements) {
        (Some(exports), _)
            if exports.len() == 1 && exports.contains(&StandardExportFact::Present) =>
        {
            "present"
        }
        (Some(exports), _)
            if exports.len() == 1 && exports.contains(&StandardExportFact::Outside) =>
        {
            "outside_module"
        }
        (Some(exports), Some(requirements))
            if exports.len() == 1
                && exports.contains(&StandardExportFact::Absent)
                && requirements.len() == 1
                && requirements.contains(&StandardRequirementFact::Legacy) =>
        {
            "legacy_absent"
        }
        (Some(exports), Some(requirements))
            if exports.len() == 1
                && exports.contains(&StandardExportFact::Absent)
                && requirements.len() == 1
                && requirements.contains(&StandardRequirementFact::V3) =>
        {
            "required_absent"
        }
        _ => "unresolved",
    }
}

const MAX_LIVE_SELECTION_TUPLES: usize = 16;
const MAX_LIVE_SELECTION_MATCHES: usize = 16;
const MAX_LIVE_SELECTION_SURFACES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExactSelectionTable {
    view: ProcessViewId,
    provider: PinnedTimingKey,
    address: u64,
    file_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InventorySurfaceKind {
    Legacy,
    Interface,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PrivateSelectionName {
    Legacy,
    Null,
    ExactStandard,
    Other(Vec<u8>),
    OtherUnmergeable(ProcessViewId, usize),
    Unreadable(ProcessViewId, usize),
}

impl PrivateSelectionName {
    fn class(&self) -> Option<SelectionNameClass> {
        match self {
            Self::Legacy => None,
            Self::Null => Some(SelectionNameClass::Null),
            Self::ExactStandard => Some(SelectionNameClass::ExactStandard),
            Self::Other(_) | Self::OtherUnmergeable(_, _) => Some(SelectionNameClass::Other),
            Self::Unreadable(_, _) => Some(SelectionNameClass::Unreadable),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InventorySurfaceBase {
    provider: PinnedTimingKey,
    table_file_offset: u64,
    kind: InventorySurfaceKind,
    name: PrivateSelectionName,
    version: SelectionVersionClass,
    flags: u64,
    /// Address-free source identity for offline surfaces. Scan surfaces use
    /// `None`; a manifest ordinal and surface index cannot collide with a
    /// different accepted manifest.
    manifest_identity: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct InventorySurfaceKey {
    base: InventorySurfaceBase,
    duplicate: u16,
}

#[derive(Debug, Clone, Copy)]
struct CgroupAdmission {
    pid: u32,
    admitted_ns: u64,
    closed_ns: Option<u64>,
}

impl CgroupAdmission {
    fn covers(self, hook_ts_ns: u64, pid: u32) -> bool {
        self.pid == pid
            && hook_ts_ns >= self.admitted_ns
            && self
                .closed_ns
                .is_none_or(|closed_ns| hook_ts_ns <= closed_ns)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LiveInventoryMatch {
    surface: InventorySurfaceKey,
    name_agrees: bool,
    version_agrees: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveSelectionTuple {
    module: plan::ModuleId,
    request: SelectionRequest,
    rv: u64,
    result: Option<SelectionRequest>,
    inventory_matches: Vec<LiveInventoryMatch>,
    authority: SelectionAuthority,
    count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SelectionClaimKey {
    binding_id: u64,
    view: ProcessViewId,
    context: u16,
    hook_owner: PinnedObjectId,
    provider: PinnedTimingKey,
    selected_object: PinnedObjectId,
    table_file_offset: u64,
    version: SelectionVersionClass,
    flags: u64,
    name: &'static str,
    file_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectionClaim {
    target: plan::AttachKey,
    /// Diagnostic only; never part of selection identity.
    object_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SelectionTableKey {
    view: ProcessViewId,
    provider: PinnedTimingKey,
    version: SelectionVersionClass,
    flags: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectionTableFact {
    object: PinnedObjectId,
    file_offset: u64,
    targets: Vec<plan::SelectionTableTarget>,
}

#[derive(Debug, Clone)]
struct ManifestSelectionAdmission {
    source: (u32, u8),
    targets: Vec<plan::SelectionTableTarget>,
}

type SelectionClaims = BTreeMap<SelectionClaimKey, SelectionClaim>;
type SelectionTables = BTreeMap<SelectionTableKey, SelectionTableFact>;
type ProposedSelectionClaim = (SelectionClaims, SelectionTables, PendingSelectionAdmission);

#[derive(Debug, Clone)]
struct PendingSelectionAdmission {
    key: SelectionTableKey,
    table: SelectionTableFact,
    previous_claims: BTreeMap<SelectionClaimKey, SelectionClaim>,
    previous_tables: BTreeMap<SelectionTableKey, SelectionTableFact>,
}

fn selection_name_class(class: u8) -> Option<SelectionNameClass> {
    match class {
        DISCOVERY_NAME_EXACT_STANDARD => Some(SelectionNameClass::ExactStandard),
        DISCOVERY_NAME_OTHER => Some(SelectionNameClass::Other),
        DISCOVERY_NAME_NULL => Some(SelectionNameClass::Null),
        DISCOVERY_NAME_UNREADABLE => Some(SelectionNameClass::Unreadable),
        _ => None,
    }
}

fn selection_version_class(class: u8) -> Option<SelectionVersionClass> {
    match class {
        DISCOVERY_VERSION_NULL => Some(SelectionVersionClass::Null),
        DISCOVERY_VERSION_UNREADABLE => Some(SelectionVersionClass::Unreadable),
        DISCOVERY_VERSION_V2_40 => Some(SelectionVersionClass::V2_40),
        DISCOVERY_VERSION_V3_0 => Some(SelectionVersionClass::V3_0),
        DISCOVERY_VERSION_V3_1 => Some(SelectionVersionClass::V3_1),
        DISCOVERY_VERSION_V3_2 => Some(SelectionVersionClass::V3_2),
        DISCOVERY_VERSION_OTHER => Some(SelectionVersionClass::Other),
        _ => None,
    }
}

fn inventory_version_class(version: (u8, u8)) -> SelectionVersionClass {
    match version {
        (2, 40) => SelectionVersionClass::V2_40,
        (3, 0) => SelectionVersionClass::V3_0,
        (3, 1) => SelectionVersionClass::V3_1,
        (3, 2) => SelectionVersionClass::V3_2,
        _ => SelectionVersionClass::Other,
    }
}

fn private_selection_name(
    interface: &ScannedInterface,
    view: ProcessViewId,
) -> PrivateSelectionName {
    match interface.name_class {
        "exact_standard" => PrivateSelectionName::ExactStandard,
        "other" => interface.name_private.clone().map_or_else(
            || PrivateSelectionName::OtherUnmergeable(view, interface.index),
            PrivateSelectionName::Other,
        ),
        "null" => PrivateSelectionName::Null,
        _ => PrivateSelectionName::Unreadable(view, interface.index),
    }
}

fn manifest_inventory_surface_key(
    provider: PinnedTimingKey,
    manifest: u32,
    index: usize,
    surface: &p11scope_manifest::manifest::SurfaceRecord,
) -> Option<InventorySurfaceKey> {
    let index = u32::try_from(index).ok()?;
    let (kind, name, flags) = match &surface.source {
        SurfaceSource::LegacyFunctionList => (
            InventorySurfaceKind::Legacy,
            PrivateSelectionName::Legacy,
            0,
        ),
        SurfaceSource::Interface {
            classification,
            flags,
            ..
        } => (
            InventorySurfaceKind::Interface,
            match classification {
                p11scope_manifest::manifest::InterfaceClassification::ExactStandard => {
                    PrivateSelectionName::ExactStandard
                }
                p11scope_manifest::manifest::InterfaceClassification::CorroboratedStandardPrefix => {
                    PrivateSelectionName::Other(Vec::new())
                }
            },
            *flags,
        ),
    };
    Some(InventorySurfaceKey {
        base: InventorySurfaceBase {
            provider,
            table_file_offset: index as u64,
            kind,
            name,
            version: surface
                .version
                .map_or(SelectionVersionClass::Other, |version| {
                    inventory_version_class((version.major, version.minor))
                }),
            flags,
            manifest_identity: Some((manifest, index)),
        },
        duplicate: 0,
    })
}

fn readable_name(class: SelectionNameClass) -> bool {
    !matches!(
        class,
        SelectionNameClass::Null | SelectionNameClass::Unreadable
    )
}

fn readable_version(class: SelectionVersionClass) -> bool {
    !matches!(
        class,
        SelectionVersionClass::Null | SelectionVersionClass::Unreadable
    )
}

fn insert_selection_loss(history: &mut CaptureHistory, reason: &str) {
    insert_selection_loss_for(history, "live interface selection", reason);
}

fn insert_selection_loss_for(history: &mut CaptureHistory, subject: &str, reason: &str) {
    let skipped = Skipped {
        subject: subject.into(),
        reason: reason.into(),
    };
    history
        .losses
        .entry((skipped.subject.clone(), skipped.reason.clone()))
        .or_insert(skipped);
}

const OFFLINE_SELECTION_LOSS_REASON: &str =
    "offline interface selection helper reported incomplete evidence";

fn canonical_inventory_keys(mut bases: Vec<InventorySurfaceBase>) -> Vec<InventorySurfaceKey> {
    bases.sort();
    let mut prior = None;
    let mut duplicate = 0u16;
    bases
        .into_iter()
        .map(|base| {
            if prior.as_ref() == Some(&base) {
                duplicate = duplicate.saturating_add(1);
            } else {
                duplicate = 0;
            }
            prior = Some(base.clone());
            InventorySurfaceKey { base, duplicate }
        })
        .collect()
}

fn admit_inventory_keys(
    history: &mut CaptureHistory,
    keys: Vec<InventorySurfaceKey>,
) -> Vec<InventorySurfaceKey> {
    let new_surfaces = keys
        .iter()
        .filter(|key| !history.selection_surfaces.contains(*key))
        .count();
    let admit_all = history
        .selection_surfaces
        .len()
        .checked_add(new_surfaces)
        .is_some_and(|total| total <= MAX_LIVE_SELECTION_SURFACES);
    if admit_all {
        history.selection_surfaces.extend(keys.iter().cloned());
    } else {
        history.selection_truncated = true;
        insert_selection_loss(
            history,
            "the bounded selection surface inventory was truncated",
        );
    }
    keys.into_iter()
        .filter(|key| history.selection_surfaces.contains(key))
        .collect()
}

fn stable_selection_mapping(before: Option<&MapEntry>, after: Option<&MapEntry>) -> bool {
    before == after
}

/// Bracket one returned table address with two complete map snapshots. The
/// callbacks are deliberately tiny so tests can prove the ordering without a
/// racy live remap: the output is read from snapshot A, then snapshot B closes
/// the attempt, and only then are generation and pin stability consulted.
fn selection_mapping_bracket(
    table_ptr: u64,
    mut read_maps: impl FnMut() -> Result<Vec<MapEntry>, ()>,
    mut view_same: impl FnMut() -> bool,
    mut pin_same: impl FnMut() -> bool,
) -> Result<(Option<MapEntry>, Resolved), ()> {
    let maps_a = read_maps()?;
    let index_a = MapIndex::new(&maps_a).map_err(|_| ())?;
    let mapping_a = index_a.containing(table_ptr).cloned();
    let resolved_a = index_a.resolve(table_ptr);
    let maps_b = read_maps()?;
    let index_b = MapIndex::new(&maps_b).map_err(|_| ())?;
    let mapping_same = stable_selection_mapping(mapping_a.as_ref(), index_b.containing(table_ptr));
    let view_same = view_same();
    let pin_same = pin_same();
    if !mapping_same || !view_same || !pin_same {
        return Err(());
    }
    Ok((mapping_a, resolved_a))
}

fn selection_table_key(claim: &SelectionClaimKey) -> SelectionTableKey {
    SelectionTableKey {
        view: claim.view,
        provider: claim.provider.clone(),
        version: claim.version,
        flags: claim.flags,
    }
}

fn canonical_selection_targets(
    entries: impl IntoIterator<Item = (SelectionClaimKey, SelectionClaim)>,
) -> Vec<plan::SelectionTableTarget> {
    let mut targets = BTreeMap::<(PinnedObjectId, u64, &'static str), String>::new();
    for (key, claim) in entries {
        let target = claim.target;
        let target_key = (target.object, target.file_offset, key.name);
        targets
            .entry(target_key)
            .and_modify(|path| {
                if claim.object_path < *path {
                    *path = claim.object_path.clone();
                }
            })
            .or_insert(claim.object_path);
    }
    targets
        .into_iter()
        .map(
            |((object, file_offset, name), object_path)| plan::SelectionTableTarget {
                object,
                object_path,
                file_offset,
                name,
            },
        )
        .collect()
}

fn same_selection_target_set(
    left: &[plan::SelectionTableTarget],
    right: &[plan::SelectionTableTarget],
) -> bool {
    let identity =
        |target: &plan::SelectionTableTarget| (target.object, target.file_offset, target.name);
    let mut left = left.iter().map(identity).collect::<Vec<_>>();
    let mut right = right.iter().map(identity).collect::<Vec<_>>();
    left.sort();
    right.sort();
    left == right
}

/// Drops ambiguous selection claims before rebuilding their table facts. One
/// semantic key is intentionally one physical table: a second offset or a
/// changed complete target set is factual loss, never a union of authorities.
fn prune_selection_table_conflicts(
    claims: &mut BTreeMap<SelectionClaimKey, SelectionClaim>,
) -> BTreeSet<SelectionTableKey> {
    type ClaimEntries = Vec<(SelectionClaimKey, SelectionClaim)>;
    type ClaimsByBinding = BTreeMap<(u64, PinnedObjectId, u64), ClaimEntries>;
    let mut groups: BTreeMap<SelectionTableKey, ClaimsByBinding> = BTreeMap::new();
    for (key, claim) in claims.iter() {
        groups
            .entry(selection_table_key(key))
            .or_default()
            .entry((key.table_file_offset, key.hook_owner, key.binding_id))
            .or_default()
            .push((key.clone(), claim.clone()));
    }
    let mut remove = BTreeSet::new();
    let mut conflicts = BTreeSet::new();
    for (semantic, by_binding) in groups {
        let mut known: Option<(u64, PinnedObjectId, Vec<plan::SelectionTableTarget>)> = None;
        let mut conflict = false;
        for ((table_file_offset, hook_owner, _), entries) in by_binding {
            let targets = canonical_selection_targets(entries);
            if let Some((known_offset, known_owner, known_targets)) = &known {
                if *known_offset != table_file_offset
                    || *known_owner != hook_owner
                    || !same_selection_target_set(known_targets, &targets)
                {
                    conflict = true;
                    break;
                }
            } else {
                known = Some((table_file_offset, hook_owner, targets));
            }
        }
        if conflict {
            remove.extend(
                claims
                    .keys()
                    .filter(|claim| selection_table_key(claim) == semantic)
                    .cloned(),
            );
            conflicts.insert(semantic);
        }
    }
    for key in remove {
        claims.remove(&key);
    }
    conflicts
}

fn selection_tables_from_claims(
    claims: &BTreeMap<SelectionClaimKey, SelectionClaim>,
) -> BTreeMap<SelectionTableKey, SelectionTableFact> {
    let mut grouped: BTreeMap<SelectionTableKey, Vec<(SelectionClaimKey, SelectionClaim)>> =
        BTreeMap::new();
    for (key, claim) in claims {
        grouped
            .entry(selection_table_key(key))
            .or_default()
            .push((key.clone(), claim.clone()));
    }
    grouped
        .into_iter()
        .filter_map(|(key, entries)| {
            let first = entries.first()?.0.clone();
            Some((
                key,
                SelectionTableFact {
                    object: first.hook_owner,
                    file_offset: first.table_file_offset,
                    targets: canonical_selection_targets(entries),
                },
            ))
        })
        .collect()
}

fn prune_selection_inventory(history: &mut CaptureHistory, live_views: &BTreeSet<ProcessViewId>) {
    history
        .selection_inventory
        .retain(|table, _| live_views.contains(&table.view));
}

fn capture_manifest_object_key(manifest: &Manifest, object: u32) -> Option<(ObjectKey, &str)> {
    let object = manifest.objects.iter().find(|record| record.id == object)?;
    let provenance = &manifest.provenance_objects[plan::provenance_of(manifest, object)?];
    Some((
        ObjectKey {
            device: Device {
                major: provenance.device_major,
                minor: provenance.device_minor,
            },
            inode: provenance.inode,
        },
        &object.path,
    ))
}

fn manifest_module_object(manifest: &Manifest, pinned: &PinnedObjects) -> Option<PinnedObjectId> {
    let module = manifest
        .objects
        .iter()
        .find(|object| object.path == manifest.module_path)?;
    let (key, path) = capture_manifest_object_key(manifest, module.id)?;
    pinned.id_for_manifest(key, path)
}

/// The reachable count-only claims, before slot admission. Shared with the
/// semantic completeness check; these never authorize argument decoding.
pub(crate) fn manifest_selection_targets<'a>(
    manifest: &'a Manifest,
    pinned: &'a PinnedObjects,
) -> impl Iterator<Item = (u8, Vec<plan::SelectionTableTarget>)> + 'a {
    let reachable: BTreeSet<_> = manifest
        .selection_evidence
        .queries
        .iter()
        .filter(|query| matches!(query.authority, SelectionAuthority::SelectionCountOnly))
        .filter_map(|query| query.selection_table)
        .collect();
    manifest
        .selection_evidence
        .tables
        .iter()
        .filter(move |table| reachable.contains(&table.id))
        .map(|table| {
            let mut targets = Vec::new();
            for function in &table.functions {
                let Resolution::Resolved {
                    object,
                    file_offset,
                } = function.resolution
                else {
                    continue;
                };
                let Some((key, path)) = capture_manifest_object_key(manifest, object) else {
                    continue;
                };
                let Some(object) = pinned.id_for_manifest(key, path) else {
                    continue;
                };
                let Some(name) = pkcs11_module::FUNCTION_LIST_FIELDS
                    .iter()
                    .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
                    .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS)
                    .find(|field| field.name == function.name)
                    .map(|field| field.name)
                else {
                    continue;
                };
                targets.push(plan::SelectionTableTarget {
                    object,
                    object_path: path.into(),
                    file_offset,
                    name,
                });
            }
            (table.id, targets)
        })
}

fn lower_manifest_selection_tables(
    plan: &mut plan::AttachPlan,
    allocated: &plan::AttachPlan,
    manifests: &[Manifest],
    manifest_ordinals: &[u32],
    pinned: &PinnedObjects,
) -> (Vec<ManifestSelectionAdmission>, Vec<String>) {
    let mut admissions = Vec::new();
    let mut refused = Vec::new();
    for (manifest, ordinal) in manifests.iter().zip(manifest_ordinals) {
        let Some(provider) = manifest_module_object(manifest, pinned) else {
            continue;
        };
        let Some(module) = plan
            .modules
            .iter()
            .find(|module| module.object == provider)
            .map(|module| module.id)
        else {
            continue;
        };
        for (table, targets) in manifest_selection_targets(manifest, pinned) {
            match plan.add_selection_table(allocated, module, targets.clone()) {
                Ok(()) => admissions.push(ManifestSelectionAdmission {
                    source: (*ordinal, table),
                    targets,
                }),
                Err(reason) => refused.push(reason),
            }
        }
    }
    (admissions, refused)
}

fn manifest_walk_label(walk: &WalkOutcome) -> String {
    match walk {
        WalkOutcome::Full => "full".into(),
        WalkOutcome::KnownPrefix => "known_prefix".into(),
        WalkOutcome::Refused => "refused".into(),
        WalkOutcome::NotWalked => "not_walked".into(),
        WalkOutcome::Unreadable { detail } => format!("unreadable: {detail}"),
    }
}

fn manifest_acquisition_label(acquisition: &Acquisition) -> String {
    match acquisition {
        Acquisition::Ok => "ok".into(),
        Acquisition::Absent => "absent".into(),
        Acquisition::Empty => "empty".into(),
        Acquisition::Error { detail } => format!("error: {detail}"),
    }
}

/// The exact target a manifest function resolves to, in the identity the scan
/// records its decoded entries under. `None` for every record the scan cannot
/// have decoded the same target for: an unresolved pointer, or an object with
/// no comparable pinned identity — the cases `manifest_function_skip` reports.
fn manifest_function_target(
    manifest: &Manifest,
    pinned: &PinnedObjects,
    resolution: &Resolution,
) -> Option<(PinnedTimingKey, u64)> {
    let Resolution::Resolved {
        object,
        file_offset,
    } = resolution
    else {
        return None;
    };
    let (key, path) = capture_manifest_object_key(manifest, *object)?;
    let id = pinned.id_for_manifest(key, path)?;
    Some((pinned.owned_timing_key(id)?, *file_offset))
}

fn manifest_function_skip(
    manifest: &Manifest,
    pinned: &PinnedObjects,
    name: &str,
    resolution: &Resolution,
) -> Option<Skipped> {
    let reason = match resolution {
        Resolution::Resolved { object, .. } => {
            let Some((key, path)) = capture_manifest_object_key(manifest, *object) else {
                return Some(Skipped {
                    subject: name.into(),
                    reason: if manifest.objects.iter().any(|record| record.id == *object) {
                        format!("object id {object} has no provenance record")
                    } else {
                        format!("object id {object} missing from manifest")
                    },
                });
            };
            if pinned.id_for_manifest(key, path).is_some() {
                return None;
            }
            format!("object id {object} has no comparable pinned identity")
        }
        Resolution::NullPointer => "null pointer".into(),
        Resolution::NonFileBacked => "non-file-backed".into(),
        Resolution::Unmapped => "unmapped".into(),
        Resolution::UnusableFile { reason, .. } => reason.clone(),
    };
    Some(Skipped {
        subject: name.into(),
        reason,
    })
}

impl CaptureFacts {
    fn can_record_selection(&self, tuple: &LiveSelectionTuple) -> bool {
        let selections = &self.visible_history().selections;
        selections.iter().any(|known| {
            known.module == tuple.module
                && known.request == tuple.request
                && known.rv == tuple.rv
                && known.result == tuple.result
                && known.inventory_matches == tuple.inventory_matches
                && known.authority == tuple.authority
        }) || selections.len() < MAX_LIVE_SELECTION_TUPLES
    }

    fn can_record_selection_claim(&self, tuple: &LiveSelectionTuple) -> bool {
        self.can_record_selection(&LiveSelectionTuple {
            authority: SelectionAuthority::SelectionCountOnly,
            ..tuple.clone()
        })
    }

    fn begin_stage(&mut self) -> Result<()> {
        if self.staged.is_some() {
            bail!("capture-fact transaction is already active");
        }
        self.staged = Some(self.history.clone());
        Ok(())
    }

    fn commit_stage(&mut self) -> Result<()> {
        self.history = self
            .staged
            .take()
            .ok_or_else(|| anyhow!("capture-fact transaction is not active"))?;
        Ok(())
    }

    fn rollback_stage(&mut self) {
        self.staged = None;
    }

    fn visible_history(&self) -> &CaptureHistory {
        self.staged.as_ref().unwrap_or(&self.history)
    }

    fn visible_history_mut(&mut self) -> &mut CaptureHistory {
        self.staged.as_mut().unwrap_or(&mut self.history)
    }

    fn replace_visible_history(&mut self, history: CaptureHistory) {
        if self.staged.is_some() {
            self.staged = Some(history);
        } else {
            self.history = history;
        }
    }

    /// Retains only the finite, address-free selection tuple. Returns true
    /// when either the tuple or its exact alias set exceeded the capture bound.
    fn record_selection(&mut self, tuple: LiveSelectionTuple, matches_truncated: bool) -> bool {
        record_selection_in(self.visible_history_mut(), tuple, matches_truncated)
    }
}

fn record_selection_in(
    history: &mut CaptureHistory,
    mut tuple: LiveSelectionTuple,
    matches_truncated: bool,
) -> bool {
    let was_truncated = history.selection_truncated;
    let existing = history.selections.iter_mut().find(|known| {
        known.module == tuple.module
            && known.request == tuple.request
            && known.rv == tuple.rv
            && known.result == tuple.result
            && known.inventory_matches == tuple.inventory_matches
            && known.authority == tuple.authority
    });
    if let Some(existing) = existing {
        existing.count = existing.count.saturating_add(1);
    } else if history.selections.len() < MAX_LIVE_SELECTION_TUPLES {
        tuple.count = 1;
        history.selections.push(tuple);
    } else {
        history.selection_truncated = true;
    }
    history.selection_truncated |= matches_truncated;
    if history.selection_truncated && !was_truncated {
        insert_selection_loss(history, "the bounded selection evidence was truncated");
    }
    !was_truncated && history.selection_truncated
}

impl CaptureFacts {
    fn record_selection_loss(&mut self, reason: &str) {
        insert_selection_loss(self.visible_history_mut(), reason);
    }

    fn invalidate_discovery_proofs(
        &mut self,
        modules: impl IntoIterator<Item = plan::ModuleId>,
        fallbacks: impl IntoIterator<Item = (u32, u32)>,
    ) {
        let mut history = self.visible_history().clone();
        for module in modules {
            let was_corroborated = history
                .modules
                .get(&module)
                .is_some_and(|snapshot| snapshot.corroborated);
            // Revoking a *derived* corroboration is exactly dropping its
            // subtraction: the module is a manifest module the plan reports as
            // uncorroborated, so the latched base already counts it. Only a
            // proof the base never counted — one the plan itself called
            // corroborated — becomes a new gap.
            let derived = history.recorroborated.remove(&module).is_some();
            if history.corroboration_tombstones.insert(module) && was_corroborated && !derived {
                history.uncorroborated_tombstones =
                    history.uncorroborated_tombstones.saturating_add(1);
            }
            if let Some(snapshot) = history.modules.get_mut(&module) {
                snapshot.corroborated = false;
                snapshot.corroboration = vec!["uncorroborated"];
            }
        }
        for fallback in fallbacks {
            history.fallback_tombstones.insert(fallback);
            history.fallbacks.remove(&fallback);
        }
        self.replace_visible_history(history);
    }

    fn resolve_module_id(&mut self, key: &PinnedTimingKey) -> Result<plan::ModuleId> {
        if let Some(id) = self.module_ids.get(key).copied() {
            if self.module_keys.get(&id) != Some(key) {
                bail!("capture module identity registry is not bijective");
            }
            return Ok(id);
        }
        let id = plan::ModuleId(self.next_module_id);
        let next = self
            .next_module_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("capture module ID space exhausted"))?;
        if self.module_keys.contains_key(&id) {
            bail!("capture module ID {id:?} was already allocated");
        }
        self.module_ids.insert(key.clone(), id);
        self.module_keys.insert(id, key.clone());
        self.next_module_id = next;
        Ok(id)
    }

    fn bind_plan_module_ids(
        &mut self,
        candidate: &mut plan::AttachPlan,
        modules: &[ReconciledModule],
        manifests: &[Manifest],
        pinned: &PinnedObjects,
    ) -> Result<()> {
        let mut stable_by_object = BTreeMap::new();
        for object in modules
            .iter()
            .map(|module| module.object)
            .chain(
                manifests
                    .iter()
                    .filter_map(|manifest| manifest_module_object(manifest, pinned)),
            )
            .chain(candidate.modules.iter().map(|module| module.object))
        {
            let key = pinned.owned_timing_key(object).ok_or_else(|| {
                anyhow!("provider object {object:?} has no exact opened identity")
            })?;
            let id = self.resolve_module_id(&key)?;
            if stable_by_object
                .insert(object, id)
                .is_some_and(|known| known != id)
            {
                bail!("provider object {object:?} resolved to unequal stable module IDs");
            }
        }

        let mut remap = BTreeMap::new();
        let mut stable_ids = BTreeSet::new();
        for module in &candidate.modules {
            let stable = stable_by_object[&module.object];
            if remap
                .insert(module.id, stable)
                .is_some_and(|known| known != stable)
            {
                bail!(
                    "candidate module ID {:?} names unequal providers",
                    module.id
                );
            }
            if !stable_ids.insert(stable) {
                bail!("candidate contains the same exact provider more than once");
            }
        }
        let remapped_slots = candidate
            .slots
            .iter()
            .map(|slot| {
                let mut slot = slot.clone();
                slot.module_ids = slot
                    .module_ids
                    .iter()
                    .map(|id| {
                        remap.get(id).copied().ok_or_else(|| {
                            anyhow!(
                                "slot {} refers to unknown candidate module {id:?}",
                                slot.index
                            )
                        })
                    })
                    .collect::<Result<_>>()?;
                Ok(slot)
            })
            .collect::<Result<Vec<_>>>()?;
        candidate.rebind_module_ids(remapped_slots, &remap);
        for module in &mut candidate.modules {
            module.id = remap[&module.id];
        }
        Ok(())
    }

    fn module_id_for_object(
        &self,
        pinned: &PinnedObjects,
        object: PinnedObjectId,
    ) -> Result<plan::ModuleId> {
        let key = pinned
            .owned_timing_key(object)
            .ok_or_else(|| anyhow!("provider object {object:?} has no exact opened identity"))?;
        self.module_ids
            .get(&key)
            .copied()
            .ok_or_else(|| anyhow!("provider exact identity has no stable module ID"))
    }

    /// The fallible surface of `merge_current` as pure checks: every `?`
    /// below runs first, in the same order, in `merge_current` itself, so
    /// this proves exactly what the merge would fail on — without cloning
    /// or walking the history. `preflight_candidate_publication` uses it
    /// instead of a throwaway merge (E25); `merge_current` re-runs it as
    /// its first step and keeps its own interleaved checks, so proof and
    /// merge cannot disagree on current inputs. If a new fallible lookup
    /// is ever added to the merge, it must be added here first, in merge
    /// order — the equivalence tests pin every current failure mode.
    fn resolve_merge_inputs(
        &self,
        plan: &plan::AttachPlan,
        pinned: &PinnedObjects,
        modules: &[ReconciledModule],
        manifests: &[Manifest],
        manifest_ordinals: &[u32],
    ) -> Result<()> {
        if manifests.len() != manifest_ordinals.len() {
            bail!("accepted manifest history lost its source ordinals");
        }
        for module in modules {
            self.module_id_for_object(pinned, module.object)?;
            pinned
                .owned_timing_key(module.object)
                .ok_or_else(|| anyhow!("scanned provider has no exact opened identity"))?;
            for (table_index, table) in module.scanned.tables.iter().enumerate() {
                let objects = module.entry_objects.get(table_index).ok_or_else(|| {
                    anyhow!("reconciled provider table has no parallel target identities")
                })?;
                if objects.len() != table.entries.len() {
                    bail!("reconciled provider table target identities are incomplete");
                }
                for object in objects {
                    pinned.owned_timing_key(*object).ok_or_else(|| {
                        anyhow!("decoded target object has no exact opened identity")
                    })?;
                }
            }
        }
        for manifest in manifests {
            let object = manifest_module_object(manifest, pinned).ok_or_else(|| {
                anyhow!(
                    "accepted manifest {} has no exact pinned provider identity",
                    manifest.module_path
                )
            })?;
            self.module_id_for_object(pinned, object)?;
            pinned
                .owned_timing_key(object)
                .ok_or_else(|| anyhow!("manifest provider has no exact opened identity"))?;
        }
        for (object, _) in plan.refused_modules() {
            self.module_id_for_object(pinned, object)?;
        }
        Ok(())
    }

    fn merge_current(
        &mut self,
        plan: &plan::AttachPlan,
        pinned: &PinnedObjects,
        modules: &[ReconciledModule],
        manifests: &[Manifest],
        manifest_ordinals: &[u32],
        counters: &DiscoveryCounters,
    ) -> Result<()> {
        // Proves the fallible surface before cloning: same checks, same
        // order, same first failure as the interleaved checks below.
        self.resolve_merge_inputs(plan, pinned, modules, manifests, manifest_ordinals)?;
        let mut history = self.visible_history().clone();
        let live_views: BTreeSet<_> = modules.iter().map(|module| module.scanned.view).collect();
        prune_selection_inventory(&mut history, &live_views);
        let current = discovery_evidence(plan, pinned, counters);

        // §4.12 by capture end. Each fresh reading replaces the retained one;
        // a publication with nothing to read keeps what the capture already
        // derived, because a retiring view does not unsay that the scan
        // reached this object. A tombstoned module is skipped outright: a
        // proof a later exact identity collision invalidated is never
        // restored.
        for (object, outcome) in recorroborate_at_capture_end(pinned, modules, manifests, counters)
        {
            let Ok(id) = self.module_id_for_object(pinned, object) else {
                continue;
            };
            if history.corroboration_tombstones.contains(&id) {
                continue;
            }
            // Only a tombstone revokes a standing corroboration. A later
            // publication whose pin set no longer holds the scan's decoded
            // tables — a subprocess exited, its view retired — is less
            // informed, not newer evidence that nothing corroborated this.
            let standing = history.recorroborated.get(&id).copied();
            if standing.is_some_and(corroboration_corroborates)
                && !corroboration_corroborates(outcome)
            {
                continue;
            }
            if outcome == Corroboration::Conflict {
                history.conflicted.insert(id);
            }
            history.recorroborated.insert(id, outcome);
        }

        for mut module in current.modules {
            // A tombstone and a re-derived capture-end outcome are both the
            // final word on this module, not another opinion to union in — so
            // both are applied *after* the merge, and the tombstone wins.
            let settled = if history.corroboration_tombstones.contains(&module.id) {
                Some((false, vec!["uncorroborated"]))
            } else {
                history.recorroborated.get(&module.id).map(|outcome| {
                    (
                        corroboration_corroborates(*outcome),
                        vec![corroboration_label(*outcome)],
                    )
                })
            };
            if let Some((corroborated, corroboration)) = settled.clone() {
                module.corroborated = corroborated;
                module.corroboration = corroboration;
            }
            let id = module.id;
            if let Some(known) = history.modules.get_mut(&id) {
                merge_discovered_module(known, module);
                if let Some((corroborated, corroboration)) = settled {
                    known.corroborated = corroborated;
                    known.corroboration = corroboration;
                }
            } else {
                history.modules.insert(id, module);
            }
        }

        for module in modules {
            let owner = self.module_id_for_object(pinned, module.object)?;
            let provider = pinned
                .owned_timing_key(module.object)
                .ok_or_else(|| anyhow!("scanned provider has no exact opened identity"))?;
            history.standard_exports.entry(owner).or_default().insert(
                if module
                    .scanned
                    .exports
                    .iter()
                    .any(|name| name == "C_GetInterface")
                {
                    StandardExportFact::Present
                } else {
                    StandardExportFact::Absent
                },
            );
            for table in &module.scanned.tables {
                let requirement = match table.version.0 {
                    2 => Some(StandardRequirementFact::Legacy),
                    3.. => Some(StandardRequirementFact::V3),
                    _ => None,
                };
                if let Some(requirement) = requirement {
                    history
                        .standard_requirements
                        .entry(owner)
                        .or_default()
                        .insert(requirement);
                }
            }
            let mut targets = BTreeMap::new();
            let mut skips = BTreeMap::new();
            let mut surfaces = BTreeMap::new();
            let mut tables = BTreeMap::new();
            for (table_index, table) in module.scanned.tables.iter().enumerate() {
                let functions =
                    table.entries.len() + table.null_entries.len() + table.unpinned.len();
                let surface = (table.version, table.walk.to_string(), functions);
                let surface_occurrence = surfaces.entry(surface.clone()).or_insert(0usize);
                let scan_surface = SurfaceOccurrence::Scan {
                    module: owner,
                    version: surface.0,
                    walk: surface.1.clone(),
                    functions,
                    occurrence: *surface_occurrence,
                };
                history
                    .surfaces
                    .entry(scan_surface.clone())
                    .or_insert_with(|| plan::SurfaceSummary {
                        source: format!(
                            "{} table {}.{}",
                            module.scanned.path, table.version.0, table.version.1
                        ),
                        walk: table.walk.to_string(),
                        acquisition: "ok".into(),
                        functions,
                    });
                let mut inventory_bases = table
                    .file_offset
                    .map(|table_file_offset| {
                        vec![InventorySurfaceBase {
                            provider: provider.clone(),
                            table_file_offset,
                            kind: InventorySurfaceKind::Legacy,
                            name: PrivateSelectionName::Legacy,
                            version: inventory_version_class(table.version),
                            flags: 0,
                            manifest_identity: None,
                        }]
                    })
                    .unwrap_or_default();
                for interface in module
                    .scanned
                    .interfaces
                    .iter()
                    .filter(|interface| interface.table == Some(table_index))
                {
                    let interface_surface = SurfaceOccurrence::Interface {
                        module: owner,
                        index: interface.index,
                        name_class: interface.name_class,
                        version: table.version,
                        walk: table.walk.to_string(),
                        functions,
                    };
                    history
                        .surfaces
                        .entry(interface_surface.clone())
                        .or_insert_with(|| plan::SurfaceSummary {
                            source: format!(
                                "interface[{}] {}",
                                interface.index, interface.name_class
                            ),
                            walk: table.walk.to_string(),
                            acquisition: "ok".into(),
                            functions,
                        });
                    if let Some(table_file_offset) = table.file_offset {
                        inventory_bases.push(InventorySurfaceBase {
                            provider: provider.clone(),
                            table_file_offset,
                            kind: InventorySurfaceKind::Interface,
                            name: private_selection_name(interface, module.scanned.view),
                            version: inventory_version_class(table.version),
                            flags: interface.flags,
                            manifest_identity: None,
                        });
                    }
                }
                let admitted =
                    admit_inventory_keys(&mut history, canonical_inventory_keys(inventory_bases));
                if !admitted.is_empty() {
                    history.selection_inventory.insert(
                        ExactSelectionTable {
                            view: module.scanned.view,
                            provider: provider.clone(),
                            address: table.address,
                            file_offset: table.file_offset.expect("admitted table offset"),
                        },
                        admitted,
                    );
                }
                let table_fact = (table.version, table.entries.len());
                let table_occurrence = tables.entry(table_fact).or_insert(0usize);
                // The same witness `plan::lower_scanned` scores by, so the
                // published linkage and the plan's naming never disagree.
                let exports = ObjectExports {
                    object: module.scanned.key,
                    symbols: &module.exports,
                };
                let table_score = table_evidence_score(
                    table_index,
                    &module.scanned.tables,
                    &module.scanned.interfaces,
                    &[],
                    &[],
                    &exports,
                );
                let linkage = table_linkage(&table_score);
                let exports_agreeing = export_agreement(table, &exports).agreeing;
                history
                    .tables
                    .entry(TableOccurrence::Scan {
                        module: owner,
                        version: table_fact.0,
                        entries: table_fact.1,
                        occurrence: *table_occurrence,
                    })
                    .and_modify(|known| {
                        // Publication proof is monotonic: a live return
                        // upgrades the initial heuristic linkage, but a later
                        // less-informed reading — a view retired with its
                        // proof — never downgrades a corroborated one.
                        if known.linkage == "heuristic" && linkage != "heuristic" {
                            known.linkage = linkage;
                        }
                        known.exports_agreeing = known.exports_agreeing.max(Some(exports_agreeing));
                    })
                    .or_insert(plan::TableSummary {
                        version: table_fact.0,
                        entries: table_fact.1,
                        source: "scan",
                        file_offset: table.file_offset,
                        linkage,
                        exports_agreeing: Some(exports_agreeing),
                    });
                *table_occurrence += 1;
                *surface_occurrence += 1;

                let objects = module.entry_objects.get(table_index).ok_or_else(|| {
                    anyhow!("reconciled provider table has no parallel target identities")
                })?;
                if objects.len() != table.entries.len() {
                    bail!("reconciled provider table target identities are incomplete");
                }
                for (entry, object) in table.entries.iter().zip(objects) {
                    let object = pinned.owned_timing_key(*object).ok_or_else(|| {
                        anyhow!("decoded target object has no exact opened identity")
                    })?;
                    let fact = (entry.name.to_string(), object, entry.file_offset);
                    let occurrence = targets.entry(fact.clone()).or_insert(0usize);
                    history.decoded.insert(DecodedOccurrence::Target {
                        module: owner,
                        name: fact.0,
                        object: fact.1,
                        file_offset: fact.2,
                        occurrence: *occurrence,
                    });
                    *occurrence += 1;
                }
                for skipped in table
                    .null_entries
                    .iter()
                    .map(|name| Skipped {
                        subject: (*name).to_string(),
                        reason: "null pointer".into(),
                    })
                    .chain(table.unpinned.iter().cloned())
                {
                    let fact = (skipped.subject.clone(), skipped.reason.clone());
                    let occurrence = skips.entry(fact.clone()).or_insert(0usize);
                    let key = DecodedOccurrence::ScanSkip {
                        module: owner,
                        subject: fact.0,
                        reason: fact.1,
                        occurrence: *occurrence,
                    };
                    history.decoded.insert(key.clone());
                    history.skips.entry(key).or_insert(skipped);
                    *occurrence += 1;
                }
            }
        }

        // Occurrences of one exact target across every accepted manifest: a
        // repeated claim stays its own occurrence (ordinals remain distinct),
        // while the first one meets the scan's occurrence 0 and merges with it.
        let mut manifest_targets = BTreeMap::new();
        for (manifest, manifest_ordinal) in manifests.iter().zip(manifest_ordinals) {
            let object = manifest_module_object(manifest, pinned).ok_or_else(|| {
                anyhow!(
                    "accepted manifest {} has no exact pinned provider identity",
                    manifest.module_path
                )
            })?;
            let owner = self.module_id_for_object(pinned, object)?;
            let provider = pinned
                .owned_timing_key(object)
                .ok_or_else(|| anyhow!("manifest provider has no exact opened identity"))?;
            let export = match manifest.selection_evidence.acquisition {
                SelectionAcquisition::Queried => StandardExportFact::Present,
                SelectionAcquisition::ExportAbsent => StandardExportFact::Absent,
                SelectionAcquisition::ExportOutsideModule => StandardExportFact::Outside,
            };
            history
                .standard_exports
                .entry(owner)
                .or_default()
                .insert(export);
            for surface in &manifest.surfaces {
                if let Some(requirement) = surface.version.and_then(|version| match version.major {
                    2 => Some(StandardRequirementFact::Legacy),
                    3.. => Some(StandardRequirementFact::V3),
                    _ => None,
                }) {
                    history
                        .standard_requirements
                        .entry(owner)
                        .or_default()
                        .insert(requirement);
                }
            }
            let mut manifest_surface_keys = BTreeMap::new();
            let manifest_surface_candidates: Vec<_> = manifest
                .surfaces
                .iter()
                .enumerate()
                .filter(|(_, surface)| selection_surface_usable(surface))
                .filter_map(|(surface_index, surface)| {
                    manifest_inventory_surface_key(
                        provider.clone(),
                        *manifest_ordinal,
                        surface_index,
                        surface,
                    )
                })
                .collect();
            for surface_key in admit_inventory_keys(&mut history, manifest_surface_candidates) {
                if let Some((ordinal, surface_index)) = surface_key.base.manifest_identity
                    && ordinal == *manifest_ordinal
                {
                    manifest_surface_keys.insert(surface_index as usize, surface_key);
                }
            }
            for (surface_index, surface) in manifest.surfaces.iter().enumerate() {
                let surface_key = SurfaceOccurrence::Manifest {
                    module: owner,
                    manifest: *manifest_ordinal,
                    surface: surface_index,
                };
                history
                    .surfaces
                    .entry(surface_key)
                    .or_insert_with(|| plan::SurfaceSummary {
                        source: plan::source_label(&surface.source),
                        walk: manifest_walk_label(&surface.walk),
                        acquisition: manifest_acquisition_label(&surface.acquisition),
                        functions: surface.functions.len(),
                    });
                history
                    .tables
                    .entry(TableOccurrence::Manifest {
                        module: owner,
                        manifest: *manifest_ordinal,
                        surface: surface_index,
                    })
                    .or_insert(plan::TableSummary {
                        version: surface
                            .version
                            .map_or((0, 0), |version| (version.major, version.minor)),
                        entries: surface.functions.len(),
                        source: "manifest",
                        file_offset: None,
                        linkage: "manifest",
                        exports_agreeing: None,
                    });
                for (function_index, function) in surface.functions.iter().enumerate() {
                    let key = DecodedOccurrence::ManifestFunction {
                        module: owner,
                        manifest: *manifest_ordinal,
                        surface: surface_index,
                        function: function_index,
                    };
                    match manifest_function_target(manifest, pinned, &function.resolution) {
                        Some((object, file_offset)) => {
                            let fact = (function.name.clone(), object, file_offset);
                            let occurrence = manifest_targets.entry(fact.clone()).or_insert(0usize);
                            history.decoded.insert(DecodedOccurrence::Target {
                                module: owner,
                                name: fact.0,
                                object: fact.1,
                                file_offset: fact.2,
                                occurrence: *occurrence,
                            });
                            *occurrence += 1;
                        }
                        // Nothing the scan can have decoded too: it is counted
                        // under its own manifest-record identity, and skipped.
                        None => {
                            history.decoded.insert(key.clone());
                        }
                    }
                    if let Some(skipped) = manifest_function_skip(
                        manifest,
                        pinned,
                        &function.name,
                        &function.resolution,
                    ) {
                        history.skips.entry(key).or_insert(skipped);
                    }
                }
            }
            if history
                .manifest_selection_ordinals
                .insert(*manifest_ordinal)
            {
                if manifest.selection_evidence.selection_truncated {
                    history.selection_truncated = true;
                    insert_selection_loss_for(
                        &mut history,
                        "offline interface selection",
                        OFFLINE_SELECTION_LOSS_REASON,
                    );
                }
                for query in &manifest.selection_evidence.queries {
                    let mut matches = Vec::new();
                    let mut match_loss = false;
                    for found in &query.inventory_matches {
                        let Some(surface) = manifest_surface_keys.get(&found.surface) else {
                            match_loss = true;
                            continue;
                        };
                        matches.push(LiveInventoryMatch {
                            surface: surface.clone(),
                            name_agrees: found.name_agrees,
                            version_agrees: found.version_agrees,
                        });
                    }
                    if query.helper_failure.is_some() || match_loss {
                        history.selection_truncated = true;
                        insert_selection_loss_for(
                            &mut history,
                            "offline interface selection",
                            OFFLINE_SELECTION_LOSS_REASON,
                        );
                    }
                    record_selection_in(
                        &mut history,
                        LiveSelectionTuple {
                            module: owner,
                            request: query.request,
                            rv: query.rv,
                            result: query.result,
                            inventory_matches: matches,
                            authority: query.authority,
                            count: 1,
                        },
                        false,
                    );
                }
            }
        }

        let retired_scan_gaps: Vec<_> = history
            .losses
            .iter()
            .filter(|(_, skipped)| scan_gap_this_capture_attached(&plan.modules, skipped))
            .map(|(key, _)| key.clone())
            .collect();
        for key in retired_scan_gaps {
            history.losses.remove(&key);
            history.scan_gap_tombstones.insert(key);
        }
        for skipped in &counters.object_skips {
            let key = (skipped.subject.clone(), skipped.reason.clone());
            if scan_gap_this_capture_attached(&plan.modules, skipped) {
                history.scan_gap_tombstones.insert(key);
            } else if !history.scan_gap_tombstones.contains(&key) {
                history.losses.entry(key).or_insert_with(|| skipped.clone());
            }
        }
        for (object, refused) in plan.refused_modules() {
            let id = self.module_id_for_object(pinned, object)?;
            // One record per module, a high-water mark like every omission
            // above: a whole refusal stays the capture's record of it and
            // outranks any growth omission (G-03); among growth omissions the
            // largest omitted count the capture saw is kept, so a growth that
            // later shrinks never under-reports what was missed. That count
            // is a lower bound on the endpoints omitted over the capture.
            // Whole capacity refusals rank by what they needed the same way
            // (PD-T6-1); any other whole refusal stays first-wins.
            let rank = |reason: &str| {
                (
                    !plan::is_growth_omission(reason),
                    plan::growth_omitted_count(reason).unwrap_or(0),
                )
            };
            let known = history
                .refusals
                .entry(id)
                .or_insert_with(|| refused.clone());
            let larger_whole = matches!(
                (
                    plan::whole_refusal_needed_count(&known.reason),
                    plan::whole_refusal_needed_count(&refused.reason),
                ),
                (Some(known), Some(refused)) if refused > known
            );
            if larger_whole
                || (plan::is_growth_omission(&known.reason)
                    && rank(&refused.reason) >= rank(&known.reason))
            {
                known.clone_from(refused);
            }
        }
        for fallback in current.manifest_object_fallbacks {
            let key = (fallback.manifest, fallback.object);
            if !history.fallback_tombstones.contains(&key) {
                history.fallbacks.entry(key).or_insert(fallback);
            }
        }
        // All three stay pure high-water marks of what the plan reports.
        // What the capture-end re-derivation adds or removes is held in
        // `recorroborated`, and `discovery` combines the two once — a latch
        // that could drop below `current` would let one module's re-derivation
        // absorb another module's tombstone gap. The spill latch below is the
        // separately-kept history `plan.rs` promises: the plan's counter
        // resolves on a live merge, this one never does.
        history.conflicts = history.conflicts.max(current.conflicts);
        history.uncorroborated = history.uncorroborated.max(current.uncorroborated);
        history.uncorroborated_candidates = history
            .uncorroborated_candidates
            .max(plan.uncorroborated_candidates);
        history.scan_unavailable = history.scan_unavailable.take().or(current.scan_unavailable);
        history.scan_ms = history.scan_ms.max(current.scan_ms);
        history.vendor_interfaces = history.vendor_interfaces.max(plan.vendor_interfaces);
        if history.interface_list.is_empty() || history.interface_list == "absent" {
            history.interface_list.clone_from(&plan.interface_list);
        }
        self.replace_visible_history(history);
        Ok(())
    }

    fn apply_to_plan(&self, plan: &mut plan::AttachPlan) {
        let history = self.visible_history();
        plan.entries_seen = history.decoded.len();
        plan.surfaces = history.surfaces.values().cloned().collect();
        plan.skipped = self
            .visible_history()
            .skips
            .values()
            .chain(history.losses.values())
            .cloned()
            .collect();
        plan.modules_skipped = history.refusals.values().cloned().collect();
        plan.vendor_interfaces = history.vendor_interfaces;
        if !history.interface_list.is_empty() {
            plan.interface_list.clone_from(&history.interface_list);
        }
    }

    fn discovery(&self, plan: &plan::AttachPlan) -> render::DiscoveryEvidence {
        let history = self.visible_history();
        let modules = history
            .modules
            .values()
            .cloned()
            .map(|mut module| {
                module.tables = history
                    .tables
                    .iter()
                    .filter(|(occurrence, _)| occurrence.module() == module.id)
                    .map(|(_, table)| table.clone())
                    .collect();
                module.skipped = history
                    .skips
                    .iter()
                    .filter(|(occurrence, _)| occurrence.module() == module.id)
                    .map(|(_, skipped)| render::capture_skipped_out(skipped))
                    .collect();
                module
            })
            .collect();
        // The three facts, combined once: the attach-time high-water mark, the
        // corroborations the capture-end §4.12 pass derived out of it, and the
        // revoked proofs it never counted. Kept apart until here so no order of
        // publications can let one cancel another.
        let derived_conflicts = history.conflicted.len() as u64;
        let derived_corroborated = history
            .recorroborated
            .values()
            .filter(|outcome| corroboration_corroborates(**outcome))
            .count() as u64;
        render::DiscoveryEvidence {
            modules,
            conflicts: history.conflicts.saturating_add(derived_conflicts),
            uncorroborated: history
                .uncorroborated
                .saturating_sub(derived_corroborated)
                .saturating_add(history.uncorroborated_tombstones),
            module_ambiguous: plan.module_ambiguous as u64,
            // Lifetime spill exposure: the latched maximum, never below the
            // current plan — projection paths that skip a merge (restore,
            // invalidation) must not hide what the engine holds right now.
            uncorroborated_candidates: history
                .uncorroborated_candidates
                .max(plan.uncorroborated_candidates),
            modules_skipped: history.refusals.values().map(skipped_out).collect(),
            manifest_object_fallbacks: history.fallbacks.values().cloned().collect(),
            scan_unavailable: history.scan_unavailable.clone(),
            scan_ms: history.scan_ms,
            ..render::DiscoveryEvidence::default()
        }
    }

    #[cfg(test)]
    fn module_key(&self, id: plan::ModuleId) -> Option<&PinnedTimingKey> {
        self.module_keys.get(&id)
    }
}

fn extend_occurrences<T: Clone + PartialEq>(retained: &mut Vec<T>, incoming: Vec<T>) {
    let mut seen = Vec::new();
    for item in incoming {
        let occurrence = seen.iter().filter(|known| *known == &item).count();
        if retained.iter().filter(|known| *known == &item).count() <= occurrence {
            retained.push(item.clone());
        }
        seen.push(item);
    }
}

/// The union of two source sets in the one order the schema allows: exactly
/// `["scan"]`, `["manifest"]`, or `["scan", "manifest"]`
/// (docs/schema/observed-profile-v2.md, "in that canonical order"). This is the
/// order `PinnedObjects::sources` already emits; a union that appends in
/// arrival order does not, and a manifest-first module the scan only reaches
/// later renders the illegal `["manifest", "scan"]`.
fn canonical_sources(retained: &[&'static str], incoming: &[&'static str]) -> Vec<&'static str> {
    ["scan", "manifest"]
        .into_iter()
        .filter(|source| retained.contains(source) || incoming.contains(source))
        .collect()
}

/// Merges one snapshot's `objects[]` into the retained set. `objects[]` is
/// "every object this module's planned slots attach into" — one entry per
/// object — and each snapshot already holds one entry per object. A later
/// snapshot of the *same* object with a grown source set is that object
/// described better, not a second object, so it coalesces rather than
/// accumulating. Entries that differ in anything but `sources` are left
/// distinct: this merge unions ownership, it never discards an identity fact.
fn merge_object_summaries(
    retained: &mut Vec<render::ObjectSummary>,
    incoming: Vec<render::ObjectSummary>,
) {
    let identity = |object: &render::ObjectSummary| render::ObjectSummary {
        sources: Vec::new(),
        ..object.clone()
    };
    for object in incoming {
        match retained
            .iter_mut()
            .find(|known| identity(known) == identity(&object))
        {
            Some(known) => known.sources = canonical_sources(&known.sources, &object.sources),
            None => retained.push(object),
        }
    }
}

fn merge_discovered_module(
    retained: &mut render::DiscoveredModule,
    incoming: render::DiscoveredModule,
) {
    merge_object_summaries(&mut retained.objects, incoming.objects);
    extend_occurrences(&mut retained.tables, incoming.tables);
    extend_occurrences(&mut retained.skipped, incoming.skipped);
    retained.interfaces = retained.interfaces.max(incoming.interfaces);
    retained.corroborated |= incoming.corroborated;
    retained.sources = canonical_sources(&retained.sources, &incoming.sources);
    for outcome in incoming.corroboration {
        if !retained.corroboration.contains(&outcome) {
            retained.corroboration.push(outcome);
        }
    }
}

struct ScanInput {
    modules: Vec<ScannedModule>,
    pins: PinnedObjects,
    counters: DiscoveryCounters,
}

type InventoryScan = (ProcessViewId, Vec<ScannedModule>, PinnedObjects);
type InventoryNewView = (ProcessView, Vec<ScannedModule>, PinnedObjects);
/// Successful scans, pids whose rescan failed (the failure path published),
/// pids whose rescan the tick quantum deferred before it ran (nothing
/// published for the view itself; only the tick-level deferral skip), and
/// the tick's skips. Failed and deferred alike stay queued for retry; only
/// failed ones are settled losses.
type InventoryScanOutcome = (
    Vec<InventoryScan>,
    BTreeSet<u32>,
    BTreeSet<u32>,
    Vec<Skipped>,
);
type PendingViewRetirements = BTreeMap<ProcessViewId, RetirementCause>;
type TerminalSelectionHandoffs = BTreeMap<u16, Vec<DiscoveryRecord>>;
type DiscoveryCollector<'a> =
    dyn FnMut(&mut dyn EngineSession) -> Result<(Vec<DiscoveryRecord>, u64)> + 'a;
/// The tick quantum's clock: one `Option<u64>` mono-ns poll per call, in
/// the scheduler-hook style (`None` is a failed clock read). Production
/// passes `crate::attach::monotonic_ns`; tests pass a scripted closure.
/// Threaded through the refreshed-scan and newcomer-admission loops so an
/// injected clock can expire mid-path; the poll count and order match the
/// direct reads it replaces exactly.
type TickClock<'a> = dyn FnMut() -> Option<u64> + 'a;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RefreshRequest {
    first_seen_ns: Option<u64>,
    serial: u64,
    owner: Option<ProcessViewId>,
}
type SlotCompletion = (u32, Option<u64>);
type TargetAttachResult = (Vec<u32>, Vec<SlotCompletion>);

/// Exactly the `Session` surface the discovery/pause path already uses. It
/// exists so the Engine/coordinator lifecycle can be driven without loading a
/// BPF object; `Session` is the only production implementation and every method
/// is a plain delegation to the existing inherent one.
pub(crate) trait EngineSession {
    fn capture_policy(&self) -> CapturePolicy;
    fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>>;
    /// Moves up to `quantum` DISCOVERY items off the kernel ring into the
    /// session's FIFO without applying any (RB-2), without letting staged
    /// plus `engine_held` exceed the shared 4,096-item allowance.
    /// `discovery_dequeue` serves that FIFO first, so ring order is kept.
    fn stage_discovery(
        &mut self,
        quantum: usize,
        engine_held: usize,
    ) -> Result<crate::attach::DiscoveryStageOutcome>;
    /// DISCOVERY items currently held in the session FIFO: staged items
    /// hold shared-allowance credits until a dequeue transfers them.
    fn staged_discovery_len(&self) -> usize;
    fn counter_snapshot(&self) -> Result<CounterSnapshot>;
    fn process_creation_tracking_unavailable(&self) -> Option<&str>;
    fn read_selection_table(
        &mut self,
        view: &ProcessView,
        address: u64,
        layout: LinuxLayout,
        budget: &mut CaptureWorkBudget,
    ) -> std::result::Result<(MapEntry, ScannedTable), ()>;
    fn detach_failures(&self) -> &[String];
    fn lifecycle_tracking_unavailable(&self) -> Option<&str>;
    fn preflight_targets(&self, targets: &[plan::Slot], objects: &PinnedObjects) -> Result<()>;
    fn attach_targets(
        &mut self,
        targets: &[plan::Slot],
        objects: &PinnedObjects,
    ) -> Result<TargetAttachResult>;
    fn replace_targets(
        &mut self,
        plan: &mut plan::AttachPlan,
        replace: &[plan::Slot],
        objects: &PinnedObjects,
    ) -> Result<ReplacementOutcome>;
    fn detach_slots(&mut self, slots: &[plan::Slot]) -> Result<DetachOutcome>;
    fn has_dynamic_export(
        &self,
        context: LoaderContextId,
        target: (PinnedObjectId, u64),
        cookie: u64,
        abi: HookAbi,
    ) -> bool;
    fn attach_dynamic_export(
        &mut self,
        context: LoaderContextId,
        pid: u32,
        target: (PinnedObjectId, u64),
        cookie: u64,
        abi: HookAbi,
        objects: &PinnedObjects,
    ) -> Result<(bool, Option<u64>)>;
    fn attach_dynamic_loader(
        &mut self,
        context: LoaderContextId,
        pid: u32,
        object: PinnedObjectId,
        file_offset: u64,
        cookie: u64,
        objects: &PinnedObjects,
    ) -> std::result::Result<bool, DynamicLoaderAttachFailure>;
    fn detach_dynamic_context(
        &mut self,
        context: LoaderContextId,
    ) -> (Vec<DynamicExportIdentity>, bool);
    fn arm_pause(&mut self) -> Result<()>;
    fn pause_state(&self) -> Result<Option<u64>>;
    fn remove_pause(&mut self) -> Result<Option<u64>>;
}

impl EngineSession for Session {
    fn capture_policy(&self) -> CapturePolicy {
        Session::capture_policy(self)
    }

    fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>> {
        Session::discovery_dequeue(self)
    }

    fn stage_discovery(
        &mut self,
        quantum: usize,
        engine_held: usize,
    ) -> Result<crate::attach::DiscoveryStageOutcome> {
        Session::stage_discovery(self, quantum, engine_held)
    }

    fn staged_discovery_len(&self) -> usize {
        Session::staged_discovery_len(self)
    }

    fn counter_snapshot(&self) -> Result<CounterSnapshot> {
        Session::counter_snapshot(self)
    }

    fn process_creation_tracking_unavailable(&self) -> Option<&str> {
        Session::process_creation_tracking_unavailable(self)
    }

    fn read_selection_table(
        &mut self,
        view: &ProcessView,
        address: u64,
        layout: LinuxLayout,
        budget: &mut CaptureWorkBudget,
    ) -> std::result::Result<(MapEntry, ScannedTable), ()> {
        Engine::read_selection_table(view, address, layout, budget)
    }

    fn detach_failures(&self) -> &[String] {
        Session::detach_failures(self)
    }

    fn lifecycle_tracking_unavailable(&self) -> Option<&str> {
        Session::lifecycle_tracking_unavailable(self)
    }

    fn preflight_targets(&self, targets: &[plan::Slot], objects: &PinnedObjects) -> Result<()> {
        Session::preflight_targets(self, targets, objects)
    }

    fn attach_targets(
        &mut self,
        targets: &[plan::Slot],
        objects: &PinnedObjects,
    ) -> Result<TargetAttachResult> {
        Session::attach_targets(self, targets, objects)
    }

    fn replace_targets(
        &mut self,
        plan: &mut plan::AttachPlan,
        replace: &[plan::Slot],
        objects: &PinnedObjects,
    ) -> Result<ReplacementOutcome> {
        Session::replace_targets(self, plan, replace, objects)
    }

    fn detach_slots(&mut self, slots: &[plan::Slot]) -> Result<DetachOutcome> {
        Session::detach_slots(self, slots)
    }

    fn has_dynamic_export(
        &self,
        context: LoaderContextId,
        target: (PinnedObjectId, u64),
        cookie: u64,
        abi: HookAbi,
    ) -> bool {
        Session::has_dynamic_export(self, context, target, cookie, abi)
    }

    fn attach_dynamic_export(
        &mut self,
        context: LoaderContextId,
        pid: u32,
        target: (PinnedObjectId, u64),
        cookie: u64,
        abi: HookAbi,
        objects: &PinnedObjects,
    ) -> Result<(bool, Option<u64>)> {
        Session::attach_dynamic_export(self, context, pid, target, cookie, abi, objects)
    }

    fn attach_dynamic_loader(
        &mut self,
        context: LoaderContextId,
        pid: u32,
        object: PinnedObjectId,
        file_offset: u64,
        cookie: u64,
        objects: &PinnedObjects,
    ) -> std::result::Result<bool, DynamicLoaderAttachFailure> {
        Session::attach_dynamic_loader(self, context, pid, object, file_offset, cookie, objects)
    }

    fn detach_dynamic_context(
        &mut self,
        context: LoaderContextId,
    ) -> (Vec<DynamicExportIdentity>, bool) {
        Session::detach_dynamic_context(self, context)
    }

    fn arm_pause(&mut self) -> Result<()> {
        Session::arm_pause(self)
    }

    fn pause_state(&self) -> Result<Option<u64>> {
        Session::pause_state(self)
    }

    fn remove_pause(&mut self) -> Result<Option<u64>> {
        Session::remove_pause(self)
    }
}

/// An incomplete terminal pull owns its exact off-ring prefix: move-only, so
/// the prefix has exactly one owner (this error or the batch it moves
/// into). A work-quantum stop, a shared-storage stop and a transport
/// failure are three distinct meanings; none is ever an empty observation.
pub(crate) struct IncompleteTerminalDrain {
    pub(crate) records: Vec<DiscoveryRecord>,
    pub(crate) malformed: u64,
    pub(crate) unvalidated_records: u64,
    /// The drain stopped at its work quantum, not on a failure: the prefix is
    /// exact and the rest is still queued on the ring for the next drain.
    pub(crate) backlog: bool,
    /// The drain stopped at the shared 4,096-item allowance with the queue
    /// not observed empty: the prefix is exact, the rest stays unread, and
    /// the operation retries only after owned items settle. Never complete.
    pub(crate) capacity_blocked: bool,
    /// Prefix records already moved into the terminal batch when this signal
    /// was rebuilt after the move. `records` is empty then; the count keeps
    /// the retry diagnostic exact without a second owned copy.
    moved_to_batch: usize,
    cause: String,
}

impl IncompleteTerminalDrain {
    pub(crate) fn new(
        records: Vec<DiscoveryRecord>,
        malformed: u64,
        unvalidated_records: u64,
        cause: anyhow::Error,
    ) -> Self {
        Self {
            records,
            malformed,
            unvalidated_records,
            backlog: false,
            capacity_blocked: false,
            moved_to_batch: 0,
            cause: cause.to_string(),
        }
    }

    fn backlog(records: Vec<DiscoveryRecord>, malformed: u64) -> Self {
        Self {
            records,
            malformed,
            unvalidated_records: 0,
            backlog: true,
            capacity_blocked: false,
            moved_to_batch: 0,
            cause: DISCOVERY_DRAIN_BACKLOG_REASON.into(),
        }
    }

    pub(crate) fn capacity_blocked(
        records: Vec<DiscoveryRecord>,
        malformed: u64,
        unvalidated_records: u64,
    ) -> Self {
        Self {
            records,
            malformed,
            unvalidated_records,
            backlog: false,
            capacity_blocked: true,
            moved_to_batch: 0,
            cause: DISCOVERY_CAPACITY_BLOCKED_REASON.into(),
        }
    }
}

impl std::fmt::Debug for IncompleteTerminalDrain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IncompleteTerminalDrain")
            .field("records", &self.records.len())
            .field("malformed", &self.malformed)
            .field("unvalidated_records", &self.unvalidated_records)
            .field("backlog", &self.backlog)
            .field("capacity_blocked", &self.capacity_blocked)
            .field("moved_to_batch", &self.moved_to_batch)
            .field("cause", &self.cause)
            .finish()
    }
}

impl std::fmt::Display for IncompleteTerminalDrain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let retained = self.records.len().saturating_add(self.moved_to_batch);
        write!(
            formatter,
            "{}; {} terminal record{} retained for retry",
            self.cause,
            retained,
            if retained == 1 { "" } else { "s" },
        )
    }
}

impl std::error::Error for IncompleteTerminalDrain {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetirementCause {
    ExecRefresh,
    ExpectedRemoval,
    GenerationLost,
}

impl RetirementCause {
    fn merge(self, incoming: Self) -> Self {
        use RetirementCause::{ExecRefresh, ExpectedRemoval, GenerationLost};
        match (self, incoming) {
            (GenerationLost, _) | (_, GenerationLost) => GenerationLost,
            (ExpectedRemoval, _) | (_, ExpectedRemoval) => ExpectedRemoval,
            (ExecRefresh, ExecRefresh) => ExecRefresh,
        }
    }
}

pub(crate) struct DeferredDiscoveryItem {
    pub(crate) before_ns: u64,
    pub(crate) after_ns: u64,
    pub(crate) item: crate::events::DiscoveryItem,
    pub(crate) terminal_batch: Option<TerminalBatch>,
}

impl std::fmt::Debug for DeferredDiscoveryItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeferredDiscoveryItem")
            .field("before_ns", &self.before_ns)
            .field("after_ns", &self.after_ns)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for DeferredDiscoveryItem {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("pause-owned discovery item requires coordinator classification")
    }
}

impl std::error::Error for DeferredDiscoveryItem {}

/// A nested collector pulled fresh session records while a pressure service
/// pass owned the dispatch order. The pulled prefix is stashed behind the
/// parked records by the service pass itself; this error only tells the
/// nested caller its operation cannot complete in this episode. It is never
/// empty, complete, backlog or failure evidence.
#[derive(Debug)]
struct PressureOrderingBlocked;

impl std::fmt::Display for PressureOrderingBlocked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "a nested collection would dispatch fresh records ahead of parked discovery records",
        )
    }
}

impl std::error::Error for PressureOrderingBlocked {}

/// A dequeue refused for shared-storage capacity: the pull stopped at the
/// allowance with the queue not observed empty. Collectors map it to a
/// capacity-blocked drain that retains its exact prefix; it is never
/// empty, complete, backlog or failure evidence.
#[derive(Debug)]
pub(crate) struct DiscoveryCapacityBlocked;

impl std::fmt::Display for DiscoveryCapacityBlocked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "the live discovery pull stopped at the shared storage allowance with records still unread",
        )
    }
}

impl std::error::Error for DiscoveryCapacityBlocked {}

/// The single queued request a pressure service pass may complete: its pid
/// and the snapshot serial the pass revalidates before completing. A
/// renewed serial keeps its newer work; the pass never completes a serial
/// it did not select.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PressureSelection {
    pid: u32,
    serial: u64,
}

/// Identifies a parked pressure head across service opportunities, so one
/// bounded rotation belongs to exactly one held head. A new head starts a
/// new episode; the episode is discarded when the head settles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PressureHeadKey {
    pid_tgid: u64,
    kind: u8,
    case_id: u8,
    hook_ts_ns: u64,
}

/// One held head's service episode: the request snapshot taken when the
/// head parked (at most 256 entries, pid order) and the entries one
/// bounded rotation already ruled out. Entries are ruled out when their
/// selected transaction frees no slot — failed, deferred or absent — so
/// no entry is retried within the episode and rotation ends after at most
/// one pass over the snapshot with an honest head refusal.
#[derive(Debug, Clone)]
struct PressureEpisode {
    head: PressureHeadKey,
    snapshot: BTreeMap<u32, (u64, Option<ProcessViewId>)>,
    ruled_out: BTreeSet<u32>,
}

/// What a pressure service pass must leave untouched. `pids` names every
/// pid an undispatched owned record requires; `block_all` shields every
/// retained context when some owned record's ownership cannot be narrowed
/// to a pid at all.
#[derive(Debug, Clone, Default)]
struct PressureProtection {
    pids: BTreeSet<u32>,
    block_all: bool,
}

/// What one selected-request service transaction did: whether anything
/// changed, and whether it ran a real attempt (a scan, an arm, an
/// admission or a completion with a working clock). A quantum/clock
/// deferral changes nothing and attempts nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PressureServiceOutcome {
    changed: bool,
    attempted: bool,
}

struct ManifestInput {
    path: PathBuf,
    manifest: Manifest,
    pins: PinnedObjects,
    stale: Vec<StaleManifestObject>,
}

struct LiveCandidate {
    pinned: PinnedObjects,
    modules: Vec<ReconciledModule>,
    plan: plan::AttachPlan,
    delta: plan::AttachDelta,
    views: BTreeSet<ProcessViewId>,
    corroboration: Vec<(BTreeSet<PinnedObjectId>, &'static str)>,
    manifest_fallbacks: Vec<ManifestFallback>,
    selection_claims: BTreeMap<SelectionClaimKey, SelectionClaim>,
    selection_tables: BTreeMap<SelectionTableKey, SelectionTableFact>,
    selection_admission: Option<PendingSelectionAdmission>,
    manifest_selection_admissions: Vec<ManifestSelectionAdmission>,
    manifest_inventory_slots: BTreeMap<plan::AttachKey, plan::Slot>,
    loader_plan_proof: Option<LoaderPlanProof>,
}

struct LoaderPlanCache {
    revision: u64,
    broad_admit: bool,
    plan: plan::AttachPlan,
}

/// One Engine-minted exec rearm: a single refresh request's matched owner
/// whose rescan re-accepted the same static targets, lowered into the
/// existing detach/replace transaction because PID-bound links may be dead
/// while still recorded as attached. Minted only inside `Engine` from one
/// selected request plus actual custody/scope/target preparation; consumed
/// by the candidate path. No public scalar constructor, `Clone`, `Default`,
/// serialized form, or authority booleans.
struct PreparedExecRearm {
    view: ProcessViewId,
    serial: u64,
    slots: Vec<plan::Slot>,
}

/// Transient baseline for one loader transaction, never a second retained
/// history cache. Only stationary accepted publication may seed/carry a plan.
struct LoaderPlanProof {
    revision: u64,
    published_plan: plan::AttachPlan,
    discovery: render::DiscoveryEvidence,
}

struct StartPublicationSnapshot {
    plan: plan::AttachPlan,
    pinned: PinnedObjects,
    discovery: render::DiscoveryEvidence,
    modules: Vec<ReconciledModule>,
    corroboration: Vec<(BTreeSet<PinnedObjectId>, &'static str)>,
    manifest_fallbacks: Vec<ManifestFallback>,
    views: BTreeSet<ProcessViewId>,
    next_selection_binding_id: Option<u64>,
    selection_bindings: BTreeMap<u64, SelectionBindingFact>,
    selection_claims: BTreeMap<SelectionClaimKey, SelectionClaim>,
    selection_tables: BTreeMap<SelectionTableKey, SelectionTableFact>,
}

/// What one `apply_candidate` actually did. `committed` used to conflate all
/// three, so a preflight refusal and a conservative post-mutation retirement
/// both spoke with an accepted candidate's authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum ApplyDisposition {
    /// Nothing was mutated: canonical identity, plan, and links are unchanged,
    /// and every retry intent the candidate would have consumed is retained.
    #[default]
    Refused,
    /// Links were mutated and the Engine kept a cleaned, conservatively retired
    /// state. It consumed its retry intent but owns no positive follow-up.
    ConservativeRetirement,
    /// The candidate became the Engine's exact current state. Only this may
    /// authorize positive provider/history facts, pause completeness, dynamic
    /// export work, and loader follow-up.
    Accepted,
}

#[derive(Default)]
struct ApplyOutcome {
    disposition: ApplyDisposition,
    changed: bool,
    stale_views: BTreeSet<ProcessViewId>,
    missing_contexts: Vec<LoaderContextId>,
    static_completions: Vec<(BTreeSet<PinnedTimingKey>, Option<u64>)>,
    static_failures: BTreeSet<PinnedTimingKey>,
    newly_rejected_keys: BTreeSet<ObjectKey>,
    selection_authorized: bool,
    /// Inventory newcomers (`extra_views`) this apply left unpublished: none
    /// of their pins, modules or links were committed (U-07).
    unpublished_views: BTreeSet<ProcessViewId>,
    /// The one-shot detach of the retired and replaced targets failed —
    /// before or after any link mutation — and the apply blocked additions
    /// for the cycle (PD-T3-1).
    detach_failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiscoveryBatchOutcome {
    pub(crate) changed: bool,
    pub(crate) required_complete: bool,
}

/// Outcome of one between-frames backlog opportunity: whether dispatch
/// changed engine state (`changed`, the same resync signal a frame's batch
/// outcome carries), whether the pass moved work forward at all
/// (`progressed`: fresh acquisition, retained-queue shrinkage through
/// dispatch, a selected pressure attempt, or a state change), and whether
/// more backlog remains after it (`pending`). The run loop sleeps nothing
/// only when work remains *and* the pass progressed; a no-progress
/// pending outcome returns to the normal readiness wait instead of
/// hot-looping a stuck clock/capacity condition. A parked rotation reads
/// back through `pending`, never as a separate loop signal. Pure queue
/// cycling — a take or pull shed back whole — is not progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BacklogOutcome {
    pub(crate) changed: bool,
    pub(crate) progressed: bool,
    pub(crate) pending: bool,
}

type BatchStart =
    std::result::Result<Vec<QueuedDiscoveryRecord>, (anyhow::Error, Vec<QueuedDiscoveryRecord>)>;

fn begin_discovery_batch(
    records: Vec<QueuedDiscoveryRecord>,
    predispatch: Result<()>,
) -> BatchStart {
    match predispatch {
        Ok(()) => Ok(records),
        Err(error) => Err((error, records)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordRejection {
    ExportNoRetainedView,
    ExportNoLowerableOwner,
    SelectionUnattributed,
    LoaderMissingCounterAuthority,
    LoaderInvalidContext,
    LoaderNoRetainedView,
    LoaderUnknownContext,
    LoaderMissingMapping,
    LoaderMismatchedMapping,
    LoaderPinnedIdentityMismatch,
    LoaderValidationFailure,
    UnknownKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiscoveryRecordOutcome {
    Applied {
        changed: bool,
        required_complete: bool,
    },
    Rejected(RecordRejection),
    TerminalSelectionHandoff {
        view: ProcessViewId,
        owner: LoaderContextId,
    },
}

impl DiscoveryRecordOutcome {
    fn applied(changed: bool, required_complete: bool) -> Self {
        Self::Applied {
            changed,
            required_complete,
        }
    }

    fn changed(self) -> bool {
        match self {
            Self::Applied { changed, .. } => changed,
            Self::Rejected(_) | Self::TerminalSelectionHandoff { .. } => false,
        }
    }

    fn required_complete(self) -> bool {
        matches!(
            self,
            Self::Applied {
                required_complete: true,
                ..
            } | Self::TerminalSelectionHandoff { .. }
        )
    }
}

struct PauseClosure {
    required_complete: bool,
}

impl PauseClosure {
    fn new(additions_allowed: bool) -> Self {
        Self {
            required_complete: additions_allowed,
        }
    }

    fn observe_apply(&mut self, outcome: &ApplyOutcome) {
        self.required_complete &= outcome.required_complete();
    }

    fn fail(&mut self) {
        self.required_complete = false;
    }

    fn required_complete(&self) -> bool {
        self.required_complete
    }
}

impl ApplyOutcome {
    fn accepted(&self) -> bool {
        self.disposition == ApplyDisposition::Accepted
    }

    fn refused(&self) -> bool {
        self.disposition == ApplyDisposition::Refused
    }

    fn required_complete(&self) -> bool {
        self.accepted()
            && self.stale_views.is_empty()
            && self.missing_contexts.is_empty()
            && self.static_failures.is_empty()
    }

    fn record_completions(
        &mut self,
        slots: &[plan::Slot],
        owners: &BTreeMap<plan::ModuleId, PinnedTimingKey>,
        completed: Vec<(u32, Option<u64>)>,
    ) {
        for (index, timestamp) in completed {
            if let Some(slot) = slots.iter().find(|slot| slot.index == index) {
                self.static_completions.push((
                    slot.module_ids
                        .iter()
                        .filter_map(|module| owners.get(module).cloned())
                        .collect(),
                    timestamp,
                ));
            }
        }
    }
}

#[derive(Default)]
struct CandidateAdmission {
    stale_views: BTreeSet<ProcessViewId>,
    missing_contexts: Vec<LoaderContextId>,
    targets_ok: bool,
    newly_rejected_keys: BTreeSet<ObjectKey>,
}

impl CandidateAdmission {
    fn refuses_candidate(&self) -> bool {
        !self.targets_ok || !self.stale_views.is_empty() || !self.missing_contexts.is_empty()
    }

    fn requires_conservative_apply(&self, mutation_started: bool) -> bool {
        mutation_started && self.refuses_candidate()
    }
}

#[derive(Clone)]
struct DynamicExportWork {
    context: LoaderContextId,
    module: Option<PinnedTimingKey>,
    object: PinnedObjectId,
    file_offset: u64,
    cookie: u64,
    abi: HookAbi,
    already_attached: bool,
    selection_binding: Option<SelectionBindingFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectionCoverageState {
    Uncovered,
    OwnedPending(NonZeroU64),
    OwnedOpen(NonZeroU64),
    OwnedClosed(NonZeroU64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SelectionCoverageVerdict {
    Observed,
    ObservedUncovered,
    AbsentCovered,
    AbsentUncovered,
}

impl SelectionCoverageState {
    fn invalidate(&mut self) {
        *self = Self::Uncovered;
    }

    fn retire(&mut self) {
        if !matches!(self, Self::OwnedClosed(_)) {
            *self = Self::Uncovered;
        }
    }

    fn open(&mut self) {
        if let Self::OwnedPending(generation) = *self {
            *self = Self::OwnedOpen(generation);
        }
    }

    fn close_naturally(&mut self) {
        match *self {
            Self::OwnedOpen(generation) => *self = Self::OwnedClosed(generation),
            Self::OwnedPending(_) => *self = Self::Uncovered,
            Self::Uncovered | Self::OwnedClosed(_) => {}
        }
    }

    fn silently_covered(self) -> bool {
        matches!(self, Self::OwnedOpen(_) | Self::OwnedClosed(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectionBindingFact {
    id: u64,
    context: LoaderContextId,
    view: ProcessViewId,
    object: PinnedObjectId,
    file_offset: u64,
    hook_id: u32,
    abi: HookAbi,
    attached: bool,
    retired: bool,
    provider: plan::ModuleId,
    observed: bool,
    coverage: SelectionCoverageState,
}

#[derive(Clone)]
struct CountOnlySeedWork {
    object: PinnedObjectId,
    object_path: String,
    file_offset: u64,
}

struct CollectedExportWork {
    dynamic: Vec<DynamicExportWork>,
    count_only_seeds: Vec<CountOnlySeedWork>,
    required_seed_complete: bool,
}

/// One queued record envelope: move-only, so each record crosses dispatch
/// through exactly one owned envelope. The payload (`DiscoveryRecord`, a
/// frozen `Copy` ABI type) is still read by value for field checks, but a
/// by-value read never creates a second dispatchable owner: only this
/// envelope (or the terminal batch/error prefix it moves into) carries the
/// record to dispatch or retention.
struct QueuedDiscoveryRecord {
    record: DiscoveryRecord,
    terminal_owner: Option<LoaderContextId>,
    terminal_exports: Vec<DynamicExportIdentity>,
}

#[derive(Clone)]
pub(crate) struct TerminalAuthority {
    pub(crate) owner: LoaderContextId,
    pub(crate) exports: Vec<DynamicExportIdentity>,
}

/// The only transfer that may carry a tombstoned loader's final exports.  It
/// stays separate from ordinary pending records so a later generic drain
/// cannot accidentally consume it. Move-only: the batch owns its records,
/// and journal/pause handoffs transfer that ownership instead of copying
/// it. (`TerminalAuthority` keeps its `Clone`: it carries only the owner
/// id and export identities, never records.)
pub(crate) struct TerminalBatch {
    pub(crate) authority: TerminalAuthority,
    records: Vec<QueuedDiscoveryRecord>,
    complete: bool,
}

impl TerminalBatch {
    pub(crate) fn empty(authority: TerminalAuthority) -> Self {
        Self {
            authority,
            records: Vec::new(),
            complete: false,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn extend(&mut self, records: impl IntoIterator<Item = DiscoveryRecord>) {
        let start = self.records.len();
        self.records
            .extend(records.into_iter().map(|record| QueuedDiscoveryRecord {
                record,
                terminal_owner: None,
                terminal_exports: Vec::new(),
            }));
        self.authority.tag_matching(&mut self.records[start..]);
    }

    #[cfg(test)]
    pub(crate) fn record_count(&self) -> usize {
        self.records.len()
    }

    #[cfg(test)]
    pub(crate) fn complete(&self) -> bool {
        self.complete
    }

    #[cfg(test)]
    /// Timing brackets of the batch records, in order, for handoff
    /// tests that cannot name the private record vector.
    #[cfg(test)]
    pub(crate) fn record_hook_stamps_for_test(&self) -> Vec<u64> {
        self.records
            .iter()
            .map(|queued| queued.record.hook_ts_ns)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn tagged_owners(&self) -> Vec<Option<LoaderContextId>> {
        self.records
            .iter()
            .map(|queued| queued.terminal_owner)
            .collect()
    }
}

#[derive(Clone, Copy)]
struct TerminalJournal {
    owner: LoaderContextId,
    dispatch_started: bool,
    retry_used: bool,
}

/// One pre-release attachment, activated by the owned executable's post-exec
/// identity check. Clean, ordered lifecycle transport identifies its first
/// EXEC; PID/executable identity alone never authorizes skipping a refresh.
#[derive(Clone, Copy)]
struct OwnedInitialExec {
    view: ProcessViewId,
    context: LoaderContextId,
    revalidated: bool,
}

impl TerminalAuthority {
    fn tag_matching(&self, records: &mut [QueuedDiscoveryRecord]) -> bool {
        let mut matched = false;
        for queued in records {
            let loader_matches = queued.record.kind == DISCOVERY_KIND_LOADER
                && LoaderContextId::from_case_id(queued.record.case_id) == self.owner;
            let selection_matches = queued.record.kind == DISCOVERY_KIND_INTERFACE_RETURN
                && self.exports.iter().any(|export| {
                    export.abi == HookAbi::Interface && export.cookie == queued.record.binding_id
                });
            if loader_matches || selection_matches {
                queued.terminal_owner = Some(self.owner);
                queued.terminal_exports = self.exports.clone();
                matched = true;
            }
        }
        matched
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ModuleTiming {
    first_causal_ns: Option<u64>,
    attach_complete_ns: Option<u64>,
    lost: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CausalTimings {
    modules: BTreeMap<PinnedTimingKey, ModuleTiming>,
    invalidated: bool,
}

impl CausalTimings {
    fn clear(timing: &mut ModuleTiming) {
        timing.lost = true;
        timing.first_causal_ns = None;
        timing.attach_complete_ns = None;
    }

    fn observe(&mut self, module: &PinnedTimingKey, timestamp_ns: u64) {
        let timing = self.modules.entry(module.clone()).or_default();
        if self.invalidated || timing.lost {
            Self::clear(timing);
            return;
        }
        timing.first_causal_ns = Some(
            timing
                .first_causal_ns
                .unwrap_or(timestamp_ns)
                .min(timestamp_ns),
        );
    }

    fn complete(&mut self, module: &PinnedTimingKey, timestamp_ns: u64) {
        let timing = self.modules.entry(module.clone()).or_default();
        if self.invalidated
            || timing.lost
            || timing
                .first_causal_ns
                .is_none_or(|first| first > timestamp_ns)
        {
            Self::clear(timing);
            return;
        }
        timing.attach_complete_ns = Some(
            timing
                .attach_complete_ns
                .unwrap_or(timestamp_ns)
                .max(timestamp_ns),
        );
    }

    fn lose(&mut self, module: &PinnedTimingKey) {
        Self::clear(self.modules.entry(module.clone()).or_default());
    }

    fn invalidate(&mut self) {
        self.invalidated = true;
        self.modules.values_mut().for_each(Self::clear);
    }

    /// The capture-level gap: the maximum of the defined per-module gaps and
    /// `null` when none is defined (design §5.5). Subtraction is checked and a
    /// lost or invalidated module never contributes an invented zero.
    fn max_gap_ms(&self) -> Option<u64> {
        if self.invalidated {
            return None;
        }
        self.modules
            .values()
            .filter(|timing| !timing.lost)
            .filter_map(|timing| {
                timing
                    .attach_complete_ns?
                    .checked_sub(timing.first_causal_ns?)
            })
            .max()
            .map(|ns| ns / 1_000_000)
    }

    #[cfg(test)]
    fn gap_ns(&self, module: &PinnedTimingKey) -> Option<u64> {
        let timing = self.modules.get(module)?;
        (!timing.lost)
            .then_some((timing.first_causal_ns?, timing.attach_complete_ns?))
            .and_then(|(first, last)| last.checked_sub(first))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestFallback {
    manifest: u32,
    object: u32,
    reason: ManifestStaleReason,
    replacement: PinnedObjectId,
    proof: BoundFallbackProof,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingManifestFallback {
    manifest: u32,
    object: u32,
    reason: ManifestStaleReason,
    candidate: CandidateFallbackProof,
}

/// Private raw scan instance that can be resolved only against the final
/// reconciled module set. It deliberately includes a process view and pathname:
/// a raw map key alone cannot select a peer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScanOutcomeLocator {
    view: ProcessViewId,
    key: ObjectKey,
    path: String,
}

impl ScanOutcomeLocator {
    fn module(module: &ScannedModule) -> Self {
        Self {
            view: module.view,
            key: module.key,
            path: module.path.clone(),
        }
    }
}

/// Private raw manifest instance captured from the opened manifest pin before
/// recorded provenance is retargeted. It is never a public key/path relation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ManifestOutcomeLocator {
    key: ObjectKey,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum OutcomeOwner {
    Scan(ScanOutcomeLocator),
    Manifest(ManifestOutcomeLocator),
}

/// One rendered corroboration item. `Vec` preserves the repeatable
/// `--manifest` input order; its owners become final pinned IDs only after every
/// accepted manifest has been absorbed and scans have been reconciled.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingCorroboration {
    owners: Vec<OutcomeOwner>,
    label: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SurfaceRequirement {
    version: (u8, u8),
    all_names: BTreeMap<String, usize>,
    resolved_names: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TableClaims {
    all_names: BTreeMap<String, usize>,
    resolved_names: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateTableProof {
    address: u64,
    requirement: SurfaceRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CandidateFallbackProof {
    module_view: ProcessViewId,
    module_key: ObjectKey,
    module_path: String,
    recorded_key: ObjectKey,
    object_path: String,
    provenance_path: String,
    is_module: bool,
    replacement: PinnedObjectId,
    tables: Vec<CandidateTableProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RequiredTarget {
    object: PinnedObjectId,
    file_offset: u64,
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundTableProof {
    address: u64,
    version: (u8, u8),
    entries: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundFallbackProof {
    module: PinnedObjectId,
    tables: Vec<BoundTableProof>,
    required_targets: BTreeMap<RequiredTarget, usize>,
}

/// How many processes of a `--cgroup` discovery scans.
///
/// ponytail: the capture byte budget already bounds work; this flat cap also bounds
/// `/proc` inventory overhead for cgroups containing thousands of processes.
/// Shared with `inspect --system` as the default `--max-scan-pids`.
pub(crate) const MAX_SCAN_PIDS: usize = 256;

/// What the discovery pass learned besides the plan itself — everything
/// `discovery_evidence` needs that the plan does not already carry.
#[derive(Debug, Clone, Default)]
struct DiscoveryCounters {
    /// Manifest modules the scan contradicted; the union is attached (spec §4.12).
    conflicts: u64,
    /// Manifest modules nothing corroborated by the time the plan was built.
    uncorroborated: u64,
    /// `Some("ptrace")` when the memory scan could not read a target's memory.
    scan_unavailable: Option<&'static str>,
    scan_ms: u64,
    /// Manifest objects ignored, and why — evidence, never silence.
    notes: Vec<String>,
    /// Objects discovery saw but could not use at all: a mapping with no usable
    /// pathname, exports it could not read, one over the byte caps, a snapshot
    /// that ended early. Whole modules, not entries — the module they belong to
    /// publishes no table, so nothing else in the plan records the loss.
    object_skips: Vec<Skipped>,
    /// Which §4.12 outcome each corroborated module got, so `discovery[]` can
    /// tell an agreement from a conflict instead of publishing a counter with
    /// nothing to explain it.
    corroboration: Vec<(BTreeSet<PinnedObjectId>, &'static str)>,
    /// Stale manifest objects replaced only by exact scan-opened objects.
    manifest_fallbacks: Vec<ManifestFallback>,
    /// Task 3.2 (S1): per-class stderr-noise accumulator. Buffered during the
    /// scan, reported once as summaries, then cleared so live accumulation
    /// starts fresh.
    noise: DiscoveryNoiseAggregator,
}

impl DiscoveryCounters {
    /// The notes, on stderr. Called as soon as they are complete rather than from
    /// `report`, because every bail between the two would otherwise swallow them —
    /// and a note is most useful exactly when discovery is about to fail. The same
    /// facts reach the report as `evidence.discovery[].corroboration`.
    fn report_notes(&self) {
        for note in &self.notes {
            eprintln!("p11scope: {note}");
        }
    }

    /// What discovery ended up with, on stderr, before the capture starts.
    fn report(&self, plan: &plan::AttachPlan) {
        if let Some(reason) = self.scan_unavailable {
            eprintln!(
                "p11scope: the memory scan could not read the target ({reason}); any \
                 --manifest offsets are attached uncorroborated"
            );
        }
        eprintln!(
            "p11scope: discovery: {} module(s), {} attach slot(s), scan {}ms, \
             conflicts {}, uncorroborated {}",
            plan.modules.len(),
            plan.slots.len(),
            self.scan_ms,
            self.conflicts,
            self.uncorroborated,
        );
    }
}

/// Which of spec §4.12's outcomes one `--manifest` gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Corroboration {
    /// Not mapped in scope, or the scan could not run: its offsets stand alone.
    Uncorroborated,
    /// Mapped, and the scan found exactly the same {object, offset} set.
    Agreed,
    /// Mapped, but the two sets differ: attach the union and count a conflict.
    Conflict,
    /// Mapped and identity-matched, but the scan decoded no table in it at all —
    /// the documented primary use of `--manifest` (offsets for a provider the
    /// scan cannot read), not two sources contradicting each other. Attached
    /// exactly like `Conflict`, reported as uncorroborated rather than as a
    /// disagreement: there is no rival set to disagree with.
    ScanEmpty,
    /// Mapped with bytes the manifest did not record: ignore this manifest.
    IdentityMismatch,
}

/// Pure so all four cases are testable without a live target. `identity` is `None`
/// when the object is not mapped in scope (or was not pinnable), `Some(false)` when
/// the object is mapped but its SHA-256 is not the one the manifest recorded.
fn corroborate(
    scan_unavailable: bool,
    identity: Option<bool>,
    targets_agree: bool,
    scan_empty: bool,
) -> Corroboration {
    match identity {
        // A scan that could not read memory found no tables to compare against;
        // that is not evidence against the manifest.
        _ if scan_unavailable => Corroboration::Uncorroborated,
        None => Corroboration::Uncorroborated,
        Some(false) => Corroboration::IdentityMismatch,
        Some(true) if targets_agree => Corroboration::Agreed,
        // Nothing decoded is not a contradiction: the manifest is the only
        // source that ever had offsets here.
        Some(true) if scan_empty => Corroboration::ScanEmpty,
        Some(true) => Corroboration::Conflict,
    }
}

struct ScanView<'a> {
    modules: Vec<&'a ScannedModule>,
    agrees: bool,
}

/// The scan views of the exact opened object a manifest describes. A digest is a
/// comparison conjunct, never authority to choose among byte-identical ordinary
/// files. Every process view of the same exact object is retained for target union.
fn scan_view<'a>(
    m: &Manifest,
    modules: &'a [ScannedModule],
    scan_pins: &PinnedObjects,
    manifest_pins: &PinnedObjects,
) -> Option<ScanView<'a>> {
    let sha = m
        .objects
        .iter()
        .find(|object| object.path == m.module_path)
        .and_then(|object| object.identity.sha256.as_deref());
    let own = manifest_pins.id_for_path(&m.module_path);
    let exact: Vec<&ScannedModule> = modules
        .iter()
        .filter(|module| {
            let Some(scan) = scan_pins.id_for_scanned(module, module.key, &module.path) else {
                return false;
            };
            let Some(own) = own else { return false };
            scan_pins.exactly_matches(scan, manifest_pins, own)
                && scan_pins.summary(scan).map(|pin| pin.sha256) == sha
        })
        .collect();
    if !exact.is_empty() {
        return Some(ScanView {
            modules: exact,
            agrees: true,
        });
    }
    let path_matches: Vec<&ScannedModule> = modules
        .iter()
        .filter(|module| {
            module.path == m.module_path
                && scan_pins
                    .id_for_scanned(module, module.key, &module.path)
                    .is_some()
        })
        .collect();
    // A module the scan saw but could not pin has no hash to disagree with: that is
    // "nothing corroborated it", never "the manifest is wrong".
    (!path_matches.is_empty()).then_some(ScanView {
        modules: path_matches,
        agrees: false,
    })
}

/// Capture-local opened object and file offset for every entry the scan decoded.
#[cfg(test)]
fn scanned_targets(
    modules: &[&ScannedModule],
    pinned: &PinnedObjects,
) -> Option<BTreeSet<(PinnedObjectId, u64)>> {
    scanned_targets_without(modules, pinned, &BTreeSet::new())
}

fn scanned_targets_without(
    modules: &[&ScannedModule],
    pinned: &PinnedObjects,
    ignored: &BTreeSet<PinnedObjectId>,
) -> Option<BTreeSet<(PinnedObjectId, u64)>> {
    modules
        .iter()
        .flat_map(|module| {
            module.tables.iter().flat_map(move |table| {
                table.entries.iter().map(move |entry| {
                    let id = pinned.id_for_scanned(module, entry.object, &entry.object_path)?;
                    Some((!ignored.contains(&id)).then_some((id, entry.file_offset)))
                })
            })
        })
        .collect::<Option<Vec<_>>>()
        .map(|targets| targets.into_iter().flatten().collect())
}

/// The same set resolved through the manifest's exact opened pins in this capture.
fn manifest_targets(
    m: &Manifest,
    pinned: &PinnedObjects,
) -> Option<BTreeSet<(PinnedObjectId, u64)>> {
    m.surfaces
        .iter()
        .flat_map(|surface| &surface.functions)
        .filter_map(|function| match function.resolution {
            Resolution::Resolved {
                object,
                file_offset,
            } => {
                let record = m.objects.iter().find(|o| o.id == object)?;
                Some((record, file_offset))
            }
            _ => None,
        })
        .map(|(record, file_offset)| Some((pinned.id_for_path(&record.path)?, file_offset)))
        .collect()
}

/// Replaces every `{device, inode}` a manifest *recorded* with the identity of the
/// object this capture actually *pinned* for it: the scan's pin of the module it
/// corroborated when there is one, this manifest's own pin otherwise.
///
/// A recorded pair is an identity from another host, another mount or another boot —
/// it is not an identity in this capture's namespace, and it must never be used as
/// one. Two things break if it is:
///
///  - plan lowering resolves a recorded pair to a capture-local pin, so a pair that
///    happens to equal an *unrelated* live pin (inode reuse after a rebuild is enough)
///    would select that file's ID;
///  - the union of §4.12 lands in two slots on one address, double-counting every
///    call, whenever the scan and the manifest name one object differently.
///
/// After this pass every manifest key lowers to the intended capture-local pin ID;
/// `attach.rs` resolves only that ID, with no key or path fallback.
fn retarget_to_pins(
    m: &mut Manifest,
    scanned: &[&ScannedModule],
    scan_pins: &PinnedObjects,
    own_pins: &PinnedObjects,
) {
    // Only exact opened objects named by the matched scan views. Digest equality
    // cannot choose among two ordinary byte-identical files.
    let seen: BTreeSet<PinnedObjectId> = scanned
        .iter()
        .flat_map(|module| {
            std::iter::once((module.key, module.path.as_str()))
                .chain(
                    module
                        .tables
                        .iter()
                        .flat_map(|table| &table.entries)
                        .map(|entry| (entry.object, entry.object_path.as_str())),
                )
                .filter_map(|(key, path)| scan_pins.id_for_scanned(module, key, path))
        })
        .collect();
    // Driven from `objects[]`, because that is what was pinned: `pin_manifest_objects`
    // opens `ObjectRecord.path` and files the pin under it, so the own-pin lookup below
    // is an exact match rather than a second guess at which record describes which
    // file. `plan::provenance_of` then says which provenance record the plan will read
    // that object's identity from — the same relation, so the record rewritten here is
    // always the record read there.
    let updates: Vec<(usize, ObjectKey)> = m
        .objects
        .iter()
        .filter_map(|object| {
            let own = own_pins.id_for_path(&object.path)?;
            let summary = seen
                .iter()
                .copied()
                .find(|scan| scan_pins.exactly_matches(*scan, own_pins, own))
                .and_then(|scan| scan_pins.summary(scan))
                .or_else(|| own_pins.summary(own))?;
            Some((plan::provenance_of(m, object)?, summary.key))
        })
        .collect();
    for (index, key) in updates {
        let provenance = &mut m.provenance_objects[index];
        provenance.device_major = key.device.major;
        provenance.device_minor = key.device.minor;
        provenance.inode = key.inode;
    }
}

/// Re-derives the §4.12 outcome for every manifest the attach-time
/// reconciliation had to judge blind.
///
/// Corroboration is judged **by capture end**: the design says the observer
/// "corroborates automatically whenever the object is mapped in scope (scan or
/// a live export record)" (spec §4.12), and the schema says `uncorroborated`
/// means "not mapped in scope, or no scan"
/// (`docs/schema/observed-profile-v2.md`). But `rebuild_discovered` — the only
/// caller of `corroborate` — runs once, at attach. A target held on a barrier
/// maps its provider afterwards: the reconciliation sees nothing, records
/// `uncorroborated`, and the live path only ever retains or invalidates that
/// record. By the end the same opened object carries both a scan alias and a
/// manifest alias, and the recorded outcome is stale.
///
/// Only a recorded `uncorroborated` is revisited. Every other outcome was
/// derived with the scan already in hand, and an `identity_mismatch` or
/// `object_fallback` is a decision, not a gap waiting to be filled.
///
/// ponytail: one re-derived outcome per opened object, not per `--manifest` —
/// the recorded outcome does not carry which manifest produced it, and every
/// manifest naming one object shares that object's scan side. Split it per
/// manifest if two manifests ever describe one object with different offsets.
fn recorroborate_at_capture_end(
    pinned: &PinnedObjects,
    modules: &[ReconciledModule],
    manifests: &[Manifest],
    counters: &DiscoveryCounters,
) -> BTreeMap<PinnedObjectId, Corroboration> {
    let mut derived = BTreeMap::new();
    // A scan that could not read memory found no tables to compare against;
    // that is not evidence against any manifest, at attach or at the end.
    if counters.scan_unavailable.is_some() {
        return derived;
    }
    for object in counters
        .corroboration
        .iter()
        .filter(|(_, label)| *label == "uncorroborated")
        .flat_map(|(objects, _)| objects)
    {
        // Both a scan alias and a manifest alias resolve to this one opened
        // object: it is mapped in scope, and the scan pinned it.
        if pinned.sources(*object) != ["scan", "manifest"] {
            continue;
        }
        let scanned: Vec<&ScannedModule> = modules
            .iter()
            .filter(|module| module.object == *object)
            .map(|module| &module.scanned)
            .collect();
        let Some(scan_targets) = scanned_targets_without(&scanned, pinned, &BTreeSet::new()) else {
            // An entry with no comparable pinned identity: there is no exact
            // set to compare, so the recorded outcome stands.
            continue;
        };
        let Some(own_targets) = manifests
            .iter()
            .filter(|manifest| manifest_module_object(manifest, pinned) == Some(*object))
            .map(|manifest| manifest_targets(manifest, pinned))
            .collect::<Option<Vec<_>>>()
            .filter(|sets| !sets.is_empty())
            .map(|sets| sets.into_iter().flatten().collect())
        else {
            continue;
        };
        let scan_empty = scanned
            .iter()
            .flat_map(|module| &module.tables)
            .all(|table| table.entries.is_empty());
        derived.insert(
            *object,
            corroborate(
                false,
                // Scan and manifest resolved to one opened object, so the
                // identity comparison already succeeded.
                Some(true),
                pinned.exactly_same_targets(&scan_targets, pinned, &own_targets),
                scan_empty,
            ),
        );
    }
    derived
}

fn corroboration_corroborates(outcome: Corroboration) -> bool {
    matches!(outcome, Corroboration::Agreed | Corroboration::Conflict)
}

/// Enumerates the processes in `scope`. Shared with `inspect --system`,
/// which walks the same membership with scan-only semantics.
pub(crate) fn scope_pids(scope: &Scope) -> (Vec<u32>, Vec<Skipped>) {
    // Whole-machine scope: every numeric /proc entry is a thread-group ID
    // (threads live under /proc/<pid>/task, never top-level). No cgroup path
    // is consulted; the caller's scan cap still bounds discovery.
    if matches!(scope, Scope::System) {
        let mut pids = Vec::new();
        let mut lost = Vec::new();
        match std::fs::read_dir("/proc") {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            lost.push(Skipped {
                                subject: scope_label(scope),
                                reason: format!(
                                    "a /proc entry could not be read ({error}); membership absence is not authoritative"
                                ),
                            });
                            continue;
                        }
                    };
                    if let Some(pid) = entry
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<u32>().ok())
                    {
                        pids.push(pid);
                    }
                }
            }
            Err(error) => lost.push(Skipped {
                subject: scope_label(scope),
                reason: format!("/proc could not be listed ({error}); no process was discovered"),
            }),
        }
        pids.sort_unstable();
        pids.dedup();
        return (pids, lost);
    }
    let (path, io_root) = match scope {
        Scope::Pid(pid) => return (vec![*pid], Vec::new()),
        Scope::Cgroup { path, dir, .. } => (
            path.as_path(),
            PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())),
        ),
        Scope::System => unreachable!("system scope returns above"),
    };
    let mut pids = Vec::new();
    let mut lost = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(relative) = stack.pop() {
        let dir = io_root.join(&relative);
        let label_dir = path.join(&relative);
        match std::fs::read_to_string(dir.join("cgroup.procs")) {
            Ok(text) => pids.extend(
                text.lines()
                    .filter_map(|line| line.trim().parse::<u32>().ok()),
            ),
            // Absent is not unreadable: a directory in the tree that is not a
            // cgroup has no `cgroup.procs` and hides nothing. Anything else —
            // permission, I/O — means processes exist here that were never listed.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => lost.push(Skipped {
                subject: label_dir.display().to_string(),
                reason: format!(
                    "cgroup.procs could not be read ({error}); no process of this cgroup \
                     was scanned"
                ),
            }),
        }
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            lost.push(Skipped {
                                subject: label_dir.display().to_string(),
                                reason: format!(
                                    "a cgroup directory entry could not be read ({error}); membership absence is not authoritative"
                                ),
                            });
                            continue;
                        }
                    };
                    let relative_entry = relative.join(entry.file_name());
                    match entry.file_type() {
                        Ok(kind) if kind.is_dir() => stack.push(relative_entry),
                        Ok(_) => {}
                        Err(error) => lost.push(Skipped {
                            subject: path.join(&relative_entry).display().to_string(),
                            reason: format!(
                                "a cgroup directory entry type could not be read ({error}); membership absence is not authoritative"
                            ),
                        }),
                    }
                }
            }
            // Gone, not hidden — the same rule as above, and the container
            // cgroups this walks churn constantly. A cgroup is only removable
            // once it is empty, so a directory that vanished between its
            // parent's listing and this read held no process to lose.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => lost.push(Skipped {
                subject: label_dir.display().to_string(),
                reason: format!(
                    "the cgroup directory could not be listed ({error}); any process \
                     below it was never discovered"
                ),
            }),
        }
    }
    pids.sort_unstable();
    pids.dedup();
    (pids, lost)
}

/// What a scope-wide loss is filed under: the cgroup path, the pid, or the
/// whole machine.
/// The skip subject naming a scope. Shared with `inspect --system`.
pub(crate) fn scope_label(scope: &Scope) -> String {
    match scope {
        Scope::Pid(pid) => format!("pid {pid}"),
        Scope::Cgroup { path, .. } => path.display().to_string(),
        Scope::System => "system".to_string(),
    }
}

/// Reads, parses and schema-checks one `--manifest`.
fn read_manifest_file(path: &Path) -> Result<Manifest> {
    let text = read_manifest(path)
        .map_err(|error| anyhow!("reading manifest {}: {error}", path.display()))?;
    let document: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", path.display()))?;
    if document.get("schema").and_then(serde_json::Value::as_str) != Some(SCHEMA) {
        bail!(
            "manifest schema mismatch: got {:?}, this build expects {SCHEMA:?}; \
             rerun `p11scope-discover` to rediscover the module",
            document.get("schema")
        );
    }
    let manifest: Manifest = serde_json::from_str(&text)
        .with_context(|| format!("parsing manifest {}", path.display()))?;
    Ok(manifest)
}

/// One newcomer queue age in whole milliseconds: first-observed-ready minus
/// first-seen. Either endpoint missing (a failed clock read, a dropped
/// mark) samples unknown — never an invented zero.
fn newcomer_age_ms(first_seen_ns: Option<u64>, now_ns: Option<u64>) -> Option<u64> {
    let (seen, now) = (first_seen_ns?, now_ns?);
    Some(now.saturating_sub(seen) / 1_000_000)
}

/// Scans one process and pins every object the scan named. The scan's own skips and
/// the pinning skips are printed rather than dropped: a module the observer could
/// see but not read is exactly the gap an operator needs to know about.
fn scan_and_pin(
    view: &ProcessView,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    budget: &mut CaptureWorkBudget,
    counters: &mut DiscoveryCounters,
    broad_admit: bool,
    stage: &mut crate::timing::StageTimings,
) -> Result<(Vec<ScannedModule>, PinnedObjects)> {
    scan_and_pin_with(
        view,
        hints,
        hooks,
        budget,
        counters,
        broad_admit,
        stage,
        scan_process_view,
    )
    .map(|(modules, pins, _)| (modules, pins))
}

/// One scan plus its pins plus whether absence inside it is verified. The
/// `complete` flag is the scan-to-live-candidate boundary: only a memory
/// scan that ran unbounded (no stop before, during or after), refused no
/// new candidate, and emitted no truncating skip may retire previously
/// observed modules by absence. Broadening and pinning run after the
/// snapshot, so their own budget effects never rewrite the scan's verdict.
#[allow(clippy::too_many_arguments)]
fn scan_and_pin_with(
    view: &ProcessView,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    budget: &mut CaptureWorkBudget,
    counters: &mut DiscoveryCounters,
    broad_admit: bool,
    stage: &mut crate::timing::StageTimings,
    scan: impl FnOnce(
        &ScanRequest<'_>,
        &ProcessView,
        &mut CaptureWorkBudget,
    ) -> std::result::Result<ScanOutcome, String>,
) -> Result<(Vec<ScannedModule>, PinnedObjects, bool)> {
    let stop_before = budget.stopped_reason();
    let refusals_before = budget.refusal_counts();
    let scan_start = crate::attach::monotonic_ns();
    let scanned = scan(
        &ScanRequest {
            pid: view.pid(),
            hints,
            hooks,
        },
        view,
        budget,
    );
    stage.span(
        crate::timing::StageKind::Scan,
        "scan_view",
        scan_start,
        crate::attach::monotonic_ns(),
    );
    let outcome =
        scanned.map_err(|error| anyhow!("scanning process view {:?}: {error}", view.id()))?;
    let complete = outcome.unavailable_reason().is_none()
        && stop_before.is_none()
        && budget.stopped_reason().is_none()
        && budget.refusal_counts() == refusals_before
        && !outcome
            .skipped()
            .iter()
            .any(|skip| scan_skip_truncates(&skip.reason));
    counters.scan_unavailable = counters.scan_unavailable.or(outcome.unavailable_reason());
    // Retain acquisition losses before pinning can fail on an exited generation.
    for skipped in outcome.skipped() {
        counters.noise.note_skip(&skipped.subject, &skipped.reason);
        attribution::note(skipped);
        counters.object_skips.push(skipped.clone());
    }
    if let ScanOutcome::Scanned { scan_ms, .. } = &outcome {
        counters.scan_ms = counters.scan_ms.saturating_add(*scan_ms);
    }
    let mut modules = match outcome {
        ScanOutcome::Scanned { modules, .. } | ScanOutcome::Unavailable { modules, .. } => modules,
    };
    // Broad (Task 1.6) augments swept modules with validated fixed-family
    // tables before pinning, so pinning covers the union with one call.
    if broad_admit {
        broad_fixed_pool_pass(view, &mut modules, budget, counters);
    }
    let pin_start = crate::attach::monotonic_ns();
    let pinned = pin_scanned_view_objects(view, &modules, budget);
    stage.span(
        crate::timing::StageKind::Pin,
        "pin_view_objects",
        pin_start,
        crate::attach::monotonic_ns(),
    );
    let (pinned, pin_skips) =
        pinned.map_err(|error| anyhow!("pinning process view {:?}: {error}", view.id()))?;
    for skipped in pin_skips {
        counters.noise.note_skip(&skipped.subject, &skipped.reason);
        attribution::note(&skipped);
        counters.object_skips.push(skipped);
    }
    Ok((modules, pinned, complete))
}

/// Task 1.6 experiment: recognized fixed-family pool layout.
///
/// Recognition is name + geometry + per-table decode validation, in that
/// order: an object exporting `p11scope_fixed` whose 53,760 bytes hold 64
/// contiguous 840-byte `{3,2}` tables (the owned fixture's contract in
/// `tests/fixtures/multi-wrapper/provider.c`). Every table validates through
/// the same bracketed exact-table reader as 1.5 heap publication (maps-A
/// membership, one bounded mem read, same-decoder decode, maps-B stability,
/// generation check); a table that fails any of those is refused loudly,
/// never attached. The symbol lookup intentionally accepts BSS: the pool is
/// filled by the provider constructor at load, so file bytes never carry it.
///
/// What broad does NOT do: unknown-layout builds (no symbol, e.g. the
/// stripped fixture) stay publication-driven; the sweep's file-backed tables
/// are never re-read (a pool table the sweep already decoded is skipped as
/// covered after an entry-equality check); names stay unauthorized (pool
/// tables are unlinked heuristic evidence — the 1.3 mislabel guard is
/// untouched). Costs charge through the shared budget like any other read.
const BROAD_POOL_SYMBOL: &str = "p11scope_fixed";
const BROAD_POOL_TABLES: usize = 64;
const BROAD_POOL_TABLE_BYTES: usize = 840;
const BROAD_POOL_BYTES: usize = BROAD_POOL_TABLES * BROAD_POOL_TABLE_BYTES;
const BROAD_POOL_VERSION: (u8, u8) = (3, 2);

fn broad_fixed_pool_pass(
    view: &ProcessView,
    modules: &mut [ScannedModule],
    budget: &mut CaptureWorkBudget,
    counters: &mut DiscoveryCounters,
) {
    if !view.still_the_same() {
        return;
    }
    let maps = match Engine::read_maps(view, budget) {
        Ok(maps) => maps,
        Err(_) => {
            broad_note(
                counters,
                "broad fixed-family",
                "the process maps could not be re-read; no fixed-family tables were added",
            );
            return;
        }
    };
    let index = match index_maps_or_refuse(&maps, budget) {
        Ok(index) => index,
        Err(_) => {
            broad_note(
                counters,
                "broad fixed-family",
                "the process maps snapshot was refused; no fixed-family tables were added",
            );
            return;
        }
    };
    for module in modules.iter_mut() {
        broad_fixed_pool_module(view, module, &index, budget, counters);
    }
}

fn broad_note(counters: &mut DiscoveryCounters, subject: &str, reason: &str) {
    let skipped = Skipped {
        subject: subject.to_string(),
        reason: reason.to_string(),
    };
    counters.noise.note_skip(&skipped.subject, &skipped.reason);
    attribution::note(&skipped);
    counters.object_skips.push(skipped);
}

fn broad_fixed_pool_module(
    view: &ProcessView,
    module: &mut ScannedModule,
    index: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
    counters: &mut DiscoveryCounters,
) {
    let Some(abi) = module.decoder_abi else {
        return;
    };
    let layout = target_layout(abi);
    let relative = match module.path.strip_prefix('/') {
        Some(relative) => relative,
        None => return,
    };
    let rooted = PathBuf::from(format!("/proc/{}/root", view.pid())).join(relative);
    let (file, key) = match open_view_object(view, &rooted, budget) {
        Ok(opened) => opened,
        Err(_) => return,
    };
    if key != module.key {
        broad_note(
            counters,
            &module.path,
            "broad fixed-family: the object file identity changed under the scan; \
             no fixed-family tables were added",
        );
        return;
    }
    let snapshot = match read_elf_snapshot(&file, budget) {
        Ok(snapshot) => snapshot,
        Err(_) => return,
    };
    let pool_vaddr =
        match snapshot.defined_symbol_virtual_address(BROAD_POOL_SYMBOL, BROAD_POOL_BYTES) {
            Ok(Some(vaddr)) => vaddr,
            // Not a recognized fixed-family build: silence is correct — selected
            // admission already covered whatever the sweep decoded.
            Ok(None) => return,
            Err(reason) => {
                broad_note(
                    counters,
                    &module.path,
                    &format!("broad fixed-family: {reason}"),
                );
                return;
            }
        };
    let bias = match index
        .entries()
        .iter()
        .find(|entry| entry.device == module.key.device && entry.inode == module.key.inode)
        .and_then(|entry| entry.start.checked_sub(entry.file_offset))
    {
        Some(bias) => bias,
        None => {
            broad_note(
                counters,
                &module.path,
                "broad fixed-family: no mapping of the object remains; \
                 no fixed-family tables were added",
            );
            return;
        }
    };
    let Some(pool) = bias.checked_add(pool_vaddr) else {
        broad_note(
            counters,
            &module.path,
            "broad fixed-family: the pool address overflows; \
             no fixed-family tables were added",
        );
        return;
    };
    let owned = index.containing(pool).is_some_and(|mapping| {
        mapping.device == module.key.device && mapping.inode == module.key.inode
    });
    if !owned {
        broad_note(
            counters,
            &module.path,
            "broad fixed-family: the pool address is not mapped by the object; \
             no fixed-family tables were added",
        );
        return;
    }
    // Table 0 establishes the stride: without it, stepping is blind.
    let mut tallies = BroadTallies::default();
    let mut refused = 0usize;
    let mut first_reason = None;
    let stride = match broad_pool_table(view, module, index, budget, pool, layout, &mut tallies) {
        Ok(stride) => stride,
        Err(reason) => {
            broad_note(
                counters,
                &module.path,
                &format!(
                    "broad fixed-family: pool table 0 refused ({reason}); the pool layout \
                 is unverified, so no fixed-family tables were added"
                ),
            );
            return;
        }
    };
    if stride != BROAD_POOL_TABLE_BYTES {
        broad_note(
            counters,
            &module.path,
            &format!(
                "broad fixed-family: pool table 0 decoded {stride} bytes, not the \
             {BROAD_POOL_TABLE_BYTES}-byte recipe; no fixed-family tables were added"
            ),
        );
        // Table 0 may already have been added above; drop it — a pool whose
        // stride is unverified contributes nothing.
        module.tables.retain(|table| table.address != pool);
        return;
    }
    let mut refused_ordinals = Vec::new();
    for ordinal in 1..BROAD_POOL_TABLES {
        let offset = (ordinal as u64).saturating_mul(stride as u64);
        let Some(address) = pool.checked_add(offset) else {
            refused += 1;
            refused_ordinals.push(ordinal);
            if first_reason.is_none() {
                first_reason = Some("the pool address overflows".to_string());
            }
            continue;
        };
        if let Err(reason) =
            broad_pool_table(view, module, index, budget, address, layout, &mut tallies)
        {
            refused += 1;
            refused_ordinals.push(ordinal);
            if first_reason.is_none() {
                first_reason = Some(reason);
            }
        }
    }
    let first_reason = first_reason.unwrap_or_else(|| "unknown".to_string());
    eprintln!(
        "p11scope: discovery: broad fixed-family: {}: {} table(s) added, {} \
         already covered, {refused} refused at {refused_ordinals:?} \
         (first reason: {first_reason})",
        module.path, tallies.added, tallies.covered,
    );
    if refused > 0 {
        counters.notes.push(format!(
            "broad fixed-family: {} refused {refused} pool table(s) at {refused_ordinals:?}; \
             first reason: {first_reason}",
            module.path,
        ));
    }
}

#[derive(Default)]
struct BroadTallies {
    covered: usize,
    added: usize,
}

/// Validates one pool table through the shared bracketed reader and appends
/// it unless the sweep already decoded the same bytes. Returns the decoded
/// table size (the pool stride) on success.
fn broad_pool_table(
    view: &ProcessView,
    module: &mut ScannedModule,
    index: &MapIndex<'_>,
    budget: &mut CaptureWorkBudget,
    address: u64,
    layout: LinuxLayout,
    tallies: &mut BroadTallies,
) -> std::result::Result<usize, String> {
    let (_, mut table, bytes) = Engine::read_exact_table_bracketed(
        view, address, layout, index, budget, true,
    )
    .map_err(|refusal| match refusal {
        ExactReadRefusal::Budget => "a decode budget ceiling stopped the validation".to_string(),
        ExactReadRefusal::Unstable => {
            "the mappings moved or the generation changed during validation".to_string()
        }
        ExactReadRefusal::Unreadable => {
            "the pool address was unreadable when validated".to_string()
        }
        ExactReadRefusal::Undecodable => {
            "the pool bytes did not decode as a function table".to_string()
        }
    })?;
    if table.version != BROAD_POOL_VERSION {
        return Err(format!(
            "pool table version is {:?}, not the {:?} recipe",
            table.version, BROAD_POOL_VERSION
        ));
    }
    table.file_offset = match index.resolve(address) {
        Resolved::File {
            file_offset, inode, ..
        } if inode != 0 => Some(file_offset),
        _ => None,
    };
    // Pool tables carry no publication evidence: unlinked, no live return,
    // no manifest support — heuristic evidence with unauthorized names.
    table.live_return = false;
    table.manifest_supported = false;
    if let Some(offset) = table.file_offset
        && let Some(known) = module
            .tables
            .iter()
            .find(|known| known.file_offset == Some(offset) && known.version == table.version)
    {
        if known.entries == table.entries {
            tallies.covered += 1;
            return Ok(bytes.len());
        }
        // Same version-word location, different entries: memory is the
        // live truth, so the pool instance admits alongside — loudly.
        eprintln!(
            "p11scope: discovery: broad fixed-family: {}: pool table at file offset \
                 {offset:#x} diverges from the swept instance; admitting the live bytes",
            module.path,
        );
    }
    module.tables.push(table);
    tallies.added += 1;
    Ok(bytes.len())
}

/// A mapping that can carry a PKCS#11 provider: a mapped file whose path
/// names a shared object. Pure so phase-1 selection can group pids without
/// decoding anything.
pub(crate) fn is_provider_mapping(entry: &MapEntry) -> bool {
    entry.inode != 0
        && entry
            .raw_path
            .as_ref()
            .is_some_and(|path| path.windows(3).any(|window| window == b".so"))
}

/// Phase 2 of the two-phase scan: choose which swept pids earn a deep scan.
/// Under the cap this is the identity (all pids ascending — today's exact
/// order); over the cap each provider group sends its lowest pid, rarest
/// providers first, and pids with no provider mapping trail as individuals.
/// Phase-2 selection, shared with `inspect --system` so one implementation
/// decides which swept pids earn a deep scan.
pub(crate) fn select_deep_scan_candidates(
    sweep: &[(u32, Vec<MapEntry>)],
    max_pids: usize,
) -> Vec<u32> {
    if sweep.len() <= max_pids {
        let mut pids: Vec<u32> = sweep.iter().map(|(pid, _)| *pid).collect();
        pids.sort_unstable();
        return pids;
    }
    let mut groups: BTreeMap<BTreeSet<ObjectKey>, Vec<u32>> = BTreeMap::new();
    let mut unmapped: Vec<u32> = Vec::new();
    for (pid, entries) in sweep {
        let key: BTreeSet<ObjectKey> = entries
            .iter()
            .filter(|entry| is_provider_mapping(entry))
            .map(ObjectKey::of)
            .collect();
        if key.is_empty() {
            unmapped.push(*pid);
        } else {
            groups.entry(key).or_default().push(*pid);
        }
    }
    // File-level rarity: over the whole sweep, how many pids map each file.
    // Each group member maps the group's whole key set, so every member adds
    // one to each of its keys.
    let mut census: BTreeMap<ObjectKey, usize> = BTreeMap::new();
    for (key, members) in &groups {
        for file in key {
            *census.entry(*file).or_default() += members.len();
        }
    }
    let mut ordered: Vec<(BTreeSet<ObjectKey>, Vec<u32>)> = groups.into_iter().collect();
    for (_, members) in &mut ordered {
        members.sort_unstable();
    }
    ordered.sort_by_key(|(key, members)| {
        let min_global = key
            .iter()
            .map(|file| census[file])
            .min()
            .unwrap_or(usize::MAX);
        (min_global, members.len(), members[0])
    });
    unmapped.sort_unstable();
    ordered
        .into_iter()
        .map(|(_, members)| members[0])
        .chain(unmapped)
        .take(max_pids)
        .collect()
}

/// Rotation's fairness-tiered variant of the selection above: identical
/// grouping, global rarity census, and group order — but within each group
/// the representative is the lowest never-evicted member (falling back to
/// the lowest stale one), and unmapped pids trail fresh-first, pid order
/// within each tier. Rarity still beats pid order across groups, so a rare
/// provider is always reached first; within a class, never-scanned pids
/// beat re-scans, so rotation covers every pid instead of churning the
/// lowest evictees back ahead of higher never-scanned ones. With no stale
/// pids this agrees with `select_deep_scan_candidates` exactly.
fn select_rotation_candidates(
    sweep: &[(u32, Vec<MapEntry>)],
    max_pids: usize,
    stale: &BTreeSet<u32>,
) -> Vec<u32> {
    if sweep.len() <= max_pids {
        let mut pids: Vec<u32> = sweep.iter().map(|(pid, _)| *pid).collect();
        pids.sort_unstable();
        return pids;
    }
    let mut groups: BTreeMap<BTreeSet<ObjectKey>, Vec<u32>> = BTreeMap::new();
    let mut unmapped: Vec<u32> = Vec::new();
    for (pid, entries) in sweep {
        let key: BTreeSet<ObjectKey> = entries
            .iter()
            .filter(|entry| is_provider_mapping(entry))
            .map(ObjectKey::of)
            .collect();
        if key.is_empty() {
            unmapped.push(*pid);
        } else {
            groups.entry(key).or_default().push(*pid);
        }
    }
    let mut census: BTreeMap<ObjectKey, usize> = BTreeMap::new();
    for (key, members) in &groups {
        for file in key {
            *census.entry(*file).or_default() += members.len();
        }
    }
    let mut ordered: Vec<(BTreeSet<ObjectKey>, Vec<u32>)> = groups.into_iter().collect();
    for (_, members) in &mut ordered {
        members.sort_unstable();
    }
    ordered.sort_by_key(|(key, members)| {
        let min_global = key
            .iter()
            .map(|file| census[file])
            .min()
            .unwrap_or(usize::MAX);
        (min_global, members.len(), members[0])
    });
    unmapped.sort_unstable();
    // `partition` preserves the sorted order within each tier.
    let (fresh_unmapped, stale_unmapped): (Vec<u32>, Vec<u32>) =
        unmapped.into_iter().partition(|pid| !stale.contains(pid));
    ordered
        .into_iter()
        .map(|(_, members)| {
            members
                .iter()
                .copied()
                .find(|pid| !stale.contains(pid))
                .unwrap_or(members[0])
        })
        .chain(fresh_unmapped)
        .chain(stale_unmapped)
        .take(max_pids)
        .collect()
}

/// Categorical over-cap diagnostic: the actual selected count out of the
/// enumerated count, the cap, and the selection method. Selection is
/// provider-rarity order, not a pid prefix, so the message must never say
/// "first N". Never names pids or paths. Refresh passes only new candidates
/// (known views excluded); it must not claim successful scans.
/// Capture discovery's published over-cap record. `inspect --system` and
/// `inventory --system` publish their own (C1b): past the cap they
/// attribute unselected processes by exact maps identity, so their record
/// says what remained unexamined instead.
pub(crate) fn scan_cap_reason(total: usize, selected: usize, cap: usize, live: bool) -> String {
    if live {
        let noun = if selected == 1 {
            "new candidate"
        } else {
            "new candidates"
        };
        format!(
            "{total} processes in scope; live discovery selected {selected} {noun} for deep scanning by provider rarity (limit {cap})"
        )
    } else {
        format!(
            "{total} processes in scope; discovery selected {selected} for deep scanning by provider rarity (limit {cap}); unselected processes may contain undiscovered providers"
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
enum MapsSnapshot {
    Read(Vec<MapEntry>),
    Unavailable,
}

/// Phase-1 maps snapshots, shared with `inspect --system`.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MapsSweep {
    snapshots: Vec<(u32, MapsSnapshot)>,
}

/// One maps snapshot per swept pid (empty when unavailable).
pub(crate) type SweepSnapshots = Vec<(u32, Vec<MapEntry>)>;

impl MapsSweep {
    fn record(&mut self, pid: u32, result: Result<Vec<MapEntry>, String>) {
        let snapshot = match result {
            Ok(entries) => MapsSnapshot::Read(entries),
            Err(_) => MapsSnapshot::Unavailable,
        };
        self.snapshots.push((pid, snapshot));
    }

    fn attempted(&self) -> usize {
        self.snapshots.len()
    }

    fn read(&self) -> usize {
        self.snapshots
            .iter()
            .filter(|(_, snapshot)| matches!(snapshot, MapsSnapshot::Read(_)))
            .count()
    }

    fn unavailable_skip(&self) -> Option<Skipped> {
        let unavailable = self.attempted() - self.read();
        (unavailable != 0).then(|| Skipped {
            subject: "process maps sweep".into(),
            reason: format!(
                "maps snapshots unavailable for {unavailable} of {} attempted processes; provider presence remains unknown",
                self.attempted()
            ),
        })
    }

    /// Rarity ordering consumes advisory hints only. Unknown snapshots stay
    /// eligible as individual candidates, alongside successful snapshots
    /// with no provider hint. This projection is never mapping or absence
    /// authority: an admitted deep scan acquires its own retained view.
    /// Return the gap with the hints so both callers publish it even when
    /// none of these candidates can receive a deep-scan slot.
    pub(crate) fn into_selection(self) -> (SweepSnapshots, Option<Skipped>) {
        let (hints, _, skipped) = self.into_selection_with_unavailable();
        (hints, skipped)
    }

    /// [`Self::into_selection`] plus the pids whose snapshot was
    /// unavailable: C1b must not read an unavailable snapshot as a process
    /// mapping nothing.
    pub(crate) fn into_selection_with_unavailable(
        self,
    ) -> (SweepSnapshots, BTreeSet<u32>, Option<Skipped>) {
        let skipped = self.unavailable_skip();
        let unavailable: BTreeSet<u32> = self
            .snapshots
            .iter()
            .filter(|(_, snapshot)| matches!(snapshot, MapsSnapshot::Unavailable))
            .map(|(pid, _)| *pid)
            .collect();
        let hints = self
            .snapshots
            .into_iter()
            .map(|(pid, snapshot)| {
                let hints = match snapshot {
                    MapsSnapshot::Read(entries) => entries,
                    MapsSnapshot::Unavailable => Vec::new(),
                };
                (pid, hints)
            })
            .collect();
        (hints, unavailable, skipped)
    }
}

/// Phase 1 reads every in-scope pid's maps snapshot with bounded I/O and
/// parsing, without decode or view allocation. Failed or budget-refused
/// snapshots remain unavailable, independently of later deep-scan selection.
/// Shared with `inspect --system`.
///
/// C7 A4: the reads are sharded by contiguous pid ranges across the
/// observer's CPUs ([`sweep_shards`](crate::discovery::sweep_shards)),
/// with every budget charge replayed in pid order, so the sweep is the
/// serial one result for result; `P11SCOPE_SHARD_THREADS=1` runs the
/// serial loop itself.
pub(crate) fn sweep_process_maps(pids: &[u32], budget: &mut CaptureWorkBudget) -> MapsSweep {
    let shards = sweep_shards::shard_count(pids.len(), sweep_shards::shard_threads());
    sweep_process_maps_with(
        pids,
        budget,
        shards,
        MapsReadLimits::LIVE,
        &|pid| std::fs::File::open(format!("/proc/{pid}/maps")),
        &crate::attach::monotonic_ns,
    )
}

/// [`sweep_process_maps`] with its shard count, read bounds, opener and
/// clock supplied (tests).
pub(crate) fn sweep_process_maps_with<R, O, C>(
    pids: &[u32],
    budget: &mut CaptureWorkBudget,
    shards: usize,
    limits: MapsReadLimits,
    open: &O,
    now: &C,
) -> MapsSweep
where
    R: std::io::Read,
    O: Fn(u32) -> std::io::Result<R> + Sync,
    C: Fn() -> Option<u64> + Sync,
{
    let mut sweep = MapsSweep::default();
    sweep_shards::sweep_maps(
        pids,
        budget,
        shards,
        limits,
        open,
        now,
        &mut |pid, result| {
            sweep.record(pid, result);
        },
    );
    sweep
}

/// Discovery for one capture: scan the scope, read and corroborate any manifests,
/// merge into one plan, pin every object, and record how all of it was found.
/// Task 1.6 experiment switch, read once per discovery (read-only, so
/// parallel tests without the variable set always observe `false`).
fn broad_admit_from_env() -> bool {
    std::env::var_os("P11SCOPE_BROAD_ADMIT").is_some_and(|value| value == "1")
}

fn discover_plan(
    a: &CaptureArgs,
    scope: &Scope,
    mut named_view: Option<ProcessView>,
) -> Result<Engine> {
    let mut discovered = Engine::empty();
    discovered.broad_admit = broad_admit_from_env();
    discovered.scope = scope.clone();
    discovered.hooks = a.hooks.clone();
    discovered.module_hints = a.modules.clone();
    discovered.max_scan_pids = a
        .max_scan_pids
        .filter(|cap| *cap > 0)
        .unwrap_or(MAX_SCAN_PIDS);
    let (pids, unlisted) = scope_pids(scope);
    attribution::note_all(&unlisted);
    discovered.base_counters.object_skips.extend(unlisted);
    // The pid the operator named is the capture; a cgroup's processes are many,
    // however few happen to be in it right now.
    let named = matches!(scope, Scope::Pid(_));
    let max_scan_pids = discovered.max_scan_pids;
    // Two-phase scan: phase 1 sweeps every in-scope pid's maps, phase 2
    // deep-scans the selected candidates only. Under the cap selection is
    // the identity, so the sweep (and its budget charge) is skipped there.
    let selected = if pids.len() > max_scan_pids {
        let sweep_start = crate::attach::monotonic_ns();
        let (sweep, unavailable) =
            sweep_process_maps(&pids, &mut discovered.budget).into_selection();
        discovered.stage_timings.span(
            crate::timing::StageKind::Scan,
            "sweep_process_maps",
            sweep_start,
            crate::attach::monotonic_ns(),
        );
        if let Some(skipped) = unavailable {
            attribution::note(&skipped);
            discovered.base_counters.object_skips.push(skipped);
        }
        let select_start = crate::attach::monotonic_ns();
        let selected = select_deep_scan_candidates(&sweep, max_scan_pids);
        discovered.stage_timings.span(
            crate::timing::StageKind::Scan,
            "select_deep_scan_candidates",
            select_start,
            crate::attach::monotonic_ns(),
        );
        selected
    } else {
        pids.clone()
    };
    if pids.len() > max_scan_pids {
        // Published, not just noted: a provider mapped only by a process past the
        // cap is undiscovered, unprobed, and has nothing else to show for it.
        // Formed after selection so the counts describe the actual set.
        let skipped = Skipped {
            subject: scope_label(scope),
            reason: scan_cap_reason(pids.len(), selected.len(), max_scan_pids, false),
        };
        attribution::note(&skipped);
        discovered.base_counters.object_skips.push(skipped);
    }
    for pid in selected.iter() {
        let opened = if named {
            named_view
                .take()
                .filter(|view| view.pid() == *pid)
                .ok_or_else(|| "named process view was not retained from scope resolution".into())
        } else {
            let id = match discovered.allocate_view_id() {
                Ok(id) => id,
                Err(_) => {
                    let skipped = Skipped {
                        subject: "process view".into(),
                        reason: format!(
                            "capture process-view capacity {max_scan_pids} was exhausted; remaining generations were not scanned"
                        ),
                    };
                    attribution::note(&skipped);
                    discovered.base_counters.object_skips.push(skipped);
                    break;
                }
            };
            // Allocated but never admitted: a member that ended before
            // discovery reached it fails open below, and its ID returns
            // to the pool instead of burning for the capture lifetime.
            ProcessView::open(id, *pid).inspect_err(|_| discovered.release_view_id(id))
        };
        let view = match opened {
            Ok(view) => view,
            Err(error) if named => return Err(anyhow!(error)),
            Err(error) => {
                if let Some(skipped) = unreadable_member_skip(
                    *pid,
                    process::generation_gone(*pid),
                    &format!("the process generation could not be pinned: {error}"),
                    &mut discovered.base_counters.noise,
                ) {
                    attribution::note(&skipped);
                    discovered.base_counters.object_skips.push(skipped);
                }
                continue;
            }
        };
        if discovered.retain_view_id(view.id()).is_err() {
            let skipped = Skipped {
                subject: "process view".into(),
                reason: format!(
                    "capture process-view capacity {max_scan_pids} was exhausted; remaining generations were not scanned"
                ),
            };
            attribution::note(&skipped);
            discovered.base_counters.object_skips.push(skipped);
            break;
        }
        let mut counters = DiscoveryCounters::default();
        let broad_admit = discovered.broad_admit;
        let scan_result = scan_and_pin(
            &view,
            &a.modules,
            &a.hooks,
            &mut discovered.budget,
            &mut counters,
            broad_admit,
            &mut discovered.stage_timings,
        );
        discovered.deep_scans = discovered.deep_scans.saturating_add(1);
        match scan_result {
            Ok((found, pins)) => {
                discovered.note_scan_observed(view.id(), &found);
                discovered.scan_inputs.insert(
                    view.id(),
                    ScanInput {
                        modules: found,
                        pins,
                        counters,
                    },
                );
                discovered.views.push(view);
            }
            // The pid the operator named *is* the capture; any other is one of many
            // in a cgroup, and may legitimately exit between listing and scanning —
            // legitimate, but still a process whose providers went unexamined.
            Err(error) if named => return Err(error),
            Err(error) => {
                // Allocated but never admitted: the failed scan drops
                // this view, so its ID returns to the pool.
                discovered.release_view_id(view.id());
                discovered.base_counters.scan_unavailable = discovered
                    .base_counters
                    .scan_unavailable
                    .or(counters.scan_unavailable);
                discovered.base_counters.scan_ms = discovered
                    .base_counters
                    .scan_ms
                    .saturating_add(counters.scan_ms);
                discovered
                    .base_counters
                    .object_skips
                    .extend(counters.object_skips);
                discovered.base_counters.noise.merge(&counters.noise);
                if let Some(skipped) = unreadable_member_skip(
                    *pid,
                    view.original_exited() == Ok(true),
                    &format!("the process could not be scanned: {error:#}"),
                    &mut discovered.base_counters.noise,
                ) {
                    attribution::note(&skipped);
                    discovered.base_counters.object_skips.push(skipped);
                }
            }
        }
    }

    discovered.seed_initial_cgroup_views();
    for path in &a.manifests {
        let manifest =
            read_manifest_file(path).inspect_err(|_| discovered.base_counters.report_notes())?;
        let pin_start = crate::attach::monotonic_ns();
        let pinning_result = pin_manifest_objects_deferred_in_views_with_budget(
            &manifest,
            &discovered.views,
            &mut discovered.budget,
        );
        discovered.stage_timings.span(
            crate::timing::StageKind::Pin,
            "pin_manifest_objects",
            pin_start,
            crate::attach::monotonic_ns(),
        );
        let pinning = pinning_result.map_err(|error| {
            discovered.base_counters.report_notes();
            for problem in error.problems() {
                eprintln!("p11scope: {problem}");
            }
            anyhow!(
                "manifest {} is not a usable trusted input; refusing to attach",
                path.display()
            )
        })?;
        discovered.manifest_inputs.push(ManifestInput {
            path: path.clone(),
            manifest,
            pins: pinning.pins,
            stale: pinning.stale,
        });
    }

    rebuild_discovered(&mut discovered)?;
    discovered.counters.report_notes();
    // Task 3.2 (S1): one categorical summary per noise class instead of one
    // line per skipped view. Cleared here so live accumulation starts fresh
    // and a later rebuild cannot re-merge initial noise.
    discovered.counters.noise.report();
    discovered.counters.noise.clear();
    discovered.base_counters.noise.clear();
    for input in discovered.scan_inputs.values_mut() {
        input.counters.noise.clear();
    }
    for refused in &discovered.plan.modules_skipped {
        eprintln!(
            "{}",
            format_module_refusal(&refused.subject, &refused.reason)
        );
    }
    discovered.counters.report(&discovered.plan);
    Ok(discovered)
}

#[allow(clippy::too_many_arguments)]
fn build_current_plan(
    modules: &[ReconciledModule],
    manifests: &[Manifest],
    pinned: &PinnedObjects,
    counters: &mut DiscoveryCounters,
    corroborated: &BTreeSet<PinnedObjectId>,
    identity_mismatches: usize,
    manifest_fallbacks: usize,
    broad_admit: bool,
    admission_scope: plan::AdmissionScope,
) -> Result<plan::AttachPlan> {
    // Every plan reference is a capture-local pinned ID. Raw mapping keys remain
    // evidence only and cannot select an attach fd.
    let mut plan =
        plan::build_from_sources_scoped(modules, manifests, pinned, broad_admit, admission_scope);
    record_object_skips(&mut plan, &counters.object_skips);
    for object in corroborated {
        if let Some(summary) = plan
            .modules
            .iter_mut()
            .find(|module| module.object == *object)
        {
            summary.corroborated = true;
            if summary.source == "scan" {
                summary.source = "scan+manifest";
            }
        }
    }
    counters.uncorroborated = uncorroborated_count(&plan, identity_mismatches, manifest_fallbacks);
    if identity_mismatches + manifest_fallbacks > 0 && plan.slots.is_empty() {
        bail!(
            "{} stale --manifest input object(s) had no usable planned replacement, and no discovery source found a function table",
            identity_mismatches + manifest_fallbacks
        );
    }
    // A named capture that can attach nothing has nothing to observe. A
    // shared-scope capture still starts: its refusals are published and
    // printed, and a provider that loads, or is corroborated, later in the
    // capture can still be admitted into the reserve.
    if plan.admission_scope() == plan::AdmissionScope::Named
        && let Some(error) = refusal_error(&plan)
    {
        bail!(error);
    }
    plan::ensure_capacity(&plan).map_err(|error| anyhow!(error))?;
    Ok(plan)
}

/// Modules whose offsets nothing corroborated, plus every `--manifest` ignored
/// as stale (§4.12 case 4). An ignored manifest never becomes a plan module, so
/// the filter cannot see it — and a stale manifest supplied for exactly the
/// provider the scan cannot read leaves that provider unobserved with nothing
/// else in the document to notice. Counted here, it forces `PARTIAL`.
fn uncorroborated_count(
    plan: &plan::AttachPlan,
    identity_mismatches: usize,
    manifest_fallbacks: usize,
) -> u64 {
    let uncorroborated = plan
        .modules
        .iter()
        .filter(|m| m.source.contains("manifest") && !m.corroborated)
        .count();
    (uncorroborated + identity_mismatches + manifest_fallbacks) as u64
}

/// Folds the scan's own object-level losses into the plan's skip list, where
/// `Evidence::verdict` already turns any skip into `PARTIAL`. Deduplicated:
/// a `--cgroup` scans every process in the tree, and one provider ten of them
/// map is one loss, not ten lines of the same one.
fn record_object_skips(plan: &mut plan::AttachPlan, skips: &[Skipped]) {
    // Judged by capture end, so what an earlier batch already recorded is
    // re-judged too: the plan's skip list is only rebuilt when its sources are.
    let modules = std::mem::take(&mut plan.modules);
    plan.skipped
        .retain(|skip| !scan_gap_this_capture_attached(&modules, skip));
    for skip in skips {
        if scan_gap_this_capture_attached(&modules, skip) || plan.skipped.contains(skip) {
            continue;
        }
        plan.skipped.push(skip.clone());
    }
    plan.modules = modules;
}

/// A scan gap is contradicted only when the capture ends up attaching a full
/// table for the same path. This covers a module that was not mapped and one
/// that was mapped but empty in file-backed data; both can race a later load.
/// Judged by capture end, like §4.12 corroboration. Every other scan loss, and
/// a module that really did stay empty, is untouched.
fn scan_gap_this_capture_attached(modules: &[plan::ModuleSummary], skip: &Skipped) -> bool {
    (skip.reason == "not mapped in the target"
        || skip
            .reason
            .contains("no function table was found in its file-backed data"))
        && modules.iter().any(|module| {
            module.path == skip.subject && module.tables.iter().any(|table| table.entries > 0)
        })
}

/// The merge refuses an over-capacity module whole rather than attaching a
/// prefix (`plan::merge`). One provider over the ceiling must not cost the
/// capture the other providers could still have shared, so a refusal is
/// reported — it reaches `evidence.modules_skipped` and forces PARTIAL — rather
/// than aborting. It stays an error only when it leaves nothing to attach: an
/// empty capture whose emptiness was caused by a refusal is not the "no modules
/// discovered" case (spec §4.10) and must not read like it.
fn refusal_error(plan: &plan::AttachPlan) -> Option<String> {
    let refused = plan.modules_skipped.first()?;
    plan.slots.is_empty().then(|| {
        format!(
            "every module discovery found was refused at the {} attach-slot ceiling, \
             leaving nothing to attach — first refusal: {} — {}",
            p11scope_ebpf_common::MAX_SLOTS,
            refused.subject,
            refused.reason
        )
    })
}

/// The `discovery[]` record: what was found, where it was found, and how well
/// the two sources agreed. Identity is `{dev, ino, sha256}` — a path here is
/// only the label the source that saw it used, and for anything the scan found
/// that label lives in the *target's* mount namespace.
fn discovery_evidence(
    plan: &plan::AttachPlan,
    pinned: &PinnedObjects,
    counters: &DiscoveryCounters,
) -> render::DiscoveryEvidence {
    let summary_of = |id, path: &str| {
        let pin = pinned
            .summary(id)
            .expect("every planned object has a comparable pin");
        render::ObjectSummary {
            dev: (pin.key.device.major, pin.key.device.minor),
            ino: pin.key.inode,
            // Absent, not empty: nothing hashed it, so there is no digest to
            // report — an empty string would read as one.
            sha256: Some(pin.sha256.to_string()),
            path: if pin.path.is_empty() {
                path.to_string()
            } else {
                pin.path.to_string()
            },
            build_id: pin.build_id.map(str::to_string),
            identity_source: pin.identity_source,
            note: pin.note.map(str::to_string),
            sources: pinned.sources(id),
        }
    };
    let modules = plan
        .modules
        .iter()
        .map(|m| {
            let mut seen = BTreeSet::new();
            let objects: Vec<render::ObjectSummary> = plan
                .slots
                .iter()
                .filter(|s| {
                    plan.is_active(s.index) && s.module_ids.contains(&m.id) && seen.insert(s.object)
                })
                .map(|s| summary_of(s.object, &s.object_path))
                .collect();
            let identity = summary_of(m.object, &m.path);
            render::DiscoveredModule {
                id: m.id,
                dev: identity.dev,
                ino: identity.ino,
                sha256: identity.sha256,
                path: m.path.clone(),
                build_id: identity.build_id,
                objects,
                sources: m.source.split('+').collect(),
                corroborated: m.corroborated,
                // Every outcome recorded against this object, not the first:
                // `--manifest` is repeatable, and two manifests naming one
                // object would otherwise render one outcome beside a
                // `corroborated` the other produced.
                corroboration: corroboration_of(counters, m),
                tables: m.tables.clone(),
                interfaces: m.interfaces,
                skipped: m.skipped.iter().map(render::capture_skipped_out).collect(),
            }
        })
        .collect();
    let manifest_object_fallbacks = counters
        .manifest_fallbacks
        .iter()
        .filter_map(|fallback| {
            let replacement = pinned.summary(fallback.replacement)?;
            Some(render::ManifestObjectFallback {
                manifest: fallback.manifest,
                object: fallback.object,
                reason: fallback.reason.label(),
                replacement: render::ManifestReplacement {
                    dev: (replacement.key.device.major, replacement.key.device.minor),
                    ino: replacement.key.inode,
                    sha256: replacement.sha256.to_string(),
                },
            })
        })
        .collect();
    render::DiscoveryEvidence {
        modules,
        conflicts: counters.conflicts,
        uncorroborated: counters.uncorroborated,
        module_ambiguous: plan.module_ambiguous as u64,
        uncorroborated_candidates: plan.uncorroborated_candidates,
        modules_skipped: plan.modules_skipped.iter().map(skipped_out).collect(),
        manifest_object_fallbacks,
        scan_unavailable: counters.scan_unavailable.map(str::to_string),
        scan_ms: counters.scan_ms,
        ..render::DiscoveryEvidence::default()
    }
}

/// Every §4.12 outcome recorded against this module's object — one per
/// `--manifest` that named it. Empty only when no manifest did, which the
/// record states as `single_source` rather than as silence.
fn corroboration_of(counters: &DiscoveryCounters, m: &plan::ModuleSummary) -> Vec<&'static str> {
    let recorded: Vec<&'static str> = counters
        .corroboration
        .iter()
        .filter(|(objects, _)| objects.contains(&m.object))
        .map(|(_, label)| *label)
        .collect();
    if !recorded.is_empty() {
        return recorded;
    }
    vec![if !m.source.contains("manifest") {
        "single_source"
    } else if m.corroborated {
        "agreed"
    } else {
        "uncorroborated"
    }]
}

fn skipped_out(s: &Skipped) -> render::SkippedOut {
    render::SkippedOut {
        name: s.subject.clone(),
        reason: s.reason.clone(),
    }
}

fn corroboration_label(outcome: Corroboration) -> &'static str {
    match outcome {
        Corroboration::Uncorroborated => "uncorroborated",
        Corroboration::Agreed => "agreed",
        Corroboration::Conflict => "conflict",
        Corroboration::ScanEmpty => "scan_empty",
        Corroboration::IdentityMismatch => "identity_mismatch",
    }
}

fn manifest_outcome_locator(
    manifest: &Manifest,
    pins: &PinnedObjects,
) -> Option<ManifestOutcomeLocator> {
    let mut modules = manifest
        .objects
        .iter()
        .filter(|object| object.path == manifest.module_path);
    let object = modules.next()?;
    if modules.next().is_some() {
        return None;
    }
    let id = pins.id_for_path(&object.path)?;
    let summary = pins.summary(id)?;
    Some(ManifestOutcomeLocator {
        key: summary.key,
        path: object.path.clone(),
    })
}

fn pending_corroboration(
    view: Option<&ScanView<'_>>,
    manifest: &Manifest,
    manifest_pins: &PinnedObjects,
    label: &'static str,
) -> Result<PendingCorroboration> {
    let owners: Vec<_> = view
        .map(|view| {
            view.modules
                .iter()
                .map(|module| OutcomeOwner::Scan(ScanOutcomeLocator::module(module)))
                .collect()
        })
        .unwrap_or_else(|| {
            manifest_outcome_locator(manifest, manifest_pins)
                .map(OutcomeOwner::Manifest)
                .into_iter()
                .collect()
        });
    if owners.is_empty() {
        bail!(
            "an accepted manifest outcome had no exact opened object instance to bind after reconciliation"
        );
    }
    Ok(PendingCorroboration { owners, label })
}

fn resolve_outcome_owner(
    owner: &OutcomeOwner,
    modules: &[ReconciledModule],
    pinned: &PinnedObjects,
) -> Option<PinnedObjectId> {
    match owner {
        OutcomeOwner::Scan(locator) => {
            let mut matching = modules.iter().filter(|module| {
                module.scanned.view == locator.view
                    && module.scanned.key == locator.key
                    && target_paths_equal(&module.scanned.path, &locator.path)
            });
            let module = matching.next()?;
            matching.next().is_none().then_some(module.object)
        }
        OutcomeOwner::Manifest(locator) => pinned.id_for_manifest(locator.key, &locator.path),
    }
}

fn bind_pending_corroboration(
    pending: Vec<PendingCorroboration>,
    modules: &[ReconciledModule],
    pinned: &PinnedObjects,
    counters: &mut DiscoveryCounters,
) -> Result<BTreeSet<PinnedObjectId>> {
    let mut corroborated = BTreeSet::new();
    for outcome in pending {
        let objects: Option<BTreeSet<_>> = outcome
            .owners
            .iter()
            .map(|owner| resolve_outcome_owner(owner, modules, pinned))
            .collect();
        let Some(objects) = objects.filter(|objects| !objects.is_empty()) else {
            bail!(
                "an accepted manifest outcome lost its exact final object during identity reconciliation"
            );
        };
        if matches!(outcome.label, "agreed" | "conflict") {
            corroborated.extend(&objects);
        }
        counters.corroboration.push((objects, outcome.label));
    }
    Ok(corroborated)
}

const STALE_VIEW_REASON: &str = "accepted process generation changed during attach preparation; its discovery claims were removed";

/// The record a failed post-detach terminal drain publishes. It announces a
/// *retry*, so it is only true while the journal that owes it is still
/// pending; `settle_terminal_drain` judges it at capture end.
const TERMINAL_DRAIN_SUBJECT: &str = "live loader retirement";
/// Records one live drain takes off the private discovery ring before it
/// returns to a caller that checks duration, signal and pause deadline. The
/// 64 KiB ring holds ~73 records, so a drain stopped here has emptied the
/// ring several times over and leaves only what the producer wrote during the
/// drain itself; that backlog is reported as an incomplete drain, never as an
/// empty ring, and any overflow it causes is the producer's `ring_loss`.
pub(crate) const LIVE_DISCOVERY_DRAIN_QUANTUM: usize = 256;

/// Discovery quanta one live frame collects before it applies them (RB-2).
/// The ring is now staged on every tick, but a frame that applied one
/// 256-item quantum a second fell behind any host producing more lifecycle
/// records than that, and the backlog then overflowed into ring loss.
/// Sixteen quanta, 4,096 items — the staging capacity — per frame; anything
/// left stays queued in ring order for the next frame.
pub(crate) const LIVE_DISCOVERY_FRAME_QUANTA: usize = 16;

/// Shared userspace allowance for ordinary discovery records (H5): pending
/// Engine records plus session-staged records plus the fresh records one
/// frame pulls — one allowance, so the staging FIFO capacity is its single
/// source. Terminal-authority batches stay outside this in-Engine bound so
/// terminal completion can never deadlock behind it; the full cross-owner
/// credit audit (including pause-held records) needs the coordinator-owned
/// credit module outside this slice's lease.
pub(crate) const DISCOVERY_HELD_CAP: usize = crate::attach::DiscoveryStage::CAPACITY;

/// How long one live discovery frame may work before it defers the rest of
/// its records, deferred loader scans, loader arming and export attach to
/// the next frame (H-1). A frame used to run all of it with no clock check —
/// 4-5.6 s ticks were measured — while EVENTS, signals, pause stops and
/// first-use attach waited. 100 ms is a tenth of the default profile frame
/// and half the trace frame; one item already started is always finished,
/// so a frame overruns by at most one item. Pause cycles and terminal
/// drains are never bounded by it: they must finish their causal work.
pub(crate) const LIVE_FRAME_WORK_BUDGET_NS: u64 = 100_000_000;

/// The one loss an under-cap polling rescan can reveal (F1): a provider-free
/// process is never armed for loader events, so a provider it loads is found
/// only by the next poll, and calls to it before then went unobserved. A poll
/// that finds nothing lost nothing and publishes nothing.
pub(crate) const POLLED_PROVIDER_LOSS: &str = "a polling rescan found a provider in a process that was not armed for loader events; calls to it before this rescan were not observed";
/// Frame-budget deferral (H-1) delays work, it does not drop it (F4): it is
/// counted in `scheduling.discovery_deferrals`. Only work the terminal drain
/// still left undone is a loss.
pub(crate) const UNFINISHED_DEFERRAL_LOSS: &str =
    "discovery work deferred by a frame budget was never completed before the capture ended";
const DISCOVERY_DRAIN_BACKLOG_REASON: &str =
    "the live discovery drain stopped at its work quantum with records still queued";
const DISCOVERY_CAPACITY_BLOCKED_REASON: &str =
    "the live discovery drain stopped at the shared storage allowance with records still unread";
const TERMINAL_DRAIN_RETRY_REASON: &str = "the post-detach private discovery drain failed; the exact terminal batch remains \
     tombstoned for retry";

/// The one published record for scope members discovery could not read.
/// Deduplication is per exact `(subject, reason)` pair, so the pid, the view
/// and the error text are diagnostics and must stay out of both: carrying them
/// there gave a `--cgroup` capture one public record per short-lived
/// subprocess, a count that tracks the workload's fork rate and no loss.
const UNREADABLE_MEMBER_SUBJECT: &str = "process view";
const UNREADABLE_MEMBER_REASON: &str = "a process in scope could not be retained or scanned before it changed; a provider \
     only that generation mapped was never discovered";

/// Pinned by `scan_pin_diagnostics_escape_target_controls`. Production stderr
/// now aggregates through `DiscoveryNoiseAggregator` (Task 3.2); this format
/// survives only as the oracle for the escaping contract.
#[cfg(test)]
fn format_discovery_skip(subject: &str, reason: &str) -> String {
    format!(
        "p11scope: discovery skipped {} — {}",
        render::escape_controls(subject),
        render::escape_controls(reason)
    )
}

/// Pinned by `unreadable_member_diagnostics_escape_target_controls`.
/// Production no longer prints per-pid lines (Task 3.2 aggregates scrubbed).
#[cfg(test)]
fn format_unreadable_member(pid: u32, detail: &str) -> String {
    format!(
        "p11scope: discovery skipped pid {pid}: {}",
        render::escape_controls(detail)
    )
}

fn format_module_refusal(subject: &str, reason: &str) -> String {
    format!(
        "p11scope: module refused: {} — {}",
        render::escape_controls(subject),
        render::escape_controls(reason)
    )
}

/// One member of the scope discovery could not read. `None` when the
/// generation is *provably* gone — the ordinary end of a process, on the same
/// authority `queue_retirement` and the live-record rule already use, and
/// nothing a capture that keeps running can still observe. Loss stays loss,
/// and loud, whenever the end cannot be proven. Loud means aggregated (Task
/// 3.2): the detail is noted to `noise` scrubbed of PIDs, never printed raw.
/// Shared with `inspect --system`, which pairs the deduped record with a
/// per-pid status in its process table.
pub(crate) fn unreadable_member_skip(
    pid: u32,
    gone: bool,
    detail: &str,
    noise: &mut DiscoveryNoiseAggregator,
) -> Option<Skipped> {
    if gone {
        return None;
    }
    noise.note_unreadable(pid, detail);
    Some(Skipped {
        subject: UNREADABLE_MEMBER_SUBJECT.into(),
        reason: UNREADABLE_MEMBER_REASON.into(),
    })
}

fn manifest_object_key(manifest: &Manifest, object: u32) -> Option<(ObjectKey, &str)> {
    let object = manifest.objects.iter().find(|record| record.id == object)?;
    let provenance = &manifest.provenance_objects[plan::provenance_of(manifest, object)?];
    Some((
        ObjectKey {
            device: p11scope_manifest::maps::Device {
                major: provenance.device_major,
                minor: provenance.device_minor,
            },
            inode: provenance.inode,
        },
        provenance.path.as_str(),
    ))
}

fn claims_covered(needed: &BTreeMap<String, usize>, available: &BTreeMap<String, usize>) -> bool {
    needed
        .iter()
        .all(|(claim, count)| available.get(claim).is_some_and(|seen| seen >= count))
}

fn fallback_requirements(
    manifest: &Manifest,
    stale: u32,
    is_module: bool,
) -> Option<Vec<SurfaceRequirement>> {
    let mut requirements = Vec::new();
    for surface in &manifest.surfaces {
        let mut all_names = BTreeMap::new();
        let mut resolved_names = BTreeMap::new();
        for function in &surface.functions {
            let affected = is_module
                || matches!(
                    function.resolution,
                    Resolution::Resolved { object, .. } if object == stale
                );
            if !affected {
                continue;
            }
            *all_names.entry(function.name.clone()).or_insert(0) += 1;
            if matches!(function.resolution, Resolution::Resolved { .. }) {
                *resolved_names.entry(function.name.clone()).or_insert(0) += 1;
            }
        }
        if all_names.is_empty() {
            continue;
        }
        let version = surface
            .version
            .map(|version| (version.major, version.minor))?;
        requirements.push(SurfaceRequirement {
            version,
            all_names,
            resolved_names,
        });
    }
    (!requirements.is_empty()).then_some(requirements)
}

fn relation_matches(proof: &CandidateFallbackProof, key: ObjectKey, path: &str) -> bool {
    key == proof.recorded_key
        && (target_paths_equal(path, &proof.object_path)
            || target_paths_equal(path, &proof.provenance_path))
}

fn raw_table_claims(
    module: &ScannedModule,
    table: &ScannedTable,
    pinned: &PinnedObjects,
    proof: &CandidateFallbackProof,
) -> TableClaims {
    let mut all_names = BTreeMap::new();
    let mut resolved_names = BTreeMap::new();
    for entry in &table.entries {
        *all_names.entry(entry.name.to_string()).or_insert(0) += 1;
        let relevant = proof.is_module
            || relation_matches(proof, entry.object, &entry.object_path)
                && pinned
                    .id_for_scanned(module, entry.object, &entry.object_path)
                    .and_then(|id| pinned.summary(id))
                    .is_some_and(|summary| summary.key == proof.recorded_key);
        if relevant
            && pinned
                .id_for_scanned(module, entry.object, &entry.object_path)
                .is_some()
        {
            *resolved_names.entry(entry.name.to_string()).or_insert(0) += 1;
        }
    }
    for name in &table.null_entries {
        *all_names.entry((*name).to_string()).or_insert(0) += 1;
    }
    for skipped in &table.unpinned {
        *all_names.entry(skipped.subject.clone()).or_insert(0) += 1;
    }
    TableClaims {
        all_names,
        resolved_names,
    }
}

fn requirement_covered(
    requirement: &SurfaceRequirement,
    table: &ScannedTable,
    claims: &TableClaims,
) -> bool {
    table.version == requirement.version
        && claims_covered(&requirement.all_names, &claims.all_names)
        && claims_covered(&requirement.resolved_names, &claims.resolved_names)
}

fn assign_table(
    surface: usize,
    candidates: &[Vec<usize>],
    seen: &mut [bool],
    owners: &mut [Option<usize>],
) -> bool {
    for &table in &candidates[surface] {
        if seen[table] {
            continue;
        }
        seen[table] = true;
        if owners[table].is_none() || assign_table(owners[table].unwrap(), candidates, seen, owners)
        {
            owners[table] = Some(surface);
            return true;
        }
    }
    false
}

fn injective_table_assignment(
    requirements: &[SurfaceRequirement],
    tables: &[ScannedTable],
    claims: &[TableClaims],
) -> Option<Vec<usize>> {
    let candidates: Vec<Vec<usize>> = requirements
        .iter()
        .map(|requirement| {
            tables
                .iter()
                .zip(claims)
                .enumerate()
                .filter_map(|(index, (table, claims))| {
                    requirement_covered(requirement, table, claims).then_some(index)
                })
                .collect()
        })
        .collect();
    if candidates.iter().any(Vec::is_empty) {
        return None;
    }
    let mut owners = vec![None; tables.len()];
    for surface in 0..requirements.len() {
        if !assign_table(
            surface,
            &candidates,
            &mut vec![false; tables.len()],
            &mut owners,
        ) {
            return None;
        }
    }
    let mut selected = vec![usize::MAX; requirements.len()];
    for (table, surface) in owners.into_iter().enumerate() {
        if let Some(surface) = surface {
            selected[surface] = table;
        }
    }
    selected
        .iter()
        .all(|table| *table != usize::MAX)
        .then_some(selected)
}

/// Locates one exact scan module and an injective table proof for every manifest
/// surface this stale object would remove. Raw paths and mapping keys only locate
/// this pending candidate; reconciliation binds it to canonical opened identities.
fn scanned_replacement(
    manifest: &Manifest,
    stale: &StaleManifestObject,
    modules: &[ScannedModule],
    pinned: &PinnedObjects,
    manifest_pins: &PinnedObjects,
) -> Option<CandidateFallbackProof> {
    let object = manifest
        .objects
        .iter()
        .find(|object| object.id == stale.object)?;
    let (recorded_key, provenance_path) = manifest_object_key(manifest, stale.object)?;
    let is_module = object.path == manifest.module_path;
    let requirements = fallback_requirements(manifest, stale.object, is_module)?;
    let module_owners: BTreeSet<_> = if is_module {
        BTreeSet::new()
    } else {
        let view = scan_view(manifest, modules, pinned, manifest_pins)?;
        if !view.agrees {
            return None;
        }
        view.modules
            .iter()
            .map(|module| (module.view, module.key))
            .collect()
    };
    let mut selected: Option<CandidateFallbackProof> = None;
    for module in modules {
        if !is_module && !module_owners.contains(&(module.view, module.key)) {
            continue;
        }
        let module_id = pinned.id_for_scanned(module, module.key, &module.path);
        let locator = CandidateFallbackProof {
            module_view: module.view,
            module_key: module.key,
            module_path: module.path.clone(),
            recorded_key,
            object_path: object.path.clone(),
            provenance_path: provenance_path.to_string(),
            is_module,
            replacement: PinnedObjectId(u32::MAX),
            tables: Vec::new(),
        };
        if is_module
            && !module_id.is_some_and(|id| {
                relation_matches(&locator, module.key, &module.path)
                    && pinned
                        .summary(id)
                        .is_some_and(|summary| summary.key == recorded_key)
            })
        {
            continue;
        }
        let claims: Vec<_> = module
            .tables
            .iter()
            .map(|table| raw_table_claims(module, table, pinned, &locator))
            .collect();
        let Some(assignment) = injective_table_assignment(&requirements, &module.tables, &claims)
        else {
            continue;
        };
        let replacement = if is_module {
            module_id?
        } else {
            let target_ids: BTreeSet<_> = assignment
                .iter()
                .flat_map(|table| &module.tables[*table].entries)
                .filter(|entry| relation_matches(&locator, entry.object, &entry.object_path))
                .filter_map(|entry| pinned.id_for_scanned(module, entry.object, &entry.object_path))
                .collect();
            if target_ids.len() != 1 {
                continue;
            }
            *target_ids.first()?
        };
        let candidate = CandidateFallbackProof {
            replacement,
            tables: assignment
                .into_iter()
                .zip(requirements.iter().cloned())
                .map(|(table, requirement)| CandidateTableProof {
                    address: module.tables[table].address,
                    requirement,
                })
                .collect(),
            ..locator
        };
        match &selected {
            Some(existing) if existing.replacement != candidate.replacement => return None,
            Some(_) => {}
            None => selected = Some(candidate),
        }
    }
    selected
}

fn bound_table_claims(
    module: &ReconciledModule,
    table: usize,
    proof: &CandidateFallbackProof,
) -> TableClaims {
    let table_record = &module.scanned.tables[table];
    let mut all_names = BTreeMap::new();
    let mut resolved_names = BTreeMap::new();
    for entry in &table_record.entries {
        *all_names.entry(entry.name.to_string()).or_insert(0) += 1;
        if proof.is_module || relation_matches(proof, entry.object, &entry.object_path) {
            *resolved_names.entry(entry.name.to_string()).or_insert(0) += 1;
        }
    }
    for name in &table_record.null_entries {
        *all_names.entry((*name).to_string()).or_insert(0) += 1;
    }
    for skipped in &table_record.unpinned {
        *all_names.entry(skipped.subject.clone()).or_insert(0) += 1;
    }
    TableClaims {
        all_names,
        resolved_names,
    }
}

fn bind_fallback_proof(
    candidate: &CandidateFallbackProof,
    modules: &[ReconciledModule],
) -> Option<(PinnedObjectId, BoundFallbackProof)> {
    let mut matching = modules.iter().filter(|module| {
        module.scanned.view == candidate.module_view
            && module.scanned.key == candidate.module_key
            && module.scanned.path == candidate.module_path
    });
    let module = matching.next()?;
    if matching.next().is_some() {
        return None;
    }
    let mut bound_tables = Vec::with_capacity(candidate.tables.len());
    let mut required_targets = BTreeMap::new();
    let mut replacement_ids = BTreeSet::new();
    for table_proof in &candidate.tables {
        let mut matching = module
            .scanned
            .tables
            .iter()
            .enumerate()
            .filter(|(_, table)| table.address == table_proof.address);
        let (table_index, table) = matching.next()?;
        if matching.next().is_some() {
            return None;
        }
        let claims = bound_table_claims(module, table_index, candidate);
        if !requirement_covered(&table_proof.requirement, table, &claims) {
            return None;
        }
        for (name, count) in &table_proof.requirement.resolved_names {
            let mut remaining = *count;
            for (entry, object) in table.entries.iter().zip(&module.entry_objects[table_index]) {
                if entry.name != name
                    || !candidate.is_module
                        && !relation_matches(candidate, entry.object, &entry.object_path)
                {
                    continue;
                }
                replacement_ids.insert(*object);
                *required_targets
                    .entry(RequiredTarget {
                        object: *object,
                        file_offset: entry.file_offset,
                        name: name.clone(),
                    })
                    .or_insert(0) += 1;
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
            if remaining != 0 {
                return None;
            }
        }
        bound_tables.push(BoundTableProof {
            address: table.address,
            version: table.version,
            entries: table.entries.len(),
        });
    }
    let replacement = if candidate.is_module {
        module.object
    } else {
        if replacement_ids.len() != 1 {
            return None;
        }
        *replacement_ids.first()?
    };
    Some((
        replacement,
        BoundFallbackProof {
            module: module.object,
            tables: bound_tables,
            required_targets,
        },
    ))
}

const FALLBACK_UNUSABLE_REASON: &str = "superseded by exact scan fallback";

fn filter_manifest_fallbacks(manifest: &mut Manifest, stale: &BTreeSet<u32>) -> Result<()> {
    for surface in &mut manifest.surfaces {
        for function in &mut surface.functions {
            if matches!(
                function.resolution,
                Resolution::Resolved { object, .. } if stale.contains(&object)
            ) {
                function.resolution = Resolution::UnusableFile {
                    reason: FALLBACK_UNUSABLE_REASON.into(),
                    path_hex: String::new(),
                };
            }
        }
    }

    let provenance: Vec<Option<usize>> = manifest
        .objects
        .iter()
        .map(|object| plan::provenance_of(manifest, object))
        .collect();
    let mut ids = BTreeMap::new();
    let mut objects = Vec::new();
    let mut kept_provenance = BTreeSet::new();
    for (index, object) in manifest.objects.iter().enumerate() {
        if stale.contains(&object.id) {
            continue;
        }
        let new_id = u32::try_from(objects.len()).expect("manifest object cap fits u32");
        ids.insert(object.id, new_id);
        let mut object = object.clone();
        object.id = new_id;
        objects.push(object);
        if let Some(provenance) = provenance[index] {
            kept_provenance.insert(provenance);
        }
    }
    manifest.objects = objects;
    manifest.provenance_objects = std::mem::take(&mut manifest.provenance_objects)
        .into_iter()
        .enumerate()
        .filter_map(|(index, object)| kept_provenance.contains(&index).then_some(object))
        .collect();
    for surface in &mut manifest.surfaces {
        for function in &mut surface.functions {
            if let Resolution::Resolved { object, .. } = &mut function.resolution {
                *object = ids[object];
            }
        }
    }
    manifest.alias_groups.retain_mut(|group| {
        let Some(object) = ids.get(&group.object).copied() else {
            return false;
        };
        group.object = object;
        true
    });
    let problems = validate_structure(manifest);
    if !problems.is_empty() {
        bail!(
            "manifest became structurally invalid after stale-object fallback: {}",
            problems.join("; ")
        );
    }
    Ok(())
}

fn fallback_proof_in_plan(proof: &BoundFallbackProof, plan: &plan::AttachPlan) -> bool {
    let mut table_addresses = BTreeSet::new();
    if proof
        .tables
        .iter()
        .any(|table| !table_addresses.insert(table.address))
    {
        return false;
    }
    let mut modules = plan
        .modules
        .iter()
        .filter(|module| module.object == proof.module);
    let Some(module) = modules.next() else {
        return false;
    };
    if modules.next().is_some() {
        return false;
    }
    let mut available_tables = BTreeMap::new();
    for table in module.tables.iter().filter(|table| table.source == "scan") {
        *available_tables
            .entry((table.version, table.entries))
            .or_insert(0usize) += 1;
    }
    let mut required_tables = BTreeMap::new();
    for table in &proof.tables {
        *required_tables
            .entry((table.version, table.entries))
            .or_insert(0usize) += 1;
    }
    if required_tables.iter().any(|(table, count)| {
        available_tables
            .get(table)
            .is_none_or(|available| available < count)
    }) {
        return false;
    }
    proof.required_targets.keys().all(|required| {
        plan.slots.iter().any(|slot| {
            slot.object == required.object
                && slot.file_offset == required.file_offset
                && slot.names.iter().any(|name| name == &required.name)
                && slot.module_ids.contains(&module.id)
        })
    })
}

fn rebuild_discovered(discovered: &mut Engine) -> Result<()> {
    discovered.loader_plan_cache = None;
    let aggregate_start = crate::attach::monotonic_ns();
    let mut counters = discovered.base_counters.clone();
    let mut scan_modules = Vec::new();
    for input in discovered.scan_inputs.values() {
        counters.scan_unavailable = counters
            .scan_unavailable
            .or(input.counters.scan_unavailable);
        counters.scan_ms = counters.scan_ms.saturating_add(input.counters.scan_ms);
        counters
            .object_skips
            .extend(input.counters.object_skips.clone());
        counters.noise.merge(&input.counters.noise);
        scan_modules.extend(input.modules.clone());
    }
    let (mut pinned, aggregation_skips) =
        PinnedObjects::aggregate_views(discovered.scan_inputs.values().map(|input| &input.pins));
    attribution::note_all(&aggregation_skips);
    counters.object_skips.extend(aggregation_skips);
    let (collapsed, overlay_skips) = canonicalize_scanned_overlays(&mut pinned);
    if collapsed > 0 {
        eprintln!(
            "p11scope: discovery: {collapsed} matching overlay mapping(s) were collapsed \
             onto one attach target; physical identity is not provable, so published \
             uncertainty makes this capture PARTIAL"
        );
    }
    attribution::note_all(&overlay_skips);
    counters.object_skips.extend(overlay_skips);
    let mut accepted = Vec::new();
    let mut accepted_ordinals = Vec::new();
    let mut pending_fallbacks = Vec::new();
    let mut pending_outcomes = Vec::new();
    let mut identity_mismatches = 0usize;
    for (manifest_index, input) in discovered.manifest_inputs.iter().enumerate() {
        let mut manifest = input.manifest.clone();
        let manifest_pins = &input.pins;
        let mut stale_ids = BTreeSet::new();
        let mut stale_replacements = BTreeSet::new();
        let mut stale_candidates = Vec::new();
        let manifest_number = u32::try_from(manifest_index)
            .map_err(|_| anyhow!("too many --manifest inputs to identify fallback evidence"))?;
        for stale in &input.stale {
            let Some(candidate) =
                scanned_replacement(&manifest, stale, &scan_modules, &pinned, manifest_pins)
            else {
                counters.report_notes();
                bail!(
                    "stale manifest object {} from {} ({}) has no exact, complete scanned replacement table",
                    stale.object,
                    input.path.display(),
                    stale.reason.label(),
                );
            };
            if pending_fallbacks.len() >= crate::manifest_input::MAX_OBJECTS {
                bail!(
                    "more than {} stale manifest objects require fallback",
                    crate::manifest_input::MAX_OBJECTS
                );
            }
            stale_ids.insert(stale.object);
            if !stale_replacements.insert(candidate.replacement) {
                bail!(
                    "manifest {} maps more than one stale object to the same scanned replacement",
                    input.path.display()
                );
            }
            stale_candidates.push(candidate.clone());
            pending_fallbacks.push(PendingManifestFallback {
                manifest: manifest_number,
                object: stale.object,
                reason: stale.reason,
                candidate,
            });
            counters.notes.push(format!(
                "ignoring stale object {} from manifest {} ({}) because the memory scan pinned an exact replacement and covered every dropped function claim",
                stale.object,
                input.path.display(),
                stale.reason.label(),
            ));
        }
        let stale_module = manifest
            .objects
            .iter()
            .find(|object| object.path == manifest.module_path)
            .is_some_and(|object| stale_ids.contains(&object.id));
        if stale_module {
            let matched: Vec<_> = scan_modules
                .iter()
                .filter(|module| {
                    stale_candidates.iter().any(|candidate| {
                        module.view == candidate.module_view
                            && module.key == candidate.module_key
                            && module.path == candidate.module_path
                    })
                })
                .collect();
            let owners: Vec<_> = matched
                .iter()
                .map(|module| OutcomeOwner::Scan(ScanOutcomeLocator::module(module)))
                .collect();
            if owners.is_empty() {
                bail!(
                    "stale manifest module had no exact scanned object instance to bind after reconciliation"
                );
            }
            pending_outcomes.push(PendingCorroboration {
                owners,
                label: "object_fallback",
            });
            continue;
        }
        if !stale_ids.is_empty() {
            filter_manifest_fallbacks(&mut manifest, &stale_ids)?;
        }
        let view = scan_view(&manifest, &scan_modules, &pinned, manifest_pins);
        let scan_targets = view
            .as_ref()
            .and_then(|view| scanned_targets_without(&view.modules, &pinned, &stale_replacements));
        let own_targets = manifest_targets(&manifest, manifest_pins);
        let scan_empty = view.as_ref().is_some_and(|view| {
            view.modules
                .iter()
                .flat_map(|module| &module.tables)
                .all(|table| table.entries.is_empty())
        });
        let outcome = corroborate(
            counters.scan_unavailable.is_some(),
            view.as_ref().map(|view| view.agrees),
            scan_targets
                .as_ref()
                .zip(own_targets.as_ref())
                .is_some_and(|(scan, own)| pinned.exactly_same_targets(scan, manifest_pins, own)),
            scan_empty,
        );
        if outcome != Corroboration::IdentityMismatch {
            pending_outcomes.push(pending_corroboration(
                view.as_ref(),
                &manifest,
                manifest_pins,
                corroboration_label(outcome),
            )?);
        }
        match outcome {
            Corroboration::Agreed => {
                retarget_to_pins(
                    &mut manifest,
                    view.as_ref().map_or(&[], |view| view.modules.as_slice()),
                    &pinned,
                    manifest_pins,
                );
                accepted.push(manifest);
                accepted_ordinals.push(manifest_number);
                let absorbed = pinned.absorb(manifest_pins.clone());
                attribution::note_all(&absorbed);
                counters.object_skips.extend(absorbed);
            }
            Corroboration::ScanEmpty => {
                counters.notes.push(format!(
                    "the memory scan decoded no function table in {}; attaching the \
                     offsets manifest {} records, uncorroborated",
                    manifest.module_path,
                    input.path.display(),
                ));
                retarget_to_pins(
                    &mut manifest,
                    view.as_ref().map_or(&[], |view| view.modules.as_slice()),
                    &pinned,
                    manifest_pins,
                );
                accepted.push(manifest);
                accepted_ordinals.push(manifest_number);
                let absorbed = pinned.absorb(manifest_pins.clone());
                attribution::note_all(&absorbed);
                counters.object_skips.extend(absorbed);
            }
            Corroboration::Conflict => {
                counters.conflicts += 1;
                counters.notes.push(format!(
                    "manifest {} and the memory scan decoded different targets in {}; \
                     attaching the union of both",
                    input.path.display(),
                    manifest.module_path
                ));
                retarget_to_pins(
                    &mut manifest,
                    view.as_ref().map_or(&[], |view| view.modules.as_slice()),
                    &pinned,
                    manifest_pins,
                );
                accepted.push(manifest);
                accepted_ordinals.push(manifest_number);
                let absorbed = pinned.absorb(manifest_pins.clone());
                attribution::note_all(&absorbed);
                counters.object_skips.extend(absorbed);
            }
            Corroboration::Uncorroborated => {
                retarget_to_pins(&mut manifest, &[], &pinned, manifest_pins);
                accepted.push(manifest);
                accepted_ordinals.push(manifest_number);
                let absorbed = pinned.absorb(manifest_pins.clone());
                attribution::note_all(&absorbed);
                counters.object_skips.extend(absorbed);
            }
            Corroboration::IdentityMismatch => {
                identity_mismatches += 1;
                counters.notes.push(format!(
                    "ignoring manifest {}: the {} mapped in the target does not hash to \
                     the sha256 it records",
                    input.path.display(),
                    manifest.module_path
                ));
            }
        }
    }

    // Pre-6.8 overlayfs splits the manifest join: the helper recorded the
    // maps/backing key while each manifest pin files the opened fd's overlay
    // key. Re-file every split alias onto its scan pin — proved by the shared
    // self-mapping probe — so plan lowering and every later exact join
    // resolve one provider. Exact captures never consult the probe.
    for manifest in &accepted {
        for object in &manifest.objects {
            let Some((key, path)) = capture_manifest_object_key(manifest, object.id) else {
                continue;
            };
            pinned.refile_split_manifest_alias(
                key,
                path,
                &mut discovered.budget,
                &KernelSelfMappingProbe,
            );
        }
    }

    discovered.stage_timings.span(
        crate::timing::StageKind::Merge,
        "rebuild_aggregate",
        aggregate_start,
        crate::attach::monotonic_ns(),
    );
    let bind_start = crate::attach::monotonic_ns();
    let (mut modules, differed) = bind_scanned_modules(&scan_modules, &mut pinned);
    discovered.stage_timings.span(
        crate::timing::StageKind::Bind,
        "bind_rebuild",
        bind_start,
        crate::attach::monotonic_ns(),
    );
    attribution::note_all(&differed);
    counters.object_skips.extend(differed);
    let proofs_start = crate::attach::monotonic_ns();
    let corroborated =
        bind_pending_corroboration(pending_outcomes, &modules, &pinned, &mut counters)?;

    let mut replacements = BTreeSet::new();
    for pending in pending_fallbacks {
        let Some((replacement, proof)) = bind_fallback_proof(&pending.candidate, &modules) else {
            bail!(
                "manifest {} object {} lost its exact scanned fallback proof during identity reconciliation",
                pending.manifest,
                pending.object
            );
        };
        // The manifest structurally agreed with these scan tables — the proof
        // verified version, name claims, and exact targets — so they inherit
        // the manifest's name authority ("or-manifest" authorization). Without
        // this, the mislabel guard would present the replacement's ordinal
        // labels as `unknown` and the proof could never complete in the plan.
        for module in modules.iter_mut().filter(|module| {
            module.scanned.view == pending.candidate.module_view
                && module.scanned.key == pending.candidate.module_key
                && module.scanned.path == pending.candidate.module_path
        }) {
            for table in module.scanned.tables.iter_mut() {
                if proof
                    .tables
                    .iter()
                    .any(|bound| bound.address == table.address)
                {
                    table.manifest_supported = true;
                }
            }
        }
        if !replacements.insert(replacement) {
            bail!(
                "more than one stale manifest object maps to the same canonical scanned replacement"
            );
        }
        counters.manifest_fallbacks.push(ManifestFallback {
            manifest: pending.manifest,
            object: pending.object,
            reason: pending.reason,
            replacement,
            proof,
        });
    }
    discovered.stage_timings.span(
        crate::timing::StageKind::Merge,
        "rebuild_bind_proofs",
        proofs_start,
        crate::attach::monotonic_ns(),
    );
    let plan_start = crate::attach::monotonic_ns();
    let manifest_fallbacks = counters.manifest_fallbacks.len();
    let broad_admit = discovered.broad_admit;
    let admission_scope = discovered.admission_scope();
    let mut plan = build_current_plan(
        &modules,
        &accepted,
        &pinned,
        &mut counters,
        &corroborated,
        identity_mismatches,
        manifest_fallbacks,
        broad_admit,
        admission_scope,
    )
    .inspect_err(|_| counters.report_notes())?;
    discovered
        .capture_facts
        .bind_plan_module_ids(&mut plan, &modules, &accepted, &pinned)?;
    let allocated = plan.clone();
    let (_, selection_refusals) = lower_manifest_selection_tables(
        &mut plan,
        &allocated,
        &accepted,
        &accepted_ordinals,
        &pinned,
    );
    for reason in selection_refusals {
        counters.object_skips.push(Skipped {
            subject: "offline interface selection".into(),
            reason,
        });
    }
    record_object_skips(&mut plan, &counters.object_skips);
    if let Some(fallback) = counters
        .manifest_fallbacks
        .iter()
        .find(|fallback| !fallback_proof_in_plan(&fallback.proof, &plan))
    {
        bail!(
            "manifest {} object {} has no complete scanned fallback proof in the final attach plan",
            fallback.manifest,
            fallback.object
        );
    }
    if pinned.has_overlay_uncertainty() {
        discovered.invalidate_causal_timing();
    }
    discovered.stage_timings.span(
        crate::timing::StageKind::Plan,
        "build_initial_plan",
        plan_start,
        crate::attach::monotonic_ns(),
    );
    let evidence_start = crate::attach::monotonic_ns();
    let discovery = discovery_evidence(&plan, &pinned, &counters);
    discovered.stage_timings.span(
        crate::timing::StageKind::Projection,
        "build_initial_evidence",
        evidence_start,
        crate::attach::monotonic_ns(),
    );
    discovered.plan = plan;
    discovered.pinned = pinned;
    discovered.discovery = discovery;
    discovered.modules = modules;
    discovered.manifests = accepted;
    discovered.manifest_ordinals = accepted_ordinals;
    discovered.counters = counters;
    discovered.identity_mismatches = identity_mismatches;
    Ok(())
}

fn remove_stale_views(discovered: &mut Engine, stale: &[ProcessViewId]) -> Result<usize> {
    let accepted: BTreeSet<_> = discovered.views.iter().map(ProcessView::id).collect();
    let stale: BTreeSet<_> = stale
        .iter()
        .copied()
        .filter(|view| accepted.contains(view))
        .collect();
    discovered.close_cgroup_admissions_at_removal(&stale);
    discovered.settle_leader_exits_at_removal(stale.iter().copied());
    let before = discovered.views.len();
    discovered.views.retain(|view| !stale.contains(&view.id()));
    let removed = before - discovered.views.len();
    if removed == 0 {
        bail!("lifecycle check did not identify an accepted process view");
    }
    for view in stale {
        discovered.release_view_id(view);
        discovered.scan_inputs.remove(&view);
        let skipped = Skipped {
            subject: "process view".into(),
            reason: STALE_VIEW_REASON.into(),
        };
        discovered
            .base_counters
            .noise
            .note_skip(&skipped.subject, &skipped.reason);
        attribution::note(&skipped);
        discovered.base_counters.object_skips.push(skipped);
    }
    rebuild_discovered(discovered)?;
    // Stale removals happen during attach preparation, after the initial
    // report: flush their summaries now so the operator sees them before the
    // capture starts, and live accumulation starts fresh.
    discovered.counters.noise.report();
    discovered.counters.noise.clear();
    discovered.base_counters.noise.clear();
    for input in discovered.scan_inputs.values_mut() {
        input.counters.noise.clear();
    }
    Ok(removed)
}

fn start_retained_with<S>(
    discovered: &mut Engine,
    named: bool,
    mut stale_views: impl FnMut(&[ProcessView]) -> Vec<ProcessViewId>,
    mut start: impl FnMut(&plan::AttachPlan, &PinnedObjects) -> Result<S>,
) -> Result<S> {
    if named && discovered.views.len() != 1 {
        bail!("the named process generation was not retained through discovery");
    }
    // Before any session exists a stale view costs one plan rebuild, and each
    // pass removes at least one accepted view, so this is bounded by them.
    loop {
        let stale = stale_views(&discovered.views);
        if stale.is_empty() {
            break;
        }
        if named {
            bail!("the named process generation changed before attach");
        }
        remove_stale_views(discovered, &stale)?;
    }

    let session = start(&discovered.plan, &discovered.pinned)?;
    let stale = stale_views(&discovered.views);
    if stale.is_empty() {
        return Ok(session);
    }
    if named {
        // No event/map consumer can see this session. Dropping it first tears
        // down every just-created link before the named capture fails.
        drop(session);
        bail!("the named process generation changed while attaching");
    }
    // H-2: a multi-process capture starts once. Restarting the whole session
    // for an ambient exit during the seconds-long load and attach detached
    // every link and attached them all again, once per exit and with no bound.
    // A view that went stale meanwhile is retired live instead, like any
    // member that ends mid-capture: the startup record pass settles it — a
    // provable exit as an expected removal, anything else as a counted
    // generation loss — and its conservative replay retires every endpoint
    // only that view owned. Until then its links stay exactly the ones the
    // accepted plan names.
    let stale: BTreeSet<_> = stale.into_iter().collect();
    discovered.queue_stale_views(&stale, &mut PendingViewRetirements::new());
    Ok(session)
}

fn export_abi(kind: u8) -> Option<HookAbi> {
    match kind {
        DISCOVERY_KIND_FUNCTION_LIST_RETURN => Some(HookAbi::FunctionList),
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN => Some(HookAbi::InterfaceList),
        DISCOVERY_KIND_INTERFACE_RETURN => Some(HookAbi::Interface),
        _ => None,
    }
}

/// The table version a record's carried prefix claims, when it claims
/// one. Export records carry the raw word; selection records carry the
/// probe's version class instead (their raw word fields stay zero by
/// transport contract). An unknown class claims nothing: the prefix is
/// unusable and the table must re-validate from memory alone.
fn record_prefix_version(record: &DiscoveryRecord) -> Option<(u8, u8)> {
    if record.kind == DISCOVERY_KIND_INTERFACE_RETURN {
        return match record.selection_version_class {
            DISCOVERY_VERSION_V2_40 => Some((2, 40)),
            DISCOVERY_VERSION_V3_0 => Some((3, 0)),
            DISCOVERY_VERSION_V3_1 => Some((3, 1)),
            DISCOVERY_VERSION_V3_2 => Some((3, 2)),
            _ => None,
        };
    }
    Some((record.version_major, record.version_minor))
}

fn interface_list_is_truncated(record: &DiscoveryRecord) -> bool {
    record.kind == DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN
        && record.interface_index == 0
        && record.announced_count > u32::from(DISCOVERY_INTERFACES)
}

fn name_class(class: u8) -> &'static str {
    match class {
        DISCOVERY_NAME_EXACT_STANDARD => "exact_standard",
        DISCOVERY_NAME_OTHER => "other",
        DISCOVERY_NAME_NULL => "null",
        _ => "unreadable",
    }
}

/// Outcome of heap-wrapper export lowering: an admitted module, or an
/// explicit refusal the caller publishes as live loss. Refusals degrade
/// confidence — they never claim the table is absent.
enum HeapLowerOutcome {
    Admitted(ScannedModule),
    Refused(&'static str),
}

/// Why one bounded exact-address validation failed. The selection path
/// collapses these to its historical unit loss; heap-wrapper lowering
/// publishes each as a distinct live loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExactReadRefusal {
    /// No readable mapping contains the table address.
    Unreadable,
    /// The bytes at the address are not a function table.
    Undecodable,
    /// The mappings moved, or the generation changed, under the read.
    Unstable,
    /// A decode budget ceiling stopped the validation.
    Budget,
}

/// Attributes a heap/anonymous published table to the provider that
/// returned it. The table's own mapping names no file, so ownership is
/// resolved from the factory that published it plus the exact validated
/// entries: candidates are the scanned modules in this view exporting the
/// hook symbol, and the winner must also hold entry targets — except the
/// proxy shape, where the sole factory exporter owns a table pointing
/// elsewhere. Anything ambiguous refuses: attribution is exact or absent.
fn resolve_heap_table_owner(
    hook: &str,
    view: ProcessViewId,
    entries: &[ScannedEntry],
    modules: &[ReconciledModule],
) -> Option<(ObjectKey, String)> {
    let exporters: Vec<&ScannedModule> = modules
        .iter()
        .map(|module| &module.scanned)
        .filter(|module| module.view == view && module.exports.iter().any(|name| name == hook))
        .collect();
    if exporters.is_empty() {
        return None;
    }
    let holders: Vec<&&ScannedModule> = exporters
        .iter()
        .filter(|module| entries.iter().any(|entry| entry.object == module.key))
        .collect();
    if holders.len() == 1 {
        let winner = holders[0];
        return Some((winner.key, winner.path.clone()));
    }
    if holders.is_empty() && exporters.len() == 1 {
        let winner = exporters[0];
        return Some((winner.key, winner.path.clone()));
    }
    None
}

/// Decoder layouts for one heap-table exact read, strongest first: the
/// scanned hook exporters' ABI when they agree, both widths otherwise.
/// At most two bounded reads; a wrong width fails fast on the version word.
fn heap_table_layouts(
    hook: &str,
    view: ProcessViewId,
    modules: &[ReconciledModule],
) -> Vec<LinuxLayout> {
    let mut abis = BTreeSet::new();
    for module in modules.iter().map(|module| &module.scanned) {
        if module.view == view
            && module.exports.iter().any(|name| name == hook)
            && let Some(abi) = module.decoder_abi
        {
            abis.insert(abi);
        }
    }
    if let Some(abi) = abis.iter().next().filter(|_| abis.len() == 1) {
        return vec![target_layout(*abi)];
    }
    vec![LinuxLayout::Lp64, LinuxLayout::Ilp32]
}

/// Lowers one already-decoded export record through the same table-layout and
/// mapping authority as the memory scanner. Runtime addresses and custom hook
/// names remain private inputs to the candidate transaction.
fn lower_export_record(
    view: &ProcessView,
    maps: &MapIndex<'_>,
    hooks: &HookRegistry,
    record: &DiscoveryRecord,
    budget: &mut CaptureWorkBudget,
) -> Result<Option<ScannedModule>, String> {
    if record.kind == DISCOVERY_KIND_INTERFACE_RETURN {
        return Err("selection record reached export lowering".into());
    }
    lower_publication_record(view, maps, hooks, record, budget, None)
}

/// The shared file-backed lowering behind export records and supported
/// `C_GetInterface` results (Package F): a selection record carries no
/// symbol ID — the transport binds it to a capture-local hook instead —
/// so its caller passes that hook as `gi_hook`. Selection results lower
/// exactly like list elements, except their interface stays unlinked: a
/// selection result has no list position, so none may widen into linkage.
fn lower_publication_record(
    view: &ProcessView,
    maps: &MapIndex<'_>,
    hooks: &HookRegistry,
    record: &DiscoveryRecord,
    budget: &mut CaptureWorkBudget,
    gi_hook: Option<(&str, HookAbi)>,
) -> Result<Option<ScannedModule>, String> {
    if !valid_discovery_record(record) {
        return Err("malformed discovery record reached export lowering".into());
    }
    let Some(expected_abi) = export_abi(record.kind) else {
        return Err("non-export discovery record reached export lowering".into());
    };
    let (hook_name, abi) = match record.kind {
        DISCOVERY_KIND_INTERFACE_RETURN => {
            gi_hook.ok_or("selection record reached export lowering without its bound hook")?
        }
        _ => {
            if gi_hook.is_some() {
                return Err("export record reached export lowering with a selection hook".into());
            }
            let Some(resolved) = hooks.by_id(record.symbol_id) else {
                return Err("export record names an unknown private hook ID".into());
            };
            resolved
        }
    };
    if abi != expected_abi {
        return Err("export record kind disagrees with its private hook ABI".into());
    }
    if record.usable_n == 0 {
        return Ok(None);
    }
    if !view.still_the_same() {
        return Err("process generation changed before export lowering".into());
    }
    // The live path's one clock poll per record: nothing between the bounded
    // snapshot read and this decode polls the batch deadline, and a sticky stop
    // another consumer of the one budget left must refuse the record here — the
    // caller publishes either as live loss. Admission below refuses on the
    // sticky stop too; a decode ceiling stays the count-only outcome it was.
    if let Some(reason) = budget.stopped_now() {
        return Err(reason.into());
    }

    budget.spend(1)?;
    let Resolved::File {
        path: MappedPath::Usable(owner_path),
        device: owner_device,
        inode: owner_inode,
        file_offset: table_file_offset,
        permissions: owner_permissions,
        ..
    } = maps.resolve(record.table_ptr)
    else {
        return Ok(None);
    };
    if owner_inode == 0 || owner_permissions[0] != b'r' {
        return Ok(None);
    }

    let Some((prefix_major, prefix_minor)) = record_prefix_version(record) else {
        return Ok(None);
    };
    let word = u64::from(prefix_major) | (u64::from(prefix_minor) << 8);
    let Some((version, spans, walk)) = spans_for(word) else {
        return Ok(None);
    };
    let usable = usize::from(record.usable_n);
    if usable > spans.iter().map(|span| span.fields().len()).sum() {
        return Ok(None);
    }
    // Byte-identical repeats skip the table charge but still decode below;
    // the interface-record charge is per record, not per table, and stays.
    let identity = TableIdentity {
        device: owner_device,
        inode: owner_inode,
        file_offset: table_file_offset,
        version_word: word,
        usable,
    };
    if !budget.table_already_admitted(&identity) {
        if !budget.admit_table(usable) {
            return Ok(None);
        }
        budget.note_table_admitted(identity);
    }
    if matches!(
        record.kind,
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN | DISCOVERY_KIND_INTERFACE_RETURN
    ) && !budget.admit_interface()
    {
        return Ok(None);
    }

    let mut entries = Vec::new();
    let mut null_entries = Vec::new();
    for (field, pointer) in spans
        .iter()
        .flat_map(|span| span.fields())
        .take(usable)
        .zip(record.pointers)
    {
        if pointer == 0 {
            null_entries.push(field.name);
            continue;
        }
        budget.spend(1)?;
        let Resolved::File {
            path: MappedPath::Usable(path),
            file_offset,
            device,
            inode,
            permissions,
            ..
        } = maps.resolve(pointer)
        else {
            return Ok(None);
        };
        if inode == 0 || permissions[2] != b'x' {
            return Ok(None);
        }
        entries.push(ScannedEntry {
            name: field.name,
            object: ObjectKey { device, inode },
            object_path: path.display().to_string(),
            file_offset,
        });
    }
    if entries.is_empty() {
        return Ok(None);
    }

    let interfaces = match record.kind {
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN => vec![ScannedInterface {
            index: usize::from(record.interface_index),
            name_class: name_class(record.name_class),
            name_lossy: None,
            name_private: None,
            flags: record.interface_flags,
            table: Some(0),
        }],
        DISCOVERY_KIND_INTERFACE_RETURN => vec![ScannedInterface {
            index: usize::from(record.interface_index),
            name_class: name_class(record.name_class),
            name_lossy: None,
            name_private: None,
            flags: record.interface_flags,
            // Unlinked (see the heap arm below): the echoed index is the
            // request version class, not a list position.
            table: None,
        }],
        _ => Vec::new(),
    };
    let module = ScannedModule {
        mapped_identity: None,
        double_loaded: false,
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key: ObjectKey {
            device: owner_device,
            inode: owner_inode,
        },
        path: owner_path.display().to_string(),
        decoder_abi: None,
        exports: vec![hook_name.to_string()],
        tables: vec![ScannedTable {
            version,
            walk,
            entries,
            null_entries,
            unpinned: Vec::new(),
            address: record.table_ptr,
            file_offset: Some(table_file_offset),
            // The provider returned this table through a live export: its
            // ordinal names carry publication evidence, unlike heuristic decode.
            live_return: true,
            // Manifest agreement is derived per rebuild by fallback binding,
            // never at lowering time.
            manifest_supported: false,
        }],
        interfaces,
    };
    if !view.still_the_same() {
        return Err("process generation changed during export lowering".into());
    }
    Ok(Some(module))
}

/// Lowers a published table the file-backed prefix path could not own:
/// heap/anonymous tables (wrapper `&live->bound`, anonymous-BSS legacy)
/// and list-element records, which carry the table address but no prefix
/// by transport contract. Validates the exact returned table through the
/// same bounded exact-address reader as the selection path (maps-A
/// membership, one bounded mem read, same-decoder decode, maps-B
/// stability bracket, generation check), cross-checks a carried prefix
/// when the record has one, and attributes anonymous tables to the
/// publishing provider via the ownership contract. File-backed tables
/// keep their mapping's own owner, so a live element over a swept table
/// merges onto the scan instance instead of duplicating it.
///
/// The lowered interface stays unlinked (`table: None`): the live-return
/// flag on the table carries the publication evidence, while linkage
/// stays the sweep's own decoded triples — a live list position never
/// widens into interface linkage. Selection results lower here under
/// the same contract (their echoed index is a request class, not a
/// position at all).
fn lower_heap_publication_record(
    view: &ProcessView,
    index_a: &MapIndex<'_>,
    hooks: &HookRegistry,
    record: &DiscoveryRecord,
    modules: &[ReconciledModule],
    budget: &mut CaptureWorkBudget,
    gi_hook: Option<(&str, HookAbi)>,
) -> Result<HeapLowerOutcome, String> {
    // Mirror the file-backed path's validation: this runs only after it
    // returned None, but a record is never trusted twice — re-derive.
    if !valid_discovery_record(record) {
        return Err("malformed discovery record reached export lowering".into());
    }
    let Some(expected_abi) = export_abi(record.kind) else {
        return Err("non-export discovery record reached export lowering".into());
    };
    let (hook_name, abi) = match record.kind {
        DISCOVERY_KIND_INTERFACE_RETURN => {
            gi_hook.ok_or("selection record reached export lowering without its bound hook")?
        }
        _ => {
            if gi_hook.is_some() {
                return Err("export record reached export lowering with a selection hook".into());
            }
            let Some(resolved) = hooks.by_id(record.symbol_id) else {
                return Err("export record names an unknown private hook ID".into());
            };
            resolved
        }
    };
    if abi != expected_abi {
        return Err("export record kind disagrees with its private hook ABI".into());
    }
    if !view.still_the_same() {
        return Err("process generation changed before export lowering".into());
    }
    if let Some(reason) = budget.stopped_now() {
        return Err(reason.into());
    }
    budget.spend(1)?;

    // Strongest layout first, at most two bounded reads; the wrong width
    // fails fast on the version word.
    let mut refusals = Vec::new();
    let mut validated = None;
    for layout in heap_table_layouts(hook_name, view.id(), modules) {
        match Engine::read_exact_table_bracketed(
            view,
            record.table_ptr,
            layout,
            index_a,
            budget,
            false,
        ) {
            Ok(valid) => {
                validated = Some((layout, valid));
                break;
            }
            Err(refusal) => refusals.push(refusal),
        }
    }
    let Some((layout, (_, mut table, bytes))) = validated else {
        // The most actionable refusal first: a capture stop, then
        // instability (the world moved mid-read), then undecodability.
        let refusal = refusals
            .iter()
            .find(|refusal| **refusal == ExactReadRefusal::Budget)
            .or_else(|| {
                refusals
                    .iter()
                    .find(|refusal| **refusal == ExactReadRefusal::Unstable)
            })
            .or(refusals.first());
        return Ok(HeapLowerOutcome::Refused(match refusal {
            Some(ExactReadRefusal::Budget) => {
                "a published table validation stopped at a decode budget ceiling"
            }
            Some(ExactReadRefusal::Unstable) => {
                "a published table moved or the process generation changed during validation"
            }
            Some(ExactReadRefusal::Unreadable) => {
                "a published table address was unreadable when validated"
            }
            _ => "a published table's bytes did not decode as a function table",
        }));
    };

    // A carried prefix is the probe's observation; the mem read above is
    // the validator's. Both name the same table, or the table changed
    // under us — refuse, never blend.
    let usable = usize::from(record.usable_n);
    if usable > 0 {
        let Some(prefix_version) = record_prefix_version(record) else {
            return Ok(HeapLowerOutcome::Refused(
                "a published selection result carried a table prefix with an unknown version class",
            ));
        };
        if prefix_version != table.version {
            return Ok(HeapLowerOutcome::Refused(
                "a published table changed between the probe capture and validation",
            ));
        }
        let mut matches = true;
        for (ordinal, expected) in record.pointers.iter().take(usable).enumerate() {
            match read_function_pointer(&bytes, layout, ordinal) {
                Ok(actual) if actual == *expected => {}
                _ => {
                    matches = false;
                    break;
                }
            }
        }
        if !matches {
            return Ok(HeapLowerOutcome::Refused(
                "a published table changed between the probe capture and validation",
            ));
        }
    }

    // Ownership: a file-backed table names its own file; an anonymous one
    // is attributed to its publishing provider — exact or absent.
    let file_owner = match index_a.resolve(record.table_ptr) {
        Resolved::File {
            path: MappedPath::Usable(path),
            device,
            inode,
            file_offset,
            ..
        } if inode != 0 => Some((
            ObjectKey { device, inode },
            path.display().to_string(),
            file_offset,
        )),
        _ => None,
    };
    let (key, path) = match file_owner {
        Some((key, path, file_offset)) => {
            table.file_offset = Some(file_offset);
            (key, path)
        }
        None => {
            table.file_offset = None;
            match resolve_heap_table_owner(hook_name, view.id(), &table.entries, modules) {
                Some(owner) => owner,
                None => {
                    return Ok(HeapLowerOutcome::Refused(
                        "a published heap table could not be attributed to exactly one provider",
                    ));
                }
            }
        }
    };

    // The provider returned this table through a live export: its ordinal
    // names carry publication evidence, unlike heuristic decode. Manifest
    // agreement is derived per rebuild by fallback binding, never here.
    table.live_return = true;
    table.manifest_supported = false;
    if matches!(
        record.kind,
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN | DISCOVERY_KIND_INTERFACE_RETURN
    ) && !budget.admit_interface()
    {
        return Ok(HeapLowerOutcome::Refused(
            "the interface-record ceiling refused a published list element",
        ));
    }

    let interfaces = match record.kind {
        DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN | DISCOVERY_KIND_INTERFACE_RETURN => {
            vec![ScannedInterface {
                index: usize::from(record.interface_index),
                name_class: name_class(record.name_class),
                name_lossy: None,
                name_private: None,
                flags: record.interface_flags,
                // Unlinked by contract (see above): no widening.
                table: None,
            }]
        }
        _ => Vec::new(),
    };
    let module = ScannedModule {
        mapped_identity: None,
        double_loaded: false,
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key,
        path,
        decoder_abi: None,
        exports: vec![hook_name.to_string()],
        tables: vec![table],
        interfaces,
    };
    if !view.still_the_same() {
        return Err("process generation changed during export lowering".into());
    }
    Ok(HeapLowerOutcome::Admitted(module))
}

/// Whether `module` has no counterpart among already-retained modules:
/// the same (view, mount namespace, object key, path) match
/// `merge_scanned_module` unions on, ignoring decoder ABI (an
/// ABI-mismatched twin keeps its raw pins; binding drops whichever twin it
/// cannot use). The retention tests keep this predicate in sync with that
/// union.
fn is_newly_observed_module(retained: &[ScannedModule], module: &ScannedModule) -> bool {
    !retained.iter().any(|known| {
        known.view == module.view
            && known.mount_namespace == module.mount_namespace
            && known.key == module.key
            && known.path == module.path
    })
}

fn merge_scanned_module(modules: &mut Vec<ScannedModule>, mut incoming: ScannedModule) {
    let Some(position) = modules.iter().position(|module| {
        module.view == incoming.view
            && module.mount_namespace == incoming.mount_namespace
            && module.key == incoming.key
            && module.path == incoming.path
    }) else {
        modules.push(incoming);
        return;
    };
    if matches!(
        (modules[position].decoder_abi, incoming.decoder_abi),
        (Some(existing), Some(incoming)) if existing != incoming
    ) {
        modules.push(incoming);
        return;
    }
    let existing = &mut modules[position];
    if existing.decoder_abi.is_none() {
        existing.decoder_abi = incoming.decoder_abi;
    }
    // Same-file double-load evidence unions (F7d): an incomplete,
    // revalidated memory rescan merges newly found modules into
    // retained ones, and neither side may drop the other's positive
    // verdict — a partial pass that sees one load is not fresh
    // evidence of one load, and a newly detected double-load must
    // land on its retained module. Clearing happens only by
    // complete-scan replacement (fresh `found` evidence rebuilds
    // the view's modules outright), never by union.
    existing.double_loaded |= incoming.double_loaded;
    for export in incoming.exports.drain(..) {
        if !existing.exports.contains(&export) {
            existing.exports.push(export);
        }
    }
    let mut table_indices = Vec::new();
    for table in incoming.tables.drain(..) {
        let index = existing.tables.iter().position(|known| *known == table);
        table_indices.push(match index {
            Some(index) => {
                // Same table seen twice: publication evidence unions —
                // whichever instance observed it, the table was observed.
                existing.tables[index].live_return |= table.live_return;
                existing.tables[index].manifest_supported |= table.manifest_supported;
                index
            }
            None => {
                existing.tables.push(table);
                existing.tables.len() - 1
            }
        });
    }
    for mut interface in incoming.interfaces.drain(..) {
        interface.table = interface
            .table
            .and_then(|index| table_indices.get(index).copied());
        if let Some(known) = existing.interfaces.iter_mut().find(|known| {
            known.index == interface.index
                && known.name_class == interface.name_class
                && known.flags == interface.flags
                && known.table == interface.table
        }) {
            if known.name_lossy.is_none() {
                known.name_lossy = interface.name_lossy;
            }
            if known.name_private.is_none() {
                known.name_private = interface.name_private;
            }
        } else {
            existing.interfaces.push(interface);
        }
    }
}

fn usable_path(maps: &MapIndex<'_>, mapping: &MapEntry) -> Option<PathBuf> {
    match maps.resolve(mapping.start) {
        Resolved::File {
            path: MappedPath::Usable(path),
            inode,
            ..
        } if inode != 0 => Some(path),
        _ => None,
    }
}

#[cfg(test)]
fn exact_executable_mapping<'a>(
    maps: &MapIndex<'a>,
    identity: ObjectKey,
) -> Option<(&'a MapEntry, PathBuf)> {
    maps.entries()
        .iter()
        .filter(|mapping| mapping.permissions[2] == b'x' && ObjectKey::of(mapping) == identity)
        .find_map(|mapping| usable_path(maps, mapping).map(|path| (mapping, path)))
}

#[cfg(test)]
const ELF_HEADER_BYTES: usize = 64;
#[cfg(test)]
const ELF_PROGRAM_HEADER_BYTES: usize = 56;
const MAX_PROGRAM_HEADER_TABLE_BYTES: usize = 64 * 1024;
const MAX_INTERPRETER_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSnapshot {
    device: u64,
    inode: u64,
    size: u64,
    ctime: i64,
    ctime_ns: i64,
}

impl FileSnapshot {
    fn read(file: &std::fs::File) -> std::result::Result<Self, String> {
        let metadata = file
            .metadata()
            .map_err(|error| format!("cannot stat retained executable: {error}"))?;
        if !metadata.file_type().is_file() {
            return Err("retained executable is not a regular file".into());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            ctime: metadata.ctime(),
            ctime_ns: metadata.ctime_nsec(),
        })
    }
}

fn read_exact_at(
    file: &std::fs::File,
    bytes: &mut [u8],
    offset: u64,
) -> std::result::Result<(), String> {
    let mut done = 0usize;
    while done < bytes.len() {
        let at = offset
            .checked_add(done as u64)
            .ok_or_else(|| "bounded ELF read offset overflowed".to_string())?;
        let read = file
            .read_at(&mut bytes[done..], at)
            .map_err(|error| format!("bounded ELF pread failed: {error}"))?;
        if read == 0 {
            return Err("bounded ELF pread ended before the requested bytes".into());
        }
        done += read;
    }
    Ok(())
}

fn little_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("a two-byte ELF field"))
}

fn little_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("a four-byte ELF field"))
}

fn little_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("an eight-byte ELF field"))
}

fn read_bounded_interpreter(
    file: &std::fs::File,
    size: u64,
) -> std::result::Result<(Option<PathBuf>, ElfAbi), String> {
    let mut ident = [0u8; 16];
    read_exact_at(file, &mut ident, 0)?;
    let (abi, header_bytes, program_bytes, machine) = match ident[4] {
        1 => (ElfAbi::Ilp32, 52, 32, 3),
        2 => (ElfAbi::Lp64, 64, 56, 62),
        _ => return Err("retained executable has an unsupported ELF class".into()),
    };
    let mut header = vec![0u8; header_bytes];
    read_exact_at(file, &mut header, 0)?;
    if &header[..4] != b"\x7fELF"
        || header[5] != 1
        || header[6] != 1
        || !matches!(little_u16(&header[16..18]), 2 | 3)
        || little_u16(&header[18..20]) != machine
        || little_u32(&header[20..24]) != 1
    {
        return Err("retained executable is not a supported conventional x86 ELF".into());
    }
    let (table_offset, ehsize_at, phentsize_at, phnum_at) = match abi {
        ElfAbi::Lp64 => (little_u64(&header[32..40]), 52, 54, 56),
        ElfAbi::Ilp32 => (u64::from(little_u32(&header[28..32])), 40, 42, 44),
    };
    if little_u16(&header[ehsize_at..ehsize_at + 2]) as usize != header_bytes
        || little_u16(&header[phentsize_at..phentsize_at + 2]) as usize != program_bytes
    {
        return Err("retained executable has a noncanonical program-header layout".into());
    }
    let count = little_u16(&header[phnum_at..phnum_at + 2]);
    if count == 0 || count == 0xffff {
        return Err("retained executable has no bounded ordinary program-header table".into());
    }
    let table_len = usize::from(count)
        .checked_mul(program_bytes)
        .filter(|length| *length <= MAX_PROGRAM_HEADER_TABLE_BYTES)
        .ok_or_else(|| "retained executable program-header table is too large".to_string())?;
    table_offset
        .checked_add(table_len as u64)
        .filter(|end| *end <= size)
        .ok_or_else(|| "retained executable program-header table is out of bounds".to_string())?;
    let mut table = vec![0u8; table_len];
    read_exact_at(file, &mut table, table_offset)?;

    let mut interpreter = None;
    for program in table.chunks_exact(program_bytes) {
        if little_u32(&program[..4]) != 3 {
            continue;
        }
        if interpreter.is_some() {
            return Err("retained executable has more than one PT_INTERP".into());
        }
        let (offset, length) = match abi {
            ElfAbi::Lp64 => (
                little_u64(&program[8..16]),
                little_u64(&program[32..40])
                    .try_into()
                    .map_err(|_| "PT_INTERP length does not fit usize".to_string())?,
            ),
            ElfAbi::Ilp32 => (
                u64::from(little_u32(&program[4..8])),
                little_u32(&program[16..20]) as usize,
            ),
        };
        if !(2..=MAX_INTERPRETER_BYTES).contains(&length) {
            return Err("PT_INTERP length is outside the bounded range".into());
        }
        offset
            .checked_add(length as u64)
            .filter(|end| *end <= size)
            .ok_or_else(|| "PT_INTERP range is out of bounds".to_string())?;
        let mut bytes = vec![0u8; length];
        read_exact_at(file, &mut bytes, offset)?;
        let Some(path) = bytes.strip_suffix(&[0]) else {
            return Err("PT_INTERP is not terminated by one trailing NUL".into());
        };
        if path.is_empty() || path.contains(&0) || path[0] != b'/' {
            return Err("PT_INTERP is not one nonempty absolute path".into());
        }
        interpreter = Some(PathBuf::from(std::ffi::OsStr::from_bytes(path)));
    }
    Ok((interpreter, abi))
}

fn loader_state_address(snapshot: &ElfSnapshot) -> std::result::Result<Option<u64>, String> {
    let offset = match snapshot.abi() {
        ElfAbi::Lp64 => 24,
        ElfAbi::Ilp32 => 12,
    };
    snapshot
        .defined_symbol_virtual_address("_r_debug", offset + 4)?
        .map(|address| {
            address
                .checked_add(offset as u64)
                .ok_or_else(|| "loader r_state address overflows u64".to_string())
        })
        .transpose()
}

const NO_EXECUTABLE_MAPPING_REASON: &str = "retained executable has no usable executable mapping";
const NO_LOADER_MAPPING_REASON: &str = "PT_INTERP has no usable executable loader mapping";

fn executable_map_snapshot(
    maps: &MapIndex<'_>,
    identity: ObjectKey,
    budget: &mut CaptureWorkBudget,
) -> std::result::Result<Vec<(MapEntry, PathBuf)>, String> {
    let mut mappings = Vec::new();
    for mapping in maps.entries() {
        budget.spend(1)?;
        if mapping.permissions[2] != b'x' || ObjectKey::of(mapping) != identity {
            continue;
        }
        budget.spend(1)?;
        if let Some(path) = usable_path(maps, mapping) {
            mappings.push((mapping.clone(), path));
        }
    }
    if mappings.is_empty() {
        return Err(NO_EXECUTABLE_MAPPING_REASON.into());
    }
    Ok(mappings)
}

fn loader_map_snapshot(
    maps: &MapIndex<'_>,
    identity: ObjectKey,
    budget: &mut CaptureWorkBudget,
) -> std::result::Result<(PathBuf, Vec<MapEntry>), String> {
    let mut by_path: BTreeMap<PathBuf, Vec<MapEntry>> = BTreeMap::new();
    for mapping in maps.entries() {
        budget.spend(1)?;
        if mapping.permissions[2] != b'x' || ObjectKey::of(mapping) != identity {
            continue;
        }
        budget.spend(1)?;
        if let Some(path) = usable_path(maps, mapping) {
            by_path.entry(path).or_default().push(mapping.clone());
        }
    }
    let mut by_path = by_path.into_iter();
    let Some(loader) = by_path.next() else {
        return Err(NO_LOADER_MAPPING_REASON.into());
    };
    if by_path.next().is_some() {
        return Err("PT_INTERP mapping identity has more than one usable path".into());
    }
    Ok(loader)
}

/// The executable snapshot for one retained fd: on pre-6.8 kernels an
/// overlayfs fd's own key finds no mapping (maps prints the backing device),
/// so retry once on the key the kernel renders for this exact fd. Any other
/// error — budget, ambiguity — keeps today's outcome unchanged.
fn executable_snapshot_for_fd(
    maps: &MapIndex<'_>,
    file: &std::fs::File,
    fd_key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    probe: &impl SelfMappingProbe,
) -> std::result::Result<Vec<(MapEntry, PathBuf)>, String> {
    match executable_map_snapshot(maps, fd_key, budget) {
        Err(error) if error == NO_EXECUTABLE_MAPPING_REASON => {
            match self_mapped_fallback_key(file, fd_key, budget, probe) {
                Some(probed) => executable_map_snapshot(maps, probed, budget),
                None => Err(error),
            }
        }
        outcome => outcome,
    }
}

/// The loader snapshot for one retained fd: the same overlay fallback as
/// [`executable_snapshot_for_fd`].
fn loader_snapshot_for_fd(
    maps: &MapIndex<'_>,
    file: &std::fs::File,
    fd_key: ObjectKey,
    budget: &mut CaptureWorkBudget,
    probe: &impl SelfMappingProbe,
) -> std::result::Result<(PathBuf, Vec<MapEntry>), String> {
    match loader_map_snapshot(maps, fd_key, budget) {
        Err(error) if error == NO_LOADER_MAPPING_REASON => {
            match self_mapped_fallback_key(file, fd_key, budget, probe) {
                Some(probed) => loader_map_snapshot(maps, probed, budget),
                None => Err(error),
            }
        }
        outcome => outcome,
    }
}

fn unique_mapping_for_offset(
    mappings: &[MapEntry],
    offset: u64,
) -> std::result::Result<MapEntry, String> {
    let mut matches = mappings.iter().filter(|mapping| {
        let len = mapping.end.saturating_sub(mapping.start);
        (mapping.file_offset..mapping.file_offset.saturating_add(len)).contains(&offset)
    });
    let Some(mapping) = matches.next() else {
        return Err("offset does not resolve inside an exact executable mapping".into());
    };
    if matches.next().is_some() {
        return Err("offset resolves inside more than one exact executable mapping".into());
    }
    Ok(mapping.clone())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LoaderAuthority {
    executable_file: FileSnapshot,
    executable_key: ObjectKey,
    executable_maps: Vec<(MapEntry, PathBuf)>,
    executable_abi: ElfAbi,
    interpreter: PathBuf,
    interpreter_file: FileSnapshot,
    loader_key: ObjectKey,
    loader_path: PathBuf,
    loader_maps: Vec<MapEntry>,
}

struct LoaderLocator {
    authority: LoaderAuthority,
    maps: Vec<MapEntry>,
}

fn candidate_identity_is_complete(
    plan: &plan::AttachPlan,
    modules: &[ReconciledModule],
    pinned: &PinnedObjects,
) -> bool {
    modules
        .iter()
        .all(|module| pinned.summary(module.object).is_some())
        && plan
            .modules
            .iter()
            .all(|module| pinned.summary(module.object).is_some())
        && plan
            .slots
            .iter()
            .all(|slot| !plan.is_active(slot.index) || pinned.summary(slot.object).is_some())
}

fn candidate_admission(
    views: &[ProcessView],
    extra_views: &[&ProcessView],
    candidate_views: &BTreeSet<ProcessViewId>,
    loader_registry: &LoaderRegistry,
    candidate_pins: &PinnedObjects,
    committed_pins: &PinnedObjects,
    targets_ok: bool,
) -> CandidateAdmission {
    CandidateAdmission {
        stale_views: stale_process_views(views, extra_views, candidate_views),
        missing_contexts: loader_registry.contexts_missing_from(candidate_pins),
        targets_ok,
        newly_rejected_keys: candidate_pins.newly_rejected_keys(committed_pins),
    }
}

fn block_unperformed_static(
    candidate_plan: &mut plan::AttachPlan,
    delta: &plan::AttachDelta,
    owners: &BTreeMap<plan::ModuleId, PinnedTimingKey>,
    outcome: &mut ApplyOutcome,
) {
    for slot in delta.new.iter().chain(&delta.replace) {
        outcome.static_failures.extend(
            slot.module_ids
                .iter()
                .filter_map(|module| owners.get(module).cloned()),
        );
        candidate_plan.deactivate(slot.index);
    }
}

fn lose_unperformed_dynamic_work(timings: &mut CausalTimings, work: &[DynamicExportWork]) {
    for work in work {
        if !work.already_attached
            && let Some(module) = &work.module
        {
            timings.lose(module);
        }
    }
}

fn delta_timing_keys(
    delta: &plan::AttachDelta,
    owners: &BTreeMap<plan::ModuleId, PinnedTimingKey>,
) -> BTreeSet<PinnedTimingKey> {
    delta
        .new
        .iter()
        .chain(&delta.replace)
        .flat_map(|slot| slot.module_ids.iter())
        .filter_map(|module| owners.get(module).cloned())
        .collect()
}

fn slot_timing_keys(
    slot: &plan::Slot,
    owners: &BTreeMap<plan::ModuleId, PinnedTimingKey>,
) -> Vec<PinnedTimingKey> {
    slot.module_ids
        .iter()
        .filter_map(|module| owners.get(module).cloned())
        .collect()
}

fn candidate_timing_keys(
    candidate: &LiveCandidate,
    scanned: &[ScannedModule],
) -> BTreeSet<PinnedTimingKey> {
    scanned
        .iter()
        .filter_map(|module| {
            candidate
                .pinned
                .id_for_scanned(module, module.key, &module.path)
        })
        .filter_map(|object| candidate.pinned.owned_timing_key(object))
        .collect()
}

fn candidate_timing_owners(candidate: &LiveCandidate) -> BTreeMap<plan::ModuleId, PinnedTimingKey> {
    candidate
        .plan
        .modules
        .iter()
        .filter_map(|module| {
            candidate
                .pinned
                .owned_timing_key(module.object)
                .map(|key| (module.id, key))
        })
        .collect()
}

#[cfg(test)]
fn candidate_sources_without_view(
    pinned: &PinnedObjects,
    modules: &[ReconciledModule],
    view: ProcessViewId,
) -> (PinnedObjects, Vec<ScannedModule>) {
    let mut pinned = pinned.clone();
    pinned.remove_view(view);
    let modules = modules
        .iter()
        .filter(|module| module.scanned.view != view)
        .map(|module| module.scanned.clone())
        .collect();
    (pinned, modules)
}

fn commit_cleaned_candidate_identity(
    candidate: &mut LiveCandidate,
    pinned: PinnedObjects,
    modules: Vec<ReconciledModule>,
    stale_views: &BTreeSet<ProcessViewId>,
) {
    candidate.pinned = pinned;
    candidate.modules = modules;
    // No release_view_id here: candidate.views is scratch; the live views stay retained by the engine.
    candidate.views.retain(|view| !stale_views.contains(view));
    let module_objects: BTreeSet<_> = candidate
        .plan
        .modules
        .iter()
        .map(|module| module.object)
        .collect();
    candidate.corroboration.retain(|(objects, _)| {
        !objects.is_empty()
            && objects.iter().all(|object| {
                module_objects.contains(object) && candidate.pinned.summary(*object).is_some()
            })
    });
    candidate.manifest_fallbacks.retain(|fallback| {
        candidate.pinned.summary(fallback.replacement).is_some()
            && fallback_proof_in_plan(&fallback.proof, &candidate.plan)
    });
}

fn completed_retirement_intent(
    removed: &BTreeSet<ProcessViewId>,
    context_views: &BTreeSet<ProcessViewId>,
    failed: &BTreeSet<ProcessViewId>,
) -> BTreeSet<ProcessViewId> {
    removed
        .union(context_views)
        .filter(|view| !failed.contains(view))
        .copied()
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
enum GenerationMutation<T> {
    PrecheckFailed,
    Committed(T),
    PostcheckFailed(T),
}

#[derive(Debug)]
enum OwnedPrearmAttachDisposition {
    Attached,
    Unavailable {
        reason: String,
    },
    Lifecycle {
        producer_exists: bool,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnedLoaderPrearmOutcome {
    Armed,
    Unavailable,
}

fn classify_owned_prearm_attach(
    attach: GenerationMutation<std::result::Result<bool, DynamicLoaderAttachFailure>>,
) -> OwnedPrearmAttachDisposition {
    match attach {
        GenerationMutation::Committed(Ok(true)) => OwnedPrearmAttachDisposition::Attached,
        GenerationMutation::Committed(Err(DynamicLoaderAttachFailure::KernelUnavailable(
            error,
        ))) => OwnedPrearmAttachDisposition::Unavailable {
            reason: format!("{error:#}"),
        },
        GenerationMutation::Committed(Err(error)) => OwnedPrearmAttachDisposition::Lifecycle {
            producer_exists: false,
            reason: format!("dynamic loader attachment invariant failed: {error}"),
        },
        GenerationMutation::PrecheckFailed => OwnedPrearmAttachDisposition::Lifecycle {
            producer_exists: false,
            reason: "the owned executable provenance changed before loader attachment".into(),
        },
        GenerationMutation::PostcheckFailed(Err(error)) => {
            OwnedPrearmAttachDisposition::Lifecycle {
                producer_exists: false,
                reason: format!(
                    "the owned executable provenance changed around failed loader attachment: {error}"
                ),
            }
        }
        GenerationMutation::Committed(Ok(false)) => OwnedPrearmAttachDisposition::Lifecycle {
            producer_exists: true,
            reason: "the pre-arm loader context unexpectedly reused an existing producer".into(),
        },
        GenerationMutation::PostcheckFailed(Ok(_)) => OwnedPrearmAttachDisposition::Lifecycle {
            producer_exists: true,
            reason: "the owned executable provenance changed around loader attachment".into(),
        },
    }
}

#[derive(Debug)]
enum LoaderArmFailure {
    Ordinary(anyhow::Error),
    Invariant(anyhow::Error),
    /// The view was never an arming candidate: no executable (exe readlink
    /// ENOENT) or a static executable (locator None). Silent `Ok(false)`,
    /// no mark, no loader-registry record — retried next tick like any
    /// unarmed view.
    NotArmable,
}

impl LoaderArmFailure {
    fn ordinary(error: anyhow::Error) -> Self {
        Self::Ordinary(error)
    }

    fn invariant(error: anyhow::Error) -> Self {
        Self::Invariant(error)
    }
}

impl From<anyhow::Error> for LoaderArmFailure {
    fn from(error: anyhow::Error) -> Self {
        Self::ordinary(error)
    }
}

fn generation_checked_mutation<T>(
    mut still_the_same: impl FnMut() -> bool,
    mutate: impl FnOnce() -> T,
) -> GenerationMutation<T> {
    if !still_the_same() {
        return GenerationMutation::PrecheckFailed;
    }
    let value = mutate();
    if still_the_same() {
        GenerationMutation::Committed(value)
    } else {
        GenerationMutation::PostcheckFailed(value)
    }
}

#[cfg(test)]
fn begin_attached_retirement_with<T>(
    registry: &mut LoaderRegistry,
    context: LoaderContextId,
    drain: impl FnOnce() -> Result<T>,
) -> Result<Result<T>> {
    registry.tombstone(context).map_err(anyhow::Error::msg)?;
    Ok(drain())
}

fn begin_owned_prearm_retirement_with<T>(
    registry: &mut LoaderRegistry,
    context: LoaderContextId,
    registry_attached: bool,
    errors: &mut Vec<String>,
    drain: impl FnOnce() -> Result<T>,
) -> Option<T> {
    let transition = if registry_attached {
        registry.tombstone(context)
    } else {
        registry.cancel_prepared(context)
    };
    if let Err(error) = transition {
        errors.push(error);
    }
    match drain() {
        Ok(drained) => Some(drained),
        Err(error) => {
            errors.push(format!("post-detach discovery drain failed: {error:#}"));
            None
        }
    }
}

enum LoaderArmOutcome {
    Changed(bool),
    OrdinaryFailure(anyhow::Error),
    GenerationLost {
        changed: bool,
        failure: Option<LoaderArmFailure>,
    },
    Invariant(anyhow::Error),
    NotArmable,
}

fn loader_arm_outcome(
    generation_valid: bool,
    result: std::result::Result<bool, LoaderArmFailure>,
) -> LoaderArmOutcome {
    if !generation_valid {
        return LoaderArmOutcome::GenerationLost {
            changed: result.as_ref().is_ok_and(|changed| *changed),
            failure: result.err(),
        };
    }
    match result {
        Ok(changed) => LoaderArmOutcome::Changed(changed),
        Err(LoaderArmFailure::Ordinary(error)) => LoaderArmOutcome::OrdinaryFailure(error),
        Err(LoaderArmFailure::Invariant(error)) => LoaderArmOutcome::Invariant(error),
        Err(LoaderArmFailure::NotArmable) => LoaderArmOutcome::NotArmable,
    }
}

fn arm_refreshed_views_with(
    positions: &[usize],
    mut arm: impl FnMut(usize) -> Result<bool>,
) -> Result<bool> {
    let mut changed = false;
    for position in positions {
        changed |= arm(*position)?;
    }
    Ok(changed)
}

/// A record's identity within one batch: who produced it, when, and what.
fn held_record_key(record: &DiscoveryRecord) -> (u64, u64, u8) {
    (record.pid_tgid, record.hook_ts_ns, record.kind)
}

/// Whether an unresolvable record of an ended generation could have announced
/// code that then ran unobserved, so the capture's causal gap is unproven. A
/// loader hit in RT_ADD or RT_DELETE state cannot: dlopen relocates and
/// initializes an object only after the transaction's RT_CONSISTENT, and a
/// deletion adds nothing. Every other record (RT_CONSISTENT or an unreadable
/// state, an export return, an exec) could.
fn record_could_publish_callable_code(record: &DiscoveryRecord) -> bool {
    const RT_ADD: u32 = 1;
    const RT_DELETE: u32 = 2;
    !(record.kind == DISCOVERY_KIND_LOADER && matches!(record.announced_count, RT_ADD | RT_DELETE))
}

fn process_view_is_current(
    views: &[ProcessView],
    extra_views: &[&ProcessView],
    id: ProcessViewId,
) -> bool {
    views
        .iter()
        .chain(extra_views.iter().copied())
        .find(|view| view.id() == id)
        .is_some_and(ProcessView::still_the_same)
}

fn lifecycle_retirement(
    views: &[ProcessView],
    pid: u32,
    hook_ts_ns: u64,
    kind: u8,
) -> Option<(ProcessViewId, RetirementCause)> {
    let view = views
        .iter()
        .filter(|view| view.matches_lifecycle_event(pid, hook_ts_ns))
        .max_by_key(|view| view.admitted_ns())?;
    let cause = match kind {
        DISCOVERY_KIND_EXEC => RetirementCause::ExecRefresh,
        DISCOVERY_KIND_LEADER_EXIT => RetirementCause::ExpectedRemoval,
        _ => return None,
    };
    Some((view.id(), cause))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeaderExitAssessment {
    AlreadySettled,
    Pending,
    WholeGroupExit,
    LinkLoss,
}

fn settle_leader_exit_view(
    pending: &mut BTreeSet<ProcessViewId>,
    counted: &mut BTreeSet<ProcessViewId>,
    losses: &mut u64,
    view: ProcessViewId,
    original_exited: Result<bool, String>,
) -> LeaderExitAssessment {
    if !pending.contains(&view) {
        return LeaderExitAssessment::AlreadySettled;
    }
    match original_exited {
        Ok(true) => {
            pending.remove(&view);
            LeaderExitAssessment::WholeGroupExit
        }
        Ok(false) => {
            pending.remove(&view);
            if counted.insert(view) {
                *losses = losses.saturating_add(1);
            }
            LeaderExitAssessment::LinkLoss
        }
        Err(_) => LeaderExitAssessment::Pending,
    }
}

fn finalize_pending_leader_exit_views(
    pending: &mut BTreeSet<ProcessViewId>,
    counted: &mut BTreeSet<ProcessViewId>,
    losses: &mut u64,
) {
    for view in std::mem::take(pending) {
        if counted.insert(view) {
            *losses = losses.saturating_add(1);
        }
    }
}

fn finalize_batch_retirement_cause(
    cause: RetirementCause,
    original_current: bool,
) -> RetirementCause {
    if cause == RetirementCause::ExecRefresh && !original_current {
        RetirementCause::GenerationLost
    } else {
        cause
    }
}

fn unmatched_exec_requests_refresh(views: &[ProcessView], pid: u32) -> bool {
    !views.iter().any(|view| view.pid() == pid)
}

/// Whether two mappings are the same file-backed object at a different load
/// base — what an `exec` does to the loader. Everything an identity is made of
/// is unchanged; only the address moved, so this is never a substitute for the
/// exact match, only a reason not to call the mismatch a discovery loss.
fn same_object_remapped(expected: &MapEntry, observed: &MapEntry) -> bool {
    expected != observed
        && ObjectKey::of(expected) == ObjectKey::of(observed)
        && expected.file_offset == observed.file_offset
        && expected.permissions == observed.permissions
        && expected.raw_path == observed.raw_path
}

fn inventory_retirement_cause(
    original_current: bool,
    membership_authoritative: bool,
    still_in_scope: bool,
    refresh_requested: bool,
) -> Option<(RetirementCause, bool)> {
    if membership_authoritative && !still_in_scope {
        Some((RetirementCause::ExpectedRemoval, true))
    } else if !original_current {
        Some((RetirementCause::GenerationLost, false))
    } else if refresh_requested {
        Some((RetirementCause::ExecRefresh, false))
    } else {
        None
    }
}

fn retirement_ready_with(
    cause: RetirementCause,
    original_exited: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    if cause == RetirementCause::ExpectedRemoval {
        original_exited()
    } else {
        Ok(true)
    }
}

fn retirement_ready(cause: RetirementCause, view: &ProcessView) -> Result<bool, String> {
    retirement_ready_with(cause, || view.original_exited())
}

fn process_views_are_current(
    views: &[ProcessView],
    extra_views: &[&ProcessView],
    ids: &BTreeSet<ProcessViewId>,
) -> bool {
    stale_process_views(views, extra_views, ids).is_empty()
}

fn stale_process_views(
    views: &[ProcessView],
    extra_views: &[&ProcessView],
    ids: &BTreeSet<ProcessViewId>,
) -> BTreeSet<ProcessViewId> {
    ids.iter()
        .copied()
        .filter(|id| !process_view_is_current(views, extra_views, *id))
        .collect()
}

fn validate_loader_record_context<'a>(
    registry: &'a mut LoaderRegistry,
    terminal_owner: Option<LoaderContextId>,
    record: &DiscoveryRecord,
    view: ProcessViewId,
    loader: PinnedObjectId,
    mapping: &MapEntry,
) -> std::result::Result<&'a crate::discovery::loader::LoaderContext, String> {
    let record_context = LoaderContextId::from_case_id(record.case_id);
    if terminal_owner == Some(record_context) {
        registry.validate_terminal_hit(
            record_context,
            view,
            loader,
            mapping,
            record.table_ptr,
            record.hook_ts_ns,
        )
    } else {
        registry.validate_hit(
            record.case_id,
            view,
            loader,
            mapping,
            record.table_ptr,
            record.hook_ts_ns,
        )
    }
}

fn mapped_object(view: &ProcessView, mapping: &MapEntry, path: &Path) -> ScannedModule {
    ScannedModule {
        mapped_identity: None,
        double_loaded: false,
        view: view.id(),
        mount_namespace: view.mount_namespace(),
        key: ObjectKey::of(mapping),
        path: path.display().to_string(),
        decoder_abi: None,
        exports: Vec::new(),
        tables: Vec::new(),
        interfaces: Vec::new(),
    }
}

impl Engine {
    fn empty() -> Self {
        Self {
            plan: plan::build_from_reconciled_modules(&[]),
            pinned: PinnedObjects::empty(),
            discovery: render::DiscoveryEvidence::default(),
            capture_facts: CaptureFacts::default(),
            views: Vec::new(),
            trace_seeds: BTreeMap::new(),
            trace_by_view: BTreeMap::new(),
            trace_owner: None,
            trace_active: None,
            trace_frame_deadline_ns: None,
            trace_terminal: None,
            trace_phase: TracePhase::Arming,
            trace_phase_visits: 0,
            trace_arm_cursor: None,
            trace_settle_cursor: None,
            trace_view_cursor: 0,
            trace_needs_health: false,
            trace_health_seed: None,
            modules: Vec::new(),
            manifests: Vec::new(),
            manifest_ordinals: Vec::new(),
            counters: DiscoveryCounters::default(),
            identity_mismatches: 0,
            scan_inputs: BTreeMap::new(),
            manifest_inputs: Vec::new(),
            base_counters: DiscoveryCounters::default(),
            budget: CaptureWorkBudget::default(),
            inventory: None,
            next_view_id: 0,
            retired_view_ids: Vec::new(),
            max_scan_pids: MAX_SCAN_PIDS,
            loader_registry: LoaderRegistry::default(),
            owned_initial_exec: None,
            terminal_batch: None,
            terminal_journal: None,
            pending_discovery_records: Vec::new(),
            pause_owned_batch: false,
            pressure_service_active: false,
            in_refresh_tick: false,
            pressure_selected: None,
            pressure_protection: PressureProtection::default(),
            pressure_episode: None,
            pressure_rotation_pending: false,
            pressure_service_passes: 0,
            pressure_attempts: 0,
            frame_fresh_blocked: false,
            terminal_capacity_backlog: 0,
            discovery_held_high_water: 0,
            held_records: BTreeSet::new(),
            paused_loader_views: BTreeSet::new(),
            unpaused_loader_views: BTreeSet::new(),
            // Ordinary tests exercise discovery semantics, not wall-clock
            // bounds, on loaded CI hosts; the H-1 tests opt in explicitly.
            frame_work_budget_ns: if cfg!(test) {
                u64::MAX
            } else {
                LIVE_FRAME_WORK_BUDGET_NS
            },
            frame_deadline_ns: None,
            frame_deferred: false,
            frame_deferrals: 0,
            polling_rescans_queued: 0,
            polled_pids: BTreeSet::new(),
            cancel_flag: None,
            scope: Scope::Pid(std::process::id()),
            hooks: HookRegistry::builtin(),
            module_hints: Vec::new(),
            counter_snapshot: CounterSnapshot::default(),
            malformed_discovery: 0,
            refresh_requested: BTreeMap::new(),
            last_refresh_serial: 0,
            scheduler: DiscoveryScheduler::new(),
            loader_records_accepted: 0,
            timings: CausalTimings::default(),
            stage_timings: crate::timing::StageTimings::new(),
            newcomer_first_seen: BTreeMap::new(),
            newcomer_ages: crate::timing::NewcomerStats::new(),
            // A fresh engine owes its first tail publication: the revision
            // starts dirty so the first batch tail publishes unconditionally,
            // exactly like the un-gated tail it replaces.
            facts_revision: 1,
            published_facts_revision: 0,
            loader_plan_cache: None,
            tail_publishes: 0,
            tail_skips: 0,
            discovery_truncated: 0,
            pending_rejected_keys: BTreeSet::new(),
            pending_retirements: BTreeSet::new(),
            retirement_intents: PendingViewRetirements::new(),
            ready_expected_removals: BTreeSet::new(),
            expected_target_exit_pending: None,
            expected_target_exit: false,
            pending_leader_exit_views: BTreeSet::new(),
            counted_leader_exit_views: BTreeSet::new(),
            exec_rearm_views: BTreeSet::new(),
            pid_descendant_gaps: 0,
            multi_rebuild_gaps: 0,
            admitted_cgroup_views: BTreeMap::new(),
            unmatched_leader_exit_events: BTreeSet::new(),
            cgroup_ingress_overflow: false,
            task_uprobe_link_losses: 0,
            next_selection_binding_id: Some(1),
            selection_bindings: BTreeMap::new(),
            selection_claims: BTreeMap::new(),
            selection_tables: BTreeMap::new(),
            loader_contexts: BTreeMap::new(),
            pending_loader_scans: BTreeMap::new(),
            broad_admit: false,
            exploratory_dirty: BTreeSet::new(),
            deep_scans: 0,
            loader_arms: 0,
            exploratory_evictions: 0,
            #[cfg(test)]
            loader_memory_scan_attempts: 0,
        }
    }

    /// Classifies the exact live-loader context this view owns after an arming
    /// attempt. Re-arming the same context in one load kind updates its entry
    /// rather than adding a second — that is what makes the published counts
    /// per-context and not per-record — while the load kind stays partitioned.
    fn record_loader_arm(&mut self, view: ProcessViewId, initial_set: bool) {
        let bound = self
            .loader_registry
            .ids_for_view(view)
            .into_iter()
            .find(|id| !self.loader_registry.is_tombstoned(*id));
        let (bound_key, bound) = match bound {
            None => (LoaderAggregateKey::Unbound, false),
            Some(id) => match self
                .loader_registry
                .context(id)
                .and_then(|context| self.pinned.owned_timing_key(context.spec.loader))
            {
                Some(key) => (LoaderAggregateKey::Bound(key), true),
                None => {
                    self.mark_live_loss(
                        "live loader discovery",
                        "loader context has no stable aggregation identity",
                    );
                    (LoaderAggregateKey::BoundUnkeyed(id), true)
                }
            },
        };
        let class = LoaderContextClass { bound, initial_set };
        self.loader_contexts
            .entry((view, bound_key, initial_set))
            .and_modify(|known| known.bound = class.bound)
            .or_insert(class);
    }

    /// The always-present finite live-loader aggregate (design §9.2). The two
    /// BPF-owned counters come only from the producer counter snapshot; the
    /// classification groups come only from the deduplicated context set.
    /// Received-record counts feed neither.
    pub fn loader_discovery(&self) -> render::LoaderDiscovery {
        let mut aggregate = render::LoaderDiscovery {
            hits: self.counter_snapshot.loader_hits,
            state_read_failures: self.counter_snapshot.loader_state_read_failures,
            ..render::LoaderDiscovery::default()
        };
        for ((view, _, _), class) in &self.loader_contexts {
            // Pause-protected: every loader hit of this view was held by a
            // pause stop, nothing it published was scanned or attached while
            // the child ran, and every cycle confirmed. That needs no loader
            // timing catalog: the child was stopped at each hit and at each
            // table publication until its probes were attached.
            let protected = class.bound
                && self.paused_loader_views.contains(view)
                && !self.unpaused_loader_views.contains(view);
            let timing = if class.initial_set {
                // Exactly one initial-set context per owned run, and the empty
                // catalog can never make it eligible (D3 amendment §3).
                if protected {
                    aggregate.initial_set_capture.pause_protected = aggregate
                        .initial_set_capture
                        .pause_protected
                        .saturating_add(1);
                } else {
                    aggregate.initial_set_capture.none =
                        aggregate.initial_set_capture.none.saturating_add(1);
                }
                &mut aggregate.initial_set_timing
            } else {
                &mut aggregate.dlopen_timing
            };
            if class.bound {
                if protected {
                    timing.pause_protected = timing.pause_protected.saturating_add(1);
                } else {
                    timing.unproven = timing.unproven.saturating_add(1);
                }
                aggregate.strategies.debug_state_every_hit =
                    aggregate.strategies.debug_state_every_hit.saturating_add(1);
            } else {
                timing.none = timing.none.saturating_add(1);
                aggregate.strategies.unavailable =
                    aggregate.strategies.unavailable.saturating_add(1);
            }
        }
        aggregate
    }

    /// Whether the owned child `pid` still has a provider whose function
    /// table is not published (GT-4): a loader memory scan deferred at an
    /// RT_ADD hit, or a provider attached only through its count-only
    /// `C_GetFunctionList` seed while its table is unknown. The pause keeps
    /// the child's epoch armed through exactly this window.
    pub(crate) fn owned_publication_pending(&self, pid: u32) -> bool {
        let views: BTreeSet<_> = self
            .views
            .iter()
            .filter(|view| view.pid() == pid)
            .map(ProcessView::id)
            .collect();
        if self
            .pending_loader_scans
            .keys()
            .any(|key| views.contains(&key.view))
        {
            return true;
        }
        let objects: BTreeSet<_> = self
            .modules
            .iter()
            .filter(|module| views.contains(&module.scanned.view))
            .map(|module| module.object)
            .collect();
        self.plan
            .provisional_objects()
            .any(|object| objects.contains(&object))
    }

    /// Publishes a gap the owned pause could not cover. It is a coverage gap,
    /// not a lost record: the causal timing still measures it.
    pub(crate) fn note_owned_pause_gap(&mut self, reason: &str) {
        self.mark_partial("owned pause", reason);
    }

    /// Whether the running live frame must stop taking on work items (H-1):
    /// its work budget is spent, or the operator asked the capture to stop.
    /// Always false outside a live frame.
    fn frame_work_exhausted(&self) -> bool {
        let Some(deadline) = self.frame_deadline_ns else {
            return false;
        };
        self.cancel_flag
            .as_ref()
            .is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Relaxed))
            || crate::attach::monotonic_ns().is_some_and(|now| now >= deadline)
    }

    /// Books one frame's deferral once (F4). Deferred work is delayed, never
    /// dropped, so it is scheduling evidence, not a loss; a provider it names
    /// is attached a frame later, which its causal timing measures.
    fn note_frame_deferral(&mut self) {
        if !self.frame_deferred {
            self.frame_deferred = true;
            self.frame_deferrals = self.frame_deferrals.saturating_add(1);
        }
    }

    pub(crate) fn with_trace_frame<S: TraceIo, T>(
        &mut self,
        session: &mut S,
        run: impl FnOnce(&mut Self, &mut S, &mut TraceWorkTicket) -> Result<T>,
    ) -> Result<T> {
        let Some(proof) = session.proof().cloned() else {
            return run(self, session, &mut TraceWorkTicket::default());
        };
        if self
            .trace_owner
            .as_ref()
            .is_some_and(|owner| !owner.same_allocation(&proof))
        {
            return run(self, session, &mut TraceWorkTicket::default());
        }
        if let Some(active) = &self.trace_active {
            return run(self, session, &mut active.clone());
        }
        self.trace_owner = Some(proof.clone());
        let prior_deadline = self.trace_frame_deadline_ns;
        let mut work = TraceWorkTicket::default();
        if let Some(start) = proof.now()
            && let Some(frame) = start.checked_add(self.frame_work_budget_ns)
            && let Some(proof_end) = start.checked_add(5_000_000)
        {
            let frame = prior_deadline.map_or(frame, |prior| prior.min(frame));
            let frame = self
                .frame_deadline_ns
                .map_or(frame, |prior| prior.min(frame));
            self.trace_frame_deadline_ns = Some(frame);
            work = TraceWorkTicket::new(
                proof.clone(),
                start,
                frame.min(proof_end),
                false,
                self.cancel_flag.clone(),
            );
        } else {
            proof.invalidate_cgroup_work();
        }
        self.trace_active = Some(work.clone());
        let result = run(self, session, &mut work);
        work.close();
        self.trace_active = None;
        self.trace_frame_deadline_ns = prior_deadline;
        result
    }
    fn drop_trace_seed(&mut self, id: SeedId) {
        if let Some(candidate) = self.trace_seeds.remove(&id) {
            if self.trace_by_view.get(&candidate.body.view_id()) == Some(&id) {
                self.trace_by_view.remove(&candidate.body.view_id());
            }
            // No ledger guard is held while dropping the sole reservation.
            drop(candidate);
        }
    }
    fn next_trace_seed(&self, cursor: Option<SeedId>) -> Option<SeedId> {
        use std::ops::Bound::{Excluded, Unbounded};
        match cursor {
            Some(id) => self
                .trace_seeds
                .range((Excluded(id), Unbounded))
                .next()
                .map(|(id, _)| *id),
            None => self.trace_seeds.keys().next().copied(),
        }
    }
    fn advance_trace_phase(&mut self) {
        self.trace_phase = match self.trace_phase {
            TracePhase::Arming => TracePhase::Health,
            TracePhase::Health => TracePhase::Settlement,
            TracePhase::Settlement => TracePhase::Seeding,
            TracePhase::Seeding => TracePhase::Arming,
        };
        self.trace_phase_visits = 0;
    }
    pub(crate) fn service_trace_images(
        &mut self,
        session: &impl TraceIo,
        work: &mut TraceWorkTicket,
        mut accept: impl FnMut(VerifiedTraceSeed),
    ) -> TraceServiceProgress {
        let mut progress = TraceServiceProgress::default();
        let Some(proof) = session.proof() else {
            progress.deferred = 1;
            return progress;
        };
        let owned = self
            .trace_active
            .as_ref()
            .is_some_and(|active| active.same_allocation(work))
            || self
                .trace_terminal
                .as_ref()
                .is_some_and(|terminal| terminal.same_allocation(work));
        if !owned {
            progress.deferred = 1;
            return progress;
        }
        loop {
            let checked = if proof.is_cgroup() {
                work.cgroup_check(proof, u64::MAX)
                    .map(|_| ())
                    .map_err(Into::into)
            } else {
                work.check(proof)
            };
            if let Err(error) = checked {
                if matches!(error, TraceWorkError::Unknown(_)) {
                    proof.invalidate_cgroup_work();
                }
                progress.deferred += 1;
                break;
            }
            match self.trace_phase {
                TracePhase::Arming => {
                    if self.trace_phase_visits >= 8 {
                        self.advance_trace_phase();
                        continue;
                    }
                    let Some(id) = self.next_trace_seed(self.trace_arm_cursor) else {
                        self.trace_arm_cursor = None;
                        self.advance_trace_phase();
                        continue;
                    };
                    if work.visit(proof).is_err() {
                        progress.deferred += 1;
                        break;
                    }
                    progress.visited += 1;
                    // An attempted confirmation consumes its fair phase turn,
                    // including when the original-pin read later defers.
                    self.trace_arm_cursor = Some(id);
                    self.trace_phase_visits += 1;
                    let candidate = self.trace_seeds.get_mut(&id).expect("visited candidate");
                    let result = match &mut candidate.body {
                        TraceCandidateBody::Cgroup(registration) => self
                            .views
                            .get(candidate.position)
                            .ok_or(TraceWorkError::Unknown(TraceProofUnknown::TargetGone))
                            .and_then(|view| {
                                let status = proof.cgroup_status(registration, view, work)?;
                                self.trace_needs_health |= status.needs_health;
                                if status.needs_health {
                                    self.trace_health_seed = Some(id);
                                }
                                match status.action {
                                    CgroupAction::Sample => {
                                        session.sample_cgroup(registration, view, work)
                                    }
                                    CgroupAction::Confirm => {
                                        session.confirm_cgroup(registration, view, work)
                                    }
                                    CgroupAction::Parked => {
                                        proof.park_cgroup(
                                            registration,
                                            TraceProofUnknown::ProofPending,
                                        );
                                        Ok(())
                                    }
                                    CgroupAction::Idle => Ok(()),
                                }
                            }),
                        TraceCandidateBody::Accepted(interest) => self
                            .views
                            .get(candidate.position)
                            .ok_or(TraceProofUnknown::TargetGone)
                            .and_then(|view| proof.cgroup_interest_status(interest, view))
                            .map(|_| ())
                            .map_err(Into::into),
                        TraceCandidateBody::PidSystem(seed) => {
                            let status = self
                                .views
                                .get(candidate.position)
                                .ok_or(TraceProofUnknown::TargetGone)
                                .and_then(|view| proof.seed_status(seed, view));
                            match status {
                                Ok((true, _)) => {
                                    let view = &self.views[candidate.position];
                                    session
                                        .cookie(view.retained_pin(), work)
                                        .and_then(|cookie| {
                                            proof.confirm(seed, view, cookie).map_err(Into::into)
                                        })
                                }
                                Ok((false, needs_health)) => {
                                    self.trace_needs_health |= needs_health;
                                    Ok(())
                                }
                                Err(reason) => Err(reason.into()),
                            }
                        }
                    };
                    match result {
                        Err(TraceWorkError::Deferred) => {
                            progress.deferred += 1;
                            break;
                        }
                        Err(TraceWorkError::Unknown(reason)) => {
                            let redirect = self.trace_seeds.get(&id).and_then(|candidate| {
                                if let TraceCandidateBody::Cgroup(registration) = &candidate.body {
                                    self.views.get(candidate.position).and_then(|view| {
                                        proof
                                            .redirect_cgroup(registration, view)
                                            .map(|interest| (interest, candidate.position))
                                    })
                                } else {
                                    None
                                }
                            });
                            if let Some((interest, position)) = redirect {
                                self.drop_trace_seed(id);
                                let body = TraceCandidateBody::Accepted(interest);
                                let target = body.id();
                                // Drop an old handle before installing the replacement:
                                // its detach cannot erase a newly installed alias.
                                self.drop_trace_seed(target);
                                self.trace_by_view.insert(body.view_id(), target);
                                self.trace_seeds
                                    .insert(target, TraceCandidate { body, position });
                                continue;
                            }
                            if let Some(candidate) = self.trace_seeds.get_mut(&id)
                                && let TraceCandidateBody::Cgroup(registration) =
                                    &mut candidate.body
                                && !matches!(
                                    reason,
                                    TraceProofUnknown::TargetGone
                                        | TraceProofUnknown::AfterEvent
                                        | TraceProofUnknown::NotSeeded
                                )
                            {
                                proof.park_cgroup(registration, reason);
                            } else {
                                self.drop_trace_seed(id);
                            }
                        }
                        Ok(()) => {
                            if let Some(candidate) = self.trace_seeds.get(&id)
                                && let Some(view) = self.views.get(candidate.position)
                            {
                                match &candidate.body {
                                    TraceCandidateBody::PidSystem(seed) => {
                                        if let Ok((_, needs)) = proof.seed_status(seed, view) {
                                            self.trace_needs_health |= needs;
                                        }
                                    }
                                    TraceCandidateBody::Cgroup(registration) => {
                                        if let Ok(status) =
                                            proof.cgroup_status(registration, view, work)
                                        {
                                            self.trace_needs_health |= status.needs_health;
                                            if status.needs_health {
                                                self.trace_health_seed = Some(id);
                                            }
                                        }
                                    }
                                    TraceCandidateBody::Accepted(_) => {}
                                }
                            }
                        }
                    }
                }
                TracePhase::Health => {
                    let mut baseline_needed = false;
                    if !proof.is_cgroup()
                        && !work.terminal()
                        && !proof.has_baseline()
                        && !self.views.is_empty()
                    {
                        if work.visit(proof).is_err() {
                            progress.deferred += 1;
                            break;
                        }
                        progress.visited += 1;
                        self.trace_view_cursor %= self.views.len();
                        baseline_needed =
                            proof.can_seed(&self.views[self.trace_view_cursor]).is_ok();
                    }
                    if (self.trace_needs_health || baseline_needed) && !work.health_attempted() {
                        let result = if proof.is_cgroup() {
                            if work.visit(proof).is_err() {
                                progress.deferred += 1;
                                break;
                            }
                            progress.visited += 1;
                            // A saved demand is only a cursor into charged state.
                            // Revalidate it before any shared health syscall.
                            let demand = self.trace_health_seed.and_then(|id| {
                                self.trace_seeds.get(&id).and_then(|candidate| {
                                    self.views.get(candidate.position).and_then(|view| {
                                        if let TraceCandidateBody::Cgroup(registration) =
                                            &candidate.body
                                        {
                                            Some((
                                                id,
                                                proof.cgroup_status(registration, view, work),
                                            ))
                                        } else {
                                            None
                                        }
                                    })
                                })
                            });
                            match demand {
                                Some((id, Ok(status))) if status.needs_health => session
                                    .refresh_health(
                                        &mut work.cgroup_reader(status.deadline, Some(id)),
                                    ),
                                Some((_, Err(TraceWorkError::Deferred))) => {
                                    Err(TraceWorkError::Deferred)
                                }
                                _ => Ok(()),
                            }
                        } else {
                            session.refresh_health(work)
                        };
                        match result {
                            Err(TraceWorkError::Deferred) => {
                                progress.deferred += 1;
                                break;
                            }
                            _ => {
                                self.trace_needs_health = false;
                                self.trace_health_seed = None;
                            }
                        }
                    }
                    self.advance_trace_phase();
                }
                TracePhase::Settlement => {
                    if self.trace_phase_visits >= 8 {
                        self.advance_trace_phase();
                        continue;
                    }
                    let Some(id) = self.next_trace_seed(self.trace_settle_cursor) else {
                        self.trace_settle_cursor = None;
                        self.advance_trace_phase();
                        continue;
                    };
                    if work.visit(proof).is_err() {
                        progress.deferred += 1;
                        break;
                    }
                    progress.visited += 1;
                    let candidate = &self.trace_seeds[&id];
                    let result = self
                        .views
                        .get(candidate.position)
                        .ok_or(TraceWorkError::Unknown(TraceProofUnknown::TargetGone))
                        .and_then(|view| match &candidate.body {
                            TraceCandidateBody::PidSystem(seed) => {
                                proof.seed_status(seed, view)?;
                                proof.ready_to_transfer(seed).map_err(Into::into)
                            }
                            TraceCandidateBody::Cgroup(registration) => proof
                                .cgroup_status(registration, view, work)
                                .map(|status| status.ready_to_transfer),
                            TraceCandidateBody::Accepted(_) => Ok(false),
                        });
                    match result {
                        Ok(true) => {
                            let candidate = self
                                .trace_seeds
                                .remove(&id)
                                .expect("visited retained candidate");
                            let position = candidate.position;
                            match candidate.body {
                                TraceCandidateBody::PidSystem(seed) => {
                                    if self.trace_by_view.get(&seed.view_id()) == Some(&id) {
                                        self.trace_by_view.remove(&seed.view_id());
                                    }
                                    if let Ok(verified) =
                                        proof.verified(seed, &self.views[position])
                                    {
                                        progress.transferred += 1;
                                        accept(verified);
                                    }
                                }
                                TraceCandidateBody::Cgroup(registration) => {
                                    match proof.verify_cgroup(
                                        registration,
                                        &self.views[position],
                                        work,
                                    ) {
                                        Ok((verified, interest)) => {
                                            self.trace_seeds.insert(
                                                id,
                                                TraceCandidate {
                                                    body: TraceCandidateBody::Accepted(interest),
                                                    position,
                                                },
                                            );
                                            progress.transferred += 1;
                                            accept(verified);
                                        }
                                        Err((mut registration, error)) => {
                                            if let TraceWorkError::Unknown(reason) = error {
                                                proof.park_cgroup(&mut registration, reason);
                                            }
                                            self.trace_seeds.insert(
                                                id,
                                                TraceCandidate {
                                                    body: TraceCandidateBody::Cgroup(registration),
                                                    position,
                                                },
                                            );
                                        }
                                    }
                                }
                                TraceCandidateBody::Accepted(_) => {
                                    unreachable!("accepted aliases cannot transfer")
                                }
                            }
                        }
                        Err(TraceWorkError::Deferred) => {
                            progress.deferred += 1;
                            break;
                        }
                        Err(TraceWorkError::Unknown(_)) => self.drop_trace_seed(id),
                        Ok(false) => {}
                    }
                    self.trace_settle_cursor = Some(id);
                    self.trace_phase_visits += 1;
                }
                TracePhase::Seeding => {
                    if work.terminal() || self.views.is_empty() || self.trace_phase_visits >= 8 {
                        self.advance_trace_phase();
                        break;
                    }
                    if work.visit(proof).is_err() {
                        progress.deferred += 1;
                        break;
                    }
                    progress.visited += 1;
                    self.trace_view_cursor %= self.views.len();
                    let position = self.trace_view_cursor;
                    let view = &self.views[position];
                    let eligible = if proof.is_cgroup() {
                        self.trace_by_view
                            .get(&view.id())
                            .and_then(|id| self.trace_seeds.get(id))
                            .is_none_or(|candidate| match &candidate.body {
                                TraceCandidateBody::Accepted(interest) => proof
                                    .cgroup_interest_status(interest, view)
                                    .unwrap_or(false),
                                _ => false,
                            })
                    } else {
                        !self.trace_by_view.contains_key(&view.id()) && proof.can_seed(view).is_ok()
                    };
                    if eligible && !proof.is_cgroup() && !proof.has_baseline() {
                        // The baseline read retains this eligible view for its
                        // capacity recheck; no sample attempt has begun yet.
                        self.trace_phase = TracePhase::Health;
                        self.trace_phase_visits = 0;
                        progress.deferred += 1;
                        break;
                    }
                    // Charge the fair slot before a sample can overrun. Partial
                    // samples roll back; this view is retried on a later pass.
                    self.trace_view_cursor = (position + 1) % self.views.len();
                    self.trace_phase_visits += 1;
                    if eligible {
                        let result = if proof.is_cgroup() {
                            proof
                                .register_cgroup(view, work)
                                .map(TraceCandidateBody::Cgroup)
                        } else {
                            session
                                .sample(view, work)
                                .map(TraceCandidateBody::PidSystem)
                        };
                        match result {
                            Ok(body) => {
                                let id = body.id();
                                self.trace_by_view.insert(view.id(), id);
                                self.trace_seeds
                                    .insert(id, TraceCandidate { body, position });
                                progress.seeded += 1;
                            }
                            Err(TraceWorkError::Deferred) => {
                                if self.trace_phase_visits as usize >= self.views.len()
                                    || self.trace_phase_visits >= 8
                                {
                                    self.advance_trace_phase();
                                }
                                progress.deferred += 1;
                                break;
                            }
                            Err(TraceWorkError::Unknown(_)) => {}
                        }
                    }
                    // One complete bounded view pass need not revisit a short list.
                    if self.trace_phase_visits as usize >= self.views.len() {
                        self.advance_trace_phase();
                        break;
                    }
                }
            }
        }
        progress
    }
    pub(crate) fn begin_trace_terminal_work(
        &mut self,
        remaining: std::time::Duration,
    ) -> TraceWorkTicket {
        if let Some(ticket) = &self.trace_terminal {
            return ticket.clone();
        }
        let mut ticket = TraceWorkTicket::default();
        if let Some(proof) = &self.trace_owner
            && let Some(now) = proof.now()
            && let Ok(ns) = u64::try_from(remaining.as_nanos())
            && let Some(stop) = now.checked_add(ns)
            && let Some(end) = now.checked_add(5_000_000)
        {
            ticket = TraceWorkTicket::new(
                proof.clone(),
                now,
                stop.min(end),
                true,
                self.cancel_flag.clone(),
            );
        }
        self.trace_terminal = Some(ticket.clone());
        ticket
    }

    /// Runs one live discovery frame under its work budget (H-1).
    fn with_live_frame<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        // A nested actual live scope reuses its existing allowance. The trace
        // wrapper alone never activates ordinary discovery or pause deferral.
        if self.trace_active.is_some() && self.frame_deadline_ns.is_some() {
            return work(self);
        }
        let prior_deadline = self.frame_deadline_ns;
        let prior_deferred = self.frame_deferred;
        // Preserve the ordinary disabled clock-failure policy.
        self.frame_deadline_ns = Some(self.trace_frame_deadline_ns.unwrap_or_else(|| {
            crate::attach::monotonic_ns().map_or(u64::MAX, |now| {
                now.saturating_add(self.frame_work_budget_ns)
            })
        }));
        self.frame_deferred = false;
        let result = work(self);
        self.frame_deadline_ns = prior_deadline;
        self.frame_deferred = prior_deferred;
        result
    }

    /// Marks the batches a pause cycle applies while the owned child is
    /// stopped: its records were held by that stop, and whatever they
    /// publish is attached before the child resumes.
    pub(crate) fn set_pause_owned_batch(&mut self, owned: bool) {
        self.pause_owned_batch = owned;
    }

    /// A pause cycle for `pid` did not confirm: nothing about its views can
    /// be called pause-protected.
    pub(crate) fn note_unprotected_owned(&mut self, pid: u32) {
        let views: Vec<_> = self
            .views
            .iter()
            .filter(|view| view.pid() == pid)
            .map(ProcessView::id)
            .collect();
        self.unpaused_loader_views.extend(views);
    }

    /// Books whether a publishing record (a loader hit or an export return)
    /// was held by a pause stop: only a record this pause-owned batch was
    /// handed is. Every other one — an ordinary frame, a carried-over or a
    /// nested-collected record — ran while the child was running.
    fn note_record_protection(&mut self, record: &DiscoveryRecord) {
        if !matches!(
            record.kind,
            DISCOVERY_KIND_LOADER
                | DISCOVERY_KIND_FUNCTION_LIST_RETURN
                | DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN
                | DISCOVERY_KIND_INTERFACE_RETURN
        ) {
            return;
        }
        let pid = (record.pid_tgid >> 32) as u32;
        let held = self.held_records.contains(&held_record_key(record));
        let views: Vec<_> = self
            .views
            .iter()
            .filter(|view| view.pid() == pid)
            .map(ProcessView::id)
            .collect();
        for view in views {
            if !held {
                self.unpaused_loader_views.insert(view);
            } else if record.kind == DISCOVERY_KIND_LOADER {
                self.paused_loader_views.insert(view);
            }
        }
    }

    pub(crate) fn discovery_deferrals(&self) -> u64 {
        self.frame_deferrals
    }

    /// Called when the terminal drain is done: deferred records it still
    /// left undispatched are the one deferral that is a loss (F4).
    pub(crate) fn settle_frame_deferrals_at_capture_end(&mut self) {
        if self.pending_discovery_records.is_empty() {
            return;
        }
        self.mark_live_loss("live discovery frame", UNFINISHED_DEFERRAL_LOSS);
        record_object_skips(&mut self.plan, &self.counters.object_skips);
    }

    /// The capture's operator-stop flag: a live frame that sees it set
    /// defers its remaining work so the loop can end sooner (H-1).
    pub(crate) fn set_cancel_flag(&mut self, flag: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        self.cancel_flag = Some(flag);
    }

    /// The admission rule this capture's plan keeps for its whole lifetime
    /// (GT-5). A named process, or a capture the operator aimed with
    /// `--module` (whose scan sees only the named objects), admits
    /// first-come. Any other cgroup or system capture admits in value order,
    /// whole modules only, with a reserve for late corroborated providers.
    fn admission_scope(&self) -> plan::AdmissionScope {
        if matches!(self.scope, Scope::Pid(_)) || !self.module_hints.is_empty() {
            plan::AdmissionScope::Named
        } else {
            plan::AdmissionScope::Shared
        }
    }

    /// True once a named target's expected exit has been fully finalized:
    /// its view, links, and pending work are all released. Never true for a
    /// cgroup capture, which continues when one member exits.
    pub fn expected_target_exit(&self) -> bool {
        self.expected_target_exit
    }

    /// The one immutable public view of capture facts (plan Task 8 Step 2).
    /// Every field is boundary-safe: no pins, views, files, timing keys, or
    /// loader/pause identity crosses it. Most fields are the projected
    /// discovery evidence and finite aggregates and stay fixed once accepted,
    /// but `table_entries`, `slots`, and `active_slots` are read live off the
    /// engine's own `plan`, not sourced from `self.discovery` — and unlike
    /// the other two, `active_slots` is not capture-lifetime history: it is
    /// the plan's current active set and can shrink or reach zero while the
    /// rest of this snapshot stays exactly what the capture accepted (see
    /// `AttachPlan::active_slot_count`).
    pub fn capture_facts(&self) -> render::CaptureFacts {
        render::CaptureFacts {
            discovery: self.discovery.clone(),
            table_entries: self.plan.entries_seen,
            slots: self.plan.slots.len(),
            // U-14: mirrors how `slots` reads the plan, but counts only what
            // `plan.is_active` still has attached right now.
            active_slots: self.plan.active_slot_count(),
            attach_gap_ms: self.timings.max_gap_ms(),
            loader_discovery: self.loader_discovery(),
            discovery_ring_loss: self.counter_snapshot.ring_loss,
            discovery_state_failures: self.counter_snapshot.export_state_failures,
            discovery_read_failures: self.counter_snapshot.export_bounded_read_failures,
            task_uprobe_link_losses: self.task_uprobe_link_losses,
            // One accumulator, each source feeding it once (design §9.1).
            discovery_truncated: self
                .discovery_truncated
                .saturating_add(self.malformed_discovery)
                .saturating_add(self.loader_registry.discovery_truncated())
                .saturating_add(self.loader_registry.context_failures()),
        }
    }

    pub(crate) fn pid_descendant_gaps(&self) -> u64 {
        if self.admits_generations() {
            self.pid_descendant_gaps
        } else {
            0
        }
    }

    pub(crate) fn multi_rebuild_gaps(&self) -> u64 {
        self.multi_rebuild_gaps
    }

    /// Whether the scope is the whole machine: only then does a pass see
    /// every process mapping an object.
    pub(crate) fn sees_whole_system(&self) -> bool {
        matches!(self.scope, Scope::System)
    }

    /// Scopes that admit process generations over time: cgroup membership and
    /// the whole machine both track an admission ledger and count descendant
    /// gaps. PID scope names one exact generation and never admits another.
    fn admits_generations(&self) -> bool {
        matches!(self.scope, Scope::Cgroup { .. } | Scope::System)
    }

    /// What an admission-ledger loss is filed under: the cgroup subject, or
    /// the system subject for whole-machine scope.
    fn ingress_subject(&self) -> &'static str {
        match self.scope {
            Scope::System => "system ingress tracking",
            _ => "cgroup ingress tracking",
        }
    }

    /// What an admission-removal loss is filed under.
    fn admission_removal_subject(&self) -> &'static str {
        match self.scope {
            Scope::System => "system admission removal",
            _ => "cgroup admission removal",
        }
    }

    fn seed_initial_cgroup_views(&mut self) {
        if self.admits_generations() {
            self.admitted_cgroup_views
                .extend(self.views.iter().map(|view| {
                    (
                        view.id(),
                        CgroupAdmission {
                            pid: view.pid(),
                            admitted_ns: view.admitted_ns(),
                            closed_ns: None,
                        },
                    )
                }));
        }
    }

    fn record_cgroup_view_admissions(&mut self, views: impl IntoIterator<Item = ProcessViewId>) {
        if !self.admits_generations() {
            return;
        }
        for view in views {
            let Some(view_data) = self
                .views
                .iter()
                .find(|candidate| candidate.id() == view)
                .map(|candidate| CgroupAdmission {
                    pid: candidate.pid(),
                    admitted_ns: candidate.admitted_ns(),
                    closed_ns: None,
                })
            else {
                continue;
            };
            if self.admitted_cgroup_views.insert(view, view_data).is_none() {
                self.pid_descendant_gaps = self.pid_descendant_gaps.saturating_add(1);
            }
        }
    }

    fn record_unmatched_cgroup_leader_exit(&mut self, record: &DiscoveryRecord) {
        if !self.admits_generations() {
            return;
        }
        let pid = (record.pid_tgid >> 32) as u32;
        if self
            .admitted_cgroup_views
            .values()
            .any(|admission| admission.covers(record.hook_ts_ns, pid))
        {
            return;
        }
        let key = (pid, record.hook_ts_ns);
        if self.unmatched_leader_exit_events.contains(&key) {
            return;
        }
        if self.unmatched_leader_exit_events.len() >= MAX_SCAN_PIDS {
            if !self.cgroup_ingress_overflow {
                self.cgroup_ingress_overflow = true;
                self.pid_descendant_gaps = self.pid_descendant_gaps.saturating_add(1);
                let subject = self.ingress_subject();
                self.mark_partial(
                    subject,
                    "the bounded unmatched-exit ledger overflowed; the gap count is a lower bound",
                );
            }
            return;
        }
        self.unmatched_leader_exit_events.insert(key);
        self.pid_descendant_gaps = self.pid_descendant_gaps.saturating_add(1);
    }

    fn close_cgroup_admission(&mut self, view: ProcessViewId, closed_ns: u64) {
        if let Some(admission) = self.admitted_cgroup_views.get_mut(&view)
            && admission.closed_ns.is_none()
        {
            admission.closed_ns = Some(closed_ns);
        }
    }

    fn update_cgroup_admissions_at_removal(
        &mut self,
        views: &BTreeSet<ProcessViewId>,
        closed_ns: Option<u64>,
    ) {
        if !self.admits_generations() {
            return;
        }
        if let Some(closed_ns) = closed_ns {
            for view in views {
                self.close_cgroup_admission(*view, closed_ns);
            }
            return;
        }
        let before = self.admitted_cgroup_views.len();
        self.admitted_cgroup_views
            .retain(|view, admission| !views.contains(view) || admission.closed_ns.is_some());
        if self.admitted_cgroup_views.len() == before {
            return;
        }
        let skipped = Skipped {
            subject: self.admission_removal_subject().into(),
            reason: "the monotonic removal boundary was unavailable; the descendant gap count is a lower bound".into(),
        };
        if !self.base_counters.object_skips.contains(&skipped) {
            self.pid_descendant_gaps = self.pid_descendant_gaps.saturating_add(1);
            attribution::note(&skipped);
            self.base_counters.object_skips.push(skipped.clone());
        }
        if !self.counters.object_skips.contains(&skipped) {
            self.counters.object_skips.push(skipped);
            self.note_facts_mutated();
        }
    }

    fn close_cgroup_admission_at_removal(&mut self, view: ProcessViewId) {
        self.update_cgroup_admissions_at_removal(
            &[view].into_iter().collect(),
            crate::attach::monotonic_ns(),
        );
    }

    fn close_cgroup_admissions_at_removal(&mut self, views: &BTreeSet<ProcessViewId>) {
        self.update_cgroup_admissions_at_removal(views, crate::attach::monotonic_ns());
    }

    fn coalesce_pre_admission_exits(
        &mut self,
        records: &mut Vec<QueuedDiscoveryRecord>,
        admitted: &BTreeSet<ProcessViewId>,
    ) {
        records.retain(|queued| {
            let record = &queued.record;
            let pid = (record.pid_tgid >> 32) as u32;
            let coalesced = record.kind == DISCOVERY_KIND_LEADER_EXIT
                && admitted.iter().any(|view| {
                    self.admitted_cgroup_views
                        .get(view)
                        .is_some_and(|admission| {
                            admission.pid == pid && record.hook_ts_ns <= admission.admitted_ns
                        })
                });
            if coalesced {
                if self.unmatched_leader_exit_events.len() < MAX_SCAN_PIDS {
                    self.unmatched_leader_exit_events
                        .insert((pid, record.hook_ts_ns));
                } else {
                    self.cgroup_ingress_overflow = true;
                    let subject = self.ingress_subject();
                    self.mark_partial(
                        subject,
                        "the bounded unmatched-exit ledger overflowed; the gap count is a lower bound",
                    );
                }
            }
            !coalesced
        });
    }

    pub(crate) fn interface_selection(&self) -> render::InterfaceSelection {
        let history = self.capture_facts.visible_history();
        let public_modules: BTreeMap<_, _> = history
            .modules
            .keys()
            .copied()
            .enumerate()
            .map(|(index, module)| (module, index as u32))
            .collect();
        let mut selection_truncated = history.selection_truncated;
        let mut surface_indices = BTreeMap::new();
        let mut module_ordinals = BTreeMap::<u32, u16>::new();
        let mut inventory_surfaces = Vec::new();
        let mut surfaces: Vec<_> = history
            .selection_surfaces
            .iter()
            .filter_map(|surface| {
                let stable = self
                    .capture_facts
                    .module_ids
                    .get(&surface.base.provider)
                    .copied();
                let public = stable.and_then(|module| public_modules.get(&module).copied());
                selection_truncated |= public.is_none();
                public.map(|module| (module, surface))
            })
            .collect();
        surfaces.sort();
        for (module, surface) in surfaces {
            let ordinal = module_ordinals.entry(module).or_default();
            let Ok(index) = u16::try_from(inventory_surfaces.len()) else {
                selection_truncated = true;
                break;
            };
            surface_indices.insert(surface.clone(), (index, module));
            inventory_surfaces.push(render::SelectionSurface {
                module,
                ordinal: *ordinal,
                kind: match surface.base.kind {
                    InventorySurfaceKind::Legacy => "legacy",
                    InventorySurfaceKind::Interface => "interface",
                },
            });
            *ordinal = ordinal.saturating_add(1);
        }

        let mut providers: Vec<_> = self
            .selection_bindings
            .values()
            .map(|binding| binding.provider)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter_map(|stable| {
                let module = public_modules.get(&stable).copied();
                selection_truncated |= module.is_none();
                module
                    .zip(self.selection_coverage(stable))
                    .map(|(module, coverage)| render::SelectionProvider {
                        module,
                        coverage: match coverage {
                            SelectionCoverageVerdict::Observed => "observed",
                            SelectionCoverageVerdict::ObservedUncovered => "observed_uncovered",
                            SelectionCoverageVerdict::AbsentCovered => "absent_covered",
                            SelectionCoverageVerdict::AbsentUncovered => "absent_uncovered",
                        },
                    })
            })
            .collect();
        providers.sort_by_key(|provider| provider.module);
        providers.dedup_by_key(|provider| provider.module);
        if providers.len() > MAX_LIVE_SELECTION_SURFACES {
            providers.truncate(MAX_LIVE_SELECTION_SURFACES);
            selection_truncated = true;
        }

        let mut standard_exports: Vec<_> = history
            .modules
            .keys()
            .map(|stable| render::StandardExport {
                module: public_modules[stable],
                status: standard_export_status(
                    history.standard_exports.get(stable),
                    history.standard_requirements.get(stable),
                ),
            })
            .collect();
        if standard_exports.len() > MAX_LIVE_SELECTION_SURFACES {
            standard_exports.truncate(MAX_LIVE_SELECTION_SURFACES);
            selection_truncated = true;
        }

        let mut tuples: Vec<_> = history
            .selections
            .iter()
            .filter_map(|tuple| {
                let Some(module) = public_modules.get(&tuple.module).copied() else {
                    selection_truncated = true;
                    return None;
                };
                let mut inventory_matches: Vec<_> = tuple
                    .inventory_matches
                    .iter()
                    .filter_map(|matched| {
                        let Some((surface, owner)) = surface_indices.get(&matched.surface) else {
                            selection_truncated = true;
                            return None;
                        };
                        if *owner != module {
                            selection_truncated = true;
                            return None;
                        }
                        Some(render::SelectionMatch {
                            surface: *surface,
                            name_agrees: matched.name_agrees,
                            version_agrees: matched.version_agrees,
                        })
                    })
                    .collect();
                selection_truncated |= inventory_matches.len() != tuple.inventory_matches.len();
                inventory_matches.sort_by_key(|matched| {
                    (matched.surface, matched.name_agrees, matched.version_agrees)
                });
                let mut inventory_conflict = false;
                let mut canonical_matches: Vec<render::SelectionMatch> = Vec::new();
                for matched in inventory_matches {
                    if let Some(prior) = canonical_matches
                        .last_mut()
                        .filter(|prior| prior.surface == matched.surface)
                    {
                        inventory_conflict |= prior.name_agrees != matched.name_agrees
                            || prior.version_agrees != matched.version_agrees;
                        prior.name_agrees &= matched.name_agrees;
                        prior.version_agrees &= matched.version_agrees;
                    } else {
                        canonical_matches.push(matched);
                    }
                }
                let inventory_matches = canonical_matches;
                selection_truncated |= inventory_conflict;
                let lost_inventory_authority = tuple.authority == SelectionAuthority::Inventory
                    && (inventory_matches.is_empty() || inventory_conflict);
                Some(render::SelectionTuple {
                    module,
                    request: tuple.request,
                    rv: tuple.rv,
                    result: tuple.result,
                    table_match: !inventory_matches.is_empty(),
                    inventory_matches,
                    authority: if lost_inventory_authority {
                        SelectionAuthority::None
                    } else {
                        tuple.authority
                    },
                    count: tuple.count,
                })
            })
            .collect();
        tuples.sort_by_key(|tuple| serde_json::to_string(tuple).unwrap_or_default());
        tuples.dedup();

        render::InterfaceSelection {
            providers,
            standard_exports,
            inventory_surfaces,
            tuples,
            selection_truncated,
        }
    }

    pub(crate) fn account_unvalidated_discovery(&mut self, count: u64) {
        if count == 0 {
            return;
        }
        self.owned_initial_exec = None;
        self.discovery_truncated = self.discovery_truncated.saturating_add(count);
        self.invalidate_silent_selection_coverage();
        self.invalidate_causal_timing();
    }

    fn allocate_view_id(&mut self) -> Result<ProcessViewId> {
        if self.inventory.is_some() {
            self.inventory_state()?;
            let Some(inventory) = self.inventory.as_mut() else {
                unreachable!("checked Inventory state");
            };
            return inventory.reserve_owner(&mut self.next_view_id);
        }
        if let Some(reused) = self.retired_view_ids.pop() {
            return Ok(ProcessViewId(reused));
        }
        if self.next_view_id as usize >= self.max_scan_pids {
            let max_scan_pids = self.max_scan_pids;
            bail!("capture process-view capacity {max_scan_pids} is exhausted");
        }
        let id = ProcessViewId(self.next_view_id);
        self.next_view_id = self
            .next_view_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("process view ID space exhausted"))?;
        Ok(id)
    }

    fn release_view_id(&mut self, id: ProcessViewId) {
        self.exec_rearm_views.remove(&id);
        if let Some(seed) = self.trace_by_view.get(&id).copied() {
            if let Some(proof) = &self.trace_owner
                && let Some(candidate) = self.trace_seeds.get(&seed)
                && let TraceCandidateBody::Cgroup(registration) = &candidate.body
            {
                proof.cancel_cgroup_view(registration);
            }
            self.drop_trace_seed(seed);
        }
        if let Some(inventory) = &mut self.inventory {
            inventory.release_reservation(id);
            return;
        }
        // Skip-if-present: a duplicate retired entry would mint one ID to
        // two live views, so a double release is a silent no-op rather than
        // a debug-only abort.
        if !self.retired_view_ids.contains(&id.0) {
            self.retired_view_ids.push(id.0);
        }
        // `exploratory_dirty` is deliberately NOT cleared here: IDs are
        // reused, and a reused dirty ID stays non-rotatable — the capture
        // budget still keys that ID's old runtime evidence, and only a
        // never-dirty ID is provably free of it. Bounded by the ID space.
    }

    fn retain_view_id(&mut self, id: ProcessViewId) -> Result<()> {
        if self.inventory.is_some() {
            return self.inventory_state()?.require_reserved_or_retained(id);
        }
        if id.0 as usize >= self.max_scan_pids {
            let max_scan_pids = self.max_scan_pids;
            bail!("capture process-view capacity {max_scan_pids} is exhausted");
        }
        let next =
            id.0.checked_add(1)
                .ok_or_else(|| anyhow!("process view ID space exhausted"))?;
        self.next_view_id = self.next_view_id.max(next);
        Ok(())
    }

    #[track_caller]
    fn mark_partial(&mut self, subject: &str, reason: &str) {
        let skipped = Skipped {
            subject: subject.into(),
            reason: reason.into(),
        };
        attribution::note(&skipped);
        if !self.counters.object_skips.contains(&skipped) {
            self.counters.object_skips.push(skipped);
        }
        // The batch-tail merge folds `object_skips` into the published
        // history: any marker (even a dedup hit after a real mutation, like
        // a repeated eviction message) dirties the publication inputs.
        self.note_facts_mutated();
    }

    pub(crate) fn selection_coverage(
        &self,
        provider: plan::ModuleId,
    ) -> Option<SelectionCoverageVerdict> {
        let bindings: Vec<_> = self
            .selection_bindings
            .values()
            .filter(|binding| binding.provider == provider)
            .collect();
        if bindings.is_empty() {
            return None;
        }
        let observed = bindings.iter().any(|binding| binding.observed);
        let uncovered = bindings
            .iter()
            .any(|binding| !binding.observed && !binding.coverage.silently_covered());
        Some(match (observed, uncovered) {
            (true, true) => SelectionCoverageVerdict::ObservedUncovered,
            (true, false) => SelectionCoverageVerdict::Observed,
            (false, true) => SelectionCoverageVerdict::AbsentUncovered,
            (false, false) => SelectionCoverageVerdict::AbsentCovered,
        })
    }

    fn mark_owned_selection_pending(&mut self, generation: NonZeroU64) {
        let prior_selection_loss = {
            let history = self.capture_facts.visible_history();
            history.selection_truncated
                || history
                    .losses
                    .keys()
                    .any(|(subject, _)| subject == "live interface selection")
        };
        let transport_loss = self.counter_snapshot.ring_loss > 0
            || self.counter_snapshot.export_state_failures > 0
            || self.counter_snapshot.export_bounded_read_failures > 0
            || self.counter_snapshot.abi_refusals > 0
            || self.malformed_discovery > 0;
        for binding in self.selection_bindings.values_mut() {
            if binding.attached && !binding.retired {
                binding.coverage = if prior_selection_loss || transport_loss {
                    SelectionCoverageState::Uncovered
                } else {
                    SelectionCoverageState::OwnedPending(generation)
                };
            }
        }
    }

    fn open_owned_selection(&mut self, id: u64) {
        if let Some(binding) = self.selection_bindings.get_mut(&id)
            && binding.attached
            && !binding.retired
        {
            binding.coverage.open();
        }
    }

    #[cfg(test)]
    fn close_owned_selection(&mut self, id: u64) {
        if let Some(binding) = self.selection_bindings.get_mut(&id) {
            binding.coverage.close_naturally();
        }
    }

    fn close_owned_selection_for_view(&mut self, view: ProcessViewId) {
        for binding in self
            .selection_bindings
            .values_mut()
            .filter(|binding| binding.view == view)
        {
            binding.coverage.close_naturally();
        }
    }

    fn invalidate_silent_selection_coverage(&mut self) {
        for binding in self.selection_bindings.values_mut() {
            binding.coverage.invalidate();
        }
    }

    pub(crate) fn finish_owned_selection_coverage(&mut self, natural_exit: bool) {
        for binding in self.selection_bindings.values_mut() {
            if natural_exit {
                binding.coverage.close_naturally();
            } else {
                binding.coverage.invalidate();
            }
        }
    }

    fn observe_selection(&mut self, id: u64) {
        if let Some(binding) = self.selection_bindings.get_mut(&id) {
            binding.observed = true;
        }
    }

    fn invalidate_selection_coverage(&mut self, id: u64) {
        if let Some(binding) = self.selection_bindings.get_mut(&id) {
            binding.coverage.invalidate();
        }
    }

    /// One unattributed-selection rejection: loss marker, coverage
    /// invalidation, `Rejected` outcome. The binding-unknown site keeps its
    /// silent variant — there is no binding id to invalidate.
    fn reject_unattributed_selection(&mut self, id: u64, reason: &str) -> DiscoveryRecordOutcome {
        self.mark_live_loss("live interface selection", reason);
        self.invalidate_selection_coverage(id);
        DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed)
    }

    fn invalidate_selection_provider_coverage(&mut self, provider: plan::ModuleId) {
        for binding in self
            .selection_bindings
            .values_mut()
            .filter(|binding| binding.provider == provider)
        {
            binding.coverage.invalidate();
        }
    }

    fn invalidate_selection_table_coverage(&mut self, key: &SelectionTableKey) {
        let ids: Vec<_> = self
            .selection_bindings
            .values()
            .filter(|binding| {
                binding.view == key.view
                    && self
                        .pinned
                        .owned_timing_key(binding.object)
                        .is_some_and(|provider| provider == key.provider)
            })
            .map(|binding| binding.id)
            .collect();
        for id in ids {
            self.invalidate_selection_coverage(id);
        }
    }

    fn record_selection_loss(&mut self, reason: &str) {
        self.capture_facts.record_selection_loss(reason);
        self.invalidate_silent_selection_coverage();
    }

    fn record_selection_loss_for(&mut self, id: u64, reason: &str) {
        self.capture_facts.record_selection_loss(reason);
        self.invalidate_selection_coverage(id);
    }

    fn record_lifecycle_tracking_unavailable(&mut self, fact: Option<&str>) {
        if let Some(fact) = fact {
            self.mark_partial("live lifecycle tracking", fact);
        }
    }

    fn record_session_lifecycle_tracking(&mut self, session: &impl EngineSession) {
        self.record_lifecycle_tracking_unavailable(session.lifecycle_tracking_unavailable());
        if self.admits_generations()
            && session.capture_policy().uses_events()
            && (session.process_creation_tracking_unavailable().is_some()
                || session.lifecycle_tracking_unavailable().is_some())
        {
            if self.pid_descendant_gaps == 0 {
                self.pid_descendant_gaps = 1;
            }
            let boundary = match self.scope {
                Scope::System => {
                    "a required process-creation or lifecycle boundary was unavailable"
                }
                _ => "a required cgroup creation or lifecycle boundary was unavailable",
            };
            self.mark_partial("live lifecycle tracking", boundary);
        }
    }

    /// A retained generation changed under an operation that needed it. Loss —
    /// unless the retained original pin *proves* the process simply ended, the
    /// same authority `queue_retirement` and the live-record rule already use:
    /// a `--cgroup` capture of a workload that forks per unit of work loses a
    /// generation mid-arm every time one of its subprocesses finishes, and that
    /// is the ordinary end of a process. Timing proof goes either way.
    #[track_caller]
    fn mark_generation_change(&mut self, view: ProcessViewId, subject: &str, reason: &str) {
        if self.original_exited(view) {
            self.invalidate_causal_timing();
            return;
        }
        self.mark_live_loss(subject, reason);
    }

    #[track_caller]
    fn mark_live_loss(&mut self, subject: &str, reason: &str) {
        self.owned_initial_exec = None;
        self.invalidate_causal_timing();
        self.mark_partial(subject, reason);
    }

    /// Whether an `exec` explains why this armed context can no longer resolve
    /// a hit. Any of three proofs, all of them "the image this context was
    /// armed on is gone and a rescan of the same live generation is already
    /// owed": the refresh is queued for this exact view; an exec record for
    /// this pid has already asked for one; or the mapping the context was
    /// armed on is absent from the current image, which only `exec` does — and
    /// `sched_process_exec` is attached unconditionally, so the refresh is on
    /// its way even when its record sits behind this hit in the same ring
    /// batch. The hit is still rejected — it cannot be resolved against a
    /// context that no longer describes anything — but the refresh rescans
    /// that view whole and re-arms it, so nothing goes unobserved. Another
    /// view's context, or a live image that still holds the armed mapping, is
    /// loss, unchanged.
    fn exec_replaced_the_armed_image(
        &self,
        context: &LoaderContextSpec,
        view: ProcessViewId,
        pid: u32,
        maps: &[MapEntry],
        pending_views: &PendingViewRetirements,
    ) -> bool {
        if context.view != view {
            return false;
        }
        if pending_views.get(&view) == Some(&RetirementCause::ExecRefresh) {
            return true;
        }
        match &context.mapping {
            // The mapping the context was armed on is gone from a live image.
            // Only `exec` replaces an address space wholesale, so this is the
            // proof; an image that still holds it is loss.
            Some(armed) => !maps.iter().any(|mapping| mapping == armed),
            // The owned pre-exec prearm is armed on the interpreter of an
            // executable the child has not exec'd yet, so it has no mapping to
            // judge by and the only signal left is a refresh this capture
            // already owes for this pid. That is weaker — `refresh_requested`
            // is also set by `GenerationLost` and is retained for pids whose
            // refresh failed — so it is confined to the one context shape that
            // has no alternative, never used for a context that carries a
            // mapping of its own.
            None => self.refresh_requested.contains_key(&pid),
        }
    }

    #[track_caller]
    fn reject_loader_record(&mut self, reason: &str) -> bool {
        self.loader_registry.reject_hit();
        self.mark_live_loss("live loader discovery", reason);
        false
    }

    fn invalidate_causal_timing(&mut self) {
        self.timings.invalidate();
    }

    fn observe_causal_timing(&mut self, modules: &BTreeSet<PinnedTimingKey>, timestamp_ns: u64) {
        for module in modules {
            self.timings.observe(module, timestamp_ns);
        }
    }

    fn complete_causal_timing(
        &mut self,
        modules: &BTreeSet<PinnedTimingKey>,
        completed: Option<u64>,
    ) {
        for module in modules {
            if completed.is_none() {
                self.timings.lose(module);
            } else if let Some(completed) = completed {
                self.timings.complete(module, completed);
            }
        }
        if completed.is_none() && !modules.is_empty() {
            self.mark_partial(
                "live discovery timing",
                "the monotonic post-attach timestamp was unavailable",
            );
        }
    }

    fn record_apply_timing(&mut self, outcome: &ApplyOutcome) {
        for (modules, completed) in &outcome.static_completions {
            self.complete_causal_timing(modules, *completed);
        }
        for module in &outcome.static_failures {
            self.timings.lose(module);
        }
    }

    /// Applies one multi-group rebuild report with the existing conservative
    /// rules: recompleted survivors record fresh completions through the
    /// same records fresh attach uses, failed survivors deactivate and
    /// record failures exactly like failed fresh targets, and every rebuilt
    /// group counts a published gap window. Detach proves no callback
    /// quiescence and the task+slot pairing key carries no attachment
    /// generation, so every rebuild also publishes pairing uncertainty for
    /// calls in flight across the window; the next call on the task+slot
    /// pairs fresh once the stale start is consumed. A report member the
    /// plan cannot resolve is never applied silently.
    fn apply_group_rebuild(
        &mut self,
        plan: &mut plan::AttachPlan,
        owners: &BTreeMap<plan::ModuleId, PinnedTimingKey>,
        report: DetachOutcome,
        outcome: &mut ApplyOutcome,
    ) {
        let DetachOutcome {
            recompleted,
            rebuild_failures,
            rebuilt_groups,
        } = report;
        if rebuilt_groups == 0 && recompleted.is_empty() && rebuild_failures.is_empty() {
            return;
        }
        for index in recompleted
            .iter()
            .map(|(index, _)| index)
            .chain(rebuild_failures.iter().map(|(index, _)| index))
        {
            if !plan.slots.iter().any(|slot| slot.index == *index) {
                self.mark_partial(
                    "multi group rebuild",
                    "a rebuilt slot has no plan entry; its reactivation is unrecorded",
                );
            }
        }
        outcome.record_completions(&plan.slots, owners, recompleted);
        for (index, _) in &rebuild_failures {
            if let Some(slot) = plan.slots.iter().find(|slot| slot.index == *index).cloned() {
                outcome
                    .static_failures
                    .extend(slot_timing_keys(&slot, owners));
                plan.deactivate(*index);
            }
        }
        self.multi_rebuild_gaps = self.multi_rebuild_gaps.saturating_add(rebuilt_groups);
        if !rebuild_failures.is_empty() {
            self.mark_partial(
                "multi group rebuild",
                "rebuilt-group survivors failed to reattach and were deactivated",
            );
        }
        self.mark_partial(
            "multi group rebuild",
            "one or more groups rebuilt; calls in flight across the rebuild window may pair entry and return across attachment generations",
        );
    }

    /// The live path's `/proc/<pid>/maps` snapshot: the scan path's bounded
    /// reader, refused whole when any ceiling or the batch deadline cuts it
    /// (`read_maps_or_refuse`). Every caller turns `Err` into a refused
    /// record or an unarmed view, never into a decision on a shorter map.
    fn read_maps(view: &ProcessView, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>> {
        let pid = view.pid();
        view.run_while_same(|| {
            let maps = std::fs::File::open(format!("/proc/{pid}/maps"))
                .map_err(|error| error.to_string())?;
            read_maps_or_refuse(maps, budget, crate::attach::monotonic_ns)
        })
        .map_err(anyhow::Error::msg)?
        .map_err(anyhow::Error::msg)
    }

    fn loader_locator(
        view: &ProcessView,
        budget: &mut CaptureWorkBudget,
    ) -> Result<Option<LoaderLocator>> {
        let pid = view.pid();
        // One mount-table read serves every identity below (H-3).
        let mut mounts = crate::process::MountTableCache::default();
        let before_maps = Self::read_maps(view, budget)?;
        let executable_path = PathBuf::from(format!("/proc/{pid}/exe"));
        let before_executable = view_object_key_cached(view, &executable_path, &mut mounts, budget)
            .map_err(anyhow::Error::msg)?;
        let executable = view
            .run_while_same(|| std::fs::File::open(&executable_path))
            .map_err(anyhow::Error::msg)??;
        let before_file = FileSnapshot::read(&executable).map_err(anyhow::Error::msg)?;
        let (interpreter, executable_abi) =
            read_bounded_interpreter(&executable, before_file.size).map_err(anyhow::Error::msg)?;
        let after_file = FileSnapshot::read(&executable).map_err(anyhow::Error::msg)?;
        if before_file != after_file {
            bail!("retained executable changed during bounded PT_INTERP discovery");
        }
        let retained_executable =
            retained_object_key_cached(view, &executable, &mut mounts, budget)
                .map_err(anyhow::Error::msg)?;

        let interpreter_file = if let Some(interpreter) = &interpreter {
            let path = PathBuf::from(format!("/proc/{pid}/root")).join(
                interpreter
                    .strip_prefix("/")
                    .expect("bounded PT_INTERP paths are absolute"),
            );
            let (file, key) = open_view_object_cached(view, &path, &mut mounts, budget)
                .map_err(anyhow::Error::msg)?;
            let object = read_elf_snapshot(&file, budget).map_err(anyhow::Error::msg)?;
            if object.abi() != executable_abi {
                bail!("retained executable and PT_INTERP have different target ABIs");
            }
            let snapshot = FileSnapshot::read(&file).map_err(anyhow::Error::msg)?;
            Some((snapshot, key, file))
        } else {
            None
        };

        let after_maps = Self::read_maps(view, budget)?;
        let after_executable = view_object_key_cached(view, &executable_path, &mut mounts, budget)
            .map_err(anyhow::Error::msg)?;
        if before_executable != retained_executable || retained_executable != after_executable {
            bail!("retained executable identity changed during PT_INTERP discovery");
        }
        let before_index =
            index_maps_or_refuse(&before_maps, budget).map_err(anyhow::Error::msg)?;
        let after_index = index_maps_or_refuse(&after_maps, budget).map_err(anyhow::Error::msg)?;
        let before_executable_maps = executable_snapshot_for_fd(
            &before_index,
            &executable,
            retained_executable,
            budget,
            &KernelSelfMappingProbe,
        )
        .map_err(anyhow::Error::msg)?;
        let after_executable_maps = executable_snapshot_for_fd(
            &after_index,
            &executable,
            retained_executable,
            budget,
            &KernelSelfMappingProbe,
        )
        .map_err(anyhow::Error::msg)?;
        if before_executable_maps != after_executable_maps {
            bail!("retained executable mappings changed during PT_INTERP discovery");
        }
        let Some(interpreter) = interpreter else {
            return Ok(None);
        };
        let (interpreter_file, loader_key, loader_file) =
            interpreter_file.expect("a PT_INTERP snapshot has its retained file identity");
        let (before_loader_path, before_loader_maps) = loader_snapshot_for_fd(
            &before_index,
            &loader_file,
            loader_key,
            budget,
            &KernelSelfMappingProbe,
        )
        .map_err(anyhow::Error::msg)?;
        let (loader_path, loader_maps) = loader_snapshot_for_fd(
            &after_index,
            &loader_file,
            loader_key,
            budget,
            &KernelSelfMappingProbe,
        )
        .map_err(anyhow::Error::msg)?;
        if before_loader_path != loader_path || before_loader_maps != loader_maps {
            bail!("retained loader mappings changed during PT_INTERP discovery");
        }
        Ok(Some(LoaderLocator {
            authority: LoaderAuthority {
                executable_file: before_file,
                executable_key: retained_executable,
                executable_maps: after_executable_maps,
                executable_abi,
                interpreter,
                interpreter_file,
                loader_key,
                loader_path,
                loader_maps,
            },
            maps: after_maps,
        }))
    }

    /// Takes at most `LIVE_DISCOVERY_DRAIN_QUANTUM` items off the private
    /// ring, which refills while it is read. `Ok` means the ring read empty; a
    /// quantum stop is an `IncompleteTerminalDrain` with `backlog` set, so no
    /// route can mistake it for an empty ring, and the terminal routes retain
    /// its exact prefix as an incomplete batch until a later drain reads empty.
    /// Test-only: every production pull goes through `nested_pull_capped`
    /// or a bounded frame/terminal quantum under the shared allowance.
    #[cfg(test)]
    fn collect_discovery_records(
        session: &mut dyn EngineSession,
    ) -> Result<(Vec<DiscoveryRecord>, u64)> {
        let mut records = Vec::new();
        let mut malformed = 0u64;
        for _ in 0..LIVE_DISCOVERY_DRAIN_QUANTUM {
            match session.discovery_dequeue() {
                Ok(Some(crate::events::DiscoveryItem::Record(record))) => records.push(record),
                Ok(Some(crate::events::DiscoveryItem::Malformed)) => {
                    malformed = malformed.saturating_add(1);
                }
                Ok(None) => return Ok((records, malformed)),
                // Whatever this drain already took off the ring is gone from
                // the producer, so it travels with the failure as the retained
                // prefix, exactly as the timed terminal collector does.
                Err(error) => {
                    return Err(IncompleteTerminalDrain::new(records, malformed, 0, error).into());
                }
            }
        }
        Err(IncompleteTerminalDrain::backlog(records, malformed).into())
    }

    /// Pulls up to `quantum` items for a capacity-bounded collector
    /// quantum, consuming `budget` only for fresh ring reads. Staged pops
    /// are credit transfers — the FIFO shrinks as the batch grows — and
    /// cost nothing, so a staged backlog never under-admits fresh room.
    /// Stops at the first observed empty read, at the quantum, or at an
    /// exhausted budget with nothing staged to transfer; all three keep
    /// their exact prefix. Only an observed empty read proves the queue
    /// drained: a budget stop is never an empty observation. A real
    /// dequeue failure still carries its retained prefix with it.
    fn collect_discovery_records_budgeted(
        session: &mut dyn EngineSession,
        budget: &Cell<usize>,
        quantum: usize,
    ) -> Result<(Vec<DiscoveryRecord>, u64, bool)> {
        let mut records = Vec::new();
        let mut malformed = 0u64;
        for _ in 0..quantum {
            if budget.get() == 0 && session.staged_discovery_len() == 0 {
                return Ok((records, malformed, false));
            }
            // A dequeue never grows the FIFO: an unchanged length means
            // the item came off the ring (a fresh acquisition), a shrunk
            // one means it transferred out of the FIFO (already counted).
            let staged_before = session.staged_discovery_len();
            match session.discovery_dequeue() {
                Ok(Some(crate::events::DiscoveryItem::Record(record))) => {
                    if session.staged_discovery_len() == staged_before {
                        budget.set(budget.get().saturating_sub(1));
                    }
                    records.push(record);
                }
                Ok(Some(crate::events::DiscoveryItem::Malformed)) => {
                    if session.staged_discovery_len() == staged_before {
                        budget.set(budget.get().saturating_sub(1));
                    }
                    malformed = malformed.saturating_add(1);
                }
                Ok(None) => return Ok((records, malformed, true)),
                Err(error) => {
                    return Err(IncompleteTerminalDrain::new(records, malformed, 0, error).into());
                }
            }
        }
        Ok((records, malformed, false))
    }

    /// Every dequeue is capture-wide work, charged where the records enter the
    /// Engine. They are already off the ring, so a refused charge never drops
    /// them: the sticky stop it leaves is what the budget's other consumers
    /// refuse on and publish under its own reason.
    fn charge_discovery_drain(&mut self, records: usize, malformed: u64) {
        let units = (records as u64).saturating_add(malformed);
        if units != 0 {
            self.budget.charge(units);
        }
        // The drain quantum returns to its caller here, so this is the live
        // collector path's one clock poll per quantum: a batch deadline that
        // expired during the drain stops the capture at this boundary instead
        // of one whole batch later. A refused charge is published exactly once,
        // under whichever ceiling actually stopped it — never mislabelled.
        if self.budget.stopped_now().is_some()
            && let Some(reason) = self.budget.take_scan_stop_reason()
        {
            self.mark_live_loss("live discovery drain", reason);
        }
    }

    fn record_malformed_discovery(&mut self, malformed: u64) {
        if malformed == 0 {
            return;
        }
        self.owned_initial_exec = None;
        self.malformed_discovery = self.malformed_discovery.saturating_add(malformed);
        self.invalidate_silent_selection_coverage();
        self.invalidate_causal_timing();
        self.mark_partial(
            "live discovery transport",
            "one or more malformed private discovery records were discarded",
        );
    }

    fn scan_retained_view(
        view: &ProcessView,
        module_hints: &[PathBuf],
        hooks: &HookRegistry,
        budget: &mut CaptureWorkBudget,
        broad_admit: bool,
        stage: &mut crate::timing::StageTimings,
    ) -> (
        Result<(Vec<ScannedModule>, PinnedObjects, bool)>,
        DiscoveryCounters,
    ) {
        Self::scan_retained_view_with(|counters| {
            scan_and_pin_with(
                view,
                module_hints,
                hooks,
                budget,
                counters,
                broad_admit,
                stage,
                scan_process_view,
            )
        })
    }

    fn scan_retained_view_without_memory(
        view: &ProcessView,
        module_hints: &[PathBuf],
        hooks: &HookRegistry,
        budget: &mut CaptureWorkBudget,
        broad_admit: bool,
        stage: &mut crate::timing::StageTimings,
    ) -> (
        Result<(Vec<ScannedModule>, PinnedObjects, bool)>,
        DiscoveryCounters,
    ) {
        Self::scan_retained_view_with(|counters| {
            scan_and_pin_with(
                view,
                module_hints,
                hooks,
                budget,
                counters,
                broad_admit,
                stage,
                scan_process_view_without_memory,
            )
        })
    }

    /// Ensure retry/setup work is queued without renewing a later consumed
    /// request or counting an unperformed retry as another dropped record.
    /// `None` keeps the original arrival clock-unknown.
    fn request_refresh(&mut self, pid: u32, now_ns: Option<u64>) -> bool {
        let accepted = self.request_refresh_with(pid, now_ns, false, None);
        if !accepted {
            // A retained owner's skipped setup/replacement must remain owed
            // when the PID queue cannot accept it. The existing bounded
            // retirement-intent replay waits for capacity before finishing
            // ExecRefresh. Stronger existing retirement causes still win.
            for view in self.views.iter().filter(|view| view.pid() == pid) {
                self.retirement_intents
                    .entry(view.id())
                    .and_modify(|cause| *cause = cause.merge(RetirementCause::ExecRefresh))
                    .or_insert(RetirementCause::ExecRefresh);
            }
        }
        accepted
    }

    /// Each consumed record renews pending intent while keeping its first
    /// arrival mark. Refusing that record preserves explicit loss evidence.
    fn request_refresh_consumed(&mut self, pid: u32, now_ns: Option<u64>) -> bool {
        self.request_refresh_with(pid, now_ns, true, None)
    }

    /// The lifecycle matcher already identified this record's retained
    /// owner. Keep that identity when an original pin now proves exit:
    /// the late record still belongs to the ended group, not a replacement.
    fn request_refresh_consumed_for_view(
        &mut self,
        pid: u32,
        now_ns: Option<u64>,
        owner: ProcessViewId,
    ) -> bool {
        self.request_refresh_with(pid, now_ns, true, Some(owner))
    }

    fn request_refresh_with(
        &mut self,
        pid: u32,
        now_ns: Option<u64>,
        consumed: bool,
        owner: Option<ProcessViewId>,
    ) -> bool {
        let existing = self.refresh_requested.get(&pid).copied();
        if existing.is_some() && !consumed {
            return true;
        }
        if existing.is_none() && self.refresh_requested.len() >= MAX_PENDING_REFRESH {
            if consumed {
                self.discovery_truncated = self.discovery_truncated.saturating_add(1);
                // Diff-first arrivals retain their known dropped age.
                let seen = self.newcomer_first_seen.get(&pid).copied().flatten();
                self.newcomer_ages
                    .note_dropped(newcomer_age_ms(seen, now_ns));
                self.mark_live_loss(
                    "live discovery refresh",
                    "refresh requests exceeded the bounded pending queue; excess requests were dropped",
                );
            } else {
                self.mark_partial(
                    "live discovery refresh",
                    "refresh retry exceeded the bounded pending queue; work remains unfinished",
                );
            }
            return false;
        }
        let Some(serial) = self.last_refresh_serial.checked_add(1) else {
            if consumed {
                self.discovery_truncated = self.discovery_truncated.saturating_add(1);
                let refresh_seen = existing.and_then(|request| request.first_seen_ns);
                let diff_seen = self.newcomer_first_seen.get(&pid).copied().flatten();
                let seen = match (refresh_seen, diff_seen) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (Some(a), None) | (None, Some(a)) => Some(a),
                    (None, None) => None,
                };
                self.newcomer_ages
                    .note_dropped(newcomer_age_ms(seen, now_ns));
                self.mark_live_loss(
                    "live discovery refresh",
                    "refresh request serials were exhausted; a consumed request was refused",
                );
            } else {
                self.mark_partial(
                    "live discovery refresh",
                    "refresh request serials were exhausted; retry work remains unfinished",
                );
            }
            return false;
        };
        self.last_refresh_serial = serial;
        let owner = owner.or_else(|| {
            self.views
                .iter()
                .find(|view| view.pid() == pid && view.still_the_same())
                .map(ProcessView::id)
        });
        self.refresh_requested.insert(
            pid,
            RefreshRequest {
                first_seen_ns: existing.map_or(now_ns, |request| request.first_seen_ns),
                serial,
                owner,
            },
        );
        true
    }

    fn clear_refresh_for_view(&mut self, view: ProcessViewId, pid: u32) {
        if self
            .refresh_requested
            .get(&pid)
            .is_some_and(|request| request.owner == Some(view))
        {
            self.refresh_requested.remove(&pid);
        }
    }

    fn refresh_request_snapshot(&self) -> BTreeMap<u32, u64> {
        self.refresh_requested
            .iter()
            .map(|(pid, request)| (*pid, request.serial))
            .collect()
    }

    fn complete_refresh_requests(&mut self, serviced: &BTreeMap<u32, u64>, failed: &BTreeSet<u32>) {
        self.refresh_requested.retain(|pid, request| {
            failed.contains(pid) || serviced.get(pid) != Some(&request.serial)
        });
    }

    /// Marks one diff-discovered newcomer's arrival (first diff wins; later
    /// diffs keep the earliest mark). Past the mark cap the mark drops and
    /// counts itself — those admissions sample clock-unknown, never zero.
    fn mark_newcomer_arrival(&mut self, pid: u32, now_ns: Option<u64>) {
        if self.newcomer_first_seen.contains_key(&pid) {
            return;
        }
        if self.newcomer_first_seen.len() >= crate::timing::MAX_NEWCOMER_MARKS {
            self.newcomer_ages.note_mark_dropped();
            return;
        }
        self.newcomer_first_seen.insert(pid, now_ns);
    }

    /// Samples one newcomer admission age: first-observed-ready minus
    /// first-seen, in whole milliseconds. First-seen is the earliest known
    /// mark (a loader event can queue a refresh before the diff finds the
    /// pid, or after — either order keeps the earlier observation).
    fn sample_newcomer_admission(&mut self, pid: u32, now_ns: Option<u64>) {
        let refresh_seen = self
            .refresh_requested
            .get(&pid)
            .and_then(|request| request.first_seen_ns);
        let diff_seen = self.newcomer_first_seen.get(&pid).copied().flatten();
        let seen = match (refresh_seen, diff_seen) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        self.newcomer_ages
            .note_admitted(newcomer_age_ms(seen, now_ns));
        self.newcomer_first_seen.remove(&pid);
    }

    /// Bumps the publication-input revision: every live-batch mutation of
    /// the batch-tail merge inputs calls this, so the tail skip gate sees
    /// it. Unconditional by design — a dedup-hit marker (an eviction message
    /// identical to an earlier one) still follows a real mutation.
    fn note_facts_mutated(&mut self) {
        self.loader_plan_cache = None;
        self.facts_revision = self.facts_revision.saturating_add(1);
    }

    fn defer_loader_memory_scan(&mut self, key: PendingLoaderScanKey, hook_ts_ns: u64) {
        if let Some(earliest) = self.pending_loader_scans.get_mut(&key) {
            *earliest = (*earliest).min(hook_ts_ns);
            return;
        }
        if self.pending_loader_scans.len() == crate::discovery::loader::MAX_LOADER_CONTEXTS {
            self.record_pending_loader_scan_loss(
                "a deferred loader memory scan exceeded the bounded loader-context ledger",
            );
            return;
        }
        self.pending_loader_scans.insert(key, hook_ts_ns);
    }

    fn record_pending_loader_scan_loss(&mut self, reason: &str) {
        self.discovery_truncated = self.discovery_truncated.saturating_add(1);
        self.mark_live_loss("live loader memory discovery", reason);
    }

    /// A deferred scan whose process provably exited before the loader
    /// transaction's RT_CONSISTENT. It stays a counted truncation, but not a
    /// causal-timing loss: dlopen relocates and initializes an object only
    /// after RT_CONSISTENT, so an object announced by RT_ADD in a process
    /// that ended first never ran, and RT_DELETE introduces nothing (GT-4).
    fn record_pending_loader_scan_end(&mut self, reason: &str) {
        self.discovery_truncated = self.discovery_truncated.saturating_add(1);
        self.mark_partial("live loader memory discovery", reason);
    }

    fn settle_pending_loader_scan(
        &mut self,
        key: PendingLoaderScanKey,
        reason: &str,
        ended: bool,
    ) -> bool {
        if self.pending_loader_scans.remove(&key).is_none() {
            return false;
        }
        if ended {
            self.record_pending_loader_scan_end(reason);
        } else {
            self.record_pending_loader_scan_loss(reason);
        }
        true
    }

    fn settle_pending_loader_scans_for_view(
        &mut self,
        view: ProcessViewId,
        reason: &str,
        ended: bool,
    ) {
        let pending: Vec<_> = self
            .pending_loader_scans
            .keys()
            .filter(|key| key.view == view)
            .copied()
            .collect();
        for key in pending {
            self.settle_pending_loader_scan(key, reason, ended);
        }
    }

    fn settle_all_pending_loader_scans(&mut self, reason: &str) {
        let pending: Vec<_> = self.pending_loader_scans.keys().copied().collect();
        for key in pending {
            self.settle_pending_loader_scan(key, reason, false);
        }
    }

    fn scan_retained_view_with(
        scan: impl FnOnce(&mut DiscoveryCounters) -> Result<(Vec<ScannedModule>, PinnedObjects, bool)>,
    ) -> (
        Result<(Vec<ScannedModule>, PinnedObjects, bool)>,
        DiscoveryCounters,
    ) {
        let mut counters = DiscoveryCounters::default();
        let result = scan(&mut counters);
        (result, counters)
    }

    fn absorb_scan_counters(&mut self, counters: DiscoveryCounters) -> Vec<Skipped> {
        self.counters.scan_unavailable =
            self.counters.scan_unavailable.or(counters.scan_unavailable);
        self.counters.scan_ms = self.counters.scan_ms.saturating_add(counters.scan_ms);
        self.counters.noise.merge(&counters.noise);
        // A scan ran: its time and availability feed the published history
        // through the batch tail, so the publication inputs are dirty even
        // when the scan found nothing new.
        self.note_facts_mutated();
        // An acquisition failure has already happened. Keep it even if later
        // inventory construction fails or normal exit suppresses a generic gap.
        for skipped in &counters.object_skips {
            if skipped.reason.starts_with("memory scan refused: ") {
                self.mark_partial(&skipped.subject, &skipped.reason);
            }
        }
        counters.object_skips
    }

    fn publish_current_capture_facts(&mut self) -> Result<()> {
        // A failed or staged publication cannot keep an earlier planning
        // proof alive. Successful stationary loader finalization may reseed.
        self.loader_plan_cache = None;
        let skips_start = crate::attach::monotonic_ns();
        record_object_skips(&mut self.plan, &self.counters.object_skips);
        self.stage_timings.span(
            crate::timing::StageKind::Projection,
            "record_publication_skips",
            skips_start,
            crate::attach::monotonic_ns(),
        );
        let merge_start = crate::attach::monotonic_ns();
        let merged = self.capture_facts.merge_current(
            &self.plan,
            &self.pinned,
            &self.modules,
            &self.manifests,
            &self.manifest_ordinals,
            &self.counters,
        );
        self.stage_timings.span(
            crate::timing::StageKind::Projection,
            "merge_facts",
            merge_start,
            crate::attach::monotonic_ns(),
        );
        merged?;
        if self.capture_facts.staged.is_some() {
            return Ok(());
        }
        self.project_capture_facts();
        self.published_facts_revision = self.facts_revision;
        Ok(())
    }

    /// Reuse a candidate's completed publication when no later input changed.
    /// The batch's `changed` flag still tells consumers to resynchronize; it
    /// does not require publishing the same revision twice. Scan time, loss
    /// markers and plan-equal pin commits dirty the revision independently.
    /// Startup staging remains ineligible for public-publication reuse.
    fn publish_batch_tail(&mut self, _changed: bool) -> Result<()> {
        if self.facts_revision != self.published_facts_revision
            || self.capture_facts.staged.is_some()
        {
            self.publish_current_capture_facts()?;
            self.tail_publishes = self.tail_publishes.saturating_add(1);
        } else {
            self.tail_skips = self.tail_skips.saturating_add(1);
        }
        Ok(())
    }

    fn project_capture_facts(&mut self) {
        self.loader_plan_cache = None;
        let project_start = crate::attach::monotonic_ns();
        self.capture_facts.apply_to_plan(&mut self.plan);
        self.discovery = self.capture_facts.discovery(&self.plan);
        self.stage_timings.span(
            crate::timing::StageKind::Projection,
            "project_facts",
            project_start,
            crate::attach::monotonic_ns(),
        );
    }

    fn start_publication_snapshot(&self) -> StartPublicationSnapshot {
        StartPublicationSnapshot {
            plan: self.plan.clone(),
            pinned: self.pinned.clone(),
            discovery: self.discovery.clone(),
            modules: self.modules.clone(),
            corroboration: self.counters.corroboration.clone(),
            manifest_fallbacks: self.counters.manifest_fallbacks.clone(),
            views: self.views.iter().map(ProcessView::id).collect(),
            next_selection_binding_id: self.next_selection_binding_id,
            selection_bindings: self.selection_bindings.clone(),
            selection_claims: self.selection_claims.clone(),
            selection_tables: self.selection_tables.clone(),
        }
    }

    fn begin_start_capture_attempt(&mut self) -> Result<StartPublicationSnapshot> {
        self.capture_facts.begin_stage()?;
        let snapshot = self.start_publication_snapshot();
        if let Err(error) = self.publish_current_capture_facts() {
            self.capture_facts.rollback_stage();
            return Err(error);
        }
        self.next_selection_binding_id = Some(1);
        self.selection_bindings.clear();
        self.selection_claims.clear();
        self.selection_tables.clear();
        Ok(snapshot)
    }

    /// Puts back the publication the failed start attempt was built on. It has
    /// to be infallible: a post-link fallible rebuild here would speak over the
    /// original failure with an error about restoring from it.
    fn restore_start_publication(&mut self, snapshot: StartPublicationSnapshot) {
        let retained_views: BTreeSet<_> = self.views.iter().map(ProcessView::id).collect();
        let removed_views: BTreeSet<_> = snapshot
            .views
            .difference(&retained_views)
            .copied()
            .collect();
        let mut pinned = snapshot.pinned;
        for view in &removed_views {
            pinned.remove_view(*view);
        }
        let modules: Vec<_> = snapshot
            .modules
            .into_iter()
            .filter(|module| !removed_views.contains(&module.scanned.view))
            .collect();
        let mut plan = snapshot.plan;
        // Normal active cleanup still applies: an endpoint whose exact pinned
        // identity left with its process view stops accepting probes, and its
        // already-accepted aggregate cell stays exactly as it was.
        plan.retire_unpinned_targets(&pinned, plan.slots.len());
        record_object_skips(&mut plan, &self.counters.object_skips);

        self.plan = plan;
        self.pinned = pinned;
        self.modules = modules;
        self.counters.corroboration = snapshot.corroboration;
        self.counters.manifest_fallbacks = snapshot.manifest_fallbacks;
        self.note_facts_mutated();
        self.next_selection_binding_id = snapshot.next_selection_binding_id;
        self.selection_bindings = snapshot.selection_bindings;
        self.selection_claims = snapshot.selection_claims;
        self.selection_claims
            .retain(|claim, _| !removed_views.contains(&claim.view));
        self.selection_tables = snapshot.selection_tables;
        self.selection_tables
            .retain(|table, _| !removed_views.contains(&table.view));
        if removed_views.is_empty() {
            self.discovery = snapshot.discovery;
        } else if self.capture_facts.history.modules.is_empty()
            && self.capture_facts.history.decoded.is_empty()
        {
            self.discovery = discovery_evidence(&self.plan, &self.pinned, &self.counters);
        } else {
            self.project_capture_facts();
        }
    }

    fn finish_start_capture_attempt<T>(
        &mut self,
        snapshot: StartPublicationSnapshot,
        result: Result<T>,
    ) -> Result<T> {
        match result {
            Ok(value) => {
                self.capture_facts.commit_stage()?;
                self.project_capture_facts();
                self.published_facts_revision = self.facts_revision;
                Ok(value)
            }
            Err(error) => {
                self.capture_facts.rollback_stage();
                self.restore_start_publication(snapshot);
                self.owned_initial_exec = None;
                self.settle_all_pending_loader_scans(
                    "a deferred loader memory scan was unresolved when capture start was cancelled",
                );
                record_object_skips(&mut self.plan, &self.counters.object_skips);
                Err(error)
            }
        }
    }

    fn live_candidate(
        &mut self,
        pinned: PinnedObjects,
        raw_modules: Vec<ScannedModule>,
        skipped: Vec<Skipped>,
    ) -> Result<LiveCandidate> {
        self.live_candidate_with_pending(pinned, raw_modules, skipped, None)
    }

    fn live_candidate_with_pending(
        &mut self,
        mut pinned: PinnedObjects,
        mut raw_modules: Vec<ScannedModule>,
        mut skipped: Vec<Skipped>,
        pending_selection: Option<&SelectionTableKey>,
    ) -> Result<LiveCandidate> {
        self.loader_plan_cache = None;
        let merge_head_start = crate::attach::monotonic_ns();
        self.pending_rejected_keys
            .extend(pinned.newly_rejected_keys(&self.pinned));
        let (_, overlay_skips) = canonicalize_scanned_overlays(&mut pinned);
        skipped.extend(overlay_skips);
        if self.pinned.has_overlay_uncertainty() || pinned.has_overlay_uncertainty() {
            self.invalidate_causal_timing();
        }
        attribution::note_all(&skipped);
        for skip in skipped {
            if !self.counters.object_skips.contains(&skip) {
                self.counters.object_skips.push(skip);
                self.note_facts_mutated();
            }
        }
        raw_modules.retain(|module| {
            !pinned.rejects(module.key)
                && !module
                    .tables
                    .iter()
                    .flat_map(|table| &table.entries)
                    .any(|entry| pinned.rejects(entry.object))
        });
        pinned.reset_derived_claims();
        self.stage_timings.span(
            crate::timing::StageKind::Merge,
            "live_merge_head",
            merge_head_start,
            crate::attach::monotonic_ns(),
        );
        let bind_start = crate::attach::monotonic_ns();
        let (modules, binding_skips) = bind_scanned_modules(&raw_modules, &mut pinned);
        self.stage_timings.span(
            crate::timing::StageKind::Bind,
            "bind_live_modules",
            bind_start,
            crate::attach::monotonic_ns(),
        );
        let merge_mid_start = crate::attach::monotonic_ns();
        attribution::note_all(&binding_skips);
        for skip in binding_skips {
            if !self.counters.object_skips.contains(&skip) {
                self.counters.object_skips.push(skip);
                self.note_facts_mutated();
            }
        }
        self.stage_timings.span(
            crate::timing::StageKind::Merge,
            "live_merge_mid",
            merge_mid_start,
            crate::attach::monotonic_ns(),
        );
        let plan_start = crate::attach::monotonic_ns();
        let broad_admit = self.broad_admit;
        let mut rebuilt =
            self.plan
                .rebuild_from_sources_broad(&modules, &self.manifests, &pinned, broad_admit);
        self.capture_facts.bind_plan_module_ids(
            &mut rebuilt,
            &modules,
            &self.manifests,
            &pinned,
        )?;
        let manifest_inventory_slots = rebuilt
            .slots
            .iter()
            .map(|slot| {
                (
                    plan::AttachKey {
                        object: slot.object,
                        file_offset: slot.file_offset,
                    },
                    slot.clone(),
                )
            })
            .collect();
        let (manifest_selection_admissions, selection_refusals) = lower_manifest_selection_tables(
            &mut rebuilt,
            &self.plan,
            &self.manifests,
            &self.manifest_ordinals,
            &pinned,
        );
        for reason in selection_refusals {
            self.mark_partial("offline interface selection", &reason);
        }
        self.stage_timings.span(
            crate::timing::StageKind::Plan,
            "rebuild_live_plan",
            plan_start,
            crate::attach::monotonic_ns(),
        );
        let mut merge_tail_start = crate::attach::monotonic_ns();
        record_object_skips(&mut rebuilt, &self.counters.object_skips);
        let module_objects: BTreeSet<_> =
            rebuilt.modules.iter().map(|module| module.object).collect();
        let mut corroboration = self.counters.corroboration.clone();
        let mut invalidated_modules = BTreeSet::new();
        corroboration.retain(|(objects, _)| {
            let keep = !objects.is_empty()
                && objects.iter().all(|object| {
                    module_objects.contains(object) && pinned.summary(*object).is_some()
                });
            if !keep {
                invalidated_modules.extend(
                    self.plan
                        .modules
                        .iter()
                        .filter(|module| objects.contains(&module.object))
                        .map(|module| module.id),
                );
            }
            keep
        });
        let mut manifest_fallbacks = self.counters.manifest_fallbacks.clone();
        let mut invalidated_fallbacks = BTreeSet::new();
        manifest_fallbacks.retain(|fallback| {
            let keep = pinned.summary(fallback.replacement).is_some()
                && fallback_proof_in_plan(&fallback.proof, &rebuilt);
            if !keep {
                invalidated_fallbacks.insert((fallback.manifest, fallback.object));
            }
            keep
        });
        if !invalidated_modules.is_empty() || !invalidated_fallbacks.is_empty() {
            self.capture_facts
                .invalidate_discovery_proofs(invalidated_modules, invalidated_fallbacks);
            // The projection below records its own span: close the merge
            // tail before it and reopen after, so stages never overlap.
            self.stage_timings.span(
                crate::timing::StageKind::Merge,
                "live_merge_tail",
                merge_tail_start,
                crate::attach::monotonic_ns(),
            );
            if self.capture_facts.staged.is_none() {
                self.project_capture_facts();
            }
            merge_tail_start = crate::attach::monotonic_ns();
            self.mark_partial(
                "live discovery evidence",
                "a late identity collision invalidated prior exact fallback or corroboration evidence",
            );
        }
        let mut selection_claims = self.selection_claims.clone();
        let active_keys: BTreeSet<_> = self
            .plan
            .slots
            .iter()
            .filter(|slot| self.plan.is_active(slot.index))
            .map(|slot| plan::AttachKey {
                object: slot.object,
                file_offset: slot.file_offset,
            })
            .collect();
        selection_claims.retain(|key, claim| {
            let Some(binding) = self.selection_bindings.get(&key.binding_id) else {
                return false;
            };
            let live_view = self
                .views
                .iter()
                .any(|view| view.id() == key.view && view.still_the_same());
            let binding_live = binding.attached
                && !binding.retired
                && binding.context.get() == key.context
                && binding.view == key.view
                && binding.object == key.hook_owner
                && self
                    .loader_registry
                    .context(binding.context)
                    .is_some_and(|context| {
                        context.spec.view == key.view
                            && !self.loader_registry.is_tombstoned(binding.context)
                    })
                && pinned
                    .owned_timing_key(binding.object)
                    .is_some_and(|provider| provider == key.provider)
                && pinned.summary(claim.target.object).is_some()
                && claim.target.object == key.selected_object
                && claim.target.file_offset == key.file_offset;
            let pending =
                pending_selection.is_some_and(|pending| selection_table_key(key) == *pending);
            live_view && binding_live && (pending || active_keys.contains(&claim.target))
        });
        for key in prune_selection_table_conflicts(&mut selection_claims) {
            self.refuse_selection_authority_for(
                &key,
                "conflicting selection claims shared one semantic table key",
            );
        }
        let mut selection_tables = self.selection_tables.clone();
        selection_tables.retain(|key, _| {
            self.views
                .iter()
                .any(|view| view.id() == key.view && view.still_the_same())
                && modules.iter().any(|module| {
                    module.scanned.view == key.view
                        && pinned
                            .owned_timing_key(module.object)
                            .is_some_and(|provider| provider == key.provider)
                })
        });
        let active_selection_tables = selection_tables_from_claims(&selection_claims);
        for (key, table) in active_selection_tables {
            if selection_tables.get(&key).is_some_and(|known| {
                known.object != table.object
                    || known.file_offset != table.file_offset
                    || !same_selection_target_set(&known.targets, &table.targets)
            }) {
                self.refuse_selection_authority_for(
                    &key,
                    "a live selection claim conflicted with its provider-generation table latch",
                );
                selection_claims.retain(|claim, _| selection_table_key(claim) != key);
                continue;
            }
            selection_tables
                .entry(key.clone())
                .or_insert_with(|| table.clone());
            let Some(module_id) = modules
                .iter()
                .find(|module| {
                    module.scanned.view == key.view
                        && pinned
                            .owned_timing_key(module.object)
                            .is_some_and(|provider| provider == key.provider)
                })
                .and_then(|selected| {
                    rebuilt
                        .modules
                        .iter()
                        .find(|module| module.object == selected.object)
                })
                .map(|module| module.id)
            else {
                self.record_selection_loss("a live selection claim lost its provider module");
                selection_claims.retain(|claim, _| selection_table_key(claim) != key);
                continue;
            };
            if let Err(reason) =
                rebuilt.add_selection_table(&self.plan, module_id, table.targets.clone())
            {
                self.mark_partial("live interface selection", &reason);
                self.refuse_selection_authority_for(
                    &key,
                    "a live selection table could not be admitted",
                );
                selection_claims.retain(|claim, _| selection_table_key(claim) != key);
            }
        }
        let mut candidate_plan = self.plan.clone();
        let delta = candidate_plan
            .extend_exact_with_stable_module_ids(rebuilt)
            .map_err(anyhow::Error::msg)?;
        if !candidate_identity_is_complete(&candidate_plan, &modules, &pinned) {
            bail!("live candidate retained an active module or slot without exact pinned identity");
        }
        record_object_skips(&mut candidate_plan, &self.counters.object_skips);
        let views = modules.iter().map(|module| module.scanned.view).collect();
        self.stage_timings.span(
            crate::timing::StageKind::Merge,
            "live_merge_tail",
            merge_tail_start,
            crate::attach::monotonic_ns(),
        );
        Ok(LiveCandidate {
            pinned,
            modules,
            plan: candidate_plan,
            delta,
            views,
            corroboration,
            manifest_fallbacks,
            selection_claims,
            selection_tables,
            selection_admission: None,
            manifest_selection_admissions,
            manifest_inventory_slots,
            loader_plan_proof: None,
        })
    }

    /// Prove only the admitted loader's pin ownership may change. Existing
    /// proof/table history is permitted; inputs requiring fresh admission or
    /// retirement stay on the original planner path.
    fn loader_inputs_are_stationary(
        &self,
        view: ProcessViewId,
        loader_module: &ScannedModule,
        pinned: &PinnedObjects,
        loader: PinnedObjectId,
    ) -> bool {
        self.capture_facts.staged.is_none()
            && self.facts_revision == self.published_facts_revision
            && self.inventory.is_none()
            && self.manifests.is_empty()
            && self.manifest_ordinals.is_empty()
            && self.manifest_inputs.is_empty()
            && self.counters.manifest_fallbacks.is_empty()
            && self.selection_claims.is_empty()
            && self.pending_retirements.is_empty()
            && self.retirement_intents.is_empty()
            && self.pending_rejected_keys.is_empty()
            && self.pending_leader_exit_views.is_empty()
            && self.ready_expected_removals.is_empty()
            && self.expected_target_exit_pending.is_none()
            && self.plan.active_slot_count() == self.plan.slots.len()
            && loader_module.view == view
            && loader_module.tables.is_empty()
            && loader_module.interfaces.is_empty()
            && self.modules.iter().all(|module| {
                module.object != loader
                    && !module
                        .entry_objects
                        .iter()
                        .flatten()
                        .any(|id| *id == loader)
            })
            && pinned
                .view_claims(view)
                .is_some_and(|claims| claims.pins.contains(&loader))
            && self
                .pinned
                .preserves_provider_inputs_for_loader(pinned, loader)
    }

    fn loader_candidate(
        &mut self,
        view: ProcessViewId,
        loader_module: &ScannedModule,
        loader_pins: &PinnedObjects,
        local_loader: PinnedObjectId,
        mut skipped: Vec<Skipped>,
    ) -> Result<(LiveCandidate, Option<PinnedObjectId>)> {
        let mut candidate_pins = self.pinned.clone();
        skipped.extend(candidate_pins.absorb(loader_pins.clone()));
        let had_exact_loader = candidate_pins
            .id_for_scanned(loader_module, loader_module.key, &loader_module.path)
            .is_some_and(|candidate_loader| {
                loader_pins.exactly_matches(local_loader, &candidate_pins, candidate_loader)
            });
        // Probe on a disposable clone: fallback retains the original exact
        // loader restoration and global canonicalization path unchanged.
        let stationary = if skipped.is_empty() && had_exact_loader {
            let mut probe = candidate_pins.clone();
            let (folds, lost) = canonicalize_scanned_overlays(&mut probe);
            probe
                .id_for_scanned(loader_module, loader_module.key, &loader_module.path)
                .is_some_and(|loader| {
                    folds == 0
                        && lost.is_empty()
                        && self.loader_inputs_are_stationary(view, loader_module, &probe, loader)
                })
        } else {
            false
        };
        let proof = stationary.then(|| LoaderPlanProof {
            revision: self.facts_revision,
            published_plan: self.plan.clone(),
            discovery: self.discovery.clone(),
        });
        let cached_plan = stationary
            .then_some(self.loader_plan_cache.as_ref())
            .flatten()
            .filter(|cache| {
                cache.revision == self.published_facts_revision
                    && cache.broad_admit == self.broad_admit
            })
            .map(|cache| cache.plan.clone());
        let mut candidate = if let Some(plan) = cached_plan {
            LiveCandidate {
                pinned: candidate_pins,
                modules: self.modules.clone(),
                plan,
                delta: plan::AttachDelta {
                    new: Vec::new(),
                    replace: Vec::new(),
                    retire: Vec::new(),
                },
                views: self
                    .modules
                    .iter()
                    .map(|module| module.scanned.view)
                    .collect(),
                corroboration: self.counters.corroboration.clone(),
                manifest_fallbacks: Vec::new(),
                selection_claims: BTreeMap::new(),
                selection_tables: self.selection_tables.clone(),
                selection_admission: None,
                manifest_selection_admissions: Vec::new(),
                // No manifest/selection admission can use rollback inventory.
                manifest_inventory_slots: BTreeMap::new(),
                loader_plan_proof: None,
            }
        } else {
            self.loader_plan_cache = None;
            let raw_modules = self
                .modules
                .iter()
                .map(|module| module.scanned.clone())
                .collect();
            self.live_candidate(candidate_pins, raw_modules, skipped)?
        };
        if candidate.delta.new.is_empty()
            && candidate.delta.replace.is_empty()
            && candidate.delta.retire.is_empty()
            && candidate.modules == self.modules
            && candidate.corroboration == self.counters.corroboration
            && candidate.manifest_fallbacks == self.counters.manifest_fallbacks
            && candidate.selection_claims == self.selection_claims
            && candidate.selection_tables == self.selection_tables
        {
            candidate.loader_plan_proof = proof;
        }
        candidate.views.insert(view);
        let loader = candidate
            .pinned
            .id_for_scanned(loader_module, loader_module.key, &loader_module.path)
            .filter(|candidate_loader| {
                loader_pins.exactly_matches(local_loader, &candidate.pinned, *candidate_loader)
            });
        let loader = if loader.is_none() && had_exact_loader {
            let restored_skips = candidate.pinned.absorb(loader_pins.clone());
            if !restored_skips.is_empty() {
                bail!("loader identity restoration produced an unexpected skip");
            }
            if candidate.pinned.rejects(loader_module.key) {
                bail!("loader identity restoration rejected its object key");
            }
            let restored = candidate
                .pinned
                .id_for_scanned(loader_module, loader_module.key, &loader_module.path)
                .filter(|candidate_loader| {
                    loader_pins.exactly_matches(local_loader, &candidate.pinned, *candidate_loader)
                });
            let Some(restored) = restored else {
                bail!("loader identity restoration could not resolve an exact pin");
            };
            if !candidate_identity_is_complete(
                &candidate.plan,
                &candidate.modules,
                &candidate.pinned,
            ) {
                bail!("loader identity restoration left an incomplete candidate");
            }
            Some(restored)
        } else {
            loader
        };
        Ok((candidate, loader))
    }

    fn conservative_candidate(
        &mut self,
        retirements: &BTreeSet<ProcessViewId>,
        keys: &BTreeSet<ObjectKey>,
    ) -> Result<LiveCandidate> {
        let assemble_start = crate::attach::monotonic_ns();
        let mut pinned = self.pinned.clone();
        for view in retirements {
            pinned.remove_view(*view);
        }
        let skipped = pinned.reapply_rejected_keys(keys);
        let raw_modules = self
            .modules
            .iter()
            .filter(|module| !retirements.contains(&module.scanned.view))
            .map(|module| module.scanned.clone())
            .collect();
        self.stage_timings.span(
            crate::timing::StageKind::Merge,
            "conservative_assemble",
            assemble_start,
            crate::attach::monotonic_ns(),
        );
        self.live_candidate(pinned, raw_modules, skipped)
    }

    fn apply_candidate(
        &mut self,
        session: &mut dyn EngineSession,
        mut candidate: LiveCandidate,
        additions_allowed: &mut bool,
        preflighted: bool,
        extra_views: &[&ProcessView],
    ) -> Result<ApplyOutcome> {
        let mut outcome = ApplyOutcome::default();
        let targets: Vec<_> = candidate
            .delta
            .new
            .iter()
            .chain(&candidate.delta.replace)
            .cloned()
            .collect();
        let timing_owners = candidate_timing_owners(&candidate);
        let target_modules = delta_timing_keys(&candidate.delta, &timing_owners);
        let preflight_start = crate::attach::monotonic_ns();
        let targets_ok = preflighted
            || session
                .preflight_targets(&targets, &candidate.pinned)
                .is_ok();
        // A preflighted candidate paid nothing here: the span still records
        // (usually zero) so invocations count applications, not syscalls.
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "apply_preflight",
            preflight_start,
            crate::attach::monotonic_ns(),
        );
        let admission = candidate_admission(
            &self.views,
            extra_views,
            &candidate.views,
            &self.loader_registry,
            &candidate.pinned,
            &self.pinned,
            targets_ok,
        );
        outcome.changed |= self.latch_candidate_ambiguity(&candidate.plan);
        let generation_stale = !admission.stale_views.is_empty();
        outcome.stale_views = admission.stale_views;
        outcome.missing_contexts = admission.missing_contexts;
        outcome.newly_rejected_keys = admission.newly_rejected_keys;
        if !outcome.missing_contexts.is_empty() {
            outcome.static_failures = target_modules;
            *additions_allowed = false;
            self.mark_partial(
                "live discovery identity",
                "candidate identity conflicted with an active loader context; the context was selected for conservative retirement before rebuild",
            );
            return Ok(outcome);
        }
        if generation_stale {
            outcome.static_failures = target_modules;
            *additions_allowed = false;
            self.mark_partial(
                "live discovery generation",
                "candidate generation changed before mutation; canonical identity, plan, and links were unchanged",
            );
            return Ok(outcome);
        }
        if !admission.targets_ok {
            outcome.static_failures = target_modules;
            self.mark_partial(
                "live discovery transaction",
                "candidate preflight failed; canonical identity, plan, and links were unchanged",
            );
            return Ok(outcome);
        }
        // The last fallible preparation this candidate needs. Past the first
        // link mutation below there is no rollback and no early return, so
        // identity, planner, and history work all has to be proven here.
        self.preflight_candidate_publication(&candidate)?;

        let selected: Vec<_> = candidate
            .delta
            .retire
            .iter()
            .chain(&candidate.delta.replace)
            .cloned()
            .collect();
        let detach_slots_start = crate::attach::monotonic_ns();
        let detach_slots_outcome = session.detach_slots(&selected);
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "detach_slots",
            detach_slots_start,
            crate::attach::monotonic_ns(),
        );
        let detach_failed = match detach_slots_outcome {
            Ok(report) => {
                self.apply_group_rebuild(&mut candidate.plan, &timing_owners, report, &mut outcome);
                false
            }
            Err(_) => true,
        };
        if detach_failed {
            *additions_allowed = false;
            outcome.detach_failed = true;
            outcome
                .static_failures
                .extend(target_modules.iter().cloned());
        }
        let may_add = *additions_allowed;
        // Whether the attach mutation for `delta.new` ran. A precheck that
        // finds a candidate generation already gone skips it (U-07).
        let mut new_targets_attached = may_add;
        if !may_add {
            block_unperformed_static(
                &mut candidate.plan,
                &candidate.delta,
                &timing_owners,
                &mut outcome,
            );
            if detach_failed {
                self.mark_partial(
                    "live discovery detach",
                    "a one-shot detach failed; additions and replacements were blocked for this cycle",
                );
            }
        } else {
            let candidate_views = candidate.views.clone();
            let mut generation_lost = false;
            let attach_targets_start = crate::attach::monotonic_ns();
            let attach = generation_checked_mutation(
                || process_views_are_current(&self.views, extra_views, &candidate_views),
                || session.attach_targets(&candidate.delta.new, &candidate.pinned),
            );
            self.stage_timings.span(
                crate::timing::StageKind::Attach,
                "attach_targets",
                attach_targets_start,
                crate::attach::monotonic_ns(),
            );
            let (attach, attach_stale) = match attach {
                GenerationMutation::PrecheckFailed => (None, true),
                GenerationMutation::Committed(result) => (Some(result), false),
                GenerationMutation::PostcheckFailed(result) => (Some(result), true),
            };
            generation_lost |= attach_stale;
            new_targets_attached = attach.is_some();
            if let Some(attach) = attach {
                match attach {
                    Ok((failed, completed)) => {
                        outcome.record_completions(&candidate.delta.new, &timing_owners, completed);
                        let failed_slots: Vec<_> = candidate
                            .delta
                            .new
                            .iter()
                            .filter(|slot| failed.contains(&slot.index))
                            .cloned()
                            .collect();
                        let detach_failed_slots_start = crate::attach::monotonic_ns();
                        let detach_failed_slots_outcome = session.detach_slots(&failed_slots);
                        self.stage_timings.span(
                            crate::timing::StageKind::Attach,
                            "detach_failed_slots",
                            detach_failed_slots_start,
                            crate::attach::monotonic_ns(),
                        );
                        match detach_failed_slots_outcome {
                            Ok(report) => self.apply_group_rebuild(
                                &mut candidate.plan,
                                &timing_owners,
                                report,
                                &mut outcome,
                            ),
                            Err(_) => {
                                *additions_allowed = false;
                                self.mark_partial(
                                    "live discovery detach",
                                    "a partial new-slot detach failed once and was not retried",
                                );
                            }
                        }
                        for slot in failed_slots {
                            outcome
                                .static_failures
                                .extend(slot_timing_keys(&slot, &timing_owners));
                            candidate.plan.deactivate(slot.index);
                        }
                    }
                    Err(_) => {
                        for slot in &candidate.delta.new {
                            outcome
                                .static_failures
                                .extend(slot_timing_keys(slot, &timing_owners));
                            candidate.plan.deactivate(slot.index);
                        }
                        self.mark_partial(
                            "live discovery attach",
                            "one or more new exact targets could not be attached",
                        );
                    }
                }
            }
            if *additions_allowed && !generation_lost {
                let detach_failures = session.detach_failures().len();
                let replace_targets_start = crate::attach::monotonic_ns();
                let replacement = generation_checked_mutation(
                    || process_views_are_current(&self.views, extra_views, &candidate_views),
                    || {
                        session.replace_targets(
                            &mut candidate.plan,
                            &candidate.delta.replace,
                            &candidate.pinned,
                        )
                    },
                );
                self.stage_timings.span(
                    crate::timing::StageKind::Attach,
                    "replace_targets",
                    replace_targets_start,
                    crate::attach::monotonic_ns(),
                );
                let (replacement, replacement_stale) = match replacement {
                    GenerationMutation::PrecheckFailed => (None, true),
                    GenerationMutation::Committed(result) => (Some(result), false),
                    GenerationMutation::PostcheckFailed(result) => (Some(result), true),
                };
                generation_lost |= replacement_stale;
                match replacement {
                    Some(Ok(replacement)) => {
                        let ReplacementOutcome {
                            completed,
                            failed_detach,
                            rebuild,
                        } = replacement;
                        outcome.record_completions(
                            &candidate.delta.replace,
                            &timing_owners,
                            completed,
                        );
                        self.apply_group_rebuild(
                            &mut candidate.plan,
                            &timing_owners,
                            rebuild,
                            &mut outcome,
                        );
                        if failed_detach {
                            *additions_allowed = false;
                            self.mark_partial(
                                "live discovery replacement",
                                "a partial replacement detach failed once and additions were blocked",
                            );
                        }
                        for slot in &candidate.delta.replace {
                            if !candidate.plan.is_active(slot.index) {
                                outcome
                                    .static_failures
                                    .extend(slot_timing_keys(slot, &timing_owners));
                            }
                        }
                    }
                    Some(Err(_)) => {
                        outcome.static_failures.extend(
                            candidate
                                .delta
                                .replace
                                .iter()
                                .flat_map(|slot| slot_timing_keys(slot, &timing_owners)),
                        );
                        if session.detach_failures().len() > detach_failures {
                            *additions_allowed = false;
                        }
                        self.mark_partial(
                            "live discovery replacement",
                            "one or more downgraded exact targets could not be replaced",
                        );
                    }
                    None => {
                        // The replacement precheck found a candidate generation
                        // gone. The old links went with `selected` above and
                        // nothing replaced them, so the targets must not stay
                        // active without a link (U-07). They are cells already
                        // accepted, so no ownership needs relabelling.
                        for slot in &candidate.delta.replace {
                            outcome
                                .static_failures
                                .extend(slot_timing_keys(slot, &timing_owners));
                            candidate.plan.deactivate(slot.index);
                        }
                        if !candidate.delta.replace.is_empty() {
                            self.mark_partial(
                                "live discovery replacement",
                                "a process generation changed before downgraded exact targets were replaced; they were deactivated",
                            );
                        }
                        // The deactivated slots' surviving owners are refreshed
                        // later (A1), through the helper shared with the
                        // `else` branch below.
                        self.request_replaced_owner_refresh(&candidate);
                    }
                }
            } else {
                for slot in &candidate.delta.replace {
                    outcome
                        .static_failures
                        .extend(slot_timing_keys(slot, &timing_owners));
                    candidate.plan.deactivate(slot.index);
                }
                if !candidate.delta.replace.is_empty() {
                    self.mark_partial(
                        "live discovery replacement",
                        "additions had already closed or a generation was lost before downgraded exact targets were replaced; they were deactivated",
                    );
                }
                // Same stranded-owner shape as the precheck `None` arm
                // above (#1): additions already closed, or the attach phase
                // lost a generation before the replacement precheck ran. A
                // retained owner that is neither stale nor newcomer would
                // otherwise never be rescanned.
                self.request_replaced_owner_refresh(&candidate);
            }
            if generation_lost {
                *additions_allowed = false;
            }
        }
        if new_targets_attached && !self.pause_owned_batch && !candidate.delta.new.is_empty() {
            // Provider slots attached while the child ran: whatever it
            // called before this attach went unobserved.
            let objects: BTreeSet<_> = candidate
                .delta
                .new
                .iter()
                .flat_map(|slot| slot.module_ids.iter())
                .filter_map(|id| {
                    candidate
                        .plan
                        .modules
                        .iter()
                        .find(|module| module.id == *id)
                        .map(|module| module.object)
                })
                .collect();
            let views: Vec<_> = candidate
                .modules
                .iter()
                .filter(|module| objects.contains(&module.object))
                .map(|module| module.scanned.view)
                .collect();
            self.unpaused_loader_views.extend(views);
        }
        self.finalize_candidate(
            session,
            candidate,
            extra_views,
            target_modules,
            new_targets_attached,
            additions_allowed,
            &mut outcome,
        );
        Ok(outcome)
    }

    /// Requests a refresh for the retained, still-current owners of a
    /// skipped replacement's deactivated slots. A replacement skipped
    /// before its links attach — the precheck's `None` arm (A1) or the
    /// `else` branch when additions already closed or the attach phase
    /// lost a generation (#1) — leaves the surviving owner's endpoints
    /// deactivated with their old links detached; a retained owner that
    /// is neither stale nor newcomer would otherwise never be rescanned.
    /// The next tick rebuilds and re-attaches them through the normal
    /// path — still no active-without-link window — and consumes the
    /// request, so one event re-requests exactly once.
    fn request_replaced_owner_refresh(&mut self, candidate: &LiveCandidate) {
        let mut owners = BTreeSet::new();
        for slot in &candidate.delta.replace {
            for module in &slot.module_ids {
                let object = candidate
                    .plan
                    .modules
                    .iter()
                    .find(|summary| summary.id == *module)
                    .map(|summary| summary.object);
                let Some(object) = object else {
                    continue;
                };
                owners.extend(
                    candidate
                        .modules
                        .iter()
                        .filter(|reconciled| reconciled.object == object)
                        .map(|reconciled| reconciled.scanned.view),
                );
            }
        }
        let pids: Vec<_> = owners
            .iter()
            .filter_map(|view| {
                self.views
                    .iter()
                    .find(|retained| retained.id() == *view && retained.still_the_same())
                    .map(ProcessView::pid)
            })
            .collect();
        for pid in pids {
            self.request_refresh(pid, crate::attach::monotonic_ns());
        }
    }

    /// The view's accepted static targets that survived the rescan unchanged:
    /// active, attributable to the view's reconciled modules, and absent
    /// from every delta list. Anything the ordinary delta already churns is
    /// excluded, so forcing never double-covers a target.
    fn unchanged_exec_targets(view: ProcessViewId, candidate: &LiveCandidate) -> Vec<plan::Slot> {
        let owned: BTreeSet<PinnedObjectId> = candidate
            .modules
            .iter()
            .filter(|module| module.scanned.view == view)
            .map(|module| module.object)
            .collect();
        let covered: BTreeSet<u32> = candidate
            .delta
            .new
            .iter()
            .chain(&candidate.delta.replace)
            .chain(&candidate.delta.retire)
            .map(|slot| slot.index)
            .collect();
        candidate
            .plan
            .slots
            .iter()
            .filter(|slot| {
                candidate.plan.is_active(slot.index)
                    && !covered.contains(&slot.index)
                    && slot.module_ids.iter().any(|id| {
                        candidate
                            .plan
                            .modules
                            .iter()
                            .any(|module| module.id == *id && owned.contains(&module.object))
                    })
            })
            .cloned()
            .collect()
    }

    /// Mints one exec rearm for an exec-refreshed view: the refresh request
    /// still names this exact matched owner at the tick's checked serial,
    /// original custody is live, and the rescan re-accepted the same static
    /// targets. Anything else mints nothing: a renewed serial, a lost
    /// generation, or a changed plan stays owned by the ordinary delta or a
    /// later attempt.
    fn prepare_exec_rearm(
        &self,
        view: ProcessViewId,
        serial: u64,
        candidate: &LiveCandidate,
    ) -> Option<PreparedExecRearm> {
        let retained = self.views.iter().find(|old| old.id() == view)?;
        if !retained.still_the_same() {
            return None;
        }
        let request = self.refresh_requested.get(&retained.pid())?;
        if request.owner != Some(view) || request.serial != serial {
            return None;
        }
        let slots = Self::unchanged_exec_targets(view, candidate);
        if slots.is_empty() {
            return None;
        }
        Some(PreparedExecRearm {
            view,
            serial,
            slots,
        })
    }

    /// Lowers one minted rearm into the existing replacement transaction: the
    /// unchanged accepted targets detach and reattach at their same
    /// object/offset/slot through `detach_slots`/`replace_targets`. The
    /// request binding is rechecked first: a renewal since minting owns the
    /// retry, and this attempt retires without touching the delta.
    fn consume_exec_rearm(
        &self,
        candidate: &mut LiveCandidate,
        prepared: PreparedExecRearm,
    ) -> bool {
        let current = self
            .views
            .iter()
            .find(|view| view.id() == prepared.view)
            .and_then(|view| self.refresh_requested.get(&view.pid()));
        let renewed = current.is_none_or(|request| {
            request.owner != Some(prepared.view) || request.serial != prepared.serial
        });
        if renewed {
            return false;
        }
        candidate.delta.replace.extend(prepared.slots);
        true
    }

    /// Forces exec-refreshed views whose rescan re-accepted the same static
    /// targets through the existing detach/replace transaction. Only views
    /// carrying a matched-EXEC marker, a matched owner at the tick's checked
    /// serial, and live original custody mint a rearm, and only their own
    /// unchanged active targets are lowered — unrelated views' links are
    /// never touched. A completed rearm, or an ordinary delta that already
    /// churned every attributable target, clears the marker; anything else
    /// keeps it for the retry the renewal owns.
    fn lower_exec_rearms(
        &mut self,
        candidate: &mut LiveCandidate,
        refreshed: &BTreeSet<ProcessViewId>,
        serviced: &BTreeMap<u32, u64>,
    ) {
        let marked: Vec<ProcessViewId> = refreshed
            .iter()
            .copied()
            .filter(|view| self.exec_rearm_views.contains(view))
            .collect();
        for view in marked {
            let serial = self
                .views
                .iter()
                .find(|old| old.id() == view)
                .map(ProcessView::pid)
                .and_then(|pid| serviced.get(&pid).copied());
            let Some(serial) = serial else {
                continue;
            };
            if let Some(prepared) = self.prepare_exec_rearm(view, serial, candidate)
                && self.consume_exec_rearm(candidate, prepared)
            {
                self.exec_rearm_views.remove(&view);
                continue;
            }
            if Self::exec_rearm_moot(view, candidate) {
                self.exec_rearm_views.remove(&view);
            }
        }
    }

    /// Whether an exec marker's work is already done: none of the view's
    /// attributable targets is both active and absent from the delta, so the
    /// ordinary transaction retired, replaced, or never owned every one.
    fn exec_rearm_moot(view: ProcessViewId, candidate: &LiveCandidate) -> bool {
        Self::unchanged_exec_targets(view, candidate).is_empty()
    }

    /// Everything a candidate can fail at, proven before its first link
    /// mutation. Post-mutation cleanup only ever drops sources, so a candidate
    /// that passes here still publishes after a conservative retirement.
    fn preflight_candidate_publication(&self, candidate: &LiveCandidate) -> Result<()> {
        if !candidate_identity_is_complete(&candidate.plan, &candidate.modules, &candidate.pinned) {
            bail!("live candidate lost exact pinned identity before link mutation");
        }
        // A dedicated preflight walk over the merge's fallible surface
        // (E25): proves exactly what `merge_current` would fail on without
        // cloning or walking the history. `merge_current` re-runs the same
        // checks first and keeps its own, so proof and merge agree.
        self.capture_facts.resolve_merge_inputs(
            &candidate.plan,
            &candidate.pinned,
            &candidate.modules,
            &self.manifests,
            &self.manifest_ordinals,
        )
    }

    /// The one complete finalization for a candidate whose links were already
    /// mutated. It never short-circuits and never returns: a lost generation
    /// downgrades the disposition and cleans up, it does not unwind.
    ///
    /// An inventory newcomer (`extra_views`) is published whole or not at all
    /// (U-07). Its links attach only in this apply and only when the attach
    /// mutation ran (`new_targets_attached`), and only an Accepted candidate
    /// retains its view. A candidate that lost a generation, or never ran
    /// that mutation, would otherwise publish the newcomer without links or
    /// commit pins and modules naming a view that nothing retains. Instead
    /// it commits none of the newcomer's sources, detaches any link it
    /// attached, and reports it in `unpublished_views` so the caller
    /// requests it again.
    ///
    /// Any other new target the mutation never attached is left inactive,
    /// never published as a live link: an active slot is keyed, so no later
    /// candidate would re-add it. That runs after the lost and unpublished
    /// sources are dropped, so a cell this candidate allocated for them keeps
    /// no owner, and before the selection checks, so no table counts it as
    /// attached.
    #[allow(clippy::too_many_arguments)]
    fn finalize_candidate(
        &mut self,
        session: &mut dyn EngineSession,
        mut candidate: LiveCandidate,
        extra_views: &[&ProcessView],
        target_modules: BTreeSet<PinnedTimingKey>,
        new_targets_attached: bool,
        additions_allowed: &mut bool,
        outcome: &mut ApplyOutcome,
    ) {
        let loader_plan = candidate
            .loader_plan_proof
            .take()
            .map(|proof| (proof, candidate.plan.clone()));
        let selection_pending = candidate.selection_admission.take();
        outcome.stale_views = stale_process_views(&self.views, extra_views, &candidate.views);
        let retired = !outcome.stale_views.is_empty();
        if retired || !new_targets_attached {
            outcome.unpublished_views = extra_views
                .iter()
                .map(|view| view.id())
                .filter(|view| !outcome.stale_views.contains(view))
                .collect();
        }
        if retired {
            *additions_allowed = false;
            outcome.static_failures.extend(target_modules);
            let dropped: BTreeSet<_> = outcome
                .stale_views
                .union(&outcome.unpublished_views)
                .copied()
                .collect();
            self.retire_stale_candidate_sources(session, &mut candidate, &dropped, &mut *outcome);
            self.mark_partial(
                "live discovery generation",
                "a process generation changed after link mutation; its targets were retired before context cleanup",
            );
        } else if !outcome.unpublished_views.is_empty() {
            let unpublished = outcome.unpublished_views.clone();
            self.retire_stale_candidate_sources(
                session,
                &mut candidate,
                &unpublished,
                &mut *outcome,
            );
            self.mark_partial(
                "live inventory transaction",
                "additions were blocked; newly observed process generations were left unpublished for a later tick",
            );
        }
        if !new_targets_attached {
            let owners = candidate_timing_owners(&candidate);
            let unattached: Vec<_> = candidate
                .delta
                .new
                .iter()
                .filter(|slot| candidate.plan.is_active(slot.index))
                .cloned()
                .collect();
            for slot in &unattached {
                outcome
                    .static_failures
                    .extend(slot_timing_keys(slot, &owners));
                candidate.plan.deactivate(slot.index);
            }
            if !unattached.is_empty() {
                self.mark_partial(
                    "live discovery attach",
                    "a process generation changed before new exact targets were attached; they were deactivated for a later attempt",
                );
            }
        }
        if let Some(pending) = selection_pending {
            let target_keys: BTreeSet<_> = pending
                .table
                .targets
                .iter()
                .map(|target| plan::AttachKey {
                    object: target.object,
                    file_offset: target.file_offset,
                })
                .collect();
            let table_survives =
                candidate
                    .selection_tables
                    .get(&pending.key)
                    .is_some_and(|table| {
                        table.object == pending.table.object
                            && table.file_offset == pending.table.file_offset
                            && same_selection_target_set(&table.targets, &pending.table.targets)
                    });
            let targets_survive = pending.table.targets.iter().all(|target| {
                let key = plan::AttachKey {
                    object: target.object,
                    file_offset: target.file_offset,
                };
                candidate
                    .plan
                    .slots
                    .iter()
                    .find(|slot| slot.object == key.object && slot.file_offset == key.file_offset)
                    .is_some_and(|slot| candidate.plan.is_active(slot.index))
            });
            if table_survives && targets_survive {
                outcome.selection_authorized = true;
            } else {
                let inventory_keys: BTreeSet<_> = self
                    .plan
                    .slots
                    .iter()
                    .filter(|slot| self.plan.is_active(slot.index))
                    .map(|slot| plan::AttachKey {
                        object: slot.object,
                        file_offset: slot.file_offset,
                    })
                    .collect();
                for slot in &mut candidate.plan.slots {
                    let key = plan::AttachKey {
                        object: slot.object,
                        file_offset: slot.file_offset,
                    };
                    if target_keys.contains(&key)
                        && inventory_keys.contains(&key)
                        && let Some(previous) = self.plan.slots.iter().find(|previous| {
                            previous.object == key.object && previous.file_offset == key.file_offset
                        })
                    {
                        *slot = previous.clone();
                    }
                }
                let detach: Vec<_> = candidate
                    .delta
                    .new
                    .iter()
                    .filter(|slot| {
                        let key = plan::AttachKey {
                            object: slot.object,
                            file_offset: slot.file_offset,
                        };
                        target_keys.contains(&key)
                            && !inventory_keys.contains(&key)
                            && candidate.plan.is_active(slot.index)
                    })
                    .cloned()
                    .collect();
                let detach_selection_start = crate::attach::monotonic_ns();
                let detach_selection_outcome = session.detach_slots(&detach);
                self.stage_timings.span(
                    crate::timing::StageKind::Attach,
                    "detach_selection",
                    detach_selection_start,
                    crate::attach::monotonic_ns(),
                );
                match detach_selection_outcome {
                    Ok(report) => {
                        let owners = candidate_timing_owners(&candidate);
                        self.apply_group_rebuild(
                            &mut candidate.plan,
                            &owners,
                            report,
                            &mut *outcome,
                        );
                    }
                    Err(_) => {
                        self.mark_partial(
                            "live interface selection",
                            "a refused selection table could not detach one-shot additions",
                        );
                    }
                }
                for slot in detach {
                    candidate.plan.deactivate(slot.index);
                }
                candidate.selection_claims.retain(|claim, value| {
                    selection_table_key(claim) != pending.key
                        || pending.previous_claims.get(claim) == Some(value)
                });
                if candidate.selection_tables.contains_key(&pending.key) {
                    if let Some(previous) = pending.previous_tables.get(&pending.key) {
                        candidate
                            .selection_tables
                            .insert(pending.key.clone(), previous.clone());
                    } else {
                        candidate.selection_tables.remove(&pending.key);
                    }
                }
                self.refuse_selection_authority_for(
                    &pending.key,
                    "a selection table did not survive exact admission and attachment",
                );
            }
        }
        let failed_manifest_tables: Vec<_> = candidate
            .manifest_selection_admissions
            .iter()
            .filter(|table| {
                table.targets.iter().any(|target| {
                    candidate
                        .plan
                        .slots
                        .iter()
                        .find(|slot| {
                            slot.object == target.object && slot.file_offset == target.file_offset
                        })
                        .is_none_or(|slot| !candidate.plan.is_active(slot.index))
                })
            })
            .cloned()
            .collect();
        if !failed_manifest_tables.is_empty() {
            let failed_sources: BTreeSet<_> = failed_manifest_tables
                .iter()
                .map(|table| table.source)
                .collect();
            let live_tables = selection_tables_from_claims(&candidate.selection_claims);
            let mut surviving_names = BTreeMap::<plan::AttachKey, BTreeSet<&'static str>>::new();
            for target in candidate
                .manifest_selection_admissions
                .iter()
                .filter(|table| !failed_sources.contains(&table.source))
                .flat_map(|table| &table.targets)
                .chain(live_tables.values().flat_map(|table| &table.targets))
            {
                surviving_names
                    .entry(plan::AttachKey {
                        object: target.object,
                        file_offset: target.file_offset,
                    })
                    .or_default()
                    .insert(target.name);
            }
            let affected_keys: BTreeSet<_> = failed_manifest_tables
                .iter()
                .flat_map(|table| &table.targets)
                .map(|target| plan::AttachKey {
                    object: target.object,
                    file_offset: target.file_offset,
                })
                .collect();
            let mut rollback_keys = BTreeSet::new();
            for key in affected_keys {
                let names = surviving_names.get(&key);
                let inventory = candidate.manifest_inventory_slots.get(&key);
                if inventory.is_none() && names.is_none_or(BTreeSet::is_empty) {
                    rollback_keys.insert(key);
                    continue;
                }
                let Some(slot) =
                    candidate.plan.slots.iter_mut().find(|slot| {
                        slot.object == key.object && slot.file_offset == key.file_offset
                    })
                else {
                    continue;
                };
                if let Some(inventory) = inventory {
                    slot.names.clone_from(&inventory.names);
                    slot.aliased = inventory.aliased;
                } else {
                    slot.names.clear();
                    slot.aliased = false;
                }
                if let Some(names) = names {
                    slot.names.extend(names.iter().copied().map(str::to_string));
                    slot.names.sort();
                    slot.names.dedup();
                    slot.aliased = slot.names.len() >= 2;
                }
            }
            let rollback: Vec<_> = candidate
                .plan
                .slots
                .iter()
                .filter(|slot| {
                    rollback_keys.contains(&plan::AttachKey {
                        object: slot.object,
                        file_offset: slot.file_offset,
                    }) && candidate.plan.is_active(slot.index)
                })
                .cloned()
                .collect();
            let detach_rollback_start = crate::attach::monotonic_ns();
            let detach_rollback_outcome = session.detach_slots(&rollback);
            self.stage_timings.span(
                crate::timing::StageKind::Attach,
                "detach_rollback",
                detach_rollback_start,
                crate::attach::monotonic_ns(),
            );
            match detach_rollback_outcome {
                Ok(report) => {
                    let owners = candidate_timing_owners(&candidate);
                    self.apply_group_rebuild(&mut candidate.plan, &owners, report, &mut *outcome);
                }
                Err(_) => {
                    self.mark_partial(
                        "offline interface selection",
                        "a failed manifest selection table could not detach its successful prefix",
                    );
                }
            }
            for slot in rollback {
                candidate.plan.deactivate(slot.index);
            }
            self.mark_partial(
                "offline interface selection",
                "a manifest selection table failed indivisible attachment and was rolled back",
            );
        }
        // PC-1: a candidate whose additions never ran — a closed tick, a
        // conservative replay, a generation lost before the attach — gives
        // back the cells it allocated for them. No link ever pointed at them,
        // so no count can be in them. Kept, they burned the capture-lifetime
        // budget: every conservative replay after an ordinary process exit
        // allocated one more cell per listed-but-inactive endpoint.
        if !new_targets_attached {
            candidate
                .plan
                .withdraw_unlinked_additions(self.plan.slots.len());
        }
        record_object_skips(&mut candidate.plan, &self.counters.object_skips);
        outcome.changed |= candidate.plan != self.plan;
        self.pinned = candidate.pinned;
        self.modules = candidate.modules;
        self.plan = candidate.plan;
        // The commit replaces the whole publication input set (plan, pins,
        // modules, and below corroboration and fallbacks) even when the plan
        // compares equal, so it dirties the inputs unconditionally.
        self.note_facts_mutated();
        for binding in self.selection_bindings.values_mut() {
            if let Some(module) = self
                .plan
                .modules
                .iter()
                .find(|module| module.object == binding.object)
            {
                binding.provider = module.id;
            }
        }
        self.counters.corroboration = candidate.corroboration;
        self.counters.manifest_fallbacks = candidate.manifest_fallbacks;
        self.selection_claims = candidate.selection_claims;
        self.selection_tables = candidate.selection_tables;
        outcome.disposition = if retired {
            ApplyDisposition::ConservativeRetirement
        } else {
            ApplyDisposition::Accepted
        };
        if self.publish_current_capture_facts().is_err() {
            // The preflight proved this for the whole candidate, so only the
            // cleaned subset can still refuse. Keep the committed state and
            // drop to conservative authority rather than unwinding.
            outcome.disposition = ApplyDisposition::ConservativeRetirement;
            self.mark_partial(
                "live discovery evidence",
                "the retired candidate's provider history could not be published",
            );
        }
        if let Some((proof, plan)) = loader_plan
            && outcome.disposition == ApplyDisposition::Accepted
            && new_targets_attached
            && extra_views.is_empty()
            && self.capture_facts.staged.is_none()
            && self.facts_revision == self.published_facts_revision
            && self.facts_revision == proof.revision.saturating_add(1)
            && self.plan == proof.published_plan
            && self.discovery == proof.discovery
        {
            // Publication invalidates first. Only this proved unchanged
            // accepted transaction can carry the exact raw plan forward.
            self.loader_plan_cache = Some(LoaderPlanCache {
                revision: self.published_facts_revision,
                broad_admit: self.broad_admit,
                plan,
            });
        }
        outcome.selection_authorized &= outcome.disposition == ApplyDisposition::Accepted;
    }

    /// Drops the pins, modules, proofs, and live endpoints that a lost process
    /// generation, or a newcomer left unpublished, owned. Infallible on
    /// purpose: it runs after link mutation.
    fn retire_stale_candidate_sources(
        &mut self,
        session: &mut dyn EngineSession,
        candidate: &mut LiveCandidate,
        stale_views: &BTreeSet<ProcessViewId>,
        outcome: &mut ApplyOutcome,
    ) {
        // A binding belongs to one process view even when its physical target is
        // shared with another view. Retire the binding itself before dropping
        // this view's claims so delayed records cannot reuse its capture-local
        // ID while the surviving owner keeps the shared slot attached.
        for binding in self.selection_bindings.values_mut() {
            if stale_views.contains(&binding.view) {
                binding.retired = true;
                binding.coverage.retire();
            }
        }
        let mut cleaned_pins = candidate.pinned.clone();
        for view in stale_views {
            cleaned_pins.remove_view(*view);
        }
        let cleaned_modules: Vec<_> = candidate
            .modules
            .iter()
            .filter(|module| !stale_views.contains(&module.scanned.view))
            .cloned()
            .collect();
        let prior_selection_keys: BTreeSet<_> =
            selection_tables_from_claims(&candidate.selection_claims)
                .values()
                .flat_map(|table| table.targets.iter())
                .map(|target| plan::AttachKey {
                    object: target.object,
                    file_offset: target.file_offset,
                })
                .collect();
        candidate
            .selection_claims
            .retain(|claim, _| !stale_views.contains(&claim.view));
        candidate
            .selection_tables
            .retain(|table, _| !stale_views.contains(&table.view));
        let surviving_selection_keys: BTreeSet<_> =
            selection_tables_from_claims(&candidate.selection_claims)
                .values()
                .flat_map(|table| table.targets.iter())
                .map(|target| plan::AttachKey {
                    object: target.object,
                    file_offset: target.file_offset,
                })
                .collect();
        let broad_admit = self.broad_admit;
        let inventory_plan = self.plan.rebuild_from_sources_broad(
            &cleaned_modules,
            &self.manifests,
            &cleaned_pins,
            broad_admit,
        );
        let inventory_keys: BTreeSet<_> = inventory_plan
            .slots
            .iter()
            .map(|slot| plan::AttachKey {
                object: slot.object,
                file_offset: slot.file_offset,
            })
            .collect();
        let orphaned_selection_keys: BTreeSet<_> = prior_selection_keys
            .difference(&surviving_selection_keys)
            .filter(|key| !inventory_keys.contains(key))
            .copied()
            .collect();
        let orphaned_selection: Vec<_> = candidate
            .plan
            .slots
            .iter()
            .filter(|slot| {
                orphaned_selection_keys.contains(&plan::AttachKey {
                    object: slot.object,
                    file_offset: slot.file_offset,
                }) && candidate.plan.is_active(slot.index)
            })
            .cloned()
            .collect();
        if !orphaned_selection.is_empty() {
            let detach_orphaned_start = crate::attach::monotonic_ns();
            let detach_orphaned_outcome = session.detach_slots(&orphaned_selection);
            self.stage_timings.span(
                crate::timing::StageKind::Attach,
                "detach_orphaned_selection",
                detach_orphaned_start,
                crate::attach::monotonic_ns(),
            );
            match detach_orphaned_outcome {
                Ok(report) => {
                    let owners = candidate_timing_owners(candidate);
                    self.apply_group_rebuild(&mut candidate.plan, &owners, report, &mut *outcome);
                }
                Err(_) => {
                    self.mark_partial(
                        "live discovery detach",
                        "stale selection claims lost their final owner but one link detach failed",
                    );
                }
            }
        }
        for slot in orphaned_selection {
            candidate.plan.deactivate(slot.index);
        }
        let retired = candidate
            .plan
            .retire_unpinned_targets(&cleaned_pins, self.plan.slots.len());
        let detach_retired_start = crate::attach::monotonic_ns();
        let detach_retired_outcome = session.detach_slots(&retired);
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "detach_retired",
            detach_retired_start,
            crate::attach::monotonic_ns(),
        );
        match detach_retired_outcome {
            Ok(report) => {
                let owners = candidate_timing_owners(candidate);
                self.apply_group_rebuild(&mut candidate.plan, &owners, report, &mut *outcome);
            }
            Err(_) => {
                self.mark_partial(
                    "live discovery detach",
                    "generation loss cleanup had a one-shot detach failure",
                );
            }
        }
        commit_cleaned_candidate_identity(candidate, cleaned_pins, cleaned_modules, stale_views);
    }

    fn latch_candidate_ambiguity(&mut self, candidate: &plan::AttachPlan) -> bool {
        if !self.plan.latch_ambiguity_from(candidate) {
            return false;
        }
        self.note_facts_mutated();
        self.discovery.module_ambiguous = self.plan.module_ambiguous as u64;
        true
    }

    fn update_counter_snapshot(&mut self, session: &dyn EngineSession) -> Result<()> {
        let next = session.counter_snapshot().inspect_err(|_| {
            self.owned_initial_exec = None;
        })?;
        if !self.counter_snapshot.replace_with(next) {
            self.owned_initial_exec = None;
            self.invalidate_silent_selection_coverage();
            self.invalidate_causal_timing();
            self.mark_partial(
                "live discovery counters",
                "a producer counter decreased; the prior absolute snapshot was retained",
            );
            return Ok(());
        }
        if self.counter_snapshot.ring_loss > 0 {
            self.owned_initial_exec = None;
            self.invalidate_silent_selection_coverage();
            self.invalidate_causal_timing();
            self.mark_partial(
                "live discovery transport",
                "the kernel could not reserve one or more private discovery records",
            );
        }
        if self.counter_snapshot.export_state_failures > 0
            || self.counter_snapshot.export_bounded_read_failures > 0
            || self.counter_snapshot.abi_refusals > 0
        {
            self.invalidate_silent_selection_coverage();
            self.invalidate_causal_timing();
            self.mark_partial(
                "live export discovery",
                "the kernel reported export state, bounded-read, or target ABI failures",
            );
        }
        if self.counter_snapshot.loader_state_read_failures > 0 {
            self.invalidate_causal_timing();
            self.mark_partial(
                "live loader discovery",
                "the kernel reported loader-state read failures",
            );
        }
        Ok(())
    }

    fn process_export_record(
        &mut self,
        record: &DiscoveryRecord,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<DiscoveryRecordOutcome> {
        if interface_list_is_truncated(record) {
            self.discovery_truncated = self.discovery_truncated.saturating_add(1);
            self.mark_live_loss(
                "live interface discovery",
                "an interface-list invocation exceeded the fixed 16-record producer bound",
            );
        }
        let pid = (record.pid_tgid >> 32) as u32;
        let Some(position) = self.views.iter().position(|view| view.pid() == pid) else {
            self.request_refresh_consumed(pid, crate::attach::monotonic_ns());
            self.mark_live_loss(
                "live export discovery",
                "an export record had no retained process generation",
            );
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::ExportNoRetainedView,
            ));
        };
        let lowered = {
            let view = &self.views[position];
            let maps = Self::read_maps(view, &mut self.budget)?;
            let index =
                index_maps_or_refuse(&maps, &mut self.budget).map_err(|error| anyhow!(error))?;
            match lower_export_record(view, &index, &self.hooks, record, &mut self.budget) {
                Err(error) => return Err(anyhow!(error)),
                Ok(Some(module)) => module,
                // The prefix path owns file-backed tables only; anything a
                // factory published that it cannot own — heap wrappers,
                // anonymous-BSS tables, bare list-element addresses —
                // validates through the heap contract instead.
                Ok(None) => match lower_heap_publication_record(
                    view,
                    &index,
                    &self.hooks,
                    record,
                    &self.modules,
                    &mut self.budget,
                    None,
                ) {
                    Err(error) => return Err(anyhow!(error)),
                    Ok(HeapLowerOutcome::Admitted(module)) => module,
                    Ok(HeapLowerOutcome::Refused(reason)) => {
                        self.mark_live_loss("live export discovery", reason);
                        return Ok(DiscoveryRecordOutcome::Rejected(
                            RecordRejection::ExportNoLowerableOwner,
                        ));
                    }
                },
            }
        };
        self.apply_lowered_module(
            lowered,
            position,
            record.hook_ts_ns,
            session,
            additions_allowed,
            pending_views,
        )
    }

    /// Pins, merges and applies one lowered publication module — the
    /// shared tail of export-record and selection-result lowering, so
    /// equivalent factory forms admit through one ownership-validation
    /// path and one causal-timing observation.
    fn apply_lowered_module(
        &mut self,
        lowered: ScannedModule,
        position: usize,
        hook_ts_ns: u64,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<DiscoveryRecordOutcome> {
        #[cfg(test)]
        crate::first_use_probe::publication_validated(&self.views[position], &lowered, hook_ts_ns);
        let (pins, pin_skips) = {
            let view = &self.views[position];
            let pin_start = crate::attach::monotonic_ns();
            let pinned =
                pin_scanned_view_objects(view, std::slice::from_ref(&lowered), &mut self.budget);
            self.stage_timings.span(
                crate::timing::StageKind::Pin,
                "pin_lowered_module",
                pin_start,
                crate::attach::monotonic_ns(),
            );
            pinned.map_err(anyhow::Error::msg)?
        };
        let mut candidate_pins = self.pinned.clone();
        let mut skipped = pin_skips;
        skipped.extend(candidate_pins.absorb(pins));
        let mut raw_modules: Vec<_> = self
            .modules
            .iter()
            .map(|module| module.scanned.clone())
            .collect();
        let observed_module = lowered.clone();
        self.note_scan_observed(lowered.view, std::slice::from_ref(&lowered));
        merge_scanned_module(&mut raw_modules, lowered);
        let mut candidate = self.live_candidate(candidate_pins, raw_modules, skipped)?;
        candidate.views.insert(self.views[position].id());
        let observed = candidate_timing_keys(&candidate, std::slice::from_ref(&observed_module));
        self.observe_causal_timing(&observed, hook_ts_ns);
        let outcome = self.apply_candidate(session, candidate, additions_allowed, false, &[])?;
        self.record_apply_timing(&outcome);
        self.queue_apply_outcome(&outcome, pending_views);
        Ok(DiscoveryRecordOutcome::applied(
            outcome.changed,
            outcome.required_complete(),
        ))
    }

    /// Lowers a supported `C_GetInterface` result through the shared
    /// export-lowering path (Package F, E08). Runs only after the
    /// selection path attributed the record: the binding supplies the
    /// hook and the exact view, so no PID-only resolution is trusted
    /// here. Decode refusals publish the same explicit omission as the
    /// equivalent list element; the selection tuple is already recorded,
    /// so a refused lowering is complete handling, not an incomplete
    /// record.
    fn process_selection_lowering(
        &mut self,
        record: &DiscoveryRecord,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<DiscoveryRecordOutcome> {
        let (binding_view, hook_name) = self
            .selection_bindings
            .get(&record.binding_id)
            .and_then(|binding| {
                self.hooks
                    .by_id(binding.hook_id)
                    .filter(|(_, abi)| *abi == HookAbi::Interface)
                    .map(|(name, _)| (binding.view, name.to_string()))
            })
            .ok_or_else(|| anyhow!("selection lowering lost its attributed binding"))?;
        let pid = (record.pid_tgid >> 32) as u32;
        let Some(position) = self.views.iter().position(|view| {
            view.id() == binding_view && view.pid() == pid && view.still_the_same()
        }) else {
            self.request_refresh_consumed(pid, crate::attach::monotonic_ns());
            self.mark_live_loss(
                "live interface selection",
                "a selection result had no retained process generation when its table was validated",
            );
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::SelectionUnattributed,
            ));
        };
        let lowered = {
            let view = &self.views[position];
            let maps = Self::read_maps(view, &mut self.budget)?;
            let index =
                index_maps_or_refuse(&maps, &mut self.budget).map_err(|error| anyhow!(error))?;
            let gi_hook = Some((hook_name.as_str(), HookAbi::Interface));
            match lower_publication_record(
                view,
                &index,
                &self.hooks,
                record,
                &mut self.budget,
                gi_hook,
            ) {
                Err(error) => return Err(anyhow!(error)),
                Ok(Some(module)) => module,
                Ok(None) => match lower_heap_publication_record(
                    view,
                    &index,
                    &self.hooks,
                    record,
                    &self.modules,
                    &mut self.budget,
                    gi_hook,
                ) {
                    Err(error) => return Err(anyhow!(error)),
                    Ok(HeapLowerOutcome::Admitted(module)) => module,
                    Ok(HeapLowerOutcome::Refused(reason)) => {
                        self.mark_live_loss("live interface selection", reason);
                        return Ok(DiscoveryRecordOutcome::applied(false, true));
                    }
                },
            }
        };
        self.apply_lowered_module(
            lowered,
            position,
            record.hook_ts_ns,
            session,
            additions_allowed,
            pending_views,
        )
    }

    /// Whether every object this view owns still has the pin it was pinned
    /// under: per-view physical-identity revalidation for retaining modules
    /// across an incomplete scan. Budget-free (fstat over already-open
    /// files) and side-effect-free, unlike the sticky capture-wide check.
    /// Manifest objects stay in the subset — a changed manifest fails
    /// closed into replacement.
    fn view_pins_unchanged(&self, view: ProcessViewId) -> bool {
        let mut subset = self.pinned.clone();
        for other in self
            .views
            .iter()
            .map(ProcessView::id)
            .filter(|id| *id != view)
        {
            subset.remove_view(other);
        }
        subset.check_unchanged().unwrap_or(false)
    }

    #[allow(clippy::too_many_arguments)]
    fn process_validated_loader_scan(
        &mut self,
        position: usize,
        context_id: LoaderContextId,
        hook_ts_ns: u64,
        terminal_owner: Option<LoaderContextId>,
        terminal_exports: &[DynamicExportIdentity],
        mode: LoaderScanMode,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<DiscoveryRecordOutcome> {
        #[cfg(test)]
        if mode == LoaderScanMode::Memory {
            self.loader_memory_scan_attempts = self.loader_memory_scan_attempts.saturating_add(1);
        }
        let broad_admit = self.broad_admit;
        let (scan_result, scan_counters) = match mode {
            LoaderScanMode::Memory => Self::scan_retained_view(
                &self.views[position],
                &self.module_hints,
                &self.hooks,
                &mut self.budget,
                broad_admit,
                &mut self.stage_timings,
            ),
            LoaderScanMode::MetadataOnly => Self::scan_retained_view_without_memory(
                &self.views[position],
                &self.module_hints,
                &self.hooks,
                &mut self.budget,
                broad_admit,
                &mut self.stage_timings,
            ),
        };
        let mut skipped = self.absorb_scan_counters(scan_counters);
        self.deep_scans = self.deep_scans.saturating_add(1);
        let (mut found, fresh_pins, found_complete) = match scan_result {
            Ok(value) => value,
            Err(error) => {
                for skip in skipped {
                    self.mark_partial(&skip.subject, &skip.reason);
                }
                return Err(error);
            }
        };
        self.note_scan_observed(self.views[position].id(), &found);
        if mode == LoaderScanMode::MetadataOnly {
            for module in &mut found {
                let Some(current) = self.modules.iter().find(|current| {
                    current.scanned.view == module.view
                        && current.scanned.mount_namespace == module.mount_namespace
                        && current.scanned.key == module.key
                        && current.scanned.path == module.path
                        && current.scanned.decoder_abi == module.decoder_abi
                }) else {
                    continue;
                };
                module.tables = current.scanned.tables.clone();
                module.interfaces = current.scanned.interfaces.clone();
            }
        }
        let export_modules = found.clone();
        let loader = self
            .loader_registry
            .context(context_id)
            .map(|context| context.spec.loader)
            .ok_or_else(|| anyhow!("loader context disappeared after record validation"))?;
        let view_id = self.views[position].id();
        // An incomplete scan is not proof that a provider disappeared: when
        // the memory rescan was bounded, this view's existing modules are
        // retained after their pins revalidate instead of being replaced by
        // partial results. Metadata-only scans keep their own explicit
        // table restoration above; failed revalidation falls through to the
        // replacement below, so stale identity still retires.
        let revalidated = !found_complete
            && mode == LoaderScanMode::Memory
            && self.views[position].still_the_same()
            && self.view_pins_unchanged(view_id);
        let (candidate_pins, raw_modules) = if revalidated {
            let mut candidate_pins = self.pinned.clone();
            // Fresh pins cover only newly observed modules: re-pinning
            // retained ones under an exhausted budget would reject their
            // keys and drop exactly what revalidation just approved.
            // `fresh_pins` (all of `found`, pinned during the scan) is
            // discarded here; its skips are already in `skipped` as
            // evidence, and its cache priming makes this second pin cheap.
            let retained: Vec<ScannedModule> = self
                .modules
                .iter()
                .filter(|module| module.scanned.view == view_id)
                .map(|module| module.scanned.clone())
                .collect();
            let new_modules: Vec<ScannedModule> = found
                .iter()
                .filter(|module| is_newly_observed_module(&retained, module))
                .cloned()
                .collect();
            let pin_start = crate::attach::monotonic_ns();
            let pinned =
                pin_scanned_view_objects(&self.views[position], &new_modules, &mut self.budget);
            self.stage_timings.span(
                crate::timing::StageKind::Pin,
                "pin_new_modules",
                pin_start,
                crate::attach::monotonic_ns(),
            );
            let (new_pins, pin_skips) = pinned.map_err(anyhow::Error::msg)?;
            skipped.extend(pin_skips);
            skipped.extend(candidate_pins.absorb(new_pins));
            let mut retained = retained;
            for module in found {
                merge_scanned_module(&mut retained, module);
            }
            let mut raw_modules: Vec<_> = self
                .modules
                .iter()
                .filter(|module| module.scanned.view != view_id)
                .map(|module| module.scanned.clone())
                .collect();
            raw_modules.extend(retained);
            (candidate_pins, raw_modules)
        } else {
            let mut candidate_pins = self.pinned.clone();
            skipped.extend(candidate_pins.replace_view_pins(view_id, fresh_pins, &[loader]));
            let mut raw_modules: Vec<_> = self
                .modules
                .iter()
                .filter(|module| module.scanned.view != view_id)
                .map(|module| module.scanned.clone())
                .collect();
            for module in found {
                merge_scanned_module(&mut raw_modules, module);
            }
            (candidate_pins, raw_modules)
        };
        let mut candidate = self.live_candidate(candidate_pins, raw_modules, skipped)?;
        candidate.views.insert(self.views[position].id());
        let observed = candidate_timing_keys(&candidate, &export_modules);
        self.observe_causal_timing(&observed, hook_ts_ns);
        let collected = self.collect_dynamic_export_work(
            context_id,
            &export_modules,
            &candidate.pinned,
            session,
            terminal_owner.is_some(),
            terminal_exports,
        );
        let mut required_seed_complete = collected.required_seed_complete;
        for seed in &collected.count_only_seeds {
            let mut owners = candidate
                .plan
                .modules
                .iter()
                .filter(|module| module.object == seed.object);
            let Some(module) = owners.next() else {
                required_seed_complete = false;
                self.mark_partial(
                    "live export hook",
                    "a C_GetFunctionList seed had no unique candidate module owner",
                );
                continue;
            };
            if owners.next().is_some() {
                required_seed_complete = false;
                self.mark_partial(
                    "live export hook",
                    "a C_GetFunctionList seed had no unique candidate module owner",
                );
                continue;
            }
            match candidate.plan.add_provisional_get_function_list(
                plan::ProvisionalGetFunctionList {
                    module: module.id,
                    object: seed.object,
                    object_path: seed.object_path.clone(),
                    file_offset: seed.file_offset,
                },
            ) {
                Ok(Some(slot)) => candidate.delta.new.push(slot),
                Ok(None) => {}
                Err(_) => {
                    required_seed_complete = false;
                    self.mark_partial(
                        "live export hook",
                        "a C_GetFunctionList seed could not be added to the candidate plan",
                    );
                }
            }
        }
        let outcome = self.apply_candidate(session, candidate, additions_allowed, false, &[])?;
        self.record_apply_timing(&outcome);
        self.queue_apply_outcome(&outcome, pending_views);
        let changed = outcome.changed;
        let mut required_complete = required_seed_complete && outcome.required_complete();
        if terminal_owner.is_none() && outcome.accepted() {
            let (retire, dynamic_complete, _) = self.attach_export_work(
                self.views[position].id(),
                &collected.dynamic,
                session,
                additions_allowed,
            );
            if !dynamic_complete {
                required_complete = false;
            }
            if retire {
                let view = self.views[position].id();
                self.queue_stale_views(&[view].into_iter().collect(), pending_views);
            }
            for work in &collected.dynamic {
                if let Some(binding) = work.selection_binding
                    && self
                        .selection_bindings
                        .get(&binding.id)
                        .is_some_and(|binding| binding.attached)
                {
                    self.open_owned_selection(binding.id);
                }
            }
        } else {
            lose_unperformed_dynamic_work(&mut self.timings, &collected.dynamic);
        }
        Ok(DiscoveryRecordOutcome::applied(changed, required_complete))
    }

    #[allow(clippy::too_many_arguments)]
    fn service_pending_loader_scans(
        &mut self,
        due: BTreeSet<PendingLoaderScanKey>,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<DiscoveryRecordOutcome> {
        let mut changed = false;
        let mut required_complete = true;
        for key in due {
            // H-1: a spent live frame leaves the rest pending; the next
            // frame's fallback pass serves them.
            if self.pending_loader_scans.contains_key(&key) && self.frame_work_exhausted() {
                self.note_frame_deferral();
                break;
            }
            let Some(hook_ts_ns) = self.pending_loader_scans.remove(&key) else {
                continue;
            };
            if let Some(reason) = self.budget.stopped_now() {
                self.record_pending_loader_scan_loss(&format!(
                    "a deferred loader memory scan was unresolved at budget exhaustion: {reason}"
                ));
                required_complete = false;
                continue;
            }
            let context_current = self
                .loader_registry
                .context(key.context)
                .is_some_and(|context| context.spec.view == key.view)
                && !self.loader_registry.is_tombstoned(key.context);
            let position = self.views.iter().position(|view| view.id() == key.view);
            let Some(position) = position.filter(|_| context_current) else {
                self.record_pending_loader_scan_loss(
                    "a deferred loader memory scan was unresolved at loader context retirement",
                );
                required_complete = false;
                continue;
            };
            if !self.pause_owned_batch {
                self.unpaused_loader_views.insert(key.view);
            }
            match self.process_validated_loader_scan(
                position,
                key.context,
                hook_ts_ns,
                None,
                &[],
                LoaderScanMode::Memory,
                session,
                additions_allowed,
                pending_views,
            ) {
                Ok(outcome) => {
                    changed |= outcome.changed();
                    required_complete &= outcome.required_complete();
                }
                Err(error) => {
                    // A target that provably exited before its fallback ran
                    // ended its loader transaction unfinished: a counted
                    // truncation, never a reason to abandon the capture, and
                    // no lost causal timing (`record_pending_loader_scan_end`).
                    if self.original_exited(key.view) {
                        self.record_pending_loader_scan_end(
                            "a deferred loader memory scan was unresolved at expected process exit",
                        );
                        required_complete = false;
                        continue;
                    }
                    self.record_pending_loader_scan_loss(
                        "a deferred loader memory scan remained unresolved after its one bounded fallback attempt",
                    );
                    return Err(error);
                }
            }
        }
        Ok(DiscoveryRecordOutcome::applied(changed, required_complete))
    }

    fn process_loader_record(
        &mut self,
        queued: QueuedDiscoveryRecord,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        deferred_mismatches: &mut Vec<ProcessViewId>,
    ) -> Result<DiscoveryRecordOutcome> {
        let QueuedDiscoveryRecord {
            record,
            terminal_owner,
            terminal_exports,
        } = queued;
        let record = &record;
        if self.loader_records_accepted >= self.counter_snapshot.loader_hits {
            self.mark_live_loss(
                "live loader discovery",
                "a loader record had no producer-counter authority",
            );
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderMissingCounterAuthority,
            ));
        };
        self.loader_records_accepted = self.loader_records_accepted.saturating_add(1);
        if record.status_flags & DISCOVERY_STATUS_LOADER_CONTEXT_INVALID != 0 {
            self.reject_loader_record(
                "the kernel rejected a loader context before userspace resolution",
            );
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderInvalidContext,
            ));
        }
        let pid = (record.pid_tgid >> 32) as u32;
        let Some(position) = self.views.iter().position(|view| view.pid() == pid) else {
            self.request_refresh_consumed(pid, crate::attach::monotonic_ns());
            self.reject_loader_record("a loader hit had no retained process generation");
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderNoRetainedView,
            ));
        };
        let context_id = LoaderContextId::from_case_id(record.case_id);
        let Some(context) = self.loader_registry.context(context_id) else {
            self.reject_loader_record("a loader hit named a retired or unknown context");
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderUnknownContext,
            ));
        };
        let loader = context.spec.loader;
        let maps = Self::read_maps(&self.views[position], &mut self.budget)?;
        let index =
            index_maps_or_refuse(&maps, &mut self.budget).map_err(|error| anyhow!(error))?;
        let view_id = self.views[position].id();
        self.budget.spend(1).map_err(|reason| anyhow!(reason))?;
        let Some(mapping) = index.containing(record.table_ptr) else {
            // The same exec transition the identity check below already
            // excuses, one step earlier: replacing the whole image usually
            // leaves the hit's address resolving to *nothing*, not to a moved
            // mapping. The queued `ExecRefresh` rescans this view whole and
            // re-arms it, so the rejection costs the capture no observation —
            // only its causal timing proof — so, exactly as in the identity
            // branch below, it is counted by nothing either.
            // The exec-transition proof scans the snapshot linearly: charge that
            // pass like every other live map iteration. A refused charge leaves
            // the sticky stop for the budget's consumers, exactly as at the
            // drain sink — it never changes this record's rejection.
            self.budget.charge(maps.len() as u64);
            if self.exec_replaced_the_armed_image(&context.spec, view_id, pid, &maps, pending_views)
            {
                self.invalidate_causal_timing();
            } else {
                self.reject_loader_record("a loader hook address no longer resolved to a mapping");
            }
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderMissingMapping,
            ));
        };
        if context.spec.view != view_id
            || context
                .spec
                .mapping
                .as_ref()
                .is_some_and(|expected| expected != mapping)
        {
            // A same-object remap can only be explained by an actual matching
            // EXEC in this dispatched record vector. The hit stays rejected,
            // but its loss decision waits until that vector is complete.
            let same_object_remapped = context.spec.view == view_id
                && context
                    .spec
                    .mapping
                    .as_ref()
                    .is_some_and(|expected| same_object_remapped(expected, mapping));
            if same_object_remapped {
                self.invalidate_causal_timing();
                deferred_mismatches.push(view_id);
            } else {
                self.reject_loader_record(
                    "a loader hit failed generation, mapping, identity, or hook-IP validation",
                );
            }
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderMismatchedMapping,
            ));
        }
        if !self.pinned.check_unchanged().unwrap_or(false)
            || self
                .pinned
                .summary(loader)
                .is_none_or(|summary| summary.key != ObjectKey::of(mapping))
        {
            self.reject_loader_record(
                "a loader hit failed generation, mapping, identity, or hook-IP validation",
            );
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderPinnedIdentityMismatch,
            ));
        }
        let validation = validate_loader_record_context(
            &mut self.loader_registry,
            terminal_owner,
            record,
            self.views[position].id(),
            loader,
            mapping,
        );
        if validation.is_err() {
            self.mark_live_loss(
                "live loader discovery",
                "a loader hit failed generation, mapping, identity, or hook-IP validation",
            );
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::LoaderValidationFailure,
            ));
        }

        let key = PendingLoaderScanKey {
            view: view_id,
            context: context_id,
        };
        if matches!(record.announced_count, 1 | 2) {
            self.defer_loader_memory_scan(key, record.hook_ts_ns);
            let result = self.process_validated_loader_scan(
                position,
                context_id,
                record.hook_ts_ns,
                terminal_owner,
                &terminal_exports,
                LoaderScanMode::MetadataOnly,
                session,
                additions_allowed,
                pending_views,
            );
            if result.is_err() {
                // An RT_ADD/RT_DELETE hit of a process that already ended:
                // its transaction never reached RT_CONSISTENT.
                let ended = self.original_exited(view_id);
                self.settle_pending_loader_scan(
                    key,
                    "a deferred loader memory scan failed during export-hook preparation",
                    ended,
                );
            } else if let Some(reason) = self.budget.stopped_now() {
                self.settle_pending_loader_scan(
                    key,
                    &format!(
                        "a deferred loader memory scan was unresolved at budget exhaustion: {reason}"
                    ),
                    false,
                );
            }
            result
        } else {
            let resolving_pending = self.pending_loader_scans.remove(&key).is_some();
            let result = self.process_validated_loader_scan(
                position,
                context_id,
                record.hook_ts_ns,
                terminal_owner,
                &terminal_exports,
                LoaderScanMode::Memory,
                session,
                additions_allowed,
                pending_views,
            );
            if resolving_pending && result.is_err() {
                self.record_pending_loader_scan_loss(
                    "a zero-state opportunity did not complete its deferred loader memory scan",
                );
            } else if resolving_pending && let Some(reason) = self.budget.stopped_now() {
                self.record_pending_loader_scan_loss(&format!(
                    "a deferred loader memory scan was unresolved at budget exhaustion: {reason}"
                ));
            }
            result
        }
    }

    fn record_selection_occurrences(
        &mut self,
        module: plan::ModuleId,
        provider: PinnedTimingKey,
        table: &ScannedTable,
    ) {
        let Some(table_file_offset) = table.file_offset else {
            return;
        };
        let mut invalidates = false;
        {
            let history = self.capture_facts.visible_history_mut();
            let mut record = |name: &'static str, object: Option<(PinnedTimingKey, u64)>| {
                let Some(ordinal) =
                    crate::kinds::function_id(name).and_then(|ordinal| u16::try_from(ordinal).ok())
                else {
                    history.selection_truncated = true;
                    insert_selection_loss(
                        history,
                        "a selection table contained an unknown canonical function name",
                    );
                    invalidates = true;
                    return;
                };
                history.decoded.insert(DecodedOccurrence::Selection {
                    module,
                    provider: provider.clone(),
                    table_file_offset,
                    version: table.version,
                    ordinal,
                    name,
                    object,
                });
            };
            for name in &table.null_entries {
                record(name, None);
            }
            for entry in &table.entries {
                record(entry.name, Some((provider.clone(), entry.file_offset)));
            }
        }
        if invalidates {
            self.invalidate_selection_provider_coverage(module);
        }
    }

    fn refuse_selection_authority_for(&mut self, key: &SelectionTableKey, reason: &str) {
        {
            let history = self.capture_facts.visible_history_mut();
            history.selection_truncated = true;
            insert_selection_loss(history, reason);
        }
        self.invalidate_selection_table_coverage(key);
    }

    fn propose_selection_claim(
        &mut self,
        binding: &SelectionBindingFact,
        provider: PinnedTimingKey,
        table: &ScannedTable,
        result: &SelectionRequest,
    ) -> Option<ProposedSelectionClaim> {
        let table_file_offset = table.file_offset?;
        let table_key = SelectionTableKey {
            view: binding.view,
            provider: provider.clone(),
            version: result.version,
            flags: result.flags,
        };
        let targets: Vec<_> = table
            .entries
            .iter()
            .map(|entry| plan::SelectionTableTarget {
                object: binding.object,
                object_path: entry.object_path.clone(),
                file_offset: entry.file_offset,
                name: entry.name,
            })
            .collect();
        let previous_claims = self
            .selection_claims
            .iter()
            .filter(|(claim, _)| selection_table_key(claim) == table_key)
            .map(|(claim, value)| (claim.clone(), value.clone()))
            .collect();
        let mut tables = self.selection_tables.clone();
        if let Some(known) = tables.get(&table_key) {
            if known.object != binding.object
                || known.file_offset != table_file_offset
                || !same_selection_target_set(&known.targets, &targets)
            {
                {
                    let history = self.capture_facts.visible_history_mut();
                    history.selection_truncated = true;
                    insert_selection_loss(
                        history,
                        "conflicting selection tables shared one returned version and flags",
                    );
                }
                self.invalidate_selection_coverage(binding.id);
                return None;
            }
        } else {
            tables.insert(
                table_key.clone(),
                SelectionTableFact {
                    object: binding.object,
                    file_offset: table_file_offset,
                    targets: targets.clone(),
                },
            );
        }
        let mut claims = self.selection_claims.clone();
        for target in targets {
            let key = SelectionClaimKey {
                binding_id: binding.id,
                view: binding.view,
                context: binding.context.get(),
                hook_owner: binding.object,
                provider: provider.clone(),
                selected_object: target.object,
                table_file_offset,
                version: result.version,
                flags: result.flags,
                name: target.name,
                file_offset: target.file_offset,
            };
            claims.insert(
                key,
                SelectionClaim {
                    target: plan::AttachKey {
                        object: target.object,
                        file_offset: target.file_offset,
                    },
                    object_path: target.object_path,
                },
            );
        }
        let pending = PendingSelectionAdmission {
            key: table_key,
            table: SelectionTableFact {
                object: binding.object,
                file_offset: table_file_offset,
                targets: table
                    .entries
                    .iter()
                    .map(|entry| plan::SelectionTableTarget {
                        object: binding.object,
                        object_path: entry.object_path.clone(),
                        file_offset: entry.file_offset,
                        name: entry.name,
                    })
                    .collect(),
            },
            previous_claims,
            previous_tables: self.selection_tables.clone(),
        };
        Some((claims, tables, pending))
    }

    fn live_candidate_with_selection(
        &mut self,
        pinned: PinnedObjects,
        raw_modules: Vec<ScannedModule>,
        selection_claims: BTreeMap<SelectionClaimKey, SelectionClaim>,
        selection_tables: BTreeMap<SelectionTableKey, SelectionTableFact>,
        selection_admission: PendingSelectionAdmission,
    ) -> Result<LiveCandidate> {
        let old_claims = std::mem::replace(&mut self.selection_claims, selection_claims);
        let old_tables = std::mem::replace(&mut self.selection_tables, selection_tables);
        let result = self.live_candidate_with_pending(
            pinned,
            raw_modules,
            Vec::new(),
            Some(&selection_admission.key),
        );
        self.selection_claims = old_claims;
        self.selection_tables = old_tables;
        result.map(|mut candidate| {
            candidate.selection_admission = Some(selection_admission);
            candidate
        })
    }

    fn ordinary_selection_view<'a>(
        &'a self,
        record: &DiscoveryRecord,
        binding: &SelectionBindingFact,
        hook_matches: bool,
    ) -> Option<&'a ProcessView> {
        let pid = (record.pid_tgid >> 32) as u32;
        if !binding.attached
            || binding.retired
            || !hook_matches
            || self.loader_registry.is_tombstoned(binding.context)
            || self
                .loader_registry
                .context(binding.context)
                .is_none_or(|context| context.spec.view != binding.view)
        {
            return None;
        }

        self.views
            .iter()
            .find(|view| view.id() == binding.view && view.pid() == pid)
    }

    fn reject_selection_attribution(&mut self, binding_id: u64) {
        self.mark_live_loss(
            "live interface selection",
            "a selection record failed binding, context, or process-generation attribution",
        );
        self.invalidate_selection_coverage(binding_id);
    }

    #[cfg(test)]
    fn process_selection_record(
        &mut self,
        queued: &QueuedDiscoveryRecord,
    ) -> DiscoveryRecordOutcome {
        self.process_selection_record_inner(queued, None).unwrap_or(
            DiscoveryRecordOutcome::Rejected(RecordRejection::SelectionUnattributed),
        )
    }

    fn process_selection_record_with_session(
        &mut self,
        queued: &QueuedDiscoveryRecord,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<DiscoveryRecordOutcome> {
        self.process_selection_record_inner(
            queued,
            Some((session, additions_allowed, pending_views)),
        )
    }

    fn process_selection_record_inner(
        &mut self,
        queued: &QueuedDiscoveryRecord,
        mut transaction: Option<(
            &mut dyn EngineSession,
            &mut bool,
            &mut PendingViewRetirements,
        )>,
    ) -> Result<DiscoveryRecordOutcome> {
        let transactional = transaction.is_some();
        let can_attach = transaction
            .as_ref()
            .is_some_and(|(_, additions_allowed, _)| **additions_allowed);
        let record = &queued.record;
        let Some(binding) = self.selection_bindings.get(&record.binding_id).copied() else {
            self.mark_live_loss(
                "live interface selection",
                "a selection record named an unknown capture-local binding",
            );
            self.invalidate_silent_selection_coverage();
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::SelectionUnattributed,
            ));
        };
        let hook_matches = self
            .hooks
            .by_id(binding.hook_id)
            .is_some_and(|(_, abi)| abi == binding.abi);
        let identity = DynamicExportIdentity {
            object: binding.object,
            file_offset: binding.file_offset,
            cookie: binding.id,
            abi: binding.abi,
        };
        let pid = (record.pid_tgid >> 32) as u32;
        let ordinary_generation = queued
            .terminal_owner
            .is_none()
            .then(|| self.ordinary_selection_view(record, &binding, hook_matches))
            .flatten()
            .map(|view| (view.id(), view.original_generation_state()));
        let authorized = if let Some(owner) = queued.terminal_owner {
            binding.attached
                && hook_matches
                && owner == binding.context
                && queued.terminal_exports.contains(&identity)
        } else {
            matches!(
                ordinary_generation.as_ref(),
                Some((_, Ok(OriginalGenerationState::Current)))
            )
        };
        if !authorized {
            if let Some((view, Ok(OriginalGenerationState::Exited))) = ordinary_generation {
                return Ok(DiscoveryRecordOutcome::TerminalSelectionHandoff {
                    view,
                    owner: binding.context,
                });
            }

            self.reject_selection_attribution(binding.id);
            return Ok(DiscoveryRecordOutcome::Rejected(
                RecordRejection::SelectionUnattributed,
            ));
        }

        let Some(request_name) = selection_name_class(record.case_id) else {
            return Ok(self.reject_unattributed_selection(
                binding.id,
                "a selection record carried an unknown request-name class",
            ));
        };
        let Some(request_version) = selection_version_class(record.interface_index) else {
            return Ok(self.reject_unattributed_selection(
                binding.id,
                "a selection record carried an unknown request-version class",
            ));
        };
        let request = SelectionRequest {
            name: request_name,
            version: request_version,
            flags: record.request_flags,
        };
        let module = match self
            .capture_facts
            .module_id_for_object(&self.pinned, binding.object)
        {
            Ok(module) => module,
            Err(_) => {
                return Ok(self.reject_unattributed_selection(
                    binding.id,
                    "a selection binding had no stable provider module",
                ));
            }
        };
        let mut result = None;
        let mut inventory_matches = Vec::new();
        let mut matches_truncated = false;
        let mut read_loss = false;
        let mut assessment_loss = false;
        let mut decoded_table = None;
        if record.return_rv == 0 && record.table_ptr != 0 {
            let Some(result_name) = selection_name_class(record.name_class) else {
                return Ok(self.reject_unattributed_selection(
                    binding.id,
                    "a selection record carried an unknown result-name class",
                ));
            };
            let Some(result_version) = selection_version_class(record.selection_version_class)
            else {
                return Ok(self.reject_unattributed_selection(
                    binding.id,
                    "a selection record carried an unknown result-version class",
                ));
            };
            let observed = SelectionRequest {
                name: result_name,
                version: result_version,
                flags: record.interface_flags,
            };
            self.observe_selection(binding.id);
            read_loss = matches!(result_name, SelectionNameClass::Unreadable)
                || matches!(result_version, SelectionVersionClass::Unreadable);
            let assessed = (|| -> Result<Vec<LiveInventoryMatch>, ()> {
                let position = self
                    .views
                    .iter()
                    .position(|view| {
                        view.id() == binding.view && view.pid() == pid && view.still_the_same()
                    })
                    .ok_or(())?;
                let provider = self.pinned.owned_timing_key(binding.object).ok_or(())?;
                let provider_key = self
                    .pinned
                    .summary(binding.object)
                    .map(|summary| summary.key);
                if !self.pinned.check_unchanged().unwrap_or(false) {
                    return Err(());
                }
                let view = &self.views[position];
                let budget = &mut self.budget;
                let (_mapping, resolved) = selection_mapping_bracket(
                    record.table_ptr,
                    || {
                        let maps = Self::read_maps(view, budget).map_err(|_| ())?;
                        index_maps_or_refuse(&maps, budget).map_err(|_| ())?;
                        Ok(maps)
                    },
                    || view.still_the_same(),
                    || self.pinned.check_unchanged().unwrap_or(false),
                )?;
                let mut matches = if let Resolved::File {
                    device,
                    inode,
                    file_offset,
                    ..
                } = resolved
                    && provider_key == Some(ObjectKey { device, inode })
                {
                    self.capture_facts
                        .visible_history()
                        .selection_inventory
                        .get(&ExactSelectionTable {
                            view: binding.view,
                            provider,
                            address: record.table_ptr,
                            file_offset,
                        })
                        .cloned()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|surface| {
                            let inventory_name = surface.base.name.class();
                            LiveInventoryMatch {
                                surface: surface.clone(),
                                name_agrees: inventory_name.is_some_and(|name| {
                                    readable_name(result_name)
                                        && readable_name(name)
                                        && result_name == name
                                }),
                                version_agrees: readable_version(result_version)
                                    && readable_version(surface.base.version)
                                    && result_version == surface.base.version,
                            }
                        })
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                };
                matches.sort();
                matches.dedup();
                Ok(matches)
            })();
            match assessed {
                Ok(matches) => inventory_matches = matches,
                Err(()) => {
                    assessment_loss = true;
                    if queued.terminal_owner.is_none() {
                        self.mark_live_loss(
                            "live interface selection",
                            "a selection result could not be bracketed by one stable live mapping",
                        );
                    }
                }
            }
            if inventory_matches.len() > MAX_LIVE_SELECTION_MATCHES {
                inventory_matches.truncate(MAX_LIVE_SELECTION_MATCHES);
                matches_truncated = true;
            }
            result = Some(observed);
        } else if record.return_rv == 0 {
            self.observe_selection(binding.id);
            read_loss = true;
        } else {
            self.observe_selection(binding.id);
        }

        let authority_shape = request.name == SelectionNameClass::ExactStandard
            && result
                .as_ref()
                .is_some_and(|result| result.name == SelectionNameClass::ExactStandard)
            && result.as_ref().is_some_and(|result| {
                matches!(
                    result.version,
                    SelectionVersionClass::V3_0
                        | SelectionVersionClass::V3_1
                        | SelectionVersionClass::V3_2
                ) && matches!(result.flags, 0 | cryptoki_sys::CKF_INTERFACE_FORK_SAFE)
            });
        if transactional
            && inventory_matches.is_empty()
            && !assessment_loss
            && !read_loss
            && authority_shape
        {
            let decoded = self
                .views
                .iter()
                .find(|view| view.id() == binding.view && view.pid() == pid)
                .ok_or(())
                .and_then(|view| {
                    if !self.pinned.check_unchanged().unwrap_or(false) {
                        return Err(());
                    }
                    let layout = self
                        .pinned
                        .abi_for(binding.object)
                        .map(target_layout)
                        .ok_or(())?;
                    let (mapping, table) = if let Some((session, _, _)) = transaction.as_mut() {
                        session.read_selection_table(
                            view,
                            record.table_ptr,
                            layout,
                            &mut self.budget,
                        )?
                    } else {
                        Self::read_selection_table(
                            view,
                            record.table_ptr,
                            layout,
                            &mut self.budget,
                        )?
                    };
                    if !self.pinned.check_unchanged().unwrap_or(false) {
                        return Err(());
                    }
                    let provider = self.pinned.summary(binding.object).ok_or(())?.key;
                    let table_owned = ObjectKey::of(&mapping) == provider
                        && table.entries.iter().all(|entry| entry.object == provider);
                    table_owned.then_some(table).ok_or(())
                });
            match decoded {
                Ok(table) => decoded_table = Some(table),
                Err(()) => assessment_loss = true,
            }
        }

        let mut tuple = LiveSelectionTuple {
            module,
            request,
            rv: record.return_rv,
            result,
            inventory_matches: inventory_matches.clone(),
            authority: if !inventory_matches.is_empty()
                && !read_loss
                && !assessment_loss
                && result.as_ref().is_some_and(|result| {
                    readable_name(result.name) && readable_version(result.version)
                }) {
                SelectionAuthority::Inventory
            } else {
                SelectionAuthority::None
            },
            count: 1,
        };
        let claim_will_truncate =
            matches_truncated || !self.capture_facts.can_record_selection_claim(&tuple);
        let unmatched = result.is_some() && inventory_matches.is_empty() && !assessment_loss;
        let mut claim_authorized = false;
        if unmatched
            && can_attach
            && queued.terminal_owner.is_none()
            && !claim_will_truncate
            && !read_loss
            && !matches_truncated
            && self.counter_snapshot.ring_loss == 0
            && self.counter_snapshot.export_state_failures == 0
            && self.counter_snapshot.export_bounded_read_failures == 0
            && self.counter_snapshot.abi_refusals == 0
            && !self.capture_facts.visible_history().selection_truncated
            && authority_shape
            && result.as_ref().is_some_and(|result| {
                decoded_table.as_ref().is_some_and(|table| {
                    table.walk == "full" && inventory_version_class(table.version) == result.version
                })
            })
            && let (Some(table), Some(result), Some(provider)) = (
                decoded_table.as_ref(),
                result.as_ref(),
                self.pinned.owned_timing_key(binding.object),
            )
            && let Some((claims, tables, pending)) =
                self.propose_selection_claim(&binding, provider, table, result)
        {
            let raw_modules = self
                .modules
                .iter()
                .map(|module| module.scanned.clone())
                .collect();
            let candidate = self.live_candidate_with_selection(
                self.pinned.clone(),
                raw_modules,
                claims,
                tables,
                pending,
            )?;
            if let Some((session, additions_allowed, pending_views)) = transaction {
                let outcome =
                    self.apply_candidate(session, candidate, additions_allowed, false, &[])?;
                self.record_apply_timing(&outcome);
                self.queue_apply_outcome(&outcome, pending_views);
                claim_authorized = outcome.selection_authorized;
                if !claim_authorized {
                    self.mark_live_loss(
                        "live interface selection",
                        "an eligible selection-only table was refused by the attach transaction",
                    );
                }
                if claim_authorized
                    && let (Some(table), Some(provider)) = (
                        decoded_table.as_ref(),
                        self.pinned.owned_timing_key(binding.object),
                    )
                {
                    self.record_selection_occurrences(module, provider, table);
                }
            } else {
                self.mark_live_loss(
                    "live interface selection",
                    "an eligible selection-only table had no attach transaction",
                );
            }
        }
        if claim_authorized {
            tuple.authority = SelectionAuthority::SelectionCountOnly;
        }
        let selection_became_truncated = self
            .capture_facts
            .record_selection(tuple, matches_truncated);
        if selection_became_truncated {
            self.invalidate_silent_selection_coverage();
        }
        if read_loss {
            self.record_selection_loss_for(
                binding.id,
                "a successful selection result was unreadable",
            );
        }
        if assessment_loss {
            self.record_selection_loss_for(
                binding.id,
                if queued.terminal_owner.is_some() {
                    "a terminal selection result had no stable live table assessment"
                } else {
                    "a selection result had no stable live table assessment"
                },
            );
        } else if unmatched && !claim_authorized {
            self.record_selection_loss_for(
                binding.id,
                "a successful selection result matched no inventory table",
            );
        }
        if transactional {
            self.project_capture_facts();
        }
        Ok(DiscoveryRecordOutcome::applied(claim_authorized, true))
    }

    fn read_selection_table(
        view: &ProcessView,
        address: u64,
        layout: LinuxLayout,
        budget: &mut CaptureWorkBudget,
    ) -> std::result::Result<(MapEntry, ScannedTable), ()> {
        let maps_a = Self::read_maps(view, budget).map_err(|_| ())?;
        let index_a = index_maps_or_refuse(&maps_a, budget).map_err(|_| ())?;
        Self::read_exact_table_bracketed(view, address, layout, &index_a, budget, false)
            .map(|(mapping, table, _)| (mapping, table))
            .map_err(|_| ())
    }

    /// Bounded exact-address table validation, shared by the selection path
    /// and heap-wrapper export lowering: maps-A membership, one bounded mem
    /// read (version word first, then the exact table extent), same-decoder
    /// decode against index A, then the maps-B stability bracket plus the
    /// generation check. Returns the containing mapping, the decoded table,
    /// and the raw table bytes (publication cross-checks need them).
    ///
    /// `allow_span` (broad fixed-family only) permits the table extent to
    /// cover a run of contiguous readable mappings instead of one: a fixed
    /// pool legitimately crosses the file-tail/anonymous-BSS split. The run
    /// is contiguity-checked mapping by mapping, fully decoded (104
    /// executable entries stay the content anchor), and every touched
    /// mapping is stability-bracketed — same contract, wider extent.
    fn read_exact_table_bracketed(
        view: &ProcessView,
        address: u64,
        layout: LinuxLayout,
        index_a: &MapIndex,
        budget: &mut CaptureWorkBudget,
        allow_span: bool,
    ) -> std::result::Result<(MapEntry, ScannedTable, Vec<u8>), ExactReadRefusal> {
        let mapping_a = index_a
            .containing(address)
            .cloned()
            .ok_or(ExactReadRefusal::Unreadable)?;
        if mapping_a.permissions[0] != b'r' {
            return Err(ExactReadRefusal::Unreadable);
        }
        let mem = view
            .run_while_same(|| File::open(format!("/proc/{}/mem", view.pid())))
            .map_err(|_| ExactReadRefusal::Unreadable)?
            .map_err(|_| ExactReadRefusal::Unreadable)?;
        let width = layout.word_bytes();
        let mut bytes = vec![0; width];
        let mut operation_bytes = 0u64;
        let mut read_exact =
            |bytes: &mut [u8], base: u64| -> std::result::Result<(), ExactReadRefusal> {
                let mut done = 0usize;
                while done < bytes.len() {
                    if budget.check_deadline_now().is_some() {
                        return Err(ExactReadRefusal::Budget);
                    }
                    let allowed = budget.allowed_io(operation_bytes, bytes.len() - done);
                    if allowed == 0 {
                        return Err(ExactReadRefusal::Budget);
                    }
                    let at = base
                        .checked_add(done as u64)
                        .ok_or(ExactReadRefusal::Unstable)?;
                    let read = mem
                        .read_at(&mut bytes[done..done + allowed], at)
                        .map_err(|_| ExactReadRefusal::Unstable)?;
                    if read == 0 {
                        return Err(ExactReadRefusal::Unstable);
                    }
                    budget.record_io(read);
                    operation_bytes = operation_bytes.saturating_add(read as u64);
                    done += read;
                }
                Ok(())
            };
        read_exact(&mut bytes, address)?;
        let table_bytes = exact_table_bytes(&bytes, layout).ok_or(ExactReadRefusal::Undecodable)?;
        let table_end = address
            .checked_add(table_bytes as u64)
            .ok_or(ExactReadRefusal::Undecodable)?;
        // Mappings the table extent touches: one, or a contiguous readable
        // run when the caller allows a span. Every touched mapping joins
        // the maps-B stability check below.
        let mut span = vec![mapping_a.clone()];
        if table_end > mapping_a.end {
            if !allow_span {
                return Err(ExactReadRefusal::Undecodable);
            }
            let mut cursor = mapping_a.end;
            while cursor < table_end {
                let Some(next) = index_a.containing(cursor).cloned() else {
                    return Err(ExactReadRefusal::Undecodable);
                };
                if next.start != cursor || next.permissions[0] != b'r' {
                    return Err(ExactReadRefusal::Undecodable);
                }
                cursor = next.end;
                span.push(next);
                if span.len() > index_a.entries().len() {
                    return Err(ExactReadRefusal::Undecodable);
                }
            }
        }
        bytes.resize(table_bytes, 0);
        if table_bytes > width {
            read_exact(
                &mut bytes[width..],
                address
                    .checked_add(width as u64)
                    .ok_or(ExactReadRefusal::Unstable)?,
            )?;
        }
        let raw_addresses =
            exact_table_addresses(&bytes, layout).ok_or(ExactReadRefusal::Undecodable)?;
        let mut addresses = Vec::with_capacity(raw_addresses.len() + 1);
        addresses.push(address);
        addresses.extend(raw_addresses);
        let mappings_a: Vec<_> = addresses
            .iter()
            .map(|address| {
                index_a
                    .containing(*address)
                    .cloned()
                    .ok_or(ExactReadRefusal::Undecodable)
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let table =
            match decode_exact_table(&bytes, address, layout, index_a, budget, Some(view.id())) {
                Err(()) => return Err(ExactReadRefusal::Budget),
                Ok(None) => return Err(ExactReadRefusal::Undecodable),
                Ok(Some(table)) => table,
            };
        let maps_b = Self::read_maps(view, budget).map_err(|_| ExactReadRefusal::Unstable)?;
        let index_b =
            index_maps_or_refuse(&maps_b, budget).map_err(|_| ExactReadRefusal::Unstable)?;
        if !mappings_a
            .iter()
            .zip(&addresses)
            .all(|(mapping, address)| index_b.containing(*address) == Some(mapping))
            || !span
                .iter()
                .all(|mapping| index_b.containing(mapping.start) == Some(mapping))
            || !view.still_the_same()
        {
            return Err(ExactReadRefusal::Unstable);
        }
        Ok((mapping_a, table, bytes))
    }

    fn collect_dynamic_export_work(
        &mut self,
        context: LoaderContextId,
        modules: &[ScannedModule],
        pinned: &PinnedObjects,
        session: &dyn EngineSession,
        terminal: bool,
        terminal_exports: &[DynamicExportIdentity],
    ) -> CollectedExportWork {
        let mut collected = CollectedExportWork {
            dynamic: Vec::new(),
            count_only_seeds: Vec::new(),
            required_seed_complete: true,
        };
        let mut seed_keys = BTreeSet::new();
        for module in modules {
            let actionable_exports: Vec<_> = module
                .exports
                .iter()
                .filter(|name| {
                    session.capture_policy() != CapturePolicy::AggregateOnly
                        || self.hooks.abi(name) != Some(HookAbi::Interface)
                })
                .collect();
            if actionable_exports.is_empty() {
                continue;
            }
            let requires_seed = actionable_exports
                .iter()
                .any(|name| name.as_str() == "C_GetFunctionList");
            let Some(object) = pinned.id_for_scanned(module, module.key, &module.path) else {
                if requires_seed {
                    collected.required_seed_complete = false;
                    self.mark_partial(
                        "live export hook",
                        "a C_GetFunctionList seed lacked an exact pinned module object",
                    );
                }
                continue;
            };
            let timing_key = pinned.owned_timing_key(object);
            let snapshot = match pinned.file_for(object) {
                Some(file) => match read_elf_snapshot(file, &mut self.budget) {
                    Ok(snapshot) => Some(snapshot),
                    Err(reason) => {
                        collected.required_seed_complete = false;
                        self.mark_partial("live export hook", &reason);
                        None
                    }
                },
                None => None,
            };
            if requires_seed {
                let seed = snapshot.as_ref().and_then(|snapshot| {
                    snapshot
                        .defined_symbol("C_GetFunctionList")
                        .ok()
                        .flatten()
                        .filter(|fact| snapshot.is_executable_offset(fact.file_offset))
                });
                if let Some(seed) = seed {
                    if seed_keys.insert((object, seed.file_offset)) {
                        collected.count_only_seeds.push(CountOnlySeedWork {
                            object,
                            object_path: module.path.clone(),
                            file_offset: seed.file_offset,
                        });
                    }
                } else {
                    collected.required_seed_complete = false;
                    self.mark_partial(
                        "live export hook",
                        "an export hook was absent or outside an executable ELF segment",
                    );
                }
            }
            for name in actionable_exports {
                let Some(abi) = self.hooks.abi(name) else {
                    continue;
                };
                let Some(hook_id) = self.hooks.id(name) else {
                    continue;
                };
                let fact = snapshot.as_ref().and_then(|snapshot| {
                    snapshot
                        .defined_symbol(name)
                        .ok()
                        .flatten()
                        .filter(|fact| snapshot.is_executable_offset(fact.file_offset))
                });
                let Some(fact) = fact else {
                    if let Some(timing_key) = &timing_key {
                        self.timings.lose(timing_key);
                    }
                    self.mark_partial(
                        "live export hook",
                        "an export hook was absent or outside an executable ELF segment",
                    );
                    continue;
                };
                let selection_binding = if abi == HookAbi::Interface {
                    let Some(view) = self
                        .loader_registry
                        .context(context)
                        .map(|context| context.spec.view)
                    else {
                        collected.required_seed_complete = false;
                        self.mark_partial(
                            "live selection hook",
                            "an interface hook had no retained loader context",
                        );
                        continue;
                    };
                    if terminal
                        && !self.selection_bindings.values().any(|binding| {
                            binding.context == context
                                && binding.object == object
                                && binding.file_offset == fact.file_offset
                                && binding.abi == abi
                        })
                    {
                        continue;
                    }
                    if collected.dynamic.iter().any(|work| {
                        work.selection_binding.is_some_and(|binding| {
                            binding.context == context
                                && binding.object == object
                                && binding.file_offset == fact.file_offset
                                && binding.abi == abi
                        })
                    }) {
                        continue;
                    }
                    let provider = match self.capture_facts.module_id_for_object(pinned, object) {
                        Ok(provider) => provider,
                        Err(error) => {
                            collected.required_seed_complete = false;
                            self.mark_partial("live selection hook", &error.to_string());
                            continue;
                        }
                    };
                    let Some(binding) = self.selection_binding_candidate(
                        context,
                        view,
                        object,
                        fact.file_offset,
                        hook_id,
                        provider,
                    ) else {
                        collected.required_seed_complete = false;
                        continue;
                    };
                    Some(binding)
                } else {
                    None
                };
                let cookie = if let Some(binding) = selection_binding {
                    binding.id
                } else {
                    let context_case_id = (context.get() - 1) as u8;
                    let Some(cookie) = export_attach_cookie(object.0, context_case_id, hook_id)
                    else {
                        collected.required_seed_complete = false;
                        self.mark_partial(
                            "live export hook",
                            "an export hook identity did not fit the checked attachment cookie",
                        );
                        continue;
                    };
                    cookie
                };
                collected.dynamic.push(DynamicExportWork {
                    context,
                    module: timing_key.clone(),
                    object,
                    file_offset: fact.file_offset,
                    cookie,
                    abi,
                    already_attached: if terminal {
                        terminal_exports.contains(&DynamicExportIdentity {
                            object,
                            file_offset: fact.file_offset,
                            cookie,
                            abi,
                        })
                    } else {
                        session.has_dynamic_export(context, (object, fact.file_offset), cookie, abi)
                    },
                    selection_binding,
                });
            }
        }
        collected
    }

    fn selection_binding_candidate(
        &mut self,
        context: LoaderContextId,
        view: ProcessViewId,
        object: PinnedObjectId,
        file_offset: u64,
        hook_id: u32,
        provider: plan::ModuleId,
    ) -> Option<SelectionBindingFact> {
        if let Some(binding) = self.selection_bindings.values().find(|binding| {
            binding.context == context
                && binding.object == object
                && binding.file_offset == file_offset
                && binding.abi == HookAbi::Interface
        }) {
            return Some(*binding);
        }
        let Some(id) = self.next_selection_binding_id.take() else {
            self.mark_partial(
                "live selection hook",
                "the capture-local selection binding ID space was exhausted",
            );
            return None;
        };
        self.next_selection_binding_id = id.checked_add(1);
        Some(SelectionBindingFact {
            id,
            context,
            view,
            object,
            file_offset,
            hook_id,
            abi: HookAbi::Interface,
            attached: false,
            retired: false,
            provider,
            observed: false,
            coverage: SelectionCoverageState::Uncovered,
        })
    }

    /// Attaches one view's dynamic export work. Returns
    /// `(retire, complete, skipped)`: `skipped` is true only when closed
    /// additions skipped unattached work, distinguishing it from an ordinary
    /// open-tick failure, which leaves `complete` false with `skipped` false.
    fn attach_export_work(
        &mut self,
        view: ProcessViewId,
        work: &[DynamicExportWork],
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
    ) -> (bool, bool, bool) {
        let Some(pid) = self
            .views
            .iter()
            .find(|candidate| candidate.id() == view)
            .map(ProcessView::pid)
        else {
            lose_unperformed_dynamic_work(&mut self.timings, work);
            return (true, false, false);
        };
        let mut retire = false;
        let mut complete = true;
        let mut skipped = false;
        for work in work {
            if work.already_attached {
                continue;
            }
            if !*additions_allowed {
                complete = false;
                skipped = true;
                if let Some(module) = &work.module {
                    self.timings.lose(module);
                }
                continue;
            }
            let detach_failures = session.detach_failures().len();
            let attach_dynamic_export_start = crate::attach::monotonic_ns();
            let attach = generation_checked_mutation(
                || {
                    self.views
                        .iter()
                        .find(|candidate| candidate.id() == view)
                        .is_some_and(ProcessView::still_the_same)
                },
                || {
                    session.attach_dynamic_export(
                        work.context,
                        pid,
                        (work.object, work.file_offset),
                        work.cookie,
                        work.abi,
                        &self.pinned,
                    )
                },
            );
            self.stage_timings.span(
                crate::timing::StageKind::Attach,
                "attach_dynamic_export",
                attach_dynamic_export_start,
                crate::attach::monotonic_ns(),
            );
            match attach {
                GenerationMutation::Committed(Ok((added, completed))) => {
                    if let Some(mut binding) = work.selection_binding {
                        binding.attached = true;
                        self.selection_bindings.insert(binding.id, binding);
                    }
                    if added && let Some(module) = &work.module {
                        self.complete_causal_timing(
                            &[module.clone()].into_iter().collect(),
                            completed,
                        );
                    }
                }
                GenerationMutation::Committed(Err(_)) => {
                    complete = false;
                    if let Some(module) = &work.module {
                        self.timings.lose(module);
                    }
                    if session.detach_failures().len() > detach_failures {
                        *additions_allowed = false;
                    }
                    self.mark_partial(
                        "live export hook",
                        "a fixed-purpose dynamic export attachment failed",
                    );
                }
                GenerationMutation::PostcheckFailed(Ok((_added, _))) => {
                    if let Some(mut binding) = work.selection_binding {
                        binding.attached = true;
                        self.selection_bindings.insert(binding.id, binding);
                    }
                    complete = false;
                    if let Some(module) = &work.module {
                        self.timings.lose(module);
                    }
                    *additions_allowed = false;
                    retire = true;
                    self.mark_partial(
                        "live export hook",
                        "the process generation changed around a dynamic export attachment",
                    );
                }
                GenerationMutation::PrecheckFailed
                | GenerationMutation::PostcheckFailed(Err(_)) => {
                    complete = false;
                    if let Some(module) = &work.module {
                        self.timings.lose(module);
                    }
                    *additions_allowed = false;
                    retire = true;
                    self.mark_partial(
                        "live export hook",
                        "the process generation changed around a dynamic export attachment",
                    );
                }
            }
        }
        (retire, complete, skipped)
    }

    fn attach_refreshed_exports(
        &mut self,
        view: ProcessViewId,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
    ) -> (bool, bool, bool) {
        let modules: Vec<_> = self
            .modules
            .iter()
            .filter(|module| module.scanned.view == view && !module.scanned.exports.is_empty())
            .map(|module| module.scanned.clone())
            .collect();
        if modules.is_empty() {
            return (false, true, false);
        }
        let contexts: Vec<_> = self
            .loader_registry
            .ids_for_view(view)
            .into_iter()
            .filter(|context| {
                !self.loader_registry.is_tombstoned(*context)
                    && self
                        .loader_registry
                        .context(*context)
                        .is_some_and(|context| context.was_attached)
            })
            .collect();
        let [context] = contexts.as_slice() else {
            self.mark_partial(
                "live export hook",
                "a refreshed provider had no unique attached loader context",
            );
            return (false, false, false);
        };
        let pinned = self.pinned.clone();
        let collected =
            self.collect_dynamic_export_work(*context, &modules, &pinned, session, false, &[]);
        let (retire, complete, skipped) =
            self.attach_export_work(view, &collected.dynamic, session, additions_allowed);
        (
            retire,
            complete && collected.required_seed_complete,
            skipped,
        )
    }

    /// Books one view's refreshed-export attach for the skipped-view
    /// retry, shared by startup and tick attach. Stale views queue for
    /// retirement, any incomplete view fails the closure, and only views
    /// whose work closed additions skipped join the retry set — an ordinary
    /// open-tick failure was attempted, not skipped.
    fn note_export_attach_outcome(
        &mut self,
        view: ProcessViewId,
        outcome: (bool, bool, bool),
        pending_views: &mut PendingViewRetirements,
        closure: &mut PauseClosure,
        incomplete: &mut BTreeSet<ProcessViewId>,
    ) {
        let (retire, complete, skipped) = outcome;
        if retire {
            self.queue_stale_views(&[view].into_iter().collect(), pending_views);
        }
        if !complete {
            closure.fail();
            if skipped {
                incomplete.insert(view);
            }
        }
    }

    /// Requests every still-current armed view whose export work the attach
    /// skipped, shared by startup and tick attach. The next tick rescans
    /// and re-attaches its exports, retiring its loader context before
    /// arming again — no double-arm, no lost generation (C2).
    fn request_skipped_export_views(&mut self, incomplete: &BTreeSet<ProcessViewId>) {
        let pids: Vec<_> = self
            .views
            .iter()
            .filter(|view| {
                incomplete.contains(&view.id())
                    && view.still_the_same()
                    && !self.loader_registry.ids_for_view(view.id()).is_empty()
            })
            .map(ProcessView::pid)
            .collect();
        for pid in pids {
            self.request_refresh(pid, crate::attach::monotonic_ns());
        }
    }

    fn attach_initial_exports(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        closure: &mut PauseClosure,
    ) {
        let views: Vec<_> = self.views.iter().map(ProcessView::id).collect();
        let mut export_incomplete = BTreeSet::new();
        for view in views {
            let outcome = self.attach_refreshed_exports(view, session, additions_allowed);
            self.note_export_attach_outcome(
                view,
                outcome,
                pending_views,
                closure,
                &mut export_incomplete,
            );
        }
        // A generation lost mid-attach closes additions and skips every
        // later view's exports, leaving it armed with hooks absent and its
        // startup attach spent. Request it like the tick path does, so the
        // next tick attaches its exports.
        if !*additions_allowed {
            self.request_skipped_export_views(&export_incomplete);
        }
    }

    /// True only when `/proc/PID/exe` provably has no target — `read_link`
    /// fails with `NotFound` (kernel thread, zombie, already-exited). A
    /// target, or any other error (permissions etc.), falls through to the
    /// normal locator path, which reports today's failure unchanged.
    /// Maps-emptiness is never consulted: transient-empty maps must never
    /// classify a live process.
    fn loader_exe_is_gone(pid: u32) -> bool {
        matches!(
            std::fs::read_link(format!("/proc/{pid}/exe")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
    }

    fn arm_loader_for_view(
        &mut self,
        position: usize,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> std::result::Result<bool, LoaderArmFailure> {
        let view_id = self.views[position].id();
        if !self.loader_registry.ids_for_view(view_id).is_empty() {
            return Ok(false);
        }
        let pid = self.views[position].pid();
        if Self::loader_exe_is_gone(pid) {
            return Err(LoaderArmFailure::NotArmable);
        }
        let Some(locator) = Self::loader_locator(&self.views[position], &mut self.budget)? else {
            return Err(LoaderArmFailure::NotArmable);
        };
        let loader_path = locator.authority.loader_path.clone();
        let loader_module = mapped_object(
            &self.views[position],
            &locator.authority.loader_maps[0],
            &loader_path,
        );
        let pin_start = crate::attach::monotonic_ns();
        let pinned = pin_scanned_view_objects(
            &self.views[position],
            std::slice::from_ref(&loader_module),
            &mut self.budget,
        );
        self.stage_timings.span(
            crate::timing::StageKind::Pin,
            "pin_loader_module",
            pin_start,
            crate::attach::monotonic_ns(),
        );
        let (loader_pins, loader_skips) = pinned.map_err(anyhow::Error::msg)?;
        let skipped = loader_skips;
        for skip in &skipped {
            self.mark_partial(&skip.subject, &skip.reason);
        }
        let Some(local_loader_id) =
            loader_pins.id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        else {
            self.mark_partial(
                "live loader arming",
                "the exact loader mapping could not be pinned",
            );
            return Ok(false);
        };
        let loader_snapshot = read_elf_snapshot(
            loader_pins
                .file_for(local_loader_id)
                .expect("the just-pinned loader has its retained file"),
            &mut self.budget,
        )
        .map_err(anyhow::Error::msg)?;
        let pinned_loader_file = FileSnapshot::read(
            loader_pins
                .file_for(local_loader_id)
                .expect("the just-pinned loader has its retained file"),
        )
        .map_err(anyhow::Error::msg)?;
        if pinned_loader_file != locator.authority.interpreter_file
            || loader_snapshot.abi() != locator.authority.executable_abi
        {
            self.mark_partial(
                "live loader arming",
                "the mapped loader did not match the retained PT_INTERP target",
            );
            return Ok(false);
        }
        let Some(hook) = loader_snapshot
            .defined_symbol("_dl_debug_state")
            .map_err(anyhow::Error::msg)?
            .filter(|hook| loader_snapshot.is_executable_offset(hook.file_offset))
        else {
            self.mark_partial(
                "live loader arming",
                "the exact loader had no executable _dl_debug_state definition",
            );
            return Ok(false);
        };
        let loader_mapping =
            match unique_mapping_for_offset(&locator.authority.loader_maps, hook.file_offset) {
                Ok(mapping) => mapping,
                Err(reason) => {
                    self.mark_partial("live loader arming", &reason);
                    return Ok(false);
                }
            };
        let state_address = loader_state_address(&loader_snapshot).map_err(anyhow::Error::msg)?;

        let (candidate, loader) = self
            .loader_candidate(
                view_id,
                &loader_module,
                &loader_pins,
                local_loader_id,
                skipped,
            )
            .map_err(LoaderArmFailure::invariant)?;
        let Some(loader) = loader else {
            self.mark_partial(
                "live loader arming",
                "the loader lost canonical identity during reconciliation",
            );
            let outcome = self
                .apply_candidate(session, candidate, additions_allowed, false, &[])
                .map_err(LoaderArmFailure::invariant)?;
            self.queue_apply_outcome(&outcome, pending_views);
            return Ok(outcome.changed);
        };
        let prepared = match self.loader_registry.preflight(LoaderContextSpec {
            view: view_id,
            loader,
            mapping: Some(loader_mapping.clone()),
            hook,
            state_address,
        }) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.loader_registry.record_preflight_failure();
                return Err(LoaderArmFailure::ordinary(anyhow!(error)));
            }
        };
        let cookie = prepared.cookie();
        let outcome = self
            .apply_candidate(session, candidate, additions_allowed, false, &[])
            .map_err(LoaderArmFailure::invariant)?;
        self.queue_apply_outcome(&outcome, pending_views);
        let changed = outcome.changed;
        if !outcome.accepted() || !*additions_allowed {
            return Ok(changed);
        }
        let context = self
            .loader_registry
            .prepare(prepared)
            .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
        let mut revalidation_error = None;
        let attach_dynamic_loader_start = crate::attach::monotonic_ns();
        let attach = generation_checked_mutation(
            || {
                if !self.views[position].still_the_same() {
                    return false;
                }
                match self.pinned.check_unchanged() {
                    Ok(true) => {}
                    Ok(false) => return false,
                    Err(error) => {
                        revalidation_error = Some(
                            anyhow!(error).context("retained object revalidation unavailable"),
                        );
                        return false;
                    }
                }
                match Self::loader_locator(&self.views[position], &mut self.budget) {
                    Ok(Some(current)) => {
                        current.authority == locator.authority
                            && current.maps.contains(&loader_mapping)
                    }
                    Ok(None) => false,
                    Err(error) => {
                        revalidation_error = Some(error.context("loader revalidation unavailable"));
                        false
                    }
                }
            },
            || {
                session.attach_dynamic_loader(
                    context,
                    pid,
                    loader,
                    hook.file_offset,
                    cookie,
                    &self.pinned,
                )
            },
        );
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "attach_dynamic_loader",
            attach_dynamic_loader_start,
            crate::attach::monotonic_ns(),
        );
        let generation_lost = match attach {
            GenerationMutation::Committed(Ok(_)) => {
                self.loader_registry
                    .mark_attached(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                false
            }
            GenerationMutation::PostcheckFailed(Ok(_)) => {
                self.loader_registry
                    .mark_attached(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                true
            }
            GenerationMutation::Committed(Err(error)) => {
                self.loader_registry
                    .cancel_prepared(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                self.loader_registry
                    .remove(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                match error {
                    DynamicLoaderAttachFailure::KernelUnavailable(_) => {
                        self.mark_partial(
                            "live loader arming",
                            "the fixed-purpose loader attachment failed",
                        );
                        false
                    }
                    error => {
                        return Err(LoaderArmFailure::invariant(anyhow!(
                            "dynamic loader attachment invariant failed: {error}"
                        )));
                    }
                }
            }
            GenerationMutation::PrecheckFailed => {
                self.loader_registry
                    .cancel_prepared(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                self.loader_registry
                    .remove(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                true
            }
            GenerationMutation::PostcheckFailed(Err(error)) => {
                self.loader_registry
                    .cancel_prepared(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                self.loader_registry
                    .remove(context)
                    .map_err(|error| LoaderArmFailure::invariant(anyhow!(error)))?;
                if matches!(&error, DynamicLoaderAttachFailure::KernelUnavailable(_)) {
                    true
                } else {
                    return Err(LoaderArmFailure::invariant(anyhow!(
                        "dynamic loader attachment invariant failed around generation change: {error}"
                    )));
                }
            }
        };
        if generation_lost {
            if let Some(error) = revalidation_error {
                self.queue_retirement(view_id, RetirementCause::ExecRefresh, pending_views);
                return Err(LoaderArmFailure::ordinary(error));
            }
            self.queue_stale_views(&[view_id].into_iter().collect(), pending_views);
            self.mark_generation_change(
                view_id,
                "live loader arming",
                "loader generation, mapping, or pinned identity changed during attach",
            );
            // A named target that provably exited mid-arm is the target
            // ending: its retirement is queued as an expected removal and the
            // capture ends the ordinary way. Only a replaced or unprovable
            // generation fails the named capture.
            if matches!(self.scope, Scope::Pid(_)) && !self.original_exited(view_id) {
                return Err(LoaderArmFailure::ordinary(anyhow!(
                    "the named process generation changed during loader attachment"
                )));
            }
        }
        Ok(changed)
    }

    fn arm_owned_loader_before_release(
        &mut self,
        child: &OwnedChild,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<OwnedLoaderPrearmOutcome> {
        let Some(prepared_executable) = child.prepared_executable() else {
            self.mark_partial(
                "owned initial-set discovery",
                "the run target was not a revalidated direct ELF with one absolute PT_INTERP",
            );
            return Ok(OwnedLoaderPrearmOutcome::Unavailable);
        };
        if !matches!(self.scope, Scope::Pid(pid) if pid == child.pid()) {
            bail!("the retained Engine scope did not name the owned child exactly");
        }
        let Some(position) = self.views.iter().position(|view| {
            view.pid() == child.pid() && view.still_the_same() && child.pin().still_the_same()
        }) else {
            bail!("the owned child generation was not retained behind its pre-exec barrier");
        };
        if !prepared_executable.unchanged()? {
            bail!("the intended executable or PT_INTERP changed before pre-exec loader attachment");
        }

        let view_id = self.views[position].id();
        let loader_identity = preexec_object_key(
            &self.views[position],
            prepared_executable.interpreter_file(),
            &mut self.budget,
        )
        .map_err(anyhow::Error::msg)?;
        let loader_module = ScannedModule {
            mapped_identity: None,
            double_loaded: false,
            view: view_id,
            mount_namespace: self.views[position].mount_namespace(),
            key: loader_identity,
            path: prepared_executable.interpreter().display().to_string(),
            decoder_abi: None,
            exports: Vec::new(),
            tables: Vec::new(),
            interfaces: Vec::new(),
        };
        let pin_start = crate::attach::monotonic_ns();
        let pinned = pin_scanned_view_objects(
            &self.views[position],
            std::slice::from_ref(&loader_module),
            &mut self.budget,
        );
        self.stage_timings.span(
            crate::timing::StageKind::Pin,
            "pin_owned_loader",
            pin_start,
            crate::attach::monotonic_ns(),
        );
        let (loader_pins, skipped) = pinned.map_err(anyhow::Error::msg)?;
        for skip in &skipped {
            self.mark_partial(&skip.subject, &skip.reason);
        }
        let Some(local_loader) =
            loader_pins.id_for_scanned(&loader_module, loader_module.key, &loader_module.path)
        else {
            self.mark_partial(
                "owned initial-set discovery",
                "the exact PT_INTERP could not be pinned through the owned child root",
            );
            return Ok(OwnedLoaderPrearmOutcome::Unavailable);
        };
        let loader_snapshot = read_elf_snapshot(
            loader_pins
                .file_for(local_loader)
                .expect("the just-pinned pre-exec loader has its retained file"),
            &mut self.budget,
        )
        .map_err(anyhow::Error::msg)?;
        if loader_snapshot.abi() != prepared_executable.abi() {
            bail!("the owned executable and PT_INTERP have different target ABIs");
        }
        let Some(hook) = loader_snapshot
            .defined_symbol("_dl_debug_state")
            .map_err(anyhow::Error::msg)?
            .filter(|hook| loader_snapshot.is_executable_offset(hook.file_offset))
        else {
            self.mark_partial(
                "owned initial-set discovery",
                "the exact PT_INTERP had no executable _dl_debug_state definition",
            );
            return Ok(OwnedLoaderPrearmOutcome::Unavailable);
        };
        let state_address = loader_state_address(&loader_snapshot).map_err(anyhow::Error::msg)?;
        let (candidate, loader) =
            self.loader_candidate(view_id, &loader_module, &loader_pins, local_loader, skipped)?;
        let Some(loader) = loader else {
            bail!("the exact PT_INTERP lost canonical identity before pre-exec attachment");
        };
        let prepared_context = match self.loader_registry.preflight(LoaderContextSpec {
            view: view_id,
            loader,
            mapping: None,
            hook,
            state_address,
        }) {
            Ok(prepared) => prepared,
            Err(error) => {
                self.loader_registry.record_preflight_failure();
                self.mark_partial("owned initial-set discovery", &error);
                return Ok(OwnedLoaderPrearmOutcome::Unavailable);
            }
        };
        let cookie = prepared_context.cookie();
        let outcome = self.apply_candidate(session, candidate, additions_allowed, false, &[])?;
        self.queue_apply_outcome(&outcome, pending_views);
        if !outcome.stale_views.is_empty() {
            bail!("the owned child generation changed before pre-exec loader attachment");
        }
        if !outcome.accepted() || !*additions_allowed {
            self.mark_partial(
                "owned initial-set discovery",
                "the exact PT_INTERP identity could not be committed before barrier release",
            );
            return Ok(OwnedLoaderPrearmOutcome::Unavailable);
        }
        let context = self
            .loader_registry
            .prepare(prepared_context)
            .map_err(anyhow::Error::msg)?;
        let attach_owned_prearm_start = crate::attach::monotonic_ns();
        let attach = generation_checked_mutation(
            || {
                self.views[position].still_the_same()
                    && child.pin().still_the_same()
                    && prepared_executable.unchanged().unwrap_or(false)
                    && self.pinned.check_unchanged().unwrap_or(false)
            },
            || {
                session.attach_dynamic_loader(
                    context,
                    child.pid(),
                    loader,
                    hook.file_offset,
                    cookie,
                    &self.pinned,
                )
            },
        );
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "attach_owned_prearm_loader",
            attach_owned_prearm_start,
            crate::attach::monotonic_ns(),
        );
        match classify_owned_prearm_attach(attach) {
            OwnedPrearmAttachDisposition::Attached => {
                if let Err(error) = self.loader_registry.mark_attached(context) {
                    return self.fail_owned_prearm_attachment(
                        context,
                        false,
                        session,
                        pending_views,
                        format!("loader registry mark-attached failed: {error}"),
                    );
                }
                if session.lifecycle_tracking_unavailable().is_none() {
                    self.owned_initial_exec = Some(OwnedInitialExec {
                        view: view_id,
                        context,
                        revalidated: false,
                    });
                }
                Ok(OwnedLoaderPrearmOutcome::Armed)
            }
            OwnedPrearmAttachDisposition::Unavailable { reason } => {
                let mut errors = Vec::new();
                if let Err(error) = self.loader_registry.cancel_prepared(context) {
                    errors.push(error);
                } else if let Err(error) = self.loader_registry.remove(context) {
                    errors.push(error);
                }
                if !errors.is_empty() {
                    errors.insert(0, format!("ordinary loader attach failed: {reason}"));
                    bail!(errors.join("; "));
                }
                self.mark_partial(
                    "owned initial-set discovery",
                    "the exact PT_INTERP loader hook was unavailable before barrier release",
                );
                Ok(OwnedLoaderPrearmOutcome::Unavailable)
            }
            OwnedPrearmAttachDisposition::Lifecycle {
                producer_exists,
                reason,
            } => {
                if producer_exists {
                    let registry_attached = match self.loader_registry.mark_attached(context) {
                        Ok(()) => true,
                        Err(error) => {
                            return self.fail_owned_prearm_attachment(
                                context,
                                false,
                                session,
                                pending_views,
                                format!("{reason}; loader registry mark-attached failed: {error}"),
                            );
                        }
                    };
                    self.fail_owned_prearm_attachment(
                        context,
                        registry_attached,
                        session,
                        pending_views,
                        reason,
                    )
                } else {
                    let mut errors = vec![reason];
                    if let Err(error) = self.loader_registry.cancel_prepared(context) {
                        errors.push(error);
                    } else if let Err(error) = self.loader_registry.remove(context) {
                        errors.push(error);
                    }
                    bail!(errors.join("; "))
                }
            }
        }
    }

    fn fail_owned_prearm_attachment(
        &mut self,
        context: LoaderContextId,
        registry_attached: bool,
        session: &mut dyn EngineSession,
        pending_views: &mut PendingViewRetirements,
        initiating_error: String,
    ) -> Result<OwnedLoaderPrearmOutcome> {
        let mut errors = vec![initiating_error];
        let detach_dynamic_start = crate::attach::monotonic_ns();
        let (terminal_exports, detach_failed) = session.detach_dynamic_context(context);
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "detach_dynamic_context",
            detach_dynamic_start,
            crate::attach::monotonic_ns(),
        );
        if detach_failed {
            errors.push("dynamic loader detach failed".into());
        }
        let mut complete = true;
        let mut unvalidated_records = 0;
        // The post-detach pull shares the allowance with everything staged
        // and held: at zero room it reports capacity-blocked (an incomplete
        // drain the journal continuation retries) instead of over-admitting.
        let prearm_budget = Cell::new(self.shared_allowance_remaining(session, 0));
        let drained = begin_owned_prearm_retirement_with(
            &mut self.loader_registry,
            context,
            registry_attached,
            &mut errors,
            || match Self::nested_pull_capped(session, &prearm_budget) {
                // The prefix is already off the ring: retain it incomplete for
                // the shared continuation instead of losing it with the drain.
                Err(error) => {
                    let incomplete = error.downcast::<IncompleteTerminalDrain>()?;
                    complete = false;
                    unvalidated_records = incomplete.unvalidated_records;
                    Ok((incomplete.records, incomplete.malformed))
                }
                drained => drained,
            },
        );
        self.account_unvalidated_discovery(unvalidated_records);
        if !complete {
            errors.push(
                "post-detach discovery drain was incomplete; its exact prefix is retained".into(),
            );
        }
        // This terminal cleanup uses the same authority batch and one-retry
        // predispatch journal as every other terminal detach route; it never
        // dispatches after a failed post-detach counter snapshot.
        match self.open_terminal_journal(context, terminal_exports) {
            Ok(()) => {
                if let Some((records, malformed)) = drained {
                    if malformed != 0 {
                        errors.push("malformed discovery record during pre-arm retirement".into());
                    }
                    self.retain_terminal_batch(records, complete, malformed)?;
                }
                let mut no_additions = false;
                let mut closure = PauseClosure::new(false);
                if let Err(error) = self.dispatch_terminal_batch(
                    session,
                    &mut no_additions,
                    pending_views,
                    &mut closure,
                ) {
                    errors.push(format!("pre-arm retirement accounting failed: {error:#}"));
                }
            }
            Err(error) => {
                errors.push(error.to_string());
                if let Err(error) = self.loader_registry.remove(context) {
                    errors.push(error);
                }
            }
        }
        bail!(errors.join("; "))
    }

    /// Whether the ownership gate in `arm_loader_or_partial` keeps this view
    /// unarmed: in a multi-process scope, a view that owns no provider module
    /// and no pin claim stays exploratory.
    fn loader_arming_gated(&self, view_id: ProcessViewId) -> bool {
        self.admits_generations()
            && !self
                .modules
                .iter()
                .any(|module| module.scanned.view == view_id)
            && self.pinned.view_claims(view_id).is_none_or(|claims| {
                claims.tables.is_empty() && claims.targets.is_empty() && claims.pins.is_empty()
            })
    }

    fn arm_loader_or_partial(
        &mut self,
        position: usize,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Result<bool> {
        // Ownership-gated arming (Package C): loader contexts are finite
        // capture-lifetime IDs (256, never reused) backing event-driven
        // tracking, so in multi-process scopes they are spent only where a
        // provider is owned. Provider-free views stay unarmed and
        // exploratory: rotation polls them within the exploration bound,
        // and a polling rescan that finds a provider upgrades the view to
        // owned and arms it then. Pid scope (including owned runs) always
        // arms: the one named generation is the capture, not exploration.
        // The skip is silent like NotArmable — the exploration envelope is
        // stated, not a per-capture loss — and unrecorded, so gated views
        // never inflate the `unavailable` aggregate.
        let view_id = self.views[position].id();
        if self.loader_arming_gated(view_id) {
            return Ok(false);
        }
        self.loader_arms = self.loader_arms.saturating_add(1);
        let named = matches!(self.scope, Scope::Pid(_));
        let result = self.arm_loader_for_view(position, session, additions_allowed, pending_views);
        let generation_valid = self
            .views
            .get(position)
            .is_some_and(|view| view.id() == view_id && view.still_the_same());
        let outcome = loader_arm_outcome(generation_valid, result);
        // NotArmable views stay out of the loader aggregate entirely: no
        // record, so they never inflate the `unavailable` count. Every
        // other outcome records exactly as today.
        let not_armable = matches!(
            outcome,
            LoaderArmOutcome::NotArmable
                | LoaderArmOutcome::GenerationLost {
                    failure: Some(LoaderArmFailure::NotArmable),
                    ..
                }
        );
        if !not_armable {
            self.record_loader_arm(view_id, false);
        }
        match outcome {
            LoaderArmOutcome::NotArmable => Ok(false),
            LoaderArmOutcome::Changed(changed) => Ok(changed),
            LoaderArmOutcome::OrdinaryFailure(error) => {
                self.invalidate_causal_timing();
                self.mark_partial("live loader arming", &format!("{error:#}"));
                Ok(false)
            }
            LoaderArmOutcome::Invariant(error) => Err(error),
            LoaderArmOutcome::GenerationLost { changed, failure } => {
                self.queue_stale_views(&[view_id].into_iter().collect(), pending_views);
                self.mark_generation_change(
                    view_id,
                    "live loader arming",
                    "the process generation changed before the loader-arm postcheck",
                );
                // `generation_valid` is false for an exit and a replacement
                // alike; the retained pin tells them apart, as it does for
                // `queue_retirement`, which already queued an expected removal.
                let exited = self.original_exited(view_id);
                match failure {
                    Some(LoaderArmFailure::Invariant(error)) => Err(error),
                    _ if named && exited => Ok(changed),
                    Some(LoaderArmFailure::Ordinary(error)) if named => Err(error),
                    _ if named => {
                        bail!("the named process generation changed during loader arming")
                    }
                    _ => Ok(changed),
                }
            }
        }
    }

    fn begin_terminal_drain<T>(
        &mut self,
        owner: LoaderContextId,
        exports: Vec<DynamicExportIdentity>,
        drain: impl FnOnce() -> Result<T>,
    ) -> Result<Result<T>> {
        if self.terminal_journal.is_some() {
            bail!("terminal loader drain authority is already pending");
        }
        self.loader_registry
            .tombstone(owner)
            .map_err(anyhow::Error::msg)?;
        self.open_terminal_journal(owner, exports)?;
        Ok(drain())
    }

    /// Opens the single authority batch plus lifecycle journal for an
    /// already-tombstoned owner. Every terminal detach route shares it.
    fn open_terminal_journal(
        &mut self,
        owner: LoaderContextId,
        exports: Vec<DynamicExportIdentity>,
    ) -> Result<()> {
        if self.terminal_journal.is_some() {
            bail!("terminal loader drain authority is already pending");
        }
        self.terminal_batch = Some(TerminalBatch::empty(TerminalAuthority { owner, exports }));
        self.terminal_journal = Some(TerminalJournal {
            owner,
            dispatch_started: false,
            retry_used: false,
        });
        Ok(())
    }

    /// Judge the failed-drain record at capture end. It announces a *retry* —
    /// "the exact terminal batch remains tombstoned for retry" — which is true
    /// only while the journal that owes it is still pending. Once the journal
    /// clears, nothing remains tombstoned: either the retry dispatched the
    /// exact batch, or it was cleaned without replay and published that loss
    /// under its own reason. Judged by capture end, like §4.12 corroboration
    /// and the empty-scan rule; a journal still pending keeps the record, and
    /// the timing proof this loss already invalidated is not given back.
    pub(crate) fn settle_terminal_drain(&mut self) {
        self.settle_all_pending_loader_scans(
            "a deferred loader memory scan was unresolved at capture cancellation or shutdown",
        );
        record_object_skips(&mut self.plan, &self.counters.object_skips);
        let pending_views = self.pending_leader_exit_views.clone();
        finalize_pending_leader_exit_views(
            &mut self.pending_leader_exit_views,
            &mut self.counted_leader_exit_views,
            &mut self.task_uprobe_link_losses,
        );
        for view in pending_views {
            self.close_owned_selection_for_view(view);
        }
        if self.terminal_journal.is_some() {
            return;
        }
        let announced = Skipped {
            subject: TERMINAL_DRAIN_SUBJECT.into(),
            reason: TERMINAL_DRAIN_RETRY_REASON.into(),
        };
        self.counters.object_skips.retain(|skip| *skip != announced);
        self.plan.skipped.retain(|skip| *skip != announced);
    }

    fn terminal_owner(&self) -> Option<LoaderContextId> {
        self.terminal_journal.map(|journal| journal.owner)
    }

    fn handoff_precharged_terminal_records(
        &mut self,
        owner: LoaderContextId,
        records: Vec<DiscoveryRecord>,
    ) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        let batch = self
            .terminal_batch
            .as_mut()
            .ok_or_else(|| anyhow!("terminal loader drain batch is missing"))?;
        if batch.authority.owner != owner {
            bail!("terminal selection handoff named the wrong loader owner");
        }
        batch.extend(records);
        Ok(())
    }

    fn reject_terminal_selection_handoffs(
        &mut self,
        records: impl IntoIterator<Item = DiscoveryRecord>,
        closure: &mut PauseClosure,
    ) {
        for record in records {
            self.reject_selection_attribution(record.binding_id);
            closure.fail();
        }
    }

    fn retain_terminal_batch(
        &mut self,
        records: impl IntoIterator<Item = DiscoveryRecord>,
        complete: bool,
        malformed: u64,
    ) -> Result<()> {
        let batch = self
            .terminal_batch
            .as_mut()
            .ok_or_else(|| anyhow!("terminal loader drain batch is missing"))?;
        let before = batch.records.len();
        batch.extend(records);
        batch.complete = complete;
        let added = batch.records.len() - before;
        self.charge_discovery_drain(added, malformed);
        if malformed != 0 {
            self.record_malformed_discovery(malformed);
        }
        Ok(())
    }

    fn collect_terminal_batch(
        &mut self,
        session: &mut dyn EngineSession,
        collect: &mut DiscoveryCollector<'_>,
    ) -> Result<Result<(), anyhow::Error>> {
        match collect(session) {
            Ok((records, malformed)) => {
                self.retain_terminal_batch(records, true, malformed)?;
                Ok(Ok(()))
            }
            // H5 pressure: the collector diverted fresh records behind the
            // parked prefix; the nested operation stays incomplete for this
            // episode. Never loss, never complete.
            Err(error) if error.is::<PressureOrderingBlocked>() => Ok(Err(error)),
            Err(error) => match error.downcast::<IncompleteTerminalDrain>() {
                Ok(incomplete) => {
                    self.account_unvalidated_discovery(incomplete.unvalidated_records);
                    // Move-only: the batch takes the prefix, and the signal
                    // back up keeps the retained count for its diagnostic
                    // without a second owned copy.
                    let mut incomplete = incomplete;
                    let prefix = std::mem::take(&mut incomplete.records);
                    incomplete.moved_to_batch = prefix.len();
                    let malformed = incomplete.malformed;
                    self.retain_terminal_batch(prefix, false, malformed)?;
                    Ok(Err(incomplete.into()))
                }
                Err(error) => Ok(Err(error)),
            },
        }
    }

    fn retry_terminal_predispatch_failure(
        &mut self,
        additions_allowed: &mut bool,
        closure: &mut PauseClosure,
    ) {
        let Some(journal) = self.terminal_journal.as_mut() else {
            return;
        };
        if journal.dispatch_started {
            return;
        }
        if !journal.retry_used {
            journal.retry_used = true;
            self.mark_live_loss(
                "live discovery counters",
                "the post-detach producer snapshot could not be read; the exact terminal batch remains queued",
            );
            return;
        }
        let owner = journal.owner;
        journal.dispatch_started = true;
        self.terminal_batch = None;
        if self.loader_registry.remove(owner).is_ok() {
            self.terminal_journal = None;
        }
        *additions_allowed = false;
        closure.fail();
        self.invalidate_silent_selection_coverage();
        self.mark_live_loss(
            "live discovery counters",
            "the terminal batch exhausted its one predispatch retry and was cleaned without replay",
        );
    }

    /// Whether `install_terminal_batch` would accept this batch: the
    /// journal exists and names its owner, dispatch has not started, and the
    /// engine holds no competing batch. Move-only callers precheck before
    /// moving ownership, so a refusal never needs the batch back.
    pub(crate) fn terminal_batch_installable(&self, batch: &TerminalBatch) -> Result<()> {
        let Some(journal) = self.terminal_journal else {
            bail!("terminal loader drain journal is missing");
        };
        if journal.owner != batch.authority.owner
            || journal.dispatch_started
            || self.terminal_batch.is_some()
        {
            bail!("terminal loader drain batch cannot be restored");
        }
        Ok(())
    }

    pub(crate) fn install_terminal_batch(
        &mut self,
        mut batch: TerminalBatch,
        records: impl IntoIterator<Item = DiscoveryRecord>,
    ) -> Result<()> {
        let Some(journal) = self.terminal_journal else {
            bail!("terminal loader drain journal is missing");
        };
        if journal.owner != batch.authority.owner
            || journal.dispatch_started
            || self.terminal_batch.is_some()
        {
            bail!("terminal loader drain batch cannot be restored");
        }
        batch.extend(records);
        self.terminal_batch = Some(batch);
        Ok(())
    }

    pub(crate) fn take_terminal_batch_for_deferred(&mut self) -> Result<TerminalBatch> {
        self.terminal_batch
            .take()
            .ok_or_else(|| anyhow!("terminal loader drain batch is missing"))
    }

    pub(crate) fn reconcile_terminal_authority(
        &mut self,
        returned: &mut Option<TerminalBatch>,
    ) -> Result<()> {
        let Some(journal) = self.terminal_journal else {
            if self.terminal_batch.is_some() || returned.is_some() {
                bail!("terminal loader drain authority has no journal");
            }
            return Ok(());
        };
        if journal.dispatch_started {
            if self.terminal_batch.is_some() || returned.is_some() {
                bail!("dispatched terminal authority still has a replayable batch");
            }
            return Ok(());
        }
        match (self.terminal_batch.take(), returned.as_ref()) {
            (Some(batch), None) => *returned = Some(batch),
            (None, Some(batch)) if batch.authority.owner == journal.owner => {}
            (Some(batch), Some(_)) => {
                self.terminal_batch = Some(batch);
                bail!("terminal loader drain authority has two batch owners");
            }
            (None, Some(_)) => bail!("returned terminal batch does not match its journal"),
            (None, None) => bail!("undispatched terminal authority has no batch owner"),
        }
        Ok(())
    }

    pub(crate) fn terminal_authority_pending(&self) -> bool {
        self.terminal_journal.is_some()
    }

    pub(crate) fn cleanup_started_terminal_journal(&mut self) -> Result<()> {
        let journal = self
            .terminal_journal
            .ok_or_else(|| anyhow!("terminal loader drain journal is missing"))?;
        if !journal.dispatch_started || self.terminal_batch.is_some() {
            bail!("terminal loader drain journal is not cleanup-only");
        }
        self.loader_registry
            .remove(journal.owner)
            .map_err(anyhow::Error::msg)?;
        self.terminal_journal = None;
        Ok(())
    }

    pub(crate) fn cleanup_terminal_batch_without_replay(
        &mut self,
        returned: &mut Option<TerminalBatch>,
    ) -> Result<()> {
        let batch = returned
            .as_ref()
            .ok_or_else(|| anyhow!("returned terminal batch is missing"))?;
        let journal = self
            .terminal_journal
            .ok_or_else(|| anyhow!("terminal loader drain journal is missing"))?;
        if journal.dispatch_started || journal.owner != batch.authority.owner {
            bail!("returned terminal batch does not match the undispatched journal");
        }
        if self.terminal_batch.as_ref().is_some() {
            bail!("engine still owns an undispatched terminal batch");
        }
        self.terminal_journal
            .as_mut()
            .expect("journal checked above")
            .dispatch_started = true;
        returned.take();
        self.invalidate_silent_selection_coverage();
        self.mark_live_loss(
            TERMINAL_DRAIN_SUBJECT,
            "the bounded terminal cleanup retry failed; its undispatched batch was discarded without replay",
        );
        self.loader_registry
            .remove(journal.owner)
            .map_err(anyhow::Error::msg)?;
        self.terminal_journal = None;
        Ok(())
    }

    fn dispatch_terminal_batch(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        closure: &mut PauseClosure,
    ) -> Result<Option<bool>> {
        let Some(batch) = self.terminal_batch.take() else {
            let Some(journal) = self.terminal_journal else {
                return Ok(Some(false));
            };
            if !journal.dispatch_started {
                return Ok(Some(false));
            }
            if self.loader_registry.remove(journal.owner).is_err() {
                *additions_allowed = false;
                self.mark_partial(
                    "live loader retirement",
                    "a dispatched tombstoned loader context could not be removed",
                );
                return Ok(Some(false));
            }
            self.terminal_journal = None;
            return Ok(Some(false));
        };
        if !batch.complete {
            self.terminal_batch = Some(batch);
            return Ok(None);
        }
        let journal = self
            .terminal_journal
            .as_ref()
            .ok_or_else(|| anyhow!("terminal loader drain journal is missing"))?;
        if journal.owner != batch.authority.owner || journal.dispatch_started {
            bail!("terminal loader drain batch was already dispatched");
        }
        let owner = journal.owner;
        let mut records =
            match begin_discovery_batch(batch.records, self.update_counter_snapshot(session)) {
                Ok(records) => records,
                Err((_, records)) => {
                    self.terminal_batch = Some(TerminalBatch {
                        authority: batch.authority,
                        records,
                        complete: true,
                    });
                    self.retry_terminal_predispatch_failure(additions_allowed, closure);
                    return Ok(Some(false));
                }
            };
        self.terminal_journal
            .as_mut()
            .expect("journal checked above")
            .dispatch_started = true;
        let mut changed = false;
        let mut exec_refresh_views = BTreeSet::new();
        let mut deferred_mismatches = Vec::new();
        for queued in records.drain(..) {
            let origin = (queued.record.pid_tgid >> 32) as u32;
            match self.dispatch_discovery_record(
                queued,
                session,
                additions_allowed,
                pending_views,
                &mut exec_refresh_views,
                &mut deferred_mismatches,
            ) {
                Ok(outcome) => {
                    changed |= outcome.changed();
                    if !outcome.required_complete() {
                        closure.fail();
                    }
                }
                Err(_) => {
                    closure.fail();
                    if self.record_generation_ended(origin) {
                        self.invalidate_causal_timing();
                    } else {
                        self.mark_live_loss(
                            "live discovery record",
                            "a structurally valid private terminal record failed exact live resolution",
                        );
                    }
                }
            }
        }
        self.settle_deferred_loader_mismatches(deferred_mismatches, &exec_refresh_views);
        if self.loader_registry.remove(owner).is_err() {
            *additions_allowed = false;
            self.mark_partial(
                "live loader retirement",
                "a dispatched tombstoned loader context could not be removed",
            );
            return Ok(Some(changed));
        }
        self.terminal_journal = None;
        Ok(Some(changed))
    }

    /// The one authority-specific continuation. It advances an incomplete
    /// terminal batch by exactly one collection attempt, then hands the journal
    /// to `dispatch_terminal_batch`, which either dispatches a complete
    /// undispatched batch or, once dispatch has started, repeats nothing but
    /// the registry removal. Generic records never reach it.
    fn continue_terminal_batch(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<Option<bool>> {
        if self
            .terminal_batch
            .as_ref()
            .is_some_and(|batch| !batch.complete)
        {
            match self.collect_terminal_batch(session, collect)? {
                Ok(()) => {}
                Err(error) if error.is::<DeferredDiscoveryItem>() => {
                    let mut deferred = error.downcast::<DeferredDiscoveryItem>()?;
                    deferred.terminal_batch = Some(self.take_terminal_batch_for_deferred()?);
                    return Err(deferred.into());
                }
                Err(error) => return Err(error),
            }
        }
        self.dispatch_terminal_batch(session, additions_allowed, pending_views, closure)
    }

    // One retirement pass owns the whole decision: the view, the terminal
    // handoffs it may still hand a selection to, and every accumulator the
    // caller needs back. Splitting it would hand out the same state twice.
    #[allow(clippy::too_many_arguments)]
    fn retire_loader_contexts(
        &mut self,
        view: ProcessViewId,
        terminal_selection_handoffs: &mut TerminalSelectionHandoffs,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<(bool, bool)> {
        if self
            .owned_initial_exec
            .is_some_and(|initial| initial.view == view)
        {
            self.owned_initial_exec = None;
        }
        let mut changed = false;
        // A pending journal owns this retirement pass: advance it once before
        // any other context of this view is touched, and never start a second
        // authority while it survives.
        if self.terminal_journal.is_some() {
            match self.continue_terminal_batch(
                session,
                additions_allowed,
                pending_views,
                collect,
                closure,
            ) {
                Ok(terminal_changed) => changed |= terminal_changed.unwrap_or(false),
                Err(error) if error.is::<IncompleteTerminalDrain>() => {
                    closure.fail();
                    self.mark_live_loss(TERMINAL_DRAIN_SUBJECT, TERMINAL_DRAIN_RETRY_REASON);
                    return Ok((changed, false));
                }
                // H5 pressure: the journal survives the episode untouched;
                // its continuation retries after the parked prefix dispatch.
                Err(error) if error.is::<PressureOrderingBlocked>() => {
                    closure.fail();
                    return Ok((changed, false));
                }
                Err(error) => return Err(error),
            }
            if self.terminal_journal.is_some() {
                return Ok((changed, false));
            }
        }
        for context_id in self.loader_registry.ids_for_view(view) {
            let Some(context) = self.loader_registry.context(context_id).cloned() else {
                continue;
            };
            if self.loader_registry.is_tombstoned(context_id) {
                // A prior one-shot retirement reached its terminal state but
                // could not remove the registry entry. Never detach it twice.
            } else if context.was_attached {
                if self.terminal_journal.is_some() {
                    bail!("terminal loader drain authority is already pending");
                }
                let detach_retire_dynamic_start = crate::attach::monotonic_ns();
                let (terminal_exports, detach_failed) = session.detach_dynamic_context(context_id);
                self.stage_timings.span(
                    crate::timing::StageKind::Attach,
                    "detach_dynamic_context",
                    detach_retire_dynamic_start,
                    crate::attach::monotonic_ns(),
                );
                for binding in self.selection_bindings.values_mut() {
                    if binding.context == context_id {
                        binding.retired = true;
                        binding.coverage.retire();
                    }
                }
                if detach_failed {
                    closure.fail();
                    *additions_allowed = false;
                    self.mark_partial(
                        "live loader detach",
                        "a one-shot dynamic detach failed; replacement was blocked for this cycle",
                    );
                }
                let terminal_drain =
                    self.begin_terminal_drain(context_id, terminal_exports, || collect(session));
                if terminal_drain.is_ok()
                    && let Some(records) = terminal_selection_handoffs.remove(&context_id.get())
                    && !records.is_empty()
                {
                    // Move-only: the handoff moves the records, so ownership
                    // is checked before the move; only a failed check keeps
                    // the originals for rejection.
                    let owner_ok = self
                        .terminal_batch
                        .as_ref()
                        .is_some_and(|batch| batch.authority.owner == context_id);
                    if !owner_ok {
                        let error = if self.terminal_batch.is_none() {
                            anyhow!("terminal loader drain batch is missing")
                        } else {
                            anyhow!("terminal selection handoff named the wrong loader owner")
                        };
                        self.reject_terminal_selection_handoffs(records, closure);
                        return Err(error);
                    }
                    self.handoff_precharged_terminal_records(context_id, records)?;
                }
                match terminal_drain {
                    Ok(Ok((owned, malformed))) => {
                        if malformed != 0 {
                            closure.fail();
                        }
                        self.retain_terminal_batch(owned, true, malformed)?;
                        match self.dispatch_terminal_batch(
                            session,
                            additions_allowed,
                            pending_views,
                            closure,
                        )? {
                            Some(terminal_changed) => changed |= terminal_changed,
                            None => return Ok((changed, false)),
                        }
                    }
                    Ok(Err(error)) if error.is::<DeferredDiscoveryItem>() => {
                        let mut deferred = error.downcast::<DeferredDiscoveryItem>()?;
                        deferred.terminal_batch = Some(self.take_terminal_batch_for_deferred()?);
                        return Err(deferred.into());
                    }
                    // H5 pressure: the tombstoned context keeps its pending
                    // journal; no loss is marked for an episode block.
                    Ok(Err(error)) if error.is::<PressureOrderingBlocked>() => {
                        closure.fail();
                        return Ok((changed, false));
                    }
                    Ok(Err(error)) => {
                        if let Ok(incomplete) = error.downcast::<IncompleteTerminalDrain>() {
                            self.account_unvalidated_discovery(incomplete.unvalidated_records);
                            self.retain_terminal_batch(
                                incomplete.records,
                                false,
                                incomplete.malformed,
                            )?;
                        }
                        closure.fail();
                        self.mark_live_loss(TERMINAL_DRAIN_SUBJECT, TERMINAL_DRAIN_RETRY_REASON);
                        return Ok((changed, false));
                    }
                    Err(_) => {
                        if let Some(records) = terminal_selection_handoffs.remove(&context_id.get())
                        {
                            self.reject_terminal_selection_handoffs(records, closure);
                        }
                        closure.fail();
                        *additions_allowed = false;
                        self.mark_partial(
                            "live loader retirement",
                            "an attached loader context could not enter its terminal tombstone state",
                        );
                        return Ok((changed, false));
                    }
                }
            } else if self.loader_registry.cancel_prepared(context_id).is_err() {
                *additions_allowed = false;
                self.mark_partial(
                    "live loader retirement",
                    "a prepared loader context could not be cancelled",
                );
                return Ok((changed, false));
            }
            if self.terminal_owner() == Some(context_id) {
                return Ok((changed, false));
            }
            self.settle_pending_loader_scan(
                PendingLoaderScanKey {
                    view,
                    context: context_id,
                },
                "a deferred loader memory scan was unresolved at loader context retirement",
                false,
            );
            // A context its own terminal dispatch already removed was removed
            // exactly once; only one still registered can fail to be removed.
            if self.loader_registry.context(context_id).is_some()
                && self.loader_registry.remove(context_id).is_err()
            {
                *additions_allowed = false;
                self.mark_partial(
                    "live loader retirement",
                    "a tombstoned loader context could not be removed",
                );
                return Ok((changed, false));
            }
        }
        Ok((changed, true))
    }

    /// Whether an inventory preflight's stale views include a generation
    /// that was *lost*, not one that merely ended. A newly opened view is
    /// counted as before; a retained view whose original pin proves it exited
    /// is the process ending, which `queue_retirement` turns into an expected
    /// removal — and for a named target, the ordinary end of the capture.
    /// Asked before the retirement drops the view, while the pin is still held.
    fn inventory_preflight_lost_generation(
        &self,
        retained_stale: &BTreeSet<ProcessViewId>,
        stale: &BTreeSet<ProcessViewId>,
    ) -> bool {
        self.retained_generation_lost(retained_stale)
            || stale.iter().any(|view| !retained_stale.contains(view))
    }

    /// Whether any of these retained views changed generation other than by
    /// a provable exit of its original process.
    fn retained_generation_lost(&self, retained_stale: &BTreeSet<ProcessViewId>) -> bool {
        retained_stale
            .iter()
            .any(|view| !self.original_exited(*view))
    }

    fn queue_stale_views(
        &mut self,
        stale: &BTreeSet<ProcessViewId>,
        pending_views: &mut PendingViewRetirements,
    ) {
        for view in stale {
            self.queue_retirement(*view, RetirementCause::GenerationLost, pending_views);
        }
    }

    fn queue_inventory_retirements(
        &mut self,
        retirement_views: &BTreeSet<ProcessViewId>,
        stale: &BTreeSet<ProcessViewId>,
        departed: &BTreeSet<ProcessViewId>,
        pending_views: &mut PendingViewRetirements,
    ) {
        for view in retirement_views {
            let cause = if stale.contains(view) {
                RetirementCause::GenerationLost
            } else if departed.contains(view) {
                self.ready_expected_removals.insert(*view);
                RetirementCause::ExpectedRemoval
            } else {
                RetirementCause::ExecRefresh
            };
            self.queue_retirement(*view, cause, pending_views);
        }
    }

    /// The one place every retirement intent is recorded, and therefore the one
    /// place that decides whether a generation that is no longer current was
    /// *lost* or simply *ended*. `still_the_same()` is false for both, so every
    /// caller that only asks that question hands this an incoming
    /// `GenerationLost`; the retained original pin is the stronger authority and
    /// `run` already treats it as definitive (`should_finish`, src/run.rs). A
    /// pin that proves the original exited names the ordinary leader-exit
    /// transition, so the capture ends instead of failing — the `LEADER_EXIT`
    /// record is still in the ring when the pidfd is already readable, and a
    /// short-lived target loses that race almost every time. Loss stays loss
    /// whenever exit cannot be proven, and an already-recorded loss stays
    /// sticky: only the incoming cause is reclassified.
    fn queue_retirement(
        &mut self,
        view: ProcessViewId,
        cause: RetirementCause,
        pending_views: &mut PendingViewRetirements,
    ) {
        if self
            .owned_initial_exec
            .is_some_and(|initial| initial.view == view)
        {
            self.owned_initial_exec = None;
        }
        let previous = self.retirement_intents.get(&view).copied();
        let cause = if cause == RetirementCause::GenerationLost && self.original_exited(view) {
            RetirementCause::ExpectedRemoval
        } else {
            cause
        };
        let cause = previous.map_or(cause, |current| current.merge(cause));
        let pending_reason = match cause {
            RetirementCause::ExpectedRemoval => {
                "a deferred loader memory scan was unresolved at expected process exit"
            }
            RetirementCause::ExecRefresh | RetirementCause::GenerationLost => {
                "a deferred loader memory scan was unresolved at loader context retirement"
            }
        };
        self.settle_pending_loader_scans_for_view(
            view,
            pending_reason,
            cause == RetirementCause::ExpectedRemoval,
        );
        if cause != RetirementCause::ExpectedRemoval {
            self.ready_expected_removals.remove(&view);
        }
        self.retirement_intents.insert(view, cause);
        pending_views
            .entry(view)
            .and_modify(|current| *current = current.merge(cause))
            .or_insert(cause);

        if let Some(pid) = self
            .views
            .iter()
            .find(|candidate| candidate.id() == view)
            .map(ProcessView::pid)
        {
            match cause {
                RetirementCause::ExpectedRemoval => {
                    self.clear_refresh_for_view(view, pid);
                    // The view is leaving, so its pending poll dies with it:
                    // no rescan will settle it, and the removal evidence is
                    // its publication (F1).
                    self.polled_pids.remove(&pid);
                }
                RetirementCause::ExecRefresh | RetirementCause::GenerationLost => {
                    self.request_refresh(pid, crate::attach::monotonic_ns());
                }
            }
        }
        if cause == RetirementCause::GenerationLost
            && previous != Some(RetirementCause::GenerationLost)
        {
            self.mark_live_loss(
                "live discovery generation",
                "a retained process generation changed and was scheduled for conservative cleanup",
            );
        }
    }

    /// Whether the generation a record came from has *ended*. A record is
    /// resolved against the address space that produced it, so one whose
    /// process exited first cannot be resolved at all — the ordinary end of a
    /// process, not a discovery loss. Same authority `queue_retirement` uses,
    /// asked about a record instead of a retirement; loss stays loss whenever
    /// exit cannot be proven.
    fn record_generation_ended(&self, pid: u32) -> bool {
        self.views
            .iter()
            .filter(|view| view.pid() == pid)
            .any(|view| view.original_exited() == Ok(true))
    }

    /// Whether this view's retained original pin *proves* its process exited.
    /// A poll failure or a dropped view is not exit evidence and stays false,
    /// so an unprovable loss is never downgraded.
    fn original_exited(&self, view: ProcessViewId) -> bool {
        self.views
            .iter()
            .find(|candidate| candidate.id() == view)
            .is_some_and(|retained| retained.original_exited() == Ok(true))
    }

    fn queue_apply_outcome(
        &mut self,
        outcome: &ApplyOutcome,
        pending_views: &mut PendingViewRetirements,
    ) {
        // Both an accepted candidate and a conservative cleanup consumed the
        // retry intent they were built from; only a refusal retains it.
        if outcome.refused() {
            self.pending_rejected_keys
                .extend(outcome.newly_rejected_keys.iter().copied());
        } else {
            self.pending_rejected_keys
                .retain(|key| !outcome.newly_rejected_keys.contains(key));
        }
        for context_id in &outcome.missing_contexts {
            let Some(context) = self.loader_registry.context(*context_id) else {
                continue;
            };
            let view = context.spec.view;
            self.queue_retirement(view, RetirementCause::ExecRefresh, pending_views);
        }
        self.queue_stale_views(&outcome.stale_views, pending_views);
    }

    /// Only a *named* target's expected removal can end a capture: a cgroup
    /// capture continues when one member exits and stops only by its normal
    /// capture policy. One place decides that, so the two scopes cannot drift.
    fn arm_expected_target_exit(&mut self, view: ProcessViewId) {
        if matches!(self.scope, Scope::Pid(_)) {
            self.expected_target_exit_pending = Some(view);
        }
    }

    fn finalize_expected_target_exit(&mut self) {
        let Some(view) = self.expected_target_exit_pending else {
            return;
        };
        if self.views.is_empty()
            && self.retirement_intents.is_empty()
            && self.pending_retirements.is_empty()
            && self.pending_rejected_keys.is_empty()
            && self.loader_registry.ids_for_view(view).is_empty()
            && self.terminal_journal.is_none()
            && self.terminal_batch.is_none()
            && self.pending_discovery_records.is_empty()
        {
            self.expected_target_exit_pending = None;
            self.expected_target_exit = true;
        }
    }

    fn queue_conservative_outcome(
        &mut self,
        outcome: &ApplyOutcome,
        retirements: &BTreeSet<ProcessViewId>,
        rejected_keys: &BTreeSet<ObjectKey>,
        pending_views: &mut PendingViewRetirements,
    ) -> bool {
        self.queue_apply_outcome(outcome, pending_views);
        if !outcome.refused() {
            self.pending_retirements
                .retain(|view| !retirements.contains(view));
            self.pending_rejected_keys
                .retain(|key| !rejected_keys.contains(key));
        }
        outcome.changed
    }

    /// Applies the queued conservative retirements and rejections. That
    /// candidate only removes, so it runs with its own additions closed: a
    /// property of the candidate, not of the tick. A replay that commits
    /// cleanly leaves the caller's additions as they were. Closing the tick
    /// for it stranded every newcomer the same tick admitted, published
    /// without links, whenever an ordinary process ended (U-07). A replay
    /// that does not commit cleanly still closes the tick: one that cannot be
    /// rebuilt or applied, one that is refused or retired, and one whose
    /// failed detach leaves ownership uncertain. Either way its batch never
    /// confirms pause completeness: the caller fails the closure.
    fn replay_pending_conservative(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> ApplyOutcome {
        let retirements = self.pending_retirements.clone();
        let keys = self.pending_rejected_keys.clone();
        let candidate = match self.conservative_candidate(&retirements, &keys) {
            Ok(candidate) => candidate,
            Err(_) => {
                *additions_allowed = false;
                self.mark_partial(
                    "live discovery transaction",
                    "a pending conservative candidate could not be rebuilt and remains queued",
                );
                return ApplyOutcome::default();
            }
        };
        let mut no_additions = false;
        let outcome = match self.apply_candidate(session, candidate, &mut no_additions, false, &[])
        {
            Ok(outcome) => outcome,
            Err(_) => {
                *additions_allowed = false;
                self.mark_partial(
                    "live discovery transaction",
                    "a pending conservative candidate could not be applied and remains queued",
                );
                return ApplyOutcome::default();
            }
        };
        // The apply's own detach flag, not growth of the session's detach
        // failures: a detach that fails before any link mutation records no
        // failure there but still blocked additions (PD-T3-1).
        if !outcome.accepted() || outcome.detach_failed {
            *additions_allowed = false;
        }
        self.record_apply_timing(&outcome);
        self.queue_conservative_outcome(&outcome, &retirements, &keys, pending_views);
        outcome
    }

    /// Whether dispatching a matched EXEC for `view` would consume the owned
    /// initial prearm as an acknowledgment instead of queueing a refresh.
    /// Read-only preview of `acknowledge_owned_initial_exec` for the pressure
    /// lookahead: the same checks without consuming the one-shot prearm.
    fn owned_initial_exec_would_acknowledge(&self, view: ProcessViewId) -> bool {
        let Some(initial) = self
            .owned_initial_exec
            .filter(|initial| initial.view == view)
        else {
            return false;
        };
        initial.revalidated
            && self.counter_snapshot.ring_loss == 0
            && self.malformed_discovery == 0
            && self.discovery_truncated == 0
            && self
                .views
                .iter()
                .any(|retained| retained.id() == view && retained.still_the_same())
            && self
                .loader_registry
                .context(initial.context)
                .is_some_and(|context| {
                    context.spec.view == view
                        && context.spec.mapping.is_none()
                        && context.was_attached
                        && !self.loader_registry.is_tombstoned(initial.context)
                })
            && self.pinned.check_unchanged().unwrap_or(false)
    }

    /// Whether dispatching this queued record would consume a refresh-request
    /// map entry for a pid that has none. Renewing an already-pending pid is
    /// free. Every arm mirrors the exact dispatch condition that calls
    /// `request_refresh_consumed`, without charging loader acceptance,
    /// emitting rejection evidence or reading provider memory. The selection
    /// arm is conservative: it predicts that lowering will need the entry
    /// whenever the record is lowerable and its generation is gone, even
    /// though attribution itself may still reject the record first.
    fn record_needs_new_request(&self, queued: &QueuedDiscoveryRecord) -> bool {
        if self.refresh_requested.len() < MAX_PENDING_REFRESH {
            return false;
        }
        let record = &queued.record;
        let pid = (record.pid_tgid >> 32) as u32;
        if self.refresh_requested.contains_key(&pid) {
            return false;
        }
        match record.kind {
            DISCOVERY_KIND_EXEC => {
                if let Some((view, cause)) = self.admitted_lifecycle_match(record) {
                    cause == RetirementCause::ExecRefresh
                        && !self.owned_initial_exec_would_acknowledge(view)
                } else {
                    unmatched_exec_requests_refresh(&self.views, pid)
                }
            }
            DISCOVERY_KIND_FUNCTION_LIST_RETURN | DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN => {
                !self.views.iter().any(|view| view.pid() == pid)
            }
            DISCOVERY_KIND_LOADER => {
                self.loader_records_accepted < self.counter_snapshot.loader_hits
                    && !self.views.iter().any(|view| view.pid() == pid)
            }
            DISCOVERY_KIND_INTERFACE_RETURN => {
                queued.terminal_owner.is_none()
                    && record.return_rv == 0
                    && record.table_ptr != 0
                    && self
                        .selection_bindings
                        .get(&record.binding_id)
                        .is_some_and(|binding| {
                            !self.views.iter().any(|view| {
                                view.id() == binding.view
                                    && view.pid() == pid
                                    && view.still_the_same()
                            })
                        })
            }
            _ => false,
        }
    }

    /// Whether this record is a pressure head: the request map is full, the
    /// record would need a new entry, and this pass is allowed to service
    /// pressure. Pause-owned batches keep their bounded timing, and a tick's
    /// own leftover passes dispatch normally, so a service pass can never
    /// nest inside the tick it is servicing.
    fn pressure_head_pending(&self, queued: &QueuedDiscoveryRecord) -> bool {
        if self.pause_owned_batch || self.in_refresh_tick {
            return false;
        }
        self.record_needs_new_request(queued)
    }

    /// What a pressure service pass must leave untouched, built from every
    /// already-owned undispatched record: the parked prefix, the pending
    /// queue, the fresh records diverted behind the prefix this episode,
    /// the terminal batch and journal authority, and pause-held records.
    /// Each record protects its pid plus the owner views of the loader
    /// context, terminal owner and selection binding it names. Ownership
    /// that cannot be narrowed — an unresolvable loader context, terminal
    /// owner, journal authority or selection binding — blocks every
    /// retained context instead of guessing an owner from PID alone.
    fn pressure_protection_for(
        &self,
        parked: &[QueuedDiscoveryRecord],
        diverted: &[QueuedDiscoveryRecord],
    ) -> PressureProtection {
        let mut protection = PressureProtection::default();
        for queued in parked
            .iter()
            .chain(self.pending_discovery_records.iter())
            .chain(diverted.iter())
        {
            self.protect_queued_record(queued, &mut protection);
        }
        if let Some(batch) = self.terminal_batch.as_ref() {
            for queued in batch.records.iter() {
                self.protect_queued_record(queued, &mut protection);
            }
            if !self.protect_loader_owner(batch.authority.owner, &mut protection.pids) {
                protection.block_all = true;
            }
        }
        if let Some(journal) = self.terminal_journal
            && !self.protect_loader_owner(journal.owner, &mut protection.pids)
        {
            protection.block_all = true;
        }
        for (pid_tgid, _, _) in self.held_records.iter() {
            protection.pids.insert((pid_tgid >> 32) as u32);
        }
        protection
    }

    /// Folds one owned record's requirements into the protection: its pid,
    /// plus the owner view of any loader context, terminal owner or
    /// selection binding it names. Unresolvable ownership sets `block_all`.
    fn protect_queued_record(
        &self,
        queued: &QueuedDiscoveryRecord,
        protection: &mut PressureProtection,
    ) {
        let record = &queued.record;
        protection.pids.insert((record.pid_tgid >> 32) as u32);
        if record.kind == DISCOVERY_KIND_LOADER
            && !self.protect_loader_owner(
                LoaderContextId::from_case_id(record.case_id),
                &mut protection.pids,
            )
        {
            protection.block_all = true;
        }
        if let Some(owner) = queued.terminal_owner
            && !self.protect_loader_owner(owner, &mut protection.pids)
        {
            protection.block_all = true;
        }
        if record.kind == DISCOVERY_KIND_INTERFACE_RETURN {
            let narrowed = self
                .selection_bindings
                .get(&record.binding_id)
                .and_then(|binding| self.views.iter().find(|view| view.id() == binding.view))
                .is_some_and(|view| {
                    protection.pids.insert(view.pid());
                    true
                });
            if !narrowed {
                protection.block_all = true;
            }
        }
    }

    /// Protects the retained view owning a loader context. Reports whether
    /// the ownership narrowed to a retained view at all.
    fn protect_loader_owner(&self, context: LoaderContextId, pids: &mut BTreeSet<u32>) -> bool {
        self.loader_registry
            .context(context)
            .and_then(|context| {
                self.views
                    .iter()
                    .find(|view| view.id() == context.spec.view)
            })
            .is_some_and(|view| {
                pids.insert(view.pid());
                true
            })
    }

    /// Begins (or continues) the held head's service episode. A newly seen
    /// head snapshots at most 256 `(pid, serial, owner)` request candidates
    /// in pid order; the same head keeps its snapshot and ruled-out set so
    /// one bounded rotation spans its service opportunities.
    fn pressure_episode_begin(&mut self, head: &QueuedDiscoveryRecord) {
        let record = &head.record;
        let key = PressureHeadKey {
            pid_tgid: record.pid_tgid,
            kind: record.kind,
            case_id: record.case_id,
            hook_ts_ns: record.hook_ts_ns,
        };
        if self
            .pressure_episode
            .as_ref()
            .is_some_and(|episode| episode.head == key)
        {
            return;
        }
        self.pressure_episode = Some(PressureEpisode {
            head: key,
            snapshot: self
                .refresh_requested
                .iter()
                .map(|(pid, request)| (*pid, (request.serial, request.owner)))
                .collect(),
            ruled_out: BTreeSet::new(),
        });
    }

    /// Discards the held head's episode when the head settles (dispatch or
    /// refusal): its rotation, protection and re-park state end with it.
    fn pressure_episode_clear(&mut self) {
        self.pressure_episode = None;
        self.pressure_protection = PressureProtection::default();
        self.pressure_rotation_pending = false;
    }

    /// The next request this episode may attempt: the lowest snapshot pid
    /// not yet ruled out whose live request still carries the snapshot
    /// serial and passes the safe-service subset. Absent or renewed
    /// candidates are skipped without an attempt and never selected.
    fn pressure_select_next(&self, protection: &PressureProtection) -> Option<PressureSelection> {
        let episode = self.pressure_episode.as_ref()?;
        episode
            .snapshot
            .iter()
            .filter(|(pid, _)| !episode.ruled_out.contains(pid))
            .filter(|(pid, (serial, _))| {
                self.refresh_requested
                    .get(pid)
                    .is_some_and(|live| live.serial == *serial)
            })
            .filter(|(pid, _)| {
                self.refresh_requested
                    .get(pid)
                    .is_some_and(|live| self.pressure_request_eligible(**pid, live, protection))
            })
            .map(|(pid, (serial, _))| PressureSelection {
                pid: *pid,
                serial: *serial,
            })
            .next()
    }

    /// Whether a queued request is safe to service while the head is held:
    /// its pid and its owner's view are outside the protected set, and it
    /// falls in the conservative service subset — provably stale with no
    /// live context obligation, or a retained owner whose old contexts are
    /// already fully retired so setup finishes without dispatching later
    /// records. A live old context, selection handoff or incomplete
    /// terminal journal blocks the request for this pressure episode. Under
    /// block-all protection only provably context-free stale requests —
    /// no views at all — stay eligible.
    fn pressure_request_eligible(
        &self,
        pid: u32,
        request: &RefreshRequest,
        protection: &PressureProtection,
    ) -> bool {
        if protection.pids.contains(&pid) {
            return false;
        }
        if let Some(view) = request
            .owner
            .and_then(|owner| self.views.iter().find(|view| view.id() == owner))
            && protection.pids.contains(&view.pid())
        {
            return false;
        }
        if protection.block_all {
            return !self.views.iter().any(|view| view.pid() == pid)
                && request
                    .owner
                    .is_none_or(|owner| !self.views.iter().any(|view| view.id() == owner));
        }
        let mut views: Vec<ProcessViewId> = self
            .views
            .iter()
            .filter(|view| view.pid() == pid)
            .map(ProcessView::id)
            .collect();
        if let Some(owner) = request.owner
            && !views.contains(&owner)
            && self.views.iter().any(|view| view.id() == owner)
        {
            views.push(owner);
        }
        for view in views {
            if !self.loader_registry.ids_for_view(view).is_empty() {
                return false;
            }
            if self
                .selection_bindings
                .values()
                .any(|binding| binding.view == view)
            {
                return false;
            }
            if self.terminal_journal.is_some_and(|journal| {
                self.loader_registry
                    .context(journal.owner)
                    .is_some_and(|context| context.spec.view == view)
            }) {
                return false;
            }
        }
        true
    }

    /// Whether a pressure service pass must leave this pid's views alone:
    /// while the pass runs, and while its head episode still holds the
    /// parked prefix for another rotation opportunity.
    fn pressure_view_shielded(&self, pid: u32) -> bool {
        (self.pressure_service_active || self.pressure_rotation_pending)
            && (self.pressure_protection.block_all || self.pressure_protection.pids.contains(&pid))
    }

    fn acknowledge_owned_initial_exec(&mut self, view: ProcessViewId) -> bool {
        let Some(initial) = self
            .owned_initial_exec
            .filter(|initial| initial.view == view)
        else {
            return false;
        };
        // Consume even a refused acknowledgment. A later identity recheck
        // cannot turn a later EXEC into the original barrier handoff.
        self.owned_initial_exec = None;
        initial.revalidated
            && self.counter_snapshot.ring_loss == 0
            && self.malformed_discovery == 0
            && self.discovery_truncated == 0
            && self
                .views
                .iter()
                .any(|retained| retained.id() == view && retained.still_the_same())
            && self
                .loader_registry
                .context(initial.context)
                .is_some_and(|context| {
                    context.spec.view == view
                        && context.spec.mapping.is_none()
                        && context.was_attached
                        && !self.loader_registry.is_tombstoned(initial.context)
                })
            && self.pinned.check_unchanged().unwrap_or(false)
    }

    /// The lifecycle generation a record resolves against, after the scope
    /// admission check. Only cgroup scope filters through the admission
    /// ledger: system scope admits every pid without a membership check
    /// (the whole machine is in scope), while the ledger still counts
    /// unmatched exits as descendant gaps below. Shared by dispatch and by
    /// the pressure lookahead so both resolve the same owner.
    fn admitted_lifecycle_match(
        &self,
        record: &DiscoveryRecord,
    ) -> Option<(ProcessViewId, RetirementCause)> {
        let pid = (record.pid_tgid >> 32) as u32;
        lifecycle_retirement(&self.views, pid, record.hook_ts_ns, record.kind).filter(
            |(view, _)| {
                !matches!(self.scope, Scope::Cgroup { .. })
                    || self
                        .admitted_cgroup_views
                        .get(view)
                        .is_some_and(|admission| {
                            if record.kind == DISCOVERY_KIND_LEADER_EXIT {
                                admission.covers(record.hook_ts_ns, pid)
                            } else {
                                admission.pid == pid
                                    && self
                                        .views
                                        .iter()
                                        .find(|candidate| candidate.id() == *view)
                                        .is_some_and(ProcessView::still_the_same)
                            }
                        })
            },
        )
    }

    fn dispatch_lifecycle_record(
        &mut self,
        record: &DiscoveryRecord,
        pending_views: &mut PendingViewRetirements,
    ) -> Option<ProcessViewId> {
        let pid = (record.pid_tgid >> 32) as u32;
        if let Some((view, cause)) = self.admitted_lifecycle_match(record) {
            if record.kind == DISCOVERY_KIND_EXEC && self.acknowledge_owned_initial_exec(view) {
                // The validated prearm now also serves ordinary live loader
                // discovery. Keep the existing per-load-kind classification;
                // no new link, hit, scan or timing proof is manufactured.
                self.record_loader_arm(view, false);
                // In particular, do not request inventory retirement or put
                // this acknowledgment in exec_refresh_views: it cannot excuse
                // a mismatched loader record elsewhere in this batch.
                return None;
            }
            if record.kind == DISCOVERY_KIND_LEADER_EXIT {
                self.close_cgroup_admission(view, record.hook_ts_ns);
                if !self.admitted_cgroup_views.contains_key(&view) {
                    self.record_unmatched_cgroup_leader_exit(record);
                }
            }
            if cause == RetirementCause::ExpectedRemoval {
                self.queue_leader_exit_assessment(view);
            } else {
                if let Some(admission) = self.admitted_cgroup_views.get_mut(&view) {
                    admission.closed_ns = None;
                }
                self.request_refresh_consumed_for_view(pid, crate::attach::monotonic_ns(), view);
                self.queue_retirement(view, cause, pending_views);
            }
            if record.kind == DISCOVERY_KIND_EXEC && cause == RetirementCause::ExecRefresh {
                // A matched EXEC may have killed this view's PID-bound static
                // links. The refresh rearms them even when the rescan
                // re-accepts the same targets; removal prunes the marker.
                self.exec_rearm_views.insert(view);
            }
            (cause == RetirementCause::ExecRefresh).then_some(view)
        } else if record.kind == DISCOVERY_KIND_EXEC
            && unmatched_exec_requests_refresh(&self.views, pid)
        {
            self.request_refresh_consumed(pid, crate::attach::monotonic_ns());
            None
        } else {
            if record.kind == DISCOVERY_KIND_LEADER_EXIT {
                self.record_unmatched_cgroup_leader_exit(record);
            }
            None
        }
    }

    fn settle_deferred_loader_mismatches(
        &mut self,
        deferred_mismatches: Vec<ProcessViewId>,
        exec_refresh_views: &BTreeSet<ProcessViewId>,
    ) {
        for view in deferred_mismatches {
            if !exec_refresh_views.contains(&view) {
                self.reject_loader_record(
                    "a loader hit failed generation, mapping, identity, or hook-IP validation",
                );
            }
        }
    }

    /// Settle any pending leader-exit assessment for views about to be retired.
    ///
    /// The assessment is answered from the view's own pidfd, so once the view
    /// is dropped nothing can resolve it and `settle_terminal_drain` counts it
    /// as a link loss. A process whose whole thread group exited is the
    /// ordinary end of a capture, not a lost link, and retirement is the last
    /// point at which that can still be told apart from a leader that exited
    /// while its group kept running. Both answers are recorded here; only the
    /// unanswerable one used to reach capture end.
    fn settle_leader_exits_at_removal(&mut self, removed: impl IntoIterator<Item = ProcessViewId>) {
        for view in removed {
            if !self.pending_leader_exit_views.contains(&view) {
                continue;
            }
            let original_exited = self
                .views
                .iter()
                .find(|candidate| candidate.id() == view)
                .map_or_else(
                    || Err("retained process view is no longer available".to_string()),
                    ProcessView::original_exited,
                );
            settle_leader_exit_view(
                &mut self.pending_leader_exit_views,
                &mut self.counted_leader_exit_views,
                &mut self.task_uprobe_link_losses,
                view,
                original_exited,
            );
        }
    }

    fn queue_leader_exit_assessment(&mut self, view: ProcessViewId) {
        self.pending_leader_exit_views.insert(view);
    }

    fn settle_leader_exit_assessments(
        &mut self,
        assessments: &BTreeSet<ProcessViewId>,
        pending_views: &mut PendingViewRetirements,
        additions_allowed: &mut bool,
        closure: &mut PauseClosure,
    ) {
        for view in assessments {
            let result = self
                .views
                .iter()
                .find(|candidate| candidate.id() == *view)
                .map_or_else(
                    || Err("retained process view is no longer available".to_string()),
                    ProcessView::original_exited,
                );
            match settle_leader_exit_view(
                &mut self.pending_leader_exit_views,
                &mut self.counted_leader_exit_views,
                &mut self.task_uprobe_link_losses,
                *view,
                result,
            ) {
                LeaderExitAssessment::AlreadySettled => {}
                LeaderExitAssessment::Pending => {
                    *additions_allowed = false;
                    closure.fail();
                }
                LeaderExitAssessment::WholeGroupExit => {
                    self.queue_retirement(*view, RetirementCause::ExpectedRemoval, pending_views);
                }
                LeaderExitAssessment::LinkLoss => {
                    *additions_allowed = false;
                    closure.fail();
                    self.invalidate_causal_timing();
                    self.close_owned_selection_for_view(*view);
                    if let Some(pid) = self
                        .views
                        .iter()
                        .find(|candidate| candidate.id() == *view)
                        .map(ProcessView::pid)
                    {
                        self.clear_refresh_for_view(*view, pid);
                        // No rescan will settle this view's pending poll, and
                        // the link loss is counted separately — forget the
                        // poll rather than publishing it twice (F1).
                        self.polled_pids.remove(&pid);
                    }
                }
            }
        }
    }

    fn promote_stale_execs(&mut self, pending_views: &mut PendingViewRetirements) {
        let stale_execs: Vec<_> = pending_views
            .iter()
            .filter_map(|(view, cause)| {
                let original_current = self
                    .views
                    .iter()
                    .find(|candidate| candidate.id() == *view)
                    .is_some_and(ProcessView::still_the_same);
                (*cause == RetirementCause::ExecRefresh
                    && finalize_batch_retirement_cause(*cause, original_current)
                        == RetirementCause::GenerationLost)
                    .then_some(*view)
            })
            .collect();
        for view in stale_execs {
            self.queue_retirement(view, RetirementCause::GenerationLost, pending_views);
        }
    }

    fn dispatch_discovery_record(
        &mut self,
        queued: QueuedDiscoveryRecord,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        exec_refresh_views: &mut BTreeSet<ProcessViewId>,
        deferred_mismatches: &mut Vec<ProcessViewId>,
    ) -> Result<DiscoveryRecordOutcome> {
        let record = queued.record;
        match record.kind {
            DISCOVERY_KIND_FUNCTION_LIST_RETURN | DISCOVERY_KIND_INTERFACE_LIST_ELEMENT_RETURN => {
                self.process_export_record(&record, session, additions_allowed, pending_views)
            }
            DISCOVERY_KIND_INTERFACE_RETURN => {
                let outcome = self.process_selection_record_with_session(
                    &queued,
                    session,
                    additions_allowed,
                    pending_views,
                )?;
                // Package F: an attributed live result also lowers through
                // the shared publication path, so equivalent factory forms
                // admit the same endpoint set. Selection runs first and
                // unchanged: its attribution decides whether lowering may
                // trust this record at all, and terminal (post-exit)
                // records never validate live memory.
                let lower = matches!(outcome, DiscoveryRecordOutcome::Applied { .. })
                    && queued.terminal_owner.is_none()
                    && queued.record.return_rv == 0
                    && queued.record.table_ptr != 0;
                let lowering = if lower {
                    Some(self.process_selection_lowering(
                        &queued.record,
                        session,
                        additions_allowed,
                        pending_views,
                    )?)
                } else {
                    None
                };
                Ok(match (outcome, lowering) {
                    (
                        DiscoveryRecordOutcome::Applied {
                            changed: first,
                            required_complete: first_complete,
                        },
                        Some(DiscoveryRecordOutcome::Applied {
                            changed: second,
                            required_complete: second_complete,
                        }),
                    ) => DiscoveryRecordOutcome::applied(
                        first || second,
                        first_complete && second_complete,
                    ),
                    (DiscoveryRecordOutcome::Applied { changed, .. }, Some(_)) => {
                        DiscoveryRecordOutcome::applied(changed, false)
                    }
                    (outcome, _) => outcome,
                })
            }
            DISCOVERY_KIND_LOADER => self.process_loader_record(
                queued,
                session,
                additions_allowed,
                pending_views,
                deferred_mismatches,
            ),
            DISCOVERY_KIND_EXEC | DISCOVERY_KIND_LEADER_EXIT => {
                if let Some(view) = self.dispatch_lifecycle_record(&record, pending_views) {
                    exec_refresh_views.insert(view);
                }
                Ok(DiscoveryRecordOutcome::applied(false, true))
            }
            _ => {
                self.mark_live_loss(
                    "live discovery record",
                    "a private record carried an unknown discovery kind",
                );
                Ok(DiscoveryRecordOutcome::Rejected(
                    RecordRejection::UnknownKind,
                ))
            }
        }
    }

    /// Dispatches one queued record with the batch's exact outcome
    /// accounting. Shared by the ordinary loop and by the pressure path's
    /// explicit head refusal, so a refused head keeps the honest accounting
    /// ordinary dispatch would have recorded for it.
    #[allow(clippy::too_many_arguments)]
    fn dispatch_one_queued_record(
        &mut self,
        queued: QueuedDiscoveryRecord,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        exec_refresh_views: &mut BTreeSet<ProcessViewId>,
        deferred_mismatches: &mut Vec<ProcessViewId>,
        terminal_selection_handoffs: &mut TerminalSelectionHandoffs,
        closure: &mut PauseClosure,
        changed: &mut bool,
    ) {
        self.note_record_protection(&queued.record);
        let record = queued.record;
        let origin = (queued.record.pid_tgid >> 32) as u32;
        match self.dispatch_discovery_record(
            queued,
            session,
            additions_allowed,
            pending_views,
            exec_refresh_views,
            deferred_mismatches,
        ) {
            Ok(DiscoveryRecordOutcome::TerminalSelectionHandoff { view, owner }) => {
                terminal_selection_handoffs
                    .entry(owner.get())
                    .or_default()
                    .push(record);
                self.queue_retirement(view, RetirementCause::GenerationLost, pending_views);
            }
            Ok(outcome) => {
                *changed |= outcome.changed();
                if !outcome.required_complete() {
                    closure.fail();
                }
            }
            Err(_) => {
                closure.fail();
                if self.record_generation_ended(origin) {
                    if record_could_publish_callable_code(&record) {
                        self.invalidate_causal_timing();
                    }
                } else {
                    self.mark_live_loss(
                        "live discovery record",
                        "a structurally valid private record failed exact live resolution",
                    );
                }
            }
        }
    }

    /// Runs one selected-request service transaction with the parked
    /// prefix withheld, to free a request-map slot for a pressure head. The
    /// transaction serves only `selection`: every other request is retained
    /// with its serial and age on every exit path. Protected views are
    /// neither refreshed nor retired. The tick's collector diverts any fresh
    /// session records into `diverted` (oldest first) instead of dispatching
    /// them ahead of the parked prefix, and reports the nested operation
    /// blocked for this episode. Diverted records are charged and counted
    /// exactly once, at their first Engine accounting boundary. H1 fairness
    /// cursors are checkpointed around the transaction and restored on every
    /// exit path, fatal or not: the selected attempt is recorded in the
    /// pressure episode's own counters, never in H1 shares.
    #[allow(clippy::too_many_arguments)]
    fn pressure_service_pass(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
        protection: &PressureProtection,
        selection: PressureSelection,
        parked_len: usize,
        diverted: &mut Vec<QueuedDiscoveryRecord>,
    ) -> Result<PressureServiceOutcome> {
        let held = self
            .pending_discovery_records
            .len()
            .saturating_add(parked_len)
            .saturating_add(diverted.len());
        let allowance = DISCOVERY_HELD_CAP
            .saturating_sub(held)
            .saturating_sub(LIVE_DISCOVERY_DRAIN_QUANTUM);
        let diverted_base = diverted.len();
        let mut diverted_malformed = 0u64;
        let fairness = self.scheduler.fairness_checkpoint();
        let scans_before = self.deep_scans;
        let arms_before = self.loader_arms;
        self.pressure_service_active = true;
        self.pressure_protection.clone_from(protection);
        self.pressure_selected = Some(selection);
        self.pressure_service_passes = self.pressure_service_passes.saturating_add(1);
        let collect_inner = &mut *collect;
        let mut service_collect =
            |session: &mut dyn EngineSession| -> Result<(Vec<DiscoveryRecord>, u64)> {
                let diverted_now =
                    diverted.len().saturating_sub(diverted_base) as u64 + diverted_malformed;
                // Once this episode has diverted anything, later nested collects
                // block without pulling: the pending journal must see its whole
                // drain, and its completion waits for the post-service
                // continuation that observes the ring directly. At capacity the
                // pass likewise blocks without pulling: claiming empty would be
                // fabricated, and pulling past the shared allowance would
                // over-admit. Every nested operation retries after the parked
                // prefix is dispatched.
                if diverted_now > 0 || diverted_now >= allowance as u64 {
                    return Err(PressureOrderingBlocked.into());
                }
                match collect_inner(session) {
                    Ok((records, malformed)) if records.is_empty() && malformed == 0 => {
                        Ok((records, malformed))
                    }
                    Ok((records, malformed)) => {
                        diverted.extend(records.into_iter().map(|record| QueuedDiscoveryRecord {
                            record,
                            terminal_owner: None,
                            terminal_exports: Vec::new(),
                        }));
                        diverted_malformed = diverted_malformed.saturating_add(malformed);
                        Err(PressureOrderingBlocked.into())
                    }
                    Err(error) => match error.downcast::<IncompleteTerminalDrain>() {
                        Ok(incomplete) if incomplete.backlog || incomplete.capacity_blocked => {
                            // A genuine quantum or storage stop: the pulled
                            // prefix is consumed, so it joins the diverted
                            // stash and the nested operation stays incomplete
                            // for this episode.
                            diverted.extend(incomplete.records.into_iter().map(|record| {
                                QueuedDiscoveryRecord {
                                    record,
                                    terminal_owner: None,
                                    terminal_exports: Vec::new(),
                                }
                            }));
                            diverted_malformed =
                                diverted_malformed.saturating_add(incomplete.malformed);
                            Err(PressureOrderingBlocked.into())
                        }
                        Ok(incomplete) => Err(incomplete.into()),
                        Err(error) => Err(error),
                    },
                }
            };
        let mut empty_records = Vec::new();
        let mut tick_now = crate::attach::monotonic_ns;
        let outcome = self.refresh_inventory(
            session,
            additions_allowed,
            &mut empty_records,
            pending_views,
            &mut service_collect,
            closure,
            &mut tick_now,
        );
        self.pressure_service_active = false;
        self.pressure_selected = None;
        self.scheduler.restore_fairness(fairness);
        // Every nested pull during the pass belonged to a terminal drain, so
        // the diverted slice keeps its terminal validation: records matching
        // the pending authority dispatch as terminal hits after the parked
        // prefix instead of rejecting as ordinary records.
        if let Some(batch) = self.terminal_batch.as_ref() {
            batch.authority.tag_matching(&mut diverted[diverted_base..]);
        }
        let fresh = diverted.len().saturating_sub(diverted_base);
        self.charge_discovery_drain(fresh, diverted_malformed);
        self.record_malformed_discovery(diverted_malformed);
        if diverted_malformed != 0 {
            closure.fail();
        }
        let changed = outcome?;
        // A real attempt ran a scan, an arm or an admission, or it settled
        // the selected request (completed, or completed-then-renewed with a
        // newer serial). A quantum deferral settles nothing and scans
        // nothing; the episode rules the entry out without an attempt.
        let completed = self
            .refresh_requested
            .get(&selection.pid)
            .is_none_or(|live| live.serial != selection.serial);
        let attempted =
            completed || self.deep_scans != scans_before || self.loader_arms != arms_before;
        Ok(PressureServiceOutcome { changed, attempted })
    }

    fn process_discovery_records(
        &mut self,
        session: &mut dyn EngineSession,
        records: &mut Vec<QueuedDiscoveryRecord>,
        pending_views: &mut PendingViewRetirements,
        additions_allowed: &mut bool,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
    ) -> Result<bool> {
        self.note_discovery_held_high_water(records.len());
        // A re-parked rotation never leaks across record passes: this pass
        // sets it again only if it re-parks a head itself.
        self.pressure_rotation_pending = false;
        let mut changed = false;
        let mut named_generation_lost = false;
        let mut conservative_replay_attempted = false;
        let mut terminal_selection_handoffs = TerminalSelectionHandoffs::new();
        // Set once a service pass concludes without freeing a request slot:
        // later heads in this pass dispatch normally instead of repeating a
        // service attempt the same state just proved fruitless.
        let mut pressure_quiet = false;
        // Fresh session records diverted by service passes, oldest first.
        // They rejoin the pending queue behind every parked record.
        let mut diverted_fresh: Vec<QueuedDiscoveryRecord> = Vec::new();
        for (view, cause) in self.retirement_intents.clone() {
            pending_views
                .entry(view)
                .and_modify(|current| *current = current.merge(cause))
                .or_insert(cause);
        }
        loop {
            let mut exec_refresh_views = BTreeSet::new();
            let mut deferred_mismatches = Vec::new();
            let mut batch = std::mem::take(records).into_iter();
            while let Some(queued) = batch.next() {
                // H-1: a spent live frame dispatches nothing more. The rest
                // waits, in ring order, at the head of the next batch. Only
                // where that cannot change a verdict: no loader mismatch
                // awaits an exec later in this vector, and no record carries
                // terminal authority.
                if deferred_mismatches.is_empty()
                    && queued.terminal_owner.is_none()
                    && batch
                        .as_slice()
                        .iter()
                        .all(|rest| rest.terminal_owner.is_none())
                    && self.frame_work_exhausted()
                {
                    self.note_frame_deferral();
                    self.pending_discovery_records
                        .extend(std::iter::once(queued).chain(batch));
                    break;
                }
                // H5 pressure: at a full request map, a head that would need
                // a new entry parks with its whole suffix in original order
                // while its episode runs one selected-request service
                // transaction per opportunity. The transaction shields every
                // view the owned records name and serves only its selected
                // request; if it frees a slot the parked prefix resumes in
                // order, otherwise the episode rotates to its next eligible
                // snapshot entry on a later opportunity. When one bounded
                // rotation rules every entry out, the head is refused exactly
                // once through ordinary dispatch and the suffix advances.
                // Never a frame deferral: deferral would suppress the
                // inventory work that frees capacity.
                if !pressure_quiet && self.pressure_head_pending(&queued) {
                    if self.frame_work_exhausted() {
                        self.note_frame_deferral();
                        self.pending_discovery_records
                            .extend(std::iter::once(queued).chain(batch));
                        break;
                    }
                    let parked: Vec<QueuedDiscoveryRecord> =
                        std::iter::once(queued).chain(batch).collect();
                    self.pressure_episode_begin(&parked[0]);
                    let protection = self.pressure_protection_for(&parked, &diverted_fresh);
                    // A failed clock is a deferral condition, never a
                    // refusal: the episode waits untouched for the next
                    // opportunity instead of manufacturing queue overflow.
                    let clock_ok = crate::attach::monotonic_ns().is_some();
                    if clock_ok && let Some(selection) = self.pressure_select_next(&protection) {
                        match self.pressure_service_pass(
                            session,
                            additions_allowed,
                            pending_views,
                            collect,
                            closure,
                            &protection,
                            selection,
                            parked.len(),
                            &mut diverted_fresh,
                        ) {
                            Ok(outcome) => {
                                changed |= outcome.changed;
                                if let Some(episode) = self.pressure_episode.as_mut() {
                                    episode.ruled_out.insert(selection.pid);
                                }
                                if outcome.attempted {
                                    self.pressure_attempts =
                                        self.pressure_attempts.saturating_add(1);
                                }
                            }
                            Err(error) => {
                                // A fatal service failure keeps every
                                // undispatched record queued in ring order.
                                // The fatal entry is ruled out so a later
                                // retry never reselects it; the episode
                                // otherwise survives for that retry.
                                if let Some(episode) = self.pressure_episode.as_mut() {
                                    episode.ruled_out.insert(selection.pid);
                                }
                                self.pending_discovery_records.extend(parked);
                                self.pending_discovery_records.append(&mut diverted_fresh);
                                return Err(error);
                            }
                        }
                    }
                    self.note_discovery_held_high_water(
                        parked.len().saturating_add(diverted_fresh.len()),
                    );
                    // A service pass may have spent the frame: defer the
                    // parked prefix untouched rather than refusing work the
                    // next frame can still service.
                    if self.frame_work_exhausted() {
                        self.note_frame_deferral();
                        self.pending_discovery_records.extend(parked);
                        break;
                    }
                    if self.refresh_requested.len() < MAX_PENDING_REFRESH {
                        batch = parked.into_iter();
                        self.pressure_episode_clear();
                        continue;
                    }
                    // Rotation continues while the snapshot holds another
                    // selectable entry: the parked prefix waits in ring order
                    // for the next opportunity, with no ordinary tick behind
                    // it and retirement still shielded. A failed clock
                    // always re-parks, even with nothing selectable.
                    let protection = self.pressure_protection_for(&parked, &diverted_fresh);
                    if !clock_ok || self.pressure_select_next(&protection).is_some() {
                        self.pending_discovery_records.extend(parked);
                        self.pressure_rotation_pending = true;
                        break;
                    }
                    // One bounded rotation ruled every entry out: refuse the
                    // head exactly once. Later heads in this pass dispatch
                    // normally instead of repeating service the same state
                    // just proved fruitless.
                    pressure_quiet = true;
                    let mut parked = parked.into_iter();
                    let head = parked
                        .next()
                        .expect("a parked prefix always holds its head");
                    batch = parked;
                    self.dispatch_one_queued_record(
                        head,
                        session,
                        additions_allowed,
                        pending_views,
                        &mut exec_refresh_views,
                        &mut deferred_mismatches,
                        &mut terminal_selection_handoffs,
                        closure,
                        &mut changed,
                    );
                    self.pressure_episode_clear();
                    continue;
                }
                self.dispatch_one_queued_record(
                    queued,
                    session,
                    additions_allowed,
                    pending_views,
                    &mut exec_refresh_views,
                    &mut deferred_mismatches,
                    &mut terminal_selection_handoffs,
                    closure,
                    &mut changed,
                );
            }
            // Diverted fresh records join the pending queue behind anything
            // the frame deferred: they are newer than every parked record.
            self.pending_discovery_records.append(&mut diverted_fresh);
            self.settle_deferred_loader_mismatches(deferred_mismatches, &exec_refresh_views);
            self.promote_stale_execs(pending_views);
            if pending_views.is_empty() {
                if (self.pending_rejected_keys.is_empty() && self.pending_retirements.is_empty())
                    || conservative_replay_attempted
                {
                    break;
                }
                conservative_replay_attempted = true;
                let outcome =
                    self.replay_pending_conservative(session, additions_allowed, pending_views);
                closure.observe_apply(&outcome);
                // A batch that replays a retirement or a rejection never
                // confirms pause completeness. That verdict is the closure's
                // alone: the tick's additions stay open for unrelated
                // generations (U-07).
                closure.fail();
                changed |= outcome.changed;
                if outcome.refused() && pending_views.is_empty() {
                    break;
                }
            }
            for (view, mut cause) in std::mem::take(pending_views) {
                if let Some(next) = pending_views.remove(&view) {
                    cause = cause.merge(next);
                }
                if let Some(persistent) = self.retirement_intents.get(&view).copied() {
                    cause = cause.merge(persistent);
                }
                let Some(retained) = self.views.iter().find(|candidate| candidate.id() == view)
                else {
                    self.retirement_intents.remove(&view);
                    self.ready_expected_removals.remove(&view);
                    // Deferred reclamation: the intent was the reason this ID
                    // stayed allocated past the tick that dropped its view
                    // (`release_unadmitted_views`). With the intent settled,
                    // the ID returns to the pool when modules and pin claims
                    // do not name it — the `still_named` check minus the
                    // intent — instead of leaking one per such event. A
                    // double release is a silent no-op.
                    let still_named = self
                        .modules
                        .iter()
                        .any(|module| module.scanned.view == view)
                        || self.pinned.view_claims(view).is_some();
                    if !still_named {
                        self.release_view_id(view);
                    }
                    continue;
                };
                let retained_pid = retained.pid();
                // H5 pressure: a service pass never refreshes or retires a
                // view whose old contexts an undispatched parked record may
                // still need. The persistent intent survives this deferral
                // and retries after the parked prefix is dispatched.
                if self.pressure_view_shielded(retained_pid) {
                    continue;
                }
                // H5 pressure: a selected transaction retires only the
                // selected pid's views. Unrelated persistent intents are
                // not whole-scope work for this pass; they retry after
                // the parked prefix is dispatched.
                if self
                    .pressure_selected
                    .is_some_and(|selected| retained_pid != selected.pid)
                {
                    continue;
                }
                // A frame-budget deferral must not let EXEC refresh retire
                // a context still needed by this view's collected records.
                // The persistent intent is retried after their dispatch.
                // Exit/generation-loss retirement keeps its terminal handoff
                // path; unrelated views remain eligible for retirement.
                if cause == RetirementCause::ExecRefresh
                    && self
                        .pending_discovery_records
                        .iter()
                        .any(|queued| (queued.record.pid_tgid >> 32) as u32 == retained.pid())
                {
                    continue;
                }
                let ready = if self.ready_expected_removals.contains(&view)
                    && cause == RetirementCause::ExpectedRemoval
                {
                    Ok(true)
                } else {
                    retirement_ready(cause, retained)
                };
                match ready {
                    Ok(true) => {}
                    Ok(false) => continue,
                    Err(error) => {
                        closure.fail();
                        *additions_allowed = false;
                        self.mark_live_loss(
                            "live discovery lifecycle",
                            &format!(
                                "the original process pin could not prove expected exit; retirement remains queued: {error}"
                            ),
                        );
                        continue;
                    }
                }
                if cause == RetirementCause::ExpectedRemoval {
                    self.close_owned_selection_for_view(view);
                }
                let (retirement_changed, complete) = self.retire_loader_contexts(
                    view,
                    &mut terminal_selection_handoffs,
                    session,
                    additions_allowed,
                    pending_views,
                    collect,
                    closure,
                )?;
                if let Some(next) = pending_views.remove(&view) {
                    cause = cause.merge(next);
                }
                if let Some(persistent) = self.retirement_intents.get(&view).copied() {
                    cause = cause.merge(persistent);
                }
                named_generation_lost |=
                    cause == RetirementCause::GenerationLost && matches!(self.scope, Scope::Pid(_));
                changed |= retirement_changed;
                if !complete {
                    continue;
                }
                // Retirement can finish after a consumed EXEC failed to queue
                // its rescan. Keep that intent until a retry fits; no new
                // producer record was lost by this retry. Leave inventory
                // running so it can free capacity instead of deferring the
                // whole frame behind the full queue.
                if cause == RetirementCause::ExecRefresh
                    && !self.refresh_requested.contains_key(&retained_pid)
                {
                    if self.refresh_requested.len() >= MAX_PENDING_REFRESH {
                        continue;
                    }
                    if !self.request_refresh(retained_pid, crate::attach::monotonic_ns()) {
                        continue;
                    }
                }
                // The conservative replay this queues drops every pin the view
                // owns. That is right for a generation that is gone, and wrong
                // for an `ExecRefresh`, which keeps its view and rescans the
                // same live generation: dropping its pins re-pins the same
                // provider under a fresh ID, so a second full slot set is
                // allocated for targets that already have one.
                if cause != RetirementCause::ExecRefresh {
                    self.pending_retirements.insert(view);
                }
                self.retirement_intents.remove(&view);
                self.ready_expected_removals.remove(&view);
                if cause == RetirementCause::ExpectedRemoval {
                    self.close_cgroup_admission_at_removal(view);
                    self.settle_leader_exits_at_removal([view]);
                    let retained = self.views.len();
                    self.views.retain(|candidate| candidate.id() != view);
                    if self.views.len() != retained {
                        self.release_view_id(view);
                    }
                    self.scan_inputs.remove(&view);
                    self.arm_expected_target_exit(view);
                }
                conservative_replay_attempted = false;
            }
        }
        let refused_handoffs = std::mem::take(&mut terminal_selection_handoffs)
            .into_values()
            .flatten()
            .collect::<Vec<_>>();
        self.reject_terminal_selection_handoffs(refused_handoffs, closure);
        self.finalize_expected_target_exit();
        if named_generation_lost {
            bail!("the named process generation changed during live discovery");
        }
        Ok(changed)
    }

    fn scan_inventory_views(
        &mut self,
        views: &BTreeSet<ProcessViewId>,
        failure: &str,
        tick_now: &mut TickClock<'_>,
    ) -> InventoryScanOutcome {
        let mut scans = Vec::new();
        let mut failed_pids = BTreeSet::new();
        let mut deferred_pids = BTreeSet::new();
        let mut skipped = Vec::new();
        let ids: Vec<u32> = views.iter().map(|view| view.0).collect();
        let ordered: Vec<ProcessViewId> = self
            .scheduler
            .retained_view_order(&ids)
            .into_iter()
            .map(ProcessViewId)
            .collect();
        for (index, view_id) in ordered.iter().enumerate() {
            // The tick's deep-scan quantum stops the phase before another
            // scan: the current and remaining views defer to the next tick
            // with their refresh requests retained, never dropped. A
            // deferral is not a failure: the rescan never ran, so nothing
            // about the view itself is published, and a polling rescan
            // among them stays pending until its retry settles it (F1).
            if self.scheduler.tick_expired(tick_now()) {
                for id in &ordered[index..] {
                    if let Some(view) = self.views.iter().find(|view| view.id() == *id) {
                        deferred_pids.insert(view.pid());
                    }
                }
                let left = ordered.len() - index;
                let noun = if left == 1 { "view" } else { "views" };
                skipped.push(Skipped {
                    subject: "live discovery tick".into(),
                    reason: format!(
                        "tick deep-scan quantum exhausted; {left} refreshed {noun} deferred to the next tick"
                    ),
                });
                break;
            }
            let Some(position) = self.views.iter().position(|view| view.id() == *view_id) else {
                // A refresh set can name a view retired after the set was
                // built (stale loader context): skip it and disclose PARTIAL
                // instead of aborting the whole capture.
                let skip = Skipped {
                    subject: format!("process view {}", view_id.0),
                    reason: format!("{failure}: inventory view is no longer retained"),
                };
                self.mark_partial(&skip.subject, &skip.reason);
                skipped.push(skip);
                continue;
            };
            self.scheduler.note_retained_view_attempt(view_id.0);
            let broad_admit = self.broad_admit;
            let (scan_result, counters) = Self::scan_retained_view(
                &self.views[position],
                &self.module_hints,
                &self.hooks,
                &mut self.budget,
                broad_admit,
                &mut self.stage_timings,
            );
            self.deep_scans = self.deep_scans.saturating_add(1);
            skipped.extend(self.absorb_scan_counters(counters));
            match scan_result {
                // Completeness is intentionally unused here: refreshed
                // views are exec refreshes whose old image may be gone, so
                // absence of the old modules is expected and retention
                // would be unsound. The loader path above is where an
                // incomplete scan of a stable generation retains.
                // Replace-always is preserved: whatever the new image
                // holds replaces the old, and the rotation classifier
                // re-reads the outcome — a refreshed view with modules is
                // owned, an empty never-dirty one stays exploratory.
                Ok((modules, pins, _complete)) => {
                    self.note_scan_observed(*view_id, &modules);
                    scans.push((*view_id, modules, pins));
                }
                Err(error) => {
                    let pid = self.views[position].pid();
                    let gone = self.views[position].original_exited() == Ok(true);
                    failed_pids.insert(pid);
                    let detail = format!("{failure}: {error:#}");
                    skipped.extend(unreadable_member_skip(
                        pid,
                        gone,
                        &detail,
                        &mut self.counters.noise,
                    ));
                }
            }
        }
        (scans, failed_pids, deferred_pids, skipped)
    }

    fn inventory_candidate(
        &mut self,
        removed: &BTreeSet<ProcessViewId>,
        refreshed: &[(ProcessViewId, Vec<ScannedModule>, PinnedObjects)],
        new_views: &[(ProcessView, Vec<ScannedModule>, PinnedObjects)],
        mut skipped: Vec<Skipped>,
    ) -> Result<LiveCandidate> {
        let assemble_start = crate::attach::monotonic_ns();
        let refreshed_ids: BTreeSet<_> = refreshed.iter().map(|(view, _, _)| *view).collect();
        let mut candidate_pins = self.pinned.clone();
        for view in removed {
            candidate_pins.remove_view(*view);
        }
        let mut raw_modules: Vec<_> = self
            .modules
            .iter()
            .filter(|module| {
                !removed.contains(&module.scanned.view)
                    && !refreshed_ids.contains(&module.scanned.view)
            })
            .map(|module| module.scanned.clone())
            .collect();
        for (view, modules, pins) in refreshed {
            skipped.extend(candidate_pins.replace_view_pins(*view, pins.clone(), &[]));
            for module in modules {
                merge_scanned_module(&mut raw_modules, module.clone());
            }
        }
        for (_, modules, pins) in new_views {
            skipped.extend(candidate_pins.absorb(pins.clone()));
            for module in modules {
                merge_scanned_module(&mut raw_modules, module.clone());
            }
        }
        self.stage_timings.span(
            crate::timing::StageKind::Merge,
            "inventory_assemble",
            assemble_start,
            crate::attach::monotonic_ns(),
        );
        let mut candidate = self.live_candidate(candidate_pins, raw_modules, skipped)?;
        candidate
            .views
            .extend(new_views.iter().map(|(view, _, _)| view.id()));
        Ok(candidate)
    }

    fn inventory_candidate_admission(
        &self,
        session: &dyn EngineSession,
        candidate: &LiveCandidate,
        removed: &BTreeSet<ProcessViewId>,
        new_views: &[(ProcessView, Vec<ScannedModule>, PinnedObjects)],
    ) -> CandidateAdmission {
        let targets: Vec<_> = candidate
            .delta
            .new
            .iter()
            .chain(&candidate.delta.replace)
            .cloned()
            .collect();
        let mut required_views = candidate.views.clone();
        required_views.extend(
            self.views
                .iter()
                .filter(|view| !removed.contains(&view.id()))
                .map(ProcessView::id),
        );
        required_views.extend(new_views.iter().map(|(view, _, _)| view.id()));
        let extra_views: Vec<_> = new_views.iter().map(|(view, _, _)| view).collect();
        candidate_admission(
            &self.views,
            &extra_views,
            &required_views,
            &self.loader_registry,
            &candidate.pinned,
            &self.pinned,
            session
                .preflight_targets(&targets, &candidate.pinned)
                .is_ok(),
        )
    }

    /// Marks the view dirty when a scan (or a live record application)
    /// observed modules for it. Every scan-result observation site calls
    /// this — initial discovery, refresh rescans, new-view admissions,
    /// loader rescans, live lowering — so the dirty set is complete by
    /// construction within this file, and eviction never needs `scan.rs`
    /// internals to prove an ID evidence-free.
    fn note_scan_observed(&mut self, view: ProcessViewId, modules: &[ScannedModule]) {
        if !modules.is_empty() {
            self.exploratory_dirty.insert(view);
        }
    }

    /// Whether the retained view is pure exploratory ballast: never
    /// contributed provider evidence, contributes none now, and owns no
    /// in-flight work that eviction would strand. Every conjunct is load-
    /// bearing — a view holding modules, loader contexts, pin claims,
    /// scan inputs with modules, selection state, retirement or exit
    /// intents, queued records, or a pending refresh is authoritative or
    /// active, never exploratory. Cgroup admission-ledger entries are the
    /// one exception: they close at eviction like any other removal.
    fn exploratory_evictable(&self, id: ProcessViewId) -> bool {
        let Some(view) = self.views.iter().find(|view| view.id() == id) else {
            return false;
        };
        if !view.still_the_same() {
            return false;
        }
        if self.exploratory_dirty.contains(&id) {
            return false;
        }
        if self.modules.iter().any(|module| module.scanned.view == id) {
            return false;
        }
        if !self.loader_registry.ids_for_view(id).is_empty() {
            return false;
        }
        if self.pinned.view_claims(id).is_some_and(|claims| {
            !(claims.tables.is_empty() && claims.targets.is_empty() && claims.pins.is_empty())
        }) {
            return false;
        }
        if self
            .scan_inputs
            .get(&id)
            .is_some_and(|input| !input.modules.is_empty())
        {
            return false;
        }
        if self.retirement_intents.contains_key(&id)
            || self.pending_retirements.contains(&id)
            || self.ready_expected_removals.contains(&id)
        {
            return false;
        }
        if self.pending_loader_scans.keys().any(|key| key.view == id) {
            return false;
        }
        let pid = view.pid();
        if self
            .pending_discovery_records
            .iter()
            .any(|queued| (queued.record.pid_tgid >> 32) as u32 == pid)
        {
            return false;
        }
        if self.refresh_requested.contains_key(&pid) {
            return false;
        }
        if self.pending_leader_exit_views.contains(&id)
            || self.counted_leader_exit_views.contains(&id)
        {
            return false;
        }
        if self.expected_target_exit_pending == Some(id) {
            return false;
        }
        if self.selection_claims.keys().any(|key| key.view == id)
            || self.selection_tables.keys().any(|key| key.view == id)
            || self
                .selection_bindings
                .values()
                .any(|binding| binding.view == id)
        {
            return false;
        }
        if self
            .unmatched_leader_exit_events
            .iter()
            .any(|(event_pid, _)| *event_pid == pid)
        {
            return false;
        }
        true
    }

    /// Evictable views in deterministic rotation order: lowest pid first
    /// (view ID breaks ties). Admission prefers the lowest unscanned pid
    /// within a rarity class, and evicted pids cool down before
    /// re-selection, so lowest-first eviction plus the cooldown walks the
    /// whole unscanned set forward instead of churning one subset.
    fn exploratory_evictable_views(&self) -> Vec<ProcessViewId> {
        let mut victims: Vec<(u32, ProcessViewId)> = self
            .views
            .iter()
            .filter(|view| self.exploratory_evictable(view.id()))
            .map(|view| (view.pid(), view.id()))
            .collect();
        victims.sort();
        victims.into_iter().map(|(_, id)| id).collect()
    }

    /// One polling round over the enumerated pids (sorted ascending): queue
    /// a bounded number of retained exploratory views — in poll-cursor
    /// order, so the cursor round-robins them — for a same-tick refresh
    /// rescan through the normal replace-always path. Unarmed views would
    /// otherwise never re-scan a process that gains a provider; a found
    /// provider upgrades the view to owned and arms it then. Already-
    /// requested pids are skipped, so event-driven work is never
    /// double-queued. Polling can only add coverage (its targets hold
    /// nothing), never flap owned modules — owned views rely on
    /// event-driven refresh instead. `pids` must be sorted ascending.
    fn queue_polling_rescans(&mut self, pids: &[u32]) {
        // H5 pressure: a service pass services already-accepted requests; it
        // never queues optional polls, which would only consume the capacity
        // it is trying to free (and set a frame deferral at a full map).
        if self.pressure_service_active {
            return;
        }
        let mut polling = 0;
        let mut last_queued = None;
        for pid in self.scheduler.poll_order(pids) {
            if polling >= MAX_POLLING_RESCANS {
                break;
            }
            if self.refresh_requested.contains_key(&pid) {
                continue;
            }
            let retained_exploratory = self
                .views
                .iter()
                .any(|view| view.pid() == pid && self.exploratory_evictable(view.id()));
            if !retained_exploratory {
                continue;
            }
            // Optional polls wait for queue capacity; no producer record was
            // dropped. Keep the cursor after the last admitted poll so this
            // candidate gets its turn when capacity becomes available.
            if self.refresh_requested.len() >= MAX_PENDING_REFRESH {
                self.note_frame_deferral();
                break;
            }
            if self.request_refresh(pid, crate::attach::monotonic_ns()) {
                polling += 1;
                last_queued = Some(pid);
                self.polled_pids.insert(pid);
            }
        }
        if let Some(last) = last_queued {
            self.scheduler.advance_poll_cursor(last);
        }
        // Queuing a poll is not a loss (F1): the rescan either finds the
        // process still provider-free (nothing lost) or finds a provider it
        // gained unwatched, which the scan result publishes precisely.
        self.polling_rescans_queued = self.polling_rescans_queued.saturating_add(polling as u64);
    }

    /// Settles the polling rescans among `scans` (F1): a provider found in a
    /// polled, unarmed view is the one loss polling can reveal, published
    /// once per round; a poll that found nothing publishes nothing. A poll
    /// whose rescan failed was already published by the refresh-failure
    /// path, and a poll whose view retired before its rescan has nothing
    /// left to settle, so both are forgotten, never published here. A poll
    /// the tick quantum deferred never ran, so it stays pending until its
    /// retry settles it — that is why `failed_pids` carries true failures
    /// only, not quantum deferrals.
    fn settle_polling_rescans(
        &mut self,
        scans: &[InventoryScan],
        failed_pids: &BTreeSet<u32>,
        removed: &BTreeSet<ProcessViewId>,
    ) {
        let mut gained = false;
        for (view, modules, _) in scans {
            let Some(pid) = self
                .views
                .iter()
                .find(|candidate| candidate.id() == *view)
                .map(ProcessView::pid)
            else {
                continue;
            };
            if self.polled_pids.remove(&pid) && !modules.is_empty() {
                gained = true;
            }
        }
        for pid in failed_pids {
            self.polled_pids.remove(pid);
        }
        for view in removed {
            if let Some(pid) = self
                .views
                .iter()
                .find(|candidate| candidate.id() == *view)
                .map(ProcessView::pid)
            {
                self.polled_pids.remove(&pid);
            }
        }
        if gained {
            self.mark_live_loss("live discovery rotation", POLLED_PROVIDER_LOSS);
        }
        let retained: BTreeSet<u32> = self.views.iter().map(ProcessView::pid).collect();
        self.polled_pids.retain(|pid| retained.contains(pid));
    }

    /// Evicts exploratory views outside the retirement transaction: by the
    /// classifier they hold no modules, contexts, claims, or queued work,
    /// so there is nothing to retire — removal drops the view, its pins
    /// (shared objects survive via their other owners in `remove_view`),
    /// its view-scoped scan inputs, and its non-authoritative loader-arm
    /// classifications, then frees the ID for the newcomer admitted into
    /// the freed slot. Admission-ledger and leader-exit settlement mirror
    /// the transaction tail. Categorical evidence only: counts, never pids.
    fn evict_exploratory_views(&mut self, victims: &BTreeSet<ProcessViewId>) {
        let victims: BTreeSet<ProcessViewId> = victims
            .iter()
            .copied()
            .filter(|id| self.exploratory_evictable(*id))
            .collect();
        if victims.is_empty() {
            return;
        }
        for id in &victims {
            if let Some(view) = self.views.iter().find(|view| view.id() == *id) {
                self.scheduler.note_evicted(view.pid());
            }
        }
        self.close_cgroup_admissions_at_removal(&victims);
        self.settle_leader_exits_at_removal(victims.iter().copied());
        for id in &victims {
            self.pinned.remove_view(*id);
            self.scan_inputs.remove(id);
        }
        self.loader_contexts
            .retain(|(view, _, _), _| !victims.contains(view));
        self.views.retain(|view| !victims.contains(&view.id()));
        for id in &victims {
            self.release_view_id(*id);
        }
        self.exploratory_evictions = self
            .exploratory_evictions
            .saturating_add(victims.len() as u64);
        let max_scan_pids = self.max_scan_pids;
        let noun = if victims.len() == 1 { "view" } else { "views" };
        self.mark_partial(
            "live discovery rotation",
            &format!(
                "exploratory rotation evicted {} provider-free process {noun} to reach unscanned processes (limit {max_scan_pids})",
                victims.len()
            ),
        );
    }

    /// Over-cap candidate selection without a full maps sweep (Task 3.1b).
    /// Ordinary passes serve event-driven refresh requests plus a
    /// fairness-rotation window over unscanned pids — no maps reads, so no
    /// budget charge — and defer the rest to the reconciliation sweep with
    /// an exact categorical gap. Every Nth over-cap pass reconciles: one
    /// bounded maps slice after the cursor (wall-time quantum, generation
    /// revalidation of covered retained views) with rarity-ordered
    /// admission inside the slice. Retained views are always desired;
    /// ordinary rotation only fills free view slots and never displaces,
    /// while reconcile passes rotate exploratory (never-owned, currently
    /// empty) views to reach unscanned processes within a finite bound.
    fn select_over_cap_desired(&mut self, pids: &[u32]) -> BTreeSet<u32> {
        let known: BTreeSet<u32> = self.views.iter().map(|view| view.pid()).collect();
        let enumerated: BTreeSet<u32> = pids.iter().copied().collect();
        let pending: BTreeSet<u32> = enumerated
            .iter()
            .copied()
            .filter(|pid| self.refresh_requested.contains_key(pid))
            .collect();
        let mut desired = known.clone();
        desired.extend(pending.iter().copied());
        let max_scan_pids = self.max_scan_pids;
        let subject = scope_label(&self.scope);
        match self.scheduler.begin_over_cap_pass() {
            InventoryCadence::Ordinary => {
                // Cooling pids sit out the rotation window (queued refresh
                // requests for them still join `desired` via `pending`).
                let exclude: BTreeSet<u32> = known
                    .union(&pending)
                    .copied()
                    .chain(
                        pids.iter()
                            .copied()
                            .filter(|pid| self.scheduler.cooling_down(*pid)),
                    )
                    .collect();
                let free_slots = max_scan_pids.saturating_sub(self.views.len());
                let window = DiscoveryScheduler::rotation_window(pids, &exclude, free_slots);
                desired.extend(window.iter().copied());
                let fresh = desired.iter().filter(|pid| !known.contains(pid)).count();
                let retained = known.intersection(&enumerated).count();
                let deferred = enumerated
                    .len()
                    .saturating_sub(retained)
                    .saturating_sub(fresh);
                if deferred > 0 {
                    self.mark_partial(
                        &subject,
                        &format!(
                            "{} processes in scope; live discovery deferred {deferred} unscanned processes to the periodic reconciliation sweep (limit {max_scan_pids})",
                            enumerated.len()
                        ),
                    );
                }
                desired
            }
            InventoryCadence::Reconcile => {
                // Exploratory rotation: the slice selects into the free
                // slots plus a bounded number of evictable views, then only
                // as many victims as the selection actually needs are
                // evicted. Ordinary passes never reach this arm, so ticks
                // outside reconciliation still displace nothing.
                let free_slots = max_scan_pids.saturating_sub(self.views.len());
                let evictable = self.exploratory_evictable_views();
                let evict_budget = evictable.len().min(self.scheduler.max_evictions_per_pass());
                let selected = self.reconcile_slice(pids, &known, free_slots + evict_budget);
                let need = selected.len().saturating_sub(free_slots);
                let victims: BTreeSet<ProcessViewId> = evictable.into_iter().take(need).collect();
                // Evicted pids leave the desired set with their views: they
                // were desired as retained views, and re-selecting them as
                // newcomers in the same tick would evict-and-readmit
                // without ever reaching the selected set. They rejoin
                // eligibility when their cooldown expires.
                let victim_pids: BTreeSet<u32> = victims
                    .iter()
                    .filter_map(|id| {
                        self.views
                            .iter()
                            .find(|view| view.id() == *id)
                            .map(|view| view.pid())
                    })
                    .collect();
                self.evict_exploratory_views(&victims);
                // Polling runs after eviction so victims are never polled.
                // `scope_pids` guarantees pid order for the poll cursor.
                self.queue_polling_rescans(pids);
                desired.extend(selected.iter().copied());
                desired.retain(|pid| !victim_pids.contains(pid));
                let fresh = desired.iter().filter(|pid| !known.contains(pid)).count();
                self.mark_partial(
                    &subject,
                    &scan_cap_reason(enumerated.len(), fresh, max_scan_pids, true),
                );
                let cooling = self.scheduler.cooling_len();
                if cooling > 0 {
                    let (noun, verb) = if cooling == 1 {
                        ("process", "is")
                    } else {
                        ("processes", "are")
                    };
                    self.mark_partial(
                        "live discovery rotation",
                        &format!(
                            "{cooling} unscanned {noun} {verb} cooling down after exploratory rotation"
                        ),
                    );
                }
                desired
            }
        }
    }

    /// One bounded reconciliation slice: re-read maps for the next slice of
    /// pids after the cursor (wrapping), stopping at the wall-time quantum.
    /// Retained views covered by the slice are generation-revalidated;
    /// eligible unscanned slice pids (cooling-down pids sit out) are
    /// rarity-ordered into the free view slots plus the bounded eviction
    /// allowance the caller folded in.
    /// Returns the selected new pids. The cursor advances past the last pid
    /// read; an incomplete slice publishes its exact coverage gap. Slice
    /// maps bytes are re-read every sweep, never served from a cache: only
    /// stable file-derived facts (pin-keyed ELF/inspection entries) are
    /// cached, never mappings or heap content.
    fn reconcile_slice(
        &mut self,
        pids: &[u32],
        known: &BTreeSet<u32>,
        free_slots: usize,
    ) -> Vec<u32> {
        let quantum_ns = self.scheduler.quantum_ns();
        let slice_pids = self.scheduler.slice_pids();
        let order = DiscoveryScheduler::rotated_after(pids, self.scheduler.cursor());
        let start = crate::attach::monotonic_ns();
        let mut slice = MapsSweep::default();
        let mut bufs = MapsReadBuffers::default();
        let mut revalidated = 0u64;
        let mut quantum_stopped = false;
        let mut clock_failed = start.is_none();
        for pid in order.into_iter().take(slice_pids) {
            let elapsed = match (start, crate::attach::monotonic_ns()) {
                (Some(start), Some(now)) => now.saturating_sub(start),
                // No clock, no unbounded slice: defer rather than run blind.
                _ => {
                    clock_failed = true;
                    quantum_ns
                }
            };
            if elapsed >= quantum_ns {
                quantum_stopped = true;
                break;
            }
            if known.contains(&pid)
                && self
                    .views
                    .iter()
                    .filter(|view| view.pid() == pid)
                    .all(|view| view.still_the_same())
            {
                revalidated = revalidated.saturating_add(1);
            }
            let result = std::fs::File::open(format!("/proc/{pid}/maps"))
                .map_err(|error| error.to_string())
                .and_then(|maps| {
                    read_maps_or_refuse_with_buffers(
                        maps,
                        &mut self.budget,
                        crate::attach::monotonic_ns,
                        &mut bufs,
                    )
                });
            slice.record(pid, result);
            self.scheduler.advance_cursor(pid);
        }
        let attempted = slice.attempted();
        let read = slice.read();
        let (slice, unavailable) = slice.into_selection();
        if let Some(skipped) = unavailable {
            self.mark_partial(&skipped.subject, &skipped.reason);
        }
        let enumerated = pids.len();
        if attempted < enumerated {
            let left = enumerated.saturating_sub(attempted);
            let tail = if clock_failed {
                format!("wall clock unavailable, {left} deferred to the next sweep")
            } else if quantum_stopped {
                format!("wall-time quantum exhausted, {left} deferred to the next sweep")
            } else {
                format!("{left} deferred to the next sweep")
            };
            let subject = scope_label(&self.scope);
            self.mark_partial(
                &subject,
                &format!(
                    "reconciliation sweep covered {read} of {enumerated} observed processes and revalidated {revalidated} retained generations; {tail}"
                ),
            );
        }
        // Cooling pids were read (and revalidated when retained) but sit
        // out selection until their cooldown expires, so rotation walks
        // forward instead of churning. Queued refresh requests for them
        // rejoin through the pending set in the caller. Cooled-but-stale
        // pids stay in the pool and sort behind never-evicted pids within
        // their rarity class (fairness tier), so every pid is covered.
        let pool: Vec<(u32, Vec<MapEntry>)> = slice
            .into_iter()
            .filter(|(pid, _)| !known.contains(pid) && !self.scheduler.cooling_down(*pid))
            .collect();
        let stale: BTreeSet<u32> = self.scheduler.stale_pids().into_iter().collect();
        select_rotation_candidates(&pool, free_slots, &stale)
    }

    /// Admits one tick's newcomer window: opens, scans, and stages each
    /// admitted pid as an inventory new view. The tick quantum stops
    /// admissions before another scan — the current pid and the rest defer
    /// with their requests retained, never dropped. Returns the staged new
    /// views, the pids to keep queued (failures and deferrals alike), and
    /// the tick's skips. Extracted verbatim from the inventory tick so an
    /// injected clock can expire mid-path; production behavior is unchanged.
    fn admit_inventory_new_views(
        &mut self,
        admitted: Vec<u32>,
        max_scan_pids: usize,
        tick_now: &mut TickClock<'_>,
    ) -> (Vec<InventoryNewView>, BTreeSet<u32>, Vec<Skipped>) {
        let mut new_views = Vec::new();
        let mut failed_refresh_pids = BTreeSet::new();
        let mut skipped = Vec::new();
        let mut unprocessed = admitted.into_iter();
        while let Some(pid) = unprocessed.next() {
            // The tick quantum stops admissions before another scan: this
            // pid and the rest defer with their requests retained.
            if self.scheduler.tick_expired(tick_now()) {
                failed_refresh_pids.insert(pid);
                failed_refresh_pids.extend(unprocessed);
                skipped.push(Skipped {
                    subject: "live discovery tick".into(),
                    reason: "tick deep-scan quantum exhausted; remaining new processes deferred to the next tick"
                        .into(),
                });
                break;
            }
            let id = match self.allocate_view_id() {
                Ok(id) => id,
                Err(_) => {
                    skipped.push(Skipped {
                        subject: "process view".into(),
                        reason: format!(
                            "capture process-view capacity {max_scan_pids} was exhausted; remaining generations were not scanned"
                        ),
                    });
                    // Exhaustion drops nothing: the unprocessed pids stay
                    // queued (bounded) so a later pass with a free slot
                    // serves them instead of losing event-driven work.
                    failed_refresh_pids.insert(pid);
                    failed_refresh_pids.extend(unprocessed);
                    break;
                }
            };
            self.scheduler.note_new_view_attempt(pid);
            let open_start = crate::attach::monotonic_ns();
            let opened = ProcessView::open(id, pid);
            self.stage_timings.span(
                crate::timing::StageKind::Scan,
                "open_view",
                open_start,
                crate::attach::monotonic_ns(),
            );
            let view = match opened {
                Ok(view) => view,
                Err(error) => {
                    // Allocated but never admitted: the ID returns to
                    // the pool instead of burning for the capture lifetime.
                    self.release_view_id(id);
                    failed_refresh_pids.insert(pid);
                    skipped.extend(unreadable_member_skip(
                        pid,
                        process::generation_gone(pid),
                        &format!("the process generation could not be retained: {error}"),
                        &mut self.counters.noise,
                    ));
                    continue;
                }
            };
            let broad_admit = self.broad_admit;
            let (scan_result, counters) = Self::scan_retained_view(
                &view,
                &self.module_hints,
                &self.hooks,
                &mut self.budget,
                broad_admit,
                &mut self.stage_timings,
            );
            self.deep_scans = self.deep_scans.saturating_add(1);
            skipped.extend(self.absorb_scan_counters(counters));
            match scan_result {
                // Completeness is intentionally unused here: a new view has
                // no retained modules, so a partial first scan simply
                // attaches what it verified with the skips as evidence.
                Ok((modules, pins, _complete)) => {
                    self.note_scan_observed(view.id(), &modules);
                    self.scheduler.note_admitted(pid);
                    new_views.push((view, modules, pins));
                }
                Err(error) => {
                    // Allocated but never admitted: the failed scan drops
                    // this view, so its ID returns to the pool.
                    self.release_view_id(view.id());
                    failed_refresh_pids.insert(pid);
                    skipped.extend(unreadable_member_skip(
                        pid,
                        view.original_exited() == Ok(true),
                        &format!("the process generation could not be scanned: {error:#}"),
                        &mut self.counters.noise,
                    ));
                }
            }
        }
        (new_views, failed_refresh_pids, skipped)
    }

    /// One inventory tick. Every process view the tick opens waits in
    /// `new_views` until an accepted candidate moves it into `self.views`,
    /// and the tick has many earlier ways out: preflight refusals, stale
    /// generations, queued retirements, a refused apply, and every `?`.
    /// Whatever is still waiting when the tick returns was never admitted;
    /// it is settled here, once, whichever exit was taken (U-11).
    #[allow(clippy::too_many_arguments)]
    fn refresh_inventory(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        records: &mut Vec<QueuedDiscoveryRecord>,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
        tick_now: &mut TickClock<'_>,
    ) -> Result<bool> {
        let mut new_views = Vec::new();
        self.in_refresh_tick = true;
        let result = self.refresh_inventory_inner(
            session,
            additions_allowed,
            records,
            pending_views,
            collect,
            closure,
            &mut new_views,
            tick_now,
        );
        self.in_refresh_tick = false;
        self.release_unadmitted_views(new_views);
        result
    }

    /// Returns the IDs of views a tick opened but never admitted. Such a view
    /// is normally named by nothing else: an apply that does not retain a
    /// newcomer commits none of its modules or pin claims either (U-07). A
    /// record pass that fails after `queue_apply_outcome` can still leave a
    /// lost newcomer's retirement intent behind. Any ID that engine state
    /// still names stays allocated: a later generation that reused one would
    /// inherit the old one's modules, claims, or retirement.
    fn release_unadmitted_views(&mut self, views: Vec<InventoryNewView>) {
        for (view, _, _) in views {
            let id = view.id();
            let still_named = self.modules.iter().any(|module| module.scanned.view == id)
                || self.pinned.view_claims(id).is_some()
                || self.retirement_intents.contains_key(&id);
            if !still_named {
                self.release_view_id(id);
            }
        }
    }

    /// The tick itself. `refresh_inventory` owns `new_views` across its exits.
    #[allow(clippy::too_many_arguments)]
    fn refresh_inventory_inner(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        records: &mut Vec<QueuedDiscoveryRecord>,
        pending_views: &mut PendingViewRetirements,
        collect: &mut DiscoveryCollector<'_>,
        closure: &mut PauseClosure,
        new_views: &mut Vec<InventoryNewView>,
        tick_now: &mut TickClock<'_>,
    ) -> Result<bool> {
        if matches!(self.scope, Scope::Pid(_)) {
            let mut stale: BTreeSet<_> = self
                .views
                .iter()
                .filter(|view| !view.still_the_same())
                .map(ProcessView::id)
                .collect();
            // `still_the_same()` is false for a generation that was lost and
            // for one that merely ended. An already-recorded `ExpectedRemoval`
            // intent settles it, but the `LEADER_EXIT` record that records one
            // is still in the ring while the retained pin is already readable —
            // so ask the pin too, the same stronger authority `queue_retirement`
            // uses. Loss stays loss whenever exit cannot be proven.
            let expected: Vec<_> = stale
                .iter()
                .copied()
                .filter(|view| {
                    self.retirement_intents.get(view) == Some(&RetirementCause::ExpectedRemoval)
                        || self.original_exited(*view)
                })
                .collect();
            for view in expected {
                stale.remove(&view);
                self.queue_retirement(view, RetirementCause::ExpectedRemoval, pending_views);
            }
            if !pending_views.is_empty() {
                let _ = self.process_discovery_records(
                    session,
                    records,
                    pending_views,
                    additions_allowed,
                    collect,
                    closure,
                )?;
            }
            if self.expected_target_exit && self.views.is_empty() {
                return Ok(false);
            }
            if !stale.is_empty() {
                self.queue_stale_views(&stale, pending_views);
                let _ = self.process_discovery_records(
                    session,
                    records,
                    pending_views,
                    additions_allowed,
                    collect,
                    closure,
                )?;
                bail!("the named process generation changed during capture");
            }
            if self.views.is_empty() {
                bail!("the named process generation is no longer retained");
            }
            if self.refresh_requested.is_empty() {
                return Ok(false);
            }
        }
        let enumerate_start = crate::attach::monotonic_ns();
        let (pids, mut skipped) = scope_pids(&self.scope);
        let max_scan_pids = self.max_scan_pids;
        let membership_complete = skipped.is_empty() && pids.len() <= max_scan_pids;
        let enumerated = pids.len();
        let over_cap = enumerated > max_scan_pids;
        // Staleness tracks the live scope: departed pids prune every tick,
        // which is what bounds the map (a reappearing pid is PID reuse, a
        // new generation, correctly fresh).
        let live: BTreeSet<u32> = pids.iter().copied().collect();
        self.scheduler.prune_stale_to_enumerated(&live);
        // Newcomer arrival marks track the same live scope: a departed pid's
        // mark is arrival evidence for a generation that can never arrive.
        self.newcomer_first_seen.retain(|pid, _| live.contains(pid));
        // Ordinary ticks never sweep maps: over the cap the scheduler serves
        // queued event-driven work plus a fairness-rotation window, and only
        // the slower reconciliation pass re-reads one bounded slice (Task
        // 3.1b). Under the cap selection is the identity, so no sweep runs
        // there; over the cap membership is not authoritative, so narrowing
        // `desired` only narrows which new pids get deep-scanned. A zero cap
        // short-circuits to empty: selection could only ever take nothing,
        // so the sweep reads are skipped outright.
        let desired: BTreeSet<_> = if let Some(selected) = self.pressure_selected {
            // Selected transaction: serve only the selected pid. No polling
            // round, no over-cap reconcile turn, no sweep: the pass neither
            // reads maps beyond this enumeration nor advances any scheduler
            // cursor of its own (H1 accounting is checkpointed around it).
            if pids.contains(&selected.pid) {
                BTreeSet::from([selected.pid])
            } else {
                BTreeSet::new()
            }
        } else if max_scan_pids == 0 {
            BTreeSet::new()
        } else if pids.len() > max_scan_pids {
            self.select_over_cap_desired(&pids)
        } else {
            // Under-cap polling round, every fourth under-cap tick: retained
            // exploratory views carry no loader context, so without this a
            // process that gains a provider while the capture sits under the
            // cap would never re-scan. Queued here so the requests flow into
            // `refreshed` below and are served same-tick. The zero cap
            // short-circuits above and never polls. `scope_pids` guarantees
            // pid order for the poll cursor.
            if self.scheduler.begin_under_cap_tick() {
                self.queue_polling_rescans(&pids);
            }
            pids.into_iter().collect()
        };
        // Only new candidates count: known views are retained, not selected.
        // The zero-cap short-circuit keeps its exact historical skip; the
        // scheduler publishes the ordinary/reconcile gaps itself.
        if over_cap && max_scan_pids == 0 {
            skipped.push(Skipped {
                subject: scope_label(&self.scope),
                reason: scan_cap_reason(enumerated, 0, max_scan_pids, true),
            });
        }
        // A complete /proc sweep is authoritative membership for system scope
        // exactly as a complete cgroup walk is for cgroup scope: a retained
        // view whose pid is absent has departed. Over the cap or with skips,
        // neither scope claims authority.
        let membership_authoritative = membership_complete && self.admits_generations();
        let serviced_requests = self.refresh_request_snapshot();
        // H5 pressure: a service pass retains every request except its
        // selected one with serials and ages on every exit path, including
        // the empty-tick early return below. Only the selected request may
        // complete; unrelated requests are never cleared.
        let mut failed_refresh_pids: BTreeSet<u32> = BTreeSet::new();
        if self.pressure_service_active {
            let selected = self.pressure_selected.map(|selection| selection.pid);
            failed_refresh_pids.extend(
                self.refresh_requested
                    .keys()
                    .filter(|pid| Some(**pid) != selected)
                    .copied(),
            );
        }
        let retirement_causes: BTreeMap<_, _> = self
            .views
            .iter()
            .filter_map(|view| {
                // H5 pressure: a view the owned records name gets no cause
                // in a service pass — neither refreshed nor retired — and a
                // selected transaction scopes causes to the selected pid.
                if self.pressure_view_shielded(view.pid()) {
                    return None;
                }
                if self
                    .pressure_selected
                    .is_some_and(|selected| view.pid() != selected.pid)
                {
                    return None;
                }
                inventory_retirement_cause(
                    view.still_the_same(),
                    membership_authoritative,
                    desired.contains(&view.pid()),
                    self.refresh_requested.contains_key(&view.pid()),
                )
                .map(|cause| (view.id(), cause))
            })
            .collect();
        let stale: BTreeSet<_> = retirement_causes
            .iter()
            .filter_map(|(view, (cause, _))| {
                (*cause == RetirementCause::GenerationLost).then_some(*view)
            })
            .collect();
        let departed: BTreeSet<_> = retirement_causes
            .iter()
            .filter_map(|(view, (cause, ready))| {
                (*cause == RetirementCause::ExpectedRemoval && *ready).then_some(*view)
            })
            .collect();
        let mut removed: BTreeSet<_> = stale.union(&departed).copied().collect();
        let refreshed: BTreeSet<_> = retirement_causes
            .iter()
            .filter_map(|(view, (cause, _))| {
                (*cause == RetirementCause::ExecRefresh).then_some(*view)
            })
            .collect();
        let known_pids: BTreeSet<_> = self
            .views
            .iter()
            .filter(|view| !removed.contains(&view.id()))
            .map(ProcessView::pid)
            .collect();
        let new_pids: Vec<_> = desired.difference(&known_pids).copied().collect();
        self.stage_timings.span(
            crate::timing::StageKind::Scan,
            "inventory_enumerate",
            enumerate_start,
            crate::attach::monotonic_ns(),
        );
        if removed.is_empty() && refreshed.is_empty() && new_pids.is_empty() {
            self.complete_refresh_requests(&serviced_requests, &failed_refresh_pids);
            // No tick queued anything (a queued poll would have made a
            // retirement cause), so any pending poll is stale: forget it
            // with the requests rather than leaking it into a later tick.
            // A selected transaction never touches ordinary polls: it
            // queued none and settles none.
            if self.pressure_selected.is_none() {
                self.polled_pids.clear();
            }
            for skip in skipped {
                self.mark_partial(&skip.subject, &skip.reason);
            }
            return Ok(false);
        }

        // The tick's deep-scan phase starts here: refreshed rescans plus
        // new-view admissions share one wall-time quantum and one admission
        // count bound. Direct scan calls outside this tick stay unbounded.
        self.scheduler.begin_deep_scan_tick(tick_now());
        // Per-tick admission bound: rotate past the last attempted newcomer
        // before selecting this tick's window. Failed opens/scans must not
        // consume the same first window forever and starve later processes.
        // Deferred requests and their explicit evidence are retained.
        let max_new_views = self.scheduler.max_new_views_per_tick();
        let mut new_pids = self.scheduler.new_view_order(&new_pids).into_iter();
        let admitted: Vec<u32> = new_pids.by_ref().take(max_new_views).collect();
        let deferred: Vec<u32> = new_pids.collect();
        // Arrival marks in processing order (first diff wins; the admitted
        // window marks first so cap pressure lands on the deferred tail).
        let arrival_now = crate::attach::monotonic_ns();
        for pid in admitted.iter().chain(deferred.iter()) {
            self.mark_newcomer_arrival(*pid, arrival_now);
        }
        failed_refresh_pids.extend(deferred.iter().copied());
        if !deferred.is_empty() {
            let pending = admitted.len() + deferred.len();
            let noun = if pending == 1 { "process" } else { "processes" };
            skipped.push(Skipped {
                subject: "live discovery tick".into(),
                reason: format!(
                    "{pending} new {noun} pending; tick admitted {} for deep scanning (tick limit {max_new_views})",
                    admitted.len()
                ),
            });
        }
        let newcomers_first = self
            .scheduler
            .newcomers_first(!refreshed.is_empty(), !admitted.is_empty());
        let (refresh_outcome, admission_outcome) = if newcomers_first {
            let admission = self.admit_inventory_new_views(admitted, max_scan_pids, &mut *tick_now);
            let refresh = self.scan_inventory_views(
                &refreshed,
                "a requested inventory refresh failed",
                &mut *tick_now,
            );
            (refresh, admission)
        } else {
            let refresh = self.scan_inventory_views(
                &refreshed,
                "a requested inventory refresh failed",
                &mut *tick_now,
            );
            let admission = self.admit_inventory_new_views(admitted, max_scan_pids, &mut *tick_now);
            (refresh, admission)
        };
        let (mut refreshed_scans, failed_scan_pids, deferred_scan_pids, refresh_skips) =
            refresh_outcome;
        failed_refresh_pids.extend(failed_scan_pids.iter().copied());
        failed_refresh_pids.extend(deferred_scan_pids);
        skipped.extend(refresh_skips);
        self.settle_polling_rescans(&refreshed_scans, &failed_scan_pids, &removed);
        let (admitted_views, failed_admission_pids, admission_skips) = admission_outcome;
        new_views.extend(admitted_views);
        failed_refresh_pids.extend(failed_admission_pids);
        skipped.extend(admission_skips);

        for (view, _, _) in new_views.iter() {
            if !view.still_the_same() {
                skipped.push(Skipped {
                    subject: "process view".into(),
                    reason: STALE_VIEW_REASON.into(),
                });
            }
        }
        let new_view_pids: BTreeSet<_> = new_views.iter().map(|(view, _, _)| view.pid()).collect();
        let mut deferred_new_view_records = Vec::new();
        let mut refreshed_ok: BTreeSet<_> =
            refreshed_scans.iter().map(|(view, _, _)| *view).collect();
        let candidate =
            self.inventory_candidate(&removed, &refreshed_scans, new_views, skipped.clone())?;
        let admission_start = crate::attach::monotonic_ns();
        let admission =
            self.inventory_candidate_admission(session, &candidate, &removed, new_views);
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "candidate_admission",
            admission_start,
            crate::attach::monotonic_ns(),
        );
        let mut changed = self.latch_candidate_ambiguity(&candidate.plan);
        self.pending_rejected_keys
            .extend(admission.newly_rejected_keys.iter().copied());
        if !admission.stale_views.is_empty() {
            let retained_ids: BTreeSet<_> = self.views.iter().map(ProcessView::id).collect();
            let retained_stale: BTreeSet<_> = admission
                .stale_views
                .intersection(&retained_ids)
                .copied()
                .collect();
            let generation_lost =
                self.inventory_preflight_lost_generation(&retained_stale, &admission.stale_views);
            self.queue_stale_views(&retained_stale, pending_views);
            for (view, _, _) in new_views.iter() {
                if admission.stale_views.contains(&view.id()) {
                    self.request_refresh(view.pid(), crate::attach::monotonic_ns());
                    failed_refresh_pids.insert(view.pid());
                }
            }
            if generation_lost {
                self.mark_live_loss(
                    "live inventory generation",
                    "an exact retained or newly opened process generation changed during inventory preflight",
                );
            } else {
                self.invalidate_causal_timing();
            }
            changed |= self.process_discovery_records(
                session,
                records,
                pending_views,
                additions_allowed,
                collect,
                closure,
            )?;
            return Ok(changed);
        }
        if !admission.targets_ok && admission.missing_contexts.is_empty() {
            self.mark_partial(
                "live inventory transaction",
                "candidate preflight failed; canonical identity, plan, and links were unchanged",
            );
            changed |= self.process_discovery_records(
                session,
                records,
                pending_views,
                additions_allowed,
                collect,
                closure,
            )?;
            return Ok(changed);
        }

        for context_id in &admission.missing_contexts {
            let Some(context) = self.loader_registry.context(*context_id) else {
                continue;
            };
            let view = context.spec.view;
            if !removed.contains(&view) {
                refreshed_ok.insert(view);
            }
            if let Some(pid) = self
                .views
                .iter()
                .find(|candidate| candidate.id() == view)
                .map(ProcessView::pid)
            {
                self.request_refresh(pid, crate::attach::monotonic_ns());
            }
        }

        let mut mutation_started = false;
        let mut failed_retirements = BTreeSet::new();
        let mut context_retirements = BTreeSet::new();
        let mut no_terminal_selection_handoffs = TerminalSelectionHandoffs::new();
        let retirement_views: BTreeSet<_> = removed.union(&refreshed_ok).copied().collect();
        self.queue_inventory_retirements(&retirement_views, &stale, &departed, pending_views);
        for view in &retirement_views {
            // H5 pressure: a view the parked records name is never retired
            // by the direct path either; its request is retained for retry
            // after the parked prefix is dispatched.
            if let Some(pid) = self
                .views
                .iter()
                .find(|candidate| candidate.id() == *view)
                .map(ProcessView::pid)
                .filter(|pid| self.pressure_view_shielded(*pid))
            {
                failed_retirements.insert(*view);
                failed_refresh_pids.insert(pid);
                self.request_refresh(pid, crate::attach::monotonic_ns());
                continue;
            }
            if !self.loader_registry.ids_for_view(*view).is_empty() {
                mutation_started = true;
                context_retirements.insert(*view);
            }
            let (retirement_changed, complete) = self.retire_loader_contexts(
                *view,
                &mut no_terminal_selection_handoffs,
                session,
                additions_allowed,
                pending_views,
                collect,
                closure,
            )?;
            changed |= retirement_changed;
            mutation_started |= retirement_changed;
            if !complete {
                failed_retirements.insert(*view);
                if let Some(pid) = self
                    .views
                    .iter()
                    .find(|candidate| candidate.id() == *view)
                    .map(ProcessView::pid)
                {
                    failed_refresh_pids.insert(pid);
                    self.request_refresh(pid, crate::attach::monotonic_ns());
                }
            }
        }
        removed.retain(|view| !failed_retirements.contains(view));
        refreshed_ok.retain(|view| !failed_retirements.contains(view));
        let completed_retirements =
            completed_retirement_intent(&removed, &context_retirements, &failed_retirements);
        self.pending_retirements
            .extend(completed_retirements.iter().copied());
        let mut pre_candidate_records = Vec::new();
        for queued in std::mem::take(records) {
            if new_view_pids.contains(&((queued.record.pid_tgid >> 32) as u32)) {
                deferred_new_view_records.push(queued);
            } else {
                pre_candidate_records.push(queued);
            }
        }
        *records = pre_candidate_records;
        let pre_candidate_result = self.process_discovery_records(
            session,
            records,
            pending_views,
            additions_allowed,
            collect,
            closure,
        );
        records.extend(deferred_new_view_records);
        changed |= pre_candidate_result?;
        if !self.pending_retirements.is_empty() || !self.pending_rejected_keys.is_empty() {
            self.mark_partial(
                "live inventory transaction",
                "completed conservative retirement remains queued for a later current-state rebuild",
            );
            return Ok(changed);
        }
        let (rescanned, failed_rescan_pids, deferred_rescan_pids, rescan_skips) = self
            .scan_inventory_views(
                &refreshed_ok,
                "a post-retirement inventory refresh failed",
                &mut *tick_now,
            );
        failed_refresh_pids.extend(failed_rescan_pids);
        failed_refresh_pids.extend(deferred_rescan_pids);
        skipped.extend(rescan_skips);
        refreshed_scans = rescanned;
        refreshed_ok = refreshed_scans.iter().map(|(view, _, _)| *view).collect();
        refreshed_ok.retain(|view| !failed_retirements.contains(view));
        refreshed_scans.retain(|(view, _, _)| refreshed_ok.contains(view));
        let mut candidate =
            self.inventory_candidate(&removed, &refreshed_scans, new_views, skipped)?;
        // Exec-refreshed views whose rescan re-accepted the same static
        // targets force them through detach/replace: PID-bound links may be
        // dead while still recorded as attached. Lowered before admission so
        // the forced targets are preflighted like any other replacement.
        self.lower_exec_rearms(&mut candidate, &refreshed_ok, &serviced_requests);
        let admission_start = crate::attach::monotonic_ns();
        let admission =
            self.inventory_candidate_admission(session, &candidate, &removed, new_views);
        self.stage_timings.span(
            crate::timing::StageKind::Attach,
            "candidate_admission",
            admission_start,
            crate::attach::monotonic_ns(),
        );
        changed |= self.latch_candidate_ambiguity(&candidate.plan);
        self.pending_rejected_keys
            .extend(admission.newly_rejected_keys.iter().copied());
        let conservative_only = admission.requires_conservative_apply(mutation_started);
        if !admission.stale_views.is_empty() || !admission.missing_contexts.is_empty() {
            let retained_ids: BTreeSet<_> = self.views.iter().map(ProcessView::id).collect();
            let retained_stale: BTreeSet<_> = admission
                .stale_views
                .intersection(&retained_ids)
                .copied()
                .collect();
            let generation_lost =
                self.inventory_preflight_lost_generation(&retained_stale, &admission.stale_views);
            let retained_lost = self.retained_generation_lost(&retained_stale);
            for (view, _, _) in new_views.iter() {
                if admission.stale_views.contains(&view.id()) {
                    self.request_refresh(view.pid(), crate::attach::monotonic_ns());
                    failed_refresh_pids.insert(view.pid());
                }
            }
            if generation_lost {
                self.mark_live_loss(
                    "live inventory generation",
                    "an exact retained or newly opened process generation changed during post-retirement preflight",
                );
            } else if !admission.stale_views.is_empty() {
                self.invalidate_causal_timing();
            }
            let outcome = ApplyOutcome {
                stale_views: retained_stale,
                missing_contexts: admission.missing_contexts,
                ..ApplyOutcome::default()
            };
            self.queue_apply_outcome(&outcome, pending_views);
            changed |= self.process_discovery_records(
                session,
                records,
                pending_views,
                additions_allowed,
                collect,
                closure,
            )?;
            if conservative_only {
                *additions_allowed = false;
            }
            self.close_cgroup_admissions_at_removal(&removed);
            self.settle_leader_exits_at_removal(removed.iter().copied());
            let released: Vec<_> = self
                .views
                .iter()
                .map(ProcessView::id)
                .filter(|id| removed.contains(id))
                .collect();
            self.views.retain(|view| !removed.contains(&view.id()));
            for id in released {
                self.release_view_id(id);
            }
            for view in removed.iter().chain(&refreshed_ok) {
                self.scan_inputs.remove(view);
            }
            if matches!(self.scope, Scope::Pid(_)) && retained_lost {
                bail!("the named process generation changed during inventory preflight");
            }
            return Ok(changed);
        }
        if !admission.targets_ok {
            self.mark_partial(
                "live inventory transaction",
                "post-retirement candidate preflight failed; conservative retirements were committed and additions were blocked",
            );
            if mutation_started {
                *additions_allowed = false;
            }
            return Ok(changed);
        }

        let extra_views: Vec<_> = new_views.iter().map(|(view, _, _)| view).collect();
        let outcome =
            self.apply_candidate(session, candidate, additions_allowed, true, &extra_views)?;
        self.record_apply_timing(&outcome);
        // Only a published newcomer is retained and armed. An unpublished one
        // committed nothing, so it stays in `new_views` for release and is
        // requested again, like a newcomer lost to a stale preflight (U-07).
        let new_view_ids: BTreeSet<_> = if conservative_only {
            BTreeSet::new()
        } else {
            new_views
                .iter()
                .map(|(view, _, _)| view.id())
                .filter(|view| !outcome.unpublished_views.contains(view))
                .collect()
        };
        let new_view_pids: Vec<_> = new_view_pids.into_iter().collect();
        for view in outcome.stale_views.iter().chain(&outcome.unpublished_views) {
            if let Some(pid) = new_views
                .iter()
                .find(|(candidate, _, _)| candidate.id() == *view)
                .map(|(view, _, _)| view.pid())
            {
                self.request_refresh(pid, crate::attach::monotonic_ns());
                failed_refresh_pids.insert(pid);
            }
        }
        if outcome.accepted() && !conservative_only {
            let (admitted, unpublished): (Vec<_>, Vec<_>) = std::mem::take(new_views)
                .into_iter()
                .partition(|(view, _, _)| new_view_ids.contains(&view.id()));
            *new_views = unpublished;
            // First-observed-ready: the accepted newcomers join the retained
            // set here, so their queue ages sample now, just before the
            // tick's event drain.
            let admission_now = crate::attach::monotonic_ns();
            for (view, _, _) in admitted {
                self.sample_newcomer_admission(view.pid(), admission_now);
                self.views.push(view);
            }
            self.record_cgroup_view_admissions(new_view_ids.iter().copied());
            self.coalesce_pre_admission_exits(records, &new_view_ids);
        }
        self.queue_apply_outcome(&outcome, pending_views);
        closure.observe_apply(&outcome);
        changed |= outcome.changed;
        changed |= self.process_discovery_records(
            session,
            records,
            pending_views,
            additions_allowed,
            collect,
            closure,
        )?;
        if !outcome.accepted() {
            return Ok(changed);
        }
        if conservative_only || !*additions_allowed {
            failed_refresh_pids.extend(retirement_views.iter().filter_map(|view| {
                self.views
                    .iter()
                    .find(|candidate| candidate.id() == *view)
                    .map(ProcessView::pid)
            }));
            failed_refresh_pids.extend(new_view_pids);
        }
        self.close_cgroup_admissions_at_removal(&removed);
        self.settle_leader_exits_at_removal(removed.iter().copied());
        let released: Vec<_> = self
            .views
            .iter()
            .map(ProcessView::id)
            .filter(|id| removed.contains(id))
            .collect();
        self.views.retain(|view| !removed.contains(&view.id()));
        for id in released {
            self.release_view_id(id);
        }
        for view in removed.iter().chain(&refreshed_ok) {
            self.scan_inputs.remove(view);
        }
        let arm_result = if *additions_allowed {
            let arm: Vec<_> = self
                .views
                .iter()
                .enumerate()
                .filter_map(|(position, view)| {
                    (refreshed_ok.contains(&view.id()) || new_view_ids.contains(&view.id()))
                        .then_some(position)
                })
                .collect();
            arm_refreshed_views_with(&arm, |position| {
                // H-1: a spent live frame arms no more views; each one left
                // is requested, so the next frame rescans and arms it.
                if self.frame_work_exhausted() {
                    self.note_frame_deferral();
                    let pid = self.views[position].pid();
                    failed_refresh_pids.insert(pid);
                    self.request_refresh(pid, crate::attach::monotonic_ns());
                    return Ok(false);
                }
                self.arm_loader_or_partial(position, session, additions_allowed, pending_views)
            })
        } else {
            Ok(false)
        };
        // Views whose export work the closed tick skipped, booked by the
        // helper shared with startup attach.
        let mut export_incomplete = BTreeSet::new();
        let fatal = match arm_result {
            Ok(arm_changed) => {
                changed |= arm_changed;
                for view in refreshed_ok.union(&new_view_ids).copied() {
                    // H-1: export attach left for the next frame is requested
                    // the way skipped export work already is.
                    if self.frame_work_exhausted() {
                        self.note_frame_deferral();
                        export_incomplete.insert(view);
                        continue;
                    }
                    let outcome = self.attach_refreshed_exports(view, session, additions_allowed);
                    self.note_export_attach_outcome(
                        view,
                        outcome,
                        pending_views,
                        closure,
                        &mut export_incomplete,
                    );
                }
                None
            }
            Err(error) => Some(error),
        };
        // A closed tick skips arming: the whole phase when the closure came
        // after the apply, and every view after the one that raised it inside
        // the phase. Keep a serviced request until that setup finishes, and
        // request any newly admitted owner the closed tick left unarmed.
        // Without that intent its loader would never be armed and its
        // dynamic exports never attached (U-07): once it owns modules polling
        // never rescans it. The next open tick rescans and arms it.
        if !*additions_allowed {
            let unarmed: Vec<_> = self
                .views
                .iter()
                .filter(|view| {
                    (new_view_ids.contains(&view.id()) || refreshed_ok.contains(&view.id()))
                        && view.still_the_same()
                        && self.loader_registry.ids_for_view(view.id()).is_empty()
                        && !self.loader_arming_gated(view.id())
                })
                .map(ProcessView::pid)
                .collect();
            for pid in unarmed {
                failed_refresh_pids.insert(pid);
                self.request_refresh(pid, crate::attach::monotonic_ns());
            }
            // The unarmed filter above cannot see an armed view whose export
            // work the closed tick skipped. Request it too, with the helper
            // shared with startup attach.
            self.request_skipped_export_views(&export_incomplete);
        }
        if *additions_allowed && self.frame_deferred {
            self.request_skipped_export_views(&export_incomplete);
        }
        failed_refresh_pids.extend(
            self.views
                .iter()
                .filter_map(|view| export_incomplete.contains(&view.id()).then_some(view.pid())),
        );
        let cleanup = self.process_discovery_records(
            session,
            records,
            pending_views,
            additions_allowed,
            collect,
            closure,
        );
        if let Some(error) = fatal {
            return Err(error);
        }
        changed |= cleanup?;
        self.complete_refresh_requests(&serviced_requests, &failed_refresh_pids);
        Ok(changed)
    }

    /// Drains private discovery records into owned storage, drops the map
    /// borrow, then applies identity/link transactions. Callers synchronize
    /// semantic consumers immediately when this reports a plan change, before
    /// draining the ordinary event ring.
    pub fn drain_discovery(&mut self, session: &mut Session) -> Result<bool> {
        self.drain_discovery_from(session)
    }

    /// Whether a frame may skip the inventory sweep: no queued work, no
    /// refresh request, no staged facts, and a sweep-driven scope. Pid
    /// scope never defers — its per-tick sweep is the generation
    /// authority and already cheap — and anything queued forces the full
    /// pass. The `/proc` sweep itself is the only deferred work, bounded
    /// by the run loop's periodic forced full frame.
    fn discovery_shallow_idle(&self) -> bool {
        !matches!(self.scope, Scope::Pid(_))
            && self.pending_discovery_records.is_empty()
            && self.pending_loader_scans.is_empty()
            && self.retirement_intents.is_empty()
            && self.pending_retirements.is_empty()
            && self.pending_rejected_keys.is_empty()
            && self.ready_expected_removals.is_empty()
            && self.expected_target_exit_pending.is_none()
            && self.pending_leader_exit_views.is_empty()
            && self.refresh_requested.is_empty()
            && self.capture_facts.staged.is_none()
    }

    /// A framed discovery pass: the ring always drains, and any records,
    /// malformed items, queued work, or pid scope upgrades to the full
    /// pass same-frame — loader events are never delayed. Only a quiet
    /// sweep-driven frame skips the inventory, unless `force_full`
    /// (the run loop's periodic full frame) says otherwise.
    pub fn drain_discovery_shallow(
        &mut self,
        session: &mut Session,
        force_full: bool,
    ) -> Result<bool> {
        self.drain_discovery_shallow_from(session, force_full)
    }

    pub(crate) fn drain_discovery_shallow_from(
        &mut self,
        session: &mut dyn EngineSession,
        force_full: bool,
    ) -> Result<bool> {
        let (records, malformed, _fresh_blocked) = self.collect_frame_discovery(session)?;
        if force_full || !records.is_empty() || malformed != 0 || !self.discovery_shallow_idle() {
            return self.with_live_frame(|engine| {
                engine.apply_discovery_batch(session, records, malformed)
            });
        }
        Ok(false)
    }

    /// Drains the detached discovery ring to an observed empty read. Every
    /// quantum is applied before collecting the next one, so each exact prefix
    /// remains accounted for and producer counters are refreshed per batch.
    pub fn drain_discovery_terminal(&mut self, session: &mut Session) -> Result<bool> {
        self.drain_discovery_terminal_from(session)
    }

    /// Drains one discovery quantum after a failed producer detach. The exact
    /// prefix is applied without admitting new static or dynamic producers;
    /// any remaining records stay queued for bounded terminal evidence.
    /// Test-only since quiesce-then-publish detached after publication: the
    /// terminal drain takes the full or Q-bounded path instead.
    #[cfg(test)]
    pub(crate) fn drain_discovery_terminal_bounded_from(
        &mut self,
        session: &mut dyn EngineSession,
    ) -> Result<bool> {
        let nested_budget = Cell::new(self.shared_allowance_remaining(session, 0));
        let (records, malformed, failure) = match Self::collect_discovery_records_budgeted(
            session,
            &nested_budget,
            LIVE_DISCOVERY_DRAIN_QUANTUM,
        ) {
            Ok((records, malformed, _)) => (records, malformed, None),
            Err(error) => {
                let incomplete = error.downcast::<IncompleteTerminalDrain>()?;
                self.account_unvalidated_discovery(incomplete.unvalidated_records);
                (
                    incomplete.records,
                    incomplete.malformed,
                    Some(anyhow::Error::msg(incomplete.cause)),
                )
            }
        };
        let mut collect =
            |session: &mut dyn EngineSession| Self::nested_pull_capped(session, &nested_budget);
        let outcome = self.apply_discovery_batch_with(
            session,
            records,
            malformed,
            false,
            false,
            &mut collect,
            None,
        )?;
        if let Some(failure) = failure {
            return Err(failure);
        }
        Ok(outcome.changed)
    }

    /// Applies discovery records staged during stop-gate quiescence: the
    /// exact prefix, without admitting new producers. Follow-up collects
    /// drain the ring as today; anything they take is pre-Q (or the
    /// terminal Q-drain flags it).
    pub(crate) fn apply_quiesced_discovery(
        &mut self,
        session: &mut dyn EngineSession,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
    ) -> Result<bool> {
        let nested_budget =
            Cell::new(self.shared_allowance_remaining(
                session,
                records.len().saturating_add(malformed as usize),
            ));
        let mut collect =
            |session: &mut dyn EngineSession| Self::nested_pull_capped(session, &nested_budget);
        Ok(self
            .apply_discovery_batch_with(
                session,
                records,
                malformed,
                false,
                false,
                &mut collect,
                None,
            )?
            .changed)
    }

    /// Drains the discovery ring to the producer `stop` position read at
    /// Q, in bounded quanta, applying each exact prefix without admitting
    /// producers. Sets `post_q_record` when the producer moved past `stop` —
    /// the post-Q invariant violation.
    pub(crate) fn drain_discovery_terminal_to_position(
        &mut self,
        session: &mut Session,
        stop: usize,
        post_q_record: &mut bool,
    ) -> Result<bool> {
        let wall_start = crate::attach::monotonic_ns();
        let totals_before = self.stage_timings.totals_ns();
        let result = self.drain_discovery_terminal_to_position_inner(session, stop, post_q_record);
        self.span_terminal_overhead("terminal_q_overhead", wall_start, &totals_before);
        result
    }

    fn drain_discovery_terminal_to_position_inner(
        &mut self,
        session: &mut Session,
        stop: usize,
        post_q_record: &mut bool,
    ) -> Result<bool> {
        let mut changed = false;
        loop {
            // Bounded by the shared allowance: each quantum pulls staged
            // transfers (free) plus fresh room, one work quantum at most.
            // Pulling nothing with the Q unreached is the stuck state —
            // nothing staged to transfer, no room to read — recorded with
            // explicit unfinished evidence instead of spinning past it.
            let remaining = self.shared_allowance_remaining(session, 0);
            let staged_before = session.staged_discovery_len();
            let quantum = staged_before
                .saturating_add(remaining)
                .min(LIVE_DISCOVERY_DRAIN_QUANTUM);
            let (records, malformed, post_q, backlog) =
                session.collect_discovery_to_position(stop, quantum)?;
            *post_q_record |= post_q;
            if backlog && records.is_empty() && malformed == 0 {
                debug_assert_eq!(quantum, 0, "only a zero quantum pulls nothing with backlog");
                self.note_terminal_capacity_backlog();
                return Ok(changed);
            }
            // Staged pops are credit transfers, not fresh acquisitions:
            // only ring reads consume the nested pulls' share.
            let transfers = staged_before.saturating_sub(session.staged_discovery_len());
            let fresh = records
                .len()
                .saturating_add(malformed as usize)
                .saturating_sub(transfers);
            let nested_budget = Cell::new(remaining.saturating_sub(fresh));
            let mut collect =
                |session: &mut dyn EngineSession| Self::nested_pull_capped(session, &nested_budget);
            let outcome = self.apply_discovery_batch_with(
                session,
                records,
                malformed,
                false,
                false,
                &mut collect,
                None,
            )?;
            changed |= outcome.changed;
            if !backlog {
                self.settle_frame_deferrals_at_capture_end();
                return Ok(changed);
            }
        }
    }

    pub(crate) fn drain_discovery_terminal_from(
        &mut self,
        session: &mut dyn EngineSession,
    ) -> Result<bool> {
        let wall_start = crate::attach::monotonic_ns();
        let totals_before = self.stage_timings.totals_ns();
        let result = self.drain_discovery_terminal_from_inner(session);
        self.span_terminal_overhead("terminal_overhead", wall_start, &totals_before);
        result
    }

    fn drain_discovery_terminal_from_inner(
        &mut self,
        session: &mut dyn EngineSession,
    ) -> Result<bool> {
        let mut changed = false;
        loop {
            // Bounded by the shared allowance: staged transfers are free
            // and fresh reads share one budget per quantum. Pulling
            // nothing without observing empty is the stuck state —
            // nothing staged to transfer, no room to read — recorded with
            // explicit unfinished evidence instead of spinning past it.
            let remaining = self.shared_allowance_remaining(session, 0);
            let nested_budget = Cell::new(remaining);
            let (records, malformed, complete, failure) =
                match Self::collect_discovery_records_budgeted(
                    session,
                    &nested_budget,
                    LIVE_DISCOVERY_DRAIN_QUANTUM,
                ) {
                    Ok((records, malformed, true)) => (records, malformed, true, None),
                    Ok((records, malformed, false)) => (records, malformed, false, None),
                    Err(error) => {
                        let incomplete = error.downcast::<IncompleteTerminalDrain>()?;
                        self.account_unvalidated_discovery(incomplete.unvalidated_records);
                        (
                            incomplete.records,
                            incomplete.malformed,
                            true,
                            Some(anyhow::Error::msg(incomplete.cause)),
                        )
                    }
                };
            if !complete && records.is_empty() && malformed == 0 {
                self.note_terminal_capacity_backlog();
                return Ok(changed);
            }
            let mut collect =
                |session: &mut dyn EngineSession| Self::nested_pull_capped(session, &nested_budget);
            let outcome = self.apply_discovery_batch_with(
                session,
                records,
                malformed,
                false,
                false,
                &mut collect,
                None,
            )?;
            changed |= outcome.changed;
            if let Some(failure) = failure {
                return Err(failure);
            }
            if complete {
                self.settle_frame_deferrals_at_capture_end();
                return Ok(changed);
            }
        }
    }

    /// Records the terminal dispatch's *exclusive* cleanup span: wall time
    /// minus the scan/pin/bind/plan/merge/projection/attach spans the
    /// terminal batches recorded inside it. Exclusive, so stages never
    /// overlap; the per-stage totals stay complete (terminal work included).
    fn span_terminal_overhead(
        &mut self,
        op: &'static str,
        wall_start: Option<u64>,
        totals_before: &[u64; crate::timing::STAGE_COUNT],
    ) {
        let wall = match (wall_start, crate::attach::monotonic_ns()) {
            (Some(start), Some(end)) => end.saturating_sub(start),
            _ => {
                self.stage_timings
                    .span_known(crate::timing::StageKind::Cleanup, op, None);
                return;
            }
        };
        let totals_after = self.stage_timings.totals_ns();
        let mut inner = 0u64;
        for (slot, before) in totals_before.iter().enumerate() {
            inner = inner.saturating_add(totals_after[slot].saturating_sub(*before));
        }
        self.stage_timings.span_known(
            crate::timing::StageKind::Cleanup,
            op,
            Some(wall.saturating_sub(inner)),
        );
    }

    /// A quantum stop is backlog, not failure: the exact prefix is applied now
    /// and the rest stays on the ring for the next tick, which the run loop's
    /// duration/signal checks precede. Overflow in between is the producer's
    /// `ring_loss`, read with every batch.
    pub(crate) fn drain_discovery_from(&mut self, session: &mut dyn EngineSession) -> Result<bool> {
        let (records, malformed, _fresh_blocked) = self.collect_frame_discovery(session)?;
        self.with_live_frame(|engine| engine.apply_discovery_batch(session, records, malformed))
    }

    /// One live frame's records: fresh pulls up to the shared allowance
    /// minus staged, Engine-held and already-pulled items, in collector
    /// quanta of at most `LIVE_DISCOVERY_DRAIN_QUANTUM`, stopping at the
    /// first that empties the queue or at the allowance. Pulled malformed
    /// items hold credits like records until the batch accounts them. A
    /// quantum stop is backlog, never failure; excess records stay unread
    /// in ring order for the next frame, and any overflow they cause is the
    /// producer's `ring_loss`. A real dequeue failure aborts the route as
    /// before. `fresh_blocked` reports stopping for capacity without
    /// observing an empty queue — capacity-blocked, never empty — and is
    /// also latched sticky so the scheduler services backlog instead of a
    /// full sleep.
    fn collect_frame_discovery(
        &mut self,
        session: &mut dyn EngineSession,
    ) -> Result<(Vec<DiscoveryRecord>, u64, bool)> {
        let budget = Cell::new(self.shared_allowance_remaining(session, 0));
        let mut records = Vec::new();
        let mut malformed = 0u64;
        let mut observed_empty = false;
        for _ in 0..LIVE_DISCOVERY_FRAME_QUANTA {
            match Self::collect_discovery_records_budgeted(
                session,
                &budget,
                LIVE_DISCOVERY_DRAIN_QUANTUM,
            ) {
                Ok((drained, drained_malformed, empty)) => {
                    if empty {
                        observed_empty = true;
                        records.extend(drained);
                        malformed = malformed.saturating_add(drained_malformed);
                        break;
                    }
                    if drained.is_empty() && drained_malformed == 0 {
                        // No credit and nothing staged to transfer: the
                        // queue stays unobserved past the allowance.
                        break;
                    }
                    records.extend(drained);
                    malformed = malformed.saturating_add(drained_malformed);
                }
                // The budgeted pull only fails on a transport failure; its
                // prefix is dropped with the route, never retained.
                Err(error) => {
                    let incomplete = error.downcast::<IncompleteTerminalDrain>()?;
                    return Err(Self::generic_drain_error(incomplete.into()));
                }
            }
        }
        let fresh_blocked = !observed_empty;
        self.frame_fresh_blocked = fresh_blocked;
        Ok((records, malformed, fresh_blocked))
    }

    /// `drain_discovery_tick` (src/run.rs) aborts the run with `?` on this
    /// route instead of retaining and replaying anything, so a collection
    /// failure here must not carry the terminal routes' "N terminal
    /// record(s) retained for retry" claim — nothing is retained.
    fn generic_drain_error(error: anyhow::Error) -> anyhow::Error {
        match error.downcast::<IncompleteTerminalDrain>() {
            Ok(incomplete) => anyhow::Error::msg(incomplete.cause),
            Err(error) => error,
        }
    }

    /// Ordinary discovery records this Engine currently holds in userspace:
    /// pending records plus the terminal batch. Measured at tick boundaries
    /// (no batch locals outstanding) it is exact; the run loop uses it to
    /// size staging quanta and readiness against the shared allowance.
    pub(crate) fn discovery_held_len(&self) -> usize {
        self.pending_discovery_records
            .len()
            .saturating_add(self.terminal_batch.as_ref().map_or(0, TerminalBatch::len))
    }

    /// Userspace-owned discovery items outside the caller's batch locals:
    /// the session FIFO plus Engine pending and terminal holdings. Every
    /// fresh acquisition stops before exceeding the shared allowance minus
    /// this. Staged malformed items hold credits like staged records until
    /// a dequeue transfers them to their accounting boundary.
    fn shared_discovery_held(&self, session: &dyn EngineSession) -> usize {
        session
            .staged_discovery_len()
            .saturating_add(self.discovery_held_len())
    }

    /// Shared-allowance room for fresh acquisition beside `local` already
    /// pulled batch-local items: the allowance minus staged, Engine-held
    /// and local items. Malformed items pulled into the local batch count
    /// like records until they are accounted.
    fn shared_allowance_remaining(&self, session: &dyn EngineSession, local: usize) -> usize {
        DISCOVERY_HELD_CAP
            .saturating_sub(self.shared_discovery_held(session))
            .saturating_sub(local)
    }

    /// One nested pull through the shared allowance: at most one work
    /// quantum and never past `budget`, which the caller seeds from
    /// `shared_allowance_remaining` and every nested pull consumes from.
    /// An empty observation is genuine (the pull reached the queue end);
    /// a quantum stop with allowance left is backlog; an allowance stop
    /// is capacity-blocked. All three keep their exact prefix; none is
    /// ever complete evidence.
    fn nested_pull_capped(
        session: &mut dyn EngineSession,
        budget: &Cell<usize>,
    ) -> Result<(Vec<DiscoveryRecord>, u64)> {
        match Self::collect_discovery_records_budgeted(
            session,
            budget,
            LIVE_DISCOVERY_DRAIN_QUANTUM,
        ) {
            Ok((records, malformed, true)) => Ok((records, malformed)),
            Ok((records, malformed, false)) => {
                // A full quantum with more pullable (budget or staged
                // transfers left) is backlog; anything else stopped at
                // the allowance with the queue not observed empty.
                let pulled_full_quantum = records.len().saturating_add(malformed as usize)
                    >= LIVE_DISCOVERY_DRAIN_QUANTUM;
                if pulled_full_quantum && (budget.get() > 0 || session.staged_discovery_len() > 0) {
                    Err(IncompleteTerminalDrain::backlog(records, malformed).into())
                } else {
                    Err(IncompleteTerminalDrain::capacity_blocked(records, malformed, 0).into())
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Whether retained discovery work waits between frames: pending or
    /// staged records, a re-parked pressure rotation, or a frame collect
    /// that stopped at the shared allowance. Schedules backlog service
    /// instead of a full sleep.
    pub(crate) fn discovery_backlog_pending(&self, staged_len: usize) -> bool {
        self.frame_fresh_blocked
            || self.pressure_rotation_pending
            || !self.pending_discovery_records.is_empty()
            || staged_len > 0
    }

    /// Takes the frame's fresh-blocked flag for the scheduler: a set flag
    /// schedules backlog service instead of a full sleep, then clears.
    pub(crate) fn take_frame_fresh_blocked(&mut self) -> bool {
        std::mem::replace(&mut self.frame_fresh_blocked, false)
    }

    /// Records a terminal drain stopping at the shared allowance with
    /// terminal work unfinished: 4,096 items are held and unsettled while
    /// the queue was never observed empty. The count is sticky evidence
    /// and the strict lossless verdict must fail on it; the drain returns
    /// without settling deferrals and never claims complete.
    fn note_terminal_capacity_backlog(&mut self) {
        self.terminal_capacity_backlog = self.terminal_capacity_backlog.saturating_add(1);
        self.discovery_truncated = self.discovery_truncated.saturating_add(1);
        self.mark_live_loss(
            "terminal discovery drain",
            "the terminal drain stopped at the shared discovery allowance with 4,096 items held unsettled and the queue never observed empty; terminal work is unfinished",
        );
    }

    #[cfg(test)]
    pub(crate) fn terminal_capacity_backlog_for_test(&self) -> u64 {
        self.terminal_capacity_backlog
    }

    /// Records quiescence staging hitting the shared discovery allowance
    /// with records still unread in the ring: at least one unit of terminal
    /// work is unfinished. The count is an explicit lower bound — the
    /// remainder stays unread, so it cannot be inventoried — and the strict
    /// lossless verdict must fail on it.
    pub(crate) fn note_quiesced_discovery_overflow(&mut self) {
        self.discovery_truncated = self.discovery_truncated.saturating_add(1);
        self.mark_live_loss(
            "terminal discovery quiescence",
            "quiescence staging reached the shared discovery allowance with at least one record still unread; terminal work is unfinished",
        );
    }

    /// Notes the current held occupancy (pending plus terminal plus the
    /// batch's in-flight records) into the diagnostic high-water mark.
    fn note_discovery_held_high_water(&mut self, in_flight: usize) {
        let held = self.discovery_held_len().saturating_add(in_flight);
        self.discovery_held_high_water = self.discovery_held_high_water.max(held);
    }

    #[cfg(test)]
    pub(crate) fn discovery_held_high_water_for_test(&self) -> usize {
        self.discovery_held_high_water
    }

    /// One between-frames backlog opportunity: at most one 256-item
    /// ordinary dispatch quantum from the retained FIFO (pending first,
    /// then staged transfers plus fresh room) or one selected
    /// pressure-service transaction. A backlog pass never rearms or
    /// claims an owned pause, never touches the frame clock or counter,
    /// never reads aggregate maps or renders, and never runs an ordinary
    /// whole-scope tick. It reuses the frame's 200 ms work budget and
    /// checkpoints, scoped to the opportunity.
    pub(crate) fn service_backlog_quantum(
        &mut self,
        session: &mut dyn EngineSession,
    ) -> Result<BacklogOutcome> {
        self.with_live_frame(|engine| engine.service_backlog_quantum_inner(session))
    }

    fn service_backlog_quantum_inner(
        &mut self,
        session: &mut dyn EngineSession,
    ) -> Result<BacklogOutcome> {
        let passes_before = self.pressure_service_passes;
        let staged_before = session.staged_discovery_len();
        let retained_before = self
            .pending_discovery_records
            .len()
            .saturating_add(staged_before);
        // The frame's fresh-blocked latch is one backlog opportunity, not
        // a standing order: take it now so a later pending check reads
        // the queues, and the pass below re-latches nothing. A pass that
        // re-armed on every non-empty pull would zero-sleep against a
        // sustained producer instead of returning to the readiness wait.
        let fresh_was_blocked = self.take_frame_fresh_blocked();
        // Retained FIFO first: pending records, then staged transfers
        // plus fresh room. Nothing to do is a quiet outcome, not work.
        if !fresh_was_blocked
            && !self.pressure_rotation_pending
            && self.pending_discovery_records.is_empty()
            && staged_before == 0
        {
            return Ok(BacklogOutcome {
                changed: false,
                progressed: false,
                pending: false,
            });
        }
        let mut malformed = 0u64;
        // Work charges accrue only at an item's first accounting boundary:
        // a pending-take replay was charged by its original batch, so only
        // a fresh pull (staged transfers plus new ring reads, neither
        // charged before) charges here.
        let mut fresh_records = 0usize;
        let queued: Vec<QueuedDiscoveryRecord> = if self.pending_discovery_records.is_empty() {
            // Staged transfers plus fresh room: staged pops move their
            // permits without reserving, and only fresh ring reads
            // consume the shared allowance. A latch-only pass pulls
            // fresh room the frame could not reach; an empty pull is a
            // quiet pass, not a re-latch.
            let budget = Cell::new(self.shared_allowance_remaining(session, 0));
            let (pulled, pulled_malformed, _) = Self::collect_discovery_records_budgeted(
                session,
                &budget,
                LIVE_DISCOVERY_DRAIN_QUANTUM,
            )
            .map_err(Self::generic_drain_error)?;
            malformed = pulled_malformed;
            fresh_records = pulled.len();
            pulled
                .into_iter()
                .map(|record| QueuedDiscoveryRecord {
                    record,
                    terminal_owner: None,
                    terminal_exports: Vec::new(),
                })
                .collect()
        } else {
            let take = self
                .pending_discovery_records
                .len()
                .min(LIVE_DISCOVERY_DRAIN_QUANTUM);
            self.pending_discovery_records.drain(..take).collect()
        };
        self.charge_discovery_drain(fresh_records, malformed);
        // A backlog pass is never pause-owned: nothing here was handed to
        // a pause stop, and no stale pause-held set survives into it.
        self.held_records = BTreeSet::new();
        self.record_malformed_discovery(malformed);
        let rest_len = self.pending_discovery_records.len();
        let mut queued = match begin_discovery_batch(queued, self.update_counter_snapshot(session))
        {
            Ok(records) => records,
            Err((error, records)) => {
                // Counter authority failed: the quantum waits at the head
                // of the queue, in order, for the next opportunity.
                records
                    .into_iter()
                    .rev()
                    .for_each(|record| self.pending_discovery_records.insert(0, record));
                return Err(error);
            }
        };
        let retained_pids: BTreeSet<_> = self.views.iter().map(ProcessView::pid).collect();
        let mut deferred_exits = Vec::new();
        if self.admits_generations() {
            deferred_exits.extend(queued.extract_if(.., |queued| {
                let record = &queued.record;
                record.kind == DISCOVERY_KIND_LEADER_EXIT
                    && !retained_pids.contains(&((record.pid_tgid >> 32) as u32))
            }));
        }
        let nested_budget = Cell::new(self.shared_allowance_remaining(session, queued.len()));
        let mut collect =
            |session: &mut dyn EngineSession| Self::nested_pull_capped(session, &nested_budget);
        let mut additions_allowed = true;
        let mut closure = PauseClosure::new(malformed == 0);
        let mut pending_views = PendingViewRetirements::new();
        let leader_exit_assessments = self.pending_leader_exit_views.clone();
        self.settle_leader_exit_assessments(
            &leader_exit_assessments,
            &mut pending_views,
            &mut additions_allowed,
            &mut closure,
        );
        let mut changed = self.process_discovery_records(
            session,
            &mut queued,
            &mut pending_views,
            &mut additions_allowed,
            &mut collect,
            &mut closure,
        )?;
        // Leftovers rejoin ahead of the unserviced rest (they were pulled
        // earlier), except behind a held prefix the rotation restores
        // below: the diverted stash stays adjacent to its parked prefix
        // (episode atomicity, as in frames) with the rest after it.
        let mut front_inserted = 0usize;
        if self.pressure_service_passes != passes_before {
            // One selected transaction per opportunity: the deferred tail
            // waits for the next one instead of running a second pass.
            queued.extend(deferred_exits);
            if self.pressure_rotation_pending || self.frame_deferred {
                self.pending_discovery_records.extend(queued);
            } else {
                front_inserted = queued.len();
                queued
                    .into_iter()
                    .rev()
                    .for_each(|record| self.pending_discovery_records.insert(0, record));
            }
        } else {
            queued.extend(deferred_exits);
            if !queued.is_empty() {
                changed |= self.process_discovery_records(
                    session,
                    &mut queued,
                    &mut pending_views,
                    &mut additions_allowed,
                    &mut collect,
                    &mut closure,
                )?;
            }
            front_inserted = queued.len();
            queued
                .into_iter()
                .rev()
                .for_each(|record| self.pending_discovery_records.insert(0, record));
        }
        // A re-park or a frame deferral appended behind the rest of the
        // queue; restore FIFO order with the held prefix first.
        if self.pressure_rotation_pending || self.frame_deferred {
            let mut held = self
                .pending_discovery_records
                .split_off(rest_len.saturating_add(front_inserted));
            held.extend(std::mem::take(&mut self.pending_discovery_records));
            self.pending_discovery_records = held;
        }
        // Publish exactly like a frame batch: an accepted plan change
        // resyncs consumers synchronously; a quiet pass only bumps the
        // tail-skip counter. Retirement intents queued above persist in
        // engine state for the next frame's ordinary tick — the pass
        // yields instead of running it.
        self.publish_batch_tail(changed)?;
        // Forward movement only: fresh acquisition, retained shrinkage
        // through dispatch, a selected attempt, or a state change. A take
        // or pull shed back whole shrinks nothing and acquires nothing
        // settled, so it correctly reports no progress.
        let retained_after = self
            .pending_discovery_records
            .len()
            .saturating_add(session.staged_discovery_len());
        let progressed = changed
            || self.pressure_service_passes != passes_before
            || fresh_records != 0
            || malformed != 0
            || retained_after < retained_before;
        Ok(BacklogOutcome {
            changed,
            progressed,
            pending: self.discovery_backlog_pending(session.staged_discovery_len()),
        })
    }

    pub(crate) fn apply_discovery_batch(
        &mut self,
        session: &mut dyn EngineSession,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
    ) -> Result<bool> {
        // Every nested pull in this batch shares one budget seeded from
        // the shared allowance beside the batch-local records.
        let nested_budget =
            Cell::new(self.shared_allowance_remaining(
                session,
                records.len().saturating_add(malformed as usize),
            ));
        let mut collect =
            |session: &mut dyn EngineSession| Self::nested_pull_capped(session, &nested_budget);
        self.apply_discovery_batch_with(
            session,
            records,
            malformed,
            true,
            false,
            &mut collect,
            None,
        )
        .map(|outcome| outcome.changed)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_discovery_batch_with(
        &mut self,
        session: &mut dyn EngineSession,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
        additions_allowed: bool,
        terminal_dispatch: bool,
        collect: &mut DiscoveryCollector<'_>,
        deadline: Option<u64>,
    ) -> Result<DiscoveryBatchOutcome> {
        self.budget.set_deadline(deadline);
        let result = self.apply_discovery_batch_inner(
            session,
            records,
            malformed,
            additions_allowed,
            terminal_dispatch,
            collect,
        );
        self.budget.set_deadline(None);
        result
    }

    fn apply_discovery_batch_inner(
        &mut self,
        session: &mut dyn EngineSession,
        records: Vec<DiscoveryRecord>,
        malformed: u64,
        additions_allowed: bool,
        terminal_dispatch: bool,
        collect: &mut DiscoveryCollector<'_>,
    ) -> Result<DiscoveryBatchOutcome> {
        self.charge_discovery_drain(records.len(), malformed);
        self.held_records = if self.pause_owned_batch {
            records.iter().map(held_record_key).collect()
        } else {
            BTreeSet::new()
        };
        let mut queued = std::mem::take(&mut self.pending_discovery_records);
        queued.extend(records.into_iter().map(|record| QueuedDiscoveryRecord {
            record,
            terminal_owner: None,
            terminal_exports: Vec::new(),
        }));
        self.record_malformed_discovery(malformed);
        let queued = match begin_discovery_batch(queued, self.update_counter_snapshot(session)) {
            Ok(records) => records,
            Err((error, records)) => {
                self.pending_discovery_records = records;
                if terminal_dispatch {
                    let mut no_additions = false;
                    let mut terminal_closure = PauseClosure::new(false);
                    self.retry_terminal_predispatch_failure(
                        &mut no_additions,
                        &mut terminal_closure,
                    );
                }
                return Err(error);
            }
        };
        let fallback_due: BTreeSet<_> = self.pending_loader_scans.keys().copied().collect();
        let mut records = queued;

        let retained_pids: BTreeSet<_> = self.views.iter().map(ProcessView::pid).collect();
        let mut deferred_exits = Vec::new();
        if self.admits_generations() {
            // Move-only: the deferred exits move out in encounter order;
            // both sides keep their original relative order.
            deferred_exits.extend(records.extract_if(.., |queued| {
                let record = &queued.record;
                record.kind == DISCOVERY_KIND_LEADER_EXIT
                    && !retained_pids.contains(&((record.pid_tgid >> 32) as u32))
            }));
        }

        let mut additions_allowed = additions_allowed;
        let mut closure = PauseClosure::new(additions_allowed && malformed == 0);
        let mut pending_views = PendingViewRetirements::new();
        let leader_exit_assessments = self.pending_leader_exit_views.clone();
        self.settle_leader_exit_assessments(
            &leader_exit_assessments,
            &mut pending_views,
            &mut additions_allowed,
            &mut closure,
        );
        let mut changed = self.process_discovery_records(
            session,
            &mut records,
            &mut pending_views,
            &mut additions_allowed,
            collect,
            &mut closure,
        )?;
        records.extend(deferred_exits);
        if terminal_dispatch
            && let Some(terminal_changed) = self.continue_terminal_batch(
                session,
                &mut additions_allowed,
                &mut pending_views,
                collect,
                &mut closure,
            )?
        {
            changed |= terminal_changed;
        }
        let fallback = self.service_pending_loader_scans(
            fallback_due,
            session,
            &mut additions_allowed,
            &mut pending_views,
        )?;
        changed |= fallback.changed();
        if !fallback.required_complete() {
            closure.fail();
        }
        if !pending_views.is_empty() {
            changed |= self.process_discovery_records(
                session,
                &mut Vec::new(),
                &mut pending_views,
                &mut additions_allowed,
                collect,
                &mut closure,
            )?;
        }
        // A frame that deferred records runs no inventory pass: the next
        // frame dispatches them first, then refreshes (H-1). A head
        // episode awaiting another rotation opportunity likewise runs no
        // ordinary whole-scope tick behind its parked prefix: the next
        // opportunity services the next snapshot entry first.
        if self.pending_retirements.is_empty()
            && self.pending_rejected_keys.is_empty()
            && !self.frame_deferred
            && !self.pressure_rotation_pending
        {
            let mut tick_now = crate::attach::monotonic_ns;
            changed |= self.refresh_inventory(
                session,
                &mut additions_allowed,
                &mut records,
                &mut pending_views,
                collect,
                &mut closure,
                &mut tick_now,
            )?;
        }
        if !records.is_empty() {
            changed |= self.process_discovery_records(
                session,
                &mut records,
                &mut pending_views,
                &mut additions_allowed,
                collect,
                &mut closure,
            )?;
        }
        self.publish_batch_tail(changed)?;
        Ok(DiscoveryBatchOutcome {
            changed,
            required_complete: closure.required_complete() && additions_allowed,
        })
    }

    /// Performs the existing one-shot initial discovery pass.
    pub fn discover(
        args: &CaptureArgs,
        scope: &Scope,
        named_view: Option<ProcessView>,
    ) -> Result<Self> {
        discover_plan(args, scope, named_view)
    }

    pub fn plan(&self) -> &plan::AttachPlan {
        &self.plan
    }

    pub fn pinned(&self) -> &PinnedObjects {
        &self.pinned
    }

    pub fn discovery(&self) -> &render::DiscoveryEvidence {
        &self.discovery
    }

    /// Per-stage wall-time accumulation (Phase 2 measurement API): totals,
    /// invocation counts, and the longest indivisible operation.
    pub fn stage_timings(&self) -> &crate::timing::StageTimings {
        &self.stage_timings
    }

    /// Newcomer queue-age evidence with pending counts sampled at `now_ns`
    /// (the caller's clock poll, scheduler style; `None` samples pending
    /// ages unknown). Admissions and drops are cumulative; pending and the
    /// oldest pending age describe this instant.
    pub fn newcomer_stats(&self, now_ns: Option<u64>) -> crate::timing::NewcomerStats {
        let mut stats = self.newcomer_ages.clone();
        // Pending is the union of the two queues: a diff newcomer with a
        // queued refresh waits once, not twice.
        let mut pending = self.newcomer_first_seen.len() as u64;
        for pid in self.refresh_requested.keys() {
            if !self.newcomer_first_seen.contains_key(pid) {
                pending = pending.saturating_add(1);
            }
        }
        stats.pending = pending;
        let mut oldest: Option<u64> = None;
        for seen in self
            .refresh_requested
            .values()
            .map(|request| request.first_seen_ns)
            .chain(self.newcomer_first_seen.values().copied())
            .flatten()
        {
            let age = newcomer_age_ms(Some(seen), now_ns);
            oldest = match (oldest, age) {
                (Some(known), Some(age)) => Some(known.max(age)),
                (None, age) => age,
                (known, None) => known,
            };
        }
        stats.oldest_pending_age_ms = oldest;
        stats
    }

    /// Deep-scan executions driven by discovery and inventory (the E06
    /// oracle alongside maps bytes).
    pub fn deep_scans(&self) -> u64 {
        self.deep_scans
    }

    /// Loader-arm attempts driven by inventory.
    pub fn loader_arms(&self) -> u64 {
        self.loader_arms
    }

    /// Batch-tail publications executed vs skipped as provably redundant.
    pub(crate) fn tail_stats(&self) -> (u64, u64) {
        (self.tail_publishes, self.tail_skips)
    }

    /// Private-loader transport failures as finite aggregate counters only.
    pub fn loader_failures(&self) -> (u64, u64) {
        (
            self.loader_registry.discovery_truncated(),
            self.loader_registry.context_failures(),
        )
    }

    /// Task 3.2 (S1): flush live-accumulated discovery noise as per-class
    /// summaries. Called once at capture end; initial noise was already
    /// reported and cleared by `discover_plan`, so this covers live only.
    pub fn report_discovery_noise(&mut self) {
        self.counters.noise.report();
        self.counters.noise.clear();
    }

    pub fn start_session(
        &mut self,
        policy: CapturePolicy,
        ring_bytes: Option<u32>,
        backend: BackendSelection,
    ) -> Result<Session> {
        self.start_session_with(policy, None, None, ring_bytes, backend)
    }

    pub(crate) fn start_owned_session(
        &mut self,
        policy: CapturePolicy,
        child: &mut OwnedChild,
        ring_bytes: Option<u32>,
        backend: BackendSelection,
    ) -> Result<Session> {
        let generation = OwnedPauseGeneration::from_owned_child(child);
        self.start_session_with(policy, Some(generation), Some(child), ring_bytes, backend)
    }

    /// Task 8 calls this only after its coordinator armed the pause epoch and
    /// released the barrier. A changed direct target, shebang, or later exec
    /// chain retires the speculative pre-exec context and uses the ordinary
    /// exact mapped-loader route without upgrading empty-catalog evidence.
    pub(crate) fn revalidate_owned_session_with(
        &mut self,
        child: &OwnedChild,
        session: &mut dyn EngineSession,
        collect: &mut DiscoveryCollector<'_>,
    ) -> Result<DiscoveryBatchOutcome> {
        let Some(view) = self
            .views
            .iter()
            .find(|view| view.pid() == child.pid())
            .map(ProcessView::id)
        else {
            self.owned_initial_exec = None;
            self.mark_partial(
                "owned initial-set discovery",
                "the owned child generation was absent after barrier release",
            );
            return Ok(DiscoveryBatchOutcome {
                changed: false,
                required_complete: false,
            });
        };
        let direct_stable = child.revalidate_after_exec().unwrap_or(false);
        let mut additions_allowed = true;
        let mut records = Vec::new();
        let mut pending_views = PendingViewRetirements::new();
        let mut closure = PauseClosure::new(true);
        let mut no_terminal_selection_handoffs = TerminalSelectionHandoffs::new();
        if direct_stable && !self.loader_registry.ids_for_view(view).is_empty() {
            if let Some(initial) = self
                .owned_initial_exec
                .as_mut()
                .filter(|initial| initial.view == view)
            {
                initial.revalidated = true;
            }
            return Ok(DiscoveryBatchOutcome {
                changed: false,
                required_complete: true,
            });
        }
        self.owned_initial_exec = None;
        if !self.loader_registry.ids_for_view(view).is_empty() {
            let (_, complete) = self.retire_loader_contexts(
                view,
                &mut no_terminal_selection_handoffs,
                session,
                &mut additions_allowed,
                &mut pending_views,
                collect,
                &mut closure,
            )?;
            additions_allowed &= complete;
        }
        self.mark_partial(
            "owned initial-set discovery",
            "the direct executable identity did not revalidate after exec; ordinary live discovery remains the fallback",
        );
        let mut changed = false;
        for position in 0..self.views.len() {
            if !self.views[position].still_the_same() {
                continue;
            }
            changed |= self.arm_loader_or_partial(
                position,
                session,
                &mut additions_allowed,
                &mut pending_views,
            )?;
        }
        changed |= self.process_discovery_records(
            session,
            &mut records,
            &mut pending_views,
            &mut additions_allowed,
            collect,
            &mut closure,
        )?;
        self.publish_batch_tail(changed)?;
        Ok(DiscoveryBatchOutcome {
            changed,
            required_complete: closure.required_complete() && additions_allowed,
        })
    }

    /// Arms every retained view's loader at capture start, staging the
    /// DISCOVERY ring after each view so the per-view locator scans, plan
    /// rebuilds and attaches never let it overflow (RB-2). Returns the first
    /// fatal arming error; the caller still runs its cleanup pass.
    fn arm_initial_views(
        &mut self,
        session: &mut dyn EngineSession,
        additions_allowed: &mut bool,
        pending_views: &mut PendingViewRetirements,
    ) -> Option<anyhow::Error> {
        for position in 0..self.views.len() {
            if !self.views[position].still_the_same() {
                continue;
            }
            if let Err(error) =
                self.arm_loader_or_partial(position, session, additions_allowed, pending_views)
            {
                return Some(error);
            }
            // Staged plus Engine-held never exceeds the shared allowance;
            // whatever does not fit waits in the ring for the next staging
            // call after the first batch (producer ring loss counts a real
            // ring overflow meanwhile).
            let held = self.discovery_held_len();
            if let Err(error) = session.stage_discovery(LIVE_DISCOVERY_DRAIN_QUANTUM, held) {
                return Some(error);
            }
        }
        None
    }

    fn start_session_with(
        &mut self,
        policy: CapturePolicy,
        mut pause_generation: Option<OwnedPauseGeneration>,
        owned_child: Option<&OwnedChild>,
        ring_bytes: Option<u32>,
        backend: BackendSelection,
    ) -> Result<Session> {
        self.seed_initial_cgroup_views();
        let snapshot = self.begin_start_capture_attempt()?;
        let retained_scope = self.scope.clone();
        let named = matches!(retained_scope, Scope::Pid(_));
        let scope = &retained_scope;
        let mut session =
            match start_retained_with(self, named, process::stale_view_ids, |plan, pinned| {
                Session::start(
                    plan,
                    scope,
                    pinned,
                    policy,
                    pause_generation.take(),
                    ring_bytes,
                    owned_child,
                    backend,
                )
            }) {
                Ok(session) => session,
                Err(error) => {
                    return self.finish_start_capture_attempt(snapshot, Err(error));
                }
            };
        self.record_session_lifecycle_tracking(&session);
        let result = (|| {
            // Lifecycle producers have been live since the load, and the
            // static attach can take seconds: stage what they produced
            // before the per-view phases add more (RB-2), within the
            // shared allowance the Engine still holds nothing of.
            let held = self.discovery_held_len();
            session.stage_discovery(LIVE_DISCOVERY_DRAIN_QUANTUM, held)?;
            let mut additions_allowed = true;
            let mut records = Vec::new();
            let mut pending_views = PendingViewRetirements::new();
            let mut closure = PauseClosure::new(true);
            let mut fatal = None;
            let owned_generation = owned_child.map(OwnedChild::generation);
            let mut owned_prearmed = false;
            if let Some(child) = owned_child {
                owned_prearmed = matches!(
                    self.arm_owned_loader_before_release(
                        child,
                        &mut session,
                        &mut additions_allowed,
                        &mut pending_views,
                    )?,
                    OwnedLoaderPrearmOutcome::Armed
                );
                // One initial-set context per owned run, armed or not.
                if let Some(view) = self
                    .views
                    .iter()
                    .find(|view| view.pid() == child.pid())
                    .map(ProcessView::id)
                {
                    self.record_loader_arm(view, true);
                }
                // The initial set's timing gap is stated once, by
                // `loader_discovery.initial_set_capture`: publishing it as a
                // "discovery unavailable" skip too counted one fact twice and
                // named nothing that was unavailable.
            } else {
                fatal = self.arm_initial_views(
                    &mut session,
                    &mut additions_allowed,
                    &mut pending_views,
                );
            }
            #[cfg(test)]
            crate::first_use_probe::discovery_loss(
                crate::first_use_probe::DiscoveryStage::LoaderArmingFinished,
                &session,
            );
            if fatal.is_none() {
                self.attach_initial_exports(
                    &mut session,
                    &mut additions_allowed,
                    &mut pending_views,
                    &mut closure,
                );
                // Stage what the export attach let accumulate; the first
                // batch applies it in ring order (RB-2). Anything past the
                // shared allowance waits in the ring for the next staging
                // call after that batch.
                let held = self.discovery_held_len();
                session.stage_discovery(LIVE_DISCOVERY_DRAIN_QUANTUM, held)?;
                if owned_prearmed && let Some(generation) = owned_generation {
                    self.mark_owned_selection_pending(generation);
                }
            }
            #[cfg(test)]
            crate::first_use_probe::discovery_loss(
                crate::first_use_probe::DiscoveryStage::InitialExportsFinished,
                &session,
            );
            // The cleanup pass's nested pulls share one budget seeded
            // from the shared allowance after all staging settled.
            let nested_budget = Cell::new(self.shared_allowance_remaining(&session, records.len()));
            let mut collect =
                |session: &mut dyn EngineSession| Self::nested_pull_capped(session, &nested_budget);
            let cleanup = self.process_discovery_records(
                &mut session,
                &mut records,
                &mut pending_views,
                &mut additions_allowed,
                &mut collect,
                &mut closure,
            );
            if let Some(error) = fatal {
                return Err(error);
            }
            cleanup?;
            record_object_skips(&mut self.plan, &self.counters.object_skips);
            self.publish_current_capture_facts()?;
            Ok(session)
        })();
        self.finish_start_capture_attempt(snapshot, result)
    }
}

/// The unprivileged stand-in for the loaded `Session` at the discovery seam.
/// Only the dequeue script, the producer counter snapshot, the link-mutation
/// scripts, and the dynamic detach outcome are programmable; every other method
/// is inert so a test can never mistake adapter behavior for Engine behavior.
#[cfg(test)]
pub(crate) mod session_fixture {
    use super::*;
    use crate::attach::attachment_admission;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    #[derive(Default)]
    pub(crate) struct ScriptedSession {
        pub(crate) capture_policy: Option<CapturePolicy>,
        pub(crate) dequeues: VecDeque<Result<Option<crate::events::DiscoveryItem>>>,
        /// The staged FIFO, mirroring production: `stage_discovery` moves
        /// scripted ring outcomes here, `discovery_dequeue` serves it
        /// first, and staged items hold shared-allowance credits.
        staged: VecDeque<crate::events::DiscoveryItem>,
        pub(crate) counters: CounterSnapshot,
        /// One entry per upcoming `counter_snapshot` call; `true` fails it.
        counter_script: RefCell<VecDeque<bool>>,
        counter_reads: Cell<u64>,
        pub(crate) detach_exports: Vec<DynamicExportIdentity>,
        pub(crate) detach_failed: bool,
        detach_failures: Vec<String>,
        pub(crate) lifecycle_tracking_unavailable: Option<&'static str>,
        pub(crate) process_creation_tracking_unavailable: Option<&'static str>,
        pub(crate) detached: Vec<LoaderContextId>,
        /// Slot counts of every `detach_slots` call, in order.
        pub(crate) detached_slots: Vec<usize>,
        /// Exact slot identities of every `detach_slots` call, in order.
        pub(crate) detached_slot_indices: Vec<Vec<u32>>,
        /// Exact slot identities of every `replace_targets` call, in order.
        pub(crate) replaced_slot_indices: Vec<Vec<u32>>,
        /// One entry per upcoming `detach_slots` call; `true` fails it.
        detach_slot_script: VecDeque<bool>,
        /// One entry per upcoming `detach_slots` call; `true` fails it
        /// before any link mutation, recording no detach failure (a program
        /// fd that cannot be resolved for a group rebuild).
        detach_slot_premutation_script: VecDeque<bool>,
        /// One rebuild report per upcoming `detach_slots` call; later calls
        /// report no rebuild.
        detach_rebuild_script: VecDeque<DetachOutcome>,
        /// Static target slot indices that the next attach reports as failed.
        fail_target_slots: BTreeSet<u32>,
        /// Slot counts of every `attach_targets` call, in order.
        pub(crate) attached_slots: Vec<usize>,
        /// Dynamic exports requested by the Engine, in order.
        pub(crate) dynamic_attach_calls: Vec<DynamicExportIdentity>,
        dynamic_export_links: Vec<(LoaderContextId, PinnedObjectId, u64, u64, HookAbi)>,
        pub(crate) dynamic_attach_reports_added: bool,
        pub(crate) dynamic_loader_attach_calls: usize,
        pub(crate) dynamic_loader_reports_added: bool,
        pub(crate) dynamic_loader_links: Vec<(LoaderContextId, PinnedObjectId, u64, u64)>,
        pub(crate) selection_table_read: Option<(MapEntry, ScannedTable)>,
        /// Killed and reaped from inside `attach_targets`, i.e. exactly between
        /// a generation precheck and its postcheck.
        kill_on_attach: Option<u32>,
        /// Killed and reaped after one dynamic link mutation, before its
        /// generation postcheck.
        kill_on_dynamic_attach: Option<u32>,
        /// Killed and reaped inside the next `attach_dynamic_loader`, i.e.
        /// between a loader arm's generation precheck and its postcheck.
        kill_on_dynamic_loader_attach: Option<u32>,
        /// Pids whose dynamic export attach fails ordinarily: no link is
        /// recorded and no detach bookkeeping is damaged, so the tick stays
        /// open. Mirrors a fixed-purpose attach error, not a refusal.
        fail_dynamic_attach_pids: BTreeSet<u32>,
        /// Refuses every `preflight_targets`, i.e. a pure preflight refusal.
        refuse_preflight: bool,
        /// One entry per upcoming `preflight_targets` call; `true` refuses
        /// that call. Later calls follow `refuse_preflight`.
        preflight_refusals: RefCell<VecDeque<bool>>,
        /// One entry per upcoming `preflight_targets` call: `Some(pid)` is
        /// killed and reaped inside that call, i.e. a generation lost after
        /// the candidate was built but before its admission reads the views.
        preflight_losses: RefCell<VecDeque<Option<u32>>>,
        /// One entry per upcoming `detach_slots` call: `Some(pid)` is killed
        /// and reaped inside that call, i.e. a generation lost during the
        /// kernel's serialized link teardown, after the candidate's admission
        /// and before the next generation check.
        detach_losses: VecDeque<Option<u32>>,
        pub(crate) preflight_targets: RefCell<Vec<Vec<(u32, PinnedObjectId, u64)>>>,
        /// How many times the Engine staged DISCOVERY off the ring.
        pub(crate) stage_calls: usize,
    }

    /// SIGKILL plus `waitpid`, so the retained generation is provably gone
    /// before the caller's postcheck reads it.
    fn kill_and_reap(pid: u32) {
        let pid = pid as libc::pid_t;
        assert_eq!(unsafe { libc::kill(pid, libc::SIGKILL) }, 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    }

    impl ScriptedSession {
        /// A session whose ring holds exactly these records and whose producer
        /// counters authorize `loader_hits` loader records.
        pub(crate) fn with_records(
            records: impl IntoIterator<Item = DiscoveryRecord>,
            loader_hits: u64,
        ) -> Self {
            Self {
                dequeues: records
                    .into_iter()
                    .map(|record| Ok(Some(crate::events::DiscoveryItem::Record(record))))
                    .collect(),
                counters: CounterSnapshot {
                    loader_hits,
                    ..CounterSnapshot::default()
                },
                ..Self::default()
            }
        }

        /// Schedules the outcome of the next producer-counter reads; `true`
        /// fails that read. Later reads succeed.
        pub(crate) fn fail_counter_reads(&mut self, script: impl IntoIterator<Item = bool>) {
            *self.counter_script.borrow_mut() = script.into_iter().collect();
        }

        pub(crate) fn counter_reads(&self) -> u64 {
            self.counter_reads.get()
        }

        /// A session whose next `attach_targets` kills and reaps `pid`, i.e.
        /// loses the retained generation exactly between a link mutation's
        /// generation precheck and its postcheck.
        pub(crate) fn losing_generation_at_attach(pid: u32) -> Self {
            Self {
                kill_on_attach: Some(pid),
                ..Self::default()
            }
        }

        /// Schedules a generation loss inside the next `attach_targets`
        /// call: kills and reaps `pid` exactly between that link mutation's
        /// generation precheck and its postcheck.
        pub(crate) fn lose_generation_at_attach(&mut self, pid: u32) {
            self.kill_on_attach = Some(pid);
        }

        /// A session whose target preflight refuses every candidate.
        pub(crate) fn refusing_preflight() -> Self {
            Self {
                refuse_preflight: true,
                ..Self::default()
            }
        }

        /// Schedules the outcome of the next `preflight_targets` calls; `true`
        /// refuses that call.
        pub(crate) fn refuse_preflights(&mut self, script: impl IntoIterator<Item = bool>) {
            *self.preflight_refusals.borrow_mut() = script.into_iter().collect();
        }

        /// Schedules generation losses inside the next `preflight_targets`
        /// calls: `Some(pid)` kills and reaps `pid` in that call.
        pub(crate) fn lose_generations_at_preflight(
            &mut self,
            script: impl IntoIterator<Item = Option<u32>>,
        ) {
            *self.preflight_losses.borrow_mut() = script.into_iter().collect();
        }

        /// Schedules the outcome of the next one-shot slot detaches; `true`
        /// fails that call. Later calls succeed.
        pub(crate) fn fail_slot_detaches(&mut self, script: impl IntoIterator<Item = bool>) {
            self.detach_slot_script = script.into_iter().collect();
        }

        /// Schedules `detach_slots` errors raised before any link mutation:
        /// `true` fails that call without recording a detach failure.
        pub(crate) fn fail_slot_detaches_before_mutation(
            &mut self,
            script: impl IntoIterator<Item = bool>,
        ) {
            self.detach_slot_premutation_script = script.into_iter().collect();
        }

        /// Schedules generation losses inside the next `detach_slots` calls:
        /// `Some(pid)` kills and reaps `pid` in that call.
        pub(crate) fn lose_generations_at_detach(
            &mut self,
            script: impl IntoIterator<Item = Option<u32>>,
        ) {
            self.detach_losses = script.into_iter().collect();
        }

        /// Schedules one rebuild report per upcoming `detach_slots` call.
        /// Later calls report no rebuild.
        pub(crate) fn report_slot_rebuilds(
            &mut self,
            script: impl IntoIterator<Item = DetachOutcome>,
        ) {
            self.detach_rebuild_script = script.into_iter().collect();
        }

        pub(crate) fn fail_target_slots(&mut self, slots: impl IntoIterator<Item = u32>) {
            self.fail_target_slots = slots.into_iter().collect();
        }

        pub(crate) fn lose_generation_at_dynamic_attach(&mut self, pid: u32) {
            self.kill_on_dynamic_attach = Some(pid);
        }

        /// Schedules a generation loss inside the next `attach_dynamic_loader`:
        /// kills and reaps `pid` between the loader arm's generation precheck
        /// and its postcheck.
        pub(crate) fn lose_generation_at_dynamic_loader_attach(&mut self, pid: u32) {
            self.kill_on_dynamic_loader_attach = Some(pid);
        }

        pub(crate) fn fail_dynamic_attach_for(&mut self, pid: u32) {
            self.fail_dynamic_attach_pids.insert(pid);
        }

        pub(crate) fn clear_dynamic_attach_failures(&mut self) {
            self.fail_dynamic_attach_pids.clear();
        }
    }

    impl EngineSession for ScriptedSession {
        fn capture_policy(&self) -> CapturePolicy {
            self.capture_policy.unwrap_or(CapturePolicy::Allowlisted)
        }

        fn discovery_dequeue(&mut self) -> Result<Option<crate::events::DiscoveryItem>> {
            if let Some(item) = self.staged.pop_front() {
                return Ok(Some(item));
            }
            self.dequeues.pop_front().unwrap_or(Ok(None))
        }

        fn stage_discovery(
            &mut self,
            quantum: usize,
            engine_held: usize,
        ) -> Result<crate::attach::DiscoveryStageOutcome> {
            self.stage_calls += 1;
            let shared_cap = crate::attach::DiscoveryStage::CAPACITY.saturating_sub(engine_held);
            let mut staged = 0;
            let mut capacity_blocked = false;
            while staged < quantum && self.staged.len() < shared_cap {
                match self.dequeues.pop_front() {
                    Some(Ok(Some(item))) => {
                        self.staged.push_back(item);
                        staged += 1;
                    }
                    Some(outcome) => {
                        self.dequeues.push_front(outcome);
                        break;
                    }
                    None => break,
                }
            }
            if staged < quantum && self.staged.len() >= shared_cap {
                capacity_blocked = true;
            }
            Ok(crate::attach::DiscoveryStageOutcome {
                staged,
                capacity_blocked,
            })
        }

        fn staged_discovery_len(&self) -> usize {
            self.staged.len()
        }

        fn counter_snapshot(&self) -> Result<CounterSnapshot> {
            self.counter_reads
                .set(self.counter_reads.get().saturating_add(1));
            if self
                .counter_script
                .borrow_mut()
                .pop_front()
                .unwrap_or(false)
            {
                bail!("scripted producer counter read failed");
            }
            Ok(self.counters)
        }

        fn read_selection_table(
            &mut self,
            view: &ProcessView,
            address: u64,
            layout: LinuxLayout,
            budget: &mut CaptureWorkBudget,
        ) -> std::result::Result<(MapEntry, ScannedTable), ()> {
            self.selection_table_read.take().map_or_else(
                || Engine::read_selection_table(view, address, layout, budget),
                Ok,
            )
        }

        fn detach_failures(&self) -> &[String] {
            &self.detach_failures
        }

        fn lifecycle_tracking_unavailable(&self) -> Option<&str> {
            self.lifecycle_tracking_unavailable
        }

        fn process_creation_tracking_unavailable(&self) -> Option<&str> {
            self.process_creation_tracking_unavailable
        }

        fn preflight_targets(&self, targets: &[plan::Slot], _: &PinnedObjects) -> Result<()> {
            self.preflight_targets.borrow_mut().push(
                targets
                    .iter()
                    .map(|slot| (slot.index, slot.object, slot.file_offset))
                    .collect(),
            );
            if let Some(Some(pid)) = self.preflight_losses.borrow_mut().pop_front() {
                kill_and_reap(pid);
            }
            let refused = self
                .preflight_refusals
                .borrow_mut()
                .pop_front()
                .unwrap_or(self.refuse_preflight);
            attachment_admission(&self.detach_failures, !targets.is_empty())?;
            if refused {
                bail!("scripted target preflight refused the candidate");
            }
            Ok(())
        }

        fn attach_targets(
            &mut self,
            slots: &[plan::Slot],
            _: &PinnedObjects,
        ) -> Result<TargetAttachResult> {
            attachment_admission(&self.detach_failures, !slots.is_empty())?;
            self.attached_slots.push(slots.len());
            if let Some(pid) = self.kill_on_attach.take() {
                kill_and_reap(pid);
            }
            Ok((
                slots
                    .iter()
                    .filter(|slot| self.fail_target_slots.contains(&slot.index))
                    .map(|slot| slot.index)
                    .collect(),
                Vec::new(),
            ))
        }

        fn replace_targets(
            &mut self,
            _: &mut plan::AttachPlan,
            slots: &[plan::Slot],
            _: &PinnedObjects,
        ) -> Result<ReplacementOutcome> {
            self.replaced_slot_indices
                .push(slots.iter().map(|slot| slot.index).collect());
            attachment_admission(&self.detach_failures, !slots.is_empty())?;
            Ok(ReplacementOutcome::default())
        }

        fn detach_slots(&mut self, slots: &[plan::Slot]) -> Result<DetachOutcome> {
            self.detached_slots.push(slots.len());
            self.detached_slot_indices
                .push(slots.iter().map(|slot| slot.index).collect());
            if let Some(Some(pid)) = self.detach_losses.pop_front() {
                kill_and_reap(pid);
            }
            if self
                .detach_slot_premutation_script
                .pop_front()
                .unwrap_or(false)
            {
                bail!("scripted program fd resolution failed before any link mutation");
            }
            if self.detach_slot_script.pop_front().unwrap_or(false) {
                self.detach_failures
                    .push("scripted one-shot slot detach failed".into());
                bail!("scripted one-shot slot detach failed");
            }
            Ok(self.detach_rebuild_script.pop_front().unwrap_or_default())
        }

        fn has_dynamic_export(
            &self,
            context: LoaderContextId,
            target: (PinnedObjectId, u64),
            cookie: u64,
            abi: HookAbi,
        ) -> bool {
            self.dynamic_export_links
                .contains(&(context, target.0, target.1, cookie, abi))
        }

        fn attach_dynamic_export(
            &mut self,
            context: LoaderContextId,
            pid: u32,
            target: (PinnedObjectId, u64),
            cookie: u64,
            abi: HookAbi,
            _: &PinnedObjects,
        ) -> Result<(bool, Option<u64>)> {
            if self.has_dynamic_export(context, target, cookie, abi) {
                return Ok((false, None));
            }
            if self.fail_dynamic_attach_pids.contains(&pid) {
                bail!("scripted dynamic export attach failed");
            }
            attachment_admission(&self.detach_failures, true)?;
            self.dynamic_export_links
                .push((context, target.0, target.1, cookie, abi));
            self.dynamic_attach_calls.push(DynamicExportIdentity {
                object: target.0,
                file_offset: target.1,
                cookie,
                abi,
            });
            if self.kill_on_dynamic_attach.take().is_some() {
                kill_and_reap(pid);
            }
            Ok((self.dynamic_attach_reports_added, None))
        }

        fn attach_dynamic_loader(
            &mut self,
            context: LoaderContextId,
            _: u32,
            object: PinnedObjectId,
            file_offset: u64,
            cookie: u64,
            _: &PinnedObjects,
        ) -> std::result::Result<bool, DynamicLoaderAttachFailure> {
            let identity = (context, object, file_offset, cookie);
            if self.dynamic_loader_links.contains(&identity) {
                return Ok(false);
            }
            attachment_admission(&self.detach_failures, true)
                .map_err(DynamicLoaderAttachFailure::Registry)?;
            self.dynamic_loader_links.push(identity);
            self.dynamic_loader_attach_calls += 1;
            if let Some(pid) = self.kill_on_dynamic_loader_attach.take() {
                kill_and_reap(pid);
            }
            Ok(self.dynamic_loader_reports_added)
        }

        fn detach_dynamic_context(
            &mut self,
            context: LoaderContextId,
        ) -> (Vec<DynamicExportIdentity>, bool) {
            self.detached.push(context);
            self.dynamic_export_links
                .retain(|identity| identity.0 != context);
            self.dynamic_loader_links
                .retain(|identity| identity.0 != context);
            if self.detach_failed {
                self.detach_failures
                    .push("scripted dynamic detach failed".into());
            }
            (self.detach_exports.clone(), self.detach_failed)
        }

        fn arm_pause(&mut self) -> Result<()> {
            Ok(())
        }

        fn pause_state(&self) -> Result<Option<u64>> {
            Ok(None)
        }

        fn remove_pause(&mut self) -> Result<Option<u64>> {
            Ok(None)
        }
    }
}

/// Real-lifecycle setup and observation for the crate's terminal-authority
/// tests. Nothing here reimplements Engine behavior; it only builds the exact
/// starting state and reports the private journal/batch it produced.
#[cfg(test)]
impl Engine {
    /// One retained live view for `pid` plus one attached loader context whose
    /// view is already queued for retirement, i.e. the state a terminal drain
    /// starts from.
    pub(crate) fn retiring_loader_context(pid: u32) -> (Self, LoaderContextId) {
        use p11scope_manifest::elf::SymbolFact;

        let view = ProcessView::open(ProcessViewId(0), pid).expect("a live process view");
        let view_id = view.id();
        let mut engine = Self::empty();
        engine.scope = Scope::Pid(pid);
        engine.views.push(view);
        engine.next_view_id = 1;
        let prepared = engine
            .loader_registry
            .preflight(LoaderContextSpec {
                view: view_id,
                loader: PinnedObjectId(9),
                mapping: None,
                hook: SymbolFact {
                    virtual_address: 0x2100,
                    file_offset: 0x2100,
                },
                state_address: None,
            })
            .expect("a preflighted loader context");
        let context = engine
            .loader_registry
            .prepare(prepared)
            .expect("a prepared loader context");
        engine
            .loader_registry
            .mark_attached(context)
            .expect("an attached loader context");
        engine
            .retirement_intents
            .insert(view_id, RetirementCause::ExecRefresh);
        (engine, context)
    }

    pub(crate) fn terminal_batch_for_test(&self) -> Option<&TerminalBatch> {
        self.terminal_batch.as_ref()
    }

    /// The deadline most recently installed into the capture work budget by a
    /// batch apply; the end-of-batch clear does not erase it.
    pub(crate) fn installed_budget_deadline_for_test(&self) -> Option<u64> {
        self.budget.last_installed_deadline
    }

    #[cfg(test)]
    pub(crate) fn malformed_discovery_for_test(&self) -> u64 {
        self.malformed_discovery
    }

    pub(crate) fn unvalidated_discovery_for_test(&self) -> u64 {
        self.discovery_truncated
    }

    pub(crate) fn start_cleanup_only_terminal_journal_for_test(&mut self, owner: LoaderContextId) {
        self.retirement_intents.clear();
        self.terminal_batch = None;
        self.terminal_journal = Some(TerminalJournal {
            owner,
            dispatch_started: true,
            retry_used: true,
        });
    }

    pub(crate) fn tombstone_loader_context_for_test(&mut self, owner: LoaderContextId) {
        self.loader_registry.tombstone(owner).unwrap();
    }

    pub(crate) fn pending_discovery_records_for_test(&self) -> usize {
        self.pending_discovery_records.len()
    }

    /// A blank engine for cross-module tests that cannot name the private
    /// constructor: pid scope on the test process, no views, no requests.
    pub(crate) fn empty_for_test() -> Self {
        Self::empty()
    }

    /// Charges the capture budget from cross-module tests: work charges
    /// are observed exactly through the ceiling itself.
    pub(crate) fn budget_charge_for_test(&mut self, units: u64) -> bool {
        self.budget.charge(units)
    }

    /// `(owner, dispatch_started, retry_used)` of the private lifecycle journal.
    pub(crate) fn terminal_journal_for_test(&self) -> Option<(LoaderContextId, bool, bool)> {
        self.terminal_journal
            .map(|journal| (journal.owner, journal.dispatch_started, journal.retry_used))
    }

    /// Loader records that passed the real producer-counter gate, i.e. the
    /// number of records the Engine actually dispatched.
    pub(crate) fn dispatched_loader_records(&self) -> u64 {
        self.loader_records_accepted
    }

    pub(crate) fn loader_context_state_for_test(
        &self,
        context: LoaderContextId,
    ) -> Option<&'static str> {
        self.loader_registry.context(context).map(|_| {
            if self.loader_registry.is_tombstoned(context) {
                "tombstoned"
            } else {
                "live"
            }
        })
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
pub(crate) mod tests;

#[cfg(test)]
#[path = "publication_tests.rs"]
pub(crate) mod publication_tests;
