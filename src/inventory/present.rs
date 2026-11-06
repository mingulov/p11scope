//! SPDX-License-Identifier: GPL-3.0-or-later
//! U0 presentation model: ONE owned snapshot reused for JSON and terminal
//! rendering (identities, lifecycle/presence states, totals, gaps).
//!
//! The JSON document (`p11scope/inventory/v1`) stays the versioned
//! contract; the pager snapshot and the dashboard render the SAME
//! [`Presentation`], never a divergent computation. Capture reads the
//! live coordinator once per pass into an immutable [`Presentation`];
//! every renderer below that point is a pure function of the snapshot.
//!
//! Dashboard vocabulary is the plan's exact wording (no synonyms):
//! presence `mapped | unloaded | process exited | unknown`; capture
//! `armed | scan only | refused | retired | coverage lost | watch ended`; activity
//! `recently observed | operation initialized / in flight | used
//! (recency unknown) | quiet | unknown (lossy) | not covered |
//! unknown`. Quiet is not unloaded; capture refusal is not application
//! inactivity; witnessed use is never quiet; an edge whose usage nothing
//! covers is neither quiet nor armed (Task 6 C2 review I3).
//! The mapping from registry state is documented on each enum and
//! pinned by tests. Per-edge usage coverage ([`UseCoverage`]) renders
//! through [`coverage_label`] in snapshots and dashboard frames and as
//! `entries.coverage` in JSON.

use crate::discovery::caller_registry::instance_input::{InstanceLifecycle, RegistryInstanceId};
use crate::discovery::caller_registry::{
    AdmissionChange, AdmissionState, BudgetRefusal, CallerId, CallerLifecycle, CallerRecord,
    ExeIdentity, ImageAuthority, JointPublicationPending, MappingState, ModuleId, ModuleLifecycle,
    ModuleRecord, NO_MAPPING_EDGE, ProcessSource, SEMANTIC_UNKNOWN, UnknownReason, UseCoverage,
};
use crate::discovery::engine::inventory_coordinator::semantics::InventoryReloadDisclosure;
use crate::discovery::engine::inventory_coordinator::{InventoryCoordinator, PrearmReportRow};
use crate::render::escape_controls;
use crate::semantics_edge::resources::SemanticResourceSnapshot;
use crate::semantics_edge::{EdgeEvidence, EdgeSemantics, S1Occupancy};

#[path = "present/render_index.rs"]
mod render_index;
pub(crate) use render_index::{PresentationRenderIndex, SemanticChildren};

/// Trailing window for the dashboard display's "recently observed":
/// an entry whose last-seen falls inside this window (of the frame's
/// `now_ns`) reads as recent on screen. The recorded activity signal
/// is per-pass instead ("rose since previous pass"), window-free.
pub(crate) const DASHBOARD_ACTIVITY_WINDOW_NS: u64 = 5_000_000_000;

/// Presence of one caller/module association: the plan's exact labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    Mapped,
    Unloaded,
    ProcessExited,
    Unknown,
}

impl Presence {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Mapped => "mapped",
            Self::Unloaded => "unloaded",
            Self::ProcessExited => "process exited",
            Self::Unknown => "unknown",
        }
    }

    /// Presence from endpoint lifecycles plus the edge's mapping proof:
    /// an exited caller reads as exited even though its edges ended;
    /// an unloaded module reads as unloaded; a live mapping on both
    /// live endpoints reads as mapped; anything uncertain
    /// (`exec_retired`, `uncertain` mapping, unknown lifecycles) reads
    /// as unknown, never as a confident label.
    pub(crate) fn for_edge(
        caller: &CallerRecord,
        module: &ModuleRecord,
        mapping: MappingState,
    ) -> Self {
        if caller.lifecycle == CallerLifecycle::Exited {
            Self::ProcessExited
        } else if module.lifecycle == ModuleLifecycle::Unloaded {
            Self::Unloaded
        } else if caller.lifecycle == CallerLifecycle::Mapped
            && module.lifecycle == ModuleLifecycle::Mapped
            && mapping == MappingState::Mapped
        {
            Self::Mapped
        } else {
            Self::Unknown
        }
    }
}

/// Capture state of one association: what the observer could do about
/// it. Refusal is admission/budget (the observer was not allowed to
/// capture); retirement is a proven end (caller retired, edge ended);
/// coverage loss is missing evidence (unresolved admission, uncertain
/// mapping, unknown lifecycles, or usage coverage that was lost or never
/// reached the edge — attach failure, not attached, health loss,
/// capacity; the edge's `entries.coverage` names the reason); scan only
/// is a live mapping no usage producer instruments; armed is a live edge
/// whose usage is actually covered (counted, witnessed, or watched);
/// watch ended is a watch frozen at capture stop or at a scope custody
/// loss before it (`WatchedNoUse{until: Some}`): a fact about a past
/// interval, never armed (C5.2 M-2; its activity reads unknown and its
/// dashboard count `?`, the interval stays in the coverage label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capture {
    Armed,
    ScanOnly,
    Refused,
    Retired,
    CoverageLost,
    WatchEnded,
}

impl Capture {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::ScanOnly => "scan only",
            Self::Refused => "refused",
            Self::Retired => "retired",
            Self::CoverageLost => "coverage lost",
            Self::WatchEnded => "watch ended",
        }
    }

    pub(crate) fn for_edge(
        caller: &CallerRecord,
        module: &ModuleRecord,
        mapping: MappingState,
        coverage: &UseCoverage,
    ) -> Self {
        if module.admission == AdmissionState::Refused {
            Self::Refused
        } else if caller.retired || mapping == MappingState::Ended {
            Self::Retired
        } else if module.admission == AdmissionState::Unresolved
            || mapping == MappingState::Uncertain
            || caller.lifecycle == CallerLifecycle::Unknown
            || module.lifecycle == ModuleLifecycle::Unknown
        {
            Self::CoverageLost
        } else {
            match coverage {
                UseCoverage::WatchedNoUse {
                    until_ns: Some(_), ..
                } => Self::WatchEnded,
                UseCoverage::Counted { .. }
                | UseCoverage::Witnessed { .. }
                | UseCoverage::WatchedNoUse { .. } => Self::Armed,
                UseCoverage::Unknown(UnknownReason::ScanOnly) => Self::ScanOnly,
                UseCoverage::Unknown(_) => Self::CoverageLost,
            }
        }
    }
}

/// Activity of one association: recency of observed entries, never a
/// sticky bit. In-flight wins — a call inside the API now OR a live
/// operation machine (S1 genuine operation state, not recency alone);
/// then recent last-seen inside the window (counted coverage is the only
/// recency source); then used (witnessed use with no count or recency —
/// never quiet, whatever the mapping); anything without a live mapping
/// reads as unknown, as does a watch that ended (a fact about its
/// interval only), and as does a watched edge whose caller's first use
/// is read but undecided (a pending row: the use may already have
/// happened, so quiet would lie); then, for a live mapping, quiet only
/// where the quiet is a fact — a loss-free counting feed or an ongoing
/// watch with no recent entry; a lossy feed reads unknown (lossy); and
/// an edge no
/// usage producer covers (scan only, refused, not attached, lost) reads
/// not covered — never idle. Quiet is not unloaded: unloaded
/// edges are never mapped, so they never read as quiet.
/// The three "right now" inputs (recent call, initialized operation,
/// in-flight API call) stay distinct facts in the JSON; this label is
/// their precedence rendering in plan vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Activity {
    RecentlyObserved,
    InFlight,
    Used,
    Quiet,
    Lossy,
    Uncovered,
    Unknown,
}

impl Activity {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::RecentlyObserved => "recently observed",
            Self::InFlight => "operation initialized / in flight",
            Self::Used => "used (recency unknown)",
            Self::Quiet => "quiet",
            Self::Lossy => "unknown (lossy)",
            Self::Uncovered => "not covered",
            Self::Unknown => "unknown",
        }
    }

    /// `active` is the pass rise (the recorded per-pass signal) or
    /// window recency (the dashboard display only); this maps states,
    /// never recomputes either. `op_active` is genuine S1 operation
    /// state (a live machine), never activity. `coverage` is the
    /// edge's usage coverage: it decides whether a silent live edge is
    /// quiet (a fact) or uncovered.
    pub(crate) fn for_edge(
        mapping: MappingState,
        in_flight: bool,
        active: bool,
        op_active: bool,
        coverage: &UseCoverage,
    ) -> Self {
        if in_flight || op_active {
            return Self::InFlight;
        }
        if active {
            return Self::RecentlyObserved;
        }
        if coverage.is_witnessed() {
            return Self::Used;
        }
        if mapping != MappingState::Mapped {
            return Self::Unknown;
        }
        match coverage {
            // A frozen watch is a fact about `since..until` only (the
            // coverage label keeps it): nothing says the edge is quiet now.
            UseCoverage::WatchedNoUse {
                until_ns: Some(_), ..
            } => Self::Unknown,
            // A first use is read but undecided: the edge is watched, so
            // "not covered" would lie — its activity is unknown.
            UseCoverage::Unknown(UnknownReason::PendingFirstUse) => Self::Unknown,
            UseCoverage::Counted { lossy: false, .. } | UseCoverage::WatchedNoUse { .. } => {
                Self::Quiet
            }
            UseCoverage::Counted { lossy: true, .. } => Self::Lossy,
            UseCoverage::Witnessed { .. } | UseCoverage::Unknown(_) => Self::Uncovered,
        }
    }
}

/// One caller incarnation, owned for rendering.
#[derive(Debug, Clone)]
pub(crate) struct CallerView {
    pub id: CallerId,
    pub pid: u32,
    pub start_time: Option<u64>,
    pub incarnation: u32,
    pub exe: Option<ExeIdentity>,
    pub exec_observed: bool,
    pub authority: ImageAuthority,
    pub lifecycle: CallerLifecycle,
    pub lifecycle_reason: Option<String>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub retired: bool,
}

/// One module instance, owned for rendering.
#[derive(Debug, Clone)]
pub(crate) struct ModuleView {
    pub id: ModuleId,
    pub paths: Vec<String>,
    pub device_major: u64,
    pub device_minor: u64,
    pub inode: u64,
    pub sha256: Option<String>,
    pub build_id: Option<String>,
    pub identity_source: Option<String>,
    pub admission: AdmissionState,
    pub admission_class: Option<String>,
    pub admission_endpoints: Option<usize>,
    pub admission_reasons: Vec<String>,
    pub admission_history: Vec<AdmissionChange>,
    pub lifecycle: ModuleLifecycle,
    pub unloaded_observed: bool,
    /// Natively witnessed use no caller edge carries (Task 6 C4).
    pub unbound_use: Option<crate::discovery::caller_registry::UnboundUse>,
}

/// One mechanism id's published facts (S1), owned for rendering.
/// The id stays verbatim; the name is `Some` iff registered.
#[derive(Debug, Clone)]
pub(crate) struct MechanismView {
    pub id: u64,
    pub name: Option<&'static str>,
    pub operations: Vec<&'static str>,
    pub calls: u64,
    pub errors: u64,
    pub last_seen_ns: u64,
    pub functions: Vec<String>,
    pub returns: Vec<u64>,
    pub truncated: bool,
}

/// Live machines aggregated by (category, state), owned.
#[derive(Debug, Clone)]
pub(crate) struct ActiveOpView {
    pub category: String,
    pub state: &'static str,
    pub count: u64,
}

/// One edge's operation aggregates (S1), owned for rendering.
#[derive(Debug, Clone)]
pub(crate) struct OperationsView {
    pub calls: u64,
    pub started: u64,
    pub completed: u64,
    pub cancelled: u64,
    pub failed: u64,
    pub unknown: u64,
    pub orphans: u64,
    pub dropped: u64,
    pub last_seen_ns: u64,
    pub active: Vec<ActiveOpView>,
    pub evidence: EdgeEvidence,
}

/// One edge's semantic column (S1), owned for rendering: the summary
/// label plus, when the edge holds claims, the mechanism rows and the
/// operation aggregates. `None` operations ⟺ an `unknown` label.
#[derive(Debug, Clone)]
pub(crate) struct EdgeSemanticsView {
    pub label: &'static str,
    pub mechanisms: Vec<MechanismView>,
    pub operations: Option<OperationsView>,
}

/// One caller/module edge with its presentation states, owned.
#[derive(Debug, Clone)]
pub(crate) struct EdgeView {
    pub caller: CallerId,
    pub module: ModuleId,
    pub mapping: MappingState,
    pub mapping_reason: Option<String>,
    pub mapping_evidence: crate::discovery::caller_registry::MappingEvidence,
    pub mapping_first_seen_ns: u64,
    pub mapping_last_seen_ns: u64,
    pub mapping_interruptions: u64,
    pub entry_count: u64,
    pub entry_saturated: bool,
    pub entry_first_seen_ns: Option<u64>,
    pub entry_last_seen_ns: Option<u64>,
    pub entry_in_flight: bool,
    pub entry_observation: &'static str,
    pub coverage: UseCoverage,
    pub presence: Presence,
    pub capture: Capture,
    pub activity: Activity,
    pub semantics: EdgeSemanticsView,
}

/// A public capture-local instance reference; private routing identity stays
/// in the registry. All renderer references resolve in this snapshot.
#[derive(Debug, Clone)]
pub(crate) struct InstanceView {
    pub id: RegistryInstanceId,
    pub caller: CallerId,
    pub module: ModuleId,
    pub state: InstanceLifecycle,
    pub reason: Option<&'static str>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

/// Return evidence and S1 aggregates for one instance. Inventory entry counts
/// remain on the physical edge and are never apportioned to this child.
#[derive(Debug, Clone)]
pub(crate) struct InstanceSemanticView {
    pub instance: RegistryInstanceId,
    pub caller: CallerId,
    pub module: ModuleId,
    pub api_returns: Option<u64>,
    pub saturated: bool,
    pub historical_only_returns: u64,
    pub semantics: EdgeSemanticsView,
    pub lossy: bool,
    pub reasons: Vec<&'static str>,
}

/// One coverage gap, owned for rendering.
#[derive(Debug, Clone)]
pub(crate) struct GapView {
    pub caller: Option<CallerId>,
    pub module: Option<ModuleId>,
    pub pid: Option<u32>,
    pub subject: String,
    pub reason: String,
    pub budget: Option<BudgetRefusal>,
    /// How many times this identical gap was recorded this run (>= 1).
    pub repeats: u64,
}

/// Shared allocation charges and actual owned-state counts at publication.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SemanticResourceView {
    pub charges: SemanticResourceSnapshot,
    pub occupancy: S1Occupancy,
}

#[cfg(test)]
impl Default for SemanticResourceView {
    fn default() -> Self {
        Self {
            charges: crate::semantics_edge::resources::SemanticResourcePool::default().snapshot(),
            occupancy: S1Occupancy::default(),
        }
    }
}

/// Every budgeted resource with limit, occupancy, and loss counter.
#[derive(Debug, Clone)]
pub(crate) struct BudgetView {
    pub callers_limit: usize,
    pub callers_occupied: usize,
    pub callers_refused: u64,
    pub modules_limit: usize,
    pub modules_occupied: usize,
    pub modules_refused: u64,
    pub edges_limit: usize,
    pub edges_occupied: usize,
    pub edges_refused: u64,
    pub endpoints_limit: usize,
    pub endpoints_occupied: usize,
    pub endpoints_refused: u64,
    /// The run's Inventory attach set: its capture-lifetime endpoint
    /// budget and the endpoints it holds (IDs are never reused, so
    /// occupancy only grows).
    pub inventory_endpoints_limit: usize,
    pub inventory_endpoints_occupied: usize,
    /// Per-pass module refusals on the attach set's endpoint budget.
    pub inventory_endpoints_refused: u64,
    /// The attach set's module records (capped at its endpoint budget).
    pub inventory_modules_limit: usize,
    pub inventory_modules_occupied: usize,
    /// Per-pass module refusals on the module-record cap.
    pub inventory_modules_refused: u64,
    pub counters_observed: usize,
    pub counters_saturated: usize,
    pub semantic_limit: usize,
    pub semantic_occupied: usize,
    pub semantic_unknown_edges: usize,
    pub semantic_refused: u64,
    pub instances_limit: usize,
    pub instances_occupied: usize,
    pub instances_refused: u64,
    pub instance_semantic_occupied: usize,
    pub instance_semantic_unknown_edges: usize,
    pub instance_semantic_refused: u64,
    pub instance_negative_limit: usize,
    pub instance_negative_occupied: usize,
    pub instance_negative_refused: u64,
    pub instance_negative_exhausted: bool,
    pub instance_semantic_resources: SemanticResourceView,
    pub retained_limit: usize,
    pub retained: usize,
    pub retained_suppressed: u64,
    /// The native lane's pre-admission stash (R-C51-5): unbound use rows
    /// held per (pid, module) until their caller's admission; `None` in
    /// the scan lane.
    pub preadmission: Option<crate::discovery::engine::inventory_coordinator::PreadmissionCounters>,
}

impl BudgetView {
    /// Budget refusals across the four refusing resources: the coverage
    /// line's refusal count.
    pub(crate) fn refusals(&self) -> u64 {
        self.callers_refused
            .saturating_add(self.modules_refused)
            .saturating_add(self.edges_refused)
            .saturating_add(self.endpoints_refused)
    }
}

/// Compact charges first, followed by counts without private identifiers.
pub(crate) fn semantic_resource_line(view: &SemanticResourceView) -> String {
    let charge = view.charges;
    let usage = view.occupancy;
    format!(
        "semantic {}/{}B peak={} refused={} | open={} active={} pending={} detached={} mechanisms={} categories={} functions={} function_bytes={} function_capacity={} returns={} async_bytes={} async_capacity={} origins={} origin_elements={} origin_capacity={}",
        charge.charged_bytes,
        charge.limit_bytes,
        charge.peak_charged_bytes,
        charge.refused,
        usage.open_bindings,
        usage.active_machines,
        usage.pending_calls,
        usage.detached_calls,
        usage.mechanisms,
        usage.operation_categories,
        usage.provenance_functions,
        usage.provenance_function_bytes,
        usage.provenance_function_capacity_bytes,
        usage.provenance_returns,
        usage.async_function_bytes,
        usage.async_function_capacity_bytes,
        usage.origin_vectors,
        usage.origin_elements,
        usage.origin_capacity_elements,
    )
}

/// The ONE presentation snapshot: immutable, owned, sorted. Built once
/// per pass from the live coordinator; JSON, pager snapshots, the
/// dashboard, and the event stream all render from this.
#[derive(Debug, Clone)]
pub(crate) struct Presentation {
    pub scope_label: String,
    pub started_ns: u64,
    pub ended_ns: u64,
    pub passes: u64,
    /// Derived summary only: some edge holds non-unknown coverage.
    pub usage_feed: bool,
    /// The native binder's census: witness rows bound to a caller
    /// incarnation, unbound per reason, waiting, and failing validation
    /// (the DR-05 unbound-witness measurement).
    pub native_witnesses: crate::discovery::native_binding::BindingCensus,
    /// Where the decided witness rows went (edge, module-level, ambiguous
    /// shared endpoint, unresolved); sums to `bound + unbound`.
    pub witness_placement: crate::discovery::caller_registry::WitnessPlacement,
    /// Display-only opt-in metadata shared by every consumer of this frame.
    pub caller_metadata: crate::caller_metadata::runtime::MetadataFrame,
    pub callers: Vec<CallerView>,
    pub modules: Vec<ModuleView>,
    pub edges: Vec<EdgeView>,
    pub instances: Vec<InstanceView>,
    pub semantic_edges: Vec<InstanceSemanticView>,
    /// The staged reload disclosure, if the capture produced one: exact
    /// router counts plus the affected modules with their registered
    /// instances. Renders as the top-level
    /// `instance_reload_not_excluded` object; absent when `None`.
    pub instance_reload_not_excluded: Option<InventoryReloadDisclosure>,
    /// Offsets into these immutable rows. A test fixture replacing rows must
    /// rebuild this cache or reset it to the lossless linear default.
    pub(crate) render_index: PresentationRenderIndex,
    pub gaps: Vec<GapView>,
    pub gaps_suppressed: u64,
    /// Files skipped by `--exclude-module` (a declared operator choice,
    /// never a loss), plus the inputs that matched nothing. Empty unless
    /// the operator passed `--exclude-module`.
    pub excluded_modules: Vec<crate::render::ExcludedOut>,
    pub unmatched_excludes: Vec<String>,
    pub budgets: BudgetView,
    /// The sanitized Detailed-lane summary (`observation.
    /// semantic_capture`): counts only, set by the run loop from the
    /// lane after capture; `disabled` without a lane. The summary
    /// grants no semantic permission.
    pub semantic_capture: crate::inventory_semantics::SemanticCaptureSummary,
    /// The H9 operation/key projection (additive, versioned): the ONE
    /// immutable observation JSON, JSONL and the dashboard share.
    /// Unavailable until Joint evidence exists; S1 never waits for it.
    pub object_observations: crate::key_operation_projection::ObjectObservations,
    /// One assembled row per `--prearm-module` input, in flag order;
    /// empty without the flag. Pass views show live watches, the final
    /// view terminal ones — no special-casing.
    pub prearm: Vec<PrearmReportRow>,
    /// Whether `--key-operations` was requested for this run (text
    /// only: distinguishes "requested but unavailable" from "off";
    /// JSON keeps the observations and gaps).
    pub key_operations_requested: bool,
    /// Whether the run carries manifests (text only: without one no
    /// semantic start is attempted, so no refusal gap exists).
    pub manifests_present: bool,
}

/// What an edge's activity label answers (Choice 3).
#[derive(Debug, Clone, Copy)]
enum ActivityBasis {
    /// Per-pass ("rose since previous pass"): the recorded activity
    /// signal (JSON, JSONL, pager). Window-free.
    PerPass,
    /// Recency within `window_ns` of `now_ns`: the dashboard display's
    /// trailing "recently observed" only.
    Recency { now_ns: u64, window_ns: u64 },
}

impl Presentation {
    /// Capture the coordinator's published state into an immutable
    /// snapshot, with the per-pass activity signal ("rose since
    /// previous pass"). JSON, the event stream, and the pager read this.
    pub(crate) fn capture<Source: ProcessSource>(
        coordinator: &InventoryCoordinator<Source>,
        scope_label: &str,
        started_ns: u64,
        ended_ns: u64,
        passes: u64,
    ) -> Self {
        Self::try_capture(coordinator, scope_label, started_ns, ended_ns, passes)
            .expect("capture requires a completed registry publication")
    }

    pub(crate) fn try_capture<Source: ProcessSource>(
        coordinator: &InventoryCoordinator<Source>,
        scope_label: &str,
        started_ns: u64,
        ended_ns: u64,
        passes: u64,
    ) -> Result<Self, JointPublicationPending> {
        Self::capture_inner(
            coordinator,
            scope_label,
            started_ns,
            ended_ns,
            passes,
            ActivityBasis::PerPass,
        )
    }

    /// Capture for the dashboard display: as [`Self::capture`], but the
    /// activity label answers window recency (last-seen within
    /// `window_ns` of the frame's `now_ns`) instead of the pass rise.
    /// Production passes [`DASHBOARD_ACTIVITY_WINDOW_NS`].
    pub(crate) fn capture_dashboard<Source: ProcessSource>(
        coordinator: &InventoryCoordinator<Source>,
        scope_label: &str,
        started_ns: u64,
        ended_ns: u64,
        passes: u64,
        now_ns: u64,
        window_ns: u64,
    ) -> Self {
        Self::try_capture_dashboard(
            coordinator,
            scope_label,
            started_ns,
            ended_ns,
            passes,
            now_ns,
            window_ns,
        )
        .expect("dashboard capture requires a completed registry publication")
    }

    pub(crate) fn try_capture_dashboard<Source: ProcessSource>(
        coordinator: &InventoryCoordinator<Source>,
        scope_label: &str,
        started_ns: u64,
        ended_ns: u64,
        passes: u64,
        now_ns: u64,
        window_ns: u64,
    ) -> Result<Self, JointPublicationPending> {
        Self::capture_inner(
            coordinator,
            scope_label,
            started_ns,
            ended_ns,
            passes,
            ActivityBasis::Recency { now_ns, window_ns },
        )
    }

    fn capture_inner<Source: ProcessSource>(
        coordinator: &InventoryCoordinator<Source>,
        scope_label: &str,
        started_ns: u64,
        ended_ns: u64,
        passes: u64,
        basis: ActivityBasis,
    ) -> Result<Self, JointPublicationPending> {
        if coordinator.publication_pending() {
            return Err(JointPublicationPending);
        }
        let registry = coordinator.registry();
        let mut caller_ids: Vec<CallerId> = coordinator
            .adapter()
            .records()
            .map(|record| record.id)
            .collect();
        caller_ids.sort();
        let mut callers = Vec::with_capacity(caller_ids.len());
        for id in &caller_ids {
            let record = coordinator
                .adapter()
                .record(*id)
                .expect("captured callers are adapter records");
            callers.push(CallerView {
                id: *id,
                pid: record.pid,
                start_time: record.start_time,
                incarnation: record.incarnation,
                exe: record.exe.clone(),
                exec_observed: record.exec_observed,
                authority: record.authority,
                lifecycle: record.lifecycle,
                lifecycle_reason: record.lifecycle_reason.clone(),
                first_seen_ns: record.first_seen_ns,
                last_seen_ns: record.last_seen_ns,
                retired: record.retired,
            });
        }
        let mut module_ids: Vec<ModuleId> = registry.modules().map(|module| module.id).collect();
        module_ids.sort();
        let mut modules = Vec::with_capacity(module_ids.len());
        for id in &module_ids {
            let record = registry
                .module(*id)
                .expect("captured modules are registry records");
            let (device_major, device_minor, inode, sha256) = match &record.key {
                crate::discovery::caller_registry::ModuleKey::Physical {
                    dev_major,
                    dev_minor,
                    ino,
                    sha256,
                } => (*dev_major, *dev_minor, *ino, sha256.clone()),
                crate::discovery::caller_registry::ModuleKey::Unidentified { .. } => {
                    (0, 0, 0, None)
                }
            };
            modules.push(ModuleView {
                id: *id,
                paths: record.paths.iter().cloned().collect(),
                device_major,
                device_minor,
                inode,
                sha256,
                build_id: record.build_id.clone(),
                identity_source: record.identity_source.clone(),
                admission: record.admission,
                admission_class: record.admission_class.clone(),
                admission_endpoints: record.admission_endpoints,
                admission_reasons: record.admission_reasons.clone(),
                admission_history: record.admission_history.clone(),
                lifecycle: record.lifecycle,
                unloaded_observed: record.unloaded_observed,
                unbound_use: record.unbound_use.clone(),
            });
        }
        let mut edge_keys: Vec<(CallerId, ModuleId)> = registry
            .edges()
            .map(|edge| (edge.caller, edge.module))
            .collect();
        edge_keys.sort();
        // Edges whose per-edge feed never materialized but whose instance
        // children hold mechanism/operation claims: their label must not
        // deny the observed feed (see semantics_view).
        let claimed_children: std::collections::BTreeSet<(CallerId, ModuleId)> = registry
            .instance_semantic_edges()
            .filter(|row| {
                row.semantics
                    .as_ref()
                    .is_some_and(EdgeSemantics::has_claims)
            })
            .map(|row| (row.caller, row.module))
            .collect();
        let mut edges = Vec::with_capacity(edge_keys.len());
        for (caller_id, module_id) in &edge_keys {
            let edge = registry
                .edge(*caller_id, *module_id)
                .expect("captured edges are registry records");
            let caller_record = coordinator
                .adapter()
                .record(*caller_id)
                .expect("every captured edge caller resolves in the adapter");
            let module_record = registry
                .module(*module_id)
                .expect("every captured edge module resolves in the registry");
            // The presented coverage overlays a pending first-use row as
            // unknown; every consumer reads through it.
            let coverage = coordinator.presented_coverage(edge);
            // Activity comes only from counted coverage: the pass rise
            // (the signal), or window recency (the dashboard display).
            let counted = matches!(coverage, UseCoverage::Counted { .. });
            let active = counted
                && match basis {
                    ActivityBasis::PerPass => edge.entry_rose_since_previous_pass,
                    ActivityBasis::Recency { now_ns, window_ns } => {
                        registry.entry_recent_within(edge, now_ns, window_ns)
                    }
                };
            let semantics = semantics_view(
                edge.semantics.as_ref(),
                claimed_children.contains(&(*caller_id, *module_id)),
            );
            let op_active = edge
                .semantics
                .as_ref()
                .is_some_and(EdgeSemantics::has_live_operations);
            edges.push(EdgeView {
                caller: *caller_id,
                module: *module_id,
                mapping: edge.mapping,
                mapping_reason: edge.mapping_reason.clone(),
                mapping_evidence: edge.mapping_evidence,
                mapping_first_seen_ns: edge.mapping_first_seen_ns,
                mapping_last_seen_ns: edge.mapping_last_seen_ns,
                mapping_interruptions: edge.mapping_interruptions,
                entry_count: edge.entry_count,
                entry_saturated: edge.entry_saturated,
                entry_first_seen_ns: edge.entry_first_seen_ns,
                entry_last_seen_ns: edge.entry_last_seen_ns,
                entry_in_flight: edge.entry_in_flight,
                entry_observation: registry.entry_observation_for(edge, &coverage).label(),
                presence: Presence::for_edge(caller_record, module_record, edge.mapping),
                capture: Capture::for_edge(caller_record, module_record, edge.mapping, &coverage),
                activity: Activity::for_edge(
                    edge.mapping,
                    edge.entry_in_flight,
                    active,
                    op_active,
                    &coverage,
                ),
                coverage,
                semantics,
            });
        }
        let instances: Vec<InstanceView> = registry
            .instances()
            .map(|r| InstanceView {
                id: r.id,
                caller: r.caller,
                module: r.module,
                state: r.state,
                reason: r.reason.map(|reason| reason.label()),
                first_seen_ns: r.first_seen_ns,
                last_seen_ns: r.last_seen_ns,
            })
            .collect();
        let semantic_edges: Vec<InstanceSemanticView> = registry
            .instance_semantic_edges()
            .map(|r| {
                let mut semantics = semantics_view(r.semantics.as_ref(), false);
                if r.semantics.is_none() {
                    semantics.label = if r.api_returns.is_none() {
                        "unknown (no calls observed)"
                    } else {
                        "unknown (no operation evidence)"
                    };
                }
                let mut reasons: Vec<_> = r.reasons.iter().map(|reason| reason.label()).collect();
                reasons.sort_unstable();
                reasons.dedup();
                InstanceSemanticView {
                    instance: r.id,
                    caller: r.caller,
                    module: r.module,
                    api_returns: r.api_returns,
                    saturated: r.saturated,
                    historical_only_returns: r.historical_only_returns,
                    semantics,
                    lossy: r.lossy,
                    reasons,
                }
            })
            .collect();
        let mut gaps: Vec<GapView> = registry
            .gaps()
            .iter()
            .zip(registry.gap_repeats())
            .map(|(gap, &repeats)| GapView {
                caller: gap.caller,
                module: gap.module,
                pid: gap.pid,
                subject: gap.subject.clone(),
                reason: gap.reason.clone(),
                budget: gap.budget,
                repeats,
            })
            .collect();
        let object_observations = coordinator.registry().joint_observations(passes);
        if let Some(gap) = silent_bootstrap_gap(&object_observations, semantic_edges.len(), &gaps) {
            gaps.push(gap);
        }
        let limits = registry.limits();
        let (observed_edges, saturated_edges) = registry.counter_census();
        let render_index = PresentationRenderIndex::build(&instances, &semantic_edges);
        let (excluded_modules, unmatched_excludes) = coordinator.excluded_snapshot();
        Ok(Self {
            scope_label: scope_label.to_string(),
            started_ns,
            ended_ns,
            passes,
            usage_feed: registry.usage_feed(),
            native_witnesses: registry.witness_census().clone(),
            witness_placement: registry.witness_placement(),
            caller_metadata: coordinator.metadata_frame(),
            callers,
            modules,
            edges,
            instances,
            semantic_edges,
            instance_reload_not_excluded: coordinator.reload_disclosure_for_inventory(),
            render_index,
            gaps,
            gaps_suppressed: registry.gaps_suppressed(),
            excluded_modules,
            unmatched_excludes,
            semantic_capture: crate::inventory_semantics::SemanticCaptureSummary::default(),
            // No Joint evidence reaches the live registry today
            // (live-loop carry): the projection is honestly
            // unavailable at this pass revision, S1 unaffected.
            // Guarded H9 section (N1): retained Joint evidence
            // commits; without it this stays unavailable, exactly as
            // before (production holds no receipts, seals or
            // projections).
            object_observations,
            prearm: coordinator.prearm_rows(),
            budgets: BudgetView {
                callers_limit: limits.max_callers,
                callers_occupied: coordinator.adapter().len(),
                callers_refused: coordinator
                    .adapter()
                    .admit_refused()
                    .saturating_add(registry.callers_refused()),
                modules_limit: limits.max_modules,
                modules_occupied: registry.module_count(),
                modules_refused: registry.modules_refused(),
                edges_limit: limits.max_edges,
                edges_occupied: registry.edge_count(),
                edges_refused: registry.edges_refused(),
                endpoints_limit: limits.max_endpoints,
                endpoints_occupied: registry.endpoints_total(),
                endpoints_refused: registry.endpoints_refused(),
                inventory_endpoints_limit: usize::try_from(
                    coordinator.attach_set().budget().endpoint_limit(),
                )
                .unwrap_or(usize::MAX),
                inventory_endpoints_occupied: coordinator.attach_set().len(),
                inventory_endpoints_refused: coordinator.attach_set().endpoint_refusals(),
                inventory_modules_limit: usize::try_from(
                    coordinator.attach_set().budget().endpoint_limit(),
                )
                .unwrap_or(usize::MAX),
                inventory_modules_occupied: coordinator.attach_set().module_records(),
                inventory_modules_refused: coordinator.attach_set().module_record_refusals(),
                counters_observed: observed_edges,
                counters_saturated: saturated_edges,
                semantic_limit: limits.max_semantic_states,
                semantic_occupied: registry.semantic_occupied(),
                semantic_unknown_edges: registry.semantic_unknown_edges(),
                semantic_refused: registry.semantic_refused(),
                instances_limit: registry.instance_limit(),
                instances_occupied: registry.instances().count(),
                instances_refused: registry.instance_refused(),
                instance_semantic_occupied: registry.instance_semantic_occupied(),
                instance_semantic_unknown_edges: registry.instance_semantic_unknown_edges(),
                instance_semantic_refused: registry.instance_semantic_refused(),
                instance_negative_limit: registry.instance_negative_limit(),
                instance_negative_occupied: registry.instance_negative_occupied(),
                instance_negative_refused: registry.instance_negative_refused(),
                instance_negative_exhausted: registry.instance_negative_exhausted(),
                instance_semantic_resources: SemanticResourceView {
                    charges: registry.semantic_resource_snapshot(),
                    occupancy: registry.semantic_resource_occupancy(),
                },
                retained_limit: limits.max_gaps,
                retained: registry.gaps().len(),
                retained_suppressed: registry.gaps_suppressed(),
                preadmission: coordinator.preadmission_counters(),
            },
            key_operations_requested: coordinator.key_operations_requested(),
            manifests_present: coordinator.has_manifests(),
        })
    }

    pub(crate) fn semantic_children(
        &self,
        caller: CallerId,
        module: ModuleId,
    ) -> SemanticChildren<'_> {
        self.render_index
            .children(&self.instances, &self.semantic_edges, caller, module)
    }
}

/// What an edge's semantic column reads while its per-edge feed stays
/// withheld but its instance children hold claims: the per-edge summary
/// is unknown, never the observed feed. Wording only; the S1 shape and
/// the childless withheld rendering are unchanged.
const SEMANTIC_WITHHELD_WITH_CLAIMED_CHILDREN: &str =
    "unknown (per-edge summary withheld; see semantic children)";

/// Project one edge's semantic state into its owned view: the label
/// always, the mechanism rows and operation aggregates iff the edge
/// holds claims. Withheld edges keep the exact U0 unknown rendering,
/// except an edge with claimed instance children, which names them.
fn semantics_view(state: Option<&EdgeSemantics>, claimed_children: bool) -> EdgeSemanticsView {
    let Some(state) = state else {
        return EdgeSemanticsView {
            label: if claimed_children {
                SEMANTIC_WITHHELD_WITH_CLAIMED_CHILDREN
            } else {
                SEMANTIC_UNKNOWN
            },
            mechanisms: Vec::new(),
            operations: None,
        };
    };
    let label = state.label();
    if !state.has_claims() {
        return EdgeSemanticsView {
            label,
            mechanisms: Vec::new(),
            operations: None,
        };
    }
    let mechanisms = state
        .mechanisms()
        .iter()
        .map(|(id, stat)| MechanismView {
            id: *id,
            name: crate::mechanism_names::mechanism_name(*id),
            operations: stat.ops.iter().copied().collect(),
            calls: stat.calls,
            errors: stat.errors,
            last_seen_ns: stat.last_seen_ns,
            functions: stat.functions.iter().cloned().collect(),
            returns: stat.returns.iter().copied().collect(),
            truncated: stat.truncated,
        })
        .collect();
    let operations = OperationsView {
        calls: state.calls(),
        started: state.started(),
        completed: state.completed(),
        cancelled: state.cancelled(),
        failed: state.failed(),
        unknown: state.unknown(),
        orphans: state.orphans(),
        dropped: state.dropped(),
        last_seen_ns: state.last_seen_ns(),
        active: state
            .active_summary()
            .into_iter()
            .map(|(category, op_state, count)| ActiveOpView {
                category,
                state: op_state.label(),
                count,
            })
            .collect(),
        evidence: state.evidence(),
    };
    EdgeSemanticsView {
        label,
        mechanisms,
        operations: Some(operations),
    }
}

/// One edge's semantic snapshot segment: the label, plus — when the
/// edge holds claims — every mechanism row (verbatim id, name,
/// categories, counts, recency, provenance) and the operation
/// aggregates. Unknown edges render the bare label, exactly as U0.
fn snapshot_semantics_at(edge: &EdgeView, now_ns: u64) -> String {
    snapshot_semantics_view_at(&edge.semantics, now_ns)
}

fn snapshot_semantics_view_at(semantics: &EdgeSemanticsView, now_ns: u64) -> String {
    let Some(operations) = semantics.operations.as_ref() else {
        return semantics.label.to_string();
    };
    let ago = |then_ns: u64| crate::render::fmt_ns(Some(now_ns.saturating_sub(then_ns)));
    let mut mechs = Vec::with_capacity(semantics.mechanisms.len());
    for mech in &semantics.mechanisms {
        let id = match mech.name {
            Some(name) => format!("{name}/0x{:x}", mech.id),
            None => format!("0x{:x}", mech.id),
        };
        let by = escape_controls(&mech.functions.join(",")).into_owned();
        let rv = mech
            .returns
            .iter()
            .map(|rv| format!("0x{rv:x}"))
            .collect::<Vec<_>>()
            .join(",");
        mechs.push(format!(
            "[{id} {} calls={} errors={} last={} ago by=[{by}] rv=[{rv}]{}]",
            mech.operations.join(","),
            mech.calls,
            mech.errors,
            ago(mech.last_seen_ns),
            if mech.truncated { " truncated" } else { "" },
        ));
    }
    let active = operations
        .active
        .iter()
        .map(|op| format!("{}:{}x{}", op.category, op.state, op.count))
        .collect::<Vec<_>>()
        .join(",");
    let evidence = operations.evidence;
    format!(
        "{} mechs {} ops [calls={} started={} completed={} cancelled={} failed={} unknown={} orphans={} dropped={} last={} ago] active [{active}] evidence [state_reconciliations={} session_cancel_ambiguities={} session_cancel_unknown_flags={} operation_state_imports={} auth_state_ambiguities={} semantic_capture_failures={} async_duplicates={} async_evictions={} unmatched_closes={}]",
        semantics.label,
        mechs.join(" "),
        operations.calls,
        operations.started,
        operations.completed,
        operations.cancelled,
        operations.failed,
        operations.unknown,
        operations.orphans,
        operations.dropped,
        ago(operations.last_seen_ns),
        evidence.state_reconciliations,
        evidence.session_cancel_ambiguities,
        evidence.session_cancel_unknown_flags,
        evidence.operation_state_imports,
        evidence.auth_state_ambiguities,
        evidence.semantic_capture_failures,
        evidence.async_duplicates,
        evidence.async_evictions,
        evidence.unmatched_closes,
    )
}

/// One edge's coverage in words: ONE wording shared by pager snapshots
/// and dashboard frames (JSON carries the structured
/// `entries.coverage`). Never says "observed" for a zero it cannot
/// prove: witnessed use is "used", an unknown names its reason.
/// Instants render relative to `now_ns` with units — raw monotonic
/// nanoseconds never reach text (JSON keeps `*_ns` with its unit).
pub(crate) fn coverage_label_at(coverage: &UseCoverage, now_ns: u64) -> String {
    let ago = |then_ns: u64| crate::render::fmt_ns(Some(now_ns.saturating_sub(then_ns)));
    match coverage {
        UseCoverage::Counted {
            since_ns,
            lossy: false,
        } => format!("counted exactly for the last {}", ago(*since_ns)),
        UseCoverage::Counted {
            since_ns,
            lossy: true,
        } => format!(
            "counted for the last {} (lossy: some records dropped)",
            ago(*since_ns)
        ),
        UseCoverage::Witnessed { first_ns } => {
            format!("used, count unavailable (first use {} ago)", ago(*first_ns))
        }
        UseCoverage::WatchedNoUse {
            since_ns,
            until_ns: None,
        } => format!("no use for the last {}", ago(*since_ns)),
        UseCoverage::WatchedNoUse {
            since_ns,
            until_ns: Some(until_ns),
        } => format!(
            "no use for {} (watch ended {} ago)",
            crate::render::fmt_ns(Some(until_ns.saturating_sub(*since_ns))),
            ago(*until_ns)
        ),
        UseCoverage::Unknown(reason) => format!("unknown ({})", reason.text()),
    }
}

/// The dashboard's compact entry count: the number only where it is a
/// fact (a counted or ongoing watched edge, or a positive count — `+`
/// marks a lossy lower bound), `?` where the count is unavailable
/// (unknown coverage, witnessed use without a count, or a frozen watch,
/// whose zero holds only for its interval). A zero never reads as a
/// fact the coverage cannot back.
pub(crate) fn entries_display(edge: &EdgeView) -> String {
    match &edge.coverage {
        UseCoverage::Counted { lossy: true, .. } if edge.entry_count > 0 => {
            format!("{}+", edge.entry_count)
        }
        UseCoverage::Counted { lossy: false, .. }
        | UseCoverage::WatchedNoUse { until_ns: None, .. } => edge.entry_count.to_string(),
        _ if edge.entry_count > 0 => edge.entry_count.to_string(),
        _ => "?".to_string(),
    }
}

/// One module's admission history in words
/// (`refused->admitted@32.10s ago`), empty when the first verdict still
/// stands. `now_ns` anchors the relative wording; raw monotonic
/// nanoseconds never reach text.
pub(crate) fn admission_history_label_at(history: &[AdmissionChange], now_ns: u64) -> String {
    history
        .iter()
        .map(|change| {
            format!(
                "{}->{}@{} ago",
                change.from.label(),
                change.to.label(),
                crate::render::fmt_ns(Some(now_ns.saturating_sub(change.at_ns)))
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Semantic budget status: `withheld` while no edge holds semantic
/// state, `observed` once any does. ONE computation shared by the JSON
/// document, pager snapshots, and dashboard headers.
pub(crate) fn semantic_status(budgets: &BudgetView) -> &'static str {
    if budgets.semantic_occupied > 0 {
        "observed"
    } else {
        "withheld"
    }
}

/// Resolve a retained caller incarnation, never the current image of its PID.
fn retained_caller(presentation: &Presentation, caller: CallerId) -> Option<&CallerView> {
    presentation
        .callers
        .binary_search_by_key(&caller, |view| view.id)
        .ok()
        .map(|index| &presentation.callers[index])
}

/// Last nonempty Linux path component, preserving only the retained deletion
/// marker. Escaping happens before a label reaches any terminal layout.
fn retained_path_label(path: Option<&str>, unknown: &str) -> String {
    let Some(path) = path else {
        return unknown.into();
    };
    let (path, deleted) = path
        .strip_suffix(" (deleted)")
        .map_or((path, ""), |path| (path, " (deleted)"));
    let Some(basename) = path.rsplit('/').find(|part| !part.is_empty()) else {
        return unknown.into();
    };
    escape_controls(&format!("{basename}{deleted}")).into_owned()
}

/// Executable name from the retained caller ID; labels are not identity keys.
pub(crate) fn application_label(presentation: &Presentation, caller: CallerId) -> String {
    retained_path_label(
        retained_caller(presentation, caller)
            .and_then(|caller| caller.exe.as_ref())
            .and_then(|exe| exe.path.as_deref()),
        "Unknown executable",
    )
}

/// Module name from its first retained path, keeping physical IDs separate.
pub(crate) fn module_label(presentation: &Presentation, module: ModuleId) -> String {
    let path = presentation
        .modules
        .binary_search_by_key(&module, |view| view.id)
        .ok()
        .and_then(|index| presentation.modules[index].paths.first())
        .map(String::as_str);
    retained_path_label(path, "Unknown module")
}

/// Human explanation of existing evidence, with positive history first.
/// `now_ns` anchors the relative coverage wording; see [`coverage_label_at`].
pub(crate) fn observation_label_at(edge: &EdgeView, now_ns: u64) -> String {
    if edge.entry_count > 0 {
        let mut label = format!("At least {} entries observed", edge.entry_count);
        if edge.entry_saturated {
            label.push_str(" (counter saturated)");
        }
        if matches!(edge.coverage, UseCoverage::Counted { lossy: true, .. }) {
            label.push_str(" (capture incomplete)");
        }
        return label;
    }
    match &edge.coverage {
        UseCoverage::Witnessed { .. } => "Use observed; count unavailable".into(),
        UseCoverage::WatchedNoUse { since_ns, .. } => {
            // A mapping first seen before the watch started leaves a
            // pre-watch window whose calls are not counted: name it. A
            // zero (unknown) or post-watch first sighting keeps the
            // plain covered-interval line.
            if edge.mapping_first_seen_ns > 0 && edge.mapping_first_seen_ns < *since_ns {
                let before = crate::render::fmt_ns(Some(
                    since_ns.saturating_sub(edge.mapping_first_seen_ns),
                ));
                return format!(
                    "No entries observed during the covered interval; mapped at least {before} \
                     before the watch started, earlier calls are not counted"
                );
            }
            "No entries observed during the covered interval".into()
        }
        UseCoverage::Counted { lossy: false, .. } => {
            "No entries observed in counted interval".into()
        }
        UseCoverage::Counted { lossy: true, .. } => "Activity unknown; capture incomplete".into(),
        UseCoverage::Unknown(UnknownReason::PendingFirstUse) => "Observation pending".into(),
        UseCoverage::Unknown(UnknownReason::ScanOnly) if edge.mapping == MappingState::Mapped => {
            "Module mapped; activity not captured".into()
        }
        UseCoverage::Unknown(UnknownReason::ScanOnly) => "Activity not captured".into(),
        UseCoverage::Unknown(_) => {
            format!(
                "Activity unknown; {}",
                escape_controls(&coverage_label_at(&edge.coverage, now_ns))
            )
        }
    }
}

/// Lifecycle explanation of this retained incarnation, secondary to its name.
pub(crate) fn caller_lifecycle_label(caller: &CallerView) -> Option<&'static str> {
    match caller.lifecycle {
        CallerLifecycle::Mapped => None,
        CallerLifecycle::ExecRetired => Some("Application executed a new image"),
        CallerLifecycle::Exited => Some("Process exited"),
        CallerLifecycle::Unknown => Some("Process state unknown"),
    }
}

/// One operation category's terminal counts across the proved and
/// unknown buckets: completed, failed and active with the category's
/// unit. Counts only — never object identity.
pub(crate) struct KeyOpTally {
    pub category: &'static str,
    pub completed: u64,
    pub failed: u64,
    pub active: u64,
    pub unit: &'static str,
}

/// Per-category terminals across proved and unknown buckets; the
/// unit comes from the rows (one unit per category, by contract).
/// Each operation counts ONCE (H9 §82): the primary association's
/// row carries the tally while secondary association rows stand
/// beside it, never double-counted. Unknown summaries already
/// partition once per primary. Tallies sort by category. Shared by
/// the text snapshot and the dashboard projection line.
pub(crate) fn key_operation_tallies(
    observations: &crate::key_operation_projection::ObjectObservations,
) -> Vec<KeyOpTally> {
    use std::collections::BTreeMap;
    let secondary = crate::key_operation_projection::SECONDARY_ROLE;
    let mut categories: BTreeMap<&str, (u64, u64, u64, &str)> = BTreeMap::new();
    for row in &observations.key_operations {
        if row.role == secondary {
            continue;
        }
        let slot = categories
            .entry(row.category)
            .or_insert((0, 0, 0, row.unit));
        slot.0 = slot.0.saturating_add(row.completed);
        slot.1 = slot.1.saturating_add(row.failed);
        slot.2 = slot.2.saturating_add(row.active);
    }
    for row in &observations.unknown_key_operations {
        let slot = categories
            .entry(row.category)
            .or_insert((0, 0, 0, row.unit));
        slot.0 = slot.0.saturating_add(row.completed);
        slot.1 = slot.1.saturating_add(row.failed);
        slot.2 = slot.2.saturating_add(row.active);
    }
    categories
        .into_iter()
        .map(|(category, (completed, failed, active, unit))| KeyOpTally {
            category,
            completed,
            failed,
            active,
            unit,
        })
        .collect()
}

/// The subject every Joint birth refusal discloses under
/// (`disclose_s1_birth_refusal`).
pub(crate) const JOINT_BIRTH_UNAVAILABLE_SUBJECT: &str = "Joint birth unavailable; retained S1";

/// A linked lane with registered instances that neither published a
/// Joint feed nor disclosed why reads `bootstrap_unavailable` with no
/// cause anywhere in the document. Name that once, at presentation:
/// `joint_birth_unoffered` (no birth was ever offered for the
/// registered instances, whether or not any call reduced yet). Any
/// recorded birth refusal already names the cause.
pub(crate) fn silent_bootstrap_gap(
    observations: &crate::key_operation_projection::ObjectObservations,
    semantic_edges: usize,
    gaps: &[GapView],
) -> Option<GapView> {
    (observations.reason == "bootstrap_unavailable"
        && semantic_edges > 0
        && !gaps
            .iter()
            .any(|gap| gap.subject == JOINT_BIRTH_UNAVAILABLE_SUBJECT))
    .then(|| GapView {
        caller: None,
        module: None,
        pid: None,
        subject: JOINT_BIRTH_UNAVAILABLE_SUBJECT.into(),
        reason: "joint_birth_unoffered".into(),
        budget: None,
        repeats: 1,
    })
}

/// Run-scoped `--quiet` switch for the pager snapshot, mirroring the
/// scan-progress toggle: set once at run entry, restored on exit, so the
/// deep run wrappers need no new display parameter.
static SNAPSHOT_SUMMARY_ONLY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Turns summary-only snapshots on or off; returns the previous setting.
pub(crate) fn set_snapshot_summary_only(on: bool) -> bool {
    SNAPSHOT_SUMMARY_ONLY.swap(on, std::sync::atomic::Ordering::SeqCst)
}

/// Whether the run renders summary-only snapshots (`--quiet`).
pub(crate) fn snapshot_summary_only() -> bool {
    SNAPSHOT_SUMMARY_ONLY.load(std::sync::atomic::Ordering::SeqCst)
}

/// Pager-friendly snapshot: a deterministic, stable text rendering of a
/// whole inventory (fit for `| less`, diffing, and test goldens).
/// Sorted, total-first, with the same identities, states, totals, and
/// gaps the JSON carries — pin equivalence with tests, not eyeballing.
/// Target-controlled strings are control-escaped; JSON is unaffected.
/// Renders at the run-scoped verbosity; see [`render_snapshot_with_verbosity`].
pub(crate) fn render_snapshot(presentation: &Presentation) -> String {
    let verbosity = if snapshot_summary_only() {
        crate::cli::TextVerbosity::Quiet
    } else {
        crate::cli::text_verbosity()
    };
    render_snapshot_with_verbosity(presentation, verbosity)
}

/// [`render_snapshot`] at an explicit verbosity: the tests' race-free
/// handle. Concise keeps the summary head, the limits line and the
/// `-v` hint; verbose is the full snapshot with the `Details:` tail;
/// quiet keeps the summary head only.
pub(crate) fn render_snapshot_with_verbosity(
    presentation: &Presentation,
    verbosity: crate::cli::TextVerbosity,
) -> String {
    let summary_only = verbosity == crate::cli::TextVerbosity::Quiet;
    render_snapshot_inner(presentation, summary_only, verbosity)
}

/// The `--quiet` summary head: header, coverage, key operations, and every
/// application edge (or the absence line), without the `Details:` tail.
/// `--json`, `-o`, and the event log are unaffected. Production reaches
/// the same shape through [`render_snapshot`] under the run-scoped
/// switch; this direct entry is the tests' race-free handle.
#[cfg(test)]
pub(crate) fn render_snapshot_summary(presentation: &Presentation) -> String {
    render_snapshot_inner(presentation, true, crate::cli::TextVerbosity::Quiet)
}

/// Closure-array (forwarding-layer) module ids, by admission class.
/// Matches the planner's `closure_array` label and its hyphenated test
/// spelling. The split set; whether an edge at one splits out is per
/// caller ([`provider_active_callers`], minus [`refused_backend_callers`]).
fn closure_module_ids(presentation: &Presentation) -> std::collections::BTreeSet<ModuleId> {
    presentation
        .modules
        .iter()
        .filter(|module| {
            matches!(
                module.admission_class.as_deref(),
                Some("closure_array" | "closure-array")
            )
        })
        .map(|module| module.id)
        .collect()
}

/// Callers with entries at a watched provider: an edge with
/// `entry_count > 0` at a non-closure module. A closure edge splits to
/// forwarding only for these callers; a caller with no entries at any
/// non-closure module stays logical, since nothing below the layer
/// observed them.
fn provider_active_callers(
    presentation: &Presentation,
    closure: &std::collections::BTreeSet<ModuleId>,
) -> std::collections::BTreeSet<CallerId> {
    presentation
        .edges
        .iter()
        .filter(|edge| !closure.contains(&edge.module) && edge.entry_count > 0)
        .map(|edge| edge.caller)
        .collect()
}

/// Callers with a refused (non-closure) backend: an edge at a non-closure
/// module whose admission is refused. A refused backend keeps the caller's
/// layer edges logical — a disclosed overcount beats hiding the caller's
/// calls — even when the caller also entered an unrelated active provider.
fn refused_backend_callers(
    presentation: &Presentation,
    closure: &std::collections::BTreeSet<ModuleId>,
) -> std::collections::BTreeSet<CallerId> {
    use std::collections::{BTreeMap, BTreeSet};
    let admission: BTreeMap<ModuleId, AdmissionState> = presentation
        .modules
        .iter()
        .map(|module| (module.id, module.admission))
        .collect();
    presentation
        .edges
        .iter()
        .filter(|edge| {
            !closure.contains(&edge.module)
                && admission.get(&edge.module) == Some(&AdmissionState::Refused)
        })
        .map(|edge| edge.caller)
        .collect::<BTreeSet<CallerId>>()
}

/// True when an edge's entries are forwarding-layer observations: the
/// edge sits at a closure-array module, its caller also entered a watched
/// provider (whose edge is the logical count), and the caller has no
/// refused backend (which keeps the layer logical).
fn edge_is_forwarding(
    edge: &EdgeView,
    closure: &std::collections::BTreeSet<ModuleId>,
    active: &std::collections::BTreeSet<CallerId>,
    refused: &std::collections::BTreeSet<CallerId>,
) -> bool {
    closure.contains(&edge.module)
        && active.contains(&edge.caller)
        && !refused.contains(&edge.caller)
}

/// Forwarding-layer (closure-array admission) modules with entries on
/// their edges, each with its entry total. Provider edges, plus the layer
/// edges of callers with no entries at any non-closure module, are the
/// logical totals and these stay separate, never summed in. Only edges of
/// provider-active callers without a refused backend count here (see
/// [`provider_active_callers`] and [`refused_backend_callers`]).
pub(crate) fn forwarding_entry_layers(presentation: &Presentation) -> Vec<(String, u64)> {
    let closure = closure_module_ids(presentation);
    let active = provider_active_callers(presentation, &closure);
    let refused = refused_backend_callers(presentation, &closure);
    let mut layers: Vec<(String, u64)> = presentation
        .modules
        .iter()
        .filter(|module| closure.contains(&module.id))
        .map(|module| {
            let entries = presentation
                .edges
                .iter()
                .filter(|edge| {
                    edge.module == module.id
                        && edge_is_forwarding(edge, &closure, &active, &refused)
                })
                .map(|edge| edge.entry_count)
                .fold(0u64, u64::saturating_add);
            let path = module
                .paths
                .first()
                .cloned()
                .unwrap_or_else(|| module.id.label());
            (path, entries)
        })
        .filter(|(_, entries)| *entries > 0)
        .collect();
    layers.sort();
    layers
}

/// Logical vs forwarding-layer entry totals over every edge. Provider
/// edges, plus the layer edges of callers with no entries at any
/// non-closure module or with a refused backend, are logical;
/// closure-array edges of provider-active callers without a refused
/// backend are forwarding observations of those same calls.
pub(crate) fn layer_entry_totals(presentation: &Presentation) -> (u64, u64) {
    let closure = closure_module_ids(presentation);
    let active = provider_active_callers(presentation, &closure);
    let refused = refused_backend_callers(presentation, &closure);
    let mut logical = 0u64;
    let mut forwarding_entries = 0u64;
    for edge in &presentation.edges {
        if edge_is_forwarding(edge, &closure, &active, &refused) {
            forwarding_entries = forwarding_entries.saturating_add(edge.entry_count);
        } else {
            logical = logical.saturating_add(edge.entry_count);
        }
    }
    (logical, forwarding_entries)
}
/// The key-operations summary when `--key-operations` was requested
/// but the semantic subset refused. The scan path (unverifiable
/// scan-derived tables; export-name agreement alone never grants
/// argument-read authority) reruns with `--manifest`; the manifest
/// path (supplied inputs still refused) checks them. Visible only
/// beside the `key operations unavailable` subset gap the seal path
/// notes; without that gap the tracking-off line stands. One module
/// names its provider by file name; zero or several modules stay
/// generic, since no single provider is nameable.
fn key_operations_manifest_line(presentation: &Presentation) -> Option<String> {
    let refused_reason = presentation.gaps.iter().find_map(|gap| {
        (gap.subject == "key operations unavailable" && gap.reason.starts_with("subset refused ("))
            .then_some(gap.reason.as_str())
    })?;
    // The seal path's remedy decides the summary: a check-the-manifest
    // gap (manifests supplied) checks, every other subset refusal
    // reruns. Both arms stay generic over providers.
    let manifest_path = refused_reason.contains("check the manifest");
    if let [single] = presentation.modules.as_slice()
        && let Some(base) = single
            .paths
            .first()
            .and_then(|path| path.rsplit('/').next())
            .filter(|base| !base.is_empty())
    {
        if manifest_path {
            return Some(format!(
                "key operations: {base}'s function table cannot be verified \
                 from the supplied --manifest inputs; check the manifest"
            ));
        }
        return Some(format!(
            "key operations: {base}'s function table cannot be verified \
             without --manifest; rerun with --manifest"
        ));
    }
    if manifest_path {
        return Some(
            "key operations: provider function tables cannot be verified \
             from the supplied --manifest inputs; check the manifest"
                .to_string(),
        );
    }
    Some(
        "key operations: provider function tables cannot be verified \
         without --manifest; rerun with --manifest"
            .to_string(),
    )
}

/// The concise gap summary (F1): one line grouping gaps by plain
/// subject/reason with counts, top three plus "and K more". Plain
/// words only (reusing `gap_plain_*`); per-gap `gap [` lines stay
/// verbose-only. Counts distinct gap rows like the coverage line, not
/// `repeats` (JSON carries `repeats`). `None` when no gaps are
/// retained; suppressed-but-unretained gaps stay in the coverage line.
fn concise_gap_summary_line(gaps: &[GapView], _suppressed: u64) -> Option<String> {
    if gaps.is_empty() {
        return None;
    }
    // Deleted mappings are unloaded libraries, not loss: fold them to one
    // plain trailing group instead of leading per-path groups.
    let (deleted, rest): (Vec<_>, Vec<_>) =
        gaps.iter().partition(|gap| gap.reason == "deleted mapping");
    let mut groups: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for gap in rest {
        let subject = escape_controls(gap_plain_subject(&gap.subject)).into_owned();
        let reason = escape_controls(gap_plain_reason(&gap.reason)).into_owned();
        *groups.entry((subject, reason)).or_insert(0) += 1;
    }
    let mut ranked: Vec<((String, String), usize)> = groups.into_iter().collect();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    const SHOWN: usize = 3;
    let shown = ranked.len().min(SHOWN);
    let mut parts: Vec<String> = ranked
        .iter()
        .take(shown)
        .map(|((subject, reason), count)| format!("{count} × {subject} — {reason}"))
        .collect();
    if !deleted.is_empty() {
        parts.push(format!(
            "{} × unloaded librar{} — mapped files were deleted (not loss)",
            deleted.len(),
            if deleted.len() == 1 { "y" } else { "ies" },
        ));
    }
    let more = ranked.len().saturating_sub(shown);
    if more > 0 {
        parts.push(format!("and {more} more"));
    }
    Some(format!(
        "gaps: {} (--json has every item)",
        parts.join("; ")
    ))
}

/// The concise limits line (INV-1): the headline budgets in words.
/// The full budget dump stays verbose-only; `--json` carries `budgets`.
/// Watched functions count against the real inventory endpoint budget
/// (the attach set's `--max-endpoints` limit), never the registry's
/// internal endpoint ceiling.
fn render_limits_line(out: &mut String, budgets: &BudgetView) {
    use std::fmt::Write as _;
    let plural = |count: usize| if count == 1 { "" } else { "s" };
    let _ = writeln!(
        out,
        "limits: {} caller{}, {} provider file{}, {} edge{} ({} refused); {} function{} watched of {} ({} refused). Full budget detail: -v or --json.",
        budgets.callers_occupied,
        plural(budgets.callers_occupied),
        budgets.modules_occupied,
        plural(budgets.modules_occupied),
        budgets.edges_occupied,
        plural(budgets.edges_occupied),
        budgets.refusals(),
        budgets.inventory_endpoints_occupied,
        plural(budgets.inventory_endpoints_occupied),
        budgets.inventory_endpoints_limit,
        budgets.inventory_endpoints_refused,
    );
}

/// The refused journal-start cause behind a `journal_unavailable`
/// observation, when `--key-operations` was requested: the first clause
/// of the "key operations unavailable" scope gap's reason (the rest is
/// the shared "broad inventory continues" tail). `None` when no such
/// gap exists, so an unrequested run still reads "tracking is off".
fn key_operations_refusal_cause(presentation: &Presentation) -> Option<String> {
    presentation
        .gaps
        .iter()
        .find(|gap| gap.subject == "key operations unavailable")
        .map(|gap| {
            gap.reason
                .split_once(';')
                .map_or(gap.reason.as_str(), |(first, _)| first)
                .trim()
                .to_string()
        })
        .map(|cause| escape_controls(&cause).into_owned())
}

/// One key-observation machine reason in plain words (text only; JSON
/// keeps the frozen reason). Unknown reasons pass through verbatim so
/// a new reason always surfaces.
fn key_observation_plain_reason(reason: &str) -> &str {
    match reason {
        "bootstrap_unavailable" => "per-key tracking never started, so no key can be named yet",
        "proof_refused_fallback" => "key proof refused; plain counts only",
        "authority_lost" => "per-key tracking stopped; plain counts are unaffected",
        "row_budget_exhausted" => "per-key rows hit their budget; plain counts are unaffected",
        "publication_budget_exhausted" => {
            "key publication hit its budget; plain counts are unaffected"
        }
        "serialization_refused" => "key rows could not be encoded; plain counts are unaffected",
        "sink_failed" => "key rows could not be written; plain counts are unaffected",
        other => other,
    }
}

/// One gap subject in plain words (text only; JSON keeps the stored
/// subject). The Joint subjects map — the disclosed refusal, the
/// silent-bootstrap one, and the unlinked-journal disclosure;
/// everything else passes through verbatim.
fn gap_plain_subject(subject: &str) -> &str {
    match subject {
        "Joint key operations unavailable; retained S1" | JOINT_BIRTH_UNAVAILABLE_SUBJECT => {
            "Per-key tracking did not start for this process; function counts above are unaffected"
        }
        "per-key tracking is off; this capture keeps S1 mechanisms and API results" => {
            "per-key tracking is off; function and mechanism counts are unaffected"
        }
        "exact image authority unavailable" => {
            "process identity checked from /proc (PID and start time), not by the kernel"
        }
        other => other,
    }
}

/// One gap reason in plain words (text only; JSON keeps the stored
/// reason). Unknown reasons pass through verbatim so a new gap lane
/// always surfaces.
fn gap_plain_reason(reason: &str) -> &str {
    if let Some(_suffix) = reason.strip_prefix("joint_seal_") {
        return "per-key tracking ended early";
    }
    if let Some(_suffix) = reason.strip_prefix("joint_fallback_") {
        return "per-key tracking fell back to plain counts";
    }
    if let Some(captured) = reason.strip_prefix("live capture refused (") {
        // The PID auto-fallback gap carries the full host summary
        // (JSON and verbose keep it); concise folds it to one short
        // clause. Only a Denied refusal carries the sudo tail, so its
        // presence is the privilege signal.
        if captured.ends_with("; run with sudo for full capture") {
            return "live capture refused (needs root); run with sudo for full capture";
        }
        return "live capture refused (see 'p11scope doctor')";
    }
    match reason {
        "joint_birth_unoffered" => "no key session was offered to track",
        "joint_image_refused" | "joint_birth_claim_ImageTainted" => {
            "process image changed before tracking could start"
        }
        "joint_birth_no_admission" => "process was not admitted for tracking",
        "joint_journal_unavailable" => "per-key tracking is off in this run",
        "foreign_or_unproven_caller" => "caller not confirmed",
        "no BPF image identity; scan-lane incarnations by pidfd/start-time with exe-identity exec detection" => {
            "some processes were identified from /proc only"
        }
        "deleted mapping" => "mapped file was deleted (not loss)",
        other => other,
    }
}

/// One module's concise outcome across its grouped edges: refused modules
/// were never watched (a proxy forwards to real providers); otherwise the
/// observed entry total, or the shared zero-use wording when nothing was
/// counted. Plain words only; per-edge coverage stays verbose-only.
fn concise_module_status(
    presentation: &Presentation,
    module: ModuleId,
    edges: &[&EdgeView],
) -> String {
    if let Ok(index) = presentation
        .modules
        .binary_search_by_key(&module, |view| view.id)
    {
        let view = &presentation.modules[index];
        if view.admission == AdmissionState::Refused {
            let proxy = view
                .admission_class
                .as_deref()
                .is_some_and(|class| class.contains("closure"))
                || view
                    .admission_reasons
                    .iter()
                    .any(|reason| crate::plan::is_closure_awaiting_publication(reason));
            if proxy {
                return "not watched (proxy)".to_string();
            }
            return "not watched".to_string();
        }
    }
    let total: u64 = edges.iter().map(|edge| edge.entry_count).sum();
    if total > 0 {
        let noun = if total == 1 { "entry" } else { "entries" };
        return format!("{total} {noun} observed");
    }
    if edges
        .iter()
        .all(|edge| matches!(edge.coverage, UseCoverage::WatchedNoUse { .. }))
        && !edges.is_empty()
    {
        return "no use in the covered interval".to_string();
    }
    if edges
        .iter()
        .all(|edge| matches!(edge.coverage, UseCoverage::Unknown(UnknownReason::ScanOnly)))
    {
        return "activity not captured".to_string();
    }
    "activity unknown".to_string()
}

/// One verbose edge line with internal caller/module ids, lifecycle and
/// coverage: the full per-edge detail `-v` promises. Concise groups by
/// provider instead (see `render_concise_edges`).
fn render_verbose_edge(out: &mut String, presentation: &Presentation, edge: &EdgeView) {
    use std::fmt::Write as _;
    let caller = retained_caller(presentation, edge.caller);
    let identity = caller.map_or_else(
        || edge.caller.label(),
        |caller| {
            format!(
                "{} pid {} incarnation {}",
                caller.id.label(),
                caller.pid,
                caller.incarnation
            )
        },
    );
    let _ = write!(
        out,
        "application {} [{identity}] -> module {} [{}]: {}",
        application_label(presentation, edge.caller),
        module_label(presentation, edge.module),
        edge.module.label(),
        observation_label_at(edge, presentation.ended_ns),
    );
    if let Some(lifecycle) = caller.and_then(caller_lifecycle_label) {
        let _ = write!(out, "; {lifecycle}");
    }
    // Other unknown reasons already accompany the zero-count explanation;
    // positive history still keeps its unknown coverage reason alongside it.
    let show_coverage = match edge.coverage {
        UseCoverage::Counted { .. } => edge.entry_count == 0,
        UseCoverage::WatchedNoUse { .. }
        | UseCoverage::Unknown(UnknownReason::PendingFirstUse | UnknownReason::ScanOnly) => true,
        UseCoverage::Unknown(_) => edge.entry_count > 0,
        UseCoverage::Witnessed { .. } => false,
    };
    if show_coverage {
        let _ = write!(
            out,
            "; coverage {}",
            escape_controls(&coverage_label_at(&edge.coverage, presentation.ended_ns))
        );
    }
    out.push('\n');
}

/// Concise application edges grouped per provider: one line per module
/// naming the mapped application count and the outcome, without internal
/// caller/module ids (those stay verbose-only). JSON keeps every edge.
fn render_concise_edges(out: &mut String, presentation: &Presentation) {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;
    let mut by_module: BTreeMap<ModuleId, Vec<&EdgeView>> = BTreeMap::new();
    for edge in &presentation.edges {
        by_module.entry(edge.module).or_default().push(edge);
    }
    let mut groups: Vec<(ModuleId, Vec<&EdgeView>)> = by_module.into_iter().collect();
    groups.sort_by_key(|(module, _)| module_label(presentation, *module));
    for (module, edges) in groups {
        let mut callers: BTreeSet<CallerId> = BTreeSet::new();
        let mut names: BTreeSet<String> = BTreeSet::new();
        for edge in &edges {
            callers.insert(edge.caller);
            names.insert(application_label(presentation, edge.caller));
        }
        let count = callers.len();
        let noun = if count == 1 {
            "application"
        } else {
            "applications"
        };
        let all_names: Vec<String> = names.into_iter().collect();
        let mut shown: Vec<String> = all_names.iter().take(3).cloned().collect();
        if all_names.len() > 3 {
            shown.push("…".to_string());
        }
        let status = concise_module_status(presentation, module, &edges);
        let _ = writeln!(
            out,
            "{}: mapped by {count} {noun} ({}); {status}",
            module_label(presentation, module),
            shown.join(", "),
        );
    }
}

fn render_snapshot_inner(
    presentation: &Presentation,
    summary_only: bool,
    verbosity: crate::cli::TextVerbosity,
) -> String {
    use std::fmt::Write as _;
    let verbose = verbosity == crate::cli::TextVerbosity::Verbose;
    let mut out = String::new();
    let budgets = &presentation.budgets;
    let _ = writeln!(
        out,
        "inventory {} ({} pass{}, {} caller{}, {} provider file{}, {} edge{})",
        presentation.scope_label,
        presentation.passes,
        if presentation.passes == 1 { "" } else { "es" },
        presentation.callers.len(),
        if presentation.callers.len() == 1 {
            ""
        } else {
            "s"
        },
        presentation.modules.len(),
        if presentation.modules.len() == 1 {
            ""
        } else {
            "s"
        },
        presentation.edges.len(),
        if presentation.edges.len() == 1 {
            ""
        } else {
            "s"
        },
    );
    if presentation.gaps.is_empty() && budgets.refusals() == 0 && presentation.gaps_suppressed == 0
    {
        let _ = writeln!(out, "coverage: COMPLETE (nothing known was lost)");
    } else {
        let gaps = presentation.gaps.len();
        let _ = writeln!(
            out,
            "coverage: PARTIAL — {} gap{}, {} refused, {} more not shown",
            gaps,
            if gaps == 1 { "" } else { "s" },
            budgets.refusals(),
            presentation.gaps_suppressed,
        );
    }
    // The edge list below never carries module-level use no caller could
    // claim: short-lived callers exit before their witness rows bind, so
    // their folded entries would hide behind an innocent edge count. The
    // summary names the unattributed totals in plain words, reusing the
    // module line's gate (unidentified rows with a positive lower bound);
    // rows bound to an identified caller are attributed, never counted
    // here. JSON keeps the per-module record either way.
    {
        let mut rows: u64 = 0;
        let mut entries: u64 = 0;
        for module in &presentation.modules {
            if let Some(unbound) = &module.unbound_use {
                let unidentified = unbound.reasons.keys().any(|code| *code != NO_MAPPING_EDGE);
                if unidentified {
                    rows = rows.saturating_add(unbound.rows);
                    entries = entries.saturating_add(unbound.entries);
                }
            }
        }
        if entries > 0 {
            let _ = writeln!(
                out,
                "unattributed use: at least {} entries in {} witness row{} never bound to a caller",
                entries,
                rows,
                if rows == 1 { "" } else { "s" }
            );
        }
    }
    // Key-operation summary: revision, status, row counts and
    // per-category terminal counts from the shared projection.
    // Counts and the fixed category/unit/status vocabulary only —
    // never object handles, labels, metadata or instances.
    {
        use crate::key_operation_projection::ObsStatus;
        let observations = &presentation.object_observations;
        if observations.status == ObsStatus::Unavailable {
            // No journal producer is linked (the default without
            // --key-operations, or a build without the journal object):
            // say plainly that per-key tracking is off (OD33/R-50).
            // Other reasons name the cause in plain words, with the
            // machine reason beside it in verbose text (JSON keeps it).
            if observations.reason == "journal_unavailable" {
                // A refused semantic subset names its rerun remedy first;
                // a refused journal start leaves a "key operations
                // unavailable" scope gap: --key-operations was requested
                // but per-key tracking never started. Name the request and
                // the cause; a request without --manifest never attempts
                // a start (no gap exists), so it names the missing flag
                // instead of reading "off"; without that gap tracking is
                // simply off.
                if let Some(line) = key_operations_manifest_line(presentation) {
                    let _ = writeln!(out, "{line}");
                } else if let Some(cause) = key_operations_refusal_cause(presentation) {
                    let _ = writeln!(
                        out,
                        "key operations: requested, but per-key tracking did not start ({cause})"
                    );
                } else if presentation.key_operations_requested && !presentation.manifests_present {
                    let _ = writeln!(
                        out,
                        "key operations: requested, but per-key tracking needs --manifest on this \
                         build"
                    );
                } else if verbose {
                    let _ = writeln!(
                        out,
                        "key operations: not reported (per-key tracking is off; \
                         reason: journal_unavailable)"
                    );
                } else {
                    let _ = writeln!(
                        out,
                        "key operations: not reported (per-key tracking is off)"
                    );
                }
            } else {
                let plain = key_observation_plain_reason(observations.reason);
                if verbose && plain != observations.reason {
                    let _ = writeln!(
                        out,
                        "key operations: not available — {plain} (reason: {})",
                        observations.reason
                    );
                } else {
                    let _ = writeln!(out, "key operations: not available — {plain}");
                }
            }
        } else {
            let status = if observations.reason == "none" {
                observations.status.label().to_string()
            } else {
                let plain = key_observation_plain_reason(observations.reason);
                if verbose && plain != observations.reason {
                    format!(
                        "{} ({plain}; reason: {})",
                        observations.status.label(),
                        observations.reason
                    )
                } else {
                    format!("{} ({plain})", observations.status.label())
                }
            };
            let sessions = observations.sessions.len();
            let objects = observations.objects.len();
            let mut line = format!(
                "key operations: rev {} {}; {} session{}, {} object{}; ",
                observations.revision,
                status,
                sessions,
                if sessions == 1 { "" } else { "s" },
                objects,
                if objects == 1 { "" } else { "s" },
            );
            // Not-attributed counters sit beside the exact rows:
            // counts per finite reason, never a guessed key.
            let unattributed_suffix = if observations.unattributed.is_empty() {
                String::new()
            } else {
                let parts: Vec<String> = observations
                    .unattributed
                    .iter()
                    .map(|row| format!("{} {}", row.reason, row.count))
                    .collect();
                format!("; not attributed: {}", parts.join(", "))
            };
            // First-observed keys with unestablished type keep their
            // rows under the `unknown` metadata label (DEMO-4): say
            // so beside the tallies, counts only, never a guessed
            // label.
            let unknown_type_suffix = {
                let rows = observations
                    .key_operations
                    .iter()
                    .filter(|row| {
                        row.metadata_at_use == crate::key_operation_projection::METADATA_UNKNOWN
                    })
                    .count();
                if rows == 0 {
                    String::new()
                } else {
                    format!(
                        "; type unknown (not established while observed) ({rows} key row{})",
                        if rows == 1 { "" } else { "s" }
                    )
                }
            };
            let tallies = key_operation_tallies(observations);
            if tallies.is_empty() {
                line.push_str("no key operations observed");
                line.push_str(&unattributed_suffix);
            } else {
                let parts: Vec<String> = tallies
                    .iter()
                    .map(|tally| {
                        // What happened to the call, not an observer
                        // failure (JSON keeps `failed`).
                        let failed_noun = if tally.failed == 1 {
                            "returned an error"
                        } else {
                            "returned errors"
                        };
                        format!(
                            "{} {} completed, {} {}, {} active {}",
                            tally.category,
                            tally.completed,
                            tally.failed,
                            failed_noun,
                            tally.active,
                            tally.unit
                        )
                    })
                    .collect();
                line.push_str(&parts.join("; "));
                line.push_str(&unattributed_suffix);
                line.push_str(&unknown_type_suffix);
            }
            let _ = writeln!(out, "{line}");
        }
    }
    {
        let layers = forwarding_entry_layers(presentation);
        if !layers.is_empty() {
            let parts: Vec<String> = layers
                .iter()
                .map(|(path, entries)| {
                    format!(
                        "{} recorded {} forwarding-layer {}",
                        escape_controls(path),
                        entries,
                        if *entries == 1 { "entry" } else { "entries" }
                    )
                })
                .collect();
            let _ = writeln!(
                out,
                "Forwarding-layer entries counted separately (not independent calls): {}. \
                 Provider edges, plus the layer edges of callers that entered no watched provider, are the logical totals; \
                 entries a layer answered itself appear only here, \
                 and a layer entry that reaches several providers counts at each.",
                parts.join("; ")
            );
        }
    }
    // Verbose keeps one line per edge with internal ids; concise and
    // quiet group per provider (see `render_concise_edges`).
    if verbose {
        for edge in &presentation.edges {
            render_verbose_edge(&mut out, presentation, edge);
        }
    } else {
        render_concise_edges(&mut out, presentation);
    }
    if presentation.edges.is_empty() {
        let _ = writeln!(
            out,
            "No application/module associations observed; this does not prove that no PKCS#11 activity occurred."
        );
    }
    render_excluded_lines(
        &mut out,
        &presentation.excluded_modules,
        &presentation.unmatched_excludes,
    );
    if summary_only {
        return out;
    }
    if verbosity == crate::cli::TextVerbosity::Concise {
        render_limits_line(&mut out, budgets);
        if let Some(line) =
            concise_gap_summary_line(&presentation.gaps, presentation.gaps_suppressed)
        {
            let _ = writeln!(out, "{line}");
        }
        let _ = writeln!(out, "{}", crate::cli::VERBOSE_HINT);
        return out;
    }
    let _ = writeln!(
        out,
        "Details: retained paths, identities, states and coverage follow."
    );
    let _ = writeln!(
        out,
        "budgets: callers {}/{} refused {} | modules {}/{} refused {} | edges {}/{} refused {} | endpoints {}/{} refused {} | counters observed {} saturated {} | semantic_state {} held {}/{} unknown {} refused {} | retained_history {}/{} suppressed {} | inventory_endpoints {}/{} refused {} | inventory_attach_modules {}/{} refused {} | {}",
        budgets.callers_occupied,
        budgets.callers_limit,
        budgets.callers_refused,
        budgets.modules_occupied,
        budgets.modules_limit,
        budgets.modules_refused,
        budgets.edges_occupied,
        budgets.edges_limit,
        budgets.edges_refused,
        budgets.endpoints_occupied,
        budgets.endpoints_limit,
        budgets.endpoints_refused,
        budgets.counters_observed,
        budgets.counters_saturated,
        semantic_status(budgets),
        budgets.semantic_occupied,
        budgets.semantic_limit,
        budgets.semantic_unknown_edges,
        budgets.semantic_refused,
        budgets.retained,
        budgets.retained_limit,
        budgets.retained_suppressed,
        budgets.inventory_endpoints_occupied,
        budgets.inventory_endpoints_limit,
        budgets.inventory_endpoints_refused,
        budgets.inventory_modules_occupied,
        budgets.inventory_modules_limit,
        budgets.inventory_modules_refused,
        semantic_resource_line(&budgets.instance_semantic_resources),
    );
    if presentation.caller_metadata.summary.enabled {
        let summary = presentation.caller_metadata.summary;
        let _ = writeln!(
            out,
            "caller context: {} sampled / {} pending / {} unknown / {} stale / {} historical",
            summary.sampled, summary.pending, summary.unknown, summary.stale, summary.historical
        );
    }
    for caller in &presentation.callers {
        let exe = caller
            .exe
            .as_ref()
            .and_then(|exe| exe.path.as_deref())
            .unwrap_or("?");
        let _ = writeln!(
            out,
            "caller {} pid {} incarnation {} {} ({})",
            caller.id.label(),
            caller.pid,
            caller.incarnation,
            caller.lifecycle.label(),
            escape_controls(exe)
        );
        if let Some(metadata) = presentation.caller_metadata.metadata(caller.id) {
            let _ = writeln!(
                out,
                "  {}",
                crate::caller_metadata::consumer::detail(metadata, presentation.ended_ns)
            );
        }
    }
    for module in &presentation.modules {
        let path = module.paths.first().map(String::as_str).unwrap_or("?");
        let history = if module.admission_history.is_empty() {
            String::new()
        } else {
            format!(
                " admission history {}",
                admission_history_label_at(&module.admission_history, presentation.ended_ns)
            )
        };
        let _ = writeln!(
            out,
            "module {} {} {} ({}){history}",
            module.id.label(),
            escape_controls(path),
            module.lifecycle.label(),
            module.admission.label()
        );
        // A refused module names its admission reason in plain words, on its
        // own detail line. Admitted modules carry no such line; unresolved
        // admission is pending evidence, not a refusal.
        if module.admission == AdmissionState::Refused && !module.admission_reasons.is_empty() {
            let _ = writeln!(
                out,
                "  admission: {}",
                escape_controls(&module.admission_reasons[0])
            );
            let more = module.admission_reasons.len() - 1;
            if more > 0 {
                let _ = writeln!(out, "  (+{more} more admission reasons)");
            }
        }
        // A module with unidentified use names its folded lower bound in
        // plain words, on its own detail line: every decided-unbound row
        // counts once with the entries it held at drop. Rows bound to an
        // identified caller (`no_mapping_edge`) are not unidentified use,
        // and a zero lower bound carries no information, so neither prints
        // the line; JSON keeps the full record either way.
        if let Some(unbound) = &module.unbound_use {
            let unidentified = unbound.reasons.keys().any(|code| *code != NO_MAPPING_EDGE);
            if unidentified && unbound.entries > 0 {
                let _ = writeln!(
                    out,
                    "  unidentified use: at least {} entries observed ({} caller image{})",
                    unbound.entries,
                    unbound.rows,
                    if unbound.rows == 1 { "" } else { "s" }
                );
            }
        }
    }
    for edge in &presentation.edges {
        // "Active now" keeps the historical observation-window meaning:
        // snapshots capture with (ended_ns, ended_ns - started_ns), so
        // recent-or-in-flight activity IS the historical active flag.
        // The dashboard's trailing window is a different view over the
        // same model, not a second computation.
        let active = matches!(
            edge.activity,
            Activity::RecentlyObserved | Activity::InFlight
        );
        let _ = writeln!(
            out,
            "edge {} -> {} mapping {} entries {} ({}{}) presence {} capture {} activity {} semantics {} coverage {}",
            edge.caller.label(),
            edge.module.label(),
            edge.mapping.label(),
            edge.entry_count,
            edge.entry_observation,
            if active { ", active" } else { "" },
            edge.presence.label(),
            edge.capture.label(),
            edge.activity.label(),
            snapshot_semantics_at(edge, presentation.ended_ns),
            escape_controls(&coverage_label_at(&edge.coverage, presentation.ended_ns)),
        );
        for child in presentation.semantic_children(edge.caller, edge.module) {
            let instance = child.instance;
            let child = child.semantic;
            let _ = writeln!(
                out,
                "  instance {} {} api_returns={}{} historical_only_returns={} semantics {} coverage lossy={} reasons=[{}]",
                child.instance.label(),
                instance.state.label(),
                child
                    .api_returns
                    .map_or_else(|| "unknown".into(), |n| n.to_string()),
                if child.saturated { " (saturated)" } else { "" },
                child.historical_only_returns,
                snapshot_semantics_view_at(&child.semantics, presentation.ended_ns),
                child.lossy,
                child.reasons.join(","),
            );
        }
    }
    for gap in &presentation.gaps {
        // Subjects and reasons carry target-controlled strings (paths,
        // error text): escaped like every other snapshot field (DR-11).
        // Known machine subjects/reasons render in plain words with the
        // machine token beside them (JSON keeps the stored strings).
        let plain_subject = gap_plain_subject(&gap.subject);
        let plain_reason = gap_plain_reason(&gap.reason);
        let mut subject = escape_controls(plain_subject).into_owned();
        if plain_subject != gap.subject {
            subject = format!("{subject} ({})", escape_controls(&gap.subject));
        }
        let mut reason = escape_controls(plain_reason).into_owned();
        if plain_reason != gap.reason {
            reason = format!("{reason} ({})", escape_controls(&gap.reason));
        }
        match gap.budget {
            Some(refusal) => {
                let _ = writeln!(
                    out,
                    "gap [{subject}] {reason} (budget {}: limit {}, requested {})",
                    refusal.resource, refusal.limit, refusal.requested,
                );
            }
            None => {
                let _ = writeln!(out, "gap [{subject}] {reason}");
            }
        }
    }
    if presentation.gaps_suppressed > 0 {
        let _ = writeln!(out, "more gaps not shown: {}", presentation.gaps_suppressed);
    }
    out
}

/// The operator's own exclusions, echoed at every verbosity: an
/// exclusion changes what the coverage above means, so it is never
/// silent — not even under `--quiet`.
fn render_excluded_lines(
    out: &mut String,
    excluded_modules: &[crate::render::ExcludedOut],
    unmatched_excludes: &[String],
) {
    use std::fmt::Write as _;
    if !excluded_modules.is_empty() {
        let _ = writeln!(out, "Excluded by you ({} files):", excluded_modules.len());
        for excluded in excluded_modules {
            let _ = writeln!(
                out,
                "  {}: excluded by you (device {} inode {}, {} processes mapped it); calls into this file were not observed",
                escape_controls(&excluded.path),
                excluded.dev,
                excluded.ino,
                excluded.processes
            );
        }
    }
    if !unmatched_excludes.is_empty() {
        let _ = writeln!(
            out,
            "Unmatched exclusions ({}): {}",
            unmatched_excludes.len(),
            unmatched_excludes
                .iter()
                .map(|input| escape_controls(input))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

#[cfg(test)]
#[path = "present_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "present_key_ops_tests.rs"]
mod inventory_present_key_ops_tests;

#[cfg(test)]
#[path = "present/reload_disclosure_privileged_tests.rs"]
mod reload_disclosure_privileged_tests;

#[path = "present/reload_disclosure.rs"]
pub(crate) mod reload_disclosure;
