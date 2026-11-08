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
    CallerRegistry, ExeIdentity, ExeResolution, ImageAuthority, JointPublicationPending, MappingState,
    ModuleId, ModuleLifecycle, ModuleRecord, NO_MAPPING_EDGE, ProcessSource, SEMANTIC_UNKNOWN,
    UnboundPid, UnknownReason, UseCoverage, module_init,
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
    /// Observed `C_Initialize` returns since the semantic lane
    /// sealed, with the judged verdict.
    pub init: ModuleInitView,
    /// The operator declared this module a forwarding layer with
    /// `--forwarding-module`: its edges split out exactly like a closure
    /// array under the same per-caller gates.
    pub operator_forwarding: bool,
}

/// One module's `C_Initialize` evidence (S1-adjacent), owned for
/// rendering: exact observed counts, the returns-shaped last error,
/// and the judged status with its detail line.
#[derive(Debug, Clone)]
pub(crate) struct ModuleInitView {
    pub calls: u64,
    pub ok: u64,
    pub already_initialized: u64,
    pub last_error_rv: Option<InitErrorView>,
    pub status: &'static str,
    pub detail: String,
}

/// The last observed init error, shaped like a `returns` row: the
/// verbatim rv, its hex, and the registered `CKR_*` name (or `None`
/// for unregistered codes — never guessed).
#[derive(Debug, Clone)]
pub(crate) struct InitErrorView {
    pub rv: u64,
    pub rv_hex: String,
    pub name: Option<String>,
}

impl ModuleInitView {
    fn capture(registry: &CallerRegistry, module: ModuleId) -> Self {
        let rollup = registry.module_init_rollup(module);
        let judged = module_init::verdict(
            &rollup,
            registry.semantic_sealed(),
            registry.semantic_events_lossy(),
        );
        Self {
            calls: rollup.calls,
            ok: rollup.ok,
            already_initialized: rollup.already_initialized,
            last_error_rv: rollup.last_error_rv.map(|rv| InitErrorView {
                rv,
                rv_hex: format!("0x{rv:x}"),
                name: crate::semantics_edge::rv_name(rv),
            }),
            status: judged.status.label(),
            detail: judged.detail,
        }
    }
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
    /// Run-wide distinct unidentified caller images (slice 1): the
    /// concise M and `native_witnesses.unbound_images` — a lower bound
    /// while [`Self::unbound_images_saturated`].
    pub unbound_images: u64,
    /// The run-wide image set hit its bound. Sticky.
    pub unbound_images_saturated: bool,
    /// COOKIE_CTL identity refusals latched from witness health
    /// (slice 1, issue 9): caller images that never got an identity,
    /// which the unidentified-caller count misses.
    pub identity_unavailable_refused: u64,
    /// Whether the identity ticket budget spent itself.
    pub identity_budget_exhausted: bool,
    /// Every collected run-wide host pid, oldest first call first
    /// (Part C): one entry per unidentified image. Historical
    /// host/init-namespace numbers, never re-read through `/proc`.
    pub unbound_pids: Vec<crate::discovery::caller_registry::UnboundPid>,
    /// Distinct images (with their host pids) the run-wide bound
    /// turned away, saturating.
    pub unbound_pids_dropped: u64,
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
    /// `--forwarding-module` inputs that matched no mapped file. Like
    /// `unmatched_excludes`: a declaration that matched nothing must
    /// never silently do nothing.
    pub unmatched_forwarding: Vec<String>,
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
                init: ModuleInitView::capture(registry, *id),
                operator_forwarding: false,
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
        let module_keys: Vec<(ModuleId, String, (u64, u64), u64)> = modules
            .iter()
            .map(|module| {
                (
                    module.id,
                    module.paths.first().cloned().unwrap_or_default(),
                    (module.device_major, module.device_minor),
                    module.inode,
                )
            })
            .collect();
        let (forwarding_declared, unmatched_forwarding) =
            crate::render::match_forwarding_inputs(coordinator.forwarding_inputs(), &module_keys);
        let declared: std::collections::BTreeSet<ModuleId> =
            forwarding_declared.into_iter().collect();
        for module in &mut modules {
            module.operator_forwarding = declared.contains(&module.id);
        }
        Ok(Self {
            scope_label: scope_label.to_string(),
            started_ns,
            ended_ns,
            passes,
            usage_feed: registry.usage_feed(),
            native_witnesses: registry.witness_census().clone(),
            witness_placement: registry.witness_placement(),
            unbound_images: registry.unidentified_images(),
            unbound_images_saturated: registry.unidentified_images_saturated(),
            identity_unavailable_refused: coordinator.identity_unavailable_refused(),
            identity_budget_exhausted: coordinator.identity_budget_exhausted(),
            unbound_pids: registry.unidentified_pids(),
            unbound_pids_dropped: registry.unidentified_pids_dropped(),
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
            unmatched_forwarding,
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
            ..
        } => format!("counted exactly for the last {}", ago(*since_ns)),
        UseCoverage::Counted {
            lossy: true,
            pid_exit: true,
            ..
        } => "counted until the PID target exited (lower bound)".to_string(),
        UseCoverage::Counted {
            since_ns,
            lossy: true,
            ..
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

/// One edge's coverage with its pre-watch window: when a watched
/// edge's mapping predates its watch, the covered-interval "no use"
/// keeps its scope but names the missed window beside it, so the
/// coverage never reads as a bare "no use" while calls before the
/// watch were missed. Other coverages delegate to
/// [`coverage_label_at`].
pub(crate) fn coverage_label_for_edge_at(edge: &EdgeView, now_ns: u64) -> String {
    let base = coverage_label_at(&edge.coverage, now_ns);
    let UseCoverage::WatchedNoUse { since_ns, .. } = &edge.coverage else {
        return base;
    };
    if edge.mapping_first_seen_ns == 0 || edge.mapping_first_seen_ns >= *since_ns {
        return base;
    }
    let before = crate::render::fmt_ns(Some(since_ns.saturating_sub(edge.mapping_first_seen_ns)));
    format!(
        "{base}; mapped at least {before} before the watch started, earlier calls are not counted"
    )
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

/// F16 (7.05 PQC): the concise display name for a PQC
/// `metadata_at_use` label, or `None` for every non-PQC label. The
/// single display authority behind the snapshot's PQC spotlight; the
/// contract test pins coverage against all eighteen labels.
pub(crate) fn pqc_display_label(metadata_at_use: &str) -> Option<&'static str> {
    match metadata_at_use {
        "ml_dsa_44" => Some("ML-DSA-44"),
        "ml_dsa_65" => Some("ML-DSA-65"),
        "ml_dsa_87" => Some("ML-DSA-87"),
        "ml_kem_512" => Some("ML-KEM-512"),
        "ml_kem_768" => Some("ML-KEM-768"),
        "ml_kem_1024" => Some("ML-KEM-1024"),
        "slh_dsa_sha2_128s" => Some("SLH-DSA-SHA2-128S"),
        "slh_dsa_shake_128s" => Some("SLH-DSA-SHAKE-128S"),
        "slh_dsa_sha2_128f" => Some("SLH-DSA-SHA2-128F"),
        "slh_dsa_shake_128f" => Some("SLH-DSA-SHAKE-128F"),
        "slh_dsa_sha2_192s" => Some("SLH-DSA-SHA2-192S"),
        "slh_dsa_shake_192s" => Some("SLH-DSA-SHAKE-192S"),
        "slh_dsa_sha2_192f" => Some("SLH-DSA-SHA2-192F"),
        "slh_dsa_shake_192f" => Some("SLH-DSA-SHAKE-192F"),
        "slh_dsa_sha2_256s" => Some("SLH-DSA-SHA2-256S"),
        "slh_dsa_shake_256s" => Some("SLH-DSA-SHAKE-256S"),
        "slh_dsa_sha2_256f" => Some("SLH-DSA-SHA2-256F"),
        "slh_dsa_shake_256f" => Some("SLH-DSA-SHAKE-256F"),
        _ => None,
    }
}

/// F16 (7.05 PQC): the v5 vocabulary rank of a PQC
/// `metadata_at_use` label (0..18 in contract §5 table order), or
/// `None` for every non-PQC label. The spotlight's sort authority;
/// the rank test pins this order against `METADATA_LABELS_V5`.
fn pqc_label_rank(metadata_at_use: &str) -> Option<u8> {
    match metadata_at_use {
        "ml_dsa_44" => Some(0),
        "ml_dsa_65" => Some(1),
        "ml_dsa_87" => Some(2),
        "ml_kem_512" => Some(3),
        "ml_kem_768" => Some(4),
        "ml_kem_1024" => Some(5),
        "slh_dsa_sha2_128s" => Some(6),
        "slh_dsa_shake_128s" => Some(7),
        "slh_dsa_sha2_128f" => Some(8),
        "slh_dsa_shake_128f" => Some(9),
        "slh_dsa_sha2_192s" => Some(10),
        "slh_dsa_shake_192s" => Some(11),
        "slh_dsa_sha2_192f" => Some(12),
        "slh_dsa_shake_192f" => Some(13),
        "slh_dsa_sha2_256s" => Some(14),
        "slh_dsa_shake_256s" => Some(15),
        "slh_dsa_sha2_256f" => Some(16),
        "slh_dsa_shake_256f" => Some(17),
        _ => None,
    }
}

/// F16 (7.05 PQC): one proved (label, category) aggregate for the
/// snapshot's PQC spotlight. Counts only — never object identity.
pub(crate) struct PqcKeySegment {
    pub display: &'static str,
    pub category: &'static str,
    pub completed: u64,
    pub failed: u64,
    pub active: u64,
}

/// F16 (7.05 PQC): proved completions per (PQC label, category)
/// across primary-role rows only (secondary rows stand beside,
/// never double-counted — the H9 §82 rule the tallies follow).
/// Unknown summaries carry no key, so they contribute nothing.
/// Segments sort by (v5 vocabulary rank of the label, category)
/// — label bytes and display bytes both sort `ML-KEM-1024` before
/// `ML-KEM-512`, so the rank carries the table order — and name
/// proved completions only; empty when no PQC-labelled proved
/// completion exists, in which case the snapshot shows no suffix.
pub(crate) fn pqc_key_breakdown(
    observations: &crate::key_operation_projection::ObjectObservations,
) -> Vec<PqcKeySegment> {
    use std::collections::BTreeMap;
    let secondary = crate::key_operation_projection::SECONDARY_ROLE;
    let mut by_label: BTreeMap<(u8, &str), (&str, u64, u64, u64)> = BTreeMap::new();
    for row in &observations.key_operations {
        if row.role == secondary {
            continue;
        }
        let Some(display) = pqc_display_label(row.metadata_at_use) else {
            continue;
        };
        let Some(rank) = pqc_label_rank(row.metadata_at_use) else {
            continue;
        };
        let entry = by_label
            .entry((rank, row.category))
            .or_insert((display, 0, 0, 0));
        entry.1 = entry.1.saturating_add(row.completed);
        entry.2 = entry.2.saturating_add(row.failed);
        entry.3 = entry.3.saturating_add(row.active);
    }
    by_label
        .into_iter()
        .filter(|(_, (_, completed, _, _))| *completed > 0)
        .map(
            |((_, category), (display, completed, failed, active))| PqcKeySegment {
                display,
                category,
                completed,
                failed,
                active,
            },
        )
        .collect()
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

/// One provider's proved-key tallies for the readable key-operations
/// block: per-category terminals over the group's non-secondary rows
/// (H9 §82, like [`key_operation_tallies`]), with the provider's
/// display name and the group's sorted instance labels (verbose
/// only). Rows whose instance resolves to no snapshot module share
/// the one unidentified group, never the raw label in concise text.
struct KeyProviderGroup {
    name: String,
    unidentified: bool,
    instances: Vec<String>,
    tallies: Vec<KeyOpTally>,
}

/// Proved rows grouped by resolved provider module: instances on one
/// module merge into its group; unresolvable labels share the
/// unidentified group. Groups form from non-secondary rows only, so
/// the header's provider count matches the lines below it. Sorted by
/// display name with the unidentified group last.
fn key_provider_groups(
    presentation: &Presentation,
    observations: &crate::key_operation_projection::ObjectObservations,
) -> Vec<KeyProviderGroup> {
    use std::collections::{BTreeMap, BTreeSet};
    let secondary = crate::key_operation_projection::SECONDARY_ROLE;
    let mut modules: BTreeMap<String, ModuleId> = BTreeMap::new();
    for instance in &presentation.instances {
        modules
            .entry(instance.id.label())
            .or_insert(instance.module);
    }
    // (tallies by category, instance labels) per resolved module, plus
    // the unidentified residual under `None`.
    type TalliesByCategory<'a> = BTreeMap<&'a str, (u64, u64, u64, &'a str)>;
    let mut groups: BTreeMap<Option<ModuleId>, (TalliesByCategory<'_>, BTreeSet<String>)> =
        BTreeMap::new();
    for row in &observations.key_operations {
        if row.role == secondary {
            continue;
        }
        let module = modules.get(&row.instance).copied();
        let (tallies, instances) = groups.entry(module).or_default();
        instances.insert(row.instance.clone());
        let slot = tallies.entry(row.category).or_insert((0, 0, 0, row.unit));
        slot.0 = slot.0.saturating_add(row.completed);
        slot.1 = slot.1.saturating_add(row.failed);
        slot.2 = slot.2.saturating_add(row.active);
    }
    let mut out: Vec<KeyProviderGroup> = groups
        .into_iter()
        .map(|(module, (tallies, instances))| {
            let (name, unidentified) = match module {
                Some(module) => (module_label(presentation, module), false),
                None => ("unidentified provider".to_string(), true),
            };
            let tallies = tallies
                .into_iter()
                .map(|(category, (completed, failed, active, unit))| KeyOpTally {
                    category,
                    completed,
                    failed,
                    active,
                    unit,
                })
                .collect();
            KeyProviderGroup {
                name,
                unidentified,
                instances: instances.into_iter().collect(),
                tallies,
            }
        })
        .collect();
    out.sort_by(|left, right| {
        left.unidentified
            .cmp(&right.unidentified)
            .then_with(|| left.name.cmp(&right.name))
    });
    out
}

/// Capture-wide unknown-key rows grouped by category with their sorted
/// machine reasons (verbose only), never merged into a provider's
/// tallies. Sorted by category.
fn unknown_keys_tallies(
    observations: &crate::key_operation_projection::ObjectObservations,
) -> Vec<(KeyOpTally, Vec<&'static str>)> {
    use std::collections::{BTreeMap, BTreeSet};
    let mut categories: BTreeMap<&str, (u64, u64, u64, &str, BTreeSet<&str>)> = BTreeMap::new();
    for row in &observations.unknown_key_operations {
        let slot = categories
            .entry(row.category)
            .or_insert((0, 0, 0, row.unit, BTreeSet::new()));
        slot.0 = slot.0.saturating_add(row.completed);
        slot.1 = slot.1.saturating_add(row.failed);
        slot.2 = slot.2.saturating_add(row.active);
        slot.4.insert(row.reason);
    }
    categories
        .into_iter()
        .map(|(category, (completed, failed, active, unit, reasons))| {
            (
                KeyOpTally {
                    category,
                    completed,
                    failed,
                    active,
                    unit,
                },
                reasons.into_iter().collect(),
            )
        })
        .collect()
}

/// One per-category tally segment: what happened to the call, not an
/// observer failure (JSON keeps `failed`).
fn key_tally_segment(tally: &KeyOpTally) -> String {
    let failed_noun = if tally.failed == 1 {
        "returned an error"
    } else {
        "returned errors"
    };
    format!(
        "{} {} completed, {} {}, {} active {}",
        tally.category, tally.completed, tally.failed, failed_noun, tally.active, tally.unit
    )
}

/// One indented key-operations detail line: `  {name}: {segment}{suffix}`.
/// A provider file name shrinks first so the tally stays exact; when
/// the line still overflows, the verbose parenthesized suffix
/// (instance labels) shrinks next, marked with `…`. When a long name
/// meets a long suffix, neither stage fits alone, so the suffix stage
/// retries with the name shrunk against the minimal suffix (`" (…)"`).
/// Fixed labels never shrink (they are short — only a pathological
/// tally beside one may exceed the cap, since counts are never
/// truncated).
fn key_detail_line(name: &str, segment: &str, suffix: &str, shrink_name: bool) -> String {
    let rest = format!(": {segment}{suffix}");
    let fixed = 2 + rest.chars().count();
    if name.chars().count() + fixed <= SUMMARY_LINE_MAX_CHARS {
        return format!("  {name}{rest}");
    }
    let budget = SUMMARY_LINE_MAX_CHARS.saturating_sub(fixed);
    let shown_name = if shrink_name && budget >= 2 {
        let kept: String = name.chars().take(budget - 1).collect();
        format!("{kept}…")
    } else {
        name.to_string()
    };
    let line = format!("  {shown_name}{rest}");
    if line.chars().count() <= SUMMARY_LINE_MAX_CHARS {
        return line;
    }
    // The tally stays exact, so only the verbose suffix can still
    // shrink: a parenthesized list truncates its inner content with
    // `…`, keeping the closing paren.
    let Some(inner) = suffix
        .strip_prefix(" (")
        .and_then(|tail| tail.strip_suffix(')'))
    else {
        return line;
    };
    let head = format!("  {shown_name}: {segment}");
    let suffix_budget = SUMMARY_LINE_MAX_CHARS.saturating_sub(head.chars().count());
    if suffix_budget >= 4 {
        let shrunk = ellipsize_to(inner, suffix_budget - 3);
        return format!("{head} ({shrunk})");
    }
    // Both stages gave up: the name stage kept a long provider name
    // because the full suffix already blew the budget, so the head
    // alone overflows. Shrink the name against the minimal suffix
    // (`" (…)"`) and retry the suffix stage; fixed labels keep the
    // over-long line instead (their tally stays exact).
    if !shrink_name {
        return line;
    }
    // 2 indent + ": " + segment + " (…)".
    let name_budget = SUMMARY_LINE_MAX_CHARS.saturating_sub(2 + 2 + segment.chars().count() + 4);
    if name_budget < 2 {
        return line;
    }
    let shown_name = ellipsize_to(name, name_budget);
    let head = format!("  {shown_name}: {segment}");
    let suffix_budget = SUMMARY_LINE_MAX_CHARS.saturating_sub(head.chars().count());
    if suffix_budget < 4 {
        return line;
    }
    let shrunk = ellipsize_to(inner, suffix_budget - 3);
    format!("{head} ({shrunk})")
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

/// Forwarding-layer module ids: closure arrays by admission class (plus its
/// hyphenated test spelling) and operator-declared `--forwarding-module`
/// shims by marker. The split set; whether an edge at one splits out is
/// per caller ([`provider_active_callers`], minus
/// [`refused_backend_callers`]). A declared single-table shim splits
/// exactly like a closure array, and never without the declaration.
fn forwarding_module_ids(presentation: &Presentation) -> std::collections::BTreeSet<ModuleId> {
    presentation
        .modules
        .iter()
        .filter(|module| {
            module.operator_forwarding
                || matches!(
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
    forwarding: &std::collections::BTreeSet<ModuleId>,
) -> std::collections::BTreeSet<CallerId> {
    presentation
        .edges
        .iter()
        .filter(|edge| !forwarding.contains(&edge.module) && edge.entry_count > 0)
        .map(|edge| edge.caller)
        .collect()
}

/// Callers with a refused (non-closure) backend: an edge at a non-closure
/// module whose admission is refused. A refused backend keeps the caller's
/// layer edges logical — a disclosed overcount beats hiding the caller's
/// calls — even when the caller also entered an unrelated active provider.
fn refused_backend_callers(
    presentation: &Presentation,
    forwarding: &std::collections::BTreeSet<ModuleId>,
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
            !forwarding.contains(&edge.module)
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
    forwarding: &std::collections::BTreeSet<ModuleId>,
    active: &std::collections::BTreeSet<CallerId>,
    refused: &std::collections::BTreeSet<CallerId>,
) -> bool {
    forwarding.contains(&edge.module)
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
    let forwarding = forwarding_module_ids(presentation);
    let active = provider_active_callers(presentation, &forwarding);
    let refused = refused_backend_callers(presentation, &forwarding);
    let mut layers: Vec<(String, u64)> = presentation
        .modules
        .iter()
        .filter(|module| forwarding.contains(&module.id))
        .map(|module| {
            let entries = presentation
                .edges
                .iter()
                .filter(|edge| {
                    edge.module == module.id
                        && edge_is_forwarding(edge, &forwarding, &active, &refused)
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

/// Advisory hint when one caller entered two attached non-layer modules
/// exactly equally (the undeclared-shim shape — every shim entry
/// re-observed at the backend). Edges carry no per-function breakdown,
/// so inventory cannot check containment and requires exact equality of
/// at least three entries instead. The observer never splits on
/// coincidence; it names both modules and the `--forwarding-module`
/// remedy instead. Text-only and count-neutral, like the render-lane
/// hint. Declared and closure layers never suggest.
fn forwarding_suggestion(presentation: &Presentation) -> Option<String> {
    use std::collections::{BTreeMap, BTreeSet};
    let forwarding = forwarding_module_ids(presentation);
    let admitted: BTreeSet<ModuleId> = presentation
        .modules
        .iter()
        .filter(|module| {
            !forwarding.contains(&module.id) && module.admission != AdmissionState::Refused
        })
        .map(|module| module.id)
        .collect();
    // Per-caller entry totals at admitted non-layer modules.
    let mut per_caller: BTreeMap<CallerId, BTreeMap<ModuleId, u64>> = BTreeMap::new();
    for edge in &presentation.edges {
        if !admitted.contains(&edge.module) || edge.entry_count == 0 {
            continue;
        }
        *per_caller
            .entry(edge.caller)
            .or_default()
            .entry(edge.module)
            .or_default() += edge.entry_count;
    }
    let mut pairs: Vec<(ModuleId, ModuleId)> = Vec::new();
    for totals in per_caller.values() {
        let ids: Vec<ModuleId> = totals.keys().copied().collect();
        for (i, left) in ids.iter().enumerate() {
            for right in &ids[i + 1..] {
                if totals[left] >= 3 && totals[left] == totals[right] {
                    pairs.push((*left, *right));
                }
            }
        }
    }
    pairs.sort();
    pairs.dedup();
    let (first, second) = *pairs.first()?;
    let path = |id: ModuleId| {
        presentation
            .modules
            .iter()
            .find(|module| module.id == id)
            .and_then(|module| module.paths.first().cloned())
            .unwrap_or_else(|| id.label())
    };
    let mut hint = format!(
        "Possible forwarding: entries at {} coincide with entries at {}; if one forwards to the other, declare it with --forwarding-module <path-or-name> so entry totals count each application call once.",
        escape_controls(&path(first)),
        escape_controls(&path(second))
    );
    if pairs.len() > 1 {
        hint.push_str(&format!(
            " ({} more module pair{} coincide)",
            pairs.len() - 1,
            if pairs.len() == 2 { "" } else { "s" }
        ));
    }
    Some(hint)
}

/// Logical vs forwarding-layer entry totals over every edge. Provider
/// edges, plus the layer edges of callers with no entries at any
/// non-closure module or with a refused backend, are logical;
/// closure-array edges of provider-active callers without a refused
/// backend are forwarding observations of those same calls.
pub(crate) fn layer_entry_totals(presentation: &Presentation) -> (u64, u64) {
    let forwarding = forwarding_module_ids(presentation);
    let active = provider_active_callers(presentation, &forwarding);
    let refused = refused_backend_callers(presentation, &forwarding);
    let mut logical = 0u64;
    let mut forwarding_entries = 0u64;
    for edge in &presentation.edges {
        if edge_is_forwarding(edge, &forwarding, &active, &refused) {
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

/// The readable summary blocks (key operations, gaps) keep every line
/// at most this many chars: one item per line, with unbounded names
/// (provider files, gap subjects) truncated and marked. Tallies and
/// counts are never truncated — exact digits win over the cap.
const SUMMARY_LINE_MAX_CHARS: usize = 100;

/// Char-safe truncation to `max_chars` chars, marked with `…`. Fits
/// already return unchanged.
fn ellipsize_to(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let kept: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// One concise gap group line: `  {count} × {subject} — {reason}`. The
/// subject (often a long path) shrinks first so the count and reason
/// stay intact; only a reason overflowing on its own truncates the
/// whole line.
fn gap_group_line(count: usize, subject: &str, reason: &str) -> String {
    let head = format!("  {count} × ");
    let tail = format!(" — {reason}");
    let fixed = head.chars().count() + tail.chars().count();
    if subject.chars().count() + fixed <= SUMMARY_LINE_MAX_CHARS {
        return format!("{head}{subject}{tail}");
    }
    let budget = SUMMARY_LINE_MAX_CHARS.saturating_sub(fixed);
    if budget >= 2 {
        let kept: String = subject.chars().take(budget - 1).collect();
        return format!("{head}{kept}…{tail}");
    }
    ellipsize_to(&format!("{head}{subject}{tail}"), SUMMARY_LINE_MAX_CHARS)
}

/// Gaps that count toward PARTIAL: every retained row except deleted
/// mappings, which read as a notes line instead (inspect treats them
/// the same way).
fn loss_gap_count(gaps: &[GapView]) -> usize {
    gaps.iter()
        .filter(|gap| gap.reason != "deleted mapping")
        .count()
}

/// Concise gap groups listed before the block folds: per-PID
/// subjects (one group per unreadable `/proc/{pid}/mem`) could
/// otherwise print hundreds of lines on a `--system` scan. The
/// header count stays exact; `--json` carries every item.
const GAP_GROUPS_SHOWN: usize = 20;

/// The concise gap summary (F1): a `gaps: N` header plus one indented
/// line per plain subject/reason group, most frequent first, up to
/// [`GAP_GROUPS_SHOWN`] groups; beyond that one fold line names the
/// remainder. Plain words only (reusing `gap_plain_*`); per-gap
/// `gap [` lines stay verbose-only. Counts distinct loss rows like the
/// coverage line, not `repeats` (JSON carries `repeats`); deleted
/// mappings read on the notes line instead. Empty when no loss gaps
/// are retained; suppressed-but-unretained gaps stay in the coverage
/// line.
fn concise_gap_summary_block(gaps: &[GapView]) -> Vec<String> {
    let mut groups: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for gap in gaps.iter().filter(|gap| gap.reason != "deleted mapping") {
        let subject = escape_controls(gap_plain_subject(&gap.subject)).into_owned();
        let reason = escape_controls(gap_plain_reason(&gap.reason)).into_owned();
        *groups.entry((subject, reason)).or_insert(0) += 1;
    }
    if groups.is_empty() {
        return Vec::new();
    }
    let mut ranked: Vec<((String, String), usize)> = groups.into_iter().collect();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    let mut lines = vec![format!("gaps: {}", loss_gap_count(gaps))];
    for ((subject, reason), count) in ranked.iter().take(GAP_GROUPS_SHOWN) {
        lines.push(gap_group_line(*count, subject, reason));
    }
    let rest = ranked.len().saturating_sub(GAP_GROUPS_SHOWN);
    if rest == 1 {
        lines.push("  and 1 more group (--json has every item)".to_string());
    } else if rest > 1 {
        lines.push(format!("  and {rest} more groups (--json has every item)"));
    }
    lines
}

/// Deleted mappings are unloaded libraries, not loss: one plain
/// notes line disclosing them, beside the gaps block. `None` when no
/// deleted mapping is retained.
fn concise_deleted_notes_line(gaps: &[GapView]) -> Option<String> {
    let deleted = gaps
        .iter()
        .filter(|gap| gap.reason == "deleted mapping")
        .count();
    if deleted == 0 {
        return None;
    }
    if deleted == 1 {
        return Some("notes: 1 unloaded library — mapped file was deleted (not loss)".to_string());
    }
    Some(format!(
        "notes: {deleted} unloaded libraries — mapped files were deleted (not loss)"
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
    // The overlay-witness unavailable family (canonical plus every
    // enriched `: <stage>` suffix) folds to one plain clause; verbose
    // keeps the machine token beside it, JSON keeps it verbatim.
    if reason
        .strip_prefix("original_file_unproven: kernel witness unavailable")
        .is_some()
    {
        return "kernel proof unavailable";
    }
    if let Some(captured) = reason.strip_prefix("live capture refused (") {
        // The PID auto-fallback gap carries the full host summary
        // (JSON and verbose keep it); concise folds it to one short
        // clause. Only a Denied refusal with capabilities actually
        // missing carries the grant tail, so its presence is the
        // privilege signal.
        if captured.ends_with(
            "; grant the minimal capability set for full capture (see 'p11scope doctor')",
        ) {
            return "live capture refused (missing capabilities); run 'p11scope doctor'";
        }
        return "live capture refused (see 'p11scope doctor')";
    }
    match reason {
        "joint_birth_unoffered" => "no key session was offered to track",
        "joint_image_refused" | "joint_birth_claim_ImageTainted" => {
            "process was not tracked from its first call"
        }
        "joint_birth_no_admission" => "process was not admitted for tracking",
        "joint_journal_unavailable" => "per-key tracking is off in this run",
        "foreign_or_unproven_caller" => "caller not confirmed",
        "no BPF image identity; scan-lane incarnations by pidfd/start-time with exe-identity exec detection" => {
            "some processes were identified from /proc only"
        }
        "deleted mapping" => "mapped file was deleted (not loss)",
        "original_file_unproven: the kernel witness proved another file" => {
            "mapping is another file, not the held file"
        }
        "original_file_unproven: witness query budget exhausted" => "kernel proof budget exhausted",
        "original_file_unproven: witness anchor binding failed" => "kernel proof anchor failed",
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
        // A pre-watch mapping names its missed window beside the
        // covered-interval "no use", so concise never reads as a bare
        // "no use" while calls before the watch were missed. A single
        // edge names its exact window; several name their count with
        // the exact windows in -v and JSON.
        let windows: Vec<u64> = edges
            .iter()
            .filter_map(|edge| match &edge.coverage {
                UseCoverage::WatchedNoUse { since_ns, .. }
                    if edge.mapping_first_seen_ns > 0 && edge.mapping_first_seen_ns < *since_ns =>
                {
                    Some(since_ns.saturating_sub(edge.mapping_first_seen_ns))
                }
                _ => None,
            })
            .collect();
        if windows.is_empty() {
            return "no use in the covered interval".to_string();
        }
        if windows.len() == 1 && edges.len() == 1 {
            let before = crate::render::fmt_ns(Some(windows[0]));
            return format!(
                "no use in the covered interval; mapped at least {before} before the watch \
                 started, earlier calls are not counted"
            );
        }
        return format!(
            "no use in the covered interval; {} of {} mappings predate the watch, earlier calls \
             are not counted",
            windows.len(),
            edges.len()
        );
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
        // The base label: the observation above already names the
        // pre-watch window, so the edge-qualified label would repeat it.
        // (The edge dump and dashboard coverage items, which show no
        // observation, keep the qualified label.)
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
/// Reason label for an unidentified image without a path. The
/// EXEC-joined kernel word reads decoded (`dev major:minor`), like the
/// published JSON pair — never the raw word.
fn unknown_exe_label(exe: &crate::discovery::caller_registry::UnboundExe) -> String {
    match exe.resolution {
        ExeResolution::PathUnknown => {
            let device = p11scope_manifest::maps::Device::from_kdev(exe.dev);
            format!(
                "unknown executable (dev {}:{}, ino {})",
                device.major, device.minor, exe.ino
            )
        }
        ExeResolution::ExecRecordLost => "executable unknown (exec record lost)".to_string(),
        ExeResolution::NoExecRecord => "executable unknown (no exec record)".to_string(),
        ExeResolution::ExeUnavailable => {
            "executable unknown (exe identity unavailable)".to_string()
        }
        // Unreachable: a resolved image carries a path. Read unknown
        // rather than panic: the path is absent, whatever the label.
        ExeResolution::ProcAlive | ExeResolution::ScanLearned | ExeResolution::SystemIndex => {
            "executable unknown (unresolved)".to_string()
        }
    }
}

/// Where one unidentified executable came from (verbose detail).
fn exe_source_label(resolution: ExeResolution) -> &'static str {
    match resolution {
        ExeResolution::ProcAlive => "via live process",
        ExeResolution::ScanLearned => "via scan record",
        ExeResolution::SystemIndex => "via system index",
        ExeResolution::PathUnknown => {
            "no path matched (deleted file, container overlay, or non-system binary)"
        }
        ExeResolution::ExeUnavailable => "the kernel exe read failed",
        ExeResolution::NoExecRecord => "no exec record joined",
        ExeResolution::ExecRecordLost => "lifecycle evidence lost",
    }
}

/// The concise executable line: unidentified caller images grouped
/// by executable with call counts and pids, busiest group first.
/// Resolved groups read by basename (full path when basenames
/// collide on the line); unknown groups read their reason. Up to
/// five groups and five pids per group; the rest counts.
fn render_unidentified_executables(pids: &[UnboundPid], dropped: u64) -> Option<String> {
    if pids.is_empty() {
        return None;
    }
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    enum GroupKey<'a> {
        Path(&'a str),
        Unknown(ExeResolution, u64, u64),
    }
    let mut members: std::collections::HashMap<GroupKey<'_>, Vec<&UnboundPid>> =
        std::collections::HashMap::new();
    for pid in pids {
        let key = match (&pid.exe.path, pid.exe.resolution) {
            (Some(path), resolution) if resolution.is_resolved() => GroupKey::Path(path),
            _ => GroupKey::Unknown(pid.exe.resolution, pid.exe.dev, pid.exe.ino),
        };
        members.entry(key).or_default().push(pid);
    }
    struct Group<'a> {
        key: GroupKey<'a>,
        members: Vec<&'a UnboundPid>,
        calls: u64,
        first_ns: u64,
    }
    let mut groups: Vec<Group<'_>> = members
        .into_iter()
        .map(|(key, members)| {
            let calls = members
                .iter()
                .fold(0u64, |calls, pid| calls.saturating_add(pid.calls_at_least));
            let first_ns = members
                .iter()
                .map(|pid| pid.first_call_ns)
                .min()
                .unwrap_or(u64::MAX);
            Group {
                key,
                members,
                calls,
                first_ns,
            }
        })
        .collect();
    groups.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.first_ns.cmp(&b.first_ns)));
    // Basenames shared by two groups on this line read by full path.
    let mut basenames: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for group in &groups {
        if let GroupKey::Path(path) = group.key {
            let basename = path
                .rsplit('/')
                .find(|part| !part.is_empty())
                .unwrap_or(path);
            *basenames.entry(basename).or_default() += 1;
        }
    }
    let mut parts = Vec::new();
    for group in groups.iter().take(5) {
        let name = match group.key {
            GroupKey::Path(path) => {
                let basename = path
                    .rsplit('/')
                    .find(|part| !part.is_empty())
                    .unwrap_or(path);
                let display = if basenames.get(basename).is_some_and(|count| *count > 1) {
                    path
                } else {
                    basename
                };
                escape_controls(display).into_owned()
            }
            GroupKey::Unknown(..) => unknown_exe_label(&group.members[0].exe),
        };
        // An ambiguous image keeps its name first; the marker lists
        // the candidates' full paths beside it -- the richest list in
        // the group when members disagree, the first two with the
        // rest counted. Counts never change.
        let richest = group
            .members
            .iter()
            .copied()
            .filter(|pid| pid.exe.identity_candidates.len() > 1)
            .max_by_key(|pid| pid.exe.identity_candidates.len());
        let name = match richest {
            Some(pid) => {
                let shown: Vec<String> = pid
                    .exe
                    .identity_candidates
                    .iter()
                    .take(2)
                    .map(|candidate| escape_controls(candidate).into_owned())
                    .collect();
                let more = pid
                    .exe
                    .identity_candidates
                    .len()
                    .saturating_sub(shown.len());
                if more > 0 {
                    format!("{name} (ambiguous: {} (+{more} more))", shown.join(", "))
                } else {
                    format!("{name} (ambiguous: {})", shown.join(", "))
                }
            }
            None => name,
        };
        let mut members = group.members.clone();
        members.sort_by(|a, b| {
            a.first_call_ns
                .cmp(&b.first_call_ns)
                .then(a.pid_host.cmp(&b.pid_host))
        });
        let shown: Vec<String> = members
            .iter()
            .take(5)
            .map(|pid| pid.pid_host.to_string())
            .collect();
        let pids_more = members.len().saturating_sub(shown.len());
        let pids_text = if members.len() == 1 {
            format!("host pid {}", shown.join(", "))
        } else if pids_more > 0 {
            format!("host pids {} (+{pids_more} more)", shown.join(", "))
        } else {
            format!("host pids {}", shown.join(", "))
        };
        parts.push(format!(
            "{name} ({} call{}, {pids_text})",
            group.calls,
            if group.calls == 1 { "" } else { "s" },
        ));
    }
    let hidden: usize = groups.iter().skip(5).map(|group| group.members.len()).sum();
    let more = u64::try_from(hidden)
        .unwrap_or(u64::MAX)
        .saturating_add(dropped);
    let mut line = format!("unidentified executables: {}", parts.join("; "));
    if more > 0 {
        line.push_str(&format!(" (+{more} more)"));
    }
    Some(line)
}

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

/// One concise per-caller scope line (F10): the per-caller entry total
/// plus the container/pod label. Only callers with a label get a line —
/// host callers stay covered by the provider lines above, and missing or
/// unavailable metadata yields `None` (no line, never a wrong ID).
fn concise_caller_scope_line(
    app: &str,
    pid: u32,
    entries: u64,
    metadata: Option<crate::caller_metadata::presentation::CallerMetadata>,
) -> Option<String> {
    let label =
        crate::caller_metadata::presentation::concise_scope_label(metadata.as_ref()?, false)?;
    let noun = if entries == 1 { "entry" } else { "entries" };
    Some(format!(
        "caller {app} pid {pid}: {entries} {noun} observed, {label}"
    ))
}

/// Concise per-caller scope lines shown before the overflow summary.
const CONCISE_SCOPE_LINES_SHOWN: usize = 8;

/// Concise per-caller scope lines, in caller order, only when the
/// `--caller-metadata cgroup` opt-in frame is on. Totals are logical:
/// forwarding-layer observations stay in the forwarding split above and
/// never inflate the caller's own count. At most eight lines print, then
/// an overflow line; a caller-context count line (nonzero parts only)
/// names labeled, unknown and pending callers with edges, so missing
/// observations never vanish silently. Callers without an edge print
/// nothing; the view degrades to the provider lines alone.
fn render_concise_caller_scope_lines(out: &mut String, presentation: &Presentation) {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;
    if !presentation.caller_metadata.summary.enabled {
        return;
    }
    let forwarding = forwarding_module_ids(presentation);
    let active = provider_active_callers(presentation, &forwarding);
    let refused = refused_backend_callers(presentation, &forwarding);
    let mut totals: BTreeMap<CallerId, u64> = BTreeMap::new();
    for edge in &presentation.edges {
        let total = totals.entry(edge.caller).or_default();
        if !edge_is_forwarding(edge, &forwarding, &active, &refused) {
            *total = total.saturating_add(edge.entry_count);
        }
    }
    let mut labeled = 0usize;
    let mut unknown = 0usize;
    let mut pending = 0usize;
    let mut lines: Vec<String> = Vec::new();
    for caller in &presentation.callers {
        let Some(total) = totals.get(&caller.id) else {
            continue;
        };
        let metadata = presentation.caller_metadata.metadata(caller.id);
        if let Some(line) = concise_caller_scope_line(
            &application_label(presentation, caller.id),
            caller.pid,
            *total,
            metadata,
        ) {
            labeled += 1;
            lines.push(line);
        } else if let Some(metadata) = metadata {
            match metadata.status {
                crate::caller_metadata::presentation::MetadataStatus::Pending => pending += 1,
                crate::caller_metadata::presentation::MetadataStatus::Sampled => {}
                crate::caller_metadata::presentation::MetadataStatus::Stale
                | crate::caller_metadata::presentation::MetadataStatus::Historical
                    if metadata.validity.is_some() => {}
                crate::caller_metadata::presentation::MetadataStatus::Unknown
                | crate::caller_metadata::presentation::MetadataStatus::Stale
                | crate::caller_metadata::presentation::MetadataStatus::Historical => unknown += 1,
            }
        } else {
            unknown += 1;
        }
    }
    let shown = lines.len().min(CONCISE_SCOPE_LINES_SHOWN);
    for line in lines.iter().take(shown) {
        let _ = writeln!(out, "{line}");
    }
    let more = lines.len().saturating_sub(shown);
    if more > 0 {
        let noun = if more == 1 { "caller" } else { "callers" };
        let _ = writeln!(out, "and {more} more labeled {noun} (-v or --json)");
    }
    if labeled + unknown + pending > 0 {
        let mut parts: Vec<String> = Vec::new();
        if labeled > 0 {
            parts.push(format!("{labeled} labeled"));
        }
        if unknown > 0 {
            parts.push(format!("{unknown} unknown"));
        }
        if pending > 0 {
            parts.push(format!("{pending} pending"));
        }
        let _ = writeln!(out, "caller context: {} (-v for details)", parts.join(", "));
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
    // One coverage format everywhere (profile, inspect, inventory):
    // `coverage: complete`, or `coverage: partial` with the nonzero
    // segments — loss gaps, refusals, suppressed-but-unretained.
    // Zero counts stay out; deleted mappings read as notes, never
    // forcing PARTIAL; the gaps block below names the reasons.
    let gaps = loss_gap_count(&presentation.gaps);
    if gaps == 0 && budgets.refusals() == 0 && presentation.gaps_suppressed == 0 {
        let _ = writeln!(out, "coverage: complete");
    } else {
        let mut segments = Vec::new();
        if gaps > 0 {
            segments.push(format!("{gaps} gap{}", if gaps == 1 { "" } else { "s" }));
        }
        if budgets.refusals() > 0 {
            segments.push(format!("{} refused", budgets.refusals()));
        }
        if presentation.gaps_suppressed > 0 {
            segments.push(format!("{} more not shown", presentation.gaps_suppressed));
        }
        let _ = writeln!(out, "coverage: partial — {}", segments.join(", "));
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
        // Slice 1: distinct unidentified caller images, run-wide. M
        // is informative even when N is 0 (callers touched the
        // provider but no call volume folded), so the gate is M
        // alone. Exactly the folded lower bound: nothing else sums
        // into N.
        if presentation.unbound_images > 0 {
            // Part C: up to five historical host pids after the
            // clause, always with the historical qualifier; the rest
            // (unshown collected plus saturation-dropped) count as
            // more. Empty only for test-direct rows without images.
            let pids = if presentation.unbound_pids.is_empty() {
                String::new()
            } else {
                let shown: Vec<String> = presentation
                    .unbound_pids
                    .iter()
                    .take(5)
                    .map(|pid| pid.pid_host.to_string())
                    .collect();
                let more = u64::try_from(presentation.unbound_pids.len())
                    .unwrap_or(u64::MAX)
                    .saturating_sub(shown.len() as u64)
                    .saturating_add(presentation.unbound_pids_dropped);
                if more > 0 {
                    format!(
                        "; host pids {} (+{more} more; not running now or never scanned)",
                        shown.join(", ")
                    )
                } else {
                    format!(
                        "; host pids {} (not running now or never scanned)",
                        shown.join(", ")
                    )
                }
            };
            let _ = writeln!(
                out,
                "unidentified callers: at least {} call{} from {} caller process{} never identified (exited or never scanned){}{}",
                entries,
                if entries == 1 { "" } else { "s" },
                presentation.unbound_images,
                if presentation.unbound_images == 1 {
                    ""
                } else {
                    "es"
                },
                pids,
                if presentation.unbound_images_saturated {
                    "; image bound reached, more callers possible"
                } else {
                    ""
                }
            );
            // The same images grouped by executable with call counts.
            if let Some(line) = render_unidentified_executables(
                &presentation.unbound_pids,
                presentation.unbound_pids_dropped,
            ) {
                let _ = writeln!(out, "{line}");
            }
        }
        // Slice 1, issue 9: caller images that never got an identity
        // are missing from M above; name the strain beside it.
        if presentation.identity_unavailable_refused > 0 {
            let _ = writeln!(
                out,
                "identity unavailable: no caller identity for {} process image{}{}",
                presentation.identity_unavailable_refused,
                if presentation.identity_unavailable_refused == 1 {
                    ""
                } else {
                    "s"
                },
                if presentation.identity_budget_exhausted {
                    " (ticket budget spent)"
                } else {
                    ""
                }
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
                        "key operations: requested, but per-key tracking needs --manifest"
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
            // Readable block: one header line plus one indented line per
            // provider and category, then the unknown, unattributed and
            // unknown-type lines. Same counts and vocabulary as the old
            // one-line enumeration, only laid out; JSON is unchanged.
            let groups = key_provider_groups(presentation, observations);
            let unknown = unknown_keys_tallies(observations);
            let sessions = observations.sessions.len();
            let keys = observations.objects.len();
            let providers = groups.len();
            let _ = writeln!(
                out,
                "key operations: {keys} key{} on {providers} provider{}; rev {} {}; {sessions} session{}",
                if keys == 1 { "" } else { "s" },
                if providers == 1 { "" } else { "s" },
                observations.revision,
                observations.status.label(),
                if sessions == 1 { "" } else { "s" },
            );
            // A non-`none` reason reads on its own line so the header
            // stays short, with the machine reason beside it in verbose
            // text (JSON keeps it).
            if observations.reason != "none" {
                // v0.7.0 issue 2: the reason must match the rows. A
                // partial `authority_lost` section whose rows continue
                // never reads "stopped" — it names the loss while the
                // exact rows beside it continue. With no rows at all
                // (counts only) the stopped wording stays accurate.
                let rows_continue = !observations.key_operations.is_empty()
                    || !observations.unknown_key_operations.is_empty();
                let plain = if observations.reason == "authority_lost" && rows_continue {
                    "per-key tracking lost some calls; exact rows continue"
                } else {
                    key_observation_plain_reason(observations.reason)
                };
                if verbose && plain != observations.reason {
                    let _ = writeln!(out, "  {plain} (reason: {})", observations.reason);
                } else {
                    let _ = writeln!(out, "  {plain}");
                }
            }
            let any_tallies =
                groups.iter().any(|group| !group.tallies.is_empty()) || !unknown.is_empty();
            if !any_tallies {
                let _ = writeln!(out, "  no key operations observed");
            }
            for group in &groups {
                // The group's sorted instance labels stay verbose-only;
                // concise names the provider, never internal ids.
                // Instance labels are projection strings: escaped like
                // every other snapshot field.
                let suffix = if verbose {
                    let labels: Vec<String> = group
                        .instances
                        .iter()
                        .map(|label| escape_controls(label).into_owned())
                        .collect();
                    format!(" ({})", labels.join(", "))
                } else {
                    String::new()
                };
                for tally in &group.tallies {
                    let _ = writeln!(
                        out,
                        "{}",
                        key_detail_line(
                            &group.name,
                            &key_tally_segment(tally),
                            &suffix,
                            !group.unidentified
                        )
                    );
                }
            }
            for (tally, reasons) in &unknown {
                let suffix = if verbose {
                    format!(" ({})", reasons.join(", "))
                } else {
                    String::new()
                };
                let _ = writeln!(
                    out,
                    "{}",
                    key_detail_line("unknown keys", &key_tally_segment(tally), &suffix, false)
                );
            }
            // F16 (7.05 PQC): the PQC spotlight names proved uses per
            // parameter set on its own line; concise shows completions,
            // `-v` adds failed/active. Absent without PQC rows, so
            // older snapshots (and their pins) never see it. It precedes
            // the not-attributed and unknown-type lines.
            let pqc = pqc_key_breakdown(observations);
            if !pqc.is_empty() {
                let segments: Vec<String> = pqc
                    .iter()
                    .map(|segment| {
                        if verbose {
                            let failed_noun = if segment.failed == 1 {
                                "returned an error"
                            } else {
                                "returned errors"
                            };
                            format!(
                                "{} {}: {} completed, {} {}, {} active",
                                segment.display,
                                segment.category,
                                segment.completed,
                                segment.failed,
                                failed_noun,
                                segment.active
                            )
                        } else {
                            format!(
                                "{} {}: {}",
                                segment.display, segment.category, segment.completed
                            )
                        }
                    })
                    .collect();
                let _ = writeln!(out, "  pqc keys: {}", segments.join(", "));
            }
            // Not-attributed counters sit beside the exact rows, one
            // line per finite reason: counts only, never a guessed key.
            for row in &observations.unattributed {
                let _ = writeln!(out, "  not attributed: {} {}", row.reason, row.count);
            }
            // First-observed keys with unestablished type keep their
            // rows under the `unknown` metadata label (DEMO-4): say
            // so beside the tallies, counts only, never a guessed
            // label.
            let unknown_type_rows = observations
                .key_operations
                .iter()
                .filter(|row| {
                    row.metadata_at_use == crate::key_operation_projection::METADATA_UNKNOWN
                })
                .count();
            if unknown_type_rows > 0 {
                let _ = writeln!(
                    out,
                    "  type unknown (not established while observed) ({unknown_type_rows} key row{})",
                    if unknown_type_rows == 1 { "" } else { "s" }
                );
            }
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
    if let Some(hint) = forwarding_suggestion(presentation) {
        let _ = writeln!(out, "{hint}");
    }
    // Verbose keeps one line per edge with internal ids; concise and
    // quiet group per provider (see `render_concise_edges`). Concise
    // adds one scope line per labeled caller when the cgroup metadata
    // opt-in is on; quiet stays a bare summary.
    if verbose {
        for edge in &presentation.edges {
            render_verbose_edge(&mut out, presentation, edge);
        }
    } else {
        render_concise_edges(&mut out, presentation);
        if verbosity == crate::cli::TextVerbosity::Concise {
            render_concise_caller_scope_lines(&mut out, presentation);
        }
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
        &presentation.unmatched_forwarding,
    );
    if summary_only {
        return out;
    }
    if verbosity == crate::cli::TextVerbosity::Concise {
        render_limits_line(&mut out, budgets);
        for line in concise_gap_summary_block(&presentation.gaps) {
            let _ = writeln!(out, "{line}");
        }
        if let Some(line) = concise_deleted_notes_line(&presentation.gaps) {
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
        let metadata = presentation.caller_metadata.metadata(caller.id);
        let mut caller_line = format!(
            "caller {} pid {} incarnation {} {} ({})",
            caller.id.label(),
            caller.pid,
            caller.incarnation,
            caller.lifecycle.label(),
            escape_controls(exe)
        );
        if let Some(label) = metadata
            .as_ref()
            .and_then(|m| crate::caller_metadata::presentation::concise_scope_label(m, true))
        {
            caller_line.push_str(", ");
            caller_line.push_str(&label);
        }
        let _ = writeln!(out, "{caller_line}");
        if let Some(metadata) = metadata {
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
                // Part C: every collected host pid with its first-call
                // time, oldest first. Historical host numbers, never
                // re-read through `/proc`, hence always qualified.
                let pids = unbound.pids_sorted();
                if !pids.is_empty() {
                    let list = pids
                        .iter()
                        .map(|pid| {
                            format!(
                                "{} (first call {} ago)",
                                pid.pid_host,
                                crate::render::fmt_ns(Some(
                                    presentation.ended_ns.saturating_sub(pid.first_call_ns)
                                ))
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    if unbound.pids_dropped > 0 {
                        let _ = writeln!(
                            out,
                            "    host pids: {list} (+{} more; not running now or never scanned)",
                            unbound.pids_dropped
                        );
                    } else {
                        let _ = writeln!(
                            out,
                            "    host pids: {list} (not running now or never scanned)"
                        );
                    }
                    // Every collected executable with its pid,
                    // dev:ino, resolution source, and first-call
                    // time, oldest first.
                    let exes = pids
                        .iter()
                        .map(|pid| {
                            let name = match &pid.exe.path {
                                Some(path) => escape_controls(path).into_owned(),
                                None => unknown_exe_label(&pid.exe),
                            };
                            let device = p11scope_manifest::maps::Device::from_kdev(pid.exe.dev);
                            // Verbose lists every candidate: the shown
                            // path plus each other spelling that
                            // verified to the same pair.
                            let ambiguity = if pid.exe.identity_ambiguous() {
                                let shown = pid.exe.path.as_deref().unwrap_or_default();
                                let others: Vec<String> = pid
                                    .exe
                                    .identity_candidates
                                    .iter()
                                    .filter(|candidate| candidate.as_str() != shown)
                                    .map(|candidate| escape_controls(candidate).into_owned())
                                    .collect();
                                format!(
                                    "; ambiguous: same identity as {} other file{}: {}",
                                    others.len(),
                                    if others.len() == 1 { "" } else { "s" },
                                    others.join(", "),
                                )
                            } else {
                                String::new()
                            };
                            format!(
                                "{} host pid {} (first call {} ago; dev {}:{} ino {}; {}{})",
                                name,
                                pid.pid_host,
                                crate::render::fmt_ns(Some(
                                    presentation.ended_ns.saturating_sub(pid.first_call_ns)
                                )),
                                device.major,
                                device.minor,
                                pid.exe.ino,
                                exe_source_label(pid.exe.resolution),
                                ambiguity,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    if unbound.pids_dropped > 0 {
                        let _ = writeln!(
                            out,
                            "    unidentified executables: {exes} (+{} more)",
                            unbound.pids_dropped
                        );
                    } else {
                        let _ = writeln!(out, "    unidentified executables: {exes}");
                    }
                }
            }
        }
        // A module with observed `C_Initialize` evidence names its
        // init verdict on its own detail line. Quiet modules print
        // nothing here; JSON keeps the per-module record either way.
        if module.init.calls > 0 {
            let _ = writeln!(
                out,
                "  init: {} ({} call{})",
                module.init.detail,
                module.init.calls,
                if module.init.calls == 1 { "" } else { "s" }
            );
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
            escape_controls(&coverage_label_for_edge_at(edge, presentation.ended_ns)),
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
    unmatched_forwarding: &[String],
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
    if !unmatched_forwarding.is_empty() {
        let _ = writeln!(
            out,
            "Unmatched forwarding declarations ({}): {}",
            unmatched_forwarding.len(),
            unmatched_forwarding
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
