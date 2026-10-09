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
    ExeIdentity, ImageAuthority, MappingState, ModuleId, ModuleLifecycle, ModuleRecord,
    ProcessSource, SEMANTIC_UNKNOWN, UnknownReason, UseCoverage,
};
use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
use crate::render::escape_controls;
use crate::semantics_edge::{EdgeEvidence, EdgeSemantics};

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
    pub callers: Vec<CallerView>,
    pub modules: Vec<ModuleView>,
    pub edges: Vec<EdgeView>,
    pub instances: Vec<InstanceView>,
    pub semantic_edges: Vec<InstanceSemanticView>,
    pub gaps: Vec<GapView>,
    pub gaps_suppressed: u64,
    pub budgets: BudgetView,
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
    ) -> Self {
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
            let semantics = semantics_view(edge.semantics.as_ref());
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
        let instances = registry
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
        let semantic_edges = registry
            .instance_semantic_edges()
            .map(|r| {
                let mut semantics = semantics_view(r.semantics.as_ref());
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
        let gaps = registry
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
        let limits = registry.limits();
        let (observed_edges, saturated_edges) = registry.counter_census();
        Self {
            scope_label: scope_label.to_string(),
            started_ns,
            ended_ns,
            passes,
            usage_feed: registry.usage_feed(),
            native_witnesses: registry.witness_census().clone(),
            witness_placement: registry.witness_placement(),
            callers,
            modules,
            edges,
            instances,
            semantic_edges,
            gaps,
            gaps_suppressed: registry.gaps_suppressed(),
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
                retained_limit: limits.max_gaps,
                retained: registry.gaps().len(),
                retained_suppressed: registry.gaps_suppressed(),
                preadmission: coordinator.preadmission_counters(),
            },
        }
    }
}

/// Project one edge's semantic state into its owned view: the label
/// always, the mechanism rows and operation aggregates iff the edge
/// holds claims. Withheld edges keep the exact U0 unknown rendering.
fn semantics_view(state: Option<&EdgeSemantics>) -> EdgeSemanticsView {
    let Some(state) = state else {
        return EdgeSemanticsView {
            label: SEMANTIC_UNKNOWN,
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
fn snapshot_semantics(edge: &EdgeView) -> String {
    snapshot_semantics_view(&edge.semantics)
}

fn snapshot_semantics_view(semantics: &EdgeSemanticsView) -> String {
    let Some(operations) = semantics.operations.as_ref() else {
        return semantics.label.to_string();
    };
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
            "[{id} {} calls={} errors={} last={} by=[{by}] rv=[{rv}]{}]",
            mech.operations.join(","),
            mech.calls,
            mech.errors,
            mech.last_seen_ns,
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
        "{} mechs {} ops [calls={} started={} completed={} cancelled={} failed={} unknown={} orphans={} dropped={} last={}] active [{active}] evidence [state_reconciliations={} session_cancel_ambiguities={} session_cancel_unknown_flags={} operation_state_imports={} auth_state_ambiguities={} semantic_capture_failures={} async_duplicates={} async_evictions={} unmatched_closes={}]",
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
        operations.last_seen_ns,
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
pub(crate) fn coverage_label(coverage: &UseCoverage) -> String {
    match coverage {
        UseCoverage::Counted {
            since_ns,
            lossy: false,
        } => format!("counted since {since_ns}"),
        UseCoverage::Counted {
            since_ns,
            lossy: true,
        } => format!("counted since {since_ns} (lossy)"),
        UseCoverage::Witnessed { first_ns } => {
            format!("used, count unavailable (first {first_ns})")
        }
        UseCoverage::WatchedNoUse {
            since_ns,
            until_ns: None,
        } => format!("no use since {since_ns}"),
        UseCoverage::WatchedNoUse {
            since_ns,
            until_ns: Some(until_ns),
        } => format!("no use from {since_ns} to {until_ns}"),
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

/// One module's admission history in words (`refused->admitted@200`),
/// empty when the first verdict still stands.
pub(crate) fn admission_history_label(history: &[AdmissionChange]) -> String {
    history
        .iter()
        .map(|change| {
            format!(
                "{}->{}@{}",
                change.from.label(),
                change.to.label(),
                change.at_ns
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
pub(crate) fn observation_label(edge: &EdgeView) -> String {
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
        UseCoverage::WatchedNoUse { .. } => {
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
                escape_controls(&coverage_label(&edge.coverage))
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

/// Pager-friendly snapshot: a deterministic, stable text rendering of a
/// whole inventory (fit for `| less`, diffing, and test goldens).
/// Sorted, total-first, with the same identities, states, totals, and
/// gaps the JSON carries — pin equivalence with tests, not eyeballing.
/// Target-controlled strings are control-escaped; JSON is unaffected.
pub(crate) fn render_snapshot(presentation: &Presentation) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let budgets = &presentation.budgets;
    let _ = writeln!(
        out,
        "inventory {} ({} pass{}, {} caller{}, {} module{}, {} edge{})",
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
    let _ = writeln!(
        out,
        "coverage: {} gaps, {} refusals, {} suppressed",
        presentation.gaps.len(),
        budgets.refusals(),
        presentation.gaps_suppressed,
    );
    for edge in &presentation.edges {
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
            observation_label(edge),
        );
        if let Some(lifecycle) = caller.and_then(caller_lifecycle_label) {
            let _ = write!(out, "; {lifecycle}");
        }
        // Other unknown reasons already accompany the zero-count explanation;
        // positive history still keeps its unknown coverage reason alongside it.
        let show_coverage = match edge.coverage {
            UseCoverage::Counted { .. } => edge.entry_count == 0,
            UseCoverage::WatchedNoUse { .. }
            | UseCoverage::Unknown(UnknownReason::PendingFirstUse | UnknownReason::ScanOnly) => {
                true
            }
            UseCoverage::Unknown(_) => edge.entry_count > 0,
            UseCoverage::Witnessed { .. } => false,
        };
        if show_coverage {
            let _ = write!(
                out,
                "; coverage {}",
                escape_controls(&coverage_label(&edge.coverage))
            );
        }
        out.push('\n');
    }
    if presentation.edges.is_empty() {
        let _ = writeln!(
            out,
            "No application/module associations observed; this does not prove that no PKCS#11 activity occurred."
        );
    }
    let _ = writeln!(
        out,
        "Details: retained paths, identities, states and coverage follow."
    );
    let _ = writeln!(
        out,
        "budgets: callers {}/{} refused {} | modules {}/{} refused {} | edges {}/{} refused {} | endpoints {}/{} refused {} | counters observed {} saturated {} | semantic_state {} held {}/{} unknown {} refused {} | retained_history {}/{} suppressed {} | inventory_endpoints {}/{} refused {} | inventory_attach_modules {}/{} refused {}",
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
    );
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
    }
    for module in &presentation.modules {
        let path = module.paths.first().map(String::as_str).unwrap_or("?");
        let history = if module.admission_history.is_empty() {
            String::new()
        } else {
            format!(
                " admission history {}",
                admission_history_label(&module.admission_history)
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
            snapshot_semantics(edge),
            escape_controls(&coverage_label(&edge.coverage)),
        );
        for child in presentation
            .semantic_edges
            .iter()
            .filter(|child| child.caller == edge.caller && child.module == edge.module)
        {
            let instance = presentation
                .instances
                .iter()
                .find(|r| r.id == child.instance)
                .expect("semantic instance resolves in presentation");
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
                snapshot_semantics_view(&child.semantics),
                child.lossy,
                child.reasons.join(","),
            );
        }
    }
    for gap in &presentation.gaps {
        // Subjects and reasons carry target-controlled strings (paths,
        // error text): escaped like every other snapshot field (DR-11).
        let subject = escape_controls(&gap.subject);
        let reason = escape_controls(&gap.reason);
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
        let _ = writeln!(out, "gaps suppressed: {}", presentation.gaps_suppressed);
    }
    out
}

#[cfg(test)]
#[path = "inventory_present_tests.rs"]
mod tests;
