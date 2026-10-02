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
//! `armed | scan only | refused | retired | coverage lost`; activity
//! `recently observed | operation initialized / in flight | used
//! (recency unknown) | quiet | unknown (lossy) | unknown (not covered) |
//! unknown`. Quiet is not unloaded; capture refusal is not application
//! inactivity; witnessed use is never quiet; an edge whose usage nothing
//! covers is neither quiet nor armed (Task 6 C2 review I3).
//! The mapping from registry state is documented on each enum and
//! pinned by tests. Per-edge usage coverage ([`UseCoverage`]) renders
//! through [`coverage_label`] in snapshots and dashboard frames and as
//! `entries.coverage` in JSON.

use crate::discovery::caller_registry::{
    AdmissionChange, AdmissionState, BudgetRefusal, CallerId, CallerLifecycle, CallerRecord,
    ExeIdentity, ImageAuthority, MappingState, ModuleId, ModuleLifecycle, ModuleRecord,
    ProcessSource, SEMANTIC_UNKNOWN, UnknownReason, UseCoverage,
};
use crate::discovery::engine::inventory_coordinator::InventoryCoordinator;
use crate::render::escape_controls;
use crate::semantics_edge::{EdgeEvidence, EdgeSemantics};

/// Trailing window for dashboard "recently observed": an entry whose
/// last-seen falls inside this window (of the frame's `now_ns`) reads
/// as recent. Snapshots instead use the observation window
/// (`ended_ns - started_ns`), matching the historical "active" flag.
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
/// whose usage is actually covered (counted, witnessed, or watched).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Capture {
    Armed,
    ScanOnly,
    Refused,
    Retired,
    CoverageLost,
}

impl Capture {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::ScanOnly => "scan only",
            Self::Refused => "refused",
            Self::Retired => "retired",
            Self::CoverageLost => "coverage lost",
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
/// reads as unknown; then, for a live mapping, quiet only where the
/// quiet is a fact — a loss-free counting feed or a watched module with
/// no recent entry; a lossy feed reads unknown (lossy); and an edge no
/// usage producer covers (scan only, refused, not attached, lost) reads
/// unknown (not covered) — never idle. Quiet is not unloaded: unloaded
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
            Self::Uncovered => "unknown (not covered)",
            Self::Unknown => "unknown",
        }
    }

    /// `recent` comes from the registry's recency predicate (the
    /// same window math the historical "active" flag uses); this maps
    /// states, never recomputes windows. `op_active` is genuine S1
    /// operation state (a live machine), never recency. `coverage` is
    /// the edge's usage coverage: it decides whether a silent live edge
    /// is quiet (a fact) or uncovered.
    pub(crate) fn for_edge(
        mapping: MappingState,
        in_flight: bool,
        recent: bool,
        op_active: bool,
        coverage: &UseCoverage,
    ) -> Self {
        if in_flight || op_active {
            return Self::InFlight;
        }
        if recent {
            return Self::RecentlyObserved;
        }
        if coverage.is_witnessed() {
            return Self::Used;
        }
        if mapping != MappingState::Mapped {
            return Self::Unknown;
        }
        match coverage {
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

/// One coverage gap, owned for rendering.
#[derive(Debug, Clone)]
pub(crate) struct GapView {
    pub caller: Option<CallerId>,
    pub module: Option<ModuleId>,
    pub pid: Option<u32>,
    pub subject: String,
    pub reason: String,
    pub budget: Option<BudgetRefusal>,
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
    pub retained_limit: usize,
    pub retained: usize,
    pub retained_suppressed: u64,
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
    pub callers: Vec<CallerView>,
    pub modules: Vec<ModuleView>,
    pub edges: Vec<EdgeView>,
    pub gaps: Vec<GapView>,
    pub gaps_suppressed: u64,
    pub budgets: BudgetView,
}

impl Presentation {
    /// Capture the coordinator's published state into an immutable
    /// snapshot. `now_ns`/`window_ns` parameterize activity recency
    /// (snapshots pass the observation end/width; dashboard frames pass
    /// the frame time and [`DASHBOARD_ACTIVITY_WINDOW_NS`]).
    pub(crate) fn capture<Source: ProcessSource>(
        coordinator: &InventoryCoordinator<Source>,
        scope_label: &str,
        started_ns: u64,
        ended_ns: u64,
        passes: u64,
        now_ns: u64,
        window_ns: u64,
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
            let coverage = registry.coverage(edge);
            // Recency comes only from counted coverage.
            let recent = matches!(coverage, UseCoverage::Counted { .. })
                && registry.entry_recent_within(edge, now_ns, window_ns);
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
                mapping_first_seen_ns: edge.mapping_first_seen_ns,
                mapping_last_seen_ns: edge.mapping_last_seen_ns,
                mapping_interruptions: edge.mapping_interruptions,
                entry_count: edge.entry_count,
                entry_saturated: edge.entry_saturated,
                entry_first_seen_ns: edge.entry_first_seen_ns,
                entry_last_seen_ns: edge.entry_last_seen_ns,
                entry_in_flight: edge.entry_in_flight,
                entry_observation: registry.entry_observation(edge).label(),
                presence: Presence::for_edge(caller_record, module_record, edge.mapping),
                capture: Capture::for_edge(caller_record, module_record, edge.mapping, &coverage),
                activity: Activity::for_edge(
                    edge.mapping,
                    edge.entry_in_flight,
                    recent,
                    op_active,
                    &coverage,
                ),
                coverage,
                semantics,
            });
        }
        let gaps = registry
            .gaps()
            .iter()
            .map(|gap| GapView {
                caller: gap.caller,
                module: gap.module,
                pid: gap.pid,
                subject: gap.subject.clone(),
                reason: gap.reason.clone(),
                budget: gap.budget,
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
            callers,
            modules,
            edges,
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
                retained_limit: limits.max_gaps,
                retained: registry.gaps().len(),
                retained_suppressed: registry.gaps_suppressed(),
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
    let semantics = &edge.semantics;
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
        UseCoverage::WatchedNoUse { since_ns } => format!("no use since {since_ns}"),
        UseCoverage::Unknown(reason) => format!("unknown ({})", reason.text()),
    }
}

/// The dashboard's compact entry count: the number only where it is a
/// fact (a counted or watched edge, or a positive count — `+` marks a
/// lossy lower bound), `?` where the count is unavailable (unknown
/// coverage, or witnessed use without a count). A zero never reads as a
/// fact the coverage cannot back.
pub(crate) fn entries_display(edge: &EdgeView) -> String {
    match &edge.coverage {
        UseCoverage::Counted { lossy: true, .. } if edge.entry_count > 0 => {
            format!("{}+", edge.entry_count)
        }
        UseCoverage::Counted { lossy: false, .. } | UseCoverage::WatchedNoUse { .. } => {
            edge.entry_count.to_string()
        }
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
