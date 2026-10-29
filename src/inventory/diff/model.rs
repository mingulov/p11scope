//! SPDX-License-Identifier: GPL-3.0-or-later
//! Typed offline report: observations on independent windows, never continuity.

use super::input;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct DiffReport {
    pub schema: &'static str,
    pub before: SnapshotSummary,
    pub after: SnapshotSummary,
    pub comparison: Comparison,
    pub summary: Summary,
    pub module_contents: Vec<ContentRow>,
    pub application_changes: Vec<ApplicationChange>,
    pub module_path_changes: Vec<ModulePathChange>,
    pub unresolved: Vec<Unresolved>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct SnapshotSummary {
    pub scope: String,
    pub clock: input::Clock,
    pub observation: input::Observation,
    pub pid_namespace: Option<input::PidNamespace>,
    pub scope_completeness: &'static str,
    pub reported_gaps: usize,
    pub suppressed_gaps: u64,
    pub refusals: Refusals,
    pub budgets: input::Budgets,
    pub loss_evidence: LossEvidence,
    pub gaps: Vec<GapEvidence>,
    pub evidence: SideEvidence,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Refusals {
    pub reported_budget_gaps: usize,
    pub budget_counters: BTreeMap<String, Option<u64>>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct LossEvidence {
    pub lifecycle: Option<input::Lifecycle>,
    pub native_witnesses: Option<input::NativeWitnesses>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Comparison {
    pub host_relation: &'static str,
    pub boot_relation: &'static str,
    pub process_continuity: &'static str,
    pub physical_continuity: &'static str,
    pub counter_relation: &'static str,
    pub scope_relation: &'static str,
    pub application_paths: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Summary {
    pub application_groups_compared: usize,
    pub application_groups_changed: usize,
    pub content_both: usize,
    pub content_before_only: usize,
    pub content_after_only: usize,
    pub module_paths_changed: usize,
    pub unresolved_observations: usize,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Presence {
    Both,
    BeforeOnly,
    AfterOnly,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Side {
    Before,
    After,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct ContentKey {
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct ApplicationKey {
    pub exe_path_ref: ApplicationPathRef,
    pub sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct PathKey {
    pub path: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ContentRow {
    pub key: ContentKey,
    pub presence: Presence,
    pub changes: Vec<&'static str>,
    pub before: Vec<ModuleRef>,
    pub after: Vec<ModuleRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ApplicationChange {
    pub key: ApplicationKey,
    pub presence: Presence,
    pub changes: Vec<&'static str>,
    pub before: Vec<EdgeRef>,
    pub after: Vec<EdgeRef>,
    pub before_population: PopulationEvidence,
    pub after_population: PopulationEvidence,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ModulePathChange {
    pub key: PathKey,
    pub presence: Presence,
    pub changes: Vec<&'static str>,
    pub before: Vec<PathEvidence>,
    pub after: Vec<PathEvidence>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct PathEvidence {
    pub sha256: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct Device {
    pub major: u32,
    pub minor: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) struct PhysicalIdentity {
    pub device: Device,
    pub inode: u64,
    pub sha256: Option<String>,
    pub build_id: Option<String>,
    pub source: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ModuleEvidence {
    pub paths: Vec<String>,
    pub identity: PhysicalIdentity,
    pub admission: input::Admission,
    pub lifecycle: input::Label,
    pub unloaded_observed: bool,
    pub unbound_use: Option<input::UnboundUse>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct ImageEvidence {
    pub authority: input::Label,
    pub exe: Option<input::Exe>,
    pub exec_observed: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct CallerEvidence {
    pub pid: u32,
    pub start_time: Option<u64>,
    pub start_time_unit: String,
    pub image: ImageEvidence,
    pub lifecycle: input::Label,
    pub lifecycle_reason: Option<String>,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    pub retired: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct EdgeEvidence {
    pub caller: CallerRef,
    pub module: ModuleRef,
    pub mapping: input::Mapping,
    pub entries: input::Entries,
    pub coverage: Option<input::Coverage>,
    pub semantics: input::Label,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct GapEvidence {
    pub caller: Option<CallerRef>,
    pub module: Option<ModuleRef>,
    pub pid: Option<u32>,
    pub subject: String,
    pub reason: String,
    pub budget: Option<input::Refusal>,
    pub repeats: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum UnresolvedKind {
    Caller,
    Module,
    Edge,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct Unresolved {
    pub side: Side,
    pub kind: UnresolvedKind,
    pub reasons: Vec<&'static str>,
    pub caller: Option<CallerRef>,
    pub module: Option<ModuleRef>,
    pub observation: Option<EdgeRef>,
}

/// References identify canonical evidence values in the indicated side, never
/// persistent entities. Occurrence lists retain source-record multiplicity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub(super) struct CallerRef(pub usize);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub(super) struct ModuleRef(pub usize);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub(super) struct EdgeRef(pub usize);
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub(super) struct ApplicationPathRef(pub usize);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct SideEvidence {
    pub callers: Vec<CallerEvidence>,
    pub modules: Vec<ModuleEvidence>,
    pub edges: Vec<EdgeEvidence>,
    pub caller_occurrences: Vec<CallerRef>,
    pub module_occurrences: Vec<ModuleRef>,
    pub edge_occurrences: Vec<EdgeRef>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct PopulationEvidence {
    pub callers: Vec<CallerRef>,
    pub modules: Vec<ModuleRef>,
}
