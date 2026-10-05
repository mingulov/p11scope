//! SPDX-License-Identifier: GPL-3.0-or-later
//! `p11scope inspect --system`: the whole-machine discovered catalog.
//!
//! Every process enumerated from `/proc` is deep-scanned with the same
//! two-phase scan capture uses (sweep, provider-rarity selection under
//! `--max-scan-pids`), every scanned module is pinned into one aggregate
//! `PinnedObjects` (the same `absorb` semantics, so aliases merge and
//! same-path observations stay comparable), and the aggregate is lowered
//! through the existing plan-lowering path — scan evidence only, no
//! manifests — far enough to report per-object admission state. No BPF, no
//! attach, no slot reservation, no history latching: `inspect` lowers under
//! the Detailed policy and drops the plan with the catalog after rendering.
//! The inventory command lowers the same collection under its Inventory
//! policy instead and hands the plan and the aggregate pins to its attach
//! set (`CatalogLowering`), so the pins this pass opened and hashed are
//! retained, never reopened.
//!
//! The catalog (what was discovered) and the admission verdicts (what a
//! capture would do with it) are visibly separate records: `objects[]` is
//! the discovered set — physical identity, mappings, per-view observations
//! — and each object carries its own `admission` verdict plus the scan-only
//! note. Refused-but-known objects appear with their refusal reason;
//! scan-level losses appear as `skipped[]` (real gaps) or `notes[]`
//! (verified absence), never as phantom modules.

use crate::attach::Scope;
use crate::attach::monotonic_ns;
use crate::discovery::caller_registry::{ExeIdentity, read_exe_identity};
use crate::discovery::engine::{
    MAX_SCAN_PIDS, scope_pids, select_deep_scan_candidates, sweep_process_maps,
    unreadable_member_skip,
};
use crate::discovery::hooks::HookRegistry;
use crate::discovery::identity::{
    ExaminedObject, PinnedObjectId, PinnedObjects, ReconciledModule, bind_scanned_modules,
    canonicalize_scanned_overlays, pin_scanned_view_objects,
};
use crate::discovery::noise::DiscoveryNoiseAggregator;
use crate::discovery::proof_stats::{ProofStatPool, proof_stat_threads};
use crate::discovery::scan::{
    CaptureWorkBudget, ScanOutcome, ScanRequest, ScannedModule, Skipped,
    scan_process_view_examined, scan_skip_truncates,
};
use crate::discovery::sweep_attribution::{
    AttributionLoss, KnownKeyIndex, MatchedObject, MemberProbe, ObjectChecks, OsMemberProbe,
    RefusedObject, SweepAttribution, SweptMember, attribute_unselected, is_caller_range,
    retain_unchanged,
};
use crate::plan::{self, AdmissionPolicy, AdmissionScope};
use crate::process::{ProcessView, ProcessViewId, generation_gone};
use crate::timing::{StageKind, StageTimings};
use anyhow::Result;
use p11scope_manifest::maps::{MapEntry, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

const DOC_ID: &str = "p11scope/inspect-system/v1";

/// The controller ruling, carried on every admission verdict and on the
/// plan recap: the catalog reports admission computed WITHOUT manifest
/// input, so an object whose admission could differ with a manifest says
/// so plainly instead of reading as a capture promise.
pub(crate) const SCAN_ONLY_NOTE: &str =
    "scan-only admission: manifest corroboration was not consulted";

/// `p11scope inspect --system` — enumerate, sweep, deep-scan, pin, lower
/// admission scan-only, render. Exit 0 when the loop ran (even with zero
/// objects); a fully-unreadable machine is a hard error like pid-inspect.
pub fn run(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
) -> Result<i32> {
    run_with_writer(
        hints,
        hooks,
        json,
        max_scan_pids,
        &mut std::io::stdout().lock(),
    )
}

fn run_with_writer(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    json: bool,
    max_scan_pids: Option<usize>,
    out: &mut dyn std::io::Write,
) -> Result<i32> {
    let catalog = collect(hints, hooks, max_scan_pids, AdmissionPolicy::detailed())?;
    if stage_timings_requested() {
        eprintln!(
            "p11scope: stage timings: {}",
            catalog.stage_timings.ops_line()
        );
    }
    if json {
        let document = serde_json::to_string_pretty(&render_json(&catalog))?;
        writeln!(out, "{document}")?;
    } else {
        write!(out, "{}", render_text(&catalog))?;
    }
    Ok(0)
}

/// The scan stages' progress lines on stderr ("enumerating…",
/// "deep-scanning…"): on by default. The interactive inventory dashboard
/// turns them off while it owns the terminal (C5.3): its own pass lines
/// say the same, and one line per scanned process would flood its bounded
/// log tail.
static PROGRESS_LINES: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Turns the scan progress lines on or off; returns the previous setting.
pub(crate) fn set_progress_lines(on: bool) -> bool {
    PROGRESS_LINES.swap(on, std::sync::atomic::Ordering::SeqCst)
}

/// `eprintln!` for a scan progress line (see [`set_progress_lines`]).
macro_rules! progress {
    ($($arg:tt)*) => {
        if PROGRESS_LINES.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!($($arg)*);
        }
    };
}

/// `P11SCOPE_STAGE_TIMINGS=1` prints each pass's per-stage wall time to
/// stderr (the system-scale cost measurement); stdout never carries it.
pub(crate) fn stage_timings_requested() -> bool {
    std::env::var_os("P11SCOPE_STAGE_TIMINGS").is_some_and(|value| value == "1")
}

/// One gap record with optional member attribution. Scope-level gaps
/// (enumeration, sweep, cap) carry no pid; member gaps carry theirs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PidGap {
    pub pid: Option<u32>,
    pub subject: String,
    pub reason: String,
    /// True only for the deduped unreadable-member record: one public
    /// record however many members were unreadable (the engine's
    /// convention), with per-pid reasons in the process table instead.
    pub generic: bool,
}

impl PidGap {
    fn scope(skipped: Skipped) -> Self {
        Self {
            pid: None,
            subject: skipped.subject,
            reason: skipped.reason,
            generic: false,
        }
    }

    fn member(pid: u32, skipped: Skipped) -> Self {
        Self {
            pid: Some(pid),
            subject: skipped.subject,
            reason: skipped.reason,
            generic: false,
        }
    }

    fn generic_member(pid: u32, skipped: Skipped) -> Self {
        Self {
            pid: Some(pid),
            subject: skipped.subject,
            reason: skipped.reason,
            generic: true,
        }
    }
}

/// What one deep-scan attempt — or, past the cap, the maps attribution —
/// concluded about a scope member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MemberStatus {
    Scanned,
    MemoryUnavailable {
        reason: &'static str,
    },
    Unreadable {
        reason: String,
    },
    Exited,
    /// Past the deep-scan cap and attributed to pinned provider objects by
    /// exact maps identity (C1b): its mappings are confirmed, nothing in it
    /// was decoded, so its absences are never authoritative.
    MapsMatched,
    /// Past the deep-scan cap and not attributed; `loss` names why a
    /// process mapping a known provider object was not attributed to it.
    NotSelected {
        loss: Option<String>,
    },
}

impl MemberStatus {
    pub(crate) const fn label(&self) -> &'static str {
        match self {
            Self::Scanned => "scanned",
            Self::MemoryUnavailable { .. } => "memory_unavailable",
            Self::Unreadable { .. } => "unreadable",
            Self::Exited => "exited",
            Self::MapsMatched => "maps_matched",
            Self::NotSelected { .. } => "not_selected",
        }
    }

    pub(crate) fn reason(&self) -> Option<&str> {
        match self {
            Self::MemoryUnavailable { reason } => Some(reason),
            Self::Unreadable { reason } => Some(reason),
            Self::NotSelected { loss } => loss.as_deref(),
            Self::Scanned | Self::Exited | Self::MapsMatched => None,
        }
    }

    /// A scan ran far enough to inventory the member's mappings, with or
    /// without its memory: pid-inspect's `Scanned`/`Unavailable` line.
    pub(crate) const fn inventoried(&self) -> bool {
        matches!(self, Self::Scanned | Self::MemoryUnavailable { .. })
    }

    /// The member's mappings are evidence a caller can be registered on:
    /// a deep scan inventoried it, or C1b attributed it by maps identity.
    pub(crate) const fn attributable(&self) -> bool {
        self.inventoried() || matches!(self, Self::MapsMatched)
    }
}

/// One member's generation as collection saw it: the pin's start time and
/// the exe identity. The coordinator joins it against the caller
/// incarnation reconcile admits (both lanes), so a reused pid or a later
/// exec never inherits these mappings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MemberGeneration {
    pub start_time: Option<u64>,
    pub exe: Option<ExeIdentity>,
}

/// One scope member's deep-scan result: its status, what it mapped, and
/// the pins the scan earned. Empty unless a scan ran.
struct MemberResult {
    pid: u32,
    view: ProcessViewId,
    status: MemberStatus,
    generation: Option<MemberGeneration>,
    modules: Vec<ScannedModule>,
    /// Objects this member's own deep scan examined without finding a
    /// module (C1b "examined" keys; empty unless the scan completed).
    examined: Vec<ExaminedObject>,
    pins: PinnedObjects,
    gaps: Vec<PidGap>,
    scan_ms: u64,
}

/// The whole collection: every member's result plus the scope-level gaps.
/// The plan lowering and the catalog assembly read this, never `/proc`.
struct Collection {
    enumerated: Vec<u32>,
    selected: Vec<u32>,
    cap: usize,
    cap_hit: bool,
    members: Vec<MemberResult>,
    scope_gaps: Vec<PidGap>,
    proc_list_failed: bool,
    /// Phase-1 maps snapshots (over the cap only): the attribution input.
    sweep: Vec<(u32, Vec<MapEntry>)>,
    /// Swept pids whose snapshot was unavailable (never "maps nothing").
    sweep_unavailable: BTreeSet<u32>,
    /// The pass's work budget, carried from the sweep and the deep scans
    /// into the confirmation reads.
    budget: CaptureWorkBudget,
}

impl Collection {
    fn scanned(&self) -> usize {
        self.members
            .iter()
            .filter(|member| member.status.inventoried())
            .count()
    }

    fn unreadable(&self) -> usize {
        self.members
            .iter()
            .filter(|member| matches!(member.status, MemberStatus::Unreadable { .. }))
            .count()
    }

    fn first_unreadable_reason(&self) -> Option<&str> {
        self.members.iter().find_map(|member| match &member.status {
            MemberStatus::Unreadable { reason } => Some(reason.as_str()),
            _ => None,
        })
    }
}

/// Enumerate the machine, sweep over the cap, deep-scan every selected
/// member fail-open, pin every view. Progress goes to stderr; stdout stays
/// empty until the final render, so `--json` stays parseable.
fn collect_members(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    timings: &mut StageTimings,
) -> Collection {
    progress!("p11scope: enumerating processes...");
    let scope = Scope::System;
    let (pids, unlisted) = scope_pids(&scope);
    let proc_list_failed = unlisted
        .iter()
        .any(|skip| skip.reason.contains("no process was discovered"));
    let mut scope_gaps: Vec<PidGap> = unlisted.into_iter().map(PidGap::scope).collect();
    let cap = max_scan_pids.unwrap_or(MAX_SCAN_PIDS);
    let mut budget = CaptureWorkBudget::default();
    let mut noise = DiscoveryNoiseAggregator::default();

    // Phase 1+2, exactly like capture discovery: the sweep and the
    // rarity selection run only over the cap; under it selection is the
    // identity (ascending pids). Past the cap the sweep is kept: C1b
    // attributes the unselected pids from it after the deep scans, and
    // the capped-or-complete record is decided then, from its counts.
    let mut sweep = Vec::new();
    let mut sweep_unavailable = BTreeSet::new();
    let selected: Vec<u32> = if pids.len() > cap {
        progress!(
            "p11scope: sweeping {} process maps (cap {cap})...",
            pids.len()
        );
        let sweep_start = monotonic_ns();
        let (swept, unavailable, skip) =
            sweep_process_maps(&pids, &mut budget).into_selection_with_unavailable();
        timings.span(StageKind::Scan, "sweep", sweep_start, monotonic_ns());
        if let Some(skip) = skip {
            scope_gaps.push(PidGap::scope(skip));
        }
        let select_start = monotonic_ns();
        let selected = select_deep_scan_candidates(&swept, cap);
        timings.span(StageKind::Scan, "select", select_start, monotonic_ns());
        sweep = swept;
        sweep_unavailable = unavailable;
        selected
    } else {
        progress!(
            "p11scope: sweep skipped ({} processes fit the {cap} cap)",
            pids.len()
        );
        let mut pids = pids.clone();
        pids.sort_unstable();
        pids
    };
    let cap_hit = pids.len() > cap;

    let mut members = Vec::with_capacity(selected.len());
    let deep_start = monotonic_ns();
    for (index, pid) in selected.iter().enumerate() {
        progress!(
            "p11scope: deep-scanning {}/{} (pid {pid})...",
            index + 1,
            selected.len()
        );
        // Monotonic view ids in scan order, like capture discovery: one id
        // owns every result of its member.
        let Ok(view_index) = u32::try_from(index) else {
            break;
        };
        members.push(scan_member(
            *pid,
            ProcessViewId(view_index),
            hints,
            hooks,
            &mut budget,
            &mut noise,
        ));
    }
    timings.span(StageKind::Scan, "deep_scan", deep_start, monotonic_ns());
    noise.report();
    Collection {
        enumerated: pids,
        selected,
        cap,
        cap_hit,
        members,
        scope_gaps,
        proc_list_failed,
        sweep,
        sweep_unavailable,
        budget,
    }
}

/// Deep-scan one member and pin what it named, fail-open: an unreadable
/// member records its status and its gap, never fails the machine.
fn scan_member(
    pid: u32,
    view: ProcessViewId,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    budget: &mut CaptureWorkBudget,
    noise: &mut DiscoveryNoiseAggregator,
) -> MemberResult {
    let mut gaps = Vec::new();
    let opened = ProcessView::open(view, pid);
    let view_handle = match opened {
        Ok(view_handle) => view_handle,
        Err(error) => {
            return member_not_scanned(
                pid,
                view,
                &format!("the process generation could not be pinned: {error}"),
                noise,
                gaps,
            );
        }
    };
    // The generation this member's mappings belong to: the pin's start
    // time and the exe identity, read while the pin holds. The
    // coordinator joins both against the caller incarnation it admits.
    let generation = MemberGeneration {
        start_time: view_handle.start_time(),
        exe: read_exe_identity(pid),
    };
    // One generation from the first check to the last pin read, mirroring
    // pid-inspect: a member that changes mid-scan is re-read as whatever
    // it is now (usually gone), never half of each generation.
    if !view_handle.still_the_same() {
        return member_not_scanned(
            pid,
            view,
            "the process generation changed before inspect",
            noise,
            gaps,
        );
    }
    let (outcome, examined) = match scan_process_view_examined(
        &ScanRequest { pid, hints, hooks },
        &view_handle,
        budget,
    ) {
        Ok(scanned) => scanned,
        Err(error) => {
            return member_not_scanned(
                pid,
                view,
                &format!("the process could not be scanned: {error}"),
                noise,
                gaps,
            );
        }
    };
    if !view_handle.still_the_same() {
        return member_not_scanned(
            pid,
            view,
            "the process generation changed while inspect was scanning",
            noise,
            gaps,
        );
    }
    let (pins, pin_skips) = match pin_scanned_view_objects(&view_handle, outcome.modules(), budget)
    {
        Ok(pinned) => pinned,
        Err(error) => {
            return member_not_scanned(
                pid,
                view,
                &format!("the process objects could not be pinned: {error}"),
                noise,
                gaps,
            );
        }
    };
    if !view_handle.still_the_same() {
        return member_not_scanned(
            pid,
            view,
            "the process generation changed while inspect was pinning",
            noise,
            gaps,
        );
    }
    let scan_ms = match &outcome {
        ScanOutcome::Scanned { scan_ms, .. } => *scan_ms,
        ScanOutcome::Unavailable { .. } => 0,
    };
    for skip in outcome.skipped() {
        gaps.push(PidGap::member(pid, skip.clone()));
    }
    for skip in pin_skips {
        gaps.push(PidGap::member(pid, skip));
    }
    let (modules, status) = match outcome {
        ScanOutcome::Scanned { modules, .. } => (modules, MemberStatus::Scanned),
        ScanOutcome::Unavailable {
            reason, modules, ..
        } => (modules, MemberStatus::MemoryUnavailable { reason }),
    };
    MemberResult {
        pid,
        view,
        status,
        generation: Some(generation),
        modules,
        examined,
        pins,
        gaps,
        scan_ms,
    }
}

/// A member no scan inventoried: provably-gone is the silent `exited`
/// status, anything else is `unreadable` with the shared deduped gap
/// record plus the per-pid detail in the process table.
fn member_not_scanned(
    pid: u32,
    view: ProcessViewId,
    detail: &str,
    noise: &mut DiscoveryNoiseAggregator,
    mut gaps: Vec<PidGap>,
) -> MemberResult {
    let status = match unreadable_member_skip(pid, generation_gone(pid), detail, noise) {
        Some(skip) => {
            gaps.push(PidGap::generic_member(pid, skip));
            MemberStatus::Unreadable {
                reason: detail.to_string(),
            }
        }
        None => MemberStatus::Exited,
    };
    MemberResult {
        pid,
        view,
        status,
        generation: None,
        modules: Vec::new(),
        examined: Vec::new(),
        pins: PinnedObjects::empty(),
        gaps,
        scan_ms: 0,
    }
}

/// The fully-unreadable rule (A3), pure over the collection counts so the
/// branches are unit-testable: a machine is unreadable when processes were
/// enumerated but not one could be inventoried and at least one loss is
/// not a proven exit. All-exited is an empty machine, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemOutcome {
    Render,
    HardError,
}

#[derive(Debug, Clone, Copy)]
struct OutcomeStats {
    enumerated: usize,
    scanned: usize,
    unreadable: usize,
    proc_list_failed: bool,
}

fn decide_system_outcome(stats: OutcomeStats) -> SystemOutcome {
    if stats.scanned > 0 {
        return SystemOutcome::Render;
    }
    if stats.enumerated == 0 {
        return if stats.proc_list_failed {
            SystemOutcome::HardError
        } else {
            SystemOutcome::Render
        };
    }
    if stats.unreadable > 0 {
        SystemOutcome::HardError
    } else {
        SystemOutcome::Render
    }
}

fn unreadable_system_error(collection: &Collection) -> anyhow::Error {
    let unreadable = collection.unreadable();
    let first = collection
        .first_unreadable_reason()
        .unwrap_or("unknown reason");
    let denied = first.contains("Permission denied")
        || first.contains("not permitted")
        || collection
            .scope_gaps
            .iter()
            .any(|gap| gap.reason.contains("Permission denied"));
    let fix = if denied {
        "; their modules are unknown, not absent. Processes owned by other users need \
         root: run `sudo p11scope inspect --system`"
    } else {
        "; their modules are unknown, not absent"
    };
    anyhow::anyhow!(
        "cannot inspect system: no process could be read ({unreadable} unreadable): {first}{fix}"
    )
}

/// Per-object admission: the plan's verdict for a pinned object, or the
/// bind loss for a scanned module that earned no comparable identity.
/// Every pinned verdict carries the scan-only note (no manifest input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionRecord {
    Admitted {
        class: &'static str,
        endpoints: usize,
    },
    Refused {
        class: &'static str,
        reason: String,
    },
    Unresolved {
        reasons: Vec<String>,
    },
}

impl AdmissionRecord {
    pub(crate) const fn state(&self) -> &'static str {
        match self {
            Self::Admitted { .. } => "admitted",
            Self::Refused { .. } => "refused",
            Self::Unresolved { .. } => "unresolved",
        }
    }

    pub(crate) fn class(&self) -> Option<&'static str> {
        match self {
            Self::Admitted { class, .. } | Self::Refused { class, .. } => Some(class),
            Self::Unresolved { .. } => None,
        }
    }

    pub(crate) fn reasons(&self) -> Vec<String> {
        match self {
            Self::Admitted { .. } => Vec::new(),
            Self::Refused { reason, .. } => vec![reason.clone()],
            Self::Unresolved { reasons } => reasons.clone(),
        }
    }
}

/// How one observation's mapping was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObservationEvidence {
    /// A deep scan decoded the member: exports, tables, interfaces.
    DeepScan,
    /// C1b: the member's confirmed maps show the pinned object by exact
    /// `(device, inode)`; nothing in the member was decoded.
    MapsMatch,
}

impl ObservationEvidence {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::DeepScan => "deep_scan",
            Self::MapsMatch => "maps_match",
        }
    }
}

/// One member's decode of one object: the scan facts from that view, kept
/// per view because generations remap (addresses) and even file versions
/// (tables) can differ between two mappings of one object.
#[derive(Debug, Clone)]
pub(crate) struct Observation {
    pub pid: u32,
    pub path: String,
    pub exports: Vec<String>,
    pub tables: Vec<crate::discovery::scan::ScannedTable>,
    pub interfaces: Vec<crate::discovery::scan::ScannedInterface>,
    /// Scan evidence (F7b): this member's mappings of the object show
    /// duplicate executable file-offset coverage (a same-file
    /// double-load in this process).
    pub double_loaded: bool,
    /// How the mapping was established. A `MapsMatch` observation decodes
    /// nothing: its exports, tables, and interfaces stay empty.
    pub evidence: ObservationEvidence,
}

/// One catalog object: every pinned physical object the machine maps —
/// admitted or refused — plus every scanned module that earned no pin.
/// The identity block mirrors `ObjectSummary`'s fields; the admission
/// verdict beside it is the separate record the brief requires.
pub(crate) struct CatalogObject {
    pub path: String,
    pub key: p11scope_manifest::maps::ObjectKey,
    pub sha256: Option<String>,
    pub build_id: Option<String>,
    pub identity_source: Option<&'static str>,
    pub note: Option<String>,
    /// `(pid, view)`: the deep-scan view that mapped it, or `None` for a
    /// member attributed by maps identity (no view was opened).
    pub mappings: Vec<(u32, Option<ProcessViewId>)>,
    pub observations: Vec<Observation>,
    pub admission: AdmissionRecord,
}

pub(crate) struct ProcessRecord {
    pub pid: u32,
    pub status: MemberStatus,
    pub objects: Vec<usize>,
    /// The generation the member's mappings belong to (deep scans and
    /// maps matches); `None` when no read reached it.
    pub generation: Option<MemberGeneration>,
}

/// A discovered relationship between catalog objects: two observations of
/// one path that are not one object, or one object observed under two
/// paths. Indices into `Catalog::objects`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Relationship {
    SamePath {
        path: String,
        members: Vec<RelationshipMember>,
    },
    Alias {
        object: usize,
        sha256: Option<String>,
        paths: Vec<String>,
        pids: Vec<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationshipMember {
    object: usize,
    sha256: Option<String>,
    pids: Vec<u32>,
}

pub(crate) struct AdmissionSummary {
    pub uncorroborated_candidates: u64,
    pub module_ambiguous: usize,
    pub admitted: usize,
    pub refused: usize,
    pub unresolved: usize,
}

/// The assembled catalog: everything both renderers read. Built once from
/// the collection; rendering is pure over it.
pub(crate) struct Catalog {
    pub scan_status: &'static str,
    /// What the admission verdicts were lowered from: inventory's attach
    /// set takes it right after collection (so the aggregate pins and
    /// their fds do not outlive that step); rendering never reads it.
    pub lowering: Option<CatalogLowering>,
    pub enumerated: usize,
    pub selected: usize,
    /// Members a deep scan inventoried.
    pub scanned: usize,
    /// Members past the cap attributed by exact maps identity (C1b).
    pub maps_matched: usize,
    /// Members past the cap mapping a shared object no deep scan examined.
    pub unexamined: usize,
    /// Distinct shared objects (maps keys) no deep scan examined.
    pub unexamined_objects: usize,
    /// Members past the cap whose phase-1 maps snapshot was unavailable.
    pub snapshots_unavailable: usize,
    /// Attribution losses by category (each member once per category).
    pub attribution_losses: BTreeMap<AttributionLoss, usize>,
    pub cap: usize,
    pub scan_ms: u64,
    pub processes: Vec<ProcessRecord>,
    pub objects: Vec<CatalogObject>,
    pub relationships: Vec<Relationship>,
    pub admission: AdmissionSummary,
    pub skipped: Vec<PidGap>,
    pub notes: Vec<PidGap>,
    pub explanation: Option<String>,
    /// Per-stage wall time of this collection (sweep, select, deep scan,
    /// confirm, assemble): the system-scale cost measurement. Never
    /// rendered in the catalog document; `P11SCOPE_STAGE_TIMINGS=1` prints
    /// it to stderr.
    pub stage_timings: StageTimings,
}

/// The one scan-only lowering behind a catalog's admission verdicts: the
/// aggregate pins every reconciled module was bound against and the plan
/// built over them under the caller's policy. Plan object IDs index these
/// pins and nothing else.
pub(crate) struct CatalogLowering {
    pub plan: plan::AttachPlan,
    pub pins: PinnedObjects,
}

/// Collect the machine, lower scan-only admission under `policy`, assemble
/// the catalog. `inspect --system` lowers Detailed; the inventory command
/// lowers Inventory. The only `Err` is the fully-unreadable machine
/// (stdout stays empty).
pub(crate) fn collect(
    hints: &[PathBuf],
    hooks: &HookRegistry,
    max_scan_pids: Option<usize>,
    policy: AdmissionPolicy,
) -> Result<Catalog> {
    let mut timings = StageTimings::new();
    let mut collection = collect_members(hints, hooks, max_scan_pids, &mut timings);
    let stats = OutcomeStats {
        enumerated: collection.enumerated.len(),
        scanned: collection.scanned(),
        unreadable: collection.unreadable(),
        proc_list_failed: collection.proc_list_failed,
    };
    if decide_system_outcome(stats) == SystemOutcome::HardError {
        return Err(unreadable_system_error(&collection));
    }
    progress!("p11scope: lowering scan-only admission and rendering...");
    let bind_start = monotonic_ns();
    let bound = bind_collection(&mut collection);
    timings.span(StageKind::Bind, "assemble", bind_start, monotonic_ns());
    // The confirmation reads run here: after the deep scans, while the
    // aggregate pins (and their fds) are held, before the pure assembly.
    let confirm_start = monotonic_ns();
    // The proof stats run on a bounded pool that lives for this
    // confirmation stage only (DR-C1b-3).
    let attributed = ProofStatPool::scoped(proof_stat_threads(), |pool| {
        attribute_sweep(
            &mut collection,
            &bound,
            &mut OsMemberProbe { pool },
            &bound.aggregate,
        )
    });
    timings.span(StageKind::Scan, "confirm", confirm_start, monotonic_ns());
    let assemble_start = monotonic_ns();
    let mut catalog = assemble(collection, bound, attributed, policy);
    timings.span(StageKind::Plan, "assemble", assemble_start, monotonic_ns());
    catalog.stage_timings = timings;
    Ok(catalog)
}

/// Collect one pid through the same member scan and the same assembly:
/// the inventory scan lane's `--pid` pass. The only `Err` is a target no
/// scan inventoried — pid-inspect's hard failure, kept honest.
pub(crate) fn collect_pid(
    pid: u32,
    hints: &[PathBuf],
    hooks: &HookRegistry,
    policy: AdmissionPolicy,
) -> Result<Catalog> {
    progress!("p11scope: deep-scanning pid {pid}...");
    let mut budget = CaptureWorkBudget::default();
    let mut noise = DiscoveryNoiseAggregator::default();
    let member = scan_member(pid, ProcessViewId(0), hints, hooks, &mut budget, &mut noise);
    noise.report();
    if !member.status.inventoried() {
        let detail = member
            .status
            .reason()
            .unwrap_or("the process could not be read");
        let fix = if detail.contains("Permission denied") || detail.contains("not permitted") {
            "; its modules are unknown, not absent. Processes owned by other users need \
             root: run `sudo p11scope inventory --pid {pid}`"
        } else {
            "; its modules are unknown, not absent"
        };
        return Err(anyhow::anyhow!("cannot inventory pid {pid}: {detail}{fix}"));
    }
    progress!("p11scope: lowering scan-only admission and rendering...");
    let mut collection = Collection {
        enumerated: vec![pid],
        selected: vec![pid],
        cap: 1,
        cap_hit: false,
        members: vec![member],
        scope_gaps: Vec::new(),
        proc_list_failed: false,
        sweep: Vec::new(),
        sweep_unavailable: BTreeSet::new(),
        budget,
    };
    let bound = bind_collection(&mut collection);
    Ok(assemble(collection, bound, None, policy))
}

/// The aggregate pin set and every module bound against it: the pure half
/// of assembly, run before the confirmation reads so they see exactly the
/// objects (and hold exactly the fds) the catalog will report.
struct Bound {
    aggregate: PinnedObjects,
    reconciled: Vec<(u32, ProcessViewId, ReconciledModule)>,
    unresolved: Vec<(u32, ProcessViewId, ScannedModule, Vec<String>)>,
    bind_gaps: Vec<PidGap>,
}

/// Aggregate every view's pins and bind every module.
fn bind_collection(collection: &mut Collection) -> Bound {
    // One aggregate pin set first: exact comparable identities merge and
    // equal raw keys with unequal full identity reject the group — the
    // same absorb semantics capture relies on.
    let mut aggregate = PinnedObjects::empty();
    for member in &mut collection.members {
        let pins = std::mem::replace(&mut member.pins, PinnedObjects::empty());
        for skip in aggregate.absorb(pins) {
            member.gaps.push(PidGap::member(member.pid, skip));
        }
    }
    let (_collapsed, overlay_lost) = canonicalize_scanned_overlays(&mut aggregate);
    let mut bind_gaps: Vec<PidGap> = overlay_lost.into_iter().map(PidGap::scope).collect();

    // Bind each module on its own so every loss attributes to the pid
    // whose scan produced it. Binding is per-module independent (the
    // overlay collapse above is the only global step), so this equals one
    // batch bind with exact attribution.
    let mut reconciled: Vec<(u32, ProcessViewId, ReconciledModule)> = Vec::new();
    let mut unresolved: Vec<(u32, ProcessViewId, ScannedModule, Vec<String>)> = Vec::new();
    for member in &collection.members {
        for module in &member.modules {
            let (mut bound, lost) =
                bind_scanned_modules(std::slice::from_ref(module), &mut aggregate);
            for skip in &lost {
                bind_gaps.push(PidGap::member(member.pid, skip.clone()));
            }
            match bound.pop() {
                Some(module) => reconciled.push((member.pid, member.view, module)),
                None => unresolved.push((
                    member.pid,
                    member.view,
                    module.clone(),
                    lost.into_iter().map(|skip| skip.reason).collect(),
                )),
            }
        }
    }
    Bound {
        aggregate,
        reconciled,
        unresolved,
        bind_gaps,
    }
}

/// What C1b concluded for the unselected members, plus the objects whose
/// sweep matching was refused or dropped (their gaps).
struct Attributed {
    attribution: SweepAttribution,
    refused: Vec<RefusedObject>,
    changed: Vec<(PinnedObjectId, String)>,
}

/// C1b over the cap: index this pass's deep-scanned keys, confirm every
/// unselected phase-1 match through `probe` while `bound`'s pins are held,
/// then recheck each matched object once. `None` under the cap (no sweep).
fn attribute_sweep(
    collection: &mut Collection,
    bound: &Bound,
    probe: &mut dyn MemberProbe,
    checks: &dyn ObjectChecks,
) -> Option<Attributed> {
    if !collection.cap_hit {
        return None;
    }
    let modules = bound
        .reconciled
        .iter()
        .map(|(_, _, module)| (module.scanned.key, Some(module.object)))
        .chain(
            bound
                .unresolved
                .iter()
                .map(|(_, _, module, _)| (module.key, None)),
        );
    let match_keys = bound.aggregate.sweep_match_keys();
    // A deep scan examined its snapshot's keys only when it completed:
    // scanned with memory and no truncating loss of its own.
    let complete: BTreeSet<u32> = collection
        .members
        .iter()
        .filter(|member| {
            matches!(member.status, MemberStatus::Scanned)
                && !member
                    .gaps
                    .iter()
                    .any(|gap| scan_skip_truncates(&gap.reason))
        })
        .map(|member| member.pid)
        .collect();
    // Examined objects come from each complete deep scan's own maps read
    // (never the earlier sweep snapshot, which a later unload would make
    // stale), each with the proof another process needs for its key.
    let examined = collection
        .members
        .iter()
        .filter(|member| complete.contains(&member.pid))
        .flat_map(|member| member.examined.iter().copied());
    let (index, mut refused) = KnownKeyIndex::build(modules, &match_keys, examined, checks);
    let selected: BTreeSet<u32> = collection.selected.iter().copied().collect();
    // A refused object is a loss only where an unselected process maps it
    // as a caller would: executably (A6, the same rule as attribution).
    let unselected_keys: BTreeSet<ObjectKey> = collection
        .sweep
        .iter()
        .filter(|(pid, _)| !selected.contains(pid))
        .flat_map(|(_, entries)| entries.iter().filter(|entry| is_caller_range(entry)))
        .map(ObjectKey::of)
        .collect();
    refused.retain(|object| unselected_keys.contains(&object.key));
    progress!(
        "p11scope: attributing {} unselected processes by maps identity...",
        collection.sweep.len().saturating_sub(selected.len())
    );
    let mut attribution = attribute_unselected(
        &collection.sweep,
        &collection.sweep_unavailable,
        &selected,
        &index,
        probe,
        &mut collection.budget,
    );
    let changed = retain_unchanged(&mut attribution, checks);
    Some(Attributed {
        attribution,
        refused,
        changed,
    })
}

/// The capped-or-complete record's shared prefix: what was deep-scanned
/// and what was attributed by maps identity.
fn coverage_prefix(total: usize, deep: usize, cap: usize, matched: usize) -> String {
    format!(
        "{total} processes in scope; {deep} deep-scanned by provider rarity (limit {cap}); \
         {matched} attributed to pinned provider objects by exact maps identity"
    )
}

/// Lower one shared-scope plan over scan evidence only under `policy`,
/// and project the catalog records — deep-scanned and maps-matched
/// members alike. Pure: no `/proc` reads.
fn assemble(
    mut collection: Collection,
    bound: Bound,
    attributed: Option<Attributed>,
    policy: AdmissionPolicy,
) -> Catalog {
    let Bound {
        aggregate,
        reconciled,
        unresolved,
        bind_gaps,
    } = bound;
    let mut bind_gaps = bind_gaps;

    // The existing plan-lowering path, scan evidence only: no manifests,
    // no history, no reserved slots, no attach. The lowering is pure over
    // its inputs, so no narrower entry point was needed — there are no
    // side effects to carve out. Detailed (inspect) and Inventory
    // (inventory) differ only in the policy passed here.
    let inputs: Vec<ReconciledModule> = reconciled
        .iter()
        .map(|(_, _, module)| module.clone())
        .collect();
    let owners: Vec<(u32, ProcessViewId)> = reconciled
        .iter()
        .map(|(pid, view, _)| (*pid, *view))
        .collect();
    let plan = plan::build_from_sources_for_policy_scoped(
        &inputs,
        &[],
        &aggregate,
        policy,
        AdmissionScope::Shared,
    );
    let refused: BTreeMap<PinnedObjectId, &Skipped> = plan.refused_modules().collect();
    let admitted: BTreeMap<PinnedObjectId, usize> = plan
        .modules
        .iter()
        .map(|module| {
            let endpoints = plan
                .slots
                .iter()
                .filter(|slot| plan.is_active(slot.index) && slot.module_ids.contains(&module.id))
                .count();
            (module.object, endpoints)
        })
        .collect();

    // Maps-matched members by the pinned object they were attributed to.
    let mut matched: BTreeMap<PinnedObjectId, Vec<(u32, &MatchedObject)>> = BTreeMap::new();
    if let Some(attributed) = &attributed {
        for member in &attributed.attribution.members {
            for object in &member.objects {
                matched
                    .entry(object.object)
                    .or_default()
                    .push((member.pid, object));
            }
        }
    }

    // Group observations by pinned object in first-seen order.
    let mut order: Vec<PinnedObjectId> = Vec::new();
    let mut groups: BTreeMap<PinnedObjectId, Vec<usize>> = BTreeMap::new();
    for (index, module) in inputs.iter().enumerate() {
        groups
            .entry(module.object)
            .or_insert_with(|| {
                order.push(module.object);
                Vec::new()
            })
            .push(index);
    }

    let mut objects: Vec<CatalogObject> = Vec::new();
    for object in order {
        let Some(members) = groups.get(&object) else {
            continue;
        };
        let group: Vec<ReconciledModule> =
            members.iter().map(|&index| inputs[index].clone()).collect();
        let (class, _lookalikes) = plan::classify_scanned_object(&group);
        let Some(pin) = aggregate.summary(object) else {
            // Unreachable: every reconciled object resolves in the
            // aggregate it was bound against. Degrade to unresolved
            // records rather than panic if that ever stops holding.
            for &index in members {
                let (pid, view) = owners[index];
                objects.push(CatalogObject {
                    path: inputs[index].scanned.path.clone(),
                    key: inputs[index].scanned.key,
                    sha256: None,
                    build_id: None,
                    identity_source: None,
                    note: None,
                    mappings: vec![(pid, Some(view))],
                    observations: vec![observation_of(pid, &inputs[index].scanned)],
                    admission: AdmissionRecord::Unresolved {
                        reasons: vec![
                            "pinned identity retired during aggregation; it was not attached"
                                .to_string(),
                        ],
                    },
                });
            }
            continue;
        };
        let admission = match (refused.get(&object), admitted.get(&object)) {
            (Some(skip), _) => AdmissionRecord::Refused {
                class,
                reason: skip.reason.clone(),
            },
            (None, Some(endpoints)) => AdmissionRecord::Admitted {
                class,
                endpoints: *endpoints,
            },
            // Unreachable: the merge decides every group. Degrade rather
            // than panic, as above.
            (None, None) => AdmissionRecord::Unresolved {
                reasons: vec!["object reached no admission verdict".to_string()],
            },
        };
        let mut mappings: Vec<(u32, Option<ProcessViewId>)> = members
            .iter()
            .map(|&index| (owners[index].0, Some(owners[index].1)))
            .collect();
        let mut observations: Vec<Observation> = members
            .iter()
            .map(|&index| observation_of(owners[index].0, &inputs[index].scanned))
            .collect();
        for (pid, object) in matched.get(&object).into_iter().flatten() {
            mappings.push((*pid, None));
            observations.push(matched_observation(*pid, object));
        }
        mappings.sort();
        mappings.dedup();
        objects.push(CatalogObject {
            path: pin.path.to_string(),
            key: pin.key,
            sha256: Some(pin.sha256.to_string()),
            build_id: pin.build_id.map(str::to_string),
            identity_source: Some(pin.identity_source),
            note: pin.note.map(str::to_string),
            mappings,
            observations,
            admission,
        });
    }
    // Unpinned modules stay separate records even when they share a path:
    // without a comparable identity there is no proof they are one
    // object, and merging them would be the guess the pin refused.
    for (pid, view, scanned, reasons) in unresolved {
        objects.push(CatalogObject {
            path: scanned.path.clone(),
            key: scanned.key,
            sha256: None,
            build_id: None,
            identity_source: None,
            note: None,
            mappings: vec![(pid, Some(view))],
            observations: vec![observation_of(pid, &scanned)],
            admission: AdmissionRecord::Unresolved { reasons },
        });
    }
    objects.sort_by(|left, right| {
        (
            &left.path,
            left.key.device.major,
            left.key.device.minor,
            left.key.inode,
            left.sha256.as_deref().unwrap_or(""),
        )
            .cmp(&(
                &right.path,
                right.key.device.major,
                right.key.device.minor,
                right.key.inode,
                right.sha256.as_deref().unwrap_or(""),
            ))
    });

    // Member → object index backlinks for the process table.
    let mut by_pid: BTreeMap<u32, BTreeSet<usize>> = BTreeMap::new();
    for (index, object) in objects.iter().enumerate() {
        for (pid, _) in &object.mappings {
            by_pid.entry(*pid).or_default().insert(index);
        }
    }
    let members_by_pid: BTreeMap<u32, &MemberResult> = collection
        .members
        .iter()
        .map(|member| (member.pid, member))
        .collect();
    let swept_by_pid: BTreeMap<u32, &SweptMember> = attributed
        .iter()
        .flat_map(|attributed| &attributed.attribution.members)
        .map(|member| (member.pid, member))
        .collect();
    let objects_of = |pid: &u32| {
        by_pid
            .get(pid)
            .map_or(Vec::new(), |set| set.iter().copied().collect())
    };
    let mut processes: Vec<ProcessRecord> = Vec::new();
    for pid in &collection.enumerated {
        let (status, objects, generation) = if let Some(member) = members_by_pid.get(pid) {
            (
                member.status.clone(),
                objects_of(pid),
                member.generation.clone(),
            )
        } else if let Some(swept) = swept_by_pid.get(pid) {
            (
                MemberStatus::MapsMatched,
                objects_of(pid),
                Some(MemberGeneration {
                    start_time: Some(swept.start_time),
                    exe: Some(swept.exe.clone()),
                }),
            )
        } else if attributed
            .as_ref()
            .is_some_and(|attributed| attributed.attribution.exited.contains(pid))
        {
            (MemberStatus::Exited, Vec::new(), None)
        } else {
            let loss = attributed.as_ref().and_then(|attributed| {
                attributed
                    .attribution
                    .member_losses
                    .get(pid)
                    .map(|(loss, detail)| format!("{}: {detail}", loss.label()))
            });
            (MemberStatus::NotSelected { loss }, Vec::new(), None)
        };
        processes.push(ProcessRecord {
            pid: *pid,
            status,
            objects,
            generation,
        });
    }
    processes.sort_by_key(|process| process.pid);

    // Gaps: dedup exact repeats, collapse the generic unreadable-member
    // record to one pid-less entry (the engine's convention; per-pid
    // reasons live in the process table), then split verified absence
    // (notes) from real losses (skipped) on the scan's own vocabulary.
    let mut gaps: Vec<PidGap> = std::mem::take(&mut collection.scope_gaps);
    for member in &collection.members {
        gaps.extend(member.gaps.iter().cloned());
    }
    gaps.append(&mut bind_gaps);
    let deep = collection.scanned();
    let matched_count = swept_by_pid.len();
    let (unexamined, unexamined_objects, unavailable, losses) = match &attributed {
        Some(attributed) => {
            let attribution = &attributed.attribution;
            (
                attribution.unexamined.len(),
                attribution.unexamined_keys(),
                attribution.unavailable,
                attribution.losses.clone(),
            )
        }
        None => (0, 0, 0, BTreeMap::new()),
    };
    let lost: usize = losses.values().sum();
    if let Some(attributed) = &attributed {
        for object in &attributed.refused {
            gaps.push(PidGap::scope(Skipped {
                subject: aggregate.summary(object.object).map_or_else(
                    || "maps attribution".to_string(),
                    |pin| pin.path.to_string(),
                ),
                reason: format!(
                    "on a {} filesystem, whose inode numbers are not unique: processes past the \
                     deep-scan cap are never matched to it by device and inode, so only deep \
                     scans attribute it",
                    object.filesystem
                ),
            }));
        }
        for (object, reason) in &attributed.changed {
            gaps.push(PidGap::scope(Skipped {
                subject: aggregate.summary(*object).map_or_else(
                    || "maps attribution".to_string(),
                    |pin| pin.path.to_string(),
                ),
                reason: format!("{reason}; its maps attributions were dropped"),
            }));
        }
        for member in &attributed.attribution.members {
            if member.unexamined > 0 {
                gaps.push(PidGap::member(
                    member.pid,
                    Skipped {
                        subject: "maps attribution".into(),
                        reason: format!(
                            "maps {} shared object{} no deep scan examined this pass; {} may be \
                             an undiscovered provider",
                            member.unexamined,
                            if member.unexamined == 1 { "" } else { "s" },
                            if member.unexamined == 1 { "it" } else { "each" },
                        ),
                    },
                ));
            }
        }
        if lost > 0 {
            let parts: Vec<String> = losses
                .iter()
                .map(|(loss, count)| format!("{count} {}", loss.label()))
                .collect();
            gaps.push(PidGap::scope(Skipped {
                subject: "maps attribution".into(),
                reason: format!(
                    "processes mapping pinned provider objects were not attributed to them: {} \
                     (per-process reasons in the process table)",
                    parts.join(", ")
                ),
            }));
        }
    }
    // Discovery capped is a loss only when something was left unexamined:
    // a process mapping a shared object no deep scan examined, or a
    // process with no maps snapshot. Otherwise the cap bounded only how
    // many processes were deep-scanned, and attribution is complete.
    let capped = collection.cap_hit && (unexamined > 0 || unavailable > 0);
    let total = collection.enumerated.len();
    if capped {
        let mut reason = format!(
            "{}; {unexamined} processes map {unexamined_objects} shared objects no deep scan \
             examined and may use undiscovered providers",
            coverage_prefix(total, deep, collection.cap, matched_count)
        );
        if unavailable > 0 {
            let _ = write!(
                reason,
                "; {unavailable} processes past the cap had no maps snapshot"
            );
        }
        gaps.push(PidGap::scope(Skipped {
            subject: "discovery capped".into(),
            reason,
        }));
    }
    let (skipped, mut notes) = split_gaps(gaps);
    let attribution_complete = collection.cap_hit && !capped && lost == 0;
    if attribution_complete {
        notes.push(PidGap {
            pid: None,
            subject: "discovery capped".into(),
            reason: format!(
                "attribution complete: {}; every other process maps only shared objects a deep \
                 scan examined",
                coverage_prefix(total, deep, collection.cap, matched_count)
            ),
            generic: false,
        });
    }

    let relationships = build_relationships(&objects);
    let admission = AdmissionSummary {
        uncorroborated_candidates: plan.uncorroborated_candidates,
        module_ambiguous: plan.module_ambiguous,
        admitted: objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Admitted { .. }))
            .count(),
        refused: objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Refused { .. }))
            .count(),
        unresolved: objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Unresolved { .. }))
            .count(),
    };
    let scan_ms = collection.members.iter().map(|member| member.scan_ms).sum();
    // Complete: nothing lost and nothing unexamined. Over the cap that
    // needs every unselected process examined (by a deep scan's keys or a
    // confirmed maps match) and no attribution loss.
    let complete = (!collection.cap_hit || attribution_complete)
        && skipped.is_empty()
        && collection
            .members
            .iter()
            .all(|member| matches!(member.status, MemberStatus::Scanned));
    let explanation = if objects.is_empty() {
        Some(empty_explanation(&collection, matched_count, &skipped))
    } else {
        None
    };
    Catalog {
        lowering: Some(CatalogLowering {
            plan,
            pins: aggregate,
        }),
        scan_status: if complete { "complete" } else { "partial" },
        enumerated: collection.enumerated.len(),
        selected: collection.selected.len(),
        scanned: deep,
        maps_matched: matched_count,
        unexamined,
        unexamined_objects,
        snapshots_unavailable: unavailable,
        attribution_losses: losses,
        cap: collection.cap,
        scan_ms,
        processes,
        objects,
        relationships,
        admission,
        skipped,
        notes,
        explanation,
        stage_timings: StageTimings::new(),
    }
}

fn observation_of(pid: u32, scanned: &ScannedModule) -> Observation {
    Observation {
        pid,
        path: scanned.path.clone(),
        exports: scanned.exports.clone(),
        tables: scanned.tables.clone(),
        interfaces: scanned.interfaces.clone(),
        double_loaded: scanned.double_loaded,
        evidence: ObservationEvidence::DeepScan,
    }
}

/// A maps-matched member's observation: the confirmed mapping only.
fn matched_observation(pid: u32, matched: &MatchedObject) -> Observation {
    Observation {
        pid,
        path: matched.path.clone(),
        exports: Vec::new(),
        tables: Vec::new(),
        interfaces: Vec::new(),
        double_loaded: matched.double_loaded,
        evidence: ObservationEvidence::MapsMatch,
    }
}

/// Split gaps into real losses (`skipped`) and verified absence (`notes`)
/// on the scan's own truncating vocabulary, after deduping exact repeats
/// and collapsing the generic unreadable-member record to one pid-less
/// entry. Pure, so the split is unit-testable.
fn split_gaps(gaps: Vec<PidGap>) -> (Vec<PidGap>, Vec<PidGap>) {
    let mut seen = BTreeSet::new();
    let mut generic_seen = false;
    let mut skipped = Vec::new();
    let mut notes = Vec::new();
    for mut gap in gaps {
        if gap.generic {
            if generic_seen {
                continue;
            }
            generic_seen = true;
            gap.pid = None;
        }
        if !seen.insert((gap.pid, gap.subject.clone(), gap.reason.clone())) {
            continue;
        }
        if scan_skip_truncates(&gap.reason) {
            skipped.push(gap);
        } else {
            notes.push(gap);
        }
    }
    let by_gap = |left: &PidGap, right: &PidGap| {
        (left.pid.is_none(), left.pid, &left.subject, &left.reason).cmp(&(
            right.pid.is_none(),
            right.pid,
            &right.subject,
            &right.reason,
        ))
    };
    skipped.sort_by(by_gap);
    notes.sort_by(by_gap);
    (skipped, notes)
}

/// Group catalog objects into discovered relationships: one path observed
/// as two objects that are not one, and one object observed under two
/// paths. Pure over the object list, so the grouping is unit-testable.
fn build_relationships(objects: &[CatalogObject]) -> Vec<Relationship> {
    let mut relationships = Vec::new();
    // Same path, distinct objects: group by observation path (an object
    // observed under two spellings shares each of them), keep groups with
    // more than one distinct identity, where identity is the full physical
    // key plus the digest. An unpinned record carries its index as well:
    // no digest was proven, so each is distinct from everything,
    // including a second unpinned observation — unproven, never merged.
    let mut by_path: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, object) in objects.iter().enumerate() {
        let mut paths: Vec<&str> = object
            .observations
            .iter()
            .map(|observation| observation.path.as_str())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        for path in paths {
            by_path.entry(path).or_default().push(index);
        }
    }
    for (path, members) in &by_path {
        if members.len() < 2 {
            continue;
        }
        let mut identities = BTreeSet::new();
        for &index in members {
            let object = &objects[index];
            identities.insert((
                object.key.device.major,
                object.key.device.minor,
                object.key.inode,
                object.sha256.clone(),
                object.sha256.is_none().then_some(index),
            ));
        }
        if identities.len() < 2 {
            continue;
        }
        relationships.push(Relationship::SamePath {
            path: path.to_string(),
            members: members
                .iter()
                .map(|&index| {
                    let mut pids: Vec<u32> = objects[index]
                        .mappings
                        .iter()
                        .map(|(pid, _)| *pid)
                        .collect();
                    pids.sort_unstable();
                    pids.dedup();
                    RelationshipMember {
                        object: index,
                        sha256: objects[index].sha256.clone(),
                        pids,
                    }
                })
                .collect(),
        });
    }
    // Aliases across views: one pinned object observed under distinct
    // path spellings (the absorb merged them on proven identity).
    for (index, object) in objects.iter().enumerate() {
        let mut paths: Vec<&str> = object
            .observations
            .iter()
            .map(|observation| observation.path.as_str())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        if paths.len() < 2 {
            continue;
        }
        let mut pids: Vec<u32> = object.mappings.iter().map(|(pid, _)| *pid).collect();
        pids.sort_unstable();
        pids.dedup();
        relationships.push(Relationship::Alias {
            object: index,
            sha256: object.sha256.clone(),
            paths: paths.into_iter().map(str::to_string).collect(),
            pids,
        });
    }
    relationships
}

/// The empty-machine explanation (D2): what was scanned, which caps hit,
/// and where to look next. Rendered in both text and JSON.
fn empty_explanation(collection: &Collection, matched: usize, skipped: &[PidGap]) -> String {
    let unreadable = collection.unreadable();
    let exited = collection
        .members
        .iter()
        .filter(|member| matches!(member.status, MemberStatus::Exited))
        .count();
    let not_selected = collection
        .enumerated
        .len()
        .saturating_sub(collection.selected.len());
    let mut parts = vec![format!(
        "deep-scanned {} of {} enumerated processes ({unreadable} unreadable, {exited} exited \
         before scan, {not_selected} past the {} scan cap, {matched} of them attributed by maps \
         identity)",
        collection.scanned(),
        collection.enumerated.len(),
        collection.cap,
    )];
    if collection.cap_hit {
        parts.push(format!(
            "the scan cap hit: only {} of {} processes were deep-scanned; re-run with \
             --max-scan-pids <n> to cover more",
            collection.selected.len(),
            collection.enumerated.len(),
        ));
    }
    if !skipped.is_empty() {
        parts.push(format!(
            "{} gap{} listed under skipped",
            skipped.len(),
            if skipped.len() == 1 { "" } else { "s" }
        ));
    }
    parts.push(
        "where next: load a PKCS#11 provider in a process, then re-run `p11scope inspect \
         --system`; `p11scope doctor` checks host readiness"
            .to_string(),
    );
    format!("No PKCS#11 modules discovered: {}", parts.join("; "))
}

/// Renders the catalog as JSON. Document id:
/// `p11scope/inspect-system/v1`. The catalog records carry structure only
/// — identities, mappings, decoded tables, admission verdicts — and never
/// observed-call fields (pinned by `catalog_json_has_no_observed_call_fields`).
fn render_json(catalog: &Catalog) -> serde_json::Value {
    let processes: Vec<serde_json::Value> = catalog
        .processes
        .iter()
        .map(|process| {
            let mut record = serde_json::json!({
                "pid": process.pid,
                "source": "proc-enumeration",
                "status": process.status.label(),
                "objects": process.objects,
            });
            if let Some(reason) = process.status.reason() {
                record["reason"] = serde_json::Value::String(reason.to_string());
            }
            record
        })
        .collect();
    let objects: Vec<serde_json::Value> = catalog.objects.iter().map(object_json).collect();
    let relationships: Vec<serde_json::Value> = catalog
        .relationships
        .iter()
        .map(|relationship| match relationship {
            Relationship::SamePath { path, members } => serde_json::json!({
                "kind": "same_path",
                "path": path,
                "members": members
                    .iter()
                    .map(|member| serde_json::json!({
                        "object": member.object,
                        "sha256": member.sha256,
                        "pids": member.pids,
                    }))
                    .collect::<Vec<_>>(),
            }),
            Relationship::Alias {
                object,
                sha256,
                paths,
                pids,
            } => serde_json::json!({
                "kind": "alias",
                "object": object,
                "sha256": sha256,
                "paths": paths,
                "pids": pids,
            }),
        })
        .collect();
    let gap_json = |gap: &PidGap| {
        serde_json::json!({
            "pid": gap.pid,
            "subject": gap.subject,
            "reason": gap.reason,
        })
    };
    let losses: serde_json::Map<String, serde_json::Value> = AttributionLoss::ALL
        .iter()
        .map(|loss| {
            (
                loss.label().to_string(),
                serde_json::Value::from(catalog.attribution_losses.get(loss).copied().unwrap_or(0)),
            )
        })
        .collect();
    let mut document = serde_json::json!({
        "schema": DOC_ID,
        "scope": "system",
        "scan": {
            "status": catalog.scan_status,
            "enumerated": catalog.enumerated,
            "limit": catalog.cap,
            "selected": catalog.selected,
            "deep_scanned": catalog.scanned,
            "maps_matched": catalog.maps_matched,
            "unexamined": catalog.unexamined,
            "unexamined_objects": catalog.unexamined_objects,
            "snapshots_unavailable": catalog.snapshots_unavailable,
            "attribution_losses": losses,
            "scan_ms": catalog.scan_ms,
        },
        "processes": processes,
        "objects": objects,
        "relationships": relationships,
        "admission": {
            "policy": "detailed",
            "scope": "shared",
            "scan_only": true,
            "note": SCAN_ONLY_NOTE,
            "uncorroborated_candidates": catalog.admission.uncorroborated_candidates,
            "module_ambiguous": catalog.admission.module_ambiguous,
            "admitted": catalog.admission.admitted,
            "refused": catalog.admission.refused,
            "unresolved": catalog.admission.unresolved,
        },
        "skipped": catalog.skipped.iter().map(gap_json).collect::<Vec<_>>(),
        "notes": catalog.notes.iter().map(gap_json).collect::<Vec<_>>(),
        // F3 (review): the same PID-numbering disclosure as capture evidence
        // and inventory; every PID here is read through /proc.
        "pid_namespace": crate::pidns::PidNamespaceEvidence::of(crate::pidns::numbering()),
    });
    if let Some(explanation) = &catalog.explanation {
        document["explanation"] = serde_json::Value::String(explanation.clone());
    }
    document
}

fn object_json(object: &CatalogObject) -> serde_json::Value {
    let observations: Vec<serde_json::Value> = object
        .observations
        .iter()
        .map(|observation| {
            let tables: Vec<serde_json::Value> = observation
                .tables
                .iter()
                .map(|table| {
                    serde_json::json!({
                        "version": format!("{}.{}", table.version.0, table.version.1),
                        "walk": table.walk,
                        "entries": table.entries.len(),
                        "null_entries": table.null_entries,
                        "unpinned": table
                            .unpinned
                            .iter()
                            .map(|skip| serde_json::json!({
                                "subject": skip.subject,
                                "reason": skip.reason,
                            }))
                            .collect::<Vec<_>>(),
                        "address": format!("{:#x}", table.address),
                    })
                })
                .collect();
            let interfaces: Vec<serde_json::Value> = observation
                .interfaces
                .iter()
                .map(|interface| {
                    serde_json::json!({
                        "index": interface.index,
                        "name_class": interface.name_class,
                        "name": interface.name_lossy,
                        "flags": interface.flags,
                        "table": interface.table,
                    })
                })
                .collect();
            serde_json::json!({
                "pid": observation.pid,
                "path": observation.path,
                "evidence": observation.evidence.label(),
                "exports": observation.exports,
                "tables": tables,
                "interfaces": interfaces,
            })
        })
        .collect();
    let mut admission = match &object.admission {
        AdmissionRecord::Admitted { class, endpoints } => serde_json::json!({
            "class": class,
            "endpoints": endpoints,
            "scan_only": true,
            "note": SCAN_ONLY_NOTE,
        }),
        AdmissionRecord::Refused { class, reason } => serde_json::json!({
            "class": class,
            "reason": reason,
            "scan_only": true,
            "note": SCAN_ONLY_NOTE,
        }),
        AdmissionRecord::Unresolved { reasons } => serde_json::json!({
            "reasons": reasons,
        }),
    };
    admission["state"] = serde_json::Value::String(object.admission.state().to_string());
    serde_json::json!({
        "path": object.path,
        "device": {
            "major": object.key.device.major,
            "minor": object.key.device.minor,
        },
        "inode": object.key.inode,
        "identity": {
            "sha256": object.sha256,
            "build_id": object.build_id,
            "identity_source": object.identity_source,
            "note": object.note,
        },
        "mappings": object
            .mappings
            .iter()
            .map(|(pid, view)| serde_json::json!({ "pid": pid, "view": view.map(|view| view.0) }))
            .collect::<Vec<_>>(),
        "observations": observations,
        "admission": admission,
    })
}

/// Renders the catalog as human-readable text: the same facts as the JSON
/// (identities, states, totals, gaps) in pid-inspect's layout. Plain
/// stdout; pager design is not this command's job.
fn render_text(catalog: &Catalog) -> String {
    let mut out = String::new();
    let word = if catalog.objects.len() == 1 {
        "object"
    } else {
        "objects"
    };
    let _ = writeln!(
        out,
        "system — {} PKCS#11 {word} in {} processes ({} deep-scanned and {} maps-matched of {} \
         enumerated, cap {}; scan {}ms, {})",
        catalog.objects.len(),
        catalog.processes.len(),
        catalog.scanned,
        catalog.maps_matched,
        catalog.enumerated,
        catalog.cap,
        catalog.scan_ms,
        catalog.scan_status,
    );
    out.push('\n');
    for (index, object) in catalog.objects.iter().enumerate() {
        render_object(&mut out, index, object);
        out.push('\n');
    }
    if !catalog.relationships.is_empty() {
        out.push_str("relationships:\n");
        for relationship in &catalog.relationships {
            match relationship {
                Relationship::SamePath { path, members } => {
                    let parts: Vec<String> = members
                        .iter()
                        .map(|member| {
                            let pids: Vec<String> =
                                member.pids.iter().map(|pid| pid.to_string()).collect();
                            format!(
                                "object[{}] sha256 {} (pid {})",
                                member.object,
                                member.sha256.as_deref().unwrap_or("-"),
                                pids.join(",")
                            )
                        })
                        .collect();
                    let _ = writeln!(
                        out,
                        "  same path {}: {}",
                        crate::render::escape_controls(path),
                        parts.join("; ")
                    );
                }
                Relationship::Alias {
                    object,
                    paths,
                    pids,
                    ..
                } => {
                    let _ = writeln!(
                        out,
                        "  alias object[{object}] (pid {}): {}",
                        pids.iter()
                            .map(|pid| pid.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                        paths
                            .iter()
                            .map(|path| crate::render::escape_controls(path))
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                }
            }
        }
        out.push('\n');
    }
    render_process_summary(&mut out, catalog);
    render_gaps(&mut out, "skipped", &catalog.skipped);
    render_gaps(&mut out, "notes", &catalog.notes);
    if let Some(explanation) = &catalog.explanation {
        let _ = writeln!(out, "{explanation}");
    }
    out
}

fn render_object(out: &mut String, index: usize, object: &CatalogObject) {
    let _ = writeln!(
        out,
        "object[{index}]  {}",
        crate::render::escape_controls(&object.path)
    );
    let _ = writeln!(
        out,
        "  identity   sha256 {}  build-id {}  dev {}:{}  ino {}",
        object.sha256.as_deref().unwrap_or("-"),
        object.build_id.as_deref().unwrap_or("-"),
        object.key.device.major,
        object.key.device.minor,
        object.key.inode,
    );
    let mappings: Vec<String> = object
        .mappings
        .iter()
        .map(|(pid, view)| match view {
            Some(view) => format!("pid {pid} (view {})", view.0),
            None => format!("pid {pid} (maps match)"),
        })
        .collect();
    let _ = writeln!(out, "  mapped by  {}", mappings.join(", "));
    match &object.admission {
        AdmissionRecord::Admitted { class, endpoints } => {
            let _ = writeln!(
                out,
                "  admission  admitted ({class}, {endpoints} endpoints; {SCAN_ONLY_NOTE})"
            );
        }
        AdmissionRecord::Refused { class, reason } => {
            let _ = writeln!(
                out,
                "  admission  refused ({class}): {} [{SCAN_ONLY_NOTE}]",
                crate::render::escape_controls(reason),
            );
        }
        AdmissionRecord::Unresolved { reasons } => {
            for reason in reasons {
                let _ = writeln!(
                    out,
                    "  admission  unresolved: {}",
                    crate::render::escape_controls(reason),
                );
            }
        }
    }
    for observation in &object.observations {
        if observation.evidence == ObservationEvidence::MapsMatch {
            let _ = writeln!(
                out,
                "  observed   pid {}: maps match at {} (not decoded)",
                observation.pid,
                crate::render::escape_controls(&observation.path),
            );
            continue;
        }
        let _ = writeln!(
            out,
            "  observed   pid {}: exports {}",
            observation.pid,
            if observation.exports.is_empty() {
                "-".to_string()
            } else {
                observation.exports.join(", ")
            },
        );
        for table in &observation.tables {
            let count = table.entries.len();
            let entry_word = if count == 1 { "entry" } else { "entries" };
            let nulls = if table.null_entries.is_empty() {
                String::new()
            } else {
                format!("  (NULL: {})", table.null_entries.join(", "))
            };
            let unpinned = if table.unpinned.is_empty() {
                String::new()
            } else {
                format!("  (unpinned: {})", table.unpinned.len())
            };
            let _ = writeln!(
                out,
                "    table      {}.{}  {}  {count} {entry_word}{nulls}{unpinned}",
                table.version.0, table.version.1, table.walk
            );
        }
        for interface in &observation.interfaces {
            let name = interface
                .name_lossy
                .as_deref()
                .unwrap_or(match interface.name_class {
                    "null" => "(null)",
                    "unreadable" => "(unreadable)",
                    _ => "(unknown)",
                });
            let name = name.escape_default();
            let target = interface
                .table
                .and_then(|index| observation.tables.get(index))
                .map_or("-".to_string(), |table| {
                    format!("{}.{}", table.version.0, table.version.1)
                });
            let _ = writeln!(
                out,
                "    interface  [{}] \"{name}\"  flags {:#x}  -> table {target}",
                interface.index, interface.flags
            );
        }
    }
}

fn render_process_summary(out: &mut String, catalog: &Catalog) {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for process in &catalog.processes {
        *counts.entry(process.status.label()).or_default() += 1;
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(status, count)| format!("{count} {status}"))
        .collect();
    let _ = writeln!(out, "processes: {}", parts.join(", "));
    let _ = writeln!(
        out,
        "admission: {} admitted, {} refused, {} unresolved ({} uncorroborated candidates, {} \
         module-ambiguous; {SCAN_ONLY_NOTE})",
        catalog.admission.admitted,
        catalog.admission.refused,
        catalog.admission.unresolved,
        catalog.admission.uncorroborated_candidates,
        catalog.admission.module_ambiguous,
    );
}

fn render_gaps(out: &mut String, title: &str, gaps: &[PidGap]) {
    for gap in gaps {
        match gap.pid {
            Some(pid) => {
                let _ = writeln!(
                    out,
                    "{title}: pid {pid} {} — {}",
                    crate::render::escape_controls(&gap.subject),
                    crate::render::escape_controls(&gap.reason)
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "{title}: {} — {}",
                    crate::render::escape_controls(&gap.subject),
                    crate::render::escape_controls(&gap.reason)
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::scan::{ScannedEntry, ScannedInterface, ScannedTable};
    use p11scope_manifest::maps::{Device, ObjectKey};

    fn key(inode: u64) -> ObjectKey {
        ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode,
        }
    }

    fn table(version: (u8, u8), entries: usize) -> ScannedTable {
        ScannedTable {
            version,
            walk: "full",
            entries: (0..entries)
                .map(|index| ScannedEntry {
                    name: "C_Sign",
                    object: key(11),
                    object_path: "/opt/provider.so".into(),
                    file_offset: index as u64 * 8,
                })
                .collect(),
            null_entries: vec![],
            unpinned: vec![],
            address: 0x7f00_0000_1000,
            file_offset: Some(0x1000),
            live_return: false,
            manifest_supported: false,
        }
    }

    fn object(
        path: &str,
        inode: u64,
        sha256: Option<&str>,
        pid: u32,
        admission: AdmissionRecord,
    ) -> CatalogObject {
        CatalogObject {
            path: path.into(),
            key: key(inode),
            sha256: sha256.map(str::to_string),
            build_id: None,
            identity_source: sha256.map(|_| "mountinfo"),
            note: None,
            mappings: vec![(pid, Some(ProcessViewId(0)))],
            observations: vec![Observation {
                pid,
                path: path.into(),
                exports: vec!["C_GetFunctionList".into()],
                tables: vec![table((2, 40), 2)],
                double_loaded: false,
                evidence: ObservationEvidence::DeepScan,
                interfaces: vec![ScannedInterface {
                    index: 0,
                    name_class: "exact_standard",
                    name_lossy: Some("PKCS 11".into()),
                    name_private: Some(b"PKCS 11".to_vec()),
                    flags: 0,
                    table: Some(0),
                }],
            }],
            admission,
        }
    }

    fn catalog_with(objects: Vec<CatalogObject>) -> Catalog {
        let admitted = objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Admitted { .. }))
            .count();
        let refused = objects
            .iter()
            .filter(|object| matches!(object.admission, AdmissionRecord::Refused { .. }))
            .count();
        let unresolved = objects.len() - admitted - refused;
        Catalog {
            lowering: None,
            scan_status: "complete",
            enumerated: 2,
            selected: 2,
            scanned: 2,
            maps_matched: 0,
            unexamined: 0,
            unexamined_objects: 0,
            snapshots_unavailable: 0,
            attribution_losses: BTreeMap::new(),
            cap: MAX_SCAN_PIDS,
            scan_ms: 7,
            processes: vec![
                ProcessRecord {
                    pid: 100,
                    status: MemberStatus::Scanned,
                    objects: vec![0],
                    generation: None,
                },
                ProcessRecord {
                    pid: 200,
                    status: MemberStatus::Scanned,
                    objects: if objects.len() > 1 { vec![1] } else { vec![] },
                    generation: None,
                },
            ],
            objects,
            relationships: Vec::new(),
            admission: AdmissionSummary {
                uncorroborated_candidates: 0,
                module_ambiguous: 0,
                admitted,
                refused,
                unresolved,
            },
            skipped: Vec::new(),
            notes: Vec::new(),
            explanation: None,
            stage_timings: StageTimings::new(),
        }
    }

    mod c1b {
        use super::super::*;
        use crate::discovery::identity::test_fixture::{PATH, SHA, module, view_pin};
        use crate::discovery::identity::{FileIdentity, MappedFile};
        use crate::discovery::sweep_attribution::{Confirmation, ConfirmedRead, MappedIdentities};
        use p11scope_manifest::maps::{Device, ObjectKey};
        use std::collections::HashMap;

        const PROVIDER: ObjectKey = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 4_242,
        };
        /// The `vm_file` identities the scripted `map_files` reads return:
        /// one file per inode (a subvolume-style device, never the maps one).
        const PROVIDER_FILE: FileIdentity = FileIdentity {
            dev: 37,
            ino: 4_242,
        };
        const LIBC_FILE: FileIdentity = FileIdentity { dev: 37, ino: 11 };

        fn vm_file(entry: &MapEntry) -> FileIdentity {
            FileIdentity {
                dev: 37,
                ino: entry.inode,
            }
        }

        fn entry(start: u64, perms: &[u8; 4], inode: u64, path: &str) -> MapEntry {
            MapEntry {
                start,
                end: start + 0x1000,
                file_offset: if perms[2] == b'x' { 0x1000 } else { 0 },
                permissions: *perms,
                device: Device { major: 8, minor: 1 },
                inode,
                raw_path: Some(path.as_bytes().to_vec()),
            }
        }

        fn libc() -> Vec<MapEntry> {
            vec![
                entry(0x2000_0000, b"r--p", 11, "/usr/lib/libc.so.6"),
                entry(0x2000_1000, b"r-xp", 11, "/usr/lib/libc.so.6"),
            ]
        }

        fn caller() -> Vec<MapEntry> {
            let mut entries = vec![
                entry(0x1000_0000, b"r--p", PROVIDER.inode, PATH),
                entry(0x1000_1000, b"r-xp", PROVIDER.inode, PATH),
            ];
            entries.extend(libc());
            entries
        }

        fn exe() -> ExeIdentity {
            ExeIdentity {
                dev: 1,
                ino: 100,
                mtime_secs: 10,
                mtime_nanos: 0,
                path: Some("/usr/bin/caller".into()),
            }
        }

        struct Probe(HashMap<u32, Vec<MapEntry>>, HashMap<u32, Confirmation>);

        impl MemberProbe for Probe {
            fn confirm(
                &mut self,
                pid: u32,
                _: &BTreeSet<ObjectKey>,
                _: &mut CaptureWorkBudget,
            ) -> Confirmation {
                if let Some(scripted) = self.1.get(&pid) {
                    return scripted.clone();
                }
                let entries = self.0.get(&pid).cloned().unwrap_or_default();
                let mapped = entries
                    .iter()
                    .map(|entry| ((entry.start, entry.end), Ok(vm_file(entry))))
                    .collect();
                Confirmation::Confirmed(ConfirmedRead {
                    start_time: 9_000 + u64::from(pid),
                    exe: exe(),
                    entries,
                    mapped,
                })
            }

            fn stat_ranges(
                &mut self,
                pid: u32,
                ranges: &[(u64, u64)],
                _: &mut CaptureWorkBudget,
            ) -> MappedIdentities {
                let entries = self.0.get(&pid).cloned().unwrap_or_default();
                ranges
                    .iter()
                    .filter_map(|range| {
                        entries
                            .iter()
                            .find(|entry| (entry.start, entry.end) == *range)
                            .map(|entry| (*range, Ok(vm_file(entry))))
                    })
                    .collect()
            }
        }

        /// Scripted object checks: the fixture pins are backed by /dev/null,
        /// whose real metadata never matches the forged pin.
        struct Checks {
            changed: bool,
            /// Scripts every object onto a filesystem without unique inodes.
            nonunique: Option<&'static str>,
        }

        impl ObjectChecks for Checks {
            fn nonunique_inodes(&self, _: PinnedObjectId) -> Result<Option<&'static str>, String> {
                Ok(self.nonunique)
            }
            fn unchanged(&self, _: PinnedObjectId) -> Result<bool, String> {
                Ok(!self.changed)
            }
            fn mapped_identity(&self, _: PinnedObjectId) -> Result<MappedFile, String> {
                Ok(MappedFile {
                    identity: PROVIDER_FILE,
                    fs_magic: None,
                })
            }
        }

        fn scanned(
            pid: u32,
            view: u32,
            modules: Vec<ScannedModule>,
            pins: PinnedObjects,
        ) -> MemberResult {
            MemberResult {
                pid,
                view: ProcessViewId(view),
                status: MemberStatus::Scanned,
                generation: Some(MemberGeneration {
                    start_time: Some(1),
                    exe: Some(exe()),
                }),
                modules,
                // Each deep scan examined libc and found no provider.
                examined: vec![ExaminedObject {
                    key: ObjectKey::of(&libc()[0]),
                    identity: LIBC_FILE,
                    key_is_identity: false,
                }],
                pins,
                gaps: Vec::new(),
                scan_ms: 1,
            }
        }

        /// 448 processes over a 256 cap: 300 identical callers of one
        /// provider (one deep-scanned) plus 148 idle processes (one
        /// deep-scanned). `extra` adds per-pid mappings past phase 1.
        fn over_cap(extra: &[(u32, Vec<MapEntry>)]) -> Collection {
            let mut sweep: Vec<(u32, Vec<MapEntry>)> =
                (10_000..10_300).map(|pid| (pid, caller())).collect();
            sweep.extend((20_000..20_148).map(|pid| (pid, libc())));
            for (pid, entries) in extra {
                if let Some((_, known)) = sweep.iter_mut().find(|(known, _)| known == pid) {
                    known.extend(entries.iter().cloned());
                }
            }
            let mut provider = module(PROVIDER);
            provider.view = ProcessViewId(0);
            let pins = view_pin(&provider, 21, SHA, 1, false);
            Collection {
                enumerated: sweep.iter().map(|(pid, _)| *pid).collect(),
                selected: vec![10_000, 20_000],
                cap: 256,
                cap_hit: true,
                members: vec![
                    scanned(10_000, 0, vec![provider], pins),
                    scanned(20_000, 1, Vec::new(), PinnedObjects::empty()),
                ],
                scope_gaps: Vec::new(),
                proc_list_failed: false,
                sweep,
                sweep_unavailable: BTreeSet::new(),
                budget: CaptureWorkBudget::default(),
            }
        }

        fn catalog_of(
            mut collection: Collection,
            overrides: HashMap<u32, Confirmation>,
            changed: bool,
        ) -> Catalog {
            let snapshots: HashMap<u32, Vec<MapEntry>> = collection.sweep.iter().cloned().collect();
            let bound = bind_collection(&mut collection);
            let mut probe = Probe(snapshots, overrides);
            let checks = Checks {
                changed,
                nonunique: None,
            };
            let attributed = attribute_sweep(&mut collection, &bound, &mut probe, &checks);
            assemble(collection, bound, attributed, AdmissionPolicy::detailed())
        }

        fn catalog_with(mut collection: Collection, checks: &Checks) -> Catalog {
            let snapshots: HashMap<u32, Vec<MapEntry>> = collection.sweep.iter().cloned().collect();
            let bound = bind_collection(&mut collection);
            let mut probe = Probe(snapshots, HashMap::new());
            let attributed = attribute_sweep(&mut collection, &bound, &mut probe, checks);
            assemble(collection, bound, attributed, AdmissionPolicy::detailed())
        }

        fn capped_gaps(catalog: &Catalog) -> Vec<&PidGap> {
            catalog
                .skipped
                .iter()
                .filter(|gap| gap.subject == "discovery capped")
                .collect()
        }

        fn attribution_complete(catalog: &Catalog) -> bool {
            catalog
                .notes
                .iter()
                .any(|note| note.reason.starts_with("attribution complete"))
        }

        /// Review fix (Important 2): "examined" comes from the deep scan's
        /// own read. The representative's phase-1 snapshot still showed
        /// `libunknown.so`, but its deep scan did not examine it (unloaded
        /// in between): another process mapping it is unexamined, so the
        /// pass is capped, never complete.
        #[test]
        fn a_key_only_the_representatives_sweep_snapshot_showed_stays_unexamined() {
            let other = vec![
                entry(0x5000_0000, b"r--p", 77, "/opt/vendor/libunknown.so"),
                entry(0x5000_1000, b"r-xp", 77, "/opt/vendor/libunknown.so"),
            ];
            let catalog = catalog_of(
                over_cap(&[(20_000, other.clone()), (20_005, other)]),
                HashMap::new(),
                false,
            );
            assert_eq!(catalog.scan_status, "partial");
            assert_eq!((catalog.unexamined, catalog.unexamined_objects), (1, 1));
            assert_eq!(capped_gaps(&catalog).len(), 1, "{:?}", catalog.skipped);
            assert!(!attribution_complete(&catalog));
        }

        /// Review fix (Minor 3): a process past the cap with no maps
        /// snapshot leaves the pass capped even when nothing is unexamined.
        #[test]
        fn an_unavailable_snapshot_alone_keeps_discovery_capped() {
            let mut collection = over_cap(&[]);
            if let Some((_, entries)) = collection.sweep.iter_mut().find(|(pid, _)| *pid == 20_100)
            {
                entries.clear();
            }
            collection.sweep_unavailable.insert(20_100);
            let catalog = catalog_of(collection, HashMap::new(), false);
            assert_eq!(catalog.unexamined, 0);
            assert_eq!(catalog.scan_status, "partial");
            let capped = capped_gaps(&catalog);
            assert_eq!(capped.len(), 1, "{:?}", catalog.skipped);
            assert!(
                capped[0]
                    .reason
                    .ends_with("; 1 processes past the cap had no maps snapshot"),
                "{}",
                capped[0].reason
            );
            assert!(!attribution_complete(&catalog));
        }

        /// Review fix (Minor 5): an object refused for non-unique inodes is
        /// a gap only when a process past the cap maps it.
        #[test]
        fn a_refused_nonunique_inode_object_is_a_gap_only_where_unselected_processes_map_it() {
            let fuse = Checks {
                changed: false,
                nonunique: Some("fuse"),
            };
            let refused_gap = |catalog: &Catalog| {
                catalog
                    .skipped
                    .iter()
                    .any(|gap| gap.reason.starts_with("on a fuse filesystem"))
            };
            let mapped = catalog_with(over_cap(&[]), &fuse);
            assert!(refused_gap(&mapped), "{:?}", mapped.skipped);
            assert_eq!(
                mapped.attribution_losses[&AttributionLoss::InodeNotUnique],
                299
            );

            let mut alone = over_cap(&[]);
            alone
                .sweep
                .retain(|(pid, _)| !(10_001..10_300).contains(pid));
            alone
                .enumerated
                .retain(|pid| !(10_001..10_300).contains(pid));
            let alone = catalog_with(alone, &fuse);
            assert!(!refused_gap(&alone), "{:?}", alone.skipped);
            assert_eq!(alone.scan_status, "complete", "{:?}", alone.skipped);
        }

        fn statuses(catalog: &Catalog) -> BTreeMap<&'static str, usize> {
            let mut counts = BTreeMap::new();
            for process in &catalog.processes {
                *counts.entry(process.status.label()).or_default() += 1;
            }
            counts
        }

        #[test]
        fn over_the_cap_every_identical_caller_is_mapped_and_attribution_is_complete() {
            let catalog = catalog_of(over_cap(&[]), HashMap::new(), false);
            assert_eq!(
                statuses(&catalog),
                BTreeMap::from([("maps_matched", 299), ("not_selected", 147), ("scanned", 2)])
            );
            assert_eq!(catalog.objects.len(), 1);
            let object = &catalog.objects[0];
            let pids: BTreeSet<u32> = object.mappings.iter().map(|(pid, _)| *pid).collect();
            assert_eq!(pids, (10_000..10_300).collect());
            assert_eq!(
                object.observations.len(),
                300,
                "one observation per caller, no duplicate"
            );
            let matched: Vec<&Observation> = object
                .observations
                .iter()
                .filter(|observation| observation.evidence == ObservationEvidence::MapsMatch)
                .collect();
            assert_eq!(matched.len(), 299);
            assert!(
                matched
                    .iter()
                    .all(|observation| observation.exports.is_empty()
                        && observation.tables.is_empty()
                        && observation.interfaces.is_empty())
            );
            let process = catalog
                .processes
                .iter()
                .find(|process| process.pid == 10_007)
                .unwrap();
            assert_eq!(process.objects, vec![0]);
            assert_eq!(
                process.generation,
                Some(MemberGeneration {
                    start_time: Some(19_007),
                    exe: Some(exe()),
                })
            );
            assert_eq!(catalog.scan_status, "complete", "{:?}", catalog.skipped);
            assert!(catalog.skipped.is_empty(), "{:?}", catalog.skipped);
            assert!(
                catalog
                    .notes
                    .iter()
                    .any(|note| note.subject == "discovery capped"
                        && note.reason.starts_with(
                            "attribution complete: 448 processes in scope; 2 \
                     deep-scanned by provider rarity (limit 256); 299 attributed"
                        )),
                "{:?}",
                catalog.notes
            );
            let document = render_json(&catalog);
            assert_eq!(document["scan"]["maps_matched"], 299);
            assert_eq!(document["scan"]["deep_scanned"], 2);
            assert_eq!(document["scan"]["limit"], 256);
            assert_eq!(document["scan"]["unexamined"], 0);
            assert_eq!(document["scan"]["attribution_losses"]["deleted_mapping"], 0);
            let observation = document["objects"][0]["observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|observation| observation["pid"] == 10_007)
                .unwrap()
                .clone();
            assert_eq!(observation["evidence"], "maps_match");
            let mapping = document["objects"][0]["mappings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|mapping| mapping["pid"] == 10_007)
                .unwrap()
                .clone();
            assert_eq!(mapping["view"], serde_json::Value::Null);
            let text = render_text(&catalog);
            assert!(
                text.contains("2 deep-scanned and 299 maps-matched of 448"),
                "{text}"
            );
            assert!(text.contains("299 maps_matched"), "{text}");
        }

        #[test]
        fn unexamined_shared_objects_make_discovery_capped_never_complete() {
            let other = vec![
                entry(0x5000_0000, b"r--p", 77, "/opt/vendor/libunknown.so"),
                entry(0x5000_1000, b"r-xp", 77, "/opt/vendor/libunknown.so"),
            ];
            let catalog = catalog_of(
                over_cap(&[(10_001, other.clone()), (20_005, other)]),
                HashMap::new(),
                false,
            );
            assert_eq!(catalog.scan_status, "partial");
            assert_eq!((catalog.unexamined, catalog.unexamined_objects), (2, 1));
            let capped: Vec<&PidGap> = catalog
                .skipped
                .iter()
                .filter(|gap| gap.subject == "discovery capped")
                .collect();
            assert_eq!(capped.len(), 1, "{:?}", catalog.skipped);
            assert_eq!(
                capped[0].reason,
                "448 processes in scope; 2 deep-scanned by provider rarity (limit 256); 299 \
                 attributed to pinned provider objects by exact maps identity; 2 processes map 1 \
                 shared objects no deep scan examined and may use undiscovered providers"
            );
            assert!(
                catalog
                    .skipped
                    .iter()
                    .any(|gap| gap.pid == Some(10_001) && gap.subject == "maps attribution"),
                "the matched member names its unexamined object: {:?}",
                catalog.skipped
            );
            assert!(
                !catalog
                    .notes
                    .iter()
                    .any(|note| note.reason.starts_with("attribution complete"))
            );
            assert_eq!(statuses(&catalog)["maps_matched"], 299);
        }

        #[test]
        fn losses_are_counted_by_category_and_named_per_process() {
            let overrides = HashMap::from([
                (
                    10_003,
                    Confirmation::Lost(
                        crate::discovery::sweep_attribution::AttributionLoss::ExecChanged,
                        "exec".into(),
                    ),
                ),
                (10_004, Confirmation::Exited),
            ]);
            let catalog = catalog_of(over_cap(&[]), overrides, false);
            assert_eq!(catalog.scan_status, "partial");
            let gap = catalog
                .skipped
                .iter()
                .find(|gap| gap.subject == "maps attribution")
                .unwrap();
            assert!(gap.reason.contains("1 exec_changed"), "{gap:?}");
            let lost = catalog
                .processes
                .iter()
                .find(|process| process.pid == 10_003)
                .unwrap();
            assert_eq!(lost.status.label(), "not_selected");
            assert_eq!(lost.status.reason(), Some("exec_changed: exec"));
            let gone = catalog
                .processes
                .iter()
                .find(|process| process.pid == 10_004)
                .unwrap();
            assert_eq!(gone.status, MemberStatus::Exited);
            assert!(
                !catalog
                    .notes
                    .iter()
                    .any(|note| note.reason.starts_with("attribution complete"))
            );
            assert_eq!(statuses(&catalog)["maps_matched"], 297);
        }

        #[test]
        fn a_changed_object_drops_every_maps_attribution_with_a_gap() {
            let catalog = catalog_of(over_cap(&[]), HashMap::new(), true);
            assert_eq!(catalog.maps_matched, 0);
            assert_eq!(
                catalog.objects[0].observations.len(),
                1,
                "the deep scan stays"
            );
            assert!(
                catalog.skipped.iter().any(|gap| gap.subject == PATH
                    && gap.reason.contains("maps attributions were dropped")),
                "{:?}",
                catalog.skipped
            );
            assert_eq!(catalog.scan_status, "partial");
        }

        #[test]
        fn under_the_cap_nothing_is_attributed_by_maps() {
            let mut collection = over_cap(&[]);
            collection.cap_hit = false;
            let catalog = catalog_of(collection, HashMap::new(), false);
            assert_eq!(catalog.maps_matched, 0);
            assert!(
                !catalog
                    .notes
                    .iter()
                    .any(|note| note.subject == "discovery capped")
            );
        }
    }

    #[test]
    fn fully_unreadable_rule_needs_a_loss_besides_proven_exits() {
        // Nothing enumerated and the listing itself failed: hard error.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 0,
                scanned: 0,
                unreadable: 0,
                proc_list_failed: true,
            }),
            SystemOutcome::HardError
        );
        // Nothing enumerated, listing fine: a vacuously empty machine.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 0,
                scanned: 0,
                unreadable: 0,
                proc_list_failed: false,
            }),
            SystemOutcome::Render
        );
        // Enumerated, nothing inventoried, all exits proven: empty, not error.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 9,
                scanned: 0,
                unreadable: 0,
                proc_list_failed: false,
            }),
            SystemOutcome::Render
        );
        // Enumerated, nothing inventoried, one real loss: hard error.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 9,
                scanned: 0,
                unreadable: 1,
                proc_list_failed: false,
            }),
            SystemOutcome::HardError
        );
        // One inventoried member renders whatever else happened.
        assert_eq!(
            decide_system_outcome(OutcomeStats {
                enumerated: 9,
                scanned: 1,
                unreadable: 8,
                proc_list_failed: false,
            }),
            SystemOutcome::Render
        );
    }

    #[test]
    fn unreadable_system_error_names_the_cause_and_the_sudo_fix() {
        let collection = Collection {
            enumerated: vec![1, 2],
            selected: vec![1, 2],
            cap: MAX_SCAN_PIDS,
            cap_hit: false,
            members: vec![
                MemberResult {
                    pid: 1,
                    view: ProcessViewId(0),
                    generation: None,
                    status: MemberStatus::Unreadable {
                        reason: "the process generation could not be pinned: Permission denied \
                                 (os error 13)"
                            .into(),
                    },
                    modules: Vec::new(),
                    examined: Vec::new(),
                    pins: PinnedObjects::empty(),
                    gaps: Vec::new(),
                    scan_ms: 0,
                },
                MemberResult {
                    pid: 2,
                    view: ProcessViewId(1),
                    status: MemberStatus::Exited,
                    generation: None,
                    modules: Vec::new(),
                    examined: Vec::new(),
                    pins: PinnedObjects::empty(),
                    gaps: Vec::new(),
                    scan_ms: 0,
                },
            ],
            scope_gaps: Vec::new(),
            proc_list_failed: false,
            sweep: Vec::new(),
            sweep_unavailable: BTreeSet::new(),
            budget: CaptureWorkBudget::default(),
        };
        let error = format!("{:#}", unreadable_system_error(&collection));
        assert!(error.contains("no process could be read"), "{error}");
        assert!(error.contains("Permission denied"), "{error}");
        assert!(error.contains("unknown, not absent"), "{error}");
        assert!(error.contains("sudo p11scope inspect --system"), "{error}");
    }

    #[test]
    fn gaps_split_on_the_scan_vocabulary_and_dedup_generics() {
        let generic = |pid| {
            PidGap::generic_member(
                pid,
                Skipped {
                    subject: "process view".into(),
                    reason: "a process in scope could not be retained or scanned before it \
                             changed; a provider only that generation mapped was never discovered"
                        .into(),
                },
            )
        };
        let (skipped, notes) = split_gaps(vec![
            generic(7),
            generic(9),
            PidGap::member(
                7,
                Skipped {
                    subject: "/opt/a.so".into(),
                    reason: "identity_mismatch: mapping (8:1, 5) != opened (8:1, 6)".into(),
                },
            ),
            PidGap::member(
                9,
                Skipped {
                    subject: "/opt/b.so".into(),
                    reason: "no function table was found in its file-backed data".into(),
                },
            ),
            // Exact repeats collapse.
            PidGap::member(
                9,
                Skipped {
                    subject: "/opt/b.so".into(),
                    reason: "no function table was found in its file-backed data".into(),
                },
            ),
        ]);
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert!(
            skipped.iter().any(|gap| gap.pid.is_none()),
            "the generic record collapses pid-less: {skipped:?}"
        );
        assert!(
            skipped
                .iter()
                .any(|gap| gap.reason.contains("identity_mismatch")),
            "{skipped:?}"
        );
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert_eq!(notes[0].pid, Some(9));
    }

    #[test]
    fn same_path_distinct_objects_group_by_identity_not_path() {
        // Pinned + unpinned under one path: a relationship with both.
        let objects = vec![
            object(
                "/tmp/x/prov.so",
                11,
                None,
                100,
                AdmissionRecord::Unresolved {
                    reasons: vec!["identity_mismatch".into()],
                },
            ),
            object(
                "/tmp/x/prov.so",
                12,
                Some("aa"),
                200,
                AdmissionRecord::Admitted {
                    class: "heuristic",
                    endpoints: 68,
                },
            ),
            object(
                "/opt/other.so",
                13,
                Some("bb"),
                100,
                AdmissionRecord::Admitted {
                    class: "heuristic",
                    endpoints: 68,
                },
            ),
        ];
        let relationships = build_relationships(&objects);
        assert_eq!(relationships.len(), 1, "{relationships:?}");
        let Relationship::SamePath { path, members } = &relationships[0] else {
            panic!("{relationships:?}");
        };
        assert_eq!(path, "/tmp/x/prov.so");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].sha256, None);
        assert_eq!(members[1].sha256.as_deref(), Some("aa"));

        // Two observations of one proven identity: no relationship.
        let single = vec![
            object(
                "/opt/same.so",
                21,
                Some("cc"),
                100,
                AdmissionRecord::Admitted {
                    class: "heuristic",
                    endpoints: 68,
                },
            ),
            object(
                "/opt/same.so",
                21,
                Some("cc"),
                200,
                AdmissionRecord::Admitted {
                    class: "heuristic",
                    endpoints: 68,
                },
            ),
        ];
        assert!(build_relationships(&single).is_empty());

        // Two unpinned records under one path: unproven, never merged —
        // a relationship even when the raw keys match.
        let unpinned = vec![
            object(
                "/tmp/x/dark.so",
                31,
                None,
                100,
                AdmissionRecord::Unresolved {
                    reasons: vec!["identity_mismatch".into()],
                },
            ),
            object(
                "/tmp/x/dark.so",
                31,
                None,
                200,
                AdmissionRecord::Unresolved {
                    reasons: vec!["identity_mismatch".into()],
                },
            ),
        ];
        let relationships = build_relationships(&unpinned);
        assert_eq!(relationships.len(), 1, "{relationships:?}");
        let Relationship::SamePath { path, members } = &relationships[0] else {
            panic!("{relationships:?}");
        };
        assert_eq!(path, "/tmp/x/dark.so");
        assert_eq!(members.len(), 2);

        // Grouping follows observation paths, not the canonical one: an
        // object observed under two spellings shares each of them.
        let mut aliased = object(
            "/opt/link.so",
            41,
            Some("dd"),
            100,
            AdmissionRecord::Admitted {
                class: "heuristic",
                endpoints: 68,
            },
        );
        let mut second = aliased.observations[0].clone();
        second.path = "/opt/real.so".into();
        second.pid = 200;
        aliased.observations.push(second);
        let distinct = object(
            "/opt/real.so",
            42,
            Some("ee"),
            300,
            AdmissionRecord::Admitted {
                class: "heuristic",
                endpoints: 68,
            },
        );
        let relationships = build_relationships(&[aliased, distinct]);
        assert_eq!(relationships.len(), 2, "{relationships:?}");
        let Relationship::SamePath { path, members } = &relationships[0] else {
            panic!("{relationships:?}");
        };
        assert_eq!(path, "/opt/real.so");
        assert_eq!(members.len(), 2);
        assert!(
            matches!(&relationships[1], Relationship::Alias { object: 0, .. }),
            "{relationships:?}"
        );
    }

    #[test]
    fn one_object_under_two_paths_is_an_alias() {
        let mut aliased = object(
            "/opt/a.so",
            31,
            Some("dd"),
            100,
            AdmissionRecord::Admitted {
                class: "heuristic",
                endpoints: 68,
            },
        );
        aliased.mappings.push((200, Some(ProcessViewId(1))));
        aliased.observations.push(Observation {
            pid: 200,
            path: "/opt/b.so".into(),
            exports: vec!["C_GetFunctionList".into()],
            tables: vec![table((2, 40), 2)],
            double_loaded: false,
            interfaces: Vec::new(),
            evidence: ObservationEvidence::DeepScan,
        });
        let relationships = build_relationships(std::slice::from_ref(&aliased));
        assert_eq!(relationships.len(), 1, "{relationships:?}");
        let Relationship::Alias {
            object,
            paths,
            pids,
            ..
        } = &relationships[0]
        else {
            panic!("{relationships:?}");
        };
        assert_eq!(*object, 0);
        assert_eq!(paths, &["/opt/a.so".to_string(), "/opt/b.so".to_string()]);
        assert_eq!(pids, &[100, 200]);
    }

    /// The E3 negative shape at the unit level: catalog records carry
    /// structure (identities, mappings, decoded tables, verdicts) and
    /// never observed-call fields. The reader test pins the same over the
    /// live document.
    #[test]
    fn catalog_json_has_no_observed_call_fields() {
        let forbidden = [
            "calls",
            "call_count",
            "observed",
            "observed_calls",
            "invocations",
            "events",
            "samples",
            "counts",
            "count",
            "latency",
            "durations",
            "rvs",
        ];
        let mut catalog = catalog_with(vec![
            object(
                "/opt/provider.so",
                11,
                Some("aa"),
                100,
                AdmissionRecord::Refused {
                    class: "closure_array",
                    reason: "module needs 388 more; only 512 attach slots are available".into(),
                },
            ),
            object(
                "/tmp/x/prov.so",
                12,
                None,
                200,
                AdmissionRecord::Unresolved {
                    reasons: vec!["identity_mismatch".into()],
                },
            ),
        ]);
        catalog.relationships = build_relationships(&catalog.objects);
        let document = render_json(&catalog);
        assert_eq!(document["schema"], DOC_ID);
        // F3: the same PID-numbering object as capture evidence and inventory.
        assert_eq!(document["pid_namespace"]["kernel_pids"], "initial");
        assert!(document["pid_namespace"]["observer"].is_string());
        let mut stack = vec![&document];
        let mut keys = Vec::new();
        while let Some(value) = stack.pop() {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        keys.push(key.clone());
                        stack.push(child);
                    }
                }
                serde_json::Value::Array(items) => stack.extend(items),
                _ => {}
            }
        }
        for key in &keys {
            assert!(
                !forbidden.contains(&key.as_str()),
                "observed-call field on a catalog record: {key}"
            );
        }
        assert!(keys.contains(&"observations".to_string()));
        assert!(keys.contains(&"mappings".to_string()));
    }

    #[test]
    fn catalog_json_marks_every_pinned_verdict_scan_only() {
        let catalog = catalog_with(vec![
            object(
                "/opt/a.so",
                11,
                Some("aa"),
                100,
                AdmissionRecord::Admitted {
                    class: "corroborated",
                    endpoints: 68,
                },
            ),
            object(
                "/opt/b.so",
                12,
                Some("bb"),
                100,
                AdmissionRecord::Refused {
                    class: "closure_array",
                    reason: "module needs 388 more".into(),
                },
            ),
            object(
                "/opt/c.so",
                13,
                None,
                200,
                AdmissionRecord::Unresolved {
                    reasons: vec!["identity_mismatch".into()],
                },
            ),
        ]);
        let document = render_json(&catalog);
        for index in 0..2 {
            assert_eq!(document["objects"][index]["admission"]["scan_only"], true);
            assert_eq!(
                document["objects"][index]["admission"]["note"],
                SCAN_ONLY_NOTE
            );
        }
        // Unresolved records carry bind reasons, not verdicts: no verdict
        // note to attach.
        assert_eq!(document["objects"][2]["admission"]["state"], "unresolved");
        assert!(document["objects"][2]["admission"].get("note").is_none());
        assert_eq!(document["admission"]["scan_only"], true);
        assert!(document.get("explanation").is_none());
    }

    #[test]
    fn empty_catalog_explains_itself_in_json_and_text() {
        let mut catalog = catalog_with(Vec::new());
        catalog.scan_status = "partial";
        catalog.explanation = Some("No PKCS#11 modules discovered: deep-scanned 2 of 2".into());
        let document = render_json(&catalog);
        assert_eq!(document["objects"], serde_json::json!([]));
        assert!(
            document["explanation"]
                .as_str()
                .is_some_and(|text| text.contains("deep-scanned 2 of 2")),
            "{document}"
        );
        let text = render_text(&catalog);
        assert!(text.contains("0 PKCS#11 objects"), "{text}");
        assert!(text.contains("deep-scanned 2 of 2"), "{text}");
    }

    #[test]
    fn text_names_identities_states_and_totals() {
        let catalog = catalog_with(vec![object(
            "/opt/provider.so",
            11,
            Some("aa"),
            100,
            AdmissionRecord::Refused {
                class: "closure_array",
                reason: "module needs 388 more".into(),
            },
        )]);
        let text = render_text(&catalog);
        assert!(text.contains("system — 1 PKCS#11 object"), "{text}");
        assert!(text.contains("/opt/provider.so"), "{text}");
        assert!(text.contains("sha256 aa"), "{text}");
        assert!(text.contains("pid 100 (view 0)"), "{text}");
        assert!(
            text.contains("refused (closure_array): module needs 388 more"),
            "{text}"
        );
        assert!(text.contains(SCAN_ONLY_NOTE), "{text}");
        assert!(text.contains("2.40"), "{text}");
        assert!(text.contains("PKCS 11"), "{text}");
        assert!(text.contains("processes: 2 scanned"), "{text}");
        assert!(
            text.contains("0 admitted, 1 refused, 0 unresolved"),
            "{text}"
        );
    }
}
